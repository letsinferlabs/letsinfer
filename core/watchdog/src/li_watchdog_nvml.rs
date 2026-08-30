// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_ulonglong, c_void};
use std::sync::Arc;

use crate::{
    WatchdogError, WatchdogLinuxCapability, WatchdogLinuxGpuProvider, WatchdogLinuxGpuSample,
    WATCHDOG_CLOCK_UNKNOWN, WATCHDOG_GPU_ENGINES, WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_TEMP_UNKNOWN,
};

const WATCHDOG_NVML_MAX_DEVICES: usize = 64;
const WATCHDOG_NVML_UUID_BUFFER_BYTES: usize = 96;
const WATCHDOG_NVML_SUCCESS: c_int = 0;
const WATCHDOG_NVML_REQUIRED_SYMBOLS: [&str; 5] = [
    "nvmlInit_v2",
    "nvmlShutdown",
    "nvmlDeviceGetCount_v2",
    "nvmlDeviceGetHandleByIndex_v2",
    "nvmlDeviceGetUUID",
];

// Reports dynamic symbol availability without exposing raw code addresses.
pub trait WatchdogNvmlSymbolProvider {
    // Returns whether one exact ABI symbol is present in the selected library.
    fn has_symbol(&self, name: &str) -> bool;
}

// Requires the exact versioned initialization, enumeration, and UUID identity ABI.
pub fn validate_watchdog_nvml_symbol_contract(
    provider: &dyn WatchdogNvmlSymbolProvider,
) -> Result<(), WatchdogError> {
    if WATCHDOG_NVML_REQUIRED_SYMBOLS
        .iter()
        .any(|name| !provider.has_symbol(name))
    {
        return Err(nvml_provider_error("required NVML symbol is unavailable"));
    }
    Ok(())
}

// Carries one exact device identity and every independently optional NVML value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogNvmlDeviceSample {
    uuid: String,
    gpu_percent: Option<u8>,
    memory_percent: Option<u8>,
    engine_percent: [Option<u8>; WATCHDOG_GPU_ENGINES],
    temperature_celsius: Option<i16>,
    power_milliwatts: Option<u32>,
    throttle_reasons: Option<u64>,
    gpu_clock_mhz: Option<u32>,
    memory_clock_mhz: Option<u32>,
}

impl WatchdogNvmlDeviceSample {
    // Creates one mockable device observation after validating every reported value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uuid: &str,
        gpu_percent: Option<u8>,
        memory_percent: Option<u8>,
        engine_percent: [Option<u8>; WATCHDOG_GPU_ENGINES],
        temperature_celsius: Option<i16>,
        power_milliwatts: Option<u32>,
        throttle_reasons: Option<u64>,
        gpu_clock_mhz: Option<u32>,
        memory_clock_mhz: Option<u32>,
    ) -> Result<Self, WatchdogError> {
        if !valid_uuid(uuid)
            || gpu_percent.is_some_and(|value| value > 100)
            || memory_percent.is_some_and(|value| value > 100)
            || engine_percent.iter().flatten().any(|value| *value > 100)
            || temperature_celsius.is_some_and(|value| !(-100..=250).contains(&value))
            || gpu_clock_mhz == Some(0)
            || memory_clock_mhz == Some(0)
        {
            return Err(nvml_error("NVML device observation is invalid"));
        }
        Ok(Self {
            uuid: uuid.to_string(),
            gpu_percent,
            memory_percent,
            engine_percent,
            temperature_celsius,
            power_milliwatts,
            throttle_reasons,
            gpu_clock_mhz,
            memory_clock_mhz,
        })
    }
}

// Isolates dynamic NVML loading and device calls from aggregation policy.
pub trait WatchdogNvmlPort: Send + Sync {
    // Returns every visible device observation in stable native index order.
    fn devices(
        &self,
    ) -> Result<WatchdogLinuxCapability<Vec<WatchdogNvmlDeviceSample>>, WatchdogError>;
}

// Aggregates bounded identity-checked NVML devices into the unchanged native record.
pub struct NvmlWatchdogLinuxGpuProvider {
    port: Arc<dyn WatchdogNvmlPort>,
}

impl NvmlWatchdogLinuxGpuProvider {
    // Creates one provider around an injected dynamic NVML port.
    pub fn new(port: Arc<dyn WatchdogNvmlPort>) -> Self {
        Self { port }
    }
}

impl WatchdogLinuxGpuProvider for NvmlWatchdogLinuxGpuProvider {
    // Samples and aggregates every visible uniquely identified device.
    fn sample(&self) -> Result<WatchdogLinuxCapability<WatchdogLinuxGpuSample>, WatchdogError> {
        let devices = match self.port.devices()? {
            WatchdogLinuxCapability::Available(devices) => devices,
            WatchdogLinuxCapability::Unsupported => {
                return Ok(WatchdogLinuxCapability::Unsupported)
            }
        };
        if devices.is_empty() || devices.len() > WATCHDOG_NVML_MAX_DEVICES {
            return Err(nvml_error("NVML device count is invalid"));
        }
        let mut identities = BTreeSet::new();
        let mut gpu_percent = None;
        let mut memory_percent = None;
        let mut engines = [None; WATCHDOG_GPU_ENGINES];
        let mut temperature = None;
        let mut power_milliwatts = 0_u64;
        let mut has_power = false;
        let mut throttled = false;
        let mut gpu_clock = None;
        let mut memory_clock = None;
        for device in devices {
            if !identities.insert(device.uuid.clone()) {
                return Err(nvml_error("NVML device identity is duplicated"));
            }
            retain_max(&mut gpu_percent, device.gpu_percent);
            retain_max(&mut memory_percent, device.memory_percent);
            for (aggregate, value) in engines.iter_mut().zip(device.engine_percent) {
                retain_max(aggregate, value);
            }
            retain_max(&mut temperature, device.temperature_celsius);
            if let Some(power) = device.power_milliwatts {
                power_milliwatts = power_milliwatts.saturating_add(u64::from(power));
                has_power = true;
            }
            throttled |= device.throttle_reasons.is_some_and(|value| value != 0);
            retain_max(&mut gpu_clock, device.gpu_clock_mhz);
            retain_max(&mut memory_clock, device.memory_clock_mhz);
        }
        let engine_percent = engines.map(|value| value.unwrap_or(WATCHDOG_PERCENT_UNKNOWN));
        let temperature_deci_c = temperature
            .and_then(|value| value.checked_mul(10))
            .unwrap_or(WATCHDOG_TEMP_UNKNOWN);
        let power_deci_w = if has_power {
            u16::try_from((power_milliwatts.saturating_add(50)) / 100).unwrap_or(u16::MAX)
        } else {
            0
        };
        WatchdogLinuxGpuSample::new(
            gpu_percent.unwrap_or(WATCHDOG_PERCENT_UNKNOWN),
            memory_percent.unwrap_or(WATCHDOG_PERCENT_UNKNOWN),
            engine_percent,
            temperature_deci_c,
            power_deci_w,
            throttled,
            gpu_clock.unwrap_or(WATCHDOG_CLOCK_UNKNOWN),
            memory_clock.unwrap_or(WATCHDOG_CLOCK_UNKNOWN),
        )
        .map(WatchdogLinuxCapability::Available)
    }
}

// Owns one dynamically loaded process-local NVML ABI and initialized device set.
pub struct DynamicWatchdogNvmlPort {
    library: *mut c_void,
    symbols: DynamicNvmlSymbols,
    devices: Vec<*mut c_void>,
}

// SAFETY: NVML documents these process-global query APIs as thread-safe after initialization.
unsafe impl Send for DynamicWatchdogNvmlPort {}
// SAFETY: all retained handles are immutable and calls write only caller-owned output buffers.
unsafe impl Sync for DynamicWatchdogNvmlPort {}

impl DynamicWatchdogNvmlPort {
    // Loads the versioned NVML ABI without adding a static NVIDIA dependency.
    pub fn open() -> Result<WatchdogLinuxCapability<Self>, WatchdogError> {
        let name = CString::new("libnvidia-ml.so.1").expect("fixed NVML library name");
        // SAFETY: name is NUL-terminated and dlopen retains its own library identity.
        let library = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if library.is_null() {
            return Ok(WatchdogLinuxCapability::Unsupported);
        }
        let result = Self::open_library(library);
        if result.is_err() {
            // SAFETY: library was returned by dlopen and ownership has not transferred.
            unsafe { libc::dlclose(library) };
        }
        result.map(WatchdogLinuxCapability::Available)
    }

    // Returns the exact physical device count retained after successful NVML initialization.
    pub fn physical_device_count(&self) -> u32 {
        u32::try_from(self.devices.len()).expect("NVML device count is bounded")
    }

    // Negotiates required versioned symbols and initializes a bounded stable device set.
    fn open_library(library: *mut c_void) -> Result<Self, WatchdogError> {
        let symbols = DynamicNvmlSymbols::load(library)?;
        // SAFETY: the address was resolved for the exact no-argument nvmlInit_v2 ABI.
        if unsafe { (symbols.init)() } != WATCHDOG_NVML_SUCCESS {
            return Err(nvml_provider_error("NVML initialization failed"));
        }
        let mut count = 0_u32;
        // SAFETY: count is writable and the symbol has the exact nvmlDeviceGetCount_v2 ABI.
        if unsafe { (symbols.count)(&mut count) } != WATCHDOG_NVML_SUCCESS
            || count == 0
            || count as usize > WATCHDOG_NVML_MAX_DEVICES
        {
            // SAFETY: initialization succeeded and shutdown uses its exact ABI.
            unsafe { (symbols.shutdown)() };
            return Err(nvml_provider_error("NVML device enumeration failed"));
        }
        let mut devices = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut device = std::ptr::null_mut();
            // SAFETY: device is writable and index is inside the just-returned device count.
            if unsafe { (symbols.handle)(index, &mut device) } != WATCHDOG_NVML_SUCCESS
                || device.is_null()
            {
                // SAFETY: initialization succeeded and shutdown uses its exact ABI.
                unsafe { (symbols.shutdown)() };
                return Err(nvml_provider_error("NVML device handle resolution failed"));
            }
            devices.push(device);
        }
        Ok(Self {
            library,
            symbols,
            devices,
        })
    }

    // Samples one handle while leaving each missing optional symbol explicitly unavailable.
    fn sample_device(
        &self,
        device: *mut c_void,
    ) -> Result<WatchdogNvmlDeviceSample, WatchdogError> {
        let uuid = self.symbols.uuid(device)?;
        let utilization = self.symbols.utilization.and_then(|function| {
            let mut value = NvmlUtilization::default();
            // SAFETY: value is writable and function is the exact resolved utilization ABI.
            (unsafe { function(device, &mut value) } == WATCHDOG_NVML_SUCCESS).then_some(value)
        });
        if utilization.is_some_and(|value| value.gpu > 100 || value.memory > 100) {
            return Err(nvml_provider_error(
                "NVML utilization is outside its native bounds",
            ));
        }
        let mut engines = [None; WATCHDOG_GPU_ENGINES];
        engines[0] = utilization.map(|value| value.gpu as u8);
        engines[1] = utilization.map(|value| value.memory as u8);
        for (slot, function) in engines[2..].iter_mut().zip(self.symbols.engines) {
            *slot = function.and_then(|function| sample_engine(function, device));
        }
        WatchdogNvmlDeviceSample::new(
            &uuid,
            utilization.map(|value| value.gpu as u8),
            utilization.map(|value| value.memory as u8),
            engines,
            self.symbols
                .temperature
                .and_then(|function| sample_u32(function, device, 0))
                .and_then(|value| i16::try_from(value).ok()),
            self.symbols
                .power
                .and_then(|function| sample_simple_u32(function, device)),
            self.symbols
                .throttle
                .and_then(|function| sample_u64(function, device)),
            self.symbols
                .clock
                .and_then(|function| sample_u32(function, device, 0)),
            self.symbols
                .clock
                .and_then(|function| sample_u32(function, device, 2)),
        )
    }
}

impl WatchdogNvmlPort for DynamicWatchdogNvmlPort {
    // Samples every initialized device or fails without publishing a partial aggregate.
    fn devices(
        &self,
    ) -> Result<WatchdogLinuxCapability<Vec<WatchdogNvmlDeviceSample>>, WatchdogError> {
        self.devices
            .iter()
            .map(|device| self.sample_device(*device))
            .collect::<Result<Vec<_>, _>>()
            .map(WatchdogLinuxCapability::Available)
    }
}

impl Drop for DynamicWatchdogNvmlPort {
    // Shuts down NVML before releasing its dynamic code addresses.
    fn drop(&mut self) {
        // SAFETY: this instance owns one successful initialization and dlopen handle.
        unsafe {
            (self.symbols.shutdown)();
            libc::dlclose(self.library);
        }
    }
}

type InitFn = unsafe extern "C" fn() -> c_int;
type CountFn = unsafe extern "C" fn(*mut c_uint) -> c_int;
type HandleFn = unsafe extern "C" fn(c_uint, *mut *mut c_void) -> c_int;
type UuidFn = unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> c_int;
type UtilizationFn = unsafe extern "C" fn(*mut c_void, *mut NvmlUtilization) -> c_int;
type U32Fn = unsafe extern "C" fn(*mut c_void, c_uint, *mut c_uint) -> c_int;
type SimpleU32Fn = unsafe extern "C" fn(*mut c_void, *mut c_uint) -> c_int;
type EngineFn = unsafe extern "C" fn(*mut c_void, *mut c_uint, *mut c_uint) -> c_int;
type U64Fn = unsafe extern "C" fn(*mut c_void, *mut c_ulonglong) -> c_int;

// Stores exact required and optional symbol addresses for the negotiated ABI.
struct DynamicNvmlSymbols {
    init: InitFn,
    shutdown: InitFn,
    count: CountFn,
    handle: HandleFn,
    uuid_fn: UuidFn,
    utilization: Option<UtilizationFn>,
    temperature: Option<U32Fn>,
    power: Option<SimpleU32Fn>,
    engines: [Option<EngineFn>; 4],
    throttle: Option<U64Fn>,
    clock: Option<U32Fn>,
}

impl DynamicNvmlSymbols {
    // Resolves required versioned identity symbols and optional telemetry symbols exactly once.
    fn load(library: *mut c_void) -> Result<Self, WatchdogError> {
        validate_watchdog_nvml_symbol_contract(&DynamicNvmlSymbolProvider { library })?;
        Ok(Self {
            init: required_symbol(library, b"nvmlInit_v2\0")?,
            shutdown: required_symbol(library, b"nvmlShutdown\0")?,
            count: required_symbol(library, b"nvmlDeviceGetCount_v2\0")?,
            handle: required_symbol(library, b"nvmlDeviceGetHandleByIndex_v2\0")?,
            uuid_fn: required_symbol(library, b"nvmlDeviceGetUUID\0")?,
            utilization: optional_symbol(library, b"nvmlDeviceGetUtilizationRates\0"),
            temperature: optional_symbol(library, b"nvmlDeviceGetTemperature\0"),
            power: optional_symbol(library, b"nvmlDeviceGetPowerUsage\0"),
            engines: [
                optional_symbol(library, b"nvmlDeviceGetEncoderUtilization\0"),
                optional_symbol(library, b"nvmlDeviceGetDecoderUtilization\0"),
                optional_symbol(library, b"nvmlDeviceGetJpgUtilization\0"),
                optional_symbol(library, b"nvmlDeviceGetOfaUtilization\0"),
            ],
            throttle: optional_symbol(library, b"nvmlDeviceGetCurrentClocksThrottleReasons\0"),
            clock: optional_symbol(library, b"nvmlDeviceGetClockInfo\0"),
        })
    }

    // Reads and validates the UUID of one exact initialized handle.
    fn uuid(&self, device: *mut c_void) -> Result<String, WatchdogError> {
        let mut buffer = [0 as c_char; WATCHDOG_NVML_UUID_BUFFER_BYTES];
        // SAFETY: buffer is writable and the resolved function uses the declared bound.
        if unsafe { (self.uuid_fn)(device, buffer.as_mut_ptr(), buffer.len() as c_uint) }
            != WATCHDOG_NVML_SUCCESS
        {
            return Err(nvml_provider_error("NVML device UUID is unavailable"));
        }
        buffer[WATCHDOG_NVML_UUID_BUFFER_BYTES - 1] = 0;
        // SAFETY: successful NVML UUID calls NUL-terminate within the supplied buffer.
        let value = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .map_err(|_| nvml_provider_error("NVML device UUID is invalid"))?;
        if !valid_uuid(value) {
            return Err(nvml_provider_error("NVML device UUID is invalid"));
        }
        Ok(value.to_string())
    }
}

// Resolves symbol presence from one live dlopen handle during ABI negotiation.
struct DynamicNvmlSymbolProvider {
    library: *mut c_void,
}

impl WatchdogNvmlSymbolProvider for DynamicNvmlSymbolProvider {
    // Checks one NUL-free symbol name against the retained library handle.
    fn has_symbol(&self, name: &str) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        // SAFETY: name is NUL-terminated and the library handle remains live.
        !unsafe { libc::dlsym(self.library, name.as_ptr()) }.is_null()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NvmlUtilization {
    gpu: c_uint,
    memory: c_uint,
}

// Samples one optional engine percentage and ignores the driver-owned sampling interval.
fn sample_engine(function: EngineFn, device: *mut c_void) -> Option<u8> {
    let mut utilization = 0;
    let mut sampling_period = 0;
    // SAFETY: both outputs are writable and function has the exact resolved engine ABI.
    (unsafe { function(device, &mut utilization, &mut sampling_period) } == WATCHDOG_NVML_SUCCESS
        && utilization <= 100)
        .then_some(utilization as u8)
}

// Samples one optional selector-based unsigned value.
fn sample_u32(function: U32Fn, device: *mut c_void, selector: u32) -> Option<u32> {
    let mut value = 0;
    // SAFETY: value is writable and function has the exact selector ABI.
    (unsafe { function(device, selector, &mut value) } == WATCHDOG_NVML_SUCCESS).then_some(value)
}

// Samples one optional simple unsigned value.
fn sample_simple_u32(function: SimpleU32Fn, device: *mut c_void) -> Option<u32> {
    let mut value = 0;
    // SAFETY: value is writable and function has the exact simple-value ABI.
    (unsafe { function(device, &mut value) } == WATCHDOG_NVML_SUCCESS).then_some(value)
}

// Samples one optional unsigned 64-bit value.
fn sample_u64(function: U64Fn, device: *mut c_void) -> Option<u64> {
    let mut value = 0;
    // SAFETY: value is writable and function has the exact 64-bit-value ABI.
    (unsafe { function(device, &mut value) } == WATCHDOG_NVML_SUCCESS).then_some(value)
}

// Retains the maximum of independently optional device values.
fn retain_max<T: Ord + Copy>(aggregate: &mut Option<T>, value: Option<T>) {
    if let Some(value) = value {
        *aggregate = Some(aggregate.map_or(value, |current| current.max(value)));
    }
}

// Resolves one required function pointer with its exact caller-selected ABI.
fn required_symbol<T: Copy>(library: *mut c_void, name: &'static [u8]) -> Result<T, WatchdogError> {
    optional_symbol(library, name)
        .ok_or_else(|| nvml_provider_error("required NVML symbol is unavailable"))
}

// Resolves one optional function pointer only when its size matches a native address.
fn optional_symbol<T: Copy>(library: *mut c_void, name: &'static [u8]) -> Option<T> {
    if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
        return None;
    }
    // SAFETY: name is a static NUL-terminated symbol and library remains loaded.
    let address = unsafe { libc::dlsym(library, name.as_ptr().cast()) };
    if address.is_null() {
        return None;
    }
    // SAFETY: the caller selects T for the exact named C ABI and sizes were checked.
    Some(unsafe { std::mem::transmute_copy(&address) })
}

// Validates NVIDIA's stable printable UUID identity without accepting control bytes.
fn valid_uuid(value: &str) -> bool {
    value.len() >= 16
        && value.len() < WATCHDOG_NVML_UUID_BUFFER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

// Creates one redacted NVML contract failure.
const fn nvml_error(reason: &'static str) -> WatchdogError {
    WatchdogError::InvalidContract { reason }
}

// Creates one redacted dynamic NVML provider failure.
const fn nvml_provider_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("NVML", reason)
}
