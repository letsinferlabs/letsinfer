# Third-party notices

## llama.cpp

Pinned source: `ggml-org/llama.cpp` commit
`c1d0e7a004015f23bc0233470b747b596f29b264`, release `b10621`.

MIT License

Copyright (c) 2023-2026 The ggml authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Qwen3 0.6B GGUF

The app downloads `Qwen/Qwen3-0.6B-GGUF` revision
`23749fefcc72300e3a2ad315e1317431b06b590a`. The repository declares
Apache-2.0. Its canonical license is
<https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/blob/23749fefcc72300e3a2ad315e1317431b06b590a/LICENSE>.

## MLC LLM and Qwen3 MLC

The optional build uses `mlc-ai/mlc-llm` commit
`9fa644f54b04983adea4d0168f49fc6af4a893ba`, including its commit-pinned TVM
and tokenizer submodules. MLC LLM is Apache-2.0 licensed; dependency notices
from the generated static libraries must accompany a distributed MLC build.

The optional model download is
`mlc-ai/Qwen3-0.6B-q4f16_1-MLC` revision
`8c14ce481d4c692769976ad52afea453a102df19`. Its model repository license and
notices apply.
