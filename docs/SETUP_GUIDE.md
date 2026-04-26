# Hướng dẫn Setup Môi trường — BridgeSentry

> Hướng dẫn chi tiết từng bước cho người mới bắt đầu.
> Viết cho máy Windows 10/11, không cần kinh nghiệm blockchain trước đó.

---

## Máy của bạn đang có gì

| Thành phần | Giá trị |
|------------|---------|
| CPU | Intel Core i5-13420H (8 cores, 12 threads) |
| RAM | 16 GB (2 × 8 GB) |
| Ổ cứng | 512 GB SSD |
| OS | Windows 10 Home |
| Python | 3.14.3 (đã cài) |
| Node.js | 22.22.0 (đã cài) |
| Docker | 29.2.1 (đã cài) |
| Git | 2.53.0 (đã cài) |
| Rust | **Chưa cài** |
| Foundry | **Chưa cài** |

### Laptop này chạy được không?

**Được, dư sức cho giai đoạn phát triển (Phase 0-4).** Cụ thể:

| Câu hỏi | Trả lời |
|---------|---------|
| Cần GPU không? | **KHÔNG.** Toàn bộ project này là CPU-bound. GPU chỉ cần nếu train model AI, nhưng mình dùng GPT-4o qua API (chạy trên server OpenAI). Sentence-transformers embedding cũng chạy CPU trong vài giây. |
| 16GB RAM đủ không? | **Đủ cho dev.** Dual-EVM fuzzer cần ~2-4GB. Phần còn lại cho Python + LLM API. Khi chạy full experiments (20 runs × 12 benchmarks) nên dùng server, nhưng dev + test thì laptop đủ. |
| SSD 512GB đủ không? | **Đủ.** Project code ~50MB. Fork blockchain state ~1-5GB mỗi benchmark. Cache tổng ~20-30GB. |
| Cần chạy trên Linux không? | **Không bắt buộc.** Dev trên Windows được. Tuy nhiên Foundry và Rust chạy mượt hơn trên WSL2 (Linux trong Windows). Hướng dẫn bên dưới sẽ cài qua WSL2. |

---

## Tổng quan: Cần cài những gì

```
┌─────────────────────────────────────────────────────┐
│                   MÁY CỦA BẠN                       │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  WSL2 (Ubuntu 22.04)                          │   │
│  │                                                │   │
│  │  ✅ Python 3.11 (tạo venv riêng)             │   │
│  │  ✅ Rust + Cargo (cho Module 3 fuzzer)        │   │
│  │  ✅ Foundry (anvil, forge, cast)              │   │
│  │  ✅ Project code (git clone)                  │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  Windows                                       │   │
│  │                                                │   │
│  │  ✅ VS Code + WSL extension                   │   │
│  │  ✅ Docker Desktop (đã có)                    │   │
│  │  ✅ Git (đã có)                               │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  Tài khoản Online (miễn phí)                  │   │
│  │                                                │   │
│  │  ✅ OpenAI API key ($5-10 credits)            │   │
│  │  ✅ Alchemy account (free tier)               │   │
│  │  ✅ Etherscan API key (free)                  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Tại sao dùng WSL2?

Python 3.14 trên Windows quá mới — nhiều thư viện chưa hỗ trợ (sentence-transformers, faiss). WSL2 cho bạn môi trường Linux chuẩn bên trong Windows, cài Python 3.11 ổn định, Rust và Foundry cũng hoạt động tốt hơn.

---

## BƯỚC 1: Cài WSL2 + Ubuntu

Mở **PowerShell (Run as Administrator)** và chạy:

```powershell
wsl --install -d Ubuntu-22.04
```

Sau khi restart máy, Ubuntu sẽ mở và yêu cầu tạo username/password.

```
Enter new UNIX username: <tên bạn muốn, ví dụ: bridgesentry>
New password: <mật khẩu, ví dụ: 123456>
```

Từ giờ, mọi thứ bên dưới đều chạy **trong terminal WSL2 Ubuntu**.

### Cập nhật Ubuntu

```bash
sudo apt update && sudo apt upgrade -y
```

### Cài các công cụ cơ bản

```bash
sudo apt install -y build-essential curl wget git unzip pkg-config libssl-dev
```

---

## BƯỚC 2: Cài Python 3.11 trong WSL2

Ubuntu 22.04 mặc định có Python 3.10. Ta cài thêm 3.11 (ổn định nhất cho project):

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev
```

Kiểm tra:
```bash
python3.11 --version
# Python 3.11.x
```

---

## BƯỚC 3: Cài Rust

Rust cần cho Module 3 (fuzzer viết bằng Rust). Chạy lệnh sau:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Khi hỏi, chọn **1) Proceed with standard installation**.

Sau khi cài xong:
```bash
source "$HOME/.cargo/env"
```

Kiểm tra:
```bash
rustc --version
# rustc 1.8x.x
cargo --version
# cargo 1.8x.x
```

---

## BƯỚC 4: Cài Foundry (anvil, forge, cast)

### Foundry là gì?

Foundry là bộ công cụ phát triển blockchain:
- **anvil**: chạy 1 blockchain giả lập trên máy bạn (như server blockchain mini)
- **forge**: biên dịch và test smart contract Solidity
- **cast**: gửi giao dịch, đọc dữ liệu từ blockchain

Trong project, ta dùng **anvil** để fork (sao chép) trạng thái blockchain thật (Ethereum) về máy tại 1 thời điểm cụ thể (ví dụ: 1 block trước vụ hack Nomad).

### Cài đặt

```bash
curl -L https://foundry.paradigm.xyz | bash
```

Đóng terminal, mở lại, rồi chạy:
```bash
foundryup
```

Kiểm tra:
```bash
anvil --version
forge --version
cast --version
```

---

## BƯỚC 5: Đăng ký Tài khoản Online

### 5.1. OpenAI API Key (BẮT BUỘC — dùng cho Module 1 + 2)

**OpenAI API là gì?** Là dịch vụ cho phép code của bạn gọi GPT-4o để phân tích code Solidity, sinh kịch bản tấn công. Mỗi lần gọi tốn ~$0.01-0.15.

1. Truy cập https://platform.openai.com/signup
2. Đăng ký tài khoản (dùng Google/email)
3. Vào https://platform.openai.com/api-keys → **Create new secret key**
4. Copy key (dạng `sk-proj-...`). **Lưu lại, không chia sẻ.**
5. Vào **Settings → Billing** → nạp $5-10 (Visa/Mastercard)

**Chi phí thực tế:**
- Dev + test: ~$5 (dùng gpt-4o-mini $0.15/1M input tokens)
- Full experiments: ~$50 (dùng gpt-4o $2.50/1M input tokens)
- Tổng project: ~$50-100

### 5.2. Alchemy Account (BẮT BUỘC — dùng để fork blockchain)

**Alchemy là gì?** Là dịch vụ cho phép bạn "nối" vào blockchain Ethereum thật để đọc dữ liệu. Khi fork blockchain, anvil sẽ gọi Alchemy để tải trạng thái (số dư, contract code) về máy.

1. Truy cập https://www.alchemy.com/ → Sign Up (miễn phí)
2. Create App:
   - Name: `BridgeSentry`
   - Chain: `Ethereum`
   - Network: `Mainnet`
3. Vào app → **API Key** → copy HTTPS URL
   - Dạng: `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY`
4. Gói miễn phí cho **300 triệu compute units/tháng** — đủ dùng

### 5.3. Etherscan API Key (NÊN CÓ — dùng lấy source code contract)

**Etherscan là gì?** Là website hiển thị mọi giao dịch, contract trên Ethereum. API cho phép code tự động tải source code contract đã được verify.

1. Truy cập https://etherscan.io/register → đăng ký
2. Vào https://etherscan.io/myapikey → **Add** → tạo key
3. Copy key. Gói miễn phí cho 5 calls/giây — đủ dùng

---

## BƯỚC 6: Clone Project + Setup Môi trường

### 6.1. Clone repo

```bash
cd ~
git clone https://github.com/Sukemcute/CrossLLM.git
cd CrossLLM
```

### 6.2. Tạo file .env

```bash
cp .env.example .env
nano .env
```

Điền các key đã đăng ký:
```
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx
OPENAI_MODEL=gpt-4o-mini

ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY
BSC_RPC_URL=https://bsc-dataseed.binance.org/

ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY

FUZZER_TIME_BUDGET=600
FUZZER_RUNS=5
RAG_TOP_K=5
WAYPOINT_BETA=0.4
```

Lưu file: `Ctrl+O`, `Enter`, `Ctrl+X`.

> **Dùng `gpt-4o-mini` khi dev** (rẻ 10x). Đổi sang `gpt-4o` chỉ khi chạy experiments cuối.

### 6.3. Setup Python virtual environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest jsonschema scipy
```

Kiểm tra:
```bash
python -c "import openai; print('OpenAI OK')"
python -c "import faiss; print('FAISS OK')"
python -c "import networkx; print('NetworkX OK')"
python -c "from sentence_transformers import SentenceTransformer; print('SentenceTransformers OK')"
```

> Nếu `sentence-transformers` lỗi, thử: `pip install sentence-transformers --no-deps` rồi cài từng dependency.

### 6.4. Build Rust fuzzer

```bash
cd src/module3_fuzzing
cargo check
```

Lần đầu sẽ tải dependencies, mất 2-5 phút. Nếu thành công → `Finished ...` không có error.

> **Nếu revm version lỗi:** Xem phần Xử lý Sự cố bên dưới.

Quay lại thư mục gốc:
```bash
cd ~/CrossLLM
```

---

## BƯỚC 7: Kiểm tra Mọi thứ Hoạt động

### 7.1. Test OpenAI API

```bash
python -c "
from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

response = client.chat.completions.create(
    model='gpt-4o-mini',
    messages=[{'role': 'user', 'content': 'Say hello in Vietnamese'}],
    max_tokens=50
)
print('API hoạt động:', response.choices[0].message.content)
"
```

Kết quả mong đợi: `API hoạt động: Xin chào!` (hoặc tương tự)

### 7.2. Test Alchemy RPC (kết nối blockchain)

```bash
python -c "
from web3 import Web3
from dotenv import load_dotenv
import os

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ETH_RPC_URL')))
print('Kết nối Ethereum:', w3.is_connected())
print('Block mới nhất:', w3.eth.block_number)
print('Balance Vitalik:', w3.eth.get_balance('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045') / 1e18, 'ETH')
"
```

Kết quả mong đợi:
```
Kết nối Ethereum: True
Block mới nhất: 1XXXXXXX
Balance Vitalik: XXX.XX ETH
```

### 7.3. Test Anvil (fork blockchain)

Mở 1 terminal mới trong WSL:
```bash
# Fork Ethereum tại block trước vụ hack Nomad (Aug 2022)
anvil --fork-url $ETH_RPC_URL --fork-block-number 15259100 --port 8545
```

Mở terminal khác:
```bash
# Kiểm tra block number trên fork
cast block-number --rpc-url http://localhost:8545
# Kết quả mong đợi: 15259100

# Đọc balance Nomad Replica contract tại thời điểm trước hack
cast balance 0xB92336759618F55bd0F8313bd843604592E27bd8 --rpc-url http://localhost:8545
# Kết quả: một số lớn (Wei)
```

Tắt anvil: `Ctrl+C` ở terminal đầu tiên.

> **Đây chính là cách BridgeSentry hoạt động:** fork blockchain về thời điểm trước vụ hack, rồi thử các kịch bản tấn công để xem bridge có bị khai thác không.

### 7.4. Test Rust build

```bash
cd ~/CrossLLM/src/module3_fuzzing
cargo build --release 2>&1 | tail -5
```

Nếu thành công: `Finished release [optimized] target(s) in Xs`

### 7.5. Chạy unit tests hiện có

```bash
cd ~/CrossLLM
python -m pytest tests/ -v
```

---

## BƯỚC 8: Kết nối VS Code với WSL2

Để code thoải mái trong VS Code trên Windows nhưng chạy trên WSL2:

1. Mở VS Code trên Windows
2. Cài extension: **WSL** (by Microsoft)
3. Nhấn `Ctrl+Shift+P` → gõ `WSL: Connect to WSL`
4. Chọn `Ubuntu-22.04`
5. Mở thư mục: `File → Open Folder → /home/<username>/CrossLLM/`
6. Cài thêm extensions trong WSL:
   - **Python** (Microsoft)
   - **rust-analyzer** (cho Rust)
   - **Even Better TOML** (cho Cargo.toml)

Giờ bạn code trong VS Code trên Windows, nhưng terminal chạy trên Linux. Tất cả `python`, `cargo`, `anvil` đều hoạt động.

---

## Giải thích Các Khái niệm Blockchain cho Người Mới

### Smart Contract là gì?
Là chương trình chạy trên blockchain, viết bằng **Solidity** (giống JavaScript). Khi deploy, nó sống trên blockchain mãi mãi. Ai cũng có thể gọi các hàm của nó bằng cách gửi giao dịch.

### Bridge hoạt động như thế nào?
```
Chain A (Ethereum)              Chain B (BSC)
     |                               |
User gửi 100 USDC                   |
     |                               |
     ▼                               |
Lock.sol khóa 100 USDC              |
     |                               |
     |--- Relayer truyền proof --->  |
     |                               ▼
     |                          Mint.sol đúc 100 USDC
     |                               |
     |                          User nhận 100 USDC trên BSC
```

Lỗi xảy ra khi: proof giả, proof dùng lại, mint mà không lock, v.v.

### Fork blockchain là gì?
"Chụp ảnh" toàn bộ trạng thái blockchain (hàng triệu tài khoản, contract) tại 1 block cụ thể, rồi chạy bản sao trên máy bạn. Bạn có thể thử bất kỳ giao dịch nào mà không ảnh hưởng blockchain thật.

### EVM là gì?
**Ethereum Virtual Machine** — máy ảo chạy smart contract. Mỗi blockchain tương thích EVM (Ethereum, BSC, Polygon...) đều dùng cùng loại máy ảo này. **revm** là bản Rust của EVM, chạy rất nhanh. Project dùng 2 revm instances song song = **Dual-EVM**.

### Fuzzing là gì?
Tự động sinh hàng triệu đầu vào ngẫu nhiên/thông minh rồi gửi vào chương trình để tìm lỗi. Trong project: sinh hàng triệu chuỗi giao dịch rồi gửi vào bridge xem có vi phạm bất biến không.

### ATG (Atomic Transfer Graph) là gì?
Đồ thị mô tả luồng tiền trong bridge:
- **Nút** = tài khoản, contract, relay
- **Cạnh** = chuyển tiền/thông điệp + điều kiện (timelock, hashlock, signature...)

LLM đọc code Solidity → sinh ra đồ thị này → fuzzer dùng để biết nên tấn công chỗ nào.

### RAG là gì?
**Retrieval-Augmented Generation**: thay vì để LLM bịa, ta cho nó tra cứu database kiến thức (51 vụ hack bridge đã xảy ra) trước khi sinh câu trả lời. Kết quả chính xác hơn nhiều.

---

## Luồng Chạy Project — Từ Đầu Đến Cuối

```
Bạn có: source code của 1 bridge (Lock.sol + Mint.sol + Relayer)

Bước 1 — Module 1 (Python, gọi GPT-4o):
    Code bridge ──→ [LLM phân tích] ──→ atg.json (đồ thị + bất biến)

Bước 2 — Module 2 (Python, gọi GPT-4o + FAISS):
    atg.json + 51 vụ hack ──→ [RAG + LLM] ──→ hypotheses.json (kịch bản tấn công)

Bước 3 — Module 3 (Rust, chạy trên CPU):
    hypotheses.json + bytecode ──→ [Dual-EVM Fuzzer] ──→ results.json (lỗ hổng tìm được)

Bước 4 — Output:
    results.json ──→ Báo cáo: lỗ hổng nào, thời gian tìm, trace chi tiết
```

**Không cần GPU ở bất kỳ bước nào.** Module 1+2 gọi API (chạy trên server OpenAI). Module 3 chạy CPU thuần trên máy bạn.

---

## Xử lý Sự cố Thường Gặp

### Lỗi: `pip install faiss-cpu` thất bại

```bash
# Thử cài bản pre-built
pip install faiss-cpu --only-binary=:all:

# Nếu vẫn lỗi, cài từ conda-forge
pip install conda-forge::faiss-cpu
```

### Lỗi: `cargo check` báo revm version không tồn tại

Revm thay đổi version thường xuyên. Sửa `Cargo.toml`:

```bash
cd ~/CrossLLM/src/module3_fuzzing

# Tìm version mới nhất
cargo search revm

# Sửa Cargo.toml nếu cần (thay "20" bằng version có sẵn)
# Ví dụ: revm = { version = "17", features = ["std", "serde"] }
```

### Lỗi: Anvil fork quá chậm hoặc timeout

```bash
# Thêm retry và timeout
anvil --fork-url $ETH_RPC_URL \
      --fork-block-number 15259100 \
      --fork-retry-backoff 5 \
      --timeout 120000 \
      --port 8545
```

Nếu vẫn chậm: Alchemy free tier có thể bị throttle. Chờ vài phút rồi thử lại, hoặc dùng giờ ít traffic (sáng sớm VN = đêm Mỹ).

### Lỗi: `sentence-transformers` không cài được

```bash
# Cài PyTorch CPU trước
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Rồi cài sentence-transformers
pip install sentence-transformers
```

### Slither parser fail với "No such file or directory: 'solc'"

Slither cần binary `solc` để compile contract. Cài qua `solc-select` (đã trong `requirements.txt`):

```bash
cd ~/CrossLLM
source .crossllm/bin/activate
solc-select install 0.8.20
solc-select use 0.8.20
solc --version  # Phải báo: solc 0.8.20+commit...
```

Sau đó chạy lại Module 1 với venv **đã activate** (cần PATH có `solc`).

### Lỗi: WSL2 hết dung lượng

```bash
# Kiểm tra
df -h /

# Dọn cache
sudo apt clean
pip cache purge
cargo clean  # trong thư mục module3_fuzzing
```

### Lỗi: OpenAI API trả về "insufficient_quota"

Vào https://platform.openai.com/settings/organization/billing → nạp thêm tiền. Cần ít nhất $5.

---

## Bảng Tóm tắt Nhanh

| Việc cần làm | Lệnh | Khi nào |
|---|---|---|
| Kích hoạt venv Python | `source ~/CrossLLM/.venv/bin/activate` | Mỗi khi mở terminal mới |
| Chạy unit tests | `cd ~/CrossLLM && python -m pytest tests/ -v` | Sau khi thay đổi code |
| Build Rust fuzzer | `cd ~/CrossLLM/src/module3_fuzzing && cargo build --release` | Sau khi sửa file .rs |
| Fork Ethereum tại block X | `anvil --fork-url $ETH_RPC_URL --fork-block-number X` | Khi cần test trên state blockchain thật |
| Chạy pipeline demo | `python src/orchestrator.py --benchmark benchmarks/nomad/ --time-budget 60 --runs 1 --output results/test/` | Sau khi tích hợp xong (Phase 3) |
| Xem trạng thái git | `git status` | Trước khi commit |
| Push code | `git add . && git commit -m "mô tả" && git push` | Sau khi hoàn thành 1 task |

---

## Bước Tiếp Theo

Sau khi setup xong, bắt đầu **Phase 0** (Tuần 1) theo [PLAN_IMPLEMENTATION.md](PLAN_IMPLEMENTATION.md):

1. Cả hai cùng review JSON schemas trong `schemas/`
2. Tạo benchmark Nomad hoàn chỉnh (`benchmarks/nomad/`)
3. Member A: bắt đầu `extractor.py`
4. Member B: thử revm proof-of-concept trong `dual_evm.rs`
