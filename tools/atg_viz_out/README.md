# ATG visualizations

Mở `index.html` bằng trình duyệt để xem đồ thị tương tác (kéo-thả, zoom, hover
vào cạnh để xem guard). Sinh lại bằng: `python tools/atg_viz.py`.

## Chú giải node
| Node | Nghĩa |
|---|---|
| Tên hợp đồng thật (`GemPadLocker`, `QBridgeETH`…) | entity/contract của bridge |
| `MockToken`, `MockMultisig` | **harness contract** — token/validator-set tái dựng để chạy offline. Với gempad/fegtoken, hành vi token harness chính là vector tấn công nên được **giữ lại có chủ đích** (không lọc). |
| `User` | gom từ `msg.sender`/`from`/`sender`/`caller` (bên gọi) |
| `Recipient` | gom từ `to`/`recipient`/`receiver` (bên nhận) |
| `ZeroAddress` | `0x0`/`address(0)` — nguồn `mint`, đích `burn` |

Chi tiết đầy đủ (vì sao harness lọt vào ATG, cách chuẩn hóa node): xem
[`docs/BENCHMARK_TEST_GUIDE.md`](../../docs/BENCHMARK_TEST_GUIDE.md) →
mục *"Harness contracts trong ATG"*.

> Lưu ý: đồ thị được chuẩn hóa lúc hiển thị (`normalize_atg_dict`) — dedup node
> + gom actor. File canonical `benchmarks/<bridge>/llm_outputs/atg.json` cũng đã
> được pipeline sinh ở dạng chuẩn hóa.
