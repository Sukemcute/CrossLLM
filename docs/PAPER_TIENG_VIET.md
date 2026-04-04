# BridgeSentry: Phát hiện Lỗ hổng trong Cầu nối Liên chuỗi được Dẫn hướng bởi LLM thông qua Mô hình hóa Ngữ nghĩa và Fuzzing Đa chuỗi Đồng bộ

> Bản dịch tiếng Việt từ `latex/paper.tex` (định dạng IEEE)

---

## Tóm tắt (Abstract)

Cầu nối liên chuỗi (cross-chain bridge) đã trở thành hạ tầng quan trọng trong hệ sinh thái blockchain đa chuỗi, tuy nhiên chúng vẫn là nguồn tổn thất tài chính lớn nhất trong tài chính phi tập trung. Tổng thiệt hại tích lũy từ các vụ khai thác cầu nối liên chuỗi đã đạt gần **4,3 tỷ USD** kể từ năm 2021, bắt nguồn từ các lỗ hổng trải dài trên nhiều blockchain và các thành phần relay ngoài chuỗi. Các công cụ bảo mật hiện có chỉ giải quyết vấn đề này một phần: công cụ phân tích tĩnh phát hiện lỗ hổng hợp đồng đơn lẻ, fuzzer đơn chuỗi khám phá không gian trạng thái on-chain, và các framework dựa trên đồ thị phân loại giao dịch tấn công sau khi khai thác đã xảy ra. Không có công cụ nào trong số này chủ động phát hiện lỗ hổng logic phát sinh từ sự không nhất quán trạng thái liên chuỗi.

Bài báo này trình bày **BridgeSentry**, một framework kết hợp suy luận mô hình ngôn ngữ lớn (LLM) với fuzzing đa chuỗi đồng bộ để phát hiện lỗ hổng cầu nối liên chuỗi trước khi chúng bị khai thác. BridgeSentry hoạt động qua ba giai đoạn:

1. **Trích xuất ngữ nghĩa dựa trên LLM** phân tích mã nguồn hợp đồng thông minh của bridge và xây dựng Đồ thị Chuyển đổi Nguyên tử (Atomic Transfer Graph - ATG), theo mô hình hình thức của Dübler và cộng sự, để nắm bắt các bất biến giao thức dự kiến trên chuỗi nguồn và chuỗi đích.
2. **Module sinh kịch bản tấn công tăng cường truy xuất (RAG)**, được nạp tri thức có cấu trúc từ 51 vụ khai thác liên chuỗi đã được ghi nhận, sinh ra các kịch bản tấn công hợp lý phản ánh động cơ đối kháng hợp lý.
3. **Công cụ fuzzing đa chuỗi đồng bộ (dual-EVM)** thực thi các kịch bản này trên các instance blockchain ghép cặp với quản lý snapshot nhất quán, sử dụng các điểm mốc ngữ nghĩa (semantic waypoints) để dẫn hướng khám phá tới các vi phạm bất biến liên chuỗi.

Thực nghiệm trên bộ benchmark gồm 12 vụ khai thác cầu nối liên chuỗi thực tế được tái dựng, bao gồm Wormhole, Nomad, PolyNetwork và 9 sự cố khác, cho thấy BridgeSentry phát hiện **11 trên 12 lỗ hổng mục tiêu** với thời gian khai thác trung vị là **47 giây** và độ lệch chuẩn 18 giây qua 5 lần chạy. Kết quả này vượt trội so với ItyFuzz, SmartAxe, GPTScan và XScope, mỗi công cụ phát hiện tối đa 5 trên 12 lỗ hổng. Nghiên cứu loại bỏ thành phần (ablation study) xác nhận rằng mỗi module đóng góp có thể đo lường được vào khả năng phát hiện tổng thể, trong đó quản lý trạng thái đa chuỗi đồng bộ đóng góp cá nhân lớn nhất.

**Từ khóa:** Cầu nối liên chuỗi, phát hiện lỗ hổng, fuzzing hợp đồng thông minh, mô hình ngôn ngữ lớn, bảo mật blockchain

---

## 1. Giới thiệu (Introduction)

Sự mở rộng của công nghệ blockchain vượt ra ngoài kiến trúc đơn chuỗi đã tạo ra một hệ sinh thái đa chuỗi, trong đó các ứng dụng tài chính phi tập trung (DeFi) hoạt động trên các mạng không đồng nhất như Ethereum, Binance Smart Chain và Solana [1, 2]. Cầu nối liên chuỗi đóng vai trò là hạ tầng chính cho phép chuyển tài sản và truyền thông điệp giữa các mạng này. Bằng cách khóa token trên chuỗi nguồn và đúc các đại diện tương đương trên chuỗi đích, cầu nối cho phép người dùng di chuyển giá trị qua các sổ cái vốn bị cô lập.

Tuy nhiên, cầu nối cũng trở thành mục tiêu sinh lợi nhất cho kẻ tấn công. Theo Wu và cộng sự [4], tổng thiệt hại tích lũy từ các vụ khai thác cầu nối liên chuỗi đã đạt gần **4,3 tỷ USD** kể từ năm 2021, với Ronin Network ở mức 624 triệu USD, PolyNetwork ở mức 611 triệu USD, và Wormhole ở mức 326 triệu USD là những sự cố tốn kém nhất [2, 3]. Các cuộc tấn công này khai thác nhiều loại lỗ hổng khác nhau: bỏ qua kiểm soát truy cập trong hợp đồng validator, khởi tạo không đúng logic xác minh, sự kiện gửi tiền giả được relay ngoài chuỗi chấp nhận, và các điều kiện reentrancy được kích hoạt thông qua chuỗi callback liên chuỗi [7, 18].

Các công cụ bảo mật hiện có giải quyết các mối đe dọa cầu nối liên chuỗi từ các góc độ bổ sung nhưng riêng lẻ chưa đủ:

- **Phân tích tĩnh** như SmartAxe [3] phát hiện các mẫu lỗ hổng đặc thù liên chuỗi trong mã nguồn hợp đồng thông minh, nhưng không thể suy luận về các chuyển đổi trạng thái runtime trải dài trên hai hoặc nhiều blockchain.
- **Giám sát dựa trên quy tắc** như XScope [6] nhận diện các chữ ký tấn công được định nghĩa trước trong nhật ký giao dịch, nhưng sự phụ thuộc vào các quy tắc đặc thù giao thức hạn chế khả năng tổng quát hóa cho các thiết kế bridge mới.
- **Framework dựa trên đồ thị** hoạt động trên dữ liệu giao dịch quan sát được thay vì là công cụ phát hiện lỗ hổng chủ động. BridgeGuard [4] mô hình hóa dấu vết thực thi giao dịch dưới dạng đồ thị. BridgeShield [5] xây dựng đồ thị hành vi liên chuỗi không đồng nhất. Zhou và cộng sự [7] sử dụng phân tích dataflow symbolic.
- **Fuzzer đơn chuỗi** như ItyFuzz [8] và SmartShot [24] khám phá không gian trạng thái hợp đồng thông minh hiệu quả thông qua kỹ thuật dựa trên snapshot, nhưng không thể mô hình hóa các chuyển đổi trạng thái ghép cặp và phối hợp relay vốn có trong giao thức liên chuỗi.
- **Công cụ hỗ trợ LLM** như GPTScan [9] và hệ thống đa tác tử của Wei và cộng sự [10] kết hợp suy luận mô hình ngôn ngữ với phân tích tĩnh hoặc đa bước để nhận diện lỗ hổng logic, nhưng chúng nhắm vào hợp đồng đơn lẻ và không nắm bắt được ngữ nghĩa liên chuỗi.

Mặc dù các công cụ này cùng thúc đẩy bảo mật liên chuỗi, một khoảng trống năng lực vẫn tồn tại: **không có công cụ hiện tại nào thực hiện phát hiện lỗ hổng chủ động cho cầu nối liên chuỗi bằng cách đồng thời suy luận về ý định ngữ nghĩa của giao thức bridge trên nhiều chuỗi và kiểm thử động cho các vi phạm bất biến trong môi trường thực thi đa chuỗi đồng bộ.**

Bài báo này giải quyết khoảng trống này bằng cách đề xuất **BridgeSentry**, một framework tích hợp ba module phối hợp:

1. **Bộ trích xuất ngữ nghĩa** sử dụng LLM để phân tích mã nguồn hợp đồng thông minh của bridge và logic relay ngoài chuỗi, tạo ra Đồ thị Chuyển đổi Nguyên tử (ATG) [27] được chú thích với các bất biến cấp giao thức bao gồm bảo toàn tài sản, thứ tự sự kiện, và các phụ thuộc ủy quyền trên chuỗi nguồn, relay và chuỗi đích.
2. **Bộ sinh kịch bản tấn công tăng cường truy xuất** truy vấn cơ sở tri thức có cấu trúc của 51 vụ khai thác liên chuỗi đã ghi nhận [4, 2] để sinh ra các chuỗi tấn công có động cơ kinh tế hợp lý nhắm vào các bất biến đã xác định.
3. **Công cụ fuzzing đa chuỗi đồng bộ** duy trì các instance EVM ghép cặp được kết nối qua mock relay, thực thi các kịch bản tấn công đã sinh dưới dạng seed được dẫn hướng, và sử dụng các điểm mốc ngữ nghĩa để lái fuzzer tới các trạng thái mà bất biến liên chuỗi có khả năng bị vi phạm.

### Các đóng góp chính

- Đề xuất framework kết hợp hiểu biết giao thức dựa trên LLM với kiểm thử động đa chuỗi đồng bộ cho phát hiện lỗ hổng cầu nối liên chuỗi chủ động.
- Điều chỉnh hình thức ATG của Dübler và cộng sự [27] cho bối cảnh fuzzing cầu nối liên chuỗi bằng cách định nghĩa bốn loại bất biến đặc thù miền và biên dịch chúng thành các assertion thực thi được.
- Thiết kế cơ chế snapshot đồng bộ cho quản lý trạng thái nhất quán trên hai instance EVM và mock relay.
- Đánh giá BridgeSentry trên 12 vụ khai thác thực tế được tái dựng, báo cáo cải thiện tỷ lệ phát hiện lỗ hổng so với bốn baseline.

---

## 2. Công trình liên quan (Related Work)

### 2.1. Phân tích Bảo mật Cầu nối Liên chuỗi

Bức tranh bảo mật của cầu nối liên chuỗi đã được khảo sát rộng rãi. Augusto và cộng sự [2] cung cấp hệ thống hóa tri thức bao gồm các giao thức tương tác, phân loại các lớp lỗ hổng và vector rò rỉ quyền riêng tư trên 34 hệ thống liên chuỗi. Duan và cộng sự [18] phân loại các vector tấn công và ánh xạ cơ chế phòng thủ theo tầng giao thức. Li và cộng sự [25] xem xét thách thức và hướng đi tương lai đặc thù cho bảo mật bridge.

Về phát hiện:

- **XScope** [6] định nghĩa ba loại thuộc tính bảo mật cầu nối và xây dựng công cụ phát hiện dựa trên quy tắc hoạt động trên nhật ký sự kiện giao dịch. Hiệu quả với các mẫu tấn công đã biết trên chuỗi tương thích EVM, nhưng khả năng phát hiện suy giảm khi nhật ký không có sẵn hoặc mẫu tấn công tiến hóa.
- **SmartAxe** [3] giới thiệu phân tích tĩnh chi tiết dành riêng cho lỗ hổng liên chuỗi (CCV), xây dựng đồ thị luồng dữ liệu liên chuỗi và quy tắc lan truyền taint để phát hiện các vấn đề như đúc tiền trái phép và xác nhận trạng thái không nhất quán. SmartAxe báo cáo phát hiện 88 CCV từ các cuộc tấn công thực tế nhưng bị hạn chế bản chất ở các lỗ hổng phát hiện được thông qua phân tích mã nguồn đơn thuần.
- **BridgeGuard** [4] tiên phong phát hiện giao dịch tấn công liên chuỗi dựa trên đồ thị bằng khai thác đồ thị toàn cục và cục bộ.
- **BridgeShield** [5] mở rộng bằng đồ thị hành vi liên chuỗi không đồng nhất (xBHG), đạt F1-score 92,58% trên 51 sự kiện tấn công thực tế.
- **Zhou và cộng sự** [7] đề xuất framework phân tích dataflow symbolic cho phát hiện lỗ hổng tương tác bên ngoài trong hợp đồng router bridge.
- **Connector** [20] của Lin và cộng sự phát triển công cụ tự động liên kết giao dịch liên chuỗi để hỗ trợ truy vết và phân tích pháp lý.

Các công trình này chứng minh giá trị của mô hình hóa đa chuỗi, nhưng tất cả hoạt động như bộ phân loại hậu kiểm trên dữ liệu giao dịch quan sát được thay vì công cụ phát hiện lỗ hổng chủ động.

### 2.2. Fuzzing Hợp đồng Thông minh

Fuzzing đã nổi lên như kỹ thuật chính để phát hiện lỗ hổng trong hợp đồng thông minh:

- **ItyFuzz** [8] giới thiệu quản lý trạng thái dựa trên snapshot để tránh thực thi lại chuỗi giao dịch dài, đạt được khám phá trạng thái nhanh chóng, phát hiện lỗ hổng thực tế bao gồm vụ hack Nomad bridge trong khung thời gian dưới 1 giây.
- **VulSEye** [13] đề xuất fuzzing graybox có hướng stateful kết hợp phân tích tĩnh cho xác định mục tiêu với thực thi động cho khả năng tiếp cận.
- **Midas** [14] mở rộng fuzzing để khám phá khai thác sinh lời bằng kết hợp khám phá phản hồi với phân tích vi phân so với triển khai tham chiếu.
- **Verite** của Kong và cộng sự [15] dẫn hướng fuzzing tới các mẫu lỗ hổng sinh lời sử dụng tối đa hóa lợi nhuận dựa trên gradient descent.
- **SmartShot** [24] giới thiệu snapshot có thể biến đổi cho phép fuzzer biến đổi trạng thái đã chụp, mở rộng không gian trạng thái đạt được, đạt tốc độ nhanh hơn 20,2 lần so với các phương pháp snapshot trước đó.
- **Chen và cộng sự** [23] chứng minh fuzzing hợp đồng thông minh tăng tốc GPU.
- **Qin và cộng sự** [16] đề xuất Đồ thị Thuộc tính Thực thi (EPG) như biểu diễn thống nhất tích hợp nhiều góc nhìn phân tích tĩnh.

Mặc dù có những tiến bộ này, **tất cả các fuzzer hiện có đều hoạt động trên một instance blockchain đơn lẻ** và không thể mô hình hóa tự nhiên các chuyển đổi trạng thái ghép cặp và giao tiếp relay định nghĩa ngữ nghĩa thực thi cầu nối liên chuỗi.

### 2.3. Phát hiện Lỗ hổng Hỗ trợ LLM

- **GPTScan** [9] chứng minh rằng kết hợp suy luận ngữ nghĩa GPT với xác nhận phân tích tĩnh có thể phát hiện lỗ hổng logic mà công cụ cú pháp thuần túy bỏ sót, phát hiện 9 lỗ hổng chưa biết trước đó trong các hợp đồng đã kiểm toán.
- **Wei và cộng sự** [10] đề xuất hệ thống LLM đa tác tử cho phát hiện lỗ hổng end-to-end.
- **Ali và cộng sự** [28] kết hợp hướng dẫn LLM thích ứng runtime với fuzzing liên hợp đồng trong thiết lập đơn chuỗi.

BridgeSentry chia sẻ nguyên tắc sử dụng suy luận LLM để dẫn hướng fuzzing nhưng khác biệt ở ba điểm: (1) hoạt động trên hai instance blockchain đồng bộ thay vì đơn chuỗi; (2) sử dụng LLM ở giai đoạn tiền xử lý để xây dựng ATG và sinh kịch bản tấn công thay vì vòng phản hồi runtime; (3) nhắm vào vi phạm bất biến liên chuỗi phát sinh từ sự không nhất quán trạng thái giữa các chuỗi.

### 2.4. Đồ thị Chuyển đổi Nguyên tử (ATG)

Hình thức ATG được giới thiệu bởi Dübler và cộng sự [27] như framework thiết kế giao thức liên chuỗi an toàn theo thiết kế trên hệ sinh thái blockchain không đồng nhất. BridgeSentry áp dụng ATG trong ngữ cảnh khác: thay vì sử dụng ATG để thiết kế giao thức mới, chúng tôi sử dụng chúng để **mô hình hóa các triển khai bridge hiện có và suy ra các bất biến kiểm thử được** cho phát hiện lỗ hổng động.

---

## 3. Phát biểu Bài toán (Problem Formulation)

### 3.1. Mô hình Thực thi Cầu nối Liên chuỗi

Giao thức cầu nối liên chuỗi B hoạt động trên ba miền thực thi: chuỗi nguồn C_S, chuỗi đích C_D, và thành phần relay ngoài chuỗi R. Một chuyển giao liên chuỗi hoàn chỉnh diễn ra qua các giai đoạn:

1. Người dùng u gọi hàm deposit trên hợp đồng router chuỗi nguồn RC_S, khóa tài sản giá trị v và phát sự kiện deposit e_dep.
2. Relay R quan sát e_dep, xác thực tính xác thực và truyền thông điệp đã xác minh m tới chuỗi đích.
3. Hợp đồng router chuỗi đích RC_D nhận m, xác minh theo quy tắc giao thức, và gọi hợp đồng token TC_D để đúc hoặc giải phóng tài sản tương đương giá trị v cho người nhận.

### 3.2. Đồ thị Chuyển đổi Nguyên tử (ATG)

Chúng tôi mô hình hóa giao thức bridge sử dụng hình thức ATG, được điều chỉnh cho bối cảnh phát hiện lỗ hổng bridge.

**Định nghĩa:** ATG là đồ thị có hướng gán nhãn G = (N, A, Λ, Φ) trong đó:

- **N = N_U ∪ N_C ∪ N_R** là tập nút đại diện tài khoản người dùng (N_U), hợp đồng thông minh (N_C), và thành phần relay (N_R);
- **A ⊆ N × N** là tập cung có hướng đại diện chuyển tài sản hoặc truyền thông điệp;
- **Λ: A → {lock, unlock, mint, burn, relay, verify}** là hàm gán nhãn cung;
- **Φ = {φ₁, φ₂, ..., φ_k}** là tập bất biến giao thức được định nghĩa trên trạng thái nút và điều kiện thực thi cung.

### 3.3. Các Bất biến Giao thức

Tập bất biến Φ nắm bắt các thuộc tính bảo mật quan trọng của bridge. Chúng tôi định nghĩa bốn loại:

**1. Bảo toàn Tài sản (Asset Conservation):**

Với mọi chuyển giao hoàn thành, tổng giá trị khóa trên C_S phải bằng tổng giá trị đúc trên C_D, trừ phí giao thức f:

```
Σ val(a_lock) - f = Σ val(a_mint)
```

Công thức này giả định f ≥ 0 có thể biểu diễn như hàm tất định của tham số chuyển giao tại thời điểm khóa. Với token có phí chuyển (fee-on-transfer) hoặc tài sản rebasing, f được mở rộng bao gồm chi phí chuyển cấp token δ_tok: f = f_protocol + δ_tok.

**2. Ủy quyền (Authorization):**

Mọi thao tác đúc trên C_D phải được đi trước bởi deposit hợp lệ và xác minh relay:

```
∀ a_m ∈ A_mint, ∃ a_l ∈ A_lock, a_r ∈ A_relay: a_l ≺ a_r ≺ a_m
```

trong đó ≺ biểu thị thứ tự nhân quả.

**3. Tính duy nhất (Uniqueness):**

Mỗi sự kiện deposit phải được tiêu thụ nhiều nhất một lần:

```
∀ e_i, e_j ∈ E_dep, i ≠ j ⟹ nonce(e_i) ≠ nonce(e_j)
```

**4. Tính kịp thời (Timeliness):**

Các thao tác khóa không hoàn thành trong cửa sổ timeout τ phải có thể hoàn tiền:

```
∀ a_l ∈ A_lock: (t_S_current - t_S(a_l) > τ_S) ⟹ refundable(a_l) = true
```

Công cụ fuzzing mô hình hóa độ trễ đồng hồ bằng cách tăng timestamp block độc lập trên mỗi instance EVM.

### 3.4. Mô hình Đe dọa (Threat Model)

Chúng tôi giả định kẻ tấn công hợp lý A có khả năng:

- Deploy và tương tác với hợp đồng thông minh tùy ý trên cả C_S và C_D, bao gồm hợp đồng token tùy chỉnh.
- Gửi giao dịch tới hợp đồng bridge với đầu vào được chế tạo.
- Quan sát tất cả sự kiện on-chain công khai và thông điệp relay.
- Khai thác sự khác biệt thời gian giữa các chuỗi, bao gồm độ trễ sản xuất block và bất đối xứng finality.

Kẻ tấn công **không thể** xâm phạm cơ chế đồng thuận của chuỗi nào hoặc phá vỡ các nguyên thủy mật mã. Mục tiêu là vi phạm một hoặc nhiều bất biến trong Φ để trích xuất giá trị trái phép.

### 3.5. Phát biểu Bài toán

Cho giao thức cầu nối liên chuỗi B với các hợp đồng thông minh và logic relay liên quan, nhiệm vụ là **tự động phát hiện các chuỗi giao dịch cụ thể vi phạm ít nhất một bất biến φ_i ∈ Φ**, từ đó chứng minh một lỗ hổng có thể khai thác.

---

## 4. Phương pháp luận (Methodology)

BridgeSentry gồm ba module hoạt động tuần tự: (1) trích xuất ngữ nghĩa dựa trên LLM, (2) sinh kịch bản tấn công tăng cường truy xuất, và (3) fuzzing đa chuỗi đồng bộ.

```
┌──────────────────────────────────────────────────────────────────┐
│  Module 1: Trích xuất Ngữ nghĩa                                  │
│  [Mã nguồn Bridge] → [LLM Semantic Extractor] → [ATG + Φ]       │
├──────────────────────────────────────────────────────────────────┤
│  Module 2: Sinh Kịch bản Tấn công                                │
│  [Cơ sở tri thức 51 vụ] → [RAG Generator] → [Kịch bản {S1..Sn}]│
├──────────────────────────────────────────────────────────────────┤
│  Module 3: Fuzzing Đa chuỗi Đồng bộ                             │
│  [EVM Chuỗi nguồn] ↔ [Mock Relay] ↔ [EVM Chuỗi đích] → [Checker]│
├──────────────────────────────────────────────────────────────────┤
│  Output: Báo cáo Lỗ hổng                                        │
└──────────────────────────────────────────────────────────────────┘
```

### 4.1. Module 1: Trích xuất Ngữ nghĩa dựa trên LLM

Module đầu tiên nhận đầu vào là mã nguồn hợp đồng thông minh bridge trên C_S và C_D, bao gồm hợp đồng router on-chain và hợp đồng token, cùng với triển khai relay ngoài chuỗi khi có sẵn. Đầu ra là ATG G cùng tập bất biến giao thức Φ.

#### 4.1.1. Phân tích Hợp đồng và Nhận diện Thực thể

Sử dụng chiến lược prompt có cấu trúc để dẫn hướng GPT-4o (phiên bản 2024-08-06, temperature 0.2, top-p 0.95) qua phân tích đa bước:

1. Nhận diện tất cả thực thể hợp đồng: router, token, governance, proxy, phụ thuộc bên ngoài.
2. Phân loại mỗi hàm public/external theo vai trò: deposit, withdrawal, xử lý relay, đúc token, đốt token, tạm dừng khẩn cấp, quản trị.
3. Trích xuất đường đi luồng tài sản: với mỗi hàm thay đổi trạng thái, theo dõi luồng số dư token, xác định nguồn và đích.
4. Nhận diện các guard điều kiện: modifier kiểm soát truy cập, kiểm tra xác minh chữ ký, xác thực nonce, điều kiện timelock, yêu cầu đa chữ ký.

Template prompt được cấu trúc để tạo output JSON tuân theo schema định nghĩa trước, cho phép phân tích tất định phản hồi LLM thành nút và cạnh đồ thị.

#### 4.1.2. Xây dựng ATG

Từ các thực thể và quan hệ đã trích xuất, xây dựng ATG G = (N, A, Λ, Φ). Mỗi hợp đồng hoặc tài khoản trở thành một nút. Mỗi chuyển tài sản, relay thông điệp, hoặc phụ thuộc trạng thái trở thành cung có hướng với nhãn phù hợp. Hình thức ATG gốc giả định giao thức thiết kế quanh Hợp đồng Timelock Có điều kiện (CTLC). Triển khai bridge thực tế hiếm khi dùng CTLC tường minh; thay vào đó dùng kết hợp ad hoc timelock, kiểm tra đa chữ ký, và ủy quyền proxy. Bộ trích xuất LLM ánh xạ các mẫu triển khai này sang nhãn cung ATG tương ứng bằng danh mục mẫu định nghĩa trước chứa 23 idiom triển khai bridge phổ biến. Trên benchmark, **94,1% cung** nhận được gán nhãn tin cậy.

#### 4.1.3. Tổng hợp Bất biến

Cho ATG, LLM sinh các bất biến ứng viên bằng phân tích ngữ nghĩa giao thức dự kiến. Mỗi bất biến được biểu diễn như vị từ trên trạng thái toàn cục: số dư chuỗi nguồn, số dư chuỗi đích, hàng đợi thông điệp relay, và nhật ký sự kiện. Các vị từ được biên dịch thành hàm assertion thực thi trong Solidity.

Để giảm ảo giác (hallucination), áp dụng pipeline xác thực ba giai đoạn:

1. Kiểm tra mỗi bất biến ứng viên với đặc tả hoặc whitepaper giao thức.
2. Đánh giá mỗi bất biến trên ít nhất 100 dấu vết giao dịch bình thường; bất biến bị vi phạm bởi giao dịch hợp lệ bị loại bỏ.
3. Kiểm tra chéo cặp đôi cho tính nhất quán logic.

Trên 12 bridge benchmark, GPT-4o sinh trung bình **18,3 bất biến ứng viên** mỗi bridge. Trong đó, 14,7 vượt qua bộ lọc dựa trên dấu vết (tỷ lệ giữ 80,3%). Kiểm tra nhất quán cặp đôi giảm thêm còn trung bình 12,1 bất biến (tỷ lệ giữ 82,3%). Kiểm tra thủ công cho thấy 10,8 trên 12,1 đúng ngữ nghĩa, đạt độ chính xác **89,3%**.

### 4.2. Module 2: Sinh Kịch bản Tấn công Tăng cường Truy xuất (RAG)

#### 4.2.1. Cơ sở Tri thức Khai thác

Xây dựng cơ sở tri thức có cấu trúc K từ **51 sự kiện tấn công cầu nối liên chuỗi** đã ghi nhận [4], mở rộng với các sự cố bổ sung đến tháng 12/2024. Mỗi mục chứa:

- Metadata tấn công: tên bridge, ngày, thiệt hại tài chính, chuỗi bị ảnh hưởng.
- Lớp lỗ hổng: kiểm soát truy cập, deposit giả, reentrancy, giả mạo chữ ký, lỗi khởi tạo, thao túng oracle.
- Giai đoạn tấn công: chuỗi nguồn, ngoài chuỗi, chuỗi đích.
- Dấu vết tấn công: chuỗi hành động mô tả cách kẻ tấn công khai thác lỗ hổng.
- Phân tích nguyên nhân gốc: lỗi cụ thể cấp mã gây ra tấn công.

Các mục được nhúng (embedding) sử dụng sentence transformer **all-MiniLM-L6-v2** và lưu trong cơ sở dữ liệu vector **FAISS** cho truy xuất hiệu quả.

#### 4.2.2. Sinh Kịch bản qua RAG

Cho ATG G và tập bất biến Φ từ Module 1, bộ sinh kịch bản hoạt động:

1. Với mỗi bất biến φ_i ∈ Φ, xây dựng truy vấn mô tả bất biến và các thành phần bridge liên quan.
2. Truy xuất top-k mục khai thác liên quan nhất từ K sử dụng cosine similarity trên embedding.
3. Xây dựng prompt chứa cấu trúc ATG, bất biến mục tiêu φ_i, và mô tả khai thác đã truy xuất.
4. Hướng dẫn LLM đóng vai **kẻ tấn công hợp lý** và sinh chuỗi hành động cụ thể S_i = (a₁, a₂, ..., a_m) vi phạm φ_i, chỉ định cho mỗi hành động: hợp đồng mục tiêu, hàm gọi, chuỗi, và ràng buộc tham số.

Mỗi kịch bản S_i cũng định nghĩa tập **điểm mốc ngữ nghĩa** (semantic waypoints) W_i = {w₁, w₂, ..., w_p}, mỗi waypoint là vị từ trên trạng thái thực thi. Ví dụ: waypoint có thể yêu cầu relay đã chấp nhận thông điệp với nonce n mà không được phát bởi router chuỗi nguồn.

### 4.3. Module 3: Fuzzing Đa chuỗi Đồng bộ

#### 4.3.1. Môi trường Dual-EVM

Khởi tạo hai instance EVM độc lập: EVM_S (mô phỏng C_S) và EVM_D (mô phỏng C_D), kết nối qua tiến trình mock relay R_mock. Mỗi instance EVM được khởi tạo bằng fork trạng thái blockchain tại block number chỉ định, deploy các hợp đồng bridge, và cấp phát tài khoản test đủ tiền.

Mock relay R_mock triển khai giao diện truyền thông điệp nhưng hoạt động dưới sự kiểm soát của fuzzer. Relay hỗ trợ **bốn chế độ**:

| Chế độ | Mô tả | Loại tấn công |
|--------|--------|---------------|
| **Faithful** | Relay thông điệp chính xác | Bình thường |
| **Delayed** | Trì hoãn relay δ block | Tấn công timing |
| **Tampered** | Sửa đổi nội dung thông điệp | Tấn công giả mạo |
| **Replayed** | Phát lại thông điệp đã tiêu thụ | Tấn công replay |

Block timestamp trên EVM_S và EVM_D tăng độc lập, cho phép fuzzer khám phá lỗ hổng phụ thuộc thời gian, race condition liên chuỗi, và drift trạng thái.

#### 4.3.2. Quản lý Snapshot Đồng bộ

Quản lý trạng thái nhất quán trên môi trường dual-EVM là thiết yếu. Định nghĩa snapshot toàn cục là bộ ba:

```
S = (S_EVM_S, S_EVM_D, S_R)
```

trong đó S_EVM_S và S_EVM_D là snapshot trạng thái EVM tương ứng (số dư tài khoản, storage hợp đồng, nonce), và S_R là trạng thái relay (hàng đợi thông điệp, tập thông điệp đã xử lý, bộ đếm nội bộ).

Khi fuzzer tạo snapshot, cả ba thành phần được chụp tuần tự dưới **khóa toàn cục** ngăn thay đổi trạng thái xen kẽ. Khi khôi phục snapshot để quay lui, cả ba được khôi phục cùng thứ tự. Điều này đảm bảo fuzzer không bao giờ khám phá trạng thái nơi chuỗi nguồn đã tiến triển trong khi chuỗi đích đã quay lui về trạng thái trước đó không nhất quán.

Snapshot được lưu dưới dạng **ảnh trạng thái vi phân** so với điểm fork, tối thiểu hóa chi phí lưu trữ.

#### 4.3.3. Dẫn hướng Điểm mốc Ngữ nghĩa (Semantic Waypoint Guidance)

Thay vì chỉ dựa vào phản hồi coverage code, BridgeSentry sử dụng semantic waypoints từ Module 2 để dẫn hướng. Định nghĩa hàm thưởng waypoint:

```
R(σ) = α · cov(σ) + β · Σ 1[w_j(σ) = true] + γ · inv_dist(σ, Φ)
```

trong đó:
- **σ**: trạng thái thực thi hiện tại
- **cov(σ)**: đóng góp coverage code (basic block mới trên cả hai EVM)
- **1[w_j(σ)]**: waypoint w_j đã đạt được hay chưa
- **inv_dist(σ, Φ)**: metric khoảng cách ước tính độ gần với vi phạm bất biến

Tham số α, β, γ khởi tạo = 0,3; 0,4; 0,3 và điều chỉnh suy giảm trong quá trình thực thi: α giảm hệ số 0,95 mỗi 100 vòng lặp fuzzing khi tăng trưởng coverage đình trệ dưới 0,1%/vòng lặp, phân bổ lại đều cho β và γ.

**Metric khoảng cách bất biến:**

- Bất biến số (như bảo toàn tài sản): d_num(σ, φ) = |locked(σ) - f(σ) - minted(σ)|
- Bất biến boolean (như kiểm tra ủy quyền): sử dụng relaxation liên tục với heuristic branch-distance từ kiểm thử phần mềm dựa trên tìm kiếm, trong đó normalize(x) = x / (x + 1) ánh xạ khoảng cách sang [0, 1).

#### 4.3.4. Vòng lặp Fuzzing

**Thuật toán 1: Vòng lặp Fuzzing Đa chuỗi BridgeSentry**

```
Đầu vào: ATG G, bất biến Φ, kịch bản {S₁,...,Sₙ}, waypoints {W₁,...,Wₙ}, ngân sách thời gian T
Đầu ra: Tập báo cáo lỗ hổng V

1.  Khởi tạo EVM_S, EVM_D, R_mock
2.  V ← ∅; Corpus ← {S₁,...,Sₙ}
3.  SnapshotPool ← {CaptureGlobalSnapshot()}
4.  WHILE thời gian < T DO
5.      Chọn seed s từ Corpus với xác suất ∝ R(s)
6.      s' ← Mutate(s, G)                          // Đột biến nhận biết ATG
7.      S_base ← SelectSnapshot(SnapshotPool, s')
8.      RestoreGlobalSnapshot(S_base)
9.      FOR mỗi hành động (c, f, chain, params) trong s' DO
10.         IF chain = C_S THEN
11.             Thực thi f(params) trên EVM_S
12.         ELSIF chain = R THEN
13.             Xử lý hành động relay trên R_mock
14.         ELSE
15.             Thực thi f(params) trên EVM_D
16.         ENDIF
17.     ENDFOR
18.     σ ← CollectGlobalState()
19.     FOR mỗi φᵢ ∈ Φ DO
20.         IF φᵢ(σ) = false THEN
21.             V ← V ∪ {(s', φᵢ, σ)}
22.         ENDIF
23.     ENDFOR
24.     IF R(σ) > R_threshold THEN
25.         Corpus ← Corpus ∪ {s'}
26.         SnapshotPool ← SnapshotPool ∪ {CaptureGlobalSnapshot()}
27.     ENDIF
28. ENDWHILE
29. RETURN V
```

Dòng 7 chọn snapshot cơ sở từ pool thay vì luôn khôi phục trạng thái ban đầu, theo chiến lược tái sử dụng snapshot trung gian của ItyFuzz.

#### 4.3.5. Đột biến Nhận biết ATG

Toán tử đột biến được thông tin bởi cấu trúc ATG. Các đột biến bao gồm:

- Sắp xếp lại hành động trong kịch bản tuân theo phụ thuộc nhân quả trong ATG.
- Thay thế tham số hàm bằng giá trị biên, giá trị zero, hoặc giá trị từ trạng thái on-chain.
- Chèn hành động bổ sung nhắm vào hàm hợp đồng kề trong ATG.
- Chuyển chế độ relay giữa faithful, delayed, tampered, hoặc replayed.
- Tăng timestamp block độc lập trên EVM_S và EVM_D với bước nhảy khác nhau, mô phỏng drift đồng hồ liên chuỗi.

---

## 5. Thực nghiệm (Experiments)

### 5.1. Câu hỏi Nghiên cứu

- **RQ1:** BridgeSentry so sánh như thế nào với các công cụ hiện có về tỷ lệ phát hiện lỗ hổng và thời gian khai thác trên các vụ khai thác bridge liên chuỗi được tái dựng?
- **RQ2:** Mỗi module (trích xuất ngữ nghĩa, sinh kịch bản, fuzzing đa chuỗi) đóng góp bao nhiêu vào hiệu suất tổng thể?
- **RQ3:** BridgeSentry nhạy cảm như thế nào với các tham số cấu hình chính?

### 5.2. Thiết lập Thực nghiệm

#### Bộ dữ liệu Benchmark

12 vụ khai thác cầu nối liên chuỗi thực tế được tái dựng, chọn từ dataset 51 sự cố [4]:

| Sự cố | Giai đoạn tấn công | Thiệt hại ($M) | Năm |
|-------|-------------------|----------------|-----|
| PolyNetwork | Chuỗi nguồn | 611 | 2021 |
| Wormhole | Chuỗi đích | 326 | 2022 |
| Ronin Network | Ngoài chuỗi | 624 | 2022 |
| Nomad | Chuỗi đích | 190 | 2022 |
| Harmony Horizon | Ngoài chuỗi | 100 | 2022 |
| Multichain | Ngoài chuỗi | 126 | 2023 |
| Socket Gateway | Chuỗi nguồn | 3,3 | 2024 |
| Orbit Bridge | Ngoài chuỗi | 82 | 2024 |
| GemPad | Chuỗi đích | 1,9 | 2024 |
| FEGtoken | Ngoài chuỗi | 0,9 | 2024 |
| pGALA | Chuỗi nguồn | 10 | 2022 |
| Qubit Finance | Chuỗi đích | 80 | 2022 |
| **Tổng** | | **2.155,1** | |

Mỗi vụ khai thác được tái dựng bằng fork trạng thái blockchain tại block trước cuộc tấn công, deploy hợp đồng có lỗi trên instance Anvil cục bộ, và xác minh chuỗi giao dịch khai thác gốc tái tạo thành công lỗ hổng.

#### Baselines

| Công cụ | Loại | Venue | Lý do so sánh |
|---------|------|-------|---------------|
| ItyFuzz [8] | Fuzzer snapshot đơn chuỗi | ISSTA 2023 | Chứng minh Dual-EVM cần thiết |
| SmartShot [24] | Fuzzer snapshot có thể biến đổi | FSE 2025 | Fuzzer snapshot tiên tiến nhất |
| VulSEye [13] | Fuzzer graybox có hướng | IEEE TIFS 2025 | Fuzzer có hướng tiên tiến nhất |
| SmartAxe [3] | Phân tích tĩnh liên chuỗi | FSE 2024 | Đối thủ trực tiếp nhất |
| GPTScan [9] | LLM + phân tích tĩnh | ICSE 2024 | Chứng minh LLM đơn chuỗi không đủ |
| XScope [6] | Phát hiện dựa trên quy tắc | ASE 2022 | Công cụ nền tảng liên chuỗi |

Ngân sách thời gian cho công cụ động: **600 giây** mỗi instance benchmark. Tất cả thực nghiệm lặp **20 lần** với seed ngẫu nhiên khác nhau.

#### Metrics

- **Tỷ lệ Phát hiện (DR):** Phần benchmark lỗ hổng được phát hiện thành công.
- **Thời gian Khai thác (TTE):** Thời gian wall-clock từ bắt đầu fuzzing đến vi phạm bất biến (giây).
- **Tỷ lệ Dương tính Giả (FPR):** Phần vi phạm bất biến báo cáo không tương ứng lỗ hổng khai thác được thực sự.
- **Độ phủ Liên chuỗi (XCC):** Phần đường đi thực thi liên chuỗi (từ ATG) được thực hiện trong fuzzing.

#### Triển khai và Phần cứng

BridgeSentry được triển khai trong khoảng **8.500 dòng Python** cho điều phối, tích hợp LLM, và pipeline RAG, và **3.200 dòng Rust** cho công cụ fuzzing dual-EVM xây trên thư viện revm. Backend LLM sử dụng GPT-4o qua OpenAI API. Giai đoạn trích xuất ngữ nghĩa tiêu thụ trung bình 12.000 token mỗi phân tích bridge với chi phí khoảng **$0,15 mỗi bridge**. Thực nghiệm trên server Ubuntu 22.04 với CPU AMD EPYC 7763 64 nhân, 256 GB RAM, và GPU NVIDIA A100 chỉ dùng cho tính toán embedding.

### 5.3. RQ1: So sánh với Baselines

| Sự cố | BridgeSentry | ItyFuzz | SmartShot | VulSEye | SmartAxe | GPTScan | XScope |
|-------|-------------|---------|-----------|---------|----------|---------|--------|
| PolyNetwork | ✓ (36±8s) | ✗ | ✓ (41±12s) | ✓ (55±18s) | ✓ | ✓ | ✓ |
| Wormhole | ✓ (51±13s) | ✗ | ✓ (74±21s) | ✗ | ✓ | ✗ | ✓ |
| Ronin | ✓ (121±28s) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Nomad | ✓ (11±3s) | ✓ (0,3±0,1s) | ✓ (0,2±0,1s) | ✓ (0,4±0,2s) | ✗ | ✗ | ✗ |
| Harmony | ✓ (89±20s) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Multichain | ✓ (65±15s) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Socket | ✓ (22±5s) | ✓ (8±2s) | ✓ (3±1s) | ✓ (6±2s) | ✓ | ✓ | ✗ |
| Orbit | ✓ (153±35s) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| GemPad | ✓ (30±7s) | ✓ (2±0,5s) | ✓ (1,5±0,4s) | ✓ (2,8±0,8s) | ✗ | ✓ | ✓ |
| FEGtoken | ✓ (42±10s) | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| pGALA | ✓ (56±14s) | ✓ (15±4s) | ✓ (9±3s) | ✓ (12±4s) | ✓ | ✓ | ✗ |
| Qubit | ✗ | ✓ (5±1s) | ✓ (3±1s) | ✓ (4±1s) | ✗ | ✗ | ✓ |
| **DR** | **11/12 (91,7%)** | 5/12 (41,7%) | 7/12 (58,3%) | 6/12 (50,0%) | 4/12 (33,3%) | 4/12 (33,3%) | 5/12 (41,7%) |
| **TTE trung vị** | **47±14s** | 5±2s | 3±1s | 5±2s | N/A | N/A | N/A |

BridgeSentry phát hiện **11 trên 12 lỗ hổng mục tiêu (DR = 91,7%)**. Cả ba fuzzer snapshot (ItyFuzz, SmartShot, VulSEye) phát hiện lỗ hổng đơn chuỗi hiệu quả nhưng **không phát hiện được bất kỳ cuộc tấn công ngoài chuỗi nào** trong 5 vụ (Ronin, Harmony, Multichain, Orbit, FEGtoken) yêu cầu thao túng trạng thái phối hợp qua các chuỗi.

Lỗ hổng duy nhất BridgeSentry bỏ sót là **Qubit Finance**, nơi hàm deposit chấp nhận deposit giá trị zero. LLM đã nhận diện đúng luồng nhưng không sinh bất biến ràng buộc số tiền gửi tối thiểu. Cả ba fuzzer đơn chuỗi phát hiện lỗ hổng này qua đột biến tham số số tiền deposit.

**Phân tích thống kê:** Mann-Whitney U test và Vargha-Delaney Â₁₂ qua 20 lần chạy: BridgeSentry vs ItyFuzz: U=38, p<0,001, Â₁₂=0,91 (lớn); vs SmartShot: U=87, p<0,01, Â₁₂=0,78 (lớn); vs VulSEye: U=72, p<0,01, Â₁₂=0,82 (lớn). Tất cả so sánh bác bỏ giả thuyết không tại α=0,01.

### 5.4. RQ2: Nghiên cứu Loại bỏ Thành phần (Ablation Study)

| Biến thể | DR | TTE trung vị (s) | FPR (%) |
|----------|------|-----------------|---------|
| BridgeSentry (đầy đủ) | 11/12 (91,7%) | 47 (±14) | 4,2 (±1,1) |
| BridgeSentry^(-SE) (bỏ Module 1) | 7/12 (58,3%) | 112 (±29) | 18,7 (±3,8) |
| BridgeSentry^(-RAG) (bỏ Module 2) | 8/12 (66,7%) | 203 (±41) | 6,1 (±1,6) |
| BridgeSentry^(-Sync) (bỏ đồng bộ) | 6/12 (50,0%) | 89 (±23) | 31,5 (±5,2) |

- **Bỏ trích xuất ngữ nghĩa:** DR giảm từ 91,7% xuống 58,3%, FPR tăng lên 18,7% — bất biến LLM chính xác và toàn diện hơn bất biến tổng quát.
- **Bỏ sinh kịch bản RAG:** DR giảm xuống 66,7%, TTE trung vị tăng lên 203s — fuzzer phải khám phá chuỗi tấn công qua random exploration.
- **Bỏ đồng bộ đa chuỗi:** Tác động nghiêm trọng nhất — DR giảm xuống 50,0%, FPR tăng lên 31,5%. FPR cao do snapshot chuỗi độc lập đạt trạng thái không thể xảy ra trong thực thi liên chuỗi đồng bộ đúng, tạo ra vi phạm bất biến giả.

### 5.5. RQ3: Độ nhạy Tham số

**Số lượng khai thác truy xuất (k):** DR tăng theo k đến k=5 và ổn định sau đó. k<3 tạo kịch bản tấn công không đủ đa dạng; k>5 thêm thông tin dư thừa.

**Ngân sách thời gian (T):** BridgeSentry tiếp tục phát hiện lỗ hổng mới khi T tăng từ 60s đến 600s. ItyFuzz bão hòa ở khoảng 120s.

**Trọng số thưởng waypoint (β):** DR đạt đỉnh 91,7% cho β ∈ [0,3; 0,5]. Suy giảm xuống 75,0% tại β=0,1 (fuzzer thiên về khám phá coverage) và 83,3% tại β=0,7 (fuzzer quá khớp vào chuỗi waypoint cụ thể). Chọn β=0,4 làm mặc định.

### 5.6. Phân tích Độ phủ Liên chuỗi

Đo hai biến thể XCC để tránh đánh giá vòng tròn:

- **XCC_ATG:** Đo theo đường đi ATG của BridgeSentry (metric nội bộ)
- **XCC_S:** Đo theo đồ thị gọi hàm cross-function được xây dựng độc lập bởi Slither, bổ sung chú thích cung liên chuỗi thủ công

| Công cụ | XCC_ATG | XCC_S |
|---------|---------|-------|
| BridgeSentry | 78,4% | 72,1% |
| ItyFuzz | 42,1% | 38,4% |
| SmartShot | — | 44,7% |
| VulSEye | — | 41,3% |

Tương quan Pearson r = 0,94 giữa hai metric. Cải thiện rõ rệt nhất cho kịch bản tấn công ngoài chuỗi: BridgeSentry đạt 71,2% coverage đường đi so với 0% cho tất cả fuzzer đơn chuỗi.

---

## 6. Thảo luận (Discussion)

### 6.1. Hạn chế

- **Phụ thuộc chất lượng hiểu code của LLM:** Với hợp đồng bị obfuscate cao hoặc chỉ có bytecode, xây dựng ATG có thể không đầy đủ hoặc không chính xác. Mô hình ngôn ngữ xác suất cho tổng hợp bất biến mang rủi ro ảo giác bất biến. Pipeline xác thực ba giai đoạn giảm rủi ro nhưng không cung cấp đảm bảo soundness hình thức.

- **Giới hạn cơ sở tri thức RAG:** Các cuộc tấn công khai thác lớp lỗ hổng không có trong 51 sự cố lịch sử sẽ nhận được dẫn hướng kịch bản yếu hơn. Mô hình embedding all-MiniLM-L6-v2 là transformer câu mục đích chung và có thể không nắm bắt sắc thái cấu trúc của code Solidity.

- **Chỉ hỗ trợ chuỗi tương thích EVM:** Mở rộng sang cặp chuỗi không đồng nhất (ví dụ: EVM + Solana SVM) yêu cầu kỹ thuật bổ sung đáng kể cho biểu diễn trạng thái và quản lý snapshot.

- **Coupling nhân tạo giữa hai instance chuỗi:** Blockchain thực tế hoạt động bất đồng bộ với sản xuất block độc lập, độ trễ finality biến đổi, và tiềm năng thao túng timestamp do MEV.

- **Chi phí và độ trễ API LLM:** Giai đoạn trích xuất ngữ nghĩa thêm khoảng 45 giây và $0,15 mỗi phân tích bridge. Thay thế backend LLM sở hữu bằng mô hình mã nguồn mở (DeepSeek-Coder, Llama-3) sẽ giảm chi phí.

- **Benchmark hạn chế:** 12 vụ khai thác tương thích EVM chiếm 23,5% dataset 51 sự cố. Hiệu suất trên lỗ hổng chuỗi không đồng nhất và zero-day cần đánh giá thêm.

### 6.2. Mối đe dọa với Tính hợp lệ (Threats to Validity)

- **Tính hợp lệ nội bộ:** Lỗi tiềm ẩn trong tái dựng benchmark. Giảm thiểu bằng xác minh mỗi tái dựng với hash giao dịch khai thác gốc. FPR 4,2% xác định qua kiểm tra thủ công bởi hai tác giả độc lập. Cohen's κ = 0,87 trên 48 vi phạm báo cáo, cho thấy đồng thuận gần hoàn hảo.

- **Tính hợp lệ thống kê:** Hỗ trợ bởi 20 lần lặp độc lập, kiểm định Mann-Whitney U, và báo cáo effect size Vargha-Delaney Â₁₂. Tất cả sáu so sánh cặp bác bỏ null tại α=0,01 với effect size lớn (Â₁₂ > 0,71).

- **Tính hợp lệ bên ngoài:** Benchmark bao phủ 12 trên 51 cuộc tấn công ghi nhận, tất cả trên chuỗi tương thích EVM. Ablation study cho thấy BridgeSentry vẫn hữu ích ngay cả không có tri thức khai thác cụ thể (DR 66,7% khi bỏ RAG).

- **Tính hợp lệ cấu trúc:** Để giảm đánh giá vòng tròn, báo cáo cả XCC_ATG nội bộ và XCC_S độc lập. Tương quan cao (r=0,94) xác nhận ưu thế coverage không phải artifact của xây dựng ATG.

### 6.3. Hướng Phát triển Tương lai

- Mở rộng BridgeSentry cho chuỗi không phải EVM (Cosmos IBC, Solana).
- Tích hợp xác minh hình thức cho bất biến đã tổng hợp (bounded model checking, framework EPG).
- Thay thế GPT-4o bằng LLM mã nguồn mở (DeepSeek-Coder-V2, Llama-3).
- Áp dụng mô hình embedding đặc thù miền cho module RAG (ví dụ: CodeBERT fine-tune trên Solidity).
- Vòng phản hồi từ lỗ hổng phát hiện được quay lại cơ sở tri thức cho học liên tục.
- Mô phỏng tính không tất định sản xuất block thực tế và sắp xếp lại do MEV trong harness dual-EVM.

---

## 7. Kết luận (Conclusion)

Bài báo này trình bày BridgeSentry, một framework phát hiện lỗ hổng chủ động trong cầu nối liên chuỗi kết hợp trích xuất ngữ nghĩa dựa trên LLM, sinh kịch bản tấn công tăng cường truy xuất, và fuzzing đa chuỗi đồng bộ. Bằng cách điều chỉnh hình thức Đồ thị Chuyển đổi Nguyên tử [27] để mô hình hóa bất biến giao thức bridge và sử dụng tri thức khai thác lịch sử để dẫn hướng fuzzing tới vùng lỗ hổng giá trị cao, BridgeSentry phát hiện **11 trên 12 vụ khai thác thực tế** được tái dựng qua 20 lần chạy độc lập, đạt **DR 91,7%** với cải thiện có ý nghĩa thống kê so với sáu baseline (Mann-Whitney U p < 0,01, Vargha-Delaney Â₁₂ ≥ 0,78 cho tất cả so sánh).

Ưu thế DR 33,4 đến 58,4 điểm phần trăm so với fuzzer đơn chuỗi — bao gồm SmartShot và VulSEye, tiên tiến nhất hiện nay trong fuzzing snapshot và graybox có hướng — chứng minh rằng **lỗ hổng liên chuỗi yêu cầu suy luận đa chuỗi đồng bộ không thể khôi phục bằng áp dụng công cụ đơn chuỗi độc lập cho mỗi chuỗi**.

Metric coverage liên chuỗi độc lập dựa trên đồ thị gọi tĩnh Slither xác nhận BridgeSentry thực hiện 72,1% đường đi liên chuỗi so với 44,7% cho baseline đơn chuỗi tốt nhất. Nghiên cứu ablation xác nhận tất cả ba module đóng góp, với **quản lý trạng thái đa chuỗi đồng bộ đóng góp cá nhân lớn nhất**.

Đánh giá hiện tại giới hạn ở chuỗi tương thích EVM và benchmark 12 vụ khai thác; mở rộng sang kiến trúc chuỗi không đồng nhất và tích hợp xác minh bất biến hình thức là các bước tiếp theo ưu tiên.

---

## Tài liệu tham khảo

[1] R. Belchior et al., "A survey on blockchain interoperability: Past, present, and future trends," *ACM Comput. Surv.*, vol. 54, no. 8, 2021.

[2] A. Augusto et al., "SoK: Security and privacy of blockchain interoperability," in *Proc. IEEE S&P*, 2024, pp. 3840-3865.

[3] Z. Liao et al., "SmartAxe: Detecting cross-chain vulnerabilities in bridge smart contracts via fine-grained static analysis," *Proc. ACM Softw. Eng.*, vol. 1, no. FSE, 2024.

[4] J. Wu et al., "Safeguarding blockchain ecosystem: Understanding and detecting attack transactions on cross-chain bridges," in *Proc. ACM Web Conf.*, 2025, pp. 4902-4912.

[5] D. Lin et al., "BridgeShield: Enhancing security for cross-chain bridge applications via heterogeneous graph mining," *ACM TOSEM*, vol. 1, no. 1, 2025.

[6] J. Zhang et al., "Xscope: Hunting for cross-chain bridge attacks," in *Proc. IEEE/ACM ASE*, 2022, pp. 1-4.

[7] Z. Zhou et al., "BridgeGuard: Checking external interaction vulnerabilities in cross-chain bridge router contracts based on symbolic dataflow analysis," *IEEE TDSC*, 2025.

[8] C. Shou, S. Tan, and K. Sen, "ItyFuzz: Snapshot-based fuzzer for smart contract," in *Proc. ACM ISSTA*, 2023.

[9] Y. Sun et al., "GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis," in *Proc. IEEE/ACM ICSE*, 2024.

[10] Z. Wei et al., "Advanced smart contract vulnerability detection via LLM-powered multi-agent systems," *IEEE TSE*, 2025.

[11] Y. Zhuang et al., "Smart contract vulnerability detection using graph neural networks," in *Proc. IJCAI*, 2021, pp. 3283-3290.

[12] Z. Liu et al., "Combining graph neural networks with expert knowledge for smart contract vulnerability detection," *IEEE TKDE*, vol. 35, no. 2, 2023.

[13] R. Liang et al., "VulSEye: Detect smart contract vulnerabilities via stateful directed graybox fuzzing," *IEEE TIFS*, vol. 20, 2025.

[14] M. Ye et al., "Midas: Mining profitable exploits in on-chain smart contracts via feedback-driven fuzzing and differential analysis," in *Proc. ACM ISSTA*, 2024.

[15] Z. Kong et al., "Smart contract fuzzing towards profitable vulnerabilities," *Proc. ACM Softw. Eng.*, vol. 2, no. FSE, 2025.

[16] K. Qin et al., "Enhancing smart contract security analysis with execution property graphs," *Proc. ACM Softw. Eng.*, vol. 2, no. ISSTA, 2025.

[17] S.-S. Lee et al., "SoK: Not quite water under the bridge: Review of cross-chain bridge hacks," in *Proc. IEEE ICBC*, 2023, pp. 1-14.

[18] L. Duan et al., "Attacks against cross-chain systems and defense approaches: A contemporary survey," *IEEE/CAA J. Autom. Sinica*, vol. 10, no. 8, 2023.

[19] S. Wu et al., "Are we there yet? Unraveling the state-of-the-art smart contract fuzzers," in *Proc. IEEE/ACM ICSE*, 2024.

[20] D. Lin et al., "Connector: Enhancing the traceability of decentralized bridge applications via automatic cross-chain transaction association," *IEEE TIFS*, 2025.

[21] X. Wang et al., "Heterogeneous graph attention network," in *Proc. WWW*, 2019, pp. 2022-2032.

[22] D. Chen et al., "Smart contract vulnerability detection based on semantic graph and residual graph convolutional networks with edge attention," *J. Syst. Softw.*, vol. 203, 2023.

[23] W. Chen et al., "Towards smart contract fuzzing on GPUs," in *Proc. IEEE S&P*, 2024.

[24] R. Liang et al., "SmartShot: Hunt hidden vulnerabilities in smart contracts using mutable snapshots," *Proc. ACM Softw. Eng.*, vol. 2, no. FSE, 2025.

[25] N. Li et al., "Blockchain cross-chain bridge security: Challenges, solutions, and future outlook," *Distrib. Ledger Technol.*, vol. 4, no. 1, 2025.

[26] J. Feist, G. Grieco, and A. Swende, "Slither: A static analysis framework for smart contracts," in *Proc. IEEE/ACM WETSEB*, 2019, pp. 8-15.

[27] S. Dübler et al., "Atomic transfer graphs: Secure-by-design protocols for heterogeneous blockchain ecosystems," in *Proc. IEEE CSF*, 2025, pp. 300-315.

[28] G. M. A. Ali et al., "CrossGuard: Runtime-adaptive LLM fuzzing for cross-contract vulnerabilities detection," *Concurrency Comput.*, 2025.
