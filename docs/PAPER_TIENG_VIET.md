# BridgeSentry: Phát hiện Lỗ hổng trong Cầu nối Liên chuỗi được Dẫn hướng bởi LLM thông qua Mô hình hóa Ngữ nghĩa và Fuzzing Đa chuỗi Đồng bộ

> Bản dịch tiếng Việt từ `latex/paper.tex` (định dạng IEEE)

---

## Tóm tắt (Abstract)

Cầu nối liên chuỗi (cross-chain bridge) đã trở thành hạ tầng quan trọng trong hệ sinh thái blockchain đa chuỗi, tuy nhiên chúng vẫn là nguồn tổn thất tài chính lớn nhất trong tài chính phi tập trung. Tổng thiệt hại tích lũy từ các vụ khai thác cầu nối liên chuỗi đã đạt gần **4,3 tỷ USD** kể từ năm 2021, bắt nguồn từ các lỗ hổng trải dài trên nhiều blockchain và các thành phần relay ngoài chuỗi. Các công cụ bảo mật hiện có chỉ giải quyết vấn đề này một phần: công cụ phân tích tĩnh phát hiện lỗ hổng hợp đồng đơn lẻ, fuzzer đơn chuỗi khám phá không gian trạng thái on-chain, và các framework dựa trên đồ thị phân loại giao dịch tấn công sau khi khai thác đã xảy ra. Không có công cụ nào trong số này chủ động phát hiện lỗ hổng logic phát sinh từ sự không nhất quán trạng thái liên chuỗi.

Bài báo này trình bày **BridgeSentry**, một framework kết hợp suy luận mô hình ngôn ngữ lớn (LLM) với fuzzing đa chuỗi đồng bộ để phát hiện lỗ hổng cầu nối liên chuỗi trước khi chúng bị khai thác. BridgeSentry hoạt động qua ba giai đoạn:

1. **Trích xuất ngữ nghĩa dựa trên LLM** phân tích mã nguồn hợp đồng thông minh của bridge và xây dựng Đồ thị Chuyển đổi Nguyên tử (Atomic Transfer Graph - ATG), theo mô hình hình thức của Dübler và cộng sự, để nắm bắt các bất biến giao thức dự kiến trên chuỗi nguồn và chuỗi đích.
2. **Module sinh kịch bản tấn công tăng cường truy xuất (RAG)**, được nạp tri thức có cấu trúc từ các vụ khai thác liên chuỗi đã được ghi nhận, sinh ra các kịch bản tấn công hợp lý phản ánh động cơ đối kháng hợp lý.
3. **Công cụ fuzzing đa chuỗi đồng bộ (dual-EVM)** thực thi các kịch bản này trên các instance blockchain ghép cặp với quản lý snapshot nhất quán, sử dụng các điểm mốc ngữ nghĩa (semantic waypoints) để dẫn hướng khám phá tới các vi phạm bất biến liên chuỗi.

Chúng tôi đánh giá BridgeSentry trên bộ benchmark gồm 12 vụ khai thác cầu nối liên chuỗi thực tế được tái dựng (bao gồm Wormhole, Nomad, PolyNetwork và 9 sự cố khác) qua **20 lần chạy độc lập mỗi benchmark (tổng 240 lần chạy)**. BridgeSentry đạt được cả **12/12 lỗ hổng mục tiêu** trong ngân sách thời gian; vì bộ kiểm tra bất biến đa chuỗi đánh giá các kịch bản dẫn xuất từ ATG trong một harness mô phỏng, vi phạm được phát hiện ở mức **dưới một mili-giây** ngay khi một kịch bản vi phạm được khởi tạo, còn thời gian thực thi end-to-end bị chi phối bởi giai đoạn mô hình hóa LLM. Để tham chiếu, các công cụ baseline gốc (ItyFuzz, SmartShot, VulSEye, SmartAxe, GPTScan, XScope) chỉ phát hiện được tối đa **một** trong 12 sự cố liên chuỗi theo kết quả per-bridge công bố của chúng, phản ánh việc không công cụ nào được thiết kế cho thực thi đa chuỗi phối hợp. Để có so sánh per-bridge khi thiếu artifact công khai, chúng tôi **tái hiện (re-implement) bốn công cụ** và chạy trên cùng 12 benchmark; theo tiêu chí khớp predicate chặt hơn, các bản tái hiện đạt 12/12 (SmartShot), 10/12 (XScope), 9/12 (VulSEye) và 4/12 (SmartAxe), với khoảng trống của bộ phân tích tĩnh tập trung ở các ca key-compromise runtime ngoài chuỗi. Các kết quả này cho thấy việc phát hiện liên chuỗi phụ thuộc vào **mô hình hóa đa chuỗi và các bất biến dẫn xuất từ LLM** mà BridgeSentry đóng góp; chúng tôi **không tuyên bố ưu thế về tỷ lệ phát hiện** so với các baseline đã được trang bị harness đa chuỗi của chúng tôi (xem Mục 5).

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
2. **Bộ sinh kịch bản tấn công tăng cường truy xuất** truy vấn cơ sở tri thức có cấu trúc các vụ khai thác liên chuỗi đã ghi nhận — lấy từ danh mục 51 sự cố của Wu và cộng sự [4] cùng các corpus SmartAxe và XScope [3, 6, 2] — để sinh ra các chuỗi tấn công có động cơ kinh tế hợp lý nhắm vào các bất biến đã xác định.
3. **Công cụ fuzzing đa chuỗi đồng bộ** duy trì các instance EVM ghép cặp được kết nối qua mock relay, thực thi các kịch bản tấn công đã sinh dưới dạng seed được dẫn hướng, và sử dụng các điểm mốc ngữ nghĩa để lái fuzzer tới các trạng thái mà bất biến liên chuỗi có khả năng bị vi phạm.

### Các đóng góp chính

- Đề xuất framework kết hợp hiểu biết giao thức dựa trên LLM với kiểm thử động đa chuỗi đồng bộ cho phát hiện lỗ hổng cầu nối liên chuỗi chủ động.
- Điều chỉnh hình thức ATG của Dübler và cộng sự [27] cho bối cảnh fuzzing cầu nối liên chuỗi bằng cách định nghĩa bốn loại bất biến đặc thù miền và biên dịch chúng thành các assertion thực thi được.
- Thiết kế cơ chế snapshot đồng bộ cho quản lý trạng thái nhất quán trên hai instance EVM và mock relay.
- Đánh giá BridgeSentry trên 12 vụ khai thác thực tế được tái dựng, và — vì hầu hết baseline không có artifact chạy được trên benchmark này — **tái hiện bốn công cụ** để có so sánh per-bridge, cho thấy các công cụ gốc không xử lý được sự cố liên chuỗi và việc phát hiện chỉ trở nên khả thi khi được cung cấp khả năng mô hình hóa đa chuỗi.

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

Sử dụng chiến lược prompt có cấu trúc để dẫn hướng LLM (`openai/gpt-oss-120b` qua NVIDIA NIM; xem Mục 5) qua phân tích đa bước:

1. Nhận diện tất cả thực thể hợp đồng: router, token, governance, proxy, phụ thuộc bên ngoài.
2. Phân loại mỗi hàm public/external theo vai trò: deposit, withdrawal, xử lý relay, đúc token, đốt token, tạm dừng khẩn cấp, quản trị.
3. Trích xuất đường đi luồng tài sản: với mỗi hàm thay đổi trạng thái, theo dõi luồng số dư token, xác định nguồn và đích.
4. Nhận diện các guard điều kiện: modifier kiểm soát truy cập, kiểm tra xác minh chữ ký, xác thực nonce, điều kiện timelock, yêu cầu đa chữ ký.

Template prompt được cấu trúc để tạo output JSON tuân theo schema định nghĩa trước, cho phép phân tích tất định phản hồi LLM thành nút và cạnh đồ thị.

#### 4.1.2. Xây dựng ATG

Từ các thực thể và quan hệ đã trích xuất, xây dựng ATG G = (N, A, Λ, Φ). Mỗi hợp đồng hoặc tài khoản trở thành một nút. Mỗi chuyển tài sản, relay thông điệp, hoặc phụ thuộc trạng thái trở thành cung có hướng với nhãn phù hợp. Hình thức ATG gốc giả định giao thức thiết kế quanh Hợp đồng Timelock Có điều kiện (CTLC). Triển khai bridge thực tế hiếm khi dùng CTLC tường minh; thay vào đó dùng kết hợp ad hoc timelock, kiểm tra đa chữ ký, và ủy quyền proxy. Bộ trích xuất LLM ánh xạ các mẫu triển khai này sang nhãn cung ATG tương ứng bằng danh mục mẫu định nghĩa trước các idiom triển khai bridge phổ biến. Khi LLM không thể phân loại tin cậy một hàm, nó gán nhãn "unknown" bảo thủ và cung tương ứng được đưa vào ATG nhưng loại khỏi việc sinh bất biến. Trên 12 benchmark, các ATG trích xuất có từ 3 đến 7 nút và 1 đến 8 cung mỗi đồ thị, phản ánh số lượng thực thể của bridge tái dựng chứ không phải độ phức tạp của exploit.

#### 4.1.3. Tổng hợp Bất biến

Cho ATG, LLM sinh các bất biến ứng viên bằng phân tích ngữ nghĩa giao thức dự kiến. Mỗi bất biến được biểu diễn như vị từ trên trạng thái toàn cục: số dư chuỗi nguồn, số dư chuỗi đích, hàng đợi thông điệp relay, và nhật ký sự kiện. Các vị từ được biên dịch thành hàm assertion thực thi trong Solidity.

Để giảm ảo giác (hallucination), thiết kế áp dụng pipeline xác thực ba giai đoạn:

1. Kiểm tra mỗi bất biến ứng viên với đặc tả hoặc whitepaper giao thức.
2. Đánh giá mỗi bất biến trên các dấu vết giao dịch bình thường thu thập từ trạng thái fork; bất biến bị vi phạm bởi giao dịch hợp lệ bị loại bỏ.
3. Kiểm tra chéo cặp đôi cho tính nhất quán logic.

Trên 12 bridge benchmark, LLM sinh ra từ 16 đến 21 bất biến mỗi bridge (trung bình ≈ 19), được phân vào bốn loại ở Mục 3 (bảo toàn tài sản, ủy quyền, tính duy nhất, tính kịp thời).

> **[TODO — chưa đo]** Tỷ lệ giữ lại sau lọc dựa trên dấu vết / kiểm tra nhất quán cặp đôi, và con số độ chính xác kiểm tra thủ công, **chưa được đo** trên pipeline hiện tại. Cần chạy harness xác thực và báo cáo số ứng viên-vs-giữ-lại + độ chính xác thủ công trước khi nộp; **không nêu số % tỷ lệ giữ/độ chính xác cho đến khi đo được**.

### 4.2. Module 2: Sinh Kịch bản Tấn công Tăng cường Truy xuất (RAG)

#### 4.2.1. Cơ sở Tri thức Khai thác

Xây dựng cơ sở tri thức có cấu trúc K các sự kiện tấn công cầu nối liên chuỗi đã ghi nhận, theo danh mục 51 sự kiện của Wu và cộng sự [4] và bổ sung các bản ghi lỗ hổng liên chuỗi tuyển chọn từ corpus SmartAxe và XScope. *(TODO — cần xác minh: nêu chính xác số bản ghi đã index; build_exploit_kb.py có ~32 bản ghi tuyển chọn + SmartAxe/XScope enumerated, ~48 tổng theo build log — thay cụm "các sự kiện đã ghi nhận" bằng con số chính xác khi chốt.)* Mỗi mục chứa:

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

BridgeSentry gồm tầng điều phối + tích hợp LLM + RAG bằng Python (Module 1–2) và công cụ fuzzing dual-EVM bằng Rust xây trên thư viện revm (Module 3). *(TODO — cần xác minh: báo cáo số dòng code chính xác Python/Rust bằng cloc trước khi nộp.)* Backend LLM là **`openai/gpt-oss-120b`** phục vụ qua **NVIDIA NIM API**; bộ truy xuất RAG dùng embedder câu **`all-MiniLM-L6-v2`** trên index FAISS. *(Ghi chú: bản phát triển dùng NVIDIA NIM gpt-oss-120b; nếu dùng mô hình cỡ GPT-4o cho lần chạy camera-ready thì cập nhật lại và chạy lại Module 1–2.)* Module 1–2 (mô hình hóa LLM) mất cỡ vài phút mỗi bridge; sweep dual-chain của Module 3 chạy với ngân sách **60 giây/lần** và **20 lần chạy mỗi benchmark**. Công cụ baseline động được cấp ngân sách **600 giây** mỗi benchmark.

### 5.3. RQ1: So sánh với Baselines

Chúng tôi tổ chức so sánh thành hai phần. Thứ nhất, tóm tắt **trạng thái per-bridge công bố** của sáu baseline (động cơ cho nhu cầu phân tích cross-chain-native). Thứ hai, vì bốn trong sáu công cụ không có artifact chạy được trên benchmark này, chúng tôi **tái hiện thuật toán lõi** của chúng và chạy trên cùng 12 benchmark để thu được ma trận per-bridge.

**Độ phủ baseline out-of-the-box.** Tổng hợp kết quả per-bridge công bố của từng baseline, **chỉ XScope** báo cáo phát hiện dương trên bất kỳ sự cố nào trong 12 sự cố của chúng tôi — nó gắn cờ 20 giao dịch khả nghi trên Qubit, gồm một giao dịch 43 ngày trước vụ tấn công \$80M. SmartAxe chỉ công bố precision/recall tổng hợp (84,95%/89,77%) trên dataset 16-bridge riêng, không liệt kê per-incident cho tập của ta; SmartShot và VulSEye được đánh giá trên corpus DeFi tổng quát; ItyFuzz và GPTScan không công bố dữ liệu per-bridge cho các sự cố này. Ma trận trích-dẫn-công-khai do đó chỉ có **1 ô dương trên 72** (6 baseline × 12 sự cố). Sự thưa thớt này là hệ quả dự kiến của khoảng trống thiết kế ở Mục 2: không công cụ nào được xây để thực thi phối hợp nguồn/relay/đích trong một harness.

**Phương pháp tự chạy (self-run).** Để có so sánh per-bridge có ý nghĩa thay vì để trống 71/72 ô, chúng tôi tái hiện bốn baseline và chạy trên benchmark theo quy trình thống nhất (cùng fork block, cùng metadata, cùng bản đồ predicate kỳ vọng, ngân sách 600s, 20 lần chạy nếu ngẫu nhiên). XScope được tái hiện thành bộ phát hiện dựa-trên-luật (6 predicate liên chuỗi I-1…I-6); SmartAxe thành bộ phân tích tĩnh độc lập dựa trên Slither (artifact SmartAxe bị giới hạn truy cập); hai fuzzer SmartShot (snapshot) và VulSEye (directed-graybox) được tái hiện thành **các chế độ dẫn hướng thay thế *bên trong* harness dual-EVM của chúng tôi**, để so sánh cô lập thuật toán dẫn hướng trong khi giữ cố định môi trường thực thi liên chuỗi. ItyFuzz (MIT) và GPTScan (Apache-2.0) chạy như công cụ gốc nhưng chỉ ở dạng smoke test trên Nomad và Qubit (sweep đủ 12-bridge đang tiến hành). Chúng tôi dùng hai tiêu chí: **phát hiện (detected)** — công cụ báo ≥1 vi phạm thật; và **khớp-predicate** chặt hơn — công cụ kích hoạt đúng predicate lỗ hổng kỳ vọng cho bridge đó. Vì các bất biến của chính BridgeSentry định nghĩa vi phạm kỳ vọng của benchmark, chúng tôi **chỉ báo cáo BridgeSentry theo tiêu chí "detected"** và dùng "khớp-predicate" riêng cho so sánh chéo công cụ, tránh tự-đánh-giá vòng tròn. Chúng tôi cũng **công khai** rằng khi thiếu taint mức bytecode hoặc opcode target, các bản tái hiện SmartShot/VulSEye lùi về dùng *metadata-seeded root-cause slots* (ghi nhận theo từng phát hiện) — một sự đơn giản hóa so với thành phần symbolic-taint / backward-analysis gốc.

| Sự cố | BridgeSentry | ItyFuzz | SmartShot | VulSEye | SmartAxe | GPTScan | XScope |
|-------|-------------|---------|-----------|---------|----------|---------|--------|
| PolyNetwork | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✓ | ○ | ✓/✓ |
| Wormhole | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✓ | ○ | † |
| Ronin | ✓ | ○ | ✓/✓ | ✓/✗ | ✓/✗ | ○ | ✓/✓ |
| Nomad | ✓ | smoke | ✓/✓ | ✓/✗ | ✓/✗ | ✗ (smoke) | ✓/✓ |
| Harmony | ✓ | ○ | ✓/✓ | ✓/✗ | ✓/✗ | ○ | ✓/✓ |
| Multichain | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✗ | ○ | ✓/✓ |
| Socket | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✓ | ○ | † |
| Orbit | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✗ | ○ | ✓/✓ |
| GemPad | ✓ | smoke | ✓/✓ | ✓/✓ | ✓/✗ | ○ | ✓/✓ |
| FEGtoken | ✓ | ○ | ✓/✓ | ✓/✓ | ✓/✗ | ○ | ✓/✓ |
| pGALA | ✓ | smoke | ✓/✓ | ✓/✓ | ✓/✗ | ○ | ✓/✓ |
| Qubit | ✓ | smoke | ✓/✓ | ✓/✓ | ✓/✓ | ✗ (smoke) | ✓/✓ |
| **Detected** | **12/12** | 2/12 (smoke) | 12/12 | 12/12 | 12/12 | 0/2 (smoke) | 10/12 |
| **Khớp-predicate** | n/a | n/a | 12/12 | 9/12 | 4/12 | n/a | 10/12 |
| **TTE trung bình** | <1 ms | smoke | 2,84 s | ≈0 s* | 4,06 s | smoke | det.‡ |

*VulSEye phát ra phát hiện ngay khi kịch bản đầu tiên thực thi (opcode-scan chạy trước vòng fuzz). ‡XScope là bộ phân loại tất định theo từng giao dịch; TTE không định nghĩa theo quy ước. ○ = chưa chạy; † = ngoài phạm vi XScope (Wormhole nguồn Solana, Socket lớp predicate ngoài bộ luật). Ô [BridgeSentry / TTE trung bình từ self_run JSON cần cập nhật trước khi nộp].

Theo tiêu chí **detected**, BridgeSentry và ba bản tái hiện (SmartShot, VulSEye, SmartAxe) đều đạt 12/12, XScope đạt 10/12, smoke test công cụ gốc phát hiện 0–2 ca lấy mẫu. **Vì vậy "detected" đơn thuần không tách biệt được các công cụ động** — điều không bất ngờ, vì các baseline được cấy vào harness thừa hưởng môi trường thực thi đa chuỗi và kịch bản dẫn xuất từ ATG của BridgeSentry. Tín hiệu phân biệt là tiêu chí **khớp-predicate** chặt hơn: SmartShot khớp 12/12 (pool mutable-snapshot đẩy toàn bộ tập mutation kỳ vọng mỗi vòng); XScope 10/12; VulSEye 9/12 (trượt Nomad, Ronin, Harmony nơi opcode-scan bề mặt một pattern khác root cause kỳ vọng); SmartAxe chỉ 4/12. Khoảng trống SmartAxe giàu thông tin nhất: là bộ phân tích **tĩnh**, nó gắn cờ bất thường trên cả 12 hợp đồng (detected=12/12) nhưng chỉ khớp predicate kỳ vọng ở 4, vì 8/12 tái dựng mã hóa hành vi V4 key-compromise **runtime** sau các guard cú pháp còn nguyên vẹn — khoảng trống ngữ nghĩa mà phân tích tĩnh không thể vượt qua nếu không suy luận symbolic trên ranh giới tin cậy. Điều này khớp với tỷ lệ phát hiện 7/16 mà SmartAxe tự báo cáo trên các tấn công tương tự.

**Đóng góp của BridgeSentry nằm ở đâu.** Hai phát hiện đóng khung đóng góp một cách trung thực. (i) **Out of the box**, không baseline nào xử lý được 5 sự cố ngoài chuỗi (Ronin, Harmony, Multichain, Orbit, FEGtoken) đòi hỏi thao túng trạng thái đa chuỗi + relay phối hợp. (ii) Việc các baseline snapshot/directed-graybox đạt phát hiện đầy đủ **chỉ sau khi được tái hiện bên trong harness dual-EVM** của chúng tôi cho thấy môi trường thực thi liên chuỗi và các bất biến dẫn xuất từ LLM — **hai đóng góp lõi của BridgeSentry** — mới là thành phần tạo điều kiện, còn thuật toán dẫn hướng fuzz là yếu tố thứ yếu trên các benchmark này. Chúng tôi **không tuyên bố ưu thế tỷ lệ phát hiện** so với baseline đã trang bị harness; thay vào đó, bằng chứng ủng hộ tuyên bố hẹp và vững hơn: **kết hợp mô hình hóa giao thức bằng LLM với harness đa chuỗi đồng bộ là điều khiến việc phát hiện liên chuỗi per-bridge trở nên khả thi**. BridgeSentry đạt 12/12 trên toàn bộ 240 lần chạy (20/bridge), không có phương sai run-to-run trong kết quả phát hiện.

**Thời gian phát hiện (TTE).** Bộ kiểm tra bất biến đa chuỗi của BridgeSentry gắn cờ vi phạm ở mức **dưới mili-giây** ngay khi một kịch bản từ Module 2 được khởi tạo (TTE trung vị per-bridge 0,25–1,9 ms qua 12 benchmark, 20 lần mỗi cái). Đây là **tính chất kiến trúc** chứ không phải kỷ lục tốc độ fuzz: phát hiện ở Module 3 là *mô phỏng có dẫn hướng* các kịch bản dẫn xuất từ ATG, nên chi phí tìm kiếm được trả ở giai đoạn mô hình hóa LLM (Module 1–2, cỡ vài phút/bridge) thay vì khám phá không gian trạng thái mù. Hệ quả về tính hợp lệ của phát hiện dựa-trên-mô-phỏng được thảo luận ở Mục 6.

### 5.4. RQ2: Nghiên cứu Loại bỏ Thành phần (Ablation Study)

> **[TODO — thí nghiệm CHƯA chạy]** Sweep ablation chưa được thực thi tại thời điểm viết. Các biến thể, hook trong harness, và metric dưới đây đã được đặc tả; bảng kết quả cố ý để placeholder, sẽ điền từ `results/ablation/<variant>/` sau khi sweep ba cấu hình loại bỏ (3 biến thể × 12 bridge × 20 lần chạy, ngân sách 600s). **Không báo cáo số ablation cho tới khi sweep hoàn tất.**

Mỗi biến thể được hiện thực bằng cách tắt thành phần tương ứng trong orchestrator: $^{-SE}$ thay 4 loại bất biến dẫn xuất từ LLM bằng template tổng quát; $^{-RAG}$ thay seed dẫn hướng-tri-thức bằng kịch bản khởi tạo ngẫu nhiên; $^{-Sync}$ chạy hai instance EVM với snapshot độc lập (không đồng bộ). Với mỗi biến thể chúng tôi sẽ báo cáo tỷ lệ phát hiện, TTE trung vị, và FPR qua 20 lần chạy mỗi benchmark.

| Biến thể | Detected | TTE trung vị | FPR (%) |
|----------|------|-----------------|---------|
| BridgeSentry (đầy đủ) | 12/12 | <1 ms | TBD |
| BridgeSentry$^{-SE}$ (bỏ Module 1) | TBD | TBD | TBD |
| BridgeSentry$^{-RAG}$ (bỏ Module 2) | TBD | TBD | TBD |
| BridgeSentry$^{-Sync}$ (bỏ đồng bộ) | TBD | TBD | TBD |

Chúng tôi **dự đoán** (và sẽ kiểm chứng) các xu hướng định tính sau, **nêu như giả thuyết cần kiểm tra chứ không phải kết quả đã đo**: bỏ trích xuất ngữ nghĩa sẽ làm giảm phát hiện và tăng FPR (bất biến tổng quát kém toàn diện và kém chính xác hơn); bỏ RAG sẽ giữ phần nào khả năng phát hiện nhưng tăng thời gian-tới-vi-phạm (fuzzer phải tái khám phá chuỗi tấn công đa bước, ví dụ chuỗi validator-compromise của Ronin); bỏ đồng bộ đa chuỗi sẽ tác động mạnh nhất lên FPR (snapshot độc lập đạt trạng thái không thể xảy ra trong thực thi liên chuỗi nhất quán, sinh vi phạm giả).

### 5.5. RQ3: Độ nhạy Tham số

Chúng tôi **dự kiến** đánh giá độ nhạy của BridgeSentry với ba tham số: số lượng khai thác truy xuất ($k$) trong module RAG, trọng số thưởng waypoint ($\beta$), và ngân sách thời gian ($T$). Cấu hình hiện tại dùng $k=3$, $\beta=0,4$, $T=600$s.

> **[TODO — thí nghiệm CHƯA chạy]** Các sweep độ nhạy ($k$, $\beta$, $T$) chưa được thực thi. Hai biểu đồ độ nhạy trong bản nháp trước chứa tọa độ placeholder minh họa và đã **bị gỡ bỏ** để tránh trình bày dữ liệu chưa đo. Tái lập biểu đồ sau khi chạy sweep trong `results/sensitivity/`: $k \in \{1,3,5,7,10\}$ (giữ $\beta=0,4$, $T=600$s); $\beta \in \{0,1\ldots0,7\}$ với $\alpha+\gamma=1-\beta$ chia đều; $T \in \{60,120,300,600\}$s so với sweep đủ của ItyFuzz. Mỗi điểm: 20 lần chạy × 12 bridge. Cho tới lúc đó, **không nêu số độ nhạy nào**.

Sweep $k$ sẽ xác định điểm bão hòa lợi ích của đa dạng kịch bản; sweep $\beta$ cân bằng khám phá theo coverage ($\beta$ nhỏ) với tìm kiếm theo waypoint ($\beta$ lớn); sweep $T$ đặc trưng hóa cách phát hiện tích lũy theo ngân sách so với baseline đơn chuỗi. Chúng tôi báo cáo các kết quả này trong bản cuối khi sweep tương ứng hoàn tất.

### 5.6. Phân tích Độ phủ Liên chuỗi

Trên harness được đo hiện tại, BridgeSentry thực hiện **XCC_ATG = 66,7%** số cung liên chuỗi liệt kê từ ATG trên benchmark tham chiếu Nomad với kịch bản LLM thật. Con số này **bị giới hạn dưới bởi một hạn chế đo đạc** chứ không phải bởi bản thân quá trình tìm kiếm: việc quy cung liên chuỗi đếm các cung ATG qua trường `contract` của hành động, mà output Module 2 không phải lúc nào cũng điền (chỉ phát ra chữ ký hàm chứ không phải hợp đồng sở hữu), nên một số cung được thực hiện không được tính. Cùng cấu hình trên mock fixtures đạt 99% độ phủ cung — xác nhận khoảng trống nằm ở quy gán (attribution), không phải khám phá. Suy ra hợp đồng sở hữu từ tra cứu nút ATG theo chữ ký hàm dự kiến sẽ thu hồi phần tín dụng thiếu.

> **[TODO — thí nghiệm CHƯA chạy]** Điền so sánh XCC chéo công cụ (XCC_ATG đã sửa quy-gán-contract; XCC_S theo đồ thị gọi hàm Slither cho BridgeSentry và baseline; và phân tách coverage riêng cho ca ngoài chuỗi). Con số 66,7% là XCC_ATG đo trên Nomad từ `results/lab_sweep`; cần mở rộng cho cả 12 bridge và sửa quy gán `touched_edges` (`src/module3_fuzzing/.../fuzz_loop.rs`) trước khi báo cáo XCC_S và so sánh per-tool.

Về mặt định tính, ưu thế độ phủ liên chuỗi mang tính **cấu trúc**: fuzzer đơn chuỗi thực hiện 0% cung qua-relay vì không thể điều khiển thành phần ngoài chuỗi, trong khi BridgeSentry duyệt qua các cung nguồn, relay và đích trong cùng một harness.

---

## 6. Thảo luận (Discussion)

### 6.1. Hạn chế

- **Phụ thuộc chất lượng hiểu code của LLM:** Với hợp đồng bị obfuscate cao hoặc chỉ có bytecode, xây dựng ATG có thể không đầy đủ hoặc không chính xác. Mô hình ngôn ngữ xác suất cho tổng hợp bất biến mang rủi ro ảo giác bất biến. Pipeline xác thực ba giai đoạn giảm rủi ro nhưng không cung cấp đảm bảo soundness hình thức.

- **Phát hiện dựa-trên-mô-phỏng:** Module 3 xác nhận vi phạm bằng *mô phỏng* các kịch bản dẫn xuất từ ATG thay vì khám phá mù trạng thái fork thật. Đây vừa là điểm mạnh (phát hiện gần như tức thời) vừa là hạn chế hợp lệ: một tái dựng quá đơn giản hóa hành vi lỗ hổng có thể làm phồng tỷ lệ phát hiện. Đây là lý do chúng tôi báo cáo thêm tiêu chí khớp-predicate chặt cho baseline.

- **Giới hạn cơ sở tri thức RAG:** Các cuộc tấn công khai thác lớp lỗ hổng không có trong các sự cố lịch sử đã index sẽ nhận được dẫn hướng kịch bản yếu hơn. Mô hình embedding all-MiniLM-L6-v2 là transformer câu mục đích chung và có thể không nắm bắt sắc thái cấu trúc của code Solidity.

- **Chỉ hỗ trợ chuỗi tương thích EVM:** Mở rộng sang cặp chuỗi không đồng nhất (ví dụ: EVM + Solana SVM) yêu cầu kỹ thuật bổ sung đáng kể cho biểu diễn trạng thái và quản lý snapshot.

- **Coupling nhân tạo giữa hai instance chuỗi:** Blockchain thực tế hoạt động bất đồng bộ với sản xuất block độc lập, độ trễ finality biến đổi, và tiềm năng thao túng timestamp do MEV.

- **Độ trễ của giai đoạn mô hình hóa LLM:** Module 1–2 mất cỡ vài phút mỗi bridge; vì Module 3 xác nhận vi phạm bằng mô phỏng kịch bản, chi phí phân tích tổng thể bị chi phối bởi giai đoạn mô hình hóa này chứ không phải khám phá động. Chúng tôi dùng backend open-weight tự host (`gpt-oss-120b` qua NVIDIA NIM), tránh chi phí API theo token nhưng vẫn có độ trễ suy luận. *(TODO — cần xác minh: báo cáo wall-clock và token Module 1–2 đo được nếu có.)*

- **Benchmark hạn chế:** 12 vụ khai thác tương thích EVM, tất cả trên chuỗi EVM. Hiệu suất trên lỗ hổng chuỗi không đồng nhất và zero-day cần đánh giá thêm.

### 6.2. Mối đe dọa với Tính hợp lệ (Threats to Validity)

- **Tính hợp lệ nội bộ:** Lỗi tiềm ẩn trong tái dựng benchmark, giảm thiểu bằng xác minh mỗi tái dựng với hash giao dịch khai thác gốc. Một đe dọa nội bộ căn bản hơn đặc thù cho cơ chế phát hiện của ta: Module 3 xác nhận vi phạm bằng *mô phỏng* kịch bản dẫn xuất từ ATG, nên một tái dựng đơn giản hóa quá mức có thể làm phồng tỷ lệ phát hiện. Giảm thiểu một phần bằng tái dựng từ root cause đã ghi nhận và bằng việc báo cáo tiêu chí khớp-predicate chặt cho baseline. *(TODO — cần đo: FPR và độ đồng thuận liên-người-đánh-giá trên review thủ công các vi phạm báo cáo chưa được đo. Cho hai người đánh giá độc lập gán nhãn rồi báo cáo FPR + Cohen's κ trước khi nộp; **không nêu số FPR cho tới khi đo**.)*

- **Tính hợp lệ thống kê:** Chúng tôi chạy 20 lần lặp độc lập mỗi benchmark cho các công cụ động ngẫu nhiên. Với BridgeSentry, kết quả phát hiện là **tất định** qua 240 lần chạy (12/12 mỗi lần), nên phương sai run-to-run trên metric phát hiện bằng 0 và kiểm định ý nghĩa giữa các công cụ trên "detected" không nhiều thông tin; do đó chúng tôi đóng khung so sánh qua khoảng trống năng lực định tính (độ phủ liên chuỗi out-of-the-box) và tiêu chí khớp-predicate, thay vì kiểm định giả thuyết về tỷ lệ phát hiện. *(TODO: nếu sweep đủ ItyFuzz/GPTScan hoặc sweep ablation tạo ra phân phối không suy biến, bổ sung kiểm định phi tham số Mann-Whitney U / Vargha-Delaney Â₁₂ ở đó.)*

- **Tính hợp lệ bên ngoài:** Benchmark bao phủ 12 cuộc tấn công ghi nhận, tất cả trên chuỗi tương thích EVM. Hiệu suất trên lỗ hổng chưa ghi nhận / zero-day, trên chuỗi không-EVM (ví dụ phía nguồn Solana của Wormhole, vốn coi là ngoài phạm vi), và trên kiến trúc bridge không có trong cơ sở tri thức có thể khác.

- **Tính hợp lệ cấu trúc:** Metric XCC được tính dựa trên ATG do chính BridgeSentry sinh. Để giảm vòng tròn, bản cuối báo cáo XCC_S độc lập (đồ thị gọi hàm Slither) bên cạnh XCC_ATG nội bộ; như nêu ở Mục 5, XCC_ATG hiện 66,7% còn bị hạ thêm bởi hạn chế quy-gán-cung đang được sửa.

### 6.3. Hướng Phát triển Tương lai

- Mở rộng BridgeSentry cho chuỗi không phải EVM (Cosmos IBC, Solana).
- Tích hợp xác minh hình thức cho bất biến đã tổng hợp (bounded model checking, framework EPG).
- So sánh hệ thống các backend LLM — mô hình cỡ GPT-4o sở hữu so với mô hình open-weight tự host đang dùng và các mô hình chuyên code (DeepSeek-Coder-V2, Llama-3) — để đặc trưng hóa đánh đổi giữa chất lượng mô hình hóa, chi phí và khả năng tái lập.
- Áp dụng mô hình embedding đặc thù miền cho module RAG (ví dụ: CodeBERT fine-tune trên Solidity).
- Vòng phản hồi từ lỗ hổng phát hiện được quay lại cơ sở tri thức cho học liên tục.
- Mô phỏng tính không tất định sản xuất block thực tế và sắp xếp lại do MEV trong harness dual-EVM.

---

## 7. Kết luận (Conclusion)

Bài báo này trình bày BridgeSentry, một framework phát hiện lỗ hổng chủ động trong cầu nối liên chuỗi kết hợp trích xuất ngữ nghĩa dựa trên LLM, sinh kịch bản tấn công tăng cường truy xuất, và fuzzing đa chuỗi đồng bộ. Bằng cách điều chỉnh hình thức Đồ thị Chuyển đổi Nguyên tử [27] để mô hình hóa bất biến giao thức bridge và dùng tri thức khai thác lịch sử để dẫn hướng sinh kịch bản tới vùng lỗ hổng giá trị cao, BridgeSentry đạt được **cả 12 vụ khai thác thực tế** được tái dựng qua 240 lần chạy (20/benchmark), bao gồm 5 sự cố key-compromise ngoài chuỗi mà không baseline nào phát hiện được out-of-the-box.

Bằng chứng ủng hộ một tuyên bố **cố ý hẹp**: thành phần tạo điều kiện là harness đa chuỗi đồng bộ và các bất biến dẫn xuất từ LLM, chứ không phải một heuristic dẫn hướng fuzz cụ thể. Chúng tôi chứng minh trực tiếp điều này — khi các baseline snapshot và directed-graybox được tái hiện *bên trong* cùng harness đa chuỗi, chúng cũng đạt phát hiện đầy đủ, và các công cụ chỉ tách biệt theo tiêu chí khớp-predicate chặt hơn (SmartShot 12/12, XScope 10/12, VulSEye 9/12, SmartAxe 4/12), với khoảng trống của bộ phân tích tĩnh tập trung ở các ca key-compromise runtime mà phân tích mức nguồn không giải được. Vì vậy chúng tôi **không tuyên bố ưu thế tỷ lệ phát hiện** so với baseline được tái-trang-bị mô hình hóa liên chuỗi; chúng tôi tuyên bố rằng **kết hợp mô hình hóa giao thức bằng LLM với harness đa chuỗi đồng bộ là điều khiến việc phát hiện liên chuỗi per-bridge trở nên khả thi** — một năng lực vắng mặt ở mọi công cụ ở dạng công bố của nó.

Đánh giá hiện tại giới hạn ở chuỗi tương thích EVM và benchmark 12 vụ khai thác, cơ chế phát hiện là dựa-trên-mô-phỏng chứ không phải fuzzing trạng thái-trực-tiếp đầy đủ, và các nghiên cứu ablation + độ nhạy tham số còn phải chạy; mở rộng sang kiến trúc chuỗi không đồng nhất, tích hợp xác minh bất biến hình thức, và hoàn tất sweep ablation là các bước tiếp theo ưu tiên.

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
