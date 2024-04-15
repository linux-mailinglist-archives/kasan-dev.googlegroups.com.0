Return-Path: <kasan-dev+bncBCF5XGNWYQBRBV7D6WYAMGQE6ZSNCKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 00FCF8A59E8
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Apr 2024 20:28:41 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-43665d8cc08sf100841cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Apr 2024 11:28:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713205719; cv=pass;
        d=google.com; s=arc-20160816;
        b=SrLJKk4egJhzM5kMsAYelZ7Nt4JmkQbTksJ/xIq0y6zbDuz4YPK44tgaPLVoOe+fA/
         QuElgN1ag4Y9z1jkYwhylziDXUnjHF8miBxtbRMkQXJtx0zcGesT/xwBw/ARjuSrwzAN
         7fn7ZqsOv25sDnJmtfHNIxrtNXOkiQoNjsW/OE54FqCfN+zbIBdbGteaZC2gHag8ZB0t
         x0FdNHFIELC1OaN9TB2CETzHdOlH5ZsPmV0JbnQm789kFkITWkAmM4ZWRq46///oYNeF
         SqG+5tqO7xGi2bWZznNDwe5kXqIs8TnPHXnMywRN07W2EhH2tmYxaLJ9wY0JWbv3aX/o
         R+BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bee4spjWb5V3ZjM74jqrXciJYW0nDFRcAe8V1sTf8qI=;
        fh=t7zgUIulSiXh8MrFFxRwU1cdYaHv0G14+/5PSJ1NHNM=;
        b=TpHY+c4h+3gVIipC0x6USw5XmEKWENApeliK9esDO25b5z3afOYkoTo3H5CufjSiao
         JHtqWaciY/Er+ecvQkKnlZh7L7Yow8P57kmEcGB3u6fG8canLByNTrwi/s07knCP0Y/n
         WqVqU+rCvuWPwc8dCUZc5VqLuBHsn/hcoV/YS/pSQvJJDdqeJPmq/pwLH47W44NcXHj4
         3RmorS/qVhkx4YFuibgrzUTcRPVYOEVvh0M3aaERfAUvuQmj04dLHMNG/DUKv9o/Nhb2
         oJZOo5+mUni2KR9vNpeRukM/Jcjyp2YbkRqfPK0fy/eUtDTkeWaLksCrvYilLZcN953T
         6Teg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WYLvOaHI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713205719; x=1713810519; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bee4spjWb5V3ZjM74jqrXciJYW0nDFRcAe8V1sTf8qI=;
        b=u/8QJMoyNQPEsFefynt2zRuAQDqWfQZP/d17ruLfoY6NztkVkt49lryBH65zbtZRcR
         5riI3hOtMfWiH83b3dp7BchrmSFYmIii5Fuvo7pYrLWhOgLMTUCYVt6n01a7kemdFdh2
         7Sdc/9E84yhJDXq+GSPVIVFk6Kq1nUwC7tQ4NpAtFKUqYfqk16kH9wZ0hg5IMiyox2X4
         JD3jxBqqRGt4pdfb8/mV93POPrjpBskWTeVzSFSD4k5k9+N+UTnrHxUG7LiQgOBn1Kn7
         +2jMQ6AhLLY2UijNRPI21o6OLwxJ0x1oxNfAnirdEsDVBJGkd6EmHnfXOXadShi7DUW9
         bs9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713205719; x=1713810519;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bee4spjWb5V3ZjM74jqrXciJYW0nDFRcAe8V1sTf8qI=;
        b=iUmVoHoxG/vCvc2hNwPqCkUpNDj85F5lFLNPyRR+MgPnjveqGGTPyt0QQAkYh2H5fo
         CpMR6y8bhqVPxQEcPPiiLB5dcraVDC33ZuWPepigto1sJvCMyribtvmPEDoTW0D9+jLX
         ZJdGpabr8WQ7pfxh7+Jqw5VXCzVHdCzFq15yL/s1Z/ZN45nGpF1+UdqQNNANiNNmPA3F
         tUgqv7dWEuW3J2BuAg7yrnkOxvLlcyfjaSOHrz8uJ4BSHIeha8baM97m1kd9lGFHjQ0+
         vzqgkp5c8lEB3fJuQ9zIvnS5VN1Ow96uC0lj+6xSXmueUHiQSXuF0W0A5fS4zr0ry+tW
         40dA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXppJCo4+4YFR4Re+/xj7LLlmlH/UuHRY2pHw2tzhg0UrLWbTy297ihKCiAjszQQllCaVKZD7R/OzGD+zxRKLQKc1Ktvy5hGg==
X-Gm-Message-State: AOJu0Yw2KTJUYYD1UHmoTdsSeUR5RUMMki/iB2E+l0HQ990/0oNys1GT
	Z5wEPsjgJxpmaxc2DKSgbVwZWZ6SXMZgo+FfPy7PrJT5/ApnWnYp
X-Google-Smtp-Source: AGHT+IGq7znJpilsaWwpVZ9e1UwMhG1mHkLNFPNHZuHtVMGZA+7QwDnccSOcxngsqIq6DOClvGYqdQ==
X-Received: by 2002:ac8:5f13:0:b0:434:98e4:e1ed with SMTP id x19-20020ac85f13000000b0043498e4e1edmr16514qta.19.1713205719561;
        Mon, 15 Apr 2024 11:28:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:190c:b0:436:a38b:7027 with SMTP id
 w12-20020a05622a190c00b00436a38b7027ls3939683qtc.0.-pod-prod-06-us; Mon, 15
 Apr 2024 11:28:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqq9Bz1wtiPVLq8VN22PVehPRvmv8xstFWnVAEBsFouSxcQ3MO34jVZ6/fBvUXiHIEvV4pAVrlRQLjIv/+LUT0gDKomRE/a/sadQ==
X-Received: by 2002:a05:620a:1710:b0:78d:5ef2:cdae with SMTP id az16-20020a05620a171000b0078d5ef2cdaemr14501772qkb.44.1713205718635;
        Mon, 15 Apr 2024 11:28:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713205718; cv=none;
        d=google.com; s=arc-20160816;
        b=DNUL7WErE6g1VIgAZml0s44HEPHEEihYf40+UTKC57D4mJhJQlq+SU4wSOdWMtT/bl
         jAcw5BNNLcYVdv4ukDWt4TLzRgmRplwc3/3NfoiLVKaKpdWXiWsIaO82B4mS5jOGl6tp
         xEM4aZEoPtGUQR6K1ekFlxC0JgUKO1PempKGh3le2KSvMCW26z/8mZZ/v/2mH+U1jAnf
         x1ggSARQt2UOM5JQCna7SmpTR5aT/cnLnaqff/rC5Jv8T3YVedF+3rf2mjGVAgzimer+
         +zpQDguNc0nJBWJYC8bOH9MgARpfkb3BRbWPQnWLZt/FoKhoVGqqi0CXjupTb0iC0PF1
         adGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=yAq4RH8QyUKSZD7HeQ0W2c2SC+MgWA2yhvwhd1FAErE=;
        fh=hJinJqEog08lt5CQFudpiXQuuoHjjGoWL+dKbXuuhCU=;
        b=UfjxrQSM5U4Tv8M8ztllcq/em8eDlxfeL4FKIW6upsY/Cw5AoyAnFpoSesspaJiKpd
         Ij8jMhtr++mf3yMsLcPUlR0F/BrbWDS+WKZ1BtXt79ylY+N0BXI1ZqdtfiIdj3vUOmPr
         FI97H2NHPkyC396gtPIuMmMbxop5hGiNQ0t47ryznf2uEOQaIOvqo60FvvA+naUsgcbE
         P72jiSymwb2Whl+dSHXxQNgiitUCEa/H4NdLBB9dMMzgBXVAEG/X7p4alBPY/5KaOeyK
         al0PVgK6I/DY/lejGSzUz4Gev+Xq9zjrnT4yBhwDkFQyF/59qNcPgWuVRgjikdYP9LfP
         U3Tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WYLvOaHI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id ra19-20020a05620a8c9300b0078eddf5584esi260333qkn.2.2024.04.15.11.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Apr 2024 11:28:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2a559928f46so1994249a91.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Apr 2024 11:28:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUSWFAnPZgiNj5PsD+v3mhAsZEsFjEkZRiu2L4SgyYlf7wMuJY45r6Z0BYNO/h6RXqBq7DsAqeUQmXRIpWbgR8GFs0iI7JkHI5Exw==
X-Received: by 2002:a17:90a:a014:b0:2a2:37ed:24d5 with SMTP id q20-20020a17090aa01400b002a237ed24d5mr9504791pjp.2.1713205717610;
        Mon, 15 Apr 2024 11:28:37 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id o7-20020a17090a3d4700b002aa783c7749sm225542pjf.41.2024.04.15.11.28.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Apr 2024 11:28:37 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] ubsan: Add awareness of signed integer overflow traps
Date: Mon, 15 Apr 2024 11:28:35 -0700
Message-Id: <20240415182832.work.932-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2297; i=keescook@chromium.org;
 h=from:subject:message-id; bh=4IaXarYUXpxYCg+9pmqyG/50QxJWM9J7LtrSTXLIMJA=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmHXHTHDcH/rU4DwAuIfF+PqCgsKiEy9TvwjM08
 XaKWEaXez6JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZh1x0wAKCRCJcvTf3G3A
 Jl3xD/45m2S6t9LECpdwfjbODqtOouLN0wH8zb51Op56fbm9xeMQ7e80mdvP9yjErlwPLyih6Nq
 WfX0zqyYp/Gw0CjTr1zZjJogFYt4k333uYlpI6JCqDJhZllXGNRInNm/dGGBADxaV7X0Mco9ATn
 u1gG/Q44QaBb2Knh1jm/NJ0fp1SdQe5NlYnx7lGJ4CpDwrugHDoxhJSEMyuW4IVcfMEENgEm3dy
 VvCXyvJlBwu7CbYMiP7RQP/n8libLaaZGbEbuf1NvtUdTBh5VSe+ZHyijtjWHzd/6idddE9Lhze
 Eu3oEPod5bbwDi/hBLQGpUNs2hdz2cryApPLcojSwYjOFxey2dzxr7bXv3SPXhXwQikMYB8nIKt
 DhLJgg9T+HsQyPnWVR9a3eTKSvJHKlzrGEaGGLiruPfM2CTPaWNnjpjSCw3xLVS/OprkO8xYwCY
 +JDjW4Yz4coVscDJMVx8JtEpxa3a3XefNYfvSlSBLpe0VUkkuO77Des8sdKZ5H2kVBr1YC7RVsu
 7zd6Lwv25OlcbntxMxul7cqG8NL8jo1CYaIIly768LWa0eDPEWB5VWTbErLWxYnZ65TmBzCUdvL
 YTAAneczLiTe+5u0Ga/AQUDykSyQPvWgaEpnR3boeAtTqqqgyFPlxN33mThPUwoh6qMbGBa8XEk
 E/kf3ER sCidHZYA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=WYLvOaHI;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On arm64, UBSAN traps can be decoded from the trap instruction. Add the
add, sub, and mul overflow trap codes now that CONFIG_UBSAN_SIGNED_WRAP
exists. Seen under clang 19:

  Internal error: UBSAN: unrecognized failure code: 00000000f2005515 [#1] PREEMPT SMP

Reported-by: Nathan Chancellor <nathan@kernel.org>
Closes: https://lore.kernel.org/lkml/20240411-fix-ubsan-in-hardening-config-v1-0-e0177c80ffaa@kernel.org
Fixes: 557f8c582a9b ("ubsan: Reintroduce signed overflow sanitizer")
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Justin Stitt <justinstitt@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/ubsan.c | 18 ++++++++++++++++--
 1 file changed, 16 insertions(+), 2 deletions(-)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index 5fc107f61934..ad32beb8c058 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -44,9 +44,10 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
 	case ubsan_shift_out_of_bounds:
 		return "UBSAN: shift out of bounds";
 #endif
-#ifdef CONFIG_UBSAN_DIV_ZERO
+#if defined(CONFIG_UBSAN_DIV_ZERO) || defined(CONFIG_UBSAN_SIGNED_INTEGER_WRAP)
 	/*
-	 * SanitizerKind::IntegerDivideByZero emits
+	 * SanitizerKind::IntegerDivideByZero and
+	 * SanitizerKind::SignedIntegerOverflow emit
 	 * SanitizerHandler::DivremOverflow.
 	 */
 	case ubsan_divrem_overflow:
@@ -77,6 +78,19 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
 		return "UBSAN: alignment assumption";
 	case ubsan_type_mismatch:
 		return "UBSAN: type mismatch";
+#endif
+#ifdef CONFIG_UBSAN_SIGNED_INTEGER_WRAP
+	/*
+	 * SanitizerKind::SignedIntegerOverflow emits
+	 * SanitizerHandler::AddOverflow, SanitizerHandler::SubOverflow,
+	 * or SanitizerHandler::MulOverflow.
+	 */
+	case ubsan_add_overflow:
+		return "UBSAN: integer addition overflow";
+	case ubsan_sub_overflow:
+		return "UBSAN: integer subtraction overflow";
+	case ubsan_mul_overflow:
+		return "UBSAN: integer multiplication overflow";
 #endif
 	default:
 		return "UBSAN: unrecognized failure code";
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240415182832.work.932-kees%40kernel.org.
