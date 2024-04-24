Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6XGUSYQMGQELOIF7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 645468B0FCB
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 18:29:48 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-36b3738efadsf698185ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 09:29:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713976187; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNq9ifYXv9V21sOWb6D5XCMMn/T8jmB3Vg9ClHI2MVaQlLb/4FAB1gQnalxV8dh1A7
         86uOR6Qlc2SaCSl/BkQn6SHY369TAsHo1DTcLh8ZhJyiCiLOS+4eZkyMxu4Ushdhrhgz
         kbwVVy0vAHKDCJu5K1Ph/+TcFBBTCPnOxjOagnAnyJhaEpNb5cqn8E9N/AwFsdlBLjAD
         Ph/aGAPryl1O22U/tDhLFY7w/VsjwVmUpLlA3QYSEqp2ha0TAEwO2sTJPKtVf/8kaRLL
         74teBEyGxTxH0D/F75bJ8TsMlwCKB8LoEYpOtJA3Vaxs+zm2qaNUccgoAiu7tsNSN7rn
         ukug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vPbygcIy9DGMTUqexMImVZj8aI8kSc61C1agWfPBz1U=;
        fh=WGTdD84gF+WbMp9CPFp6bn3Js3KNv5GtrkkiFvrYJ48=;
        b=fISZyP/phntxYyRbYXjpwoekSHl+AU9pfLHsxHJHnUUNHHPxQxnfCyZShEsaNjyBbd
         /xM/irVariMZ12O8fxOnqj07WHd2S7nlb5qx9yPkbzZmMU/AapPM5CoDHiAX+cFJONKW
         IHrHcw1kzvZtYoNVcbP2UXizUtNsHQinncWXHCZPkjICQKFdLWv0JUj9KENbgT1ZZJZT
         K8ZZI2RQVMa5a3T1Rvs4+U+23ETzXmZ5ilWcRtGiSqshQ8f6f2NEcM82X1sGClcIJuQY
         YS/dGKSSv4RrTvjlIy5ZXd7k+gnOfR/xu1mHNBMvh7SRwnvO7LI9tl0HX7YlxQafaWv+
         nXIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ES8nKK2V;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713976187; x=1714580987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vPbygcIy9DGMTUqexMImVZj8aI8kSc61C1agWfPBz1U=;
        b=U6nGms4FBuKtURI/h6Bm8j7OLkBZ9xFlZpdIhXUsi2FaTeICPr/e4P4coUbJVy1aRP
         6uP6sFIwuuD8wuR/v3tnjmhSakZyConhrj6OS+mnlBS03B/tpSYmeA0DzicvHX0YUYDx
         XyBHYjcZoXyCMX7zht7fWSiyFirPpeF5Hy2Ax+Qxsih40j+HKFr6ISWmZcbzoSq0XT2u
         3jyASZiT6hLyXJ/bjxegTwOLXkaESeHJcEbB0Rz4A51QNmLPFqv4AGF688RcZtJ18Gwc
         cLzwt1syg2IGe3k8Iw6TMjCPEJjBr0/ATnzaC76EPE4SWjRi9H3e99333FVm97Tc+wME
         pfXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713976187; x=1714580987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vPbygcIy9DGMTUqexMImVZj8aI8kSc61C1agWfPBz1U=;
        b=LNM5bOroUJKG5ML+Zmx7CfE1lQhWxolg20QmkIIaE6eildv7j2N7nvzc/yqgEiPMqK
         hbDLFUguJZgLAtQVknq+iJMBdZWPYIZU6bAqUrUBKOv2ZPy5CalVAHTE4aAwSNoznIeM
         aoQnYgDMlJrFBKwuSfCdtZQxAoP+xqelx8Nz0LFiumWiea3hnf8IDLyCWD9L8A2+WVAH
         9OlogKtL7iD8+0ASH3gPlA/JGyobqt/ZhoWYw3U7VotlBRQzuh44imkGO1iF5X8Yee+0
         bfGX9hJ7c2QQ8R286p6sWt0zvUoypyM3KNJyUUPZ+kU4M0i1IPnI3DgqVWxl9zaBoloH
         mK9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWakkc+ebQWdXbhvssvfR+oJl/cjGeLXmKdgHJaHO7HjcMiER3CCEnsNcvaGcRwdfQsMOr27mWzrSpV65rlypYhZJbq10YUGw==
X-Gm-Message-State: AOJu0YxbNbWqltKxxYlcHFRDyOuLGyK8Nykrd9LBUR9JQvywriTRVp95
	HFFADuLRcYU3tGGnSyLuCk41I+YkTea+kbBPhdO/tKBCWzCm18E1
X-Google-Smtp-Source: AGHT+IHWFGAV3KDkMFNRf6OWeUKk2AFj/yyicoBFky4eEkcSKOSmwDXYq1N/q7f+PrYWKV+k+wsdww==
X-Received: by 2002:a92:ca06:0:b0:36a:b4f2:ac17 with SMTP id j6-20020a92ca06000000b0036ab4f2ac17mr3740083ils.8.1713976187033;
        Wed, 24 Apr 2024 09:29:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17c5:b0:36b:300b:3a61 with SMTP id
 e9e14a558f8ab-36c29d8837bls543665ab.0.-pod-prod-03-us; Wed, 24 Apr 2024
 09:29:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxJYmUPrsgdOklzmi47NALxxnzHz1BAeQ52vaVMX1FW698RkZHVlSa/P/NQanRNaSOFdIxIVfyaUFvCPMwSoTlxbC9Te0NCg8cjA==
X-Received: by 2002:a05:6602:1dd2:b0:7d9:a53a:c9bc with SMTP id hk18-20020a0566021dd200b007d9a53ac9bcmr2808523iob.10.1713976186163;
        Wed, 24 Apr 2024 09:29:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713976186; cv=none;
        d=google.com; s=arc-20160816;
        b=FY48Gw0bA/nXJhUJkt86h1UPZQThPzk0CnS/xj3KS9ZUq7FwEiT4yMUKZ+I+DxLEzd
         DoPY1DjiXUZjvrwlbzk0K1BdjtWVpDcDlwMKpdKHHH9QRo61cKU6c4Xv0xxB66aU2zja
         s3JdxXQ1/Aci1SzL1avKlyVF9YujAntxLevrx+SzXc0zFkMLHa+0sC2E1wD4SDIMPdF/
         gazGZ+lpNfEMI9J9bPJbW1WaPUInNlt+WAhBF6wCJgjY+WIdwJyyUjO1jKAj9OpwsB9Q
         rzlv5FvkbMpX4L5n8kQtXl48SVPN9qWVKHTBzZqDeRPa2H2QCM/OvRf1so4Z3aA1Q8dd
         gM7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b+9qworkCYA/dEd2E6NqOCyfCT0RGwXnd8JnfZdAXT8=;
        fh=o0imiaenrEkcRBkMN1N5+aFGley5ohaF3JkpWmjoGH0=;
        b=0u0mLRGqI1oQuBO3NzMLiU+8eYRpqq4BlCu9uYMb7t9zHuL7r8e4STVW84elJZ4Pb9
         CgeYTm6dL5qcVCzP4eY4ItHPIj7Rzp4Wufrr/Km4lRRMPAGnSL5oOfymDkV8x0O1qu+T
         8z09klGngoKiHvWSC79Oz/kWFqgkLbTRIjIXDdmN0tpbg8uK8/YT3HFQTBovVR3yBsAO
         E4nfrlvv4XqShHzN2R/AJyDIgVWpkhAAbhoPNczx0BwKkF/khpKY2Dlil1ZBbxitO30q
         XZOu8/6DAkfNX+ieL7MfR++svT1HijpYnp0j/+aFH5feBz89/I3u7Gxpa+RJlF1CzvDX
         dwow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ES8nKK2V;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id ke3-20020a056638a60300b00484954df3a1si1218554jab.0.2024.04.24.09.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 09:29:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-2ac1674d890so81327a91.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 09:29:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6gZQSEtwTWdMwOOTJtHWOjwLo/8jauQ18PGLsE6h4V55u7ijrzVQNNKK3bo3gOBMubH4rUfcZNQlSmfcFPsa4fsHB93lS/JK57g==
X-Received: by 2002:a17:90b:1b51:b0:2a5:12dc:1609 with SMTP id nv17-20020a17090b1b5100b002a512dc1609mr2715263pjb.39.1713976185447;
        Wed, 24 Apr 2024 09:29:45 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id e5-20020a17090a4a0500b002a269828bb8sm11388846pjh.40.2024.04.24.09.29.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 09:29:44 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ubsan: Avoid i386 UBSAN handler crashes with Clang
Date: Wed, 24 Apr 2024 09:29:43 -0700
Message-Id: <20240424162942.work.341-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3634; i=keescook@chromium.org;
 h=from:subject:message-id; bh=8+7ximJNE3huew93u7w7rKw7nI9gr+b5vuxXFU9vyvI=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmKTN3dyNIMp+O7q+bYM3wOmd9O8k5WMCGmgktL
 WF4UQsY51yJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZikzdwAKCRCJcvTf3G3A
 JosuD/4l0IQyly+v15MjXYIsDPKX4IUkiRHY6oGlP49ZY8fFeuSdWJ3yArBs2w2o0pI0Xz7TeNc
 xcw5Xe5jnSvWWVDiu6qp0yW4tCOvqM6yNZrf7rn7xlvHjmJ30bKKPw5RC0sNlkxt5V/nPLVUoER
 /k68qektDitJ9fBrTUwESO45p5eEMf02JAGnZEWFiKRx1VLYS9p4eLuHsegE2iV6NBeoQoWbjwp
 ogvJwyBtZbApgP1wO3TnY6fU2f7t91bS2KKqv7oaFXxiR1VIoHLnSjMD7E3juz/7XvDWRkdH9aV
 MKVZIOoiX6ab+ck7wlBvhVEUqJwGboQ9DeZ75AY2+SueBm/5ZfdIL9JRYMoCtSbMxPi+QLCfc9Z
 gSNMRitoL7+KpQFNircO1i/MsOr1So2bnjiGk+JJv/I9QbAI22XZRCVwFebXoc98lAhooaByiYV
 m+BDlmdQC9F8Bo5Qu7GUHHYcBQvrhI61ZNlcRSC2RpmDi2/grWEZCJws+Mn558xoHd9PLeX0sQK
 l7hQO4NRBwXVkglPNiVSiT6b/ZKBR7+ys46WMhRmOtxhm0JQhJGo5LSfrCa3HRahV8uw335O4P4
 uyRt7a8PDmyCLIOM97cCwO8uPgqPud0XMPyhHaEpnusRbh5Icubm3EELeU/K+gvYCId554loEZ6
 /UXvy36 I133L96A==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ES8nKK2V;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031
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

When generating Runtime Calls, Clang doesn't respect the -mregparm=3
option used on i386. Hopefully this will be fixed correctly in Clang 19:
https://github.com/llvm/llvm-project/pull/89707
but we need to fix this for earlier Clang versions today. Force the
calling convention to use non-register arguments.

Reported-by: ernsteiswuerfel
Closes: https://github.com/KSPP/linux/issues/350
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Bill Wendling <morbo@google.com>
Cc: Justin Stitt <justinstitt@google.com>
Cc: llvm@lists.linux.dev
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
 1 file changed, 27 insertions(+), 14 deletions(-)

diff --git a/lib/ubsan.h b/lib/ubsan.h
index 50ef50811b7c..978828f6099d 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,19 +124,32 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
-void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_negate_overflow(void *_data, void *old_val);
-void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
-void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
-void __ubsan_handle_out_of_bounds(void *_data, void *index);
-void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_builtin_unreachable(void *_data);
-void __ubsan_handle_load_invalid_value(void *_data, void *val);
-void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
-					 unsigned long align,
-					 unsigned long offset);
+/*
+ * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
+ * option used on i386. Hopefully this will be fixed correctly in Clang 19:
+ * https://github.com/llvm/llvm-project/pull/89707
+ * but we need to fix this for earlier Clang versions today. Force the
+ * calling convention to use non-register arguments.
+ */
+#if defined(__clang__) && defined(CONFIG_X86_32)
+# define ubsan_linkage asmlinkage
+#else
+# define ubsan_linkage /**/
+#endif
+
+void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
+void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
+void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
+void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
+void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
+void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
+void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
+						       unsigned long align,
+						       unsigned long offset);
 
 #endif
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240424162942.work.341-kees%40kernel.org.
