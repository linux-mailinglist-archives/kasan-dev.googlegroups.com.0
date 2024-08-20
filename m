Return-Path: <kasan-dev+bncBDI7FD5TRANRBRPGSO3AMGQEGJMNXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 85142958EC6
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:49:27 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-27061a48e70sf2441959fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:49:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183366; cv=pass;
        d=google.com; s=arc-20160816;
        b=KCxkIIgm2u8Ksy0euTHV/tqREq9rp1rkmyMWlDpHJnwBjVQq/9k5tzCauqdvTATTac
         /5osH0gEj7BnUnEbk6sGXEOmwqU7cN/CxX/98aLQbWhBp40/vP+ybIiHGFVUhywUCot4
         p8ShRmIYRIS0vWg9GIKBtO9DgKnDwUUdze5N4ErEjm48Jj98wUGGc0zKpflMzKq8MSUJ
         2SSDFhgOBXn5Lg3w310SnJzxXQqTtFwJs4vXOS2hF+UJBDIQINXFfRKnEb4YF02/GTpW
         Qyqr//kezsRP4OjCR6YIplvQHWl22Xe6UBvlTTKIIgcoMzFOoCQjpNBhAwD8m4kuzDpd
         g9Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=aNZWyoMgBiEUC9E4GRgb4MFNTo5+GD7qUM6QSTgT07Y=;
        fh=TduQPl7Lf5QdwPC4V5eVGpmdvtI5CgBYOimAIj5uaGw=;
        b=Wk5qcA7ppAgqPW+UMeuybXQjnBv+FS8uer4kbGQce/Ze5Up+O/FTmgsF7zNheZXA+G
         DsGcdimKDjbmCnQALH26peKXsZj0mvBhHK+YgcJb2KvIwsmMcZkfAWC7r/N+Mq9DYoXd
         /69gGLKGMEExuIPkQazbAPooumG4QwmEUEJeZzc1rZJqMkv2oUnZXTE11UXLesWvnb4k
         rExaRVNJjaXlCXjOS7u4zm4wHSUUZCAZdCRcgVK05ble7eJvE1lfeQLwA+FVQpseq++Q
         H0PlLyaL/p9RWHA+K5kRLWwYRq3DOnbQ40pfjKiucI8zJMloFF4mN+Pqg2DSGjPL2k8R
         7OkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GtoSqXgg;
       spf=pass (google.com: domain of 3rppezgckcxsllztqdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3RPPEZgcKCXsllZtqdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183366; x=1724788166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aNZWyoMgBiEUC9E4GRgb4MFNTo5+GD7qUM6QSTgT07Y=;
        b=Mf8KsOC0H4XjjfYJ0U0wQ1vbkuszjXKKKiEuETIFNqmZP5lNx2tB2beuzOXioevbdS
         TTLkE9j9SEaHEC1uKL8kVj3VqjhnIvpdw8a9juW9MTbx6jgn4fv9Ol5t850TFl7O41UZ
         xB4hi751m6B7Zv9qQn82wq5AF4MmFK9cOh0rBSUaatRFdTZogbw0zaFchLkOEDN0dJNT
         3FBekRHB9gO5F6ihEIegdMKrLLn5Wv1fI8WT9iWhnxibd/wU0hMvHGHn66xzw6eCvct7
         gZyokHrwbkLuv70fldKeVCh/1VuOvaa2XyJ6n1vax5t7uBUGCEVROQWZIacPgQaYxK8V
         IE4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183366; x=1724788166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aNZWyoMgBiEUC9E4GRgb4MFNTo5+GD7qUM6QSTgT07Y=;
        b=wl5UykNh32V4Mq6o3sq+T7LygYzfUHAqinlyrTM7w6s0JxcFpjzUeX/9SfibvWsSmt
         kNhdtNtZlNNNdssJ5F5GnsmHbt4csLcje4/gfcgoriKdEXcbEUMmzXlwNubzlERHdoKe
         HI+hzmJLHzdU3XuicFkSFRWpH5tSSIOlboE/KGfOs8CcxjolKghrlG+ZjHDfiJuD894z
         b5Wg9A8LNwge9JXo0L/78Qeuioivqi32V+vdNCykpMt2Bai2+RubR0Kr24Jj9CD7Yfyx
         nojNNEwIOu9p5j3UMEnhIGsEixrjQ5J8Yjs/27kqFm85JZeHqysAWfTFyzwD5wTXXI/q
         vI2g==
X-Forwarded-Encrypted: i=2; AJvYcCXPTOg63yrAyVkZwwMoqpZ9A1RXCdVtfCCPiLuaph6zZV7WiPNMpHP6RoPz+fD29x8zDC6jXw==@lfdr.de
X-Gm-Message-State: AOJu0YwW0GACJjkpVgJJMZGFGaRwVWL+HzfBBmN5m3fSuBEUrzyzpjGV
	IDxwmre3JEDMtChZmCk5p23h/RKXgjH5RTQbul8F37F8Q8o8ZpSm
X-Google-Smtp-Source: AGHT+IHwZoEVyTc+e7sy0/4xAFRo+cJM6B8Ypg43/K6QV29UepN35osvqtEvWWtRsaGEwhmZDZqJNw==
X-Received: by 2002:a05:6870:88a7:b0:261:acf:e964 with SMTP id 586e51a60fabf-2701c575253mr17193391fac.48.1724183366072;
        Tue, 20 Aug 2024 12:49:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:7509:b0:254:6df2:beae with SMTP id
 586e51a60fabf-26ffeed9692ls8252514fac.0.-pod-prod-04-us; Tue, 20 Aug 2024
 12:49:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVU8JE31zu5lKCHqKhlBPejQUN3mNmfGOMP+vvk4ccYSOgC8iOUJ3txUYtzkxpDlmm/9zEurwbAgT4=@googlegroups.com
X-Received: by 2002:a05:6870:71c3:b0:261:86d:89e2 with SMTP id 586e51a60fabf-2701c516d37mr17452035fac.36.1724183365298;
        Tue, 20 Aug 2024 12:49:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183365; cv=none;
        d=google.com; s=arc-20160816;
        b=NUd08mX1dThF0iivUG5c610HwexNd+SH1fdoMeR4Crpa4bmBGtYGCxRfXi3AsdvD8E
         qY+nDenAKFGMGY9ast7LjGFmp4g/lU2WkW4jCBwfWF4HOKjGx2xBT9S64UjPjN+/AkrI
         6tYKmvVHuxUKeGK+T7iKQqtm8vLYYZge8G7fpKLJpu8qAhhcr4WARAyWpbbtYQTvyVU4
         Rk7/Be5irtsoNaODJAov+M2SGC9gkc2/nH3MHHoKxmq6x/9Y+Lhn0IE6jRmWeW/Lced8
         9xBYsSFHPxkKJiIfPNV1UPs+TX6usEDRx9nZ/twLMEP7JiTSF+v3Bcd0kq/QW6hJSv3L
         JR0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jYOQ4ic50oYuK2FpEcKGnGi9zqTDnUtCD7+2BoOkpco=;
        fh=Zyz05c/leNExm3X+c32eHj9YYvxT2Al8WnpS0sO2zAU=;
        b=gwTpWboAwoiGyVSY03TjD0icIhb1bGObzFawxVev23VVC13mfh6TMqaf851Rgnx5Yf
         iIfaPbX+aZZEgCZsiCR22lcTWiFirAmaxvea4N9pSkETiVlRxnER4DgirBooF/s1FjAG
         0q5/P4HE8AT5Bf8gvQm7YeOL3g2KPkn3IDgxeXdsvHv1gKSkuDz58ky7boMpEkBn+2+P
         Sgo8iJILw5AvQ1KW5LqWCbTCZn2yjS3jptvTni9XIzuvGPL1ycx8JoRXZyHzP2uVpIf6
         /oE9pnU0aX53iCDJwnlCZIULFQNOCpc0g7jOQ6tJtIgbKT2m1wTnZkEhCgl6gJQntSqy
         No/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GtoSqXgg;
       spf=pass (google.com: domain of 3rppezgckcxsllztqdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3RPPEZgcKCXsllZtqdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-70ca6622aa6si533142a34.3.2024.08.20.12.49.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:49:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rppezgckcxsllztqdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6b1adbdbec9so89171907b3.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:49:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2FcY3l2xBzw0rd00328QZ3jByX0SkHJsDNoxIhYRFED/1HaUNDe40f0wqnBA3J++PCJXNEBUpQI8=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:340a:b0:6ad:351e:a9d0 with SMTP
 id 00721157ae682-6c09c5982aamr6117b3.3.1724183364571; Tue, 20 Aug 2024
 12:49:24 -0700 (PDT)
Date: Tue, 20 Aug 2024 19:48:58 +0000
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240820194910.187826-4-mmaurer@google.com>
Subject: [PATCH v4 3/4] kbuild: rust: Enable KASAN support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com, ojeda@kernel.org, 
	Masahiro Yamada <masahiroy@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: dvyukov@google.com, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	Matthew Maurer <mmaurer@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GtoSqXgg;       spf=pass
 (google.com: domain of 3rppezgckcxsllztqdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3RPPEZgcKCXsllZtqdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
set properly.

Suggested-by: Miguel Ojeda <ojeda@kernel.org>
Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 scripts/Makefile.kasan          | 57 ++++++++++++++++++++++++---------
 scripts/Makefile.lib            |  3 ++
 scripts/generate_rust_target.rs |  1 +
 3 files changed, 45 insertions(+), 16 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index aab4154af00a..97570df40a98 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -12,6 +12,11 @@ endif
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
 cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
+rustc-param = $(call rustc-option, -Cllvm-args=-$(1),)
+
+check-args = $(foreach arg,$(2),$(call $(1),$(arg)))
+
+kasan_params :=
 
 ifdef CONFIG_KASAN_STACK
 	stack_enable := 1
@@ -41,39 +46,59 @@ CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
 		$(call cc-option, -fsanitize=kernel-address \
 		-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
 
-# Now, add other parameters enabled similarly in both GCC and Clang.
-# As some of them are not supported by older compilers, use cc-param.
-CFLAGS_KASAN += $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-		$(call cc-param,asan-stack=$(stack_enable)) \
-		$(call cc-param,asan-instrument-allocas=1) \
-		$(call cc-param,asan-globals=1)
+# The minimum supported `rustc` version has a minimum supported LLVM
+# version late enough that we can assume support for -asan-mapping-offset.
+RUSTFLAGS_KASAN := -Zsanitizer=kernel-address \
+		   -Zsanitizer-recover=kernel-address \
+		   -Cllvm-args=-asan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+
+# Now, add other parameters enabled similarly in GCC, Clang, and rustc.
+# As some of them are not supported by older compilers, these will be filtered
+# through `cc-param` or `rust-param` as applicable.
+kasan_params += asan-instrumentation-with-call-threshold=$(call_threshold) \
+		asan-stack=$(stack_enable) \
+		asan-instrument-allocas=1 \
+		asan-globals=1
 
 # Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
 # instead. With compilers that don't support this option, compiler-inserted
 # memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
-CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
+kasan_params += asan-kernel-mem-intrinsic-prefix=1
 
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
 
+CFLAGS_KASAN := -fsanitize=kernel-hwaddress
+
+# This sets flags that will enable KHWASAN once enabled in Rust. These will
+# not work today, and is guarded against in dependencies for CONFIG_RUST.
+RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
+		   -Zsanitizer-recover=kernel-hwaddress
+
 ifdef CONFIG_KASAN_INLINE
-	instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
 else
-	instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
+	kasan_params += hwasan-instrument-with-calls=1
 endif
 
-CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		$(call cc-param,hwasan-instrument-stack=$(stack_enable)) \
-		$(call cc-param,hwasan-use-short-granules=0) \
-		$(call cc-param,hwasan-inline-all-checks=0) \
-		$(instrumentation_flags)
+kasan_params += hwasan-instrument-stack=$(stack_enable) \
+		hwasan-use-short-granules=0 \
+		hwasan-inline-all-checks=0
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
 ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
-	CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+	kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
 endif
 
 endif # CONFIG_KASAN_SW_TAGS
 
-export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
+# Add all as-supported KASAN LLVM parameters requested by the configuration.
+CFLAGS_KASAN += $(call check-args, cc-param, $(kasan_params))
+
+ifdef CONFIG_RUST
+	# Avoid calling `rustc-param` unless Rust is enabled.
+	RUSTFLAGS_KASAN += $(call check-args, rustc-param, $(kasan_params))
+endif # CONFIG_RUST
+
+export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE RUSTFLAGS_KASAN
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 9f06f6aaf7fc..4a58636705e0 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -167,6 +167,9 @@ ifneq ($(CONFIG_KASAN_HW_TAGS),y)
 _c_flags += $(if $(patsubst n%,, \
 		$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object)), \
 		$(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
+_rust_flags += $(if $(patsubst n%,, \
+		$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object)), \
+		$(RUSTFLAGS_KASAN))
 endif
 endif
 
diff --git a/scripts/generate_rust_target.rs b/scripts/generate_rust_target.rs
index ced405d35c5d..c24c2abd67db 100644
--- a/scripts/generate_rust_target.rs
+++ b/scripts/generate_rust_target.rs
@@ -192,6 +192,7 @@ fn main() {
         }
         ts.push("features", features);
         ts.push("llvm-target", "x86_64-linux-gnu");
+        ts.push("supported-sanitizers", ["kernel-address"]);
         ts.push("target-pointer-width", "64");
     } else if cfg.has("LOONGARCH") {
         panic!("loongarch uses the builtin rustc loongarch64-unknown-none-softfloat target");
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240820194910.187826-4-mmaurer%40google.com.
