Return-Path: <kasan-dev+bncBDI7FD5TRANRBC54RO2QMGQEKT7S4GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8406193CB2E
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 01:21:49 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-81f8c78cc66sf25840239f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 16:21:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721949708; cv=pass;
        d=google.com; s=arc-20160816;
        b=OXxkyfXHbUBtkSFE6ePQOPPdDyQnMkq+mgDaLP/ztbKag1A7mAdr6MCmOXyuN4jz1t
         z3uJBPAFYwdydQHk+ApFR9bBsTP9QnXTdpvj29VnWCD3RJVUQl8V0s+MwrshGUqnu8rq
         Zqo3njPE0IMdGBZYfH7GHPT3f4g2yUqiFmXE565yqql8mDwd5GeWlOdC20g6VbVmhVWW
         9aOQG4fKPm/knYVWgjg5bX6S3V2hQKH0PX1dNBHiMkNWIOr6r2fKiUzLjek7t5zniL5F
         bH0tXVBuDp70AtUjcJgZQFoTADGv3pxQSYiYlwPFo4d6nDJRUHRrQWRQ2N9Lt1Y549m9
         grhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fkdRzmHz4+3ipMi8fwjY5KV7nuBCy2qSUkDnYuEBic8=;
        fh=QHWQvh9TrQpuR6kqLQM13sFJ4pQBK0BLEx0NXIeB9yM=;
        b=c6m9nrp6TQWI0rk4EWbZ3okN9YT6mn5xwgCg/1kUm6iOSl2Zquwi5RIB5RFcXt+Zr0
         SowoG3WWZbpCwzQWBDqPHTLtRf1+DrcyuAPix3RMAOq5zYEHt+CeJ51SSEtv6PZxXAmi
         KBbE0/kyHwZVQNrLKnebfswjdfxlPpoennHLpnqp4qIjPtN5a0GntGPMCI5tM88sRzCt
         93qCdxCyppW9PMhy7fSOQiAKZP2a2qGaSpNJDSY5i5rzgornT07WZK5/mBRtVnOF+nmG
         N3aQJqPsgZz/NvCtN4hS07vrzh2SuBmp6XKD8BYMuBXeaOhZJid7jJmSbRpozFoFN2si
         KmmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YXZ4yNYg;
       spf=pass (google.com: domain of 3ct6izgckcy033rb8v8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ct6iZgcKCY033rB8v8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721949708; x=1722554508; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fkdRzmHz4+3ipMi8fwjY5KV7nuBCy2qSUkDnYuEBic8=;
        b=QVz9uNDSXdkc3KNNxWkTO6b2XbrOoMdBISL2Yt5YbfS0u5Oe9crfrRnzbyfuxqf0l1
         sAX1Et7whuV3p95klDGDKvBHjDRaDVZVvku6Wy+nuf1My4mB37PGst7zxq264kJUB3Bg
         hHest7dM+V8TeJK8fQ+5v0MrQptwfjE/PJT1a0h9XrmucS5TUHprM1gS97utR/boyR1n
         +ORT7GO2NU5stCq9QcV8obhz7LiTE+rfmPlU7keyan1NtA+K5kJlyQkBrUtrcRTXoksu
         X7LdKLyxZkRVpr/R8QS8+TDR6ny0mzbHban2F2ZWmX4w2htREIfmA/GHvC6HB03iKrIp
         eHVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721949708; x=1722554508;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fkdRzmHz4+3ipMi8fwjY5KV7nuBCy2qSUkDnYuEBic8=;
        b=LR5ocS8bxPsUuZEytBqrcmYD/wYZYmRldMkavb+nPncvF+xzNMZnSAwzmP33iBiyuW
         W8DSlpk7R1Er4xEDH74lrtB9T1Xci3C/1YTymhoCnmUNP6jbbTQZ6AoY/biW6+pxXniZ
         QKDIFoeJWxtasq/NHnOw4F0qNRS8R6GhxchPnHMu+X8kGt2VuRjSeeDFVjAe3zNP5rrL
         0sBynSM00OQG8HXVORFPwEEM0HFSSoqa/uWCn0KEuclYMC5aAWC4cNf8M2AFMR6ZMm6C
         G8WEG1qj/6dz2uyz3lNPDaX1GNJt4mNj+aTr7+vpaMTZG0dwZucnuFtoZSyfElSCMsJK
         Adyg==
X-Forwarded-Encrypted: i=2; AJvYcCXZI2ncEIpKobd26d6UiVzYNOzAs0KjE9pK3Y0+yMR3tSxayM75bhBNhaDaH+Dx9zuz9Sh/UxkbI3EIIv0QWv8PVIyl3RfROg==
X-Gm-Message-State: AOJu0YynPUfn0/pGHtT+bNMA431gEL/s5jonpkwe7XPfO6s5998//aAt
	zLIwX6GfcIfv9ePw/mJP+sboZJ8O0zFtBElMdglM4++PaoUUSQ9j
X-Google-Smtp-Source: AGHT+IHH1HOQy4KnVdnKJlV5nCqdRi9QckCOhDU2NYLhLUwvY7w1T48q4iXOHl1Lsj+gKvA46nzhAg==
X-Received: by 2002:a05:6e02:154e:b0:397:b45d:d009 with SMTP id e9e14a558f8ab-39a2180a58bmr61820905ab.16.1721949707685;
        Thu, 25 Jul 2024 16:21:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:174b:b0:375:c45a:cd5d with SMTP id
 e9e14a558f8ab-39a2179f675ls11655845ab.2.-pod-prod-02-us; Thu, 25 Jul 2024
 16:21:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsIhU8r1gfVmV37qD33gal21XQ/W87ZDwkyisw8Ei3CG03urU6uamkoNJVvcn3pshn9pVjA1/WUIga80CQR8gaVct1abcytWW0Zw==
X-Received: by 2002:a05:6602:6d05:b0:803:980e:5b39 with SMTP id ca18e2360f4ac-81f7bd01b4cmr553578339f.4.1721949706854;
        Thu, 25 Jul 2024 16:21:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721949706; cv=none;
        d=google.com; s=arc-20160816;
        b=LRCNSbChso9xAF83VZ4cBvC9jUf8DXQrHlX9UY8OdfAAlvSJ3E/m433yzZQHTCWPyQ
         +wYkG8mlY0P0zr4rQ+CUTRPA80P8pF7EDV1oI/qPxTjwJ//O2bPpHUyYMU66YL4+g7zW
         yz80TWBNimB1JeJVTt9zloUStx/DTcoMoM8IYeuOy92eiH1jDp5kjR8VjyWFAY6iO9l7
         WmxRV5Yixj7C6zQumugjbOfyOz5jIQXyX9WzrexMPFaeSU4DUvsc3TbYdGdFWCS99cRa
         0Il2MF83nCtH2KHficm3dsi2dkZw3iE8AxpWXle8VaPTHKiVjYkGdRXPLyzi8/N91jOg
         Dz+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NIeg3QD3T42p/ZQnVld0CvS5klyquBslVZ8Cnqk2AWw=;
        fh=EwKRNs3D0EssiILv9lVHEkAViY/n7DsSlZrb036Y7cc=;
        b=UqGup9FwiRr81fki6AjydWgz9wFuu3SDuS0hUxyq3b4CwOZmYxWqAv2gbGQ1PceJtl
         7IBSB57+zwMLa8A1bMnX9q1KNHqTIdYXrmw2etAszJsXdAAFpO2ZllhucS67UCe8qap6
         z1hlSn7/f6eaO7oBahpHWUrqVBBczubP4Tq0fGWT2HoP1TtYc5D3yaermH9wnPtrIADg
         4PlWmKpVcpPzu/hqFnfNikv5VR2+Nmqd2isXWHm3brTGlS0QEVjTCaLYnAPvob2Llupv
         W8TdrGM0Wmx4Ou/IuWDgdf9nzG0MuTUKL0KGwZOVq0zWF2AVrJSgBRxzn5JieKH2nCf2
         Lz4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YXZ4yNYg;
       spf=pass (google.com: domain of 3ct6izgckcy033rb8v8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ct6iZgcKCY033rB8v8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4c29fb9081asi116660173.4.2024.07.25.16.21.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 16:21:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ct6izgckcy033rb8v8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-e0b2af9de57so2301734276.3
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 16:21:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWd3pakwDgaiNE+cyZUclYu3NWIXaaXJpatCO9kg5TRT9cFZgFU4bLS27y/jqRs9mhtfYZnendMJgJ1R9QYOuPTBAy/Tr4AHzZZ2w==
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a25:9bc1:0:b0:e08:6c33:7334 with SMTP id
 3f1490d57ef6-e0b2cd29922mr30221276.8.1721949706306; Thu, 25 Jul 2024 16:21:46
 -0700 (PDT)
Date: Thu, 25 Jul 2024 23:20:47 +0000
In-Reply-To: <20240725232126.1996981-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240725232126.1996981-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.rc1.232.g9752f9e123-goog
Message-ID: <20240725232126.1996981-3-mmaurer@google.com>
Subject: [PATCH 2/2] kbuild: rust: Enable KASAN support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>
Cc: Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Alice Ryhl <aliceryhl@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YXZ4yNYg;       spf=pass
 (google.com: domain of 3ct6izgckcy033rb8v8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ct6iZgcKCY033rB8v8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--mmaurer.bounces.google.com;
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
 scripts/Makefile.kasan | 46 +++++++++++++++++++++++++++++++++++++++++-
 scripts/Makefile.lib   |  3 +++
 2 files changed, 48 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 390658a2d5b7..84572c473e23 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -12,6 +12,7 @@ endif
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
 cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
+rustc-param = $(call rustc-option, -Cllvm-args=-$(1),)
 
 ifdef CONFIG_KASAN_STACK
 	stack_enable := 1
@@ -28,6 +29,7 @@ else
 endif
 
 CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
+RUSTFLAGS_KASAN_MINIMAL := -Zsanitizer=kernel-address -Zsanitizer-recover=kernel-address
 
 # -fasan-shadow-offset fails without -fsanitize
 CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
@@ -36,13 +38,36 @@ CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
 			-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
 
 ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
+	KASAN_SHADOW_SUPPORTED := n
+else
+	KASAN_SHADOW_SUPPORTED := y
+endif
+
+ifdef CONFIG_RUST
+	RUSTFLAGS_KASAN_SHADOW := $(call rustc-option $(RUSTFLAGS_KASAN_MINIMAL) \
+				  -Cllvm-args=-asan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+	ifeq ($(strip $(RUSTFLAGS_KASAN_SHADOW)),)
+		KASAN_SHADOW_SUPPORTED := n
+	endif
+endif
+
+ifeq ($(KASAN_SHADOW_SUPPORTED),y)
 	CFLAGS_KASAN := $(CFLAGS_KASAN_MINIMAL)
+	ifdef CONFIG_RUST
+		RUSTFLAGS_KASAN := $(RUSTFLAGS_KASAN_MINIMAL)
+	endif
 else
 	# Now add all the compiler specific options that are valid standalone
 	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
 	 $(call cc-param,asan-globals=1) \
 	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
 	 $(call cc-param,asan-instrument-allocas=1)
+	ifdef CONFIG_RUST
+		RUSTFLAGS_KASAN := $(RUSTFLAGS_KASAN_SHADOW) \
+		 $(call rustc-param,asan-globals=1) \
+		 $(call rustc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
+		 $(call rustc-param,asan-instrument-allocas=1)
+	endif
 endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
@@ -52,6 +77,11 @@ CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 # memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
 CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
 
+ifdef CONFIG_RUST
+	RUSTFLAGS_KASAN += $(call rustc-param,asan-stack=$(stack_enable))
+	RUSTFLAGS_KASAN += $(call rustc-param,asan-kernel-mem-intrinsic-prefix=1)
+endif
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
@@ -73,6 +103,20 @@ ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
 CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
 endif
 
+ifdef CONFIG_RUST
+	ifdef CONFIG_KASAN_INLINE
+		rust_instrumentation_flags := $(call rustc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+	else
+		rust_instrumentation_flags := $(call rustc-param,hwasan-instrument-with-calls=1)
+	endif
+	RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress -Zsanitizer-recover=kernel-hwaddress \
+			   $(call rustc-param,hwasan-instrument-stack=$(stack_enable)) \
+			   $(call rustc-param,hwasan-use-short-granules=0) \
+			   $(call rustc-param,hwasan-inline-all-checks=0) \
+			   $(call rustc-param,hwasan-kernel-mem-intrinsic-prefix=1) \
+			   $(instrumentation_flags)
+endif
+
 endif # CONFIG_KASAN_SW_TAGS
 
-export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
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
 
-- 
2.46.0.rc1.232.g9752f9e123-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240725232126.1996981-3-mmaurer%40google.com.
