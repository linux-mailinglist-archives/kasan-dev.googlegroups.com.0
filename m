Return-Path: <kasan-dev+bncBDI7FD5TRANRBUFV5K2QMGQEBM76SXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F8AD94FA43
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 01:29:22 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6b7b3ed86ccsf64108266d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 16:29:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723505361; cv=pass;
        d=google.com; s=arc-20160816;
        b=dw01s1mfor198xLKP9DDyBZ0yNLpsKueXIHsxv282Z8MJIMHS/pU4+bOpUvgEqFTcj
         bFwptNEg9/iRHZFUrYjfTClhpiyIw+FCWgiug26CtbiW+EFqscW56PgEkvxPtiUPAumo
         UgOznzoO5jbavfOIRQ5zBW/Ai/yRSiHMKK6rF4I6gs9fTHEwQJXMYs13Md3TfhOTK+R8
         80GukDOp5/bt/oqCIYg8A5DYBwYkf78jpXi3dxxoVG9ZWKDZbn5gi+U+AJiUZgRpXckv
         jVcScnmBSsUSlwcTYR7JmjjYtVCpVsZW1/gpbH08k8HdEtqd3ijdlky5GGRZHSQlXoFY
         mbOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oZByeoANV8pi4dfuiqyCWrbPRV00kyMn3Q+wh/R6VfA=;
        fh=JjsGDIdu1oUS2mZI5svl8daHwL2EVb2Gmr0fUVbPFEU=;
        b=RGYJomm513T2U0FuBONe9tfX+BYtNiU4a316i8VnlU35XlANgQy3xxb72G8YstzsAH
         lcR8ThLq2LZI6pU2C3/KNsHJ69K8fWY+ZDElOdoY4lvI2UlD04HPAGu/PNMQ5pWdKueJ
         xn84/uQI9V2YYnpWaSfM1GNKTOJEN7OZfZrz/J488INTMkxQltDG81U/lnKwVdoxrca7
         qG2U/tjyedu2F/IcfqQW90ep1zRDTDOc+dtGrkNYxmNEmBkbt+Q5H3qr6Oz3P6m+tGFL
         rJNYUDjIu59k17i5ZzxES29uYnxwJ1cc9TYLlAxrPXDEAvZm914a5KTvfobLgswYJJ9l
         F7iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FRkwpJdX;
       spf=pass (google.com: domain of 3z5q6zgckcswuuiczmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3z5q6ZgcKCSwUUIcZMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723505361; x=1724110161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oZByeoANV8pi4dfuiqyCWrbPRV00kyMn3Q+wh/R6VfA=;
        b=LRqaaW7K9bPGcSkXsNqW7onS6Iuin1CW4+Ime9LxHU/gRBSopulDanPkr59URat2eV
         zPbgfwFFclGrpjFbm4pPlm8TyTrx0D3A++vHEy0r5fZOL3cTSSBNGAl/mjUgsna0E8+Y
         8dyDsj7fczil3guB1dVT9ziaIEeykog6CRx5W5SXk79DwP0Uysb/tIpHPLGPterH6b7v
         7bVDgDcAhCV4ZPE1YIZQglMBesOggBE7av+HIfJ6R/eayQqKZnzw3DTNRCIx4/O6qvLO
         hwptFhBiOqFBKNqMio4wfWHrlIEgj+zUqe4B+i0ow+A5nmOss4EvAAl4o0cKXZmaJEP6
         9R2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723505361; x=1724110161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oZByeoANV8pi4dfuiqyCWrbPRV00kyMn3Q+wh/R6VfA=;
        b=EvKXPrAVOmas2KdpHbrpr8mn7icoeY1dRVRuWLfRxxF2BylCKtui5ubctzfvC/MZhZ
         z0TmxRbVBbGiLXjXjsR00D25rrr8vH+xg0wqfhXk0H2D8lXt6DGuPunxSBjvNFSpG5YH
         AQLlLYRf9meh15yMVNDnHndvVP/CmPJAcKcZf58WUbRvFB7j+h4yz/eIuWW3g7uz8qeH
         FiqONrBycBPzoJCRQGxj+mrf+NPNQ0cZFZqEU3HomrJ4INy9sw4mJNKBXZ3G2hHJHynL
         AC/nIm5i8/KIaYrVz7eKHti1sRSh65Rb7t+6+91GY/v4qXu+VZYbeSYHXfvwjITbV+eT
         T8bw==
X-Forwarded-Encrypted: i=2; AJvYcCU4kr9HWhXXtvvKULVkP1Dj9e8L+XzxCw8miqAO7W72PLlzDiTAtlO3jlqW9i1hF9ZpOrV0AA==@lfdr.de
X-Gm-Message-State: AOJu0YylYmG2WwFt2sjSQYnOVnoyKFwy9eKaalFSPsn1B/4P3r01Boin
	zsSwYGoDZt74oBeE+cARCk26atea0TsELtZ4sGC3inRLdnKSBy5/
X-Google-Smtp-Source: AGHT+IE8nFSVrxLoODWoIQyxAn9Qt5w51xIdBaqHX5exFSeuGTK461+urFDFOhM8efnVkxp7HzOakw==
X-Received: by 2002:a05:6214:4288:b0:6bd:8248:1f42 with SMTP id 6a1803df08f44-6bf4f79ded8mr23998306d6.5.1723505360944;
        Mon, 12 Aug 2024 16:29:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:cae:b0:6b5:a3b:a77 with SMTP id 6a1803df08f44-6bc697bc398ls112704126d6.0.-pod-prod-09-us;
 Mon, 12 Aug 2024 16:29:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlLJ6NYHHIBjaTuR+HaX+y24c4MaUe2QQihNI0/ZlItVDTqKcgU9FBAUt8nesIHngaPGlw1yzYLZo=@googlegroups.com
X-Received: by 2002:a05:6214:3d87:b0:6bb:bc46:fb79 with SMTP id 6a1803df08f44-6bf4f8f6d8cmr21798646d6.47.1723505360281;
        Mon, 12 Aug 2024 16:29:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723505360; cv=none;
        d=google.com; s=arc-20160816;
        b=aU7TsX9xf0Z0hQnfSEf6PJPNdG5HHvi0I53S4NL4XMG7552sf19YcFvo2unnVIsn0z
         sXPZbwo9bGZM0V0YmslJ4655eage2cgkG+lEA5erbNBxu0TcoV1YZ2c3SrCHCMUO3IFb
         l6PYeZYFBfsC5nsy5GUiJU+TEJQUvmk/MqnOXb6ILI9KX8csz6ZGRcPJS6fdCzfOpFQq
         n+Tz7u9emSCfyjEBdK7Rk+YECxv2SlHZ0DWiZL1avVv61LxdheB6cX19Fgf3oZ2udoRL
         e/mGF3IAuVB2eSZP5htHDTwu+B0bqfhBdLnlIlh1VCn9HYrMzmdT+XPwIx2TRiLDUiQm
         U9xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NYZAmb95Zdt4FYIjmbgakWRAyFL76pOHkgozh+PgbQY=;
        fh=JH8pl5uRMIv169D1xKK41ZnOQU/eSxXC8aCz0r9uGQc=;
        b=rOOTQdE7VZTAZ9hdZSqkKXJB+5rUGg00g281DgamNxmYkSuqOaQ0cXIYaahyLY3MG3
         YLrYtLmGXPKm19yXQPEafR4W+XnHnQXuKeOmTJ18v5ToTx+4amuY3Njr8PIWWPqVP2I0
         VgAxPJ0DqDEBDXZAn8OmPP1PdTK1HoKTRZvKRXQdrKoy5f0F1VDhy5Ma1WQVz1JOPq7Z
         8f88FgUOe3w0AQYp/J5zfjqXbUq2DMejMIxxkJfgVVnJl+3nzboAc7dCbGKjWnMCEWlg
         Dz4W2JHS6SsW5UK2V9jJ1msLutF9w6G+dCYlpG5k+GIPv4ITLpAVUDCA3oZmypc/uchp
         4fKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FRkwpJdX;
       spf=pass (google.com: domain of 3z5q6zgckcswuuiczmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3z5q6ZgcKCSwUUIcZMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bd82f83ee9si2469746d6.7.2024.08.12.16.29.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Aug 2024 16:29:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z5q6zgckcswuuiczmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-68d1d966c06so113500427b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2024 16:29:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcfNt5kQ1JY+tdVUxwQI3j7+dKhtFnTm25YA8efwNqD4FpzobxmsY+zzeNmVDnEKRJ2sdV3U8J8Ok=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:6902:145:b0:e03:2f90:e81d with SMTP id
 3f1490d57ef6-e113d2867a6mr91705276.11.1723505359845; Mon, 12 Aug 2024
 16:29:19 -0700 (PDT)
Date: Mon, 12 Aug 2024 23:29:02 +0000
In-Reply-To: <20240812232910.2026387-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240812232910.2026387-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.76.ge559c4bf1a-goog
Message-ID: <20240812232910.2026387-3-mmaurer@google.com>
Subject: [PATCH v2 2/3] kbuild: rust: Enable KASAN support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, 
	Masahiro Yamada <masahiroy@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: aliceryhl@google.com, samitolvanen@google.com, 
	Matthew Maurer <mmaurer@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FRkwpJdX;       spf=pass
 (google.com: domain of 3z5q6zgckcswuuiczmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3z5q6ZgcKCSwUUIcZMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--mmaurer.bounces.google.com;
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
 scripts/Makefile.kasan          | 51 +++++++++++++++++++++++----------
 scripts/Makefile.lib            |  3 ++
 scripts/generate_rust_target.rs |  1 +
 3 files changed, 40 insertions(+), 15 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 390658a2d5b7..bfd37be9cc45 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -12,6 +12,9 @@ endif
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
 cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
+rustc-param = $(call rustc-option, -Cllvm-args=-$(1),)
+
+check-args = $(foreach arg,$(2),$(call $(1),$(arg)))
 
 ifdef CONFIG_KASAN_STACK
 	stack_enable := 1
@@ -28,6 +31,7 @@ else
 endif
 
 CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
+RUSTFLAGS_KASAN_MINIMAL := -Zsanitizer=kernel-address -Zsanitizer-recover=kernel-address
 
 # -fasan-shadow-offset fails without -fsanitize
 CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
@@ -35,44 +39,61 @@ CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
 			$(call cc-option, -fsanitize=kernel-address \
 			-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
 
+# The minimum supported `rustc` version has a minimum supported LLVM
+# version late enough that we can assume support for -asan-mapping-offset
+RUSTFLAGS_KASAN_SHADOW := $(RUSTFLAGS_KASAN_MINIMAL) \
+			  -Cllvm-args=-asan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+
+KASAN_PARAMS :=
+
 ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
 	CFLAGS_KASAN := $(CFLAGS_KASAN_MINIMAL)
+	# We still need to consider this case for Rust because we want Rust code
+	# to match the behavior of possibly old C compilers when linked together.
+	ifdef CONFIG_RUST
+		RUSTFLAGS_KASAN := $(RUSTFLAGS_KASAN_MINIMAL)
+	endif
 else
-	# Now add all the compiler specific options that are valid standalone
-	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
-	 $(call cc-param,asan-globals=1) \
-	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-instrument-allocas=1)
+	KASAN_PARAMS += asan-globals=1 asan-instrumentation-with-call-threshold=$(call_threshold) asan-instrument-allocas=1
+	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW)
+	ifdef CONFIG_RUST
+		RUSTFLAGS_KASAN := $(RUSTFLAGS_KASAN_SHADOW)
+	endif
 endif
 
-CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
+KASAN_PARAMS += asan-stack=$(stack_enable)
 
 # Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
 # instead. With compilers that don't support this option, compiler-inserted
 # memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
-CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
+KASAN_PARAMS += asan-kernel-mem-intrinsic-prefix=1
 
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
 
 ifdef CONFIG_KASAN_INLINE
-    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+    KASAN_PARAMS += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
 else
-    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
+    KASAN_PARAMS += hwasan-instrument-with-calls=1
 endif
 
-CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		$(call cc-param,hwasan-instrument-stack=$(stack_enable)) \
-		$(call cc-param,hwasan-use-short-granules=0) \
-		$(call cc-param,hwasan-inline-all-checks=0) \
-		$(instrumentation_flags)
+KASAN_PARAMS += hwasan-instrument-stack=$(stack_enable) hwasan-use-short-granules=0 hwasan-inline-all-checks=0 $(instrumentation_params)
+CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
 ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
 CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
 endif
 
+ifdef CONFIG_RUST
+	RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress -Zsanitizer-recover=kernel-hwaddress
+endif
+
 endif # CONFIG_KASAN_SW_TAGS
 
-export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
+# Add all as-supported KASAN LLVM parameters requested by the configuration
+CFLAGS_KASAN += $(call check-args, cc-param, $(KASAN_PARAMS))
+RUSTFLAGS_KASAN += $(call check-args, rustc-param, $(KASAN_PARAMS))
+
+export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE RUSTFLAGS_KASAN
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index fe3668dc4954..27999da3d382 100644
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
index 8a0644c0beed..1a4d468c575f 100644
--- a/scripts/generate_rust_target.rs
+++ b/scripts/generate_rust_target.rs
@@ -187,6 +187,7 @@ fn main() {
         }
         ts.push("features", features);
         ts.push("llvm-target", "x86_64-linux-gnu");
+        ts.push("supported-sanitizers", ["kernel-address"]);
         ts.push("target-pointer-width", "64");
     } else if cfg.has("X86_32") {
         // This only works on UML, as i386 otherwise needs regparm support in rustc
-- 
2.46.0.76.ge559c4bf1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812232910.2026387-3-mmaurer%40google.com.
