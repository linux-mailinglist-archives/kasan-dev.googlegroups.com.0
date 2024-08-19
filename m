Return-Path: <kasan-dev+bncBDI7FD5TRANRBM7VR23AMGQEJ5Y5BHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF209576A1
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 23:35:49 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39d51267620sf11473045ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 14:35:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724103347; cv=pass;
        d=google.com; s=arc-20160816;
        b=TLwGW3GTKNgvnnw0n3ntDmj/T9viix9ujy1O9whkDIBmuJiUdaz4wUn8SARthMD86m
         n9atrLbPHItyArLbswknh9bAO4lLSOpHvuMcvZFlfK1SVGYE8/qTIO3Kzqzw/j5tTvSx
         xwf7vBeDamsdAWvIWcUfyNqgkBv+Lc4K9qvK+FPQhghynvEBrKi2Qj3xOrZSojS4JQZ9
         yfcbe8wsUcTp9BIOH/AuJLZiG5sf24aUuJgUeH6HE4yYbRr9mWBNK2BqyMJWarV0fMff
         C/j9qJf2CV5L4/gOESScC6uCgqaftbC2u4Bqpkh23ohcM+dTlK4U+m/ebaouE64v6RP0
         P1ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jAG11BlxyN1l5UPniWeqTBJtWQBp3pkMOgkSU1N02/Q=;
        fh=9xzbXd1bkPInyPsbkTCp+Cqs/6ZmLCdR9+z6zA3u64Y=;
        b=ZH7IMFClCZ4GyTXGCMXjfHOcC6PUwjkoplA33KAmKfpJ38vZ3o7YylbuTgg5IDxjTW
         AlwEOvBk5+rECVhuc5Ubk73GtYYNwEgbqOtdQopM51D/HlMwTCFEIX0LP5b7jAQt+APp
         k9CTyqZuf+ADDcJQVmbbFQz9Ibdua+3du+h24BOHTaiHi5wXMgnpxCya0iyhOWFlQ34R
         0749sAhSGw2uJNrV9ufn2/uMpBLuqGno2NPEkFapyq+JHFAnLkOyWtNJNrYDKx6NbG7i
         TRiE8ZierNyKOohGGyqNyEc29eZlHAOBsIvizviNkaNCezxybsDslGFfV10/yfDEM/OB
         7oWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0oxj9tXI;
       spf=pass (google.com: domain of 3sbrdzgckcxiccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sbrDZgcKCXIccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724103347; x=1724708147; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jAG11BlxyN1l5UPniWeqTBJtWQBp3pkMOgkSU1N02/Q=;
        b=AplTHDPvUtnoxH6ixJR60N2d0DKE40gvFB9iFlm5yynRg8eqvSeMBaolmRU6HmEg66
         E13oy+/6L4iDuLtfptGkRl35gerzU3xc+EZV2Nvm7ex19KIiVKLaGQCqHE0bgoU12pdK
         gJEVjt2dxlga3ZXhsPkjFyB0N2SgrVrumZJgg1kWIeidQpm4grbwv9Sk9yG6EVg7Tq20
         +HC5LggXp+QyUr9YN1WxPPjmzbrds+rftd4HE0yQMJi56vGXya3fck5R7iQZgoIID+1A
         /I55b+e3YRrueMDJ+gRBoyAZRE+Wz1PWpzx6Ru/jOTtWgYg7dVJv2klmX9g1XYNGq8ki
         MiYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724103347; x=1724708147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jAG11BlxyN1l5UPniWeqTBJtWQBp3pkMOgkSU1N02/Q=;
        b=j7LddUrm0mso4gF4qFEQlT0V5z+qQdiSMtMz5dYtZfQdn3Pp0t3ZMU9kq+0c+nzElD
         71CZWF0c+BupUnSA9DUYVyK6DCtBYmRHoUHzayUyfoczyVdL+vj5Q34mMwmx4NoczPqV
         Qv0BVXfiyw/9ZvrIJj7KAABdVwl+yEqZpl6IdlxnM5eUn0MZ58lH8dKGJaoQ9HTNpkA3
         rMIjfZ1SoTUpx/9apAio9KAYCay0ohwtYNOqhOR2WXrY9dynx8J+HZfbgyJaBAJDmOOj
         x3qQ3VTCNwmc6cZbHIxRTjyWmKSDkNizxvWg2suFRgV0/Yvm4WI+hrTH5uaXIGH4I5hZ
         BdpA==
X-Forwarded-Encrypted: i=2; AJvYcCXUSjLPNmhXR9/mb2IrgedmNieBbdZPHxALp2UawB664tTXn+eAlT6Z2fpIDUmJfn5hz/IKig==@lfdr.de
X-Gm-Message-State: AOJu0Yxy7MSym372c5cNrTq+4iXbSh/W68NbvRs93emRvj1p/Qcx00SD
	WzJez1BtXEFZaEEZjOeaoTqzU5c8dr94ktXK0C5SaQFAQIjQrUCV
X-Google-Smtp-Source: AGHT+IHvWbFaxsHxjH6ATn62dMgeLDWS/TqLpM0TNmGLFGi3v35v3FuOt2csPUdHNyLNrwpiRmrV7w==
X-Received: by 2002:a05:6e02:148c:b0:39d:229d:864e with SMTP id e9e14a558f8ab-39d26cde62dmr130194935ab.2.1724103347429;
        Mon, 19 Aug 2024 14:35:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ec9:b0:39d:473c:5c6e with SMTP id
 e9e14a558f8ab-39d473c5daals10874705ab.1.-pod-prod-06-us; Mon, 19 Aug 2024
 14:35:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCkJtIZebiVNHGOvKuw9AgfuZx0vOGgA/4qmcHqXvLagcfdTehLsQ47pA3PClKFhJ6IODLi+OHatA=@googlegroups.com
X-Received: by 2002:a05:6602:6b0f:b0:81f:d520:782e with SMTP id ca18e2360f4ac-824f268339bmr1667886039f.10.1724103346691;
        Mon, 19 Aug 2024 14:35:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724103346; cv=none;
        d=google.com; s=arc-20160816;
        b=kQHemkFHMzCSF36Uh1dvUr6Abe6EDIFbgaN3YiV3aAxmB2ysVtpS/vCimHcS3SeNxY
         Cc40JDQiDZ/oNHLejUYoat3yq3FHbeIDFUYB7Md/GAzLvO7/+Jd6dLvqpYQ1A+fzkucB
         h1I0gIKDuGtO3JLX+2eOvPnd/j8kYUygRD2f+hngV6wblvuMgEDcxNRwXPP5923xLk6I
         AFFW5nKesHretQBGjIuf32RzMf3P1kqDNGLm+9lse8364uSyyJgd33wJjch4PWGi+dXR
         2CRd8ozLokGzZvlzNN2uKAmy1RJTphBIoTUNKod6bz2s/VfCEuWBpbTLx9guPVoiRutU
         UUHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aFJ5TYFEs+yR5IdjkZAHXbLg1gl48k9ppZEG1vmVjrs=;
        fh=Q1SCKFVLFS1Wm1vFJy0ES6Nt3GK6lueSh/nwb6nzahk=;
        b=EjLdtHEOxYuEyL04XTRhVc6s/AOF4VWFASqkjStmXPT8p8+m2Uv5lTzmb/jH7nztdt
         kA6ULlBmr4DkNV2je6kWoQ8R/jpTN3VyLYdOWhAqxuv4qW7bbPK5gFRY+SJPOaRhyCYq
         EONZFXwE/cgxi9LgSlvNYfDobST9tLJJLPhm/PYgam7AwYNt3D9nyVDhWqYXRGyHL7L3
         RfvuNx+p2e9G53Cmd8ZEorPKLICuioSI1q2DWI4gngl7H4SYtiQE/4WfDAyeXFkSeMye
         9jsKms7IyTEIoINUToVTOao2JKNqXLCLz45bf5NNXkomotOx2KxdEabm4R4E4hF3dJ+b
         ZwGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0oxj9tXI;
       spf=pass (google.com: domain of 3sbrdzgckcxiccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sbrDZgcKCXIccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-824e9b6b173si39242339f.3.2024.08.19.14.35.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2024 14:35:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sbrdzgckcxiccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-e0b3d35ccfbso6792894276.3
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2024 14:35:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSlFRr/UIX6KrASuhpHm4igDUq4qye+RYkbfWYWuzC4WzjvF/pdU5VPFXK8EkToUPSnckcpSM5aDk=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a5b:4cb:0:b0:e11:7a38:8883 with SMTP id
 3f1490d57ef6-e1180f71f9dmr21204276.7.1724103345780; Mon, 19 Aug 2024 14:35:45
 -0700 (PDT)
Date: Mon, 19 Aug 2024 21:35:20 +0000
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240819213534.4080408-3-mmaurer@google.com>
Subject: [PATCH v3 2/4] kbuild: rust: Enable KASAN support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, Matthew Maurer <mmaurer@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0oxj9tXI;       spf=pass
 (google.com: domain of 3sbrdzgckcxiccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sbrDZgcKCXIccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
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

Rust hasn't yet enabled software-tagged KWHASAN (only regular HWASAN),
so explicitly prevent Rust from being selected when it is enabled.

Suggested-by: Miguel Ojeda <ojeda@kernel.org>
Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 scripts/Makefile.kasan          | 54 +++++++++++++++++++++++----------
 scripts/Makefile.lib            |  3 ++
 scripts/generate_rust_target.rs |  1 +
 3 files changed, 42 insertions(+), 16 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index aab4154af00a..163640fdefa0 100644
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
@@ -41,39 +46,56 @@ CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
 		$(call cc-option, -fsanitize=kernel-address \
 		-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
 
-# Now, add other parameters enabled similarly in both GCC and Clang.
-# As some of them are not supported by older compilers, use cc-param.
-CFLAGS_KASAN += $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-		$(call cc-param,asan-stack=$(stack_enable)) \
-		$(call cc-param,asan-instrument-allocas=1) \
-		$(call cc-param,asan-globals=1)
+# The minimum supported `rustc` version has a minimum supported LLVM
+# version late enough that we can assume support for -asan-mapping-offset
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
+
+CFLAGS_KASAN := -fsanitize=kernel-hwaddress
+RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
+		   -Zsanitizer-recover=kernel-hwaddress
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
 ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
-	CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+	kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
 endif
 
 endif # CONFIG_KASAN_SW_TAGS
 
-export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
+# Add all as-supported KASAN LLVM parameters requested by the configuration
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240819213534.4080408-3-mmaurer%40google.com.
