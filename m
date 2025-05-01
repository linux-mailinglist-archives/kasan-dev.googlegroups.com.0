Return-Path: <kasan-dev+bncBCG5FM426MMRBJOMZXAAMGQEDD6VFGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 11798AA5E2C
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 14:16:58 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-43d08915f61sf3859865e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 05:16:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746101799; cv=pass;
        d=google.com; s=arc-20240605;
        b=A/O+BQk++xu7AUsSGIpZavbtsEY/OlkkWGh5tBWI/HAfyYfnlQ3cDZxrhg9UYRNOtQ
         A6e+SqZzEr1XDoqobB2VC2FWtsFvRAzthjCLeHecvR2Bj4/+dpdeCB5uoyHrcJt8ezul
         /m9ePN45EnuJmgkSl94NFX91Jmpq2DJk4czyaR+lh9A6r0uS4MHfgqqN2CgpB82jwWHc
         Gt3Oj8wOL/z+diT6GD8N5pUG+OxWU221gWqFZ16b43m+xvpfgSxVpwSb7aueHdSIrZYi
         XW7qJn3ZuKr526BUczYsHWZ5qXE+9+aCikzS4U9dl5XSpTmcWnkknlQill6/jfZaMp7w
         HZWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=m8Q4XUab4DAXtITc9kD5jrhd/DFbQ1HHjZq3kCLq//M=;
        fh=pS4YXpexRE0F/2KpFVJZ3ycpFFXrk7D9JOmaDXSuZ7M=;
        b=FzgX1JuOv4fKATmrcEly4H5AdTcqjKWE+d0qFwCy/VdupDcyNGlVHXoViRKFVYYg5d
         6LEC8DKD76EYAp42lyytpFh9W/RYLLI1XnjeLXXd8O5Ifi7CX/WwhqwBhHP0hQhRC0y6
         5rtu1z1bkFN4vCSSKawSdPkh+Q3sU3/S8H6M1sPi+vHfkHySXqmBVngJbVWTXc/OPstb
         EOTAFyRpjlYOujC5hUH559py7y00HzQ27qJ26B2r1MPG3JdFK5gK6ZUGGoyQ/xY7u9kJ
         wNMDPB2GXCGvnA8PpjGZhWCuLtpSlWhsd35MT1eSOmo5fodvJrKjsvZ7epQGk0y4WuDr
         UmHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D0MTij9i;
       spf=pass (google.com: domain of 3i2ytaakkcyqitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I2YTaAkKCYQitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746101799; x=1746706599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m8Q4XUab4DAXtITc9kD5jrhd/DFbQ1HHjZq3kCLq//M=;
        b=cO3UL4C7SWv/GvfamvCiRHyczUGQBNrC5DwEgqlFxNLx3gcN1F9Mo+wYn0ps//lYvn
         2hpJTGOXLhb6+a1RSR5xpr+milnrLglfq3WXcBjr161VLuW0AhTUxVM0Syqn20W0bFj+
         NYGk96dpIjWiOskX6gpR1/9GY1zEn192Rkuo1qCCU8E2cb3/5l6jZi2/xjNNKUR22QoG
         e4OOwulum/IE7Co8FP23D5/twu62UYL6UM/JvftVpSTyK0jBV81RMdgZhEoAum+kmz8L
         qWHLDx7Zye5VJIX5XEZnfnYHFfbzce9r8vwSZrg9QZcFxmpNV4Z2jTz2BFISg7MXcsiy
         2pkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746101799; x=1746706599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=m8Q4XUab4DAXtITc9kD5jrhd/DFbQ1HHjZq3kCLq//M=;
        b=QV+yeO1RImExfruUXRwXQxd/nQpmOjHpWuT/d6J8eIpgsfgHmeTT1dfiJ/44VzavY1
         AD/r4x8/jZl6NMQRTB3GQRfFrRrvRzXMyi5InYPB0Vxp2kRzR8sNGERmf4IbWcmiJ3JG
         bBu9HVAnU97LluIAsdz5nMADJFPqUuJYWtSnnlIBaqYTrZk/XLNgiGCmT30+/TCoASfk
         3Gf6RJRUIf68NWCkzrSyQbJ8SH0Gg0fYM56WKRwvFksy4msJ/i+j05j84DVsg3RIDo9m
         Bi2vYm4EnyLU7qs3Fp69ed+2BkuciNvECHiJQx7jOljnAev0PSSm3eSmzWHzPt1VnUlp
         4vbQ==
X-Forwarded-Encrypted: i=2; AJvYcCUlfZoVbghOllOdvtzYg0jFr2NUTsmta9isFnGVvPuQmApt1CHBxKfxy6M36UZYRNmEfh7s3g==@lfdr.de
X-Gm-Message-State: AOJu0YxBxHCPh1frifMorlWWGhGWVOaTzjx+yFY/j1YLyPcM0aPGSS9n
	GPiHPEqVbkta0dz44YPT1IYFfkgDatHP2wPq1zTIprJp6olQwkJx
X-Google-Smtp-Source: AGHT+IHOwQXTWtrIvSM54HwlVbRJqKy4UUyHG+TQiu11RJbFXj+1DjxRMKBAJz7yuD0kfaSaQzDUrA==
X-Received: by 2002:a05:600c:4f42:b0:43d:77c5:9c1a with SMTP id 5b1f17b1804b1-441b6ff1fb0mr23080225e9.4.1746101798429;
        Thu, 01 May 2025 05:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEUf/E/9GB4dotGp49pjAo9RIvpuwXvh+TIG60m8y0MOw==
Received: by 2002:a05:600c:4f01:b0:43d:1776:2ebe with SMTP id
 5b1f17b1804b1-441b5c961d5ls63905e9.2.-pod-prod-08-eu; Thu, 01 May 2025
 05:16:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6swNjsmFQw5tQwqMe4SYARtOve78rI7p5YUR7vMv+uNHOF8X/BOkRUdL6kUK+dFU1K10apPpT280=@googlegroups.com
X-Received: by 2002:a05:6000:188e:b0:39c:1257:dba8 with SMTP id ffacd0b85a97d-3a09417d6b2mr2070590f8f.56.1746101795679;
        Thu, 01 May 2025 05:16:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746101795; cv=none;
        d=google.com; s=arc-20240605;
        b=M6KYA/nlrKLAdqG76zvBcAab0N6Lcx08ID5uAS7eXzxVcV3BEZcSQ7NFXC8jc6endN
         Hip1okJAECxFlf3BBaaFI72xbIeQJrtjqqTDSRvoSArv+zFbTRzPWvc6xmh4WBsUOTzZ
         5CvA7x0Y2HiZzd3wl7NXDNgWoHDe8AbA79MZWWTWOCfWWindgoyK6g+r5P/Ni5bHiUyl
         vnA7mQwd0b/HVerpWsMHwcCbEUgW0vOe+gXapOtyOmHsBrzdO5+Uz7I+LvV4ifYTcPSH
         umxNtDeASY44x21Tubd1sjKA6DnipC6fc51MnBPTrVmapin3kNdDvFGsloHBGTJUI5x/
         UzGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=/0A3i0y7AEXGrVw5WCxmIfPgVwLI2iY2Vm/Il51dpo4=;
        fh=iYziWQ/GOeUQixE+Oz8DZ/gfRBWH8mlZAo9XFH4iMso=;
        b=dgjaVoDrPjktIQCgOxWZme9wFX77jQIwY64CGGRjelH0wnuhS1tRT+g0ipM6NhQmGi
         VXU9GDPsDv+rIamAdou8DDYhWhy69ZixiqNNG17kmaxL+WS2dqChhwkzma7voaSWxsBN
         PunLhKOEO52WfeLAWbVnf4iS+JiFYNbBe345qU+R8NlRxe5CXYrO0OqAXAbz2PeW0nsX
         Ocd/zjkWl5/pDZ2PgB76vxg875LR2z0EiQ51idnWa96J+79WxOBe1uqrB+rnZ4JorAYd
         iMYAhbhHw6G+mM3RUmEnKqcpT7h3wzior064QYRFsdElvwpj3DQYJzENxoUSMUtWTrGk
         RdnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D0MTij9i;
       spf=pass (google.com: domain of 3i2ytaakkcyqitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I2YTaAkKCYQitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a095a3de82si17245f8f.2.2025.05.01.05.16.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 May 2025 05:16:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i2ytaakkcyqitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5eb80d465b7so753753a12.3
        for <kasan-dev@googlegroups.com>; Thu, 01 May 2025 05:16:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxTn2MUZZQqIEDiqon/9dy7NJDZ8rzggamcx7FPyOQlBWvEIfDvzdkbV3s7Fh2cjEb3/wV2sZb73Q=@googlegroups.com
X-Received: from edi23.prod.google.com ([2002:a05:6402:3057:b0:5f8:f539:d6d4])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6402:3549:b0:5f7:eafe:76d5 with SMTP id 4fb4d7f45d1cf-5f89ae69fdbmr5712393a12.8.1746101795323;
 Thu, 01 May 2025 05:16:35 -0700 (PDT)
Date: Thu, 01 May 2025 12:16:16 +0000
Mime-Version: 1.0
X-B4-Tracking: v=1; b=H4sIAA9mE2gC/23MQQ7CIBCF4as0sxbDIG2tK+9huqh0oETtGKhE0
 3B3sWuX/8vLt0Kk4CnCqVohUPLR81xC7Sow0zA7En4sDUqqWuqDFOEVF3EznERjWm1HadHKBsr /Gcj692Zd+tKTjwuHz0Yn/K3/lIQCxbUbqNOoj9jWZ8fs7rQ3/IA+5/wF2Ne1B6MAAAA=
X-Change-Id: 20250430-rust-kcov-6c74fd0f1f06
X-Developer-Key: i=aliceryhl@google.com; a=openpgp; fpr=49F6C1FAA74960F43A5B86A1EE7A392FDE96209F
X-Developer-Signature: v=1; a=openpgp-sha256; l=3372; i=aliceryhl@google.com;
 h=from:subject:message-id; bh=IyknQ/1KxQ4jy7cl/9HHS98hqktVwXtxDa2ScsUKzik=;
 b=owEBbQKS/ZANAwAKAQRYvu5YxjlGAcsmYgBoE2Yc1seMwVTR5LqQgHftFKn3mcU9oBGoTAYMA
 XywZQOUJWaJAjMEAAEKAB0WIQSDkqKUTWQHCvFIvbIEWL7uWMY5RgUCaBNmHAAKCRAEWL7uWMY5
 RruED/41KjyEBSNGnCAlbC4pSd6vvUYRCa5IqugILNA8EWWtm5XV9HG03IkpVx9l+WPGCL4raW7
 bT2QtGi8GeAZbwMap6yw8UgVvZiY28Lij+WpnY2OVdsJF/K2HbjEdk4JEHNYj2C9+i+ASxTwG69
 A/X717LIJcJ4EXFsfO3TVIafKmpqbCgonlQuaio5BGKsE1UzRW0+SpM6s7LTkNi6aNu/9wmKpnb
 8tq+mESF2tJgKjOiFddb2iHUR3Rx3lR4XQYNN38JC73fjMfW7t6CPEsLwQscoS/3u60zajicOS5
 lZQoWisQNarEmFfngt6PDpK91WJJDjrIHWH0KPdiJ2FHWjVP1XTXY4d5nBgk9NCOl39TmerwCYW
 M59Id7N74zcvrA6sVIrOGB73JiWdYpZcnCxYBH3kvTTErHZvtqM7KMBPl5WWhbimVOnY1WYMXv+
 6bg/rZjLhQwVgsdVcjUEKk901szchGmin0XreBHwnx9KZEGkCtW8+rfROMpkliIP1HLl/dMTxAN
 drQr4WXpIrbkME5OIUtsW03u3HqG4iW1x9cmNXhtQb44r0TDoEKS23in3hEfqarJ/he4hxMhumA
 WtZWUY5kI7tm+uZaFe1e2preFMcwNYTTbkTcobH0Yuv1OdUEtfltjYFn69OMriD0xJc3aVcMnYi HWr3YoEPbjHxiNQ==
X-Mailer: b4 0.14.2
Message-ID: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
Subject: [PATCH v2] kcov: rust: add flags for KCOV with Rust
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, 
	"=?utf-8?q?Bj=C3=B6rn_Roy_Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>, 
	Alice Ryhl <aliceryhl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D0MTij9i;       spf=pass
 (google.com: domain of 3i2ytaakkcyqitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I2YTaAkKCYQitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

Rust code is currently not instrumented properly when KCOV is enabled.
Thus, add the relevant flags to perform instrumentation correctly. This
is necessary for efficient fuzzing of Rust code.

The sanitizer-coverage features of LLVM have existed for long enough
that they are available on any LLVM version supported by rustc, so we do
not need any Kconfig feature detection. The coverage level is set to 3,
as that is the level needed by trace-pc.

We do not instrument `core` since when we fuzz the kernel, we are
looking for bugs in the kernel, not the Rust stdlib.

Co-developed-by: Matthew Maurer <mmaurer@google.com>
Signed-off-by: Matthew Maurer <mmaurer@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alice Ryhl <aliceryhl@google.com>
---
I did not pick up the Tested-by due to the changes. I verified that it
looks right under objdump, but I don't have a syzkaller setup I can try
it with.
---
Changes in v2:
- Ignore `core` in KCOV.
- Link to v1: https://lore.kernel.org/r/20250430-rust-kcov-v1-1-b9ae94148175@google.com
---
 rust/Makefile         | 1 +
 scripts/Makefile.kcov | 6 ++++++
 scripts/Makefile.lib  | 3 +++
 3 files changed, 10 insertions(+)

diff --git a/rust/Makefile b/rust/Makefile
index 3aca903a7d08cfbf4d4e0f172dab66e9115001e3..80c84749d734842774a3ac2aabbc944a68d02484 100644
--- a/rust/Makefile
+++ b/rust/Makefile
@@ -492,6 +492,7 @@ $(obj)/core.o: $(RUST_LIB_SRC)/core/src/lib.rs \
 ifneq ($(or $(CONFIG_X86_64),$(CONFIG_X86_32)),)
 $(obj)/core.o: scripts/target.json
 endif
+KCOV_INSTRUMENT_core.o := n
 
 $(obj)/compiler_builtins.o: private skip_gendwarfksyms = 1
 $(obj)/compiler_builtins.o: private rustc_objcopy = -w -W '__*'
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b7dcf7552e675cffe356788e6c3a2..ddcc3c6dc513e1988aeaf07b8efa106e8dffa640 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -3,4 +3,10 @@ kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
+kcov-rflags-y					+= -Cpasses=sancov-module
+kcov-rflags-y					+= -Cllvm-args=-sanitizer-coverage-level=3
+kcov-rflags-y					+= -Cllvm-args=-sanitizer-coverage-trace-pc
+kcov-rflags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -Cllvm-args=-sanitizer-coverage-trace-compares
+
 export CFLAGS_KCOV := $(kcov-flags-y)
+export RUSTFLAGS_KCOV := $(kcov-rflags-y)
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 2fe73cda0bddb9dcf709d0a9ae541318d54754d2..520905f19a9b19631394cfb5e129effb8846d5b8 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -169,6 +169,9 @@ ifeq ($(CONFIG_KCOV),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
 	$(CFLAGS_KCOV))
+_rust_flags += $(if $(patsubst n%,, \
+	$(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
+	$(RUSTFLAGS_KCOV))
 endif
 
 #

---
base-commit: 9c32cda43eb78f78c73aee4aa344b777714e259b
change-id: 20250430-rust-kcov-6c74fd0f1f06

Best regards,
-- 
Alice Ryhl <aliceryhl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501-rust-kcov-v2-1-b71e83e9779f%40google.com.
