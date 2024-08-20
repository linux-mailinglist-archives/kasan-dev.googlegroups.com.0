Return-Path: <kasan-dev+bncBDI7FD5TRANRBPXGSO3AMGQEYE6CNAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A53D0958EC4
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:49:19 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3db39b025a2sf6999617b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:49:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183358; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCiOTGOsLb9PfClfEWwKHffIzNbzoQEoG8xDPKoM/5jMwYpOnGSTBoCCDnc2daY+Wu
         QDvoB0axVGFwVmDi/Lzqv2jrfwd+SJ5ZPT6AaxJk0wNvHaibnMSudCe+w1weYQauKldP
         eSUIoUm7/pnKZfM9rxOEdyLEt6kzQuf+6Za4IHe8iZ+wZ0Vpo8fP3sDYB4L4E5HpqRHt
         F5yqORUEb8+CZCgmSeVX89vpGBvxoxahgZOjcR8fenpxvZkETCA28vsQOkSXVJpFeT0X
         7IlB4i6TPCbdGnm3LLjNQpSD3PTF9bmSohzUh+S33ALdzPC0nFTj16Q+ZkukWFehEECP
         bu+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=OxjCyzllh9d9YSipOsNMj8Vo5iv3S922WY2UXR+iu8E=;
        fh=9WwrUq+H+IR5NdHHdGwJuDqMfWoWBNjZAGnDvC9ddzs=;
        b=LFkpPRLsFvCx25ovltlpRLsqWAEdx7QIIoMDf0ad4FWOBpkrGAPxBEM9RD0DOHdbNT
         2u49FlgaYiJCPZC2dxSHYl+P+ZdYS9mhX2CRoaBiQF49ARWCLP8uwWBjXFONU7GmEi+1
         VkUpLvvfnTiiNgKmeChgeAQIoFDhSfx7NbFJCr7J3U/pxQUE87ZTqv+4F8pwsSexeB9l
         94n4sv5ViKuXizBtbq56PqneLkP4RYoUOJeHGIQCGS5FZEhGNKDNKZ80S6vLSsC3VCCc
         nK4yOHK0hnH/qXh22KJADqZR4Q0htr+LmGJ9OVKzXsNT249kdVBvm7YBJIbw4g07iBwV
         8fww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TkSjZ7gp;
       spf=pass (google.com: domain of 3pppezgckcxmddrlivixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PPPEZgcKCXMddRliViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183358; x=1724788158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OxjCyzllh9d9YSipOsNMj8Vo5iv3S922WY2UXR+iu8E=;
        b=HHhaUZCEtRDytTHPzJ/4rentf/GwKtn89Lw0yNajAryfgkp/jG5aoP3qZVhg2pksi/
         a7yBQoCm3bFirVabby/sTJT75BsqBpZOwjKoNUgHD9omNnLxxCNlurpf5W/fqAxDNbyi
         Z1vB6qo1CLCwdXXFJ2QaqXfbZd3u4wm37PNU0swsiH5m4dItCrIrCGpW0H4tAI/RLMwA
         dzKB8IYsMA/TU9k+OL36QNDAlpUoT0yoV0O0QGPxtilAoLP/xRKhBfBlta5UMk+/kVgy
         YlaMJqxcwiuDrHPdY4qQ/1lSaFSxUxTAZNu+0HJaXxbAJ9L8AXq47bsuK3SEoSWOnBWa
         Xsfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183358; x=1724788158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OxjCyzllh9d9YSipOsNMj8Vo5iv3S922WY2UXR+iu8E=;
        b=nTF8i1m5/G0UsoJr4+O8oFvmxE/WlARNSC4V25EMbaGI/3T1q6FPOuxe0C+JwMGWbV
         I2ndSHjV28saIfR3/+GgMHeKG6GqKwPolYBSDhfwIvPa7CSdA+Ix2whk3gt8x4DPpFIe
         YY/93kqXgRXaI7L2MSJXCwrkL4l29nwbLKkh7QHbOb3e6RKqcY8io35Oq75rm8XIMeoG
         q6vdqP0F19uR/PemkalVQfIf91qNp5YJ36X57g61BihndbLO9myQW5hZRkuQmX1jpSLD
         EZ4ab8CZkL2+LU7C9QglshP50lVOvMNMRdRVW6txpHLIOgIWsmSLgRLVHYfIiW3biWQk
         FAyw==
X-Forwarded-Encrypted: i=2; AJvYcCXRviGY8cwUS0V7l1wKervmCD2BW6Ftp2S8uDAnmYr9jCBZJ7fvNceydTZ5cj6PAZsQ/ZjQyg==@lfdr.de
X-Gm-Message-State: AOJu0YxfPBVA/7tLRIiuDs1YUUZnZrHvuWB8ncVqq4+whZK6sVz/Q2Wq
	BA0uI5cROMdyqezCX6eLRFfO5Rb2HxfQTtkGw4W+erDd9rnBbGRX
X-Google-Smtp-Source: AGHT+IGYV3sdStbvNVFPMb30WzdvvTT5+Dio+pia9m1u+1ZS/dI3a69MMIDQmqJMbqTLNvWITntEYQ==
X-Received: by 2002:a05:6870:ec88:b0:25e:1f67:b3bb with SMTP id 586e51a60fabf-2701c35480fmr18247116fac.10.1724183358273;
        Tue, 20 Aug 2024 12:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7a15:b0:25d:f93b:9be0 with SMTP id
 586e51a60fabf-26fff480306ls1202019fac.1.-pod-prod-05-us; Tue, 20 Aug 2024
 12:49:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnbXaCSeSaqZQOPCEhljVk5SNTxvm6BIHpIxyYRjjqxnO5JNPX5yWSj2LY32Vtzh7MzIMeaiePNBI=@googlegroups.com
X-Received: by 2002:a05:6871:208:b0:25e:bd07:4743 with SMTP id 586e51a60fabf-2701c0a9dbfmr18782180fac.0.1724183357075;
        Tue, 20 Aug 2024 12:49:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183357; cv=none;
        d=google.com; s=arc-20160816;
        b=KOflfXLIaC7PChXGiTWPTgfSnSPWp/iRdshwq6r52jy/46aRKoEaNJmfyDsMJ1adMx
         TQwisNWZRBJezRxqYsvn3vEyTs6+ckPNqSm7NzdB7D4wPZk+uVcPaBBgZktOkyH+mJfc
         gWT+qUOaDb1bFBuMTHJr6C7dPgaAt6fqzO5R0QnI9JizZXCv0LuCHFiTlmvc6IgUZGYK
         xCayGGjDXNIeeDext80eVkRBXH8gkwvPOiKIHwOx5gxkkmOpSnsPYIfDJF65laCMjQIX
         k4vCbbh5+gLnfplfkq8ItSBy+f9rGSgoh0DzWSdaaaRP5c4m9OOTVIUkywMoqzKnbLC+
         XOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iaH1ZLIse1MjjuwT90Rd2NUzJfAssHJQQ3PmJWNR6mE=;
        fh=nN3ubwf30/aBto2woY2xVRh7TTOZFrHI/dwdDikJI3Y=;
        b=Owtu++9j1a/+kZKOiy5N5KxEVNOtaNUKZUDW7+DiQpJo8oJe2em28C307e5QigGqC0
         F7MbxCKJvW8pPDKYJzYcZMoRA2liXrCX5u/5Y2g5TS51k/KhZiSQ3cbcx1N2EPYqfS+Z
         t72yL8rO5k0LV/8qg0HWXGrdmweMoAH6E/ZXF0vIzceLk18WXmQjxhZhyajGOm6gdL2w
         ajDwBMQc1W8WV9E2zyB9MNyIPifiZVAjnRgDE4t+9tsBa0yteHQs6Y5NjVOqO0/23dVN
         S5QrV6zTdZQEnnODrF9dVa6Zocin6qZYGFippXapJdITj+DwZcCx7crkM+GBLfXTMtW0
         mssA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TkSjZ7gp;
       spf=pass (google.com: domain of 3pppezgckcxmddrlivixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PPPEZgcKCXMddRliViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7c6b60a3050si656663a12.0.2024.08.20.12.49.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:49:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pppezgckcxmddrlivixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6b3fec974e5so71404797b3.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:49:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDug1lBU1fSzJDpGhwju8GolNsDOBXoWdpzOqwAamIX9UmCuZVgqYXRTf4xGkiDmXh31VWaavsX+Y=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:4813:b0:6be:9d4a:f097 with SMTP
 id 00721157ae682-6c0a0236c74mr8387b3.7.1724183356156; Tue, 20 Aug 2024
 12:49:16 -0700 (PDT)
Date: Tue, 20 Aug 2024 19:48:56 +0000
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240820194910.187826-2-mmaurer@google.com>
Subject: [PATCH v4 1/4] kbuild: rust: Define probing macros for rustc
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com, ojeda@kernel.org, 
	Masahiro Yamada <masahiroy@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>
Cc: dvyukov@google.com, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Matthew Maurer <mmaurer@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TkSjZ7gp;       spf=pass
 (google.com: domain of 3pppezgckcxmddrlivixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PPPEZgcKCXMddRliViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--mmaurer.bounces.google.com;
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

Creates flag probe macro variants for `rustc`. These are helpful
because:

1. The kernel now supports a minimum `rustc` version rather than a
   single version.
2. `rustc` links against a range of LLVM revisions, occasionally even
   ones without an official release number. Since the availability of
   some Rust flags depends on which LLVM it has been linked against,
   probing is necessary.

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 scripts/Kconfig.include   |  8 ++++++++
 scripts/Makefile.compiler | 15 +++++++++++++++
 2 files changed, 23 insertions(+)

diff --git a/scripts/Kconfig.include b/scripts/Kconfig.include
index 3ee8ecfb8c04..bdb187af45fd 100644
--- a/scripts/Kconfig.include
+++ b/scripts/Kconfig.include
@@ -63,3 +63,11 @@ ld-version := $(shell,set -- $(ld-info) && echo $2)
 cc-option-bit = $(if-success,$(CC) -Werror $(1) -E -x c /dev/null -o /dev/null,$(1))
 m32-flag := $(cc-option-bit,-m32)
 m64-flag := $(cc-option-bit,-m64)
+
+# $(rustc-option,<flag>)
+# Return y if the Rust compiler supports <flag>, n otherwise
+# Calls to this should be guarded so that they are not evaluated if
+# CONFIG_RUST_IS_AVAILABLE is not set.
+# If you are testing for unstable features, consider testing RUSTC_VERSION
+# instead, as features may have different completeness while available.
+rustc-option = $(success,trap "rm -rf .tmp_$$" EXIT; mkdir .tmp_$$; $(RUSTC) $(1) --crate-type=rlib /dev/null --out-dir=.tmp_$$ -o .tmp_$$/tmp.rlib)
diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
index 92be0c9a13ee..057305eae85c 100644
--- a/scripts/Makefile.compiler
+++ b/scripts/Makefile.compiler
@@ -72,3 +72,18 @@ clang-min-version = $(call test-ge, $(CONFIG_CLANG_VERSION), $1)
 # ld-option
 # Usage: KBUILD_LDFLAGS += $(call ld-option, -X, -Y)
 ld-option = $(call try-run, $(LD) $(KBUILD_LDFLAGS) $(1) -v,$(1),$(2),$(3))
+
+# __rustc-option
+# Usage: MY_RUSTFLAGS += $(call __rustc-option,$(RUSTC),$(MY_RUSTFLAGS),-Cinstrument-coverage,-Zinstrument-coverage)
+__rustc-option = $(call try-run,\
+	$(1) $(2) $(3) --crate-type=rlib /dev/null --out-dir=$$TMPOUT -o "$$TMP",$(3),$(4))
+
+# rustc-option
+# Usage: rustflags-y += $(call rustc-option,-Cinstrument-coverage,-Zinstrument-coverage)
+rustc-option = $(call __rustc-option, $(RUSTC),\
+	$(KBUILD_RUSTFLAGS),$(1),$(2))
+
+# rustc-option-yn
+# Usage: flag := $(call rustc-option-yn,-Cinstrument-coverage)
+rustc-option-yn = $(call try-run,\
+	$(RUSTC) $(KBUILD_RUSTFLAGS) $(1) --crate-type=rlib /dev/null --out-dir=$$TMPOUT -o "$$TMP",y,n)
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240820194910.187826-2-mmaurer%40google.com.
