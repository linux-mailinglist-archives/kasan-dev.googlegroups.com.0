Return-Path: <kasan-dev+bncBDI7FD5TRANRBMHVR23AMGQELOTJLSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5030695769F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 23:35:46 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e0353b731b8sf7763933276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 14:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724103345; cv=pass;
        d=google.com; s=arc-20160816;
        b=eota7MSGnwd3BsdhC0+684OeyVPf9XC+GsbLQz0loCx5OYDEdBbSbAToQdAJxqQvK9
         e/BcwMLzCJVwEYtQt9Ij3a7kU92HQvCDCDnzvAZIyDZ4EFknsai4ILfRDCAWohvXTxfR
         Y8oST+Iy3B2E6Ey1qFhHsTM2v8YEEzCmRMpmpjFsUG75SW2zQKRsS0es58BgjXWyXe6E
         fPgY36zflSrJLFQjntFQq5EXq3xy0lEJVlzqJdmSCgcqPGw3xHXXC9gjga8iEIg0dpg7
         Tw8Rc5LPk/DnCNAJGwe7OhbifoP4RstZynVGXRiSZzjnXCmIVrx0Yzto0pPPYImBfeEI
         8uYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=x3ipYYt3hwp+JR00jZz4jSVpUFuyoUdd5h+nQR8vENE=;
        fh=uN93KvAub7m3i/HCuYLSPCHoN/lpoPwtbtkzaNmQK6c=;
        b=RrV5B7gqaSICul0mIEKLgulFOa4bDaeSbkh2rw8TR7nBn79L4GI5+UxQGYLPi+WKBp
         q5a9N2UrUT9jshURB4heHQuqSlbkANq3MZ8Ap+RUDSajveaDjfFZ3fdr1Sliauf3lfw4
         qr2iLXzb7puYmFGxQuLitPoTNLG6/xTIHH6YqP1GD6OZ/ABGFeA5mK4AKvgj2dH5t07b
         qenClaX3tDzGLtjZM0eVT3Ezk8dKfHtMMkID8n3XlI+SmgUduZPNl7yMrKpnlD8ekTnv
         UVuFT2rDaYqBiXYvbV/vV1CWiGCh8kbCIrVqH5RpSvuy2s7JufMlxMOImhNknnnQ97Sp
         o3+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bGrKVGvy;
       spf=pass (google.com: domain of 3r7rdzgckcxaaaoifsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7rDZgcKCXAaaOifSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724103345; x=1724708145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=x3ipYYt3hwp+JR00jZz4jSVpUFuyoUdd5h+nQR8vENE=;
        b=toMZTHknrieOZB1790gS3AGqFr+58bRRbHkD9iABkgc3JQfVwCw7KQTuXUwDv5DMQo
         2LXKDjwqFRKdraWvuMSZDK/AQMqyf7akVMadv3F3UcfwIfRd5W/akFdOsOIRKo5ip28t
         Qnnbtq0jU6tuufOIetiJrM382Gg+MUoYvQDdV0pCpVoIhi4BVAMGd6UPTccou58+U9t9
         NZRQZ22yBAyoh1Ng5abEwAE85q7nXaJpfHcU0dK9X+mdODAvfQRmSg4uw/pGto1ycerH
         DmYDRuS/B1kE/difHe5z74z6WT9i5wHDci41C3mASlAgTVHChVSg8p7F7EY5nj6VmNQ8
         BOMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724103345; x=1724708145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x3ipYYt3hwp+JR00jZz4jSVpUFuyoUdd5h+nQR8vENE=;
        b=UTM9geTTGjTJyUXJJbArFVK1KghG/XS+o2fhfX95mUcIt/Ypp1sXBPlFwtZDB3Jm6c
         5vMT5un0Nm3POrYTYRw54LKGDgexZNeyGItx3ZRNw1VwCpyCzoYXtfFCmHlf4q8kXm/a
         DWdSMY8BMlPXY1jzjWbWq1P6J0eDi4llN7e67JPePDcpzyadJyimpo9jn9RAOh9g6Xx3
         neeHhXpSooav1quapTCmUQcg+td8WkjC7o+TlktUMbdeZCaPhmou9Emk2nIgBAiPrd+r
         ydquGhmo2476mM94WIlDHSJGrK4ctDr0C/lJwG7Ak6ot1A0Q21Hz3AbScji8mbSZ34oM
         YnEw==
X-Forwarded-Encrypted: i=2; AJvYcCW1vuBV4a+ePjedcSTyjsBt5JC1JsaAK2Un7yHnUvNfAT5kiCGcot9p2zc1++9oostiYFwOgUzOAX9x1B1PEne2XXpFhs/aHQ==
X-Gm-Message-State: AOJu0YyyZC+V8j9ZVH0kh2JdVDvICzzGXZRI/gtBne3LlX72duuo7qYR
	MDb5yP0n7L4CLpvJnN5puJJgubSdaIOXqhBrCFsb8Xk3y+/P5Ygb
X-Google-Smtp-Source: AGHT+IHUGMdDtZrwkpsnvFlGS2MBpcPIiMJem8ofInLmzCXbM+rIwmyicnR/VCop9iU8m9SQGwWqYA==
X-Received: by 2002:a05:6902:2689:b0:e13:e606:1ab1 with SMTP id 3f1490d57ef6-e13e6061df5mr6269537276.14.1724103344689;
        Mon, 19 Aug 2024 14:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:100b:b0:e0e:8941:c387 with SMTP id
 3f1490d57ef6-e116c019ec5ls568561276.2.-pod-prod-03-us; Mon, 19 Aug 2024
 14:35:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2FTspgtMrNMpZrb3wNZc2tvUTeOec8TFiEC4UgqyibCObUbh+9eJDjVYvE+eoZcKWJ7NP2u5E2ebdgHPtVWTP8Do3J2eLwjDcXQ==
X-Received: by 2002:a05:690c:f:b0:6af:a6aa:2b3a with SMTP id 00721157ae682-6b1b6ebeb20mr128061097b3.1.1724103343945;
        Mon, 19 Aug 2024 14:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724103343; cv=none;
        d=google.com; s=arc-20160816;
        b=Kq1tizj817dPxFkO/Cq/lQCcWJmVmNOA2GTGN34lCNYCmD6lpb1FtvXN+2VhzyKnm+
         TR5YCsb8EuKA/j/ubASYxRNp8rdgM01f3qgR1NE98ftqoymRHeSF8TblRyvU27pYJNVN
         couybIoRcc/P1GdbUJThm2ySp78RS750rkzRj6zvLtZc0BIHfBWB66iAcdVgp2x7THDX
         nCPkTWhjfoGqETLr+XC/eyxi3Og5oCMHygse+N/esiXCB/D7/SWDeZjVwLmV01shRKuw
         stIRtQo5H7n3myvEY0SSH+kPqsgKmJhNK1BHECQXTi/0ix93qPZfyXDks2Y6v4NHBStm
         fx+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dYHfB1jRSques99oHkY91uNPL3BC6i2xvsHR0qX5+O4=;
        fh=Zr6GZ3xQvC21gJBiYfi5xtrW2tX88y7iKKsJFXGVz0U=;
        b=SsrUkeUjXqAzUhsxpEG7ZSEMkyFT78bHjXkU0AzXtm5MzW+ccMCKsBNhi5ufDuRZpL
         3apaI1KXcxtLq/V8bbIt/9m9AJKhJ4jTxxr4g4bB58wkKzvI9z7m/7qH4knK5CyOAa0H
         LemhDHR97mD4Uw4CWkNW9v9KYYlbHoAg+HIYefR4MyNRMabacMK7bbfAPDfOg8LH2Ijt
         S0nUMdeSD+YegCFmerTbvwUghzgUZU7ACSo1pfe8TZjuDfrlSuC2DIjCHtRMhijaHyJH
         HOTJK+wRONmGqAoyWyIXdm6AuiSe56Ziv23cbAbw+4X4SnPZtK+kcWWwKjJqXa6fxZkd
         nKIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bGrKVGvy;
       spf=pass (google.com: domain of 3r7rdzgckcxaaaoifsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7rDZgcKCXAaaOifSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6af9e1d9412si4380227b3.4.2024.08.19.14.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2024 14:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r7rdzgckcxaaaoifsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6b8d96aa5ebso32737297b3.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2024 14:35:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXuO6QoAqTmtso7cXPD2QKgGveF0d+DsOB0jVZ/7tL9zx6mlbsmrhqH/BIExI7msp0uVG2/yN3wiboErvrejIrynOLo2b/CMkiYnw==
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:2912:b0:62f:f535:f41 with SMTP id
 00721157ae682-6b1bc5e4037mr4097737b3.9.1724103343636; Mon, 19 Aug 2024
 14:35:43 -0700 (PDT)
Date: Mon, 19 Aug 2024 21:35:19 +0000
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240819213534.4080408-2-mmaurer@google.com>
Subject: [PATCH v3 1/4] kbuild: rust: Define probing macros for rustc
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Masahiro Yamada <masahiroy@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>
Cc: aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, ryabinin.a.a@gmail.com, 
	Matthew Maurer <mmaurer@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bGrKVGvy;       spf=pass
 (google.com: domain of 3r7rdzgckcxaaaoifsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3r7rDZgcKCXAaaOifSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--mmaurer.bounces.google.com;
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

1. `rustc` support will soon be a minimum rather than a pinned version.
2. We already support multiple LLVMs linked into `rustc`, and these are
   needed to probe what LLVM parameters `rustc` will accept.

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 scripts/Kconfig.include   |  8 ++++++++
 scripts/Makefile.compiler | 15 +++++++++++++++
 2 files changed, 23 insertions(+)

diff --git a/scripts/Kconfig.include b/scripts/Kconfig.include
index 3ee8ecfb8c04..ffafe269fe9e 100644
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
+# CONFIG_HAVE_RUST is not set.
+# If you are testing for unstable features, consider `rustc-min-version`
+# instead, as features may have different completeness while available.
+rustc-option = $(success,trap "rm -rf .tmp_$$" EXIT; mkdir .tmp_$$; $(RUSTC) $(1) --crate-type=rlib /dev/null -o .tmp_$$/tmp.rlib)
diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
index 92be0c9a13ee..485d66768a32 100644
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
+	$(1) $(2) $(3) --crate-type=rlib /dev/null -o "$$TMP",$(3),$(4))
+
+# rustc-option
+# Usage: rustflags-y += $(call rustc-option,-Cinstrument-coverage,-Zinstrument-coverage)
+rustc-option = $(call __rustc-option, $(RUSTC),\
+	$(KBUILD_RUSTFLAGS),$(1),$(2))
+
+# rustc-option-yn
+# Usage: flag := $(call rustc-option-yn,-Cinstrument-coverage)
+rustc-option-yn = $(call try-run,\
+	$(RUSTC) $(KBUILD_RUSTFLAGS) $(1) --crate-type=rlib /dev/null -o "$$TMP",y,n)
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240819213534.4080408-2-mmaurer%40google.com.
