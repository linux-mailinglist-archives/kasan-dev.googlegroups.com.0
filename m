Return-Path: <kasan-dev+bncBCVLV266TMPBB2HC767QMGQEO4BG2AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9525FA90ACF
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:05:30 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5498f71580csf3865200e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 11:05:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744826730; cv=pass;
        d=google.com; s=arc-20240605;
        b=OOmtBfYW3Bnw+kzjvAWPSBhnyLqosVe4ra3a6ISKj6Pvy30oG/skQUKFC7iy6iqYlY
         uXMIbYzY+3SYUvOET87RLmZ4B2spxzEyCEu0ONtFLM2vAahHSxLdwjehe8m/A6sqmnx1
         TvAc+kzsTkE1czApqC9XWCTCDcXFBg9J9gjufD3rI/aJ6CZrC3ZhTNJzq/Cb6x9M6e/u
         RcYZusQ0CFQ5cpLVBc9x3JYzCERVGUWAib3ychxXDZbEWbkKlAmzIbGxpRV1Q03c+uzW
         BrsZeiIAt8Aj8iAxapX798GwZRmD0ycx1uGetyAQ1llDNyCAygWLBKOpYL9HF5Ukww4h
         Yz7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PagkSydAl2JiDfH5+zZiCFbFajoRm8cNOUZIxNfIsAI=;
        fh=EkiO0VBs8r0G21HV1BgWFRdNk0FFNuf75p0hvmkNXIg=;
        b=EtcelC4koC0aTN8ThMaAdzSbqLZZ0AbLJgmpAaVKQuJjb1wJPjc7SJUltFwH+AseGU
         wQiNCwDEakHpL1BSLXRbWrRf59zk/co1nFxMvHkbds4UuINlNbuUr9PvzicFYSCeb3kl
         H6XNv5wU9xHgBefYHRo3QJAUN9lJetnE1RFpLAx2OjLTJOCZ0e4FjqERyiFpLRjJ5XPp
         8GJ7H9hfswoFee9+vLt1/WtNOa1cgPuOHPFR0yf3f3KwjS3LqgQYskL4UHg9/27abtdk
         DSkuqpaXClptyMUODflVtA3NUU3TSYiZ24U22hBTtusv2oHBxrII77uiOgOz2Go0QCMW
         2n/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Oqff/jxU";
       spf=pass (google.com: domain of 3y_h_zwgkcyw82489qvqw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Y_H_ZwgKCYw82489qvqw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744826730; x=1745431530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PagkSydAl2JiDfH5+zZiCFbFajoRm8cNOUZIxNfIsAI=;
        b=kJ8f6SOxIYR90bg95snKgDlfy//c+wFN83/tDdea/34weMNXf8tt5vN0AQviV7jvCc
         OGGUIV64vYtm01KmEC+dG6tXSRLjQwevQEEHrxB+mz4/TlfiDnu+fGdynKuwtnf0tRyl
         0rR3M9mJF1tQUMlbKHVbHBn0n9EAz6YypTlJFgfKxlfN5mNAsdS2jMD8DnSqlcfWgaGj
         MhwvgyoGJFuSeA//vvfO98SiibwwlvAYnSxPCtC37oJeAracZhyE6+nwqwF+B0LfRk/K
         MDY+oM6aZpYbpltRks2lOXGQtYxAWpJLm+CqXc5CItmnRqIIq/YqlA8nJai2cXFEk8I8
         E8mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744826730; x=1745431530;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PagkSydAl2JiDfH5+zZiCFbFajoRm8cNOUZIxNfIsAI=;
        b=KaqTyRovc+sTfAi3h+87vtx/O4P1gxbCgAcGJqjk3CeHF1BFCi9+UdDfQgon/uDGSO
         QnpvaE6GhHBjJATFpwk0zhuh6k9vzWrnIGcowCrwHmWoWSL8cxCviNszf7GsXaDgpwCS
         E+SlAVDTQr2heVo5RlbIuwi0jnK8jib7h8v6MnYA/d2TwMBfV07+Z7krVzVMCbFlKN5r
         B/CvnTss6r6rUFZP3lXHw+G4WnU8UrmlZvlfEUbYTg35d0UEwzgVqR4G8EaxUYUcI+PU
         BWSEweFaUxrZsYoQkTCVlHjc4oO+vlm7nQJu1XbdG5onLboEyIob3TCZCOe6254iTHdK
         SK0g==
X-Forwarded-Encrypted: i=2; AJvYcCV37f9pycW7Asc9kiyFLqI/fUOf0LO/06k397To8q1S0K/UROsfscBIB1rSJZmWyOCWy5HVyw==@lfdr.de
X-Gm-Message-State: AOJu0Yz4EfeZGI12zlI5owBOFlrAMVN9kCa3lbBki5dowY157J8MkwP6
	bihy2eciBtFi6AFC/5pn++lNDVjYe/iNZoqzXkXZHt7HG4AFBfEy
X-Google-Smtp-Source: AGHT+IFrFJ9C80OPqlXm1hJRszs2lhz2oTzKDdpBzcGtB8Ts1K2B3+9VEc/rtvA7aeULlSpDM/C0Mg==
X-Received: by 2002:a05:6512:3e0c:b0:545:3037:a73a with SMTP id 2adb3069b0e04-54d64a98ee3mr986887e87.13.1744826729369;
        Wed, 16 Apr 2025 11:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJFdUNe9KzRJbTZ39m5idmeYelZNV5kft3D/j8SIcSOiw==
Received: by 2002:a19:8c41:0:b0:549:9221:d9db with SMTP id 2adb3069b0e04-54d68bb2d93ls32947e87.0.-pod-prod-08-eu;
 Wed, 16 Apr 2025 11:05:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUytLIoshc5dwqqicXoiX3v+o9lTQtQTny4cnyqfHgubVNvUQch9otTpT2i2pV6MeWeoAA30kDSgso=@googlegroups.com
X-Received: by 2002:a05:6512:3c9f:b0:549:b1c1:4d76 with SMTP id 2adb3069b0e04-54d64a7abf1mr903850e87.5.1744826724374;
        Wed, 16 Apr 2025 11:05:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744826724; cv=none;
        d=google.com; s=arc-20240605;
        b=diFbMKefvzSR5Y4gyfEH6JeJI8+dAsdP3mizuHzfs/3mgHfeeY46QGP9Kr8vh4oMMJ
         4r5xXG09nJ8w1qSEplIddOoGx1Uk4z1D3/r18d0hIN9o3OzhyRp3cGucmf9PG4Ep+Tfs
         vdjshKIquaRcQaJPUGViA80YkQJ+WRzBo+GzWDQgADg0brjhGO7ioUlO+dp0/lz5E9O7
         cIvsyu0ZAWFT5TZEk0rVwj8cecRhcyjitxAFuY3rv/yJOtl3+BAfJYtYi4ftmHs3C4XR
         BO/Wae1qGBY6OF/46JyIenTVBh5oTdILW9XLz1C6ejsOVHA28jK6vDmEqulcyQNHvfEz
         KeWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KCvuX6D9+WTa2u7saZuKw/wens1B8oyovtAYHu1B0nk=;
        fh=/vp5lkni8l3F7yd/r1gBcfI3UHG0N6fJIbp+s3IX/BQ=;
        b=JupFtpmzrhP/riQhNhkDJsG94KpAiXZFTRrXirJRioz1dFDmW7WBiwZeh8Rbgcin1m
         s2aeYFEur1dOfBnllRP+a0K4/MT6PeGK3n6SBemsmM1HjLzlPKrX3qHKcCDo38dPKw2J
         UFUA7Utc4EWf7iTkDC6dmJuN/kKW45TcCCxFWrUsFgNVuw9BTdHlORaWU9FLNnOfV/rd
         vj0dz8NaWs2/ZGsMX8r/R3ts45ebKNbNoajzj7bZO+wDFkegq9uCNZo+mPuhxfyxYqo4
         P6qZckhbChzl01pmkrWwt4ucBNM5vEbasHHZ9Xk4NLlcUFn0aUw0lmJ8lAjl2YaPStqE
         Fyqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Oqff/jxU";
       spf=pass (google.com: domain of 3y_h_zwgkcyw82489qvqw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Y_H_ZwgKCYw82489qvqw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54d3d508a4bsi440899e87.6.2025.04.16.11.05.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 11:05:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y_h_zwgkcyw82489qvqw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43d734da1a3so36228835e9.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 11:05:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvc3mVrUGanF/FHPqy610S/bNoMta+4XoqPNN+o/q1WdEIV8S5qUxIBMB283JUfukTcNaARnGyjOc=@googlegroups.com
X-Received: from wmbh25.prod.google.com ([2002:a05:600c:a119:b0:43d:586a:9bcb])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:a0e:b0:43d:d06:3798 with SMTP id 5b1f17b1804b1-4405d6adc5emr27421125e9.20.1744826723681;
 Wed, 16 Apr 2025 11:05:23 -0700 (PDT)
Date: Wed, 16 Apr 2025 18:04:33 +0000
In-Reply-To: <20250416180440.231949-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250416180440.231949-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.777.g153de2bbd5-goog
Message-ID: <20250416180440.231949-4-smostafa@google.com>
Subject: [PATCH 3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Oqff/jxU";       spf=pass
 (google.com: domain of 3y_h_zwgkcyw82489qvqw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Y_H_ZwgKCYw82489qvqw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Add a new Kconfig CONFIG_UBSAN_KVM_EL2 for KVM which enables
UBSAN for EL2 code (in protected/nvhe/hvhe) modes.
This will re-use the same checks enabled for the kernel for
the hypervisor. The only difference is that for EL2 it always
emits a "brk" instead of implementing hooks as the hypervisor
can't print reports.

The KVM code will re-use the same code for the kernel
"report_ubsan_failure()" so #ifdefs are changed to also have this
code for CONFIG_UBSAN_KVM_EL2

Signed-off-by: Mostafa Saleh <smostafa@google.com>
---
 arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
 include/linux/ubsan.h            | 2 +-
 lib/Kconfig.ubsan                | 9 +++++++++
 lib/ubsan.c                      | 6 ++++--
 scripts/Makefile.ubsan           | 5 ++++-
 5 files changed, 24 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
index b43426a493df..cbe7e12752bc 100644
--- a/arch/arm64/kvm/hyp/nvhe/Makefile
+++ b/arch/arm64/kvm/hyp/nvhe/Makefile
@@ -99,3 +99,9 @@ KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS), $(KBUILD_CFLAG
 # causes a build failure. Remove profile optimization flags.
 KBUILD_CFLAGS := $(filter-out -fprofile-sample-use=% -fprofile-use=%, $(KBUILD_CFLAGS))
 KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
+
+ifeq ($(CONFIG_UBSAN_KVM_EL2),y)
+UBSAN_SANITIZE := y
+# Always use brk and not hooks
+ccflags-y += $(CFLAGS_UBSAN_FOR_TRAP)
+endif
diff --git a/include/linux/ubsan.h b/include/linux/ubsan.h
index c843816f5f68..3ab8d38aedb8 100644
--- a/include/linux/ubsan.h
+++ b/include/linux/ubsan.h
@@ -2,7 +2,7 @@
 #ifndef _LINUX_UBSAN_H
 #define _LINUX_UBSAN_H
 
-#ifdef CONFIG_UBSAN_TRAP
+#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
 const char *report_ubsan_failure(u32 check_type);
 #else
 static inline const char *report_ubsan_failure(u32 check_type)
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 4216b3a4ff21..3878858eb473 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -166,4 +166,13 @@ config TEST_UBSAN
 	  This is a test module for UBSAN.
 	  It triggers various undefined behavior, and detect it.
 
+config UBSAN_KVM_EL2
+	bool "UBSAN for KVM code at EL2"
+	depends on ARM64
+	help
+	  Enable UBSAN when running on ARM64 with KVM in a split mode
+	  (nvhe/hvhe/protected) for the hypervisor code running in EL2.
+	  In this mode, any UBSAN violation in EL2 would panic the kernel
+	  and information similar to UBSAN_TRAP would be printed.
+
 endif	# if UBSAN
diff --git a/lib/ubsan.c b/lib/ubsan.c
index 17993727fc96..a6ca235dd714 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -19,7 +19,7 @@
 
 #include "ubsan.h"
 
-#ifdef CONFIG_UBSAN_TRAP
+#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
 /*
  * Only include matches for UBSAN checks that are actually compiled in.
  * The mappings of struct SanitizerKind (the -fsanitize=xxx args) to
@@ -97,7 +97,9 @@ const char *report_ubsan_failure(u32 check_type)
 	}
 }
 
-#else
+#endif
+
+#ifndef CONFIG_UBSAN_TRAP
 static const char * const type_check_kinds[] = {
 	"load of",
 	"store to",
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 9e35198edbf0..68af6830af0f 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,5 +1,8 @@
 # SPDX-License-Identifier: GPL-2.0
 
+#Shared with KVM/arm64
+export CFLAGS_UBSAN_FOR_TRAP := $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
+
 # Enable available and selected UBSAN features.
 ubsan-cflags-$(CONFIG_UBSAN_ALIGNMENT)		+= -fsanitize=alignment
 ubsan-cflags-$(CONFIG_UBSAN_BOUNDS_STRICT)	+= -fsanitize=bounds-strict
@@ -10,7 +13,7 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
-ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
+ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(CFLAGS_UBSAN_FOR_TRAP)
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416180440.231949-4-smostafa%40google.com.
