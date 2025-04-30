Return-Path: <kasan-dev+bncBCVLV266TMPBB5M6ZHAAMGQEKHYT2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D6B87AA51A2
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:27:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-30bf554ea7bsf335051fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:27:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746030455; cv=pass;
        d=google.com; s=arc-20240605;
        b=YSRUl9WdsYsnYplimuNLtAV5hWtL4p0DPi87uVPpnhf0KnjyDmANDq4V/jDDAN1rpt
         esFhZNZqJ/92QQhf9juRI0eNN+qCobkyTBqh3sVq/apOjQQKQexE4UGaX9q7NT/bLT4L
         LrZ4b/e3v6Dn2d+50eJZFGOiat7oaCPLDr54pYmDKIcqvbmAjk7uHr8g8RY6jhnGGeN/
         naqDbHieyAUU35eYKE+xnTFXSMZloSg1ySHsae735E1D9EN8qV+zw+xAKTC+bGTx8eSx
         tOnFsAtJ03uAXx6eyH/aFgqZ43eHDum09JT8fk3Iphf3MocrS+d+269ctY6acQ28E180
         f1bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LOOhLbs1nPt16PxuzuhCGW6FxrSt58YFw0qLaHllaZE=;
        fh=vy2LzJvcDmQQzbtFyDyezUUGD3dM0Vj6vu5McHC5Q6o=;
        b=R9W4IgT7s9gmI/oSKd5ghWu1c6pq2K2mfvBi7Ydi9GyVNDBcnd0WqhxfAyNbbBCQVs
         CaF+nBTT3OzmhEJFCI2Tk7dBmhsejf8g0cbvx/CaPclsBAi/u0I6YjxEVc4vDX5AwVWy
         I3a+kcUnPhum2I5PWPRN6T6CKpYCcZLEhqYjx5t1UI7TU1IssdeJl9WcXWLcKekIaWgF
         OoZo7BrdIwn+GICHP1SfsMHb2KCx2Wu1vHtnNiDJ8Y+KDs3Eohmvqzuo1qbmp920AijA
         BczNp9U8tWkNl3AOsh0ejbz3ij9n4vFC13Hqc1t5sRxWjbYJctdck/kGpOrihBkzXArQ
         mbSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BOb02g+a;
       spf=pass (google.com: domain of 3ck8saagkcaetnptubgbhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ck8SaAgKCaETNPTUBGBHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746030455; x=1746635255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LOOhLbs1nPt16PxuzuhCGW6FxrSt58YFw0qLaHllaZE=;
        b=vSvHhwbW4QvoaPg5oXv5Km2Y4OJ+snvqEr7plOaEonLtiCvav1tcCM/YFfTAo62LY7
         laE6tlkHGN5KwLl9WiHzArspmA8Ph8xNMNEPhu+FyX+ju+8kPo3QEeKcXJrXusXdE5/d
         T9tHSBLXSmqxpRQElSSm5F+6lHoh4XBWLsxgtyUCF03WB/sXw88ezuGqHXTdsgUVdzPf
         pHuNAZJRFOTXS96OLaV2/4afFtoD/lZ5Q6k144oH6HHaWHW0fgiZHl0ZNVSR85tvH+An
         Bx92Z2vFGEsQv7NpjUMwRhllUMDIknkiHPZOoGWEn10+VlI2OelN25hAdkTLUX631cme
         0ijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746030455; x=1746635255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LOOhLbs1nPt16PxuzuhCGW6FxrSt58YFw0qLaHllaZE=;
        b=K1fQQV/ezXOSmKnL07nfihLLFHbM3nhNX1bJpWZCW68h7A3GOWPhxOGJVG1seSit+c
         85UcDxPET2gJBxNabXk/5MRWseOOZk7FQjNiNHWs8j1Pqp8NlamEWBeqQOwelOizDZlD
         izfDeK7u8NPSCHrx2IUAl8vNVkdo5C+wgeYeMJy8f82r1JGmg1zdeJ637pJvBfweoSpI
         kIKa19eX0dLdDO6WrOaHsIThZX5QFsvdXQBz9NeTv1o8y6KgUz3Hdst7Y+nkzQS2MeEg
         hy0mBW92uCxRTdyCTXOFJxPT1dD2oKkeDSXHMJiqXm/f+JPy3SsUyh3MgaSiTTBKvW53
         mMEA==
X-Forwarded-Encrypted: i=2; AJvYcCVXtfM7g0tEvC1LH0KPgI5ram4Jvzi5xUQloifMZy+NWKl+NOkYkeM28aYpibOpZCXSRotMyA==@lfdr.de
X-Gm-Message-State: AOJu0YyoWuqqZkQKIkKL5v6jhHszJRuEB6M2BNkjcBoEobl//KS7Ik/W
	CWzGXuIthCZ/wJL784JvUCeSdmKQbOBMK5ov/A6q2lhtN4FVUNxR
X-Google-Smtp-Source: AGHT+IGUm5vTXiqMWm+dP5Z97+I7JoqUvLkzNSvX+B2CyubTPQm4mE51wiLYNMrH4ulC/FDMu2oY1A==
X-Received: by 2002:a05:651c:2221:b0:30b:9af5:9549 with SMTP id 38308e7fff4ca-31f7e808fa7mr723301fa.2.1746030454184;
        Wed, 30 Apr 2025 09:27:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF8KGyyOwp6LOSUJhqztm90CEPLuzy2LVUCA2GYvBtYJQ==
Received: by 2002:a2e:e19:0:b0:30b:eb0a:ed6a with SMTP id 38308e7fff4ca-31f770deacals121741fa.0.-pod-prod-00-eu;
 Wed, 30 Apr 2025 09:27:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVX0uUGlNlcdEqX9lnJEuoBBswsupgwUmj2cmJ/wts+E7fTOpWdIa1WdMKiAPM9JqisYZNk2WzkjU4=@googlegroups.com
X-Received: by 2002:a2e:bd03:0:b0:309:22dc:6917 with SMTP id 38308e7fff4ca-31f7fd68513mr413201fa.19.1746030451158;
        Wed, 30 Apr 2025 09:27:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746030451; cv=none;
        d=google.com; s=arc-20240605;
        b=Du7sXgOcw7VVLlxqaRUeW8oia9Y2nmwoVB3fcCdUrFLyd8gtNDcaV6zR8K7a+pNkXt
         v1MdM20i0mHoGEFdsTuNgZnGYxBsOTRtX7wVFCMDxxRZGiq3835vY7RVXjmW6RLaLTiD
         H0E4p7Rrx50PR0eDDnTronhPuYNYbu0Fhp7KyUoQJAIxECCbyG7Q/5cYO2TD6qt2oqor
         MsEwjAzmeJTnUFpVaQ17zkSaMarf/aZMkT1lEHRPcsWHymELHCCGya43nYmUnyUgtWmi
         d1ySJlSlErPMKszcimQmYdSFNBj2NkRhDlkQPxqlbCo9Rw5IjzCaS3F4ToHLb6Gw/rWH
         Yk9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=V1qsu6fkrd6uduOladyyR4ZyoWD5vL8Q+jaWgw+feE0=;
        fh=rDN7APA5NsiZxdu7B4QKDms2FZ/btOOsKUWPq6xNNU0=;
        b=NjH3Jkl/MIEvTZUQ9r1U5yeAA4DX8tzF9CFh+vc6q+SSQ9mVjYaTsLWP3Ir+Xe1eJw
         1q5sFQDt54F9XUFofSHWyAvb+gQH5UmkKvr0YaYB8AnCx8nz8csZkesgD4xMrd9FwQ+n
         9CGk3B1Vz2XqgvAVn4+DhmzmTy38m1ieHCaN2UxHtTSvGhOQFbAtVc1K/J/aZJ8+YmFH
         r3ncMTvM5oVtgYTEloDuPJ/9bbumk97PSn1vAo587NqFVUmykeQvUiFe4Us6Fv6HhbfG
         Ku5gD7wcnsL6FskEgzg4tNCHI3N29IVjumTFfS7ePil+ljghQ7q+Gd8V2sku7brStZ6k
         sP9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BOb02g+a;
       spf=pass (google.com: domain of 3ck8saagkcaetnptubgbhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ck8SaAgKCaETNPTUBGBHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-31e95af4e93si260451fa.5.2025.04.30.09.27.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:27:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ck8saagkcaetnptubgbhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-39ee57e254aso3639723f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:27:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUImccFVL/3xTgtBb8tTt02ps4MMCpvF1REQ4LJvbQW4+GwmisTtchjdhMWTZZQxTf16XYwacB4uRk=@googlegroups.com
X-Received: from wrbbh10.prod.google.com ([2002:a05:6000:5ca:b0:391:434a:b7c9])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:adf:fbc4:0:b0:3a0:7fd4:2848 with SMTP id ffacd0b85a97d-3a08f7a4abamr2805108f8f.52.1746030450479;
 Wed, 30 Apr 2025 09:27:30 -0700 (PDT)
Date: Wed, 30 Apr 2025 16:27:10 +0000
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250430162713.1997569-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250430162713.1997569-4-smostafa@google.com>
Subject: [PATCH v2 3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
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
 header.i=@google.com header.s=20230601 header.b=BOb02g+a;       spf=pass
 (google.com: domain of 3ck8saagkcaetnptubgbhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ck8SaAgKCaETNPTUBGBHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--smostafa.bounces.google.com;
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
index b43426a493df..a76522d63c3e 100644
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
+ccflags-y += $(CFLAGS_UBSAN_TRAP)
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
index f6ea0c5b5da3..42ed41804644 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -165,4 +165,13 @@ config TEST_UBSAN
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
index 9e35198edbf0..73c7a9be0796 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,5 +1,8 @@
 # SPDX-License-Identifier: GPL-2.0
 
+# Shared with KVM/arm64.
+export CFLAGS_UBSAN_TRAP := $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
+
 # Enable available and selected UBSAN features.
 ubsan-cflags-$(CONFIG_UBSAN_ALIGNMENT)		+= -fsanitize=alignment
 ubsan-cflags-$(CONFIG_UBSAN_BOUNDS_STRICT)	+= -fsanitize=bounds-strict
@@ -10,7 +13,7 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
-ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
+ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(CFLAGS_UBSAN_TRAP)
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250430162713.1997569-4-smostafa%40google.com.
