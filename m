Return-Path: <kasan-dev+bncBCH67JWTV4DBBJ7VRDYQKGQEXWPQDNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B67414146B
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:52:23 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id o6sf11048495wrp.8
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:52:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301543; cv=pass;
        d=google.com; s=arc-20160816;
        b=R4SaH0WOna2O43P0LQKtFR/ppyyOHbjyiFPJdEJz/HrOzuKGKF/V3jS10GQnpN1zBX
         ADUF1tS11fHq3rItvl2c6YL/lBOS7C/vWeLn1FTZv7Y61Z6bBxPoaU/cjcFg9Z+jDDvI
         CnhtZQD849kF8ANRDIduBlr6YbHYuXz3dBiRtnxeDWEDjoI4mYUScT9qfcP0HBZpldCG
         4waqItBy/L3U3AE9Yp4mypsaH8HN3o1IUEcgR5w4vz/LPRNxUbOPkmQMFAkjXk5dpbl7
         yzSFGoPnVSDWGSlHmFaIdvTafkW4T9ubj1m1ZiCl5HEAPSTuWeIdS9tYqK+H1juSUv0P
         1cww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Urk3cphKdTDpgloNXKBvWCk9GGxzhDrFNkLRd5rtrzw=;
        b=TdO//gIRqdtXPz3VZatWsQqKtrqMeAIdsa9MAMAdSo2XuEk+TnqHRpmdZyKba2F/EG
         JrPQLXYmJ7th2m47MYRAaT9NMxi3Ef+W34BZXcYaf6PvVWR73pAoVNqylU+iGW+TA2g6
         mz73JTJ5/AafyrXUc9a69hkKCdJ4qWpoVfKR+pF85SdyVJdDfQ21ziCESE4Lo3F6+U5B
         kzhegwSnMcQfBHHB/K043vmpEbQa7WFDkHZDCeRzQUJW4sqoKc7Z2pyo3G1vYE9i9cOW
         Pr0ZkeQq9FFjmFuL8TqenarkWRrOWb7TaXONyf542gj1nKkfWNkqG4a/ZvCUQpVc9L3y
         iBoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ITxORkbK;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Urk3cphKdTDpgloNXKBvWCk9GGxzhDrFNkLRd5rtrzw=;
        b=VrKBXJ70XLjfnXwP3XH+mqgF1SwWOXXXl1tXJ8glXjkxFNSdfqFvueRv1JKTpr/U18
         LDL0N35f9hXJLTLZzCVawRX1+820pJ+bQ25Dv0ZAPsT3eRh+ibprquA+zn7LcvHpy94w
         VevlCYsE/LOKQvxS9lxAZessM9lD4gojdeScfW2oe2u+n2qZYi7VJ8q1J1CtD3xbevDc
         VGgPMPSU/X5625HaYJqp6/zEzicKJcSNi1EUeANHfSSHhb5vcH5eiHe7LFaTNHsUdcy/
         vF7/D+2cjkkk/W8uNEppJ5CUMLhitoO+gcOznWyQxKbkxQlXybcyxayPCAdlVTiPZuwz
         leZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Urk3cphKdTDpgloNXKBvWCk9GGxzhDrFNkLRd5rtrzw=;
        b=Lmf/34VTvk25eD2vwmfyqGEzMEf3G84Je1MxuW251SlwxiLBMbmtjbg8vkUq9u97oA
         xPXzb//Qn+1kbdECEepigxsItbg3HghSD8UgteyBepEltRd9+AgQOGoZKhe3sGq/wblW
         W+dql24Nrav2jCA3RxSRo9YVl2dytFI8hn3hEKRViDMe3KpgvDOH3s2V78avvAQFM9Px
         PBi4z3c9hqOqOYkNx+cL2NLeEfHWXQqIRXm/9c/MshDinAfrg00gUJYVvW72C3EcZY+U
         sRczj2bTWdoBbA++7xtIx0vR4jTulq0xGSpatd8BtkvZ64FEsii0A6Qi+uEWaqDgc9mj
         xLvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Urk3cphKdTDpgloNXKBvWCk9GGxzhDrFNkLRd5rtrzw=;
        b=IHxkU6uReUU60ib+L704DxiTd8bhH6HuRMxm4WRXBLL26PpkY1sOgLH17jthVhNFM4
         0oTuish6QSs0/gDohbBKaFFuHUXF8EdNuAXG8Q4vegXBSNdrC+fxVRGk+MhpmbiQAJ15
         YSXNyQkl/ussP6Hf7FaXE7i6XPGcZsXYFSFf+Q7bmOKJUyFs+1BNPwSAHfsXKhhL0eQy
         Y+2VW7TzexYX0DLlIeygM+TwfiYzAEkfTCBbigayQAxWlYNSNsieGGVB63i5lwcHTVAG
         ZgQ72Eqx8u1lZCQ5arR4CtVGPgA7deGj/EHz0eYWO+tkqQuVCzf5iEeA286z4309BekX
         Rn1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUpXhA94lCCn33w/9r2YYUd8+l71ilipicTrdkFkoz1ZgAfMFRs
	xzXi9hNALRFJHhdkbLzsnUQ=
X-Google-Smtp-Source: APXvYqwsCDcNv/t4R/Auz9p0pe+mnXmWtQNQTx4rFPpkiWKpuNygsun0wNvKyO2lTR9rTE/XqU3iBw==
X-Received: by 2002:a7b:c450:: with SMTP id l16mr7046599wmi.31.1579301543154;
        Fri, 17 Jan 2020 14:52:23 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9dd4:: with SMTP id g203ls3141818wme.1.gmail; Fri, 17
 Jan 2020 14:52:22 -0800 (PST)
X-Received: by 2002:a7b:c216:: with SMTP id x22mr7006605wmi.51.1579301542521;
        Fri, 17 Jan 2020 14:52:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301542; cv=none;
        d=google.com; s=arc-20160816;
        b=QBxkgB7GenLGqRA5QHAOb5AxEHiG3DBxf2Btw1QSb6JE4qafC1phtHPFM89IsZ+zoq
         GQ/cFggnwm/uwh15TKk+6KWJnfBbsoP3k41ja38ZJ2RIFK0wrOguTxSKpQ7Zq8QnbsH9
         XJ+/n4wt/63xPfmNK6No2M6t3KD7Lc1r4TSKD/c05n8WnCD0QvyLLDrv3HP+IaCjR5XT
         L8inZMPItmV7Y4/KNu6DQgF28NiCss32pFcBFucMiUTe/1l4/FAKEG5xEII7ytVNVMsR
         8vORrZHmJADFj4ugNgERe3cHnFHUkbJNJ9AmY3Zo26/HOR3MXIUeYtsoIC1NDaUaSRVi
         U2FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=kkVH3WV4mS0X3+3FT56qa2DP27GgNwjhnKPZdjR/cEg=;
        b=O7t9tk1ygbl1JgBnuAFpG4NmMxTpNe5iM3C0/IQA+RIhCWGSQhLkWXElYzGu1F2BN/
         MbUQM21gBtAV8FNEqlD6KiNWaQe1YyRg5GPFp1ajg5+D97NdYIMaWVb6tlLZ0lHWsV2C
         WeVmu5HD7ndBYx2PvlPrPCc31gikja7RAhNiZV8Yjg31d/lDimJE+2lEdbWdGt13fQM/
         ZRfih9bw4rNaY5w3Z8ZhPzmEJhzKoNqPjv324lBXvwpL7NMnKKQzm5wtHox+r9DKjRC6
         +ij63NSLAN8JGO9t71cUyJXDxb1FUqNn4ZSvXsuOQ4MsknMQW8gXGeNFTDusdfEhVGWA
         MciQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ITxORkbK;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id t131si282909wmb.1.2020.01.17.14.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:52:22 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id g17so24172394wro.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:52:22 -0800 (PST)
X-Received: by 2002:a5d:4ed0:: with SMTP id s16mr5523773wrv.144.1579301542065;
        Fri, 17 Jan 2020 14:52:22 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.52.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:52:21 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Andrey Ryabinin <ryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v7 7/7] ARM: Enable KASan for ARM
Date: Fri, 17 Jan 2020 14:48:39 -0800
Message-Id: <20200117224839.23531-8-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ITxORkbK;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Andrey Ryabinin <ryabinin@virtuozzo.com>

This patch enables the kernel address sanitizer for ARM. XIP_KERNEL has
not been tested and is therefore not allowed.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 Documentation/dev-tools/kasan.rst     | 4 ++--
 arch/arm/Kconfig                      | 9 +++++++++
 arch/arm/boot/compressed/Makefile     | 1 +
 drivers/firmware/efi/libstub/Makefile | 3 ++-
 4 files changed, 14 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e4d66e7c50de..6acd949989c3 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -21,8 +21,8 @@ global variables yet.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa and
+s390 architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 96dab76da3b3..70a7eb50984e 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -65,6 +65,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
@@ -212,6 +213,14 @@ config ARCH_MAY_HAVE_PC_FDC
 config ZONE_DMA
 	bool
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN
+	default 0x1f000000 if PAGE_OFFSET=0x40000000
+	default 0x5f000000 if PAGE_OFFSET=0x80000000
+	default 0x9f000000 if PAGE_OFFSET=0xC0000000
+	default 0xffffffff
+
 config ARCH_SUPPORTS_UPROBES
 	def_bool y
 
diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 83991a0447fa..efda24b00a44 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -25,6 +25,7 @@ endif
 
 GCOV_PROFILE		:= n
 KASAN_SANITIZE		:= n
+CFLAGS_KERNEL		+= -D__SANITIZE_ADDRESS__
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index c35f893897e1..c8b36824189b 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -20,7 +20,8 @@ cflags-$(CONFIG_ARM64)		:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
 				   -fpie $(DISABLE_STACKLEAK_PLUGIN)
 cflags-$(CONFIG_ARM)		:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
 				   -fno-builtin -fpic \
-				   $(call cc-option,-mno-single-pic-base)
+				   $(call cc-option,-mno-single-pic-base) \
+				   -D__SANITIZE_ADDRESS__
 
 cflags-$(CONFIG_EFI_ARMSTUB)	+= -I$(srctree)/scripts/dtc/libfdt
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-8-f.fainelli%40gmail.com.
