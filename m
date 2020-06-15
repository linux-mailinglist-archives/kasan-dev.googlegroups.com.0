Return-Path: <kasan-dev+bncBDE6RCFOWIARBOPTTT3QKGQES5YASWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 634751F92A3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:04:57 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id d6sf6779196wrn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 02:04:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592211897; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dpg5cMSziKoRGWc4yH+ReiRDKQ3ywGDn58AY3Z6QivDZcvf/rbnqbSif/p6kz4FP1x
         bg4ME5QSculXdCcNJnarO8ynrSzyQ3nJKlCnmtSXO6aZ18cdfkT5VJ1Lgr/iZNeKwUBE
         8jwwLidyldtHr4GIvLqjspVnvFKs41vRM7KWbDrU4EEcX4vrEGyO+cnLwQvC4+YO9yVP
         u8AtTkkjQBx/d2Vxfm/GO2WB7n294E0xvkp6oAgOH2bFJ57EzCL8iYveersdoNC+yVrm
         yQ+4HlVol2jpMwLnY1eq9Fke1h2kRFvZzU2ivKSuU9PU3/fI+YLfB9R/KF9SBSjXLt8A
         i29Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QbFbDRHp7fMT2SCk2zx6g+Dd3NWRft4YaYKpTQ0LYMc=;
        b=1Hj/xjnCMI1Jq5ZggH4PR9XJKlz1b0VyfE4pE/OCxVdOOrqZ73/pcr2ivpG9IzFgsG
         3Gzyk3zQvSpH2fNE8loouGmGCop0MrFhG9GQtXb42zKo1+XlCjxCgz4TSa9y171BJjF2
         UN5jds12c4+vcXH68xsJuOd5Mc1EQqmlvC5HgltcJdaapZjFI4uYx8TCrc/H1B1a4R3J
         InRhD8iKMDBIYmc5H8tJsRxAKuKYaLLbNWOflnx5P4lrN4/XreLrTxUoXQu7RX72UF5F
         xHRQuOtk2HDkpG6dIXGZRo1Bxz757j6dS8O8SgNdv2bkVHx4RwjCspgD5nluPtEE2Vfr
         NsXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SVb6Zt8V;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QbFbDRHp7fMT2SCk2zx6g+Dd3NWRft4YaYKpTQ0LYMc=;
        b=HkIGhvypJgKbAPFdrk28RmM3WBpOAf+v4CLiH1s5TLHUVMRHrTpSMoueHMykHNCETo
         6QXJ9RAKAQ0dkEiaUQlElFR68zJWSXpZm9X1bjtrPmy3R6AA5QWJK+fr7D2dybWlbskt
         +JPBFbdvxRQSdd7585EHFGmdBmdYjmIUWdIFHRbWZ5idHhPndjnm1iwKod2ypbSA5hoo
         pdDjUnMh83f3Bt8q8vK6rwLXmuvC9SkzJhtA26t2nCfQriawQJFW/R/bJlEawSOsJWzG
         7fe9jIeMN+kvCkn9+ws4KhOf4gNuo3PhivxdYMq72KLxgnGNG/ReBt+wK2lH36D7BKqk
         ubZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QbFbDRHp7fMT2SCk2zx6g+Dd3NWRft4YaYKpTQ0LYMc=;
        b=QysMvKM196NIVoyEdWZYgZ6X2dIzAEFfliv/JhiBLqaQ+spFo0B/x2z7FKhO8n8eCu
         X4CFyHyPsnQP/p+1zdVS2aKbLa4zPVkHykxjmPOLJobn2OsP7C/lbrY3+ahdqAbDtjjW
         XuDnU+wTiO9qHZx1ZHGAFBUp+2dqpAF5ggWB2ZflMJ6vxAQFnay5zuKJnhHNW5Doe2W5
         ZFW7/9J/G6Marzbz1nbs3F84t3BOVRSOqs86fAYhfSwBckQ9Xz5W3iVENPacVzyIQSpz
         yBoTmWDpTnM1EBAKPYbCLLeEVtDCGBwb7iw1WWV9QULny++MAjNjotZyM0TPSSWwUQ3x
         O88A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327ptZOHoJvNctLBNLHWVtjqO79heIoLIGiYzUP7xhP9xngF2yd
	jdq86T+7Lu2mUXn0rceJlbI=
X-Google-Smtp-Source: ABdhPJzyOVIBAR5xDe1n6DOqonro0kkxTn5JTroAYlyeeRfQ1pAgHlIawKV2De3dLo09wf/CS1Ve8g==
X-Received: by 2002:adf:f582:: with SMTP id f2mr29957555wro.204.1592211897110;
        Mon, 15 Jun 2020 02:04:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82ce:: with SMTP id 72ls8203909wrc.1.gmail; Mon, 15 Jun
 2020 02:04:56 -0700 (PDT)
X-Received: by 2002:adf:8b55:: with SMTP id v21mr28925764wra.187.1592211896560;
        Mon, 15 Jun 2020 02:04:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592211896; cv=none;
        d=google.com; s=arc-20160816;
        b=cn9flZpp5WF/PElTXCXs/6FAG6gWeAAMVRV4AOh2VOGsbytO0JQeQ89NJ76JOc+hnM
         PzJUFJC9Eq7r9OR0OJqHZ7tbaw79VHHxV6QjnpK7ZZEoyHkOq2dgGXl46ATcpNIOcnT6
         fmD/9kRPYR8zmCUF631eIyRC9OlpoHB48fWJcZPsoZ1ZqHRui7X78LAqBDhkegsmkCnV
         KvTu4pmgj5Pv8kOYpZpIMMy5lgHkhi6WemKpPctTp7NjnaAZQ+g7FkL1qlbjrlcRwq5b
         Q3aXDckjcIfv2W0yhwGS+u97HBCPFrpcF3aVdz9oPQ0k4K/W+srJ93UZRO/SBdtH3Zca
         NIDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Vlh54lde7Ac790L1VIZHjiID0UsLtjo+K5a58z7ZLwQ=;
        b=SU2Q1amlN5sXrcusteutE5TX+EtW5EMUyAvaaph44d+xL1Ri49o1zRj8wFDiBGfQY2
         DDIQSxu5QJml5ldE0HpPkaj3zWzRScrb0PRrA1L6ecDpAJw/mMu4q4SDQhqEH7EoAVoY
         VR1x/1kcvtEYDsNhB0Hkp8ip//4Lo9s9PLpl6f0XMVJQkSvubd3HCaHY17B+Vdv6mRb8
         9026fy6gw4QIcfFegMPB44x/xR3ET6C8WtekF/L1W2GShoCP8o5KiG1ou3arfeiKtFLt
         P8Ukzw+uMWTmU19oyWNkR8h2hZCuJS8XBBncE3PvDy8I5dLkfNIVOlR7kbyqiAbRnczu
         so8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SVb6Zt8V;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id r204si1074147wma.1.2020.06.15.02.04.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 02:04:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id e4so18242908ljn.4
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 02:04:56 -0700 (PDT)
X-Received: by 2002:a2e:8055:: with SMTP id p21mr13502031ljg.80.1592211895609;
        Mon, 15 Jun 2020 02:04:55 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id c78sm5284434lfd.63.2020.06.15.02.04.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 02:04:55 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Marc Zyngier <marc.zyngier@arm.com>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 1/5 v10] ARM: Disable KASan instrumentation for some code
Date: Mon, 15 Jun 2020 11:02:43 +0200
Message-Id: <20200615090247.5218-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200615090247.5218-1-linus.walleij@linaro.org>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=SVb6Zt8V;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Disable instrumentation for arch/arm/boot/compressed/*
since that code is executed before the kernel has even
set up its mappings and definately out of scope for
KASan.

Disable instrumentation of arch/arm/vdso/* because that code
is not linked with the kernel image, so the KASan management
code would fail to link.

Disable instrumentation of arch/arm/mm/physaddr.c. See commit
ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
for more details.

Disable kasan check in the function unwind_pop_register because
it does not matter that kasan checks failed when unwind_pop_register()
reads the stack memory of a task.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Collect Ard's tags.
ChangeLog v7->v8:
- Do not sanitize arch/arm/mm/mmu.c.
  Apart from being intuitively correct, it turns out that KASan
  will insert a __asan_load4() into the set_pte_at() function
  in mmu.c and this is something that KASan calls in the early
  initialization, to set up the shadow memory. Naturally,
  __asan_load4() cannot be called before the shadow memory is
  set up so we need to exclude mmu.c from sanitization.
ChangeLog v6->v7:
- Removed the KVM instrumentaton disablement since KVM
  on ARM32 is gone.
---
 arch/arm/boot/compressed/Makefile | 1 +
 arch/arm/kernel/unwind.c          | 6 +++++-
 arch/arm/mm/Makefile              | 2 ++
 arch/arm/vdso/Makefile            | 2 ++
 4 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 00602a6fba04..bb8d193d13de 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index d2bd0df2318d..f35eb584a18a 100644
--- a/arch/arm/kernel/unwind.c
+++ b/arch/arm/kernel/unwind.c
@@ -236,7 +236,11 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	/* Use READ_ONCE_NOCHECK here to avoid this memory access
+	 * from being tracked by KASAN.
+	 */
+	ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
+	(*vsp)++;
 	return URC_OK;
 }
 
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 7cb1699fbfc4..99699c32d8a5 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -7,6 +7,7 @@ obj-y				:= extable.o fault.o init.o iomap.o
 obj-y				+= dma-mapping$(MMUEXT).o
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o
@@ -16,6 +17,7 @@ endif
 obj-$(CONFIG_ARM_PTDUMP_CORE)	+= dump.o
 obj-$(CONFIG_ARM_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
 obj-$(CONFIG_MODULES)		+= proc-syms.o
+KASAN_SANITIZE_physaddr.o	:= n
 obj-$(CONFIG_DEBUG_VIRTUAL)	+= physaddr.o
 
 obj-$(CONFIG_ALIGNMENT_TRAP)	+= alignment.o
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index d3c9f03e7e79..71d18d59bd35 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -42,6 +42,8 @@ GCOV_PROFILE := n
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT := n
 
+KASAN_SANITIZE := n
+
 # Force dependency
 $(obj)/vdso.o : $(obj)/vdso.so
 
-- 
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615090247.5218-2-linus.walleij%40linaro.org.
