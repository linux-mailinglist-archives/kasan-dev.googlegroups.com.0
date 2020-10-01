Return-Path: <kasan-dev+bncBDE6RCFOWIARBSXI275QKGQEJCVDL4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 083AC280281
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 17:22:51 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id v128sf1963079lfa.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 08:22:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601565770; cv=pass;
        d=google.com; s=arc-20160816;
        b=pbPLHxjt6vnADGNajdP1dF5Zi+7rO3AtxL2CDstwmf4ywdKv58fJ0YxBUocH0iPIGg
         jw+/FNgiWzfHnYchpg+RFePbwI25uj77uC4ry4SliDdTlGKDjsj5xSztal7+uBmkcJNv
         HFUZg+bt/ov3ZOhF7uomqdRlWJziz4Ck8nOBE3hO/egxMpAOHk6s7VIAo+KMkuO//AVX
         D5HTxrt01QP9kIT44jhkieTpmTxVC/l4kCa4nYuCv5ufDrddhRHHnOwxGKLkwIKIFVvP
         GDdtBzP/bQP83Ec8oRDZXcFCd5YYBBVx36XqvnxBw1T6s3T0IlL7z4EGIkRr/mlxaVdv
         zrjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4x0kEXIVLvXI34xnkPURRndGX1U/yB/yinCJiwkz/A0=;
        b=c0XQ1U/+KkU1cr9mSQNsPxMqIWSdYkbCk2UzPFcXthdToCZW7fsIVdegzyxMjWMDW2
         LrvbjPL7qgRtiOniUGTfMhvM4M3c9nbO1C5dtDuY+akJoN7kZS70cW+Z6U8NQg9XWGKZ
         7uzbTTK2ldLPSColY5moU3EtYTwpRLNCbl47nK1X4R9pb25UAHcKsjAKGrTGyC61RwyI
         XVrM0QGRHk9mMOLfsGRuWIGob/fdbW1YTYjlBTxjaxBEaadHIEM/911JZWTzuJ6Nvsye
         Vs12JyBh+gP3gyeYG3v/1XBGHTmAo6d3q0IsBnf1OrVEvz5y4HIK/+Fvb3lRZaU09C+A
         iZCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XEVoiK4k;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4x0kEXIVLvXI34xnkPURRndGX1U/yB/yinCJiwkz/A0=;
        b=VN/qdzX1vPiWx9uNhnus5pz9JBrCsTjLd2qpy0OGNKv9VSxtgSOMjGdq4HQgg9VP2m
         ZbuArFImREM2FqgoM/bnQqTQ2sPrs3MiIpZzMvPqNc1sbK20uBDR7chcQROkShNVDdYu
         r+2jaTNhf3XwqF81s3x/VdM2oNcP8xRsBT07uj8o6qYlMu/lagahWs9A/u1PRuDHqri4
         qWYMgGv5SFq748P5yblZSImwhY/j7caAzojh5QGc2YM5pISYEBNN1hCd+mhS1fFY+YME
         it6I7HP4hmILVfVtsOmo9l1bkgtCF9O/RpwaEsO7aLVtbCybXZ9Z3Qa2Q5MBV8cFqtSl
         eM4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4x0kEXIVLvXI34xnkPURRndGX1U/yB/yinCJiwkz/A0=;
        b=DE4Hulbv9XstQb+yFOrPNIhiMnaK3XRJ/TGi9vDIess7E3nBM2XFXANnPSAgdVUQRF
         e/czd0x0cZSLhUzUc+u15Wi5eD2hAiq11SR2Inv76juG48wMQxXAIViRXcGkXBdyhfKv
         dgvyigvAZFSMTKLkQuW3maI2IcEDjrSzuFNVnuvUTzKqObJkl3ZJIRam1NGBaIPCMVLk
         nyxa/oataT5mCVzli5Vzu3lOgIX2ANANei/LJK+tD8fTkBjiAkJbELcuf8hVrsf1ew9I
         mtAM0ceirWYzbiIy47Q5Pj4ZV1LuibWKBgJPR3q6yhGrk05K6fUjQo9CIBwn13lRAZ38
         n+tA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530s/+1JbchruW0ikP0mQ3VIfE9EEVMRq/gFnNAvU2maGjNVN3dz
	GP7QGuOioEKFLFYCAbU8GcI=
X-Google-Smtp-Source: ABdhPJy1r1+IfKN9/tAlTJuIxUYcFC9Vsha50Lx0uViU7I9GRIBzonxMFfhmXfZv73SJ6+/uFHuOoQ==
X-Received: by 2002:a05:6512:3606:: with SMTP id f6mr3077371lfs.282.1601565770547;
        Thu, 01 Oct 2020 08:22:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1430031lff.0.gmail; Thu, 01
 Oct 2020 08:22:49 -0700 (PDT)
X-Received: by 2002:a19:7e0d:: with SMTP id z13mr2658387lfc.455.1601565769503;
        Thu, 01 Oct 2020 08:22:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601565769; cv=none;
        d=google.com; s=arc-20160816;
        b=WTO6sBCKRyLc9KcrqWj/mbiRRHMTkPSArPaBhLi9rppHIj+hMdOnRH+zN3j4UU8fu/
         spz+R3McKBBLwAW0Ag1JssOE5jTBq/Z++P06j8mY0Dq5j1BVTcPdGwSM+mKSeiQ/6Gdu
         /6UFhwQAGlZwT0sOJwcDDalMk+PZczNW6kQhhly1J1QZ1O+h6O9UzrbWlligx06afLZY
         p6Uj6JF65qL1GWq1oo2VqYaB9oD7jMylQFO97NP9VJa3a2yxctcvBH1pTIcbuY9GnC4N
         e8ra4/wz5Y1MJeZ8J16b0XQUVkYFEzUMaRauBhzeGJNDBAQtqp7oawDhUIznXFVNq/xw
         lRow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fvoVo/AlK8YyGNVarOwLDRqDnwOyPvSHJNcg2HWaJGI=;
        b=wrbjaVY8dtM/l8bfiEBLlOZPWTs+VKk1SSTZVvIe4xByyNfOgD4dcDsjlpSoJcvxhA
         fB2gLunu3aNPK08uvrh9nDFYMda7DDAeN9p9m1qHZ7yttBg5R/1GNR1OSOwoHH0dKqZD
         DpucFqzui7VVEFDCXjzVSvJXyRBF1lA7WiU0t/VkSlN7pTMkS3IRAkREvs7dg3Hep4Sg
         5KY71XFLJAF3mZA+9T9Neww38TJ07SfCSbJWZM9dWR+AhGH++APdgZK2UuP28mxOFmEt
         Z+jd0ZznqGsNBi1hiiYtoU/HwdOA5F7W49RGobYyPm8LTsLiz7lATWLjY07B9LEl208Y
         QHew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XEVoiK4k;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id z6si190144lfe.8.2020.10.01.08.22.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 08:22:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id y4so4990309ljk.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 08:22:49 -0700 (PDT)
X-Received: by 2002:a05:651c:10cc:: with SMTP id l12mr2314455ljn.351.1601565769170;
        Thu, 01 Oct 2020 08:22:49 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id v18sm587578lfa.238.2020.10.01.08.22.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 08:22:48 -0700 (PDT)
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
Subject: [PATCH 2/6 v14] ARM: Disable KASan instrumentation for some code
Date: Thu,  1 Oct 2020 17:22:28 +0200
Message-Id: <20201001152232.274367-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201001152232.274367-1-linus.walleij@linaro.org>
References: <20201001152232.274367-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=XEVoiK4k;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
ChangeLog v13->v14:
- Resend with the other patches
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
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
index b1147b7f2c8d..362e17e37398 100644
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
index a54f70731d9f..171c3dcb5242 100644
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
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001152232.274367-3-linus.walleij%40linaro.org.
