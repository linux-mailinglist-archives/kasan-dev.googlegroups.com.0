Return-Path: <kasan-dev+bncBDE6RCFOWIARBKVRRT4AKGQE5MHDGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB5621572D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 14:27:22 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id h26sf13961240ljl.18
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 05:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594038442; cv=pass;
        d=google.com; s=arc-20160816;
        b=cY6bRCJv7ODx3WoAB4lZs80JkFritlwl9aTUnF+Km7jnvW7EglHyLy7/xsad95AOlc
         LxI2kS4t0Vhx65guRyqCUWxCrZrhGm/p5tjPXQYH5ljL2lkc2WBg18p0KzTApDUOwY58
         NhI0qeVuhK/pmlMkoogWpQ2e1vm+hFyMQyYkYn/w9eZggKR+zib1I2Opvn9LGY+KTX8q
         COqc/QihwTK6prsdXixDQzOYsf9h57TyLSE39UFTyJbp6REUZhwGKjmpcAJxqq8go8ip
         aYf0jVMuoOMApo6vcZCVo012frKRuzM7ZmndnZavsaQbw8M+8LlOs5E3gEr5fHdUcmzP
         t1Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EDui9iOpvkG/uq26jfjOTtY+OC18SgV2321Wmcfm4OU=;
        b=Ou4FMQmeCwY4c60TtRi8qtYjt8z2Z6xSo+ciotpLGumIlfq2KB++mFTy/fCXTCoPAV
         0+ndnlw+GrqndPUixgEFcjCaHAJKM+opjHyTKQGBJjz18mPXK6ghDQ1E+oRTLRORQ2xk
         BQg1tQvkyQ12ZjDKkE3Zeam+xLtQGKDcAIvvFd8yE8Q+lMvxYJB6QnuVAkx0MxNtaJLw
         4zuVL9uIUZyKj5fj6LEuMSBBjp7l+jyt2hm6YHX5rTnKK6AiyOD5N4yDbBxMteavcKk8
         8t2IUtI5lkir2VX5iatS04LNHI16Iwun/sm8iWXVlhvbkz20pbdlSw0svtTaJWoSQK7Z
         C/BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xrd4KBVx;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDui9iOpvkG/uq26jfjOTtY+OC18SgV2321Wmcfm4OU=;
        b=QGTpBqtohuPkLET9Fz6W1TVWeMFvjgH0WMTipIOPfXrOrtaZnYBQrzLU5G2ev4MlwX
         Xf72WF7mVV51MXfmfI4m5V11KBkjTr0O4U4PxbejnULStxYnlTkoHgkoB695o+CNAMHI
         Dz3ru97QCR7gsCGMamX4mcbVdEnTEAbwJCj2Yq4Pqp/xOLiYXOK6bYtmGBcBUnadODX+
         p1dKbDrJ3ZNAjuyveEc/mO4b+tcIy1INWg1//ICB1StcZ0F01CNy7EvUY5YkvJvIjx4W
         tRryUbYKDg/XaC59lAIrT4CyGeuNv01ceA85vsfI/QINU1EEuyBVMc6kebPozE39FqS7
         KXPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDui9iOpvkG/uq26jfjOTtY+OC18SgV2321Wmcfm4OU=;
        b=gOvEWIIdDr5fvjIrPt6JyzsueYrZIcKEGgtMKhRTk1dIt4AKPZjkSxuSkmxQ+vYJZH
         XpX4ESEXTYLZ+C+xSPp+ZSN4vAyiLLurJiPmSakOn25/rWbyz0sQr5O+YgOwO9L2tGMi
         2v6Zj+Mvka8ILmSfaavsrJ/u6ScHO1Bp6w1DwUGDOCCdqsd+X2JcFbhWoNSU+znYvJN1
         P2zNuU/MPLq0WWgy7K+WZal4hQ52mN13p8NWzkfpyaC0JbxcjQ1ilduc/R0pNdUTUJUe
         TmIhOuPifMP4nTuTvZAUsNe+d/aMAiKSBzmv62DbP2IaSPLGbZxCoXWMurxoPYsB6HMZ
         CBbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WfiAMQoXESDINnKnmYbkddvvqhST7QVbAPbQZhayJWASjMotm
	ZyJfgk8SMe6AKubfPNJTMOI=
X-Google-Smtp-Source: ABdhPJxN5/G8fjLKC5BtHV15nLnLPRYJpS+OMk6vsXz+IBXlwd/a3i2YziJ15JZVPYQ92by0UEW68A==
X-Received: by 2002:a2e:574b:: with SMTP id r11mr15644880ljd.417.1594038442108;
        Mon, 06 Jul 2020 05:27:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec1:: with SMTP id p1ls1735094lfr.1.gmail; Mon, 06 Jul
 2020 05:27:21 -0700 (PDT)
X-Received: by 2002:a19:c4a:: with SMTP id 71mr30168602lfm.27.1594038441564;
        Mon, 06 Jul 2020 05:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594038441; cv=none;
        d=google.com; s=arc-20160816;
        b=mS9ywss/8e4Odv5VvSAo147etztTKk/2I4hF1H/XWTJR32qcIC8opOWyJrfaivBaJE
         SRYO7OQ4WzEUw978oVB5xsQG84bT2JTG1fzmntUvO/RErwcU3YxjFKr/1EKO20b5QnC2
         V20LHmPqVNDI1rhgRTxPJzfQkZ9V4Ulpqiyh3FQdmJBW60DQ7XSYj/1u7+zfany+yvRE
         mwpEsbw1FP3YdTGrLiE9DBu9Cp3ra4YDSUVa7nZeLYy5OD/ZTtHpe8ssRqUI1qSpSFdQ
         sC9PKqPqU9h/OxQ0/64gjaL9+vnrTrlA0jvGI8fFaVvwPJBBKfrrksE9ZeTGCoa7I5vC
         9fIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OD2fwo9UCHwSVakD8iz4327kKhLkFmPd2Kbgh3G3heE=;
        b=ZvQ6/zKerHYzyOw8RKrA+t8AHM6uZJnL4eGOfizO67juTmN+p3N44DppdmElSAUf1+
         QYT/0RREn3ty+PPu4X2rWvNiacu0iHRfMUad6EmI2c5usdgaD2Jtsx0TiVjJViEB8RzW
         PzzRDeodS84dtdAfjVxNQp7VG1RQczyBN66I6KmMlrsrtwUi7pVdtZeulrCiJJiqczmJ
         yHfitGhE+KuHR2H8pdK881Dv+crzb4pQHEVcPq+JPn4+GoN0KBRFgtFPYNjGMkQOHwLk
         U//Qj/kAeNna9ZiBhT51Y/+1YlaxqiUyKiZbtXM90v0ml0v9DmUqIHwfEP7VprjvA7+L
         nZ5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xrd4KBVx;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id a15si1092294lfb.3.2020.07.06.05.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jul 2020 05:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id h22so37903245lji.9
        for <kasan-dev@googlegroups.com>; Mon, 06 Jul 2020 05:27:21 -0700 (PDT)
X-Received: by 2002:a2e:3a15:: with SMTP id h21mr15191015lja.112.1594038441250;
        Mon, 06 Jul 2020 05:27:21 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id v20sm8534223lfr.74.2020.07.06.05.27.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Jul 2020 05:27:20 -0700 (PDT)
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
Subject: [PATCH 1/5 v12] ARM: Disable KASan instrumentation for some code
Date: Mon,  6 Jul 2020 14:24:43 +0200
Message-Id: <20200706122447.696786-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200706122447.696786-1-linus.walleij@linaro.org>
References: <20200706122447.696786-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=xrd4KBVx;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706122447.696786-2-linus.walleij%40linaro.org.
