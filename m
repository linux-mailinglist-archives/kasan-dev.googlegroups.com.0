Return-Path: <kasan-dev+bncBDE6RCFOWIARBRNDSP6AKGQE4RFWILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 223FF28C462
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 23:59:34 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f28sf3177382lfq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 14:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602539973; cv=pass;
        d=google.com; s=arc-20160816;
        b=EyYDL4bryGVgv7HmA2TfTMTy/lYMxM3WG4FDz52DVXxeOCPSqAHLMsDbHEOP62YtjA
         KSTnIek9VhkxaYHpr2ZkRfo65u9Th1BlXcWL20dJscm4F1dXzbidBb+TlWpqo9hJdRUZ
         Y3scp3vkDpzC6lwtSEZcKS0BX0A+R1MijEMe5SklfgEwuuJLpguDbL7ELIe+b7xDZQGy
         OyJxfxQVd1LBj14DBLH7LYcdapZzBrbLhAgP4RcjxaIAr1w5KvLkT6fBwA5/8ZDXqMHx
         80IWJBIfB7pmGn9GoED6SGU8dNT7o0989+VWAWUEzbsBJcbsDS+4FouEHY5GImUJeUzY
         3mKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MmA75Z1DXt5ZDxBxNQjMvOQBW9OLUpd/k0oCv0MHddE=;
        b=amEN5StaAP9LQHeuya/NCEmk8QS9CDmcsWom6p6RoMPqa1TDY0eqKj2EYoQLIESycS
         zStLB9X6nVg3z4NDPYyGwSHrZVh34bse2VBEpLz2TolQ9BIfZ29uS9ukzXNSCtEP2Efe
         dE4UCeqnRCQtVv1q5e2XYAbsVjbtitzgmBV16Rv2H+CVMGmvSfKZmzUdqM3AIKFVChht
         0hJVGYZhwUFIeJEx93/uEPAn3EeNFLuRAfrYQY8hmN0Un1bNuyXlv7+/44h123QRDabE
         tN69USdO4txEHk/oDImzgwFUJ8o3DLmcPenM6zUPpzkANIYkp9pkgywe5eUUhbfFdBa7
         kEgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="aUKMld/w";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmA75Z1DXt5ZDxBxNQjMvOQBW9OLUpd/k0oCv0MHddE=;
        b=tjoI1+dlTsl4VDq9hgFFgoH3nGvVJgOwIml3dRWNrGy7H9P855vgWNCEioggXLaACO
         ZuweUvwQXwLywSVxUdnkM+RlnlwvU+WxJX3AcL6wMtXImocbzQvps9aq/944sdsoCAGc
         Tz/YkBvKmtIEEhn9sdxHjxYnaATPxSDKUIdRKS42c9ya1VKyqnxmjQQfrw1zrMdhMTci
         hhbdkFeWxpQqxGwMHHqHPUfLnKm81ITvMO4EIl0ZyjLL6fXtHPPxUqloY24GT8G/dOsf
         sOO1LHgccvRX0zK6dPXZDUCy1E2DygQonCVyvCNY9oaIhxIK+Il3nZ9Uy2PAY2a+oME8
         5tDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmA75Z1DXt5ZDxBxNQjMvOQBW9OLUpd/k0oCv0MHddE=;
        b=gTO+Cw9KYV/FWP8FFlAu1OcwSA33uauXwIcm4ZycrgVfFYZOl45kHBOuzj1mysTcDP
         KoqDBTqyYB0knMmWnVpz9fJ1LS24NwZwP6nsjWX72D5iFFJrY5bwRfrL9Bmchqb/HIxY
         ceW7CYVmjHR1u3i/DG46ETJ5VP1lAL9YH4rFGINCTjvoIC1tmU4nS6rTHVNuzDnGqMou
         HT0aJhEy3f9u2QVleRAlLc2qAHsWyFR5x8vFp3Q1btX738ULV4/IP864k2TGXP0Letr5
         bsibiIoXC0HEU3PiEYl9fSpclMdop/PYJVNbTFZ6FZ8IU8mksfCJL3esukCES8+cqe1M
         WicQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oFWivpEA6Haz/V59pD/h2XD5Jm09FXiWYifQaXhuKi9pnz169
	2asQPtdKeFonrbd1wbSLFvs=
X-Google-Smtp-Source: ABdhPJz1m1SdfLd9pKeCAE+jdzmiNtcAEEfvR9h4DNGmWu881H3fPTgjWOk4bm2aBTae/ylDy7dkEg==
X-Received: by 2002:a2e:914d:: with SMTP id q13mr4391764ljg.299.1602539973680;
        Mon, 12 Oct 2020 14:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls906361lfd.3.gmail; Mon, 12 Oct
 2020 14:59:32 -0700 (PDT)
X-Received: by 2002:ac2:544f:: with SMTP id d15mr9009625lfn.368.1602539972600;
        Mon, 12 Oct 2020 14:59:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602539972; cv=none;
        d=google.com; s=arc-20160816;
        b=du9YgeQKT9Lk6ltwghWgH4CWPwSrkUS/UwCfQDhQyvzwaP7O2y4qXG76YWU8jggjoA
         /vwFXCcHI+0J4HNicqzhFtQhSfDUXAVnnLljGGeE22T2ThB6CvjcSbOSFt9QVH5aevVG
         sXXnh9rJ0rBeO2YkyuLZHeCe3dSfU/VjTAemlx3LrRMCcyhTWNgifDxCwI1RG2PFEpVV
         ah9YP/Pz8EBK2lUV7ROAvgcqIjm/W++QI4G9V4w0AUDDR4I1T9GNbTn7y2y+oW6EeS1r
         GcCYGTBGIiEGKBIUsrfj5HRi7pH8FO/sKthJ6l2g1havnK1VLH+0Rbn42UHnX1m+EFvH
         s6mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DiksqQt2obtvvgVOB/HJbRqvUSzPoz727SfBhAiH22A=;
        b=UcioCg7fmdYl1txdHe9Ul1s0HoLGHlcfbaJQhyB/cGlubwVC1N/FZEjCr6WtfLMTWg
         EPLyVf7cxFptqdeGRUCQAoROJZM213X1agF1CRDGSt5yiFC5JqtUkcd17rnCo22UNrUw
         c+gG5yG+0jDr/XimMAAHJupYF02sn1UEjiT0R2WpJlESEdWAto3sJJygLoaue0U25jY4
         fWHIfW9NWjL/OlWrDTAceO+CnAJXLtdIiM/ivTD2NKuHEbpc4ridkVDxYZYUFz08De8B
         T3Pfvet8TeqvA1A/oo4AIFGIp5Yoq+NZgmMZlMnACfY6ha8goJL+fnWGfFX94O7vNsHj
         PsUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="aUKMld/w";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id r22si146169lfe.0.2020.10.12.14.59.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 14:59:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id c21so1899357ljj.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 14:59:32 -0700 (PDT)
X-Received: by 2002:a2e:1614:: with SMTP id w20mr11814853ljd.103.1602539972319;
        Mon, 12 Oct 2020 14:59:32 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id w9sm2985887ljh.95.2020.10.12.14.59.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Oct 2020 14:59:31 -0700 (PDT)
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
Subject: [PATCH 1/5 v15] ARM: Disable KASan instrumentation for some code
Date: Mon, 12 Oct 2020 23:56:57 +0200
Message-Id: <20201012215701.123389-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201012215701.123389-1-linus.walleij@linaro.org>
References: <20201012215701.123389-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="aUKMld/w";       spf=pass
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
ChangeLog v14->v15:
- Resend with the other patches
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201012215701.123389-2-linus.walleij%40linaro.org.
