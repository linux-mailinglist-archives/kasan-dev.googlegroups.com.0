Return-Path: <kasan-dev+bncBDV37XP3XYDRBNFQT6RAMGQEWWJ4UPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8226EE33E
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 15:40:05 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-50489ad5860sf5185282a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 06:40:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682430005; cv=pass;
        d=google.com; s=arc-20160816;
        b=RBLWR9/dV8GcN1ByMV7SavyFS2EBMkBV6UOcjle7dtJFyy3r5M4Z+kuITPvroQLm+6
         lBAiufMHztoyDtx2+/KUr3p4Y0in1ki/m41+OY53aI282iFMb6vyVY4/A6aLefJU/2+e
         kg9QbFqxwlYVS8tvHcM9mW3EAx/ZP7Qu0eOUMe86Ken9xD2LLPN22uEP+L/tx3ELY0TD
         5lo6lKEVWfy/wrX9mFKALee2QQgMKS/TB8hhrt3K6COpxHTdvLsYNLLubPsew8piyfLd
         gBAHztqnpzyImcpE75xSlP3SnZBpGlhWz5fQfTFkzrxEehBnVIEUbGAmT+6kMKVzt/J+
         3DgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gZ1rPtILXn1U+e3JPin9Jn1IvaGENadszLWN1olH/JA=;
        b=d4eZDIUspU67IU04OjxnS0CtZ/VBbt/+Slsz2rV8sw8NEoywBE/aSMbhVkqhHvt1Cr
         Eg4Aa014Du0ceJoJOr5qhNu3CixhPIyohBUcpnapMMn1ccTdJOyaaXPiYtP3c6brCIHR
         mUdz4nDFP08Mp3+7xQU1mt+bUUM3LKLYm/hq35Fw90eoEjeTu4v6HJbk0niSLWYC566i
         6DeO/gXkkmbjAGG+GVEQte5biUAd5EeSFfCAQqJZ8wxwxyg7n2FqvknRPeDydwtlXnL0
         wLRJslnQj0ssVASkrxep2IKbYpd6NdYMpGj4x//4r1KfXPt4iS5Iq/dMVQXTFKFs9+Or
         l4lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682430005; x=1685022005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gZ1rPtILXn1U+e3JPin9Jn1IvaGENadszLWN1olH/JA=;
        b=tc+8A7HhVYc8aaud4fPE2BFvmZ2QvFWmTRTn4erzjHYzFCOKC+UPdxLfMlQYeLG38N
         PaQ3GjlMyLm31mc8dEShKEwx90z36Mq4JPeOu29zoRqCdhBYrdOI+Lh6CItZxMtKIidq
         3hMMmFok4EiprVBwtjHEobwNop5ApY8BvN12fHoqDSpnB+zS+8APLQx+amQD4ZkcRlac
         1r60Dyq1UtjIMb/IiR5rjAuoTB+iOlICDLkZ4X8npc2YPnbID7FL4m1lneHFLy0jCMrT
         WDk5ICFyIrNLaTo+qcspBFNHdgw0M6LArjXgzBIYWw/fnd1oEuM9iHsZmgJgwgLvOaNu
         leQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682430005; x=1685022005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gZ1rPtILXn1U+e3JPin9Jn1IvaGENadszLWN1olH/JA=;
        b=EBHlJDHCzQk+Wxat819OZ11X3olm84tEwgsRCeZJlvNhsdNcZZK3RTMS6NvsnzEhck
         BCbIFqGTwByzUWsixDvy8aT7Ud+XyGZ6ki6D2+Hn3foN21iddaIfbkqxGgrqmgNCi+r8
         VdSu+SQBqBFm5FT7tqWlS2Ez3PLG/Qqy6e2FS1HR1i/fDYdg3gOjspxw3oZAI4s3vrlh
         +qj/N94HQwx2z49M0NdlscqDaj04zi2QkwlOrfq7u0dPYhkUn/7WeIl0SkgJRXpkpBZe
         jEs0rOQEQbPy1ErVjEFWSLA2L2bYExmBR2I8n6qOKGFIjCMhdQLSojA6z0wgvgTsMumx
         zlZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cXGmks1u1kv5FIBCjnLNaJoUCwd2HRYF296222gIes2rw/zyHO
	hhpSkdnvdfqxw0AquKHUVmE=
X-Google-Smtp-Source: AKy350Y6eZbQ6CHSh3GiF1x/rOgmviQWVK2gg9oJ2DOA8laGfu/ZOOj92Otl9vmeohZiewLBWXYTQQ==
X-Received: by 2002:a50:a6dd:0:b0:504:8cf0:c3ec with SMTP id f29-20020a50a6dd000000b005048cf0c3ecmr5107942edc.8.1682430004789;
        Tue, 25 Apr 2023 06:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4402:b0:505:4cd:5bc2 with SMTP id
 y2-20020a056402440200b0050504cd5bc2ls3515033eda.1.-pod-prod-gmail; Tue, 25
 Apr 2023 06:40:03 -0700 (PDT)
X-Received: by 2002:aa7:cd7c:0:b0:4fc:3777:f630 with SMTP id ca28-20020aa7cd7c000000b004fc3777f630mr13839755edb.0.1682430003145;
        Tue, 25 Apr 2023 06:40:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682430003; cv=none;
        d=google.com; s=arc-20160816;
        b=TxgiSpzHrPY+dXXmmnEm4C8s8pgMUtGun3av7EDYQqvNXKLUwJ/FiO5RrjjNscF0sA
         D6YPIEGatIvuDMCQpEejo0dFTprk0yP+JY6x5i1JuyFR8a1+d5nFwbmDoUSjIWGfg2vR
         S4VeuNOCw2aoBP2R+8XRLdmeg6kNKVvONCQxCujZkO4ojQxkEt/gVDGDHxkEp86mec2z
         ySYkc0fxUVHR/bZnKzJSFYBXYfxhJbUPelCzJ2liB0qcMT9IbzgWkVLt45uOHQfuby10
         wCljvNG/0f/XBkqBNNniM+qREjynrX/IiYKI7ta4kdoohHQ7QiaBknDHUArZjiGwO3uY
         AKIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=4uqalJMT1EQCF07KjUmod8cV0hJoJJCz/DOHI0adsRU=;
        b=UlQcXSDu1N4iNV7luLCiU/quX1+MDOk4/+PRDtA7mklfJIMnmNRF9b29KtTFsvbwxM
         S9wFz8HNctEAUS2OSFQeSDO/KTsGFG6QrsnYl3aM/FzSv0HnQUrZkNVgCB7KvqeIHL8h
         7OLkga6d4Ekr66WVI5VPKeFc7jwKOnn+82VztU3UTcLhDKDui4SIR1SeNCjJho46uwSI
         KF6Z+mYLgyA+LGXgikzv6tHX5Pgd8uVAzJe3rjnkkFNOLnLh5fZmXmp/35xRGKYe1LBc
         aFMbL3dKi2E4zZQuGJ+CABiE6FUyICW96lzXRaaX4OBhiy1BtnX/6oNo42jL8WHnUImY
         0Rog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h15-20020a0564020e0f00b00504adbbf1a6si693335edh.1.2023.04.25.06.40.02
        for <kasan-dev@googlegroups.com>;
        Tue, 25 Apr 2023 06:40:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4CC6A4B3;
	Tue, 25 Apr 2023 06:40:46 -0700 (PDT)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.38.148])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6C1123F64C;
	Tue, 25 Apr 2023 06:40:00 -0700 (PDT)
Date: Tue, 25 Apr 2023 14:39:51 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Youngmin Nam <youngmin.nam@samsung.com>
Cc: catalin.marinas@arm.com, will@kernel.org, anshuman.khandual@arm.com,
	broonie@kernel.org, alexandru.elisei@arm.com, ardb@kernel.org,
	linux-arm-kernel@lists.infradead.org, hy50.seo@samsung.com,
	andreyknvl@gmail.com, maz@kernel.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>, d7271.choe@samsung.com
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZEfYJ5gDH4s6QJqp@FVFF77S0Q05N.cambridge.arm.com>
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
 <20230424010436.779733-1-youngmin.nam@samsung.com>
 <ZEZhftx05blmZv1T@FVFF77S0Q05N>
 <CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
 <ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N>
 <ZEc7gzyYus+HxhDc@perf>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZEc7gzyYus+HxhDc@perf>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Apr 25, 2023 at 11:31:31AM +0900, Youngmin Nam wrote:
> On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> > On Mon, Apr 24, 2023 at 02:09:05PM +0200, Dmitry Vyukov wrote:
> > > On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
> > > >
> > > > On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > > > > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > > > > from its call stack.
> > > > > And in_irqentry_text() which is called by filter_irq_stacks()
> > > > > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> > > > >
> > > > > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > > > > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > > > > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
> > > >
> > > > TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> > > > remove them.
> > > >
> > > > The irqchip handlers are not the actual exception entry points, and we invoke a
> > > > fair amount of code between those and the actual IRQ handlers (e.g. to map from
> > > > the irq domain to the actual hander, which might involve poking chained irqchip
> > > > handlers), so it doesn't make much sense for the irqchip handlers to be
> > > > special.
> > > >
> > > > > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> > > > >
> > > > > This problem can makes unintentional deep call stack entries especially
> > > > > in KASAN enabled situation as below.
> > > >
> > > > What exactly does KASAN need here? Is this just to limit the depth of the
> > > > trace?
> > > 
> > > No, it's not just depth. Any uses of stack depot need stable
> > > repeatable traces, so that they are deduplicated well. For irq stacks
> > > it means removing the random part where the interrupt is delivered.
> > > Otherwise stack depot grows without limits and overflows.
> 
> Hi Dmitry Vyukov.
> Thanks for your additional comments.
> 
> > 
> > Sure -- you want to filter out the non-deterministic context that the interrupt
> > was taken *from*.
> > 
> > > We don't need the exact entry point for this. A frame "close enough"
> > > may work well if there are no memory allocations/frees skipped.
> > 
> > With that in mind, I think what we should do is cut this at the instant we
> > enter the exception; for the trace below that would be el1h_64_irq. I've added
> > some line spacing there to make it stand out.
> > 
> > That would mean that we'd have three entry points that an interrupt trace might
> > start from:
> > 
> > * el1h_64_irq()
> > * el0t_64_irq()
> > * el0t_32_irq()
> >
> 
> Hi Mark.
> Thanks for your kind review.
> 
> If I understand your intention corretly, I should add "__irq_entry"
> to C function of irq_handler as below.

I'd meant something like the below, marking the assembly (as x86 does) rather
than the C code. I'll try to sort that out and send a proper patch series after
-rc1.

Thanks,
Mark.

---->8----
From 7e54be3ea2420af348c710afab743b94ced72881 Mon Sep 17 00:00:00 2001
From: Mark Rutland <mark.rutland@arm.com>
Date: Tue, 25 Apr 2023 14:13:39 +0100
Subject: [PATCH] WIP: arm64: entry: handle irqentry consistently

Follow the example of x86 in commit:

  f0178fc01fe46bab ("x86/entry: Unbreak __irqentry_text_start/end magic")

... and consistently treat the asm IRQ/FIQ entry points as irqentry, and
nothing else.

TODO:
* Explain stackdepot details
* Explain why dropping __kprobes is fine
* Explain why placing entry asm in .irqentry.text is fine.
* Explain why we don't need to mark ret_to_* or the actual vector
* Check how this works for ftrace

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
---
 arch/arm64/include/asm/exception.h | 10 +++++-----
 arch/arm64/include/asm/irq.h       |  6 ++++++
 arch/arm64/kernel/entry.S          | 20 +++++++++++---------
 drivers/irqchip/irq-dw-apb-ictl.c  |  4 +++-
 4 files changed, 25 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
index 92963f98afece..6c74a8a3aad99 100644
--- a/arch/arm64/include/asm/exception.h
+++ b/arch/arm64/include/asm/exception.h
@@ -13,11 +13,11 @@
 
 #include <linux/interrupt.h>
 
-#ifdef CONFIG_FUNCTION_GRAPH_TRACER
-#define __exception_irq_entry	__irq_entry
-#else
-#define __exception_irq_entry	__kprobes
-#endif
+/*
+ * irqchip drivers shared with arch/arm mark IRQ handlers with
+ * __exception_irq_entry. Make this a NOP for arm64.
+ */
+#define __exception_irq_entry
 
 static inline unsigned long disr_to_esr(u64 disr)
 {
diff --git a/arch/arm64/include/asm/irq.h b/arch/arm64/include/asm/irq.h
index fac08e18bcd51..a1af8fafc6cb5 100644
--- a/arch/arm64/include/asm/irq.h
+++ b/arch/arm64/include/asm/irq.h
@@ -6,6 +6,12 @@
 
 #include <asm-generic/irq.h>
 
+/*
+ * The irq entry code is in assembly. Make the build fail if
+ * something moves a C function into the __irq_entry section.
+ */
+#define __irq_entry __invalid_section
+
 struct pt_regs;
 
 int set_handle_irq(void (*handle_irq)(struct pt_regs *));
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index ab2a6e33c0528..a66cd0ce79956 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -562,7 +562,8 @@ SYM_CODE_END(__bad_stack)
 #endif /* CONFIG_VMAP_STACK */
 
 
-	.macro entry_handler el:req, ht:req, regsize:req, label:req
+	.macro entry_handler el:req, ht:req, regsize:req, label:req, section = ".entry.text"
+	.pushsection \section, "ax"
 SYM_CODE_START_LOCAL(el\el\ht\()_\regsize\()_\label)
 	kernel_entry \el, \regsize
 	mov	x0, sp
@@ -573,29 +574,30 @@ SYM_CODE_START_LOCAL(el\el\ht\()_\regsize\()_\label)
 	b	ret_to_kernel
 	.endif
 SYM_CODE_END(el\el\ht\()_\regsize\()_\label)
+	.popsection
 	.endm
 
 /*
  * Early exception handlers
  */
 	entry_handler	1, t, 64, sync
-	entry_handler	1, t, 64, irq
-	entry_handler	1, t, 64, fiq
+	entry_handler	1, t, 64, irq,	".irqentry.text"
+	entry_handler	1, t, 64, fiq,	".irqentry.text"
 	entry_handler	1, t, 64, error
 
 	entry_handler	1, h, 64, sync
-	entry_handler	1, h, 64, irq
-	entry_handler	1, h, 64, fiq
+	entry_handler	1, h, 64, irq,	".irqentry.text"
+	entry_handler	1, h, 64, fiq,	".irqentry.text"
 	entry_handler	1, h, 64, error
 
 	entry_handler	0, t, 64, sync
-	entry_handler	0, t, 64, irq
-	entry_handler	0, t, 64, fiq
+	entry_handler	0, t, 64, irq,	".irqentry.text"
+	entry_handler	0, t, 64, fiq,	".irqentry.text"
 	entry_handler	0, t, 64, error
 
 	entry_handler	0, t, 32, sync
-	entry_handler	0, t, 32, irq
-	entry_handler	0, t, 32, fiq
+	entry_handler	0, t, 32, irq,	".irqentry.text"
+	entry_handler	0, t, 32, fiq,	".irqentry.text"
 	entry_handler	0, t, 32, error
 
 SYM_CODE_START_LOCAL(ret_to_kernel)
diff --git a/drivers/irqchip/irq-dw-apb-ictl.c b/drivers/irqchip/irq-dw-apb-ictl.c
index d5c1c750c8d2d..ad315bdfc3ef6 100644
--- a/drivers/irqchip/irq-dw-apb-ictl.c
+++ b/drivers/irqchip/irq-dw-apb-ictl.c
@@ -19,6 +19,8 @@
 #include <linux/of_irq.h>
 #include <linux/interrupt.h>
 
+#include <asm/exception.h>
+
 #define APB_INT_ENABLE_L	0x00
 #define APB_INT_ENABLE_H	0x04
 #define APB_INT_MASK_L		0x08
@@ -30,7 +32,7 @@
 /* irq domain of the primary interrupt controller. */
 static struct irq_domain *dw_apb_ictl_irq_domain;
 
-static void __irq_entry dw_apb_ictl_handle_irq(struct pt_regs *regs)
+static void __exception_irq_entry dw_apb_ictl_handle_irq(struct pt_regs *regs)
 {
 	struct irq_domain *d = dw_apb_ictl_irq_domain;
 	int n;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEfYJ5gDH4s6QJqp%40FVFF77S0Q05N.cambridge.arm.com.
