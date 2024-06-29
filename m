Return-Path: <kasan-dev+bncBCT4XGV33UIBB5PD7WZQMGQEV4QCRAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id F382091CAA3
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:18 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-700d0c0ed70sf1315144a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628278; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmLR7tKHDPsphBj5tZ/Nt6CgT5ijQfriJ46AqzopZP7UP7IAzO8zgO+O1FzEUuiSCw
         zBA9QMSUERWS2+NysPKlnDgMLdl1kEV48YcwHw80CPX7g/MWOZu8ljByLKnDcxCWfFG+
         gcu7D1MFW3cxgLJ44U4iJCmeVOkvSLGFVHtzc2roy2++OPig6QyQJYJRDjq8gPku4ZMH
         0UoUPrqMyIB/E9jVCYQg+Z02SzVS4N0Ipt9ijmtdPfkAO/ydtlsmgJ/VplhxFNlo+ohT
         3ftX4/aqZ7g9OkUiV8V6yF2PTGUwkqp81kDQmFrjcA5Fza8/CoTpT3s3twnAJHdCv/VI
         HiIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=xpZSaAZl+a5WC81/gnMH8fvr4RwYtVLFuFaFzL4ZDiw=;
        fh=GnXDznPdz362Gp+o8tf0iceWIK+2Ks68Qel5n0fuZ9M=;
        b=H+gNdpWNZpkmfKKYlBz1OpM89EipOtWfQhpXF51rSAQPtYEaxn52o9IHOe4Gd1Q0ih
         bvY4lBy5CZ/hyyGPUqWQs4O4WOHS/LxivSWK5o1xMlJE4lz+9y84/mUHZ/dsjDLCQFD6
         sLoQ7ycP6lraF3O/BwfYUxZnZ+bcknrMeZlIlEHBRxT55nV62ncIDoUR/4egCFxHegz8
         c+tBeHXjnnPvY4YtQu/cag1xAWe/dkj6y8RiyTq6RzIwa309Ux5tMMLa5Pio4xFWES38
         dEo0tGaOjahvTnPOh3z9vmJZdCm7sNfCMcFQKzJdtJVow1ToIOUjHEx3XjOdvpiflUA4
         cjcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LPjWrHjS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628278; x=1720233078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xpZSaAZl+a5WC81/gnMH8fvr4RwYtVLFuFaFzL4ZDiw=;
        b=ECWsyW9ZGbhfjbUgZMM8j0Bsyv9DkzbfsGis+yLWSW2YXiTUQACv2cUVzia1BJWRBR
         ZG4UweSf2WghJS/NATmo7bpu8b8QcBkM+Jtr0HZhF7q/PoWpIR/a6TN49QC2vrY7+ICT
         FV7P5IPQVrQHDXIK+tL0v+W1zDQUaS/paeX93ce7WkFdHmKjaX6Ucz9GCCZ95T9KZFtt
         nl2N7hWJtx5386lKPT/+VD1Ix1ZGf/Qw9j0lDSvvHJqXaYNYJdRAVFVeasV4SLgBg1fA
         k5qXGuHG1cjM2xu7nzGIWjmHfRQf/QKhhDLFPGIgL3RyFoHzhzz7GguRcijkq+MNyLIJ
         OCAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628278; x=1720233078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xpZSaAZl+a5WC81/gnMH8fvr4RwYtVLFuFaFzL4ZDiw=;
        b=rZVQGw+CbAlZ48Ldgc7xlr5u3EvS7xnPFNHJLDdxHajdUhxztkAMWR42FvXU+QWsib
         GtsmQCGMGqLF40c6ACRCwt19DvwSHNtqieHEgTANqWuVZhPppAmdGR9K6C/JdFp1IxMY
         pvOv2ShhCGZUBt2y7ebZstTpGO0Xjh315o/ac1sAtZZ90pcTI2NQwCo3h7rujMESjPIG
         oyirR4wdUIWUolhAmWEPcSy/Oa9CvHGib44UKL8C851qhPfEEWXDBeISguyR8tzUnIFw
         Fd25mGHU2URfrAClNn0NmdYFni6murzaZiLl6iZ5qle0BEqk+iDQZ1BhZyD+t0t1ah2s
         iy5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJ1pzuWzvgrWrpBPHEJV79NVt9guQKjfGr+GF0gJ0mAJjmp9AG9SzI3q//+sn+YEzhljoffxf8M1O8Em+Dksy2r6MK9lQjUA==
X-Gm-Message-State: AOJu0YyR4KIgtL8Y7S10w9e9aWKCNSEk+4nSPLOUY7iHF1KE7UjPpJym
	hJ21L32QTn4bOGGj8bI1FqUIHG2PlFfZb/LqJrFlP3NL4HR3yQXA
X-Google-Smtp-Source: AGHT+IHTghtV7e3xuJF+6CC2qi4Qm7A2EbacnnEgic2ixJOxviOPmEbZxxLoru7157dxta3ln4D+RA==
X-Received: by 2002:a9d:5f07:0:b0:6f9:6577:71c3 with SMTP id 46e09a7af769-700af8f2ea9mr17407063a34.6.1719628277729;
        Fri, 28 Jun 2024 19:31:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:946:0:b0:5b9:946f:8e43 with SMTP id 006d021491bc7-5c417eb6d9dls863025eaf.2.-pod-prod-03-us;
 Fri, 28 Jun 2024 19:31:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEjzNEGh1hozUmLp0moRbxfVyzpWbIrhWW7C7SFSEdYYDy088Vv8JZi5zPDaflnod14LSkw3fPbiv0NHNAcybGQvf/2Mb6nrXTdA==
X-Received: by 2002:a05:6808:1906:b0:3d6:2adc:3878 with SMTP id 5614622812f47-3d62adc3b1amr8178202b6e.15.1719628276364;
        Fri, 28 Jun 2024 19:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628276; cv=none;
        d=google.com; s=arc-20160816;
        b=run9Cj85ip2KFwv2eUEQOX9sNjKsH8Q9URLI2w363l8jTwQnFiJPbjHCbsvmThNI6C
         /Vt6jneAIyHm2L00LS6g5yWgd78ewTus009anOpRFVhLWvgUfxG+whDylXgrWlb4wKHX
         7edP7Gpe4aqgc0x4EfXWtDwXvYg/y7hBhWXIyethhguZ5ffj0JtaGoRG9DWIe8MNcYeX
         BuZhjbEUypFLW9F7lmqJ1cCz5Nt6pm7nkm6Es37dyW9iSnNCB5eI5WMesxZz0nR9RU99
         eF439NM5zpWQX/UM1toM7t7oUAVIvTmlpQy6lQWUUq5v3ipHlcLP9+uxIJBvvjWFrXzW
         6w0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=L+438zAjAaDpK3vVMYvWCibUe/OCKy1s87p4uzxQoAk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=XHE2rntRiVLKADYlCWgJhykXOcmN2G0Wkfg7Yv8dUhehtwsAeufuoIFB3Qp/4/7DiR
         uQXUx4uemcXfQc8KvA5RQ8AIoQjrz38MZuEzr7VTOv0WGqAwDAUjq/NVvLxekbakotDh
         s3IxhkPiVoptGQYsc5Ejh5LeHL9fehQBeEYX6LZZ6ALIJYqQjbOvqW+T3uv8nox1XkzZ
         3A8M3pmdEsMaByQaHsbUZY4+32LhrchofqzT8UB8AdjHweRTgaV/mmBzagA8c3ncEYSp
         qcdddJpKb15ZFqg58o3gh/myXWkls/6vpU2BArBXkEvD7Lj74idIXha08M9CN0wG3ELP
         PXZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LPjWrHjS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70800fada07si150958b3a.0.2024.06.28.19.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AC764622C7;
	Sat, 29 Jun 2024 02:31:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 551D0C116B1;
	Sat, 29 Jun 2024 02:31:15 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:14 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch removed from -mm tree
Message-Id: <20240629023115.551D0C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LPjWrHjS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: s390/irqflags: do not instrument arch_local_irq_*() with KMSAN
has been removed from the -mm tree.  Its filename was
     s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/irqflags: do not instrument arch_local_irq_*() with KMSAN
Date: Fri, 21 Jun 2024 13:35:14 +0200

Lockdep generates the following false positives with KMSAN on s390x:

[    6.063666] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
[         ...]
[    6.577050] Call Trace:
[    6.619637]  [<000000000690d2de>] check_flags+0x1fe/0x210
[    6.665411] ([<000000000690d2da>] check_flags+0x1fa/0x210)
[    6.707478]  [<00000000006cec1a>] lock_acquire+0x2ca/0xce0
[    6.749959]  [<00000000069820ea>] _raw_spin_lock_irqsave+0xea/0x190
[    6.794912]  [<00000000041fc988>] __stack_depot_save+0x218/0x5b0
[    6.838420]  [<000000000197affe>] __msan_poison_alloca+0xfe/0x1a0
[    6.882985]  [<0000000007c5827c>] start_kernel+0x70c/0xd50
[    6.927454]  [<0000000000100036>] startup_continue+0x36/0x40

Between trace_hardirqs_on() and `stosm __mask, 3` lockdep thinks that
interrupts are on, but on the CPU they are still off.  KMSAN
instrumentation takes spinlocks, giving lockdep a chance to see and
complain about this discrepancy.

KMSAN instrumentation is inserted in order to poison the __mask variable. 
Disable instrumentation in the respective functions.  They are very small
and it's easy to see that no important metadata updates are lost because
of this.

Link: https://lkml.kernel.org/r/20240621113706.315500-31-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/s390/include/asm/irqflags.h |   17 ++++++++++++++---
 drivers/s390/char/sclp.c         |    2 +-
 2 files changed, 15 insertions(+), 4 deletions(-)

--- a/arch/s390/include/asm/irqflags.h~s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan
+++ a/arch/s390/include/asm/irqflags.h
@@ -37,12 +37,18 @@ static __always_inline void __arch_local
 	asm volatile("ssm   %0" : : "Q" (flags) : "memory");
 }
 
-static __always_inline unsigned long arch_local_save_flags(void)
+#ifdef CONFIG_KMSAN
+#define arch_local_irq_attributes noinline notrace __no_sanitize_memory __maybe_unused
+#else
+#define arch_local_irq_attributes __always_inline
+#endif
+
+static arch_local_irq_attributes unsigned long arch_local_save_flags(void)
 {
 	return __arch_local_irq_stnsm(0xff);
 }
 
-static __always_inline unsigned long arch_local_irq_save(void)
+static arch_local_irq_attributes unsigned long arch_local_irq_save(void)
 {
 	return __arch_local_irq_stnsm(0xfc);
 }
@@ -52,7 +58,12 @@ static __always_inline void arch_local_i
 	arch_local_irq_save();
 }
 
-static __always_inline void arch_local_irq_enable(void)
+static arch_local_irq_attributes void arch_local_irq_enable_external(void)
+{
+	__arch_local_irq_stosm(0x01);
+}
+
+static arch_local_irq_attributes void arch_local_irq_enable(void)
 {
 	__arch_local_irq_stosm(0x03);
 }
--- a/drivers/s390/char/sclp.c~s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan
+++ a/drivers/s390/char/sclp.c
@@ -736,7 +736,7 @@ sclp_sync_wait(void)
 	cr0_sync.val = cr0.val & ~CR0_IRQ_SUBCLASS_MASK;
 	cr0_sync.val |= 1UL << (63 - 54);
 	local_ctl_load(0, &cr0_sync);
-	__arch_local_irq_stosm(0x01);
+	arch_local_irq_enable_external();
 	/* Loop until driver state indicates finished request */
 	while (sclp_running_state != sclp_running_state_idle) {
 		/* Check for expired request timer */
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023115.551D0C116B1%40smtp.kernel.org.
