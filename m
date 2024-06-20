Return-Path: <kasan-dev+bncBCT4XGV33UIBBY75ZWZQMGQEEFHZLJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E62D90FAAB
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:16 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3d227ca3b18sf271109b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845155; cv=pass;
        d=google.com; s=arc-20160816;
        b=qGboPD9WTdmQoblnNH7yLUdmFR6RO5teEsRAWpJDZ9Z6VZwmGS7sDrZ8g2pXHKNkMK
         RrTCPxw/zD1CPR4wHbzhJ9ReD8a5XyglDKpRirmyLmu5zPNGsS0+lJudHOfn0aNr7Vds
         fdMXZV7nwIRbgO7RCeH1poEaY2yV0x0k+oY6hwlua0vBJXdjQA40X6HdFjzoD/4Yi/J3
         nhSaVaw3gy3hzbXANKnT2/v9boQVL4sg8aFCl/lb+R1GMQrhfq9ohPyrwTjRd/Jl9ztf
         trDESwesKO+iNiDijStgQ95AT2xX1L9tWKUCXAeaTYQUu6zu/f1iDHmEnCzUl9p3LAcb
         mL+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=+oUCzxKf4l6F4NTP+G9FMv7BnyLosY0ViHiYCoytMS8=;
        fh=RhHHNYqdfm13yAAC/Kidlf1+si8Z1F61izRnM5Y54z4=;
        b=H2wsv5Bc892REbatSP8+oJTxl9fbX95D4v1hxcFSLWjFY9gd50LUb1CJp3/c1Y3xLq
         Xj0sh19u8q14OdEfCOVp5bORJCQ6HhNq6cDThbc8SuBxXIlDA51//GY/hH4eL7PUkYUo
         dPWFCrzvCfO03FelW9RlqX5Tt/7cTORnrkPgPm9ttFfdXqYQo+X2E8KViIPqd7QKP+2M
         4w4cdrH+WlADayjYZZeDxwf8ObiTL4L4Z/EobNAWTZC1tYHdun88cZUGwe84VvZkblIU
         kz4vlWXDHk7WgrMltRmsYJ3J/nm9IFybIThRA6oObTZTUK8T4oDnie2ZPjUpDqok57Jv
         Qo0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Q56XbFNS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845155; x=1719449955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+oUCzxKf4l6F4NTP+G9FMv7BnyLosY0ViHiYCoytMS8=;
        b=MvHA0khkRyX32FSC0q9McRiO1rIwc12oqld8O2uf3r/XH3ojnaf06TcSqr22Als2S4
         nTSbZ3E4+f9DezrBnyTsSGhxaM6uKqBiPo7E0ysWyZ9wz6yTwDwLl75h1F8yjhwqr3qN
         Rzvx0zYOohf136lwuNWkJA48umLPjRSDdhimSQBhGNEUgCxWxfjjHNCmgVRDNOR53wDo
         hnzYkBXy/DzJTfDK02dLR1C3lZGj8+aA5IHOVE+rGCIUlIq04tKOZyWkATUclVDQY3rD
         NpFu/4W0XpBQPikRZFl1lU1NH8ie0KmyFre7pmH4H5Ap+san1Vp2pD+KMxoKrbQPgcLs
         GPaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845155; x=1719449955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+oUCzxKf4l6F4NTP+G9FMv7BnyLosY0ViHiYCoytMS8=;
        b=G9ckHdnzu6SwhKSB/Evd8yhWcBsxN0B+qZ+phEUjjdon6q+aM3uJ0GDLt9SJG34VsJ
         /oOzmL1niVMfXaKY1KTB8cOqIoDmoaX9uSam8eWodbdlK6387e41c6FcsfWTrb2bOYSp
         Yj3dy3v7Rnd2g9UOBMfoa3xdZErtqjtMS2e94r7WZlXjYp8ynLIGcyS9IrOz7QrtJX2P
         iMTSrGdMw0ENVObY4fCxKz8KTaaqMDPd+7JDzUNil4k06wAHnfDSXI1073G9VVWDm3yT
         d3ZhC3gUduUkTUEaQRK3Es3ackDaziOyJJ3Y3ifOM4RA3eJbpXxtF/G4j8jEaw+TTLPr
         FisA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwp/6j1kzWro7ekhunzZ/eQGspar8QRNqMve/UOqLRZhn8PE6gZPkDtSbqPtf95P+14ayLxSS4dgbg96nERkY/GgzCwYTAZw==
X-Gm-Message-State: AOJu0Yw/CJrjMrAV7uaJpdmLWf6DFooUBfEsnhwjPYwwaFzeFCErf/eG
	YUrwCDpSKnNfZEtlNMuB8NeldKH3J4EKWyZjZFl+vdSyVl6lLnkZ
X-Google-Smtp-Source: AGHT+IGMmDqjQt8IqpRz6IcHHDodArvg/QgW/mI3CWXOVIafLW/JCruMcejJT9X5K2IQZxjrwl+OtA==
X-Received: by 2002:a05:6870:c0cd:b0:25c:be1e:4cef with SMTP id 586e51a60fabf-25cbe1e4d96mr324713fac.32.1718845155240;
        Wed, 19 Jun 2024 17:59:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:700f:b0:23d:21b7:fd9 with SMTP id
 586e51a60fabf-25cb5f44a68ls419225fac.2.-pod-prod-03-us; Wed, 19 Jun 2024
 17:59:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXv8flRTVhFfwwVcC4qk63ZRFNICDp9yaM9FVJRBRbnRfXJSG+38cVhMWy+sEcV5Yj+EIxq69sAOF6o7/i6qx/1iQJnuWySuDdynA==
X-Received: by 2002:a05:6870:41cf:b0:254:b24e:e351 with SMTP id 586e51a60fabf-25c94db972emr4426226fac.59.1718845154471;
        Wed, 19 Jun 2024 17:59:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845154; cv=none;
        d=google.com; s=arc-20160816;
        b=CkqEBbSKBTbZGojvab8kWbvPnfZBwU6G4DGHT3TBDp+bWz2p+7XVhMq0isL9P0GWvk
         CLNU17UBcAdOvQSExiolBZOAaoGij5/3KyXZLtHUgl/3DiNKEyap9SSl/GGYe7GPyCZ5
         wMCIMdo+8A4ZnAqjbELVwWo5xBuHsenQG3+y5Leq3y+qaevwMJZxM+/KmeCof50xmGDI
         3Hj6sTaUOyb3gKOCGnqCU/BlhpvsujxVYU3/MN45WjJCqnHF1DiimTo5wto140LaQylq
         bgqA0MIuEMqxgm0mfBOK61ScDBXe7LLJEaSf++ADqKcTL+SM/dN+hoB5DZzBPunheraE
         1g+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=rwhbEbJicV0GsbPDyIXT9Mk7gFAMiwuhtYKnMH7no3Q=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=sJzrQCcXyxjBa7EpSkLJf2QbMMjY/bWazrnlSbFJQ5UufQIdoyAZB1btj7iOs8/2At
         d81D9FfZYUuoEFf1SYwoSUiGsbjKVlLjRk89L8TXPlBl2c5dg6SfHTb2PqQ+Tqh7HywO
         DSvVfgC37VU1mqvmJnH6iYrYWSiYrA8eQBkrwa5smQohLp/o6njOqhqqDn7Q8u9lBg95
         cp8yADhkMLgMx6EuaxrkScE3Kad899qj+yXJOgp4sxfcRl8cwm+i1us1OavHhGbkRn4o
         IebXMumjJJRbjRtgxfZH+OFHyTFvYINVzhny2LE5khuf/Opfj9Y2IwAdqhGSVi2HD+GO
         dAlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Q56XbFNS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705cc9201c0si684660b3a.2.2024.06.19.17.59.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D645661E9D;
	Thu, 20 Jun 2024 00:59:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7BCEBC2BBFC;
	Thu, 20 Jun 2024 00:59:13 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:12 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch added to mm-unstable branch
Message-Id: <20240620005913.7BCEBC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Q56XbFNS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: s390/irqflags: do not instrument arch_local_irq_*() with KMSAN
has been added to the -mm mm-unstable branch.  Its filename is
     s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/irqflags: do not instrument arch_local_irq_*() with KMSAN
Date: Wed, 19 Jun 2024 17:44:04 +0200

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

Link: https://lkml.kernel.org/r/20240619154530.163232-30-iii@linux.ibm.com
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

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005913.7BCEBC2BBFC%40smtp.kernel.org.
