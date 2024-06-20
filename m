Return-Path: <kasan-dev+bncBCT4XGV33UIBBK75ZWZQMGQEZWU3Y4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E7D90FA90
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:20 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4405e3b3b78sf647051cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845099; cv=pass;
        d=google.com; s=arc-20160816;
        b=nvmtk9CaM+ju5Ylmaxlj9kgTUSjvr5cvflrDreFrLwtjJuXAlH97LU6xxynzCoO1jt
         6kQWtkBglMeL1AVKT89iDqnEgiGVqTIke7Mfka7xG8565BobEdOzDr+D7PW9Yve6iiUJ
         K/jq0xE7yPoCOnTGhknI2I1y/geqPnrXRRi1AgFAK8JpzJQfzHSRXDuqdnahSfQdm79s
         2XNtUchYBdaLlN3lErjQJlndsMpwmkNudiHm2VEfU6NVmPCF0AA5jD6c+JPat8xs/gKL
         zBsIsAW3EJdDu1aDQ3xciJtkDOGtpzb/2xg601UbzSbMboMms9qml3PiOGwrIb5PGsXk
         dkUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=wzanSOo2mHaGeXtru/nHCINWEGCaU0bkiH8TLGQt+zI=;
        fh=omnH+TTyKo9lFeB39WUdQOo6TV2gT9m7/zAW8KAG7o8=;
        b=tM4fHXCiUAPxZ4aNKrBekFFtvzRDBpw2QrdSr1g4KilOq0fWV0Pv/wQ6HoZ1a/wEdh
         uys/VP420fqCLjQ8DbfU45XB6xfOfcylEwYEFAvtMAH9iuIxQmAUYSSFHeJFluv4dxt1
         7IbyZdznbb3SdG9pbXWZyE/j8DQSWkHcOlQdlrwWgx9dZFn+0SyGOHwa6gPAulwgoqQz
         k+ZUxhNEIbZXyD0KlpP6IElW7rFeuiHXox9Ce66Vb6yvmRx+Klyou4DW7OQSHjlIYrMN
         t5uKK1yvypsMLT6uLGvXqNK2R0Pk8/tOZvRT2iFt1xhHXjIFOLEbYvFDcDZIWWOYT6t2
         saBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TUJ5UjQ3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845099; x=1719449899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wzanSOo2mHaGeXtru/nHCINWEGCaU0bkiH8TLGQt+zI=;
        b=ETRH992XmOQB58cn24Jo8DyRvgSBAlgeUw9vECrih0DD0wdGZ0wQ1gc825IBGaJ/GZ
         2q3bPM3YzbqlIpFp9cs1FTGf5aco2nm8In4LG/+RkGw5R9aKONEh7iMllAkZvJvfadYX
         Wpv1nQtYkZpj1bMVGFV6qY1TRcpndjK+Y8MGnkqflkE8MAQZmmPk5+Fxnre9mY3559U4
         vCAorcgj/voT6qzsKFRLie2DH33RfSmyhRlmpr0ZjlB1mY2mMso1WXp6x8q1fynDeon7
         QUq+BYfMNq6qQ4LViaUHhbybNFD2AhevMaEtaUGXNnI9tShFk0fJ0zlWPU83r5uF+gnD
         XvnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845099; x=1719449899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wzanSOo2mHaGeXtru/nHCINWEGCaU0bkiH8TLGQt+zI=;
        b=W7CotD8jvrEPNpk9byhM30lFtRWaTJ4madhvSc1btPnVvCzAMzvDQz2YLmTrbX/eoR
         DMTqkJ3wg1mCMOYkykmgQME7DiClc6C2VFUP+uKgVQgbzsz1c2gfpO3jG6NqSFNViWFn
         Q8bzzsJvpCCA+A0LADDrtbq3+cAD5fPi72ZxatJY7td2IdcYxbMa+skvdi2VjcAoHDB6
         kpDjHJCR9aWffCI3uzV2GovnmJTCNl2vKYb9Z/MwkbDprZC1/t7kVEIpTeihczatTtLO
         6cHU1g9Usy2pEAueWJ3qbi//RwKbhFFviQvt+4QjS6flis8TX+vewVPqOlNOZj6J3oWQ
         tVkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXd7lp+fhiFIg22BlNuP7ZZty4yDdkx8w6kWCNmK0fiLD0RRiDGIs6OAkiKOApW9pT7ZbD2QuqtUN2tqWPrimlnv7dh/QEIvA==
X-Gm-Message-State: AOJu0Yxx8XE0LQLxEl254n4Fsrqti8ahNEDMQOy9d+AWeYkXfY/QiP1h
	5OGCLicnUJ915f41E+/NoDFCtrpEg6GVgzbBIWuQ4u86O0gOjS7R
X-Google-Smtp-Source: AGHT+IHqgT1KVggWUFOpXA0idoxUQAarYeYIJCDY6kPRpu16HBxXMzZ/WCD0UkUVdtz85C+GCoT4cQ==
X-Received: by 2002:ac8:5808:0:b0:440:3996:84aa with SMTP id d75a77b69052e-444aa406154mr3837181cf.15.1718845099524;
        Wed, 19 Jun 2024 17:58:19 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1895:b0:dff:34c9:92f8 with SMTP id
 3f1490d57ef6-e02d0ac0766ls576763276.0.-pod-prod-05-us; Wed, 19 Jun 2024
 17:58:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZWln70TQRaRAqhUQNJSCfaQaGAEDuyOD2PVpQFx2iykWJsmPVcW681gEMP4lk9tcrwypt2C5o1lC6qQQDxG65WSmUA8eLHSIpDQ==
X-Received: by 2002:a25:db85:0:b0:dff:3c42:8b02 with SMTP id 3f1490d57ef6-e02be10a1a2mr4183337276.3.1718845098623;
        Wed, 19 Jun 2024 17:58:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845098; cv=none;
        d=google.com; s=arc-20160816;
        b=fUjDNXMwn+VXwaP79+hKqNBf9bThpOhlUQzOHx6UwOyegOCqX0m4hzysFlGQ2jFNY0
         UNTjObGS9EE2RdZrwzlSUZWLDHRyTmIqzfbI1EXe4PwN+upRyh4xbpl23cUVG8qUmfaN
         p1cqmFntLCb9jwBqXD2ULkzeEWD3ODnPfsRhhR/FCCFnhKE251IcO0azJWZxjsXiNVVX
         iam7sJBNRu8mGgC9TRpG7kl/UfpoKtCwrb/clX6AvZ1jDm4Q8HJKS4eMhyH8YJqjGGdP
         3LuvTv1JjjZdJKKPtjXZakUn2bPBGyP0k8kLrrlcZPC5bjblTbVtZdRaHtPVfw0om5DG
         NSwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=NW5CqsOX/ksOjpun6Q57nXcar3c0gC9h7vuUl4K6aVE=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=JMRF54p0oOQJfENzoeL60I6twa3rpUXPHh6JAwZKq4yaKu3Fyx18ZPv0zTcuAMz5Pd
         4k+rf/UGfJWxvjTwItstn8ZdVdIOY3znGgG+oD7Cq8Fkdi3EJObgioCQ2g1WG1kxxYfo
         lp5yu7EsrlOPGcUMdhdFcHmOV7RCulMSNVgYLeH3zoSJnuKHJvaTmTHflmBnNWLpe7XO
         g3kfHPb6V7/ZWQzx61ov8hbWrZfup0kMgbQS76Krz0TQOOPJPzOFluLufSgll/0gaSOl
         c1OyXyHawV/m8gup61ghjeTLYrXtn0aq99ROziLh0Qz8fimuoUZKtQ7awvlDqEFLaFi/
         8qHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TUJ5UjQ3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e02c70d09bcsi131061276.4.2024.06.19.17.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1D5AF62023;
	Thu, 20 Jun 2024 00:58:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B76DBC2BBFC;
	Thu, 20 Jun 2024 00:58:17 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:17 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch added to mm-unstable branch
Message-Id: <20240620005817.B76DBC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=TUJ5UjQ3;
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


The patch titled
     Subject: kmsan: disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch

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
Subject: kmsan: disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Wed, 19 Jun 2024 17:43:38 +0200

KMSAN relies on memblock returning all available pages to it (see
kmsan_memblock_free_pages()).  It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages.  This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered an error.
DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as incompatible with
KMSAN.

Link: https://lkml.kernel.org/r/20240619154530.163232-4-iii@linux.ibm.com
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

 mm/Kconfig |    1 +
 1 file changed, 1 insertion(+)

--- a/mm/Kconfig~kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled
+++ a/mm/Kconfig
@@ -946,6 +946,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005817.B76DBC2BBFC%40smtp.kernel.org.
