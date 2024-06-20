Return-Path: <kasan-dev+bncBCT4XGV33UIBBNP5ZWZQMGQEPC6FKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 33FFC90FA96
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:31 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3d2495664b4sf293991b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845110; cv=pass;
        d=google.com; s=arc-20160816;
        b=PuLkmkAjtGP/qzVZU7tJQ3VZxMtKCMRzI2OJcKbQC+BVQebe/HCvtnrVkNCZQtwym9
         KfLp6TkRCK1qT7PBPlOggsRhU7qohLGJJJOimHu4hrTUOrSD6KMUyuFC6AJFGgGwoXwn
         VduDVmxhWfDdhvsC+3s4YYTgeo8ZKveDzA5qfI3euL+xtFJnQAA9xM/aY0K5iO/fqF3i
         N8xfYY5jJZZc2XW1SZ0p9QVb6akFEvILXyUmPzCaZDvpsT/V88UvvPbcyvrrxYG/sCSk
         fp1kjx8108iQBaJSVX9ZbfApoUCbpHxfXnHwkyWD1gXHsKT5y/dxptCHp5OQTsy/Mgef
         grQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=GMaudnR3OQsWWnDyLbSx3p8dqBk3ofXAh3SyRe5Asck=;
        fh=3clePesr6TE2XKgsXS38AwQwid0S5UpB3cEDTm6aHc0=;
        b=ZpZGjF9BzR33muMkvwdmacC8WU6GtpEHAIyxqym9fsdEbV3j+qAFGiNA21KYPZ79zT
         SfaqSUpn3r1gO59l3lOEDbIPa3pAx7BCU9youI27TI7n7T7ODbf/Jz2S1Du9vXaZf+CW
         5h2VPb+ni30wjdftWTDg53jLnhgV1GIttP9n45BX1aEZjbSUp9Ck48IstG/h1wEdHtyQ
         +UeKZ5sHykoMAJMGj5awwbE8tWnxaylwFFke4PxUWfaYTZxHovOOU1jcbqrv2enI/tSC
         PoOd4Q7D4oH5nrh9S81Ze1o8uN9dASlcXYDmGIgf1TvNph87FAR3BZoEXCmHwGIO+BGF
         AdDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jUJb1ih7;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845110; x=1719449910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GMaudnR3OQsWWnDyLbSx3p8dqBk3ofXAh3SyRe5Asck=;
        b=cWaHDXgAdGE3C7Dm9DM9P48ZkaDt5/jBvW5wRfa6WzPoLgVr+NQTeczd0p4fgHWl93
         qyr60kzbA0TNAsAoeVKcQ106O2OSS8uw3qfUFWRPJQJNM2HYm2/vMytEos4hiZ4bMdM6
         FMUKMX+J3NPoBVgmXEuUVcuURNLPWriB9bG9fWUczghrGKT2X08HDqxsX5S32PiIj2b6
         eS55ilZHyc/ljV6+8EZWGL2e1+wcunRKUsc8HdoiczO/pEu+KfuUf/D4NtWApcp0mCrX
         uKq1cScouh7fFnuRRJ4tVqpyThUpJjqQTlzKDYE+9MqHv5S22VoZFIt74I3pQAyeay/5
         o77g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845110; x=1719449910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GMaudnR3OQsWWnDyLbSx3p8dqBk3ofXAh3SyRe5Asck=;
        b=k4JkPAgTQquXjdZX6P7OsLURqjxhxAXr25znUDO7GRAmZYigRmVmY5rlNsFaaTX+Q4
         DpnLUrEHyUpJsd3o+tEMlawinhW+Q14asmahznYcS6H41xaDCW8/+vd7Qqq24rJCHl6o
         gI0sDvLRYsaYqecSQqFccMV8Dmu78076uGi2mAyFhTCuRW/q6YGR5XUZd/2gW2joyT3n
         tt3GWgLbh9Jz/+2f5vlCdDc7TAIjuHQR5/BrgHRuLCWnim2ONeBl9a9Zm/iknChvSZ6+
         Ewdr8OU0wIzCQfb6kK36zqRYT+tsGsnSQS6S7hTbdmyWGcePbeGR6EwGgtmoGjqi3I/i
         MhlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+ru9+OLzaGrC3xCiZJcHR1rK8/Whqs1l3Ik8+cN+4aBHNa5krpakDVuSpDWwCYp7feFjX7XsTgH0q1QDH2QUP9CgVN5hYCQ==
X-Gm-Message-State: AOJu0Ywd6aUPMNjqz4VCzQsmVQPLBjhpr7Tg01IUGBx7fGskO9kBcolf
	WBC0nNF9Vf7BKqfplboAKU5NfvFNzvSJ2HJxpJxRHNRYrTBij6NS
X-Google-Smtp-Source: AGHT+IEshKLj0xAjqS/1QONW4RDRvikzoXkWGCPBY7sEx29Wtub00wy/rU/Q7MKOr9nxmN1bTqtUvw==
X-Received: by 2002:a05:6871:58a8:b0:24f:dad3:97c with SMTP id 586e51a60fabf-25c94d05a4bmr4742184fac.46.1718845109779;
        Wed, 19 Jun 2024 17:58:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8008:b0:706:4559:9351 with SMTP id
 d2e1a72fcca58-7064559996fls32732b3a.1.-pod-prod-04-us; Wed, 19 Jun 2024
 17:58:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRpi3O1zhqrqD06JKhSKuaCRv6YTAXACQrXcfvY7Tv7xY1x36YpTWPc96NbfLfc3FzAkXXGzTWIEziOXvxkbgwgBQvP1SarrbFTQ==
X-Received: by 2002:a05:6a00:1b51:b0:706:334a:43d8 with SMTP id d2e1a72fcca58-706334a4790mr3106509b3a.2.1718845108453;
        Wed, 19 Jun 2024 17:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845108; cv=none;
        d=google.com; s=arc-20160816;
        b=OmIXojNzQzmpqQ8UcLCzdtnQahgnO9Cpzd0H1KIj+TjiOH62I9i8RaXJS87WMAjCUI
         FKMVbaup0BAdyH6l3M+5cNIUuqMhHHjPxGeTiruN7eklVFHC81IsqSV3sG3DMXcbXidR
         VHKZCI6nuiWQGfDS9sO+uKIHwXqvi59NUbZTUGN5GcxA0ALntW8S9622uqgAlr/8d0lr
         2oLw1UjgzFCyLQuYMcfjQR3b169t2JbUOWKVLfO9A11RSl+R5kGrlfuwpftGzzKRJ4vg
         +cSqfaogJEq32lFN6wkMQvOFP/sXufzLgpivd3A3jI5UEXkCDA4ugNORMCuHXmhi566R
         KAtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=iiUDJw6WRQzcBecq65uPcR/eQFySiOKyun2W6T1/2hM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=yw67HxjXBx+u/NdrLX9VMO0+UxkBRMj77zFf/HpV4bJOddMqY7tjQBvdzu+B0xJJIF
         N2P4O4heK31096GceYf2wNkC80bEJepADAJp2ViuoAa2FS02NoKYOT6vJMMusR2lROkh
         DKtZ7U1Fn/WsQhcyV2Nv2Jbv64lvCPP1fjGinxzfaO58egxwICMA23WimLcnxAm/MNY0
         MQYBdhGLsN9kjRnQ3Fsb07ToYggEEoSt4zWlp4cviq2bEBvfc51DU3n1Cce1t7v9ijgX
         O44WOsxfjnczU4TpXO9T40rnCevLvto9XqG/7gGaS0YaN60uM44DAy4d5JgNzY1u9R34
         jWjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jUJb1ih7;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705cc9201c0si684619b3a.2.2024.06.19.17.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C8D8361F4B;
	Thu, 20 Jun 2024 00:58:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E6E2C2BBFC;
	Thu, 20 Jun 2024 00:58:27 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:26 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-remove-an-x86-specific-include-from-kmsanh.patch added to mm-unstable branch
Message-Id: <20240620005827.6E6E2C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=jUJb1ih7;
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
     Subject: kmsan: remove an x86-specific #include from kmsan.h
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-remove-an-x86-specific-include-from-kmsanh.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-remove-an-x86-specific-include-from-kmsanh.patch

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
Subject: kmsan: remove an x86-specific #include from kmsan.h
Date: Wed, 19 Jun 2024 17:43:43 +0200

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of consistency
with other KMSAN code.

Link: https://lkml.kernel.org/r/20240619154530.163232-9-iii@linux.ibm.com
Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
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

 mm/kmsan/kmsan.h |    8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

--- a/mm/kmsan/kmsan.h~kmsan-remove-an-x86-specific-include-from-kmsanh
+++ a/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005827.6E6E2C2BBFC%40smtp.kernel.org.
