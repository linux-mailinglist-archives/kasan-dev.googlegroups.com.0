Return-Path: <kasan-dev+bncBCT4XGV33UIBB2X5ZWZQMGQEVCXCEFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89DE390FAAD
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:23 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-375dada31b4sf333725ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845162; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVHXUWw1Av5Ln+nIyYLXm5iIsndpjdsR8USokM3h+qmByOr41nUFCrS2wnnf9QUmeh
         of4pZKdpb28PVjZ0pKyDz2WfvtkJOx+0pfEWWgPGf5Tup+2rZG8KJvecGSqHDylqhtW7
         QyaPDx75THn/KiG/O+UWUt6KlvPmttkJvnklA1d1VMm5qjXqWji+NwemTj8K8cvjbLu7
         ZVmTBvA7oxdfbsqV9gLCSZp34USStLCTD2pv4SfVCDLuC495GJsxHrr8W9ZZ35cr3iY/
         S6hU8PCB35t2UqiVL/G771jsF4WZd6lkWzKa/0TTR6zOxK4zzZDbTqLuoXQoX/TkQcb/
         Peww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=LnqOSgSZZHPKEkJWhzYGqNkrGcf/byv8hlCl5/qllMo=;
        fh=svUtoZMvtgSv/aPBvt2Bq/Ibp7998p/fsBLfkkS3KD8=;
        b=xYeqTwKLNITCPsL8KjdH8C4wlAyUrKZkDPp9E0t6Vw5iVBbOETkroTVLsX1UtRVHNp
         /8xwFc17bHbZGAZSyI5fA61Vjl0n/gSAYBqUMwmcrRbCl4Yw5CNp/U4bd1GwIbWkN51y
         TkZWfvlB311dUuY2blbYcFUmgy7nv9RSCnyqED9HLAJbjacL2IVqJJ4Z2gtMdNCeJ/bD
         6AjU9a7zlBLGYi+I23DTPNleFBJqH0rsCr1qo484kFMff/sIBQvnJkbIDtegYAU09gxO
         f6mOoo+cZNsguO1gMN6WvqiEHUiWXCFTKvZj0HWyYfcPUWynSMlEGlmycGyXe1ZXVgA2
         TCfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=09Ijkcb9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845162; x=1719449962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LnqOSgSZZHPKEkJWhzYGqNkrGcf/byv8hlCl5/qllMo=;
        b=pjWMCPtdeNwNY2MMOBTLXDLDqKaOvGclzx0Ur0Ivbs4R0NjJyxMud8/nOdwFR1Q1Jj
         S2URd+OwxPvckBlj/M2fMqOcAVSKW5JPIHURu9Tsl7z1IvQmr5f8bzYtaLJ/8KL1u1dx
         X7jIpjWCFMs0yOxlyoEnTYxYcVHSbHY4mcu0RNc5vRBwhRf3CHwKvu1UMKSLvWY0KeCg
         LJDEMxEF08GsGmB9c1w0RDQX/0mS3F++FlN0w0YrTQYGUCHFi3it36fhxjc7UvtohVmY
         PcI7m8DuKP9JL26MPQBPuGwZdZpNnt8SYQuUvfaUqvH8feACGo0K72tWEvzVA+nIsxyo
         WrTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845162; x=1719449962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LnqOSgSZZHPKEkJWhzYGqNkrGcf/byv8hlCl5/qllMo=;
        b=g2MOLP0pN4ZeTvkHVX7x5o9YNi8odG3R5nvT8eDflY1P2UKoF2+IZbjIKCeNNqR1EV
         32T4kSWOw4vK+hp5fLaNcJ13Rl4FmWeecrCJVfP9EjQTO/qhynZ99a/IgDRFmude6Xk/
         wHNxgyHgNG24HkYZmpw8+KuVUMEa8Z3uWL2CCrBsD8YAh75m7PzaUMcdG3rG+iMCC8fb
         VJ/pEIVoXBiEcqQMlnwltnYtsfrXgli2BbmJLErXfBCddDGScda0++MMHx4NmDdqjm9E
         C2PL/395rsSkc+/g7eslyFR3HENKEKsp7imzHPHII7rSbqxwqzRjV3O6RBKv8AQ5ZLtc
         swPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULmdjsQtIbulpBb1sNOcDgjSMYipXO8qZkqX+O+tv9OvWwx5dyM5t5bONdVQjSwVY132DasfPxhM9Fd3WrKEmy4AV4xzgtqA==
X-Gm-Message-State: AOJu0YxmCeOdS5KWAaPuIvrfBmzH26QfK3JsB/pYq+FTZ6yp6Lpjh/eI
	7hTAeirohcN5yLA680MzeZC/ZZ6RPE2VLfu6H+uSGQs9ADQ7qebk
X-Google-Smtp-Source: AGHT+IF5qDnclEACAmD3qfn3w9tRKh2ejEs/zZ6FRp/VfLIr5t9K/e6Xky3Y6OuQJojCDe24yKXtPQ==
X-Received: by 2002:a92:c801:0:b0:376:21cf:9e5 with SMTP id e9e14a558f8ab-37621cf0b14mr2541845ab.22.1718845162156;
        Wed, 19 Jun 2024 17:59:22 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12c4:b0:375:b30c:ffd with SMTP id
 e9e14a558f8ab-37626b2a46els3101795ab.2.-pod-prod-06-us; Wed, 19 Jun 2024
 17:59:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVNMu9hn1JhYsodRwgutfETMdywmUOixG8N0I9U6HUkSMhwz736V8EkeQ5FYurndMOrFtYo0zr+Dp+bb+UA6tfJpeh+ADiglosZHg==
X-Received: by 2002:a05:6602:2c87:b0:7eb:eb7e:93c3 with SMTP id ca18e2360f4ac-7f13ee778c4mr479459139f.13.1718845161244;
        Wed, 19 Jun 2024 17:59:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845161; cv=none;
        d=google.com; s=arc-20160816;
        b=tyzGxB5NqP/PHURTps3naoRpwUraybySCMWzarueUtdamKfQ0xGQXUejWEBjrVU2on
         2h7BF+wFLKhTF2ylR9PEIWTq2QW3EwOCYw22fNcT70CzHEhDJfiizZJwOPL64LB6XiiW
         dVroxz+v6HQn691X3hnxRonbeeBmtyeUOkAZL5maAo3cBx+Cnlq/mwE41IoVwUhDaoqZ
         LYQsXh7n5pB60QDIWAsJJtVNUuU/NQ66bn8DP87TlDTJBFQZGoHJw3FUFYL4a7euN6+e
         SBXZf5s/+4/v2lm9nOsfoV3g3eDQF9Hn6jiLQlj/Cq6ufdy8PVT0gfw5p6YjG/MHEYbo
         rbpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=D8DzHEM2N8ZoQkt/SdELxnwXrsoRnew4GHWxu1sDApo=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=ce+q93erV3uUDrF9qakQBkezmSBIg+N5cmP8jpqzQkpyqsdo9/0BElNgrtLYsSnt99
         3fu8rGavOfaiJHRW7JoKu5l1tVnFFALA463o4emzRQPWdiSsgI1oG3JbMbdalbM0cPjP
         eJ24OQdo57taGK1irnhG9brXyv/lb3u5JrCRb2nfwm7r8pEDGofdJAJ3tjM87Ds64IHe
         bgnwUjqCtV4M9MuKc6ASDLOxuLYXoe1yldWia3So/igxWg5dkAcBF2es3NgzLbzZFYmx
         wRASNh12akIC0qxZm7txkezfzKzFbxUXdmYcjZcNtXOYEvIpjkL7o1pLC2Tgd/AXJCbM
         d70Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=09Ijkcb9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9568bb7a7si666205173.2.2024.06.19.17.59.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E7A1D61F4B;
	Thu, 20 Jun 2024 00:59:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8DD1AC2BBFC;
	Thu, 20 Jun 2024 00:59:20 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:20 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch added to mm-unstable branch
Message-Id: <20240620005920.8DD1AC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=09Ijkcb9;
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
     Subject: s390/traps: unpoison the kernel_stack_overflow()'s pt_regs
has been added to the -mm mm-unstable branch.  Its filename is
     s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch

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
Subject: s390/traps: unpoison the kernel_stack_overflow()'s pt_regs
Date: Wed, 19 Jun 2024 17:44:07 +0200

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Link: https://lkml.kernel.org/r/20240619154530.163232-33-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
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

 arch/s390/kernel/traps.c |    6 ++++++
 1 file changed, 6 insertions(+)

--- a/arch/s390/kernel/traps.c~s390-traps-unpoison-the-kernel_stack_overflows-pt_regs
+++ a/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/vtime.h>
 #include <asm/fpu.h>
@@ -262,6 +263,11 @@ static void monitor_event_exception(stru
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	/*
+	 * Normally regs are unpoisoned by the generic entry code, but
+	 * kernel_stack_overflow() is a rare case that is called bypassing it.
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005920.8DD1AC2BBFC%40smtp.kernel.org.
