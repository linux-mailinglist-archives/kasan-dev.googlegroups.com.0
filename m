Return-Path: <kasan-dev+bncBCT4XGV33UIBBVH5ZWZQMGQESGYAGVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 13B1190FAA3
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:02 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6f9810627dasf370591a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845141; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewb67A8WRoVJltMtCd5/1+Ddb1KaCJ+vX3XDkX0F6Zr7d7k5TMSerZ/xtF3Myq45SX
         xUHQpLesgTwmZ5FrkONKKFWa8hULBW9o+ByW0Zi+4SxAtVmKSqcvtZuDekX+6cbHhWhF
         Bl97BB5wiZpfIMsUQl0hP64ePwgL8Ydus4z0sLR7UUpug05L+EbAWgGajaDWfV3rnA1d
         SShuIAY8P6eFccWFNPmKsmzOF8iQuDPtPXaOp+KQkm7SBHt5WUntRpwfve/4TSlZQJ4x
         /KgXqRe3wTt+y4wc5mwfsY5liJiFJQ2/eXVd5OaQ1drDk45ZVQvW6Tb9bPOXWzPbyOtx
         LwMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=j3Vk6Z6qF9MBY6ZJlNpnIphRk/0amPIWs7MFHPX1BlQ=;
        fh=M4/1uDGkMH1J10KCL15QPspkaT023c5Yv3J1cIK4szw=;
        b=MrRkA9DLQj+f7hv3B68PLn8u2ORSaIhB9QKUtyCoOw3HZvTPiJ2fpjCdMSq86+fckx
         XYm65jkco8hWapleoMIo7a/x4CCfTLp7XkfI2zSs6q+6pG2drLSIwxQgGbkYFQL1cezX
         D5CKWp72lNxZZB8iJhzHGqVu4su9xgfK/Zx0Y0IPauG2ezwe59x27lWkUC0PtY2e4nCs
         22Oq5xon6AFBvRUA4Kt8hCB6KIS5s4ANagI89ulttSCCJh/R/RET6PajmV3LQfsEAqe6
         /ssFZv2t6Cwzhm8tQ5+loVog+xpnFU0YhWgXRazOPqB1F5vC5zVZqMJX9EnCIWc7paH8
         iDhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CUU8a6wh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845141; x=1719449941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j3Vk6Z6qF9MBY6ZJlNpnIphRk/0amPIWs7MFHPX1BlQ=;
        b=M3VvKbJNfzDYcQ1vfYOeKKDI/RjUmkCpXI5NA7TYnOqfypylqq9OSGoWFaLgXwCcw1
         Qb2S2AGwfWF/rMIadfVE3fPjjnj0GxCIXnDSJ8zU2h7ACSQKeCfB89maEyciVcrTkHsH
         1J0t5UDR40sWD+JHGDcS4C/72Y1s2vf6PIthHy58pmMcj3JtXXnoe49vtXhYWjgRnQA4
         LKkui4oL8ZXCNYuk7OpkTlsP/McwWXYKv1CW2LvCLep4PQ3sguchVd4qXT1+Q1Oi5qi8
         bgGT0oZ5ACB3LAvuUhk5RDXVu3LeS4gxXcJL/xWfWrRgn1L/AIoUKnd5wFxI21MwXmvB
         M8PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845141; x=1719449941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j3Vk6Z6qF9MBY6ZJlNpnIphRk/0amPIWs7MFHPX1BlQ=;
        b=EE/91JPMaaFDrNN9G7DO1BvEnJQ5ZclcBws/UDzSltKbd+pGWopaFVgELOhubWWvZ+
         fCttKWi4WwFMc586E2nmU+2y2hSQKDOh2MJSmioKsFsuSLHGmI3ng1+Y0ChTpuq5sjP/
         0fq3g6cldX/j7wK+po7xgZGsupx4Duy+bEWvH3fBGNMwGY8PNBWysI4YCVPVaZIFkxLD
         4O4I56siqg7JDjTuGOplkBVDU09ktx0lcnXbPScIoFJe/HH/LAOP0oAdA841HHfel56u
         VmPhTjgnhY7sMP/nhK1Kl4D2u3KEQqt6rxeEcqisCDpRC6QjnZtex0e3dA9faCblkNGU
         tt1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2jMNGR035iWp3uk9o+7+R5OkF5q6fU5Dxrym5hHa+mf1pNmpbuUY53MFcHxaoIfuIv3sSPSHYR8USp30QqWofZ+vT9AQOAw==
X-Gm-Message-State: AOJu0Yz7ncdtxFnRvawMMMmYGtv4Fbaqp+gdKC+8XVZKsQvKxE0lezuD
	ugxX9e5LhuWsjVmFCOKvbdUMDpUp+gMyUmsQAUIhPWAROlqDe4nd
X-Google-Smtp-Source: AGHT+IEYTUeqQWLAHc86nOofTqmbmtkvzal/XNnP+AZLBKV5o+EuJbVtYff7CHoUbI3K6YzzoEntuA==
X-Received: by 2002:a05:6870:5490:b0:254:be61:26d6 with SMTP id 586e51a60fabf-25c94dfdd21mr4799933fac.44.1718845140814;
        Wed, 19 Jun 2024 17:59:00 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2105:b0:25a:6d0f:1a98 with SMTP id
 586e51a60fabf-25cb583ea96ls434210fac.0.-pod-prod-08-us; Wed, 19 Jun 2024
 17:59:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViZu4NbuxzpJy425L4BhUMnNZInxc+T5bfzfG60TeAykeMW/DpcDvAB/tKjFi2HdkHl4uUHm35nxjrk+/ArpSrdlqKbQu2bSyArw==
X-Received: by 2002:a05:6870:ac2b:b0:25b:6d53:d294 with SMTP id 586e51a60fabf-25c94ac546bmr4855506fac.23.1718845139965;
        Wed, 19 Jun 2024 17:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845139; cv=none;
        d=google.com; s=arc-20160816;
        b=XgoHPf817pMaj+rCedVKmpC/ykiGg3EZfjEQcn2BOFAu8pl3UW/UIdaxxmNC1KVl6r
         0n8oZjOI4/5+2Z3dWhs4uBqX7zmhwCFlIGY8UsLV/w+mSaLvzgfQZkoqhE4U8C3vt8x6
         ctA5dveVF+4vK7aZr6W3nlFuWwM4Sv93QkQ8tCRU3dB3cBrjXXj/NmDvRUUbXcoLAtYe
         68TeSYYIbDfabs1gcpCj7XZi/Nu/Oc/RJmlczKsJiB7jIO8tEx2UA+hOWUfqycfiVYNi
         i/ykqW8qDcqa+EIQKRSrYy2hsvFm/acZiD66gjr60el4PzYiRIlXrIaV9iSfXjEpFCY7
         7oLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=h5Qz0RdxCbBWGuQ/IscDGZILPeCvL2wmEyXnbUbpqAg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=UoB03jdOA6XYq8RkorvKbzjCTT3M8t70C9BnH6Cwb11e5tNdUDuuPEM2aX3JPRPCQM
         LidBJ7r7Rc8UsCPGOwe6JuThEHjs9Y1zzEZ9syUPEEejjNqh7TbRIaMu2N2ObCRkoUH3
         WX2jus17vHvPMGAWU55at16iV+ojcfGt1qJLTLdBtP1ASnjWDiHgr2m8mIcbocGM3tL2
         VIDBtW2B4lNJzP1UFN7hkU07IOOGUj3d3/TkVlxfCjaMP+y/odpQatkMqZYkF12u/Qci
         HpPpCJJaT3zWVwTLADZns6qkIQ0vlsCQDwoILRPfONsTRaAAzRZXDCO89qwAZSuYs9QD
         J9kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CUU8a6wh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2567a98fae0si637815fac.2.2024.06.19.17.58.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 67074CE22D6;
	Thu, 20 Jun 2024 00:58:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A8C2EC2BBFC;
	Thu, 20 Jun 2024 00:58:56 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:56 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-boot-turn-off-kmsan.patch added to mm-unstable branch
Message-Id: <20240620005856.A8C2EC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=CUU8a6wh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: s390/boot: turn off KMSAN
has been added to the -mm mm-unstable branch.  Its filename is
     s390-boot-turn-off-kmsan.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-boot-turn-off-kmsan.patch

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
Subject: s390/boot: turn off KMSAN
Date: Wed, 19 Jun 2024 17:43:56 +0200

All other sanitizers are disabled for boot as well.  While at it, add a
comment explaining why we need this.

Link: https://lkml.kernel.org/r/20240619154530.163232-22-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/boot/Makefile |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/boot/Makefile~s390-boot-turn-off-kmsan
+++ a/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005856.A8C2EC2BBFC%40smtp.kernel.org.
