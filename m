Return-Path: <kasan-dev+bncBCT4XGV33UIBBKP5ZWZQMGQE2DDIOZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D31EF90FA8F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:19 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f99666500asf3835265ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845098; cv=pass;
        d=google.com; s=arc-20160816;
        b=Richr74Ntaz2RPZpDnnJCkJAoq0sZCnALocj/qe0HUZ0jCaDTSBEnWDK3BVLgwgUGi
         wCXaBK+Tw2nrvJrzmZQNfE1yDgLm6RFimK+PNTHS9gym1/ZYGZK4CyA8ZtWvTPuRjIV1
         uexxL0lXHvWrcdILWdC3DlqyewU2jqL0em+wzd9gtfX3Uy3W2v/NXWl3FI4E5EtcDu1o
         pWBN4gLMOVGlpKkgUVeliOPCD5GP1SoYYSxQDve7SELofAPTVrfFpRHp24I3gY+0QJT0
         PXUNVc7Q+eXfy00PaPjodfJJzezbt1jLJC4bE9YTfPcbmnJRxtRHgdYOvMMVZOGg6H7K
         Z5hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=vomQDyd5iMiilY+3PVWpF3n0NU6nVHoKIIRHQBdWtQo=;
        fh=wNRl8RTJcXYPZKqwDJTDJq9FD5H6DxrQQzRTnguJc+k=;
        b=IeQMZrzX++1+GGAq8g8xfo4bsX4FwBka/Qa/LtkWheM0wZKA/07a/2ZT8lgjGel/ob
         tNz/4xS76OeI4yp10pCL3WZnfH6fKM6NWd33/ZlJoBA0KvNngcBgaPN0yyV2/fl7LPwl
         dcJRr279dKOYqYxILfgkpMhD6Zlq4Xn0P3jr0cEhvsfi3DFr6BYZD1bXPu8KfQWtGujj
         rnLduQNQfPQ9teOTbcQZK2UtrbaZ7Qnrb5sYD4y0xT+SHqD+5WLoWpRAYUi20iMYoo7l
         cira0v2eyBxYIkqT4O5a9EXqq/lkGBsUfMxfY6Rx8DUPNgrdXT+rbk/7albPTNenlEov
         HKcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YbiHSF4t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845098; x=1719449898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vomQDyd5iMiilY+3PVWpF3n0NU6nVHoKIIRHQBdWtQo=;
        b=jZjQ8fizL54MTNm9FJ02Q9RSrorIq7FPyjn8O/qUNd8Hq+Ui18W4JMpsOk9GKfoLyH
         byvzNZcqjz6TDDTrqpvVOAdctjL9rUCSny+DzLesOS5gNZEnbFNb33FBLrKExTnywyIi
         SwCIOy6c4g57OcevZzVdbBY7sGwjg2Ki+Qu8UXt5WJMh1N9L+XQEq0KQV+BlMmS77QTL
         PKwpVzsU2XHh2VW5C8LLe1fDSP7bW2IT/dqFqeq4kYFeEO1a0y58gSc83LUWFrcNxrLb
         1jXU+RSg5wZBLbIQ5iHAcorJNDOWAYQHPa8+dQ6wZQwL1OqI0l27FwD1oa8BbvBmu7x3
         I70Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845098; x=1719449898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vomQDyd5iMiilY+3PVWpF3n0NU6nVHoKIIRHQBdWtQo=;
        b=t9ap8O/R3qcBme1SYX1KXwQtKhRA5me/1wfc8stt5DgwUaDy6PIg1/D7FHyK1CGM/7
         uvL97TXLTcaWY/V/1K8cL30G0jBdgLDuflK3DOuyray8kizoMwLA8i5+ujtjJdjl9baX
         dHMovB4sQpP5N8Mc9bZPpIxwzjl1VIDsw9f4Rykm89v4bPSqHCAlkZc0NwdhussvK0Zz
         AAG28nK7+7Ka7Ew4+7WZv8uj3kraUjMz7ysK0SMLLMU1O2k1HRCrIgyII0sUeVXn2YTk
         1OidrBeiJVLuFjOEBCp49V0SCQOeMLY18a8Fz1ar6GTmixhm5ZHaOLut+1DIXsv7beJP
         a9MQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUarMZX2KRB7cbFy9tXfQ8X666BsMPAyo0fJCqOzeTPJQOglrhvqa40ocZ0jMv2Q0RTkCQG0hip+BHhd55Bz9mnGOgJEL6smw==
X-Gm-Message-State: AOJu0Yyrh61eobWHhiBN95x/+9iIc4XfkqtptXMWWkzQ7i9WVKeFyi0+
	zfpQveTxf+8POJGPIkayfvwmKRbzWamtnnDXx+d2OrYWya5+F/Qz
X-Google-Smtp-Source: AGHT+IE+GQZCmTulyZC5JZmP1KJ1vg38BsCSzPyjcfUsu1FyiCsZzbCxoXP7BqeqRiY2U3/HmZCHGA==
X-Received: by 2002:a17:902:c103:b0:1eb:fc2:1eed with SMTP id d9443c01a7336-1f9aa41802emr36715815ad.41.1718845098090;
        Wed, 19 Jun 2024 17:58:18 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac9:b0:1f8:593e:ebe3 with SMTP id
 d9443c01a7336-1f9c50cea90ls2433225ad.2.-pod-prod-08-us; Wed, 19 Jun 2024
 17:58:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWhbob85V7b0Q+mFXYwaA/RvX9uN5ynCr+ENAgLq2kNO3ICAPDTo8RZH6DLR6WjMOfHtM1VQ7lvg0GpsybBquD4keI9DWWy7ffnw==
X-Received: by 2002:a17:903:120d:b0:1f6:e4ab:a1f4 with SMTP id d9443c01a7336-1f9aa3b12d4mr48788965ad.12.1718845096714;
        Wed, 19 Jun 2024 17:58:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845096; cv=none;
        d=google.com; s=arc-20160816;
        b=zYn8cAQl++tMjeju1P+Rbut2YnrT6SkY/ngRoqh1D5Q/wd2huA9+HAjiO/YSWNk08L
         zUM5QAio902OjNr19m65IO3eiBThje7IxP9bR4pSqWpxeKVVIHDcXelu6OrEPVVCThoB
         WPqXnirlOAVCRQfWrUWsEeu4i+ua0CnhzOmbXfqMFPZjudHjKw64Se1e6gWGGuah3yTn
         lL1t/vxUd28sT+Jt9vup5u3JNC1M3CNI6sWO1sa3NtZ8Jyf/gCm+lOf/JbV3mh+mW1/U
         6QUZSvjPjGK97YGJtUpGWqiweldmijptdJd3tN8VR4llV8pPf6nf3QFZsuheWAmLYISa
         LSqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=UivrLOBUDQT8zPIvlNbaJnfZpxd8PXdD8XgMMTnEDdk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=tu/K4aVrZUeHgQjSns7H1PEsJ1Cg8UvZu5QbURW+Q6CDjotgnRj5Wq87HnaoTz4Un1
         Q35/eF4GDQL9EeC2XuzKf55R0unGL/eUXgX8EjGZKp/udHmSrFvWaZrVvjkvly1LGOsM
         cq5lF50v7QzYFdFGw0f11hoPqXfMB1+hBETtIgHm68ZRoSwowKDr2UwXvbo1rj9r2DCa
         sA7vo4xyOKi4dl99Js1wPOhPK+kcfAF2z0op1ncwDn3OhCDuwb+NA5wIKU6SwXGW7fJr
         nKdwwwWe/Ym+B+gJftinfvlCw4udB9WmzrAkgCSnaD3Wov5p3HdMgDIfK7vcpFqZDAze
         /L3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YbiHSF4t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9a6286599si1476335ad.5.2024.06.19.17.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 68BD0CE22CC;
	Thu, 20 Jun 2024 00:58:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A65F1C2BBFC;
	Thu, 20 Jun 2024 00:58:13 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:12 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch added to mm-unstable branch
Message-Id: <20240620005813.A65F1C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=YbiHSF4t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: ftrace: unpoison ftrace_regs in ftrace_ops_list_func()
has been added to the -mm mm-unstable branch.  Its filename is
     ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch

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
Subject: ftrace: unpoison ftrace_regs in ftrace_ops_list_func()
Date: Wed, 19 Jun 2024 17:43:36 +0200

Patch series "kmsan: Enable on s390", v5.

This series provides the minimal support for Kernel Memory Sanitizer on
s390.  Kernel Memory Sanitizer is clang-only instrumentation for finding
accesses to uninitialized memory.  The clang support for s390 has already
been merged [1].

With this series, I can successfully boot s390 defconfig and
debug_defconfig with kmsan.panic=1.  The tool found one real s390-specific
bug (fixed in master).

[1] https://reviews.llvm.org/D148596


This patch (of 37):

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func().  Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry().  This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame.  Poisoning stack frames before returns [1] makes
the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Link: https://lkml.kernel.org/r/20240619154530.163232-1-iii@linux.ibm.com
Link: https://lkml.kernel.org/r/20240619154530.163232-2-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
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
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 kernel/trace/ftrace.c |    1 +
 1 file changed, 1 insertion(+)

--- a/kernel/trace/ftrace.c~ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func
+++ a/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ out:
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005813.A65F1C2BBFC%40smtp.kernel.org.
