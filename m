Return-Path: <kasan-dev+bncBCT4XGV33UIBB5H5ZWZQMGQEBLEQHOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11A4A90FAB2
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:34 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6f9d8c1603fsf371919a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845173; cv=pass;
        d=google.com; s=arc-20160816;
        b=K2eAzZXCcr0ry3RzfW0UPgnG+55dLPurrFqriUeCyFTjX7iIFnwcliO0elEk8J/Awu
         T+1DiaK9xdpaqjNyKaPABqkv3PCJXEiVOq0snWqINyjfk+gOhNuIHwsNfdVfvKhr9pTl
         e/ykwGzkFYWNtZeciPj1H7nuAH6BqUsfPrdqbyiatd2quAw3a3zIh3EqimrU+YVwruRN
         BWwN3JttEWwwB88dJyvdF3bgnlwRItMNvpoEBTxIjClpuDwpkimnNw6bCVhNZFn9QFFi
         8dkS9q41UqWeWUj+VJZOcvnTtoQ+QDhruLuKSkYwQY5DNsvu1vKzKNAC7ADwJwqx/FSV
         msFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=wdKgOtKqhPB+uncUEUhWVPIR96lGgATPHiU3+ZJnBig=;
        fh=sY9jgmM8TPxia3eqRCyucXQKGw9e5OifwTAMagSPpPM=;
        b=MbHxZ0EqNvQ1dtLBlNmVK/jmUVuf19qcgAyp0Z74t3hjv2Y88rkCkesf4lSPjrTuqD
         hPsvIAltWYdEjmtZghj+wRte9W7Vv6yitzLtJaFJ6KqceatxULr8St5h3wncQuav78EN
         Bpy3UTSPN5YZ7QFyXHlyb/LXC3VxuWNk50OSKAyOyF+/dDm6LNxPDx3O3/6WqqUzJOKG
         GVkmK5Bck9EyZmUA33aO19KE8mLOZmxZpL+CVIIjpi4mibusPaaXV6x0nkIL0w2uMQ8b
         zwF7FoMRrb8U3TrU46Yg10CMnRHhT0iJN8fEKUqh+uVx6pzYR8Nmp3tv3UHx4ZIpxE8Y
         fo6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TbHTVoHZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845173; x=1719449973; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wdKgOtKqhPB+uncUEUhWVPIR96lGgATPHiU3+ZJnBig=;
        b=STC9u+idq+i28r5aZtRLZnGJF6fn1D3rmAEJsu/56raoJP1rRZBGZPrRRIHrM5tetl
         T3pdv7TuNcSsXOJ62Qy4OeFqUhmcO58+wnolP844zfw5h7VW4FMtH7pCD3an2J2F8K6x
         D7TiUt3ahmu74sH4gZk18O77ocYxaef+1CHfymayHFyJYa34BHe8GrsKVg2GC+bQ+DqC
         oxSjkLIAxXGBLk5XrinbCCHtxWjeENM0q2iBaoOadY6XYC+qwX/zI2SKWbJiwPsP+Qi7
         Ubcn5UBrQQlj6CEbqyhBvjJfmwaFBXzwIuOEomYYegQ3NHb+ZQp9DpVzzP4Lhj2epQR2
         2ymQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845173; x=1719449973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wdKgOtKqhPB+uncUEUhWVPIR96lGgATPHiU3+ZJnBig=;
        b=l68XAsl+MzFKF2+NfjUIPEKBPgjI2tpJdVZk2AhQKpOqhEHbu1bzZspLhMEwxS+0Ah
         LoPj3RZYPzyWDbsM0AKgnfGzr+MCR9TH5OVb9QgkV6hG6B6xAgRVVJqoBPvPpb+zmgL0
         4diLXT0Ic6MwusLV51b4bPQWWCh6JjtHELU7jLeVLQ44hwHXhOS2AoTLQXCIKtZVpeYD
         3DdKoH/WinxVJmCnUZ/s+sx8LE8Rq20melirC9jvOTRffq2l5xn1fbHYcCnEdqXzHn5j
         k+z2Q55vM7z8LOh8+6c57xqnXmpdRIxj9/IjlIrtlm3imz4hpe3DgxOWgkkCcI+uUiHT
         huGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7h4XqSLWdyylIHKdke5vTQLEsU10huY6fXWxVvrWOUNQpdCl8ulvK8wsWAY8UvyjQMO4JeNz4QRVP2zclHESUvCW22Hpz5Q==
X-Gm-Message-State: AOJu0YxLYSJIk0m+mCXyQtdwZ+IdpsfwFFK+/YofNIs4XUdFrXFEI4OR
	7pXjPmZzRK73rcJCeHoNiyo2mHlg+e8hXKCfDLU+PkhZB/+JTOhR
X-Google-Smtp-Source: AGHT+IG4IHzugIXvyyJCW9tHJiNR1fJSRE1dL+QaT6aTekr7hHf/zQQg/IGf0igF9w+jBNxqWr844Q==
X-Received: by 2002:a05:6870:c18b:b0:258:42be:ce5e with SMTP id 586e51a60fabf-25c9498fcd6mr4293116fac.16.1718845172757;
        Wed, 19 Jun 2024 17:59:32 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:1c8:b0:259:8c55:f25b with SMTP id
 586e51a60fabf-25cb5816a35ls391328fac.0.-pod-prod-02-us; Wed, 19 Jun 2024
 17:59:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwuC9b2zmgKJIOgIWGlu2FQt98j5nBiJxJvvAdF3y7wb3VEjCzovFiXBwtExYGrNUjDXU5fJLhI3e6y//mJIXGpe+t1/Ksa+ByRw==
X-Received: by 2002:a05:6870:d0c1:b0:254:f00e:569e with SMTP id 586e51a60fabf-25c94990391mr4145408fac.17.1718845171974;
        Wed, 19 Jun 2024 17:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845171; cv=none;
        d=google.com; s=arc-20160816;
        b=gF8F4ve1cHtXlwSh91hkby2LcR+wH5paY1yWTluC+jpyQ0ZFRNeAP9zDYJa3F0coGL
         6apcN0Fs4GVFnpw/z5xDD9bHNVNRPN2h1s9wkh+iOGugNVyzR4zTKO2ubEcjk64FWnd7
         vCxaCFLToA9pmF1QAWsiXi/kZjQq97K+Bu+7Nfyk/c9hKGCaN95WWG9wR2BopzBH7QPu
         /WxvslxgXb/IdwB+rqzg3VYWwHc1CMwh3USY85XOP89fkgjNunceH9+Vg3cAjTCwzvkd
         SmD3bG4yxUlJ8aM7RhyX/4VLhf8O5HrU5aGv3bbqQSrX68iDS75IjZERy4nsx8z8UfYs
         Llng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=YSlPrjlqsOZ7Pcvw5f/GXLwhkruFCo76HUkUyqhrJTE=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=mCURLyXaiwiFtYQki2glocVh1DFribtgjSDKIlBuAs2lKAooeyRPmB/5rofkqw1XlN
         2lJxs7z3IQCussjn6Fbkt2qp5+1zg3SQv00xPqadz8NDWdwvwHWrlsZPvDgX1j9qFu5f
         975W9rgbJHecZFC5B0Mxq3yyCSudUPPAr/kgx56aiVazkczrw+8UvsFs1+U3332Ybjwu
         pjGDjCj0gp0Ju2HOb/Mwe2xcGuSilE0sa130z2NTAphRjTEsaYzQfhJfAcMzkaMXp4GT
         qONnVI4WAUyqT0FloYOPvyDbm6kM/xlK/rs2excnZQAw/E7AJxb2GES2GeS0ZzFkF5hi
         fWUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TbHTVoHZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2567a98fae0si637838fac.2.2024.06.19.17.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 641E0CE22DD;
	Thu, 20 Jun 2024 00:59:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A5931C2BBFC;
	Thu, 20 Jun 2024 00:59:28 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:28 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-kmsan-implement-the-architecture-specific-functions.patch added to mm-unstable branch
Message-Id: <20240620005928.A5931C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=TbHTVoHZ;
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
     Subject: s390/kmsan: implement the architecture-specific functions
has been added to the -mm mm-unstable branch.  Its filename is
     s390-kmsan-implement-the-architecture-specific-functions.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-kmsan-implement-the-architecture-specific-functions.patch

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
Subject: s390/kmsan: implement the architecture-specific functions
Date: Wed, 19 Jun 2024 17:44:11 +0200

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Link: https://lkml.kernel.org/r/20240619154530.163232-37-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>
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

 arch/s390/include/asm/kmsan.h |   59 ++++++++++++++++++++++++++++++++
 1 file changed, 59 insertions(+)

--- /dev/null
+++ a/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,59 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_S390_KMSAN_H
+#define _ASM_S390_KMSAN_H
+
+#include <asm/lowcore.h>
+#include <asm/page.h>
+#include <linux/kmsan.h>
+#include <linux/mmzone.h>
+#include <linux/stddef.h>
+
+#ifndef MODULE
+
+static inline bool is_lowcore_addr(void *addr)
+{
+	return addr >= (void *)&S390_lowcore &&
+	       addr < (void *)(&S390_lowcore + 1);
+}
+
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	if (is_lowcore_addr(addr)) {
+		/*
+		 * Different lowcores accessed via S390_lowcore are described
+		 * by the same struct page. Resolve the prefix manually in
+		 * order to get a distinct struct page.
+		 */
+		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
+			(void *)&S390_lowcore;
+		if (WARN_ON_ONCE(is_lowcore_addr(addr)))
+			return NULL;
+		return kmsan_get_metadata(addr, is_origin);
+	}
+	return NULL;
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	bool ret;
+
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing reschedules to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = virt_addr_valid(addr);
+	preempt_enable_no_resched();
+
+	return ret;
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_S390_KMSAN_H */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005928.A5931C2BBFC%40smtp.kernel.org.
