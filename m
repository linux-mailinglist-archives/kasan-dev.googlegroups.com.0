Return-Path: <kasan-dev+bncBCT4XGV33UIBBNP5ZWZQMGQEPC6FKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0046E90FA95
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:30 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-44051e6249asf3087291cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845110; cv=pass;
        d=google.com; s=arc-20160816;
        b=spZJMI9HgyGGvMYUJR1X1PRgRqUbuoU93PZ3WYaRA9qKlr1AcMCBw1h6DddtECv7Nl
         GNNy1+J5U8O61k95vO0YNcPukuckhEKhOXb94TVuTlnmIx9QLSin13rgpNChfjlI3jUB
         eKlyP91K0UoM++Mnjr88mC8THKHKIFreC2mc8Ta1XrPy6p1Yprhmq9LOKU26/43OHfo2
         HfQh/GQFCOLi7dMTYMJDwLpxJwUEdnNzZrbfw4ftbfVXbESz5VxQfbdA4OmuMnVkzTzS
         Kj3/o1nIYhoBxMqqlPQre3/Nx5e6FuM/aZ8MT6yhmG3435QZx27IRSq3xC74SHueszbf
         5VIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=R0uMan8nxiEhetI4OEx9argqKk40oTlFJyEnBwzJk0A=;
        fh=iPQxtMuNpZzFFf8TdWPON61E9sKpzERz77vxGJ/4NkI=;
        b=CifyB7yg714pXg1HlxhEtA50+fxz55OKh7slIjJvqzKgn389UevJYzOS79wCmOkV53
         WKDM46ZgOjmK/mzmJV1qh7dr1p5ED/pRy5VNIE9a15U1oVT75TdTIbtX9i221NlX+j9J
         BJmxY2ZlTLtylPFQkxVEAifqSI5jN5c6u1F2+QgvXEoyT6a9H4a521SeeicnDIv08EKz
         ayh0tqoN1BqgOmU8WRt6Lohv4a81AAq3siJzjy+JD7N9J74mOjNObS2F0vzfoaIrW4aP
         J9zDsCbHtdVYJC7b9omk2JjyklFqWZEkCG2Y+rUflpSTtM99Olt5N4ZjJ/IYLwxKDygV
         lodg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UH1qLKf+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845110; x=1719449910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R0uMan8nxiEhetI4OEx9argqKk40oTlFJyEnBwzJk0A=;
        b=wBKTV+4PJOzJeqLltZf/XNEuJD6Lni1THw+UC8nBjVHkAIlkVYXE5mID0+UDjbMvN8
         UfzZ2CYMeJuKpqls5TYBilmHCoupoKO3cWLX+zkajJKJhFvgfxxJFJKsVnSVoX0cUqhp
         l4PAEOtNxk6wQ0+K83nz/189XjS67Nm0lc3QOQXNvckh/ss/VY8DAyXgjjLwgNN+SZox
         i0Q+sSag41KmGLMcfKPfI64X6blXu/sjwCW0lVw8OABILOhQK4SfNt6+mXSXnewCSHwE
         YpO1YQkI1rZTmuGiyY100NfYl4iSTlM8ZtVCSNVV3j9PkbhyRmc5vqrZoWLgizpiJU4X
         RttQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845110; x=1719449910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R0uMan8nxiEhetI4OEx9argqKk40oTlFJyEnBwzJk0A=;
        b=slVpr2RGCBgwIoZSMGlMtab54WLFap5pjCHvLE0yX+uncuoQvMU4P9ao1jt/etr2wh
         MZHF7E54Bihpuyf9MieGEPL02w5asV0iMhP2Cf27hC8gem6dKHGSrTBJOc3Ib1tPBnlG
         IJOKTVZ+eQFzDDRKSITZ5rL4cEaKChVATAEUB5Xf3FqCi4HZqF+eV2MIJbwJzGBkgg0l
         N+TatxClcYsxtxM7fVredtF9c1fr/fQWB/oboQcyWLvjL2l+fo6FrXZ4pIqQ78OiPDrl
         ZJdkCX8oBFURap8CtUWOjVEhFJcMmvVid5UT+Ob4h0pm9MngK+ztM/pWKv0XEVm7UFRc
         EubQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjSiFGTBnEnDzBon3qtX4Ut6whdBGhtJGac1XI/6xufokfCb7f/gKUsBgzIrq1mVFNiMpm3DxyTuctqM0uuK5PJzNt1SW3JA==
X-Gm-Message-State: AOJu0Yx+piqRdei1QfS2y804lTzpELD7Sko3Pe8ydJrskECd9QFix+rR
	qZK3mTsiIEvT9OlOczN+7loCd2mIhI9ujpQ69Dy9xPAcxN2URl+m
X-Google-Smtp-Source: AGHT+IEc8e0QyJY5Rtiq8JPPRLGB0Fq3XJXIljLYoBusZrUmH8VRu8ggERnxtCpYLqCFRAE477LL3w==
X-Received: by 2002:a05:622a:110f:b0:43a:f698:2b21 with SMTP id d75a77b69052e-444a79de220mr39546821cf.36.1718845109909;
        Wed, 19 Jun 2024 17:58:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5f54:0:b0:440:348c:4bc with SMTP id d75a77b69052e-444b4a38c4dls4044731cf.0.-pod-prod-06-us;
 Wed, 19 Jun 2024 17:58:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9SMqOItbf44aGlF9SqhC9irTUi+Zm1EXXmyUigASgBSDyKrr4fcJdq7jHjIsHvMWvlo9R7WfUSDU5HTpxCs2diuoX9a94hzvpFQ==
X-Received: by 2002:a05:620a:24d3:b0:797:d55a:515c with SMTP id af79cd13be357-79bb3e1bb03mr450515385a.13.1718845108989;
        Wed, 19 Jun 2024 17:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845108; cv=none;
        d=google.com; s=arc-20160816;
        b=0FBTuRtF2KspHDCxMrPeOq/2c78yUex4SiOlXDQpfVWO4DN8BpackcNnvgWjON3Ue1
         gULiJaQWb0kum3jMb9amyj6oGgofsAV2TWqHOY0Vku7Vppu3BlLtIBGYCq5iYoPLwEJk
         YrqicPTtrKiYH+XOK35qMtwu/k/15iQxCcm4IAiPLokRrWjb+SQpXIDNAXto5oCivLid
         G7u2B4aDpFibrUpK8OLG9Pafd0Q+Wora/4ayhIIOQaOn87FMYx1ZsuZSWMMhpRlqLbCj
         HpbbgX5LKzzYjlJyQZo3S4nXUVZYZFW/wleUHGxM+rXeAsV03A0n0nfZNvUHMXvf4Swe
         +THg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=qsO1pPwm3qlhUADJJLSgXxakBnn2ZYANezzJqMGglbo=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=ONNchaCuro9WB4ACe58yZZwGhXmY+XsazwYWioNX7ddpDy9/KhWp0JPZVffM25pwCN
         Dzz7hynQqOB8At+XM9p6UP4y7IrsF1gwH5vHQzpbcpBDm2MqOIF+hF+tdG9VhnFBlEaC
         HwOUUalj+7riPsHTUuktFYABHtfeGxdwRnnwomLh2ZHfdXtjMkOheLmsio0oRQ9/u8Yr
         JDTVN/5W/h3VTe2ob5pum2wZXRyOZmbRyJv0BquA7ECeSbZnHktXH34riUztoTkfn85V
         VwE3CJ1/h8saSh6PDu6AcdYXCWgzOUyvXlaAXo4jITEUcmLnGLn9A1JnXJ4/Bp7J8x52
         RCmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UH1qLKf+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798ac0ada77si68498585a.7.2024.06.19.17.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 40857CE22D6;
	Thu, 20 Jun 2024 00:58:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8288FC32786;
	Thu, 20 Jun 2024 00:58:25 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:25 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch added to mm-unstable branch
Message-Id: <20240620005825.8288FC32786@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=UH1qLKf+;
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
     Subject: kmsan: remove a useless assignment from kmsan_vmap_pages_range_noflush()
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch

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
Subject: kmsan: remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Wed, 19 Jun 2024 17:43:42 +0200

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL.  The right hand side of the assignment has no
side-effects.

Link: https://lkml.kernel.org/r/20240619154530.163232-8-iii@linux.ibm.com
Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 mm/kmsan/shadow.c |    1 -
 1 file changed, 1 deletion(-)

--- a/mm/kmsan/shadow.c~kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush
+++ a/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsig
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005825.8288FC32786%40smtp.kernel.org.
