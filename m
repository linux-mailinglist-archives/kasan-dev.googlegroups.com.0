Return-Path: <kasan-dev+bncBCT4XGV33UIBB4H5ZWZQMGQEAKXLCNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id F1B1A90FAB0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:29 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5bad2fe768bsf334521eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845169; cv=pass;
        d=google.com; s=arc-20160816;
        b=RGhkarmmN02ga903SC8gwvvfB5rYmMDC5zNHK7bSzmIFELkrL7N8rugT7uPLbdioZF
         I/8Q3Q3cd0gybO5/OLWW9gzxtFyNOo1hYrYNWmDW/jjtBHCTdujJ1GV0rKlhwdJFhirV
         m6AJPH9PMRRIIWIEI9bzgT/8qA3WTgeR42Kvn6ug+8V3TyHdM0PvWw11XtrgqDtoi1xb
         hfhsOkQ2xyxO/EGgrKafWdtLWruBomkLhGz9IxVjamFowXygDLEYzxcUSNzU7lJL/WHE
         LSX8glLS0BaP76XL9yb+RRvklsPiLVmKjqPZiZqfO+YAAB23VHsnmo5U++Xw6mnCuNsV
         uibQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=0e6hoDi2nP8KUqGX3rNpp1CvIIILtd6/M56rDSQsvnc=;
        fh=a8ZgooF+trEHe0HwIKdJx59jHtDrlpOT0qJgtMZgrwY=;
        b=N52YLLVnaq0KkIXA3ylrr714B61cUxzCsqJg3y0X/bLfe7Mbb/Ci1tb/QHRLCfIrac
         BFEHjpUjjXawR9a4mIfHcPQZEkWKMJ/iSmyL6ExNCMhPpSS2VQ057GWk10qZf51k1Lam
         mKMO61KbGu5KDDXd/rQM+xyNA8aWRT6msl32pHTRLC1dAfmcOE9i0NqtDsNG4770+WXM
         RKqDPYFzQrlHfNeu5lU2xWS9YRHhYs55expmA/76HGKpgI96BAfzCwlrtrvhMm39lqq/
         fA7PtWaEC8H/4UcmDsDi1vDQKn8ui0XkWwIqOh04vLlXoerEPjP2jEaN96GdehNuEfc6
         l6Ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="uv/DHq0Q";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845169; x=1719449969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0e6hoDi2nP8KUqGX3rNpp1CvIIILtd6/M56rDSQsvnc=;
        b=ftvVCjYfjOizD+dzw3wc5oRCCqi/RoLf5bGuF43GdUm791q68sfy9nvURhpcXd42LJ
         dBmMwk+L8U5iHxzpu4n9Sf1krHHysDhluQVgXKTU2VrGNgO+p9ZodJyTh8RXxcm98ndw
         KtgghK8D+xZKGRO8hOXf8j0gQnh3HlXAB3CeCa0lyvAULuoqBJ624JKSuu+Jv72z/Qb9
         bYOaokgM/+gGiXjjvX8JZ2KIw4tNQCOf+Fl8gZaKAI5jyOxHsVcwq1kcALxS946Kfjnb
         M8RQxCTsCNV4EyP4H8v14OoJDwfuPUdIqUBQRbVmfQtt3L/2W0Qf3W0DXYKxVXYdKC6F
         sYPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845169; x=1719449969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0e6hoDi2nP8KUqGX3rNpp1CvIIILtd6/M56rDSQsvnc=;
        b=etRpb9RtgqKolLYZmzSZbiJZg7K8GSKwQc+0jBqP8DZKQQ9Ps63XhOFNCXlAoNvNYZ
         KLEgaOleQwGXamnpmx9Y6CWZltpsdeCDs8nTVqL4+ZuF1W8bvT3vPlOb9faXroUgA0Sl
         q0O8hqeXgfcD+9GVQN/Kx73tOkQ/q/IwvJDtvDVvv81YGe/YICWkOnBLFk6r3zjg7et6
         3j2S87cv3EsQttgRUKuQooE4YkdZmal/0MjIJThejvla4kY8Y2FUQqvj3fv4Qph/eNB5
         IVJBLcbA1ExzdYFmWyR6fXS1k0IHIo/e+9dTOOH3K5+3nEToLoILE17FX6UAgMKm8fOZ
         Vl7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/sGPT/ytx4cRuEp1kR6UlVKzvLei9tjLrsHItMpMMEX16uIybBQgKS4+LFitHMt4oLl8hAEE3Hkdyb0nArFRglhPa2Nv/Hw==
X-Gm-Message-State: AOJu0YwPfCW3gfeq0REpEcsJ1Xcz7JliPTnNRGX48OB3ID0lcaXoxxHE
	7x8bd1rimfyHx6JdKLIa1iHLTfAkrkuOzJG3veb5GgdwxP1lwIkd
X-Google-Smtp-Source: AGHT+IFbckOFE9eGFdDto5fGtfPV6Rh24Hr8VCGT2y0L1obJwGlasBeTQOYPuA2F8uguBcHTYOOKJg==
X-Received: by 2002:a4a:d285:0:b0:5bd:c0a2:c349 with SMTP id 006d021491bc7-5c1adbeae27mr4642391eaf.4.1718845168819;
        Wed, 19 Jun 2024 17:59:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2541:0:b0:5ba:8d10:758 with SMTP id 006d021491bc7-5c1bfd9c11cls266390eaf.0.-pod-prod-01-us;
 Wed, 19 Jun 2024 17:59:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPRCBo9kFB5PTfhUVUc3TX0QEGFMUebKTYMGLObwP4CPDRTHVuuloL+vMVgk2mX3HXkKAtgmqNrhfBatq2lqw0R31lVnK8lUU1mQ==
X-Received: by 2002:a05:6808:18a8:b0:3d2:226e:2fb7 with SMTP id 5614622812f47-3d51b98d973mr4578625b6e.10.1718845167703;
        Wed, 19 Jun 2024 17:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845167; cv=none;
        d=google.com; s=arc-20160816;
        b=NUW4l/Q8C0ozmvZDF7hpYUMR949kEIM743ZEd2HMuzGzd76NrzleULvBgQb80fRzoc
         EB6U+5SjU3PrYPtgL5xVScn/ZfwPOZMyy4IzvZ4TR6wPJILQcjdFtK/r4/BKuDy/yUTh
         8meG6GSzf2JesX15boqgf91fel8yisF+d9OK/LtCZsJimNUIZYAgEYRdKUJIUiMz5knp
         a3RYMUWHdgu50EfkrRtCJcLt6o8KEQ5lQKnMffD+JH5G8hHx+bklO8xUVUYkNd5TYQbe
         nyiQfj7na0prUv+8wNApv8rBEvB0XX4OxZ4Hn9JpleBVRCE2imldY/X+op/1ZDdem6R9
         KjBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=7XlDySY0bT6sJ1nP2b/H6h9SCksGsEtI/Xd3it0Lyv4=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=w+tl1Zdng9zBpNejskCZvE67d74v0lYhTfoSjzDJStExO3D0VXmVFOVvccyhlpvv1O
         CFj/kBI+dWnA+/GBVXv/Xe2RAifPRM/f6ZWFrQv9SWlqtAYcRfZFNM2Ejrqj5BoY0rkQ
         SLXZepwIrh+SirdjhRiGM+wn0tAsEG0WuJqxthUG5bCV0/yjllzKiDu4ZVE6mry3gWQE
         mMtsqomAJQgg5X1iLBvTFshkBUByu7meZx7Pw/Uu9pmlzN3V8U+JLRmSrUZn0Rx3tqDT
         u7uIdAxEezEyQ96IVSeQKt+k3+enGlQCPIsLdwdviXvXO00L0WifoTJnqhQ5kAplf8cG
         HY3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="uv/DHq0Q";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbdb4d1si685843b3a.6.2024.06.19.17.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0B01062068;
	Thu, 20 Jun 2024 00:59:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4CFCC2BBFC;
	Thu, 20 Jun 2024 00:59:26 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:26 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-unwind-disable-kmsan-checks.patch added to mm-unstable branch
Message-Id: <20240620005926.A4CFCC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="uv/DHq0Q";
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
     Subject: s390/unwind: disable KMSAN checks
has been added to the -mm mm-unstable branch.  Its filename is
     s390-unwind-disable-kmsan-checks.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-unwind-disable-kmsan-checks.patch

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
Subject: s390/unwind: disable KMSAN checks
Date: Wed, 19 Jun 2024 17:44:10 +0200

The unwind code can read uninitialized frames.  Furthermore, even in the
good case, KMSAN does not emit shadow for backchains.  Therefore disable
it for the unwinding functions.

Link: https://lkml.kernel.org/r/20240619154530.163232-36-iii@linux.ibm.com
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

 arch/s390/kernel/unwind_bc.c |    4 ++++
 1 file changed, 4 insertions(+)

--- a/arch/s390/kernel/unwind_bc.c~s390-unwind-disable-kmsan-checks
+++ a/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(stru
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ out_stop:
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005926.A4CFCC2BBFC%40smtp.kernel.org.
