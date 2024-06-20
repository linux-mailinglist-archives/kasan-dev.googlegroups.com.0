Return-Path: <kasan-dev+bncBCT4XGV33UIBBQP5ZWZQMGQEG5FS4NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F7A90FA9B
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:43 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-375dada31b4sf333565ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845122; cv=pass;
        d=google.com; s=arc-20160816;
        b=YIq9ZGS3CZtjwKiqXJ32bX7yqm2xSrc3zSk2ZDdr1jMTlTraSC49+WhcGbxvF8tbE0
         CpW6964KFD66XQW1f78Kdiy3sw89INvul3rieQobirES5V8ZzEQy6QVT3pCF+Vl3xxzF
         /TOktubBmLyn1JX0Qgm/z/El4O2GTDC1R3WfL34Cm9YM63OP1lLuoE+bEPotlhcqNx8r
         8dIPhuLXLhWxe1GtyjCVzDOJO2kW4f1oM/ZPpy8rAm1O/GUVuFO7dYFKtvqjROToAWDt
         zb52X1rTTS3fmokZN+pYnCRN/YqQJVE26IS7UE/ge9+8wWJAnskYNw6rDIhLViGhr+as
         WkYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=kaBUvs3fZR5qMaDxCYA/wQRa8eXy8EgJLS48MOtnTZ4=;
        fh=4J2F70N8dnMVkdVFyyI2iOzfyh5lyxyxvSvjLd+HW0M=;
        b=p86gQF2W8HVneRrOEkMsgMXrxr6d5+bA3WvLH8wDrPamvoMHHCcvzhOWgnZC/7dHnh
         iIUNVVM1KGTd+QX0Njt+Kzyya5hSLjn/R+vaESfISuP7VK9YbNZgCsdmNT1eViQ564Rg
         d3kS8Qd3NzOoOIRRjriXy/PrOMHkr6bMPJk1AUfqsQGnbJTMZL9Z2yUh1xHkv1CWea9/
         hJpMGLbO67fAqSt8T+SZdUZ7LjpXPhzZTU8kUpH2RaymzE3osVjF9ndwZQBbreClQ/9k
         4RtxaS2hrghAFq/0DB8I0WKgh8EybTSHC01u0k1EF3xgNjz/diuI2Z/wNEuzCN60stvX
         0YPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Q2awJkMf;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845122; x=1719449922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kaBUvs3fZR5qMaDxCYA/wQRa8eXy8EgJLS48MOtnTZ4=;
        b=FwcOUjzKY1U1XVKTTYOZ+flmgJ/OFJ/MuLDv+3QIivc5/ycKc20lyRPlbJaC6veNdX
         BZNf3vnMvBUS+5Zt4jxgx/WKMDdBCJwpfwqOPDN5k6jJ5XuSOh7Rzvt9Nl5Po57eu1WL
         j8Cl0U/eRHI7mZBfZznb07g4lDuzC41rTflvm5ILOUEJu63U+N1JHdwJbkza4gB2nC+C
         eAIpaTs7/lwglnOOFA8ZJgH6cogq4O3isOY++B5sN1AW4duWrebm8R3gQD/W518iD+jC
         pHLKTtCJl6GijyAVl0ziEho+WJwc+FE9nDE5BCydzWuRl9lg++LIbq5NP5FhA5XQfcqN
         pzSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845122; x=1719449922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kaBUvs3fZR5qMaDxCYA/wQRa8eXy8EgJLS48MOtnTZ4=;
        b=epuMzu4DFQYs3/nTXHnFlHo4l1tTtAKM911Yi0ZKFge6SHvN+Sb6hRJFcwSLMvTf4l
         uBreAAZfIwegZRLYaxu3xfMK9ebwKa48P9C+Su4qr/AI0+dzIUgk4AoZteKjQe5Cv2zM
         gDkTh/IRFYCoN+asQP+OlayVYHFbWiWi3wphAFnvGho9PF2n6FUFtBa/nKs8VbkqA3hm
         dJwsoXIsB0iDay3noq2mSIcN7j8FEkZXqOclLi+B/jnzqiS91jjwQPTenQyf9t8nygoG
         cuEo/yLXolXZIxrUnyvPqxbuQBtlt7dhU+RgptFTKPXuOxXMaL2RkdT/nvuoBp2lFQJs
         Rl4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTN1JJIBKO4e3zIrqSClAwWdj0+r3EtAgkBniSuR4zAz51XRZ1/1rtClE8tq/iCTGnYsZ20nHZ0OjTsvSi6pVhX8QubNRyTg==
X-Gm-Message-State: AOJu0Yxru5F3uoaEh73OHZSt67YhAiTPlSHXdo89uREG+nzc9+k/KPHW
	R+hsxsgaftllmYKno8MSAa/+npXdQTNPQUjSPM6sqkAnZj6KnCk7
X-Google-Smtp-Source: AGHT+IFSvKazCHXXWXOkuYKzGA6Q6+eyoYur8YpAaKf1nz1tEw2fdnG9XAC9+kuPLMwXLKddOe7zZA==
X-Received: by 2002:a92:c846:0:b0:375:aec4:eaa8 with SMTP id e9e14a558f8ab-3761e68744amr3847165ab.8.1718845121805;
        Wed, 19 Jun 2024 17:58:41 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1feb:b0:375:af6a:e6ec with SMTP id
 e9e14a558f8ab-3762693b4f5ls2874115ab.0.-pod-prod-05-us; Wed, 19 Jun 2024
 17:58:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3OwZ0nLC89tpYpys3/s6oPJ/dsgfkRVV0phbtctzgfVCa1lrv8ZQohsfT7EzpGXjOYIWFi93d2hMQBK9hltSzK042OjtVySxT7w==
X-Received: by 2002:a05:6602:2dd1:b0:7eb:771c:4021 with SMTP id ca18e2360f4ac-7f13ee2435bmr468115339f.12.1718845120844;
        Wed, 19 Jun 2024 17:58:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845120; cv=none;
        d=google.com; s=arc-20160816;
        b=OHBlB/DP6NNhDeDKLWR4bueYQAawW7OeLz7fy+xRg+hWBLom/fCmhCjc2MMYFN1R3W
         XQPVB0ozIV1EXixNpiQMpYauxnUlPC92oWOkKUb4asjVi3kTZxjRn8C/P1etx7kHSjIM
         PI28+8RyIC6bV6yQFphXiXi8DQOM1NlDcchy339+IslwGknHfJXpYzCPVAfvgjCl7f2p
         Y7oOMmV9qMvvS4/nW/G3702uqWl5iOxYhkQJw8w53JbFS3pKsn5a/vFRo52hKfXZ+uLK
         /acZ+u0kc2+mBxjAigmhlEhPZ7w/G8/TcAhPJTd5z/6VbnMxJhkBITJ206xfXxsxCdEs
         /pqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=qJTsljMp7NJR5X+rBQqs+vyXK8pw8ZV/agvz4bu5oqI=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=jC2OTuih3Uvk83SpUG9eyoxIvaqyzBE3vqEErXihXoZiJk6OvvCvmLzmW2AWQ5oiSV
         s1Qif5Dby1tY1bImnqwfqD940VtLvAiJe9b7J40boWyo4qeCYSAdbwqizNkFT4dF3RFL
         3FlaEfSyKsDWEMonaXyd6H+oYWoqjmrXxydfjYpXm/YC7yga4GUghbv9Qi5vGueviFsI
         aXGVg6sSbl8+JUBoX0xg+44m2To9JQo8HIXNzAPs7CQHkxcn6kD2xT8fjeZCbYhs6Efm
         ML13Abbi9yDVvuWGUOmO7+z9eFJvzXsfhjEaKu3Jmt2U6El8sbZ+bha86g/YZapqhvM1
         8vWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Q2awJkMf;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdb75e03asi63433639f.0.2024.06.19.17.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7BC0A62064;
	Thu, 20 Jun 2024 00:58:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2276FC2BBFC;
	Thu, 20 Jun 2024 00:58:40 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:39 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-support-slab_poison.patch added to mm-unstable branch
Message-Id: <20240620005840.2276FC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Q2awJkMf;
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
     Subject: kmsan: support SLAB_POISON
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-support-slab_poison.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-support-slab_poison.patch

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
Subject: kmsan: support SLAB_POISON
Date: Wed, 19 Jun 2024 17:43:48 +0200

Avoid false KMSAN negatives with SLUB_DEBUG by allowing kmsan_slab_free()
to poison the freed memory, and by preventing init_object() from
unpoisoning new allocations by using __memset().

There are two alternatives to this approach.  First, init_object() can be
marked with __no_sanitize_memory.  This annotation should be used with
great care, because it drops all instrumentation from the function, and
any shadow writes will be lost.  Even though this is not a concern with
the current init_object() implementation, this may change in the future.

Second, kmsan_poison_memory() calls may be added after memset() calls. 
The downside is that init_object() is called from free_debug_processing(),
in which case poisoning will erase the distinction between simply
uninitialized memory and UAF.

Link: https://lkml.kernel.org/r/20240619154530.163232-14-iii@linux.ibm.com
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

 mm/kmsan/hooks.c |    2 +-
 mm/slub.c        |   15 +++++++++++----
 2 files changed, 12 insertions(+), 5 deletions(-)

--- a/mm/kmsan/hooks.c~kmsan-support-slab_poison
+++ a/mm/kmsan/hooks.c
@@ -74,7 +74,7 @@ void kmsan_slab_free(struct kmem_cache *
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
--- a/mm/slub.c~kmsan-support-slab_poison
+++ a/mm/slub.c
@@ -1139,7 +1139,13 @@ static void init_object(struct kmem_cach
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		/*
+		 * Here and below, avoid overwriting the KMSAN shadow. Keeping
+		 * the shadow makes it possible to distinguish uninit-value
+		 * from use-after-free.
+		 */
+		memset_no_sanitize_memory(p - s->red_left_pad, val,
+					  s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1152,12 +1158,13 @@ static void init_object(struct kmem_cach
 	}
 
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, poison_size - 1);
-		p[poison_size - 1] = POISON_END;
+		memset_no_sanitize_memory(p, POISON_FREE, poison_size - 1);
+		memset_no_sanitize_memory(p + poison_size - 1, POISON_END, 1);
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + poison_size, val, s->inuse - poison_size);
+		memset_no_sanitize_memory(p + poison_size, val,
+					  s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005840.2276FC2BBFC%40smtp.kernel.org.
