Return-Path: <kasan-dev+bncBCT4XGV33UIBBMP5ZWZQMGQERVPXSUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 577C890FA93
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:27 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5bfad6bf464sf364329eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845106; cv=pass;
        d=google.com; s=arc-20160816;
        b=BeB7m9cLz+N2I9xfWmDHNgao7+jOlufVOFZIbOkmMxbS7UmEYiu9DUZrIDKHRi8nKS
         0lYdHobs10YPUowZiM4FJO4bEg7bujMgIIrC75MtyS3CpbjdKR/IsD/+fVzVtlgv7s3s
         1napG9uop/otpnjerC01UbodCQcA19Ez5WK/Wp5BqFHO1q1RONuYMKuVca6gvtQfbYkt
         o3PrJp3KEFV+6JnO2L0vYb2dA0CEPJzyaQOab8x+uYtQtGs8d173V8bHdj+xWjujkrjC
         6YXFp/7guf+VGvuuR0OsXdgP8LSWFNU5YHLr8kDZB8rA1kxDL5d6rNkItc/qup4JANA5
         xbsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=/4VZyXrII6xQ+xK9BtNC9N8e9fee0utfjT1fZcj2Tdo=;
        fh=vogqJzIIC9Zjaq0MZbdShkZqq9UihaGt4JXDiB6ZYSE=;
        b=YbL71lg0pj9u93lDaKwjE1qYgsxuTwrI8uOynpciKlhKzc2H0ai3vQFd6Iyb5q7GeL
         LyiHkZYAD3TGoyvwiPVuTbV+7I+ROeo5DIoxJzHsWIiecXGj9OoI/c6NyYsbQdA//mlo
         lyBVoLF7tZVG7aaB45DIlYX+nC/vehu/2k257xDHvg5K1Qr9sjEb8cUkmpYRFHUuQODZ
         hh6YlpJwOF03g2cdBL7KdodONyYVPdwrj6w3FFMnZRfXLng70drneQNckec4jBcpZ3hB
         MnrW8C8fhrqGH9W9pfcWAifyJX0a7Zsk50hfk9DToQUCM6qdMQbOflft+t9bT/pKskJq
         2hxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vwa3TDcC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845106; x=1719449906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/4VZyXrII6xQ+xK9BtNC9N8e9fee0utfjT1fZcj2Tdo=;
        b=sEU8klMcGX4e+RAQGWCMqKjIt953V70AKXga/AA9cQeDUQ0jlfEx7f9xYBevGqfyI3
         z82R/UVTz7Nnb9iUbittG8TejcGX4p32pkjX6iL3uRynqSW3PDdDjWKzf2Unaw6n4GcG
         spfmN7AkBItQddiue5kIFakjSnVjVrgL0mUQt130l3o6yhLHPRsRYqxfUXJqPW9as8Sm
         0vgogzNjIk9k+moxiChznDhCBHNidtIViCqmuyMD4D2dF+MzwADLS2+pvLIXm0GhYn6y
         qmdo+GCZ8KUvur9F1rJFWoU0u+w4qkr4daTAlni0AwiUHDr3XlpHeHxTJdJC2b50HiZk
         Se0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845106; x=1719449906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/4VZyXrII6xQ+xK9BtNC9N8e9fee0utfjT1fZcj2Tdo=;
        b=DFQC207HdzI2ylYPlCxRFADN8ddrJQm89vRIK2uLeux5VMoG1gJRRwMg3L1ixVQyKN
         yGGXHPHpBGC9aJtpxgxqXiwJPr1d2p9Y+9JKfrAQ9azKD+/KtHTz5CwVl9qGW17A+rFN
         BMBkMgcylz0PIad5dc4Fa8WrIDyYBZb3bK0N2gTxOEBtIrUkA4ML5wd9IpA8S1poiWX3
         4yIZXJxxBJodho9bV9lzD9tnWKT+/pT3y1yYy2h0sLrDzQxjqQvJuoECL9BvBz+vRxpj
         eMFKZZvLfP9lwRCrNf04GBvI+x9Qj50/LXg+Vgk6x0u1eYmFMO2qVCYsoc+Z++wpewSm
         VgBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo8Hhgfrb5Tc90MJNka97A7XT7fk4JmfXoW9bz70bwzBrg9UWque0VmbCYkU4rotcdQhENqO9lrpkeEoHv2cKS6jNugHoxmg==
X-Gm-Message-State: AOJu0YwZ5wsuQkXfkhRoupVO/meFudKHIr9osNjOIRB6QcTl8xiee8H4
	u015kCezwDm1UGFGrNE0ksMtEJDB4g86nj3zeF/3ovu8jcMNs3v3
X-Google-Smtp-Source: AGHT+IGmF+PFh0KgmnU9haIdTgRQEvTaIdWcddRINNOnGJlZA9vGCgllqVUIRMFTe4ETZhSD5rcxnQ==
X-Received: by 2002:a4a:3006:0:b0:5bd:15fc:8ff3 with SMTP id 006d021491bc7-5c1adbfa8dfmr4605530eaf.8.1718845106062;
        Wed, 19 Jun 2024 17:58:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8604:0:b0:5aa:18dc:5145 with SMTP id 006d021491bc7-5c1bfcee75bls308619eaf.0.-pod-prod-04-us;
 Wed, 19 Jun 2024 17:58:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV63GnejVCjKmkQg67Whh+NvI8kHxp9lfRESfVGfp/WXIFZ5eGitFc0pJh6lQNzUibJu6xzRR1xI6Nr66esN4DeQOEO7iIjZO7OIw==
X-Received: by 2002:a54:4098:0:b0:3d2:23b6:de9e with SMTP id 5614622812f47-3d51bb13a4emr3545837b6e.58.1718845105111;
        Wed, 19 Jun 2024 17:58:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845105; cv=none;
        d=google.com; s=arc-20160816;
        b=oNIrtYChcYnnarVOta2mPOpEmSEdNe0S/roxJ1A4VIIFiR2AcWq5CQk7aMxt95+/3Z
         svT7S68gmydlGxDxSbsd4p/DCY19dazKk2hNX78r43Psobtxy06kS1UWbcbJtJ+OtGM2
         FJ81yCIWgsObOgD6ll3wC4UWXSFSkZ0bPv2Xbba73eGyVc2aZT6BosMq9hNC2cuDPipG
         z14hRluqBURWse39DgZynIMVFlfzWpzKDDDCPp7TePWkOquDOrjf0lrUBjTqtlPa5VNf
         d4lyb6HN2zj1PXmEkU384ftZgmf/ANwyWL+UHkiYb5kGdCYeK9ymZ2sOTzeLeQyEXkzG
         zpZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=cckP9mWO0cMJMYO4406JX0nqnvYkRKSfL0VoX/UPLyg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=K2rWa3fEBj4lFmMFbcDNgfATmxJI02Cibt3RaPR7Bjx6eGMyGhCcXSnPrZXaDCSfTB
         0tCMliAfUGd6svF/iLjar41jG1fxUvSbnQiu0HErDSd3RWlSoG7JZFQS9aev5nLV2b6w
         EXSSY8ppLZIKn/K+WEKeTEh0QGJzkANGxFoyN1Ak2PJk2vq0BIiqtxOiqSIkax2E7nMZ
         FxCDo8Ua7H0+QWp9mKx9Owuily2KMZhQx/UhRYw8MfuZo4oDscBynukUTvw7Fs8K36aN
         ywzi49xjXDrEnpc1C3OwyUoLG4CvmIgH5M0RiErshUF7a9DdEsdxJw4OA/bl0ZmDO/YK
         Hpkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vwa3TDcC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2477c736csi672937b6e.5.2024.06.19.17.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 4C75ECE22DA;
	Thu, 20 Jun 2024 00:58:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8F1A7C2BBFC;
	Thu, 20 Jun 2024 00:58:21 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:21 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch added to mm-unstable branch
Message-Id: <20240620005821.8F1A7C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=vwa3TDcC;
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
     Subject: kmsan: fix is_bad_asm_addr() on arches with overlapping address spaces
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch

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
Subject: kmsan: fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Wed, 19 Jun 2024 17:43:40 +0200

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap.  Skip the comparison when this is the case.

Link: https://lkml.kernel.org/r/20240619154530.163232-6-iii@linux.ibm.com
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

 mm/kmsan/instrumentation.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

--- a/mm/kmsan/instrumentation.c~kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces
+++ a/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005821.8F1A7C2BBFC%40smtp.kernel.org.
