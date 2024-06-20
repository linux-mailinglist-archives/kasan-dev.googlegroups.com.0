Return-Path: <kasan-dev+bncBCT4XGV33UIBBNX5ZWZQMGQETLKYOSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B6AC90FA97
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:32 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-375da994725sf3494305ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845111; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpi0Er75DxK3eiBnoa3qIXdUBYYbHo1J9IFXEXlpAvG7zmF8GCbI2V59xjoEC9FHb2
         eYYBd9/qdiFAbCjoQk8UOwNZ5dOJgvXWBIpn/BjemUvieZ6ZSdB3ULJgEQA0DcsaibsU
         3jCXh6B4bb+3qoItrfQElpkDVgkN05L4yAqi7+PpHJ9b7XRfnsPNvvDPHdbG5zICV148
         IFGisIzVF7fTdrAeZsWZeVeGxGwF16RKosCkgdnGkDZhrLtdEyiXqk2n9TtXJf+0HtIB
         4Fxo2dTfQ3O4791z4FCG1RJuoQ80LK18/o70P+n4tti5kAEOiSSL8zgo/Xz+HOLxLQae
         gHng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=yT4fxErO7RyqGwe2Dq33HvUUJFcnJiuxwm5WP2iyD4c=;
        fh=B35FlMYsFHMjZUf8LF/0V/rPgjXOnFjJQ902USsH+xw=;
        b=Wiv4D0PO1G0jThEZnAzGhiaXKCrDAWhzlIetYXfHVoFe543a6sNCA7v7N3FenjhTvu
         109Ebhg7Ne0wi8M5m3eLdGdhgiKRVYp9cjt6782qKCPN0Nt9bshiSIr91S+ajfkn0v9U
         zT/JChAEEF6FJeXwEq2d5djf2QKCCwstRA/LO0MqNhPAxfy3Yutn+02i6P0sx7BCvgEw
         E8MLzdOBeQCelwYwFEzqbsHl5mtFcX99zvQ2zq55do6bFRvkwJgdDkJeW5Z3aULVNK7u
         jD5lQfRJbqtkitjDIK6HxFsPe0HqXi61aCQqw2mWnV6c/XH8sGVABahX30qayGeJeEPm
         7vCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ENf0YHCr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845111; x=1719449911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yT4fxErO7RyqGwe2Dq33HvUUJFcnJiuxwm5WP2iyD4c=;
        b=dDXt8DjsvcfwYbFKrEHO0BJdZ0MBsGRTU/0cTv+30HH695vi4BYUXoYeLyViqDJUgu
         ND5Ou+WFbJt9RZm1PADuX+jwkKTl1YmGhLnftaCzaP7Mmlqv6BgvivtetNrwZBcEdBgK
         L3kwDIt3Yq+TToMTW+6fX5/rtNTyeINBxPkubeSq7JvnsLKEa4LlOoyArpc85rAPFhVK
         ySQRXEuGlpTxiLXHGhibKMwB82WxNGqifINKHycWNadP4H/8/c9WXzM/Fp/rKbBBJfHn
         +hcOw0NPJasj9ig+i1uRMX5DHa/N/pL5vQDG5fZk4du7yWoeOmEt6Nes7PSNkqC14v2R
         0T+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845111; x=1719449911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yT4fxErO7RyqGwe2Dq33HvUUJFcnJiuxwm5WP2iyD4c=;
        b=jz3MEJWf236xhfXXMhEQgBH0YEYApBzTf1YZ/1lk8IGbef23DOqScFy3CTvui+TsTH
         4LRrPGQ1O9Md6i9GLMU7ZlsxB9/G0rV9GmKtQlbJrUtqXjh1TwELpaSXUFOsMZC8Q6KN
         ebngrF4CcEthieyhmVMso9H3lZgr748iBgGpaJ0atsviB6U4+JnN3wI84R1+Niz2ZM/L
         QCSkRO+Atsy1/SXFnrre5vgzX32VC2IICI9olCy2W2aHl1nrsw4AAIjx8stpARSY80Rg
         mynwr+aVXddiejgn0sPLt6wHAeJLOpVI04ZoH8N7ixvmvLXtJ6Vc/NEJYCx7xOttHx8J
         8j3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVf+ZDj1J0HGo7kb6krRVGfRS1dUSYfwv4VGxZ5NOAtteHUGX8vu2u6pQAdJBmibIKEQPVPrju6lMEf/IaDj+WxNUGNZYoTjQ==
X-Gm-Message-State: AOJu0YzF3njsUqzcWtMslC0c0Ww0XNdxpDLY1m9GC7VPnBFlLMhkEcy5
	G6VO0By5xmqiucbpCVFBYPlLlDM5Fl2lQzvGOI6R/59FC6VfMrHO
X-Google-Smtp-Source: AGHT+IEyuKzazANbU7OugH3pZpHx6bYRWpRnuK/o8HFabd0iZn+fGyih3+Tg0hWy1neSzsJHn5RNyw==
X-Received: by 2002:a05:6e02:1d1c:b0:375:a180:b3d1 with SMTP id e9e14a558f8ab-3761d72b21emr45164055ab.20.1718845111085;
        Wed, 19 Jun 2024 17:58:31 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a24:b0:375:c5d4:a300 with SMTP id
 e9e14a558f8ab-3762693bdd5ls3254325ab.0.-pod-prod-08-us; Wed, 19 Jun 2024
 17:58:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXeUL3KgbYBmFS1hOY9R2DfDjsH0KqDgQLs2MtZ0jqMur1ov78RUFolnUg93cLw3L26ZYXCraHMIJyphf/nquWvqjrk8akDIlkpfg==
X-Received: by 2002:a05:6602:6d13:b0:7eb:5250:a54a with SMTP id ca18e2360f4ac-7f13edcf588mr502509639f.7.1718845110210;
        Wed, 19 Jun 2024 17:58:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845110; cv=none;
        d=google.com; s=arc-20160816;
        b=q4MxK7+f8jrNbrXxE5QWPAcH6pcIftXLdvlImwjevzLe4MKTzRaaDoK+VQhEoYSsaW
         +JwHt/PyoE6NiHTH/1gdLUxrzAJLxvo67msawT3+h+gEbvljkrrhcXU6XONeZkLh58db
         zVEtTBA3qyJxAfoi9wH6lF4bTett5fDptBgch9VWvImPMjkU9CZLn3GALmLMrRN1cGDd
         RpagOhesw/4X9S0IqLxrIamUthmyevAQ2XnZfYitGMHAVYBc8JEWz+5uM18/aH4qwDl9
         R9N4GeF1te0dH0btM6RBQ4YZwOpDcJMBNaUpd0KoutNB9/K4l7Ngo3ERrfrrC5ZexxOV
         BF8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=6afipVf3Hvd5y0P1B9zME1nbpmUT2Qz8Dw2NI5YrHcM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=JyMUg4iPNMwgWsG5cEl9vDJIhuLEGzfTy8p+MACYZD4HfAVc+JqMT1XGrpSsszY9++
         l8BGPYimFz8MI7/tzSBhErRYeOwXYX0m4hhT3CurLLEETOM6RbnxIwwbs47ZP5Yh5QL1
         mhBd/2thb3lSX7NirLBUerY7CikG7mydf10s8vOfndksYtQa6I5R/YMe7HrcXV69VfHi
         heCLHHJAlKX2VVbXtI6K9MuwCeKgiEYGiAsviycjfskWM/O67LiR2Weioki7SoNoZcqX
         MG6+RY5PWEx4Bja5dTSvXLBYA9mUiRNHslPkjjCXnXeixVWCeatPlV4iXnoLDSostamq
         1B0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ENf0YHCr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9581ffbe5si725652173.0.2024.06.19.17.58.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BBB616205B;
	Thu, 20 Jun 2024 00:58:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 615A6C2BBFC;
	Thu, 20 Jun 2024 00:58:29 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:28 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-expose-kmsan_get_metadata.patch added to mm-unstable branch
Message-Id: <20240620005829.615A6C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ENf0YHCr;
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
     Subject: kmsan: expose kmsan_get_metadata()
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-expose-kmsan_get_metadata.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-expose-kmsan_get_metadata.patch

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
Subject: kmsan: expose kmsan_get_metadata()
Date: Wed, 19 Jun 2024 17:43:44 +0200

Each s390 CPU has lowcore pages associated with it.  Each CPU sees its own
lowcore at virtual address 0 through a hardware mechanism called
prefixing.  Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to resolve
metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the arch
code.

Link: https://lkml.kernel.org/r/20240619154530.163232-10-iii@linux.ibm.com
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

 include/linux/kmsan.h      |    9 +++++++++
 mm/kmsan/instrumentation.c |    1 +
 mm/kmsan/kmsan.h           |    1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

--- a/include/linux/kmsan.h~kmsan-expose-kmsan_get_metadata
+++ a/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
--- a/mm/kmsan/instrumentation.c~kmsan-expose-kmsan_get_metadata
+++ a/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
--- a/mm/kmsan/kmsan.h~kmsan-expose-kmsan_get_metadata
+++ a/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005829.615A6C2BBFC%40smtp.kernel.org.
