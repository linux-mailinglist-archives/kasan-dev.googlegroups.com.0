Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB2U35CSQMGQEWFWQODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B8F4B75BD7B
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 06:47:39 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-635e6c83cf0sf19398796d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 21:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689914858; cv=pass;
        d=google.com; s=arc-20160816;
        b=jKd38X8EVxfLzmK5xWWnYRIwGFGxFqmQ1bE/cfddaNjzhd85pewAO70VXqALLKTuBs
         H+F+mBEzobaXgWb/iyrtJrBC7uXYyBXAvuup1Xr6y6c7Xc0IHv51Xt3ck//k8DEx5I0G
         /zqxHSRPmy5e2Yj24gtoXY9RHIIpvMfoHTi6nwHkUojGexZmGrwWcZCcd/3olKhJJXOE
         9luao7QK71L93s95KQ5DEO0ml545yFqafKyJ+43MtendBnrxDGxdVexK8mjWi48kufh0
         aKKNO/68YDEum2Mut2hupv2O1hOMzjh7RjyCDoMYbg3MUeRj3Ul54eWR/8SvCIdxfrSE
         WPig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=He7MGQWdDJBJrqeIpMfRVQiS0+7OG5r3iqRPJF7Ugdc=;
        fh=I3jawtxdOKE+DAnVtmfMFnY7h2erJmqxbEnAOy9ksnQ=;
        b=AXdlBbFIsJVs/SK6gF9szRUsu+1Nh11FuUZT0L3s9ODwKKRDx4y20DYuUYt4vEvxEf
         WfJX+u8uRkX5SDL9o1WIJcPR+6tpwd41RSDaaCQhaDKciC5mz3DEx+jWT1LXwzM0f648
         PqpXjPpIfI3Xo4GBxwfUC/H4+PX7s/TXfN/s5rVk5Y0pmQ8YXj81VtsqJ6ZcrDO1yLFQ
         7CUQoGbCzCY0msfD06BZLojCqGTG1mgOOfInts/rmqAZPjNNZenYwEGtT6BBx/vDdPOP
         Qh/VlTHU+hor+g9DG92lfz+5j8xSG0A2VZEePphbxrKneJFtJXKJ+ScB5MY4es37Urlc
         oiLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=wfjVMYsq;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689914858; x=1690519658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:from:cc:to:subject
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=He7MGQWdDJBJrqeIpMfRVQiS0+7OG5r3iqRPJF7Ugdc=;
        b=D6n8BZLrIABOUs0Ce23x6ai9UHYTQdoeRHXYFilkigCyFtaj/iSCc3v3orS1evifRu
         9O4bOsqgtK+aaGR9dpnYRpfjoAaGh/4i96trqYeIuQY2PLi/AOomEyMGrRO2ZCyIEx0O
         zLyBZ45/XsaJH73ESby8GfVCavG6V0bfLZ3nkUbpzbWJuK0YjhkX3YlSNCaP202frpfD
         cvb6RCxkPeKJd+UEuo2OHT3HpLSGKm3oIUFm+y++6Y5TRZkCi7i+YXEzc8fJcGUvIe9M
         XvSJUFsP0/8WGAx4vScOY6Ci4OH+wElAxY6+JnFyQKjxctLCOk7T/n2bej8DAqOTAhc5
         oyjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689914858; x=1690519658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:from:cc:to:subject:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=He7MGQWdDJBJrqeIpMfRVQiS0+7OG5r3iqRPJF7Ugdc=;
        b=bamlkB36uaZTG9+UhplDzBhAuuRv61FGsOXW46rbQ/uGZfM2a5pOvrVqbKtwUeo59e
         PGxeGNet7pr/XcZENIMa9s3rMRL/DAzlXh0EF+LInuef9iMrIzOLv9DSImppREBc31ce
         7a9ud9nTwK5e54FoSl9B1mpWFEvwT7SUCI8sz3fEilu5OLJEZ9E9bjoiogNDR3u1/Fpu
         naRqF/3AfQEPMPKUdgVjg0zIUz+vs9mi/iiTnK7daoJ9Nn/rnjNQdChVylSWvxKZLlgb
         T1oh7DTmptoTlF1HRN25uix8z7vLnDE6rZLyr9ap1egI3IjGoYUN74Z7z176URBApD/E
         XuGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZsbwv59zTvt/s8l4RgKosCgX09j9LQ3Jlg+hS825L/ik+XE7L5
	knhdfvlnGzvpknMkbLVVz8g=
X-Google-Smtp-Source: APBJJlGXUMvoK0SXNsahAWUoGqj3rYVLgWaNOyXk/CuJdC/0+OYvk68fNdRsncmQWkosqG0JO6h5tQ==
X-Received: by 2002:a0c:f652:0:b0:635:e113:a0ff with SMTP id s18-20020a0cf652000000b00635e113a0ffmr986582qvm.30.1689914858419;
        Thu, 20 Jul 2023 21:47:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aa17:0:b0:62d:f315:97a9 with SMTP id d23-20020a0caa17000000b0062df31597a9ls1302840qvb.1.-pod-prod-02-us;
 Thu, 20 Jul 2023 21:47:37 -0700 (PDT)
X-Received: by 2002:ac8:5ad0:0:b0:403:b6bf:ee50 with SMTP id d16-20020ac85ad0000000b00403b6bfee50mr1345957qtd.14.1689914857598;
        Thu, 20 Jul 2023 21:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689914857; cv=none;
        d=google.com; s=arc-20160816;
        b=uRJAoRtMhxENe1cp/qiTGkt0IQdFBo3DAngCLNVkDxSRu20cGL4dNOPshA7fbcSmkW
         OSl9a2xN45nR3lWWUg7SRcNuJ7G65+AZUSCpySpclZqy/xfRqHVM20Q3OIzV7dju/Rd3
         Hr9QtJN3AbQT2ljOl3mTRe5lUn/wbC+Rce+eT5cAfRc4UZ9Bs9bCvqsqWvOdmoh/THQh
         iw4KUu7UOtQwUWbP9LQu97nmMGTHLRA9q0P/vtvQCwqM0eCSnNuOLtnC/hJPwwyuRoKi
         MBh8QxvkOfTPW7rAQ2SokavdXXnBwOaaIH9B1ylsxnDVaYwJqTJFn7l8Db+N6UjhqjS9
         Q8xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=Rkekmvls4yofjivbvxqx5E70zMdWBLiGsv2MXr06VNU=;
        fh=I3jawtxdOKE+DAnVtmfMFnY7h2erJmqxbEnAOy9ksnQ=;
        b=ebwCV6Ea/uzs2DkWVn16fEVit10H2xDS9Nmorg5gq1jBEz8wx4IH55rf020swMVFa2
         7aNTt6KV/4zg+JS1UJHmoxokMRm05UMKE3uEKIf1k9JN9XzFRiC6gZy19RLufcCrKlGD
         Q2mCZVJa7fGCBwIZ5YMwXAsA1fEHZWJw0AL5TVma5lMlZncbE7QrK3qGsyGVTBQj4VfV
         tUut8LknnHioyzUZxJzLdID7LT8jFIc89mZThQcz+t9NGrNdHKZ8a1sezzooptd1U4DM
         m63RdU16qrNo1mOuD/Mva1N+7AfEIAKwMTB80TomNthtKxrsKmIAUobYdujRZkb1GAcy
         9QcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=wfjVMYsq;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ez13-20020a05622a4c8d00b0040388ea9a6dsi194014qtb.2.2023.07.20.21.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Jul 2023 21:47:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 175086108F;
	Fri, 21 Jul 2023 04:47:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DD908C433C9;
	Fri, 21 Jul 2023 04:47:35 +0000 (UTC)
Subject: Patch "kasan, slub: fix HW_TAGS zeroing with slub_debug" has been added to the 6.4-stable tree
To: 42.hyeyoo@gmail.com,akpm@linux-foundation.org,andreyknvl@google.com,catalin.marinas@arm.com,cl@linux.com,dvyukov@google.com,elver@google.com,feng.tang@intel.com,glider@google.com,gregkh@linuxfoundation.org,iamjoonsoo.kim@lge.com,kasan-dev@googlegroups.com,mark.rutland@arm.com,pcc@google.com,penberg@kernel.org,rientjes@google.com,roman.gushchin@linux.dev,ryabinin.a.a@gmail.com,vbabka@suse.cz,vincenzo.frascino@arm.com,will@kernel.org
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Fri, 21 Jul 2023 06:45:53 +0200
Message-ID: <2023072152-galore-apron-cd97@gregkh>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=wfjVMYsq;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    kasan, slub: fix HW_TAGS zeroing with slub_debug

to the 6.4-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     kasan-slub-fix-hw_tags-zeroing-with-slub_debug.patch
and it can be found in the queue-6.4 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From fdb54d96600aafe45951f549866cd6fc1af59954 Mon Sep 17 00:00:00 2001
From: Andrey Konovalov <andreyknvl@google.com>
Date: Wed, 5 Jul 2023 14:44:02 +0200
Subject: kasan, slub: fix HW_TAGS zeroing with slub_debug

From: Andrey Konovalov <andreyknvl@google.com>

commit fdb54d96600aafe45951f549866cd6fc1af59954 upstream.

Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
kmalloc space than requested") added precise kmalloc redzone poisoning to
the slub_debug functionality.

However, this commit didn't account for HW_TAGS KASAN fully initializing
the object via its built-in memory initialization feature.  Even though
HW_TAGS KASAN memory initialization contains special memory initialization
handling for when slub_debug is enabled, it does not account for in-object
slub_debug redzones.  As a result, HW_TAGS KASAN can overwrite these
redzones and cause false-positive slub_debug reports.

To fix the issue, avoid HW_TAGS KASAN memory initialization when
slub_debug is enabled altogether.  Implement this by moving the
__slub_debug_enabled check to slab_post_alloc_hook.  Common slab code
seems like a more appropriate place for a slub_debug check anyway.

Link: https://lkml.kernel.org/r/678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com
Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated kmalloc space than requested")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reported-by: Will Deacon <will@kernel.org>
Acked-by: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Feng Tang <feng.tang@intel.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: kasan-dev@googlegroups.com
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Peter Collingbourne <pcc@google.com>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 mm/kasan/kasan.h |   12 ------------
 mm/slab.h        |   16 ++++++++++++++--
 2 files changed, 14 insertions(+), 14 deletions(-)

--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -466,18 +466,6 @@ static inline void kasan_unpoison(const
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
-	/*
-	 * Explicitly initialize the memory with the precise object size to
-	 * avoid overwriting the slab redzone. This disables initialization in
-	 * the arch code and may thus lead to performance penalty. This penalty
-	 * does not affect production builds, as slab redzones are not enabled
-	 * there.
-	 */
-	if (__slub_debug_enabled() &&
-	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
-		init = false;
-		memzero_explicit((void *)addr, size);
-	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -684,6 +684,7 @@ static inline void slab_post_alloc_hook(
 					unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	bool kasan_init = init;
 	size_t i;
 
 	flags &= gfp_allowed_mask;
@@ -701,6 +702,17 @@ static inline void slab_post_alloc_hook(
 		zero_size = orig_size;
 
 	/*
+	 * When slub_debug is enabled, avoid memory initialization integrated
+	 * into KASAN and instead zero out the memory via the memset below with
+	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
+	 * cause false-positive reports. This does not lead to a performance
+	 * penalty on production builds, as slub_debug is not intended to be
+	 * enabled there.
+	 */
+	if (__slub_debug_enabled())
+		kasan_init = false;
+
+	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
 	 * kept together to avoid discrepancies in behavior.
@@ -708,8 +720,8 @@ static inline void slab_post_alloc_hook(
 	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
 	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, init);
-		if (p[i] && init && !kasan_has_integrated_init())
+		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
 			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);


Patches currently in stable-queue which might be from andreyknvl@google.com are

queue-6.4/kasan-slub-fix-hw_tags-zeroing-with-slub_debug.patch
queue-6.4/kasan-fix-type-cast-in-memory_is_poisoned_n.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2023072152-galore-apron-cd97%40gregkh.
