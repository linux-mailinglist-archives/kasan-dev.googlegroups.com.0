Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5HCXWKAMGQE7O6FSJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98FD6534F0E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 14:24:22 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id w3-20020acadf03000000b0032b02f1a1a0sf639793oig.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 05:24:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653567861; cv=pass;
        d=google.com; s=arc-20160816;
        b=UaG80UH+0hZWAvBxxJy50RTLM/x4RszmLg/XJFcXb5pMlTav2pA6Kgk9gpml+dwSc4
         a8oFv3/qp9EbWbAoNOUqFJjG+cNgSnpUIh4aG/e2Or8s3MzmSbrWWFaJ3F+ppeLpcDDf
         JbMyiOYZ3Gx+AcydWCIpXOvktsdIVPPpm03KaPZZgDIB8BODsm1Uew4Of47iZTVYwE1/
         ppB6lmAL1j8LWKvAEG9xrs58MHpWg/7krTj0b1VH2TG+EJk7SbVNsDODFNO5svu2r6D1
         sNy3zryvjGIJVJdTrONNxULhHV6zWbJ+k9nUBxIL2sNV0nYHhIOmedMogdfnZyFKuIM6
         vNOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MsyHlOHQnbC1w7nU7IXjNpgM/RYa6D18G79oJF7Y2ak=;
        b=pMf89iVDFjl01BbUXqxsDpV/XQY6ZU+clh3rskLgkQvzHus8vb6C+hEs/G57s2CRf2
         2TWNCmUCciRTD09Ch75YU3oNR2/N5DJ6LPvlVzVuzIJMh90j0dcky+bXv3a+W/ExPIEr
         WF1WqR5T4DsbUUShPd3I2IFQ2g2zvKHELQhaW6Dmz8uC1MSSRn5JwzfqqNLNXIwVc0J0
         S+fuV0zJF992vSvugFpGicMpfuXYCRoGQCH3YezWsEAS6ZFaHdPSxBb0cbGdgBAydTo+
         8nMqT/+XtoiypIxkl1W2GICAzy0iobq+8S7Txc8NHI8cpeJgIxxCee+30OHB6Mc07NoV
         YAhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MsyHlOHQnbC1w7nU7IXjNpgM/RYa6D18G79oJF7Y2ak=;
        b=EF9Mh6YBmf7BXJGnvsadn+Ds9/oDGtIs+F/98v1Z+xlzl7xRiXe1lotHXAEONdGCC/
         voR8W+Em6ECAqQeZMKD/E4Cl+b3zHRPCnYwF8fGWx6GDmy370Ec6r/cGHpCqgJE5TY6a
         YL7EX0F9aeTM+ufZk/sEN9sX0SrdHs7Mb0bnXAZsaBmEuFTmJ3pzFIh1LVuxlYujricN
         uOvcP1qVD3PmVcXSFgr/U+QNresjNUM0vWd0AVRU5NfTyASy9cr7F1CRH4Vbc5TjIyYi
         0ddhtDpW8fPrPzY0Qr/JYsQ6nQJu+RIPMn3gcNiSSMwdvwKhulEhyKZ6NmepxSE0Ccxu
         r2CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MsyHlOHQnbC1w7nU7IXjNpgM/RYa6D18G79oJF7Y2ak=;
        b=YySU3IEwkRjVK13/kbQMn8YQfl9ITLEFE5vY+OblxlByG8Oay//kCqfkSu/K2xC1RA
         C4ZZ+MghvNTFeFv4fPUZhSWMP1CHsdVq9aCfi6DRiSMYA91yGlpdp2rpoK52TwxKR8bD
         VzSVh7x5oq9YEH6y2owYHQP7N+3vmHuVv7waCnntn/CKBaCqIWCRZoO1XnD5yot37A1X
         z+ERpjcO+0wpzpoMN01cWj1+xFj2ttcZ6BwgWzwm3mQvWf/vJrR3KA9uOjViEeqLwh4d
         SfuJZqlhFG1lHbcDundTuoxNA2CfkLqjW5hbM7+5txQeXfb/WWuV0ZgbBALO0CBuFlbI
         Ytrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532y1UA7G14n+BPvQ1WyolNP16uBDj5iHrpCoW3obCG56zLqsPQ2
	iU2EIAb0jER2v3aa76ew9Qw=
X-Google-Smtp-Source: ABdhPJyjqT74X2QTlDM7/F2FV/rD4iDR8FrII+PakRAYvn9yuvdU9la2PXxz3+yopEC5cYKlEt1HXw==
X-Received: by 2002:a9d:5506:0:b0:60b:1f4c:85b5 with SMTP id l6-20020a9d5506000000b0060b1f4c85b5mr6163336oth.174.1653567861010;
        Thu, 26 May 2022 05:24:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:815:b0:60b:18ee:64dc with SMTP id
 r21-20020a056830081500b0060b18ee64dcls2560796ots.3.gmail; Thu, 26 May 2022
 05:24:20 -0700 (PDT)
X-Received: by 2002:a9d:1b09:0:b0:606:e384:138e with SMTP id l9-20020a9d1b09000000b00606e384138emr14388152otl.141.1653567860601;
        Thu, 26 May 2022 05:24:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653567860; cv=none;
        d=google.com; s=arc-20160816;
        b=QG/SeBq76JtLAMDOqBC1Ac13T41L46r8Hhh5RB54Vb5LGrycbDHkQcMV0OmXk52r4J
         4B3bVit/kbVbCciiLb6Dga6Tzt0cjp0Vn11m0WcNBm/xtzRHPpiZlOvIS2JXRa6/d4NP
         e/b3wBV4Q5v5ZlRNxWwIPcVMk6Gj6uGKUKO6+oMDlZhhe3HdE23zZ2vTZvsstRVv4hbK
         v0ocJ5V3wj40NX9RZR9nkQEpDcY9Ke6yAq1hBsELJQLBtJfIr3N0PCwH/RmMdgyRbgoF
         FyKhgrvvudU13wDuASfYQg+3RrGBu8SurkZ09MjnaAKW/Q5Ai/4GNDA1b+gpuytdj/WR
         4tFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=GfaF+v1mp4GSMGZQrFdv1tqXIyE3BI+P6UNVXmeS2+w=;
        b=dzVa4GM8Kv4y8Vb7rJ6LSTthvKwc6pSCROVlMucbWUzEmzYDpbe5zibYYrZmwYaQz5
         ov7DLrFuU7dTS9dOFCZQoXEu4DOCdM78zvbwsSQdY7M8rn0+hra802boQ3b2TpRojjJz
         reLWh9jFscDHYXzD7qErJKAvYrElkdTmvIs5/D5UZScUSF2OHZWxbmp81sDOy1Xybo0D
         sbvf7Wi/oWNIgxP+3XjFYXHNmvJQ8MmbPjKmEkTzsyyNt3u+bs4zVt2+CEPIakX/1Cee
         jG3hTFN98b7/mZs6xdoeKJWuhFC8bNjNoTSFN969cL1/Xaxmn+QADgoIZC1Hs8wQho6e
         1BwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id f10-20020a05680814ca00b003222fdff9aesi74917oiw.0.2022.05.26.05.24.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 May 2022 05:24:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5D0886199F;
	Thu, 26 May 2022 12:24:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3FD7FC34113;
	Thu, 26 May 2022 12:24:18 +0000 (UTC)
Date: Thu, 26 May 2022 13:24:14 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and
 page->flags
Message-ID: <Yo9xbkyfj0zkc1qa@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com>
 <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
 <Yo5PAJTI7CwxVZ/q@arm.com>
 <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, May 25, 2022 at 07:41:08PM +0200, Andrey Konovalov wrote:
> On Wed, May 25, 2022 at 5:45 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > Adding __GFP_SKIP_KASAN_UNPOISON makes sense, but we still need to
> > > reset the tag in page->flags.
> >
> > My thought was to reset the tag in page->flags based on 'unpoison'
> > alone without any extra flags. We use this flag for vmalloc() pages but
> > it seems we don't reset the page tags (as we do via
> > kasan_poison_slab()).
> 
> I just realized that we already have __GFP_ZEROTAGS that initializes
> both in-memory and page->flags tags.

IIUC it only zeroes the tags and skips the unpoisoning but
page_kasan_tag() remains unchanged.

> Currently only used for user
> pages allocated via alloc_zeroed_user_highpage_movable(). Perhaps we
> can add this flag to GFP_HIGHUSER_MOVABLE?

I wouldn't add __GFP_ZEROTAGS to GFP_HIGHUSER_MOVABLE as we only need it
if the page is mapped with PROT_MTE. Clearing a page without tags may be
marginally faster.

> We'll also need to change the behavior of __GFP_ZEROTAGS to work even
> when GFP_ZERO is not set, but this doesn't seem to be a problem.

Why? We'd get unnecessary tag zeroing. We have these cases for
anonymous, private pages:

1. Zeroed page allocation without PROT_MTE: we need GFP_ZERO and
   page_kasan_tag_reset() in case of later mprotect(PROT_MTE).

2. Zeroed page allocation with PROT_MTE: we need GFP_ZERO,
   __GFP_ZEROTAGS and page_kasan_tag_reset().

3. CoW page allocation without PROT_MTE: copy data and we only need
   page_kasan_tag_reset() in case of later mprotect(PROT_MTE).

4. CoW page allocation with PROT_MTE: copy data and tags together with
   page_kasan_tag_reset().

So basically we always need page_kasan_tag_reset() for pages mapped in
user space even if they are not PROT_MTE, in case of a later
mprotect(PROT_MTE). For (1), (3) and (4) we don't need to zero the tags.
For (1) maybe we could do it as part of data zeroing (subject to some
benchmarks) but for (3) and (4) they'd be overridden by the copy anyway.

> And, at this point, we can probably combine __GFP_ZEROTAGS with
> __GFP_SKIP_KASAN_POISON, as they both would target user pages.

For user pages, I think we should skip unpoisoning as well. We can keep
unpoisoning around but if we end up calling page_kasan_tag_reset(),
there's not much value, at least in page_address() accesses since the
pointer would match all tags. That's unless you want to detect other
stray pointers to such pages but we already skip the poisoning on free,
so it doesn't seem to be a use-case.

If we skip unpoisoning (not just poisoning as we already do) for user
pages, we should reset the tags in page->flags. Whether __GFP_ZEROTAGS
is passed is complementary, depending on the reason for allocation.
Currently if __GFP_ZEROTAGS is passed, the unpoisoning is skipped but I
think we should have just added __GFP_SKIP_KASAN_UNPOISON instead and
not add a new argument to should_skip_kasan_unpoison(). If we decide to
always skip unpoisoning, something like below on top of the vanilla
kernel:

-------------8<-----------------
diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 3e3d36fc2109..df0ec30524fb 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -348,7 +348,7 @@ struct vm_area_struct;
 #define GFP_DMA32	__GFP_DMA32
 #define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
 #define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
-			 __GFP_SKIP_KASAN_POISON)
+			 __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOISON)
 #define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
 			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
 #define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0e42038382c1..3173e8f0e69a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2346,7 +2346,7 @@ static inline bool check_new_pcp(struct page *page, unsigned int order)
 }
 #endif /* CONFIG_DEBUG_VM */

-static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+static inline bool should_skip_kasan_unpoison(gfp_t flags)
 {
 	/* Don't skip if a software KASAN mode is enabled. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
@@ -2358,12 +2358,10 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
 		return true;

 	/*
-	 * With hardware tag-based KASAN enabled, skip if either:
-	 *
-	 * 1. Memory tags have already been cleared via tag_clear_highpage().
-	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 * With hardware tag-based KASAN enabled, skip if this was requested
+	 * via __GFP_SKIP_KASAN_UNPOISON.
 	 */
-	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+	return flags & __GFP_SKIP_KASAN_UNPOISON;
 }

 static inline bool should_skip_init(gfp_t flags)
@@ -2416,7 +2414,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+	if (!should_skip_kasan_unpoison(gfp_flags)) {
 		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
-------------8<-----------------

With the above, we can wire up page_kasan_tag_reset() to the
__GFP_SKIP_KASAN_UNPOISON check without any additional flags.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yo9xbkyfj0zkc1qa%40arm.com.
