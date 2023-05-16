Return-Path: <kasan-dev+bncBD52JJ7JXILRB46XRORQMGQE2OL24WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 037F4704375
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 04:35:33 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-76c56d109efsf591393439f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 19:35:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684204532; cv=pass;
        d=google.com; s=arc-20160816;
        b=WiiTF/Lag5l/QDsZJLQZA0w89Eh3YoCPut5pRt7Mh82l0TOIxl+CvGl2DGsyciQe0A
         kgcknxq7/yjsndAXD5pa8NGNZVKXihuCuKKDxVH8uqx8+hbISshXiOkYf5wEMN5wWf5W
         DSczwnnpsZpeHsGQeCgwY/MfCLFcoEnj2YZc7Y+U+wCkbAPmpNM+3qRKRDNpK2rfjlbN
         sptCx6+vz7F6XFpbUPrRT655ft0b0lNpy1RQB7FndJyk1RTMtrgRFXg4EYoKr8JbXdqi
         f5IRFYIL7LecNoxADmJtoC0slCSvzApCiA6QknCrwCkuUFlr+vbWR7PhkP6ADo9xMlsU
         d85Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Q5ZJEfp/j2LEzUOK+189PMOI3NBIMLtuy+bEnZ76yhs=;
        b=Ir5zCumc7GoUnEunXgkpmIKxoIbp0Rnml1HUGWNSmrvylWdeYHtHZLO0gBPNGy/0lF
         wSb+kLDSTRE9iMgA8Z4VDrn1UdSFXj0e6OMM+N74yCVjfrTEpRHT6pnn3dd7nEZhW176
         JKSve4MJsMcSR6FujrBqdJ2B1lQHOsBIINZegvEba/RhE1fAgrCWaYj/dvVgRGZPZEn5
         tLIvYScwyIUyT5n4vsHaBmF5xPVH1pT2C5ksQ6vBvznA3/PRQQ/kkS8y3QMo5WyUafbA
         dvRj4oE5keaH08U1Vhb/3/jBv8XFsj8hWW73zxUgmFUz5XLydGgyrNTFYgOhGlUb05Pd
         nDTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Y9M5TADW;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684204532; x=1686796532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Q5ZJEfp/j2LEzUOK+189PMOI3NBIMLtuy+bEnZ76yhs=;
        b=gum3WbnziTYYZ9/v7ggfCiQcMMQvbhZr02zHh1X2vXubJPtUu++aGaRL6deQVcLOsK
         yIiEWp/S2h07OFWMdtgJBXlpn6n/RBYpPHYhjx7JpO0DfR3STHChXlxKnWMH1Ttv2tBa
         ZM87A51wrlcscb2slVHksP5aRW8HOT4W5Z3eTH+UfP07Q1cntJ4bhFMOhc927rgzoop3
         10q1SWafnoC3CvHYdhlT2eenlrP8hrGMoaU4pSNY+nmAcHkfNyvYHEOb1Cv/WQv3zoVL
         G0V3c9z/jK5ykn1BfWIodQ0/MVY8Ewt2i3DQlnRTQeqlwkr2tYsVvFvtU2NgsBJ4P3ZU
         QZAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684204532; x=1686796532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q5ZJEfp/j2LEzUOK+189PMOI3NBIMLtuy+bEnZ76yhs=;
        b=iBM5/TWa8ts2pdxDE3euKHEjnbxffhw+N+wr/hy+uanP33TC3NXC2oh9bR21CFyRqZ
         6fpSv05BVbjvP3jFzjbhJ94IgxebVsWbLXC0vLmWIegNs/HwQ3nq8zntiWxdisbHtUPd
         s5tlXW0wDzVI+cZOUwSeUkj4ibh0jl0KgNxZe3S0+l+W8AiQMjqiUlRoS+WKd2a0HWJB
         7HzOh3THWK3tTpBm6uYJ0PMUi5ybe0Rx2/OfBWHNqdb+BAN5uMmqNndum0tGVn6cd+kE
         fGCRZzBncriaSlerV1hvq92OfOVBG4p442Q9XNkpVEiStWsf98IHRGqWDvRWIJWM3WGd
         QayA==
X-Gm-Message-State: AC+VfDyL7ICqQ9cEjd281IGRCqqoHi+p5MNMW2G8seC/J98fIsYE5lOj
	0Yxm1gzvwAvi1Qyi9KtCnEU=
X-Google-Smtp-Source: ACHHUZ79/2oJWQzmMv+uhIPmGfAKFSum3y/yJDKhKAOUlA9X5XLarQMXjfGMSeQP1Q/2ZpatkLhnhQ==
X-Received: by 2002:a5d:9619:0:b0:766:655b:37a3 with SMTP id w25-20020a5d9619000000b00766655b37a3mr918891iol.4.1684204531917;
        Mon, 15 May 2023 19:35:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2209:b0:331:2df7:644b with SMTP id
 j9-20020a056e02220900b003312df7644bls3183269ilf.0.-pod-prod-02-us; Mon, 15
 May 2023 19:35:31 -0700 (PDT)
X-Received: by 2002:a92:c0c9:0:b0:337:8342:e6a5 with SMTP id t9-20020a92c0c9000000b003378342e6a5mr4604403ilf.31.1684204531440;
        Mon, 15 May 2023 19:35:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684204531; cv=none;
        d=google.com; s=arc-20160816;
        b=s5oHvGESgKwwyQNzKpcSYXQLbc2IV14nZlHRok91p6HKqdjK3XemewJOZPoOdG6mkG
         oe0lVTRnglwAKYP7bCNXlH7HTyblLE6Apk6ZXQMC5YWVk8XWvX17AaISzXlLYA60C0I8
         hRPGTL9OxZuFLfPn2SkwCd+GPSaa+NmdeinvDG0NoBSCoNWy0VtRLQBnSAIUpupcA3/w
         tqZkCHjNil84x2gLnqJui9/URx8VsyAgrfRzumoI5WU2JwKlt1WkeF0cgsH7N79GFwms
         S296HZgh0QoMXPyVD35xrD3sgzk8XnX3M2MCO/hJoWFetL3FUJnX3gPeUv21J6OIDj/g
         3rZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LMBjYQfNrE6XjpDNQgsEFZW5LIEYARmq7ri2dsjhSck=;
        b=krguzQ/s4uNPyEfiqP4dZHE9IF4qqkCasUyD5HsLlG5dTA7+iglbiHMlC77ihvGz/n
         vb171fmrme0kNsWAy5ucP28Hco2eeq+eNmD6o77+qOpq53Zw3r7M0AI7UeK3KIevNIwV
         Hd9S65AHaX5BgYMu7cpm01QcvPt1rSv8xgx3AdNYTxTevFBVFKSKRcw5XqB3selKJ5jn
         4hOvWR1iX+YPRFCYBSen/XPRkLbnOKz23IHE6cEs4b3nYagc9R+njBw4ktKgCUv2dU7I
         T/GOuMdndWamMQI7+VP7jpTzhekV7HfhaK2Pr8stbj2JHA/kjP4PxlQXqQflMqxiK+Rz
         bkyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Y9M5TADW;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id ee24-20020a056638293800b0040fa7700d64si2040087jab.4.2023.05.15.19.35.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 19:35:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1ac65ab7432so798205ad.0
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 19:35:31 -0700 (PDT)
X-Received: by 2002:a17:902:c1d3:b0:19c:c5d4:afd2 with SMTP id c19-20020a170902c1d300b0019cc5d4afd2mr9124plc.11.1684204530548;
        Mon, 15 May 2023 19:35:30 -0700 (PDT)
Received: from google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
        by smtp.gmail.com with ESMTPSA id t23-20020a634457000000b0051afa49e07asm12283006pgk.50.2023.05.15.19.35.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 May 2023 19:35:30 -0700 (PDT)
Date: Mon, 15 May 2023 19:35:24 -0700
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
Message-ID: <ZGLr7CzUL0A+mCRp@google.com>
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
 <ZGLLSYuedMsViDQG@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZGLLSYuedMsViDQG@google.com>
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Y9M5TADW;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::634 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Mon, May 15, 2023 at 05:16:09PM -0700, Peter Collingbourne wrote:
> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> > On 13.05.23 01:57, Peter Collingbourne wrote:
> > > Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> > > the call to swap_free() before the call to set_pte_at(), which meant that
> > > the MTE tags could end up being freed before set_pte_at() had a chance
> > > to restore them. One other possibility was to hook arch_do_swap_page(),
> > > but this had a number of problems:
> > > 
> > > - The call to the hook was also after swap_free().
> > > 
> > > - The call to the hook was after the call to set_pte_at(), so there was a
> > >    racy window where uninitialized metadata may be exposed to userspace.
> > >    This likely also affects SPARC ADI, which implements this hook to
> > >    restore tags.
> > > 
> > > - As a result of commit 1eba86c096e3 ("mm: change page type prior to
> > >    adding page table entry"), we were also passing the new PTE as the
> > >    oldpte argument, preventing the hook from knowing the swap index.
> > > 
> > > Fix all of these problems by moving the arch_do_swap_page() call before
> > > the call to free_page(), and ensuring that we do not set orig_pte until
> > > after the call.
> > > 
> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > > Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
> > > Cc: <stable@vger.kernel.org> # 6.1
> > > Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
> > > Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")
> > 
> > I'm confused. You say c145e0b47c77 changed something (which was after above
> > commits), indicate that it fixes two other commits, and indicate "6.1" as
> > stable which does not apply to any of these commits.
> 
> Sorry, the situation is indeed a bit confusing.
> 
> - In order to make the arch_do_swap_page() hook suitable for fixing the
>   bug introduced by c145e0b47c77, patch 1 addresses a number of issues,
>   including fixing bugs introduced by ca827d55ebaa and 1eba86c096e3,
>   but we haven't fixed the c145e0b47c77 bug yet, so there's no Fixes:
>   tag for it yet.
> 
> - Patch 2, relying on the fixes in patch 1, makes MTE install an
>   arch_do_swap_page() hook (indirectly, by making arch_swap_restore()
>   also hook arch_do_swap_page()), thereby fixing the c145e0b47c77 bug.
> 
> - 6.1 is the first stable version in which all 3 commits in my Fixes: tags
>   are present, so that is the version that I've indicated in my stable
>   tag for this series. In theory patch 1 could be applied to older kernel
>   versions, but it wouldn't fix any problems that we are facing with MTE
>   (because it only fixes problems relating to the arch_do_swap_page()
>   hook, which older kernel versions don't hook with MTE), and there are
>   some merge conflicts if we go back further anyway. If the SPARC folks
>   (the previous only user of this hook) want to fix these issues with ADI,
>   they can propose their own backport.
> 
> > > @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> > >   	VM_BUG_ON(!folio_test_anon(folio) ||
> > >   			(pte_write(pte) && !PageAnonExclusive(page)));
> > >   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> > > -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> > >   	folio_unlock(folio);
> > >   	if (folio != swapcache && swapcache) {
> > 
> > 
> > You are moving the folio_free_swap() call after the folio_ref_count(folio)
> > == 1 check, which means that such (previously) swapped pages that are
> > exclusive cannot be detected as exclusive.
> 
> Ack. I will fix this in v2.

I gave this some thought and concluded that the added complexity needed
to make this hook suitable for arm64 without breaking sparc probably
isn't worth it in the end, and as I explained in patch 2, sparc ought
to be moving away from this hook anyway. So in v2 I replaced patches 1
and 2 with a patch that adds a direct call to the arch_swap_restore()
hook before the call to swap_free().

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGLr7CzUL0A%2BmCRp%40google.com.
