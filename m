Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLW2RGRQMGQE7R7D5CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 052477038C2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 19:34:40 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-643aeb66f4bsf6842715b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 10:34:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684172078; cv=pass;
        d=google.com; s=arc-20160816;
        b=l6D5QYcD233kymhP+SoP/gM5+rlJAeuumM92aJAUAkAgXxi4f6hVRPiO85/YLSdWdY
         0kz7XVQkjA1Iu4tMKov49zvYwOLBV4n/xSkk1pBzgf9p24Dc5gAUpQ9d2ho1xPsnSYjb
         ipFmLEeECgpwlzxm3npfT80pe0l5035gKTaczjvoinhF1GFcLJavOQKWf7aVGbZW10Ri
         yzrUqupvuS7yZXf3tF7/5fdzHUyNhs3g3Z7QHMVaKvClDhnrQcOpxjYuU3ii8gcueGLv
         kMFITHgHZN6gFBloqcY4KVMVTilM39I4sNtTBEwlOLX3HVrCXuuiTPLydl2R2KOrJyLQ
         dQsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5WwKyVxJBFuDePF/cLaKfWQih49m5X7Dm0g55FmKLA8=;
        b=L/CnRZ6zCLz1rq79e0xLXEKJa/2PnK+ko6M8jvbi4M1ZCEkfOkYkmQThuntcDKlL2z
         rLo2Lwfc9oeZhhnDbFEDJM4NacJbCJZq4vWbC/WusRed/DW2uiyUHVXmC3ySX2RUUL+3
         5i621dVE0jEQUHzKSxHLC71njEJSC64LnAkbpak7obbGFQJeC5lZQ/YGkFbHHRPm1wyb
         BT8vpbZ1qOrooZeOvSKiaLkHVUD+eN4Z4batXc9Vdn+d/fGeQKdbeXcQb7eWWS9XFc3i
         eklVadcpFN6BpQz/ujG63yJu7+lci9ffgwmjhKXI6hlFZLDh/nX/nl7poQ89dwXZ781/
         HLMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684172078; x=1686764078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5WwKyVxJBFuDePF/cLaKfWQih49m5X7Dm0g55FmKLA8=;
        b=M/cKA+1wImoTuvhucHfqTXcnSmWBhqczvHuEw7lyfXKqfib6BXsQYxBVAO5bFsbnfx
         +hOOxvjXwyGfvZLKxlmOZ64W9boe0zCiMGdosqtgdOv/gCJNawuzhRRNaf+nRUJMtx54
         u6oJAAYHS9hCEE4BHE8D2j61fZbQVeNPcKGZJUzHQsCtvABBXFTcD7vYCyNamkIj4jEs
         smrMs735A7BVSX8s871rgF1Kf/3qySDFceGmuSPDxfJpn3Bdk6WzFak8VJqZ6IsskpUZ
         I1G+rcEozQ/Ocw4yt2HlvfU866JlZ/2n4VOhxocvmq67haayKEg4FCn1aUxINFR078/R
         4fyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684172078; x=1686764078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5WwKyVxJBFuDePF/cLaKfWQih49m5X7Dm0g55FmKLA8=;
        b=E8lqA9QQmDDzJtXreDApLYc+v7xSuxCS5T25/SYKFgJX3H2nDTVNfDq2UkQV9UAwHs
         kAZSPumojWRF5s2wnEH14TlqE/btukIGERecrP0AbRJ0mi9KkrYeEs31ZYOdfQBiBwyO
         srygahylUEJlfofLkR8tRj0YBYxNxdwtl0D2TVYN1u9ac/4QirYtigTI6grvr1yaKqjC
         80r3A6hFsHF899hcJQkqqlBF3twFUZZL5Ai/jzYWtg4JLC5ASmjhKX2n40JdAhoIXDM6
         mKiUhQL6QVsnZ1tlcVFHSDwcOckAHFub4HFGyLAx4cFwMENu6IPHi9PsawFMqW9UjiIz
         FapQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx1888McM4j5YZ0UMxYPTWtu6oEMdvQgm+q5ILnHRd1u59HxXIu
	TAM/5cZOJ3cIYQUuhLacrP0=
X-Google-Smtp-Source: ACHHUZ7vWB0ZlL0kQxHeoe3CT6UKNQSWTRCBaUjF61zphCYgafvpzjjP+g4K6M2p9PGwMZx9g2aEqA==
X-Received: by 2002:a05:6a00:785:b0:643:7916:16e2 with SMTP id g5-20020a056a00078500b00643791616e2mr9169541pfu.1.1684172078326;
        Mon, 15 May 2023 10:34:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f406:b0:250:91ca:b582 with SMTP id
 ch6-20020a17090af40600b0025091cab582ls11330991pjb.0.-pod-canary-gmail; Mon,
 15 May 2023 10:34:37 -0700 (PDT)
X-Received: by 2002:a17:90a:b292:b0:24d:fb21:3d7c with SMTP id c18-20020a17090ab29200b0024dfb213d7cmr34082250pjr.30.1684172077426;
        Mon, 15 May 2023 10:34:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684172077; cv=none;
        d=google.com; s=arc-20160816;
        b=olVQkf87XIBji9Bjy3ffFrdSSthCZECu8GDzbKqNOlnmo8e8scZGIW5hFtaQGI0lYr
         ZTBrOSYrRguGJR/t95gwBMexv4XXzmAhrWYG6E+rYHbKnu20pSI+E57Zpp0E0z/Ij42K
         GwiWDN2HNRPhrvCXH3ED2T2fRdfyBgU4G40de+7MatwpDeucEiy2/x3G25ZqD/pbNjxf
         My5KkUuKBF7ArF5JujKzp/0MF3VJjuab+6sgwPMFNtTCTRWgizJKM9FioBt1R94SIE99
         gyVYNK/jq1NMyrNPs8ats/y3aO3lJMHCF9Fn5b8kOZQM02us9rNSqGzV66MVSdyRRZ5n
         /iig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=8p+ihgkPcPd2D3/3WODxI3pDEcclMK1kAB3O4bitP2M=;
        b=HwUhJn85UJ2jXc317u0tDVlcappvQix9r/B51+Haw1Sw70ujF+N5lvCcgqSu4YKyuG
         IGtmyrM8utL/u62SuCsjcYS1BRvuhiT/54h5/gihaZpnSDI0aCkOOoSDHCL2rNL+l9yz
         ljCW0wEvESwQenwklKx/gLLolNrkgsF8NXMf71vfw8Ie8aT5IRH+ub5S0s3Z6CThOF8I
         nh05F5I+C9qQWISOaZR1h04t1xzyUqYBKlnOWbewcSLpsIvxmqQ5ulN4ob0KYtonnQ7O
         Z58DXDbjeDfNSEI1mdLDwW7TX0iYTyrMaS/hBsXaIijwgN8Mjigl7fJXvnWDu7XrMRCe
         3Myw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id u16-20020a17090adb5000b002527c7fe603si9613pjx.0.2023.05.15.10.34.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 May 2023 10:34:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DBE0B62DBE;
	Mon, 15 May 2023 17:34:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6F0F4C4339B;
	Mon, 15 May 2023 17:34:33 +0000 (UTC)
Date: Mon, 15 May 2023 18:34:30 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: David Hildenbrand <david@redhat.com>
Cc: Peter Collingbourne <pcc@google.com>,
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
Message-ID: <ZGJtJobLrBg3PtHm@arm.com>
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> On 13.05.23 01:57, Peter Collingbourne wrote:
> > diff --git a/mm/memory.c b/mm/memory.c
> > index 01a23ad48a04..83268d287ff1 100644
> > --- a/mm/memory.c
> > +++ b/mm/memory.c
> > @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >   		}
> >   	}
> > -	/*
> > -	 * Remove the swap entry and conditionally try to free up the swapcache.
> > -	 * We're already holding a reference on the page but haven't mapped it
> > -	 * yet.
> > -	 */
> > -	swap_free(entry);
> > -	if (should_try_to_free_swap(folio, vma, vmf->flags))
> > -		folio_free_swap(folio);
> > -
> > -	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> > -	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> >   	pte = mk_pte(page, vma->vm_page_prot);
> > -
> >   	/*
> >   	 * Same logic as in do_wp_page(); however, optimize for pages that are
> >   	 * certainly not shared either because we just allocated them without
> > @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >   		pte = pte_mksoft_dirty(pte);
> >   	if (pte_swp_uffd_wp(vmf->orig_pte))
> >   		pte = pte_mkuffd_wp(pte);
> > +	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> >   	vmf->orig_pte = pte;
> > +	/*
> > +	 * Remove the swap entry and conditionally try to free up the swapcache.
> > +	 * We're already holding a reference on the page but haven't mapped it
> > +	 * yet.
> > +	 */
> > +	swap_free(entry);
> > +	if (should_try_to_free_swap(folio, vma, vmf->flags))
> > +		folio_free_swap(folio);
> > +
> > +	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> > +	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> > +
> >   	/* ksm created a completely new copy */
> >   	if (unlikely(folio != swapcache && swapcache)) {
> >   		page_add_new_anon_rmap(page, vma, vmf->address);
> > @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >   	VM_BUG_ON(!folio_test_anon(folio) ||
> >   			(pte_write(pte) && !PageAnonExclusive(page)));
> >   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> > -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> >   	folio_unlock(folio);
> >   	if (folio != swapcache && swapcache) {
> 
> 
> You are moving the folio_free_swap() call after the folio_ref_count(folio)
> == 1 check, which means that such (previously) swapped pages that are
> exclusive cannot be detected as exclusive.
> 
> There must be a better way to handle MTE here.
> 
> Where are the tags stored, how is the location identified, and when are they
> effectively restored right now?

I haven't gone through Peter's patches yet but a pretty good description
of the problem is here:
https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/.
I couldn't reproduce it with my swap setup but both Qun-wei and Peter
triggered it.

When a tagged page is swapped out, the arm64 code stores the metadata
(tags) in a local xarray indexed by the swap pte. When restoring from
swap, the arm64 set_pte_at() checks this xarray using the old swap pte
and spills the tags onto the new page. Apparently something changed in
the kernel recently that causes swap_range_free() to be called before
set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
from the xarray and the subsequent set_pte_at() won't find it.

If we have the page, the metadata can be restored before set_pte_at()
and I guess that's what Peter is trying to do (again, I haven't looked
at the details yet; leaving it for tomorrow).

Is there any other way of handling this? E.g. not release the metadata
in arch_swap_invalidate_page() but later in set_pte_at() once it was
restored. But then we may leak this metadata if there's no set_pte_at()
(the process mapping the swap entry died).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGJtJobLrBg3PtHm%40arm.com.
