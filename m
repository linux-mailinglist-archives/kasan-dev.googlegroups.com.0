Return-Path: <kasan-dev+bncBDV37XP3XYDRBNWRWDVAKGQE6WJQHHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 65376863AB
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 15:50:46 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id e9sf47142565edv.18
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 06:50:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565272246; cv=pass;
        d=google.com; s=arc-20160816;
        b=W0EbSFbiueZghlNh/vFC+64Cv6xAYrxcfBmpwbd56x97CEz+hxjQbrTDHODT3m9z80
         iKT4cd9PKN0RG7ULktDj6z7TjQ5JnbOTLwhTSbCjtg3T+5p2XVuEREyeBorxb+sTC8II
         jghebuc7W/+EN5DzWOU1BQoayOtU50gUITrNMcazD5ogJEX4xfk/zUPBS6iGFMorJLru
         hP1LXTSzMrc+xaq9wg6ZTqdYmOyc+28fsLw21XhynKPDHvbUHPvshVjEAwx/gxwAfpmc
         GY6OaCl1yHknfT0aeCFEhYiAnhQaxYRsK0THowpeaIwfU8qSEfTCpHlKcFEOUf6OZAro
         X9nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DB+EGkljToY5kGR3tyZzxRrUTM979Wfhp5GilyexiCU=;
        b=xSkBFixkKdxXZuco0TgPpKL5SwUHElUuASSJMb8LW9aBs0MX00BIs+ktxPxoJisdbD
         qHVkbe9wqvkjd6qj733NYr6/HWLKuIV6dhdq3F9mJ2PT1BZuNKsuAWjmDfQGbJcse3Fw
         kPvcq01gOBF7US6eb1db534EB2H3YTbxpYmiDRn5BqoJ/ATx5QF6zInbQY/0hMj1FNZL
         45dGphRVBx0jyWFI3K3TG4HvwDMuXZxAUD30bh2eG/kxkYw43JF8sp/Y6qJcm5mP+PYR
         TMPh/yGa5S1f3bchgEPu4apM2jtCQUPAMcng+VUy++njecGBjprCPgqvgjeIygpOlavw
         YkDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DB+EGkljToY5kGR3tyZzxRrUTM979Wfhp5GilyexiCU=;
        b=O+nQmDrORlZy/fVpZ00TjmCE1/wBhqu+uF1GxE6ROdMJ9VH93sV7lOyULE37pP/m53
         ifbcPcBWJZSnmBUkG+AzZuKRMw6Z+4+49GNZG/RpskwsrIt13moOMAit9awt7v2twERi
         15g1W9b4/bt5tB0cnKi6PcRT+kVT/fc/L1SQzs3QvAh/CtLrTqmpTUCEj6IZBClVKHZL
         mnErII2RaT38H/6sVqV+W7nBB9Daz+stuWeG5vKTwpqNCYWhefTd1olv2T4vF1QLnsI+
         LNMi8XUXGhaAQ5nIxX3C1cDxogA8G0qUcg3a6M0ENlfBiNbWUdRdjW3Y7XMYS586GRwd
         6MTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DB+EGkljToY5kGR3tyZzxRrUTM979Wfhp5GilyexiCU=;
        b=s7wt8slDdo0JAYN2vZJVkoR7p2RhuzAuHthdlao5fPv5IvQuZbiFboiwW+aWTvw1gy
         IO8RDTmfmH1YSUBrna85wJrsTT5tfka3xwbrK2g1DXO9gKdlgE/yEmHVT3j8jI668CkW
         K3koGHubAl5dib29TeHNJBPvHMrv2g0biWsZFyykTE+lnV6pESu/j7bLv1otvLBhpxjC
         f7SljD2jOXsRieewlWp5hOiK9l37NhJL8NKmSRrkdyPC0AXq9g0tre6P5M0DKpIHQiKU
         SQ24rs1b0qs46qO+KbxXqJ1gtNV+lohxGmP0FLy1jWyks/1F+MhFA5ou5yNZrdxSwH3f
         NEjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWtXRV9vGvzrputNTNzRJEnfVCNYznD5ZyN6G79t9Um9BF3tKEN
	pXOPJFlBiggk9aVNsfzPw9I=
X-Google-Smtp-Source: APXvYqw7+woNdpKirYYB5wX0NsvK+lZYEYpeR7sL0WU8WkszHaDfm7rSFNKuS+TYzHZvd2ymvnV5Yw==
X-Received: by 2002:a17:906:3f91:: with SMTP id b17mr13146377ejj.74.1565272246091;
        Thu, 08 Aug 2019 06:50:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7a05:: with SMTP id d5ls23316311ejo.13.gmail; Thu,
 08 Aug 2019 06:50:45 -0700 (PDT)
X-Received: by 2002:a17:907:20a6:: with SMTP id pw6mr13217530ejb.111.1565272245479;
        Thu, 08 Aug 2019 06:50:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565272245; cv=none;
        d=google.com; s=arc-20160816;
        b=tKNV2ZItOphIpuYfJVbmVdC2Jc1rAZ+yo4EfrELPfavwGh2ZevpECwhRVSh1YK+VI1
         RgGdJ214zEO2pDAjv6njmxUd/pR7sx/cH4MMwwyZoNsSLlqiblt5dJNp/FHV+BeRi9wF
         hEBEWQiNfwnCc9wh7WbpkAuCP0kjk4+eLvknCoK1MC7lvtbbpn/d1AjDSse+CE1KjZDH
         Oax3RFK/Z/KzyvNkGb3+gPFoagdhutyyeNndiJyM//HrEDBbRLtC5rnEoPgp4/JhqNSz
         LbRXSD35dC2PSpcL4V5R7c+qR12A6+gsb8+LKkEsqeTHPl1c+c45XpPmcLOSyMpuO8WF
         tmFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=tufBRt3P+EuxEuI2pjNG6+/RV3b6Ua59haN5tEaIpOM=;
        b=jmsRG/WZgtVJEP702Y8CNZmE3PAIow8xR7f/uvr8hgT7g4m9k8a0JrIBQhRL8WTiOz
         DclJjbuaTocnFZAmwWZR01590OmJcArVYpu4JI9FSRQcSiEfSetmByPtj8bTrb8YDQIh
         YL5GnIp2cqsiMmbUTTJ4Xxjao5zIiHvZveQiQ3bSRu3bxOHRfMntutC3bsTZNa46O1sV
         OFVypkY+4Bm0lQPgR7NsUeABo80fY7URDsLWnXbypkD4Rlie89ObIDQGcq79EehE2mQV
         /V9AQM8phCRPxkIbmE23elVyfHT/yerv9A5zAjnRiM47BoFMVRYfToPlnLOT9D8wVMlq
         HILg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s30si2117185eda.4.2019.08.08.06.50.45
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Aug 2019 06:50:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 843FE15A2;
	Thu,  8 Aug 2019 06:50:44 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4B4873F694;
	Thu,  8 Aug 2019 06:50:43 -0700 (PDT)
Date: Thu, 8 Aug 2019 14:50:37 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190808135037.GA47131@lakrids.cambridge.arm.com>
References: <20190731071550.31814-1-dja@axtens.net>
 <20190731071550.31814-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190731071550.31814-2-dja@axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi Daniel,

This is looking really good!

I spotted a few more things we need to deal with, so I've suggested some
(not even compile-tested) code for that below. Mostly that's just error
handling, and using helpers to avoid things getting too verbose.

On Wed, Jul 31, 2019 at 05:15:48PM +1000, Daniel Axtens wrote:
> +void kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
> +{
> +	unsigned long shadow_alloc_start, shadow_alloc_end;
> +	unsigned long addr;
> +	unsigned long page;
> +	pgd_t *pgdp;
> +	p4d_t *p4dp;
> +	pud_t *pudp;
> +	pmd_t *pmdp;
> +	pte_t *ptep;
> +	pte_t pte;
> +
> +	shadow_alloc_start = ALIGN_DOWN(
> +		(unsigned long)kasan_mem_to_shadow(area->addr),
> +		PAGE_SIZE);
> +	shadow_alloc_end = ALIGN(
> +		(unsigned long)kasan_mem_to_shadow(area->addr + area->size),
> +		PAGE_SIZE);
> +
> +	addr = shadow_alloc_start;
> +	do {
> +		pgdp = pgd_offset_k(addr);
> +		p4dp = p4d_alloc(&init_mm, pgdp, addr);
> +		pudp = pud_alloc(&init_mm, p4dp, addr);
> +		pmdp = pmd_alloc(&init_mm, pudp, addr);
> +		ptep = pte_alloc_kernel(pmdp, addr);
> +
> +		/*
> +		 * The pte may not be none if we allocated the page earlier to
> +		 * use part of it for another allocation.
> +		 *
> +		 * Because we only ever add to the vmalloc shadow pages and
> +		 * never free any, we can optimise here by checking for the pte
> +		 * presence outside the lock. It's OK to race with another
> +		 * allocation here because we do the 'real' test under the lock.
> +		 * This just allows us to save creating/freeing the new shadow
> +		 * page in the common case.
> +		 */
> +		if (!pte_none(*ptep))
> +			continue;
> +
> +		/*
> +		 * We're probably going to need to populate the shadow.
> +		 * Allocate and poision the shadow page now, outside the lock.
> +		 */
> +		page = __get_free_page(GFP_KERNEL);
> +		memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +		pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> +
> +		spin_lock(&init_mm.page_table_lock);
> +		if (pte_none(*ptep)) {
> +			set_pte_at(&init_mm, addr, ptep, pte);
> +			page = 0;
> +		}
> +		spin_unlock(&init_mm.page_table_lock);
> +
> +		/* catch the case where we raced and don't need the page */
> +		if (page)
> +			free_page(page);
> +	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
> +

From looking at this for a while, there are a few more things we should
sort out:

* We need to handle allocations failing. I think we can get most of that
  by using apply_to_page_range() to allocate the tables for us.

* Between poisoning the page and updating the page table, we need an
  smp_wmb() to ensure that the poison is visible to other CPUs, similar
  to what __pte_alloc() and friends do when allocating new tables.

* We can use the split pmd locks (used by both x86 and arm64) to
  minimize contention on the init_mm ptl. As apply_to_page_range()
  doesn't pass the corresponding pmd in, we'll have to re-walk the table
  in the callback, but I suspect that's better than having all vmalloc
  operations contend on the same ptl.

I think it would make sense to follow the style of the __alloc_p??
functions and factor out the actual initialization into a helper like:

static int __kasan_populate_vmalloc_pte(pmd_t *pmdp, pte_t *ptep)
{
	unsigned long page;
	spinlock_t *ptl;
	pte_t pte;

	page = __get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
	pte = pfn_pte(page_to_pfn(page), PAGE_KERNEL);

	/*
	 * Ensure poisoning is visible before the shadow is made visible
	 * to other CPUs.
	 */
	smp_wmb();
	
	ptl = pmd_lock(&init_mm, pmdp);
	if (likely(pte_none(*ptep))) {
		set_pte(ptep, pte)
		page = 0;
	}
	spin_unlock(ptl);
	if (page)
		free_page(page);
	return 0;
}

... with the apply_to_page_range() callback looking a bit like
alloc_p??(), grabbing the pmd for its ptl.

static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr, void *unused)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;

	if (likely(!pte_none(*ptep)))
		return 0;

	pgdp = pgd_offset_k(addr);
	p4dp = p4d_offset(pgdp, addr)
	pudp = pud_pffset(p4dp, addr);
	pmdp = pmd_offset(pudp, addr);

	return __kasan_populate_vmalloc_pte(pmdp, ptep);
}

... and the main function looking something like:

int kasan_populate_vmalloc(...)
{
	unsigned long shadow_start, shadow_size;
	unsigned long addr;
	int ret;

	// calculate shadow bounds here
	
	ret = apply_to_page_range(&init_mm, shadow_start, shadow_size,
				  kasan_populate_vmalloc_pte, NULL);
	if (ret)
		return ret;
	
	...

	// unpoison the new allocation here
}

> +	kasan_unpoison_shadow(area->addr, requested_size);
> +
> +	/*
> +	 * We have to poison the remainder of the allocation each time, not
> +	 * just when the shadow page is first allocated, because vmalloc may
> +	 * reuse addresses, and an early large allocation would cause us to
> +	 * miss OOBs in future smaller allocations.
> +	 *
> +	 * The alternative is to poison the shadow on vfree()/vunmap(). We
> +	 * don't because the unmapping the virtual addresses should be
> +	 * sufficient to find most UAFs.
> +	 */
> +	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
> +	kasan_poison_shadow(area->addr + requested_size,
> +			    area->size - requested_size,
> +			    KASAN_VMALLOC_INVALID);
> +}

Is it painful to do the unpoison in the vfree/vunmap paths? I haven't
looked, so I might have missed something that makes that nasty.

If it's possible, I think it would be preferable to do so. It would be
consistent with the non-vmalloc KASAN cases. IIUC in that case we only
need the requested size here (and not the vmap_area), so we could just
take start and size as arguments.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190808135037.GA47131%40lakrids.cambridge.arm.com.
