Return-Path: <kasan-dev+bncBDV37XP3XYDRBZFI7TUQKGQEWNSSMTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0113878FB1
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 17:44:37 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id c18sf13505533lji.19
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 08:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564415076; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRzBEk+IuykzdWly57siSb/gfSzp4izhJIVdg3poW0N0pCfoj3/bQxquWNHzCBaoWN
         Uv0u5tdGxv0Uu2yy/aipGbCUMtyRrXhZgXPwhtDfPmUanENqApix5s1ambWVdJARVSII
         S8NOUa5GZ/dUeCmQCQH4rpqYM+FyYjpz91TzEy+0+zWDTbow6MStvpIeOg3Pc8c+xqgi
         vS3oqlhaqCrflh2WLdn7iADU59xHkTewVZrCj9DGhkFIJ2p9jJffd1FAnW6tIO6P48wz
         dLkGQdwG2lzQJX50pviKlg3cDbEQ0lirO+LfTo+Hmgv9tiNE8/MI906Dm7E6ptJi09IV
         AwwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sMx0h/5bVSW6IsUzzE1rFLmgt3RA6P57YxSEBdTzx3Y=;
        b=Nu8cj7fkUrV657lu0kIC+eXvsiYbVqWarDf9PrHAvyp1joHig9K9ngiQb1L6yIkMAv
         yygKe4fR60BUEJhLiRZrbUwCCfeQnEShJ9exPb7om3VlhS6lJ4LdK2gNwI0CBvlyjPld
         f/OSUvO9MqI12fieGk6ad4dhUsJqb3hGpnc5n/K5GBvMVjpr8bm4p1rlwXLG2XlFAaHm
         kp5y+7dbEuHPa7tZfG4Rsz9eD7NAx3RPlXPQFjcfC64nSVVDUpxbW7+nWd8k6aG8i0WW
         CBVKpA9tDXdiSRHysm2GpY50octpy0uz5A0cI11CkrOFqGr539cY8QNuzz73OdyhJcAA
         VQ3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sMx0h/5bVSW6IsUzzE1rFLmgt3RA6P57YxSEBdTzx3Y=;
        b=sZVOCFtChH8qtOAviYEbPJzNAA17fEjkb94vsh4pN2HbVLjSWAPJ8vnNrcUD9H98hX
         oazL8YdfP4Fnl5GrmLptHZmUNa59Jztq0G89dmEWnsd8Kx1mIGct+rlxuexdYgR0tG5q
         FcOc0jc8xIu4Qroh/5dLDzfi2a/HSBHJkLLE2E/A9w+0hLNBfJSByCUsFoUGVsR6CDbW
         0DMAErkNSPVbAR7wsYlzJgJT3ZBGoICJ6Vhb2sEZWVjPBCKlmjYoiZs9iCRL4fCsKc9Z
         0PoLX2atdgPCvIvXXzaUYxBsfPMuH1MM6D7qlcEvHMJpu1yDit43VeqmYhpW05Rd50wQ
         ktQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sMx0h/5bVSW6IsUzzE1rFLmgt3RA6P57YxSEBdTzx3Y=;
        b=FBo+x4cl2HbFCQilzBtbtovpTdIB84a4USnchWDh52u9V+/NTNQDxEYWSrqJLmS1FK
         v1kc3YrRJn5+JggCVfFqrwvMur2+rpf3XO309LnLlE5/n9rDto8pdhNbpkUzWu4BFxWH
         tc5+64Vuf1VAF1n0PFR2wQHjiW5IAtoxDipz/gvOE4uFU/IFqPGX7bk25GaPhiEObBTG
         xNnubil5fxzLyakjNPHj2qp0G5CsRC4XaymbSD5W93ey20v7J31alTwA9tLmayXSo/WV
         BriWubb+pVquboxPB7fTz+wfSZL2eZnEFKRfzS8sPm3StF3PyNS3yX6kGQzDmGhNU+x9
         iPiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVk7vb+7+pzs75LwX4jPnsvqwK1a3XqenLz4Bg5AfwvJtbZdf2x
	Jatjj2pe4HO2bL9tNHxz5GI=
X-Google-Smtp-Source: APXvYqyp75gv2EWxKulEzphz07ZEuRb6gxVM4dl4Nw4N4JMFDhcDrzfwY7XCa8+x+VgnqCd5IcxTmA==
X-Received: by 2002:a2e:9188:: with SMTP id f8mr12840064ljg.33.1564415076591;
        Mon, 29 Jul 2019 08:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:65da:: with SMTP id e87ls7004020ljf.1.gmail; Mon, 29 Jul
 2019 08:44:35 -0700 (PDT)
X-Received: by 2002:a2e:9048:: with SMTP id n8mr11636673ljg.37.1564415075820;
        Mon, 29 Jul 2019 08:44:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564415075; cv=none;
        d=google.com; s=arc-20160816;
        b=WRwiArKiD73a4N4nnsoWuxElWPFcqYaStRpxc1UWGmDgRsqPxkGW2xx2RILR1/QAWz
         qeQfGCTjAXXfnMh0o/vgrPBMi3VYfYdT8Bf4UbKePr0nehEt58md5RIyGHTU5034BxEc
         ODHcR7TuuzKcs194di37tiGQROtAEX3PQYlWizGcTRDkZAdBnsv6m8l6UDot4AymdmOS
         VKcpOKv8yNN9T0VJ/gi2O81Sg1LT/k52SnmNl+i9DByFtv0Rdiv/42/ggsxgnWJLsJyG
         hSP2fQnIxU1lPxUF66wKlR19vwQaWFOq9cmq0IVaGIvsJcw14i4SRXHz7X0rSK7j7JW7
         U5lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4w0NvDQJHYunFbzTs84/ma+toZ+YlE3yjMHTTx7zgK0=;
        b=NPd5byTIufeStqef7MXP9t3n73Bulwe7olPRhsLczJR0tbYI3S6XpuY/HAiLS0Vnwt
         b98GM3Zf04+os6G3WIZOS8T6VmTdZl8/h541RE1oUuk8ZLYv9kd0n9R1tjXg0Noxn2Dh
         qdCZgs+W3Ccjurvr3Wi3+R8xR6Z36Qo2uhSLyjhmWLVH3cPL9ySHbUDj6FBGJPw556Dd
         Bdl+eRY56RoENvCVJB3SA+VK2pA7cIrsREnivHWzEYygNR6iFjt2SQJMvohOVRHzvrIc
         juEQq4CCIYjW62Vl8Mr1riUs42v4MGdVK+mb3aRsXu2ApIwK6X7PG8IxUclDGeuOqI7W
         Q+9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z18si2672173lfh.1.2019.07.29.08.44.33
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Jul 2019 08:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1FD8337;
	Mon, 29 Jul 2019 08:44:32 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 86A4B3F694;
	Mon, 29 Jul 2019 08:44:31 -0700 (PDT)
Date: Mon, 29 Jul 2019 16:44:26 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v2 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190729154426.GA51922@lakrids.cambridge.arm.com>
References: <20190729142108.23343-1-dja@axtens.net>
 <20190729142108.23343-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190729142108.23343-2-dja@axtens.net>
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

On Tue, Jul 30, 2019 at 12:21:06AM +1000, Daniel Axtens wrote:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate
> a backing page the first time a mapping in vmalloc space uses a
> particular page of the shadow region. Keep this page around
> regardless of whether the mapping is later freed - in the mean time
> the page could have become shared by another vmalloc mapping.
> 
> This can in theory lead to unbounded memory growth, but the vmalloc
> allocator is pretty good at reusing addresses, so the practical memory
> usage grows at first but then stays fairly stable.
> 
> This requires architecture support to actually use: arches must stop
> mapping the read-only zero page over portion of the shadow region that
> covers the vmalloc space and instead leave it unmapped.
> 
> This allows KASAN with VMAP_STACK, and will be needed for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on).
> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> Signed-off-by: Daniel Axtens <dja@axtens.net>

This generally looks good, but I have a few concerns below, mostly
related to concurrency.

[...]

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..15d8f4ad581b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -568,6 +568,7 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>  	/* The object will be poisoned by page_alloc. */
>  }
>  
> +#ifndef CONFIG_KASAN_VMALLOC
>  int kasan_module_alloc(void *addr, size_t size)
>  {
>  	void *ret;
> @@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
>  	if (vm->flags & VM_KASAN)
>  		vfree(kasan_mem_to_shadow(vm->addr));
>  }
> +#endif

IIUC we can drop MODULE_ALIGN back to PAGE_SIZE in this case, too.

>  
>  extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
>  
> @@ -722,3 +724,52 @@ static int __init kasan_memhotplug_init(void)
>  
>  core_initcall(kasan_memhotplug_init);
>  #endif
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area)

Nit: I think it would be more consistent to call this
kasan_populate_vmalloc().

> +{
> +	unsigned long shadow_alloc_start, shadow_alloc_end;
> +	unsigned long addr;
> +	unsigned long backing;
> +	pgd_t *pgdp;
> +	p4d_t *p4dp;
> +	pud_t *pudp;
> +	pmd_t *pmdp;
> +	pte_t *ptep;
> +	pte_t backing_pte;

Nit: I think it would be preferable to use 'page' rather than 'backing',
and 'pte' rather than 'backing_pte', since there's no otehr namespace to
collide with here. Otherwise, using 'shadow' rather than 'backing' would
be consistent with the existing kasan code.

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
> +		 * we can validly get here if pte is not none: it means we
> +		 * allocated this page earlier to use part of it for another
> +		 * allocation
> +		 */
> +		if (pte_none(*ptep)) {
> +			backing = __get_free_page(GFP_KERNEL);
> +			backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
> +					      PAGE_KERNEL);
> +			set_pte_at(&init_mm, addr, ptep, backing_pte);
> +		}

Does anything prevent two threads from racing to allocate the same
shadow page?

AFAICT it's possible for two threads to get down to the ptep, then both
see pte_none(*ptep)), then both try to allocate the same page.

I suspect we have to take init_mm::page_table_lock when plumbing this
in, similarly to __pte_alloc().

> +	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
> +
> +	kasan_unpoison_shadow(area->addr, requested_size);
> +	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
> +	kasan_poison_shadow(area->addr + requested_size,
> +			    area->size - requested_size,
> +			    KASAN_VMALLOC_INVALID);

IIUC, this could leave the final portion of an allocated page
unpoisoned.

I think it might make more sense to poison each page when it's
allocated, then plumb it into the page tables, then unpoison the object.

That way, we can rely on any shadow allocated by another thread having
been initialized to KASAN_VMALLOC_INVALID, and only need mutual
exclusion when allocating the shadow, rather than when poisoning
objects.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729154426.GA51922%40lakrids.cambridge.arm.com.
