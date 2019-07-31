Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCPNQTVAKGQE7S35BSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E6937B9BA
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 08:34:51 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id t196sf57253051qke.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2019 23:34:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564554890; cv=pass;
        d=google.com; s=arc-20160816;
        b=ae17iCLn9BJi3GCn+HHJP5qBD8+MX+Sv2ls2/ONgQt5VzGH3ol+sZ+SLRr+qFNWmBe
         thx6DbWomia3b09PpVi9qYWTbbz/wKvHRP6jfWgjHtbUHL2rlKbIqfi7EwQHNmLewCLQ
         FFVaJjLzK/pQzgvcmACLpQ6JjEXIQ2jzpmKyWyg5PAnhOadIy9A7J+UQGROnVPfB5S2u
         adNQ/5MNu3dfC1/Il9WLfl3dSbecsE+5RbxUZya0Ox91vGl5gt2y+sD5OZPg5H9uDqMt
         kYbEvANnMMafh/J1CIvzcFSMGGlWilGTMKoHCOHb66Ppdb4yLdRjr8gjA3HtDZ/ArSC0
         XzuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=lShzkgh2gpOZ1/KvorQW7GrPbWBa/OqM+P8v8LpAE+Q=;
        b=BA1OIY3t99BEEs7+LLeA4dEhyj2US7X3OwcW0zHyD29xXXfEqb+tM5xBKTKaiRsDn/
         lt/0DNQRAHTVo5Mm7WuT9qc7MPmORJ6iVEJc7aki6RhJqKrBZS6mam879qpQtFCKx2y2
         XChQt6IaeMmnhzLdGhKUIs/4BgcJ3RJP+lP7JbDBnliiVL6+rUNhooz9AWU9CHJHCW/d
         brtGH/s+FYxRQPeFnpeVBs4joHlRwOwHAPFjlIfZS37uSydx5poUOskGkXoeuz99kBw8
         dtdMPSzc8YH3z/yz2F4wENfNUSa2EPoSoDdgs1lIEAeXl2yTKLdt9FUcsQswmqGbj3ku
         IUOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="FDcn/+VG";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lShzkgh2gpOZ1/KvorQW7GrPbWBa/OqM+P8v8LpAE+Q=;
        b=N1td/24h0Mnl9mOdk1Wmjp89Ro292i470lQ6orBB4+Ni8WvAm0wEBHtrKsoAeFCeAQ
         GTWkbdrLQ0E/9TJjmhN0DARb84m+Jnwa60ADXnKl3SSAyleBAOTeThMksIRcc1cgj+WD
         XaTY7ZzrqkhXyk8YRdqd/AFu6e6f10W2CSbBsUEjfvpMjkun3yEgpUIdBcuqSB62wuH3
         iRrC6Ua/l1a6HnpAACufceEtjrxsF75ijKmfG46q+bHjt+IXyCvYv4E5l8aS6KFG1gxv
         472/lcdqTmvgEuotfUDcEtGAfSVRVL3wAlFGn9eyitM18kdVMqxP3pb8m4Bu8L6YA+1l
         j0zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lShzkgh2gpOZ1/KvorQW7GrPbWBa/OqM+P8v8LpAE+Q=;
        b=ESGVWHCusXX847h1IuQ/IbrJZJPUA+mSmHky1nxnHiEW3wS8ReRTGBViCSm3Jd27yf
         8Rc/TKIPc1TEhdpyf5ICrkZxv6tCTMIcP4RQhNpP1RpN+MW8ouUWWalo1W9OWTH74G1f
         yA2nMAfNHQfeC+fnvh9w1seK/Wqw8lz4SkmNWBLcoY1RQ+FiuddLQ2V7izz2MdXLekgu
         +2mdsuCPOJoR654gaGo15L+TCFFESsItC7zYD/L7/R1GVLt/x+W2rdxmHxV3aNBVteL6
         zlJVF9V5fTQqzx/dEGBhizaHR5ks51pr7a895wm4p1f//TQdD0qe0wAtJSbt1siCa9pz
         fGaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUHIgy+jEyGAPNgpZp4k0HiKRipSgVLbCzWn1MbI0zmilTymxCM
	Bg+dodpoGWSsvXPIkD9wYaQ=
X-Google-Smtp-Source: APXvYqzYvQvYs1t2L+gRAWyfEy93MYy3vWRg07BArwZLUuKMfQKPWagsDjSr4leW35dInAq52gOwJg==
X-Received: by 2002:a0c:b90a:: with SMTP id u10mr86612961qvf.201.1564554889903;
        Tue, 30 Jul 2019 23:34:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8684:: with SMTP id i126ls61403qkd.8.gmail; Tue, 30 Jul
 2019 23:34:49 -0700 (PDT)
X-Received: by 2002:ae9:ef06:: with SMTP id d6mr78594559qkg.157.1564554889575;
        Tue, 30 Jul 2019 23:34:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564554889; cv=none;
        d=google.com; s=arc-20160816;
        b=P8r4Be0jYL37nUoFiXBRPZIa1AiZ5B1X0E99fASgvjp2ESFkC7YbiyAmoMNYssqp/+
         AKfm0Ky2K1aHEYwJUK1UCImn6SMsdFIv3HKZh2JkmewrL0NzBHbMd6W5INtlwInglI1J
         rqAs521Wcxi4ADPEfQT96NDgzBUCFpBhHM0qu8lzFohYvxsLu3o8m9hzde2NbIfwAyte
         hqi5MGBX1mwppsMmlL0l5v/gFOrNHreWOxaR7iIjKlWhc8mWbuSqjvcqfhJi8VwIX3PC
         DqoupBlAoYctuDbInEJMdzCQPxCOibv8jtcTumMWVGKcE1myBKDdb/2aK0CgI9petuhM
         vk5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=5/aeGLYPf40z7c7ppyzA+em+8QsWfsCwbNPz1NrmSfc=;
        b=hXbRQ2KCS1PZ/Utkf4i6HHO0SYWuMiIQGg+Oaq9RXurmPOoO7IoFUlJR7RhMp3xZ9u
         n0qvLKP/eof/dpaUpjP8eWubtuk2JHalWMNDGstyBH2nr7OlYpR6oLRBsBL99DRa3t4j
         s0NYUQsYiJ0CQ3Zavzt2o7Em3UrmclLoIRhOwi4YhPM7u7Rc1sUuesjJH8FTv+ppjy0y
         AytbNzcbmFVRFjYOoHcbkzPGS3Gx1KVDM5ah57DIghW8LMJv1wp283epZ3p3te2+fc5I
         ewBrfBl8lSIzApK6oxxzGJUKhEwYriHV7QM73dZS/+p4wog26L8bqv/luQQn5K3STS65
         ydqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="FDcn/+VG";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id r4si2925937qkb.1.2019.07.30.23.34.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jul 2019 23:34:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id p184so31267596pfp.7
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2019 23:34:49 -0700 (PDT)
X-Received: by 2002:a17:90a:c68c:: with SMTP id n12mr1286047pjt.29.1564554888522;
        Tue, 30 Jul 2019 23:34:48 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id e11sm80266144pfm.35.2019.07.30.23.34.46
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 30 Jul 2019 23:34:47 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v2 1/3] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <877e7zhq7c.fsf@dja-thinkpad.axtens.net>
References: <20190729142108.23343-1-dja@axtens.net> <20190729142108.23343-2-dja@axtens.net> <20190729154426.GA51922@lakrids.cambridge.arm.com> <877e7zhq7c.fsf@dja-thinkpad.axtens.net>
Date: Wed, 31 Jul 2019 16:34:42 +1000
Message-ID: <871ry6hful.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="FDcn/+VG";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Daniel Axtens <dja@axtens.net> writes:

> Hi Mark,
>
> Thanks for your email - I'm very new to mm stuff and the feedback is
> very helpful.
>
>>> +#ifndef CONFIG_KASAN_VMALLOC
>>>  int kasan_module_alloc(void *addr, size_t size)
>>>  {
>>>  	void *ret;
>>> @@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
>>>  	if (vm->flags & VM_KASAN)
>>>  		vfree(kasan_mem_to_shadow(vm->addr));
>>>  }
>>> +#endif
>>
>> IIUC we can drop MODULE_ALIGN back to PAGE_SIZE in this case, too.
>
> Yes, done.
>
>>>  core_initcall(kasan_memhotplug_init);
>>>  #endif
>>> +
>>> +#ifdef CONFIG_KASAN_VMALLOC
>>> +void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area)
>>
>> Nit: I think it would be more consistent to call this
>> kasan_populate_vmalloc().
>>
>
> Absolutely. I didn't love the name but just didn't 'click' that populate
> would be a better verb.
>
>>> +{
>>> +	unsigned long shadow_alloc_start, shadow_alloc_end;
>>> +	unsigned long addr;
>>> +	unsigned long backing;
>>> +	pgd_t *pgdp;
>>> +	p4d_t *p4dp;
>>> +	pud_t *pudp;
>>> +	pmd_t *pmdp;
>>> +	pte_t *ptep;
>>> +	pte_t backing_pte;
>>
>> Nit: I think it would be preferable to use 'page' rather than 'backing',
>> and 'pte' rather than 'backing_pte', since there's no otehr namespace to
>> collide with here. Otherwise, using 'shadow' rather than 'backing' would
>> be consistent with the existing kasan code.
>
> Not a problem, done.
>
>>> +	addr = shadow_alloc_start;
>>> +	do {
>>> +		pgdp = pgd_offset_k(addr);
>>> +		p4dp = p4d_alloc(&init_mm, pgdp, addr);
>>> +		pudp = pud_alloc(&init_mm, p4dp, addr);
>>> +		pmdp = pmd_alloc(&init_mm, pudp, addr);
>>> +		ptep = pte_alloc_kernel(pmdp, addr);
>>> +
>>> +		/*
>>> +		 * we can validly get here if pte is not none: it means we
>>> +		 * allocated this page earlier to use part of it for another
>>> +		 * allocation
>>> +		 */
>>> +		if (pte_none(*ptep)) {
>>> +			backing = __get_free_page(GFP_KERNEL);
>>> +			backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
>>> +					      PAGE_KERNEL);
>>> +			set_pte_at(&init_mm, addr, ptep, backing_pte);
>>> +		}
>>
>> Does anything prevent two threads from racing to allocate the same
>> shadow page?
>>
>> AFAICT it's possible for two threads to get down to the ptep, then both
>> see pte_none(*ptep)), then both try to allocate the same page.
>>
>> I suspect we have to take init_mm::page_table_lock when plumbing this
>> in, similarly to __pte_alloc().
>
> Good catch. I think you're right, I'll add the lock.
>
>>> +	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
>>> +
>>> +	kasan_unpoison_shadow(area->addr, requested_size);
>>> +	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
>>> +	kasan_poison_shadow(area->addr + requested_size,
>>> +			    area->size - requested_size,
>>> +			    KASAN_VMALLOC_INVALID);
>>
>> IIUC, this could leave the final portion of an allocated page
>> unpoisoned.
>>
>> I think it might make more sense to poison each page when it's
>> allocated, then plumb it into the page tables, then unpoison the object.
>>
>> That way, we can rely on any shadow allocated by another thread having
>> been initialized to KASAN_VMALLOC_INVALID, and only need mutual
>> exclusion when allocating the shadow, rather than when poisoning
>> objects.

I've come a bit unstuck on this one. If a vmalloc address range is
reused, we can end up with the following sequence:

 - p = vmalloc(PAGE_SIZE) allocates ffffc90000000000

 - kasan_populate_shadow allocates a shadow page, fills it with
   KASAN_VMALLOC_INVALID, and then unpoisions
   PAGE_SIZE >> KASAN_SHADOW_SHIFT_SIZE bytes

 - vfree(p)

 - p = vmalloc(3000) also allocates ffffc90000000000 because of address
   reuse in vmalloc.

 - Now kasan_populate_shadow doesn't allocate a page, so does no
   poisioning.

 - kasan_populate_shadow unpoisions 3000 >> KASAN_SHADOW_SHIFT_SIZE
   bytes, but the PAGE_SIZE-3000 extra bytes are still unpoisioned, so
   accesses that are out-of-bounds for the 3000 byte allocation are
   missed.

So I think we do need to poision the shadow of the [requested_size,
area->size) region each time. However, I don't think we need mutual
exclusion to be able to do this safely. I think the safety is guaranteed
by vmalloc not giving the same page to multiple allocations. Because no
two threads are going to get overlapping vmalloc/vmap allocations, their
shadow ranges are not going to overlap, and so they're not going to
trample over each other.

I think it's probably still worth poisioning the pages on allocation:
for one thing, you are right that part of the shadow page will not be
poisioned otherwise, and secondly it means you migh get a kasan splat
before you get a page-not-present fault if you access beyond an
allocation, at least if the shadow happens to fall helpfully within an
already-allocated page.

v3 to come soon.

Regards,
Daniel

>
> Yes, that makes sense, will do.
>
> Thanks again,
> Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871ry6hful.fsf%40dja-thinkpad.axtens.net.
