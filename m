Return-Path: <kasan-dev+bncBDV37XP3XYDRBINTTTWQKGQEMSK5BFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 682E7D925A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 15:22:42 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id f63sf979690wma.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 06:22:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571232162; cv=pass;
        d=google.com; s=arc-20160816;
        b=MHHqcx/5wsOMIH4rtqLig5DP7iDuemYAi/WrPojvUqg0gLPyOpfwtBrK+/ihpAbbfp
         9/8mkX5XyxMcEEd70r7z8ApuZEGqcjO5sZI/Lpz+Pi8pbCWTev6W3lD/mmha6F0nkGGV
         Q7poziS3pEesQR/bP0fENrb98s1fKmwHNEt8zXqKtkavfIvG2rb5Vl9npC5ED2p0Kf/r
         Ji0a6S+lP5lM3xuAitbyRIsQf73QzFyBCwIsmIFJwGUJHyal8lGYh8PJKsfrJyxRU0hU
         JXRuVcnOEVLaczXqgIKvg0LWqC0/Crgfli/H85h6fQXdHyWughHRvZ2eS5otGRK88JEG
         6zyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=g0RVaZ1wpIbssrNmd8tEWdYyU7xQUFLDUWfD4NV0xPE=;
        b=cUqo/B3JqEn8lOMlGYIAzSOxzLfSj0Nnktt5CrtonZKI4C6DD7KgV+WKcxKUTeLvkN
         s/sOm80l/emx5JO/vBzN56Dy7fDli3Q4IzhQ4gxDisDWZqZW4mkgBYFsmUaYse9zUocF
         jfl8QhRYJiQ6UopWltCE4AFckTB5iAHaJqeqgCC4vGK2GCim10sb+0BGcPPSLqWMObWH
         81juNo6OXxAD/c2sKT1paXd0rONRNZJRxmifvDrbpQFlV59WjiNSInMMwDU47p6KfKaX
         V4zgMARascj8hjeXoRotqPAUnlal1V+/mjvZKGN79SJFHLP8Pmjy9WBT0tEw0heLeg/h
         Ojow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g0RVaZ1wpIbssrNmd8tEWdYyU7xQUFLDUWfD4NV0xPE=;
        b=nV/BpD8qkXQ3MIgYRUHL0O4kigx1EiXxyjKxtiHa4AEDwctSoujP6WCO1/dsjTnVj2
         PgwNbPLe3AeBib/o8R8nKhi0YdbnTqHJdq7vbvl8k1DkyGUDMVJrLxabJ3f63Z1HXpCL
         q0Q+RZ0soNEnsX5t1+bUQTws3L+2p0eNAKG9C9yPn45z5Bi1NFdGPehdRpw7C9cTkjDE
         WL7DgoLwkW6/7nDsY7Th67lfrWbpzTV39iVVeyaEBkJgapcTsKDoPpn8sU8xX9/wpnDb
         JPPmTOT5kweSblElsB1u+XGvDUOLBPmpj0olasSek+8uTUKzaDXchOH0nAd1vry4U81X
         PUHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g0RVaZ1wpIbssrNmd8tEWdYyU7xQUFLDUWfD4NV0xPE=;
        b=AQdNF4nO0kAkyHYR5TLWm5u7eST/XcXW3vzYypt7seaA+ID/Nq0nFwYCWrlW9o5d+N
         JStZaJlhftyAMoqFJtu83Yb0QTYPj9ACdiRJY/5Jox25rweSImCo12IseRqtVWiUCrfx
         8dE2lgastsbvbckpuY6P9Z3/hAquluCO3UrT9JMOf/CweVQcj4KNroyjiRqelMRR7eSB
         QFVrrrtIdCJvch8i2vcRq/Lq2NDTrw9eeabPlodI2jfICiHVBYI6kUuf41TSwkHk27H5
         ToMBjDo14fJDuK496IF+N/anXoe3i9DWjKsgMZmbWonWBmebXp5zUqlEz78ZNELzYHAV
         e8Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXiTdv0Kg8xW1+ILpCV386XrUquD/XQGPOlAxMghPGGfVR5xMBp
	OtJSHk225sGcIVS38413gDE=
X-Google-Smtp-Source: APXvYqzhf6afjZLU+rDtxhB9/7GAv3lOscXsnxxnTMEw2hRVGwEEBWAKgDrrJfwZw/asg82MZ2v9Fg==
X-Received: by 2002:adf:f343:: with SMTP id e3mr1631241wrp.315.1571232162121;
        Wed, 16 Oct 2019 06:22:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c408:: with SMTP id v8ls8282122wrf.10.gmail; Wed, 16 Oct
 2019 06:22:41 -0700 (PDT)
X-Received: by 2002:a5d:6a4e:: with SMTP id t14mr2830309wrw.286.1571232161311;
        Wed, 16 Oct 2019 06:22:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571232161; cv=none;
        d=google.com; s=arc-20160816;
        b=uuoUmMVRIFWYwOAblJGv39hLYtkl552VHwWTs5t06zUI1aJHP4fOlBBfhjzTNZwyKy
         kRMa/DOiq/o6kb/IP/o4tbXsPvGmErty+F4P11YzzUDPCU9YLZ0VouUPkCgBKvoyhyZE
         kqWPwmJUMWRYc/U5Wq6zkpPANkKppTdSOUG3ZqdiDElEdel+TipAFucCmsKYLBdVDSSE
         rQGD73QPpJueZ0H2TAaMCw7ftHrWZDa69Ii8UZJdnnmyovDQPS/Gu+Oz0e3aCYsLj34t
         +pyOibjLjREe8OnKB60eqS/fZchKkv+8rApbpX+czTFG96u6ZNYgCJ5iX2Rvn80ASRgb
         hLTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=NAIRkKt/Gtrtj9U/pnfETSk/2UXH3BaWY/3T2IH5YA0=;
        b=oxnsSFx57yVnXy0Xx8u4R1885SXpDbDdedPSQKjliNcOVQXPmBFp/NkrizrtciUJjp
         BhflNxTM1oRqe7ojFis5YQjKuU4cvkpctbm7wmLomzZLhfx8kt/37fZJVx9T2OooMgCw
         ieTMwbf7a4JUachsaAiVe+nNXSMV9Hd7fZA/JZXwJ7e/BEpzMteZMLJaWlWn3CWHhbl8
         NhDlrHQ9HmSuipm0Xurxh3BV38xrZTY4vgp9WslWxZgxldGfp0wvPcLJ76SyzR2I2j9c
         KRsjh9CyMy/vKcfaI3jRm4EGWPCcXRyoIhUdiIJuaVp/elbJ0cf3VNLtn5AAREM5qsz/
         8nAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l3si331620wmg.0.2019.10.16.06.22.41
        for <kasan-dev@googlegroups.com>;
        Wed, 16 Oct 2019 06:22:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 69FD8142F;
	Wed, 16 Oct 2019 06:22:40 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8962B3F68E;
	Wed, 16 Oct 2019 06:22:38 -0700 (PDT)
Date: Wed, 16 Oct 2019 14:22:33 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, x86@kernel.org, glider@google.com,
	luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com,
	christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191016132233.GA46264@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
 <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
 <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
 <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of mark.rutland@arm.com designates
 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi Andrey,

On Wed, Oct 16, 2019 at 03:19:50PM +0300, Andrey Ryabinin wrote:
> On 10/14/19 4:57 PM, Daniel Axtens wrote:
> >>> +	/*
> >>> +	 * Ensure poisoning is visible before the shadow is made visible
> >>> +	 * to other CPUs.
> >>> +	 */
> >>> +	smp_wmb();
> >>
> >> I'm not quite understand what this barrier do and why it needed.
> >> And if it's really needed there should be a pairing barrier
> >> on the other side which I don't see.
> > 
> > Mark might be better able to answer this, but my understanding is that
> > we want to make sure that we never have a situation where the writes are
> > reordered so that PTE is installed before all the poisioning is written
> > out. I think it follows the logic in __pte_alloc() in mm/memory.c:
> > 
> > 	/*
> > 	 * Ensure all pte setup (eg. pte page lock and page clearing) are
> > 	 * visible before the pte is made visible to other CPUs by being
> > 	 * put into page tables.
> > 	 *
> > 	 * The other side of the story is the pointer chasing in the page
> > 	 * table walking code (when walking the page table without locking;
> > 	 * ie. most of the time). Fortunately, these data accesses consist
> > 	 * of a chain of data-dependent loads, meaning most CPUs (alpha
> > 	 * being the notable exception) will already guarantee loads are
> > 	 * seen in-order. See the alpha page table accessors for the
> > 	 * smp_read_barrier_depends() barriers in page table walking code.
> > 	 */
> > 	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
> > 
> > I can clarify the comment.
> 
> I don't see how is this relevant here.

The problem isn't quite the same, but it's a similar shape. See below
for more details.

> barrier in __pte_alloc() for very the following case:
> 
> CPU 0							CPU 1
> __pte_alloc():                                          pte_offset_kernel(pmd_t * dir, unsigned long address):
>      pgtable_t new = pte_alloc_one(mm);                        pte_t *new = (pte_t *) pmd_page_vaddr(*dir) + ((address >> PAGE_SHIFT) & (PTRS_PER_PAGE - 1));  
>      smp_wmb();                                                smp_read_barrier_depends();
>      pmd_populate(mm, pmd, new);
> 							/* do something with pte, e.g. check if (pte_none(*new)) */
> 
> 
> It's needed to ensure that if CPU1 sees pmd_populate() it also sees initialized contents of the 'new'.
> 
> In our case the barrier would have been needed if we had the other side like this:
> 
> if (!pte_none(*vmalloc_shadow_pte)) {
> 	shadow_addr = (unsigned long)__va(pte_pfn(*vmalloc_shadow_pte) << PAGE_SHIFT);
> 	smp_read_barrier_depends();
> 	*shadow_addr; /* read the shadow, barrier ensures that if we see installed pte, we will see initialized shadow memory. */
> }
> 
> 
> Without such other side the barrier is pointless.

The barrier isn't pointless, but we are relying on a subtlety that is
not captured in LKMM, as one of the observers involved is the TLB (and
associated page table walkers) of the CPU.

Until the PTE written by CPU 0 has been observed by the TLB of CPU 1, it
is not possible for CPU 1 to satisfy loads from the memory that PTE
maps, as it doesn't yet know which memory that is.

Once the PTE written by CPU has been observed by the TLB of CPU 1, it is
possible for CPU 1 to satisfy those loads. At this instant, CPU 1 must
respect the smp_wmb() before the PTE was written, and hence sees zeroes
written before this. Note that if this were not true, we could not
safely swap userspace memory.

There is the risk (as laid out in [1]) that CPU 1 attempts to hoist the
loads of the shadow memory above the load of the PTE, samples a stale
(faulting) status from the TLB, then performs the load of the PTE and
sees a valid value. In this case (on arm64) a spurious fault could be
taken when the access is architecturally performed.

It is possible on arm64 to use a barrier here to prevent the spurious
fault, but this is not smp_read_barrier_depends(), as that does nothing
for everyone but alpha. On arm64 We have a spurious fault handler to fix
this up.

Thanks,
Mark.

[1] https://lore.kernel.org/linux-arm-kernel/20190827131818.14724-1-will@kernel.org/
[2] https://lore.kernel.org/linux-mm/20191014152717.GA20438@lakrids.cambridge.arm.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016132233.GA46264%40lakrids.cambridge.arm.com.
