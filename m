Return-Path: <kasan-dev+bncBC5L5P75YUERB7NOU3WQKGQE5OZRDJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B0658DC2FE
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2019 12:44:13 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id m24sf1187630lfh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2019 03:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571395453; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEpJeNLMXI3cL38eKjLUXUxP1jMPwnnUakbItudWwWynlMfO7UsQPNy+lxUk/h1cfv
         oWFe/g1DvM5AJj6wgeodZILjOHIMfEEKVCCP2Jw/EyeL1OGA1fTTqulqQz9/IjsTcLVl
         /cvxEk2K9z5NAqHwnmE6lYbXAgr2QJ2608E8UEcpY9n4SCMKDX733p4hk5YbCmJBNjAq
         W+WjMO9TySJ7Af5G1gVx6g6SRrkoMlJccxron5r2YmfvqQJAB2kRjNUwVv6YyCDQRWSK
         afgCngAeQ15mIt7q4p40dGgqMKUiLywhphRD4vGxG8aDWcs1XPtoNng1zp9OFZO41101
         u7OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=e/B3XjNttTAhZ7JUGgGHSBTAedWDXApAoSu7FvT42qc=;
        b=u5bIzHLXN9AEjL0/DwmKqEUBTph9Z65hN78ZY2dIlyXykmm1ItF64LDm2gyU5ym7FS
         png6q1QYBsP8CSY7vcytW9kOVm4PcttrfJ7FPAe8FpCtUb+N8k5lraX5AyAYuwQex6qt
         gYRhobkRLg9qsEXQGxaL4h17uRORLM1ZT6WQVgLV+Q6813Ckx8787GOH9AqObfB3BMn1
         KhBNARu5FIS7gif3zgmwHGSfAjW2L/hV+SsKu6BLWWe+bUUjvSRh2efApRGBRgDyn8Mf
         aMX6gwWcxeAROMip1gcMvTPo/yOtXOvMQ+Vz18G+Hep9SPwDc08wmY2U/oTqgNVbAZ7q
         8gfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e/B3XjNttTAhZ7JUGgGHSBTAedWDXApAoSu7FvT42qc=;
        b=hcROP+tBO69icEWLW0ieJqrn80Vzhqaj3vRQFPUb/ApB1dz0MCUhT5wXzaf/3nRsQj
         meA5K6dCe/McFgMBcNAZS4sD+BxBAlHeJ8p+FHQtLttzVNnNYzwqx4NBPPCFp1psEdt/
         caNWF+9/3qRaskBYrIchfTTJvtWk4jIB19ON0Jnlh+20+OUahimfMnz7IkwUytseJdSa
         RQyZtr7WRv8lyKyJ5rYVupqo143FAFLlSSpVMBrNuOPP9Z5wVsQeWkyJqejsc+K8cE9Y
         ZocPzWvfhkCDUfnTIllmh+lshMjn/Ph/hW+QF6bj9DXjPXjSqCgxF59z2WFVQEVrjBJu
         yCrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e/B3XjNttTAhZ7JUGgGHSBTAedWDXApAoSu7FvT42qc=;
        b=ihsgGYsc7kyKollJ+t0HeQuhyuJxSEWx9tpQfN9J5Qmed8r+4TECOyrCfukissTZX/
         2pHhTNArnqDrLBo2K/aK0sx2MnDX7CWBXO14BhecKQGB8yw+PoQzmz1f5auQtKqF+TaE
         E797UKrd/t+xADhD5x1yB2Qes8z1Te4Bl7SXwLe1OKpxgceXkzZ4XaMUAne0j9TnAzDe
         XDg1m1v81OIdoCmzNI4R0yE/hvwj+O1daR5TxqsifUbmX1i2WCH8EV7s4DOvObbNaYGk
         s+BTl8QEWfJDYqr85wOn5Dxz1r85ntk5WkiPpyw5FjdDMpm1mFj68uFo9XhUOeXwnLlv
         Jqwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV6UEijWllL2kJxkhH1aDbt5W46zEQY/lE7RiRuclLa3n3Z+8dK
	sNkSbVMgCUreyD/0rdLP0Sw=
X-Google-Smtp-Source: APXvYqzLbbplTxLctswlDkmsawU9RZ2M19OFg9gGheczsyn3eOq1LC5RtvCZhmXEMi6QiIrILh1rUQ==
X-Received: by 2002:a2e:8893:: with SMTP id k19mr5657499lji.5.1571395453157;
        Fri, 18 Oct 2019 03:44:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7102:: with SMTP id m2ls520777lfc.15.gmail; Fri, 18 Oct
 2019 03:44:12 -0700 (PDT)
X-Received: by 2002:ac2:483c:: with SMTP id 28mr1503201lft.174.1571395452584;
        Fri, 18 Oct 2019 03:44:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571395452; cv=none;
        d=google.com; s=arc-20160816;
        b=M7DoMMNP8ARmbdceSIHhyuA8bRn1vV6LXxlJGE7gh6vUq35wP8bYHZq+VPsPdkGRu/
         fsTMCrCnc65sANjzaB2DWg0b3LzPfbwQ4BRlfk9SUHYys8ktxNmv8/32IdoVwzukrdsu
         FdA2y1TRxaxhvKju4E1FnzDVJ3iu/TtcncW5aEJhbMaQfolD/sYi8LN0QBuRvAgTd0p0
         17SXxXpcEhdN3WJzT6HblqD+B+6c3wK9NDYfiI6f+5DYTvraHSWuU6NamvZpbm0v+9od
         Fn14gTt0vOkbKrWwp+FVR0jEx2FqfRfLMzT/EAiFUhow3UU8tDa1XI1E+CPsWDQfOJVx
         1GdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=0WHBnMLgOLmd/npHiQyID9+qb80qvlWwDAaya/qPhxA=;
        b=RdDIPngyMPlwTrjJIfF9bC8dBETv+nlmtVlKzSEdesZfnjf4AgHmJNuNfAWrKyEwnA
         5WQMdl9K2JFHHAlsC0CTfnBL/fkkcGtINBUTRLKSq0esIhnrWbk+pfW6imM4SXYk8x6Z
         lSV6qt2hcqH8VN3fw3VAX+ufNaIUYskSHpzCQLDV9rtNkhxognXCzoJCVL6v8yvDeNzz
         L2b1230O8opQMHAbuW0yW48xp2YAfbB4G9mpE4so//IwhzcU/AxxES0T6ml8A4dAQF3b
         tfDWqf9MxPhdzxHyxvjqsXn+/a4zhQ1+mc/Cw+euiGzovPCCATRsl4ZCVCjND3rvX2QD
         bCBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id c25si244567lji.2.2019.10.18.03.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Oct 2019 03:44:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iLPjg-0004Zn-5t; Fri, 18 Oct 2019 13:43:56 +0300
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
To: Mark Rutland <mark.rutland@arm.com>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr,
 linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
 <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
 <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
 <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com>
 <20191016132233.GA46264@lakrids.cambridge.arm.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <95c87ba1-9c15-43fb-dba7-f3ecd01be8e0@virtuozzo.com>
Date: Fri, 18 Oct 2019 13:43:40 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191016132233.GA46264@lakrids.cambridge.arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 10/16/19 4:22 PM, Mark Rutland wrote:
> Hi Andrey,
> 
> On Wed, Oct 16, 2019 at 03:19:50PM +0300, Andrey Ryabinin wrote:
>> On 10/14/19 4:57 PM, Daniel Axtens wrote:
>>>>> +	/*
>>>>> +	 * Ensure poisoning is visible before the shadow is made visible
>>>>> +	 * to other CPUs.
>>>>> +	 */
>>>>> +	smp_wmb();
>>>>
>>>> I'm not quite understand what this barrier do and why it needed.
>>>> And if it's really needed there should be a pairing barrier
>>>> on the other side which I don't see.
>>>
>>> Mark might be better able to answer this, but my understanding is that
>>> we want to make sure that we never have a situation where the writes are
>>> reordered so that PTE is installed before all the poisioning is written
>>> out. I think it follows the logic in __pte_alloc() in mm/memory.c:
>>>
>>> 	/*
>>> 	 * Ensure all pte setup (eg. pte page lock and page clearing) are
>>> 	 * visible before the pte is made visible to other CPUs by being
>>> 	 * put into page tables.
>>> 	 *
>>> 	 * The other side of the story is the pointer chasing in the page
>>> 	 * table walking code (when walking the page table without locking;
>>> 	 * ie. most of the time). Fortunately, these data accesses consist
>>> 	 * of a chain of data-dependent loads, meaning most CPUs (alpha
>>> 	 * being the notable exception) will already guarantee loads are
>>> 	 * seen in-order. See the alpha page table accessors for the
>>> 	 * smp_read_barrier_depends() barriers in page table walking code.
>>> 	 */
>>> 	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
>>>
>>> I can clarify the comment.
>>
>> I don't see how is this relevant here.
> 
> The problem isn't quite the same, but it's a similar shape. See below
> for more details.
> 
>> barrier in __pte_alloc() for very the following case:
>>
>> CPU 0							CPU 1
>> __pte_alloc():                                          pte_offset_kernel(pmd_t * dir, unsigned long address):
>>      pgtable_t new = pte_alloc_one(mm);                        pte_t *new = (pte_t *) pmd_page_vaddr(*dir) + ((address >> PAGE_SHIFT) & (PTRS_PER_PAGE - 1));  
>>      smp_wmb();                                                smp_read_barrier_depends();
>>      pmd_populate(mm, pmd, new);
>> 							/* do something with pte, e.g. check if (pte_none(*new)) */
>>
>>
>> It's needed to ensure that if CPU1 sees pmd_populate() it also sees initialized contents of the 'new'.
>>
>> In our case the barrier would have been needed if we had the other side like this:
>>
>> if (!pte_none(*vmalloc_shadow_pte)) {
>> 	shadow_addr = (unsigned long)__va(pte_pfn(*vmalloc_shadow_pte) << PAGE_SHIFT);
>> 	smp_read_barrier_depends();
>> 	*shadow_addr; /* read the shadow, barrier ensures that if we see installed pte, we will see initialized shadow memory. */
>> }
>>
>>
>> Without such other side the barrier is pointless.
> 
> The barrier isn't pointless, but we are relying on a subtlety that is
> not captured in LKMM, as one of the observers involved is the TLB (and
> associated page table walkers) of the CPU.
> 
> Until the PTE written by CPU 0 has been observed by the TLB of CPU 1, it
> is not possible for CPU 1 to satisfy loads from the memory that PTE
> maps, as it doesn't yet know which memory that is.
> 
> Once the PTE written by CPU has been observed by the TLB of CPU 1, it is
> possible for CPU 1 to satisfy those loads. At this instant, CPU 1 must
> respect the smp_wmb() before the PTE was written, and hence sees zeroes
                                                                 s/zeroes/poison values

> written before this. Note that if this were not true, we could not
> safely swap userspace memory.
> 
> There is the risk (as laid out in [1]) that CPU 1 attempts to hoist the
> loads of the shadow memory above the load of the PTE, samples a stale
> (faulting) status from the TLB, then performs the load of the PTE and
> sees a valid value. In this case (on arm64) a spurious fault could be
> taken when the access is architecturally performed.
> 
> It is possible on arm64 to use a barrier here to prevent the spurious
> fault, but this is not smp_read_barrier_depends(), as that does nothing
> for everyone but alpha. On arm64 We have a spurious fault handler to fix
> this up.
>  

None of that really explains how the race looks like.
Please, describe concrete race race condition diagram starting with something like

CPU0                   CPU1
p0 = vmalloc()         p1 = vmalloc()
...




Or let me put it this way. Let's assume that CPU0 accesses shadow and CPU1 did the memset() and installed pte.
CPU0 may not observe memset() only if it dereferences completely random vmalloc addresses
or it performs out-of-bounds access which crosses KASAN_SHADOW_SCALE*PAGE_SIZE boundary, i.e. access to shadow crosses page boundary.
In both cases it will be hard to avoid crashes. OOB crossing the page boundary in vmalloc pretty much guarantees crash because of guard page,
and derefencing random address isn't going to last for long.

If CPU0 obtained pointer via vmalloc() call and it's doing out-of-bounds (within boundaries of the page) or use-after-free,
than the spin_[un]lock(&init_mm.page_table_lock) should allow CPU0 to see the memset done by CPU1 without any additional barrier.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/95c87ba1-9c15-43fb-dba7-f3ecd01be8e0%40virtuozzo.com.
