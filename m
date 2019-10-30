Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYFY43WQKGQEF2L6MXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 22C77E9D59
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 15:21:22 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id t1sf2119795ilq.21
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 07:21:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572445281; cv=pass;
        d=google.com; s=arc-20160816;
        b=EhATMvL2vxCZsUvGRWFXyHSpSrVYtcuTANXc4BO19cYR+P41cEn03c2dwyB8UdTCbD
         vBHIF6I1JSc2lwh9KbFByhgM9CriAleq3K0BTXJhR+/ey/+Pbu17ARuvmriELs1DFUN7
         4VStA1/z6UJBeTU2BVHGIAmDqzslrtuY9hn4RYQVTCq5GwQzkcQCATKHhT1GvxniXgpR
         Xewqg+YkeQjBXgiqlGnm4ddsYTXxqRFdaEtje/QsNoS233aYccyj3l2m3B9cCwfiGDyU
         md4lz9ITN2p6oCb5/QdLRZ0njQyIaqf/NFgAcW48919kVeFzrWN+pBLvVqhrbwl4lg+c
         LBVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=4otFFW1zB0hOo6h04SAI8nGtYrehJmlP3NHKr3Ga5d8=;
        b=NLrRtXiO/3wiyLjHYHcSdlOc0cXfdhCcU46Dw9vgvKz17xlPGeGCO+K1NlBQLs6n0Z
         EHHt/MFjKlejgWI+nLdGZCrY+2DwcidBWqhfwAAH/Di+Ac8hT3FTNpskRFmuFXiJ3H4b
         RDnfdemocn6WMy1E5kc3asxau5Cs2SPyzuU4NOMtBYyNYnbeRbt+u+Eu6VJ7yaUAG/eb
         pyqflTw56L9WNKl7FTW1K1xFSfbqDZpAs4XSKWm+B/ItjUQteEsfRgl9j6NKMmNHguBs
         RS4b2FRv4hKe//d9F7A7uuFBD6BVKPBTNdWBsPejIpFp6XujjZjDR6yTfaQnbwlWkoMD
         hNxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qwVsaT6C;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4otFFW1zB0hOo6h04SAI8nGtYrehJmlP3NHKr3Ga5d8=;
        b=AzIpnzVCae2P4SZghtxLgPF7XbYuL69SNGWbzKnFUgt2Ba1IVvmNx3ROsddId39ClH
         WjMnwVzAWuWxa1frXJlFZV2qT1pT2e6hDKCjINvz4hqOgU7QUQoPuZKg6zxNHcLItiSH
         R6yaW5Rg24XJw5kQQwQzO5msND52rys8B0l6v+MGjur3csJuJXV7eoxKBVqlk1k4wvvd
         cuJhuv5bU2QhYVTNhJ9RgEDtNPNncB9qua/gxsimRsuM2MC8NMpyf7Ta+jKf2xuy8UX9
         NgEItqJmAC0hef9MbFkrfvIoKzqmmlfWvhmy0WJoU1PG1FaP4VKWvFixjXHLJnXoiN6D
         97iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4otFFW1zB0hOo6h04SAI8nGtYrehJmlP3NHKr3Ga5d8=;
        b=MuPgTxwhBcoNn4YSLyI17uXqrqWVghAocd3e1afVFrkS0qqx4KQH78WmkoI3D9G779
         CHcYeuCnyRE2MAfSQ4WxsmJ96kRS81mQZGQ3uvK0jWN24UBl2OU5P8w4kzHAMNwOxyC2
         YowdQwgvePCgV86AmtgCuhFxnVwvE8iu+nFFy31yaWLlG7wuSoU25zXD741+rDlItcrL
         ULwlGWZL7FtOl2VZWBB5k7VkprjdVQ6hf5GT1OMCAkPotqIIbxgbBbk5MObTur4hpUWc
         /q4NDv65IHbA8MdG+1Dv0GRh/M3ABQ7YeVY9cErwZhduq7q1DD7gp/ghsx9n/0rpLk0y
         EVcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUhzuMyND5nPpusOtnOjmOKaasMe/AYyXv8vwB2Hjaronxx5Mv7
	1RuqD9OjWo8gkCzE62RDjrk=
X-Google-Smtp-Source: APXvYqw0cmjlzBw7mZkoIMgR/hOamyRTSzbxDhzWZUW9yDCt0t5N3Srjl0yzRHp08a1YogUJfNqMOg==
X-Received: by 2002:a92:3b9a:: with SMTP id n26mr331139ilh.82.1572445280756;
        Wed, 30 Oct 2019 07:21:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:712b:: with SMTP id n43ls1791315jac.2.gmail; Wed, 30 Oct
 2019 07:21:20 -0700 (PDT)
X-Received: by 2002:a05:6638:533:: with SMTP id j19mr28832186jar.33.1572445278673;
        Wed, 30 Oct 2019 07:21:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572445278; cv=none;
        d=google.com; s=arc-20160816;
        b=ELHWeKgoeldtDfqXmYxkR681QauNaKihfu/0gMX0gKFkoeD6aTY6uJqe3MDxOQBdfT
         F5lTqmb02dzVRX8UlwMBiRH7LMMkhmsAP91/2cVYZ9UBZ9NvfPQz8WlxYCJhROURNivH
         H1asnM1oBJvDx1NFK6/pASpsmDsZePpo0HH3yHfNXqUAIG8J3bw2H3D8e/g21rWksRmY
         S67MHKxkNHvEC7U74Be7VAwKGwH0kkdCf/4qXwP0B71G+YLFy77LawV4jR2vY+azsL/2
         q2HGsCL69PR1H0b+dYRJdhTzZ9Gir0jwg/+TAzuBNOrlyFN8KKPvXQaxNwWaHR607UEQ
         RNUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=lLBDwfjg5YnQXNE+xQ4JmNR71OHaPXxKWZ+MT4DW3/A=;
        b=kUP3qH43epfZzcPgHJ/U564Ncmmurt5ylHmRms96uxY4++T+r/V3I09+aOpZK7AM2M
         ff/bJmTNxNQQ1BsJdIVyjfnvJzCZVqQLvf42PDJ60M9igHrgJ0jtC1bjmGS3ZZ7SzTW9
         Hs+4FQn+WPwQMveUBi+kmgIUgyPHbIkMoeBQpwAd/uBDkTThS2CQoQ1IDjOsQCVje9+B
         zQ/dyc/qd9mje+3He+P5Rj811r0+5DJxYObfUDvUF/gB7IOnQAg2fLAu/iiX2E4aAFik
         3yS0e7YTgopTFM4aaWeNP7ew/eZAJMDbImOndKTEhkw2mVNLj+c8qp7ZzqulyIr7VMXT
         Bo6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qwVsaT6C;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id k11si117962ilg.4.2019.10.30.07.21.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2019 07:21:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id w8so1059820plq.5
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2019 07:21:18 -0700 (PDT)
X-Received: by 2002:a17:902:44d:: with SMTP id 71mr241216ple.274.1572445277919;
        Wed, 30 Oct 2019 07:21:17 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id q6sm75232pgn.44.2019.10.30.07.21.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2019 07:21:17 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com, Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v10 4/5] x86/kasan: support KASAN_VMALLOC
In-Reply-To: <ff1c2089-9404-21f6-dac6-661917e47181@virtuozzo.com>
References: <20191029042059.28541-1-dja@axtens.net> <20191029042059.28541-5-dja@axtens.net> <a144eaca-d7e1-1a18-5975-bd0bfdb9450e@virtuozzo.com> <87sgnamjg2.fsf@dja-thinkpad.axtens.net> <ff1c2089-9404-21f6-dac6-661917e47181@virtuozzo.com>
Date: Thu, 31 Oct 2019 01:21:13 +1100
Message-ID: <87mudimi06.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qwVsaT6C;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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

Andrey Ryabinin <aryabinin@virtuozzo.com> writes:

> On 10/30/19 4:50 PM, Daniel Axtens wrote:
>> Andrey Ryabinin <aryabinin@virtuozzo.com> writes:
>> 
>>> On 10/29/19 7:20 AM, Daniel Axtens wrote:
>>>> In the case where KASAN directly allocates memory to back vmalloc
>>>> space, don't map the early shadow page over it.
>>>>
>>>> We prepopulate pgds/p4ds for the range that would otherwise be empty.
>>>> This is required to get it synced to hardware on boot, allowing the
>>>> lower levels of the page tables to be filled dynamically.
>>>>
>>>> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>>>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>>>
>>>> ---
>>>
>>>> +static void __init kasan_shallow_populate_pgds(void *start, void *end)
>>>> +{
>>>> +	unsigned long addr, next;
>>>> +	pgd_t *pgd;
>>>> +	void *p;
>>>> +	int nid = early_pfn_to_nid((unsigned long)start);
>>>
>>> This doesn't make sense. start is not even a pfn. With linear mapping 
>>> we try to identify nid to have the shadow on the same node as memory. But 
>>> in this case we don't have memory or the corresponding shadow (yet),
>>> we only install pgd/p4d.
>>> I guess we could just use NUMA_NO_NODE.
>> 
>> Ah wow, that's quite the clanger on my part.
>> 
>> There are a couple of other invocations of early_pfn_to_nid in that file
>> that use an address directly, but at least they reference actual memory.
>> I'll send a separate patch to fix those up.
>
> I see only one incorrect, in kasan_init(): early_pfn_to_nid(__pa(_stext))
> It should be wrapped with PFN_DOWN().
> Other usages in map_range() seems to be correct, range->start,end is pfns.
>

Oh, right, I didn't realise map_range was already using pfns.

>
>> 
>>> The rest looks ok, so with that fixed:
>>>
>>> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> 
>> Thanks heaps! I've fixed up the nit you identifed in the first patch,
>> and I agree that the last patch probably isn't needed. I'll respin the
>> series shortly.
>> 
>
> Hold on a sec, just spotted another thing to fix.
>
>> @@ -352,9 +397,24 @@ void __init kasan_init(void)
>>  	shadow_cpu_entry_end = (void *)round_up(
>>  			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>>  
>> +	/*
>> +	 * If we're in full vmalloc mode, don't back vmalloc space with early
>> +	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
>> +	 * the global table and we can populate the lower levels on demand.
>> +	 */
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +	kasan_shallow_populate_pgds(
>> +		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>
> This should be VMALLOC_START, there is no point to allocate pgds for the hole between linear mapping
> and vmalloc, just waste of memory. It make sense to map early shadow for that hole, because if code
> dereferences address in that hole we will see the page fault on that address instead of fault on the shadow.
>
> So something like this might work:
>
> 	kasan_populate_early_shadow(
> 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
> 		kasan_mem_to_shadow((void *)VMALLOC_START));
>
> 	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)
> 		kasan_shallow_populate_pgds(kasan_mem_to_shadow(VMALLOC_START), kasan_mem_to_shadow((void *)VMALLOC_END))
> 	else
> 		kasan_populate_early_shadow(kasan_mem_to_shadow(VMALLOC_START), kasan_mem_to_shadow((void *)VMALLOC_END));
>
> 	kasan_populate_early_shadow(
> 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
> 		shadow_cpu_entry_begin);

Sounds good. It's getting late for me so I'll change and test that and
send a respin tomorrow my time.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mudimi06.fsf%40dja-thinkpad.axtens.net.
