Return-Path: <kasan-dev+bncBC5L5P75YUERBV5U43WQKGQEPOBWB3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7327EE9D37
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 15:12:39 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id g21sf661330wmh.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 07:12:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572444759; cv=pass;
        d=google.com; s=arc-20160816;
        b=zwGEx6DHvjKGF5zjKps5tkYKPHr38kaf2WPoF0nEaVCTbLqj3HZzZzGP7ebAEcU95j
         QHilMwo72Np6MPZZberoK9Opw1CTlMpdwbbvODlEyq6NcMdcgnlfgcQv30+QU75f1re1
         j3Mn1WmG07IzNtuYyjFvY+Km+LX1UhlCCF8v6SIu8J+0N3IT9x3jOEIZU/VCT28ewnSp
         eqNgaByCXgobOWyi+b461BmMCtqBm+7KXqRHwWWrYg85kMw8DihosG2NzxRcy45RRzTg
         WjFO9MYSN+2tZG33R96YxfdZqI2W+8lE3MOr2ibDhCzplZ0D/uGDAkp/jHD00ocbkdA7
         vrkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RZ5QHp/48nZGlMOnViEKsd81YT7xlbIAC2Ljq4vQ84Q=;
        b=SCF0v0XMDQfYvTg2ghE783MJJDVznDyh593yOT8wTYyMXREzckodyOkCrlWHXSJTPw
         KGg3cjNJSHUDko7joNj4qDOTCwStb3EghBoiocJ+Bpko8vixyGeCQBoTA4KPAShzC0Y7
         0yS096gsW0gEeCv3hkKU7a9MTk/wMN+9/7TdVjcN6I/8UOHc1wqMxg/+kolYZGl4ViWS
         +eemf2HLNL+z2wWJGG0K90Xaps5fMa789q/AU/olo598PZsT1hGVygeg/lbioazHibgu
         1A+iREhbOJQThSrVDtl8JPPi/MzGrNc6kydO92jByWFBQahtVoQJFnIUsl8d7g156xwb
         V7Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RZ5QHp/48nZGlMOnViEKsd81YT7xlbIAC2Ljq4vQ84Q=;
        b=n3TB9VZ/QpGBtW7bb3PV3aLXjvB5V8BLoL8dFAYlu9xmHiq8whzL/Pi+ia8HJTUZev
         kCWdimYN689nvy1o39Ui9N+PcKsGx6MLPveUDJuPaO+JmNyKG1iweaIAW511fOwuHM1Y
         VBGlLAh5FvS1/tVpFk9PlVojjheGwzkTIQrPIVnP256iYwcPzacP4/eUcW6PqlnApagx
         Zgil4BPrt+E3drMdudVviSPD8u70KuAmkpYCKoOVMwNJJkJi2XWAceKjDfML/gyvTERx
         8ihPIgffL8809h97VBEbIcADBo3tadVQ9VPdxHRnAMqxVGL5iiWAbaj5V5vgOmZTq5MU
         xacw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RZ5QHp/48nZGlMOnViEKsd81YT7xlbIAC2Ljq4vQ84Q=;
        b=Z8avF2URlWxsvAIEkvOVfzEPwVgC+zk8MTIKXrrrSQvAzPx+c7INk6MuVJfvJt8MXV
         Xe2u5NVR5UdsXIl5TVHedM6Y0X2ONTAMbew85o2xhreNJIqDvnDIjSfPrJKkJ4M97qE+
         4un7fi9XSz9p5B4qvzGoD/bohr8iHtc180tByQ4liJknOuLyFOMd16sKPx3QG6YokNip
         tz1BnagPiT2ssMm49BVMKwxP0LsMQJgdmwtODZJUbw5YKS3Sh4hWB45IyNardrPKTFoR
         Dd9Mhi6Z2oAS+/GgWx4ck0yX7lLIAGb1dXzydcpMTVUZheUDl+uWmpOKy2xUY9YtcYkx
         ppuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU29RADsp7upytYvtP9698QKYkbJDRloHKY9LrnnEQ14CKUgylS
	bdGfTcicwALjR2TLBX9jPkQ=
X-Google-Smtp-Source: APXvYqyIUKGf+B+QR9lebDMyItiX+Wsnyh07ggpu5IhLe4M/QyfdYcYXgVphUMldkD5kuSP64MJw3w==
X-Received: by 2002:adf:dc44:: with SMTP id m4mr62403wrj.203.1572444759226;
        Wed, 30 Oct 2019 07:12:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:12ca:: with SMTP id l10ls17445358wrx.16.gmail; Wed,
 30 Oct 2019 07:12:38 -0700 (PDT)
X-Received: by 2002:a5d:5707:: with SMTP id a7mr62566wrv.177.1572444758627;
        Wed, 30 Oct 2019 07:12:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572444758; cv=none;
        d=google.com; s=arc-20160816;
        b=U5xWaWJb1BaUpLckBrk2c13SluyvLO/M4dPxfXjWZrmTWss1FWQp43k0PCcK8KJbq6
         A6jSKO9jsWZtmptipmtcpVtiQPjcLagdF52YB9akfqF+llRcjMeO4U/YeZTQmK75hZtz
         CEyIk/zJkFRf7EmM5pyMZxH2Rru0CQCLe7kGYCnYURpzpkGirtErKfxOU4jD99O2jexv
         fdx1F4hRPsC6fecR00WW4wRKuO60t2FOEIggnoM104DFHBXHmxYLQQDL2S43kkFA4MIT
         C4Z3MmJ0XS5WWsve3pcAHdqfwshGfT0rT2BBEjwnN+VMDVKsrdZEFwgZdw/YK4XqESKf
         xSSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7wNlHbpGfe5SuMrfffApDUey9WSzzoUupSY6SDw2fZk=;
        b=hRgTvzjCkkLHrWBP979HuUhljl8RkBqUqvkJCGKjwWHfserYjKsNeKBWrAU7peNyVm
         HnhAfcwmyoSLWlkxd0XUwB3Q0w+g1GFQUJTQb0avZEG33ICuZyQ7d8vwaVEyk5uDuRaP
         o0AAkdbgsZu/YHW7SQivv/YeFuvlwCqmxl3IALKrfrMqHQlAiTfNsVZNF+BapHHD5Xso
         bzHztS/bVzNQHy0Aiv5u81k88lNUPs0Ra9Xk+2k0NDDytRzYY/cDTJ4gCcy/C3hXHS00
         mJqXk5LTA9ZVzW/qWSdlgL3jJxdym7lmzAPHXxA9z5fb6Tz2GLxIg9xH78zIqoK3HXqD
         8nwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id x2si19550wrv.1.2019.10.30.07.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Oct 2019 07:12:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPohu-0005hC-HE; Wed, 30 Oct 2019 17:12:18 +0300
Subject: Re: [PATCH v10 4/5] x86/kasan: support KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-5-dja@axtens.net>
 <a144eaca-d7e1-1a18-5975-bd0bfdb9450e@virtuozzo.com>
 <87sgnamjg2.fsf@dja-thinkpad.axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <ff1c2089-9404-21f6-dac6-661917e47181@virtuozzo.com>
Date: Wed, 30 Oct 2019 17:12:00 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <87sgnamjg2.fsf@dja-thinkpad.axtens.net>
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



On 10/30/19 4:50 PM, Daniel Axtens wrote:
> Andrey Ryabinin <aryabinin@virtuozzo.com> writes:
> 
>> On 10/29/19 7:20 AM, Daniel Axtens wrote:
>>> In the case where KASAN directly allocates memory to back vmalloc
>>> space, don't map the early shadow page over it.
>>>
>>> We prepopulate pgds/p4ds for the range that would otherwise be empty.
>>> This is required to get it synced to hardware on boot, allowing the
>>> lower levels of the page tables to be filled dynamically.
>>>
>>> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>>
>>> ---
>>
>>> +static void __init kasan_shallow_populate_pgds(void *start, void *end)
>>> +{
>>> +	unsigned long addr, next;
>>> +	pgd_t *pgd;
>>> +	void *p;
>>> +	int nid = early_pfn_to_nid((unsigned long)start);
>>
>> This doesn't make sense. start is not even a pfn. With linear mapping 
>> we try to identify nid to have the shadow on the same node as memory. But 
>> in this case we don't have memory or the corresponding shadow (yet),
>> we only install pgd/p4d.
>> I guess we could just use NUMA_NO_NODE.
> 
> Ah wow, that's quite the clanger on my part.
> 
> There are a couple of other invocations of early_pfn_to_nid in that file
> that use an address directly, but at least they reference actual memory.
> I'll send a separate patch to fix those up.

I see only one incorrect, in kasan_init(): early_pfn_to_nid(__pa(_stext))
It should be wrapped with PFN_DOWN().
Other usages in map_range() seems to be correct, range->start,end is pfns.


> 
>> The rest looks ok, so with that fixed:
>>
>> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> 
> Thanks heaps! I've fixed up the nit you identifed in the first patch,
> and I agree that the last patch probably isn't needed. I'll respin the
> series shortly.
> 

Hold on a sec, just spotted another thing to fix.

> @@ -352,9 +397,24 @@ void __init kasan_init(void)
>  	shadow_cpu_entry_end = (void *)round_up(
>  			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>  
> +	/*
> +	 * If we're in full vmalloc mode, don't back vmalloc space with early
> +	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
> +	 * the global table and we can populate the lower levels on demand.
> +	 */
> +#ifdef CONFIG_KASAN_VMALLOC
> +	kasan_shallow_populate_pgds(
> +		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),

This should be VMALLOC_START, there is no point to allocate pgds for the hole between linear mapping
and vmalloc, just waste of memory. It make sense to map early shadow for that hole, because if code
dereferences address in that hole we will see the page fault on that address instead of fault on the shadow.

So something like this might work:

	kasan_populate_early_shadow(
		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
		kasan_mem_to_shadow((void *)VMALLOC_START));

	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)
		kasan_shallow_populate_pgds(kasan_mem_to_shadow(VMALLOC_START), kasan_mem_to_shadow((void *)VMALLOC_END))
	else
		kasan_populate_early_shadow(kasan_mem_to_shadow(VMALLOC_START), kasan_mem_to_shadow((void *)VMALLOC_END));

	kasan_populate_early_shadow(
		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
		shadow_cpu_entry_begin);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff1c2089-9404-21f6-dac6-661917e47181%40virtuozzo.com.
