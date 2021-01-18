Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5WSSWAAMGQE2EZ4FSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A2672F9D49
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:56:55 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id t7sf13102895oog.7
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:56:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610967414; cv=pass;
        d=google.com; s=arc-20160816;
        b=QwrExhVf2byNoMbXy+npqMC1tmDqM+qcjoVvjoZFKDiLwme971pfjY5Re0HnYapBsU
         21b114+cyAmmvXcEBSnffCiqIrErvJbyarD9EpMq62FCUCmOoyKDt7uQeunvtQhGvG+e
         o6puNeNPWQjVvtFZaFWILJm7WqwTIJFmFzzkBpm/Dh9/eSLHWGUvaRhOzst+mZW/swvz
         ckubSSXHh+du/riqA4MYYgU53lzT/cXj0MixshZBNuK4CRdJyXCMW1qSNw/8IL2bUlRP
         bIq+sTgwAteCr+UBpbb2Sdsodth7H2IyAAM/3+3DDH4k8rKL1ig3PaCc/DiKC1pZjqKX
         jWqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=+YdGO9glI3+CjSQ2aIVrghCZ7mc+iSjQTD0PhkM+auI=;
        b=DIUIjrMTKpWnq0Ej5fbBfoSLmDpbQhaRkOYfAOb4glMH9e0Dy/y2V9fiogi7RUeICs
         UGKKbyfp07Rb9zK+b6J32hMDRc82BjRC885fYCbkI1/t5UcdIuReTgo77AFJ6DiuU6CO
         4EgnEiYjl5K17eQewpmvp6VYYswckey3hg0h14rTeehQG/c0yY/XVAb/16LnBxuRn1uB
         siO9rW22Dl/Nu+bpfMQd5w+OxsmfnMeFJKHUUx7HtHEG0n5Eawh4GbLHyeWrxV3/TAt9
         83l/nj5WJXS0WF/kvMmanVyqzt0Cr/jzqUvjvv1qDY//oxDYOO5wCj0bZGCatdjBsJR2
         4XHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+YdGO9glI3+CjSQ2aIVrghCZ7mc+iSjQTD0PhkM+auI=;
        b=W3Vdl07YlWtTHpWuxHShr5UsJmp8U6SmmcXCPgCDHjonsltJ2tGTCQuaRHXbyVrdG+
         4LRtmEaANrsVy9cZqujCqiY+OQRbDVzD43E9Me9F09OW9tIQK7LDq8CiVE2o65eQf/72
         +WaSV9w5Pzvu2NPLUw38F/o3wTyhWQZwq3Tx7YgbotA2JlbjBmuF/Won7ccWWi6eFg7g
         KpaQcP7/6PyTfTOkUPRDQeN7ZqJKG+wAH1EArIIwnHvqaPDTVTVOox6EvGVqxAmRr/+D
         mD9XGXow0eT5nubLbidzhecEN1y7VCsPI3o2zR4j+hpl0exMy8EiFn+bAVyvpTAttez2
         QaxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+YdGO9glI3+CjSQ2aIVrghCZ7mc+iSjQTD0PhkM+auI=;
        b=H/gjZEf+UNUWCWBWqs6PhTY2bfSEiodjk6bBVs/4Jqtz0FsquFFXkc7JMegf4fHIJi
         3IFXRdaUecG+2KQF/ECQJJgheOUOuT7UUzbuPzMxNZ0Pk944taSTOwRNZ02LLWDJm8u/
         hrNnpkRS+FcvB2LqbxHWB5PgP8TDw2CsfSpSaHRQZvVfOACvIccIL0UZMfmOWHplffi8
         9khILE6aZAQGRc8Us/9XGpSdA4cP+IFsxa4zTP+sgptr5rcRMjOR6GiLV3LhVoStzvTx
         Ql1qN/GqEaitUjkenp7d+Do3z2JJuyP992EXpZndYjKWBw0vAJYx18aYU8PKN47RRnBd
         9MLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZChAH84pkTwQl7T2zKs6zJ7N4GoYhYujQAZc/m41XFDx/IPXR
	gcoGZyJkzXadCfzZtFeiFD4=
X-Google-Smtp-Source: ABdhPJzIjLIMpb0ueoZtBLmGJuF/Yu5q1q56KE9NQIVpWMVZ1cQqd1aKI/egK+WtI0VVTmwAIO6mtQ==
X-Received: by 2002:a05:6808:982:: with SMTP id a2mr12856446oic.40.1610967414145;
        Mon, 18 Jan 2021 02:56:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7a8e:: with SMTP id l14ls4482233otn.1.gmail; Mon, 18 Jan
 2021 02:56:53 -0800 (PST)
X-Received: by 2002:a05:6830:4b5:: with SMTP id l21mr17560578otd.321.1610967413822;
        Mon, 18 Jan 2021 02:56:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610967413; cv=none;
        d=google.com; s=arc-20160816;
        b=b+5fPwwusAnDKiCL/gdhTHD00tDjF2RSrnP8OtPQkAbK66B8TiSDBAKXmL1wPFunNP
         GfkKmRXnNHiNpuPbH2DMa39QQ6cDm2Vb3W51nzv+eI1hWx+TaKmxL8+9/904nqgkH6KZ
         MAZqJ3Bi1GTSrDRdYCfGs11taLK7/YmmBkMXTScDkEchewKWH91bHA3zVU3cEtIw2vLz
         BpoyxvsTzbZI3YFw9FMO2il2PKYdCOloHoK0O2izC6kOPZdKZhrg8IF2qKjUt5ZSmJD/
         B9Qyg4J0wkOAgap9sm9+cUKh8L81G3pYld9RLEjf0Ed0l+qIYYiVW7RPZJ+Na0aPnpGk
         LLAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=QR9VUaKC4xPc1MPQWQs68iRrgL3O9oojAs2cu7ayC9Y=;
        b=cTkdZskUHCnt5fcWI9Sn4iPOSc2QickUeygIdMXggU6X8Femu7ZeH8jYSjtu+VZlGt
         l+y8pQFLwi0ePqKBkyd8l4USWf968srcIPEapayRGAKD2BSmSmFciFa+8ngftDmOWIgg
         N5Gr8r0MFWX+K1vC7mWUyeQ1v904Beka4aCCkNlUeF7pxbipe+x+vGI8zBA+HeyNrwFN
         bp4VCichJ42MxjdCWdPz4BCFbyynV5zIoka+k/goA9vDcX0l/4MkaqLYOoj6bs7zFxAe
         wc4A1/fHbyD9kwnSXcCN2q3VaeWiyl3IWJkEpNB83Opo/zB4AeexYjE6UGNtCiP1CdPG
         8qTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x20si1951109oot.1.2021.01.18.02.56.53
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 02:56:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 907681FB;
	Mon, 18 Jan 2021 02:56:53 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EF5F33F68F;
	Mon, 18 Jan 2021 02:56:50 -0800 (PST)
Subject: Re: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-5-vincenzo.frascino@arm.com>
 <20210115154520.GD44111@C02TD0UTHF1T.local>
 <4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03@arm.com>
 <0c1b9a6b-0326-a24f-6418-23a0723adecf@arm.com>
 <20210118104116.GB29688@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ead05a9a-edef-7be9-b173-3a62caf187c3@arm.com>
Date: Mon, 18 Jan 2021 11:00:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210118104116.GB29688@C02TD0UTHF1T.local>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/18/21 10:41 AM, Mark Rutland wrote:
> On Sun, Jan 17, 2021 at 12:27:08PM +0000, Vincenzo Frascino wrote:
>> Hi Mark,
>>
>> On 1/16/21 2:22 PM, Vincenzo Frascino wrote:
>>>> Is there any chance that this can be used for the last bytes of the
>>>> virtual address space? This might need to change to `_addr == _end` if
>>>> that is possible, otherwise it'll terminate early in that case.
>>>>
>>> Theoretically it is a possibility. I will change the condition and add a note
>>> for that.
>>>
>>
>> I was thinking to the end of the virtual address space scenario and I forgot
>> that if I use a condition like `_addr == _end` the tagging operation overflows
>> to the first granule of the next allocation. This disrupts tagging accesses for
>> that memory area hence I think that `_addr < _end` is the way to go.
> 
> I think it implies `_addr != _end` is necessary. Otherwise, if `addr` is
> PAGE_SIZE from the end of memory, and `size` is PAGE_SIZE, `_end` will
> be 0, so using `_addr < _end` will mean the loop will terminate after a
> single MTE tag granule rather than the whole page.
> 
> Generally, for some addr/increment/size combination (where all are
> suitably aligned), you need a pattern like:
> 
> | do {
> |       thing(addr);
> |       addr += increment;
> | } while (addr != end);
> 
> ... or:
> 
> | for (addr = start; addr != end; addr += increment) {
> |       thing(addr);
> | }
> 
> ... to correctly handle working at the very end of the VA space.
> 
> We do similar for page tables, e.g. when we use pmd_addr_end().
>

Good point! I agree it wraps around otherwise. I will change it accordingly.

Thanks!

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ead05a9a-edef-7be9-b173-3a62caf187c3%40arm.com.
