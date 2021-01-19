Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQUDTWAAMGQET4N4BXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 300EC2FC107
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 21:32:04 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id t16sf13986992pfh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:32:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611088323; cv=pass;
        d=google.com; s=arc-20160816;
        b=ivxNq17JmjSFWP+HLPHcrKLui1uJR/HH+n0FavtPHOYbdHmqessNXVcTKADHeKlPxt
         /8aJTUHJCvCYXpPmzYOri1vRJAsDkXMLOpSqljrGoL2V2YTjkljn+FRZahvHAptKRox+
         HrklfmhS48ufPzDU4YSILzxcmZZxW29MYvbbENQgkYCjkXn5gvrpXSKEJsDnJ1q92tYb
         4d8omyYzFrbVdtrSAbr8wyarxIMDOtd0byRIj2bcB8Jb2mdrAOeQbZTGRC0htdfVE3xl
         V2Cyxnb1VsmlU9WQsYBv4MsD8z/UtwYfBpHsYuom490kBU/SfCifg4eG92V67GU0v6hX
         yT7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=xB34ncmkbs2qPfhvY6TaE+BHUKakAXN7kgRGZqFJ7Tk=;
        b=qGggaTK90mc4soPayWJQK7teiaDyP+OrOLbQeZcBEGejfrdOT+C5jfLw6TNFR5EbJB
         njHD/I2/B/74+bvdAbfY9CuO+r9sWyfbpvMLuXCeQXGKuqXY/BwLDV9+2Ldp4tglWpVf
         SV0kRrt9F/rhnszZ4FwmBvXPdFOWFDZAEKk2f7IEN576cPXgw8ShWzhhbpQw4L9vMlFL
         QEpe7UnZpxdPoiNsehN9p5K8WuyMz02KWZ1yhdZzqB6CgfqeOvN2nzQQNNbP1ZqPH7nP
         h1hX9lK7/Ybwr4KbqQCvy/MNvlS2yTFpJKOpegsxLULaqj6Mg67T9bnyft1C7F3Elwe6
         qbNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xB34ncmkbs2qPfhvY6TaE+BHUKakAXN7kgRGZqFJ7Tk=;
        b=OdO48+k5CncqZ5CTW28VEq11Xo1j+C8Buh/7gISF8suse9BX+WtndHxG8UYZJ9K7PH
         pwHgst6DtW28Y9C4KIa9Xqmk6SPE4vx2ExXWPGrvbbZahGyqBcgMu4lyCGWjQTKO7KWt
         6aCt94UbmjykJBFXBw+TBHuY322Q+vTZy/hQ0AD6GK79bC8tZnw5qjCPmvOISg3BoZWB
         ODkSvOWoBaYa0wLqJJXev++AKkuvGc6UpnaTkHSyFYyI6vpvEcZVDnburFdA2pzlQqAz
         ESkvy0vRMFn1apITRegrrS0pGwok034AneHbQXZvbwOtZhOu5PzgWxqhF1Vb4uVplMfT
         +PvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xB34ncmkbs2qPfhvY6TaE+BHUKakAXN7kgRGZqFJ7Tk=;
        b=RuClbqsfTzouMfN3FhnTN+cl23yD7GeS64v5xp/FjCtuYiWCVmazmRbS1oQNej/XkV
         hDlw0djSkve/bySXCWytRpArkXHa9bKwmKjlrch1sR/J4zv4A+z2ZA5THK7lfOQxgEFx
         Lqgfa3ZNwrZMBb1L7UJY5ore2rWnj6QDRLyshpjQT1ijVFEnAw4h139/ILfVWyy7xce8
         Xktw9xMJrB6137uXd96F3CWGYS9f4n7FyyVp/1lOPfut4L5Ktycgm0WpKHOMvEyZmP6n
         wme/1J68VcLGYKS1GvT7DL/W0cYtf3eWrLH2cr0tcwdfDdg38owBOXYRl/kszRGqStZr
         ULCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53163cLRIq/5OpVBS6vn4Z4ZYKlOR3FdtdopAqSc0S5wJiJl9r3h
	rRGtkkUB732dQvvpAHkW6TE=
X-Google-Smtp-Source: ABdhPJwZv/eOFbwyc6Lr8b+muWfcRWn5T0mY7ckGVlRNEVbCWHr4L8feftSeHD4II16w5m1ZS+WovA==
X-Received: by 2002:a65:6116:: with SMTP id z22mr6087028pgu.264.1611088322920;
        Tue, 19 Jan 2021 12:32:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls8095354pgj.1.gmail; Tue, 19 Jan
 2021 12:32:02 -0800 (PST)
X-Received: by 2002:a62:75c1:0:b029:1b6:b71a:a369 with SMTP id q184-20020a6275c10000b02901b6b71aa369mr5900403pfc.27.1611088322400;
        Tue, 19 Jan 2021 12:32:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611088322; cv=none;
        d=google.com; s=arc-20160816;
        b=kCVT/S/MPSBNKwzUFNaur71DmTjN6SJuV5IUJaxMR9sDF2p7MdbOX7b15vz3+mcw4E
         c/i+zS487RTjUODiHjcHL/cvIo8WeiM/2+jjrYpQU63s42iAY7Y/wQpjsJHuJdZufg15
         1xrc2Pxa/U2hbiCK389Shkb8wanIFDAO5hRshnaPzjz916d7TaF7SExJ/t50m4yWCMRu
         XECl6+CgyjM4xkJTtFCv3he3+Bc4bIFCidTIZDeaWQuZK569U7a/CYTuvqkO1pt39l+5
         6X6Z8TWN5vqs5O1fp19FrHP4mbIzpQSurTAR4nw/ui+ry5bgEKeSLrYieaJh/TVYjwr2
         Z3kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/jBIQn40A/aqg6L8xafdo5uDa98XCY+uTDcN3j+khr8=;
        b=hrA/RCcElR7BJNsku5/EaTwKI3iTL0ypbEt+kMqYlh00eXNwDOTfrjTU1bFPeNWmWj
         aaJdNox7duKvCpwiGGWu27Y2yKs9+EjWJASyWFVmkaazAFeQ0vSoly6eTrXnCVZLWMu3
         DC+J0DrWjeFThV4OnKmVCzumsERp2R2w5/W+jYWT3nPXtxjmEMdqnhzN8K5edYKgmD9M
         OS7DH5L/hY6ebBEGnilU5ff/VsN1jvb1EzIdihEtQJf9iznU8WDw7x210dZ83Y0gAUmS
         TtQ/ZjdZiNWTFPX37TTc+Uu8BK4u9JuUHdvLrDphv3VHm7xjpXCNdjglWjub8ge/mFBn
         ZL4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z18si1586548plo.5.2021.01.19.12.32.02
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 12:32:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A0FDAD6E;
	Tue, 19 Jan 2021 12:32:01 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 24D853F719;
	Tue, 19 Jan 2021 12:32:00 -0800 (PST)
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Leon Romanovsky
 <leonro@mellanox.com>, Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
Date: Tue, 19 Jan 2021 20:35:49 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119185206.GA26948@gaia>
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



On 1/19/21 6:52 PM, Catalin Marinas wrote:
> On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
>> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
>> <vincenzo.frascino@arm.com> wrote:
>>>
>>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
>>> the address passed as a parameter.
>>>
>>> Add a comment to make sure that the preconditions to the function are
>>> explicitly clarified.
>>>
>>> Note: An invalid address (e.g. NULL pointer address) passed to the
>>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
>>>
>>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>>> Cc: Alexander Potapenko <glider@google.com>
>>> Cc: Dmitry Vyukov <dvyukov@google.com>
>>> Cc: Leon Romanovsky <leonro@mellanox.com>
>>> Cc: Andrey Konovalov <andreyknvl@google.com>
>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>> ---
>>>  mm/kasan/report.c | 11 +++++++++++
>>>  1 file changed, 11 insertions(+)
>>>
>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>> index c0fb21797550..2485b585004d 100644
>>> --- a/mm/kasan/report.c
>>> +++ b/mm/kasan/report.c
>>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>>         end_report(&flags);
>>>  }
>>>
>>> +/**
>>> + * kasan_report - report kasan fault details
>>> + * @addr: valid address of the allocation where the tag fault was detected
>>> + * @size: size of the allocation where the tag fault was detected
>>> + * @is_write: the instruction that caused the fault was a read or write?
>>> + * @ip: pointer to the instruction that cause the fault
>>> + *
>>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
>>> + * the address to access the tags, hence it must be valid at this point in
>>> + * order to not cause a kernel panic.
>>> + */
>>
>> It doesn't dereference the address, it just checks the tags, right?
>>
>> Ideally, kasan_report() should survive that with HW_TAGS like with the
>> other modes. The reason it doesn't is probably because of a blank
>> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
>> guess we should somehow check that the memory comes from page_alloc or
>> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
>> instruction to check whether the memory has tags?
> 
> There isn't an architected way to probe whether a memory location has a
> VA->PA mapping. The tags are addressed by PA but you can't reach them if
> you get a page fault on the VA. So we either document the kasan_report()
> preconditions or, as you suggest, update addr_has_metadata() for the
> HW_TAGS case. Something like:
> 
>         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> 

This seems not working on arm64 because according to virt_addr_valid 0 is a
valid virtual address, in fact:

__is_lm_address(0) == true && pfn_valid(virt_to_pfn(0)) == true.

An option could be to make an exception for virtual address 0 in
addr_has_metadata() something like:

static inline bool addr_has_metadata(const void *addr)
{
	if ((u64)addr == 0)
		return false;

	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
}

Let me know what do you think.

Thanks!
	
-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/418db49b-1412-85ca-909e-9cdcd9fdb089%40arm.com.
