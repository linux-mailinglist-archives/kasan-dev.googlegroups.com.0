Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZ7ITOAAMGQEVS57EBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDF302FBA9D
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 16:02:02 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id l125sf10824819vkh.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 07:02:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611068519; cv=pass;
        d=google.com; s=arc-20160816;
        b=aDh6gA+MbU5l2+bnHU/WWd5UAA6/ltmJxw98QbC47U5pqxPalrnHrHrqsxw9OpHJfJ
         YMosxZdloWaD7V4Lft6R3cAuU45UrV96EdsvDj0IoXptxtfLwMmGhvHLs0rRZjgwTgBk
         n9vBiywt1htngLyikKgwRKY92LhL0HfQyc25RBYHPvZiePH6lMCcjGD16a84GHjrBjQU
         O9Dhw7WBnVdbKI5mvh4QQCb7n9xO5uaa/Sku1Wwk+R20TI02+VN8aqxWy+Xnx2vVKJB+
         dwulNyUXKYZ5duO42POlOO6ffv6eZVXtbVi37ET85bgFxsQwcwODQb1sbjA4ii3TcB6U
         plLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=I1gN41v3erCkDkCfNOBnYQdxU7lVuhN5GIxE66R0v8Y=;
        b=jQNprKNzQ796gLoxvI6w2ejblHGph6zIjhJHtV32fT280cypP+wxw//0dBqhPuyQQ0
         GNgX58izEhQOrd5lIBRJ3VSTWpsyWcowOuBbpyzXkCSTkg6QjpFxsjtp7HQTnqQ8NvDx
         cREUminxDMhpylRVgfnBRJBCAagzLMkryLbAYxnaLwdnLIoOt1e0YC10Cfm6Ei7qUhPl
         fXLXJ8ezIPrKjlCdpTxVrd2yIvt+HSLFcdKNP4eyrWLGBqGmU/j8J5Vj2u/EY57g64mk
         VBSnKH6hfP72fI1DSSLeWHF+LnHOBqQfkblEB6ANvIz8O1Y+FOyLVIvNkI3enbIUJHod
         hang==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I1gN41v3erCkDkCfNOBnYQdxU7lVuhN5GIxE66R0v8Y=;
        b=BeXgpI5L2BU7U39ZDkmdjuX/Z1uqxMJI9WwX48xuGqvCvCNw6HZB8xDzpoLy/BGs1i
         0JZ+lf8N8IQbyKrqDKtBhkuUpM7LCnb5K+upz0TU0OgoLiUN52PjC+jz+5vn+Mu+lvmo
         LH8o6moZyeSoS98NF8alCb91XPPKOxB4kutIwzR5bi3l1Rm8XZ1gVykTbIGdkx99NP1/
         gdAB2AgvG+8J5tEFflOKdToHdaFuHTiwnGzMwmqNFMh1T3q4NpVLotFxiVcyPtOJB8Eq
         v6F/mIRIjspUz5A+meZj8D7vzhqlR4dtRsHY1zMREuqfC2RnSwqyPAy0FRWNp0YmSEqg
         75mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I1gN41v3erCkDkCfNOBnYQdxU7lVuhN5GIxE66R0v8Y=;
        b=XxYazRY9/jrmpVDKsx+FJBy8MISVj/PAOwguQzVoItqn8viaGCHeqmovG6PDW1zFki
         KGrcxLOnCja3DnTjhpPajl12ArWXVl0+mMeUaVWeoS007LorMK4LHAibf8MDBVmBdtJr
         J+csa0nBmUSkfeVwEAuJej4EumUN8RM02aZcg+9O3qx7Ij7IiWFyWS/gnOQ6AsZqAlR8
         dDam4Ygad7scEuc6Y4v6DNiOfIs3AfskxSSuX2INBwHWgWJJnej+Wbj33TbgLcI2DdNz
         H6d6pHm5C11WaSrgUbVhzDHZwKr6Ys7RpE82tIs0ha8wjvKBmxCOBdJOzXRrxjno/Eco
         PJBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dLnNfbVYS2agLDCAB06VPGk3BGooUmmYUC3tJVcT9csOoqLp7
	PzhNcnXXyQQxTqwTaR1K13U=
X-Google-Smtp-Source: ABdhPJxuPmdLssE84bFuGOdyd1AgM6RgQc2w2B3Jt+5mBm2sTmsdnawgk7AllhvMhAuqljNpYXVyVQ==
X-Received: by 2002:ab0:2549:: with SMTP id l9mr2524728uan.128.1611068519706;
        Tue, 19 Jan 2021 07:01:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:30c2:: with SMTP id k2ls321080uab.8.gmail; Tue, 19 Jan
 2021 07:01:59 -0800 (PST)
X-Received: by 2002:ab0:4588:: with SMTP id u8mr2541766uau.41.1611068519085;
        Tue, 19 Jan 2021 07:01:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611068519; cv=none;
        d=google.com; s=arc-20160816;
        b=aGTe1PVohF4sKC7xnbhRFCj5paAqigj4XcfdBQ0tFilv9k54qafOjsRktSf/ke/lem
         aC5V79kEUdK/AxxuAe2uI/uigeCtrKYl1hD8XkjpXY//tZvEhrktL8MduWI0Ig9KwEcF
         BcYB/W4V86n7Z+BVqfriWp/D/RRZ/ADz61UAO3jFuVVi2Id4xlRq0t02SXmr+OhF/kap
         T2ySSkKKGPa3nDR7K/kX1Iz29GKCKousWsOiw5YR9p/Fvgp1T1wgg1DFvlFeBi6/pxi6
         dcFW2qx7DjBvLdYLD+vdkSoiTnf2uDkzMMtk3JtPfeoFkiqKMjMqZk/2IpnCe5JHQF3e
         XSqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=tLqW3vSN9B7n0h9/TIoy592DbxYcTCCDenF/hNh1aJg=;
        b=jPUX0xGFN34elTw/V4rZCQlls+iMkDQodW0f1LME4Hy5LvJxmYCBGF7t7+5a6SpuP5
         U5EhvkvzNBLJc7xGXRceq5E3HJR2vw/Sr0enQfR5LluyKsokbI8Mer6oFgXo0u0PcfwH
         eVkwceuO51/ZrztxyIINmWFQPGDfOwUIEIjNmAYsy/vJ3i//OXeVjZ3XWpZ21mm5KCIq
         2dQHF4ZOWMzvJ/k1eW/SX28kue+4yeRL1Zfj0k+JC7tTJ1CqFXQL95xvL7nAtPUjK1BQ
         HE3g33Bzy9ZDfx6NrrVxKlf6O4D2qmvayPhMIPAP3ls2dkBQvwqqmV9+ZjdBO5kbvVVk
         2I1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q11si832838ual.1.2021.01.19.07.01.58
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 07:01:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5911DD6E;
	Tue, 19 Jan 2021 07:01:58 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 409AF3F66E;
	Tue, 19 Jan 2021 07:01:56 -0800 (PST)
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
To: Mark Rutland <mark.rutland@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
 linux-arm-kernel@lists.infradead.org,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com>
 <20210119130440.GC17369@gaia> <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com>
 <20210119144625.GB2338@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ebcc47e0-5d8c-8642-2e78-09eaad81aa4a@arm.com>
Date: Tue, 19 Jan 2021 15:05:45 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119144625.GB2338@C02TD0UTHF1T.local>
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



On 1/19/21 2:46 PM, Mark Rutland wrote:
> On Tue, Jan 19, 2021 at 02:23:03PM +0000, Vincenzo Frascino wrote:
>> On 1/19/21 1:04 PM, Catalin Marinas wrote:
>>> On Mon, Jan 18, 2021 at 06:30:31PM +0000, Vincenzo Frascino wrote:
> 
>>>> +bool kasan_report_async(unsigned long addr, size_t size,
>>>> +			bool is_write, unsigned long ip);
>>>
>>> We have no address, no size and no is_write information. Do we have a
>>> reason to pass all these arguments here? Not sure what SPARC ADI does
>>> but they may not have all this information either. We can pass ip as the
>>> point where we checked the TFSR reg but that's about it.
>>
>> I kept the interface generic for future development and mainly to start a
>> discussion. I do not have a strong opinion either way. If Andrey agrees as well
>> I am happy to change it to what you are suggesting in v5.
> 
> For now, I think it's preferable that this only has parameters that we
> can actually provide. That way it's clearer what's going on in both
> callers and callees, and we can always rework the prototype later or add
> separate variants of the function that can take additional parameters.
> 
> I don't think we even need to use __kasan_report() -- more on that
> below.
> 
> [...]
> 
>>>> @@ -388,11 +388,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>>>  	start_report(&flags);
>>>>  
>>>>  	print_error_description(&info);
>>>> -	if (addr_has_metadata(untagged_addr))
>>>> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0))
>>>>  		print_tags(get_tag(tagged_addr), info.first_bad_addr);
>>>>  	pr_err("\n");
>>>>  
>>>> -	if (addr_has_metadata(untagged_addr)) {
>>>> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0)) {
>>>>  		print_address_description(untagged_addr, get_tag(tagged_addr));
>>>>  		pr_err("\n");
>>>>  		print_memory_metadata(info.first_bad_addr);
>>>> @@ -419,6 +419,18 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>>>>  	return ret;
>>>>  }
>>>>  
>>>> +bool kasan_report_async(unsigned long addr, size_t size,
>>>> +			bool is_write, unsigned long ip)
>>>> +{
>>>> +	pr_info("==================================================================\n");
>>>> +	pr_info("KASAN: set in asynchronous mode\n");
>>>> +	pr_info("KASAN: some information might not be accurate\n");
>>>> +	pr_info("KASAN: fault address is ignored\n");
>>>> +	pr_info("KASAN: write/read distinction is ignored\n");
>>>> +
>>>> +	return kasan_report(addr, size, is_write, ip);
>>>
>>> So just call kasan_report (0, 0, 0, ip) here.
> 
> Given there's no information available, I think it's simpler and
> preferable to handle the logging separately, as is done for
> kasan_report_invalid_free(). For example, we could do something roughly
> like:
> 
> void kasan_report_async(void)
> {
> 	unsigned long flags;
> 
> 	start_report(&flags);
> 	pr_err("BUG: KASAN: Tag mismatch detected asynchronously\n");
> 	pr_err("KASAN: no fault information available\n");
> 	dump_stack();
> 	end_report(&flags);
> }
> 
> ... which is easier to consume, since there's no misleading output,
> avoids complicating the synchronous reporting path, and we could
> consider adding information that's only of use for debugging
> asynchronous faults here.
> 
> Since the callside is logged in the backtrace, we don't even need the
> synthetic IP parameter.
> 

Agree, especially because I tend to not like to rely on compiler builtins and
what you proposed solves the problem ;)

I will refactor my code once Andrey had a chance to take a look as well.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebcc47e0-5d8c-8642-2e78-09eaad81aa4a%40arm.com.
