Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBRMLWT6QKGQE6ME3HJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 172482B0247
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:52:06 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id e8sf1539001vsb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:52:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174725; cv=pass;
        d=google.com; s=arc-20160816;
        b=BOaD+9g2reDeRnrUsKJrg5ydUSHsy7HYsFWYlcTiISf+RmadtxGiV3EukWwnHtcnLT
         Br7eeSXLOWcwR7AHVJJgi/jBSmXtEWrJcKBZpkWdxTsGFqzSM98/btKwtVhnnLING5eM
         x3WgnZf97Dx5NFBHTUrBJjiRDUfRSEV46pqii4DhnbeJxFfIUWv49fXT7tQMrnDeAh0n
         RDsMRpnMGXK3K47OCtvnKMYPHZdXEVBslYqBBxlC3VP3mZa4g6uMQbepXGTxi+n3nPjJ
         uyrg4Eup38xegcQeFhsWEyIPH/JJUySCIMEWIIkO00U3XNzOlJmAj6gqx6aSRFyN68y2
         6SeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RTfKLTTWR4fbZblAXB0RgcvqOpvkAupvVUgGMz7sCWA=;
        b=uLZq8jlQVFy/Lo6oeq/NIEji775MsPRj7lvNcsPwg4Bnb2SKfht94db6YI/JLLIAMc
         EEx+UtSTBmGR8bkqVwKtrNh5z0t0rO2dexB0Feo+IQI6FqFvMj2mxpa4bxcjbVFmDeMj
         A1mWa/H5Rnk0w05o4604ebxsqgh69jdV3V5TMBcPZ/IdX0tiISVqA6r2pYOpyrv9ls4J
         y3O7CWZcBidQTQPCOpweI70J65XbFCjQukDzgSzMgbHfxj4z2mDvw/RrH9QuUriziHiM
         /vNutrXEG2O7YxhubrVcah3FBMh/f5tV0V+9BOYuazZVTzJDst4p2o2SmOqvc3pyLrxe
         KcfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RTfKLTTWR4fbZblAXB0RgcvqOpvkAupvVUgGMz7sCWA=;
        b=bnjTPPqc2oRq9L+c7wYGPdpfBSVd5Wr0o8wnIihxea/dC2mJyM6OtWbG4WjjvrEbXb
         d3v0dbPcrK8tpBWO9HoBMQpusH1l30A2hQbzDj21/vpvL5GH5sgNcxQcl00Kjom+LoA+
         MNL5rcYpkK2PlOyzGnGz475B0AwkzpcmecjMshJWfLMDgbAESJOYwWh//Rb1+vmihYc1
         UkL3A0TzwqLMm9TDy/Nb76ISb6wpzn9NLoE84IPIXw/hFJuIMH9weYuvcyhfODy5Saq+
         E/soXXsUuOKqg4bctRs9PmGMI2r0RengFhR6Yhe+DvTb9RzvP3LNB0KXp65JEJqDw+Lv
         mpAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RTfKLTTWR4fbZblAXB0RgcvqOpvkAupvVUgGMz7sCWA=;
        b=m72Xz0KX1/hkbUHv5xgmeIWVB+OLxql+MGslFW1mUyYcsTzXxn4NlBI7GsPPrVYoPn
         znzVQ0yU6Cdu4fcMJ0pK5rfNimqbFI0Twda2PU9I8kE+yi/EB22eKZWhKOfqCdBTUz7J
         iuWQlp/TOSWEVpdCcj9x0gr706yLqqm9sQJXCnaX6DNMfgJXrZz5rZ9rTAdkmDllEtds
         T0vcNK4OC5IvcloJU7NQyL68WpyLnF0f3OJVAZKUmxz3dVdCEB6Mzr4/K5dlMHo8E5hk
         YKtXRzWbPLUAXlndn3GyWjnZwXn4nfyG2e+puGBRk7b3jRw8gPP4AehOb3jLFElzw4qy
         LaLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303edvZdb7hJ9rLrMAHdhn2lUgTf4NxIBOn/P6bSasysCvsvFY4
	UCLyvsfMHO5mTTUuZ9hWQIM=
X-Google-Smtp-Source: ABdhPJyC3FdvmgmlX7DmQ/hdZGvoRz6o0gZQzXcbxeIA5jB7OEqZJU9t6X4vvK/MeU1JL28vwUVlOA==
X-Received: by 2002:a1f:9987:: with SMTP id b129mr10293548vke.5.1605174725197;
        Thu, 12 Nov 2020 01:52:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f583:: with SMTP id i3ls335245vso.4.gmail; Thu, 12 Nov
 2020 01:52:04 -0800 (PST)
X-Received: by 2002:a67:f559:: with SMTP id z25mr18132402vsn.60.1605174724758;
        Thu, 12 Nov 2020 01:52:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174724; cv=none;
        d=google.com; s=arc-20160816;
        b=sCS9cGD3KfAr3XKa00sI6/KZor2X8schn5/DiJ7cTNJzStmbGEWGoEN4I7ypBnpPfb
         plzyHUJAlFqRzhAxD+rr+X3zTXthaWcJxPHXb4nv+Gs8VtfJZTlAa39PMtiY59FZKRW1
         thnh+QGcJjYSd9WHOS/zr5cF00vFcFaREWD5eOoyxm8i0nSGNrPd6cpTwaRcG72PhERz
         G7L/S7AdBN6ZlZ6BZnE7LQJwL5nyndEKNEk5Ab+mu/7Ld5DPxGt2m5WCJ4ZjC645hCJf
         /MWogfvdaaqFeukFYv2QqfnOAMIzFybIcHJaP+Rp9Hhorv/mXVJFPuQ+oEew4/ArsFma
         tDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=FbK46oGbXzEFVDttHTQ3Iw6UvsSC9wmqXMYA5kDM4fk=;
        b=w0ZPOxpLLqYQU070Ymrp8uCkqyNxeEnpHUtqDBnbU8uBMkQIQ1WnksozUVGG3Gy+l6
         FRKyeSF7ydWqSgO7EFaBIr+oYOfcvnj1mJKvfIMjyvKI2wzYVxjhsoXNP6CuboMNhs/o
         7gDp80EPuo/fJgro+xWNgL6LzK0fdt8ZVUmRaWXcdjQh9RDmlVUK/PBdMe1XJYCoBVTx
         vcKRK1JjRha0muvT53qwZkvh7eTDUCoByP0WcUZ2hrenRfvQDuFsXopmGEs3FIQIBZNv
         6QcJ6UaXVf3nJJR5wdSjR5gotvbgEHHZZdO7UUphdEq01TidY+urgBD5oNPFKoPqM00o
         va9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p17si369107vki.0.2020.11.12.01.52.04
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Nov 2020 01:52:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 54D9E139F;
	Thu, 12 Nov 2020 01:52:04 -0800 (PST)
Received: from [10.37.12.33] (unknown [10.37.12.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 47B643F73C;
	Thu, 12 Nov 2020 01:52:01 -0800 (PST)
Subject: Re: [PATCH v9 32/44] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1605046192.git.andreyknvl@google.com>
 <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
 <20201112093908.GE29613@gaia> <db6e3a5d-290f-d1b5-f130-503d7219b76b@arm.com>
 <20201112094553.GG29613@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6aec6a77-f9b0-cf73-6bf3-4f8df8f8cd13@arm.com>
Date: Thu, 12 Nov 2020 09:55:05 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201112094553.GG29613@gaia>
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



On 11/12/20 9:45 AM, Catalin Marinas wrote:
> On Thu, Nov 12, 2020 at 09:45:45AM +0000, Vincenzo Frascino wrote:
>> On 11/12/20 9:39 AM, Catalin Marinas wrote:
>>> On Tue, Nov 10, 2020 at 11:10:29PM +0100, Andrey Konovalov wrote:
>>>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>>>> index 664c968dc43c..dbda6598c19d 100644
>>>> --- a/arch/arm64/kernel/mte.c
>>>> +++ b/arch/arm64/kernel/mte.c
>>>> @@ -129,6 +131,26 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>>>  	return ptr;
>>>>  }
>>>>  
>>>> +void mte_init_tags(u64 max_tag)
>>>> +{
>>>> +	static bool gcr_kernel_excl_initialized = false;
>>>> +
>>>> +	if (!gcr_kernel_excl_initialized) {
>>>> +		/*
>>>> +		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
>>>> +		 * This conversion extracts an MTE tag from a KASAN tag.
>>>> +		 */
>>>> +		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
>>>> +					     max_tag), 0);
>>>> +
>>>> +		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
>>>> +		gcr_kernel_excl_initialized = true;
>>>> +	}
>>>> +
>>>> +	/* Enable the kernel exclude mask for random tags generation. */
>>>> +	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>>>> +}
>>>
>>> I don't think this function belongs to this patch. There is an earlier
>>> patch that talks about mte_init_tags() but no trace of it until this
>>> patch.
>>
>> Could you please point out to which patch are you referring to?
> 
> I replied to it already (or you can search ;)). But this patch is about
> switching GCR_EL1 on exception entry/exit rather than setting up the
> initial kernel GCR_EL1 value.
> 

Temporally after I asked ;) (I give you the benefit of delay of the mail server
;) ). I think that during the development the logic changed a bit, but I agree
that the comments are outdated. I am fine to move the code.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6aec6a77-f9b0-cf73-6bf3-4f8df8f8cd13%40arm.com.
