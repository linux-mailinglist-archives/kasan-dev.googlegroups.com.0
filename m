Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBUFBQCAAMGQECFA43RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9429A2F5DC7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 10:37:21 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id u66sf747601vsc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 01:37:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610617040; cv=pass;
        d=google.com; s=arc-20160816;
        b=fKrU/r4n0ibeSsQk9xSnWssCJNB00lAvCchsb7+B1cuJNjHnzp5k4QZZPpXRq44PAY
         jhz6mATm3h1wWCBOmBYea9BlbLICMNpUjJp7H+/UFYeaA/8Iv1ClWMS3/D4C3LfkhRez
         LFNIVt0LkIxYX5KA2Sb7GW4uJedfx9zehA08CaiaEoH1yaa+g8E+iNDoUGRSpc2nMLcR
         ZtAOClM641saUU5hO1PIf769fuqTIZ5eZQBAG3aG9ZAXJZDimxEmn/kwtWCD27kZAwFx
         ZA8547YD8MYTCTE8TRibQsMFw9zesOiAM6TfhOdpVcluYKfYAuBRk8I+QYSlqxwzT8JZ
         TndQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=7LboBco5rZSDIhZQepQIV6UikS1oYlZ0hUAIZaHM7aE=;
        b=FMhac9xJ35S54vxy3ZG7spUQvxvwlaLsbouZ4rIz0mK3CaWZfldljfpw/zeeXJqBHx
         kZNZcR+LAdVKSV9O2slcXPqRoygyDt5+x8MwdoO8+irh5MQXzhOQ1y8vpCLtUNMBXXxJ
         1Lr9S8LF5ZbLEIG2hLrwAgX7RmDkcGEcovytOQNqMLnU7x5CCQaGcw20s/DFN0jBPj6w
         hzdx4jVE3Q6f5I3mwWxtql+MNNVfKGcegFaqaRW4oZwvcFZJi6lxnzOGzPY0UkgV4As0
         +En3ah3VzNcKZPp2nDq1fw003xreDOeT0M6NqX75Ls78p8gdRZpBrwVBZFs2Hv7FHpUW
         U4Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7LboBco5rZSDIhZQepQIV6UikS1oYlZ0hUAIZaHM7aE=;
        b=kakn6FA2ZVJezOiyYvG1L1fBs7Ukz4lRcIXGLJRxzMAiWSN/7FP9fS4fVKepx8z3hK
         m//DR8+lmkekJqHmbrbfW/Zqs7cQmshJkAc3ZOcnfVkS0T0umv2R7d9wPo1//8fv+tOx
         tDx0PTzvpwEN1+lNmy3DWrSCbZps3iAPxdZKceRbKoecM5bEqXHvpAbakn2danFjWjmI
         GF3HOEyzRZ4rhli96hs1Rm4BHS71uQdKIgVgJq3kccf0/VAg1NvNHgN6NqGJxzT62gaN
         UWmrHr3y91hAM45E9cCEkRjHPTZZP/6fvtFw//5aGhUF1wwTAKRCZH1xkvwFXBrtNK90
         mPzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7LboBco5rZSDIhZQepQIV6UikS1oYlZ0hUAIZaHM7aE=;
        b=tLNbghjR2XavWYDHOfWiqEiKKzOWaO9Bpv37mwlC4Ikw+yiZIx2grlLEk0fTroxaZm
         tyj3SO7IsGzgustvznfjLJPxTlxap/616AQljkpo+AS9dNWtpHmBVUd+UT7NeFZB3pKT
         lb5KG/sVbh52LmGLjG0/nEmnlaZ3ssPnbO/Bfi+n7pqgsiNnnfu3pq7m6o4BWx7PccIi
         EbU72P1eIOdHBh7tU4MB6baLPLb+RKkPksLE1PTvrAV+5WXiwKH+AA+c0s3cVMeg8jSS
         86ogxiorKjdQJsEB6EX/DlCbTIGWtiJJbn7vjcSpaSkMAcRMECGqxRtVhAv3SCHg57a8
         eZsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ym1108+0oqgxA18jEa5QxIJEHn7aQbHI7d6NqWGBPq7VsI0ws
	qhqLx6GZinh8cPmt1mT3DiM=
X-Google-Smtp-Source: ABdhPJzjiW8Mx8w5jAftAj2TVcr1Wwy4Saa/PI0a2uAog86+PwMvtmwqZEbtCeSgaFZvI8jAD63SdQ==
X-Received: by 2002:ab0:63cf:: with SMTP id i15mr5094656uap.12.1610617040402;
        Thu, 14 Jan 2021 01:37:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:22d4:: with SMTP id a20ls564871vsh.10.gmail; Thu,
 14 Jan 2021 01:37:19 -0800 (PST)
X-Received: by 2002:a67:d989:: with SMTP id u9mr5513649vsj.27.1610617039868;
        Thu, 14 Jan 2021 01:37:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610617039; cv=none;
        d=google.com; s=arc-20160816;
        b=aQBPJV5gwWgA9WuRs2Z2o65X2mclwk3yEPNi+Gp/Fj9SOq54CdCi8FrvUe3bOaMBZf
         vcMhH1FQCnEbfQj4mx2d7GHJ2hVIdRbzpU9ovF4Pz0SM17S3w0w0qElJ2vqGz06JTBrb
         9aE6+Mhjye9FOGMKUsHqRWBc0i6Q36kOQ+nM+TsXmRkC/H3G/s3IsmvibS3vKH+dIHvk
         RJXU9W6YJwQEM+ZUz6wPFMehqQmCstt9of+/OtiOuHePjSth6EMJ7EoaoUfwG6tzIJBD
         3RUMyUkgpIPU6zSMhDg7k5fWODC9NxFlgP5kZQ54UxJSdqTZyYjaNCaT8pjnlZ+5pglW
         JCYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=R+KrOgn5LAvg0ic4lYSFJ5QcjCpKw3ErmTywN5zXVgI=;
        b=nUJkG4Q7t/NEQ01pa1KO5sZ20h5C/52/ATi7HtlHUitQfwCGVnhzY4IG6yPq7e+Vxz
         Y0oaTeBCYdp4R8Y+UQmWYfjYz9LHC4w3PhXL5TFdSvYgBXZrTFj/RXb9kBvcflDIB8YF
         m4CQwzqXg9JpA2a9hHyZ4YFKnNmqKXqyK7g+FpqmrTJpCl9nt7Pm4BySkDcY6HsQc0k/
         au/Sd49hpqa2+Z18wxE5E4KGhJRJ81Xmf8xiGPkriTGwUQRTjKFOtqzFrqFBmRNkPWhm
         Yu1W5GRfN7J+AGn7EzN2+3vdKjO+owdVxAg4tTkMhcMiC+mcTuCIae3qQ4vk3niyMtT+
         BLZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g17si320901vso.1.2021.01.14.01.37.19
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Jan 2021 01:37:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1CB3E1FB;
	Thu, 14 Jan 2021 01:37:19 -0800 (PST)
Received: from [10.0.0.31] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 66C6C3F70D;
	Thu, 14 Jan 2021 01:37:16 -0800 (PST)
Subject: Re: [PATCH v2 1/4] kasan, arm64: Add KASAN light mode
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-2-vincenzo.frascino@arm.com>
 <20210113171602.GD27045@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <7125af39-2572-1b08-d223-51f4ea6e686b@arm.com>
Date: Thu, 14 Jan 2021 09:40:57 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210113171602.GD27045@gaia>
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

On 1/13/21 5:16 PM, Catalin Marinas wrote:
> On Thu, Jan 07, 2021 at 05:29:05PM +0000, Vincenzo Frascino wrote:
>> Architectures supported by KASAN HW can provide a light mode of
>> execution. On an MTE enabled arm64 hw for example this can be identified
>> with the asynch mode of execution. If an async exception occurs, the
>> arm64 core updates a register which is asynchronously detected the next
>> time in which the kernel is accessed.
> 
> What do you mean by "the kernel is accessed"? Also, there is no
> "exception" as such, only a bit in a register updated asynchronously. So
> the last sentence could be something like:
> 
>   In this mode, if a tag check fault occurs, the TFSR_EL1 register is
>   updated asynchronously. The kernel checks the corresponding bits
>   periodically.
> 
> (or you can be more precise on when the kernel checks for such faults)
>

Yes, I agree, I will change it accordingly. What I wrote has a similar meaning
but your exposition is more clear.

>> KASAN requires a specific mode of execution to make use of this hw feature.
>>
>> Add KASAN HW light execution mode.
> 
> Shall we call it "fast"? ;)
> 
>> --- /dev/null
>> +++ b/include/linux/kasan_def.h
>> @@ -0,0 +1,25 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +#ifndef _LINUX_KASAN_DEF_H
>> +#define _LINUX_KASAN_DEF_H
>> +
>> +enum kasan_arg_mode {
>> +	KASAN_ARG_MODE_DEFAULT,
>> +	KASAN_ARG_MODE_OFF,
>> +	KASAN_ARG_MODE_LIGHT,
>> +	KASAN_ARG_MODE_PROD,
>> +	KASAN_ARG_MODE_FULL,
>> +};
>> +
>> +enum kasan_arg_stacktrace {
>> +	KASAN_ARG_STACKTRACE_DEFAULT,
>> +	KASAN_ARG_STACKTRACE_OFF,
>> +	KASAN_ARG_STACKTRACE_ON,
>> +};
>> +
>> +enum kasan_arg_fault {
>> +	KASAN_ARG_FAULT_DEFAULT,
>> +	KASAN_ARG_FAULT_REPORT,
>> +	KASAN_ARG_FAULT_PANIC,
>> +};
>> +
>> +#endif /* _LINUX_KASAN_DEF_H */
> 
> I thought we agreed not to expose the KASAN internal but come up with
> another abstraction. Maybe this was after you posted these patches.
> 

Yes, indeed we agreed and I am going to change it in v3. The agreement
temporally came after I posted v2 hence it is not reflected here.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7125af39-2572-1b08-d223-51f4ea6e686b%40arm.com.
