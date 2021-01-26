Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDGBYGAAMGQEOJE653A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 271D130464D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 19:33:50 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id k16sf12078500qve.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 10:33:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611686029; cv=pass;
        d=google.com; s=arc-20160816;
        b=roWK+l0900xMqW1ERU7+m2oY7jXAhs6lMrl4Au5F8ZddGabTo73cgI31PBjsiZ3CGJ
         TEIXkDG1xoVHzz7lFsIeMu/DbTdBidfAnDHFWGzyndLvosOdVf8XLz6wXIORvc6qeAy4
         dAgtIOui1vgQG4Mcd5wHROkuyZycRI6xaj+ODgI0E3SCaIAgqdOZsMq7bU7PPmlzICjS
         C35oK6q0rJErYS3Qk0mCs1PIrHTpswS72ADevZtN8t19WWaICfPkHBgVr32gwYAwWYrK
         95lWVxM310koLmTm3pH5I4efiVjIOa+RbSE2m+a052m9yJ473Y4lUv9ZnG4/+KGe6fq6
         4V2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=6pE9DKEaj8c6uUhJjouqVegM6dpnytx6G43lrdr5mwU=;
        b=g7BmdEkfwUd6fAU2TbyxPYwpJaYlCIE5w4MlEn/U5JO33HSk72jN4hTeTckZu/c6sB
         Lvyd3HBDuxcSgStBL5VRePRtGaMn23bD6GylsGv6L4l+LfuOUr/mi9hYptXgxp2KDKbk
         hbQTL/pCKF83yHFv4/g97LJVlgNYUCoO0aQyC5r4yo7mbttkPWssNFJNpwUd06AadtS2
         ZD6nUNjQKVMO5Vj+yuXk7n7OppCGSgsIIzANzC84qNhQj3uDzQR4tQWAgaEoLsi3Ll+Z
         p207KgoKndumJOi8VNdAMay/IKJdzthgdJDhyUbIG76jCgJQoyhTShEQetCB7d2MAviH
         N1kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6pE9DKEaj8c6uUhJjouqVegM6dpnytx6G43lrdr5mwU=;
        b=ZMYd2trOm4H1lksHw4Y6B/XwUjzdv5xjSwCQiuAbBMTkXPi4WrfeFaCVdmkfoREocv
         wfMkbY9RX+lADnGaXM9Xm9f1Ya648/t4NtsFKqVqm1qudceGZPyITDAwZjEm0tkb96IF
         mosOfA7An3j1ndB6E8VnO1yXjC2FHEhF5ovDD6+DDR1VgIDZKfe3PymwGrEImf9DBC86
         l3++REXTlQVNUxla+r3TsU0pm/lI962dfEdQiqm0YRILCRGQ74drLZGXfu8bbOX5BJcJ
         fX/xM7NHxkXn7wCRL9dVhmga2S5A3t6TtgBk+Sts8N4lrB3xfds1cFa9+yL4s6Cu4YgV
         fY8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6pE9DKEaj8c6uUhJjouqVegM6dpnytx6G43lrdr5mwU=;
        b=IKVh7dI5ZZ8/eSNrF0pc3IRi0pb7+4kWgI6Kr4zottzbf2xSDE6BrUx86A3S7ihNkA
         dXe8O+G3XKtnJjILrxJX7CHKwQJMntNrb8dNLB/4ICDdO6Z2tcNYaRs35Zlsmk/D3zGh
         AQ9HlFx+w+My7VQ1TlIEBXm3fRmqR8TMVKrJUUIRtfSjXFYw1PwIv1P1orc2OFXq2I5O
         6mxjmb8Q3mpvISSuKw0ukccN7eoIjZFkaGjNrIN09wPGGosDG8ybvsBNKv+oSiAzkK40
         gcUbc812UByWmoS9EFQPLh6+1jQEOUSu0pYu41eD0R6RsqtW89kC4sselJIo95Aj8Rxx
         pGXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w6P9SrSH8MM7mqDds1lugj2WtLxx6/FsvVebzJqWGGLmvmWOQ
	Z9sIoQTZPORRMtyylMp/ZJ4=
X-Google-Smtp-Source: ABdhPJzNYzrqGQStsXfmI2faPIAAf+bQ3BEWxgnhAlT0vOs1GyN8VXlbEe0j+Tim9qzMMxYvTLFiPg==
X-Received: by 2002:ac8:718f:: with SMTP id w15mr6366867qto.179.1611686028896;
        Tue, 26 Jan 2021 10:33:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls6708353qtl.9.gmail; Tue, 26 Jan
 2021 10:33:48 -0800 (PST)
X-Received: by 2002:a05:622a:3ca:: with SMTP id k10mr6474577qtx.270.1611686028424;
        Tue, 26 Jan 2021 10:33:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611686028; cv=none;
        d=google.com; s=arc-20160816;
        b=nsSKXFp3NkObVe6w+wKcfUWCUjDSA04nYUH1qkwZ16+CQZUjtggjHaSav09gAYaYeo
         M9MOO7EisqqhUqHMpc6AosThopASmOouG6VLVd35BynULFrPJmj5O8CLA4pBdzB1KHAK
         Ul34Evi+2+L414riCMAXptMHfZ86ODKeN76SyTvYODtEZM6kUxG6zi3g+A4ut9NE+JBd
         pVRu/2TEet7nXz6G8kkfYaoQbEo4IZ6mt/5oNJOZ300k76o3lCj+Pwk4mZVI0+8tU1QW
         LBVk8w+FOTEQS1Xsj49kemsGHF4JxIvuZPGJt/n2MUpHDUNWVgOkhUAfh91RI0XBhG5U
         hVzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=sc9panwwd377GgpGT74VhsH8COd30eTzM5wnSPWv8ug=;
        b=TBH9OqZbG5twyOiN2XGv9+sh2gIB/wLWiL/8EPO7jJ87Oayk2dapRSSOrQm8zP/JH3
         wI7oOTJd0rs2iuhxqCbNAxGFEPhxTMJW92YN5K455DJ4muj/B7m1Ae9J3cD0hMj1RpvV
         TuFwF0xAwEWIlL3yMjgaMOlAGJt4rVoW6JovNHTN56vUVZ8aZi/qX4AzuKpw1V0cJodV
         SNH4VOLL/H0sjdlplNu3F3Dl1nDeI/+c28Kz5uiNTM/6jzPbn+RtzOFBWAObrkuTDPp6
         5Rx+HFyO7rcMJn+W16pxOxPfDqk9gwl0fCSSvgVzHkDb9Ysmr5I0wWHaSY36Hkp0bdA2
         GRlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j40si853685qtk.2.2021.01.26.10.33.48
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 10:33:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A2E0D106F;
	Tue, 26 Jan 2021 10:33:47 -0800 (PST)
Received: from [10.37.12.25] (unknown [10.37.12.25])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F2E5A3F66B;
	Tue, 26 Jan 2021 10:33:45 -0800 (PST)
Subject: Re: [PATCH] arm64: Fix kernel address detection of __is_lm_address()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, stable@vger.kernel.org,
 Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
References: <20210126134056.45747-1-vincenzo.frascino@arm.com>
 <20210126163638.GA3509@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1fe8bff7-3ed2-ae96-e52b-dad59cd22539@arm.com>
Date: Tue, 26 Jan 2021 18:37:39 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210126163638.GA3509@gaia>
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



On 1/26/21 4:36 PM, Catalin Marinas wrote:
> On Tue, Jan 26, 2021 at 01:40:56PM +0000, Vincenzo Frascino wrote:
>> Currently, the __is_lm_address() check just masks out the top 12 bits
>> of the address, but if they are 0, it still yields a true result.
>> This has as a side effect that virt_addr_valid() returns true even for
>> invalid virtual addresses (e.g. 0x0).
>>
>> Fix the detection checking that it's actually a kernel address starting
>> at PAGE_OFFSET.
>>
>> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
>> Cc: <stable@vger.kernel.org> # 5.4.x
> 
> Not sure what happened with the Fixes tag but that's definitely not what
> it fixes. The above is a 5.11 commit that preserves the semantics of an
> older commit. So it should be:
> 
> Fixes: 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using __is_lm_address()")
> 

Yes that is correct. I moved the release to which applies backword but I forgot
to update the fixes tag I suppose.

...

> 
> Anyway, no need to repost, I can update the fixes tag myself.
>

Thank you for this.

> In terms of stable backports, it may be cleaner to backport 7bc1a0f9e176
> ("arm64: mm: use single quantity to represent the PA to VA translation")
> which has a Fixes tag already but never made it to -stable. On top of
> this, we can backport Ard's latest f4693c2716b35 ("arm64: mm: extend
> linear region for 52-bit VA configurations"). I just tried these locally
> and the conflicts were fairly trivial.
> 

Ok, thank you for digging it. I will give it a try tomorrow.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1fe8bff7-3ed2-ae96-e52b-dad59cd22539%40arm.com.
