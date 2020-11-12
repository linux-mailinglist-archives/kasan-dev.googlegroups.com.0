Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGOMWX6QKGQEJNWQFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id DE48C2B0A5A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 17:43:06 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id i6sf4123652pgg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 08:43:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605199385; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRcmJ5OZFN8LTUOMpqg/wgu1O1WxfIQSqWuTnHkUhYQi/y/lGGfQGvRvt+z0YYDrxk
         fe/2psKDpMmm8u6wPJXE/XcjSv9JnrFwrgptTI4q/pwFr547L9PV0WbbKEzPQ7B0KHZb
         Fuz7+uNkcedGojqEW54aRWi5DNSIHYweVletnXaq9KPhKzuHXKO/z8e59D3bK1l3Ok4X
         IDKjSzu/OlOXbP25xxVFDuAATgKG30Y5jLKwGhvOGMhlkDzIPRNpwIohY+pk5wHpnQfN
         Nf8Qivir4AzFuCRqOm+sORVp32HlUyS0XJNYJwIcM0N+LmAewEk1qCDguPa9XukImJjb
         jo4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dMlkTL6LZf4vgv58pthyO0Cd7t/rl390pEPGqDgJhZc=;
        b=SLHPdR1ZSu9562kiOlreSbYVcpwREzCpuMQ+WnR3QT9STP+bcugSB8V4Y7sP0Z4z1Y
         mGZ1yIMKOXqsuRbgVYzoraqAPwyGp5bmiTQaYJJkQRjbKJ7j3/meExqbZ3MGwAW7Z32G
         t2dsDrrJYzW1RfmmW9hEph0R6IJW7V2N1Fq1ZGF+7/vcyNmKqvHmvfXFs+6SYhH92iv9
         BA7uQZyg1TFJdj1hDI5/OohpvJ2de8H6zH5V+V1ri/sRwkm9i1Vrj5vXQvUQqnDUwIbr
         fh0fqzGpXYHpYAGdZi2twMMre4V5/cOBM8VKIJZdTrbzwsB9OIWd9OFbrPwgiaOLy5fU
         BH4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dMlkTL6LZf4vgv58pthyO0Cd7t/rl390pEPGqDgJhZc=;
        b=LbysrLriaPQ3ghqEukeQANzDBnkzvRGlIsw/tmqd6TqdOx9Lx1hd/IKBKNaqJ4HZfm
         7AX6h0+ClprEP/ipgChmKwkyRcWO2xjbaws//6JBQD3y1vwZEJKq1/1tOv7byRCounx3
         l27xdiNiG3POJbGfm9pQ8XzF5Ofs4GMvqnInjyjiZGPb1nCP2kLE5pYCNTIZxrIwrZ4f
         SPRRDZA+8MNa3iwwrB7odnyxlgVX7gURraz/YYfOn2L0GFwPwxFHPWpctYZ4H00d7WlX
         Q55QA0yEFKdeMQB/Mw4n/vVrHw1j5pcBx9NIpZI+ag0XOkOR5lUYMsYGxsCmPQx0Qvcd
         CFTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dMlkTL6LZf4vgv58pthyO0Cd7t/rl390pEPGqDgJhZc=;
        b=RBD2y37y2fTzkcUu/umBdOPwH/K+TkwLj7MqrLy3dBT6WGzy/OijC5UmZZfpXj3wU2
         owUAUvhdzuYegeOO6Y/zElamD4tApqoQCzma03WD+oIPFcUi23ISlNANDPLZL3gV55s6
         q9lLFodrbEHXnQcPTmUkgeJeyM52Ma99MxDsdDp3fKTAgBwA/v/AbGQMFEG+Gxzr/LBz
         VdlTv0XHfrUFLvBBmEm37ENnVgdhCpMwUjqbhyblCgX6Osx9AiZJtjy/XBLoE4z4Lrqq
         NzT4iEuJQu9pr+fs95krJ8/wV249b4wwAL2acZMVuLCEJx3geixbfcFXJBABnPEa0qh1
         1Faw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jdvSFtUfaZ1GIbF8znzaWoCnD3tpHymg6d6y4OuUiVv4vKAq+
	n4takvX2nRgGmTdBjTM8mUc=
X-Google-Smtp-Source: ABdhPJw/Rz0dwNW7SKOc7bWzXib01iHtRVNRRaYYNg/RThYJiusiqYaQnXxgFCu8kNnCeSVUACnhYQ==
X-Received: by 2002:a17:90a:ec04:: with SMTP id l4mr10746937pjy.131.1605199385695;
        Thu, 12 Nov 2020 08:43:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4d:: with SMTP id l13ls1232004pgk.0.gmail; Thu, 12 Nov
 2020 08:43:05 -0800 (PST)
X-Received: by 2002:a63:6981:: with SMTP id e123mr305689pgc.364.1605199385180;
        Thu, 12 Nov 2020 08:43:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605199385; cv=none;
        d=google.com; s=arc-20160816;
        b=rvH2sJn+bNnktOwAtoImRA0lP734OlxmnbyjZUXgf0hMzvB+O/ez2uogPo0yHbERAy
         +epEWabjQp2XkhGLSrYF93ZEX/ON/yZjwFGSmIUc6npIaz8dsx2HE/ZnnUddRVthPEGS
         DDWco1ifMA5f+4ur+ZrOfq7kM/GuPTj2c3UtXHqbrsi2icNNvwnfCg+XpfDtRg4ehirC
         WjzcGpHF80oGwlHWWm7GJm5I57Mmq1YUa5vDy+y0dQC+y8ByUAYDyEQJbdmYCE7LMpP0
         LJ9sfJywkvlNshMHErEYeQ2azkF1IYsHI0t0XHIWeypSrlx8CRmUfEsgjQCJIHjuHFUJ
         WA0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=RMxgbyyMv75+O93Av9gAbKvMeTxfhY9oipabnXxckQ8=;
        b=wFkcV7Vqf/UlxTdotV2sKnJdBdQr8MhLeN/ASmUAV5HJmJfnT0d1abRhwtEAzg6BPL
         YT/QzbLJKNc69tlf9LYp4TYnS4GPpQai6DbrF990raVIuxECi7VSFeVA8iJ+aabO52Cg
         0oV1UjkLNMd/oC/sU8kRZVb4lk8g8MWTqtxkOLYvHtVJnjnxSDWYJSRPS65au55eIfwU
         +Fh5/LqvcLvMda4rGBkUrjctpOivfmFoHUdnRwluHxnYyjhbQ595227I8DXcrT+8pfNE
         qGumfa3pGTRusKwbGchiKsS7EiIBGl5Y1pkZQ6J65WUeFk2BEZu8LutPQeJLe1Pv3Ye9
         hDgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t126si384831pgc.0.2020.11.12.08.43.04
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Nov 2020 08:43:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5F3A7142F;
	Thu, 12 Nov 2020 08:43:04 -0800 (PST)
Received: from [10.37.12.33] (unknown [10.37.12.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5280A3F73C;
	Thu, 12 Nov 2020 08:43:01 -0800 (PST)
Subject: Re: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1605046192.git.andreyknvl@google.com>
 <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
 <20201112094354.GF29613@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6a72b3e3-1b35-5ead-bfff-f4e2f3d5296e@arm.com>
Date: Thu, 12 Nov 2020 16:46:05 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201112094354.GF29613@gaia>
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

Hi Catalin,

missed this one.

On 11/12/20 9:43 AM, Catalin Marinas wrote:
> On Tue, Nov 10, 2020 at 11:10:27PM +0100, Andrey Konovalov wrote:
>> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>
>> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
>> feature and requires it to be enabled. MTE supports
>>
>> This patch adds a new mte_init_tags() helper, that enables MTE in
>> Synchronous mode in EL1 and is intended to be called from KASAN runtime
>> during initialization.
> 
> There's no mte_init_tags() in this function.
> 
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 600b26d65b41..7f477991a6cf 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -129,6 +129,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  	return ptr;
>>  }
>>  
>> +void mte_enable(void)
>> +{
>> +	/* Enable MTE Sync Mode for EL1. */
>> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +	isb();
>> +}
> 
> Nitpick: maybe rename this to mte_enable_kernel() since MTE is already
> enabled for user apps.
> 

I will fix this in the next iteration.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a72b3e3-1b35-5ead-bfff-f4e2f3d5296e%40arm.com.
