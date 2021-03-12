Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBVMYV2BAMGQEPLZDXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B47D933919E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:44:22 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id z19sf12388134oot.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615563861; cv=pass;
        d=google.com; s=arc-20160816;
        b=g6ESaXJtztvwpWx6Oaf8pq5dceuf3Vw40A7zBG0VRZfsoWkA4yj2NKyb9Po1hWbVZW
         Cp+xst2oAmthsqjeK4tpqEM2BH40PKlb2YPO84XtfGIC6izWOv019WW9VkSLW1n0zVB2
         twP0WPrWQMAlCphzeypoYzPL4CYdGCBft23YZ2ctOdBGNJPBnMd+tH14V49aeiLf06mw
         lh9k1Lb+XT8i8tqbgOyExez8+UTtDzwKTPb9lBFJBrdLm5/xHppPS/GH/B0kH0ib0ol5
         4Nj+cVXW6j+BDG08tWLdTokZIQc5cPRD5QD7qgkZ7hgLILUdEW0OuWw1gqELbzIYHdIC
         f7Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=5M5wIbcFHDhdZkHesvesffcDv1h57hxlGgcWyUERQM4=;
        b=NGP5iRDO+qKH6oJYX/if7w8xfVZ5mNq9LZT3ZXT+8vCdQpgw2ClwIhD9J1V4+/2uyP
         9wjs0Vfr4WgXmq10XTLCh3t0uS7JYLoJ60nCuvVAH8KJpHUmCSmjTM8s9Tv/DYkll8Az
         RfVJ3FFVpkKGsUz/bOb0NQgIik0X8JNNswj3Vmeizj2AUacddIXmwxMAOfFXQs7vFTaf
         SJzOrnCkG9FnZPxsWlx3zK3WQhhifEXYAc62FlWd90cNKtSpaH/qxJaDYcUp9rpZ91rS
         WTSRc5PEPU0CUI2izB8bwILR5qwTbzKClAE+01+sGe3EiQvNjbpAb3YRlDc5QP6fZ+U8
         pGlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5M5wIbcFHDhdZkHesvesffcDv1h57hxlGgcWyUERQM4=;
        b=WHzly5CtioLnMaDNaJrGpoinRvd0dAl94fFvfIVAiECPFSgCER/KfEouBkTyKHrpTI
         VTvkHuYTmEsf4X97B9WaY2XqEKcHA36cgK5ePfGSayp+VEJVwS9qzPzI+tVHYmWIYMgT
         u76YyUS1Rxx1KWePVsQZiH5Q5GKUY7O+BHtnp8hFpaF9lv9vg03Xg6UAjttjjDLP1lFB
         lsXGETyVelGqJG+9+Q7FSBCWxZfrNyMLkOijE6YVBQffjW1tm4no31L8qRrly+G4c5HQ
         Xi8xFFZBq2ub1tOJh9iQ59haLI/lNQTFRaQFIDanTIJdJSB+iwp5HE59qVlPyiubrqDi
         NHUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5M5wIbcFHDhdZkHesvesffcDv1h57hxlGgcWyUERQM4=;
        b=XAxM7POAvPcMS51uYOfXKV+0uS6PkhgK6nQtOz/TTh4UkDF8+mHf2mON0mG7SCdIcn
         2HSnp2jNYavZOpG2CieyCjuwpvACt0NHFjkcF684iG0bHxpKPqtEEE5yAM5x7awIK3Vl
         ivfwRnaqnyX7cDIXtJZ8+v787bKsJEjJoQF7RrmtJQpgjrjLNUoCFGlCqPgWsnu4gvoX
         5W0f8SumcOohwtis5BEZt1Bf/BxVkQi7sd1gRB3tS/bbVNleNElpqD4vY/G5I/tZT/MQ
         FwFsWC00VXwxdxyLmuX5MR5pVBfYP9TRueEAPagkT42i/0mts2UPXz7jWWyN6F6oDgDb
         zN9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305nYoCTqSra2nlmvHWGx6lRvuK+vJdJKjkXFLolOdtQOSI3c/A
	Mi8uaiC43gTjqZeFjKzYvoY=
X-Google-Smtp-Source: ABdhPJwCFx/xDYWUgiJkgufcGWAjuBNxIY5e3Hi2S3iL9JTamnbuiReZ6fVC47paTtdH25NAiplXEA==
X-Received: by 2002:aca:3195:: with SMTP id x143mr8161182oix.74.1615563861606;
        Fri, 12 Mar 2021 07:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4a0f:: with SMTP id x15ls2272743oia.8.gmail; Fri, 12 Mar
 2021 07:44:21 -0800 (PST)
X-Received: by 2002:aca:fd10:: with SMTP id b16mr10056542oii.26.1615563861217;
        Fri, 12 Mar 2021 07:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615563861; cv=none;
        d=google.com; s=arc-20160816;
        b=F1kjTCydL/JbWdzNKFM+Gq5v7gZbnEhm6mOyk6qYzO4FlA+hjgRj4WfHL3KS6kwB+k
         gXk/h+S9nd1F9CHoW/XwuClzkFBjExxL7AU+bOd52YrGqmPEbChvwIKwyEaDwzThQHDp
         K6ixAER1OqL5Ie5SbyjlpX2q5yFwxEAmGqktQWM+96gfXrBqwm8U2q4oxQ4FG5aNGbyC
         l4X0+j+9Sui8a1rmiaMBQsj+wW8kjiSwxALufRM4W8OMq/t7qHOXIZqPLhoUQr5Vd0GY
         uQBaY6ZluPFmzudodQS5DT7jpfjlpOSItP0u8KVVWyUWE5s8VklVrbtWN2HMmDSyZ4sZ
         dftA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GBK+8Xd/DWyCKiyxJxEbU/sOF8S9//L/OgPKIO0OOr4=;
        b=aLyP2Y/YSTsLnNimiSM9Vw+wX3UTxJbEejFgWPiV4Olx2yeGTqtVTLhOyzAalc9nlz
         r58BDN09MZ6XuwHJ+JBNmGrN+yMyA8Iu3AS4G05aIvEYNUriJ/MJ0yfvBUfkmrew+buS
         tXiafqBAUtXuopgNY+9veEZVx1WsTTW39uoVFmzhg9HxJoZSRtJchF5ixQlglYFBhWY0
         zCOdI0mArogAdvGBLTPr1soEw20MXXzn4eRbTvQqsY67dRrPMvznLqjfSb868Hy0hTGi
         VqbUi2Y5QUQne67GnR5L5y60uyxN6cqDbOEpR2aiWv0DMd3X+X9GXo+gUxHJ2GCjPJTt
         p83g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i14si322236ots.4.2021.03.12.07.44.21
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 07:44:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EF6851FB;
	Fri, 12 Mar 2021 07:44:20 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 02E3A3F7D7;
	Fri, 12 Mar 2021 07:44:18 -0800 (PST)
Subject: Re: [PATCH v15 5/8] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <20210312142210.21326-6-vincenzo.frascino@arm.com>
 <20210312151259.GB24210@arm.com>
 <31b7a388-4c57-cb25-2d30-da7c37e2b4d6@arm.com>
 <20210312152927.GD24210@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a47c2109-844d-1435-2b01-3d985d942514@arm.com>
Date: Fri, 12 Mar 2021 15:44:17 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210312152927.GD24210@arm.com>
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



On 3/12/21 3:29 PM, Catalin Marinas wrote:
> On Fri, Mar 12, 2021 at 03:23:44PM +0000, Vincenzo Frascino wrote:
>> On 3/12/21 3:13 PM, Catalin Marinas wrote:
>>> On Fri, Mar 12, 2021 at 02:22:07PM +0000, Vincenzo Frascino wrote:
>>>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>>>> index 9b557a457f24..8603c6636a7d 100644
>>>> --- a/arch/arm64/include/asm/mte.h
>>>> +++ b/arch/arm64/include/asm/mte.h
>>>> @@ -90,5 +90,20 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>>>>  
>>>>  #endif /* CONFIG_ARM64_MTE */
>>>>  
>>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>> +/* Whether the MTE asynchronous mode is enabled. */
>>>> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
>>>> +
>>>> +static inline bool system_uses_mte_async_mode(void)
>>>> +{
>>>> +	return static_branch_unlikely(&mte_async_mode);
>>>> +}
>>>> +#else
>>>> +static inline bool system_uses_mte_async_mode(void)
>>>> +{
>>>> +	return false;
>>>> +}
>>>> +#endif /* CONFIG_KASAN_HW_TAGS */
>>>
>>> You can write this with fewer lines:
>>>
>>> DECLARE_STATIC_KEY_FALSE(mte_async_mode);
>>>
>>> static inline bool system_uses_mte_async_mode(void)
>>> {
>>> 	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
>>> 		static_branch_unlikely(&mte_async_mode);
>>> }
>>>
>>> The compiler will ensure that mte_async_mode is not referred when
>>> !CONFIG_KASAN_HW_TAGS and therefore doesn't need to be defined.
>>
>> Yes, I agree, but I introduce "#ifdef CONFIG_KASAN_HW_TAGS" in the successive
>> patch anyway, according to me the overall code looks more uniform like this. But
>> I do not have a strong opinion or preference on this.
> 
> Ah, yes, I didn't look at patch 6 again as it was already reviewed and I
> forgot the context. Leave it as it is then, my reviewed-by still stands.
> 

Ok, thanks.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a47c2109-844d-1435-2b01-3d985d942514%40arm.com.
