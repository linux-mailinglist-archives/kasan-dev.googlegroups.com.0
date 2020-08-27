Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYXQT35AKGQEK6KCNUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C298F25462A
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 15:42:59 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id y2sf3011368oos.15
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 06:42:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598535778; cv=pass;
        d=google.com; s=arc-20160816;
        b=NjflYqHN48HI0XC6FrNSUmfnv1Wk75jxo9vK4Gt2hNWNCwdZ1XCcbtqa52qOlvD38/
         HZvbh7kEeKg179of/S0z45KLeZ8EW+sVLNF/1/EqOcCfGs2SBqnoQRqBxi3PaOY4PdTA
         VBiGe8i4U0ME/pwHliSGHgaWu5RAWa/8n1Wu3UcDqpqc1WFo2zzwlz0jvl5kyi9NDWlG
         6pmjIF8iixRA+9Swq0yBamukAZGKncoCo+dCF4nR9oO++RwNsBCYEAhVMT3pgyDx7UGp
         rInf5KgtHNpIALdsdGS88KwhcPw/o7VdB/UfOn4b86O/YRZu6VfySVMDixHD5DlDaeS7
         lK9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=CHu0S9z2LKhS9a7asVWjgFPX5WQ4wfkdOyzLaqJEqQU=;
        b=yHscCLLsyX7zOjmgcyw2F23sgk9ILgU4uS/ZV6AoOa79k8RyQS2Z4F8f93kZBvQmuL
         wATn0rbsWzMiYEuPavGowo9dF8CljdmgqqwBWMMSiConVqwUaaz11tbsHXz2hnxPwxsz
         ZAcJAnBTb6ESq0ZdxtJtAxtIlI4ldTWyWYRHAcPqTw1BBT/87W2asVMPQ3Fc2CDdjPML
         vWtIyGsjI9s6Hzsw0FaJ9H3rlKwZDHveJlF+O7z7J3V1qbOyLgLRHcsr7afHJQgkyD9n
         y1D+FNb2xltB97vm+xIN16a5fpoV0kLRrgV9EQgsqzm/bTXnXcCEMLbk+/KEv3h1JUMG
         mIzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CHu0S9z2LKhS9a7asVWjgFPX5WQ4wfkdOyzLaqJEqQU=;
        b=l/P1gtgrSJjmkYx+AoH7Lii0fM/xyQ6i+M+lvsCwL42Gt6+jxEe34US2DdqoNrQzCO
         gQOwvuz7lnMphtfHtWLddp5K/7OKdE0O/kMvDmNNnNQ6uhghjazEhNv5cJHGaxBJF1K9
         NqzIoKU9FW23WwI8ZBO0VwYJvJuRhQBmtHpwStNyBUKz7v45dM5eVN4puw0mAlQw8jMv
         iRH9Ek1TY9qyDHUs4QymMkXI/L5j2zo16D0DEr1wAJssXg1ud+J47D6OOhHIAvlUJatp
         XCO0sUrUP03J/D1rpS5fgQdCqsdiLDlqj9YY7XfNNjyxAiqq/GXYjd0eWvNTwu8HdK2f
         YtxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CHu0S9z2LKhS9a7asVWjgFPX5WQ4wfkdOyzLaqJEqQU=;
        b=sQQICCSLXyDlwZLzQHrHlpUgwwlQX3cYTeAuAC5fLHLrCIDiNT3k9D9enEC5jq+TaC
         ptDPKYpNcIj4LGEtqC/aX/b12i2B0MHEVLkCnxaTPNZCs1KJKU7Quu/Sr2wz6CQScHiS
         Va6WqrWki/nL3odZJBKDcSzAYo74nEIbT0nfkSsJkFOFsN9aubYth9EFd/luLjMM/mwS
         373GZVRyaOY3Ug/PQDcckEO7g7AP8NxZLzGAc5pbteFp2oZlqkRYI0WoCC4nbjGglZh+
         v13e5ET4pxLPQp09M2Xzvlcwywk3Nu1REHFloGU3qm+mmQ3yJbky2iHCYO+tbeRIx7uU
         Er9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SzvbDYvvDDPcONjY4R+J9HwvxQ4EtjSZ/yzPOgRkfsd5sUHS6
	o+wG/G88lID3IZWZylr4eXI=
X-Google-Smtp-Source: ABdhPJxubb4xHyYh8SyDNUlZWKhlqOsXwLJJfYXuV2I0WrhpSLI0EEi7hfuQJKa5cDl3xA0A3/R4Qw==
X-Received: by 2002:a9d:74c3:: with SMTP id a3mr4506679otl.292.1598535778544;
        Thu, 27 Aug 2020 06:42:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f31:: with SMTP id e17ls650192oth.2.gmail; Thu, 27
 Aug 2020 06:42:58 -0700 (PDT)
X-Received: by 2002:a05:6830:1502:: with SMTP id k2mr14216538otp.130.1598535778269;
        Thu, 27 Aug 2020 06:42:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598535778; cv=none;
        d=google.com; s=arc-20160816;
        b=EuUspjANLmWXPtPpNDnm4gvTvZX9WFmMZa8mEHZcXR6N89VV6FrwnDFqfi+WjL16wi
         NhsCt9I+WGMNOylAAAWBODzKCaNA/s5oCWOZE1fV2+xsl2Gf1b1IpiIAmynjhDXHVeA4
         am7hc6xHi8HLJi9OgKf4cvIZdswF4RAuvequQp5PeNcOU3befUgyVFApof4do0fUuO7s
         LAGbpSqTKSB3XwSU2v74GKKjGO5EXakZVUqXJx2vLUdWZK4ACXVpTU3CzumMiSAcaZLw
         m4g3Nhehg2J8r71L4arRgW4Oqxz4LHl4waebUmb6nKewIXMuzPPWqq1Yu0QPZmr9PgL6
         NpKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=W3EFPRVbhmSqLD27PpfoaSoJkn43bxXalalQzavb36k=;
        b=cATJsO5zrklHE99Z1KUpm/5ceG0F2r/WiISL5FxpPasGUiK/RTPcdu3CclROBrQXKu
         STSn6I2ZGCSd4WcMMhGYiV9Kc5m7tsQeSDlCAjDdM8xOI2eWXpqd+8sh6jVtZHvTOYfe
         4oLlXunQo11wQTui7GmfexUgUcNd+Hdwgl6ZPJh7VcMESMRLRf1gR/gxmg4YlRu6WCnf
         lkvqEJylMDJQLfnpKeqvPLn5Jpa1hu52Y727nLxaiMw/d79kXEjJmS+TMg1ha8RMgZ0+
         qdpkMDBuBiST67xunGUYrblcwMuNtFp2nelVCEjaqMkv0RIgZiIrHJC7BqgUDHNyXGPX
         RQDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j139si143563oib.1.2020.08.27.06.42.58
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 06:42:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0A38C31B;
	Thu, 27 Aug 2020 06:42:58 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D9E2B3F68F;
	Thu, 27 Aug 2020 06:42:55 -0700 (PDT)
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia> <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
 <20200827111344.GK29264@gaia> <d6695105-0484-2013-1012-fa977644e8ad@arm.com>
 <CAAeHK+wGKjYX6eLztiwQA2iObjibHPKt3A4oU0zpXPKk-4qdOw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <30b90e66-2ac0-82b3-b590-5a2b35fad446@arm.com>
Date: Thu, 27 Aug 2020 14:45:09 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wGKjYX6eLztiwQA2iObjibHPKt3A4oU0zpXPKk-4qdOw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

Hi Andrey,

On 8/27/20 1:43 PM, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 1:15 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>>
>>
>> On 8/27/20 12:13 PM, Catalin Marinas wrote:
>>> On Thu, Aug 27, 2020 at 12:05:55PM +0100, Vincenzo Frascino wrote:
>>>> On 8/27/20 11:40 AM, Catalin Marinas wrote:
>>>>> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
>>>>>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
>>>>>> index 152d74f2cc9c..6880ddaa5144 100644
>>>>>> --- a/arch/arm64/mm/proc.S
>>>>>> +++ b/arch/arm64/mm/proc.S
>>>>>> @@ -38,7 +38,7 @@
>>>>>>  /* PTWs cacheable, inner/outer WBWA */
>>>>>>  #define TCR_CACHE_FLAGS   TCR_IRGN_WBWA | TCR_ORGN_WBWA
>>>>>>
>>>>>> -#ifdef CONFIG_KASAN_SW_TAGS
>>>>>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>>>>>>  #define TCR_KASAN_FLAGS TCR_TBI1
>>>>>>  #else
>>>>>>  #define TCR_KASAN_FLAGS 0
>>>>>
>>>>> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
>>>>> user series, just do this in __cpu_setup.
>>>>
>>>> Not sure I understand... Enabling TBI1 only if MTE is present would break
>>>> KASAN_SW_TAGS which is based on TBI1 but not on MTE.
>>>
>>> You keep the KASAN_SW_TAGS as above but for HW_TAGS, only set TBI1 later
>>> in __cpu_setup().
>>>
>>
>> Ok, sounds good.
> 
> Sounds good to me too.
> 
> Vincenzo, could you take care of Catalin's comments on your (arm64)
> patches, do the rebase onto user mte v8, and share it with me? I'll
> work on KASAN changes in the meantime, and then integrate everything
> together for v2.
> 

I am happy to do that. I will be on holiday though from this Saturday till the
September, 9. After that I will start the rebasing.

> Perhaps the best way to test only the arm64 part is writing a simple
> module that causes an MTE fault. (At least that's what I did when I
> was testing core in-kernel MTE patches separately.) Or reuse this
> series, all KASAN patches should rebase cleanly on top of the latest
> mainline.
> 

I can reuse the patches as they are, unless they require changes when I start
rebasing. In such a case to not duplicate the work I will scale back to use a
simple module.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/30b90e66-2ac0-82b3-b590-5a2b35fad446%40arm.com.
