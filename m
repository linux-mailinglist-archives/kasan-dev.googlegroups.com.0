Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGFA2GAAMGQEH3UK6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EDDA308C2B
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:12:42 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id ez7sf6111112pjb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:12:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611943961; cv=pass;
        d=google.com; s=arc-20160816;
        b=HC8G5k3qpKsapLJKWBCa2L+4XfI/4OH2SONT8bL55ySBn16o/FODhEdKR2eYMUhiAo
         ckC9EHx6FJtoh0BWWykoTY5eVXE7soVWtX1cWPafuxROcyjqqOJMYCl+cu2gAgUDwcWy
         TInYOE33ZWVijNTT8R59wDVIMc7xkVVyekzLsIJrcriOlWzSnbLAS1swVUR/ee5mYwQ3
         lyazt/MSb58buWfieGbnez0kBqRZuRtaVv9VJkVw5NxkN3laZ9yMkz/lzhzoSdatviMx
         f85+X4MJ/EJsPxsHs+GVKzRW7ldWN30q5kHw5xsOBqt1HBU8Qt800TtRm8tHHv4xDdAu
         NKew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=1TUFEBLUO5qr9lA+ovwgR87fCSqEj6ALZvttieLDB7Q=;
        b=lfv9RduLvN4KTJn9a95GwP4jSELJKnZSep8yhmE2bLp159T5NPDWozmxiRqW3QUiGK
         KzBmJEpJMp91Xfv487uw4wJ1Mx95KnTHBi3GU5Nzx0wdmv6nd67/HLdoDw2oCaOndmY4
         9Urt4TNyCLYPaGhLx/Ad45Wm5IPirOeYFmJOQjkhtSl93zqDCjTD53cKOfRNNYyGNETg
         7JZWpBCVBB6Mk3R7pLrYjiX0R0bj4t8JjYK43loZLg/BmWiVWZzm38LsavM6VoVk0Vxf
         3HvzJxyMiwrWuq6NwPGPNa3FYR72HcV6sH3LEnYwD46uSLs3GEB0DtoFjhUIRSWcCKn5
         Nw/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1TUFEBLUO5qr9lA+ovwgR87fCSqEj6ALZvttieLDB7Q=;
        b=bL7ZyIaM+J2sYSVAgyemEJ179PcbxEiPgDEAQu/DvaHthHmHHiyl2Uw7csvZo0f15e
         dBh7U7B0MqokpX72rSDFgLOEZORK/spP7a66czaiNfic6I1n/rzWtGCy0hSjpQK2G8tp
         zE8IW5ZtNY0oIhvALMSktr3/i9jRNZWLx12CcnhaJUOcZ2Vsg9hi4/qCBD9aeJpv0Zhs
         +s85KqWXqziJ+hZSg/jomnm6+SJ1Su3+fBflgn27OXt/gu9xgAiE+LH2SSCO/1Zt6IWh
         WX10oAsX1wxCHhyRgxiQam3gbe5sNZoobdr3MCWiq5O3cD9j9RZ2zgIdGkZwFKyL68Md
         N3Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1TUFEBLUO5qr9lA+ovwgR87fCSqEj6ALZvttieLDB7Q=;
        b=LQf/i7CbF7QZw3RwdDb1maj1lrdtd94LgOnTp01KSuv/24Px9akyoBuPCgEvxJwzul
         8FVCyPf7cASemg2q8O98cCCPkOmbieUBQvrunzn/4aEnQjoZf46nJn9/xZAykf4aLPtD
         OvvY1LieNxkW90PnvhNu2CPJfmEFEw7sr61iPYB7P/VLzUJ1pE09y8Tp/hvDmXL4FJOH
         uOHxX5QF+HclaUIl2Iy02oG5U99z/fIGiJCax5sqH49LY96G50qwdZzh0RanQfdsrbIJ
         DHRs8b/6Nj3zgrIEFXWyBbXIaR7cZ5gByT6URYceYwpGpKujegfwbd5JmhIYTIJmUda9
         DhZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53033LufuhavhGvZK2tiBrAEESSaVCrWRbeNfEr2ZIqGyYZtbpnc
	SerspTtxFpbHHO9xoWZtr4Y=
X-Google-Smtp-Source: ABdhPJxrf0saaTks+0jkGuDkTk7ufrQ+4O7U5ustwM9JmOF+OVbnoZjW2ybBYJcoIP9hLkKusKTXYw==
X-Received: by 2002:a63:d903:: with SMTP id r3mr6031557pgg.445.1611943960845;
        Fri, 29 Jan 2021 10:12:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d507:: with SMTP id b7ls2582206plg.8.gmail; Fri, 29
 Jan 2021 10:12:38 -0800 (PST)
X-Received: by 2002:a17:902:edcb:b029:df:cce5:1105 with SMTP id q11-20020a170902edcbb02900dfcce51105mr5497304plk.2.1611943958751;
        Fri, 29 Jan 2021 10:12:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611943958; cv=none;
        d=google.com; s=arc-20160816;
        b=flLek9+mPGo4TQdR4AVx899AQjPpuW2v4Z4R1NAYBKh6u5vXW3dho8duMtPV1RsB+a
         6THQpcnnJ+pdG6LL3mLdr8sLyUmP1v2m8ZA27Cy+VfK5boeDc2d6lHmGr/dzvsIG3itZ
         g3kLSkDJ0uxiRbpMgfcxHXbIaKhPGbP74NsD8sSCgiBR09YMF14ORII+7zcm1J7ziIor
         NGEsXo+W+1I6Qi/cXf/3yyW8FZns16J0P+WQjrcumuRY/9fWcsvZP4dloepGroo1U+WR
         JYFsjrYxJ9U8F25xtG5ALjEUbXFQuDfim0bQsRd479MyvLH2LkPrWQi5JAo6PNr0HZO8
         SmzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=m27wCjVHLFFn8ixqW+d19fphE+DZ0v+0/1vXDT5Sb28=;
        b=bdNk8jhNe0J7jWyZWWCTgh3in8vpPwLxIdTE59aG8/qBSRpHnLkhaKUwD1EQ01V246
         hXt+3gSsxhCAD7HfmoMSpVzUlQC6Gc1PPKGZJhUAFrBWZlnmDXN9uEGtAju2FdAzkBxU
         jXwLKYJGqG86+2xzJi8210S4JIYB3eDxYyXis/vmnOq3ObTHs4nncXEwL8tTFB3edP4w
         kgt6L9vbyTd3qxXG34ePNpoKPIpbBDWjVWZDjKJaqGrix5HGwhtfuAzddTdMk/2GxatR
         5LX1ttEadMGBA/GSZIm1MEKFpyVxwUcLKqhzu1CTuMBFBzK6oq7cJjpd0OxQicIVNQyL
         KgDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p10si226999plq.0.2021.01.29.10.12.38
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:12:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B969913A1;
	Fri, 29 Jan 2021 10:12:37 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9F5033F885;
	Fri, 29 Jan 2021 10:12:35 -0800 (PST)
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com>
 <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <e5582f87-2987-a258-350f-1fac61822657@arm.com>
 <CAAeHK+x5O595yU9q03G8xPvwpU_3Y6bQhW=+09GziOuTPZNVHw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <f1ad988d-6385-45e0-d683-048bfca0b9c0@arm.com>
Date: Fri, 29 Jan 2021 18:16:31 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+x5O595yU9q03G8xPvwpU_3Y6bQhW=+09GziOuTPZNVHw@mail.gmail.com>
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



On 1/29/21 6:09 PM, Andrey Konovalov wrote:
> On Fri, Jan 29, 2021 at 6:56 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> Hi Andrey,
>>
>> On 1/29/21 5:40 PM, Andrey Konovalov wrote:
>>> I suggest to call end_report(&flags, 0) here and check addr !=0 in
>>> end_report() before calling trace_error_report_end().
>>>
>>
>> Probably this is better as:
>>
>> if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>>
>> Because that condition passes always addr == 0.
> 
> Not sure I understand. Call report_end(&flags, 0) and then there do:
> 
> if (addr) trace_error_report_end(...);
> 
> Although maybe it makes sense to still trace all async bugs to address
> 0. Or to some magic address.
> 
> Alex, WDYT?
> 

What I meant is instead of:

if (addr) trace_error_report_end(...);

you might want to do:

if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS)) trace_error_report_end(...);

because, could make sense to trace 0 in other cases?

I could not find the implementation of trace_error_report_end() hence I am not
really sure on what it does.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f1ad988d-6385-45e0-d683-048bfca0b9c0%40arm.com.
