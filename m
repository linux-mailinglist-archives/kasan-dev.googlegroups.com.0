Return-Path: <kasan-dev+bncBC5L5P75YUERBP433TXAKGQERBLDIII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D801105C8D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 23:20:48 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id f20sf1306999lfh.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:20:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574374848; cv=pass;
        d=google.com; s=arc-20160816;
        b=FhLAJ+P/FUtfyKp8bLXSd0mkK9ubefA/UyG00QuBeJdS5oQyqRd8rgJ/9FCGAaoK9w
         mGw43xvqXg9AQOlgctzENM3Vswilap4xlYZOL6WqkBxGHRB+54L+CRHcxBgYRbeKAofQ
         rgNZQVL2aZc6sd0UXFCZsUNuaRC6NgQzB6f/JbamZvyPzuam8GxV8/MfDvEvTJERc0U9
         cEGEN8h4dLuh/7LMP/PBvLme0mfoAYB1To3RLTHER77ylmwjUhv6UsvjMiF4FCnZuUfS
         91sdQa9Wf+6aDVpDUtyYqyWxvvK1uvCpX7vhQUoM1KHV6UENReLKJ91qxXIwFSshwxg+
         cnRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=e1NbziHEdZIRDHjrcQmMg5cwA4KC+iGMYur+1bvEicY=;
        b=aHzCYwPMY75rKn7BBCI+erlYthYbaKjxbXd0GvRpqTPI6xTW173twTlDg9+g+XT9o6
         upzIdCeYde26l7mpPRkNUmy+evxAF/npxbS5D1ic4YzTqydLhtjVFaPHc1y9hvdPDN2o
         oarBKw7Vlw7289Uyk+8CQ2l97b401M/8qBeNIqS9wVjns7JI3GzsTHk6Njh8JfHaNeP2
         St1fEi5bzF7c88ZyMOpgN8EgK5YmbTuBlQAUXGbdSKVCxDHcrcwWBie/1CQAH2qOv0nX
         vq5krzK9PB+ch+RGylXjTgW2BgUVHvmnqOolrw+GaZsygOCHeShqP07rfpDt8j202GeY
         +2zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e1NbziHEdZIRDHjrcQmMg5cwA4KC+iGMYur+1bvEicY=;
        b=Jc+f3MobkmwaFodXb3k7UqrRNxIs/NWYBuDkYsjSSCPLP9NSHL3TWtM+1lv1qb7FcS
         mgFN3AMC1oJfAHTOMhLJYA2OgMl+VAIdqYcDK8xyELHLgR34T0dtxVzNaGiOdfrFJV6p
         28f9sbYo8fjJCGLet6M7p7xX0IhaXgzGqAHtzkVJd/bXIfRESiQTUAa3QvCOCDz1jKQc
         tBg3nJ49ONsxR3ZqHYFp9535xh1OzWHxpgIF0JbJ+rSL5PsOIeOAURQgYw2uNY81EuV4
         KGaCrpB6fZGuZ03Qwplv7gGlriXqG+jZnptk07j7joNCQ4zAlFTTOJ2jO05aNSLedC8H
         fcrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e1NbziHEdZIRDHjrcQmMg5cwA4KC+iGMYur+1bvEicY=;
        b=iWhG+hYTPAJI3NxA/Y4ky4cBEyss276msyMAO3A1APpbjpJNCV6GLxkpwcqjG6ZCvj
         tcT95Kbb+gk+Zv6Qa8vJ6Tgt4unIuXhwyhMHRp9AGOshcLoca8yf0MbfNgW++rwCrh+E
         LUrPh6JwRmCFkNHyGi6wj04mPMEPEZxWTpWFegiMEK2fJ1mkb9Am3X0DGNKF+cMlHeMm
         n/TsBW8jKWyVQa9zrozeiLMUjXqTbwYrXO1niQxxUXEYvKqDpZ6ScX4O5xS1amxUaMi/
         ZM+K4tioMXJmDdObk2/k7UKb2uoXdFCihkHX62h5k+W77jR/XT53B48qEGplvJbgviPG
         kKvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWZjsma9U4tJY4CkKyKpc0UpLlGZisF2WZWjUqjIqE4qIx7ZJ1A
	Rr7suz2R/FmKlum++e+xLDQ=
X-Google-Smtp-Source: APXvYqy7x4988rntP6ZTXLxyr0RnvebcwbDFBn0L2J/7/pcbVGhveOSNy+J3gqTFTvDrG2v32kgcfA==
X-Received: by 2002:a05:651c:87:: with SMTP id 7mr9868326ljq.20.1574374847878;
        Thu, 21 Nov 2019 14:20:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ee08:: with SMTP id g8ls909330lfb.0.gmail; Thu, 21 Nov
 2019 14:20:47 -0800 (PST)
X-Received: by 2002:ac2:5c09:: with SMTP id r9mr6939352lfp.136.1574374847323;
        Thu, 21 Nov 2019 14:20:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574374847; cv=none;
        d=google.com; s=arc-20160816;
        b=PhX09HyZp9w/TspBtpscnf5tD+Y6dFTZ/VvtEuETt7Hc3QbjKddhYNHYhNPJhBlA4D
         MmyjZB8sxT6UT5jqhNDppbnVsvWdrFX/5cSSsTYwEpoR9dyKpLn4iFpItJ+l19KbxXR/
         5vHvUg7e5Ct5RXDq9O7hyj6kZ0K01Ao0xVeQ1oW+VsLvwI9Q121MajbegC05S9H9415J
         pyVqrDsore6xmc+dRndbe+n5uTldPR+2g6Ft3GG3X9OT7MKkyKwuU7tsdqJ3o6e8Xsxh
         SdkJ99iAE/PVMFi7lOVRGyFcN49TK1ElsII5zlJtQNAdmFVT7covW3q4CQ7kVX9ehRRP
         Nsug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=+AB/9Sm9DUswifV1IgH5NCvGEGSb1/O0nPDfQF8SVhc=;
        b=DRLecHrL6CnQfM6XkQN2VX6ALse7kU5un08bX3W6w3xfC18R4clCbbYgAFoG+xXLxc
         iUfMocTSFZZ4KuySiwkriaDVRy9yiwLUNBDlVWzG2I7Am4YqSIkqqV7HWs57UGNY3ky/
         YaL2w9QDxDwo57uA3qWLjQVevVYKcyzNEBsnuAWAuKtJDZKH7tcPF45xdYJdDBJsPPV3
         2MIuhchYZQ8YYerrCjTajJsX0d1LkNURMP2nWRn8zVqRlLejABMaZebPhLTKx5ah1iXO
         7n4yomfKoYxLKI1enfcktwR3GLHwJcIH3Kh8E6LzdI8l1qd3/Igggy6Wx7qS2IKIWwv/
         qR3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id t3si123996ljj.1.2019.11.21.14.20.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 14:20:47 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.154]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXuoL-0007nb-4j; Fri, 22 Nov 2019 01:20:25 +0300
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
 <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
 <CACT4Y+botuVF6KanfRrudDguw7HGkJ1mrwvxYZQQF0eWoo-Lxw@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <ad1aa63b-38d7-4c8d-00c0-bd215cf9b66e@virtuozzo.com>
Date: Fri, 22 Nov 2019 01:18:38 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACT4Y+botuVF6KanfRrudDguw7HGkJ1mrwvxYZQQF0eWoo-Lxw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/21/19 10:58 PM, Dmitry Vyukov wrote:
> On Thu, Nov 21, 2019 at 1:27 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>>> index 6814d6d6a023..4bfce0af881f 100644
>>> --- a/mm/kasan/common.c
>>> +++ b/mm/kasan/common.c
>>> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>>>  #undef memset
>>>  void *memset(void *addr, int c, size_t len)
>>>  {
>>> -     check_memory_region((unsigned long)addr, len, true, _RET_IP_);
>>> +     if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
>>> +             return NULL;
>>>
>>>       return __memset(addr, c, len);
>>>  }
>>> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>>>  #undef memmove
>>>  void *memmove(void *dest, const void *src, size_t len)
>>>  {
>>> -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +     if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>>> +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
>>> +             return NULL;
>>>
>>>       return __memmove(dest, src, len);
>>>  }
>>> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
>>>  #undef memcpy
>>>  void *memcpy(void *dest, const void *src, size_t len)
>>>  {
>>> -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +     if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>>> +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
>>> +             return NULL;
>>>
>>
>> I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
>> poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
>> but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.
>>
>> So let's keep this code as this, no need to check the result of check_memory_region().
> 
> I suggested it.
> 
> For our production runs it won't matter, we always panic on first report.
> If one does not panic, there is no right answer. You say: _some_ bugs
> don't have any serious consequences, but skipping the mem*() ops
> entirely might introduce such consequences. The opposite is true as
> well, right? :) And it's not hard to come up with a scenario where
> overwriting memory after free or out of bounds badly corrupts memory.
> I don't think we can somehow magically avoid bad consequences in all
> cases.
>

Absolutely right. My point was that if it's bad consequences either way,
than there is no point in complicating this code, it doesn't buy us anything.

 
> What I was thinking about is tests. We need tests for this. And we
> tried to construct tests specifically so that they don't badly corrupt
> memory (e.g. OOB/UAF reads, or writes to unused redzones, etc), so
> that it's possible to run all of them to completion reliably. Skipping
> the actual memory options allows to write such tests for all possible
> scenarios. That's was my motivation.

But I see you point now. No objections to the patch in that case.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad1aa63b-38d7-4c8d-00c0-bd215cf9b66e%40virtuozzo.com.
