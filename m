Return-Path: <kasan-dev+bncBC5L5P75YUERB4XARXUQKGQEKARMUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA99D6266E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 18:33:54 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id l16sf47690wmg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 09:33:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562603634; cv=pass;
        d=google.com; s=arc-20160816;
        b=P4ULmQt4Z9wSWCWh+cI6LlerijXv7zEIaWyt9nW+FUvRnUhvE/Y9X+pP55XyQ9h3Xr
         T9yjtdNV3gHNlAU60v83CV/GKnBH3yu6t3v2LMpW5emlyqzRhvpiOLSTfAPlrwvnuAOy
         ZzhITCvmaO3XzUhkHfopV26F2e2FQ5pc/RJYWEKAS7izuRf59JU5rGDJyAkt8OpyKHJK
         bRTqzuK+ijfeKhhAnHKCtJv9v6NXzjXzrPqLDGyd/+svxPUMEC+ZE4tlh+oyU/lcoul0
         2yCjJnOZ5uSSiiIlyRAwME2ACFEmIVrGCvBvhCyyR98L759OvC3Y/k/qzHtE5cpOUwyE
         ugnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QU5Vrbb93muyCHiRTNjuihFf7F+ts3M/LnU/irLgLwY=;
        b=Colhpyhxndza7Vk62nlBdnuG/xaKdTQ6ywJVHiobx0GN9EMvriJ5nS3PRhxSpJeCNl
         7ZtcU+gYCvvvmG0XHP3Jf3vSHHZ+oPETAKsVLOMYksDK6eLKbcUG3HRzgXAjJGj8e6Yj
         EkfNioXAUT+951lLLeTll6cBBgtFFcYyrSopReBEthMN+tKhdyU/uPrsAoXSWFzVKYJ4
         N9Uzpcg4+ua8XG2e2xGIVuxUwaaBUsqXyJX2varwR/NY598iH4g+MJ82Qj0Af7W6SIPT
         Wcc120e1QzP3dQ1GOpxu27UKzQPs7d6sy4ZiUyp7950EschxxkhHuMPRGiS+HIFjE/Ff
         dJCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QU5Vrbb93muyCHiRTNjuihFf7F+ts3M/LnU/irLgLwY=;
        b=MBJxzCRRW0AmKSs0AtrswMnS8uDaL1QFq9leULBXjHjVg1XyCxt7pnT4s34DtBXB8q
         JWc21DeVEN9bJ7ftNkYicIBA+7As5GHDlC12Skk24d+ukzViGybUpb3/uWK64L/wu862
         I+Np4Iix+2LJinlxeCk4Lh1PdX681LuEYV0x1YlpAjjDTNj2545NeWXDGKxgpbA0Lp+u
         EogDjZrGMV/mvuiO7AX0TcS1Z22CxU91BfYWPVcVrlcnr+MVBO5XqJyszq4d2y4orxMf
         K4u5CghxgbFC7RedYkMwO12alrjA5q0UutAo2PeXoTIn3SiIw95j9ESC4shsdmPq4lGy
         RlZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QU5Vrbb93muyCHiRTNjuihFf7F+ts3M/LnU/irLgLwY=;
        b=eL0v941Q16s5jipHWG1QEeaFd5cx4W6rUZ1GyB6IsH2GvzA20eKwSdEukluxEG3uPw
         2wwXOF2jgCHCARjXc2IGA4aIaeRSz/dM0outlu7Nr6g7o7rA1qzXnaQYo3oJJDUduwL+
         I7Pirzc+yjscNnoqIds2g0V1L4iMZ+ba4GFVbeJtH+ylZQFboLZJdipsoxpdWNKfNZ//
         +GsyNcBXNhypRjxQ14CbyXpdZMNb2SpacWCxazp0fiJeWfTaF03C6dumxE3CA33CfgR4
         V/6vkPZHRQSUWG+JL33TTJRxatcVXBeLMbUAPz20NzgzX0hpQPGKc6N3UsVD+qnDUDYx
         rLqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU2q4k5xfZWr3w1HrkZaXB5HrSwdL/ASmzyAjcMcI+7iFOHG3D5
	EfU+N8hxszC1wZR7yk4XLNw=
X-Google-Smtp-Source: APXvYqxuGQKmN/SqpJVtYBR5cwOvO0BefDEpeeTdqozKzrT0AXPp03FJRjIxjrxK0qc5wEC9E4LbBg==
X-Received: by 2002:a05:6000:42:: with SMTP id k2mr18962247wrx.80.1562603634523;
        Mon, 08 Jul 2019 09:33:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb4f:: with SMTP id c15ls3877069wrs.11.gmail; Mon, 08
 Jul 2019 09:33:54 -0700 (PDT)
X-Received: by 2002:a5d:4489:: with SMTP id j9mr20088131wrq.15.1562603634118;
        Mon, 08 Jul 2019 09:33:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562603634; cv=none;
        d=google.com; s=arc-20160816;
        b=eK7o3q5ipSmzc04fMCOcHkKOpK19jAc2EJuhPd8VKAl2TLLkFlL/n5pngldyiMEAs7
         1xXoqF55ZQ5o38J2az1BdeMn/QwfLFZDwRwBAY0nz1bFNsyb1AE+utZJ0WgatfEziV0e
         KW02sAm/yO3NekfOwNQVbJijKo/oTKmzQ8J2mgdOvZ5H18z6/dsNuWylsUsrgA1rZsPE
         Q2V7+yiR4p3nDKoL6OgPPuZucjLu8NpZenhHIDxE3vbGvAZNdREiCNlFF5N9X0Eh9Aef
         TlJoTqNFU7AbEfnC8d4OhfeXm64ZiaCeEKGhJvKD8DiO8xUV6j9lLrzwkei0QDD1vnKh
         rVXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=8xnud/qEILYwa7BJOMRtOBOSIve8spYjI6fhHhkcm+Q=;
        b=x6LL+345289uOWcXQq15orKiZtd8uMOrsC7bWwMEq719+V6yyN229eVuEYyxjKdhrb
         jAiXYEzGdepvF0JrSP/lfudxcQEAZ5QnkoYYrJGnM/WiSc2U3q6U8yW7Jfjt6yLiHSUT
         sebzV/Vb2dOikawktMBIJ+0eGicX2Qm5hluz4TY7rDWXi2ATadWXByfjCNmZMZyOhvSY
         KVuq12wHklrVI2yWCZZmZf/ceC5uOcUGvQeA5La88m9UnDV36ufxWUjAu1bF6cigMtVr
         DXe4Su01df7a2q6CWv9EVjFMC/4YF8lTbKWxEynUgZMeiTiquKmUakckE1/fuy/UBqgc
         Gugw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id a10si3815wmm.2.2019.07.08.09.33.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 09:33:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hkWa8-00028e-L6; Mon, 08 Jul 2019 19:33:36 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>
Cc: Alexander Potapenko <glider@google.com>, Christoph Lameter
 <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <1560447999.15814.15.camel@mtksdccf07> <1560479520.15814.34.camel@mtksdccf07>
 <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
Date: Mon, 8 Jul 2019 19:33:41 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
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



On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>>>>>>>>> This patch adds memory corruption identification at bug report for
>>>>>>>>> software tag-based mode, the report show whether it is "use-after-free"
>>>>>>>>> or "out-of-bound" error instead of "invalid-access" error.This will make
>>>>>>>>> it easier for programmers to see the memory corruption problem.
>>>>>>>>>
>>>>>>>>> Now we extend the quarantine to support both generic and tag-based kasan.
>>>>>>>>> For tag-based kasan, the quarantine stores only freed object information
>>>>>>>>> to check if an object is freed recently. When tag-based kasan reports an
>>>>>>>>> error, we can check if the tagged addr is in the quarantine and make a
>>>>>>>>> good guess if the object is more like "use-after-free" or "out-of-bound".
>>>>>>>>>
>>>>>>>>
>>>>>>>>
>>>>>>>> We already have all the information and don't need the quarantine to make such guess.
>>>>>>>> Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
>>>>>>>> otherwise it's use-after-free.
>>>>>>>>
>>>>>>>> In pseudo-code it's something like this:
>>>>>>>>
>>>>>>>> u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
>>>>>>>>
>>>>>>>> if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
>>>>>>>>   // out-of-bounds
>>>>>>>> else
>>>>>>>>   // use-after-free
>>>>>>>
>>>>>>> Thanks your explanation.
>>>>>>> I see, we can use it to decide corruption type.
>>>>>>> But some use-after-free issues, it may not have accurate free-backtrace.
>>>>>>> Unfortunately in that situation, free-backtrace is the most important.
>>>>>>> please see below example
>>>>>>>
>>>>>>> In generic KASAN, it gets accurate free-backrace(ptr1).
>>>>>>> In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
>>>>>>> programmer misjudge, so they may not believe tag-based KASAN.
>>>>>>> So We provide this patch, we hope tag-based KASAN bug report is the same
>>>>>>> accurate with generic KASAN.
>>>>>>>
>>>>>>> ---
>>>>>>>     ptr1 = kmalloc(size, GFP_KERNEL);
>>>>>>>     ptr1_free(ptr1);
>>>>>>>
>>>>>>>     ptr2 = kmalloc(size, GFP_KERNEL);
>>>>>>>     ptr2_free(ptr2);
>>>>>>>
>>>>>>>     ptr1[size] = 'x';  //corruption here
>>>>>>>
>>>>>>>
>>>>>>> static noinline void ptr1_free(char* ptr)
>>>>>>> {
>>>>>>>     kfree(ptr);
>>>>>>> }
>>>>>>> static noinline void ptr2_free(char* ptr)
>>>>>>> {
>>>>>>>     kfree(ptr);
>>>>>>> }
>>>>>>> ---
>>>>>>>
>>>>>> We think of another question about deciding by that shadow of the first
>>>>>> byte.
>>>>>> In tag-based KASAN, it is immediately released after calling kfree(), so
>>>>>> the slub is easy to be used by another pointer, then it will change
>>>>>> shadow memory to the tag of new pointer, it will not be the
>>>>>> KASAN_TAG_INVALID, so there are many false negative cases, especially in
>>>>>> small size allocation.
>>>>>>
>>>>>> Our patch is to solve those problems. so please consider it, thanks.
>>>>>>
>>>>> Hi, Andrey and Dmitry,
>>>>>
>>>>> I am sorry to bother you.
>>>>> Would you tell me what you think about this patch?
>>>>> We want to use tag-based KASAN, so we hope its bug report is clear and
>>>>> correct as generic KASAN.
>>>>>
>>>>> Thanks your review.
>>>>> Walter
>>>>
>>>> Hi Walter,
>>>>
>>>> I will probably be busy till the next week. Sorry for delays.
>>>
>>> It's ok. Thanks your kindly help.
>>> I hope I can contribute to tag-based KASAN. It is a very important tool
>>> for us.
>>
>> Hi, Dmitry,
>>
>> Would you have free time to discuss this patch together?
>> Thanks.
> 
> Sorry for delays. I am overwhelm by some urgent work. I afraid to
> promise any dates because the next week I am on a conference, then
> again a backlog and an intern starting...
> 
> Andrey, do you still have concerns re this patch? This change allows
> to print the free stack.

I 'm not sure that quarantine is a best way to do that. Quarantine is made to delay freeing, but we don't that here.
If we want to remember more free stacks wouldn't be easier simply to remember more stacks in object itself?
Same for previously used tags for better use-after-free identification.

> We also have a quarantine for hwasan in user-space. Though it works a
> bit differently then the normal asan quarantine. We keep a per-thread
> fixed-size ring-buffer of recent allocations:
> https://github.com/llvm-mirror/compiler-rt/blob/master/lib/hwasan/hwasan_report.cpp#L274-L284
> and scan these ring buffers during reports.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebc99ee1-716b-0b18-66ab-4e93de02ce50%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
