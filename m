Return-Path: <kasan-dev+bncBC5L5P75YUERB3O2TDUQKGQE2WKNFLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0051264C07
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2019 20:24:45 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id b14sf1301304wrn.8
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2019 11:24:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562783085; cv=pass;
        d=google.com; s=arc-20160816;
        b=HNocKiZKerCJ9E2zj2vAl1fG/nAchpcs94o7fUlMNki9MokQ5BkOku1wgZarBqDCeG
         +0PP3PKH39V7jLH/m5+I5SBNCqGDTNfezb1+5ywCoJZS0DWAfMhQghSidUhDJaKADep5
         YvLQJVzZbr5s8gb9YL5pMcdySjBrXVx2x4acmEvEbHTx1gW0O72O5YcAqAgfSRzDMpKc
         P4SEIvXcPp1tg2P5Zlc+QcIPGbJWhTmozFOJbQRbaVXn6BxOtJFdT3/lCzCixasDUH0U
         6xZb/+R2YggGORQmC3vhKRDI4JYDyUidQKsFB+oC9itu/qLSWW2saOdoP2UKpcQzqcya
         ESdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=fWjKFdywMejFkLDD+jg5rCR23C75L+sG+Q1QLFbhU00=;
        b=JrpVqZn/RM2XNyUK389FsnDMYiwimXXeshpNcrGtkBI0fZyjp9gEGPCjy+NyJYRvep
         MZh0DHG6s+6u4vK1TjMmD00Ikz24qL4GSGMHH31ykTdbf1qdBxQobXHVkruY5jo3vmWg
         RhwNdKqxRgdbt8VY+R3c8Ya6Qn6FJ6o7EKeJYOpktMkEX+12Z4smpSIg3oiiAnS3QuAa
         6RDMEXuOukMCwcWsz7QdyNWalCo5Ixkt38JcvGJUvRBlLQOsuEEC4DcWDTkKUjrgLaLo
         756mEmO+EDaxHVzceryWpEeqdzVSnJwWRMVzur+FIV37EB0cUXHyIiwAd2LjQcIulRb+
         0hMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fWjKFdywMejFkLDD+jg5rCR23C75L+sG+Q1QLFbhU00=;
        b=i5R/AS45jgmXJVnKcQIIB/cgQ9oPgI/9dz/QMr9iv1BVQSebrCWkn/mC59nZRyVo02
         W85Je1WD0gfS0TRzVh/g5ZrJ0k8RPP+MxvAcEsiZJh8EUGRGlFeV3RQKSAt7NkVa+JD6
         piSah9lwxEjUyRFNj5aZHyNbSKeaCdE3JabrAxcTmhKycN/T+4rWmzszLNTwzQrGBflb
         1+PdR0y9YaT5Axbikf0NgdJZTjHD870EnmhJWVIvmSeCA2ZAho+GOBp4OnNodyIR+ZQM
         bIojPvKJvj2l/2fa6fpPaqB6n2kaOu7ABLyP0lFqPMBSRa2OPLIRtvijh4deymAi73Nf
         zRjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fWjKFdywMejFkLDD+jg5rCR23C75L+sG+Q1QLFbhU00=;
        b=PxH3/JNyUgip13Hux30NEyVJBZqU+jSTueTFb+g3Bjfev/PWjx6X4jBt273WS5OQje
         VGRRowmGhq5EDkoSEUCFmuaVqfrfqaIlOnuSfPuhDMTC5Pd+8lU+YyQaf0vqlH5OLpSB
         myUiULNhr+JusYGs/VgEFJMPLophf7Tf/SN7p8PcGtqlZrBhdsnAH9Ozqiq7vR6hBTuc
         waC4va/L7xXvhRs0tSYv6BpEPEGQleaFzIuHo+PfAKdZpkx5OH5fMEuU0bI/WvbmH5Ak
         64hzL8S0/wS0OwIuVAtNYZdDy0F3LTyCYGwZTW89CJmsC0zzP44ipPCFm2SblhkyFn7E
         zvNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgJIJfA9wemPvGCEQZ/IMXq+ksjhfpUk7o+qPckqHxjCQ7ezWS
	i8Hgvc0jgc5J8uwGPWWpLYY=
X-Google-Smtp-Source: APXvYqy6LtMhx4Rhn7nTNMGNcB2xZ/XRojWn9VvlDuN5ggoTA/BCTyJT514ZtdiIg7CmU0kN3EsCOg==
X-Received: by 2002:a1c:e109:: with SMTP id y9mr6093827wmg.35.1562783085675;
        Wed, 10 Jul 2019 11:24:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a745:: with SMTP id e5ls993311wrd.5.gmail; Wed, 10 Jul
 2019 11:24:45 -0700 (PDT)
X-Received: by 2002:adf:f591:: with SMTP id f17mr33482491wro.119.1562783085231;
        Wed, 10 Jul 2019 11:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562783085; cv=none;
        d=google.com; s=arc-20160816;
        b=XGg5Xef3EvaEnyp0jNcW1L3l7A9STC8zgrXziD9ADLzJYLUCnq7i+GXs44GfDikJ1E
         O6dT5GS/BrZz/2hxT53tMlVMmaCqjHyrk5IoN98uJbsGHv76IQHNtKWgsGoWNAxZrYSo
         7ajtf/XXZTgk8NalgAVtWXyxVgdeStSAa7VKCe1DWPIO66LhOBIOLUlX3MIPjfsessFT
         K+iXJp/lU+fgyatsLynF0udDvlEaSnLaV2kzr8ScY8SndjJOSPOBxX1soqkLgIiL2Lc7
         RF8RU6HJGDG41FWc9oaEjrfa6F195ixn1se4mBfZI/JjVam4RSWfEgNPGkqJDqeyNHBM
         yN4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=wZtz7lm7J/SagsRkoCghKnDoEzNg/tnMRP90/zbxSlc=;
        b=ydsA/5EzxUvh2hRWYHseWlmZYp4KwfH4Ns1stn7aFrA2CyrfaUAj6IEiGlvVW8nQta
         exxA2Mis7hAi8CYWRybCndQTRrJSknIaVpkXVwRdvIEAcUE4oXdwsJvJkBuFBw2tuepf
         FjQoIr7Kkh+mvSWYritV3NR6YS4g8LDEBiuiQAaiOpvRyZbP9ckUrhYBXmwHgfCU4OmJ
         kg+L5F1GrNtMraFoF8d8uNF3SFtUEwMamJmQVh6kaK3ws8LshiJ2rJMa1usvovG9PSLk
         PXxsEujuEo/rm7eeplfVL4rTkF4p9F1MF7tCWy7v8xm7LYPiKp0eXlnDpHoEWXjiZ3x1
         GB6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id 60si91267wra.2.2019.07.10.11.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Jul 2019 11:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hlHGV-0006Kk-L9; Wed, 10 Jul 2019 21:24:27 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>, Dmitry Vyukov <dvyukov@google.com>
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
 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
 <1562640832.9077.32.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
Date: Wed, 10 Jul 2019 21:24:22 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <1562640832.9077.32.camel@mtksdccf07>
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



On 7/9/19 5:53 AM, Walter Wu wrote:
> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
>>
>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:

>>>
>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
>>> promise any dates because the next week I am on a conference, then
>>> again a backlog and an intern starting...
>>>
>>> Andrey, do you still have concerns re this patch? This change allows
>>> to print the free stack.
>>
>> I 'm not sure that quarantine is a best way to do that. Quarantine is made to delay freeing, but we don't that here.
>> If we want to remember more free stacks wouldn't be easier simply to remember more stacks in object itself?
>> Same for previously used tags for better use-after-free identification.
>>
> 
> Hi Andrey,
> 
> We ever tried to use object itself to determine use-after-free
> identification, but tag-based KASAN immediately released the pointer
> after call kfree(), the original object will be used by another
> pointer, if we use object itself to determine use-after-free issue, then
> it has many false negative cases. so we create a lite quarantine(ring
> buffers) to record recent free stacks in order to avoid those false
> negative situations.

I'm telling that *more* than one free stack and also tags per object can be stored.
If object reused we would still have information about n-last usages of the object.
It seems like much easier and more efficient solution than patch you proposing.

As for other concern about this particular patch
 - It wasn't tested. There is deadlock (sleep in atomic) on the report path which would have been noticed it tested.
   Also GFP_NOWAIT allocation which fails very noisy and very often, especially in memory constraint enviromnent where tag-based KASAN supposed to be used.

 - Inefficient usage of memory:
	48 bytes (sizeof (qlist_object) + sizeof(kasan_alloc_meta)) per kfree() call seems like a lot. It could be less.

	The same 'struct kasan_track' stored twice in two different places (in object and in quarantine).
	Basically, at least some part of the quarantine always duplicates information that we already know about
	recently freed object. 

	Since now we call kmalloc() from kfree() path, every unique kfree() stacktrace now generates additional unique stacktrace that
	takes space in stackdepot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9fd1d5b-9516-b9b9-0670-a1885e79f278%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
