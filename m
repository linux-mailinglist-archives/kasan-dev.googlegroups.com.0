Return-Path: <kasan-dev+bncBC5L5P75YUERBB6NUHUQKGQE6FGPE3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id BC3C266B1A
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jul 2019 12:52:55 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id l4sf2299344lja.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jul 2019 03:52:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562928775; cv=pass;
        d=google.com; s=arc-20160816;
        b=Id+Av4UauYLHPaLthUns0NTKp5Af6K7cq4TvZ7zGJzZZYndWxsHpfSQ9Yi8gX76dft
         1KSqrd4sdWJXBsc0CDTB5JQQOPyax+vD9zqhkP9DimuX+Mk8cxhvkznB0mpwwR9neeYp
         j4bEuwk9tHGME5PWLRvss0qdKRS0gznTwBeu8lC+ulen700NwduD+e38UHiLtAUXuSvj
         x4oCKUM9NKRVNevPygBpMVQXxuK7YWa4ULvwlxuFl2NBINsXs2ArdZVR4HNg/kjMgfVJ
         oBhC2oWkEPH03iPu9eux1DWMl79QI8+wfGM1yrkidUw1p+xBnLCr4iYwv6h1EvwI3E0J
         kycg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=b8Ciq5oJydgrW+G4VYLu4Ywz5NbUR1FkYBXQjTQqwyE=;
        b=m1xMjCtuUJT2XN1L/g2tfwnlezOZEwP84NcyKWbylMQkLNDcefw4rrYgCZUh5MKRxQ
         2IbrKruu8PYznGKcXykT5pued83HboZFzqlotBILCijDdbmefVP3OLP+XB54Jr2CHisT
         /0wH6zcPA67aOV3iCeVxoo/oQe/rXq598ag8zyX2u7FwiBomPdsk6OJHC+l9cJVzKOQO
         Lf0l/n/JafmmlaQRy/OYjx6XW+2u3usn7QJCxePqkoxYOrVU9vVLux/sW5aKC38VXoJn
         lW1gw5JOErwfJhbn5wRrXk28ft7tf/8hQuKBQEOSUvCgPqgFleU7ILz/Kg+oc7IKEYvV
         bLHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b8Ciq5oJydgrW+G4VYLu4Ywz5NbUR1FkYBXQjTQqwyE=;
        b=DL+NUxIyuk9PFIJLPVU1b6sMt4j1dodWtEOCAWhiI7XJLL4cpGJ24naF07PmSIxW2R
         vI4Uem8v4gwR/lsFQ91FiQ0vjj7nEa9vtz4HpAfuFJCIs8akS3+0SMQe4P8uYLbgnQYL
         gykED7ixZsk7sWskIvzCSGlYIMjauzcxV1FqoGS9S4UTsGApNapz8lIig9fdcjDHBntg
         kZ1aa6ozlmDrgXNj2iLqFSkY5vyoenOE6YueslMqctShsV2qXgJ/uFf01ZsN4sIVvyZS
         zv0z/+OCtYke6IcQGQgPw6uoUwB1Lgo9i2ZXdGnO1AvV5aI+7UDD3vpOwkIY2DxXOURp
         gr+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b8Ciq5oJydgrW+G4VYLu4Ywz5NbUR1FkYBXQjTQqwyE=;
        b=Uh09klhWPGerqY5OtYOVpgpa1CFHd5izJzSzFan7Z/IQD02y3WS+SQzo7XZym764Bl
         Z6hG+oxK1pMBLYSZ5UH8XS2LMB4FihIsihxgzdINXAZMhhtz3W3d2RPHwRi20WkGVYwJ
         pACXgBcMVqAFXx46EEpDWQaMYTqLixjySzPpfZBh1EFBB/DBB1EmvWEXBYHS8j2092Z2
         oJ3qinl+U7vhmO82/hRfFR8OfUdLueeHscLLPRZ3WlaZY/b6RmnitJR/sQZFZmTe5DAc
         VoA32c4PeouhOV2XTFBaXIxbjM6ADFPF6ECVk6JI0mLiJlsv8fisTgcUnEKM5X7BKhIQ
         noTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUhhxmFlvoel0H78ZETXtA1ZrfqzoAF0UpaZtkQAttNX5ETxbzr
	+JTdT2cHy0VbfJqE3aW+s1E=
X-Google-Smtp-Source: APXvYqwRImBLfXUQUXqQ2S26gkm5PLk23JsQjzx5KpUanVnELNoyuzEYlrgmi8EKVUOKSuLDY1kJBw==
X-Received: by 2002:a2e:b047:: with SMTP id d7mr5755064ljl.8.1562928775250;
        Fri, 12 Jul 2019 03:52:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9153:: with SMTP id q19ls1111027ljg.13.gmail; Fri, 12
 Jul 2019 03:52:54 -0700 (PDT)
X-Received: by 2002:a2e:995a:: with SMTP id r26mr5573095ljj.107.1562928774824;
        Fri, 12 Jul 2019 03:52:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562928774; cv=none;
        d=google.com; s=arc-20160816;
        b=hPXrG7XFVMkalb4MqA/vfwBBi/2hGoma09E8A602waKMu0Vv7LbQedBeYPEAUMlVR7
         TPmQ5e5vV1gNFyRf28SWmxpiimXO/1mCWxzLZvr6q+UtrYcZ5Q7JQzgnDnsv0g+wL7I3
         rUmI8u5xG/c4xaCmy+3lmt4Dn93LdfCIlJ//RsXr7ALYXe6mr6CYucfbOIBlIOW7zByY
         8qfc4kE4hrR16OVOlRQBajBl+gazjdb67X4KbIvQvITiGRnUfSot2Xo1xwAhZ/f3gTC2
         aXE5uhqZw/HRqs2D7qCmGj5yX2LRRG6/nxJZtJw17GfjBVthDJ2VYwtwdwt/AX8bBZcc
         6N/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=O67v3k5bom5Y2GHrnJOdlacQsTwxZnyxwR9ee+CLLBI=;
        b=AACCyqW+hpkpVNaGrnV8hOWKPwzSknEDZKJTmrl7dg1WKUSSDFI80KrBRprlGxXrmw
         wVUiLvAQ4OPNn0uA/3ehghArlkxPvx5IICR4PgypBzY8CJ7fHxaKhyl3CwtCAnQCrT74
         rSh1p6jJlybehzrsLSxA06LodlV7CQlZatdoMETc5nypr081i+CQKZN4+3pZJiyfKfdV
         7YZJ+V1n6/1buKxyD1y6tGQNVwofp6D9HrE1wyzP5OCW1GyTWoN7R4wXZP+fOLW8ElVn
         cSLfpjR/nSZAFSky7JNCM0kPHFTxugbBFWcCPSkBSi/W3CLJ/cy2VJsCkQDe8/01EW2I
         NFJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id q11si484641ljg.2.2019.07.12.03.52.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jul 2019 03:52:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hltAL-0005Ih-PS; Fri, 12 Jul 2019 13:52:38 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
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
 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
 <1562839579.5846.12.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
Date: Fri, 12 Jul 2019 13:52:40 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1562839579.5846.12.camel@mtksdccf07>
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



On 7/11/19 1:06 PM, Walter Wu wrote:
> On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
>>
>> On 7/9/19 5:53 AM, Walter Wu wrote:
>>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
>>>>
>>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
>>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>>
>>>>>
>>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
>>>>> promise any dates because the next week I am on a conference, then
>>>>> again a backlog and an intern starting...
>>>>>
>>>>> Andrey, do you still have concerns re this patch? This change allows
>>>>> to print the free stack.
>>>>
>>>> I 'm not sure that quarantine is a best way to do that. Quarantine is made to delay freeing, but we don't that here.
>>>> If we want to remember more free stacks wouldn't be easier simply to remember more stacks in object itself?
>>>> Same for previously used tags for better use-after-free identification.
>>>>
>>>
>>> Hi Andrey,
>>>
>>> We ever tried to use object itself to determine use-after-free
>>> identification, but tag-based KASAN immediately released the pointer
>>> after call kfree(), the original object will be used by another
>>> pointer, if we use object itself to determine use-after-free issue, then
>>> it has many false negative cases. so we create a lite quarantine(ring
>>> buffers) to record recent free stacks in order to avoid those false
>>> negative situations.
>>
>> I'm telling that *more* than one free stack and also tags per object can be stored.
>> If object reused we would still have information about n-last usages of the object.
>> It seems like much easier and more efficient solution than patch you proposing.
>>
> To make the object reused, we must ensure that no other pointers uses it
> after kfree() release the pointer.
> Scenario:
> 1). The object reused information is valid when no another pointer uses
> it.
> 2). The object reused information is invalid when another pointer uses
> it.
> Do you mean that the object reused is scenario 1) ?
> If yes, maybe we can change the calling quarantine_put() location. It
> will be fully use that quarantine, but at scenario 2) it looks like to
> need this patch.
> If no, maybe i miss your meaning, would you tell me how to use invalid
> object information? or?
> 


KASAN keeps information about object with the object, right after payload in the kasan_alloc_meta struct.
This information is always valid as long as slab page allocated. Currently it keeps only one last free stacktrace.
It could be extended to record more free stacktraces and also record previously used tags which will allow you
to identify use-after-free and extract right free stacktrace.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37897fb7-88c1-859a-dfcc-0a5e89a642e0%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
