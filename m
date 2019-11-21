Return-Path: <kasan-dev+bncBC5L5P75YUERBQEW3LXAKGQE4AU752I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 41534105296
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:04:01 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id n11sf541273lji.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 05:04:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574341440; cv=pass;
        d=google.com; s=arc-20160816;
        b=xzC+vswbm/SzVenfucCTBrnkSQ/XWFfqsNd13XmfZEZ4PIrT6MekJG7Q8BNjd69a9a
         j4S7WJOb8J+7vl8dHCk393rAVnJE+P+MSd8nCv503Nxtj8w/u9VGrqFWYMeJQeJTqvHA
         YdbTFgosueG2DaisCaOH6EDHKTWxSGIKCCzFIL8xZv3BS1CXthh7SqaqWFKklE8Ry/mS
         9Gsx3n82Ez1wAM4soQhc5pB9UHA2uToCA1NSXLVXf06pbdElmdnPOFiDRtIbQfciElqn
         jm/hT9kOARLSTGXy3EPO090Uvm3GfR6GikixCR3Kq86kXpmmBbvVkZyYKBimt5NmstNC
         wghQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=lIXUo9txOv6iPfylK6P+72/hV/sWUqVrvOxN8SLJnEM=;
        b=DMhTPaH0hhPpkL/zMMUdXO3DCSYgmK5a6xc5U1RkU3TNDXbVrwgQt/6N28wdrQdx2j
         ObsdbxaQjGH6jp5wAQgPYNLSXpLErRMKlur5K2PJDh2lL6ajzlefqtL89mPkYA9MF5jR
         PgIEnDuB3H34NiO6qd7/PZQ5AeC7bGE8o77eghKgKc3rt8lIaChHkU/Yyfm21afHJ7NH
         p7+jUod7FpxGZh+vuPxentKZdjNVWugFp23onQJkTx52d2e3WS3REnblVoEebMUuSO0g
         Ge1nxUGorKYmhygg8L4WIsUZgF7ZxaDaylaZT2Yiu4LpeD+NgSwMAwAPmD+mSFALNHY1
         ZJwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lIXUo9txOv6iPfylK6P+72/hV/sWUqVrvOxN8SLJnEM=;
        b=OaXNDO2EM4c5LIqAo+C0HGmu9ot6/Zak2OEDLoI0VZjimdAFyDYsHktyDeyJJqntoV
         73BOQ7njQrGzXTumc5gImqjIzY2g/UGBeO9hpIhtLNEAKKB2YSqvsh8+aDL5UlvnHUHH
         Qftb+vTNp9CoIWAitebVRIFNBsQpcrJJCqssx2utinXkP8ttJ1y5KtQ5x6zPrGvGLnlN
         L5mH/UsqTwVydZnPR1HHadGCvYG6nCXPJJVYlZxHWhDcCGb6h0X5NZL1ESl4zlpDvY3Z
         2J3skFm6msTX7n9k6SBVOCIgHPd6vU60gKHSBhLghapCMyGBAompVVQNpAxT2I0Qe/eO
         1YPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lIXUo9txOv6iPfylK6P+72/hV/sWUqVrvOxN8SLJnEM=;
        b=dGClKdque9J1yn5PqMhEGDrHgwsuqUT+JRsQvZj3ugQR4BSI7WkDJs9ZqwvEoWrlaX
         utGQPh/G+Tb77VNIR8MVdfFfDPmhXgvvI9V0e0mU8gxvrV+ENgmShxbUwkmKcEFxX0Yc
         LSrNqsiDEJee7oCmem5IKPWaXxb6919INnaOyuroqAH3xwW3xkZz+oAIzGrJIwbocSbl
         MSB28lcqZ6r1LlDDkuhfa9Pb7EJezt53easGgHWVQL3W9n5wGdzcQptzAomU5jYIvsti
         Dr1/TLSP38clxAudVpqbWZXTK8grEo4P5u/WnhphXdoACDQt4dS2oUBv7TW53NjdQLTX
         Xnqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUf16BulO8U2HwH5ekVbS5jBqvJVo+u4myV8+Ba/VifdD3G73e2
	vqeKETs0WJedd+Rgzi84KIM=
X-Google-Smtp-Source: APXvYqyPthk/ahFCAyY29FQm2RQnauGhdTMMJZHI27v5YGMnDmj2Dio3JCIo+TD7SfalIO8VvcSdag==
X-Received: by 2002:a2e:b54d:: with SMTP id a13mr7601584ljn.4.1574341440805;
        Thu, 21 Nov 2019 05:04:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2e01:: with SMTP id u1ls969854lju.12.gmail; Thu, 21 Nov
 2019 05:04:00 -0800 (PST)
X-Received: by 2002:a2e:85d0:: with SMTP id h16mr7661617ljj.75.1574341440274;
        Thu, 21 Nov 2019 05:04:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574341440; cv=none;
        d=google.com; s=arc-20160816;
        b=d+C/yEJ1MY0md2HcBV97HY3aue0A7MBWxYSNjV8N5mBinqHWGFD4+olwwmhWYd68OH
         7hSH5qmJMcgv0o1FXRrF4CZRBzOFr8bwkworPdzjmcjgOl2ylOIz6C6eCK/LHgsukqG8
         aBvt6ugswANV0G33ClHLufcybhNIPZQLLQPmFrY0vA2Q8qCw8nJios4ktvII7C+CVRbg
         h2CAp99rTVWfm9F7uMzn9HTSBWPBvoohqdZjkauyrEQZ1yUbmnjboxeH2yIpvxOzBfxP
         YtzXxxO7wcU/CBjPNmzkhG1/wboZjOM2dF8cAfpSB4c97A8J/7SzDwBChuw3Gyl/LhIc
         Vglw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=EBcTiMM5yBnrH7fTMom6myKUpQTRFOmVctAF+o4fa7Y=;
        b=sBuR0BjEAoflbnrc3N5B1ZDf+kR/6mCFY2qK1HlzIdcOD4RP9zITbnKfZI0iuVe4DB
         LeSIUg0tf3KbJvfcsUT0GiwJ5WJaAg06z88m1GIXiQ0gqw59o5+InN++gO0SXhGECgva
         6AcyjhFLPvJChymOG0IGoTOPSaz6VtjS/E4+dZ58GyYS4KoL/9mLfkMJ9lWo785jmWXb
         pxA6kKPl7dtvyLg62UXn1tmTDTq5pchaOUTkBK9G+auV26+V595kF+HWpg9UeJEKjXWd
         wKmRqaohtcL+c5lXYfwCWQSv2ue/o1/JKKf4GX14ZRjMhLDkcc/yB1HOxeg12lBC6LDB
         v51w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id k20si99879ljg.0.2019.11.21.05.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 05:04:00 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXm7i-0002DQ-S4; Thu, 21 Nov 2019 16:03:50 +0300
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
 <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
 <1574341376.8338.4.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <217bd537-e6b7-3acc-b6bb-ac9c5d94da89@virtuozzo.com>
Date: Thu, 21 Nov 2019 16:03:38 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <1574341376.8338.4.camel@mtksdccf07>
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



On 11/21/19 4:02 PM, Walter Wu wrote:
> On Thu, 2019-11-21 at 15:26 +0300, Andrey Ryabinin wrote:
>>
>> On 11/12/19 9:53 AM, Walter Wu wrote:
>>
>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>>> index 6814d6d6a023..4bfce0af881f 100644
>>> --- a/mm/kasan/common.c
>>> +++ b/mm/kasan/common.c
>>> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>>>  #undef memset
>>>  void *memset(void *addr, int c, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
>>> +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
>>> +		return NULL;
>>>  
>>>  	return __memset(addr, c, len);
>>>  }
>>> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>>>  #undef memmove
>>>  void *memmove(void *dest, const void *src, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
>>> +		return NULL;
>>>  
>>>  	return __memmove(dest, src, len);
>>>  }
>>> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
>>>  #undef memcpy
>>>  void *memcpy(void *dest, const void *src, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
>>> +		return NULL;
>>>  
>>
>> I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
>> poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
>> but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.
>>
>> So let's keep this code as this, no need to check the result of check_memory_region().
>>
>>
> Ok, we just need to determine whether size is negative number. If yes
> then KASAN produce report and continue to execute mem*(). right?
> 

Yes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/217bd537-e6b7-3acc-b6bb-ac9c5d94da89%40virtuozzo.com.
