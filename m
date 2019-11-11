Return-Path: <kasan-dev+bncBC5L5P75YUERBOGUUTXAKGQEVIC44XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 35801F70B7
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 10:30:33 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id y3sf9540338wrm.12
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 01:30:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573464632; cv=pass;
        d=google.com; s=arc-20160816;
        b=L5u1XDynkhdQEdyrRZy/j7+wvw87+4Ib+DGpYHYjxG9hIhIIsSeGKsLupnv6Y9oW0z
         L8ebr0K5eAOaF59NNPlMDyp+Jie4e/ejVkuBx1447DRqWGmMQlrHeIPGaDxopP1T2sRA
         6hdCuOiFM9zeeYhhpgfR8MwtV3ImKU+xPdiMSOj5sGQFH9oMzPAgKS95vl8DIkCFx0R7
         /VZHXNRy4BE5e1HAbP9cbUqxjxvYjWGJB4cxo/GGzjGC6mYL6Q2CHisYHGhVwxXgnMPs
         NS9rkEt723DQbag6RmT3GvLVJdE0koZKnpIWjkQzA6ZckNXAIFjKhNzYTST48gq4hadM
         h+Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=46mEGAt/hyo/jqbhWMPXfJcD4viyivo9xnkNiJ3vqaU=;
        b=clOHMnbpg6XAVe9pBEfgUL8RgNB8kxxsTp1SBFfak5S00gJcEg5Lu2J/ZfaIhKdU32
         fPMLxd5A/ERPgwhzl4HG3p9Yc1+86R8MEEu/v6MKO7f0z7nehA1wh1kzTOMY1alBrlh5
         mw3iwCopoMCIP1H5vx3WEbNFCqEeS/87Yeh0StuZSMUopqazqHvp26J122mBSHVczTe7
         oUU4DD+uX9nu4ZpRbWeIufoHmx9+aaB7OJUi6rNmbh24eHgPWcC3B4tdGQw/7ZO8vsbA
         rMS7b3MUOQOtJFzX/wEDiLsJbIFIevX8dkcl88wa6ACD41EnpOVhXesToUXs1I9T4Cfk
         tgZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=46mEGAt/hyo/jqbhWMPXfJcD4viyivo9xnkNiJ3vqaU=;
        b=EgkhxKlJu8ZBf2rgQ76vmMaaSGjJTTBi3I1Tz5bGsuu0G+IBciWTe0kpjMskTqTVHN
         p9g/21e+zmStdCO5xHszr7VKt+7TgYE51QF56F3JXidWegpQfHQT5Lsaa6cqQGS+dDN6
         ECldGjWZy7RPAGL4T047LLE3gPbEbXoxQ5rsW8xT+7uHy4PdH31+YP20yBQUILOaWMTi
         KO/toZb5EArbr5jEegtKIh7XH1Mh+STbKyeVmMh8jtRrpNIOfxWZn38DodF0lebHhC/B
         hbqv5H3Iy/1nEpIQCA7tQUXjJxdXc3x152LrjAKa3Ubo47rUUAWomHt2hVNEsdWFho2d
         UEOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=46mEGAt/hyo/jqbhWMPXfJcD4viyivo9xnkNiJ3vqaU=;
        b=KM9Hzf0dRPgy9CLd+goqQ17yG6+ARKSRsJmM2zOD3f1285bNiaPuCZJGzvDgOHBndW
         O/glJGEGobPWwfaoyUki9AOSffgopeFLr9XDERcf0nXtvcH86o8BKZN9+5GhkvpgPPMZ
         TIuJZy5zjz71H+lyIAbkjJLdc/wwwOWExQyY0bXAr7zpI8AVW1gNenDFAPnYydwPpeFi
         lA6G3sSs33RLYCLvWvIbcD1Alrug2Fjlj3OJZ7kaYdikXuxZ0CuRlDCU7OVjvY97hRDa
         L+LxGyaeUKIDJ5yrc9iNhzePq/htHhS5aissEPBaNFe5L+lnKqxbQCre/4uo8bF3OZEN
         QGFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU5V2AxMTqLBUjRDfAQnH6aa4l/uMArrRk1ZIryki4JaRNWc/U4
	IhHjddg8zfDgCo+bzOAudAg=
X-Google-Smtp-Source: APXvYqyMBmq1rtklN5RVjw6P+U4NTZRUGzmD3wyBeWHGXHhHmVBk/VWNJ2KYSmTdruqL8lfs/bblYA==
X-Received: by 2002:a5d:4f09:: with SMTP id c9mr21101351wru.175.1573464632854;
        Mon, 11 Nov 2019 01:30:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:960a:: with SMTP id y10ls9454921wmd.0.gmail; Mon, 11 Nov
 2019 01:30:32 -0800 (PST)
X-Received: by 2002:a1c:f612:: with SMTP id w18mr9554956wmc.28.1573464632287;
        Mon, 11 Nov 2019 01:30:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573464632; cv=none;
        d=google.com; s=arc-20160816;
        b=GatTYf19S1mysAfUlYDgkRKbULoqhasULENnc9i+R6C2MSrnaMxrUN24zhXHkrPx5U
         KGYxNE04+LkRIINHxHGLB1Qu/rawK+iI8y6vu6f/sakZjEOGkEmi50XhS9L5LEWoXwgu
         XLJSuibQ5gUCicN6u6+lKgzQbOenXpHUbGNX/kOBmSrCFDGAXyUly8x8ygvXch52fELi
         4MvZYbysOqW0dPBF0qA+hEBnBSe/topfeLm49XPTX19GCZOaMvBdXMYqUZCVP4aKFTiQ
         bnB/vFKDCc6BWUGF8pn6g3ALVnCOP+YKubeqCfyOal07lQXLfitowRfvCBPWMJLC88yU
         Z3pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ZWs7Q8BoDGnMECJcYrgtTA776G+F4DlAE1GcBF/cp5w=;
        b=C/gjSSNPiUZu8iSEkTiopJu3Vxg1M8F1UzzISbB2TVHKh0/EfiNwoHNu72Qr9KYJFI
         c1UX7575dZwtv0Xj2yfa4qzqhEhFxvRJBnzPW5dTpugAX8+CmEAZUJ2rLrKPUydVPAmI
         0tgEZx9yLDW6v295ZwRcxnQE7YQZMXDkQ/rU5uJrg+laoozzanwPZAFzNAALL4J07YbT
         y0erhixJtleyTfpek+xo4G5rY9BDnpKauyJuMML8ItMSrsJkFk7+ID50WDUIMvMgeki8
         xNZrlYHMOQOFE61CzUfYH5l2ZZbFaDQW9+hjKhE25nkPatXw7VSw1I0U2GpfUR0g/c4G
         C3Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id q128si799674wme.1.2019.11.11.01.30.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Nov 2019 01:30:32 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iU61K-0001Yc-OX; Mon, 11 Nov 2019 12:30:02 +0300
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
 <1573456464.20611.45.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <757f0296-7fa0-0e5e-8490-3eca52da41ad@virtuozzo.com>
Date: Mon, 11 Nov 2019 12:29:51 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <1573456464.20611.45.camel@mtksdccf07>
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



On 11/11/19 10:14 AM, Walter Wu wrote:
> On Sat, 2019-11-09 at 01:31 +0300, Andrey Ryabinin wrote:
>>
>> On 11/4/19 5:05 AM, Walter Wu wrote:
>>
>>>
>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>>> index 6814d6d6a023..4ff67e2fd2db 100644
>>> --- a/mm/kasan/common.c
>>> +++ b/mm/kasan/common.c
>>> @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
>>>  }
>>>  EXPORT_SYMBOL(__kasan_check_write);
>>>  
>>> +extern bool report_enabled(void);
>>> +
>>>  #undef memset
>>>  void *memset(void *addr, int c, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
>>> +	if (report_enabled() &&
>>> +	    !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
>>> +		return NULL;
>>>  
>>>  	return __memset(addr, c, len);
>>>  }
>>> @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
>>>  #undef memmove
>>>  void *memmove(void *dest, const void *src, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +	if (report_enabled() &&
>>> +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
>>> +		return NULL;
>>>  
>>>  	return __memmove(dest, src, len);
>>>  }
>>> @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
>>>  #undef memcpy
>>>  void *memcpy(void *dest, const void *src, size_t len)
>>>  {
>>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
>>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>>> +	if (report_enabled() &&
>>
>>             report_enabled() checks seems to be useless.
>>
> 
> Hi Andrey,
> 
> If it doesn't have report_enable(), then it will have below the error.
> We think it should be x86 shadow memory is invalid value before KASAN
> initialized, it will have some misjudgments to do directly return when
> it detects invalid shadow value in memset()/memcpy()/memmove(). So we
> add report_enable() to avoid this happening. but we should only use the
> condition "current->kasan_depth == 0" to determine if KASAN is
> initialized. And we try it is pass at x86.
> 

Ok, I see. It just means that check_memory_region() return incorrect result in early stages of boot.
So, the right way to deal with this would be making kasan_report() to return bool ("false" if no report and "true" if reported)
and propagate this return value up to check_memory_region().


>>> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
>>> index 36c645939bc9..52a92c7db697 100644
>>> --- a/mm/kasan/generic_report.c
>>> +++ b/mm/kasan/generic_report.c
>>> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>>>  
>>>  const char *get_bug_type(struct kasan_access_info *info)
>>>  {
>>> +	/*
>>> +	 * If access_size is negative numbers, then it has three reasons
>>> +	 * to be defined as heap-out-of-bounds bug type.
>>> +	 * 1) Casting negative numbers to size_t would indeed turn up as
>>> +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
>>> +	 *    so that this can qualify as out-of-bounds.
>>> +	 * 2) If KASAN has new bug type and user-space passes negative size,
>>> +	 *    then there are duplicate reports. So don't produce new bug type
>>> +	 *    in order to prevent duplicate reports by some systems
>>> +	 *    (e.g. syzbot) to report the same bug twice.
>>> +	 * 3) When size is negative numbers, it may be passed from user-space.
>>> +	 *    So we always print heap-out-of-bounds in order to prevent that
>>> +	 *    kernel-space and user-space have the same bug but have duplicate
>>> +	 *    reports.
>>> +	 */
>>  
>> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
>> type, but at the same time you code actually does that.
>> 3) says something about user-space which have nothing to do with kasan.
>>
> about 2)
> We originally think the heap-out-of-bounds is similar to
> heap-buffer-overflow, maybe we should change the bug type to
> heap-buffer-overflow.

There is no "heap-buffer-overflow".

> 
> about 3)
> Our idea is just to always print "heap-out-of-bounds" and don't
> differentiate if the size come from user-space or not.

Still doesn't make sence to me. KASAN doesn't differentiate if the size coming from user-space
or not. It simply doesn't have any way of knowing from where is the size coming from.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/757f0296-7fa0-0e5e-8490-3eca52da41ad%40virtuozzo.com.
