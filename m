Return-Path: <kasan-dev+bncBC5L5P75YUERBWPRSPVQKGQE7575TNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24BB59E456
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2019 11:33:14 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id f11sf11290720edn.9
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2019 02:33:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566898393; cv=pass;
        d=google.com; s=arc-20160816;
        b=akHm0EwAVIdplqDEXE3jTirWhVQNnyNEx3NhbfgAvV3puNPoe07jN+xLKjeOVnm4XK
         /eYjrYU1GWEVmp15kBgy7Fc/tD/M3BjneWsDoVLcbokBHrHqvHAUKhJh1Kox5dKrmU5J
         A9+YwOYBcfE1H9iMEkIvy1ITd4/AjXq2AjAorAmsSqR14eLWky3mkzk5htQyAQG6ZGHZ
         Lkz+ASQGfAJHFX4EQiu8XgyPnSh1+MIH4k3CUYFfe5YIo92TZiuFC94+77+P3ihQ/g/W
         6A7yruflHewUzgN63Juqzv+72SkZOIlcGwibHZmROp29u5ngdFuG6mo3iL4ZV73YuEqj
         eHOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=LxlucOJwFzojop/0QQzSkABlcsK+v6dWF9UI1MqQke4=;
        b=k06d83plRtgXJIzOI82fE0bvmZLqhHTY+0eRtFge1oqV7XYRsIa6PspSDwVmnp/wTQ
         lEorF/tMe+qBX9BaOetBTtAzU737tqagOoqieJeHEqG1HDC3KXrl8lLbeV/y9kMZkteM
         JkRh7enBNaGuTWlYlVjiXYXrX9wQlYD5CagdeBM6UnaaGFZM9N9A/vNzYRzf6TeTjDei
         Qh/Iz+lW45kyGFXXbbNUITTvx+7C4gd4vu9mfh5mM69X4u2QisKEa0RMPd3Lr6fMs2iR
         37QQ/BRdNGkKv1yuiLjr9+m5qkw2PECKXZubDziLHbUB8ktODdVsnAF7QH+VE2D8WGS6
         N/Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LxlucOJwFzojop/0QQzSkABlcsK+v6dWF9UI1MqQke4=;
        b=INwYIPi4VtzLV1YCCpzoLzLMsB+UZm9VIziwiyBE8XyiDLinLVuOAAPBHZOKAdEVRA
         bQbRl0I+PfdrOLWU/yVFB2DO5/Q3/sGgn+6RBYQny1dABbUllPeyi9j0lQh+QzScYIj0
         2OPrPSB6bKwv5+NxjoY/IDinUYkkEA/m1LrokyygRJdieKOZcLpB/zw1e+k4/UwoMx8b
         uw3l6S1Jt0CS5qNYEC3bmh0KbfyIjuiojMHQze5mVYL8fm7gspV0oz2aHXFJ7U3J7WMn
         lY4SULVmOfIBb4wmvwmXmZx6gIxmTNgDXJu+JzgFUc6v7voq/3GphVMYaReNqJy8rf7x
         lDGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LxlucOJwFzojop/0QQzSkABlcsK+v6dWF9UI1MqQke4=;
        b=aqb1YiYAn/m/5hXEX/s5qNSVTZ1uw9B6j0XGBXn3atnwJDi9jqZnZhrC5va2w3gbl2
         ktDKgX726Xt+n39xq4fL9P5y+FQKX9SOl8q0KldLETI0xcFqGML5ml7zqkzvqi3Q6kuW
         +Y5Q5Y4Ek/JrQ3H2Dkanou0GNAbh7AO/bxp/OMJFTwWyYruSJ9LSky4h5bLx0P05nh5r
         FmrRi+1zdV601zv7kywh4SHrOvVpM7XU4D6xJv/0pkzkUvWHXHDOZBGWlgCBF+WBPT28
         stIlVhl/vsFLGNDlQLyHL0YceEfBwt/CgmD58h54cfkGP+EsvqyHqPieR45tl/AYwpFm
         Ewlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWqOabQTxBSqsoLX7OWXWrA/eH56f2t296TdrTmBq6AhH6JZJtc
	jgB3rO+CKv7aHgYN+XZHc7w=
X-Google-Smtp-Source: APXvYqwc6UNqY94O8cCUz8mSeyCByeACAUEmQVNr46dQBv4H3Rl5IDmJDKFKyUStt61UbxfQQXmnKg==
X-Received: by 2002:a50:88c5:: with SMTP id d63mr22843185edd.122.1566898393830;
        Tue, 27 Aug 2019 02:33:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:90d5:: with SMTP id d21ls7167824eda.11.gmail; Tue, 27
 Aug 2019 02:33:13 -0700 (PDT)
X-Received: by 2002:a05:6402:1450:: with SMTP id d16mr23218430edx.198.1566898393478;
        Tue, 27 Aug 2019 02:33:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566898393; cv=none;
        d=google.com; s=arc-20160816;
        b=yNuvkOBHHMmgZ0VVBOumpnr8+FHjg5Os5s7aginqMka7LCq++Kx5eG/e5v0R+J66ur
         WqWuvWuo6nQ604WEzm4wAgmLbzvLimqYFCQu7pY88RkzbLu+K5ItBghC3vOFn6dFDxd5
         D9PshDmviTpuwD8mvN1tE9InBIN8Q/o6rmJQJX8ZOJ+lzsxPVy9/F4de0UmC7pMPhqUH
         MEMS18Zca2xfz7xze6nsJLNvzAR3fH2EkD7XlpZkV1PNu1gsRfglJwxxZcYbqDC/gSRC
         CvIpylwJUmsJ6V8j9WOaiqG8lCQ4TVsVhTiGp7VkDCjc4s7hDKScJ2BUP0XsVQNk7rBx
         FieA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=72Uo2bN4xNj6wMxzqbWtwOd6j3qjjG3q+meftdN5l0g=;
        b=a5EComlYvOXFFpbPqzFwlgXI6xaMowVtUi3EOQ3qfCeX9KLoOxxEK6Q4CJtU/UzeRt
         HkUadH2GKNK381eNl+bYo7nM9RVRF1CzXmDmvVqeQwxkU0ALgW+0gnDPjhnTIOEi3N9U
         IX7252mIA0oasgyNNoww+dwjkOWvFX6OdbgnBknut/khjkcaaQyKl18aE7fMb3AvHY4a
         R/xUxH9wZun0d79s7ggeG2OzAzZ+qNtsrpc17zIK0kIXpFfI2Zo01mBlo+ZSztIEqMF7
         DRgdxJ0lcQBNy/F4YliifBWw1o+szB+BIr+B+WBxHlKqxS1q8sbYWHBQppVqnz7noarc
         P46g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id d22si594501edq.5.2019.08.27.02.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Aug 2019 02:33:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i2Xqa-0000bE-FK; Tue, 27 Aug 2019 12:33:04 +0300
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
To: Nick Hu <nickhu@andestech.com>
Cc: =?UTF-8?B?QWxhbiBRdWV5LUxpYW5nIEthbyjpq5jprYHoia8p?=
 <alankao@andestech.com>, "paul.walmsley@sifive.com"
 <paul.walmsley@sifive.com>, "palmer@sifive.com" <palmer@sifive.com>,
 "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
 "green.hu@gmail.com" <green.hu@gmail.com>,
 "deanbo422@gmail.com" <deanbo422@gmail.com>,
 "tglx@linutronix.de" <tglx@linutronix.de>,
 "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "glider@google.com" <glider@google.com>,
 "dvyukov@google.com" <dvyukov@google.com>,
 "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 "alexios.zavras@intel.com" <alexios.zavras@intel.com>,
 "atish.patra@wdc.com" <atish.patra@wdc.com>,
 =?UTF-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
 <zong@andestech.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
 <09d5108e-f0ba-13d3-be9e-119f49f6bd85@virtuozzo.com>
 <20190827090738.GA22972@andestech.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <92dd5f5f-c8a2-53c3-4d61-44acc4366844@virtuozzo.com>
Date: Tue, 27 Aug 2019 12:33:11 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190827090738.GA22972@andestech.com>
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



On 8/27/19 12:07 PM, Nick Hu wrote:
> Hi Andrey
> 
> On Thu, Aug 22, 2019 at 11:59:02PM +0800, Andrey Ryabinin wrote:
>> On 8/7/19 10:19 AM, Nick Hu wrote:
>>> There are some features which need this string operation for compilation,
>>> like KASAN. So the purpose of this porting is for the features like KASAN
>>> which cannot be compiled without it.
>>>
>>
>> Compilation error can be fixed by diff bellow (I didn't test it).
>> If you don't need memmove very early (before kasan_early_init()) than arch-specific not-instrumented memmove()
>> isn't necessary to have.
>>
>> ---
>>  mm/kasan/common.c | 2 ++
>>  1 file changed, 2 insertions(+)
>>
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index 6814d6d6a023..897f9520bab3 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
>>  	return __memset(addr, c, len);
>>  }
>>  
>> +#ifdef __HAVE_ARCH_MEMMOVE
>>  #undef memmove
>>  void *memmove(void *dest, const void *src, size_t len)
>>  {
>> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
>>  
>>  	return __memmove(dest, src, len);
>>  }
>> +#endif
>>  
>>  #undef memcpy
>>  void *memcpy(void *dest, const void *src, size_t len)
>> -- 
>> 2.21.0
>>
>>
>>
> I have confirmed that the string operations are not used before kasan_early_init().
> But I can't make sure whether other ARCHs would need it before kasan_early_init().
> Do you have any idea to check that? Should I cc all other ARCH maintainers?
 

This doesn't affect other ARCHes in any way. If other arches have their own not-instrumented
memmove implementation (and they do), they will continue to be able to use it early.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/92dd5f5f-c8a2-53c3-4d61-44acc4366844%40virtuozzo.com.
