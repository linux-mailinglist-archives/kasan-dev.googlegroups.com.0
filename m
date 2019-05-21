Return-Path: <kasan-dev+bncBC5L5P75YUERBYP4SDTQKGQE3XEQWNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9515725743
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 20:07:29 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id c26sf31803239eda.15
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 11:07:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558462049; cv=pass;
        d=google.com; s=arc-20160816;
        b=wug8Oiog3nsw4k1qtAsi4CBkP4PvOmYTS1esUb+0fffuvw2ZBJ7yGDDCBYbvDlwnqx
         1mNDyT17QuDzcZ4SLhcRvY81DYPad6CccpU46iLNKc4PNcPLAHfwqymTNahSSpfwwVmZ
         kd/9BlkLNrM5UopQ9Wh+JRQC5qFFCHLaF85RPsayOuu4QkRMP13DMxEE4P3D3FFaBhYq
         f59oM2IAW/wGr4cl/77IxOogQFKZJKVacARfwJh4ekQ1OdTweAgcorFdK5NrbCJb/bxZ
         QCxKG75miMswnPm6Utov6khTFWK/ri3YzOe7UESHzCvLT0E5hhhsyxHlG346IYlFB6BW
         JR7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RAem77WzxMVbR5bUfiuialbnlQJLscccjZKk24sXXN0=;
        b=X8mqSlB2izO31+XrRB/2aNIKu/gAQb/gWEFsPqs4OQSBfXm8xJaimauXXGGdmYsCgP
         X4h9o4Vlmm7+AQVhC+Gyg+y3u1PADCEEQcBWkkwZtJYRvrJj8vg/all+Apb/KDkwP7EF
         HFVlk4b4i+dWxn7mF7TVuuHg6Fh3SOG15k2ZdW2DdqLj0K98BMh/G79NfMFNoK5/btv9
         s9b/23h4G+jKrKGj1GF72ydfZhumFem2foW0rE/MReANImIyNUaDpjxIgeMjeJt6lIJ3
         1LzKwCIHz6/GZXNc6rf/TbU8NFXaOmkH6xTW+g/FNo7I1nYqyZCmggWVejsU99KTFzvp
         NsKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RAem77WzxMVbR5bUfiuialbnlQJLscccjZKk24sXXN0=;
        b=GFjU70mmqoiKrzqVAAgq3zQcv1V1S4wkQpTh1tCWQYmSDVnCB2VKLdGFY9Db8opE1W
         aeoR2mGCaw/eqj0t+w8ICBhK8Rd46LJ8OaM05jqTrwrKATHP9X1sXYVIWI5KOYA0ZD74
         1JP/+6QWMg2H9EYaWg3ADcI08Tv1ZWH5pupWFv98eOJvaR0pUaGH6WQiNK1ph5NdaIOJ
         IyPy1SZKZwE/x0X/8NO6DWV3tpohnyQmqeXeF1XUJAGcACW+YPTTYyCD93LjPOceZBNn
         XOQ008jT9d4dSRGsfA7zArkxSNTiVBjNpqkkBi5yajrDmBzmFJlvt/CYnxq5ok82SAxv
         Z3yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RAem77WzxMVbR5bUfiuialbnlQJLscccjZKk24sXXN0=;
        b=ZiOgkOUc2LYfg30fsVbKM365oS3ZsKQawYCpijA9jA3e8samrbQQ9lF3VqTqAg5tEr
         x/Xjyq2QwYCeckNtL2BmMZ7zm8+ePrQ2ETXHe1hd6Qt2xqevqUYb7SYMsixixcHLYKy2
         b6ywj1fIY2aDjgmyTQLIWCBhjYWt4gGD+dqgPEckAY+FMZaDlB5U1R0h6nTzkEgsV0LI
         CKfuXavyovjhde+LACFUTcmLev7JS3jtj8nTKOb4fXsl9c4LCwcYXFdwEXwLEzTGX13A
         w6CDvWDI3eGLdbcaUCDvrCLdp3XBEmt6X8z9S0K9ppLh1cXg59wFlbtcjHT4MttZgnlE
         BucA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW/3FHExRBaTIINk+Esy/G8ONvB3jsYITsVQWKL8dTjdNkpcsrt
	XvPHzkB21KYBTG96Eyc1mTM=
X-Google-Smtp-Source: APXvYqyJ1qWqCfhu3f6QwzESmz6xNc9HEF6P4F4c4eh4P+4/LhJ2J4NHGe9L+3/pgL1Sb7svgwILoQ==
X-Received: by 2002:a17:906:a354:: with SMTP id bz20mr40353553ejb.209.1558462049365;
        Tue, 21 May 2019 11:07:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:b806:: with SMTP id j6ls6287387ede.3.gmail; Tue, 21 May
 2019 11:07:28 -0700 (PDT)
X-Received: by 2002:a50:8ba3:: with SMTP id m32mr3948435edm.58.1558462048955;
        Tue, 21 May 2019 11:07:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558462048; cv=none;
        d=google.com; s=arc-20160816;
        b=o4MJzJAG4gnVZ5HBSbQuwemQtasnLHCC4mcdtJp5N9gWllIFVbcFdUuXTeKqdGZ8K0
         hQvnkikTSdfQP8qnDuKCOIKaC27EV6fdagi/QfZdYE/P7U6ms+FYUYlnDxZfNM60QzYJ
         ETiXs5g+lyWJQB2AaXj06HsXXC1Vy2nIxyRTNv/IwIxqDxVFv7rNIX+dsV9uBTP+wC/t
         fqUNgKqRpEYRwib3YF9zQI+WOMU/UD6PXRyyBiuVoZLMBK9PwcqnVqSfQBd//fADqCmd
         oixaCmi6HZqvpPiCuhTphDzPEN8vi+i2WBzM+4FTLNm5+1/WiSY/Qn/u3OysMz3/wwDN
         72Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VW5Gqms6RUuTMruuwhVT0/XMTieYuN/y7XeRBAJOnCU=;
        b=sDoGmdl56qaRplID1uEZTkngCa/w+topyYVE6LszKLj8NbUKuAMCn2so1x/Qz9zmxH
         QNk3kxeOHslhrIbEA4wp2bWBPGBuHSH22+XkYnHhZLbNselksT1m+FSXNuCwkCCHdo5w
         gk7wJTZCpf4kQPDljMfFXZV7K2XfGr/aj88a4REfrLJ53CIqfTyPr4iz9O+lKwevkC10
         YU6uDbLUyVZIllVCi5Onj+4E1pmQaHQko/qSILQTB5m7qpDIfm282OzzuAGXmjuYT0Ju
         P5NBNKiEprA70xLuDOdZfH/kNmHaqMcqd6tybGKbj7YDVx8ZAtG3/CnZlTOK/gyzgHnj
         5nwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id w5si2469367edw.1.2019.05.21.11.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 May 2019 11:07:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.91)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hT9Ad-00083b-Gp; Tue, 21 May 2019 21:07:27 +0300
Subject: Re: [PATCH v2] mm/kasan: Print frame description for stack bugs
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Dmitriy Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20190520154751.84763-1-elver@google.com>
 <ebec4325-f91b-b392-55ed-95dbd36bbb8e@virtuozzo.com>
 <CAG_fn=W+_Ft=g06wtOBgKnpD4UswE_XMXd61jw5ekOH_zeUVOQ@mail.gmail.com>
 <CANpmjNN177XBadNfoSmizQF7uZV61PNPQSftT7hPdc3HmdzSjA@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <292035fd-64b7-1767-3e8a-3a6cb50298b5@virtuozzo.com>
Date: Tue, 21 May 2019 21:07:45 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNN177XBadNfoSmizQF7uZV61PNPQSftT7hPdc3HmdzSjA@mail.gmail.com>
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



On 5/21/19 7:07 PM, Marco Elver wrote:
> On Tue, 21 May 2019 at 17:53, Alexander Potapenko <glider@google.com> wrote:
>>
>> On Tue, May 21, 2019 at 5:43 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>>>
>>> On 5/20/19 6:47 PM, Marco Elver wrote:
>>>
>>>> +static void print_decoded_frame_descr(const char *frame_descr)
>>>> +{
>>>> +     /*
>>>> +      * We need to parse the following string:
>>>> +      *    "n alloc_1 alloc_2 ... alloc_n"
>>>> +      * where alloc_i looks like
>>>> +      *    "offset size len name"
>>>> +      * or "offset size len name:line".
>>>> +      */
>>>> +
>>>> +     char token[64];
>>>> +     unsigned long num_objects;
>>>> +
>>>> +     if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
>>>> +                               &num_objects))
>>>> +             return;
>>>> +
>>>> +     pr_err("\n");
>>>> +     pr_err("this frame has %lu %s:\n", num_objects,
>>>> +            num_objects == 1 ? "object" : "objects");
>>>> +
>>>> +     while (num_objects--) {
>>>> +             unsigned long offset;
>>>> +             unsigned long size;
>>>> +
>>>> +             /* access offset */
>>>> +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
>>>> +                                       &offset))
>>>> +                     return;
>>>> +             /* access size */
>>>> +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
>>>> +                                       &size))
>>>> +                     return;
>>>> +             /* name length (unused) */
>>>> +             if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
>>>> +                     return;
>>>> +             /* object name */
>>>> +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
>>>> +                                       NULL))
>>>> +                     return;
>>>> +
>>>> +             /* Strip line number, if it exists. */
>>>
>>>    Why?
> 
> The filename is not included, and I don't think it adds much in terms
> of ability to debug; nor is the line number included with all
> descriptions. I think, the added complexity of separating the line
> number and parsing is not worthwhile here. Alternatively, I could not
> pay attention to the line number at all, and leave it as is -- in that
> case, some variable names will display as "foo:123".
> 

Either way is fine by me. But explain why in comment if you decide
to keep current code.  Something like
	 /* Strip line number cause it's not very helpful. */


>>>
>>>> +             strreplace(token, ':', '\0');
>>>> +
>>>
>>> ...
>>>
>>>> +
>>>> +     aligned_addr = round_down((unsigned long)addr, sizeof(long));
>>>> +     mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
>>>> +     shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
>>>> +     shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
>>>> +
>>>> +     while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
>>>> +             shadow_ptr--;
>>>> +             mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
>>>> +     }
>>>> +
>>>> +     while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
>>>> +             shadow_ptr--;
>>>> +             mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
>>>> +     }
>>>> +
>>>
>>> I suppose this won't work if stack grows up, which is fine because it grows up only on parisc arch.
>>> But "BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROUWSUP))" somewhere wouldn't hurt.
>> Note that KASAN was broken on parisc from day 1 because of other
>> assumptions on the stack growth direction hardcoded into KASAN
>> (e.g. __kasan_unpoison_stack() and __asan_allocas_unpoison()).

It's not broken, it doesn't exist.

>> So maybe this BUILD_BUG_ON can be added in a separate patch as it's
>> not specific to what Marco is doing here?
> 

I think it's fine to add it in this patch because BUILD_BUG_ON() is just a hint for developers
that this particular function depends on growing down stack. So it's more a property of the function
rather than KASAN in general.

Other functions you mentioned can be marked with BUILD_BUG_ON()s as well, but not in this patch indeed.

> Happy to send a follow-up patch, or add here. Let me know what you prefer.
> 

Send v3 please.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/292035fd-64b7-1767-3e8a-3a6cb50298b5%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
