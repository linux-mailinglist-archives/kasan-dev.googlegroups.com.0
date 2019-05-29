Return-Path: <kasan-dev+bncBC5L5P75YUERBNGXXHTQKGQEYF6OWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7024B2DBB4
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 13:23:32 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id c26sf2952181eda.15
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 04:23:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559129012; cv=pass;
        d=google.com; s=arc-20160816;
        b=rT7Ss/nH1RnuaqVEi6LLKPoStI0OkoJxry0fTEaL2F4qrtvsDNRm0kp19aorCN2AHS
         CR6jp+jDtNfaJO3zsSiYLY2i1bsnsvtYqXjGvzT04E/0MAT6Kfmtu/xVOcYiM8sbFM3l
         ITqcMz+xxMvLby/13pFBBO1l5f40/K/cIEA0OqIV4UNhFAQcjEaaabVozZcVaJVzMxAT
         RbPy3n4DycNeOGY0Ql8lUfA6xyYmYR5IW6tLaFqsqJTJa5cjYCsLAYbogRuvWCBMdhZ8
         9BRgqdPxUFFBqit1Hrf27HXJ88Ldevbbrwr+SmPzKrFquA4RbTZ646AOMQC5Fy2AoDto
         YQqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QLYXyucn0rrlPyaH4OctkPK3FtgKHMCcNXeByXIA/xA=;
        b=kSUydRhGVxCMpRW3E7cH0chai4mrr8/HH36YknAgbYbijntUmLR4dqf3IkxG+keySz
         Ahc26zsz2OjLOHlMoxyaDE55YF/lcGZmOzdeQKw6Zkjr1hkaGGNjScEdKoFBNhS9Kojk
         RYtns3Y5zMDkwMO8OBHkjIBEbxF89bj+y/zYRcyfHZVrVdX6wei9eo2kHiRRFgY8zpPO
         ltFIGXLLH44yyfdEhrG5P1641ft+Y49G7TWB/SD5wx1UFaFJYNXp5SWiBu17WZvpyOXt
         /6Uv4zsehN72qZPOY7mHxhIl98twLq60KDada82TFIXOTMbmDJbn+2OlBfAvsnh0IWwb
         vNWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QLYXyucn0rrlPyaH4OctkPK3FtgKHMCcNXeByXIA/xA=;
        b=dE8Ul1yASgEwUkS8Y/Fg2NEc+GmCL6I3wiTJ+BlHH4UnJ4ELmOUnCCA+KzTWdSbVrt
         0sjp6QakLTOnSS+CDjs0t3IRI12kOYCw6sVjHZCkkM6x2L8vG4sgpLC9rVVaDviPW3AM
         2QOUyYYgM7PhGL0BaOHEALxmeetdgmU8RArKSPqVOFXgSx/C2UxcOMuXBpoKAdSF2SYj
         4JvR6c7rYst2eJpj/W0xVJ9uHgzmtea+q6INIT31CPFIe+TXxN3fyZ2O2NAYcN2Fg/tb
         VBl7bibnMp9ZF1P69efWloM+mlAPZAYApokD9/0RfJ1KrrXRMeTK7t6+VLQx0BDZ8iXw
         QHXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QLYXyucn0rrlPyaH4OctkPK3FtgKHMCcNXeByXIA/xA=;
        b=rjQdIJ05kK/JOqafh1Y9tVEHdYzNpvme1quL/J9YeYp7VADUzyn/D23sEAC0EMOG0D
         T2hjCMy5DhhbMBeSBg5t2bmERK7HxQLKsRngARxkETGilRt8XWMjX242FOGdF95thLq8
         GuRnMQi/eloChGCwQFA9nFpKwlLtEQOsW0/6lmJjQ89XRpKQ5nHo5x00BXO1OtbtiDhY
         u3thWH0QnFQGII4TkbOLACgC33rICAg02sIkjcgpiL+UQ9LmeQ0Kjgg5HnrBenJIJvpx
         k006xeMl0qBXQ5lsIzm/cHJ2tXHjyNwIvS9vJr3JNdI86deHOBnE7hxmxDxBJuJUToYF
         8phQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX6abnz8wr9959UQ8EKOgfDIO58S8en6XJQ4PSe7rTyXRXOmPtl
	OUXpAuajC9L+wKaJwGhlngU=
X-Google-Smtp-Source: APXvYqxMzG9pbrzzLSon1/Su4m/4sYfER1IIii43q4GPAA+V+bwg/ZUyp/sM7hdoxcj9Hty4ShkMxA==
X-Received: by 2002:a17:907:2131:: with SMTP id qo17mr59320417ejb.220.1559129012217;
        Wed, 29 May 2019 04:23:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:916e:: with SMTP id f43ls597875eda.15.gmail; Wed, 29 May
 2019 04:23:31 -0700 (PDT)
X-Received: by 2002:a05:6402:1214:: with SMTP id c20mr134272164edw.38.1559129011844;
        Wed, 29 May 2019 04:23:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559129011; cv=none;
        d=google.com; s=arc-20160816;
        b=v8o/g71NzMCzpvz/0g1/Amm0VEoXZt1SklyQCCELRZc0eulr0eESTC6KriCrkGkrQ1
         41Bl3Me7Q/q37OcdYtM0Losei4/ecjXmkZ9gVci/lmaDrfMI+6myCPmht7Xho3HG3LU5
         fQQ7a8pU1uRmMXzFV7P8hJ8RDwC9viRtdwLCRLsEeqnCdYMvtJDKbZJDPRfSlKPoTQrF
         9jtBunPrDaFbS2s2v4OxKLzYFrm/ulm1MUDABUbBQgoYO5luYWLWvQHgdr5omdL++brS
         ZNWuDPJkf/Ya5UPzRtnXB5sSnqdGGa5O899hLkEO7Fb26clWn6Cxb7fsqGKADxKwVB7N
         7SWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=b1J91yX2zVhTc1ircllj3SxGuZ/ZgBBMC46Z1z2bUog=;
        b=M3O1zz261Xds6aVIoeG+W+CnpGAGZXPXGzFNc3Xka3zsv0zoR9jUtwFmcJeeR+rW9T
         wGa8j4ZaURUDscU+R6Xq/333psYAQTk5phN2MUW1oOCVZYUawNqgBmsptUTuxlcdR+IJ
         BszxavYI4VGpp9PGWimd9nUT7f2roa0obZUeXJNQo6P4vJGhpkbWez6Dx5PVnIqFnflA
         iXA3d+806vG5+2Hv4KKUAiglRVcgfGjPfptYnvWsV0zTS0Q7Lk3vIIjHc+MUQ8Kaz8nQ
         xsjzzPgEQGsQZcj2fjYhbNhJ6E0K3etjSorOiFIEp9u8M4VovL/7CRCbd6g5r+AXUTy/
         gq5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id t36si808133edb.0.2019.05.29.04.23.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 04:23:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.91)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hVwg1-00037i-FP; Wed, 29 May 2019 14:23:25 +0300
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
To: Dmitry Vyukov <dvyukov@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
 the arch/x86 maintainers <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Josh Poimboeuf <jpoimboe@redhat.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-arch
 <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
 <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <377465ba-3b31-31e7-0f9d-e0a5ab911ca4@virtuozzo.com>
Date: Wed, 29 May 2019 14:23:40 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
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



On 5/29/19 1:57 PM, Dmitry Vyukov wrote:
> On Wed, May 29, 2019 at 12:30 PM Peter Zijlstra <peterz@infradead.org> wrote:
>>
>> On Wed, May 29, 2019 at 12:16:31PM +0200, Marco Elver wrote:
>>> On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
>>>>
>>>> On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
>>>>> For the default, we decided to err on the conservative side for now,
>>>>> since it seems that e.g. x86 operates only on the byte the bit is on.
>>>>
>>>> This is not correct, see for instance set_bit():
>>>>
>>>> static __always_inline void
>>>> set_bit(long nr, volatile unsigned long *addr)
>>>> {
>>>>         if (IS_IMMEDIATE(nr)) {
>>>>                 asm volatile(LOCK_PREFIX "orb %1,%0"
>>>>                         : CONST_MASK_ADDR(nr, addr)
>>>>                         : "iq" ((u8)CONST_MASK(nr))
>>>>                         : "memory");
>>>>         } else {
>>>>                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
>>>>                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
>>>>         }
>>>> }
>>>>
>>>> That results in:
>>>>
>>>>         LOCK BTSQ nr, (addr)
>>>>
>>>> when @nr is not an immediate.
>>>
>>> Thanks for the clarification. Given that arm64 already instruments
>>> bitops access to whole words, and x86 may also do so for some bitops,
>>> it seems fine to instrument word-sized accesses by default. Is that
>>> reasonable?
>>
>> Eminently -- the API is defined such; for bonus points KASAN should also
>> do alignment checks on atomic ops. Future hardware will #AC on unaligned
>> [*] LOCK prefix instructions.
>>
>> (*) not entirely accurate, it will only trap when crossing a line.
>>     https://lkml.kernel.org/r/1556134382-58814-1-git-send-email-fenghua.yu@intel.com
> 
> Interesting. Does an address passed to bitops also should be aligned,
> or alignment is supposed to be handled by bitops themselves?
> 

It should be aligned. This even documented in Documentation/core-api/atomic_ops.rst:

	Native atomic bit operations are defined to operate on objects aligned
	to the size of an "unsigned long" C data type, and are least of that
	size.  The endianness of the bits within each "unsigned long" are the
	native endianness of the cpu.


> This probably should be done as a separate config as not related to
> KASAN per se. But obviously via the same
> {atomicops,bitops}-instrumented.h hooks which will make it
> significantly easier.
> 

Agreed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/377465ba-3b31-31e7-0f9d-e0a5ab911ca4%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
