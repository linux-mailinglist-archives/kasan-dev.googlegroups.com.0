Return-Path: <kasan-dev+bncBCS37NMQ3YHBB6XE3D5QKGQEVPQDX6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DB80280803
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 21:48:11 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id f22sf1449ljh.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 12:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601581690; cv=pass;
        d=google.com; s=arc-20160816;
        b=u/jZxhC2VQY6F6tg3H8CDcl5UdE8dfrNCXXoBLABXvYZC6eFZvJUUcgrewC/aZztzH
         ngNtMlFhHr2bhNAxew/AFyxKLN+W1HYuzPGKCQLwWR2dmEFrlSy1xSyAVoITn3ICk0yO
         t60mkSJx3WQ9vtC5Ey+CwrHFhv4bBHcJ39hfOxSSh7L75TT0hHcX2tRkSc8rvwhwaZ/O
         G7+31i95G2sCRZrQ2++MbkuUQEykXNlc5IRE42FBC4u3C7cuUlnBgJW05cNG7CjTk2cv
         2Qy303iu61OU7NEqdh+w+UGKY8GOU3V4sFF3Kxx8CXaP66CjB24DzdBzAYbLgcTLoLVX
         9n9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=CU7q52qPPwG/Xzx4pTUqPMOPEPlgPxBMovb8n/6vDOo=;
        b=eGQEXNRqsdIEWl5WPB6G0lhERDKtj78e/2fdtMTXrMY60gFJvzAh41foXUXweGJoSZ
         DUgVqUA6EcJGAKBxMBYf8Da0vXSX9JaVqMjFcsFlt5pRrf3z+Pu9XQkVxYAqX7uCJtdV
         OhxGNck+oQ8bB2JaYva4Ub3SXKw3vXfwA7V1e1GEGxYeZD+xRimJutJ/ytTQtpA1/dV2
         z7AwTk2WYEJWB+iySmMP5HeQwTNX99mKRFVb3XtTg/KAkmcoapJI5/ETML/5yEOtLyV/
         Q4n8D6DCSIKDhxq71aeHaUleUP8G3mc7+fvMbvNSOKzVkdaicF+mbtsGcZEixUsijHv6
         +aCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CU7q52qPPwG/Xzx4pTUqPMOPEPlgPxBMovb8n/6vDOo=;
        b=BNfC3XWrf9yUrPOQnmysTdWJXyzWi4NvjdLQcx1QubJNSXUm9+/gGFmBiKm0nawxL0
         GS+tDhP20ULw+gExvb4c6W7mcjaBBusLVK5knYiIbpvNRgYa7QGAT5BB/qDW4B2msVhs
         l+xvK8I0oq7ioaKs3jpfvmReykpoXkWutDHE/xzWcepjtRFc0T/DxJBi3x35NbTdZLH4
         V/WY70QQySRIQVUbSdznOwLfMiMuQOsA5jUsPwWiJ70ByWU1NPK7rOn27YDCzPd6M/mF
         PMFEpGPbBg33VlQVAr8ex4KNsYgHxHWNi9mgrUpt5pIzzjJnSHGWopVYGnJae3U4qUM0
         49Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CU7q52qPPwG/Xzx4pTUqPMOPEPlgPxBMovb8n/6vDOo=;
        b=Nw1h6ZEzxoG48o/YiBHFv88tvPlYtQV6KCAlXYzoomEDIDu0b5IBjeqa4B5fYsSFKS
         RlKoFTAxZ5D+ORFdLK19RIo5KX3+pHuO8UgEh0HfXYwXI6nQ4qHPUIefo+GdSSwQYurU
         e/Q46vB4aJdjXCoY4EMqqv8wzbR3qeJLdaOx6CFjYfjop08ueawFOxfzoBAapve/MYRq
         omhU1gIqtLuHsUp3dVRPjGSMprRIL7kgqi+nrA4IYGoUBw39T4InSgm2S7L67FveC1n7
         x9EZkIKKREycip8oQA6fOGSPZj1zP8LzSfETfPa2KgSBWpttlVF+KZdn3tIXW87PoPYt
         nr0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306e+rCkzxjErBpH5zvoYsDzbK4181sgOu2cs++B/ek3X8wWsCM
	ON8Im+OP+GhU2Kac2flscoA=
X-Google-Smtp-Source: ABdhPJxG5j95b24JOhzCdCtpVxSUVp51dsvFAkRDtzP7RGAW31kWFiusOVLAi+xj9Gl7CR8tKw6Fhg==
X-Received: by 2002:a19:610a:: with SMTP id v10mr3471546lfb.414.1601581690652;
        Thu, 01 Oct 2020 12:48:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:555:: with SMTP id q21ls1018196ljp.3.gmail; Thu, 01
 Oct 2020 12:48:09 -0700 (PDT)
X-Received: by 2002:a05:651c:104:: with SMTP id a4mr3056498ljb.273.1601581689498;
        Thu, 01 Oct 2020 12:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601581689; cv=none;
        d=google.com; s=arc-20160816;
        b=bblREuaUe/0ti/yNNC5BTz1nZnyi31lg3PiyDwZbIP5EkDVeNbaR+RP0l3Oh1y/7dU
         N56VgWWxUUpBiH+5UpyQ7u9sAWYha/U98a9RiRONkvdxaGdDC/ekz0lPRNvHr9GmmOqe
         KfeprKW5TG74NY/MgxvgsQQL6l8LhHu4jvNhsqr532rcJHbtVcWmuycoENc+KHnUkH/w
         6xGvQADrPQ2LdjAwIPnhO5rdRX+O+Yg5nA3ODVsMVHITMlTl8VS8O6Ooa16KQHn5joYs
         ZvQYvE4A6RnnxpLNF62bqbw4yM7u70wZQ76em1QVZtIOh3JAkgj4ypCnDkmFt8b2qoXS
         +Zcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=MyMIarbO3O8wfhAK1LaZuGf5QXnGx7zNw8blfiATqfQ=;
        b=hTgI/r4phsWu7+CAfMiTeHIEOmLf+fU5LB6zT93y1k9yVHIPhbjNRd9gulyvISEm7S
         no+F0UcT3Q/ELU3ol7zHAL2b3RKmXwACsZte5lpsg1akKDUMfG96M5Ryd8LGQ09R004u
         0L7bkygEqla7Qc75DjttzTf04LfS+c3ciVKdpGYLwID34gKdKQlkxsOeJkoO9FN9yoG1
         pe03f0ehekNxzwTHB+bmrElhfOBulFaoY9rhYuX2MqGBrd4WozY8WTav/RggSsnzbsQ5
         KSQvqKtTrl2nM4oUgUHUqx2k/LsydRd8kpKqCXh1nktB+OiKwkYWjt/WA180hHzvtwRh
         B6nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f66.google.com (mail-wm1-f66.google.com. [209.85.128.66])
        by gmr-mx.google.com with ESMTPS id b5si174585lfa.0.2020.10.01.12.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 12:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) client-ip=209.85.128.66;
Received: by mail-wm1-f66.google.com with SMTP id t17so4390442wmi.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 12:48:09 -0700 (PDT)
X-Received: by 2002:a1c:5988:: with SMTP id n130mr1677086wmb.95.1601581689018;
        Thu, 01 Oct 2020 12:48:09 -0700 (PDT)
Received: from [10.9.0.22] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id j10sm10435948wrn.2.2020.10.01.12.48.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 12:48:07 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
To: Alexander Potapenko <glider@google.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Daniel Micay <danielmicay@gmail.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Matthew Wilcox <willy@infradead.org>, Pavel Machek <pavel@denx.de>,
 Valentin Schneider <valentin.schneider@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Kernel Hardening <kernel-hardening@lists.openwall.com>,
 LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
References: <20200929183513.380760-1-alex.popov@linux.com>
 <20200929183513.380760-3-alex.popov@linux.com>
 <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <e4b78739-1cec-b9a2-7371-7407cfbb4904@linux.com>
Date: Thu, 1 Oct 2020 22:48:03 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

On 30.09.2020 15:50, Alexander Potapenko wrote:
> On Tue, Sep 29, 2020 at 8:35 PM Alexander Popov <alex.popov@linux.com> wrote:
>>
>> Currently in CONFIG_SLAB init_on_free happens too late, and heap
>> objects go to the heap quarantine being dirty. Lets move memory
>> clearing before calling kasan_slab_free() to fix that.
>>
>> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks for the review, Alexander!

Do you have any idea how this patch series relates to Memory Tagging support
that is currently developed?

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e4b78739-1cec-b9a2-7371-7407cfbb4904%40linux.com.
