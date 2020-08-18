Return-Path: <kasan-dev+bncBCS37NMQ3YHBBF766D4QKGQE7ZQ5ELQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 079FA248FB3
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 22:50:32 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id i15sf70087wmb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 13:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597783831; cv=pass;
        d=google.com; s=arc-20160816;
        b=k6L8RDPOZ2pL5lY0PwEKF6mEwhc06LDQl4/WgE3KJTQl26Eg7PexbFbccUP+NU8WBt
         dlSJkrykWdAepQNFO3RF1PrwpE2g49oWUaknU+UX67ej86eN5k83MmPbJeOVML0MqViv
         f9SbPEzBBAvYjWEvPkSdQKkSE1NVURKrsQ52HG0eV7TRliUFDizhh/foBeyYrd9ctdTc
         kcE0wJvHZHA0sJsvy+Tv6QrSdZjRKSWwBqp293WrKAQDqXC4tnzY3SI8o1EVtC+fhba6
         GO2tdTaHbUA7wj7HOU+dtupFIbzCJyprkvLgZ5mb2IuOGrJfajoCHbNk3zYVMYZeYDXh
         o7/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=oflvLHh4a6NINJXA/m16MvuRz4kvTaSdOjTbYmd5yfA=;
        b=bu1pVFOr5OLbCmY3I+Fcg62qUgGH4jqqmp74dQF+BKRMYi7bx9l+ahA8InsBlnuJU0
         1lo5NW5/nxuA3ejUDmsgaP5dRQrrFZmhyO9YuFU97ubnimbjMfy/QI03NqDPmYnpgfhq
         A5HDJMrt/awDJG0xMTYvlAdv8fy8cmZUZ8k93RvF2jBNOJjh5olthLzk1/uwb2XbvR+x
         fQV1xRBhJDHojDHG+4Vpb5s+Wl/eGo0GYp9UtBA4q/x1VSdUNlbdWJoNJPulQZ68DZq3
         w/XiVquyknfQ4Y4WFygpU62nYZQ2Y0jdpeoJIPl2Wpi+mI3dEtcIUxrlNENk0dIpuyCE
         CEgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oflvLHh4a6NINJXA/m16MvuRz4kvTaSdOjTbYmd5yfA=;
        b=K/WOE89AeLz9LdocX2Z9uenPpWv0gjLhG228OfrwforVDO5b7jvzeDftBof1A43uab
         nJYz3rSvEQyA+KJnYCfKgbO4C/3WBCZSNVMPt5aulkKCX2hXPELxixBm5Sk5kxaTzH1F
         bkIrwqceIjcUAKDZR90gYwm0VJP5QO5pYF+uE7W92LJyqTtCFMZs4lGPgJToNdXivVnX
         rZ99JhllGq/Z8AsGsT00xJ/QqFkcwS46z/x3M63BDndio8mdeYL40ErQy9nvt3LqTmN7
         kv6AY5abb2xRC/uNhelf5eQRnEyymiaMzJ1LyycjNqsHBqBYOhkaurunfWFlaXoPNf+t
         jBhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oflvLHh4a6NINJXA/m16MvuRz4kvTaSdOjTbYmd5yfA=;
        b=jWKZOt7Ar/P5j+On2lUn7S4cVw77GlwbUoDMYzAgol/cO19nZQpcCOnYXdqFSD8k1x
         2FSDNYC/+RhC66vOpnooLw4UMXV/5rJu3lJyb8ZZFBM3V6Lie/EMuowhyArW7DLaR6x8
         Nb1dKiE/goTyv7dW6yZ7z7v+W2aj5fRipd10Pg/yt2nwzzzd3lQcw+/i5QOfmPTX5lws
         gDL4jC5H1uz3XrTiAbsbA8lSVIc42kqgSheDv9iHwhYw/kkgLG6UJCNyiwZ3mYA4yXwA
         x0zobfeBnEC420m43RHTii+cff0uboqHle34/X43gva3gTat51wc9CMw5sH2Wdpopv62
         VBnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53058U5wMw2CrCOA716UelZHMWhuqIVmV2nBS2iltc6DjO5hG3xX
	E1MVdsywgYqrHQ9kimSRfcI=
X-Google-Smtp-Source: ABdhPJzkmYaA96tdS8/mJohnM+7CIQP7cKMu0APcQV6yeQEzGOlKmzfG+DNGLD7kRM/qfljzWnwFlQ==
X-Received: by 2002:a1c:2350:: with SMTP id j77mr1668572wmj.31.1597783831771;
        Tue, 18 Aug 2020 13:50:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e78f:: with SMTP id n15ls350789wrm.1.gmail; Tue, 18 Aug
 2020 13:50:31 -0700 (PDT)
X-Received: by 2002:adf:a4d7:: with SMTP id h23mr1004952wrb.276.1597783831116;
        Tue, 18 Aug 2020 13:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597783831; cv=none;
        d=google.com; s=arc-20160816;
        b=ncYPFvXJXPNcMDkKBRG4d1VD+zI+N49SnEZMqgbc3UByfBeZ+lziHQwX/Ka8SS9RZp
         iD7xVEvt3Ljz86ya9kA131wo3CBAW9lmstJHLXw6+kCvmyTzCQFBb1EgE4ZfukzJrdoZ
         zPv9HjzHzaGS2uB2/RT4k7ekmokjaKgBS0JSW/tLB+AGyAIeVDeyhNb+sd+8BDTDdMWy
         bHsFhyxgPmipunXrh0V5rtrz+Jga4clD9OKuMN9EEDLqUDqn0LqMhfobmIM4G970EYOt
         8ET9cd+TCuB1a5zTvB0qp6XlfGfk2reHqrOJ7YH6VRT17CJYZf5VHKV9JrtHZGxk4H1c
         iThw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=5uvLQdwA9XnjdyJ8uI+0lrr22ouPyu6AUfsbqa6bRP0=;
        b=alg34dDrxWayGL22iGVY2EeNEuOpuztM4Kav5jEDGpIs0nBmW69fwYuuMEXKga5QZ6
         S9/a3yetjS4KZVutfBoT1XRvqqbe2iTc0qEWMggwPUfcfx9qroLNF1DP0obmeUE6RGva
         dPE8mVgJ5xoJ9yyG6zINwLFDGi20NRX2EQHDJkXUAoOXcNzAusMQbKuXNLl6gzCUynSJ
         X3ctEged77VO5Dv08AvbgOftK3ioCtRAulomS7/HmCbUcPk+330D5PjKm1AiU60Mr/on
         vK9WCVoVXA50zPFhBh7rJh0czgetZiroVCrXPwF9H72wZvBd2vbsppcXFpVWf0UbH61K
         AEUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-ed1-f66.google.com (mail-ed1-f66.google.com. [209.85.208.66])
        by gmr-mx.google.com with ESMTPS id o134si37812wme.0.2020.08.18.13.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 13:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.66 as permitted sender) client-ip=209.85.208.66;
Received: by mail-ed1-f66.google.com with SMTP id ba10so16355169edb.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Aug 2020 13:50:31 -0700 (PDT)
X-Received: by 2002:a05:6402:174d:: with SMTP id v13mr20748953edx.231.1597783830798;
        Tue, 18 Aug 2020 13:50:30 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id s16sm17277427ejr.31.2020.08.18.13.50.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 13:50:29 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev <kasan-dev@googlegroups.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Christoph Lameter <cl@linux.com>,
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
 Linux Memory Management List <linux-mm@kvack.org>,
 kernel-hardening@lists.openwall.com, LKML <linux-kernel@vger.kernel.org>,
 notify@kernel.org
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
 <202008150939.A994680@keescook>
 <82edcbac-a856-cf9e-b86d-69a4315ea8e4@linux.com>
 <CAAeHK+z9FPc9dqHwLA7sXTdpjt-iQweaQGQjq8L=eTYe2WdJ+g@mail.gmail.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <b15d41a5-034c-6fb5-dedf-5fd75d609ccf@linux.com>
Date: Tue, 18 Aug 2020 23:50:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+z9FPc9dqHwLA7sXTdpjt-iQweaQGQjq8L=eTYe2WdJ+g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.66 as
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

On 18.08.2020 18:45, Andrey Konovalov wrote:
> On Mon, Aug 17, 2020 at 7:32 PM Alexander Popov <alex.popov@linux.com> wrote:
>>
>> On 15.08.2020 19:52, Kees Cook wrote:
>>> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
>>>> Heap spraying is an exploitation technique that aims to put controlled
>>>> bytes at a predetermined memory location on the heap. Heap spraying for
>>>> exploiting use-after-free in the Linux kernel relies on the fact that on
>>>> kmalloc(), the slab allocator returns the address of the memory that was
>>>> recently freed. Allocating a kernel object with the same size and
>>>> controlled contents allows overwriting the vulnerable freed object.
>>>>
>>>> Let's extract slab freelist quarantine from KASAN functionality and
>>>> call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
>>>> spraying technique used for exploiting use-after-free vulnerabilities
>>>> in the kernel code.
>>>>
>>>> If this feature is enabled, freed allocations are stored in the quarantine
>>>> and can't be instantly reallocated and overwritten by the exploit
>>>> performing heap spraying.
>>>
>>> It may be worth clarifying that this is specifically only direct UAF and
>>> doesn't help with spray-and-overflow-into-a-neighboring-object attacks
>>> (i.e. both tend to use sprays, but the former doesn't depend on a write
>>> overflow).
>>
>> Andrey Konovalov wrote:
>>> If quarantine is to be used without the rest of KASAN, I'd prefer for
>>> it to be separated from KASAN completely: move to e.g. mm/quarantine.c
>>> and don't mention KASAN in function/config names.
>>
>> Hmm, making quarantine completely separate from KASAN would bring troubles.
>>
>> Currently, in many special places the allocator calls KASAN handlers:
>>   kasan_cache_create()
>>   kasan_slab_free()
>>   kasan_kmalloc_large()
>>   kasan_krealloc()
>>   kasan_slab_alloc()
>>   kasan_kmalloc()
>>   kasan_cache_shrink()
>>   kasan_cache_shutdown()
>>   and some others.
>> These functions do a lot of interesting things and also work with the quarantine
>> using these helpers:
>>   quarantine_put()
>>   quarantine_reduce()
>>   quarantine_remove_cache()
>>
>> Making quarantine completely separate from KASAN would require to move some
>> internal logic of these KASAN handlers to allocator code.
> 
> It doesn't look like there's quite a lot of KASAN-specific logic there.
> 
> All those quarantine_*() calls are either at the beginning or at the
> end of some kasan annotations, so it should be quite easy to move
> those out. E.g. quarantine_reduce() can be moved together with the
> gfpflags_allow_blocking(flags) check and put before kasan_kmalloc()
> calls (or maybe also into some other places?), quarantine_put() can be
> put after kasan_slab_free(), etc.
> 
>> In this patch I used another approach, that doesn't require changing the API
>> between allocators and KASAN. I added linux/mm/kasan/slab_quarantine.c with slim
>> KASAN handlers that implement the minimal functionality needed for quarantine.
>>
>> Do you think that it's a bad solution?
> 
> This solution doesn't look clean. Here you provide a second KASAN
> runtime implementation, parallel to the original one, which only does
> quarantine. It seems much cleaner to put quarantine logic into a
> separate module, which can be either used independently, or together
> with KASAN built on top of it.

That sounds reasonable, I agree. Thanks, Andrey.
Added to TODO list.

At first I'm going to focus on exploring security properties of the quarantine.
And then I'll do the refactoring that you and Kees propose.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b15d41a5-034c-6fb5-dedf-5fd75d609ccf%40linux.com.
