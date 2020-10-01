Return-Path: <kasan-dev+bncBCS37NMQ3YHBBRXC3D5QKGQEBAQGEIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 400D52807EB
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 21:43:03 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id l1sf2651868edv.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 12:43:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601581383; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGdUnPaY+b/h8t8/7SGI85GiKhbk1wSTo5Nrv6yGfKO7zwmvR9VcD+5veU5nwWUyTz
         b/elqvR2S1dPmlpzijqkbk+Ap0bhKwPJeIAVuU78xU5aeAO6HbtIytKv+pG1jzA2Ko+c
         JP+kunPrux7FrRV9ftieM9MI9/rFuZS4qg5jOCSNth8iV9T2TAvw1+8EhjwO2KZhjjoM
         vFsL9cnH5W0f3ES1aZjbQJ03ebWO3JWluEMcyApKGBQ9knOkR72OcSRs/ZrGcsprAsMv
         2QSrV886IF+ZeYWPBXu83iDKwy4yxSPO4bkoWZ4Y94XXgwXpbAM+8VjJLthErNXnBUkW
         tyuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=zQPfwuj0CgTE5B634ffv39hpQKcG0DP/a93sMuxV4Ug=;
        b=zvj147TLKwpyf8AUCdpdT8to3JrgJ42mOe2DeNlNuCIy4Z4Zx848E4Rja/ctrk5G6r
         VTIqH0RuLyKXjO+CUMr+EwJOXT4XofMcx4hmjH+R7mw+6qHMeu4SuMtPO5YDIFRw0jNa
         z0MbxVoKpwV8cski9nTJkSVo+RkOQNwbOF8o9dKz4SX8IvYh7SE0As9KpxGApDZ56KDG
         yg16cTN6Aab94TndQkuiij/Nx4BeQfFRBXus8H/84IrHYcKJ0xc4cpTV/bDpWMLzuc7S
         mHkzYPG23YHbU3WY2oTIsXBmSZQ3KbGiYlhBd7Aau3iDDAxFUJnQApvt6nkfbvwJbCDB
         6x8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQPfwuj0CgTE5B634ffv39hpQKcG0DP/a93sMuxV4Ug=;
        b=k4UrZzD5AfIZagks7eFueeFDdHZHvU5W/tNTrCqXDMX6XHYBXYYE3QjhxtUtHWhKC1
         sBaL16peqDCtoiwCV7yiJRfn03xdtVDockkFRNxKYgUpV6Pyqwe1tLFic7w88uGzTUJ0
         irGvibZ29YOfhC8YliZ1u62Nz3Rm/zmCj/c1ErYgPjPBbxh+bwAyl0hGkgUSdwjBZWY/
         HPomL0zR9tz9lyQiAuV/LEbhDbZZWz9xTH7LP/CMPBJK6socAvo74fyaEu3398HXCZki
         5WlidZsGqoD9kIe7kRJ6c0DUub4yT2xTRPvFuiB0cPjnvxQLY9J5VKLuzUKzEwHJX+Kh
         BvyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQPfwuj0CgTE5B634ffv39hpQKcG0DP/a93sMuxV4Ug=;
        b=hLDY19WsJhrQdb6wPhthlmzaR0Un3kJxl7SQrSDx6dYV1VfIaNfLNJifjNUwfcWYGl
         9sQDbd0S5yiuHqnKKcUGfJI7Ap7UkgzqBoVbvP7YPe4mWazrN7U3dO1w6WJxYjFlZgW6
         DbekBWp7sbbkw8Cee3X9P/rcHAiRmHwpMvySmucM0ed222eRswOjHwPcaLPJ9oLs8xG3
         vS/ZE69ZPK7lI2j1zwXN75Cvg5XYRI+wsHzs1Ra7UJZRIKTEYA4s5/4k+wsaJD3iJChp
         HSUvFl6SHAqkr45UDbEHtBoQncuRcCTI5ZzQqQR/kfqMDcrwcx/8AN0FcmRw5saAQuLu
         R2kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532s0sX8b7MsuVA/t/XnYPam9rXQhWa4mo9iQEFrDrk+7O/PSUwc
	a2lmMoO+Icciv/DcbOYQRnw=
X-Google-Smtp-Source: ABdhPJwF/tR+Nwb4mYJHZP8QSNAqnPW06kFX9HpXPps/aRxVq3EkieosgwPmTSnIqZy1STQHNvA7DA==
X-Received: by 2002:a17:906:cb98:: with SMTP id mf24mr10271657ejb.90.1601581382926;
        Thu, 01 Oct 2020 12:43:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bf49:: with SMTP id g9ls2554922edk.1.gmail; Thu, 01 Oct
 2020 12:43:02 -0700 (PDT)
X-Received: by 2002:a05:6402:503:: with SMTP id m3mr10012468edv.45.1601581382002;
        Thu, 01 Oct 2020 12:43:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601581381; cv=none;
        d=google.com; s=arc-20160816;
        b=eCUQhyHSnL/zV/sVfUXiqLbLBABoSZoBeEF/i3XTOPkXC2e4or6JQUYHqPATW+ApuG
         sbGJEPbJLxw7WBj0HjOKNvY1rSCJKWNTjfph1wG19MYvXAaa7Sb0fQ4ZNlP1Hn1kEoGP
         AT0Fvz/gyXK8T5+9SGcaJ5qyUjnh24V7wBVSwm1MWpJyasmhtEyPHuzhx5sXpUh1qw7w
         Sn/6vFMqc3V27Uronp0V2WDGHGsRJagqauXWOj1MjLWS/vcl0wUt4pUyRMSucLD5DfbX
         qF6Je6LyE2csv1QFNNxTNZmRCXPbXlX1HW+s12YEPkRL/oUS39OcDKpkG078BxH4t5/a
         wkzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=G0aEub7gOD3fpd+1L2aWOLaEytl2vzggmvmyvv/QLiI=;
        b=N+669tH6Yk8iKSPiUWuPQvuJ0o4gAwnKohnYomJC0ngzYJn9q5Axw1DXPHXW1HYrhZ
         Bi8ZjksoRSfbiY1oPhSHum8gBaMpyIhRljiAYncv14Dbo3QsEfMknt3lO3KMbSl2eCcw
         U3TcdUTZ+cNEUn/sX86Py1YZpqH1wuyAZy9GESe0nQxt8n/QeCy6LerldnAkhQdXwEEK
         UyPJPkJupGkRCgKZjcr45QmByzG9G/h3Km/xNJ7EUREB1HTAExwhpD5/C+MRHsG630A3
         OIYnUWBJrPpTWtf5x1Lk+PWPtzW0wS1md2X9Q16FWR3RMK6qSS5qDLd2boqp73LWwGum
         h1cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f65.google.com (mail-wr1-f65.google.com. [209.85.221.65])
        by gmr-mx.google.com with ESMTPS id u13si121107edb.0.2020.10.01.12.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 12:43:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) client-ip=209.85.221.65;
Received: by mail-wr1-f65.google.com with SMTP id o5so2712wrn.13
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 12:43:01 -0700 (PDT)
X-Received: by 2002:a05:6000:1084:: with SMTP id y4mr10303304wrw.138.1601581381449;
        Thu, 01 Oct 2020 12:43:01 -0700 (PDT)
Received: from [10.9.0.22] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id f14sm11378629wrt.53.2020.10.01.12.42.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 12:43:00 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
To: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
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
 Valentin Schneider <valentin.schneider@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org
Cc: notify@kernel.org, Alexander Popov <alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
Date: Thu, 1 Oct 2020 22:42:54 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as
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

Hello! I have some performance numbers. Please see below.

On 29.09.2020 21:35, Alexander Popov wrote:
> Hello everyone! Requesting for your comments.
> 
> This is the second version of the heap quarantine prototype for the Linux
> kernel. I performed a deeper evaluation of its security properties and
> developed new features like quarantine randomization and integration with
> init_on_free. That is fun! See below for more details.
> 
> 
> Rationale
> =========
> 
> Use-after-free vulnerabilities in the Linux kernel are very popular for
> exploitation. There are many examples, some of them:
>  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
>  https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1
>  https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
> 
> Use-after-free exploits usually employ heap spraying technique.
> Generally it aims to put controlled bytes at a predetermined memory
> location on the heap.
> 
> Heap spraying for exploiting use-after-free in the Linux kernel relies on
> the fact that on kmalloc(), the slab allocator returns the address of
> the memory that was recently freed. So allocating a kernel object with
> the same size and controlled contents allows overwriting the vulnerable
> freed object.
> 
> I've found an easy way to break the heap spraying for use-after-free
> exploitation. I extracted slab freelist quarantine from KASAN functionality
> and called it CONFIG_SLAB_QUARANTINE. Please see patch 1/6.
> 
> If this feature is enabled, freed allocations are stored in the quarantine
> queue where they wait for actual freeing. So they can't be instantly
> reallocated and overwritten by use-after-free exploits.
> 
> N.B. Heap spraying for out-of-bounds exploitation is another technique,
> heap quarantine doesn't break it.
> 
> 
> Security properties
> ===================
> 
> For researching security properties of the heap quarantine I developed 2 lkdtm
> tests (see the patch 5/6).
> 
> The first test is called lkdtm_HEAP_SPRAY. It allocates and frees an object
> from a separate kmem_cache and then allocates 400000 similar objects.
> I.e. this test performs an original heap spraying technique for use-after-free
> exploitation.
> 
> If CONFIG_SLAB_QUARANTINE is disabled, the freed object is instantly
> reallocated and overwritten:
>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>    lkdtm: Performing direct entry HEAP_SPRAY
>    lkdtm: Allocated and freed spray_cache object 000000002b5b3ad4 of size 333
>    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
>    lkdtm: FAIL: attempt 0: freed object is reallocated
> 
> If CONFIG_SLAB_QUARANTINE is enabled, 400000 new allocations don't overwrite
> the freed object:
>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>    lkdtm: Performing direct entry HEAP_SPRAY
>    lkdtm: Allocated and freed spray_cache object 000000009909e777 of size 333
>    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
>    lkdtm: OK: original heap spraying hasn't succeed
> 
> That happens because pushing an object through the quarantine requires _both_
> allocating and freeing memory. Objects are released from the quarantine on
> new memory allocations, but only when the quarantine size is over the limit.
> And the quarantine size grows on new memory freeing.
> 
> That's why I created the second test called lkdtm_PUSH_THROUGH_QUARANTINE.
> It allocates and frees an object from a separate kmem_cache and then performs
> kmem_cache_alloc()+kmem_cache_free() for that cache 400000 times.
> This test effectively pushes the object through the heap quarantine and
> reallocates it after it returns back to the allocator freelist:
>   # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
>    lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
>    lkdtm: Allocated and freed spray_cache object 000000008fdb15c3 of size 333
>    lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
>    lkdtm: Target object is reallocated at attempt 182994
>   # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
>    lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
>    lkdtm: Allocated and freed spray_cache object 000000004e223cbe of size 333
>    lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
>    lkdtm: Target object is reallocated at attempt 186830
>   # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
>    lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
>    lkdtm: Allocated and freed spray_cache object 000000007663a058 of size 333
>    lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
>    lkdtm: Target object is reallocated at attempt 182010
> 
> As you can see, the number of the allocations that are needed for overwriting
> the vulnerable object is almost the same. That would be good for stable
> use-after-free exploitation and should not be allowed.
> That's why I developed the quarantine randomization (see the patch 4/6).
> 
> This randomization required very small hackish changes of the heap quarantine
> mechanism. At first all quarantine batches are filled by objects. Then during
> the quarantine reducing I randomly choose and free 1/2 of objects from a
> randomly chosen batch. Now the randomized quarantine releases the freed object
> at an unpredictable moment:
>    lkdtm: Target object is reallocated at attempt 107884
>    lkdtm: Target object is reallocated at attempt 265641
>    lkdtm: Target object is reallocated at attempt 100030
>    lkdtm: Target object is NOT reallocated in 400000 attempts
>    lkdtm: Target object is reallocated at attempt 204731
>    lkdtm: Target object is reallocated at attempt 359333
>    lkdtm: Target object is reallocated at attempt 289349
>    lkdtm: Target object is reallocated at attempt 119893
>    lkdtm: Target object is reallocated at attempt 225202
>    lkdtm: Target object is reallocated at attempt 87343
> 
> However, this randomization alone would not disturb the attacker, because
> the quarantine stores the attacker's data (the payload) in the sprayed objects.
> I.e. the reallocated and overwritten vulnerable object contains the payload
> until the next reallocation (very bad).
> 
> Hence heap objects should be erased before going to the heap quarantine.
> Moreover, filling them by zeros gives a chance to detect use-after-free
> accesses to non-zero data while an object stays in the quarantine (nice!).
> That functionality already exists in the kernel, it's called init_on_free.
> I integrated it with CONFIG_SLAB_QUARANTINE in the patch 3/6.
> 
> During that work I found a bug: in CONFIG_SLAB init_on_free happens too
> late, and heap objects go to the KASAN quarantine being dirty. See the fix
> in the patch 2/6.
> 
> For deeper understanding of the heap quarantine inner workings, I attach
> the patch 6/6, which contains verbose debugging (not for merge).
> It's very helpful, see the output example:
>    quarantine: PUT 508992 to tail batch 123, whole sz 65118872, batch sz 508854
>    quarantine: whole sz exceed max by 494552, REDUCE head batch 0 by 415392, leave 396304
>    quarantine: data level in batches:
>      0 - 77%
>      1 - 108%
>      2 - 83%
>      3 - 21%
>    ...
>      125 - 75%
>      126 - 12%
>      127 - 108%
>    quarantine: whole sz exceed max by 79160, REDUCE head batch 12 by 14160, leave 17608
>    quarantine: whole sz exceed max by 65000, REDUCE head batch 75 by 218328, leave 195232
>    quarantine: PUT 508992 to tail batch 124, whole sz 64979984, batch sz 508854
>    ...
> 
> 
> Changes in v2
> =============
> 
>  - Added heap quarantine randomization (the patch 4/6).
> 
>  - Integrated CONFIG_SLAB_QUARANTINE with init_on_free (the patch 3/6).
> 
>  - Fixed late init_on_free in CONFIG_SLAB (the patch 2/6).
> 
>  - Added lkdtm_PUSH_THROUGH_QUARANTINE test.
> 
>  - Added the quarantine verbose debugging (the patch 6/6, not for merge).
> 
>  - Improved the descriptions according to the feedback from Kees Cook
>    and Matthew Wilcox.
> 
>  - Made fixes recommended by Kees Cook:
> 
>    * Avoided BUG_ON() in kasan_cache_create() by handling the error and
>      reporting with WARN_ON().
> 
>    * Created a separate kmem_cache for new lkdtm tests.
> 
>    * Fixed kasan_track.pid type to pid_t.
> 
> 
> TODO for the next prototypes
> ============================
> 
> 1. Performance evaluation and optimization.
>    I would really appreciate your ideas about performance testing of a
>    kernel with the heap quarantine. The first prototype was tested with
>    hackbench and kernel build timing (which showed very different numbers).
>    Earlier the developers similarly tested init_on_free functionality.
>    However, Brad Spengler says in his twitter that such testing method
>    is poor.

I've made various tests on real hardware and in virtual machines:
 1) network throughput test using iperf
     server: iperf -s -f K
     client: iperf -c 127.0.0.1 -t 60 -f K
 2) scheduler stress test
     hackbench -s 4000 -l 500 -g 15 -f 25 -P
 3) building the defconfig kernel
     time make -j2

I compared Linux kernel 5.9.0-rc6 with:
 - init_on_free=off,
 - init_on_free=on,
 - CONFIG_SLAB_QUARANTINE=y (which enables init_on_free).

Each test was performed 5 times. I will show the mean values.
If you are interested, I can share all the results and calculate standard deviation.

Real hardware, Intel Core i7-6500U CPU
 1) Network throughput test with iperf
     init_on_free=off: 5467152.2 KBytes/sec
     init_on_free=on: 3937545 KBytes/sec (-28.0% vs init_on_free=off)
     CONFIG_SLAB_QUARANTINE: 3858848.6 KBytes/sec (-2.0% vs init_on_free=on)
 2) Scheduler stress test with hackbench
     init_on_free=off: 8.5364s
     init_on_free=on: 8.9858s (+5.3% vs init_on_free=off)
     CONFIG_SLAB_QUARANTINE: 17.2232s (+91.7% vs init_on_free=on)
 3) Building the defconfig kernel:
     init_on_free=off: 10m54.475s
     init_on_free=on: 11m5.745s (+1.7% vs init_on_free=off)
     CONFIG_SLAB_QUARANTINE: 11m13.291s (+1.1% vs init_on_free=on)

Virtual machine, QEMU/KVM
 1) Network throughput test with iperf
     init_on_free=off: 3554237.4 KBytes/sec
     init_on_free=on: 2828887.4 KBytes/sec (-20.4% vs init_on_free=off)
     CONFIG_SLAB_QUARANTINE: 2587308.2 KBytes/sec (-8.5% vs init_on_free=on)
 2) Scheduler stress test with hackbench
     init_on_free=off: 19.3602s
     init_on_free=on: 20.8854s (+7.9% vs init_on_free=off)
     CONFIG_SLAB_QUARANTINE: 30.0746s (+44.0% vs init_on_free=on)

We can see that the results of these tests are quite diverse.
Your interpretation of the results and ideas of other tests are welcome.

N.B. There was NO performance optimization made for this version of the heap
quarantine prototype. The main effort was put into researching its security
properties (hope for your feedback). Performance optimization will be done in
further steps, if we see that my work is worth doing.

> 2. Complete separation of CONFIG_SLAB_QUARANTINE from KASAN (feedback
>    from Andrey Konovalov).
> 
> 3. Adding a kernel boot parameter for enabling/disabling the heap quaranitne
>    (feedback from Kees Cook).
> 
> 4. Testing the heap quarantine in near-OOM situations (feedback from
>    Pavel Machek).
> 
> 5. Does this work somehow help or disturb the integration of the
>    Memory Tagging for the Linux kernel?
> 
> 6. After rebasing the series onto v5.9.0-rc6, CONFIG_SLAB kernel started to
>    show warnings about few slab caches that have no space for additional
>    metadata. It needs more investigation. I believe it affects KASAN bug
>    detection abilities as well. Warning example:
>      WARNING: CPU: 0 PID: 0 at mm/kasan/slab_quarantine.c:38 kasan_cache_create+0x37/0x50
>      Modules linked in:
>      CPU: 0 PID: 0 Comm: swapper Not tainted 5.9.0-rc6+ #1
>      Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-2.fc32 04/01/2014
>      RIP: 0010:kasan_cache_create+0x37/0x50
>      ...
>      Call Trace:
>       __kmem_cache_create+0x74/0x250
>       create_boot_cache+0x6d/0x91
>       create_kmalloc_cache+0x57/0x93
>       new_kmalloc_cache+0x39/0x47
>       create_kmalloc_caches+0x33/0xd9
>       start_kernel+0x25b/0x532
>       secondary_startup_64+0xb6/0xc0
> 
> Thanks in advance for your feedback.
> Best regards,
> Alexander
> 
> 
> Alexander Popov (6):
>   mm: Extract SLAB_QUARANTINE from KASAN
>   mm/slab: Perform init_on_free earlier
>   mm: Integrate SLAB_QUARANTINE with init_on_free
>   mm: Implement slab quarantine randomization
>   lkdtm: Add heap quarantine tests
>   mm: Add heap quarantine verbose debugging (not for merge)
> 
>  drivers/misc/lkdtm/core.c  |   2 +
>  drivers/misc/lkdtm/heap.c  | 110 +++++++++++++++++++++++++++++++++++++
>  drivers/misc/lkdtm/lkdtm.h |   2 +
>  include/linux/kasan.h      | 107 ++++++++++++++++++++----------------
>  include/linux/slab_def.h   |   2 +-
>  include/linux/slub_def.h   |   2 +-
>  init/Kconfig               |  14 +++++
>  mm/Makefile                |   3 +-
>  mm/kasan/Makefile          |   2 +
>  mm/kasan/kasan.h           |  75 +++++++++++++------------
>  mm/kasan/quarantine.c      | 102 ++++++++++++++++++++++++++++++----
>  mm/kasan/slab_quarantine.c | 106 +++++++++++++++++++++++++++++++++++
>  mm/page_alloc.c            |  22 ++++++++
>  mm/slab.c                  |   5 +-
>  mm/slub.c                  |   2 +-
>  15 files changed, 455 insertions(+), 101 deletions(-)
>  create mode 100644 mm/kasan/slab_quarantine.c
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91d564a6-9000-b4c5-15fd-8774b06f5ab0%40linux.com.
