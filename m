Return-Path: <kasan-dev+bncBCS37NMQ3YHBBT676L5QKGQEJYK6XDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B9C2028513C
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 19:56:32 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 76sf2160570ljf.22
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Oct 2020 10:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602006992; cv=pass;
        d=google.com; s=arc-20160816;
        b=YCSpTShgehcZsgBK4hDKTBt38ztKgCiX/g+oaB2wmSJgI/YeGQrD5izJ8rSi/DllpX
         OVSCvM4p8qrINhMWrHJlfus4seOXpIAJSFIBEEA3UC7432vDRxTB6PCH7UfaMWk2xcKv
         R1Z7eYYoUsqBWcR+W8R+tt71k/rkjxLK8PGtPhx3fEwqyt9yjYu3d/JWIYDEvzc1N7Ys
         Q4aRHAG8jSsiuvHnQ6N/+GHZKlOtxoUnvKcC+F4PtwGtlogCioah/uSU+Ml5Vj5H/pPb
         Wm2pdR0n9b237ulhAUMTR8OEtoRf/7cYoE4zNrX+JUOFGYZsXuDgnGpxZn3bPsepHHDw
         eQ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=IvPiDLX4RSQggnNFA1yOUvY0XtGt3xFXuU7/oso0Muc=;
        b=gffVGksXqQetpTIQJkl+ogDwtsNKHC60LKY1oeQvY5vhMFR0uzz91a7KDlNW6Md3PL
         naR9C5rvxdjtrg373c/4q99uYjEUFDu+EJNIqNWcdIysV8g7BWA0KthyEkc6fmxGkMw+
         kfb0g360w4jU/1gpcR5IiIcUf7UWur+jm81idmt3wF7JXVjGY2Zw5ZCgyKLvfezkqIiH
         d1zTanJK/mCSHoOInFsZrmfcDvILph3lhrtYw7obXevOpf2zcXCDmr427+FBDWxucnIF
         SEnEaU9Ik9x5B9DIjw5GxBCQbp4wDbYTEtN1bnQl0bZpPZeg5o+HKeZ0IvzGhDNioj+F
         61RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IvPiDLX4RSQggnNFA1yOUvY0XtGt3xFXuU7/oso0Muc=;
        b=h1fngXAYwL1C3PpjfpOPYUG5KpKKMQ/Lj/I0Saihkl3qdNl+JPH9FOFUIQduwpz4CY
         TnuIJzD/rCrFeQWYTJrJWcaGoPXnCWlhUH1fggDhC+aOnnG1QBpb3ai+CjOBrKfghKXx
         2d5Irq1Vtu+pk3nnI5CJkTislaAQDVWdFsz4IBjrRWADTqDINFl5OeXzPKWaqgV4KgHp
         BNY5+N9xKTDym8BaOihr7tNg9zctta1WFZiKn8kBYWNR9lY7x0YPjnVbRHKWTeLTY1tn
         eVKXWXTOp1cB8DY3GqbHV2liizWP8S2fFYMEvMhTcCuqS8timkgyiBpN57+AByDw5A54
         VBBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IvPiDLX4RSQggnNFA1yOUvY0XtGt3xFXuU7/oso0Muc=;
        b=E/p849Mf75rKYHM8ntZTf2MCa6dg7a+3HJNumB2V00eDYnzSeFiQYCWG6Jnrx51ipl
         oSLz2V9l3DiGtdxrpElrfF8rSVZEXYSUnvu9wCdks4mNb34ZyoLwcB1gnZiPZ3nX4740
         FY1Bk8EB0lbFF1XvHpoA5r8IXySmU/Z1NIoVhAD93giLQsbtONDVMcLmwGgjhl/yPV0b
         hVbbc36ywoN5V+4v3PSzlj/Z/o/BYM6iPnJ8Y2erewqJ1Z/omdE1XzJ/mD1RcmQPWFT7
         OYqgtDWSSKofJwa7S3Cia5TgWVFHQil3TbBREPm81ZCVDUEDneaVO1XqvLDGUCIb1qPt
         AOTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Mc6Q7PEN3iuUDRLwffhMEw29l6Jx/oHC4ap31iORCHtVVHmwd
	aiq45fCYq5Dmp+mi+LXGuZQ=
X-Google-Smtp-Source: ABdhPJxVPeBPrVVKMqqqbJMhW8ZT2kMf61TF/IdYS+dZnkaC81UVbUtBo6RxWgr5QI/FXLpmXMMUPg==
X-Received: by 2002:a05:651c:1397:: with SMTP id k23mr2474776ljb.263.1602006992205;
        Tue, 06 Oct 2020 10:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls2654183lff.0.gmail; Tue, 06
 Oct 2020 10:56:31 -0700 (PDT)
X-Received: by 2002:a19:ae0e:: with SMTP id f14mr829990lfc.249.1602006991076;
        Tue, 06 Oct 2020 10:56:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602006991; cv=none;
        d=google.com; s=arc-20160816;
        b=JjkvNJhrls/1o3C4wfS6ZUTDVdTbDdu2EhGuVfArOS9Li3uXDjJGRH3r9dxWvK1WHS
         fFh07UGIpef+PaDzb/oCwwYaES1i0Y1xxoA0xteZsgWX5nVDHC6qP+959pVESD/Qx+9m
         3jigSLI9Ghk39LJkLQoPXslnMWaf6FXVgszK+sW5JsNbzeAviEZXazl0id19GLVXzJ7n
         3t820A+NgTCxqnXs8mVfeoAYH1fLY5kDsImpiIeviqObnVodr4pe/GpUKhBPhoX4k84v
         phpnNY+9V04v2RR+nmY+mNBFwvcS+txgDkS/UT0rnzijuQ/uUk4yZCZiQqK1uBgrTmhs
         gfGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=wVdi2/OxqFwgY+ziEPANSgeobWDkkZO7TjHJe/9DTlk=;
        b=042uM2L6paReiBwqMjQEmeLp6umlRjfSngadRtuDH43PJxWcv9l+h6MXrFTjfXOix8
         PjuguLQKMO6BTsIh2kzWiLka15ZtkViBRtNWo/g2TcYwsd70q761coMWwUwmEo/FkjFG
         o0HTd0eH1hDZRMMpoVc8uGS9bSmEAjrUJYlWIIscKeaH8yTlEH7+kSkEgGkeNQyq/NTq
         NWTdQjhLfdL4nCA5/UMfGzctdbd6A1rSP4oEORZk/cuxYt9rIEgmT1qOS333Qz25jK3e
         p9uQDjmcs4bKmjsC6xV4nC42HfOl49K9JEBl9G71anAmdYbbL2zM/HIgIh+kY/NRpzJp
         n1AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f67.google.com (mail-wm1-f67.google.com. [209.85.128.67])
        by gmr-mx.google.com with ESMTPS id x74si95665lff.12.2020.10.06.10.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Oct 2020 10:56:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) client-ip=209.85.128.67;
Received: by mail-wm1-f67.google.com with SMTP id k18so4009038wmj.5
        for <kasan-dev@googlegroups.com>; Tue, 06 Oct 2020 10:56:30 -0700 (PDT)
X-Received: by 2002:a1c:2042:: with SMTP id g63mr5956792wmg.174.1602006990380;
        Tue, 06 Oct 2020 10:56:30 -0700 (PDT)
Received: from [10.9.0.26] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id m13sm5703296wrr.74.2020.10.06.10.56.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Oct 2020 10:56:29 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
To: Jann Horn <jannh@google.com>, Kees Cook <keescook@chromium.org>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
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
 Valentin Schneider <valentin.schneider@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 Kernel Hardening <kernel-hardening@lists.openwall.com>,
 kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
References: <20200929183513.380760-1-alex.popov@linux.com>
 <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <1b5cf312-f7bb-87ce-6658-5ca741c2e790@linux.com>
Date: Tue, 6 Oct 2020 20:56:09 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as
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

On 06.10.2020 01:56, Jann Horn wrote:
> On Thu, Oct 1, 2020 at 9:43 PM Alexander Popov <alex.popov@linux.com> wrote:
>> On 29.09.2020 21:35, Alexander Popov wrote:
>>> This is the second version of the heap quarantine prototype for the Linux
>>> kernel. I performed a deeper evaluation of its security properties and
>>> developed new features like quarantine randomization and integration with
>>> init_on_free. That is fun! See below for more details.
>>>
>>>
>>> Rationale
>>> =========
>>>
>>> Use-after-free vulnerabilities in the Linux kernel are very popular for
>>> exploitation. There are many examples, some of them:
>>>  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html

Hello Jann, thanks for your reply.

> I don't think your proposed mitigation would work with much
> reliability against this bug; the attacker has full control over the
> timing of the original use and the following use, so an attacker
> should be able to trigger the kmem_cache_free(), then spam enough new
> VMAs and delete them to flush out the quarantine, and then do heap
> spraying as normal, or something like that.

The randomized quarantine will release the vulnerable object at an unpredictable
moment (patch 4/6).

So I think the control over the time of the use-after-free access doesn't help
attackers, if they don't have an "infinite spray" -- unlimited ability to store
controlled data in the kernelspace objects of the needed size without freeing them.

"Unlimited", because the quarantine size is 1/32 of whole memory.
"Without freeing", because freed objects are erased by init_on_free before going
to randomized heap quarantine (patch 3/6).

Would you agree?

> Also, note that here, if the reallocation fails, the kernel still
> wouldn't crash because the dangling object is not accessed further if
> the address range stored in it doesn't match the fault address. So an
> attacker could potentially try multiple times, and if the object
> happens to be on the quarantine the first time, that wouldn't really
> be a showstopper, you'd just try again.

Freed objects are filled by zero before going to quarantine (patch 3/6).
Would it cause a null pointer dereference on unsuccessful try?

>>>  https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1
> 
> I think that here, again, the free() and the dangling pointer use were
> caused by separate syscalls, meaning the attacker had control over
> that timing?

As I wrote above, I think attacker's control over this timing is required for a
successful attack, but is not enough for bypassing randomized quarantine.

>>>  https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
> 
> Haven't looked at that one in detail.
> 
>>> Use-after-free exploits usually employ heap spraying technique.
>>> Generally it aims to put controlled bytes at a predetermined memory
>>> location on the heap.
> 
> Well, not necessarily "predetermined". Depending on the circumstances,
> you don't necessarily need to know which address you're writing to;
> and you might not even need to overwrite a specific object, but
> instead just have to overwrite one out of a bunch of objects, no
> matter which.

Yes, of course, I didn't mean a "predetermined memory address".
Maybe "definite memory location" is a better phrase for that.

>>> Heap spraying for exploiting use-after-free in the Linux kernel relies on
>>> the fact that on kmalloc(), the slab allocator returns the address of
>>> the memory that was recently freed.
> 
> Yeah; and that behavior is pretty critical for performance. The longer
> it's been since a newly allocated object was freed, the higher the
> chance that you'll end up having to go further down the memory cache
> hierarchy.

Yes. That behaviour is fast, however very convenient for use-after-free
exploitation...

>>> So allocating a kernel object with
>>> the same size and controlled contents allows overwriting the vulnerable
>>> freed object.
> 
> The vmacache exploit you linked to doesn't do that, it frees the
> object all the way back to the page allocator and then sprays 4MiB of
> memory from the page allocator. (Because VMAs use their own
> kmem_cache, and the kmem_cache wasn't merged with any interesting
> ones, and I saw no good way to exploit the bug by reallocating another
> VMA over the old VMA back then. Although of course that doesn't mean
> that there is no such way.)

Sorry, my mistake.
Exploit examples with heap spraying that fit my description:
 - CVE-2017-6074 https://www.openwall.com/lists/oss-security/2017/02/26/2
 - CVE-2017-2636 https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html
 - CVE-2016-8655 https://seclists.org/oss-sec/2016/q4/607
 - CVE-2017-15649
https://ssd-disclosure.com/ssd-advisory-linux-kernel-af_packet-use-after-free/

> [...]
>>> Security properties
>>> ===================
>>>
>>> For researching security properties of the heap quarantine I developed 2 lkdtm
>>> tests (see the patch 5/6).
>>>
>>> The first test is called lkdtm_HEAP_SPRAY. It allocates and frees an object
>>> from a separate kmem_cache and then allocates 400000 similar objects.
>>> I.e. this test performs an original heap spraying technique for use-after-free
>>> exploitation.
>>>
>>> If CONFIG_SLAB_QUARANTINE is disabled, the freed object is instantly
>>> reallocated and overwritten:
>>>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>>>    lkdtm: Performing direct entry HEAP_SPRAY
>>>    lkdtm: Allocated and freed spray_cache object 000000002b5b3ad4 of size 333
>>>    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
>>>    lkdtm: FAIL: attempt 0: freed object is reallocated
>>>
>>> If CONFIG_SLAB_QUARANTINE is enabled, 400000 new allocations don't overwrite
>>> the freed object:
>>>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>>>    lkdtm: Performing direct entry HEAP_SPRAY
>>>    lkdtm: Allocated and freed spray_cache object 000000009909e777 of size 333
>>>    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
>>>    lkdtm: OK: original heap spraying hasn't succeed
>>>
>>> That happens because pushing an object through the quarantine requires _both_
>>> allocating and freeing memory. Objects are released from the quarantine on
>>> new memory allocations, but only when the quarantine size is over the limit.
>>> And the quarantine size grows on new memory freeing.
>>>
>>> That's why I created the second test called lkdtm_PUSH_THROUGH_QUARANTINE.
>>> It allocates and frees an object from a separate kmem_cache and then performs
>>> kmem_cache_alloc()+kmem_cache_free() for that cache 400000 times.
>>> This test effectively pushes the object through the heap quarantine and
>>> reallocates it after it returns back to the allocator freelist:
> [...]
>>> As you can see, the number of the allocations that are needed for overwriting
>>> the vulnerable object is almost the same. That would be good for stable
>>> use-after-free exploitation and should not be allowed.
>>> That's why I developed the quarantine randomization (see the patch 4/6).
>>>
>>> This randomization required very small hackish changes of the heap quarantine
>>> mechanism. At first all quarantine batches are filled by objects. Then during
>>> the quarantine reducing I randomly choose and free 1/2 of objects from a
>>> randomly chosen batch. Now the randomized quarantine releases the freed object
>>> at an unpredictable moment:
>>>    lkdtm: Target object is reallocated at attempt 107884
> [...]
>>>    lkdtm: Target object is reallocated at attempt 87343
> 
> Those numbers are fairly big. At that point you might not even fit
> into L3 cache anymore, right? You'd often be hitting DRAM for new
> allocations? And for many slabs, you might end using much more memory
> for the quarantine than for actual in-use allocations.

Yes. The original quarantine size is
  (totalram_pages() << PAGE_SHIFT) / QUARANTINE_FRACTION
where
  #define QUARANTINE_FRACTION 32

> It seems to me like, for this to stop attacks with a high probability,
> you'd have to reserve a huge chunk of kernel memory for the
> quarantines 

Yes, that's how it works now.

> - even if the attacker doesn't know anything about the
> status of the quarantine (which isn't necessarily the case, depending
> on whether the attacker can abuse microarchitectural data leakage, or
> if the attacker can trigger a pure data read through the dangling
> pointer), they should still be able to win with a probability around
> quarantine_size/allocated_memory_size if they have a heap spraying
> primitive without strict limits.

Not sure about this probability evaluation.
I will try calculating it taking the quarantine parameters into account.

>>> However, this randomization alone would not disturb the attacker, because
>>> the quarantine stores the attacker's data (the payload) in the sprayed objects.
>>> I.e. the reallocated and overwritten vulnerable object contains the payload
>>> until the next reallocation (very bad).
>>>
>>> Hence heap objects should be erased before going to the heap quarantine.
>>> Moreover, filling them by zeros gives a chance to detect use-after-free
>>> accesses to non-zero data while an object stays in the quarantine (nice!).
>>> That functionality already exists in the kernel, it's called init_on_free.
>>> I integrated it with CONFIG_SLAB_QUARANTINE in the patch 3/6.
>>>
>>> During that work I found a bug: in CONFIG_SLAB init_on_free happens too
>>> late, and heap objects go to the KASAN quarantine being dirty. See the fix
>>> in the patch 2/6.
> [...]
>> I've made various tests on real hardware and in virtual machines:
>>  1) network throughput test using iperf
>>      server: iperf -s -f K
>>      client: iperf -c 127.0.0.1 -t 60 -f K
>>  2) scheduler stress test
>>      hackbench -s 4000 -l 500 -g 15 -f 25 -P
>>  3) building the defconfig kernel
>>      time make -j2
>>
>> I compared Linux kernel 5.9.0-rc6 with:
>>  - init_on_free=off,
>>  - init_on_free=on,
>>  - CONFIG_SLAB_QUARANTINE=y (which enables init_on_free).
>>
>> Each test was performed 5 times. I will show the mean values.
>> If you are interested, I can share all the results and calculate standard deviation.
>>
>> Real hardware, Intel Core i7-6500U CPU
>>  1) Network throughput test with iperf
>>      init_on_free=off: 5467152.2 KBytes/sec
>>      init_on_free=on: 3937545 KBytes/sec (-28.0% vs init_on_free=off)
>>      CONFIG_SLAB_QUARANTINE: 3858848.6 KBytes/sec (-2.0% vs init_on_free=on)
>>  2) Scheduler stress test with hackbench
>>      init_on_free=off: 8.5364s
>>      init_on_free=on: 8.9858s (+5.3% vs init_on_free=off)
>>      CONFIG_SLAB_QUARANTINE: 17.2232s (+91.7% vs init_on_free=on)
> 
> These numbers seem really high for a mitigation, especially if that
> performance hit does not really buy you deterministic protection
> against many bugs.

Right, I agree.

It's a probabilistic protection, and the probability should be calculated.
I'll work on that.

> [...]
>> N.B. There was NO performance optimization made for this version of the heap
>> quarantine prototype. The main effort was put into researching its security
>> properties (hope for your feedback). Performance optimization will be done in
>> further steps, if we see that my work is worth doing.
> 
> But you are pretty much inherently limited in terms of performance by
> the effect the quarantine has on the data cache, right?

Yes.
However, the quarantine parameters can be adjusted.

> It seems to me like, if you want to make UAF exploitation harder at
> the heap allocator layer, you could do somewhat more effective things
> with a probably much smaller performance budget. Things like
> preventing the reallocation of virtual kernel addresses with different
> types, such that an attacker can only replace a UAF object with
> another object of the same type. (That is not an idea I like very much
> either, but I would like it more than this proposal.) (E.g. some
> browsers implement things along those lines, I believe.)

That's interesting, thank you.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1b5cf312-f7bb-87ce-6658-5ca741c2e790%40linux.com.
