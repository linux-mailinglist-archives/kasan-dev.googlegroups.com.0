Return-Path: <kasan-dev+bncBCS37NMQ3YHBBJX65L4QKGQEIHAWNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A1D85246E79
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 19:32:22 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id x12sf6742254eds.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 10:32:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597685542; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wwiam6BiXTZGr2lU7eapJ2+OCDaonEr8E4lNULDvFN8PNhOdhoXhUt98wdT6tzv9ft
         EzeQXgYMM050DHySqG98cTAPoAM3+bikapiyQCydp9Afk8fcI212LK/nZtfE1+FB1skS
         r4aeKAQe3Ivr0tYuAebpyqM9TLJ6EanBBS64g9IE4ZhhC8FDDC12jJi3XVemKyiIQJIm
         lqFzy2YRegtXGmLFwLciE37d77WEUfVXBQW8nFY2c7b5BjGukmzdVPI8T3EHE4OZnJa6
         lQtgOaKqLKuoycp4Tv830N2BiKy44OdgfFC9+7B4EykyTZIrPisvEy6foC0BTp3ZyiFN
         TdKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=PTojZnC4dtEvFGob959ict34uWwLYHIuoL7zKSX3dDk=;
        b=w19yHiQYIOD9iIC9ysx8ZFR7aBrtfG+GOAQAfJrp5PIQDUK9rXpRE/PkaiZAik9Mk2
         OmlRoy/muHmpYgHo9aEe9USDE4VjozhY/5ckts/hL9Np5Mhem2L0MBKhg6UjvDVNg3xF
         88Y6AZ8V19tKzIrbe1jMfU+ZLO57/AZWjLwd2UG612tC87OdQFB51U8t7eZqTz/MwrhL
         dasyfME6uUkmS18eG5XFR8OS8M8RImlmT5yBtLCNKRioqnRBPIjSOhnOezQqa78p5zLQ
         TTn8bKqeElrxsBVsmnXj+mzS6M3IV5BjM6N+4RYnsWqND98x5Rh23efN0OSh9ZVfSWlW
         V1cQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PTojZnC4dtEvFGob959ict34uWwLYHIuoL7zKSX3dDk=;
        b=q3z7ayjI3MTHGEKGrRF8YPGS/mdRYgkM07dC/3XjwenBA86prDeFopWaw1VzqhF7Ho
         dtXy+ObPokt5vgD/Chxwng6O1mFihf8ryzSgaFGiwU8ygHwZ7KlAhkimS/2FkLzt4N78
         wa3qJ05VHX0vDsLwNdywzGKftD6QNePcQOGBiO0q/snyiqNKZqwnqOaJaaRVHwb3MtJ4
         AMp9bweFHMTrB5XWk2qlYDjJ+T0E3PnzNLHCAmTQy64rhr7DX7c1Vv36pg16iW9Eeg5m
         eMiDmE3CVQDJqTKEuFufpL8VnNVb7YJwVLH6EUMm165v8inPqinarQxOw+8Sdt34KYSy
         u5lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PTojZnC4dtEvFGob959ict34uWwLYHIuoL7zKSX3dDk=;
        b=FgBz85b8NFPMq+RWj3I/dhKVdSdFU0AvH3DKSdCKzRBSfI7RQEcd4PrSdE78jg1I/t
         iaLQmuhY/19JSqDTsENZ3uKD3D/UmLzUsdZQR69ze3plZyLo1P/sZtpF4opRIGIO1qIX
         sicIQu5sWDsazNyEy+ChXLFCjN9ev7qEyLi2DxOi/O5EvUIWvSaXBghNHUvSVZvf0P6W
         UqIGokV4sNTBsGyvgHOMCV85JcWJQpKjfbJLeru6jqztqUKIWUpDVwhYGnvVFbvSR1ri
         yWxM/ETrgk6Pgkhtv+yFqrgz/ovK28sdaCaEnXLWJKYNY9Ds1pdXogLCsFoJsKeh7e4/
         nMag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GfYcH+zoYr/iukPhja2AnKZNk5Y16g0oaZZ4Ce0yLu2EkA5Q7
	ylY9KnFLP67IUMQHDVLqrXE=
X-Google-Smtp-Source: ABdhPJyvwbS9mxP28wzOwG2wIWd9tV1M7n0n7fV2Ew8EBZLGUKkinSF0i+FVQM50/2qk/NegK5yWvA==
X-Received: by 2002:a17:906:ce59:: with SMTP id se25mr17087330ejb.359.1597685542334;
        Mon, 17 Aug 2020 10:32:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5e03:: with SMTP id n3ls8277377eju.1.gmail; Mon, 17
 Aug 2020 10:32:21 -0700 (PDT)
X-Received: by 2002:a17:906:9984:: with SMTP id af4mr16829286ejc.90.1597685541558;
        Mon, 17 Aug 2020 10:32:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597685541; cv=none;
        d=google.com; s=arc-20160816;
        b=tbEIW8Y0VEqrBHUYDkhgAQC2gjBP5Q6KS4R6tUAVGaxYtj8D90pwxUbapYJilPEZd1
         L5p1uTLgomuQ5MfbhtJ0z8LrnQvfE7RQlrf/QkfHMJzAJB1JHaq1O/OlEJLclHOu78YD
         Bu0cSX7F6nigKBpr3SAkOeUdQP5c7IWtzO7nkcU4Tl/4qMtZ0mdr4cEKGK54acp8hcKB
         5nQODJAypFjUmQMvzJAaDC/qOOhRm9aUwvgI/+bxM8nyjQLDTvjp4cbaaupVJ55Tdsic
         BQI/5pvWoFJ5YxynEvlJAGKu6SOpFzx7dFEAljvwUW9+0AXGs8RjCcGJpUY3pIA5tOY0
         Nzaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=KF+Lijn2GoIDaHXMKcv5dyj265MiB5w1dhwFUWa9B/E=;
        b=Xc09cQhPDb4+GoZX9nRxCCZg9UAD594KDIuS6QHcsd0f+qx7apEYJbYEVUjB7BmkOL
         TBCQCFMP84KwAAv7GwxcjgpkOvsEOr0AJlr6OD26VRxErZQM/YSNlHVazPi4HdNUCi/h
         ZZvabi5R2wPCzI9wfXL8y3+U+IJa52/JdwuR93qc6lHkgWUJT8A02bDCeRjsNy2cvQ2l
         qm0WKz9p3VjM1L2Xh3G2v7lPN9mqCd1iIq5vYs/e3NK1JZOvpKdomOXqWXVUqyLD9GQI
         BwZqgZIpSODRqbtrBUvpEW7z1Dmqh+qcb73LdbNspOghcVPyiuxBrmHLTRxHII4tLqKq
         61GQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f66.google.com (mail-wr1-f66.google.com. [209.85.221.66])
        by gmr-mx.google.com with ESMTPS id lw8si793276ejb.1.2020.08.17.10.32.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 10:32:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) client-ip=209.85.221.66;
Received: by mail-wr1-f66.google.com with SMTP id a15so15756174wrh.10
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 10:32:21 -0700 (PDT)
X-Received: by 2002:adf:bc45:: with SMTP id a5mr16073823wrh.215.1597685541159;
        Mon, 17 Aug 2020 10:32:21 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id s2sm11849415wrr.55.2020.08.17.10.32.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 10:32:20 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Kees Cook <keescook@chromium.org>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
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
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org, notify@kernel.org
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
 <202008150939.A994680@keescook>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <82edcbac-a856-cf9e-b86d-69a4315ea8e4@linux.com>
Date: Mon, 17 Aug 2020 20:32:13 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <202008150939.A994680@keescook>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as
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

On 15.08.2020 19:52, Kees Cook wrote:
> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
>> Heap spraying is an exploitation technique that aims to put controlled
>> bytes at a predetermined memory location on the heap. Heap spraying for
>> exploiting use-after-free in the Linux kernel relies on the fact that on
>> kmalloc(), the slab allocator returns the address of the memory that was
>> recently freed. Allocating a kernel object with the same size and
>> controlled contents allows overwriting the vulnerable freed object.
>>
>> Let's extract slab freelist quarantine from KASAN functionality and
>> call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
>> spraying technique used for exploiting use-after-free vulnerabilities
>> in the kernel code.
>>
>> If this feature is enabled, freed allocations are stored in the quarantine
>> and can't be instantly reallocated and overwritten by the exploit
>> performing heap spraying.
> 
> It may be worth clarifying that this is specifically only direct UAF and
> doesn't help with spray-and-overflow-into-a-neighboring-object attacks
> (i.e. both tend to use sprays, but the former doesn't depend on a write
> overflow).

Right, thank you.

>> Signed-off-by: Alexander Popov <alex.popov@linux.com>
>> ---
>>  include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
>>  include/linux/slab_def.h   |   2 +-
>>  include/linux/slub_def.h   |   2 +-
>>  init/Kconfig               |  11 ++++
>>  mm/Makefile                |   3 +-
>>  mm/kasan/Makefile          |   2 +
>>  mm/kasan/kasan.h           |  75 +++++++++++++-------------
>>  mm/kasan/quarantine.c      |   2 +
>>  mm/kasan/slab_quarantine.c |  99 ++++++++++++++++++++++++++++++++++
>>  mm/slub.c                  |   2 +-
>>  10 files changed, 216 insertions(+), 89 deletions(-)
>>  create mode 100644 mm/kasan/slab_quarantine.c
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 087fba34b209..b837216f760c 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h

[...]

>>  #else /* CONFIG_KASAN_GENERIC */
>> +static inline void kasan_record_aux_stack(void *ptr) {}
>> +#endif /* CONFIG_KASAN_GENERIC */
>>  
>> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_SLAB_QUARANTINE)
>> +void kasan_cache_shrink(struct kmem_cache *cache);
>> +void kasan_cache_shutdown(struct kmem_cache *cache);
>> +#else /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */
>>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>> -static inline void kasan_record_aux_stack(void *ptr) {}
>> -
>> -#endif /* CONFIG_KASAN_GENERIC */
>> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */
> 
> In doing this extraction, I wonder if function naming should be changed?
> If it's going to live a new life outside of KASAN proper, maybe call
> these functions quarantine_cache_*()? But perhaps that's too much
> churn...

These functions are kasan handlers that are called by allocator.
I.e. allocator calls kasan handlers, and then kasan handlers call
quarantine_put(), quarantine_reduce() and quarantine_remove_cache() among other
things.

Andrey Konovalov wrote:
> If quarantine is to be used without the rest of KASAN, I'd prefer for
> it to be separated from KASAN completely: move to e.g. mm/quarantine.c
> and don't mention KASAN in function/config names.

Hmm, making quarantine completely separate from KASAN would bring troubles.

Currently, in many special places the allocator calls KASAN handlers:
  kasan_cache_create()
  kasan_slab_free()
  kasan_kmalloc_large()
  kasan_krealloc()
  kasan_slab_alloc()
  kasan_kmalloc()
  kasan_cache_shrink()
  kasan_cache_shutdown()
  and some others.
These functions do a lot of interesting things and also work with the quarantine
using these helpers:
  quarantine_put()
  quarantine_reduce()
  quarantine_remove_cache()

Making quarantine completely separate from KASAN would require to move some
internal logic of these KASAN handlers to allocator code.

In this patch I used another approach, that doesn't require changing the API
between allocators and KASAN. I added linux/mm/kasan/slab_quarantine.c with slim
KASAN handlers that implement the minimal functionality needed for quarantine.

Do you think that it's a bad solution?

>>  #ifdef CONFIG_KASAN_SW_TAGS
>>  
>> diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
>> index 9eb430c163c2..fc7548f27512 100644
>> --- a/include/linux/slab_def.h
>> +++ b/include/linux/slab_def.h
>> @@ -72,7 +72,7 @@ struct kmem_cache {
>>  	int obj_offset;
>>  #endif /* CONFIG_DEBUG_SLAB */
>>  
>> -#ifdef CONFIG_KASAN
>> +#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
>>  	struct kasan_cache kasan_info;
>>  #endif
>>  
>> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
>> index 1be0ed5befa1..71020cee9fd2 100644
>> --- a/include/linux/slub_def.h
>> +++ b/include/linux/slub_def.h
>> @@ -124,7 +124,7 @@ struct kmem_cache {
>>  	unsigned int *random_seq;
>>  #endif
>>  
>> -#ifdef CONFIG_KASAN
>> +#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
>>  	struct kasan_cache kasan_info;
>>  #endif
>>  
>> diff --git a/init/Kconfig b/init/Kconfig
>> index d6a0b31b13dc..de5aa061762f 100644
>> --- a/init/Kconfig
>> +++ b/init/Kconfig
>> @@ -1931,6 +1931,17 @@ config SLAB_FREELIST_HARDENED
>>  	  sanity-checking than others. This option is most effective with
>>  	  CONFIG_SLUB.
>>  
>> +config SLAB_QUARANTINE
>> +	bool "Enable slab freelist quarantine"
>> +	depends on !KASAN && (SLAB || SLUB)
>> +	help
>> +	  Enable slab freelist quarantine to break heap spraying technique
>> +	  used for exploiting use-after-free vulnerabilities in the kernel
>> +	  code. If this feature is enabled, freed allocations are stored
>> +	  in the quarantine and can't be instantly reallocated and
>> +	  overwritten by the exploit performing heap spraying.
>> +	  This feature is a part of KASAN functionality.
>> +
> 
> To make this available to distros, I think this needs to be more than
> just a CONFIG. I'd love to see this CONFIG control the availability, but
> have a boot param control a ro-after-init static branch for these
> functions (like is done for init_on_alloc, hardened usercopy, etc). Then
> the branch can be off by default for regular distro users, and more
> cautious folks could enable it with a boot param without having to roll
> their own kernels.

Good point, thanks, added to TODO list.

>> [...]
>> +struct kasan_track {
>> +	u32 pid;
> 
> pid_t?

Ok, I can change it (here I only moved the current definition of kasan_track).

>> +	depot_stack_handle_t stack;
>> +};
>> [...]
>> +#if defined(CONFIG_KASAN_GENERIC) && \
>> +	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB)) || \
>> +	defined(CONFIG_SLAB_QUARANTINE)
> 
> This seems a bit messy. Perhaps an invisible CONFIG to do this logic and
> then the files can test for that? CONFIG_USE_SLAB_QUARANTINE or
> something?

Ok, thanks, I'll try that.

>> [...]
>> + * Heap spraying is an exploitation technique that aims to put controlled
>> + * bytes at a predetermined memory location on the heap. Heap spraying for
>> + * exploiting use-after-free in the Linux kernel relies on the fact that on
>> + * kmalloc(), the slab allocator returns the address of the memory that was
>> + * recently freed. Allocating a kernel object with the same size and
>> + * controlled contents allows overwriting the vulnerable freed object.
>> + *
>> + * If freed allocations are stored in the quarantine, they can't be
>> + * instantly reallocated and overwritten by the exploit performing
>> + * heap spraying.
> 
> I would clarify this with the details of what is actually happening:

Ok.

> the allocation isn't _moved_ to a quarantine, yes? It's only marked as not
> available for allocation?

The allocation is put into the quarantine queues, where all allocations wait for
actual freeing.

>> + */
>> +
>> +#include <linux/kasan.h>
>> +#include <linux/bug.h>
>> +#include <linux/slab.h>
>> +#include <linux/mm.h>
>> +#include "../slab.h"
>> +#include "kasan.h"
>> +
>> +void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>> +			slab_flags_t *flags)
>> +{
>> +	cache->kasan_info.alloc_meta_offset = 0;
>> +
>> +	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
>> +	     cache->object_size < sizeof(struct kasan_free_meta)) {
>> +		cache->kasan_info.free_meta_offset = *size;
>> +		*size += sizeof(struct kasan_free_meta);
>> +		BUG_ON(*size > KMALLOC_MAX_SIZE);
> 
> Please don't use BUG_ON()[1].

Ok!

> Interesting!
> 
> -Kees
> 
> [1] https://www.kernel.org/doc/html/latest/process/deprecated.html#bug-and-bug-on
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82edcbac-a856-cf9e-b86d-69a4315ea8e4%40linux.com.
