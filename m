Return-Path: <kasan-dev+bncBCS37NMQ3YHBBQ4I5P4QKGQEFJBGE5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F053246FCD
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 19:54:12 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id f14sf3016027ljg.23
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 10:54:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597686851; cv=pass;
        d=google.com; s=arc-20160816;
        b=lIIWzzCoX3WCTmIRhxIhRvab+nsl5WanO/lqTwp9DsjdaF8WFeEOh5M8ztv3LuGM4j
         eTfGhQIgS7uH1ZygJgf5UD5Pz1GPxs8o/061cztpTnLBS8EgwqAmL4yxkO8Rg3Ojd0Xe
         JJm0bRiuMNbuw6NxiJCPo+u7UEZ/BThfk5iHg/fCW5SfLGfF3z5NUurE0nFVd75ytQj4
         vpukKnWVZ99zz/nzMuY3/ggj25ehskkDsCCyPcT7a/fVsxh1YgxxN1ymvVnQ22+KeDWj
         cs6NZZ4fL6V298OsvIyMgpP6D3VnRnwz1DYO217lY6ETXvcIUv1YpPEedqQVMHpqLjS+
         7X9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=pFFI3blTOVNGAs583gPBtPbix6qg5O5odwxC6tVZZjs=;
        b=ymr0SXvn6RDu1WDVoF7TtAbcb6OC7CwGQ1y7HlDrPeK/fggtDNnugwdJ8L2NRtcGoU
         TASXPBfbh3eZjN7LLQxIs/lZzqwUgASff9Ta23IHqFEhOSdo7GxJMQrCRjyNK2QfYNj7
         nMNUGMwUpxirpFiM/ISO5uFwvoTlx+oo/ld8+9cylRfHk5zLG5D1c7IAysJpz4cqZ3mF
         JucwHbKF47ewluI76ogPnJR1fsEES1NVFukH4IbwadtJae5dgLQxev8xB7ZZ+0kCYJBP
         V0vnYQ82ypNGDBYJPzqZGrFvDUYPWZSoD4v5kAQEPERBVqESO8nmnKd583Zoas7ZBm7R
         lSlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pFFI3blTOVNGAs583gPBtPbix6qg5O5odwxC6tVZZjs=;
        b=tF0t1aB+zZmWg6l+ZkVbDsJ7h6oYtbF9FB2w8m9kZhQf0W6Gp5JaL3tEmpq4I4mUV4
         kf8O/U1lz7ATQIfP6exF8sesvID+Kf5n38BEzuHqkuHJJdxm4LDXBRlAPnw+Up2N6LRT
         ZXcfay23VgD73jKHHgnucLXS/nClybqT9dz5K5yFj138jl+cT/uKl1mLLrMGnwHt8f71
         gWtfJrSjKOoe58cr8WdSzR2voOznHey4jvOUX6q4ln/oOSYorPN0SuP34Pq8wUd+MjDp
         +Uw/f8CBy7VQUlPZ0FNtgzktttfNTppC/Ull86Blhpbd9scqobZbQnUjhhUGbyLCClSZ
         w7gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pFFI3blTOVNGAs583gPBtPbix6qg5O5odwxC6tVZZjs=;
        b=qBcfXsn5eM791uCbAdmo78od6a93sjXPSuOzU2SlJu6wNrSnd8a9mpaomtAY6WcpWi
         ukU/OVHijXNkuQFgECQcSQBWI+0MEzy82VZDUinxaHYE7OpxLdarRFxGUxZ94MXEawJb
         YnMfPnSgipJS1qx7BoDj2Z8YyhxOCuB7buuWOGU+737pBV3OiARovudi9hjjRlH5hmp9
         EVzqB4tXekzJlwjnu7se4jvRZpkdVIid2z1SAY7WTfTjuUBKPQL5PzeUIn5Q2sUeUJfK
         /zQfFgjIfQAo5ZBUKHUPcHgASh+1XXRM5jf7EtCsOo6CbHHhLOobiv3exEyVMWdNEmOC
         rYyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y6qcWAnRl6aP4HO3CXnDhgztYr09v8v8ihafH44kGY6n08Oy5
	K55Upt7Diz4queeNc3eCR4I=
X-Google-Smtp-Source: ABdhPJwGmX5zce/K8DjU1AtBG9cBboGTvGPSaIoSFAUrbCNvkcTcBOjzP3eCimJzOU0W3JwGUfnkUA==
X-Received: by 2002:a19:c653:: with SMTP id w80mr7966898lff.167.1597686851755;
        Mon, 17 Aug 2020 10:54:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a58:: with SMTP id k24ls197398ljj.4.gmail; Mon, 17 Aug
 2020 10:54:11 -0700 (PDT)
X-Received: by 2002:a05:651c:1136:: with SMTP id e22mr2283895ljo.422.1597686851029;
        Mon, 17 Aug 2020 10:54:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597686851; cv=none;
        d=google.com; s=arc-20160816;
        b=Y52DfhKgbD4ThY8J2nAsYytohJZKebW/RrchQ6QrJSSXVYf1KKhqoQ3wswtoLqMBtJ
         TS3mzqqNfpRyFkPqMrnuxxRycNi+A7xv/S7J/w2lPynGF0gT1hjzrXifGMdX2VhaUqXP
         Pt0r2oOz4kJZ+tw2WHegZlHPAYHiEPDD2NwsJpGoscvjivnFRXc6JjehaONMDsWHdnIv
         MWZB6HOFHGlxI8B2StaI4EYEYQhgFp1n6GTKvuAFTJGzXirY/5OIcFie9/de8AVDMDJ7
         4JSJOyXjN0bXWRkYT/y1FGBVyVmxym5r9k2T9+z6SP1Y8DRIcq/T/8dY/3UR88bnqZPB
         0Jgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=zioXayb3aZ1+dwOWJvBfiHPq2HNW4QALEO2XKd3ld70=;
        b=IU28GROBqb21iEspLx+bvvWCY6RS1kBsooBGqzJfyawxApAo8A1/LxnUI1aWE1KqUX
         ax36tJW5HSNIAHt+rkk2iRj4k8fv5dXQxnbq/GaGQlKMuRaf7y07ADN2wSIn53HmkSiG
         B8/v/1e3W0tR8ef5oyo9ttIj71ivrTcfDtdS/81Q3N1+3W8Vc0vQHRtaPZYYKh/KWbEr
         8iFUshj3H6mcnVtOEdzmFqFf+DHpo9Gu2Ex+h2lE65PrwC/Emu/FMjwsmYMAh4J89gti
         yqknZkg4l9XzSKeG+UEM/PSBUJ4NJ/X3CuGp8tJ+axUbw2GYaIAm9BdKOyucow5eMHBs
         5WEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-ej1-f68.google.com (mail-ej1-f68.google.com. [209.85.218.68])
        by gmr-mx.google.com with ESMTPS id u9si854552ljg.8.2020.08.17.10.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 10:54:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.68 as permitted sender) client-ip=209.85.218.68;
Received: by mail-ej1-f68.google.com with SMTP id a26so18807848ejc.2
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 10:54:10 -0700 (PDT)
X-Received: by 2002:a17:906:528d:: with SMTP id c13mr16654442ejm.61.1597686850290;
        Mon, 17 Aug 2020 10:54:10 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id m12sm10332353eda.51.2020.08.17.10.54.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 10:54:09 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 2/2] lkdtm: Add heap spraying test
To: Kees Cook <keescook@chromium.org>
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
 linux-kernel@vger.kernel.org, notify@kernel.org,
 Andrey Konovalov <andreyknvl@google.com>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-3-alex.popov@linux.com>
 <202008150952.E81C4A52F@keescook>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <37ec713d-10c8-0222-f624-27815b96da7a@linux.com>
Date: Mon, 17 Aug 2020 20:54:04 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <202008150952.E81C4A52F@keescook>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.68 as
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

On 15.08.2020 19:59, Kees Cook wrote:
> On Thu, Aug 13, 2020 at 06:19:22PM +0300, Alexander Popov wrote:
>> Add a simple test for CONFIG_SLAB_QUARANTINE.
>>
>> It performs heap spraying that aims to reallocate the recently freed heap
>> object. This technique is used for exploiting use-after-free
>> vulnerabilities in the kernel code.
>>
>> This test shows that CONFIG_SLAB_QUARANTINE breaks heap spraying
>> exploitation technique.
> 
> Yay tests!

Yes :)
I'm going to improve it to demonstrate the quarantine security properties.

>> Signed-off-by: Alexander Popov <alex.popov@linux.com>
>> ---
>>  drivers/misc/lkdtm/core.c  |  1 +
>>  drivers/misc/lkdtm/heap.c  | 40 ++++++++++++++++++++++++++++++++++++++
>>  drivers/misc/lkdtm/lkdtm.h |  1 +
>>  3 files changed, 42 insertions(+)
>>
>> diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
>> index a5e344df9166..78b7669c35eb 100644
>> --- a/drivers/misc/lkdtm/core.c
>> +++ b/drivers/misc/lkdtm/core.c
>> @@ -126,6 +126,7 @@ static const struct crashtype crashtypes[] = {
>>  	CRASHTYPE(SLAB_FREE_DOUBLE),
>>  	CRASHTYPE(SLAB_FREE_CROSS),
>>  	CRASHTYPE(SLAB_FREE_PAGE),
>> +	CRASHTYPE(HEAP_SPRAY),
>>  	CRASHTYPE(SOFTLOCKUP),
>>  	CRASHTYPE(HARDLOCKUP),
>>  	CRASHTYPE(SPINLOCKUP),
>> diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
>> index 1323bc16f113..a72a241e314a 100644
>> --- a/drivers/misc/lkdtm/heap.c
>> +++ b/drivers/misc/lkdtm/heap.c
>> @@ -205,6 +205,46 @@ static void ctor_a(void *region)
>>  static void ctor_b(void *region)
>>  { }
>>  
>> +#define HEAP_SPRAY_SIZE 128
>> +
>> +void lkdtm_HEAP_SPRAY(void)
>> +{
>> +	int *addr;
>> +	int *spray_addrs[HEAP_SPRAY_SIZE] = { 0 };
> 
> (the 0 isn't needed -- and it was left there, it should be NULL)

It is used in tear-down below.
I'll change it to { NULL }.

>> +	unsigned long i = 0;
>> +
>> +	addr = kmem_cache_alloc(a_cache, GFP_KERNEL);
> 
> I would prefer this test add its own cache (e.g. spray_cache), to avoid
> misbehaviors between tests. (e.g. the a and b caches already run the
> risk of getting corrupted weirdly.)

Ok, I'll do that.

>> +	if (!addr) {
>> +		pr_info("Unable to allocate memory in lkdtm-heap-a cache\n");
>> +		return;
>> +	}
>> +
>> +	*addr = 0x31337;
>> +	kmem_cache_free(a_cache, addr);
>> +
>> +	pr_info("Performing heap spraying...\n");
>> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
>> +		spray_addrs[i] = kmem_cache_alloc(a_cache, GFP_KERNEL);
>> +		*spray_addrs[i] = 0x31337;
>> +		pr_info("attempt %lu: spray alloc addr %p vs freed addr %p\n",
>> +						i, spray_addrs[i], addr);
> 
> That's 128 lines spewed into dmesg... I would leave this out.

Ok.

>> +		if (spray_addrs[i] == addr) {
>> +			pr_info("freed addr is reallocated!\n");
>> +			break;
>> +		}
>> +	}
>> +
>> +	if (i < HEAP_SPRAY_SIZE)
>> +		pr_info("FAIL! Heap spraying succeed :(\n");
> 
> I'd move this into the "if (spray_addrs[i] == addr)" test instead of the
> pr_info() that is there.
> 
>> +	else
>> +		pr_info("OK! Heap spraying hasn't succeed :)\n");
> 
> And then make this an "if (i == HEAP_SPRAY_SIZE)" test

Do you mean that I need to avoid the additional line in the test output,
printing only the final result?

>> +
>> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
>> +		if (spray_addrs[i])
>> +			kmem_cache_free(a_cache, spray_addrs[i]);
>> +	}
>> +}
>> +
>>  void __init lkdtm_heap_init(void)
>>  {
>>  	double_free_cache = kmem_cache_create("lkdtm-heap-double_free",
>> diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
>> index 8878538b2c13..dfafb4ae6f3a 100644
>> --- a/drivers/misc/lkdtm/lkdtm.h
>> +++ b/drivers/misc/lkdtm/lkdtm.h
>> @@ -45,6 +45,7 @@ void lkdtm_READ_BUDDY_AFTER_FREE(void);
>>  void lkdtm_SLAB_FREE_DOUBLE(void);
>>  void lkdtm_SLAB_FREE_CROSS(void);
>>  void lkdtm_SLAB_FREE_PAGE(void);
>> +void lkdtm_HEAP_SPRAY(void);
>>  
>>  /* lkdtm_perms.c */
>>  void __init lkdtm_perms_init(void);
>> -- 
>> 2.26.2
>>
> 
> I assume enabling the quarantine defense also ends up being seen in the
> SLAB_FREE_DOUBLE LKDTM test too, yes?

I'll experiment with that.

Thank you!

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37ec713d-10c8-0222-f624-27815b96da7a%40linux.com.
