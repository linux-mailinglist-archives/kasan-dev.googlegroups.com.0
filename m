Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBRFXZ2GQMGQEMTYWG5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A5A94708A1
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 19:26:13 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id c1-20020aa7c741000000b003e7bf1da4bcsf8841776eds.21
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 10:26:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639160773; cv=pass;
        d=google.com; s=arc-20160816;
        b=HQfus+r3q9CUpM60DP/JWtiLYRMlfp1F/L5/UeLJQp7k5fcz9nVFMLKpHl7sr8YHNM
         4ZPSyp6tqg2nrKz6HY2FLRHOjIeRiY/7TMsP8ylcBxuoRZBr2tyKIvRVL7CcyM6BrA3S
         wq59FwmIGmiY7yJLwsTUzf/BKhqbfELBX4eWzjNGs7rD02VCruegHcFpX8noqyqiT1YR
         p389zaoQi5oTQ2RLoW+S97+YgN7gZ3uJmjly/ivLlCBxiVHthR3UZmxMs3qSSPb8WBAr
         yWhvjGrSQtbuaZhIXAr6EScOij2ofrFWfCE+QE91DijPtTaWEe9aVs/A/kOJ/qscL8+2
         m1nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=kXPd+eESNNDLR+mUh6CECbnn/mohAH2mzC1iIfAA4mU=;
        b=cnalFPUsD1k7RzOnChGcv9BUhZFkzlrr9C/vaaJR/9xtMgo6MajDHFCsVFYU9xuofC
         vkV4V2gQY6G2ZuEkbyrKZxd6goJyMVHyP1cW3vueMFaE0zUpjesSEVKtqSvbJeytP/Fz
         kCXTQg7bg44n+CXz0P6MwdY+RYDIJnLH1zxt4koBm5L1aUSO0jx2nm4VlMa9tbVLPvAN
         dSp/4uvYA2ejjvhQ7IAwrTttlroHIHofRJElPZkSjn3ovYBsyqTbHQNRBfgyvN73zKuu
         eccRiFifBPY3YAAH+t+ZzcZ2ojCS1Gsxec5HJM2Qj62oz9LKj6RbFsHmN/OmGRAHzJ1v
         xjhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DEzJI8fL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kXPd+eESNNDLR+mUh6CECbnn/mohAH2mzC1iIfAA4mU=;
        b=RcxG9r+5lhW+9z0/Z5C5CuMIQrKJdACo5LeL/GYvsG8kMmqBzV6fPmGgY3D5ZohGVk
         4fVStVubv+8xdUeQJHAQCuU6mJiZLpISwi+4kdTPlr4a+p2HQDB8LsmbjfWDScgBfWbN
         YGvUvUgYluPSc3rfg2fnh4bgAtsdSrml/IpfHKC0rpt630t6vDc9OuvLMm7ZkH2ypsGV
         zOfz1WjwbFtQMF7j34jXr1d0XZ1SSBZWGGQ2DMPH34l6m9bVwzMKYD3EHzkQZ1SJL2VT
         Gu+xnJs2H3WtTvspTVXOn0oornSKbw4YGTWtBEzTM3sRmbi433zeprLc7G/cYlpGVBIf
         ImcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kXPd+eESNNDLR+mUh6CECbnn/mohAH2mzC1iIfAA4mU=;
        b=K6wiL8KXlfWmtNek6k2H8mzjHS2jVDiph6qwEm9uZKtuOH5N8vovWCn4zn8kdXBVXh
         lLbRrgJfyaCDtIFhFM91Dlq+tHxMe8kzMVuXAQmFM7YXuP4jQoM5NdXjSLN4XDikZL7L
         4wibBgYG/v4HB2QardJNeZw9gXQiaMJLsCiK4bNDqsN6y2m5APnciUXsRIVNdRaJIUOf
         H5stHk8GBf3qcmwy8Z5Dz4RJFOJ3qjkapa6+1mFNsRaTCbtq3fRJ8588VENQqw91qqO9
         6LaB6jGn3EjsuRxH7v7hw3p6hrWRUuajdeQ/BI+3wL3RSGyOuT0ODL/Cvzy/Na1oTtoX
         jPKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530q7a40e8/YpGDaFSQa09/H6uoRDsSs8iTqSu0YYrM5J9rYW7Ls
	OSxxXd8i5HBDKpoChdsyKq0=
X-Google-Smtp-Source: ABdhPJwW3uXSe7pfe1io6lhr6u7DrZT4hrRmbyb2kygWhOsrIE9abBhNq5UDe3gi4P2qiPAYhSzsSg==
X-Received: by 2002:a17:906:8c3:: with SMTP id o3mr25906663eje.10.1639160773157;
        Fri, 10 Dec 2021 10:26:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c013:: with SMTP id e19ls3453952ejz.3.gmail; Fri, 10
 Dec 2021 10:26:12 -0800 (PST)
X-Received: by 2002:a17:906:c14f:: with SMTP id dp15mr25765808ejc.283.1639160772116;
        Fri, 10 Dec 2021 10:26:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639160772; cv=none;
        d=google.com; s=arc-20160816;
        b=VcHxY3rKfo26B149G7BwYoYpyfLLmSYbUgiQ+aAlxwB3WM5kkrj8Ddqx3PsgdG4GPl
         xHo9uNzZxpXOG/G3w/V7iAt2kgHWO/klwSsGVloEkH8yFyMtspY5gkJQPk5xUUQD9rK+
         PKClW387WjCqbMUv23vk0kr/GF1m4VNZ63ROFnAi+hQSJwo3PGHH+8AgIE5gizfjcTEH
         /mnsqP+CpA0ftOQDg6nOR64+n9JgukMZyXQIv0eWSkVOEhP0uHNedVfkmsVZrBOcVT4D
         CYh0GMIkKD0CRXSVIoD68mxL3UVVzHvNdpPUNc9lup+cZZZ09zxwGD84LnkqBPYkk1Av
         pPqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=Z/UbW0ZhlY6juPUlloosi+upV54XzRqkoxBUDz/LC9M=;
        b=o3tj+SohhHrxBDx+OoTBJUek4NZzGkFmpO0PabVRAVEG01hrFwSMtU8JgrPn35DWlr
         SvMAl8MafbwSaQgMPuVVnXkUBZEtRxg8/q5uBxBZAPRp13/SHkBq418u7yF/STThOhY0
         PoTVvQ1FIuJEOc7vuPw2APWZZOXyXo7UY1Q13GWmuMZ9PPZnHKCnRZ+E4cgQE7M/ZJmZ
         wgBxyHHbifQ2XvbZLG/VqpFD8E4Lg8yEegAqvKHh4FqY+7XoG5VPfx7BjsdZ7/nTiIgI
         ATTQBawc/ZWT3Azw0VArqWM8wj5u0BLzeY0TSmBstrp56VIqIQW4cBZBy2Sfs2d3zgUI
         Gjmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DEzJI8fL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id i23si232131edr.1.2021.12.10.10.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Dec 2021 10:26:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A2F3C21116;
	Fri, 10 Dec 2021 18:26:11 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 654F713BFF;
	Fri, 10 Dec 2021 18:26:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id tB0uF8Obs2GwKgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 10 Dec 2021 18:26:11 +0000
Message-ID: <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
Date: Fri, 10 Dec 2021 19:26:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
 Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz> <20211210163757.GA717823@odroid>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
In-Reply-To: <20211210163757.GA717823@odroid>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DEzJI8fL;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/10/21 17:37, Hyeonggon Yoo wrote:
> On Wed, Dec 01, 2021 at 07:15:08PM +0100, Vlastimil Babka wrote:
>> With a struct slab definition separate from struct page, we can go further and
>> define only fields that the chosen sl*b implementation uses. This means
>> everything between __page_flags and __page_refcount placeholders now depends on
>> the chosen CONFIG_SL*B.
> 
> When I read this patch series first, I thought struct slab is allocated
> separately from struct page.
> 
> But after reading it again, It uses same allocated space of struct page.

Yes. Allocating it elsewhere is something that can be discussed later. It's
not a simple clear win - more memory used, more overhead, complicated code...

> So, the code should care about fields that page allocator cares when
> freeing page. (->mapping, ->refcount, ->flags, ...)
> 
> And, we can change offset of fields between page->flags and page->refcount,
> If we care about the value of page->mapping before freeing it.
> 
> Did I get it right?

Yeah. Also whatever aliases with compound_head must not have bit zero set as
that means a tail page.

>> Some fields exist in all implementations (slab_list)
>> but can be part of a union in some, so it's simpler to repeat them than
>> complicate the definition with ifdefs even more.
> 
> Before this patch I always ran preprocessor in my brain.
> now it's MUCH easier to understand than before!
> 
>> 
>> The patch doesn't change physical offsets of the fields, although it could be
>> done later - for example it's now clear that tighter packing in SLOB could be
>> possible.
>>
> 
> Is there a benefit if we pack SLOB's struct slab tighter?

I don't see any immediate benefit, except avoiding the page->mapping alias
as you suggested.

> ...
> 
>>  #ifdef CONFIG_MEMCG
>>  	unsigned long memcg_data;
>> @@ -47,7 +69,9 @@ struct slab {
>>  	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
>>  SLAB_MATCH(flags, __page_flags);
>>  SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
>> +#ifndef CONFIG_SLOB
>>  SLAB_MATCH(rcu_head, rcu_head);
> 
> Because SLUB and SLAB sets slab->slab_cache = NULL (to set page->mapping = NULL),

Hm, now that you mention it, maybe it would be better to do a
"folio->mapping = NULL" instead as we now have a more clearer view where we
operate on struct slab, and where we transition between that and a plain
folio. This is IMHO part of preparing the folio for freeing, not a struct
slab cleanup as struct slab doesn't need this cleanup.

> What about adding this?:
> 
> SLAB_MATCH(mapping, slab_cache);
> 
> there was SLAB_MATCH(slab_cache, slab_cache) but removed.

With the change suggested above, it wouldn't be needed as a safety check
anymore.

>> +#endif
>>  SLAB_MATCH(_refcount, __page_refcount);
>>  #ifdef CONFIG_MEMCG
>>  SLAB_MATCH(memcg_data, memcg_data);
> 
> I couldn't find any functional problem on this patch.
> but it seems there's some style issues.
> 
> Below is what checkpatch.pl complains.
> it's better to fix them!

Not all checkpatch suggestions are correct and have to be followed, but I'll
check what I missed. Thanks.

> WARNING: Possible unwrapped commit description (prefer a maximum 75 chars per line)
> #7: 
> With a struct slab definition separate from struct page, we can go further and
> 
> WARNING: Possible repeated word: 'and'
> #19: 
> implementation. Before this patch virt_to_cache() and and cache_from_obj() was
> 
> WARNING: space prohibited between function name and open parenthesis '('
> #49: FILE: mm/kfence/core.c:432:
> +#elif defined (CONFIG_SLAB)
> 
> ERROR: "foo * bar" should be "foo *bar"
> #73: FILE: mm/slab.h:20:
> +void * s_mem;/* first object */
> 
> ERROR: "foo * bar" should be "foo *bar"
> #111: FILE: mm/slab.h:53:
> +void * __unused_1;
> 
> ERROR: "foo * bar" should be "foo *bar"
> #113: FILE: mm/slab.h:55:
> +void * __unused_2;
> 
> ---
> Thanks,
> Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f3f02e1e-88b2-a188-1679-9c6256d19c7a%40suse.cz.
