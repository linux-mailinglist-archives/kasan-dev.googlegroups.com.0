Return-Path: <kasan-dev+bncBCKLZ4GJSELRB2XBYGVQMGQETIXGEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF63807079
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 14:02:36 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-33340d20b90sf683481f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 05:02:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701867756; cv=pass;
        d=google.com; s=arc-20160816;
        b=fmykmf0m4coKm99eQgXt5JeP3QfrwyGd211scUnXYi5ur+KDbmkzzoN0APQXqEkXhE
         MZ/ZpAa933wQ6xIDu8gxoTXZqnYwoy+wJffT1QZ1hFek7DqVVUem3ryXo1ngMjEwh1I2
         sMCrGwM8dHuGzK6ioXrRjBVWRgh+8aS7Dyi2dQxvGdnqL1R6xJBz0W+d9M7riC7gOc8/
         pctv5tEe4SuAjLCFpHcrIf9fO6GgXHiAyXZEotMQ4/Pbfy4+LVvGk44YrnHFuhhFbay9
         J54o4CNa9sqiBFkLsnH11fFEEyQoxXqzAOKSKj3BO0VsMwzJ4NMIeNlT7/zNE3x6XDXe
         lqmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=B5pSfhkfNcwPb4pgah7nUZWd0GcZCqnADpfMIdNBFmA=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=z34CF9KEHxabM2zl81CrCbFC7K74K626JenMnXzvMd6l8fzJQSDbtVreR/EwITOU1y
         PuMtj6LEwDjUhh8FiubNoeyL9qvdgU5LslOilpbaAEqXklYqauY4dVb73wY6okHUT0mS
         U9/w+k+KWciv3AXu1ktP7Ole2iNUb+dnGgjabaox5YTcfGs67NwRNFDn0rSZiU8gkKw2
         Vi35Ts2S+wfcZGpTUr1QAKmWhu8DAJEPQ4xZd40tMWel1uhgEBM1iODIipGIPH3zlWoh
         y1hYv3LhE4Obw/ekxWk+0AP2bbZmOze0bCXBn0xI010Ooi6eYQJo+HiqUwIvLoNYafcF
         h6sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vT7C/0yE";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701867756; x=1702472556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=B5pSfhkfNcwPb4pgah7nUZWd0GcZCqnADpfMIdNBFmA=;
        b=GhwwtxEPezciqzxXW3MlkgXbg79RjRpiBHCqAqUXxp75+ZiWJE0AinkyJcdNFTtwyD
         SAQfXkL2Td9cN7HZ3oKcBI7GGM14dS6q6bD0z+NLNaJCnIc2/nXzl8myqfQWrFQYEIpj
         T7zbivzhLlz7OSyC7Voip3B0JUuuj4ulwaS0wKOmemLmObNBkbgtn06p8FoOctqoUa3q
         vhT4Rfns1/PgmCI6F7nLf3d20zc/wHFz0FdqtplcaHQfsD595nNTYEpOYouKm3z00E9+
         augD0djnInuqZPUaTaHoC/d2iNYZsGkvdhO7zeIJVmpM+KOAoI5uH6d2+hRDIMlKk2D9
         xoEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701867756; x=1702472556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=B5pSfhkfNcwPb4pgah7nUZWd0GcZCqnADpfMIdNBFmA=;
        b=ICiadu/eqg82kljSZ0iqOE0PEisRkOtwCrWBHANz0lDLHQt1GnnxioTPvAqvMCeRIf
         pzPncicIHswp6gelAMIKPQU+eQNXtdW4Cenfb2OxqqHMPFLXz3o/MOgohHzHuer4IM83
         tM/1t4YtdxBWqnrfqgzCFkm8coEqquUMJBccBpPmxP5ddVFyVgM4qTV/mIIhCPOTuaRA
         StyMU/uYejX0EoiL61No0NQlo/PFhHuVSMyYqfYjv3ax5sv6V7oKathbi/ES549cPmc6
         uYLZnLx+AE5csvgEOHo+yGffGhHAA2GJTq+H9JqgK4rTQsLny23VLLXZul7HpV3tHz7v
         Mhfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyxF8IXSSUjdPrm9UUCQlt3440NmGlQas+yR235BkmM9a6w1UK9
	EhLPhOodFJpqn141T2te2iY=
X-Google-Smtp-Source: AGHT+IHiBoWLxpU5fOz9o9vV1pVzG0856X8or02Sgf0wHftjPKM7rSwrDkSbNYSEt7vmfoEj3Ro39A==
X-Received: by 2002:a05:600c:2d86:b0:40c:23ca:1444 with SMTP id i6-20020a05600c2d8600b0040c23ca1444mr263687wmg.80.1701867755145;
        Wed, 06 Dec 2023 05:02:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b13:b0:40c:2324:253c with SMTP id
 m19-20020a05600c3b1300b0040c2324253cls222474wms.1.-pod-prod-04-eu; Wed, 06
 Dec 2023 05:02:33 -0800 (PST)
X-Received: by 2002:a05:600c:501e:b0:40c:982:4968 with SMTP id n30-20020a05600c501e00b0040c09824968mr570612wmr.136.1701867753358;
        Wed, 06 Dec 2023 05:02:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701867753; cv=none;
        d=google.com; s=arc-20160816;
        b=Z2zQV9JH/N0LiTuOoWsCK6D128PNUKQe3/RVLIUhsGWU1dVyLhhUxx7X3ceqxHUnpd
         JvdM2OFY3s1FKACvaUUKVlW4XEDUUGvF7OzMlQBa2YnR8EvN8adklFipF02uXpDyWIKw
         sDftuVqEC1gll/2DSUyY34hZ4tDSOn/TuMa7OhxFPcqfa2ehAFd8dqrOBSZbzW8MR0UF
         jCVKGBOBl361sstdLlPoTqKChpa6H29Ux1S1Fx42wv2x1S+ndRAb/GAQDneD7ubOgRiF
         qJnUIvHo2C+Yjh6NyvEqM9XTFLbU6bb3TtAQL38QIjPnczX/IV36wl+7Cmcx1hQXxnx4
         S2Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=8FwFOjfZZq5xgvqF5C0gDT7tc2X7JK7alFPfrUHoiQ0=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=jYxLkq3rZStoHCZNCv6MNkaQ/lKnvkgkT4grOFXpzpCP3M7d15H3CuNa3fkLfxMrY/
         sQO0mQVmUfLJRfuwvVOsGYANpTufdnGRV/mGznf4ccx2aIXHTM+R/nbt73XFCfkPunzM
         Hmj00sjI3GvnmnP1cEZi21q43iJN2IziLWKbpkGus2Ph1ACxtGCKZDtAyMFaBNq9qKLQ
         1HZr7f7sVMZOjJ5V1ruJtPFe7jfDLJL067NCdk5E/p3dnyqYffAYX/ES+M0PsfUmNu3d
         C87UdXWLHuo3EAySoKdslnHx49eAc8bRXH1kAY5jv/PCY3tvPFR1fqzQ+S+DSsFM6i+j
         N9rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vT7C/0yE";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [2001:41d0:1004:224b::b6])
        by gmr-mx.google.com with ESMTPS id bg17-20020a05600c3c9100b0040b473eceb3si901243wmb.2.2023.12.06.05.02.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 05:02:33 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) client-ip=2001:41d0:1004:224b::b6;
Message-ID: <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
Date: Wed, 6 Dec 2023 21:01:58 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
 <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
 <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="vT7C/0yE";       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2023/12/6 17:58, Vlastimil Babka wrote:
> On 12/5/23 14:27, Chengming Zhou wrote:
>> On 2023/12/5 03:34, Vlastimil Babka wrote:
>>> When freeing an object that was allocated from KFENCE, we do that in the
>>> slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
>>> the cpu slab, so the fastpath has to fallback to the slowpath.
>>>
>>> This optimization doesn't help much though, because is_kfence_address()
>>> is checked earlier anyway during the free hook processing or detached
>>> freelist building. Thus we can simplify the code by making the
>>> slab_free_hook() free the KFENCE object immediately, similarly to KASAN
>>> quarantine.
>>>
>>> In slab_free_hook() we can place kfence_free() above init processing, as
>>> callers have been making sure to set init to false for KFENCE objects.
>>> This simplifies slab_free(). This places it also above kasan_slab_free()
>>> which is ok as that skips KFENCE objects anyway.
>>>
>>> While at it also determine the init value in slab_free_freelist_hook()
>>> outside of the loop.
>>>
>>> This change will also make introducing per cpu array caches easier.
>>>
>>> Tested-by: Marco Elver <elver@google.com>
>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>> ---
>>>  mm/slub.c | 22 ++++++++++------------
>>>  1 file changed, 10 insertions(+), 12 deletions(-)
>>>
>>> diff --git a/mm/slub.c b/mm/slub.c
>>> index ed2fa92e914c..e38c2b712f6c 100644
>>> --- a/mm/slub.c
>>> +++ b/mm/slub.c
>>> @@ -2039,7 +2039,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>>>   * production configuration these hooks all should produce no code at all.
>>>   *
>>>   * Returns true if freeing of the object can proceed, false if its reuse
>>> - * was delayed by KASAN quarantine.
>>> + * was delayed by KASAN quarantine, or it was returned to KFENCE.
>>>   */
>>>  static __always_inline
>>>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>>> @@ -2057,6 +2057,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>>>  		__kcsan_check_access(x, s->object_size,
>>>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>>>  
>>> +	if (kfence_free(kasan_reset_tag(x)))
>>
>> I'm wondering if "kasan_reset_tag()" is needed here?
> 
> I think so, because AFAICS the is_kfence_address() check in kfence_free()
> could be a false negative otherwise. In fact now I even question some of the

Ok.

> other is_kfence_address() checks in mm/slub.c, mainly
> build_detached_freelist() which starts from pointers coming directly from
> slab users. Insight from KASAN/KFENCE folks appreciated :)
> 
I know very little about KASAN/KFENCE, looking forward to their insight. :)

Just saw a check in __kasan_slab_alloc():

	if (is_kfence_address(object))
		return (void *)object;

So thought it seems that a kfence object would be skipped by KASAN.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fdd11528-b0f8-48af-8141-15c4b1b01c65%40linux.dev.
