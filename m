Return-Path: <kasan-dev+bncBDXYDPH3S4OBBIXCUO2QMGQEIRLXZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E3CA09413BA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 15:56:51 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-52f028a33aasf523737e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 06:56:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722347811; cv=pass;
        d=google.com; s=arc-20160816;
        b=K0N3nLFXVV13B8mz7FDOlMzekfCdR3N5CD72kzwB9uC0azsabRONnDo1INicdkARdf
         YVNbm5ZzJ+f6SYiC2e1UtaYrk4Y2+W/u8gCfa7gDtYa+vN5UwR9kUGJ4eZGHxKIyqVHT
         SlDjBhDNOSnHIGG29yYxGnd0EHXKmkA6vtxdS/CMdnfkbOj7KefibUqN1SnLizQHLq+3
         7rOFop5II1OsNDg7rQW9ZfBHoyoUf7eq2iy5XFhTKd0XKGKzbOjaZx3aWn1T45exKOHH
         fsG9HR9b0gCLelZekdM7xLgltVRhgkrwnwJoipED21ieNHfRGFo9KGEwQYbTdP6A8RKW
         Ci4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xNa3JOFnoAlOWbQiNYNLFEVvAQIuktpYHnEi5q5mFRc=;
        fh=d6avup6/HHCqkzJonzFMwv3I0sL2FqbNOuxMFcpQdSE=;
        b=Vd1Qdmt1xbppoXGyUm4VrVc3+u/4AhudCn+FgtFj2Dy5acEdNwEIh+vg3n1o0bRyL0
         U0Tl+8Y4pdHaC4SdtZ5bzh/ySjN/EpiWJsSQT1c4AQ9pL65Il7F94nb/pYbZ+uQSHip3
         k67yG0OwAKyxKW06iEKJv+hFRr4RYXHgUfA73LEXR7sUAaogxG37tLJkY2QDqY/9Pz9b
         KscTzWt7eKgSWrrTFF3zN5U7/QiUK/OIsH3RtV2T1lq6AfILkek4uY7evj56ueXJQy7v
         +h56rPlokUZM99mmNuRIHYRoMEWlWGTJT57e4AoCQWNFOknc0eoQnQOqIdsidk2Bofmy
         6tTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=cRVQ0sHw;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722347811; x=1722952611; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xNa3JOFnoAlOWbQiNYNLFEVvAQIuktpYHnEi5q5mFRc=;
        b=Y7PT90//VGT0xNiZIAwLKmQK3yZq9BrCma5hNCbYoZMcc535Jb4ol5JtlIzAz/evR7
         QMh55eNjuvpEg+tXRQURbBAfcobdLa8T7YpVyHnOMyc2QSbu/oQYFwnUJmOPg6fO1KK/
         +rkclZABU8fZIri9870MA15rbkPCFO68Ht4vJD4y6laSKgxUZGr6HSieybEKvkYSZegs
         yrUBiL3zaIpdh/ne9I9vQcYyzXkWt0a4TfXZUGJ4LQiCalTG2fr6hFTHXcKUKNNeH/v0
         SLIv+c5LhGb9o459agtqfD7McmY3O6eGV0/Php9BeKZTHkKC6o99j3Ohk7sOuCTzmXLg
         8pMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722347811; x=1722952611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xNa3JOFnoAlOWbQiNYNLFEVvAQIuktpYHnEi5q5mFRc=;
        b=upSGFQ9RkURq7njAy2jki4bvSL6/GMJ+Lejdku40zIKlm/2fM5HHUFftiewLVEVFqe
         eIaz/+hZJAHpwM56buK3Z0KMPHLGPEHu9bvR3bgUVPcioT7Y/xqZBSMVrVZTwlhwLlJH
         pCcjbVlFHFqB+x9UnS1ZOw156WpAbHZkEXqy5X6enBsCNtl/neVM1Zn5m+IOfPM+ZmO3
         V6OdtrplIe5kIW64V2dKj3zlJNq/cb1YLC+XLafTl1d54w3pxM2eKXWrIvYvW8Ifo8du
         OBsvT9yy0QoIZ9nh4u4Lmk851IMxf91gJayjeEgAtttLyQQpMVpo/zp+5JmkY3V/xxgQ
         M+bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuQskk5fAe87lT0RilBvFshcCH8HqSlJzC/ym0O7GLIV863HpanAnYlNp09jaL3zcNm4ynHQ==@lfdr.de
X-Gm-Message-State: AOJu0YzESyWV7HI+NrAi4kaUAWjoMoLXFZUOzlE7xS/8FgH/7w4iU9Cx
	BiZk1c7s+FbR2iJs/pGg/GmiPCq2yS6Q6E/UwM5imSOgh37LiIbz
X-Google-Smtp-Source: AGHT+IGdMU5cEutYB+GGk1GHsnd5k5Xk9aOihU0Li55yHZVM66i4A5ncTQdGRPC0jZkE7fNeG2omXA==
X-Received: by 2002:a2e:a7d6:0:b0:2ee:d55c:603 with SMTP id 38308e7fff4ca-2f03c7c94fcmr72344311fa.7.1722347810491;
        Tue, 30 Jul 2024 06:56:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a989:0:b0:2ec:5941:b0cb with SMTP id 38308e7fff4ca-2f03aa6455cls8891fa.1.-pod-prod-04-eu;
 Tue, 30 Jul 2024 06:56:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUhYQfMiGInw+lRhKPSuN2cHg/TdHb3/jbqWDGE6py3Y5fV3T2qDDuOdBYVybED36LbEhvmLLnT78VpUKi7RMMqojCuqnWk4BqEMA==
X-Received: by 2002:a2e:8607:0:b0:2ef:22e6:233f with SMTP id 38308e7fff4ca-2f12ee07eb3mr63139531fa.21.1722347808177;
        Tue, 30 Jul 2024 06:56:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722347808; cv=none;
        d=google.com; s=arc-20160816;
        b=fLKAOqebYsYwcJzz/qeNFCESggOKIYiTs8u4DeLRO6vgqFXft6oZJHKTeflHH9Q8Mw
         Z7+WcJSXBQukbetBcxqhu4PdiaEaXf55fCFbgWUuFRX+WgsMfxkQgG6PjZqLHgvX1zPz
         n2M2paZ+jLgLGrL8+9tCTJP9b859noV4q/2D9lqXKVlvttY6kbFTAgV08r6AKYj6zjnL
         T1ZiBqDk+FFEohOLvbMVCMC6yLV9FKG6U9/4Ua8eY6ZojdUQd9tF+p6XD6ifSYheoH59
         AfyTnifhrOH56Z+DF22ocoINrQLfUkoQ4OQNznYaGppma1cfRQF7iT725aLfFjCHQL5C
         du2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=tTjsllBsZ0Sc2hQb4mXDp4REPh1mWvWiYq8KYR/uMy4=;
        fh=rbcTT3JSVrPSc++gBSPkZj4/f4crDCAcafdoFrC4BI4=;
        b=zKGTHDBhRRA1wkRWkEtlIl+m3fkSvxKU68x00bWl3jIz/aPwEjOUg0piWNgyW7I/Y/
         LWhnKMqLDcBtoAyL/aUni8w/p9sCa1fc8eGGtY97oxhb3DMthBM0x49R7xh2wNzE2j4f
         Ls+S6HTVC8+z6bEfnYihE5Hio4Swnfh3Dc8lhmsUXwMGv5NOj+kY6glW9TNuMWxkgeud
         WudD0hO6bmkWmcRdcqNpC+aBy3r+fKdEgIUnW1cqU2QCPw9jAJLpkwArzsCgXDANOprA
         wZYfyp2oXO4R2PNrT3Gi8cQWnZpTgpID7242Xxvn1JVaZDJS0BeqTr3kq3krCMywUNvn
         91iQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=cRVQ0sHw;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03d04cf58si2456971fa.8.2024.07.30.06.56.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 06:56:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6C6D721B2B;
	Tue, 30 Jul 2024 13:56:47 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AE61813983;
	Tue, 30 Jul 2024 13:56:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tlP5KR7xqGYoYwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 30 Jul 2024 13:56:46 +0000
Message-ID: <d0234a41-811e-40a7-b239-e51b35862adc@suse.cz>
Date: Tue, 30 Jul 2024 15:58:25 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
To: Danilo Krummrich <dakr@kernel.org>
Cc: cl@linux.com, penberg@kernel.org, rientjes@google.com,
 iamjoonsoo.kim@lge.com, akpm@linux-foundation.org, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, urezki@gmail.com, hch@infradead.org, kees@kernel.org,
 ojeda@kernel.org, wedsonaf@gmail.com, mhocko@kernel.org, mpe@ellerman.id.au,
 chandan.babu@oracle.com, christian.koenig@amd.com, maz@kernel.org,
 oliver.upton@linux.dev, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 rust-for-linux@vger.kernel.org, Feng Tang <feng.tang@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz> <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae> <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz> <ZqjnR4Wxzf-ciUGW@pollux>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <ZqjnR4Wxzf-ciUGW@pollux>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [0.41 / 50.00];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[24];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,infradead.org,ellerman.id.au,oracle.com,amd.com,vger.kernel.org,kvack.org,intel.com,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: 0.41
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=cRVQ0sHw;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yzGxhFWz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/30/24 3:14 PM, Danilo Krummrich wrote:
> On Tue, Jul 30, 2024 at 02:15:34PM +0200, Vlastimil Babka wrote:
>> On 7/30/24 3:35 AM, Danilo Krummrich wrote:
>>> On Mon, Jul 29, 2024 at 09:08:16PM +0200, Danilo Krummrich wrote:
>>>> On Fri, Jul 26, 2024 at 10:05:47PM +0200, Danilo Krummrich wrote:
>>>>> On Fri, Jul 26, 2024 at 04:37:43PM +0200, Vlastimil Babka wrote:
>>>>>> On 7/22/24 6:29 PM, Danilo Krummrich wrote:
>>>>>>> Implement vrealloc() analogous to krealloc().
>>>>>>>
>>>>>>> Currently, krealloc() requires the caller to pass the size of the
>>>>>>> previous memory allocation, which, instead, should be self-contained.
>>>>>>>
>>>>>>> We attempt to fix this in a subsequent patch which, in order to do so,
>>>>>>> requires vrealloc().
>>>>>>>
>>>>>>> Besides that, we need realloc() functions for kernel allocators in Rust
>>>>>>> too. With `Vec` or `KVec` respectively, potentially growing (and
>>>>>>> shrinking) data structures are rather common.
>>>>>>>
>>>>>>> Signed-off-by: Danilo Krummrich <dakr@kernel.org>
>>>>>>
>>>>>> Acked-by: Vlastimil Babka <vbabka@suse.cz>
>>>>>>
>>>>>>> --- a/mm/vmalloc.c
>>>>>>> +++ b/mm/vmalloc.c
>>>>>>> @@ -4037,6 +4037,65 @@ void *vzalloc_node_noprof(unsigned long size, int node)
>>>>>>>  }
>>>>>>>  EXPORT_SYMBOL(vzalloc_node_noprof);
>>>>>>>  
>>>>>>> +/**
>>>>>>> + * vrealloc - reallocate virtually contiguous memory; contents remain unchanged
>>>>>>> + * @p: object to reallocate memory for
>>>>>>> + * @size: the size to reallocate
>>>>>>> + * @flags: the flags for the page level allocator
>>>>>>> + *
>>>>>>> + * The contents of the object pointed to are preserved up to the lesser of the
>>>>>>> + * new and old size (__GFP_ZERO flag is effectively ignored).
>>>>>>
>>>>>> Well, technically not correct as we don't shrink. Get 8 pages, kvrealloc to
>>>>>> 4 pages, kvrealloc back to 8 and the last 4 are not zeroed. But it's not
>>>>>> new, kvrealloc() did the same before patch 2/2.
>>>>>
>>>>> Taking it (too) literal, it's not wrong. The contents of the object pointed to
>>>>> are indeed preserved up to the lesser of the new and old size. It's just that
>>>>> the rest may be "preserved" as well.
>>>>>
>>>>> I work on implementing shrink and grow for vrealloc(). In the meantime I think
>>>>> we could probably just memset() spare memory to zero.
>>>>
>>>> Probably, this was a bad idea. Even with shrinking implemented we'd need to
>>>> memset() potential spare memory of the last page to zero, when new_size <
>>>> old_size.
>>>>
>>>> Analogously, the same would be true for krealloc() buckets. That's probably not
>>>> worth it.
>>
>> I think it could remove unexpected bad surprises with the API so why not
>> do it.
> 
> We'd either need to do it *every* time we shrink an allocation on spec, or we
> only do it when shrinking with __GFP_ZERO flag set, which might be a bit
> counter-intuitive.

I don't think it is that much counterintuitive.

> If we do it, I'd probably vote for the latter semantics. While it sounds more
> error prone, it's less wasteful and enough to cover the most common case where
> the actual *realloc() call is always with the same parameters, but a changing
> size.

Yeah. Or with hardening enabled (init_on_alloc) it could be done always.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d0234a41-811e-40a7-b239-e51b35862adc%40suse.cz.
