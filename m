Return-Path: <kasan-dev+bncBDXYDPH3S4OBBH6HRXEAMGQE4Q25DIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5563BC202BB
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 14:10:01 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-369b2d355d0sf6952641fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 06:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761829792; cv=pass;
        d=google.com; s=arc-20240605;
        b=QZIkt45f+Ubtwxbf/oHOueC2h02lAlciH7Yo671hrD80+7BB3pIy5e9y7cg5CsyPb5
         g8iaDEshnY8X8i61mQ2HAi89IVodxF4V3UzrwB1OUddWSkrbOURROHQ7PvkuaM82CIcf
         k9bhA7tN6tEOcJcSf/s4vneYmsODyPOniHE7WgfN2PxWCDQsZJ5tlu77hW+uHC4o7TGl
         f2fLLDhsABqY95MY/CFAKvRM51PVoqJ/Yemawvytk0gsH4bAoJBQ6SM3eNbbCLqo0hRU
         wGctd3EBvK/iKrvYJDpsT3+vQetzRlzEIFLD7QcpCuHKP8m9HJ0uzgRSmsbvEl+lk1nF
         tJiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Sw1VJHZKnMIjKthmpNBuzpvucTRQ96Nom92GXPXVPFI=;
        fh=k/AtMg9nxGozhYgnFrbfEajGmVitfuKByuKagv/dZx0=;
        b=VHvHKZb0HrAh7sWyGhkF1nDTqWSviqT4kv0OZutZKq5E73nqc5DZOPsQQjg6pG7d0L
         qpUmT3t4vw3JVjJo/cKMaRiLorvefer5ucP/rVIifRlOGBwXTifi5wiXaj5fXD4PVazs
         VIIzyOM5NhB8YnmlOOupI6k/JTE5f4zPRP+nWRuShTQ4GAUvu72hspkmB2cNGjAE2Cyc
         vFI65UA0vFcFpoQVxzfm8CWZzhfvyK+Gxb9oG1E0r2eHYgt6gSNAnYkN07UBR6DGiKXS
         hTk3SR20vHirF6jE59gd4TXMhtft7pbx2W7CS3y4W7n2KVbPUTREzpWy9P/C3Hc3rwv0
         YTDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=u35zjXeH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=u35zjXeH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761829792; x=1762434592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sw1VJHZKnMIjKthmpNBuzpvucTRQ96Nom92GXPXVPFI=;
        b=M2Ef+/jS8GmQ91TA4l6epLeTPJWryEP4NoMb3jS4zNplVoc6VoTI6nq1I8W7ZvS9qS
         +NRNEbJQeQoOM2MDjZyHkROX2GLvymfhUtiDAjg/NkaAMwuKkjkKb78cJH4HVrS9ou5M
         iFYRGZ1nT0qUp2T23ZQ/OwGwER+n/TNzbb/ZHwji74dBEPuKmdm99LNGC8uJ6N+Y0ogI
         V1YxeZ2pFtbO20I6d9KJ5xIC1GhkZjFV/8zRLRz2nYtht3I5DPHDLMh7Oc6jgyE7mBMj
         QApR6Tma9mZTVyPiYTyHbT31OQJqWKnJNpFFKUl/Vocp0RYIf7LvB+wdTF89WU8AgWea
         jfaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761829792; x=1762434592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sw1VJHZKnMIjKthmpNBuzpvucTRQ96Nom92GXPXVPFI=;
        b=Nel348tWn16MY0DQtEUQ1GZDjkVShFNyzE4nuZl0POBuDf62sURnQYD0Z9Yo4+FdKP
         hjymlHGSSASr2X+VGNzgOTJAisKoexTj090vcwswqt453KcWX9UYMf0ZUhLRD9K971mb
         QhCq4J6VoDq/HcVUvIUrfByRZUrt85LIwKPlyW0lBo4oTjZUxoGCnhuDdAB8EAVnGUmW
         a0syMdMZHBCmlpyjfgTnyNn5OL2+9mXIV/3wF+taevbv9J89jx6a258VmEzH07uixqkx
         WxjqRRKz0QjyjUniiUP+2BWvj5ZrvteHfwJxK/3/L8KV87Gotl8BsXHGkSCIxxvbBUUP
         8lGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWU4XcA+p5oPaCUtQ6D9z1zLDTvEippx5iMlXjGavR9xJBHEG+PuOx7b//ZFOt/crS6E8X4EA==@lfdr.de
X-Gm-Message-State: AOJu0YyZZqErXdlyufWfL//fLPM9KZM2k76Lsy7g4crgj9BqTYRDPviH
	cRLPC1h583OQRqeoJHi2I8M58PqcqNBY2/j6fcs32b9y1irFur29R2jc
X-Google-Smtp-Source: AGHT+IGveN6PW4a2dNYJzt0tDWcWTIjVluhLuLBajDczXFmM8svhX+7S6wrlgGs0xqWXkfTs1Meuyg==
X-Received: by 2002:a2e:a98b:0:b0:378:d690:5d9b with SMTP id 38308e7fff4ca-37a023c6b66mr20842911fa.14.1761829792200;
        Thu, 30 Oct 2025 06:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z6i7Yt0GPdlG6V1XIC3nq4EyAO78JAzIeBvo1/2cEutQ=="
Received: by 2002:a2e:8e8c:0:b0:337:f40b:d07a with SMTP id 38308e7fff4ca-37a109d0675ls1351721fa.0.-pod-prod-03-eu;
 Thu, 30 Oct 2025 06:09:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNq7+iJghfRwONfvaYgHUVUbS1WU9xHmy+RJ/piwc6JN1/3SyGavaO6jz/V25PxB6yjywD1hTeo4k=@googlegroups.com
X-Received: by 2002:a05:651c:1505:b0:351:786c:e533 with SMTP id 38308e7fff4ca-37a023cc689mr18772831fa.15.1761829789058;
        Thu, 30 Oct 2025 06:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761829789; cv=none;
        d=google.com; s=arc-20240605;
        b=WfyDZeqwImnpTH1pCMh9kqZUBK2kYEqsMVkpHkzgum7hT+Ku+ZARtelp8o+oP/uOhT
         3bKAXDpZdscjt/73W2xZkUT5leApnLaeW2PNIWSJnZOu9MsX7gO/oUCx5SUgSGA7ra66
         Sqd3SBL3euivkYN1F0/GSiodRXwDlENODOyjLeB0BtX/jDQA5TGjBweB8ZrIxRxPU7x4
         oSOmdDoaTFUgvFvv4oj5upiDVMRdZavSgbq12Z/BP0rvvR60AvohRN7ewrhb5mri8IpT
         2Fw3XRLCnZzRR5A3TIz6Uf7WwsYGUBIZMLrJjj1n7vHLCGZH2zDzZXnOB6z3KnMyytwc
         khhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=nEBccaffx0laznQLZDcBToe4Zq9sfm7DWgMbpIyXv10=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=Bb6XX9KTm1tBXmVyZhFC+2cQCLBg09IwdyNWrO2fP52OfFv8rB1dnJdf+dkCIz3dNv
         /AikCPQRyBp/LaFzFT2MWXr1lkrmo/NDL47hhXSCDLR2eiUSRPZghUoNkpXDXuqQyYp7
         mwKxDo5HQAh+OeT6p6f5LbRBd4a0wL8MuikjEZZL26Hz/1+xfmv0cYFGCU1Db2jBAXBU
         lZnFV05cIwxY5XHDD3YoR0BHzJeT8eoDqgvIdc88tVmVYSv83F+pctJpz8hJlGREs8qG
         FFipYpI0nqBTGY8L4mQVJufCBdymQTGZ9Y9A5WcxBIUzqHXVdCKMRdVBrHVOtpIej80N
         EsKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=u35zjXeH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=u35zjXeH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef28281si2277681fa.5.2025.10.30.06.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Oct 2025 06:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 16A611F6E6;
	Thu, 30 Oct 2025 13:09:48 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F0F0B13393;
	Thu, 30 Oct 2025 13:09:47 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id PQNuOptjA2kCUQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 30 Oct 2025 13:09:47 +0000
Message-ID: <06241684-e056-40bd-88cc-0eb2d9d062bd@suse.cz>
Date: Thu, 30 Oct 2025 14:09:47 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
 <aQLqZjjq1SPD3Fml@hyeyoo>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aQLqZjjq1SPD3Fml@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[15];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=u35zjXeH;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=u35zjXeH;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/30/25 05:32, Harry Yoo wrote:
> On Thu, Oct 23, 2025 at 03:52:32PM +0200, Vlastimil Babka wrote:
>> diff --git a/mm/slub.c b/mm/slub.c
>> index e2b052657d11..bd67336e7c1f 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>>  
>>  	stat(s, ALLOC_SLAB);
>>  
>> -	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>> -		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
>> -
>> -		if (unlikely(!freelist))
>> -			goto new_objects;
>> -
>> -		if (s->flags & SLAB_STORE_USER)
>> -			set_track(s, freelist, TRACK_ALLOC, addr,
>> -				  gfpflags & ~(__GFP_DIRECT_RECLAIM));
>> -
>> -		return freelist;
>> -	}
>> -
>> -	/*
>> -	 * No other reference to the slab yet so we can
>> -	 * muck around with it freely without cmpxchg
>> -	 */
>> -	freelist = slab->freelist;
>> -	slab->freelist = NULL;
>> -	slab->inuse = slab->objects;
>> -	slab->frozen = 1;
>> -
>> -	inc_slabs_node(s, slab_nid(slab), slab->objects);
>> +	freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
>>  
>> -	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
>> -		/*
>> -		 * For !pfmemalloc_match() case we don't load freelist so that
>> -		 * we don't make further mismatched allocations easier.
>> -		 */
>> -		deactivate_slab(s, slab, get_freepointer(s, freelist));
>> -		return freelist;
>> -	}
>> +	if (unlikely(!freelist))
>> +		goto new_objects;
> 
> We may end up in an endless loop in !allow_spin case?
> (e.g., kmalloc_nolock() is called in NMI context and n->list_lock is
> held in the process context on the same CPU)
> 
> Allocate a new slab, but somebody is holding n->list_lock, so trylock fails,
> free the slab, goto new_objects, and repeat.

Ugh, yeah. However, AFAICS this possibility already exists prior to this
patch, only it's limited to SLUB_TINY/kmem_cache_debug(s). But we should fix
it in 6.18 then.
How? Grab the single object and defer deactivation of the slab minus one
object? Would work except for kmem_cache_debug(s) we open again a race for
inconsistency check failure, and we have to undo the simple slab freeing fix
 and handle the accounting issue differently again.
Fail the allocation for the debug case to avoid the consistency check
issues? Would it be acceptable for kmalloc_nolock() users?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/06241684-e056-40bd-88cc-0eb2d9d062bd%40suse.cz.
