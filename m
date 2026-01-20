Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTWDXTFQMGQEJ5V424Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C10FD3BF41
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:33:51 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-b870870f1aesf727941666b.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 22:33:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768890831; cv=pass;
        d=google.com; s=arc-20240605;
        b=ditAvQoXd/w7Tr4/KG2HpRNphdyoxOJoU2YoSv8VkCiWeES7qR53Is65pR5qB8tI2q
         vIsh9EYIj0GjsPs4pOSucUhzsITU2iUbCgQEkdNz+Mt6uVX9NgsLUqkU8bXaiG8A1yGJ
         7MyPTtMpux16pFUyuEnPHAIE0ZV1GexebDENYOBNhucte5cNuvqHX87NovKbyyrNdUDt
         HotHMH6bMo7DlTfAhBkmKq0nqsvJYLItwLG7YbTIjj5Rn4DTVEwKN6V6Oq74f+A2RRiP
         Mm8QjY3MC4uCkU2T0UVhzQeBfrI7nn87Mo3YYIILUGyL+sNMCw8R0C0fJUCh4Csxv8lY
         TtdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=DS1b+cmltEhmjqLIQbHYHdQur2A4Qtxx2HL4bgHPRYo=;
        fh=MyH3ZPP/hX4GCQZ4ygni/Jd5siojFc8wJK86w3rTixM=;
        b=DT6xZPmuksYnKCRWpTsrfcKHMVqwgtrkULmHDm3ffUxHORdLwpqIgAAnSNFoIKyCbV
         hYGyGaQ9H0yUrKLmlqqV5AIHbEA9L+kuWw2Je2s1+X4FjsOCK2couvU7nQST8ls0e3Ru
         P3+T7b0yom/RP89ioH3Vcpd2U6BLx3eJauC5aD8rcfQzAQSZiv6slOe2g7IiREXuGJyf
         ZzAbmSBgay1gAqcMQaH5al4y2Odx5VcZRh8G4Pc0k5ct4+i6cyHjT99cOQ0g257v+BTv
         0DLl0oNGugqww1PNqFPWO1BqeVxk3OkIrf6gzUSDAGhRZRgOrMW5FlLLtG5ksDfZCK3s
         NotA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HgCjMk+E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScNhbrR+;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768890831; x=1769495631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DS1b+cmltEhmjqLIQbHYHdQur2A4Qtxx2HL4bgHPRYo=;
        b=hO1yAuocc7zAYROnXH3PojOy5aZ9VmA8/DEBf2bPyrWH5cln1P9hg4rOjabVtB+SeJ
         3weQxtcRpcmfvGoa5+HgEF6YwVKYUdkM/U9I9ejpuimttvpgsP9zax8gZE9R/oVAzzHA
         fKlvMEm/ox+HYctCA0gSULelM/8drK+sClntWDAeO26nIf1GCuoWq5eQI2b9oCtNuL3W
         aIbTS/xxSW2Irg5AqrAq8T6i1m1/qASYVkXuEFdfQGCOppgnulPVy6DdHtPPKJcCkufm
         AV+ZHmzckT9lLrOA92YnJRmlyUJpRFXqMFcbD9N8eg49ZJvNX44vAG5yDEPuLPQrcGS2
         ny9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768890831; x=1769495631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DS1b+cmltEhmjqLIQbHYHdQur2A4Qtxx2HL4bgHPRYo=;
        b=Qw1Sz0Td/7Eg69bGPTdnSMD/hqIe/cLDqP5J228WEDy6SyyM273wn6fjclA7pIAWrJ
         zBHbriUQDhRy2v7PN0NjitjwAddLIYtp85MqfB4gww1PbeZhwaB6+B15pBpYAccVswZB
         GRiPwCZD9OGAj6NNjqLDqSkdbWw6kt3Bgttemi3FxzCbP/6yJmRr0rDcs3lIjk5Lgu1U
         YqHW6iH9fIlLuPa5AoKv5mTuhxRg6TEYbkfxiLb2zEHrAwLJuO24S1/N9p5qML99W1Mc
         7a64ZF6ycec/XQA73XdBibQlaUGkwhAJn1QN7BCiQru0gXHuisHyLXP4w8deb26iSZB9
         oJBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDZ2ysQIXELeZDNphtfHm0MIZ0ld2+wuPG9jm+30pOvvMwzg5ig/zqRUqWgAEybz9J+5F1TA==@lfdr.de
X-Gm-Message-State: AOJu0Yz+ntMh+7EK2aY8WcobFUxu+D93Fir8tIBEUKfu/bNqlp8/APC8
	wCZ4oBe+8KaR9lcF/mwAOjKiphH/eJQcsFLCPvDY9sPvlY9FrHpR68Wl
X-Received: by 2002:a17:907:50ad:b0:b86:f216:e7c2 with SMTP id a640c23a62f3a-b8777c7c352mr1145869966b.32.1768890830840;
        Mon, 19 Jan 2026 22:33:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G6QyjrnUqOpPYS8C/RcBU8tbhvtEcu+lLRgaiRYNIG2Q=="
Received: by 2002:a05:6402:3256:20b0:64b:6e67:b69c with SMTP id
 4fb4d7f45d1cf-653ea29b65cls3364236a12.2.-pod-prod-00-eu-canary; Mon, 19 Jan
 2026 22:33:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUu0GeHlAqmvMMUQaQvKyrbIRUT6SjLZewRTPfxnyjl61eeSVuI1Bw1eJDitS/oGtgNMJYXNsPw+9Y=@googlegroups.com
X-Received: by 2002:a17:907:940e:b0:b7d:266a:772c with SMTP id a640c23a62f3a-b87939da075mr1465788466b.21.1768890828593;
        Mon, 19 Jan 2026 22:33:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768890828; cv=none;
        d=google.com; s=arc-20240605;
        b=SSHnxA4wNflH3MfsRYfhvcvr1C6R5CiRTSgD1AyQC4tVg2TiBma35f37jyLX8gDEW6
         xOyhDQhgp+BtDbXfIgsMf1CrJRRsBF0NgK+/j13DVzTH4A5AamYKG0SALXPzZxwH5OYj
         kLUan1PgenFHG829eZBRlFP2SV3XxJUzYwqkjvRrPSHnKxyxIMYtef91iZoXoTpKKpPR
         c4KM+29Sv3H4LU+G4fMKwVorMYuvgfBdiUQrTJeE2MGpIEYlYpWp4aFQeBFjppoWiYIP
         xsUtFPnZmORFBd2JWBDnZkwcmOZHvABTYaIFDQ31s9uermWdd5qWTM3xFRe8bumf2QSu
         NFgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=VK5LAWZJGesYmfMe3akrFE9Qr+u5i9eRqUPU6M9O84A=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=Q3jHFO4oC7CFt6Z29lyA5zgvM0qisCsRn+JAWaD1LqzlMui4B8lHUZ3mAZhb1A6K2D
         pBucGJbAVNh2+xpiwC8L2nNAPJwf65h5Q57cUOK4CFq8SRN4s0S6sjKZW7lnP36G/7EM
         uyWq9iqtb8m3tt1HZ2A18eNRBAcmCk/qxLM6KEz956sP/XNij8b+auVPibYyzum2slz5
         K+rCvM+3U/6ZdgyLE2gKp8vMua9gJzY7H4wXYee7riKvslRbstxIWpT5DpFR5gTaLfXJ
         1HiX6kDw9m0W75NtvFqHJYmnUBkye0VAaNgIYkGQqwXp+9zHIHSONwQ8Sw5N2pxww6DR
         mlCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HgCjMk+E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScNhbrR+;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959b318fsi25135566b.3.2026.01.19.22.33.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 22:33:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id DDF775BCC9;
	Tue, 20 Jan 2026 06:33:47 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AC09A3EA63;
	Tue, 20 Jan 2026 06:33:47 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id c0s8KMshb2lLAgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Jan 2026 06:33:47 +0000
Message-ID: <2232564a-b3f7-4591-abe2-8f1711590e6e@suse.cz>
Date: Tue, 20 Jan 2026 07:33:47 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW7pSzVPvLLbQGxn@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aW7pSzVPvLLbQGxn@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HgCjMk+E;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ScNhbrR+;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/20/26 03:32, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
>> At this point we have sheaves enabled for all caches, but their refill
>> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
>> slabs - now a redundant caching layer that we are about to remove.
>> 
>> The refill will thus be done from slabs on the node partial list.
>> Introduce new functions that can do that in an optimized way as it's
>> easier than modifying the __kmem_cache_alloc_bulk() call chain.
>> 
>> Extend struct partial_context so it can return a list of slabs from the
>> partial list with the sum of free objects in them within the requested
>> min and max.
>> 
>> Introduce get_partial_node_bulk() that removes the slabs from freelist
>> and returns them in the list.
>> 
>> Introduce get_freelist_nofreeze() which grabs the freelist without
>> freezing the slab.
>> 
>> Introduce alloc_from_new_slab() which can allocate multiple objects from
>> a newly allocated slab where we don't need to synchronize with freeing.
>> In some aspects it's similar to alloc_single_from_new_slab() but assumes
>> the cache is a non-debug one so it can avoid some actions.
>> 
>> Introduce __refill_objects() that uses the functions above to fill an
>> array of objects. It has to handle the possibility that the slabs will
>> contain more objects that were requested, due to concurrent freeing of
>> objects to those slabs. When no more slabs on partial lists are
>> available, it will allocate new slabs. It is intended to be only used
>> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
>> 
>> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
>> only refilled from contexts that allow spinning, or even blocking.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>>  1 file changed, 264 insertions(+), 20 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 9bea8a65e510..dce80463f92c 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -246,6 +246,9 @@ struct partial_context {
>>  	gfp_t flags;
>>  	unsigned int orig_size;
>>  	void *object;
>> +	unsigned int min_objects;
>> +	unsigned int max_objects;
>> +	struct list_head slabs;
>>  };
>>  
>>  static inline bool kmem_cache_debug(struct kmem_cache *s)
>> @@ -2663,8 +2666,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>>  	if (!to_fill)
>>  		return 0;
>>  
>> -	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
>> -					 &sheaf->objects[sheaf->size]);
>> +	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
>> +			to_fill, to_fill);
> 
> nit: perhaps handling min and max separately is unnecessary
> if it's always min == max? we could have simply one 'count' or 'size'?

Right, so the plan was to set min to some fraction of max when refilling
sheaves, with the goal of maximizing the chance that once we grab a slab
from the partial list, we almost certainly fully use it and don't have to
return it back. But I didn't get to there yet. It seems worthwile to try
though so we can leave the implementation prepared for it?

> Otherwise LGTM!
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2232564a-b3f7-4591-abe2-8f1711590e6e%40suse.cz.
