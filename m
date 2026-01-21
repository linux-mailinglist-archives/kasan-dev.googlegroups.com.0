Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX7AYLFQMGQEUTEYSUQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CGBKFmGwcGmKZAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBX7AYLFQMGQEUTEYSUQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 11:54:25 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id F23315590D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 11:54:24 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-6505cbe401asf6118571a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 02:54:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768992864; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rbwlyn1IRjVWV5ejrTUxAZBkxu5yZDvIhYIZyqNcn1LkF7QAzssCX9GIQpMVYirD7w
         AaaDbjy2y2sKyx53YIKpiuW2DoMR7hO4KLSTRUBLZJOEUFtKzsqVV2H+Ear0wC91X/oo
         h43WYgZILzPUF30uIiGjgkt/YDHpYIzx2T008aPESbYDWdsHmHrDsnR8ZsnjpEah3TAD
         nfsLfT8PhrxfhjY/ikph9UvlNsdT3PsI5Rlkzki90WHN8gLvqjfPU4Fzzrg3yEGvpubF
         c3KsNWpX0UBRCIQEMTVLqqX+gVB33Jbmv0SLP0OjDJ8qwONsCtQH6yrkPNjRbxjqjEhf
         16ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=dA0kWe5wyjKbpgSL2DMMbEEkxSqL08TAP6dk/eD5ZmU=;
        fh=56EkHBGFwSNbxaIe0DabWkyET6PPJpuzQgeu9BiMxio=;
        b=g8irJffSoyCkdcFIzrnoCBBIM+E1wzKUsA1RsCiqKmxEYSd9Qe2p3O9a7ZvmkmoP7u
         WUwBLsVgRrTe9aMjkfyMvPG1ZyMb32DAH9oQT1WkRIVtPmGzHwGp8mEA36fj6DpSwVhP
         luwxgBQt1IeNYHOlQU61slJuSvhd+ntfCYjEpeBCDIzPPm+8HWlbfl2OqntMDOHGddkl
         ePJab0lf87TBS4RBZYm5Nxsu2GtIpc5erFGGRWOWsSMbQTgay8re6OzzTmTqXh2gEUVH
         w+j5xwzZERkERh/JSn7bjsczCCPEviSgiTlJTgKqzjaosSGHIns5fCCF2vX3Cya8tYmS
         1++A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCs9L39d;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCs9L39d;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768992864; x=1769597664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dA0kWe5wyjKbpgSL2DMMbEEkxSqL08TAP6dk/eD5ZmU=;
        b=eEL+xKvOWvi7m6UxbDjdRVYCNSSdSID0ooZ2b5MzwvO1SZN9oYNmbVZziTVGPY3IbO
         sp9X7iLTarubfLCEiRp3Qd08wP7Yt5BSyPXBpM7SHfHXJCESi6JmYKYcahVuyOaK12Iy
         1lS2JR4kKxmxX0iEhk9Xxbygim4AM/OEjQKkPHd8GC4sNKe95wmA+1sZcLyJCsPERRpx
         ZzbatyycsJFNKCOudmHerM6EGHYlf4jAWHV9wdxf2HM8M4vEDR6Y4PJ5kdvAK2pMVYL4
         xWPXS49tcpgjQDRMFOOfQrLM0DgyO/zKCwkswlFzNSkfIRVZO6u4l3skdMOuQmRDCApD
         Ofdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768992864; x=1769597664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dA0kWe5wyjKbpgSL2DMMbEEkxSqL08TAP6dk/eD5ZmU=;
        b=tMqGmWw8v/WspBVvIBBh/V6NclThG7mBSlpXfXP67+HGlfuR33QldXZkzyytL2WRkS
         od1omPB2xIv2OlLSwqA01ewn8hrRuMtlpk6nXnEE08JCPsL1fqwiwY7RSIxdY3qWAV4J
         NE4bs0rykl1qA5evReeJbAnV5A4FeFOkOOCfxgfDIPUhwVqYMsoAPau2AlTQ9v26BNgW
         a6ChKPCoK7jMzZIcqeSZscA6CeHDPNP817a0B98LUc1n4223xVXB6KJwe0OSjzRcoMYF
         Mk0wsFrlfz1pLHluoptH/yQj5sumcNJYKuYAQGt981zeKUVRHHhJq/vEldtVMsMJ+IX2
         LlIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVrHK1damnwNCuNK7DFIp64/lkc083GkC3R8tQV2WAkTb8sdd0xDCSXmIu3GYNFDgzwZDtpQ==@lfdr.de
X-Gm-Message-State: AOJu0YylwZMOV5RLPQHwoBrF14LtUioA+uAgzt+lEYnooY0BjYEBf2Bn
	EJ+yaq61Xi6uG4vXaxLtamQVTC4pxjb5fkYMy70Eb3oseO5OPYtMQV9s
X-Received: by 2002:a05:6402:52d9:b0:658:380:a2ad with SMTP id 4fb4d7f45d1cf-6580380a447mr2976793a12.5.1768992863815;
        Wed, 21 Jan 2026 02:54:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HlkntX3CWTVUTJ+GjuqposT8CQ7OEK93u3vjgTKGi8ug=="
Received: by 2002:a05:6402:3042:20b0:658:21a5:3edd with SMTP id
 4fb4d7f45d1cf-65821a542c8ls196929a12.1.-pod-prod-09-eu; Wed, 21 Jan 2026
 02:54:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWV7YP5y0Hlt8Om2HyNRJxe8q3PUeuHeVWSu6ck2pxR/yW2VGu2jlOF1YgsprtLo/surrZG3Aw0o+Y=@googlegroups.com
X-Received: by 2002:a17:906:f59d:b0:b7a:1bde:1222 with SMTP id a640c23a62f3a-b88003a8a15mr372838966b.63.1768992861546;
        Wed, 21 Jan 2026 02:54:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768992861; cv=none;
        d=google.com; s=arc-20240605;
        b=cNWYO8IpAahFAv0btYW3E6WgDzlE+3v8o0lZNJ6idCcrQG8R8TaczoDW0Zq7eqiJZn
         1YoJB22ktQlT55m9M4cL4NIeF6sFNFVAxtOxB2h/o6oZT/eZk0w5/NWR0+MBsmAzwHM2
         sjEfTIaGZBo0tkS9aVYugKG2p5mYXh+xCMBHew7BiJ2ix7GpVD1LsSTs8UF4qBxOC7/m
         p7cRCvmtFsPT/wmvjOeTSB18tWsgRX9RopYdiveHP5QkASNHv64pnCHa9vpevHuJDrXH
         uv5UhcEU1VYPmy2IHPSgCZPmhvLD/Av1Xa/v0wy9X0LHG96lXbtXu68uvM31pMDUqBj8
         6o/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=7lL5k0cEGVYqwhOMRXHItIyxfFAmPKDrcwpZ8VQ9GNw=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=cGE28z3XRZBoK34wpLGU+kZgVyJf1w8AKFZHGLakrRjOV0A34qh3WutJHD+8oh+0QA
         Urtv5xqholhuhgIh01XSsc7bWSMVK/yY+rmSIv6Jze82/oFa0QIJ6WMbrM692PZXdkQ/
         EjoMzTUlAkX76JggkMtgbsaQakk1hHxjECgincfnqGj4+bmoWpXm064z3SpGCWtt5YLf
         GvOGJtG2JWGLBibjhliR1NyhB/DPhvK+TM9Nl3AnHCdNVl/jWj//Do30rDSulV7CCm6z
         a1zLY/qiEXZtj55jSaYij7AMKpBVeCLHAlYOrzG6rba0Q7QGQ1bH+adpFAxZOf/jjEVS
         kKcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCs9L39d;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCs9L39d;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8794f89946si35528766b.0.2026.01.21.02.54.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 02:54:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0C7EE3368B;
	Wed, 21 Jan 2026 10:54:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D05143EA63;
	Wed, 21 Jan 2026 10:54:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id idjLMVywcGn4EwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 10:54:20 +0000
Message-ID: <83f2ee6e-f767-40da-8cf4-08c6c185b92b@suse.cz>
Date: Wed, 21 Jan 2026 11:54:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
 <7rzlxxqawgasthkhlk2fccync42blr3mehtfbylcsihy7kr5m5@m2bzma4qifo7>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <7rzlxxqawgasthkhlk2fccync42blr3mehtfbylcsihy7kr5m5@m2bzma4qifo7>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=oCs9L39d;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=oCs9L39d;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBX7AYLFQMGQEUTEYSUQ];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: F23315590D
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/19/26 12:32, Hao Li wrote:
> On Fri, Jan 16, 2026 at 03:40:26PM +0100, Vlastimil Babka wrote:
>> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
>> sheaves enabled. Since we want to enable them for almost all caches,
>> it's suboptimal to test the pointer in the fast paths, so instead
>> allocate it for all caches in do_kmem_cache_create(). Instead of testing
>> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
>> kmem_cache->sheaf_capacity for being 0, where needed, using a new
>> cache_has_sheaves() helper.
>> 
>> However, for the fast paths sake we also assume that the main sheaf
>> always exists (pcs->main is !NULL), and during bootstrap we cannot
>> allocate sheaves yet.
>> 
>> Solve this by introducing a single static bootstrap_sheaf that's
>> assigned as pcs->main during bootstrap. It has a size of 0, so during
>> allocations, the fast path will find it's empty. Since the size of 0
>> matches sheaf_capacity of 0, the freeing fast paths will find it's
>> "full". In the slow path handlers, we use cache_has_sheaves() to
>> recognize that the cache doesn't (yet) have real sheaves, and fall back.
>> Thus sharing the single bootstrap sheaf like this for multiple caches
>> and cpus is safe.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++--------------------
>>  1 file changed, 81 insertions(+), 38 deletions(-)
>> 
> 
> Nit: would it make sense to also update "if (s->cpu_sheaves)" to
> cache_has_sheaves() in kvfree_rcu_barrier_on_cache(), for consistency?

Ack, will do. Thanks.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/83f2ee6e-f767-40da-8cf4-08c6c185b92b%40suse.cz.
