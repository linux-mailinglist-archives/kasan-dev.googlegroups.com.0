Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDOS3TFQMGQE3XEJ52Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OHQ/Hg8pd2lzcwEAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBDOS3TFQMGQE3XEJ52Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 09:42:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1DFB8592A
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 09:42:54 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-b83c3dd2092sf459339066b.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 00:42:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769416974; cv=pass;
        d=google.com; s=arc-20240605;
        b=i7MHfHjJMDX7CxAXiW49rMG5d2TYg3aApoP0wh4mpmQ2n1SipWwZug1+fq1QBStJ8T
         1aGXTFbcYzwPPAbDgCb6SscfMtVm1zm18/a8sQB5/TaQp2pG2IwTg3qgd/4MzFeATjs0
         YbXPezpWHQogMCTWt4OXbJmaEPHTXlb+up6elKF7mNWHybqr6hFjTKIUe+gb6ZT52/zu
         XPf4GG03/n5A8yhKWteRrSA89zNTnyrGOus4yKAKzQyOh6kzw+m5ZEMdsdqA4phNtK4u
         C/jWeEqTNUP2PVMUC/BG9F9/Suia4TePK/pC5Feksk7qrCZSWZ02H+n57ts38JnZioic
         Wp/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=6j4g69+AE7C3Nihpc0LDtEDDeulAaCAlLQ4CqtH2koI=;
        fh=JYbm5N8vbgwx3N0P12HXlFjSUnDsW3/H5pRLcbAsir0=;
        b=kqERS9nJquyALath/mM8T0Gmefo6FrzfqvuqRD7LF0IoCFqy0asTVLvYCo8Gz4+22B
         dwAjvd5LVdYq6YI6jsXaUY3RL3gRewwiq69Pm2swOcs7lX9g0PcJgdEh2/jz9QaBrss+
         jbF3J5TzhESf+JVDocmtU6mGYOwnaLJZE1vk2uaiYHKliwryRLAUFr2AqPHNaQXAT6sv
         r7Xc022wqj6aDNiBuvlIJY/Qkw41N8+FPn4dKe5tsOwHsbillLNCP3ia+Jl8bd5Ve1Mp
         p+Yqek/0kzpiPzBc38XxHIeJTA5lggaftHewp49FA8f/wNiLgtrXMKrRxFXOhsHWC+q6
         lK3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ODTiACZL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Q/cm50UY";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769416974; x=1770021774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6j4g69+AE7C3Nihpc0LDtEDDeulAaCAlLQ4CqtH2koI=;
        b=JNEqvgJrurEnNE3+aN7HxLXUSiHH91LQLbT7YQybdLO2e2D24nZ3jKP5tBH8IDoBnu
         dC8oqVATC71IvebvowqkRem1ayrMewlQ+ComppLOwWC4libFnWy21bMCvNHeAQ3ZyRaP
         3qsbG5VqSBspLXD4eL+eGuCcz5diJy7cG18Xpl9h1qDq3goLdv5+Wd9O0b5vrRjkyDlF
         Afh2qtLbjRaomtlIf2wPWZsUxG+5HEK7j2D7F7rkAOJjU6QsAYAppDiO8u3bV8WJ95NS
         7Eqq0vzRezBhYZpzef1SiisjdWvutpXmhkYep0H1FHPfappi0Iq0tgl6XepgzSim7nmg
         dwyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769416974; x=1770021774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6j4g69+AE7C3Nihpc0LDtEDDeulAaCAlLQ4CqtH2koI=;
        b=NHU6/QJ23f7JxZ5YPtKkWWSssvZ0bbyR0uFXYeNGROwBafvH9D8sS3eqcDI2iT3k7C
         g0ym/0SZJsi1JY3DOLEB5IUUX2eTN7LRhc/86HkOcMprkme60ATIn6BXVE04JMn4gaPB
         rYEu5JQvneDzITyCTJjDaxyN7pu2ijxWb1viuXrhFUffVi1d+5CIj8VM3crMq0A3MyoC
         FKDW3w/YDYUcYZnMGbecVDoukYovxqx4vKgym0crzHIv8zHV2ENgaSa0nlhYrokNN+fT
         5aYlJQzSzZG7uQKJnvZ5mVTD8IYR+SlydB1CZwCBf5RSSZb43YH9Plr7JYJQ5xsrMNED
         fKTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWT8u+L8Y+NKZEMupAXlwHM3OAtNNrTTBu+G33DoBsgkF01rhBq2VauJ4I0pZS6p4AcCqzFrg==@lfdr.de
X-Gm-Message-State: AOJu0YyzbizAguv6gS070GijyVs2sL1sF1Av6vBA7HJcXFvuEx3kNGbx
	aNy5NFmMq14+oiN2MqlKQRPpT2MSnui5zspnYT57SKBAK8DhwO04svbi
X-Received: by 2002:a17:907:c0e:b0:b87:d839:ae8 with SMTP id a640c23a62f3a-b8d2e850e73mr265871166b.54.1769416974102;
        Mon, 26 Jan 2026 00:42:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HzPOSy738K1c6oVI9bAUw7Hh8tUpi8J7knUeuY5Re4dQ=="
Received: by 2002:aa7:c916:0:b0:653:9932:b504 with SMTP id 4fb4d7f45d1cf-65832d80f8els3246634a12.2.-pod-prod-01-eu;
 Mon, 26 Jan 2026 00:42:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvKaHged3L5PHvvKGKQExhajb7R1bEC4detpGzNfWZUguRrQYPEuvyReP2fUr5QQ0hTMTzZizo3lQ=@googlegroups.com
X-Received: by 2002:a05:6402:2813:b0:658:337f:1577 with SMTP id 4fb4d7f45d1cf-658706dd427mr2630343a12.30.1769416971760;
        Mon, 26 Jan 2026 00:42:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769416971; cv=none;
        d=google.com; s=arc-20240605;
        b=WDrEVsEsn7eBP2WlIVZfSB3bNGBbNwZUl7cAKH13Idt35Yq4bkQWE6G5AcgBlMfTNL
         PPu1MkhpKRh+5P6y317dJEqTwxhiqIzaZY3BJOvb8cH/EyKsFWzbUWLRmF3rYAY4uF9t
         +du9xWLDHKa3iVhBD8af7sUJubwoEZFPrZcAlzGPaPeaGVZ3JE6Cn+7Azqsa9FNW1WYI
         huV4QlLdwgDC5oRWRgTcjvqGc3CaXCygKDJUNg/coYHliBIpfx+mKNr2yXndJo9x+P7H
         O7AQTRodEYhjgyvd+mspKhJXk4YhKkjOO2MbFXhJHZWXWPY9sLLCrSm5Gfi3LRsIbV6P
         sR0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Sgs+T/VXcMnUbDMuJnWkmVFhshs/1VjbTRgWWbUlNSI=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=deJe1z8DmWxAToHJg9efevO5WRX/B4uZ5xGa7a0kVzk5RImVphFnva4CsMwg+UOEko
         X3bVizlbYz06cwsZy56tcb/sK/aqxDGdFIbFC8i9D7jzjjQVDDvtIILwr4kQLCAJCAeQ
         o7GwLYxOORZx++uBX7c9syaV/loIgcb99HDfnxRXBQsv+yxCtlukmptQVHzasX/gK7XI
         BDMobnV0nBFUuQGi/JuojtbDbQ8G9HshytYanvqgx+UgkrqL4iqgYvIOsxDYZb3v8SfS
         iLj6P6tvKYoI4EfbqbMk+k+BINOzVrU+9Ogg7wxnqH69Vt2aZVT1bmWH0+F72VAtZukh
         BTUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ODTiACZL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Q/cm50UY";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b927e43si203250a12.7.2026.01.26.00.42.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 00:42:51 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3F3005BCD6;
	Mon, 26 Jan 2026 08:42:50 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0BEAB139F0;
	Mon, 26 Jan 2026 08:42:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id J4x7Agopd2ltKwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Jan 2026 08:42:50 +0000
Message-ID: <0c337f99-98b3-4955-b9aa-6a5e9bacb041@suse.cz>
Date: Mon, 26 Jan 2026 09:42:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 07/22] slab: introduce percpu sheaves bootstrap
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
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
 <qrekwm7js5t4kmahu3toqnrepnvk7ve5h624f6hm262mmybvtx@rewwd4rbvf3b>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <qrekwm7js5t4kmahu3toqnrepnvk7ve5h624f6hm262mmybvtx@rewwd4rbvf3b>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ODTiACZL;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b="Q/cm50UY";       dkim=neutral (no key)
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBDOS3TFQMGQE3XEJ52Y];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim,oracle.com:email,linux.dev:email]
X-Rspamd-Queue-Id: F1DFB8592A
X-Rspamd-Action: no action

On 1/26/26 07:13, Hao Li wrote:
> On Fri, Jan 23, 2026 at 07:52:45AM +0100, Vlastimil Babka wrote:
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
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slab.h        |  12 ++++++
>>  mm/slab_common.c |   2 +-
>>  mm/slub.c        | 123 ++++++++++++++++++++++++++++++++++++-------------------
>>  3 files changed, 95 insertions(+), 42 deletions(-)
> 
> Tiny consistency nit: in kfree_rcu_sheaf(), there's a remaining "if
> (s->cpu_sheaves)" that could be replaced with "if (cache_has_sheaves(s))" for

Ah thanks.

> consistency. It's trivial, so no need to respin - happy to have it addressed
> opportunistically.

Actually we should remove it completely from the fastpath per the design, as
__kfree_rcu_sheaf() checks that. Will do.

> The rest looks great to me!
> 
> Reviewed-by: Hao Li <hao.li@linux.dev>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0c337f99-98b3-4955-b9aa-6a5e9bacb041%40suse.cz.
