Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUPLW7FQMGQERZGQAEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 30D85D3A292
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:13:55 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-64d1b2784besf6443425a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:13:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768814034; cv=pass;
        d=google.com; s=arc-20240605;
        b=XyajusS+09ejj16N6e02oS+7bZbELbyqKvvZqELr2vAmibDKOl/oMM64BIE3/5Sx3K
         es0qbhhW1eY73HK4YdWYRqa3hfw02cBLw/wk7njhi6rOk7xmLMwgOYBaNmfcjfKZO1Nv
         P3Uc/phZh8QhqskuRqVZn8gmGW1y4KuKZapsKNcJBLZFy/UNAArQQ7oLjIzj6qWbhaUP
         Tf5zixR0uA47OdjEowVJYtRI/1WySNzJgJeZITIyBdBknie2uKw7l4AbbGooxrSYUqs/
         Tmi0zPTrJtagrPWOAnIYMHLQpdkmkRJJaXcur3B89UYzy3LmrAIqS4FD4ysmJkGCO7V1
         Hoig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=t0CiZLzTa6idJLWFaX4uJVqbL0gCb15U4yOrIdo3+T0=;
        fh=LIhasJ764nK3V4EJtpXpbf1R2+QodbyhCWKLHMM46bE=;
        b=Okerp59emPD/Fwv6xuhhA+jEvmvLoAyUR2SzITpoEPnSg4SybQDFJuqD6Vm4CPnYa4
         u2FR644dHDpZvYKhXbEbCv8xf1hNrByHq7kKt/jFstHor3lJ6O0EfzWBM2k2kvUwkn8h
         L8dsmWJfQrXWiSCLUYjFobWwR+jWPbNKamHPco4SUER4OrWJgLLVfGaMLWKeQXR/3ug/
         sN7kynS3X2SRSIgS5dhiQvMNXOuTrangzk5KypxkhK2t0yUKysLwIlhpdut2aGOnFKfU
         +QCkaOTG92rS+TqPTYY/BGcfOWIw8IvNWdL9U71VGJ21bvjNDlpgfGWeCK3+SnGYY34u
         Ua6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;
       dkim=neutral (no key) header.i=@suse.cz header.b=jYX9y27W;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768814034; x=1769418834; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t0CiZLzTa6idJLWFaX4uJVqbL0gCb15U4yOrIdo3+T0=;
        b=EO9eoxA5ctiLQSoSga4Cq3H9kWIM/pI+xfhYW8haMarfv5JjqwUtB0ImgtCH4jMf4L
         hyheNuOEdZ3zZw6WiZarGVt3wuOsVqKc1c0OATonyfkmlu93U0/zyd0l8QPGHWYBqvfX
         mbcyMvVq0MJ+eZkOc7IlwAAKcH6nbyx3Mg1N9QMOA3xr0zaGR1WrBxctzHBj35myxSnX
         y3wpN6yqPu2ojBqyRKtHT1Pv1DvQ9e0bIQb7e0TGYyqRDREM4Qu9Vjkc4SEHbasXRoQ5
         0rzmRVNSF45NmmF5OHTuomWaA5KH7xJ4ou16R/LqgSeFSzLv14EBeZVHLxaqVluVr9cy
         pADw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768814034; x=1769418834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t0CiZLzTa6idJLWFaX4uJVqbL0gCb15U4yOrIdo3+T0=;
        b=q6mO5sfD5Qge8r/SFldQlraqrypIPvtBtrMIgfpWKTQ1S8wAC0F2gMykBUmDq2++wN
         5R4BmWnmmD8eu91kOt+MG1/qs/4EPXX3mAWdDujeZj2CQis6pGt5vinfcsVP+gLq/wRU
         vEouiFV1dlIFL9At3aCHkSsP/1RfMK1B52eMvHMFz2mw5HdmSj4JH5Iqxmzc71kQvGtK
         J82PoGKFSx+lPVHtJgy4acPSPXtEVFyMlx6oWjW6MziCG48ljvAyRwKs3Lt5NOw8cUrs
         WNGM88DukXmVWTl4QPQ5edHOOA/NF+ljBTI/uZdc4RHQ3LQPDOT2qZnT8X8lmyA8bZxx
         7BKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdF/5qNJTkC0PSFgTwWiGKtXJPPQEl/pf00Rm7KXqrt+dskrstXNffVTRePWx5DmSL/FBaPw==@lfdr.de
X-Gm-Message-State: AOJu0YwFxIpOEp+ONPrx0eAwHwpShISK+gAjgKpp2iVSm4F9qvi0HR2O
	1sDJ2Of7ymozevfqLEoTSpENN7y1EQvOouwN9TPOoKx31ld0NAsjEw7G
X-Received: by 2002:a05:6402:3511:b0:64b:416a:cb48 with SMTP id 4fb4d7f45d1cf-654bb236919mr8006135a12.19.1768814034387;
        Mon, 19 Jan 2026 01:13:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GvPO0CReciPl2ThXLzPYVeJgxXBJ/ZhM/jZO0B9tS2uw=="
Received: by 2002:a05:6402:a25b:20b0:649:7861:d7d7 with SMTP id
 4fb4d7f45d1cf-6541c6e10bfls4509418a12.2.-pod-prod-04-eu; Mon, 19 Jan 2026
 01:13:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQIQ0s1a6dTe4Kfj35QnNrwlpiaOwH7aOt/QC20C451YvXxYIS+Upn1Ve8IEODk/DgBDQxnPRgMM4=@googlegroups.com
X-Received: by 2002:a17:907:3f1d:b0:b86:fca7:3dbc with SMTP id a640c23a62f3a-b87968d0c90mr956891866b.12.1768814032116;
        Mon, 19 Jan 2026 01:13:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768814032; cv=none;
        d=google.com; s=arc-20240605;
        b=Nw/CqgU8iH6QcwOOCPjGV/LfyPVSrZHy/llMcPws7i/onCyfb4VC7t1uDBha5eQABp
         WeIUUagckTob/y4txlakkjK4PyUZZCfvXDLZxew8VqbT77x2BpC9oGz/N506vBgY/7p/
         P2fNm3QDEOEyCgoeDAnCb1XvqyFSY+SeG9P2LlVGE2FLjgnHuTPM4z5Ldi5LQ6L+N4UL
         2aiyQzSUMmFAdLPshlCNkZOCETfxIDY5LlBi7Ybjm3mbnFh2vi5sJhrNphiHmQwY3kPS
         lTLbArl5fMd2wQuosYVju9Ay9Ma/QI2jE5tbKV8hUQlbY8vzyN+pvR7jbPd90tDprStK
         QcDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XhooBqjIFB2Zss7F6dtPfbhQAxjPz0yCTX0IY1G6TwY=;
        fh=ZwYQjARiTFQ+fTNBunpxmkQMfRX2Mn4XzLRX+yobm5g=;
        b=Z7zAKW2DmIlG7qeyhCXzz2TOvv2GRT+6vVl2BuuVjDgJKrrw0SsFY902PfyQ6jvuWw
         QQD+b4JB4msYHGLHSKMhNq2FrGEJ1z7Dl9vTG5xHpiQ9cdPkAkA+twjVRsc3q851A1Ie
         0yEs8nqS8gZD7xOMn7MzleZioHVAnTsR2GiU42Hg5A1J3w9h+/JtlYWqFrzUesgZG4LH
         YKe6PJs/Ja9mdId2AWuzpMMu+9hN4tJ8KtwL6NGA1py/Z4id2qK1fj4c5LxrPvOvRYtf
         pBhhsndHl6D78KZIANF5S4xgbQblGo1ooBRDqRZgEQHSpQ+bQgDIemOdznCgvgRqfNiW
         r4Mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;
       dkim=neutral (no key) header.i=@suse.cz header.b=jYX9y27W;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959619dasi15684666b.2.2026.01.19.01.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 01:13:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8B814336FE;
	Mon, 19 Jan 2026 09:13:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5D7AD3EA65;
	Mon, 19 Jan 2026 09:13:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OFZ/Fs/1bWnsQwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Jan 2026 09:13:51 +0000
Message-ID: <41048e09-5dd9-42a6-b5d8-dadee3ecfd9c@suse.cz>
Date: Mon, 19 Jan 2026 10:13:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>, Suren Baghdasaryan <surenb@google.com>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
 <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
 <aW2nlIlXFXGk4yx1@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aW2nlIlXFXGk4yx1@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
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
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;       dkim=neutral
 (no key) header.i=@suse.cz header.b=jYX9y27W;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=quUkNXI8;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/19/26 04:40, Harry Yoo wrote:
> On Sat, Jan 17, 2026 at 02:11:02AM +0000, Suren Baghdasaryan wrote:
>> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
>> >
>> > Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
>> > sheaves enabled. Since we want to enable them for almost all caches,
>> > it's suboptimal to test the pointer in the fast paths, so instead
>> > allocate it for all caches in do_kmem_cache_create(). Instead of testi=
ng
>> > the cpu_sheaves pointer to recognize caches (yet) without sheaves, tes=
t
>> > kmem_cache->sheaf_capacity for being 0, where needed, using a new
>> > cache_has_sheaves() helper.
>> >
>> > However, for the fast paths sake we also assume that the main sheaf
>> > always exists (pcs->main is !NULL), and during bootstrap we cannot
>> > allocate sheaves yet.
>> >
>> > Solve this by introducing a single static bootstrap_sheaf that's
>> > assigned as pcs->main during bootstrap. It has a size of 0, so during
>> > allocations, the fast path will find it's empty. Since the size of 0
>> > matches sheaf_capacity of 0, the freeing fast paths will find it's
>> > "full". In the slow path handlers, we use cache_has_sheaves() to
>> > recognize that the cache doesn't (yet) have real sheaves, and fall bac=
k.
>>=20
>> I don't think kmem_cache_prefill_sheaf() handles this case, does it?
>> Or do you rely on the caller to never try prefilling a bootstrapped
>> sheaf?
>=20
> If a cache doesn't have sheaves, s->sheaf_capacity should be 0,
> so the sheaf returned by kmem_cache_prefill_sheaf() should be
> "oversized" one... unless the user tries to prefill a sheaf with
> size =3D=3D 0?

I'll add a

        if (unlikely(!size))
                return NULL;

to kmem_cache_prefill_sheaf() so we don't have to deal with oversized
sheaves of size 0 just for this theoretical case...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
1048e09-5dd9-42a6-b5d8-dadee3ecfd9c%40suse.cz.
