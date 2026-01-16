Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCWAVDFQMGQEDZKLJ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id D1F09D30550
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 12:24:59 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-64d1b2784besf2411586a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 03:24:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768562699; cv=pass;
        d=google.com; s=arc-20240605;
        b=KKY8W9AAU/gkSOTasJYOaODVPkkNdIHQoNnBugkdqN6vZcyKpd61u1XjRMKEWPwH3K
         gxOBlvTxOAPkXC0gNI3jaQlxa43qpGiFn0rrXFCayc6XfEofRLAqj/2ZOopO4OyUylB6
         GwTBCDEjxn8/3L0WhjBTpNb80fDfNUG8j6N5Yd0Au2L/Bc6sdv1s1IwHWV4f/q/g4QeL
         LfXdpB7nJtsM+co07e3OewCjspeAvGSL61vN79ZbQNMv7H1cmJY8WLGfsvpvCPE+U4/s
         gK2tQxNPrsHbPMQCQF3Cna505kAeEPRc/JviLbhcwX2oFcbK/lJbVCbAxwv+KeeaZSn8
         k2bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=2tE9HRm3zk0dn2e0+7yfAB9fX1dgXXwN2ZE4qPTkJCw=;
        fh=mvKCCu82yVbfHjTEBDxnE7TEienaXCm5cI5X7xfW1Q8=;
        b=hQ3FOfqpkksJ9T4wWQQ8nrCytxtK6ZQxZCOY+vschvhFQ7QtiZGsfWcBd14eXE94/K
         Brh8b/Y88lox6jcy2tU5V8KkANrKc+kTW62YcUwavXeTWxXnVQb2UF2isxkOqKU1vt81
         VYmp/oLzZ0S3SyFlXLWajYOJuqEUU9bvnw12/5w++APycAkLSM80rWI5OhYyT74NPenh
         2Y0YAJ7fcGpDpDnl7DjVTPG2VlYds1600Qz04LwzG1LKMX/z3KNBcD0hz0sN9gfMf59L
         Gz6/FZ5mwylt+06VDOPRVxMoc9ewudd01g/ZuXxy0yXHsS+/vzBFT6UCploq+oIYvqsc
         9a5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=biNtuGN7;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=biNtuGN7;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768562699; x=1769167499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2tE9HRm3zk0dn2e0+7yfAB9fX1dgXXwN2ZE4qPTkJCw=;
        b=dzR7NyE/MaAZFjD6jgyE92jnciE2+A70kxg6iDQ0Pvjw1zWYx42G8Q1/Cr8npYhw1m
         E9rE7ybi+v1Fep/dZbVIecFH6OGg0nPk1lkW2Wv2hcDdianVIvII2J6GydzVMJxUsBy5
         h8kkFISmYefbzjVYPkoyK4LkYt/ktaFp77Z09L5ca/OnaBznzd2EWRMxP8G9rCptiymw
         ZQWQAxobTThgQLtruhMDylLIE7iRydyOlK1ZS2L5FmSwt7hgSiY9v49lNDDRC2wthGmR
         ks2gPEz9jQN/W5GHlRJsEidDY+dhZYQYGbBMszzVMqfLAOu9gpAgm4PuMZbNINniO+qE
         nZMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768562699; x=1769167499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2tE9HRm3zk0dn2e0+7yfAB9fX1dgXXwN2ZE4qPTkJCw=;
        b=gF4l9nJeShv55dhR3FYaIdBwlKK4tCISz+R/focS8nELcCgLXV9u3FLt8N40lbBnyg
         B1ESkOmXoa04OxkdrH1AGO/b5E81M8QN9XT3FETRLR6G0u0l67BFPudlDON2GyRDT4u3
         NuZ21IDwAFuHHWGO8aelpmhWWpl/KxNLkyCpjskkCSvzsexEkdUrf/rij1hr5LuHxi+4
         fmYjF1Yu1KGcbZSYv/hiLbTDBIztuKLzmsKzXhmJWpU8Duabh4KJW2dYfQDZ9RVAkMFc
         j9z+M//unI9iKyQ6RacB+6Kw95uDfCdiwiYv/S4sj06AIsW2j25kRJdxWTFSpp+bJZlJ
         Eswg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWE2AKpEx46O+aR7tdK13DM37YsZHp74tqFL+tHrZ4qDLF/wb+vjZhhfytkBwmJxwJugCfO6g==@lfdr.de
X-Gm-Message-State: AOJu0YxxEZgfnNVl2Zko/q7ri/qsrZxhh/hVIDAKl6+Wf0SuiDLK1Q4E
	8XEVwvi00K1oyycqGNtKwzDIWzG5g2HNASU7SaJi4eAccdRGAzrQSDnQ
X-Received: by 2002:a05:6402:401b:b0:655:c395:457b with SMTP id 4fb4d7f45d1cf-655c395480cmr662515a12.21.1768562699371;
        Fri, 16 Jan 2026 03:24:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HjY/oYV6ZeRYU6pdL6XksygTC9QOexjS4OS22GuHEqMQ=="
Received: by 2002:a05:6402:a25b:20b0:649:7861:d7d7 with SMTP id
 4fb4d7f45d1cf-6541c6e10bfls1642129a12.2.-pod-prod-04-eu; Fri, 16 Jan 2026
 03:24:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCW3+10rsRP3gK04bblZBXQCRnCVzbMNMmRBcmF7BCIhsDEF+/1w5S9m9mE22wPLtl3qvQtWKqSys=@googlegroups.com
X-Received: by 2002:a17:907:7f91:b0:b87:12ad:d4d3 with SMTP id a640c23a62f3a-b8796bb1bc0mr177753666b.55.1768562696589;
        Fri, 16 Jan 2026 03:24:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768562696; cv=none;
        d=google.com; s=arc-20240605;
        b=IOnUzQfXTY5qy6gjDgsB2v4hqfuFQjNlqRaSNviYiLbxsApJMc3u4frijWfCMKUOrn
         ICFo65nTQvl0XMBPlxJQKaXbxKG4fodXdjegpg2POr9PelaOpo3ZbKAu+LQM69zad3ik
         hs7ZfrLFJD9BXgcbovOnM7+h3tJrDoD9x7OopK+o+REaXwbi+RwdFH+uRCXM+uX34M2j
         ubJbslqO6pTmiCakMrp5STyEp0oGaPueiBLy3SCFeCpG4wFQpM6Bw22LFGYA7/sPgChT
         +soGRGVvafdTLiLDQdkpkkROf5gp+gdUAy4UU/UyYNrZCQQnh7FO0Y57ALjo6fHww/sN
         FgCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=EPxWoGREDJBDCfaaqNFnAl/rLl9XxuU79MPtOoauRfg=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=OgacYY4JRnx6f5mexpLavebd9YuwhKFwtcMzl3d/FTgijqu41DInPEH/tbTIpdFrA7
         TeQ3A9a7lowOLK105NOee4EuRlyGN9eK1bPtOWaIC9XYz0dAZtMioqYD6aESMQbd9Q0/
         X928FW64EbosOY2aRLqP8M/HCTnbtDBiuIubraqobAAR4K+y98OQNrghX9v2PG9BCiPC
         fMozwMkKmD/ZFD8jTR2BARBjWCsFftjgc/cHYdX2o1FTFqqpSF++O7q8/Zaan/A+J4br
         9PtKA6Hh/8SWDfFDjk83E6EgiTTss02mTbmyDLy9SFGDfB9I5XIUWfGG+wWlUghVPwJw
         g6Lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=biNtuGN7;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=biNtuGN7;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959b318fsi4940566b.3.2026.01.16.03.24.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 03:24:56 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0C47D336A7;
	Fri, 16 Jan 2026 11:24:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D44ED3EA63;
	Fri, 16 Jan 2026 11:24:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 45r3MQcgamlWMQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 11:24:55 +0000
Message-ID: <d310d788-b6df-47dc-9557-643813351838@suse.cz>
Date: Fri, 16 Jan 2026 12:24:55 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 04/20] slab: add sheaves to most caches
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
 <CAJuCfpFKKtxB2mREuOSa4oQu=MBGkbQRQNYSSnubAAgPENcO-Q@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpFKKtxB2mREuOSa4oQu=MBGkbQRQNYSSnubAAgPENcO-Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.994];
	MIME_GOOD(-0.10)[text/plain];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	FROM_EQ_ENVFROM(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=biNtuGN7;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=biNtuGN7;       dkim=neutral (no key)
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

On 1/16/26 06:45, Suren Baghdasaryan wrote:
> On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> In the first step to replace cpu (partial) slabs with sheaves, enable
>> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
>> and calculate sheaf capacity with a formula that roughly follows the
>> formula for number of objects in cpu partial slabs in set_cpu_partial().
>>
>> This should achieve roughly similar contention on the barn spin lock as
>> there's currently for node list_lock without sheaves, to make
>> benchmarking results comparable. It can be further tuned later.
>>
>> Don't enable sheaves for bootstrap caches as that wouldn't work. In
>> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
>> even for !CONFIG_SLAB_OBJ_EXT.
>>
>> This limitation will be lifted for kmalloc caches after the necessary
>> bootstrapping changes.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>=20
> One nit but otherwise LGTM.
>=20
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>

Thanks.

>> ---
>>  include/linux/slab.h |  6 ------
>>  mm/slub.c            | 51 +++++++++++++++++++++++++++++++++++++++++++++=
++----
>>  2 files changed, 47 insertions(+), 10 deletions(-)
>>
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index 2482992248dc..2682ee57ec90 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -57,9 +57,7 @@ enum _slab_flag_bits {
>>  #endif
>>         _SLAB_OBJECT_POISON,
>>         _SLAB_CMPXCHG_DOUBLE,
>> -#ifdef CONFIG_SLAB_OBJ_EXT
>>         _SLAB_NO_OBJ_EXT,
>> -#endif
>>         _SLAB_FLAGS_LAST_BIT
>>  };
>>
>> @@ -238,11 +236,7 @@ enum _slab_flag_bits {
>>  #define SLAB_TEMPORARY         SLAB_RECLAIM_ACCOUNT    /* Objects are s=
hort-lived */
>>
>>  /* Slab created using create_boot_cache */
>> -#ifdef CONFIG_SLAB_OBJ_EXT
>>  #define SLAB_NO_OBJ_EXT                __SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT=
)
>> -#else
>> -#define SLAB_NO_OBJ_EXT                __SLAB_FLAG_UNUSED
>> -#endif
>>
>>  /*
>>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 8ffeb3ab3228..6e05e3cc5c49 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -7857,6 +7857,48 @@ static void set_cpu_partial(struct kmem_cache *s)
>>  #endif
>>  }
>>
>> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
>> +                                            struct kmem_cache_args *arg=
s)
>> +
>> +{
>> +       unsigned int capacity;
>> +       size_t size;
>> +
>> +
>> +       if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
>> +               return 0;
>> +
>> +       /* bootstrap caches can't have sheaves for now */
>> +       if (s->flags & SLAB_NO_OBJ_EXT)
>> +               return 0;
>> +
>> +       /*
>> +        * For now we use roughly similar formula (divided by two as the=
re are
>> +        * two percpu sheaves) as what was used for percpu partial slabs=
, which
>> +        * should result in similar lock contention (barn or list_lock)
>> +        */
>> +       if (s->size >=3D PAGE_SIZE)
>> +               capacity =3D 4;
>> +       else if (s->size >=3D 1024)
>> +               capacity =3D 12;
>> +       else if (s->size >=3D 256)
>> +               capacity =3D 26;
>> +       else
>> +               capacity =3D 60;
>> +
>> +       /* Increment capacity to make sheaf exactly a kmalloc size bucke=
t */
>> +       size =3D struct_size_t(struct slab_sheaf, objects, capacity);
>> +       size =3D kmalloc_size_roundup(size);
>> +       capacity =3D (size - struct_size_t(struct slab_sheaf, objects, 0=
)) / sizeof(void *);
>> +
>> +       /*
>> +        * Respect an explicit request for capacity that's typically mot=
ivated by
>> +        * expected maximum size of kmem_cache_prefill_sheaf() to not en=
d up
>> +        * using low-performance oversize sheaves
>> +        */
>> +       return max(capacity, args->sheaf_capacity);
>> +}
>> +
>>  /*
>>   * calculate_sizes() determines the order and the distribution of data =
within
>>   * a slab object.
>> @@ -7991,6 +8033,10 @@ static int calculate_sizes(struct kmem_cache_args=
 *args, struct kmem_cache *s)
>>         if (s->flags & SLAB_RECLAIM_ACCOUNT)
>>                 s->allocflags |=3D __GFP_RECLAIMABLE;
>>
>> +       /* kmalloc caches need extra care to support sheaves */
>> +       if (!is_kmalloc_cache(s))
>=20
> nit: All the checks for the cases when sheaves should not be used
> (like SLAB_DEBUG_FLAGS and SLAB_NO_OBJ_EXT) are done inside
> calculate_sheaf_capacity(). Only this is_kmalloc_cache() one is here.
> It would be nice to have all of them in the same place but maybe you
> have a reason for keeping it here?

Yeah, in "slab: handle kmalloc sheaves bootstrap" we call
calculate_sheaf_capacity() from another place for kmalloc normal caches so
the check has to be outside.

>> +               s->sheaf_capacity =3D calculate_sheaf_capacity(s, args);
>> +
>>         /*
>>          * Determine the number of objects per slab
>>          */
>> @@ -8595,15 +8641,12 @@ int do_kmem_cache_create(struct kmem_cache *s, c=
onst char *name,
>>
>>         set_cpu_partial(s);
>>
>> -       if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
>> -                                       && !(s->flags & SLAB_DEBUG_FLAGS=
)) {
>> +       if (s->sheaf_capacity) {
>>                 s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_sheav=
es);
>>                 if (!s->cpu_sheaves) {
>>                         err =3D -ENOMEM;
>>                         goto out;
>>                 }
>> -               // TODO: increase capacity to grow slab_sheaf up to next=
 kmalloc size?
>> -               s->sheaf_capacity =3D args->sheaf_capacity;
>>         }
>>
>>  #ifdef CONFIG_NUMA
>>
>> --
>> 2.52.0
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
310d788-b6df-47dc-9557-643813351838%40suse.cz.
