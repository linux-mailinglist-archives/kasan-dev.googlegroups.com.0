Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFWPU7FQMGQECSU55NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 35565D2D1ED
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:24:08 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47d3c9b8c56sf18833275e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 23:24:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768548247; cv=pass;
        d=google.com; s=arc-20240605;
        b=JS9qORjXH/haxrRWfvCNq8LOdkslikkqEQtuOmM0BRQjApSPP38zrT5Ike+V4Xwgkp
         Y3oYCZqFuvboGlye4ABohzfRFQm0a56ffq/dCIQNYYR6KecDVEzq7gtJ851WqdjEz//J
         LXGIf+z2xJ+mxy+gWbq51LWWMhs5XKGEDygREukSU2tHUQi48v12mxyCHhW+8mjkeO+A
         QAQVjYkwe+ryUrdnEFTnmriMwM7dIfAFlpZuTCrxCPpI7tjvAWv6sECGx6YDNYPb8dee
         ANq2zEEX4+amHZXD0mF9q0e8tj0HWN7IvRIt3Pak6SWtaZnAne49/te24aVU5UW/4wKx
         Vd9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Cy6+Jwfh80oRCtxyMBcsjiZNx7y+gUeKOkKFmsK/eiE=;
        fh=F5B9MhQ4mzdyJDN3+qLTDhbkQEwLywNG5u7wlBIsIug=;
        b=NHE10r0bei7ApMD0V4CrWJhhJptuF4z3z0ELk95kD8yLI2hb2JidJDZHv5gSWMpjAz
         S66sdwTy+EitH+M3CdqU0waDmOOloNnYDi0BWxZ3oTRzZ92N/fWvQamWkn2YyiAYFCv4
         Te930JyBEQeNHLeenVHKx+EitJHKD8lVVJ3M39OR94G20pu7cQ7qMxbbAruufgq6PzaR
         fVp9qumm3RE6GRYz3ZFpMF4Suso5wUsecWKmpo3QQJgocFWdMP9aXuAtUS67NpwI7PsD
         GLSf3U8ByxsuObFVFQykz7a9J40GdNpTDSsMO9t5S/6exfqx5m/pimvYi10dQ95UUCAt
         7mLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OLUJb7Uk;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YhgNMuFF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7p5T4iVz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768548247; x=1769153047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Cy6+Jwfh80oRCtxyMBcsjiZNx7y+gUeKOkKFmsK/eiE=;
        b=etmO4ZAoSAX7Q3BpzgW+Bfg3VtHg7lGZaksH3JLoD2Hs+LxxYn7P2tjiiUafIqbWHx
         OsdtVIicK6KLKP5f21357R6fJVny7FUJG2JXFkgqNHFXin5/lKBBreoHJPlDlO5IH8v4
         9Xfzp7DTX0BH9ktaIoseUrFY07W5Nba+R2A/1v7tVufj+zA/MF10Pk9wKsEj+FCDaaDn
         uxlMcfSgCOH1OoBtWrmLhI0ElYOw+AdTsQA3KMHBMaC5PlPI7S01gdwDmvICguuBiegT
         3cZwX/iesMwdU/FHSPSEPduf47sK36e/Y+1YH/jdiQ8FNdmoIBcss8DA13QWA9p8gtEU
         0FCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768548247; x=1769153047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Cy6+Jwfh80oRCtxyMBcsjiZNx7y+gUeKOkKFmsK/eiE=;
        b=tIVjgfD8wNPN1wsv2AD956S2ngMdijapeL/KO45NCKC/WbhzZgRBGjgkSdgJjZr5e9
         7qS8qJeGevGgIFfJ4HbV590rV+kMqperWsyhVHuaVghuq//D33JaSG6j58b23+08eTBV
         Hs12eDNrk8N6qrUfvV4r1tYHYHRH/f4BkmIQv6uWUTV5AvP5MHudUQ3t+KAWpYfVdAWT
         C7f1kT+wyj84rXJZPMNsOQO2LviaiUjoIPFvPJqftGq+5hYhr5peJLgzEyqMPaqJ1Wrv
         iZ9+6VxOLQLkAfJboTp/BjAPy8bGtA1ZEdEitiDXn1nUSHvJQ9VMnqt3kQfH8ou3A9j8
         3J9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7lV4z+OH8uN5VcEyCQq4Q0YfX9uKuaHOf2qOqSbyCLoJ8WyxMozxIDVers46QiepnitaUxA==@lfdr.de
X-Gm-Message-State: AOJu0Yzt3tRyf4WfS3jeZdoMSoz2Le6WwSYxNmrCFmsRAHIPV6vHyRZ6
	WHjAnOMqjV2zllXZ7n8NtHSHyc+orur+2enE2QXwq/yECelM+ASCeehP
X-Received: by 2002:a05:600c:8710:b0:471:14f5:126f with SMTP id 5b1f17b1804b1-4801eb142famr17934665e9.33.1768548247313;
        Thu, 15 Jan 2026 23:24:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EgsjV61TmeqwzsNiYx0V8ju4WMzzDegUoj4A0MdqfaKw=="
Received: by 2002:a05:600c:3110:b0:47d:603a:6c1 with SMTP id
 5b1f17b1804b1-47f1a8fc091ls10287655e9.0.-pod-prod-05-eu; Thu, 15 Jan 2026
 23:24:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUORq0eSevLZcYO/1KLtM6uNwEeFg0Aa90CM/kzMyyt8ZeIhkvmzBZiGzN6l4qFO705FnMEbV8yORM=@googlegroups.com
X-Received: by 2002:a05:600c:810b:b0:47e:e78a:c832 with SMTP id 5b1f17b1804b1-4801eb1c65emr13152735e9.37.1768548244992;
        Thu, 15 Jan 2026 23:24:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768548244; cv=none;
        d=google.com; s=arc-20240605;
        b=ANGJIyK1SQeviOJ/QMnOVSb2ihQpu7rEeB3X0NLPlesSJW3f+/DSjtyxSrAruiRI6v
         QmiX1XsIsKtLBnNssFalIewUk/QpbidMbSRWRrmnQArqXxyeqhDlrj5wqxwaBBuzjyWI
         n4hfme0Of38ILqKw2CKfFPK4nYysWVd7UMxo+xvjUuNgUmRoPpFkro+X5KDvi+HdoqcE
         lfuhnWeM+S0+bc6UMm9mh0Um0kyv6kQs+1W7c+DG33bZ4capcCYWueiYBzwV8g2SN2jj
         H7EgUO0FY/HmQpiOiiJ9p7UezX9n+34rUvsPUCnG7MkGLVcz1TaHrgKcEo+WLhPTyULl
         D+FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=GPiikwMqJqiuLvHyDiQ9rmcag8VASTg2rI5qe5VsjEQ=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=Y9LSQoExGbenVK62lwQz3zc+WdDp861/VJqemr0tS0RBjNb4tWzGzYt9klMpwAKpHw
         u/nEAkrDpBoL6TWrX1r9XHc4lQVUfAJUcqsV57pfoLibsu0elvTIyErKahzrXXXiKqdp
         qjQs/dblF+l+TMt7kRnGeW50D7XmjVV+FemOhj/uz0nTst7keO+pxpv8/6fVx4eTkjg+
         ekhgcE3v+0We2MIiHKU3Y1YW9ENH23bUz8rWZ7gCzAdpnp2VM/Nw31EMidz4Gfml1GIj
         QGOdPbM0FJx7GgzEKhd4UUIXhM47i5b2uOdqBrT3St6j+oDkhCWJCPMAqCLX+KeHLbHS
         n5oQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OLUJb7Uk;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YhgNMuFF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7p5T4iVz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4801e9b8be3si91305e9.3.2026.01.15.23.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 23:24:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4A5623368D;
	Fri, 16 Jan 2026 07:24:03 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 260CD3EA63;
	Fri, 16 Jan 2026 07:24:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id iiuTCJPnaWkFRQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 07:24:03 +0000
Message-ID: <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz>
Date: Fri, 16 Jan 2026 08:24:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 03/20] mm/slab: make caches with sheaves mergeable
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
 <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
 <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=OLUJb7Uk;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=YhgNMuFF;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=7p5T4iVz;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/16/26 01:22, Suren Baghdasaryan wrote:
> On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> Before enabling sheaves for all caches (with automatically determined
>> capacity), their enablement should no longer prevent merging of caches.
>> Limit this merge prevention only to caches that were created with a
>> specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slab_common.c | 13 +++++++------
>>  1 file changed, 7 insertions(+), 6 deletions(-)
>>
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index 52591d9c04f3..54c17dc6d5ec 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -163,9 +163,6 @@ int slab_unmergeable(struct kmem_cache *s)
>>                 return 1;
>>  #endif
>>
>> -       if (s->cpu_sheaves)
>> -               return 1;
>> -
>>         /*
>>          * We may have set a slab to be unmergeable during bootstrap.
>>          */
>> @@ -190,9 +187,6 @@ static struct kmem_cache *find_mergeable(unsigned in=
t size, slab_flags_t flags,
>>         if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
>>                 return NULL;
>>
>> -       if (args->sheaf_capacity)
>> -               return NULL;
>> -
>>         flags =3D kmem_cache_flags(flags, name);
>>
>>         if (flags & SLAB_NEVER_MERGE)
>> @@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(const c=
har *name,
>>         flags &=3D ~SLAB_DEBUG_FLAGS;
>>  #endif
>>
>> +       /*
>> +        * Caches with specific capacity are special enough. It's simple=
r to
>> +        * make them unmergeable.
>> +        */
>> +       if (args->sheaf_capacity)
>> +               flags |=3D SLAB_NO_MERGE;
>=20
> So, this is very subtle and maybe not that important but the comment
> for kmem_cache_args.sheaf_capacity claims "When slub_debug is enabled
> for the cache, the sheaf_capacity argument is ignored.". With this
> change this argument is not completely ignored anymore... It sets
> SLAB_NO_MERGE even if slub_debug is enabled, doesn't it?

True, but the various debug flags set by slub_debug also prevent merging so
it doesn't change the outcome.

>> +
>>         mutex_lock(&slab_mutex);
>>
>>         err =3D kmem_cache_sanity_check(name, object_size);
>>
>> --
>> 2.52.0
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
e73da60-b58d-40bd-86ed-a0243967017b%40suse.cz.
