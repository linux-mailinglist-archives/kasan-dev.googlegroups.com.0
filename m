Return-Path: <kasan-dev+bncBDXYDPH3S4OBBV4IY7FQMGQE7IEK4MI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UOgBJVnEcWnfLwAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBV4IY7FQMGQE7IEK4MI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:31:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D51D62412
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:31:53 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-59b6a9c53b3sf890264e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 22:31:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769063512; cv=pass;
        d=google.com; s=arc-20240605;
        b=hNnVfmZeoRweb8QMpQA3qU/AMuHVKHikxKdJhYH2Hqry4uWV2u/j+oq9C76yy1VLh6
         rq1dJAlCIQwhn9PAp9gh5uQznkejwJli46/QQFmX8ILPu/Lo4SZdqINCkNTWgo9YeyE/
         fFXm2BtrjX4XLKsNQQ63pa2LkdjirPSlZz2jLZWhE812PjtdC164jefAI4lqZ1A0HwXu
         T37TPfIBtrMWGaw1FeYdgA9DByxsGB3YKwNLGXvGeJ8F0uQ1R9pHbyKtZqeO89CKajKe
         VBetHmFUjKIUkNbUOkYCBkxDu0S1IA6iwhl3w7qKQw8bim3aXaGscegop/3eicWhyeNw
         /R2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=nBcBSHXatBGLXV866K6L+OhF+C1NeaQX5sT9l29P1GA=;
        fh=CXsD52a4XIeyFJ1IKK6EgZ0digFx6gJUocTQvWu1cCo=;
        b=Z09HF0LXGpG3rM4q3vlhjl4tylB0SIyMSjCa2+ueuvuSI9jYyfJvg6OmOyRBDAjX1X
         bYEyUhsdk4rU4AKJYYes8NpjIWQkFH3YaUa3bwIWywZvG3+pMXDMpuTpn1rPkKV6vU32
         rKo0sPg8xUrNuyoo/nAaDCzgyB1OS4YlBXm0KaRLERghdTeg+kl7AdAExQSb5zkPl8mv
         B8LD3hqQFKV/BVEKMevJFDiCqPabBnCwYlnoL5WTi1a4pM0TekdnE+/pXEx+a9wOIbCB
         mo+Y5Vt5L/7J+/uf74s4o6FNTn5NlHgd/+uiPgKFsE8H+xr/EmwhhbPJ6GscP3BB7KFZ
         bbog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zHQ1hoLe;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zHQ1hoLe;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769063512; x=1769668312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nBcBSHXatBGLXV866K6L+OhF+C1NeaQX5sT9l29P1GA=;
        b=P2hPhTvsUjaPyZ/47aeiu/pWnr0vnBTttypGe+qTLYfHDVQlU97vOT9eH+ucfagcyy
         ne33kkegu3hRutqzMwk46fozlcx5cX+Wk7fakDrSqFE0JUgl3/CjySZSGpGcg23IBiny
         VdnfbWx8ROtT/Q8xHGcF0fundOoyUnvw6uNPJ9ipdXk7QvCyT0MpUynXwDN2zy2VrPFF
         zZyxp3zavUA42wMfSqFghNFDE64jPiAV/mbRA+JhHM1tWVUnW6bTwQ39x6cCxB6bWXl5
         VlR7/bzgZcwXm1w3xto/+NbbxkreHY2TC+gYHac3TSedKv6vML3nbZ/Hrwy4IhcW8APa
         p3wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769063512; x=1769668312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nBcBSHXatBGLXV866K6L+OhF+C1NeaQX5sT9l29P1GA=;
        b=s2QZmFe6aXZhRFHfxTooAYctsMpBoHD3LRDf53zvYwAdDHzcn07KT4PXWD3QarSrlq
         fSJLVvvjzgy+v7qBWuf32gMb0cCf93WZ1r9dyC1ht2Rhry1IcvuU1127K9h6TFjglJeC
         /hp0QaICITrfAzdUsZLr81O+QRlvPFjFjeo8oLOu8apd3aiaimk2nnwBTq1tRjj+V9fz
         FFbnTbMT89o5cuOPK5IY/uKmRbuVoC0aOPtvROBCGEg8YgPHWT1kkvkwmYzPHnJ/Rush
         C4U4yti3JvYuW6sNOijOGdqA/limipn9t5c3HS9Ba0C+BxCxLX6SDPF+i408YYid/xR/
         blfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUy4vmndztRD7wiuM8lCKSFm2zsdW5dcEg1UeMeAa3ABkoVrm4OvMAVm+gCugzqN64qBkbAmw==@lfdr.de
X-Gm-Message-State: AOJu0YzyCh8FBkLXw6mnoNVb/N9Qujz+AZGYpKSr4ouUbYl2X9ybFtIo
	6zIb8+rs6TgEtzs5VHo/5556oEDDNfVDHzqh3e81QBi1jKuJU31erqsn
X-Received: by 2002:a05:6512:132a:b0:59b:6dbc:e507 with SMTP id 2adb3069b0e04-59dc9360ec9mr2790440e87.47.1769063512183;
        Wed, 21 Jan 2026 22:31:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gstebh2nJpfxPnpT8yaldQnKQf/QUer+GmaybX1isrjA=="
Received: by 2002:a05:6512:4005:b0:59b:6d59:1e81 with SMTP id
 2adb3069b0e04-59dd796ee2als536996e87.1.-pod-prod-08-eu; Wed, 21 Jan 2026
 22:31:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbDHk7stsX7SZJOfiOwd6wBb0+okY6hLdO+WOufuj2pJnuLeQ/HxkqRuhnL9dEZBAyDaIG8FWAkSY=@googlegroups.com
X-Received: by 2002:a05:6512:b08:b0:59d:d684:5ea5 with SMTP id 2adb3069b0e04-59dd6845f7fmr888793e87.35.1769063509356;
        Wed, 21 Jan 2026 22:31:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769063509; cv=none;
        d=google.com; s=arc-20240605;
        b=JznvACnqdrJfC2bVUwCtmJmaWIDfVbuO1ogEhEGpSaeClHCE4cXQv5Aq+yesczn3ap
         qpXyC5XnQozWsf5I8rhXiRPAB4u5cRzVfHsEJayc1ScEBE0LH5IBrS8nM7hJdijSJKFX
         uOUqQQSDOfKr2msJTMomR14LOMnBN4lwl3lLv7+XYDmuPPVaHiCAkCdIXCDlT527///M
         LZj//m1erosu9h+Esabh0L2qQuQzchz/OxuibB1Z16WafToKIZa6xtPhFUXw9PGA0OA9
         W3dA5VQ7MW1qW5UmyvvqRLWhZe5yWz7qvZbgF4xGECQE9j24UVIjWqHmnb+2LyxqgMsh
         fjMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=snlThi6xEbyLHgpAGreIAptLTtIG/sStzORilk3J78o=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=W2Qs0q3c0Xlfu4jS3A6530xPa9tMAw3/AeN38u29X1ZmvKRu5XtuhRMH+g9UztCBBG
         HJ1VBhIJBxWXLBgEFLALhts87kV8bqWbiMNxTuGvO1cX8nVN+VgKQ0kF7L2KfMeTJMqp
         8LL/UoYVS0Z4QRH4OcHFL7sGtohHUQ7jlGO4pP9kw6ZHJQqceS9a4J+aGBjxMlhnMN74
         n/U4m6kQjKvM+F8EKvX7IOAGlmVbiyuSx5ZDqMFLBStK48WOuXcBJ22CiK33pIenzO0W
         ZvVtnAHn37Nt/FaPWovt7ehmPvqm0Vf8mrGU+Csj4+0J9vlyoW3UHgsXbiADi38zNtEX
         kX6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zHQ1hoLe;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zHQ1hoLe;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf38ed2fsi332386e87.4.2026.01.21.22.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 22:31:49 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 69642336E2;
	Thu, 22 Jan 2026 06:31:48 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 46BC63EA63;
	Thu, 22 Jan 2026 06:31:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id vbnsEFTEcWnTdwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 06:31:48 +0000
Message-ID: <6b48cc0f-f006-4d4c-af76-55f86f4267e3@suse.cz>
Date: Thu, 22 Jan 2026 07:31:47 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 19/21] slab: remove frozen slab checks from
 __slab_free()
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
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
 <CAJuCfpHggP+iefwGTOWnSxDma5U=uMROYNs8KS0A=u2w=1rq_w@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpHggP+iefwGTOWnSxDma5U=uMROYNs8KS0A=u2w=1rq_w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zHQ1hoLe;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=zHQ1hoLe;       dkim=neutral (no key)
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
X-Rspamd-Server: lfdr
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBV4IY7FQMGQE7IEK4MI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 2D51D62412
X-Rspamd-Action: no action

On 1/22/26 01:54, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:41=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> Currently slabs are only frozen after consistency checks failed. This
>> can happen only in caches with debugging enabled, and those use
>> free_to_partial_list() for freeing. The non-debug operation of
>> __slab_free() can thus stop considering the frozen field, and we can
>> remove the FREE_FROZEN stat.
>>
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>=20
> Functionally looks fine to me. Do we need to do something about the
> UAPI breakage that removal of a sysfs node might cause?

Only if someone complains. Just this week it has been reiterated by Linus:
https://lore.kernel.org/all/CAHk-%3Dwga8Qu0-OSE9VZbviq9GuqwhPhLUXeAt-S7_9%2=
BfMCLkKg@mail.gmail.com/

Given this is behing a config no distro enables, I think chances are good
noone will complain:

https://oracle.github.io/kconfigs/?config=3DUTS_RELEASE&config=3DSLUB_STATS

> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>=20
>> ---
>>  mm/slub.c | 22 ++++------------------
>>  1 file changed, 4 insertions(+), 18 deletions(-)
>>
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 476a279f1a94..7ec7049c0ca5 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -333,7 +333,6 @@ enum stat_item {
>>         FREE_RCU_SHEAF_FAIL,    /* Failed to free to a rcu_free sheaf */
>>         FREE_FASTPATH,          /* Free to cpu slab */
>>         FREE_SLOWPATH,          /* Freeing not to cpu slab */
>> -       FREE_FROZEN,            /* Freeing to frozen slab */
>>         FREE_ADD_PARTIAL,       /* Freeing moves slab to partial list */
>>         FREE_REMOVE_PARTIAL,    /* Freeing removes last object */
>>         ALLOC_FROM_PARTIAL,     /* Cpu slab acquired from node partial l=
ist */
>> @@ -5103,7 +5102,7 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>>                         unsigned long addr)
>>
>>  {
>> -       bool was_frozen, was_full;
>> +       bool was_full;
>>         struct freelist_counters old, new;
>>         struct kmem_cache_node *n =3D NULL;
>>         unsigned long flags;
>> @@ -5126,7 +5125,6 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>>                 old.counters =3D slab->counters;
>>
>>                 was_full =3D (old.freelist =3D=3D NULL);
>> -               was_frozen =3D old.frozen;
>>
>>                 set_freepointer(s, tail, old.freelist);
>>
>> @@ -5139,7 +5137,7 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>>                  * to (due to not being full anymore) the partial list.
>>                  * Unless it's frozen.
>>                  */
>> -               if ((!new.inuse || was_full) && !was_frozen) {
>> +               if (!new.inuse || was_full) {
>>
>>                         n =3D get_node(s, slab_nid(slab));
>>                         /*
>> @@ -5158,20 +5156,10 @@ static void __slab_free(struct kmem_cache *s, st=
ruct slab *slab,
>>         } while (!slab_update_freelist(s, slab, &old, &new, "__slab_free=
"));
>>
>>         if (likely(!n)) {
>> -
>> -               if (likely(was_frozen)) {
>> -                       /*
>> -                        * The list lock was not taken therefore no list
>> -                        * activity can be necessary.
>> -                        */
>> -                       stat(s, FREE_FROZEN);
>> -               }
>> -
>>                 /*
>> -                * In other cases we didn't take the list_lock because t=
he slab
>> -                * was already on the partial list and will remain there=
.
>> +                * We didn't take the list_lock because the slab was alr=
eady on
>> +                * the partial list and will remain there.
>>                  */
>> -
>>                 return;
>>         }
>>
>> @@ -8721,7 +8709,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
>>  STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
>>  STAT_ATTR(FREE_FASTPATH, free_fastpath);
>>  STAT_ATTR(FREE_SLOWPATH, free_slowpath);
>> -STAT_ATTR(FREE_FROZEN, free_frozen);
>>  STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
>>  STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
>>  STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
>> @@ -8826,7 +8813,6 @@ static struct attribute *slab_attrs[] =3D {
>>         &free_rcu_sheaf_fail_attr.attr,
>>         &free_fastpath_attr.attr,
>>         &free_slowpath_attr.attr,
>> -       &free_frozen_attr.attr,
>>         &free_add_partial_attr.attr,
>>         &free_remove_partial_attr.attr,
>>         &alloc_from_partial_attr.attr,
>>
>> --
>> 2.52.0
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
b48cc0f-f006-4d4c-af76-55f86f4267e3%40suse.cz.
