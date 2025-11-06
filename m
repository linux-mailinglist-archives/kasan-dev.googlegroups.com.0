Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBE2WHEAMGQE367ZYII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 50205C39627
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 08:23:50 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-6409f6d6800sf929102a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 23:23:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762413830; cv=pass;
        d=google.com; s=arc-20240605;
        b=PHggRfekxRlWM4J+yZBeaLKYHEC6nAHCQxcopoT4g0mX1QIwV0yFv/8/DNV+XYj3Z1
         5l+Q9ztuUgbZ4dDSccoQiHtDujEvc9nbYhx74dOLBNZBxb/yht8saDSIy0sZMNWuLwJr
         2mLq4zY0Wxqz0snm+MD3t8DHknJfitlwQfsBuu4/U7KQy0H52KUGKsOsc2SYCQzFfiJ2
         7FkYKcO8cvp8vvW0IBaLrrx79kxIZc7FoNya7cJM2CwlC0CpK7D5NmQnWB+I9SLvul70
         JDnbnFlfJ7LxxLvhjkGTyJCVdOHF+lD9q7HLREp9UCKM9f+g/gIdAWLmgSMoiooK00WL
         YyMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=lZYzrYhaXay7TtTY3gjxjjUIlS4ENQEOYKYzRTQYfyg=;
        fh=yyRX4mNSpo4Zw6RMfx5XN7DZ6GwGMyiZ+U53odrNOIQ=;
        b=DbxsK8vilZDRaS1CSK4hXXWx8K7y7XwLymooaWgOmaId5SipCJjGBvpIPwQZfJLQ6K
         51PlJB5yY5v+lFNPWSOWKzHyqyt8dvCqDooDAqViDaFV1BB4en8vvxwmMppwpFkY3kxF
         33oeTqNorEd13UyLewTpoYjYN7pd02Vg435WGZKrwUMHW8IVopmYfOV+ZwlB453hVPCu
         SyGwrxg253Ux0gHCFSZMPQnAhQlEj2seWDPZ8bMRUz7K9FZM0GQL1RyYA2ImoeSDNoAn
         g0ULup8pDX4SForHMa0c1hA5PMES7SN4DCVs4KPMtOY0sj096wpfcdEb5RIYKFh/MeFv
         NbyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1ru3bnl6;
       dkim=neutral (no key) header.i=@suse.cz header.b=BsryQK1I;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hkkosBGu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762413830; x=1763018630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lZYzrYhaXay7TtTY3gjxjjUIlS4ENQEOYKYzRTQYfyg=;
        b=p5jCb0/D53WoD+0wyU9vbKDUz5OcBQY+UclXXJx5QeylhHbkT2Xu+av6rUCFcGmzOK
         WL2oJHODWuFmw3dxteE/2W9dvdta781eOVt1v9P/afiUv6PqPLpu2VuYs32PUhSK7o03
         A9wyVUMSVrlYRekCFFcpwXRoHIoFhTgi/YnDbAagn2F3baoiwvFyiUSUCwQPi3kBNMdG
         vkDvub+gSEcGvGxPqRVCUmcEIzgO9PmX8omzw/U5JPXdsWzXdJNIXz31bfs0GwXFXANC
         p1LlR1keM4vb50RpnJ73jP6Hs4OzFvMJ8ZVN0EINbH2h3b7J0H+wPjSbKZhhNvrol2ax
         Mdjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762413830; x=1763018630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lZYzrYhaXay7TtTY3gjxjjUIlS4ENQEOYKYzRTQYfyg=;
        b=kiSYrhxml40kNmBX5VCRN4xNhYu/9ZqP/W70k0Jg15w32RwS+rBFyxrZvu+Xk1KFr3
         FyTL1A6/NwQptW7MyOvW3YKXZEz7NdobgZJCBmsu6I4b+WfU91OuG/lwBOoJJtdCv7SJ
         OWRX9V12dLtetFMbgyqOkekurOQlw4iktx/X/OBXqd4sNxA75oxuuOkSts+Mpo/hh875
         9HHHJm7TDFglPv7olR+YX9PltDlXLt2ZLfC5HwAabTv9hj/rxnRl2IN23ktW8mNl1leD
         w09FsZcwln8Xl9//Ydc1Zr9aAj3j3CjDWytNFTAvZmGkMnYdpvHRDh4rG3rVAZEqHbaf
         K15Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUX1KmfMWaTm8ZDt8JMFc+J36SAGgTbnA2hxNXEaSZOkVAMzI6ia08gGXXvKF2NbymJkIzMVA==@lfdr.de
X-Gm-Message-State: AOJu0YxPhGJ7A5w6avTvqyBzIYV+Qfwh+frix0iTC0iXf9sCLumYSZaC
	YaSEXdNf3Q+bP04EL/9URLLiD5MgCvI+riRaEwZdK1PIdICU0ZKvyQZo
X-Google-Smtp-Source: AGHT+IHx01jjZqvSehbfZBbu+YT1pAAII1Jf5s5c95hiDPkxlHxOuKmYxxzlvwTmw/Siit+7zMcLSA==
X-Received: by 2002:a05:6402:51d3:b0:639:ff5f:bdfb with SMTP id 4fb4d7f45d1cf-64105a5367amr4702917a12.19.1762413829321;
        Wed, 05 Nov 2025 23:23:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aIOqAwJdIBp2lUVD1gW+TAJUTpG81hzCishRGendaIFA=="
Received: by 2002:aa7:ce04:0:b0:63a:a6f:a132 with SMTP id 4fb4d7f45d1cf-6411d8247ccls455369a12.1.-pod-prod-04-eu;
 Wed, 05 Nov 2025 23:23:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2HoBHV9z+twEbt9UHEj3/RjTDCdv56Du13c0BN8n1hKxzhCvUwpdABT3HMJbVb1Dw6KKstMTRxyM=@googlegroups.com
X-Received: by 2002:a17:907:3e90:b0:b4a:d60d:fb68 with SMTP id a640c23a62f3a-b7265154edamr571427266b.6.1762413826676;
        Wed, 05 Nov 2025 23:23:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762413826; cv=none;
        d=google.com; s=arc-20240605;
        b=jxsn82Lr6XgWy/v3vxXLRPx6sJG19uNlp2Jf4yx/2jG9lyLrGpZlLa+tQHwS8xLm6b
         cCBzgKb02vgiMdXJSJ9rbqaSI3rUdklFK9nmalHdihc9GtHYdfQJxcQGGJhsKhxyNfFa
         XmGcFynZWXuIGulrV/yQbQDM3S44F9dZrTS3hNYymyoutCZ4heGIzHINuVyYHOEprhlE
         W8EPLHNj2IzB+hUnRwG8Nj2rtKfEtP+alf/FGnod4i++sWa6pAkatYpU6PJiPaVPE85E
         44C3pbcqnhb85ztrX9Bkjz5YiKglOKA6h5IxDXIqoMne12FrQHA9APGp3wzZts73VtpE
         Ziow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=7KuTnD+Lrz4fdyLGJ4uF39ab38gWiaLaVToVQMrbw5E=;
        fh=4q/Oe4Arytrs1XoYGKfYd618F649p6x1uGoR6xVmJTs=;
        b=IWHeD93l6jA1RjBlnA1QrVP+/d9f9eMSTSEsC9cDJTI52btakf0j0F/7PkcDVRGogo
         VKd8T47EX+2n5w7HzDecOELCkrEHIvwgSMmMnL1cN746wOqo3h7r8cN2jfwTXmv0yu7m
         CXlHdHmPY2BHyURY+w1CerIQfR+LD9qm2l8HVOBtW+xlInTMxvlwS/a/on8iuw4MvWV9
         62tEKMQqM+/MTOGExkqMZFEy4vuCUqz8GCJuKnfDHBYtH3+Mn5YA+KW07HJ5YVilDc1a
         3cPkqkunMQGmD+2Hsjl+qa7192Qs+4uOc5Mefo0VBWnUKyxOpGlfW1FNtXDy+IErRBg6
         6+fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1ru3bnl6;
       dkim=neutral (no key) header.i=@suse.cz header.b=BsryQK1I;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hkkosBGu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6411f8571acsi44073a12.1.2025.11.05.23.23.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 23:23:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D7F59211C4;
	Thu,  6 Nov 2025 07:23:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B68C9139A9;
	Thu,  6 Nov 2025 07:23:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AZ9yKwFNDGk8GAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 06 Nov 2025 07:23:45 +0000
Message-ID: <2d4356a4-a0c1-423a-bd40-af1f8a28fd84@suse.cz>
Date: Thu, 6 Nov 2025 08:23:45 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/5] slab: move kfence_alloc() out of internal bulk alloc
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>,
 linux-mm <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
 <20251105-sheaves-cleanups-v1-2-b8218e1ac7ef@suse.cz>
 <CAADnVQJY_iZ5a1_GbZ7HUot7tMwpxFyABEdrRU3tcMWPnVyGjg@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQJY_iZ5a1_GbZ7HUot7tMwpxFyABEdrRU3tcMWPnVyGjg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Queue-Id: D7F59211C4
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_DN_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_TO(0.00)[gmail.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:mid,suse.cz:dkim]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -3.01
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1ru3bnl6;       dkim=neutral
 (no key) header.i=@suse.cz header.b=BsryQK1I;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=hkkosBGu;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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

On 11/6/25 03:39, Alexei Starovoitov wrote:
> On Wed, Nov 5, 2025 at 1:05=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>>
>> SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
>> allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
>> but it's conceptually the wrong layer, as KFENCE allocations should only
>> happen when objects are actually handed out from slab to its users.
>>
>> Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
>> object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
>> was refilled with KFENCE objects. Continuing like this would also
>> complicate the upcoming sheaf refill changes.
>>
>> Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
>> to the places that return slab objects to users. slab_alloc_node() is
>> already covered (see above). Add kfence_alloc() to
>> kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
>> prefilled sheafs, with a comment that the caller should not expect the
>> sheaf size to decrease after every allocation because of this
>> possibility.
>>
>> For kmem_cache_alloc_bulk() implement a different strategy to handle
>> KFENCE upfront and rely on internal batched operations afterwards.
>> Assume there will be at most once KFENCE allocation per bulk allocation
>> and then assign its index in the array of objects randomly.
>>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Marco Elver <elver@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 44 ++++++++++++++++++++++++++++++++++++--------
>>  1 file changed, 36 insertions(+), 8 deletions(-)
>>
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 074abe8e79f8..0237a329d4e5 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -5540,6 +5540,9 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, =
gfp_t gfp,
>>   *
>>   * The gfp parameter is meant only to specify __GFP_ZERO or __GFP_ACCOU=
NT
>>   * memcg charging is forced over limit if necessary, to avoid failure.
>> + *
>> + * It is possible that the allocation comes from kfence and then the sh=
eaf
>> + * size is not decreased.
>>   */
>>  void *
>>  kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
>> @@ -5551,7 +5554,10 @@ kmem_cache_alloc_from_sheaf_noprof(struct kmem_ca=
che *s, gfp_t gfp,
>>         if (sheaf->size =3D=3D 0)
>>                 goto out;
>>
>> -       ret =3D sheaf->objects[--sheaf->size];
>> +       ret =3D kfence_alloc(s, s->object_size, gfp);
>> +
>> +       if (likely(!ret))
>> +               ret =3D sheaf->objects[--sheaf->size];
>=20
> Judging by this direction you plan to add it to kmalloc/alloc_from_pcs to=
o?

No, kmem_cache_alloc_from_sheaf() is a new API for use cases like maple
tree, it's different from the internal alloc_from_pcs() caching.

> If so it will break sheaves+kmalloc_nolock approach in
> your prior patch set, since kfence_alloc() is not trylock-ed.
> Or this will stay kmem_cache specific?

I rechecked the result of the full RFC and kfence_alloc() didn't appear in
kmalloc_nolock() path. I would say this patch moved it rather in the
opposite direction, away from internal layers that could end up in
kmalloc_nolock() path when kmalloc caches have sheaves.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
d4356a4-a0c1-423a-bd40-af1f8a28fd84%40suse.cz.
