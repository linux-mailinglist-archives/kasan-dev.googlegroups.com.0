Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZFFRHEAMGQEDIHNMUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 49EE3C1C8DA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 18:46:14 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-37a0a95ab61sf682331fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 10:46:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761759973; cv=pass;
        d=google.com; s=arc-20240605;
        b=CQz+Tj9Ixo1Br3t9g0Ndc2hMNmOeHglknybzwViu+3eUX3LauzB0PVvex6gOSJW1gv
         OLlQtCoUmLrzS3atryAhu4OW6LQ8r5WhnAGArDQ1pP6dH3Rh95p7EYXr997Low92Y44d
         XHbTNbQbSKiSCKnPKk5zZkdGVisXkzO2s8DfGbHh+o4S1rj8hXOj/Ih1rdmB0UcxAkPk
         lCLv/GLP000KXBA4xZIQXdQKVEXsbvahfexZ+S1vSNEheAO25uTQxABsLtr4zP0NBYLN
         ksjH6DWK08DghrWkDgdZkz+kvY9nMhOK0ZBF9t1Z7dwlk3Dl+VWBLZyPkmvTQojgbAGG
         xAaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=/v88fmOb4PGk+nhSMZxHgJGvMCiVaDMqePSbMNSTuuQ=;
        fh=TSuAvbwIJoasBfj3DnmoyumGr1JDG3dGiQzStpN2G88=;
        b=DX1nSMhScDnCLztgbkV6A8XjFujUN7JzwFp6DWp7MKwI68DkQSjHSyHsDpBUBpxi13
         mtOazoXM/2MedWFKHqYDspJP86cMy+B+/MtQ3wkUqtmVrN4VbsT891Cd9Ve+Blszfel7
         P5KUGJtj0y/vfbX6thtgb92vnEmmJM+iMF+N5seyCTyZeh6crElZD98Vh0VTInizHbIO
         L7L7WesWs643ImU+LRMgxewG4BJy3DG2qUHvN1Qrr8gZ9clH997Aq/T2R4DUMwlHUa7M
         WSo0fprJBc4U7Sgwq/CJvE9QF+Yb+oBCEDfGjWeQ0XFOqzI0nRjHGMtwCcOWdpObCIB9
         2lbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y0vqg8o/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KxFlbH0u;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761759973; x=1762364773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/v88fmOb4PGk+nhSMZxHgJGvMCiVaDMqePSbMNSTuuQ=;
        b=lhO7TbyIdQrJPoOqOYjAm9yJQIxP0o1KsIvacCOn2XMQctERLpTUYgElZinBSr88cT
         JzFd8HhvMs9uRlR0Ql/bI9Bc2Fq0S/h6KKs9gM5FCF6Q7EtrD6zQAXC+CsLglsnsEJul
         Jt5z3hz62TufGqYazqml9W7i+EmfAOi7AOR0vdUO49oLwBTms/4pTzN5tYlVoxoBB53N
         A2rTFYWvQKUWeZsB2QgMEokv+CW7L2zNh1JLDNXrXh7OFSqFznAksVXOQMEdG/+iG+wU
         otAUcOQaA6LS1WFldo6HaqBxmrt85KCclUMJGL0rY6DkypCDHnqq1JQ5qOj/wVMp25PM
         KiNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761759973; x=1762364773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/v88fmOb4PGk+nhSMZxHgJGvMCiVaDMqePSbMNSTuuQ=;
        b=hbnEfeqf5gemI1EyWHRHDBy55ocww4jThW7FaGQhxAWG4fvFgD2qSfMjjocBlpYX83
         1HymhSYuKk+9PmTFo5ZF2zEpZocJ/wLMWSiG67PcUn/rsLbnWiJq/4EY6gz6z07viIai
         ytU7fA7TBMYeZK9IYtVkajmB6D1qBaQOIeiUOCrmr/pARnnSGcwCMAA46484iqRoSbjs
         76mIu5CQxeYBhP1RqMmFh6yKK8b01ZSGNbC7qnKJmhPuiu+/Jo+vB2ldZJGnqTIt1Hdd
         Gq5mPzUVHP0215J722hOF3kSYsgAUkFuv91aA9lH1H6+d3VILYCugpfmNpK+NJodYTc2
         xEow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkBw1kw3KqMRGcyljig2P6uRQSnUtBBUEAxLAFrwc1P6PRFnuoGnjWfBRZqKMBUmZNrxw6yw==@lfdr.de
X-Gm-Message-State: AOJu0YzBdDRZnz27VaSmsLZPaKGRGP7nM0oP9/Nwd2MQylY7lr5m1Crz
	+0UUFRTjpnlFgidf8MPDAP7eqwjTOCKKcreKT3Fxcw31ZLlz487l5qfp
X-Google-Smtp-Source: AGHT+IFFOks6Xud1PZcMFi1YiiUP4OEZURupifmqX9xJA1dJNKqHejM+BFLWqqP/8XApUUFZM1RNog==
X-Received: by 2002:a2e:a554:0:b0:378:ec14:f79d with SMTP id 38308e7fff4ca-37a023cc944mr9713201fa.22.1761759973107;
        Wed, 29 Oct 2025 10:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YkMdMsRxmSdoG8jttPh+0uteLxhxoryyirk9+Wfw4e/g=="
Received: by 2002:a2e:3514:0:b0:338:4aa:556a with SMTP id 38308e7fff4ca-37a10a17737ls217151fa.0.-pod-prod-01-eu;
 Wed, 29 Oct 2025 10:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlmEzvpwkzQiFJb31ha8ZK4//laztDt2cuqYk3k8MFXPMOpiQ+X1H4PZMKmfkBwNAhQ6qunz/c+Q4=@googlegroups.com
X-Received: by 2002:a05:651c:509:b0:36b:b0eb:9d64 with SMTP id 38308e7fff4ca-37a023fc5c6mr13787891fa.30.1761759969828;
        Wed, 29 Oct 2025 10:46:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761759969; cv=none;
        d=google.com; s=arc-20240605;
        b=jfzpnP3MOuL7soPE/w5pMg87c+JeNA9P241PdIVCc2Ae/GPukxYop+VdCiwc5ivJ3u
         +kI+i03UThuNZJePkUP6UTSgPiRBVkwOMLZcuHraxYp3j2vWa8vpvR4agq7IUmAcfLFZ
         FiFzc7P8iAxDYYZKpNdw3W0DTFKxTCLc2PobGgDLK1BFtjlDSo914ydmJcOAb7Hxq/UD
         DtnWpolw6KsvLKDVZAjTd1EYR+OoSRn3GcAzRkrEQHLX4iKha0z/MlQbusDyRpWIc1tw
         okCK1e4BIRDjJQQe9MRabVSwKrfpbOBg/swKRZu64dM1eFEStwJQX8TqoSwhyh/ROodU
         F0Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=F0sZF9w7yuT5ed92au3G/YD+ry/VcKsoeWBjNEV7kJ8=;
        fh=DeHBzlWLBuUz4lrF8r1FiD1LIVm9vx53xH2yAfKWBjc=;
        b=Je5HW+pY56I6+RYfMnWA8dimU/gUyWkiU3apz2cW9Aa5J06GJRH65Ycd5jdWtXd+rT
         9YABX8vzQ6YEj2NHU2vnhBLh8kNPs6bfEIe42iKl+lmehb8PepYs2lY2YHRNR4dimzVc
         wb69TDgrdUxGZ4YCXLCQ6I2+xf/gmfPM9xbWJbXRsfu/IYBLDPoyVD4dhDRf/Ef1mhrM
         lFxJJv8X3ntw09Pq742qlanpJCYIQTCTFDB3AEdD8uNMbq/m4pI+NO4J2eShRrXRKk0U
         d49eY4fSYwN7nLRfNHBfQfyp74p5WmbifWtwg894OwVCv1v1rFqdbvBWNWujVR164LtJ
         8hWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y0vqg8o/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KxFlbH0u;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378f028287bsi2329521fa.7.2025.10.29.10.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 10:46:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E93E85C054;
	Wed, 29 Oct 2025 17:46:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BA1A61349D;
	Wed, 29 Oct 2025 17:46:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RUQaLeBSAmkkdwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 17:46:08 +0000
Message-ID: <8a8271f1-a695-4eeb-9a98-3d6268ed0d45@suse.cz>
Date: Wed, 29 Oct 2025 18:46:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 07/19] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
 Chris Mason <clm@meta.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-7-6ffa2c9941c0@suse.cz>
 <CAADnVQLAFkYLLJbMjEyzEu=Q7aJSs19Ddb1qXqEWNnxm6=CDFg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQLAFkYLLJbMjEyzEu=Q7aJSs19Ddb1qXqEWNnxm6=CDFg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Queue-Id: E93E85C054
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	FREEMAIL_TO(0.00)[gmail.com,meta.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -3.01
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Y0vqg8o/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KxFlbH0u;
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/24/25 21:43, Alexei Starovoitov wrote:
> On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> Before we enable percpu sheaves for kmalloc caches, we need to make sure
>> kmalloc_nolock() and kfree_nolock() will continue working properly and
>> not spin when not allowed to.
>>
>> Percpu sheaves themselves use local_trylock() so they are already
>> compatible. We just need to be careful with the barn->lock spin_lock.
>> Pass a new allow_spin parameter where necessary to use
>> spin_trylock_irqsave().
>>
>> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
>> for now it will always fail until we enable sheaves for kmalloc caches
>> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
...>> @@ -5720,6 +5735,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t
gfp_flags, int node)
>>                  */
>>                 return NULL;
>>
>> +       ret =3D alloc_from_pcs(s, alloc_gfp, node);
>> +
>=20
> I would remove the empty line here.

Ack.

>> @@ -6093,6 +6117,11 @@ __pcs_replace_full_main(struct kmem_cache *s, str=
uct slub_percpu_sheaves *pcs)
>>                 return pcs;
>>         }
>>
>> +       if (!allow_spin) {
>> +               local_unlock(&s->cpu_sheaves->lock);
>> +               return NULL;
>> +       }
>=20
> and would add a comment here to elaborate that the next
> steps like sheaf_flush_unused() and alloc_empty_sheaf()
> cannot handle !allow_spin.

Will do.
>> +
>>         if (PTR_ERR(empty) =3D=3D -E2BIG) {
>>                 /* Since we got here, spare exists and is full */
>>                 struct slab_sheaf *to_flush =3D pcs->spare;
>> @@ -6160,7 +6189,7 @@ __pcs_replace_full_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs)
>>   * The object is expected to have passed slab_free_hook() already.
>>   */
>>  static __fastpath_inline
>> -bool free_to_pcs(struct kmem_cache *s, void *object)
>> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>>  {
>>         struct slub_percpu_sheaves *pcs;
>>
>> @@ -6171,7 +6200,7 @@ bool free_to_pcs(struct kmem_cache *s, void *objec=
t)
>>
>>         if (unlikely(pcs->main->size =3D=3D s->sheaf_capacity)) {
>>
>> -               pcs =3D __pcs_replace_full_main(s, pcs);
>> +               pcs =3D __pcs_replace_full_main(s, pcs, allow_spin);
>>                 if (unlikely(!pcs))
>>                         return false;
>>         }
>> @@ -6278,7 +6307,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void =
*obj)
>>                         goto fail;
>>                 }
>>
>> -               empty =3D barn_get_empty_sheaf(barn);
>> +               empty =3D barn_get_empty_sheaf(barn, true);
>>
>>                 if (empty) {
>>                         pcs->rcu_free =3D empty;
>> @@ -6398,7 +6427,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s,=
 size_t size, void **p)
>>                 goto no_empty;
>>
>>         if (!pcs->spare) {
>> -               empty =3D barn_get_empty_sheaf(barn);
>> +               empty =3D barn_get_empty_sheaf(barn, true);
>=20
> I'm allergic to booleans in arguments. They make callsites
> hard to read. Especially if there are multiple bools.
> We have horrendous lines in the verifier that we still need
> to clean up due to bools:
> check_load_mem(env, insn, true, false, false, "atomic_load");
>=20
> barn_get_empty_sheaf(barn, true); looks benign,
> but I would still use enum { DONT_SPIN, ALLOW_SPIN }
> and use that in all functions instead of 'bool allow_spin'.

I'll put it on the TODO list. But I think it's just following the pattern o=
f
what you did in all the work leading to kmalloc_nolock() :)
And it's a single bool and for internal function with limited exposure, so
might be an overkill. Will see.

> Aside from that I got worried that sheaves fast path
> may be not optimized well by the compiler:
> if (unlikely(pcs->main->size =3D=3D 0)) ...
> object =3D pcs->main->objects[pcs->main->size - 1];
> // object is accessed here

only by virt_to_folio() which takes a const void *x and is probably inlined
anyway...

> pcs->main->size--;
>=20
> since object may alias into pcs->main and the compiler
> may be tempted to reload 'main'.

Interesting, it wouldn't have thought about the possibility.

> Looks like it's fine, since object point is not actually read or written.

Wonder if it figures that out or just assumes it would be an undefined
behavior (or would we need strict aliasing to allow the assumption?). But
good to know it looks ok, thanks!

> gcc15 asm looks good:
>         movq    8(%rbx), %rdx   # _68->main, _69
>         movl    24(%rdx), %eax  # _69->size, _70
> # ../mm/slub.c:5129:    if (unlikely(pcs->main->size =3D=3D 0)) {
>         testl   %eax, %eax      # _70
>         je      .L2076  #,
> .L1953:
> # ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1=
];
>         leal    -1(%rax), %esi  #,
> # ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1=
];
>         movq    32(%rdx,%rsi,8), %rdi   # prephitmp_309->objects[_81], ob=
ject
> # ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1=
];
>         movq    %rsi, %rax      #,
> # ../mm/slub.c:5137:    if (unlikely(node_requested)) {
>         testb   %r15b, %r15b    # node_requested
>         jne     .L2077  #,
> .L1954:
> # ../mm/slub.c:5149:    pcs->main->size--;
>         movl    %eax, 24(%rdx)  # _81, prephitmp_30->size

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
a8271f1-a695-4eeb-9a98-3d6268ed0d45%40suse.cz.
