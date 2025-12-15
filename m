Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOGOQDFAMGQEG6AAYTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 47464CBE97F
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 16:20:26 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47799717212sf29927105e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 07:20:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765812025; cv=pass;
        d=google.com; s=arc-20240605;
        b=g46xYNZgul1pBYQEuwgIvpy9kLtOhUDby0v4Bvf2pxhrLHt3pZduY9g2n+t9bG5YDs
         YHBeoo5J1Htlv1mqvfVzGTZ47y4SK8SCREmGpVT40WL1QM1Dt0MTGQxzXX8B66+OrQka
         d1+jP0/WfR871XiCwcFDMSCbDzEgDz1HGKHWFjFxjB9BuMEx7HPaFs429QQpQwtKule5
         A0PeJdS5ab0eSL4ZM54VsiMt3QRGoR17LR4XM19HhltmQL7F5DMXBeMsTmOPON5y9fy/
         n8mJtmEnpHF5jBJioXikoCOQqeJf9s9h/xSFRYWY+DB92di68abk/DWyzEk163m1eqf8
         Te3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=4wShzDnSMYsNsWZXrvDCbY3TF/PGSbOg94KsqvIaCqc=;
        fh=MhWn4bVD3RR/Ca2nGOqQzgktqIC3lFQcrl3SxMef12g=;
        b=Dd65MCDRaJXt4Q9Rd7t7/8sSwrYWs02S2fOYsvf0iCZDSsLQOlU7WYa8VmBm0Pp1zg
         u3phTLact2v4T0wD8flOvkU/Qi2WK6uav5VrK0/9ZyphggDblgCt+GawTFOPnbDUPtGc
         oo/Pg3IMpf1tbgatGuOzKlB1GC1+NNCxP8gPGtCAa1Od8iwdc6NHIGqObs2cGhtAgZ/v
         8WY1FfKPfKXIqgQui+WffsZ+1lXYnM2Y9ViP/bdgO062UVN7zqQZMFytJstOvudtCEb6
         g6SpcF1mo6vWJcHFKXLGnY2PC4de/DDzARHAas6lHyoOWmBr20GgXOYZe0iJ0kehiXfB
         r2tQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ekZ3+tR1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E7lDI2Ut;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765812025; x=1766416825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4wShzDnSMYsNsWZXrvDCbY3TF/PGSbOg94KsqvIaCqc=;
        b=SVwh46eka2VgIAKb9scG8y7iuxHVjbTTkM89XpyMOOY6T6r7Dydkx4T7XOJK4rCg9C
         QLK3xGlhFHwEN/FS3PUUWncZVxh1m/Cot+3pxoP+eGHW2neovrcL1rsxZOYhtVcPCWum
         Wt/wcLVyf4lfJJEmesnadVbYrIr3aqERrIiZ7ECk05N+bvksCeYA/IBn6trB55xEgtI8
         9AorQqiPgI66W0LR18nu5bFr8vlapm5CV+zkpY0Jvykm87HdPA7bHe9ONfXtsN7Z/sWa
         3jyY4R5UKd+XJAqkMxanm/g5UFHU4yZA8rW/pBdnJ0h2QLfvzrTd4M8ZqOwp18RLPMsl
         LAgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765812025; x=1766416825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4wShzDnSMYsNsWZXrvDCbY3TF/PGSbOg94KsqvIaCqc=;
        b=wxFF+TJnssNB8wyqJC/Kke3PI7qrinIJJw6iCPiv1LsuRLr/mvifkuOE9qQ44WEGh+
         EO+7QqkfO0OsenbiEDdTC0O+povz1l67QQeI41FH2+5Q2gcdvxxi7jWZgeZadQIsmkgq
         JlbXB0ulnq1b4j8YSJi5ZKGCfxZ3ws9bA4b2sYKavIw3HB1FgOTJ4bvLFn10Vyy3eJHT
         G0y4vLLiQbGBOu2+i9QjtCpOLonCezoAC5KkdRy70Um8aNDrmce+cUPGWvdVYkPfXWBh
         O94uF/HLD4QsiKyCPZFFDqobynFTjNaHu1Cb2Z4vL20GW6DwCQDGD50GQcSIjll98vxd
         MaYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzTOgX4MADg1YAcZcj6o9IFBpGTTGJSdx+qGbyFOVVATKhebO4WV5m237KdeFSE8bOmJ/Auw==@lfdr.de
X-Gm-Message-State: AOJu0YxD86zuz+PRbHDGTGF3p98e4IYql+aOEL487B56NcYlwhw9HMJN
	njjHnzw88Ppx6yYYRChB+tBJfhGhX32F52H81cKPGUOvxCsMoSabIjKT
X-Google-Smtp-Source: AGHT+IHgUOeG1RE/pLBKSbmfICv4+EkZT5RqOL0y9f6k4KmvBM3/2AOkiENBcOyVR/62SozAbGzPnw==
X-Received: by 2002:a05:600c:4e4c:b0:471:114e:5894 with SMTP id 5b1f17b1804b1-47a8f90da04mr124126625e9.25.1765812025500;
        Mon, 15 Dec 2025 07:20:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaXrQGUbj44LXfU4eKaTk39/4xhS2az0IjfdEjZk7Bd8w=="
Received: by 2002:a05:600c:46c8:b0:477:980b:bafe with SMTP id
 5b1f17b1804b1-47a8ea5b5d4ls21210775e9.1.-pod-prod-04-eu; Mon, 15 Dec 2025
 07:20:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVsMVZFqfjqSOEKjftGqe/vtEdf7bF+nkHHDzAhKdsAsJWilbAsSoGE5xv361QJGfSFJ4lVq5NbQA8=@googlegroups.com
X-Received: by 2002:a05:600c:6912:b0:479:3a88:de5d with SMTP id 5b1f17b1804b1-47a8f91dac4mr123182065e9.36.1765812022750;
        Mon, 15 Dec 2025 07:20:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765812022; cv=none;
        d=google.com; s=arc-20240605;
        b=ZLssHgfZgWSzPFBuxL2GYjN2HjU1o3INSfFomE4rCWl4tqcQNkiaGZqolkcXTF4q1s
         v7dGy2TV6TxpW12dLUKvJJsYYDtGdxs3c4ubevIDH80oFc859cIySAnlAxgA/aAg/+PT
         zXo8Hh1j+TVeYg8CoL6d4Ao/HqDOphkFZzvj30aaoFWKPtjqSbflcT0Q+2F2Ugfqss+t
         eaVQL/dkxfKcfqL7LWIX4A6uO99EQ7cWenw5QW8s5DGpltWYsh+49ofEUuMZHzYK/OlV
         VFxG1bxSWNnJkYujcrArfTdWqPw9CqCRE99DcBMfnwBBD2aaUCMu+OIcPANyiF01S3Sf
         DRgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=FmO7Y+7Jh332+Soq1KGuWIcarbnspe5a6pb6NrIblac=;
        fh=lHkFV9K/xCYP4TZvEP9eQPk/i1dfhZdJRbTI+EwbyJ0=;
        b=Pm2B6znDRm3h6WHUZxtlVAUNME1BGP70DzcgK1AhwI85TdFRYo9pphnoNfmo6uBMzJ
         KoRFXR0xX6WFmPu3fECZpv0356X4SCV/ksLhOnF/Rt/lt7LhldVKHHNvE99m4Y/4vv74
         RY3qMXPQul6gpfTczSTXh4uciRfX2W7OMJWzQvkJHIKJBKkjLGEZfK785kirojnAQswa
         g90qb4ZHRT1YJ6mBoJQ3o+lx06nvUrY7VYK5kKQLW0NRH5SnUXL9ZTlYOQ2s5Jp5PUbx
         mXEqftS0T73fPx9xEQDYDXgONiYRYvyOu0wEzjskK0YwfjKzUQWVv3pLKDHqvBYyx8h3
         RXtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ekZ3+tR1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E7lDI2Ut;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a8f701770si1325575e9.2.2025.12.15.07.20.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 07:20:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0E12F5BDCB;
	Mon, 15 Dec 2025 15:20:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DED283EA63;
	Mon, 15 Dec 2025 15:20:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id nsa6NDQnQGk5TwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 15 Dec 2025 15:20:20 +0000
Message-ID: <5153dc10-c041-4283-9722-b93a76c44a20@suse.cz>
Date: Mon, 15 Dec 2025 16:20:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 06/19] slab: introduce percpu sheaves bootstrap
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-6-6ffa2c9941c0@suse.cz>
 <ct5pjdx3k4sxw5qjuzs7rsblkxpkah3qdx6kbhe2oeuaontaii@fwgb6ovi36zj>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <ct5pjdx3k4sxw5qjuzs7rsblkxpkah3qdx6kbhe2oeuaontaii@fwgb6ovi36zj>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_TLS_ALL(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Rspamd-Queue-Id: 0E12F5BDCB
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ekZ3+tR1;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=E7lDI2Ut;       dkim=neutral (no key)
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

On 12/15/25 13:17, Hao Li wrote:
> On Thu, Oct 23, 2025 at 03:52:28PM +0200, Vlastimil Babka wrote:
>> @@ -8608,12 +8656,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>>  
>>  	set_cpu_partial(s);
>>  
>> -	if (s->sheaf_capacity) {
>> -		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
>> -		if (!s->cpu_sheaves) {
>> -			err = -ENOMEM;
>> -			goto out;
>> -		}
>> +	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> 
> After this change, all SLUB caches enable cpu_sheaves; therefore,
> slab_unmergeable() will always return 1.
> 
> int slab_unmergeable(struct kmem_cache *s)
> {
> ...
> 	if (s->cpu_sheaves)
> 		return 1;
> ...
> }
> 
> Maybe we need to update slab_unmergeable() accordingly..

Yes, I meant to do that but seems I forgot. Thanks for the reminder!

>> +	if (!s->cpu_sheaves) {
>> +		err = -ENOMEM;
>> +		goto out;
>>  	}
>>  
>>  #ifdef CONFIG_NUMA
>> @@ -8632,11 +8678,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>>  	if (!alloc_kmem_cache_cpus(s))
>>  		goto out;
>>  
>> -	if (s->cpu_sheaves) {
>> -		err = init_percpu_sheaves(s);
>> -		if (err)
>> -			goto out;
>> -	}
>> +	err = init_percpu_sheaves(s);
>> +	if (err)
>> +		goto out;
>>  
>>  	err = 0;
>>  
>> 
>> -- 
>> 2.51.1
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5153dc10-c041-4283-9722-b93a76c44a20%40suse.cz.
