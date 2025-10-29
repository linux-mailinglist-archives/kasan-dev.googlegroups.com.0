Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNXHRHEAMGQE2TAZBXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EEC6FC1D216
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:06:15 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-378dd2050b9sf1888611fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:06:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768375; cv=pass;
        d=google.com; s=arc-20240605;
        b=NSo7qLbnpIK84aN7Ex/nS3d+dubiswh4Qgf22w1H+nYArVeOTp+npSVSR90PYTqwh7
         7VK9AckzZhZ0ABSgDLE8zymANV74QIEj2qWx8iso3c5sIdXyHGWYQc9uvDcL4y3aUN2o
         6Sc84TyhTBOJiAuim1BJgnCsw2IiVnrRXsddFXDDgdb3OcNABkcmZyMqhJUpcsbVL6Ga
         9INgEKEHGF8YtoR0h6B0OYNL2EnCc1ffDJM8oZc002dlojSS9rhs4RPGLS3OiTHbCl7c
         pQ86CGH2tgmB9UzS4+ys70OwRoQoFjziNVIqV3JjWtGiqv9XeUM3fCoS7ajBXQzcVRCt
         fD2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=j6+lp0LjsJtgUXezfarSq1jIELD5m2KZ7q4a3tsL9Fg=;
        fh=ZjlZpKlh4C7dmeMQ6ECRWirmhvydg0tHMa5RaCBnWKI=;
        b=P2xfrOWDZUnb2Xi1u6RAQXnxUGmWbq6rSmQ//Rjov0QS/FhPrMuwtoNYJa/lZI7fzq
         cK6B6bYmo71T4BTBdXIQwb74Tg6yIkTuZniavUtnn38LaJoJkEiqkmdQ1N/dDwVbOs9n
         mtz/CUASwP/kR5+tQ5U1dqSNRiaZd/IXIHeQIdzjaQ7S3ryJC7GX36mVri2EOXbKRjcv
         HZtMIR5y/Xt8ZagKD/wBv0p03R71hRjKZAYqBICFKYPJjN8YBEG95b+oIZqj8Zyn4tIJ
         p7KAQFX49EUJ3ZY0wBAszYh94nG0lFOzgHLMRj4fF25sZfChQnF9j9U9sZ/uzlq9CoyE
         bpLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XesAeEvE;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XesAeEvE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768375; x=1762373175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j6+lp0LjsJtgUXezfarSq1jIELD5m2KZ7q4a3tsL9Fg=;
        b=r877slB4Z8XCs5GTr2vYkhxHX9xmMpiswvGeG2YaNDIUwBaS3FYGpMWPWPxjpenzkh
         EFAgCJblLcFpV8k51POTkLImthZbfNKQq8yoTt+Q0+gbTxLkAT6nzU58qwLbyJpPTPqi
         VdxjhtQRZgOEUAnPyDSB9wDaZ5yUQwOCnNse7FW5eAJZgYI1/4arS/+6/RDaNA9W1Wkn
         trt2pbc6MZYehYPm+qWpwYu3Eu8rMHhLZtuP8dPpXcvlUIsfQ832eIYSM0/U9S487S4L
         h5nvn1fnDSikOEDZOsx9+lXMQ+xy/C6R5rHumlAlgOi86bSLhK+tWEBhFP/TXrnviEGH
         1Flg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768375; x=1762373175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=j6+lp0LjsJtgUXezfarSq1jIELD5m2KZ7q4a3tsL9Fg=;
        b=fjwzedLIj4ZgNtI5VLhgDakdWQItiuj6KqbGz0sV1qUdZ50aDxY3O3eH5ZW7W8PTXg
         QKlsSp8Xnmd6j6Juf4DnubAyHTuuZCLyEwZQuyilprsYoFKslqcYQ4m+Km+AiUgZ+tjv
         FVBYWmime/xHn2ATBHy9DOLwsbArT/z+1pRWfLWi5eqfwP0zvc42zMLvxttbUXKPJ4aY
         cD7U4hW99usKqpDmjJ3LVNSc0rM/Sibt4X86glwTc0rOk7vd+sPJFTtuk2i3jfy8nSth
         2a0CFU+nVMGolmJQ0Jo003+gSadfRvddu7eC5PgVfDb23KuzJqG395tpNOuuTNpM4C19
         3CwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUC3s2QnhPyJWODP7khy58QjQRPkxaRqlvbAb4tDQkTYdAf+8qSSG1oslXfDIuLN8rnhhTKZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyp29WXT3OZ21oDyZn5AsRySHj1jaKIUSn2TsbKMQwYdpVQodEN
	Pyjwz9gCY48/PSm7CscD5Sqw7+BZbUBCJPJ2ZXwqepYqgf651CHEQq6d
X-Google-Smtp-Source: AGHT+IHbg1TT1/T2eqZGUMXf3xQN3crBMCUbwhCPSHL4vHz0aHw0hF6IGqHRAn76GffYhhuMmveYHQ==
X-Received: by 2002:a05:651c:150a:b0:378:ee95:cb10 with SMTP id 38308e7fff4ca-37a0f8c96f2mr4310461fa.44.1761768374973;
        Wed, 29 Oct 2025 13:06:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+al82V367C9O0L9NQazrPwv6eVoWrvNQ12GA3tENvYN5w=="
Received: by 2002:a05:651c:1073:b0:376:386d:5485 with SMTP id
 38308e7fff4ca-37a10bbd905ls488911fa.2.-pod-prod-02-eu; Wed, 29 Oct 2025
 13:06:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3xkMtulya0rq0Pa/2yevBit5+iwlR6h+5Vbci10xY/YikJmlWdJHjZVHlDrYFz+YNm8b+Fbjpgpg=@googlegroups.com
X-Received: by 2002:a2e:be8f:0:b0:373:a537:6a27 with SMTP id 38308e7fff4ca-37a023b97bcmr14078091fa.4.1761768371138;
        Wed, 29 Oct 2025 13:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768371; cv=none;
        d=google.com; s=arc-20240605;
        b=jhKFfwUzbghYdtKeggggTxYLctdAO5x2BIKhsA9jm+6pGKuoMnQDOgm5Xadk5ExFgl
         aBgWu+W3+2L7Ob8OR9HEFL0zxQpi20qkuKW7oDuskspNItcpZ4Hhp9RN35UPBi4KC+ag
         OfyNBbXcnqCGsMjSHfhJ5Yse+2R5z2wAaHUlwOHswVBDzyM58wpZQ7497nTkeKKg9Pbn
         zrD5toXG0M6a7aJPZcLEHvnKgrBRsMhESMqalQVOzeRvlT5/XfbJOWpPzMXRuOPWD9k+
         Bo6rI6s1MaKLMSYa1t7wYj3UowAFCqIkAmObrNL7JF2+5q51ajAAi4WmRuamDfOyVpgv
         y3qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=1K2si2V9W9zo0go0yDRYK2pKFo0UoWxQ6EW/yImCMlg=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=SRUEhY2EFCMoa9plrAyZmyM3M/jtDoKshZXMnE2lmlRX7EtxH4OIrqL0IKYPMYiraf
         yqV60Wh/1Mvq78xYA/800k2NUDj1laOJqDDLNQFrCpKb/O7yJzwvi5gejPMcwd8jDxhe
         e/Yvea0PgWJV0mAnxr1TvkUg4b4okZG5uPXJ38jmK59RSrZxTi8LW9m4wYf0xcyBAZ5t
         UhEq/aeSk7eea9cte7JVeZkHxmSt66sZJ9YvIlWbGVB60uOwqgDvOzLbUi1HbkaL5aXe
         W+UagDsza5crVQKU7yYltw9pXdCwwmkhQiJvHgnoJbbssCoXEnZvNFjLkR/MvH6KjTM7
         62tQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XesAeEvE;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XesAeEvE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378f028287bsi2389091fa.7.2025.10.29.13.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4DF833462A;
	Wed, 29 Oct 2025 20:06:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D8A0D1349D;
	Wed, 29 Oct 2025 20:06:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id XH2dM7FzAmnXfAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 20:06:09 +0000
Message-ID: <982967fc-5636-46dc-83a1-ed3f4d98c8ae@suse.cz>
Date: Wed, 29 Oct 2025 21:06:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 08/19] slab: handle kmalloc sheaves bootstrap
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
 <aP8NMX48FLn8FPZD@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aP8NMX48FLn8FPZD@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 4DF833462A
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid]
X-Spam-Score: -4.51
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=XesAeEvE;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=XesAeEvE;       dkim=neutral (no key)
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

On 10/27/25 07:12, Harry Yoo wrote:
>> @@ -8549,6 +8559,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
>>  	return s;
>>  }
>>  
>> +/*
>> + * Finish the sheaves initialization done normally by init_percpu_sheaves() and
>> + * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
>> + * since sheaves and barns are allocated by kmalloc.
>> + */
>> +static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
>> +{
>> +	struct kmem_cache_args empty_args = {};
>> +	unsigned int capacity;
>> +	bool failed = false;
>> +	int node, cpu;
>> +
>> +	capacity = calculate_sheaf_capacity(s, &empty_args);
>> +
>> +	/* capacity can be 0 due to debugging or SLUB_TINY */
>> +	if (!capacity)
>> +		return;
> 
> I think pcs->main should still be !NULL in this case?

It will remain to be set to bootstrap_sheaf, and with s->sheaf_capacity
things will continue to work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/982967fc-5636-46dc-83a1-ed3f4d98c8ae%40suse.cz.
