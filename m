Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNUW4OXAMGQEFCRTUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 47F71861841
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 17:43:36 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-512bdd07758sf897347e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 08:43:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708706615; cv=pass;
        d=google.com; s=arc-20160816;
        b=UKA81PW5qgAlxX5GTczPbH+CvSpgA7prm6ztwTs8DoauWNJLXQqlL2Obuj3E2UbyjT
         vSyH+jHXEr1Cn816OoRSkw4aj0KeiRk8gtlM0x1ksKf9t/1Zi0W2qGBY3ViU6V3FXANa
         +XiuLvZbSQuuZGJRfPVHG0sV13xoE9gMCLUhQ9H1VejEfd6m+FLaRETk3I8b/M12aNEq
         tdxUt8M22A+5eegfbdNkQi6TV50cC0dh5Wybwmksc7D3Q9vVj7XCJTvzGbm7hhIkhyJU
         dZzA2o3RvooH81zNNmJjVb2QEyPz7a0W8poFyWsPbQYBtY4/8Wx4KtP1xPL3DrUMs7CC
         DY7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=yNND1cfnECzhrFeoFCiGY6nly48JgjxFgvcjLEN2TIk=;
        fh=xoBIhFf2GgfbCS2ZNNVV/mobAqscKJPzTnGESeqWVJE=;
        b=vBKnwgXg/KfveRTdLuXuiJYKA//whMRHudo83bEF0hsxM/c6eSiqzMMFTxDYPL0VD0
         TuVSR2k2dRjYmVK6EtZI6kbODaFFYgOHspeJdMtiq4JPKKlZRZfP/cO/b5BwIedwiKSj
         gXBnhkQZkLoJqsz0ajU0kCfJVNOKTKl+bmsJoA97G55J5HDwC68DNXd4WTEjTTIkD+65
         bYMLD05PJ1asx1WAteeQjkDy6LOmUIhywuriUP7+sAYg4MMqJiFYrRwXPSlzukoskYsx
         h1xmKWH4PRrqiFge1BIzstyjRC2UvrQiFp50Q9W2OT+ZzBETNt6Cp+QkF1gZL0wuT+uK
         r1ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;
       dkim=neutral (no key) header.i=@suse.cz header.b=wLxSkZPx;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708706615; x=1709311415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yNND1cfnECzhrFeoFCiGY6nly48JgjxFgvcjLEN2TIk=;
        b=fc8PIVVfpq4qRnJ0FrpMIDwDEajw+5CaOjiKup6nrxnWEoQptbAqAtEY6xCqmnfckC
         1nWPyb2aC7OYzUmTCO9jNYa6HZ7O7IcFUM5R6fZvOSzKZJ/8jyhmggkCZruKy58Gw0dQ
         40t1G2ikRBYOfIPHIPUGV9BQ2E/LrRO9xLFVzQysYwsEfT21BCHSIlBGu0PH9Y7ohMjN
         2qw1ctbhlQ7QKGCS/usnMH6fmSicgKtpatC5Q8sNHNoyOfLVvJdEn98ZKiHpEyjNoN1o
         dNlw/J5+ocyplhdSxftt0GX0hd65w6GOwY4CIkofqT7EciIdHVLNz9TcMLCIJ+XsK9hu
         hK7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708706615; x=1709311415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yNND1cfnECzhrFeoFCiGY6nly48JgjxFgvcjLEN2TIk=;
        b=C8ROgmaPGU8Mux0vXzjz7b+a54C7tgxEnvoGVLNvOrm4GLVxZi2gVI82GGj8P5DRsz
         DLTJ7fTJOSulPCKyqZ8XrzwEysZdXwo7ih3UfLOfQHwJtCuV4unL7kFKlH5kgTJM4l7f
         dNNK2NHYvgf7Kmg1ZOp1gPbOoYeC8Czk7pwvYXWtr5xn6kzKNuEov004vKLYJyFPtli7
         iIvbCgj5mAmOMxHQMyaa7d54Xx/hvCpo85BfxDPeNdJKme2mJSs+1hHqBC+S8gYxWipH
         SUQnQkfCrpJfVs8VkFCYW0ZJr8rWRinrDY05acArPYwsHWX8Eb36hd+y12UbVn3R2Vtq
         CF6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeAMTxc+9dBHkfYUUUyqBco58OItrQvYH2NcKjyVn0HPoJam6NuEblVFDq6TsdIIF7ck4joUuW2KPvujiKEUZK2gxhGhUkPA==
X-Gm-Message-State: AOJu0YwZtX9FDaaYAySP4pZNp76Zeq0DfTUY9kOclWSFSythrIfg76Td
	wOu8rXD0uBvHUXRwD0pwH/XSGQp33tKJigCSk/MBW9MBvTnpZyDnR1Q=
X-Google-Smtp-Source: AGHT+IHhNdLbfcmZkACFHOzoTKxXlbpVpxTzohM8LjnIAy51irUcGDMkClSKh8ZQy0uv6EgHE+Y12A==
X-Received: by 2002:a05:6512:4cd:b0:512:b2b1:1797 with SMTP id w13-20020a05651204cd00b00512b2b11797mr219863lfq.14.1708706615130;
        Fri, 23 Feb 2024 08:43:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3194:b0:511:98b7:8d99 with SMTP id
 i20-20020a056512319400b0051198b78d99ls654361lfe.1.-pod-prod-02-eu; Fri, 23
 Feb 2024 08:43:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV88wsYcvka/W7RI4hrfP6xprHlNRkv6NVUNFZsMHE3amlKKvaNdqJNLP9qiMgLL/qIf4jnhDhcOG0rYsbsvzjBbJVm7xty4JbI2g==
X-Received: by 2002:a19:6545:0:b0:512:bdd3:150d with SMTP id c5-20020a196545000000b00512bdd3150dmr180592lfj.52.1708706613200;
        Fri, 23 Feb 2024 08:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708706613; cv=none;
        d=google.com; s=arc-20160816;
        b=ogFEJYATF7lnJTO0v6jHGM0uKQlI9XfAu28a+NAOOuTapfZJbf1Ug9ZU+uwBpiqLr1
         szfEiOoBDTyYcOeeLd0Qfk5zgCiZQHpJjwHyjl6OCWtyuLl1ouvkC1HZ1qVlIPsp8ZpJ
         GdZn4wJAOsm53yWqiQdafRqu1KOkr4WJUI3DOq0r2IY79NWTbXXQ25WlMuwpOMjVhGJI
         68PVVxVZzvEnCuRVCFyqAlfegjs2DJug7+Az4DHBO09ayRllV1dVGuS7XN7BsQxG1Unf
         CBpQx2kU2uuRI/3w/oqlPTfx4Txc9eDDU6HTgXotFVuj3Ymdeq6BQBTQVC5219TFRKIQ
         /ZSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=GE2URHICWI/LHH1AjYAsqoMojZ4QR/fYwJKrudMYFC4=;
        fh=cBYUlA+uwD4T8IcXfChJsberjdmqy0sqyrIncYrddH0=;
        b=EQ85fCmC7it3Zes9qC2GoULTdImRQCMr1k18aqDRd3/ZqkMduSiSQoSYt99j0XMuTa
         2GZWbOGPgXdqpw6Nc7Yj9OVEvwWzVuAHQvhEjasA5zNibt27Ib5RJ7kJL1kMRNSIEBnv
         Qk8XTliQqR8rD1KPphU1LMIzG1t/MWzcBNOyhrbd49zwwKGXcd+G6fOXxtOZA1q6cW11
         QC4uQ/aIGCgFu51uLxCsUJkVog4iZzZIoalZDk14Azejsl5ZX+T7j4HSnpzFKUG/IVIM
         uk2b394S0PQ9VeNYUZr8jEvQgeNG6yX1/p9msBuLk9S2Ga+tDizdwub01+9cWHaYpwmd
         4NEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;
       dkim=neutral (no key) header.i=@suse.cz header.b=wLxSkZPx;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id b1-20020a056512024100b0050e69030a77si625864lfo.6.2024.02.23.08.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 08:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3B54B1FC2A;
	Fri, 23 Feb 2024 16:43:32 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 01059133DC;
	Fri, 23 Feb 2024 16:43:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id iOK0OjPL2GWUNAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 16:43:31 +0000
Message-ID: <7ff66c6a-4127-417b-a71f-a10ab47090b4@suse.cz>
Date: Fri, 23 Feb 2024 17:43:31 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Content-Language: en-US
To: "Christoph Lameter (Ampere)" <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>,
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
 <8bc31ec7-5d6e-b4c0-9d6e-42849673f35f@linux.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <8bc31ec7-5d6e-b4c0-9d6e-42849673f35f@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.02 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.18)[70.21%];
	 MID_RHS_MATCH_FROM(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[18];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com,huawei.com,windriver.com,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.02
X-Rspamd-Queue-Id: 3B54B1FC2A
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;       dkim=neutral
 (no key) header.i=@suse.cz header.b=wLxSkZPx;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2OT+Qh3D;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/23/24 04:12, Christoph Lameter (Ampere) wrote:
> On Tue, 20 Feb 2024, Vlastimil Babka wrote:
> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 2ef88bbf56a3..a93c5a17cbbb 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
>>
>> /* Internal SLUB flags */
>> /* Poison object */
>> -#define __OBJECT_POISON		((slab_flags_t __force)0x80000000U)
>> +#define __OBJECT_POISON		__SF_BIT(_SLAB_OBJECT_POISON)
>> /* Use cmpxchg_double */
>>
>> #ifdef system_has_freelist_aba
>> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0x40000000U)
>> +#define __CMPXCHG_DOUBLE	__SF_BIT(_SLAB_CMPXCHG_DOUBLE)
>> #else
>> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0U)
>> +#define __CMPXCHG_DOUBLE	0
>> #endif
> 
> Maybe its good to put these internal flags together with the other flags. 
> After all there is no other slab allocator available anymore and having 
> them all together avoids confusion.

Good poiint, will do. Then I can also #undef the helper macro after the last
flag.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7ff66c6a-4127-417b-a71f-a10ab47090b4%40suse.cz.
