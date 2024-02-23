Return-Path: <kasan-dev+bncBDXYDPH3S4OBBENB4OXAMGQEO55Y2NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A00B68618D5
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 18:06:26 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2d24b0b52a3sf7476191fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 09:06:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708707986; cv=pass;
        d=google.com; s=arc-20160816;
        b=zy+MUIW5PSuqJ/6ogfBjXOq057AVip6hOkX6p8KKoPROW0EJTSIBOlSUvhLe8KFY6x
         BMtnxSKt2wf0CMMueBiU+tbCRy052MQHRk2M/AShMoXo3kpVWwvhE4mhwwo/cF3jAo39
         FSbjzvougPNab+r7M/3TUMDt6PJ1nTPFcmCzGQ4zCFpVXq4JX8Mrxg7XyFkVw+klNPch
         GBRfHVCwGgwvDhyH4U9XSxzTywz54a8EPVr5cWApdhzQ8MBlE0JuKNlcCbtFhP36HhjQ
         u1pwGBwZdTUmolMh+z1xVkx4ibhqWCwdWYgwmTjQmbTm9cyK18fHalVE+awTcj6LCxBZ
         yCpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9I5ZtevyVFytzdlEaHF7OnjcEONIIueo4wLMzBFB2+g=;
        fh=fAJxu8WNPBW76Ot7CqJW/GI+f+GlsxRAdKuDcd1mF+0=;
        b=cV/8eZW1jUYmTas+NqvzPKo6rkzedWMKFqNT22wH/MVs7LBquPs5KtN+jZHm869JOM
         qK4bOS4SjcmGmBsN855pyJhKmc1oU+0zDLFRJ4mYrnv/RfL4IbVpbHdbYPJxO6WdZQ2U
         BRCsC+j3DPIRDN0A/tjwYEURZz4+r5p4j6tU6b+Hy6riiEh6l2zjvfrQuSZS47cuPFR6
         jmZVTinpll0Jh3QUDJ45afb1PNjJwbRjqJ9YHIyGN3ODG6HLbOTjKmATr9khlO2NGcck
         f/e7MceLa+ylvt9MoAYEsfAVqgt+rp/TNOufu4Y68e+SfCQHoHbidD24oMluCDzgjivt
         onEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708707986; x=1709312786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9I5ZtevyVFytzdlEaHF7OnjcEONIIueo4wLMzBFB2+g=;
        b=L80dG78OaQr6nDUjI06fpxUZN3TmAfDM1S+4BmgoAQ73VmuHWk/gc97peTVtFwqUmY
         VI2JOF6kykYT41VHokf71Hb//MwxqpRM/pE2nQjtLy05mPa35puxd085uE9UoJ+bEzDP
         ZwAIPjPw/9hgUfXvLXiZsku9QqAt35trbLf0wBW6CJ9bS7t5//fnknzPqbnajg9mBwp+
         SNODH18GdFKYbpQGRvmbiS0jyRf+BPbwhSlqF9p5EvLqTm11gA90IC/VrQ8OKi30nTyl
         wzbGeR2d3ed8yLNg43a4ldZlU1+rkvegzg57hbHOxqPrclDWmiKZx9HMGnt8+A3G34hV
         Hzag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708707986; x=1709312786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9I5ZtevyVFytzdlEaHF7OnjcEONIIueo4wLMzBFB2+g=;
        b=YUE0HZAsc698Wz5ioEFYxhwZAHCmnAocE8jR0yBoC8yxR+0gceg8pxhhQm5KUYedGY
         AviUqSsZpaHYsi/Yg+gdZ0xYZFDM8OjoXns69OMolnmMwStkzqW6rNNU8OZpyJYhVRqn
         hCPc1Zm0K7rIHvfbaHBguUfJAIdZvNUEGx/ptHTScc/EBZFJnPi4npdstZBh8AmhlJIP
         fKO0ggJoZpC+Jb1yN6qt5lZx+Ldse+/hgg+TMhG2Z2CP0fEn8f56UskurNU8Slj7mK7G
         99DBfttb8idyBbtUYAu0NKRNOhHedtAOfc4eKgWRn/0ONnc/9CTUnD7tDS8KIlCaUooy
         wk7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiyx0At2rrYMop7G25jwcnVo5FfhMLo88IG3YdHJ3itXR5Lh1lo2+fmcf+E8+WZNjfSXrvBUj5gVH4XP1jwOvaI9UC1LTfbA==
X-Gm-Message-State: AOJu0YzIns0NdGMMi8pD6ZjwL7pXt+018MaYqp8NU4Bu8Fjwys4FaFpi
	WVv5dzO89fZPXTMv13tpc1bFVOTpJqt7EgdHJMpd1HvsY+LqyHZN
X-Google-Smtp-Source: AGHT+IGfoJf7ARn+qy+9eylqwuw7AQSM9o8y4Fyy/9TjCcN6xufevfWHv34nWy8RJnHwAyAl0GKNSw==
X-Received: by 2002:a05:651c:2044:b0:2d2:77ee:213c with SMTP id t4-20020a05651c204400b002d277ee213cmr193851ljo.40.1708707985255;
        Fri, 23 Feb 2024 09:06:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1694:b0:2d2:3a2b:cea1 with SMTP id
 bd20-20020a05651c169400b002d23a2bcea1ls466231ljb.2.-pod-prod-04-eu; Fri, 23
 Feb 2024 09:06:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJASmE4+NRsH6hXE7dog9a53kiExg9OK6U6r4KvM+9lJaSjIX7NKv5pctdGM6Y9Q4OGINhUu6lw/3tBdUUk3mKp7iLc8tBTb2oFg==
X-Received: by 2002:a2e:8784:0:b0:2d2:32b0:c88a with SMTP id n4-20020a2e8784000000b002d232b0c88amr325860lji.9.1708707983235;
        Fri, 23 Feb 2024 09:06:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708707983; cv=none;
        d=google.com; s=arc-20160816;
        b=E2Y9zL9Kwp9yb4Sfyj3Dicau9DjaX8vbmPtRsd+44zRHFaDHfVe5gJZWoWOSxeDSgg
         NunpZRjCrdIQ3uTaGlb5AX6C1UPnfTUEpLz9Aihuf8uY4yCDX4U70BqqyCq0EDE5E1O7
         ZtpIDxjnkUQDRI2HO5OagyWef65fcQFsLfrEmlAxDns3yLoz6JMIeKqEv6lLvow4RjTI
         Fr353uXO68jrifNpkIqGcKGre3q7dtRCbtudzHQLaWAIQ+Gytft8A9MKkhwSecmw6jrE
         OOkYAgtkc3zRPBNQo9NQgO60TasuRrhvPXN3TVV/GlSVi4jHQyTR+csF/s3YSEz4Z0sA
         1MhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=aRXLoTFs1yNmoq5dTsBkasLC6qtPSY+4X/YPItbqSTo=;
        fh=cBYUlA+uwD4T8IcXfChJsberjdmqy0sqyrIncYrddH0=;
        b=vcGubGAuIHehQO9lDmbnY8Iduz0JNXJ90wHkYEJKbwIWH7xu+KWNl4/5XhHKhaU/3+
         nkMFlggG9puDlzZY80DbqgkK/6Z+duS2sjps7ZWYlJKrKytZqfptxDvyJiR8di9vMt0P
         CVAR3Zle6SeQwcgLhCrEJ483xZuxjkkH+4LlQIfBksi05RZB+xW3mJR677/mJv2tbB/a
         1FqC8gA2liB6P+kRtuceQu1p+KBdtvzhCSH9qkK6Zutw11+CrekEyIq3O1Mlvrkco6HN
         Vp/wb183ZkEvJXGCh2q9ThXWWe+R7DxwWlr49TUqa50TVWBUcfBHckuZg27p9Zlb8ivQ
         ZgGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id b39-20020a2ebc27000000b002d0e0aad823si617748ljf.0.2024.02.23.09.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 09:06:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2F90E1FC2A;
	Fri, 23 Feb 2024 17:06:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EBDC2133DC;
	Fri, 23 Feb 2024 17:06:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Eu36OIzQ2GW0OgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 17:06:20 +0000
Message-ID: <9b6a4b83-0922-494e-9284-9214152c8e9c@suse.cz>
Date: Fri, 23 Feb 2024 18:06:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
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
 <7ff66c6a-4127-417b-a71f-a10ab47090b4@suse.cz>
In-Reply-To: <7ff66c6a-4127-417b-a71f-a10ab47090b4@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-0.05 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.05)[59.48%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[18];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com,huawei.com,windriver.com,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -0.05
X-Rspamd-Queue-Id: 2F90E1FC2A
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=c3nbt8eP;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

On 2/23/24 17:43, Vlastimil Babka wrote:
> On 2/23/24 04:12, Christoph Lameter (Ampere) wrote:
>> On Tue, 20 Feb 2024, Vlastimil Babka wrote:
>> 
>>> diff --git a/mm/slub.c b/mm/slub.c
>>> index 2ef88bbf56a3..a93c5a17cbbb 100644
>>> --- a/mm/slub.c
>>> +++ b/mm/slub.c
>>> @@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
>>>
>>> /* Internal SLUB flags */
>>> /* Poison object */
>>> -#define __OBJECT_POISON		((slab_flags_t __force)0x80000000U)
>>> +#define __OBJECT_POISON		__SF_BIT(_SLAB_OBJECT_POISON)
>>> /* Use cmpxchg_double */
>>>
>>> #ifdef system_has_freelist_aba

Hm but we only have this in the internal mm/slab.h

>>> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0x40000000U)
>>> +#define __CMPXCHG_DOUBLE	__SF_BIT(_SLAB_CMPXCHG_DOUBLE)
>>> #else
>>> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0U)
>>> +#define __CMPXCHG_DOUBLE	0

And keeping the 0 is desirable to make the checks compile-time false when
it's not available.

So maybe it's best if it stays here after all, or we'd pull too much of
internal details into the "public" slab.h

>>> #endif
>> 
>> Maybe its good to put these internal flags together with the other flags. 
>> After all there is no other slab allocator available anymore and having 
>> them all together avoids confusion.
> 
> Good poiint, will do. Then I can also #undef the helper macro after the last
> flag.
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9b6a4b83-0922-494e-9284-9214152c8e9c%40suse.cz.
