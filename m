Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNPX6KXAMGQEWANQ5GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id F3AE8867BDB
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:26:30 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d23293d981sf20313881fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:26:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708964790; cv=pass;
        d=google.com; s=arc-20160816;
        b=0voF1WSSC9QO/m9ffZx1/OoWvqnzXf+JxipuSzlWxQwaD6Ge5h7JY879XW+3TXDW/7
         CtKSN/2hDOBrWbQ5DR7+C2Gbay2P4UWq343mtY18RgHdHTDC7vYwHEJH5lB5FA0XGyQk
         Oyj+GAJIvYF7Y2bCB1KjCpOvOyuB0BTF0gR+wOJSlHf9PmFJKXv59fS+8YYxlLB8Dp/X
         YQKXXeXy5KaiTQDBC5tPTsEYTesN4tNX0KUNYNNednbct9iN2E6vht4N0LOXOj/zYnst
         wS9/V712e4MhZl30C656czynOtJlsBKrLMZFKwLU3ommSj60fEtnxJ8Dt3M0C7TqMHHl
         fm5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=rApbRR1kljJzlrglXsKwgHz9Ux5n7+uk8trXVM/S4nI=;
        fh=P15W8zR3LcCIYSGaVgqYa6K9a3siXGI9v9BwqDsNzAk=;
        b=l29tokg1Quh30thD2YM8iqdrBsKqKTNvdt7bG1LEqmAU/HQWpCNsGDO4wi/IvBcXlY
         kH5norO0yWM5u0ujUmpfykIgAehgfUGzVJ/kiZrqGOjBnb5Ax27BSIXy2lth8oPXu9BY
         w0QV9XCfo4i0V18JJz9Zckr3O+AnPRIHdlHkhT9XfVFKI2qj/0ffGRt1Kaj+j1IC3z2K
         38lspeTXWzT+VBfJkcxBOi54aBYr15AZN/cA49zbjinW9/QfBZAaBLKZxQYawV4MWKuO
         AVUdPHJ5ijyZIbFM9GWrIrqdC45WJPYiHokWlip2ODrqac+En8nF1OKtMrCQ+qG+5pTs
         pXmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=prylBFUV;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=prylBFUV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708964790; x=1709569590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rApbRR1kljJzlrglXsKwgHz9Ux5n7+uk8trXVM/S4nI=;
        b=P+KjhYVAOEXzHavr8cpvn84iQRpr0bV7Ylyps/vF0FdBOLmCf7pT4qMUHLRJmz1TUY
         RBoU3MqgDlRCgv/7ew19dvgQi3y2qo/W2iRZKvLiR2KpL7s1DNEYZVLGNS58gT8Q02di
         ElRzepkmcgitkGdaCTY9rCGb2D6DLuuuNRgATNsT8WT62e6vh6F/xw5FsgCoct+ymo3A
         3iGZo0OkZwDpSSvRUZgG0yPXieWIjL3KVDbRCzatwcnDV3MPkzJZ1nvzLt4h16wHJYNa
         qwRaSQ62DBmR8iJnpRjKWki3u8hXxh/ILC9Rea9LqbvGhHY7NynNWtsPwkHb7I2hxQ4T
         JFCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708964790; x=1709569590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rApbRR1kljJzlrglXsKwgHz9Ux5n7+uk8trXVM/S4nI=;
        b=UjPus6iOyWvVXKIgq2j5iK1RLHEn0kweLIVl9I0gSFmNvDL0MK+rVYXgupQyjhIFNG
         x0vyq2D2PX8rownwLA0rOVq+MS6sKOXc7Iz5nugkiWaS6eP3jich9nVoH730wcotEwJa
         srvQwxexN8HtScL6b+8Re6Da3xLqXKrMIEpsW2oDwKauHazXsduB/N2bwBx/spulyJz8
         yWWbDuJKpbG8ko7Br2qYw3ygA9FsDAwLTkx2V13O4KPHU1RHizcdi438aR4eDsCbyTSg
         lqM3qllXLGjIEMTx7ehYCdIkSDGqOMmlMCy5WxniLBEyOePok5kSDgH2Ru2ybij/8oDc
         bWNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVj8l6A5JhppFsX7K3zGl5EkuEPvh+6KmzbymOA3f0mD2LKmMq4xUi1g0yxRqxjk0VaBqnPVFWIxCHUxgbWqHsv6uFgtdgqNw==
X-Gm-Message-State: AOJu0YyNuS9aSDWY9WW2D0ztLJ3P4LGGdSlOdHTPeU7KLhymZrLEh+I7
	X2dDAzeKBZ6FaDBXo+DkMWDbd2kTfUfc9r3b7ebC+02R6XcLiCM1
X-Google-Smtp-Source: AGHT+IFkUZ/cV4qkwdlbYuHovhIXjWE28VtI0kGdJ7A32A7A64UCV16SipzhsWC8OKURCONSoAXhEw==
X-Received: by 2002:a2e:820b:0:b0:2d2:4c6d:e08d with SMTP id w11-20020a2e820b000000b002d24c6de08dmr4374555ljg.21.1708964789911;
        Mon, 26 Feb 2024 08:26:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a261:0:b0:2d2:6574:4024 with SMTP id k1-20020a2ea261000000b002d265744024ls607160ljm.2.-pod-prod-09-eu;
 Mon, 26 Feb 2024 08:26:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWwfMtFmaaT10Kq+J4ZLjZcBZmvK8WbDGM/Vcx6gc5aXqof1dubSqFf2ss+Od6YPWfMaSgRcqx/bqVyeIB6lmhFnXWe+Po5AZtD1w==
X-Received: by 2002:a05:651c:90:b0:2d2:84cc:3934 with SMTP id 16-20020a05651c009000b002d284cc3934mr2962310ljq.27.1708964787958;
        Mon, 26 Feb 2024 08:26:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708964787; cv=none;
        d=google.com; s=arc-20160816;
        b=yBjAmAK0OhtXPzN+UmuN4VLP+AwYayHmmunhZDuX5eXTtvT0AAI9y2Ffg008CsaCdV
         GM9Ou8J4LUY0C+CVuhoq9lr9KVwQlvGcUB3iiSs1VGpHFQiLZpxGq4ChDKZfCkzu9v0Y
         30gH+msn8ATDtSmdK5HQITF8MG/8i2/RUSByi6YlO98scLYLZrAtocdHrJ+dzKGBJ1g0
         nbeVdwTEzgh0GcGT5jaVgPAbng1279X9dhK66JeM6m+hRZWwWku9XOOi9PUDnXgxo6ZZ
         foSojTLD33QQsd5t7UXybpWPzwc1OSIXimHsssIOuStxcBrG183qLlErXAywUEYB3Kb0
         yNUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=kt81o7iYJbd84eehNyWBdCqngFrw9GogG9YZ6mhQs9s=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=OU0P0WZhXiPJ1ksBzP5p7aYSSlDgvy194f3uB2Ni0ylqCWJz7FEFO4+5HOUVKfW/NS
         g04vE2jRXerjmhvE7F7tmXLAmAWkmkpNbszv9Vw06TQYHGm19gMokaaIk4YeiuQH3PDH
         ba/Nod4VkDYJx4uI4fkLQSbVXpzWgCAVyxZFokDNp1Vl+Byic1nODFqY8ICnpKaid8au
         EU5E44Ktr6A+ZoKt/18ftDU/OfuwLGPb9x7y9DqWm8NuHMMfNHqQ0fFNFcqiu03ZTLfE
         potTbxYeKDoBYrSY6gnDvu0NY+fVXxx4ufW1mZ3RMr6vKaWG80i654EMVBamHfZeeJ5r
         O2nA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=prylBFUV;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=prylBFUV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id c9-20020a2ea1c9000000b002d26782e8f1si377858ljm.7.2024.02.26.08.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 08:26:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 15890225D9;
	Mon, 26 Feb 2024 16:26:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7FD3C13A3A;
	Mon, 26 Feb 2024 16:26:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 4j3mHrK73GXJDwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 16:26:26 +0000
Message-ID: <6851f8a0-e5d2-4b79-9cee-cff0fdec2970@suse.cz>
Date: Mon, 26 Feb 2024 17:26:26 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 07/36] mm: introduce slabobj_ext to support slab object
 extensions
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-8-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-8-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 MX_GOOD(-0.01)[];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.20
X-Rspamd-Queue-Id: 15890225D9
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=prylBFUV;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=prylBFUV;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Currently slab pages can store only vectors of obj_cgroup pointers in
> page->memcg_data. Introduce slabobj_ext structure to allow more data
> to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> to support current functionality while allowing to extend slabobj_ext
> in the future.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Hi, mostly good from slab perspective, just some fixups:

> --- a/mm/slab.h
> +++ b/mm/slab.h
> -int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> -				 gfp_t gfp, bool new_slab);
> -void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
> -		     enum node_stat_item idx, int nr);
> -#else /* CONFIG_MEMCG_KMEM */
> -static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
> +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> +			gfp_t gfp, bool new_slab);
>

We could remove this declaration and make the function static in mm/slub.c.

> +#else /* CONFIG_SLAB_OBJ_EXT */
> +
> +static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
>  {
>  	return NULL;
>  }
>  
> -static inline int memcg_alloc_slab_cgroups(struct slab *slab,
> -					       struct kmem_cache *s, gfp_t gfp,
> -					       bool new_slab)
> +static inline int alloc_slab_obj_exts(struct slab *slab,
> +				      struct kmem_cache *s, gfp_t gfp,
> +				      bool new_slab)
>  {
>  	return 0;
>  }

Ditto

> -#endif /* CONFIG_MEMCG_KMEM */
> +
> +static inline struct slabobj_ext *
> +prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> +{
> +	return NULL;
> +}

Same here (and the definition and usage even happens in later patch).

> +#endif /* CONFIG_SLAB_OBJ_EXT */
> +
> +#ifdef CONFIG_MEMCG_KMEM
> +void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
> +		     enum node_stat_item idx, int nr);
> +#endif
>  
>  size_t __ksize(const void *objp);
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index d31b03a8d9d5..76fb600fbc80 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -683,10 +683,10 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
>  
>  	if (s->flags & __CMPXCHG_DOUBLE) {
>  		ret = __update_freelist_fast(slab, freelist_old, counters_old,
> -				            freelist_new, counters_new);
> +					    freelist_new, counters_new);
>  	} else {
>  		ret = __update_freelist_slow(slab, freelist_old, counters_old,
> -				            freelist_new, counters_new);
> +					    freelist_new, counters_new);
>  	}
>  	if (likely(ret))
>  		return true;
> @@ -710,13 +710,13 @@ static inline bool slab_update_freelist(struct kmem_cache *s, struct slab *slab,
>  
>  	if (s->flags & __CMPXCHG_DOUBLE) {
>  		ret = __update_freelist_fast(slab, freelist_old, counters_old,
> -				            freelist_new, counters_new);
> +					    freelist_new, counters_new);
>  	} else {
>  		unsigned long flags;
>  
>  		local_irq_save(flags);
>  		ret = __update_freelist_slow(slab, freelist_old, counters_old,
> -				            freelist_new, counters_new);
> +					     freelist_new, counters_new);

Please no drive-by fixups of whitespace in code you're not actually
changing. I thought you agreed in v3?

>  static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
>  					     struct list_lru *lru,
>  					     struct obj_cgroup **objcgp,
> @@ -2314,7 +2364,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
>  					 struct kmem_cache *s, gfp_t gfp)
>  {
>  	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
> -		memcg_alloc_slab_cgroups(slab, s, gfp, true);
> +		alloc_slab_obj_exts(slab, s, gfp, true);

This is still guarded by the memcg_kmem_online() static key, which is good.

>  
>  	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
>  			    PAGE_SIZE << order);
> @@ -2323,8 +2373,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
>  static __always_inline void unaccount_slab(struct slab *slab, int order,
>  					   struct kmem_cache *s)
>  {
> -	if (memcg_kmem_online())
> -		memcg_free_slab_cgroups(slab);
> +	free_slab_obj_exts(slab);

But this no longer is, yet it still could be?

>  
>  	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
>  			    -(PAGE_SIZE << order));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6851f8a0-e5d2-4b79-9cee-cff0fdec2970%40suse.cz.
