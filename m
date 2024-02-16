Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVM3X2XAMGQERNDFV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 43141858273
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 17:31:19 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5118b336cd7sf9770e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:31:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708101078; cv=pass;
        d=google.com; s=arc-20160816;
        b=FrwSqsvI2YlLwVGfb243i7Wqv/ljikAyvr3rWeo2WoGRgjQWka17p9NsHgrFLJa9kX
         CZ02+EhGuEgg2inLDUpGm2JhRaakHYvNx0RwmVGV6zLPCLuCe+GIf+AaTeGdA+YsH9aY
         NSm39+V3kg/nEWmaMl7SVlkcsYgVshjn3HpY5UrYtnJJV2ickg8FjECzjkp/GmsBVvPT
         LphGVNGgDwXiVT6svIjfwcWXREAyX8265X2Q2/d9p5jxsfRUrHq8emcrqUfbILMK+MeZ
         IFNBz7l8WpyGlmCg6UNQxWIZdYhlS0XQ86rItyG7RAC8jgcz6U3rK0CUzRegnME+O/Aj
         c+og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=o1eEFzCVwWVwK4cs+VxQwaUUkhFWLLSb9XiU8nBhBts=;
        fh=ke/K6JWq5cD0V6IqQHh9J0hfJ67o/8DFgJm9FUlvCV4=;
        b=rcUvBK1Z1dxIib3CjnMFGaSU+j3mZXUxLF30z6XXRH+Rfi0hXwoWK3RCyAI5x/aWE6
         29OkDR5tND9FAqx4Eb+3LF6uzJLIVnHDX1rWlfgooE8kCJInVVUDgxUALfOD8qYDUX8W
         aaJWEci2OXsESiHKSlXvkcDfWv7J0CC+R9npeeE981MsYSa4lAo0Ty4dYx8vvv0By+DA
         /rcdytVXmUeGYPKQ6+4RZ5+9FfQ7OMiuxal9R55zCnEsukXrc9vIJdxvSNAwBLdrMmeW
         im9IMZyVEuVnyKTAc275JjckqRltALCmhrE38nvZPsegDtp/836VZz93Z6I20bXAl2hy
         fHLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=PvWNYFER;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2RqONsA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708101078; x=1708705878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o1eEFzCVwWVwK4cs+VxQwaUUkhFWLLSb9XiU8nBhBts=;
        b=p9AfbL5+fp9vDNrNe1ZibcJFbNiCpSkq6oZvSWl5U4Hgja8gT5egelZK8fFbJcSkBY
         LRSE7gxgBaP7TRu/AVri1MvvttZDYsUTNIdISWXP6lyFw8w4batB1/w65dI/V+aFzTON
         c+Q3vWRz4RIHigDjYnaf6pBQjOiDfuF7fA52n7BvErhmnkBDyxIUF1JvTkgmzbMadpKe
         gx35m3nxcvIBWITEm1e3CJVAfV888On8RfgoVHZy5Rzgn/8wenQr3Mm0atFg0euYfYkk
         Q9AhXel6IDiAU87wPkPxocSZif6mkuNC+zNECVcnH3sfi1f898ZBx32PIBAD+hxbmZaF
         67AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708101078; x=1708705878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o1eEFzCVwWVwK4cs+VxQwaUUkhFWLLSb9XiU8nBhBts=;
        b=U+bBhv+VuK3JiMNBbWR3ekb3bFsH1OPxuvblxbfwJ9XOYckNnxf7deTYZvSkRg8wKX
         bOJlVezhLhCqHVMBKDmGTzmCXaZLu47KksDo+vUOMaWsGqbHePrL7rHdOIMvEbfS6kbV
         MWNxg4thQRe83lmKK9f0gbBETuo7O9UJUcCL/wAJCxbWz3OoOuZb4JqUP8ilk4zn/+1h
         XfJbVQc66pejApgD78trQ8rIGAHOzoH9OMr8RWUrHZNb+wn9AeNJUlHGkD1u144z+dd1
         zKHT7fVggcuCKdeqmr2XO+7xe0BTHbOoirVfRQt2GiDi91e45QkdT0h6xCv4K6frMgTq
         Q29g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWu80xfHbNeh6cuIWVAlvkDuzNUImzr4GgoV5364RvtsJM97XGC1rqYra7n1J6CwfvxjueBN2Z7AEPvfNe5ReWn+lqs1h20GQ==
X-Gm-Message-State: AOJu0YxTXCdqud49St/nUVco6mDMyRy3hblfUF9oCTX2po4mMBIDeHGO
	BlW2j+eqgZGtVnI6MKhJFDtZxei9tlGoHovrp4Cimux7N+gbO74F
X-Google-Smtp-Source: AGHT+IE1hxh7+W0RhP0yd7UmvFp7ZMeDPOKPd57qDJukGG4dt7KYUBhPX8oXz8ssIfI1xiKoX9Nbhg==
X-Received: by 2002:a19:435b:0:b0:512:949d:4db3 with SMTP id m27-20020a19435b000000b00512949d4db3mr94683lfj.5.1708101078089;
        Fri, 16 Feb 2024 08:31:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3094:b0:511:694c:ab91 with SMTP id
 z20-20020a056512309400b00511694cab91ls510982lfd.0.-pod-prod-08-eu; Fri, 16
 Feb 2024 08:31:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVL5/+zrVaVftf3QSnPk0zpjvEC/s+Z/J3ZER/Mw5Uxc5+TD1Zez71E1YnbNRHVN1XlZXg8W8H2eQl4v2dbQe+RgASXIyfaeFTrUQ==
X-Received: by 2002:a05:6512:118e:b0:511:87b4:d01 with SMTP id g14-20020a056512118e00b0051187b40d01mr4471764lfr.27.1708101075893;
        Fri, 16 Feb 2024 08:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708101075; cv=none;
        d=google.com; s=arc-20160816;
        b=lAiNrtJ2LKPktgy3utVmJxLvcxLge2VExIIbwONxkMeuZrif/p2hd2WUrcUuEgNfNo
         Uc74etdqdulvkt8cQVkUzlveoIUxpQRHQTaU5C/QemMEy1c3+c1CsJ3oiOYr3Fp08T/u
         7jBuFqitItgf7QjmKWYNo6xD/tfW8hYY41hFKDBQBURZFGJFNfK+FV8HouNQGRYnJ5+I
         filTGhjyRE8zErMQQtxZ3HOPextxOT/qwXKZ6C0G/IXxw1/EH2iPLYlYmObJYOcPiHi4
         SbIkfyfS8+qU1NeDGxN44feiGteF/8eGsgihhLIRmQjTY6G/mx2HZmQUHzIoo0mQ8U7C
         9FHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=lPLurTqAKLnQ458IhhqsUiDYFpmaxE3prWq99XPtm2A=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=jTwRy3nYEI2Yo647ZrBcgLmCCr0oezLSpR1oi+sVUblmHDrsGWHgP2vpgafj/VnuKx
         tk5TnYGLJ48m1YSd2NDANE2zSUIZxtbyj2Lq8neSkQAbfspB2bUBdVBcVt5IOVU05tjR
         WuafHUYkJw7zgIMV4knyfwx3Er3F+ImhB+qnIwjvhkoZhKyJ2eq7Fhnie0gWPbwsX2v9
         CBj1kmuEZPD9vAJwslrsob3igkIO5FRfD9iASdSSSIyxcHkP/vLbLXplk9mJcSApfIQc
         mYFAbtIqx/6/OHwgRRw/8QTyoh9KRoYj9FfwRthws3ZHLffUvA6P9kroR4X8ilz0LYf+
         okqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=PvWNYFER;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2RqONsA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id o10-20020ac25e2a000000b005116bbbbd07si4873lfg.12.2024.02.16.08.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 08:31:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CCD472227C;
	Fri, 16 Feb 2024 16:31:12 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3CE2F1398D;
	Fri, 16 Feb 2024 16:31:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id bsViDtCNz2U/UAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 16:31:12 +0000
Message-ID: <ec0f9be2-d544-45a6-b6a9-178872b27bd4@suse.cz>
Date: Fri, 16 Feb 2024 17:31:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 21/35] mm/slab: add allocation accounting into slab
 allocation and free paths
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-22-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-22-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-0.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[11.08%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -0.00
X-Rspamd-Queue-Id: CCD472227C
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=PvWNYFER;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=w2RqONsA;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/12/24 22:39, Suren Baghdasaryan wrote:
> Account slab allocations using codetag reference embedded into slabobj_ext.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> ---
>  mm/slab.h | 26 ++++++++++++++++++++++++++
>  mm/slub.c |  5 +++++
>  2 files changed, 31 insertions(+)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 224a4b2305fb..c4bd0d5348cb 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -629,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
>  
>  #endif /* CONFIG_SLAB_OBJ_EXT */
>  
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +
> +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +					void **p, int objects)
> +{
> +	struct slabobj_ext *obj_exts;
> +	int i;
> +
> +	obj_exts = slab_obj_exts(slab);
> +	if (!obj_exts)
> +		return;
> +
> +	for (i = 0; i < objects; i++) {
> +		unsigned int off = obj_to_index(s, slab, p[i]);
> +
> +		alloc_tag_sub(&obj_exts[off].ref, s->size);
> +	}
> +}
> +
> +#else
> +
> +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +					void **p, int objects) {}
> +
> +#endif /* CONFIG_MEM_ALLOC_PROFILING */

You don't actually use the alloc_tagging_slab_free_hook() anywhere? I see
it's in the next patch, but logically should belong to this one.

> +
>  #ifdef CONFIG_MEMCG_KMEM
>  void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
>  		     enum node_stat_item idx, int nr);
> diff --git a/mm/slub.c b/mm/slub.c
> index 9fd96238ed39..f4d5794c1e86 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3821,6 +3821,11 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  					 s->flags, init_flags);
>  		kmsan_slab_alloc(s, p[i], init_flags);
>  		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +		/* obj_exts can be allocated for other reasons */
> +		if (likely(obj_exts) && mem_alloc_profiling_enabled())
> +			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
> +#endif
>  	}
>  
>  	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec0f9be2-d544-45a6-b6a9-178872b27bd4%40suse.cz.
