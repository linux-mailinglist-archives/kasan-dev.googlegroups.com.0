Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3X6WOXAMGQEYRAJL2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CCD0855106
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 18:59:12 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d0d1cafe68sf20389601fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 09:59:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707933551; cv=pass;
        d=google.com; s=arc-20160816;
        b=Adi2ExEe4ZhdMM3Ymab5WwMURbM0kf+ma6Fxhgem1vGfYnCa+78PS+kgOdNdkqFRGN
         qO0n++3/jwzsW8sVuSglVdN/DyixUuqlgurSZEoBlI66x4C15xgJauM/YWDDTzRU16yQ
         jcKpOqsp7GybN5BkGG1GlaCOzFYvJWdX2SzNYCdiOod2s8RwJczuuf9LyMqBEkGALis9
         hwqXbQ2vAs7FEvL3N1cxwYUvdU0o9TAM3wIDgBu+qyZvQMaXZwnZveIkOCrjVF+hgL3/
         ixsAiEMPib80tyFHEwtqYGf4JFVop2jkPl/mrBSZqHzaz3VQ+IKvmt0ncYolK6TLeTWE
         9WRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XXZroSyqJ02wJHuGjdeL+lDeOn19QGGXTAXD/0s4pD8=;
        fh=dxB9YTIfKxS5C3Lw9THgkRli5KaOOGeiGMmhQ3mCaRI=;
        b=fWxGu/OKrEw/oBQKtkg6JqDBmzLpoffFKjsjXaY7KQQiIaeNr7WXW9OtTDCelqUxW/
         +cjlW9Ut7XQfr2dnFsKyPK2iu7WzXcLvmpPpONH1JpjlSB7pvAWkHPBRGYlj68mdui8G
         WyXJEtFiLvAIY4Ya5+IgbW2cJLBaFb4gtNGv8hmsQupUfeOTJfvBIdIR/fRKuT0AkURr
         VY8rM5/g9j6smBX8dMD1Z3fxRPuigW0sl8rslICfygO/tH+6bMFRGr0OZKpxYijgJja/
         w1lRhwDI+EdbqgqDNHWzgUx5YElV11jlFNqUPKx6U650PNcw1R6XFqlQinRipUeeIAXY
         s4XQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707933551; x=1708538351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XXZroSyqJ02wJHuGjdeL+lDeOn19QGGXTAXD/0s4pD8=;
        b=UNy7VwzCTlIk6/N1OJgZM87DrDwgxLjKvWUDXmB9UAsKdiV0seurgxjf5+N2/IxDeO
         bONwivIeK8evYJQYMTjv8Nya8VZ7KwH+NjcrrHsED5e2sxXbSvAlwmhEZi0/vFhkwPy6
         kG8+7TZDK3TXPrW3XlDOgyWRYgIXH4gePi5N6INLVnfDFtEVyXgiBGoOUq52fnuOQKbY
         hD3sgca9g/GmohU5HcGeS5dLMHR/cQFdc84mN+wX0/FbSTZLEOJjhhbstGW1QsyUSphq
         Rc6sSpS1Ng8pVDBI7PoWSII5iyYp6tbo1W8lUvGaSRWuu0bhLuqS4Gl/1LMHCitFc43A
         Hvuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707933551; x=1708538351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XXZroSyqJ02wJHuGjdeL+lDeOn19QGGXTAXD/0s4pD8=;
        b=Sn4Lugd4GYUxexggYd5x4CXVozSGKQdx6unNqCeRPE5oU0kFfL+PZpdqYXfTY0tzum
         bNT/IMKr0W0f0Lwsrcwhr14l/BcMs4ubEneqcSG044DhsMQ39B7lZWhOOgen6UnmYUIp
         QoCqHyaxIlr2107CRWixlBVPfCx9hGFgXF+YIiCvoSHcyWwjtJ4Tql0gTcB/RcADeKQW
         rmN/8oNOBcf0EWu19/KT2nBFkLYOrpQxjzebuDYpmcUnd2gt0Lk8430JmjXZqgEMTPKV
         zlNobpH8gTFnQEe8zX47vUjciq2Z9BNmQzTQAxrw8BB3kBgI6MJc5RkQbOZhTtuDSsXw
         +/vQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAEhp1Crs7lZhnMzCgdKFS1WFvAhoRMUug3ujuaGOUKL4KYosOaezpdg8R+HENDVOfLF66XkpnpzB3UpA+6RwrOID62zdHqw==
X-Gm-Message-State: AOJu0YxFMlRWT5olmylwzGmL4Pn2PK08FWpKDF7eqBr6NwGL6/fz7FSY
	bN0cT5Sqk29aBmuIjh/9dAYFbSmX9hB/Fbm9hkJAseWMP9Oui2Uq
X-Google-Smtp-Source: AGHT+IGoMinJf0lewR4TmsayPi5hWMcqFayaWLbPP/rq+8Go5iqMoAsf4a3S7Ot4rzFkG2RHH6qMXA==
X-Received: by 2002:a2e:9b51:0:b0:2d0:e35a:3ba6 with SMTP id o17-20020a2e9b51000000b002d0e35a3ba6mr2293661ljj.7.1707933550754;
        Wed, 14 Feb 2024 09:59:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10a3:b0:2d0:d976:e44a with SMTP id
 k3-20020a05651c10a300b002d0d976e44als951455ljn.2.-pod-prod-02-eu; Wed, 14 Feb
 2024 09:59:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZTJ3fP0EbMpB9KSC6S80T0vlb44RfTsKgwYxBD+Y1NMB80QeKVHPNxQeycvR+l+1GxF3yISbu3yFYgyK1G0mqZWZws6rm2AwRVg==
X-Received: by 2002:a2e:be0c:0:b0:2d0:480b:8d76 with SMTP id z12-20020a2ebe0c000000b002d0480b8d76mr2556040ljq.47.1707933548784;
        Wed, 14 Feb 2024 09:59:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707933548; cv=none;
        d=google.com; s=arc-20160816;
        b=XBzeOTcIcCj8HtadRFAK+9CZml+2D/jjtfzM8/nCrvt/Vn7oLUOKVXnCXuUplUtwoe
         nNZkyppOhIrOuGtiGtzJmEdjvTcv5rJPSidi2mHsU2CagujJVvATW2Vg+M9ZcwqMMJw8
         C4TrMVJcz3g/aAmYfRD2IXXbkZBEbD3RaZ73ls1C6T3WMH6zq5jBE5qVZDa8wckWFvUz
         FK2OHFRJHuqpMKYBzbO1akWXiOZPgHxeySkAMf0/vLm1NoUYMfjcB/SIdPcFDN848kUb
         xsYmdltm91eqWdQ5U65BoEl1F9emalgUMf7YMIunFi9fbGHrUCX6eR3IkUuR+61x+tuy
         Zv4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=f2RWtNk8U1R2XRFQl1j1CoYNmJnR10fxgpFPBsng0LI=;
        fh=WYesAzbk7px5w4pVj2MQwV+W4sSV2Ecgp58LOz4evqY=;
        b=LWJbbYzRqbhYS/zvWWt38tuSq40H6KaliXwF6Jr+PMjZZmtL8JH1iZisseyr4+flJq
         VOam0vKZJkFusED4MPPaBiRuTfCseKTILeG6OcziO4+GgPbcXUpTpdyr+kZq3dA9TwNH
         82Rx27mTPLSblV8iULqWQvfrfh6qCIndD8aF5EqAj32RphX234BVy5rEgYFkolhzUyDl
         WU12robfsy8uDLBBwdXHw2zyMonzn60hg25s4rXpdaMOx1qqZ9geKH0rEX0PHIUvyCx+
         4fdxsg49rmwWQvjzFO5wIHzv4fRn2/JguA9QmybdYF+MmWzcw6h4K9CHYGx9Air0813o
         6TXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
X-Forwarded-Encrypted: i=1; AJvYcCVU0jdsRZwMcfFtzvSzhL6TBbn+R/DiZ3JHtr3ai6LJh4yi50Sz8x04eB5OY60Gfy+duMfwh68G8mVphZnFedO9kiqWanGEZ4WvDQ==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id p30-20020a05600c1d9e00b00410d2828564si97454wms.0.2024.02.14.09.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 09:59:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 113CF1F815;
	Wed, 14 Feb 2024 17:59:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5910813A6D;
	Wed, 14 Feb 2024 17:59:07 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Om60FGv/zGWRTgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Feb 2024 17:59:07 +0000
Message-ID: <3cf2acae-cb8d-455a-b09d-a1fdc52f5774@suse.cz>
Date: Wed, 14 Feb 2024 18:59:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/35] mm: introduce slabobj_ext to support slab object
 extensions
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
 <20240212213922.783301-6-surenb@google.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-6-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-6.50 / 50.00];
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
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DWL_DNSWL_HI(-3.50)[suse.cz:dkim];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -6.50
X-Rspamd-Queue-Id: 113CF1F815
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=aK+8VjyI;       dkim=neutral
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

On 2/12/24 22:38, Suren Baghdasaryan wrote:
> Currently slab pages can store only vectors of obj_cgroup pointers in
> page->memcg_data. Introduce slabobj_ext structure to allow more data
> to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> to support current functionality while allowing to extend slabobj_ext
> in the future.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

...

> +static inline bool need_slab_obj_ext(void)
> +{
> +	/*
> +	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
> +	 * inside memcg_slab_post_alloc_hook. No other users for now.
> +	 */
> +	return false;
> +}
> +
> +static inline struct slabobj_ext *
> +prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> +{
> +	struct slab *slab;
> +
> +	if (!p)
> +		return NULL;
> +
> +	if (!need_slab_obj_ext())
> +		return NULL;
> +
> +	slab = virt_to_slab(p);
> +	if (!slab_obj_exts(slab) &&
> +	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
> +		 "%s, %s: Failed to create slab extension vector!\n",
> +		 __func__, s->name))
> +		return NULL;
> +
> +	return slab_obj_exts(slab) + obj_to_index(s, slab, p);

This is called in slab_post_alloc_hook() and the result stored to obj_exts
but unused. Maybe introduce this only in a later patch where it becomes
relevant?

> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -201,6 +201,54 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
>  	return NULL;
>  }
>  
> +#ifdef CONFIG_SLAB_OBJ_EXT
> +/*
> + * The allocated objcg pointers array is not accounted directly.
> + * Moreover, it should not come from DMA buffer and is not readily
> + * reclaimable. So those GFP bits should be masked off.
> + */
> +#define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | \
> +				__GFP_ACCOUNT | __GFP_NOFAIL)
> +
> +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> +			gfp_t gfp, bool new_slab)

Since you're moving this function between files anyway, could you please
instead move it to mm/slub.c. I expect we'll eventually (maybe even soon)
move the rest of performance sensitive kmemcg hooks there as well to make
inlining possible.

> +{
> +	unsigned int objects = objs_per_slab(s, slab);
> +	unsigned long obj_exts;
> +	void *vec;
> +
> +	gfp &= ~OBJCGS_CLEAR_MASK;
> +	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
> +			   slab_nid(slab));
> +	if (!vec)
> +		return -ENOMEM;
> +
> +	obj_exts = (unsigned long)vec;
> +#ifdef CONFIG_MEMCG
> +	obj_exts |= MEMCG_DATA_OBJEXTS;
> +#endif
> +	if (new_slab) {
> +		/*
> +		 * If the slab is brand new and nobody can yet access its
> +		 * obj_exts, no synchronization is required and obj_exts can
> +		 * be simply assigned.
> +		 */
> +		slab->obj_exts = obj_exts;
> +	} else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
> +		/*
> +		 * If the slab is already in use, somebody can allocate and
> +		 * assign slabobj_exts in parallel. In this case the existing
> +		 * objcg vector should be reused.
> +		 */
> +		kfree(vec);
> +		return 0;
> +	}
> +
> +	kmemleak_not_leak(vec);
> +	return 0;
> +}
> +#endif /* CONFIG_SLAB_OBJ_EXT */
> +
>  static struct kmem_cache *create_cache(const char *name,
>  		unsigned int object_size, unsigned int align,
>  		slab_flags_t flags, unsigned int useroffset,
> diff --git a/mm/slub.c b/mm/slub.c
> index 2ef88bbf56a3..1eb1050814aa 100644
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
> +					    freelist_new, counters_new);

I can see the mixing of tabs and spaces is wrong but perhaps not fix it as
part of the series?

>  		local_irq_restore(flags);
>  	}
>  	if (likely(ret))
> @@ -1881,13 +1881,25 @@ static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
>  		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
>  }
>  
> -#ifdef CONFIG_MEMCG_KMEM
> -static inline void memcg_free_slab_cgroups(struct slab *slab)
> +#ifdef CONFIG_SLAB_OBJ_EXT
> +static inline void free_slab_obj_exts(struct slab *slab)

Right, freeing is already here, so makes sense put the allocation here as well.

> @@ -3817,6 +3820,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, init_flags);
>  		kmsan_slab_alloc(s, p[i], init_flags);
> +		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);

Yeah here's the hook used. Doesn't it generate a compiler warning? Maybe at
least postpone the call until the result is further used.

>  	}
>  
>  	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3cf2acae-cb8d-455a-b09d-a1fdc52f5774%40suse.cz.
