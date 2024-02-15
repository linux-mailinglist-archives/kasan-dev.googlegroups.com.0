Return-Path: <kasan-dev+bncBDXYDPH3S4OBBJ4LXKXAMGQESF5YHVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FB5E856F7A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 22:44:08 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2d0c647f8ddsf15726121fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 13:44:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708033448; cv=pass;
        d=google.com; s=arc-20160816;
        b=PFv7zodr32rAEcjo8IesSYQYxoYM9nGsvNnqUbDnK3vh4Qd5qb25gBHuTId21BpcXw
         8YUoUufVCiyG5ZEZfGB3fvd/7WVBD8As2XKjEcV+UprFKqnSnZRHIQfVTpluWZ3yKfLU
         D0+Z4HfJ5e5+Vb30x+d22/NBXZTjGIKPt0DZ1i+IfoIbGPnhtpV5vO+rCAsAcuM8FVew
         vD6p6QRxKpVqRdj/Fzbbk8lcXx7+xT8Kne+9VgJg4AZMue1BZDZT8lEbCjcMJK/AmWhy
         O9E1lajj5J+TooDJ4iYyNnERdvN5jGVkMYgVyiJlieAxOgNQ6dj3wZaUe945eQf6heQM
         zlAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+z28Wv8KCj7v8mFwc7JhJwVLmj8Nla6tP0TYgpt4xW4=;
        fh=cNBVjLPbxnaM5BRZuwtYAbAcOAKlKMuU824a+hRO96I=;
        b=hgcUhX0p6+Fo7+fpRf/tL+J9xX4j1oUNFEy+KKtuA7HJnny7iWXNtWlFML0J9T1q7X
         BXCmULAWFvSTLAM2GOlJEiGXzUqCqQyyKiilt44q5Zo5pSXndvpGwcqZC1i0FSRCwHox
         GEsRZ7P+zMdLE7lLhcOYKBr7G8ck1BKLWvHCk9L0KeEw4qNSNLcNW5gmo219SjAYYcPO
         X/aOrVIULVMlUamGd2jq9i2AUNwQU7kwq9PtelTZXFtuOVJjGpkQiloeLaHfIKriKE+S
         O+mHLB9t4TB8pt4tW2qfugG+NCSVyF0dC/nZXvIo2HXZpHH1I661qst4exDLLDRlh5pV
         IXew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708033448; x=1708638248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+z28Wv8KCj7v8mFwc7JhJwVLmj8Nla6tP0TYgpt4xW4=;
        b=PS21jHddaocv/gF1ysPpS3Osw5nuwRh3NibmqPe1KxWyfJBSKvX5uFmetifdC7lFSO
         +Ews2MODfkAARWrXSPmGmcgPqstieih7Av5FlRGy2hIjqgsOVzAr+ReM35zRHuoEHqOl
         oHdDub/dszEFoBXYxIhuelH2RSKPVNOL8HFxw1Qx5BP4ctuVosmw4DTzVtYeN0xhNdtz
         SItfwe159BU1EK3IjtXjn8BlSNlP8I3n7j8sqpTA/DLNwY3rLp/UjpG6DEZDSmf+AKtm
         T6maCT4ftxzQ7h75LMEt9SwxeHno6g9E3qZXT9yNOpK1B4BwzIZ80hvsAc+xqiQn/oAQ
         Kvmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708033448; x=1708638248;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+z28Wv8KCj7v8mFwc7JhJwVLmj8Nla6tP0TYgpt4xW4=;
        b=kpIDOLkpVLyF4hc0PcGcsLQZR8yJ6NmhP4v1eoSTHc6QrcbwYn/97oJeT1yKhneZzX
         L/wiMj9nIllVPbp69ODkJOVnEZJYXUO+gW36qftV1tVH+WuNvN0fxHDrXlwbSsMtrfjb
         PI1t7YM7KNGApIz1i1w+6SOVx4DyJwX0innGXAH/i/THfikjr2aIJWUUfCbhavWztszs
         TU7FuNA/eNHNdaTAUdev9TIM5pQSR7DW5ztwFsu21w7bljG3fuUpblEG9F75jsGuNkf5
         gVm66N+wre6EoWM1oqyhbjzSXw0FQdVH0O76RPlDLks+ri08N4UanBhqSCp/BdYmPlWy
         JyQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeBdZuSol28MHcyEk0Luf0STilRpiOadL/KqP3oGesGddO572P6HOj74Y+812wwsTAOBrnnZnkmoToWZvrdudAS4wsfPAnMg==
X-Gm-Message-State: AOJu0YxWNs71LzHRHEdSoyRKdrfvp3ZLWJtfuzA/5vTdj5HwIukgXCHD
	WRnDYkeZH9fz9dsy7nz5oVqWC9vfBKtEMn8A3xhYUgZflHULQuHj
X-Google-Smtp-Source: AGHT+IGuFTjCzAEEo43Ig3cS9Uj0q/uu0eD3yJXtbehRIrZP6P0mYgug8F7AXsxWoOQqsAheo+aUBA==
X-Received: by 2002:a19:e01e:0:b0:511:42b5:5616 with SMTP id x30-20020a19e01e000000b0051142b55616mr2123556lfg.17.1708033447219;
        Thu, 15 Feb 2024 13:44:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:138d:b0:511:4864:dd3d with SMTP id
 fc13-20020a056512138d00b005114864dd3dls123579lfb.0.-pod-prod-07-eu; Thu, 15
 Feb 2024 13:44:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGDm3Ab0K9iYE+A1PrcuVMNjfzjoG9Qv3rZCWXhb7p7DrRlk6j9IccwzaDYrsilUTQ6J3vPxdl5aKZHROhW40Yc87Ve5nbs4Tlkw==
X-Received: by 2002:a19:9156:0:b0:511:4e8c:7d02 with SMTP id y22-20020a199156000000b005114e8c7d02mr2350331lfj.48.1708033445245;
        Thu, 15 Feb 2024 13:44:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708033445; cv=none;
        d=google.com; s=arc-20160816;
        b=eWLgeA1U3wATWmBT8nDWMXI/OBzVrYKO7/qCFSZP8a3Jgduh8syMoYfHOEUr5wgq5u
         wuDKs76Z0FpwaHF2HzoGkQAnnzLHXjvQHe02WmUKcjouQ19+Du671ST/TbjYrUnyQZKa
         qjoXfZn/140OSP5EpFYwwtMRqlcAUnYRS/tatUFoMK9Ky5u1PDvMp6rszl9Syt9RWExC
         iikD7BvZUQgbNvtiNs4drS7UH7WrbTD/mWOBvbsk6ID8XpN8GhA5mptuajp7T4R16QBd
         8dtk77WWKREI43F0JuR6VvZ/YnTwGxZ05jiPxBlIFYgRsxA7Us1wVBgVYTVAx5UoU5KB
         ISPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=sQY+F3nMlxstoB6O6HK9gnIcEp2qVMn7wy1cyDkxwTk=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=zyjqVglo4j1wNR8/i2KTnhgYaUkgJAPM6OoD1zW4m+KomJPiu72WFSfRPR3NM3oWt4
         RoDTDfL1Q3/o33wnoHnfyU1+jza/OlWlTQTREp7C1M9bh8oAqRUJlgQvWOoWVO1ypnyp
         LegJjL6az+FW7jvZnk7gKdNDgQwWPv8ugetmg0WZX49hVdEUK+4+SSNzVCcX+iaXky0w
         icbfXFWIcjic66LTjyOpoXZCJ29sQoNqXeE++C/rpV4egJ+Em8KbWwf4W+nPXRb1UmQv
         egJUqElJPY7/ctW42lgiXUiodjATMNt+nMgoBXTOWsxxLGBIEUpNFSaNIxeFMR2sIRJX
         TsuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id g10-20020a0565123b8a00b005116bbbbd07si74318lfv.12.2024.02.15.13.44.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 13:44:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 632D9220D6;
	Thu, 15 Feb 2024 21:44:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6209F13A53;
	Thu, 15 Feb 2024 21:44:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +AxGF6OFzmUvTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Feb 2024 21:44:03 +0000
Message-ID: <02cb04cd-0d8d-4948-b3ef-036160c52e64@suse.cz>
Date: Thu, 15 Feb 2024 22:44:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 08/35] mm: prevent slabobj_ext allocations for
 slabobj_ext and kmem_cache objects
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
 <20240212213922.783301-9-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-9-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: 0.21
X-Spamd-Result: default: False [0.21 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
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
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Ay4ravC8;       dkim=neutral
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

On 2/12/24 22:38, Suren Baghdasaryan wrote:
> Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
> objects. Also prevent slabobj_ext allocations for kmem_cache objects.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  mm/slab.h        | 6 ++++++
>  mm/slab_common.c | 2 ++
>  2 files changed, 8 insertions(+)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 436a126486b5..f4ff635091e4 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -589,6 +589,12 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
>  	if (!need_slab_obj_ext())
>  		return NULL;
>  
> +	if (s->flags & SLAB_NO_OBJ_EXT)
> +		return NULL;
> +
> +	if (flags & __GFP_NO_OBJ_EXT)
> +		return NULL;

Since we agreed to postpone this function, when it appears later it can have
those in.

>  	slab = virt_to_slab(p);
>  	if (!slab_obj_exts(slab) &&
>  	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 6bfa1810da5e..83fec2dd2e2d 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -218,6 +218,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  	void *vec;
>  
>  	gfp &= ~OBJCGS_CLEAR_MASK;
> +	/* Prevent recursive extension vector allocation */
> +	gfp |= __GFP_NO_OBJ_EXT;

And this could become part of 6/35 mm: introduce __GFP_NO_OBJ_EXT ... ?

>  	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
>  			   slab_nid(slab));
>  	if (!vec)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/02cb04cd-0d8d-4948-b3ef-036160c52e64%40suse.cz.
