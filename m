Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4GT2CXQMGQEA7I4KSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DD3A287CBB2
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 11:58:57 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d33e6f838dsf14847511fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 03:58:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710500337; cv=pass;
        d=google.com; s=arc-20160816;
        b=niNn+48GVKyjtRrtYyppc7g6dHgA6SzGADueWOQOAb5TzzEPS+7emSXqdg3LWFkQ5o
         LSnAfEFpypMnOTLVxUxORPeTke5SMoUK+n1WU2IVh4HK+R0cqJ2jHEM/GV1zGEJmWNSo
         de/wX4hiANe8r4ykEKsZowy8WrSd2igG968lgiyu6Dha273geutdEwEvoscesq1N4WHO
         MKYnsQvQvaNxZISXFm1dmnI1K6EOpZefWGevEZesjabxOTGuR/VYn5QKfAZHhGrnaSzD
         qMjHWp3Sk2zU1dzurT5A2TZL1IzTClfYV6KRVsnBABxMKUjG78QtY3a7HC7gjtj0wXAS
         WMYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=M+67AxShjfX4C+A6OiHHaXdwkBlgH5M7ozYRvBa8Jx0=;
        fh=k6wdmlxzbGl6mzJ2kqW/3WOIiL99p+kWPl2amOsqbsA=;
        b=wQwi1OJHUre3E2SNTRaszT36Tlzbk59USj6z4vUTahZNfoUantODU+rwNfaA5a29O9
         EepLLSlM3u1tcfg0nC5nyugKQQ1o41SkPMYlyFCdYQTieulMi5Y07eGGx+ukkw0YV08Y
         guoMuX+uqDoLdphE0NDh2qrdBe8PrsIsP80TMZMQ7jftVjb6mO8Wa5jA749C/ouqST+f
         waYsuT5FskO8dMSYGmQwImJzNFP5UTEMOJdbQJa6f5EYWrQnLLzo+rDcC/Rn0CUwnPEF
         p1ysThBNqb3o9YS0v2a7ujEyv2zEEq1e/c6TWHPEV9VtAzYJBFkEEk/LUd0Hb2+LsgL+
         b6ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710500337; x=1711105137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=M+67AxShjfX4C+A6OiHHaXdwkBlgH5M7ozYRvBa8Jx0=;
        b=Qv5w6S5GmvNelxYNCMoWd/zFBsgeaouaOyKNLyp7Q65qvU7O+FquTMbvCmNFOE1dlU
         AcLjshRYImMgP0osP8wfrQvxz7iVHiwJuUg337V0IFeVTCIAFx7zK+rKfIp+Ir6FM7mE
         LjDpdzgIjHIji60Z4rNU3dACYmCL/kaFLpXqpsvcUM2vfLVC+r+sbMD0o0h4jDGTOS31
         FIOza75O6wQH+QKAHSmkgXYE4AjqoNW6TjPV8B4ovq8AV8fhlhlMGDrGFDIHY8Lcc6dG
         D4W5WVrUL9FrJPAaxNql8eiJbJzj0Ch+Xx1nAHPHQ9yCyVRoLwMFkLaAntNE3Va9asdc
         C9zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710500337; x=1711105137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M+67AxShjfX4C+A6OiHHaXdwkBlgH5M7ozYRvBa8Jx0=;
        b=WdoMMn2HMcYWgyQ776WC7MUwhlVTgRSvLFmG0wgZWMMUX89P8gv6Hc3e1eRublvWQn
         DUEGHZ1JlKkBXJEfDa1YijoX5eiwLJiTkFKb+e7mWBvgmoO3Eq34q0XFkeih8A6InS/d
         3Q1JM3Wkkl8QMpCK+p4Vyk2RBdi1gbRFhLLb1N5FwaBB/G0CxjUHF7i35EtjapNjpKGi
         Xtl6r/emuO/iyow5CVGgg2zDABddtprEt6NsYkTaqM+DDeYfMrup7YtQQj+rd0m2pz97
         p4ct5McP9oFKoC5i/4mCsZz2pM/Hc2TknteFb+3eTJLbojRGgExFBCw7iveRsKwSxK06
         5ZHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW905XJ2lFkx5+IjGYOGpy067986AMIYlv85HYETgNNIPAhmXY3jzseoqXL1Jlu7xeSGQmmc02lr9P8J0Kk6Z7jTMuWakiRTQ==
X-Gm-Message-State: AOJu0YwRgUiBGTCWR5bEk8OBMpauKmN3uqNDLCIHxSVvpjhxyL4iZT5A
	BlRrqqaxwMaqLY/5iy5+AZp2dNdK5yEt3AFbzuuL194q7eqnNU4Z
X-Google-Smtp-Source: AGHT+IECXktr/9wdQQvgQmdyTViWEBe/vPrFKBqt2A5wquHIKO1XerziAsGXLuHxxzsBvj67YWuVAA==
X-Received: by 2002:a05:651c:1029:b0:2d4:2358:6f18 with SMTP id w9-20020a05651c102900b002d423586f18mr2959806ljm.43.1710500336447;
        Fri, 15 Mar 2024 03:58:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:19ab:b0:2d4:3db9:66b1 with SMTP id
 bx43-20020a05651c19ab00b002d43db966b1ls130222ljb.1.-pod-prod-01-eu; Fri, 15
 Mar 2024 03:58:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9jpuR2yD874kNoM3RW7DZTiwfMFYWXVN8TnTqVGXekye8OA6DwHYLrUGt46cv6TZQ9eR+yZFx2Gll/4qzQRxhGZw8pDMzALFvPw==
X-Received: by 2002:a05:6512:ba4:b0:513:3dc5:cd5f with SMTP id b36-20020a0565120ba400b005133dc5cd5fmr3547872lfv.40.1710500334437;
        Fri, 15 Mar 2024 03:58:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710500334; cv=none;
        d=google.com; s=arc-20160816;
        b=GR+DRqdGhYrPKr4pfmHl3ICsnBD1GSAy6AchwJPG2lyoHcJayTlyEik9g3WybZbRdJ
         nNSgNPRfcnG7fZ4AJv5zpSBjJ7chV28dXMpQ4ApLzCxx+DlmapELxPXilvMbsvNjX0pz
         I4AwozQqzuia8++F1tOM0z4WpcHfWWSreukYQMcQKJC68DF+D8U6AsGSYfNYEtTUOgRq
         OCt2KJeHHWr+bIWqLx9/BPnYyfGoYD+hcHTLdFI6F79hi4Mg76EiNA9NmzqN86WFnYPZ
         95BjzF/mTWCwcWdPFLH07ijVGJUpJR/DPk0J6miFkz5e1c66pE7ntSZTftl9a+2LP3uP
         TDrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=9muM8bo+rTj/3DcyAeA4j1Dljj8nhnMTXgWWpTVnpQM=;
        fh=Q5QK3mEHpiSw50+k3en+vN00KR+pxr1dxz1JLzJfHmQ=;
        b=dH7GIY5fApcka7dwKDTceUw2FSqkujv83nJfRy6Z2SvVf+8O0fRrH66gJjUVeRqV8q
         zkpJbKQCdCu7K2EPk6bxgReH9JBDNnNLsmbeS+dmdoaClWxNl3/ehsTDOl0EYbi4uJi4
         KJbLYyojjoqRNSPRcFzb/JhwcZ2cvrHI33fSfuwu7kru+iRNZWhYbP2UpvwOxr9IF4Rd
         /NyJxLUPy2keRtfBnkvk1AcQjmI8QDBO7KAYpaJacuaEiTyK3Fc20JmVh9aFdYuRFiS/
         1z87flNiEYA4tRL+7YbMj3Y0S+judcvDvykpf3ILnZ3/uUpgfHxMJDlUGOUaqi0JPXXv
         Azrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id z7-20020a056512308700b005132cbccbb3si196382lfd.7.2024.03.15.03.58.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Mar 2024 03:58:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4FD17210F0;
	Fri, 15 Mar 2024 10:58:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B4DD81368C;
	Fri, 15 Mar 2024 10:58:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id BxitK+wp9GU7dwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 15 Mar 2024 10:58:52 +0000
Message-ID: <1f51ffe8-e5b9-460f-815e-50e3a81c57bf@suse.cz>
Date: Fri, 15 Mar 2024 11:58:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 23/37] mm/slab: add allocation accounting into slab
 allocation and free paths
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
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
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
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-24-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240306182440.2003814-24-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[76];
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
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -3.00
X-Rspamd-Queue-Id: 4FD17210F0
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="kIeV/N+n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/6/24 19:24, Suren Baghdasaryan wrote:
> Account slab allocations using codetag reference embedded into slabobj_ext.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

Nit below:

> @@ -3833,6 +3913,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  			  unsigned int orig_size)
>  {
>  	unsigned int zero_size = s->object_size;
> +	struct slabobj_ext *obj_exts;
>  	bool kasan_init = init;
>  	size_t i;
>  	gfp_t init_flags = flags & gfp_allowed_mask;
> @@ -3875,6 +3956,12 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, init_flags);
>  		kmsan_slab_alloc(s, p[i], init_flags);
> +		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +		/* obj_exts can be allocated for other reasons */
> +		if (likely(obj_exts) && mem_alloc_profiling_enabled())
> +			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
> +#endif

I think you could still do this a bit better:

Check mem_alloc_profiling_enabled() once before the whole block calling
prepare_slab_obj_exts_hook() and alloc_tag_add()
Remove need_slab_obj_ext() check from prepare_slab_obj_exts_hook()

>  	}
>  
>  	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> @@ -4353,6 +4440,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	       unsigned long addr)
>  {
>  	memcg_slab_free_hook(s, slab, &object, 1);
> +	alloc_tagging_slab_free_hook(s, slab, &object, 1);
>  
>  	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
>  		do_slab_free(s, slab, object, object, 1, addr);
> @@ -4363,6 +4451,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>  		    void *tail, void **p, int cnt, unsigned long addr)
>  {
>  	memcg_slab_free_hook(s, slab, p, cnt);
> +	alloc_tagging_slab_free_hook(s, slab, p, cnt);
>  	/*
>  	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
>  	 * to remove objects, whose reuse must be delayed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f51ffe8-e5b9-460f-815e-50e3a81c57bf%40suse.cz.
