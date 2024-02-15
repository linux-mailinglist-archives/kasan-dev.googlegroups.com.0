Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHUFXKXAMGQEZXB2EGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9AC8856F58
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 22:31:11 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-33d07e6074dsf437947f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 13:31:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708032671; cv=pass;
        d=google.com; s=arc-20160816;
        b=LRzXLo+rFAybn3GiUzZ5eMexDoNh+WIoJB5BxnNo+5cudN0HZ3ejC53cO4kjGVXom3
         He2PalA+bqB8fyogjFiNa6RKLwrskhLK/hQBBBwTzjy4H7/B9rdecCJlXUXV67yCmCIf
         63QvX5LJnnZtB8w/ZTMCqblfFtwkXqUlnmFL6YiqpKK4aaf+L76FHtMkHi/LYmrHXOrR
         Bae1WgGJuqVMhVLigaxmIG0oRIiSpmFraAJb0dhzYcLgAAv+Kse31Wib15SY+BreTXda
         J7OLTwX18SVd6+LJz9qEJ5fZjpfUCyHyYQEywFSTAe3NeP2q9seLnKPCwyylSN1LSegr
         kYsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tzIqbXRy3Y6FHTCq05VoleS+jQsMirBa5QDOeF2ulDo=;
        fh=lJtgT0R2ty5N3g/SIUgeFC+fns+Ab9wKb1zgwi3ESNw=;
        b=c+eYCL8vr/3O6UWCoDqPLcX5ujl6+QJI5yjQYUzpOTYm4golbwgZpPv9cBVFyNjL3P
         1Eslwzc5EL54MukPCLhLD4rqOzFUPGkORTe7GwKO1zh/4zgPDYiAgHKtaaL2lK+vkfwC
         jQqgNks5mQc8KWXLYxYmD5Igj2wmJANz763Ww9H5AKWjOVzC/CWbjTSj8bF1XGzdEdSm
         7K3QUruyV3ZtpDViXYECRWLTX1sXwc0ZgiP78LSz016Yy/WrGg7TkU9GRuwp6Upvrj3I
         N7BMYZeCBdJ/1IwsUiISzq5gtTVchBc9VcApB/M8KqoaDrFNm9d/TbOLeKRR6/ddSfq8
         KKRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708032671; x=1708637471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tzIqbXRy3Y6FHTCq05VoleS+jQsMirBa5QDOeF2ulDo=;
        b=qxl5avcO0SFeBA5vM3CGBOLW8UWcIeh2EMRSgXRNXOW2QdistovglwCFc/PmMWeNpg
         +ZBTuhn3BIGb2UDN9viixhqfspk1Df09eX9Yvv52NHR8Jg7sE+/nCvnu+SbgXkbUFpyv
         jfi5SRjqrLb7Y1Z5ur7LaunDUImkv15re5mgj5Wf7AFoZ3lr35jI1lnfcBIR36B/Of98
         F4PNfhRywPbB0c0lqENCZDwHAbUTB/oqCF+X/R6uLPdnkw4cLGjsBACZwS3rgEXSZnp1
         h+/5pGa2UVqtZm8Sfq9XgRDL5N3Lkg5PymXum48S3Tj3DqnbUhpr3r1AjIg/et3CKrBD
         Iv2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708032671; x=1708637471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tzIqbXRy3Y6FHTCq05VoleS+jQsMirBa5QDOeF2ulDo=;
        b=xALykBFg4CqQRKjKpi43ShyDg59kzCBMUpKgUhBWeaeGQsF5qF/Ftqz3P2BRjvBN3U
         sZYvIrGcx4ZpYkZ8G1oInvn/huPq2JfgkDHBnvPsvBBi/hMqtRhSDF3IipWks8QH09dD
         1pKt0v5MLDwddbXq6wL8fbrct7QYKg/wuRsT/VeqP8+T5z0FAXQejTcrfKdxK+xK0IMD
         ZB5f9Oh8fbM5+xVX+FyEWT0NUM+lH8RG6vuLeY5il3itNQ72rfAovfoGz/ZmjzlH66dG
         ye4OrLPY6QVidVPmEkUIiw+yx496JEtPWsBgVCwTBIh4113udYxkeziT04z5OFHsRov2
         LySw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBsrGFNNfwxn9SnNO1zV2fo6LvT1Els9OnoZWd/wZBqpn8NKrjT6fV38QemJbwBRnr8lFb8NEFDQf1/LfuYzgpylKu6FxVgA==
X-Gm-Message-State: AOJu0YwIktG+2Nm0O5HsyxASVRgBbxiVc2WjBiDDJ4kCoP91Ha2sMRVE
	ORqCWXqUO/+SReOADbGoU4taASEM0w25kuXz4MDfCx1KQRDg3IMa
X-Google-Smtp-Source: AGHT+IEUJMEeNZGfTyGNK8zsDrPCL6E3AZnpmAt9H52H5yBq8rtamADjvveTEYImGNPorykrofGDIQ==
X-Received: by 2002:a5d:64a7:0:b0:33d:ed3:e70c with SMTP id m7-20020a5d64a7000000b0033d0ed3e70cmr2719257wrp.28.1708032670779;
        Thu, 15 Feb 2024 13:31:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5025:b0:410:d600:ef96 with SMTP id
 n37-20020a05600c502500b00410d600ef96ls48365wmr.1.-pod-prod-00-eu; Thu, 15 Feb
 2024 13:31:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUN18DdTWlNy4grqgsKZPKtXgFilq5qIKRdl1N8DPXqbym77Bp8x+B40ARZWW77iswyRa938vh0uZSIhtNOOS/AQfpOmS5xbpes1Q==
X-Received: by 2002:a05:600c:474d:b0:411:fe8d:6f0 with SMTP id w13-20020a05600c474d00b00411fe8d06f0mr3458923wmo.20.1708032668927;
        Thu, 15 Feb 2024 13:31:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708032668; cv=none;
        d=google.com; s=arc-20160816;
        b=GbWrk8YYzVrSXGS+3qJYhL9g5cpqmko13bgs7iiWdw11socFVf0no9rDmtm4Ji28a0
         cCpLqMkOEViSBASxCC+6OLlGgceQpQhhXZTRsNCHOpUseCN/NpivY/13vwd4am+mfhNN
         2VqCTsYsvkrIGttXsSS6PneXXPRvf9X94wYeCIPay9Qc72Us0O/+xUFzrPyx2MCtukl/
         LRMFQ5RbeHu9EqXFdNzR3diShtQNdH+bCX6ANpr72+EiSjslzPOGPmchIZn81AoSpXuB
         AmXIrcDz3dNbkyJgq5ewH8ltrNJlg6bVl7Kklgf+CFHSgRlN9c1Z3ZMtobeattzRt5JH
         Qipg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=A6ZvPT33F9NrnVg8JxGTJmzEamMsclNNB8LU0yx6M8A=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=z8aklDPe2fyQycFU3ev4ObZvr2zmrXO9wqEPe4C29Z4dwejz9NKCWGdvLexJ6XaR3S
         TJop/i1l0gfJf1tj+n/CnfT43qRUym4iknBbVcjS0/AKxTpnskuCi8Uz0kJUz3nKACVR
         LXTiEjcsi095WH7IzNsWo5+Ew12vphcbAvbfUluci9zdC4mo11RYFZ3acHwWGQ+Em4/x
         VNu0TbRZUExnb8vV9KF6m5oxiZZZluWqRBy1kBgbuiyqOL2nnbtrcOkbjET1uSUP+puw
         QxprgMmridZTnwcpTuZ8qLfP1xJ5eEvwV7yeq3l2SFRFNacBW1+uAh5eVDglVzdIVvpD
         zBmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id y9-20020a05600c364900b00411fc619abfsi9775wmq.1.2024.02.15.13.31.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 13:31:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 50AEE1FD40;
	Thu, 15 Feb 2024 21:31:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4D6D813A53;
	Thu, 15 Feb 2024 21:31:07 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 2LUvEpuCzmWGSgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Feb 2024 21:31:07 +0000
Message-ID: <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz>
Date: Thu, 15 Feb 2024 22:31:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
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
 <20240212213922.783301-8-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-8-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.20 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[29.02%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.20
X-Rspamd-Queue-Id: 50AEE1FD40
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=E8Nsov5u;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
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

On 2/12/24 22:38, Suren Baghdasaryan wrote:
> Slab extension objects can't be allocated before slab infrastructure is
> initialized. Some caches, like kmem_cache and kmem_cache_node, are created
> before slab infrastructure is initialized. Objects from these caches can't
> have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
> caches and avoid creating extensions for objects allocated from these
> slabs.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/slab.h | 7 +++++++
>  mm/slub.c            | 5 +++--
>  2 files changed, 10 insertions(+), 2 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index b5f5ee8308d0..3ac2fc830f0f 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -164,6 +164,13 @@
>  #endif
>  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
>  
> +#ifdef CONFIG_SLAB_OBJ_EXT
> +/* Slab created using create_boot_cache */
> +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)

There's
   #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x20000000U)
already, so need some other one?

> +#else
> +#define SLAB_NO_OBJ_EXT         0
> +#endif
> +
>  /*
>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
>   *
> diff --git a/mm/slub.c b/mm/slub.c
> index 1eb1050814aa..9fd96238ed39 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5650,7 +5650,8 @@ void __init kmem_cache_init(void)
>  		node_set(node, slab_nodes);
>  
>  	create_boot_cache(kmem_cache_node, "kmem_cache_node",
> -		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
> +			sizeof(struct kmem_cache_node),
> +			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
>  
>  	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
>  
> @@ -5660,7 +5661,7 @@ void __init kmem_cache_init(void)
>  	create_boot_cache(kmem_cache, "kmem_cache",
>  			offsetof(struct kmem_cache, node) +
>  				nr_node_ids * sizeof(struct kmem_cache_node *),
> -		       SLAB_HWCACHE_ALIGN, 0, 0);
> +			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
>  
>  	kmem_cache = bootstrap(&boot_kmem_cache);
>  	kmem_cache_node = bootstrap(&boot_kmem_cache_node);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbfab72f-413d-4fc1-b10b-3373cfc6c8e9%40suse.cz.
