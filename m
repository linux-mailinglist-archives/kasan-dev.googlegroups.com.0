Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAF566XAMGQEBRZCVFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DBBB86915A
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 14:07:14 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-33d1d766f83sf1751997f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 05:07:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709039234; cv=pass;
        d=google.com; s=arc-20160816;
        b=oAeG4rMZruO1C9b6haoUrdjTO3va55TvNwPdSFWMU+X2SGH03MQ7HHGU6kAzKMKB9d
         UwtVBGFbwNR6inA9x+NOMq6k1mndqt8lH3e+Z/T6HCzoKiHGSgcphm4kb1z8y1coaiOT
         E3r7KLcARYuENEyJ03NVtEP2lDW00COgaRCJ3wVLBJwQhJe8EfGXRoaSIkxmfR/js8Ur
         Kuhwk8Dz1TJUPmPvrFLo4M/+onZHDUT8EYn74zDlhJy0dyO5D0kirYMIpay5RjBF/ikD
         wP862LnYfJ/gL1k3L+ITqiO5RtpW/7/YNevkZwBAANJPV2iCm+eptRmfCP/9EG6YHDfn
         s1xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=M7RZtFwStFs7pB0/OUXCgEehTY8jSZKRJKWusyHLve8=;
        fh=hKcxivpNQBzNFqQBvOUbivB3keU5smgr6kIPe9hHhi8=;
        b=hWKsXyyvyoSBKtECJeKj0RKomsWSzYMRSkQsH0wYDOCcssFSh+nrzX7dtZaSnH//gi
         HdD8ux28MhM3LU+ndnARaSbMK1vtdGwmV/z1ya4fVAcl/R0X04UdQMvDWpF1DtBn898K
         6yZxxQ+EII5hYBX68IuqTH+HIsLiO4e4ID0y1OM+RELGcBEmxSkn/7FvDtQbr1WBBYyW
         v6DmHn0/Nqa2DtvdPTIT3QN4xoO26bNJXLjEbxm1lPUl8JAUFsC0yZUXmHGoqCGEiqMV
         rwbDDGoOBNQ/SHGqh6kKblSfBbQ7jzSCEl86jtWsTsFtI4M3OzUtZIwuQpqoSZpKS/NM
         uxzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lLjXBkwS;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TDeXG6qf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709039234; x=1709644034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=M7RZtFwStFs7pB0/OUXCgEehTY8jSZKRJKWusyHLve8=;
        b=Cr6mBx6XFTCyou688QNqITaesxK508UoJdYlWaxqZqsIHA9FSU/fY6/GiQdtxlnCsS
         ysiFhevuyWyA+ON8piNY7aVok8rM8hle1ihwzHC9Y8I13//Lg0/3LJ/LHr18F33zIGHX
         Ovm2tURj2c1/8q5jcJCZWhMEbPZfqODhba31y8vyG0F302TN+y1Z8Ir5V0XkPQtmcnRp
         QmlbxQCeKgYBP2l3AMA03qiMCc9rsBJA1zLPIdcj18qeepEXJxu/1RmF/MTywxepx7Qt
         NVNtVyQqVfxd7UafDUt6FZXYhfJFZGD9nY+vp5HPMq/GB6Y9FUgM6tROI2VemiVpzacP
         l1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709039234; x=1709644034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M7RZtFwStFs7pB0/OUXCgEehTY8jSZKRJKWusyHLve8=;
        b=FG46A1SCg6E3CqWUXF8UvR/h6QwtX6IkaWgkIK7+LUWWA/oOYNTwqxRfQMeoQoFf+9
         b+zjPIGHqQpC9mybeRg5mjaFBcxovn/lKOBbGKcQMPWC0D4f0ppJjEIkT4naa9XfwrGy
         fSiug9/t+NFuuRUWKDZTH46Wmpn4Jwlu2oIXLltWX6kCQAMv3NfuRQxYJv60oQY155/E
         X6KDK/nZW1oNrrfAXHs2LwrBU2YWV6rM7szRqrzJuvLY5TXSHwXRTHcmrFfaBoaF3brF
         sBW25sp9uGQRuMMBmKGgteqCIDiOFW+CybOPJShXKGd8qRXYIXnKygc9ytj2h2JZ+qto
         tIEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVR2aR8ayaOTln5iolJlq0efpq3RHtQ8dow/OiILuyiJSWFIocGVSAqRrJTzPWHpmDIvRpMqSWFU4KZh1PyTgYMzFkunps+9w==
X-Gm-Message-State: AOJu0YxyZdFa7haGc8IhBeLfogHVqaKc8eqUikwmTON1QrDHcxK9wPEk
	OUm4cR6bj6finUti+BqL0WtB7JFEUaCxkM1gFCmzaVikRj/ZF2Pg
X-Google-Smtp-Source: AGHT+IG6Pt9ChdHJhoqkxj+XlbqLPD57iTGSmm5VEKxY/Fzq0Lx5b76FYG9+jBnbgBydIuZFrvRpRA==
X-Received: by 2002:adf:db4b:0:b0:33d:76a9:89ae with SMTP id f11-20020adfdb4b000000b0033d76a989aemr6677572wrj.12.1709039233058;
        Tue, 27 Feb 2024 05:07:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ac8:b0:412:ad33:62b1 with SMTP id
 d8-20020a05600c3ac800b00412ad3362b1ls279528wms.0.-pod-prod-05-eu; Tue, 27 Feb
 2024 05:07:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUE7x4Qr4BaZxByKxIpZMTQ4RPHVLkxCGw1bZ4VSenRCZaA4aDfQKYMmapl34IPyf3JAZFN/xyuMM3IYNsZr5Txi6h/cHCmzVRp+w==
X-Received: by 2002:a05:600c:4752:b0:410:c69f:4db7 with SMTP id w18-20020a05600c475200b00410c69f4db7mr7531844wmo.20.1709039231208;
        Tue, 27 Feb 2024 05:07:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709039231; cv=none;
        d=google.com; s=arc-20160816;
        b=e1HkWPVOueHo7qJHoTT3pgwxSX+h9OszcrPd70gYpHlvxRWl+gTu+SfpeV6K51+cM3
         bzAIwN/djvyDgSknWMIvMJP53NIJmGtQ3ogh6EAY7HQbFTqDcTB9uWrcd7WHAMyxUiQJ
         QGJiEFeJzc6GpI44C9mGhC/7sDGSrZ39IVmTqPNqZWCd4LwNtFdzF6hyXyyqwLCRhERa
         JelIGCnHMm3MQTPoNuQwktYWVtecHpAejwQFbwr+vUPhYUD/DfnGVAnRT6pfbmopxU/6
         5/V8RxLylMJF3gWtomgbCMaNCLxuRmPH7lxdtM01uhkp4FMCw3OosCu5yZemRbmIc4BA
         goKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=cW70zYu78ce27du6nFlEM9h9LcRqy3qIdoJOEMgxHrU=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=ut7vu5+Hni0l1lQ5a39BTULofMpeH+UKjpig5jqLJjq4T5eH66O5AIwxtshtqQeQ5p
         WhK0yEazKCvcgKKsmZJPFcW3grmX7ZExXw6DxBB/sblY+kO/skJDtPc4rUQxwKgyr/qi
         V5lWhBBs91CLf2Iml4cTXChXuhEF1CIzzxj/Ca1prpTwH2uRQFhDmyWG232xwbgvog2j
         +Mrz3oI1kBG5paAy3eDiV2A0wHE8Ri72Jd5omLM3WVCNhExBpcP0XLZAABBnij05iFgI
         iceUDcTcybWBNcCNaTLVcQn2T+Jm1QFVCC2+Wibcuw9MMlYhQLaVqczuox6C/Om5DDlq
         g/uQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lLjXBkwS;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TDeXG6qf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id n15-20020a05600c3b8f00b0041211adb88dsi459710wms.1.2024.02.27.05.07.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 05:07:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A36851F7B9;
	Tue, 27 Feb 2024 13:07:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F129813A58;
	Tue, 27 Feb 2024 13:07:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id XexAOnre3WWJKQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 13:07:06 +0000
Message-ID: <4a0e40e5-3542-4d47-bb2b-c0666f6a904d@suse.cz>
Date: Tue, 27 Feb 2024 14:07:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 22/36] mm/slab: add allocation accounting into slab
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
 <20240221194052.927623-23-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-23-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-1.59 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[chromium.org:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -1.59
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lLjXBkwS;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TDeXG6qf;       dkim=neutral
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



On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Account slab allocations using codetag reference embedded into slabobj_ext.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> ---
>  mm/slab.h | 66 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
>  mm/slub.c |  9 ++++++++
>  2 files changed, 75 insertions(+)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 13b6ba2abd74..c4bd0d5348cb 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -567,6 +567,46 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
>  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  			gfp_t gfp, bool new_slab);
>  
> +static inline bool need_slab_obj_ext(void)
> +{
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	if (mem_alloc_profiling_enabled())
> +		return true;
> +#endif
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
> +	if (s->flags & SLAB_NO_OBJ_EXT)
> +		return NULL;
> +
> +	if (flags & __GFP_NO_OBJ_EXT)
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
> +}
> +
>  #else /* CONFIG_SLAB_OBJ_EXT */
>  
>  static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
> @@ -589,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
>  
>  #endif /* CONFIG_SLAB_OBJ_EXT */
>  
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +
> +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +					void **p, int objects)

Only used from mm/slub.c so could move?

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
> +
>  #ifdef CONFIG_MEMCG_KMEM
>  void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
>  		     enum node_stat_item idx, int nr);
> diff --git a/mm/slub.c b/mm/slub.c
> index 5dc7beda6c0d..a69b6b4c8df6 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3826,6 +3826,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  			  unsigned int orig_size)
>  {
>  	unsigned int zero_size = s->object_size;
> +	struct slabobj_ext *obj_exts;
>  	bool kasan_init = init;
>  	size_t i;
>  	gfp_t init_flags = flags & gfp_allowed_mask;
> @@ -3868,6 +3869,12 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, init_flags);
>  		kmsan_slab_alloc(s, p[i], init_flags);
> +		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +		/* obj_exts can be allocated for other reasons */
> +		if (likely(obj_exts) && mem_alloc_profiling_enabled())
> +			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
> +#endif

I think that like in the page allocator, this could be better guarded by
mem_alloc_profiling_enabled() as the outermost thing.

>  	}
>  
>  	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> @@ -4346,6 +4353,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	       unsigned long addr)
>  {
>  	memcg_slab_free_hook(s, slab, &object, 1);
> +	alloc_tagging_slab_free_hook(s, slab, &object, 1);

Same here, the static key is not even inside of this?

>  
>  	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
>  		do_slab_free(s, slab, object, object, 1, addr);
> @@ -4356,6 +4364,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>  		    void *tail, void **p, int cnt, unsigned long addr)
>  {
>  	memcg_slab_free_hook(s, slab, p, cnt);
> +	alloc_tagging_slab_free_hook(s, slab, p, cnt);

Ditto.

>  	/*
>  	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
>  	 * to remove objects, whose reuse must be delayed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a0e40e5-3542-4d47-bb2b-c0666f6a904d%40suse.cz.
