Return-Path: <kasan-dev+bncBDXYDPH3S4OBBPHN62XAMGQELFBC3LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AD64868D1D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 11:17:34 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2d25a02f48fsf33154121fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 02:17:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709029054; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fik+KMZIhfiRptc8TlxNpWehunFerUgpXo4lBrlOjAV6548sqBUMNIry3HKccor7JM
         hzNyiVfTx1u6SL97/DoBMTr8B+RK3yA1i0SIb4IVSrzE7+PunoOnbfqiP12m7BFdMB9G
         6CH8JR2kTXyfZht6eFRBwOd6GGkYf5qARPhIrZvRT2+JO4/wfEtnm81t9S02lTHkWO55
         qKmPfKsfArpXJvIgbHpKBgeoQD5qvORe1iH5Ekib+XjUxowG860xfinXFgsvlvQH/yIP
         OZ8Yy+pUBIqx8HHKSJ59kK4+nJfWwZut7XBeZZpPrMJdBdTKXuLHHfC4mkJs/GHvHuY0
         bWdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=KlUpghK4dTQbtVX5qZs4mAPfiMtTDH5GvU1vV7AxM4k=;
        fh=SiU1Q8Bh1LzongGLAHDPy+/x2ppwK7nLXcCf3G0RkHg=;
        b=zD7o3gmi4nyD9S0j2YnQ/MjBfxJvRJgodqP7Ns1vUBO7Ib5ZC2HpFFFgf3NfMnOsA4
         KMVHQnGIJXRFvbr3hsdOpi3xoK4pI3wlEC4eIGiHc05YTjqUDDGL0/YyKrnSBaM4/6vM
         RN0VbvsBK7E0r3gkatr+qPkIV8X798Mrs4SpkxTZr/pFLkgFhOsVQY5jcpSBkjq4TVm2
         oNPI9d3lIyczbAtYeWCBEjD79xsjfw1o+GWlKoi+bwAv9IkQV70Vx8/VDFfLtgPaZzmU
         PGvENlFsvmMkCdmMsGPvgklbj7JP1lD8Qz4GOcJHoUkVJpU1bVoNAiFGMxeYlhdlLOWz
         DK1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2SXuPYm8;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709029054; x=1709633854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KlUpghK4dTQbtVX5qZs4mAPfiMtTDH5GvU1vV7AxM4k=;
        b=isWRLMrGWKnZguTjpE5UNOUmb5VHakKJSJdO6fsxIvJCSoM0hju9/2tfThVcOqqEO3
         XmGAwNU/yKxsYo9bnGxnIPlwHltnoxVyjBQbxn9pkHzEFQj3wEAbLSsRY8O9pgDEFY52
         giBhmuqo+LKFzNctUaG2yg81zLyFuUzwUWxi+3qMIGnp7N/JBCq73DdOtJ0XU9sRa8pR
         FFkbLgF7wy/mTEjZFvwTWW8tz321jydp6Z+tyXOnhXI68rweeU4CUnPilbmqIhS5X/+t
         EJ30tqcLod7rP3vhISed3H5VIFeiZEvRGs7EvgO/fRgtHy5K5UZl22VnYkaE5aRU1LWR
         4qBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709029054; x=1709633854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KlUpghK4dTQbtVX5qZs4mAPfiMtTDH5GvU1vV7AxM4k=;
        b=FJODgVZLIbBaQ8WtCZhpce773vkJCeYgbXzwShHBEt2qAZTwqTXS4gy6/g7+PfoxfT
         sxpdCgKgWTs4NCFf+j061Te2TJMylTSjeBwNjDI565aYgjA4X2neUZgehan9/fNQ7Kta
         Iw05UwlD/l8sIOaPMnttEE4zQGZFhWBTyvn4rW9rQz8bL2DrjliMLBJkLPW6kfIsddqy
         ++ipuOLyB5XgrKZTJeE3ct2y0fwElyDvXMFdoEERLN8pheOkA5IIci9Fqwfb97VWMKfW
         7DKUxM5He8pa84Pup+HqD2EpP4wcq4e1sVz9RD119MkBY8+mJZXHg9urAZ3jOpY8DERK
         uVqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXo1RSU/iF4p2tmaGv8UCaOICTv2oBE2GrTm267w6XSc1XTrXfcb/sQFHIPNtIspIRsygbWa3abrixLdsE5KrcKGSX5xOuJqg==
X-Gm-Message-State: AOJu0YxjRd6l0uYo7mG938QRmPuxSllRfI1xiOfmqRL7dnRHpN4DhqvD
	RsXrMcmJjC8pKgHv9iZlL13AP2VgQc2RRbPFgIGt3LPun/wDhAXG
X-Google-Smtp-Source: AGHT+IFoacGps+oDMslVmH+andtT7gMx/4XASywBo8bUcKwHsLBJqvQV0wnylT63w9DFO2puprvWkQ==
X-Received: by 2002:a2e:2c18:0:b0:2d2:5f8b:1386 with SMTP id s24-20020a2e2c18000000b002d25f8b1386mr5466254ljs.10.1709029053162;
        Tue, 27 Feb 2024 02:17:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a264:0:b0:2d2:3a2b:ce93 with SMTP id k4-20020a2ea264000000b002d23a2bce93ls77944ljm.2.-pod-prod-02-eu;
 Tue, 27 Feb 2024 02:17:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKaCnPTqE+Zah0SWE5c4YOKaOLGOpEpyUPTEX/fYin/yt/7rifmODXdvzM/ux+//8ESXPm4xLEuJq1r2bwbjRyTvfgQcEka0BtoA==
X-Received: by 2002:a2e:99d9:0:b0:2d2:a3b7:da41 with SMTP id l25-20020a2e99d9000000b002d2a3b7da41mr527350ljj.43.1709029051319;
        Tue, 27 Feb 2024 02:17:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709029051; cv=none;
        d=google.com; s=arc-20160816;
        b=0UAmUbxubQK4OtukP17nHw6ux9OZXNBsEkPW/0/2xrk3FpbmI1EHmmmzdT/RjgmgZs
         2fsJPPOaSz1Q5oc/2YIFifA7J45iu9dldUb0f47JABHi/xybrUTAKgp6RjVGoiohZ7M7
         MGv7d+q0TAftgKmpCtV84gi9BfTKpBUAUbhTcRZxL/mZkX5u/lRwBB3BrlcrUek7oCNv
         3DOfZC1xu3jPV1yacQ4iCylLFXQccrs6SeAUl3YketXx9YVS68W98SjLoSZhywkKlgoj
         pIvOcPCJHe1gxQtfDEVG/Q2Sq/K+Oc53/xz1g9FCa39s/ENzGaZy2mLdmMw/zN/E2DyD
         +/rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=CWojS/ZBMHmeYzh+o2egixF9yHAOBC8s1LHQ5pVRk5E=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=ioyD6UW3l7ZAijpiF0kSgB4jEgt+1Jjn8YOubs+gv55mVL1xW8z4JzQcFcG5cvLMTY
         tonOWfDC4In5bdoN73TmXIr3EYUnRqeF1WARyX99DQuQv9rK+BldKOF35PNDJNewpMff
         2AyKTc+2NjgLqVy02HMymH8U/5EfZPJfjQgGUUhjRz4a4BSDL61TExSrEV/az+p97AgM
         SNVLFccMY+6YY8mFnHp85ghu+hqmPJ/oY4s1LJWrHhz0KuEddiCEncHJb8U0ZkxgVQ1c
         G6dMvwGrqNkJczol2oV1mHQ8YajgfXrrsd6WjDlBqgmBxYVD31YAa2Al3XGaUkeAHX+e
         sh1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2SXuPYm8;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id n6-20020a05600c3b8600b0040fe8290f9fsi36620wms.0.2024.02.27.02.17.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 02:17:31 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7684122721;
	Tue, 27 Feb 2024 10:17:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2F5E913A65;
	Tue, 27 Feb 2024 10:17:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oUVMCrq23WXqfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 10:17:30 +0000
Message-ID: <49c33680-2a08-4d59-86ba-72f8850099a5@suse.cz>
Date: Tue, 27 Feb 2024 11:18:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 20/36] mm/page_ext: enable early_page_ext when
 CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 <20240221194052.927623-21-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-21-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.11 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.30)[75.07%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Score: 1.11
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YYsNtmEp;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=2SXuPYm8;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> For all page allocations to be tagged, page_ext has to be initialized
> before the first page allocation. Early tasks allocate their stacks
> using page allocator before alloc_node_page_ext() initializes page_ext
> area, unless early_page_ext is enabled. Therefore these allocations will
> generate a warning when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
> Enable early_page_ext whenever CONFIG_MEM_ALLOC_PROFILING_DEBUG=y to
> ensure page_ext initialization prior to any page allocation. This will
> have all the negative effects associated with early_page_ext, such as
> possible longer boot time, therefore we enable it only when debugging
> with CONFIG_MEM_ALLOC_PROFILING_DEBUG enabled and not universally for
> CONFIG_MEM_ALLOC_PROFILING.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/page_ext.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
> 
> diff --git a/mm/page_ext.c b/mm/page_ext.c
> index 3c58fe8a24df..e7d8f1a5589e 100644
> --- a/mm/page_ext.c
> +++ b/mm/page_ext.c
> @@ -95,7 +95,16 @@ unsigned long page_ext_size;
>  
>  static unsigned long total_usage;
>  
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +/*
> + * To ensure correct allocation tagging for pages, page_ext should be available
> + * before the first page allocation. Otherwise early task stacks will be
> + * allocated before page_ext initialization and missing tags will be flagged.
> + */
> +bool early_page_ext __meminitdata = true;
> +#else
>  bool early_page_ext __meminitdata;
> +#endif
>  static int __init setup_early_page_ext(char *str)
>  {
>  	early_page_ext = true;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/49c33680-2a08-4d59-86ba-72f8850099a5%40suse.cz.
