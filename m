Return-Path: <kasan-dev+bncBDXYDPH3S4OBBH7K62XAMGQEFZZ22VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 1915B868CFB
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 11:10:40 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5655cb0e849sf3022950a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 02:10:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709028639; cv=pass;
        d=google.com; s=arc-20160816;
        b=aquyFVvrCJzvmD7/2wKJeJeR1dkVbHlADvm8CIAIDFvXRvGqJbE7oCPCVGpxEgF9zJ
         cMD++TR/cV3+p22lFae9CND0lDz/TouUnDbRNLe+aBa6H08p7gejvDosuagPsDF4F7V0
         FZYxzAPmxZXsk3vmgLsrOMAB+DTZ4FRdGTVYy1wEC0e5qFu/ClyOiSIisodyy35o3+fa
         L30cBd3ga5puVSQZFATckg66dj0T8SrRr2KIQ2AN/H+0Jf1uStTnFW15j5/1/Uim+hP4
         qqlhzlw6rUrpg/7PtWiweqjpx/4WjNohGV/2XH/OfFuUab1W+gaCDFyKAe6WvENqi581
         hIVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=C70+in31kSiQVVPublssnO0yF+rU+WVeupgZYGQ/e6E=;
        fh=HpBUmgg2u4iKSKF6ff0yzEv7Ypps6v6/icRoH9VwGoU=;
        b=nKhjKFdctTPmhGbYzm41hqWwBzFLclC5JHy1ilYf9ezqUCPtV32ELdSUtUUcXPq1Y/
         SPsRSFOjCCXTXFVv2cWdjmhwDbwK5AZhpoa4U8irVKitzyIIl4847N5sr6KBbHIaZ+th
         CaV34PuJ2ZF/C2ZOa2ukTSdvfj3YRnzeEPkatITa2Z13TYu7kk6G0h1J4Hq7XUeo8Y4G
         2bVWjEA27nIm2T33B4BJ49daAC5QAHEYpqCBuSHR007pVkVc4QU7YyJWR4hoHSMSuxqZ
         93QEx9+CmVUWQuAQxboVP+fEEft1hfZsZufmMAu+zqJ2VHXye7XKDR/CdXdKKp3vmxqe
         m2wg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709028639; x=1709633439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C70+in31kSiQVVPublssnO0yF+rU+WVeupgZYGQ/e6E=;
        b=ehBqoeIob+rv5LG4erTA0HvxY6BDqqoXL98yoAAgo7utcMVCDG/Gx84kP6PUF9EZoH
         hH9qJmPMQMwHk39ziCID/tYAB57+OnhVx597DDbSBY6kzsxV/mi3qjQHaYLP9Y1FKPgb
         SQQEWQeGiP/dQWCDeH/SU1ZUvazSrNtl/K88C8dYS5Q4hlDgh5hDRf+Bt7H5SlrFyJ2f
         T2cQOI9zxgfSiGf6yFldAJSTxk65f5fr5Rco1wKV6Ow3AB3o29NVh0c4AO0zAmAKZbjb
         wpovJWcRpKxv/9PFauTso7X1aVEcNxlj1nZGQqwXe+Mx3kw2V1cdYEGO1EfKNjQMDt16
         +aEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709028639; x=1709633439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C70+in31kSiQVVPublssnO0yF+rU+WVeupgZYGQ/e6E=;
        b=Zqy+4r1vO49fWrkvLGP4w646ip2HhQHgDmUAF0RZ+O1x7wszU1mat31N7lsgbc4J6D
         o0Og+WbD9atWygyl8s1SQe1KvambnYvSk0uYe9GlJXFGYlA4XWZnZup28T4EMUAqO8ob
         wlbwHbi3gYNK50FqJOcTGA+xOOYtjycy0hWLab7FdHoO72dtPNTBzCnn2CRQ/Rj8QcoA
         TpPoHLqLIvtDdjlbwWtIjHMlQfkUcILIsPvAteuKGJZlxN/q6LnZSeyLfmb/i3erPYO7
         ElB/zOtzWEU83yH+/UbymdJ3CWTAIXD/uocKSTKnuxmix4nurzaiXLyaL+tP6DAFjNej
         KUzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuQdrrWYSD2AuDM9fFTAkQ6EvjE49QNf7BNUbfVETe2HVG2UJ2G98tBO9i48D34+ElnE+1jgpoQGJq9xHa1jOnyY0PYTEZWQ==
X-Gm-Message-State: AOJu0Yw/bHy5HgIfJCzUlhC4CLQiSQZ/04z8/Lz3uC+6TtR8uxKalwr2
	ORPHahS49VdzUsld2LfAU04AMSM9SiQNFk13DbAc6u6Lpr2wtVJp
X-Google-Smtp-Source: AGHT+IEXAoeeTV+9o4mzFUiXvn0TQmOvhJlBiGGzRJchebh8/WKA9OUVaE5vXdHpjatEH1FDeTGSEQ==
X-Received: by 2002:aa7:d388:0:b0:565:bb25:bb79 with SMTP id x8-20020aa7d388000000b00565bb25bb79mr4665259edq.28.1709028639460;
        Tue, 27 Feb 2024 02:10:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f24:b0:562:c01:5808 with SMTP id
 i36-20020a0564020f2400b005620c015808ls854692eda.2.-pod-prod-06-eu; Tue, 27
 Feb 2024 02:10:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXL2iBeAxMnTuvyzThzHBQvzZr4p424CGd25ILFdUngziCBMLH5P5OboS5aVksPE0JHL03xhsOd6AoXg77SBDKPfsh4bJ85L4Mypg==
X-Received: by 2002:aa7:d80f:0:b0:566:743:25b9 with SMTP id v15-20020aa7d80f000000b00566074325b9mr2682239edq.3.1709028637745;
        Tue, 27 Feb 2024 02:10:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709028637; cv=none;
        d=google.com; s=arc-20160816;
        b=rhiXK5tOwZEVNGdfHk3FnAttVtZR17bKwZxMMx648ewgLXb/ta9u+bwr7a+ok2uhsv
         wrjnPO5rljUCPoojonm22yPXGVcF5MZk+PUJkrwgETEfsIBCeZDDFeiB4Xbf/BfKOcRH
         pj99a5RBOCdTGEajTEHalVfUReKNxedbOz+bWDekP1WV0dTeKscnN/v+//Isam1VkXWd
         MNrtMkF3EBE9ro2j1mrBxUS3EDPDCxbjPRP9QQ9yyBLTlEHoemuGUOpRAwMGMy436AS2
         lywvHRierBghbvAvY/2Edj4U3O8Nrz2d99xcyB0DzJBKd+8QW6PrWObxdjUv8CvIKHRH
         Y1MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=VEOHXhvS8pNNR8cMkMn4kxWIAkdQZXWg7A8CfENtHNM=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=fXJn1mvpA4UyPE/588vFEliZAbLsE+QfEQS9Xv2DVotqj/ObQHvo4zOrSiFgNF8wc1
         UzTgyVcbmPJet5/0UdsyI9fPYreqXsb4G6/jjYa9rAeGED/EwrMX/CS8Udm2OCccscg9
         esnilb92+ViCuUvtWcLsZ84mI2XqfcfispYOFhW8WR0jQF9Jc/mpFJL+2BkEOXjzudyI
         zoVJgViBxxvgKkkoO89OTE2rQg9Q3NndgcgddO7zXJvKbVbba0q5GX9VigZuoOzSGMw1
         eGO5v5pPKZK5A7Kle+i1juzu6zh7aBpKZQU/gV4/v4/fFH7+B6OOSPmzYBTdhq7e5jil
         F//Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id g15-20020a056402320f00b005664c40072bsi4401eda.0.2024.02.27.02.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 02:10:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 142E5226F8;
	Tue, 27 Feb 2024 10:10:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DF8CA13A65;
	Tue, 27 Feb 2024 10:10:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id TYO6NRu13WUkfAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 10:10:35 +0000
Message-ID: <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz>
Date: Tue, 27 Feb 2024 11:11:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page
 splitting
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
 <20240221194052.927623-20-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-20-surenb@google.com>
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
	 RCPT_COUNT_GT_50(0.00)[74];
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
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -3.00
X-Rspamd-Queue-Id: 142E5226F8
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NRedWJGW;       dkim=neutral
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> When a high-order page is split into smaller ones, each newly split
> page should get its codetag. The original codetag is reused for these
> pages but it's recorded as 0-byte allocation because original codetag
> already accounts for the original high-order allocated page.

This was v3 but then you refactored (for the better) so the commit log
could reflect it?

> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

I was going to R-b, but now I recalled the trickiness of
__free_pages() for non-compound pages if it loses the race to a
speculative reference. Will the codetag handling work fine there?

> ---
>  include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
>  mm/huge_memory.c            |  2 ++
>  mm/page_alloc.c             |  2 ++
>  3 files changed, 34 insertions(+)
> 
> diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
> index b49ab955300f..9e6ad8e0e4aa 100644
> --- a/include/linux/pgalloc_tag.h
> +++ b/include/linux/pgalloc_tag.h
> @@ -67,11 +67,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
>  	}
>  }
>  
> +static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
> +{
> +	int i;
> +	struct page_ext *page_ext;
> +	union codetag_ref *ref;
> +	struct alloc_tag *tag;
> +
> +	if (!mem_alloc_profiling_enabled())
> +		return;
> +
> +	page_ext = page_ext_get(page);
> +	if (unlikely(!page_ext))
> +		return;
> +
> +	ref = codetag_ref_from_page_ext(page_ext);
> +	if (!ref->ct)
> +		goto out;
> +
> +	tag = ct_to_alloc_tag(ref->ct);
> +	page_ext = page_ext_next(page_ext);
> +	for (i = 1; i < nr; i++) {
> +		/* Set new reference to point to the original tag */
> +		alloc_tag_ref_set(codetag_ref_from_page_ext(page_ext), tag);
> +		page_ext = page_ext_next(page_ext);
> +	}
> +out:
> +	page_ext_put(page_ext);
> +}
> +
>  #else /* CONFIG_MEM_ALLOC_PROFILING */
>  
>  static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
>  				   unsigned int order) {}
>  static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
> +static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
>  
>  #endif /* CONFIG_MEM_ALLOC_PROFILING */
>  
> diff --git a/mm/huge_memory.c b/mm/huge_memory.c
> index 94c958f7ebb5..86daae671319 100644
> --- a/mm/huge_memory.c
> +++ b/mm/huge_memory.c
> @@ -38,6 +38,7 @@
>  #include <linux/sched/sysctl.h>
>  #include <linux/memory-tiers.h>
>  #include <linux/compat.h>
> +#include <linux/pgalloc_tag.h>
>  
>  #include <asm/tlb.h>
>  #include <asm/pgalloc.h>
> @@ -2899,6 +2900,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
>  	/* Caller disabled irqs, so they are still disabled here */
>  
>  	split_page_owner(head, nr);
> +	pgalloc_tag_split(head, nr);
>  
>  	/* See comment in __split_huge_page_tail() */
>  	if (PageAnon(head)) {
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 58c0e8b948a4..4bc5b4720fee 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2621,6 +2621,7 @@ void split_page(struct page *page, unsigned int order)
>  	for (i = 1; i < (1 << order); i++)
>  		set_page_refcounted(page + i);
>  	split_page_owner(page, 1 << order);
> +	pgalloc_tag_split(page, 1 << order);
>  	split_page_memcg(page, 1 << order);
>  }
>  EXPORT_SYMBOL_GPL(split_page);
> @@ -4806,6 +4807,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
>  		struct page *last = page + nr;
>  
>  		split_page_owner(page, 1 << order);
> +		pgalloc_tag_split(page, 1 << order);
>  		split_page_memcg(page, 1 << order);
>  		while (page < --last)
>  			set_page_refcounted(last);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2daf5f5a-401a-4ef7-8193-6dca4c064ea0%40suse.cz.
