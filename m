Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDHO62XAMGQEIFEACEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 843B0868D29
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 11:18:53 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-512f500e780sf2221884e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 02:18:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709029133; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rb/2bRdKqlRaoblJ5Gl/Ga97jjWgR00q2fP/mUc4OFdqSbMHCf1/iYHgF4+vGsy2Ok
         SnsJ1WEWYCs/JqMe4Gl2eQkdNYuOYWO1NUU0SFocC73NEiQVWZCEjla9ukKoCrcoY3Lm
         rSApm0H+gHefBR7/c7ycnlR7UbLTIM+E4IGpos/jv+6Oiz80Vdf6boaHWSVkyrOVlONU
         /bZ8QjVhAmjnCMke3aM0QuxzW9kldJliDEJHEKyftfXw+QvC+5xukKW6KXN+VN5lABGb
         hHJP60xn70COIV66RXxDm6mTb7c0wFCtQqVESlzWZb46qZH+CAJeAs5tylk96js2dmXH
         FnEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Wfolz1dzZlKZ4zmUu4cbpFEZVAczsvqruzVYyYpnk10=;
        fh=t+7My/J214rQYpXfwN3jglNaVIF0V1WseIwS396UTLY=;
        b=iE/SDz+d0qbuH373t2Zp1IYGVWYXlxCcFKgsYjw8UWclOGgs94mIYz+kaTJD8l2hJx
         t8WTuRmBNyZn4dt5L5wHmOIyJVKV6bRuLdN5eAKsKmMplm3xvP1ZCNFAZA7R/25r36nF
         Fi9DDyzB84rtbAWY5afRianO5DOs/Zsvgjtp1tmgY8tdFvVQ/TdddDSQ4RPE4xHgc7ph
         QtGWm9txmRDBpz2o4BA2Uwbc8HMx5THmReZ/xfVQccRmKzORx74lNUssNCRb0P7fz6d9
         5cH7asjTL/3PLhZDwAlthiaH2mCrTlorI+L+363uDzXSoe5pAtRDKsNfJ360lOqJh+Uu
         7I2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;
       dkim=neutral (no key) header.i=@suse.cz header.b=UuxALrSs;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709029133; x=1709633933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Wfolz1dzZlKZ4zmUu4cbpFEZVAczsvqruzVYyYpnk10=;
        b=QoH48GKIBu/TXGpvHBVbmAClGCaUDQ74HrjQFwyFvrHufpyZXOAnlUG9zOvLj0LIoA
         y/S/01sgVY16ewRXnenjQ3CgOzegfIHQO57saLMK1DQiC4cnKD2QmRIKp+jwzqvF+UP6
         0B0NR0VylL3X+9WDS7ZhXoX0dKVfVhtjJI9jO3D35Xq64lcUla3qo9clx1x4/c9n6jhE
         zTjxXdAp7qkx56yoGTS6M602IMeIHo3K2SzTQrsL+4GZMueIsdy25ng95wyAfuMK8OwE
         SoFQTxQwSwfwVUG3EYNNzUjcjamOEZSP3yRKU9JD3DVSACJSBwSDguyS1gQmdIjFsnWR
         9Tkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709029133; x=1709633933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Wfolz1dzZlKZ4zmUu4cbpFEZVAczsvqruzVYyYpnk10=;
        b=GyelvCSz6c9xUMfAfi7OBMeKpiVY2InXOMR1erApZKiWPhLjDWX20JZxDMXzoMN7VL
         Jhkwjx+QBSYZz8eedGlS2VJx8gypmUOMZ5O6IXK5HAddJ9WyNkrcTkmBYwXdbWIqG1DC
         ZTdZACAF57MW9Yuj985t41zanu3vUUHHp7A1qlZxeGCqW8geVpGH5s3tMUUhNpjrGNDr
         IDpMXDwKt6UU7z6FnTLKO5d7i4NkZRa60Z1Pr/5sbRDNMp2UhZGm35jaU0WuI/JeHEaq
         GJjxc5doNYSj1azp8JwJeWRST911ONFNFFGUqojNwk/D+jQk7tI9mPdy8OxDL7COnjPB
         XzKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnBFLukttMoFJNCHKPxYfLd/0MlVJpIWNksgNBMSCyQ+w7Fzkk/34d8CffNk0OWqxaDEd78FgKXWPKZW3Oc9/iGyUEiRGe+Q==
X-Gm-Message-State: AOJu0Yy4uAiJePdj7XOdDRPB3iHObUi/NdAqQvilGwaOU7P43cZfmZdT
	4lpK0l/aFz2psgJU17ZdXoLfTCjkYGr49HcLWep/sALeyM9F7MQt
X-Google-Smtp-Source: AGHT+IEE+fjzZqh6HwCpRvi+aiET3BFht/HVS3nxvXO/ZSlMTWZODGyAJwV8qdUUKcTq1C36ZIyjJA==
X-Received: by 2002:a05:6512:3ba6:b0:512:d643:8ce0 with SMTP id g38-20020a0565123ba600b00512d6438ce0mr7635931lfv.3.1709029132347;
        Tue, 27 Feb 2024 02:18:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f04:b0:512:b2ea:39a6 with SMTP id
 y4-20020a0565123f0400b00512b2ea39a6ls499354lfa.2.-pod-prod-09-eu; Tue, 27 Feb
 2024 02:18:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMhBn2ffeF85ogwAkyJ6VT9KA4ycWWVGuolI6QbocGzWTqUzqIUqSdmNiJElw2FIqAS6BdbLDwJfduZB40WugOeNy/jc5E8FcwOg==
X-Received: by 2002:a05:6512:4007:b0:512:d575:4745 with SMTP id br7-20020a056512400700b00512d5754745mr6530308lfb.1.1709029130424;
        Tue, 27 Feb 2024 02:18:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709029130; cv=none;
        d=google.com; s=arc-20160816;
        b=mEOI1M5nwBkefGpqB1VfFdlz7aEFlXoU/eA12xhMTLoaCkrm/8QNXeWdp508ZWa2rd
         9SeQm8fPN0GZey8TD9SmLRQsccZO8C5BQPZt8qE+/Jkvc+yG6UNWOzBd5by3r6AGipdI
         a7RZPZeiFEJ3yxdlb29jnqtuQnLFZm5sgJ6J1K/x9ONnq2eEGt6QMqDzf/x8fXFQEkhv
         SHoKuNgOirzO1p73LBNZNZXwyk9S/crDJzBHdmxxhW7h0U50zSPvCKlzEA5zf1qdZ4nS
         GkbOebuom3O8aFAxGnvmjt9A5BObYFlwjwUSXamsBvPmztEVqUINBUZmLk0QiOYCif9e
         X3uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Q4pT87ICIgMrimfBYIsFt4403+jQ655os57F8M8rAV0=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=b8HsowA3nETmOa0N87TxibHeieNg4EKW0HGzoJ32ArIUR64GE4JnsDYJMTOEZMBsbA
         B6fsnPfDIMv9G+/iZ8KL/4wWkTFAVS5jU8qihpg8KRu6S2vdYNL54F9/vvYPfKP1+ViM
         1vNqRa+/6GG7OrH+ib2eOFs54WPxhrztA2avR45roe3UyGF9LAWu6+jPuirYhLsSU+c6
         AtLDzC5/eDWmxecHylMqQEdihJerYKVCve8/NRS7A0iI6jU7kYxLDx8c4dtK1gdlCYUK
         4jKtkP+Tb67fzBUidBzOQGJj4/WySQ/emMzqAvbNlR+w7aLzogpvdDW73JrUpkOMMDc7
         mpLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;
       dkim=neutral (no key) header.i=@suse.cz header.b=UuxALrSs;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id i30-20020a0565123e1e00b00512f7e02e9dsi397532lfv.11.2024.02.27.02.18.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 02:18:50 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5DE931F44E;
	Tue, 27 Feb 2024 10:18:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B14DF13A65;
	Tue, 27 Feb 2024 10:18:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id UH3gKQi33WXqfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 10:18:48 +0000
Message-ID: <4e648451-31a8-4293-bc14-e7ea01c889b1@suse.cz>
Date: Tue, 27 Feb 2024 11:19:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 21/36] lib: add codetag reference into slabobj_ext
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
 <20240221194052.927623-22-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-22-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.25 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.16)[69.28%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Score: 1.25
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cpyVIP79;       dkim=neutral
 (no key) header.i=@suse.cz header.b=UuxALrSs;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> To store code tag for every slab object, a codetag reference is embedded
> into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  include/linux/memcontrol.h | 5 +++++
>  lib/Kconfig.debug          | 1 +
>  2 files changed, 6 insertions(+)
> 
> diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
> index f3584e98b640..2b010316016c 100644
> --- a/include/linux/memcontrol.h
> +++ b/include/linux/memcontrol.h
> @@ -1653,7 +1653,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
>   * if MEMCG_DATA_OBJEXTS is set.
>   */
>  struct slabobj_ext {
> +#ifdef CONFIG_MEMCG_KMEM
>  	struct obj_cgroup *objcg;
> +#endif
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	union codetag_ref ref;
> +#endif
>  } __aligned(8);
>  
>  static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 7bbdb0ddb011..9ecfcdb54417 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -979,6 +979,7 @@ config MEM_ALLOC_PROFILING
>  	depends on !DEBUG_FORCE_WEAK_PER_CPU
>  	select CODE_TAGGING
>  	select PAGE_EXTENSION
> +	select SLAB_OBJ_EXT
>  	help
>  	  Track allocation source code and record total allocation size
>  	  initiated at that code location. The mechanism can be used to track

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e648451-31a8-4293-bc14-e7ea01c889b1%40suse.cz.
