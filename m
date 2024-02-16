Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5EBX2XAMGQE27UYGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id EA6F7858137
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 16:36:21 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-56261857d31sf1205149a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 07:36:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708097781; cv=pass;
        d=google.com; s=arc-20160816;
        b=S+B/7nAmPUrJkbeivCMBqr/630QOjgOJrylKnKvBtOED+8tvwVZBxXgohC9WMp3vjR
         gs4BdFlzn8gBuYE0QbgsJYjVsyXGqiYj13prhFmkgMxFFRsUCaGlTtifhFiBM3vSFJ3q
         FULFfjFIVPEPjsRG1VNlbSMTrDbi2eb6UYv5wtxXeM/w2UaCdEqqlV/sA0vX7IgrYV/4
         fwQtcZZl/6l9ETm77k0IRCOCVJpIXixvb5zk/VdMJ3Nn7A7pRee30NnZvXsmy4KyykRl
         wLPg7KTfdTRWY9n9cegWCJrarjxyDrx9/WxuOMvqA3I+eJyxvw7RN92BTzC+LK0Uy3U9
         D8ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=bzQ+yduFMu7E1anNwhPlteRKldK1xvRrQ0tImVfohfQ=;
        fh=ur4la8PGV9oZmm5i4A3K2viVoZgcbthkwDDT3cH52ag=;
        b=k0apL1KR2nNV71I3RdjhHz4bSa1geYJHP6GOIaJxrsHkZbv3oOW/p02bvn2UdQSCgd
         jdIdlTw3tpFeuEM4uGLmdn/guJVWvhBg4FhB9bLppyadSKyDTol/SeqtA3UJ7+qjaCcm
         PeGUlkZfqutxE6pEz04feZlwxyLOJWwyGv7aaKYaL9dt2QfGrCDNz6R2gWkIEcTftXjD
         yvBFkO9B7CEqrES3OGqinT6lZZl+kB7UFCnetcbYP2M5dmNtWILkcZGs08VUVnHv/YjL
         46gyYmRGSuVJu+D5tyg6jTMLndv4tomGaahEeRHrXEYi0TYTlvohawgWo1zcbT7Dd4hE
         o+zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fXAS9CXU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wLNfUmnQ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dSrBHIt3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708097781; x=1708702581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bzQ+yduFMu7E1anNwhPlteRKldK1xvRrQ0tImVfohfQ=;
        b=QMsh9LM6RoGLOme243mFzBENFLN23bra9J017efTsF+frZ1+lzVXEHnWyMN6XBg2hv
         +SdhiMweUjlaBxyOED6rZ9g82KlsRgJk+Qioyq0wPx2e9VwO4TjU22iFP3ydXEzC2lbB
         1uwdSIlQPXbB9zQIQgLWiCjunj3uKCLjWOTtCYo/Ay8v/m3lJN4hi3AVx716Mp709rse
         WmEmcoL1ydZXg7L4GDxHv1wS8CfBDr9ziSxxkfQlG2N3J2GHGuqlxlHiuvlZBZO8WlHJ
         GELB+A6l+96PI+mOiLYcPZoNwN8T3g6M/lio0Z0ObnFRQbYoA4h+BxZyoA8Hk4O8EbM+
         KQEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708097781; x=1708702581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bzQ+yduFMu7E1anNwhPlteRKldK1xvRrQ0tImVfohfQ=;
        b=aozDu31AX+99d/n0hbJ6mCyLyRJl/I59rnV71xLmMxqh9J9tcLHvMSvbnMFI1Mg/t2
         J+SILCf8u/n4I/i1AYKz7YJj3d075nKEgzUNOYAEIJjwouvFMEfAHdJEgjb99dsPnYEo
         jqiPMFWC4zkpocQvSbnAMhSIQ9cHlSLESE+ov+cTMIaYMttEhRJONvX9nOgYdM5i3i7v
         JTe+R03Om8kXElNJSvAtGUJJSw2OeBsFKqWa/1yTGu0B7M7mp3mZXY00hLjHEtfV7Y3i
         oK11mqpbEBENKB+RYYJCCUElQsTOR2oK+tY3BJ6yBWP3IMmH51XUGv3S/L6n0iVn4Y/1
         CL8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUqO1Zr8i1RA8Hq5R9tYn/MEFGnCNSaeqGvCtBEDURAk0Qt2xYtE8SzLKVxvpseDZY01/ppHZLlj+2sdBqEtE2sm3nIO+QVw==
X-Gm-Message-State: AOJu0YxvJT9KbCrJaps5hbFk352h6BhkP3TxAT9Rq8hoVDm9u5uDW/4V
	c6doAKKLCDrDaf2FXGRFKcyhZI6G++dOSMchwURUeXR7PKLtb136
X-Google-Smtp-Source: AGHT+IH6jwLnyJbGuMTZ170NFs/T4eHPWeNKcBBswSi4PZP9SKM6bz1ODkCHgvtmdZJvvN4mpNhkQQ==
X-Received: by 2002:a05:6402:1a41:b0:55f:e493:33b4 with SMTP id bf1-20020a0564021a4100b0055fe49333b4mr3677286edb.15.1708097781057;
        Fri, 16 Feb 2024 07:36:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5293:b0:563:ac79:7bab with SMTP id
 en19-20020a056402529300b00563ac797babls196233edb.0.-pod-prod-08-eu; Fri, 16
 Feb 2024 07:36:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxpJnshUEZ/iENSlkvOWGvGPk9IAcTr/UW8qs3ZkncBp0VqJZrCSqx1Y2JGeRAuZLK0jf57B6aVaLxydekFlCwncElw1+oQxo7Rw==
X-Received: by 2002:a17:906:16da:b0:a3d:fb0a:ecd2 with SMTP id t26-20020a17090616da00b00a3dfb0aecd2mr710456ejd.49.1708097779257;
        Fri, 16 Feb 2024 07:36:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708097779; cv=none;
        d=google.com; s=arc-20160816;
        b=wzNmytFuWDCgNai+7mR1ByFYZRNFS38R0J8p604yjHdut9HgAn+ny5u2H8BGlSQBbC
         360v7dZUe3Qze0WMzHq/bbmMKo4zAswEf9RmpTbYTPUcXXUKmVEVRDXKK8HTJLt5G4kT
         iVVSPQ7Z0EulSFAZ31wQdgQs8eTF88BYTMsqwnS643/eEk/QdALi7Pc358XBdk/GMxqt
         ctn23p+VVyMp2gpn2W3pvlYqyhrZLJF+K/8vutmvS7Ns1rqsIbzo1Hq1OjbnW1sKhydz
         FQBgOR18SCXaXwpr9EjjbXNizd5Ht9FpXKVHXadcOJbw1ezO280mLBv4gJsumhfO+iLC
         nfZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=l4vJJ3H+AAWRQYjB/9/s6lx7LTkhnUXf/MDDTj+Stkc=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=i78AxakmS/tncOBZqI/QehjPbZzmWfoXGZe08f/2GI+IsG4dFN932lGvbZwwhxxO/h
         K3WtnKQgg5woyLbua5YqhK2dB1gnRQ13W6WO5qCS0IfLPfF9Wt13K7LLQSALOUvjsH4l
         sf6WMexDJkF+cauT1P6bKFczxkxoemaiV+p0z6mIcDQhmV9HCPyhpERhnBcpMi8yHyjT
         nw+orifSrPamxMsrE49th6PlE8KXhg1qnYL1dvsJhQd6E6DI6IlDXshC61Z3wuu9m8iM
         UxcaLJjz3V1nBQ3jvXNg2lmUEYYfzxBWPwjzR9PnUOACBsA/JOcWRZVZAQMbNnDzeIS3
         nnRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fXAS9CXU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wLNfUmnQ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dSrBHIt3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id lt5-20020a170906fa8500b00a3ddbfe5347si3643ejb.2.2024.02.16.07.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 07:36:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 883E21F8B2;
	Fri, 16 Feb 2024 15:36:17 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D3BB013A39;
	Fri, 16 Feb 2024 15:36:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Xg0ZM/CAz2W1QwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 15:36:16 +0000
Message-ID: <e845a3ee-e6c0-47dd-81e9-ae0fb08886d1@suse.cz>
Date: Fri, 16 Feb 2024 16:36:16 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 20/35] lib: add codetag reference into slabobj_ext
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
 <20240212213922.783301-21-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-21-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-1.50 / 50.00];
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
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Spam-Score: -1.50
X-Rspamd-Queue-Id: 883E21F8B2
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=fXAS9CXU;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wLNfUmnQ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dSrBHIt3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> To store code tag for every slab object, a codetag reference is embedded
> into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> ---
>  include/linux/memcontrol.h | 5 +++++
>  lib/Kconfig.debug          | 1 +
>  mm/slab.h                  | 4 ++++
>  3 files changed, 10 insertions(+)
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

So this means that compiling with CONFIG_MEM_ALLOC_PROFILING will increase
the memory overhead of arrays allocated for CONFIG_MEMCG_KMEM, even if
allocation profiling itself is not enabled in runtime? Similar concern to
the unconditional page_ext usage, that this would hinder enabling in a
general distro kernel.

The unused field overhead would be smaller than currently page_ext, but
getting rid of it when alloc profiling is not enabled would be more work
than introducing an early boot param for the page_ext case. Could be however
solved similarly to how page_ext is populated dynamically at runtime.
Hopefully it wouldn't add noticeable cpu overhead.

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
> diff --git a/mm/slab.h b/mm/slab.h
> index 77cf7474fe46..224a4b2305fb 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -569,6 +569,10 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  
>  static inline bool need_slab_obj_ext(void)
>  {
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	if (mem_alloc_profiling_enabled())
> +		return true;
> +#endif
>  	/*
>  	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
>  	 * inside memcg_slab_post_alloc_hook. No other users for now.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e845a3ee-e6c0-47dd-81e9-ae0fb08886d1%40suse.cz.
