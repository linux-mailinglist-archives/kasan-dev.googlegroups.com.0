Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNXD7OXAMGQEOQ5RI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 864B386AA3B
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 09:41:27 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-33d7e755f52sf2570085f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 00:41:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709109687; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q7YdRvzsFApt2uy1ZaZx6o2VOS7O+egbi8MIGrzSurS2jIb9nPbAnbV8d/VxTQGmh1
         wLlZZpTfLQlnlbfflsGHZugk3eaeulxu3BOoV236ciBxCxZ+3I721hfOz8kV3j+akr6T
         oxNuHKCN0i+p72AvbbkmiGXCkHdtAgu4lO+x2w2hDsyYkfjiZ5gj0HcwyoNsglyqmoQe
         ykFCuwxtGbYi5qrQzg8wBtvi3OpOqm0qK9bC2vvn6ItHpYY04RD5DB7/eA3e7tjE5rh1
         TaAGINWzUWt8T5FhH6sBLLNlIbhwo5Tu+GKetZs3XQqetGIE8kL2TBROQpnZynpD0aXC
         9P2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=c+AcV3HspGHbjwQ4CJ8wnAIr6Un3X6GRdqiX+k3qxco=;
        fh=SGCpTVFYw3ViAbxJHiEOkwGodH5+v3sSX8jb1v2MvR0=;
        b=z97s3R04OfxvNjurSjk1tNMem4rXMnpVSTvtPxUT9hUYVh212daCjqm+74d4txfA/Z
         TPq3mWbW2Z3fUw0otxArzlgnvX5KwMY2IvS8ZP78NHoHw4NTG5m+z3GaCUudyFyA2yzQ
         UbiEt69olEZWYOqQlOyzGXCvvwBruy7ZZfLXdTR6NAksWOJy9IFgC3j6Wg3De/ZycYVT
         5vXGpjQxIlLlxA3rksorqJjqZCcEpMPZjxL5ZEgpfSTx1EVJNvq/KcQa0lTJUJy5ze/f
         nyBJXvirOIZoJ/vpnbVT5owA//WouacKVmJ2NcN5SWfa2Hrhm7k7NNoVI6aklJUoTz7W
         QIWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709109687; x=1709714487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c+AcV3HspGHbjwQ4CJ8wnAIr6Un3X6GRdqiX+k3qxco=;
        b=bxnJmcxbz4C62Zt6fZG2bs8k9USNHxISGhNSkvQ5Fjada9ZFu5V/HnRzQu69m/0iGl
         EtTNaVat7Fdo5LYK3Q5oVGMRywWtt+hPDEw0pRu3/VgHLSIVTgrq0b2IYr/TU4uYaUeu
         +lpNBARni1mCqctBFEpv6/QMNWT/QWn7bEdUcZ15AqyrN0Rl+tE3x1bfR2+yv41SdrVx
         JBFy/o0YhkaKQTZu1V9pbY7Ucp4MmW0qh7H/8Rai+L/G/2zl0ubKG2wl3RXL80fgY/SO
         SIWggFOQ3lwcwooX4Yc5iOySKEyGvOsNI2IJG0zCTr+V65kH+G/a77vIn/fK7u74EhcS
         IgUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709109687; x=1709714487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c+AcV3HspGHbjwQ4CJ8wnAIr6Un3X6GRdqiX+k3qxco=;
        b=QQ/55YUmAr2ax37jP5+uC7wP2uykw9WoqqQX3iFat03kJ/DuZsVVN43TIcNKjb3HyY
         otyY0UUQBAaYVCYB5f8qQlCz2ulomcC2PbF2fCgbm0zm+FaRxYovMuiNf/1nGrTegAHE
         YCL+dInoDVib1iBZw0PFrt6hGIhmtSSBcjVjE4lB1u5uV36i5tN9L7fkPOiKX9VnfEfk
         Vk3eiw9XQZS81Xry6TUuuS64hySWgx8MFY4hIs4JS7hw2iatyShHiuf/VBdE3zCqmQw9
         FOeTEyJXKdvqUKzoKc/zUR9jnsgzQtqNfAxHKqBbhCpRny4dxCjf5+jJ1cB6ZAuXAuOS
         2yEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDxBoL/5v8lgmCH+cy0m7i8mmijqnJ6DdUF3JBctrJiKhRzs8PRrdeAbo23svzR0BEcoCUXvMDhp+6TLCL0oUpyxQG2nKOqA==
X-Gm-Message-State: AOJu0YzZX0Z0FoNx+XbfSWSZynnE/MW/iK9+3ZCMnZ887HJJDwnsTbGR
	8NbvI4L7R5frvP8dzCWzh7nV6R++s+h05Qkv2k3s+ZMvsGtlVlin
X-Google-Smtp-Source: AGHT+IH3HrU0w6THpYP5/8f+7oQD0wNcdrSyhRn6QSgyJwTl3FKF5AkHXBeqO0bhU/rDb82Vfo7/dg==
X-Received: by 2002:a5d:5692:0:b0:33d:2071:9b85 with SMTP id f18-20020a5d5692000000b0033d20719b85mr7432381wrv.19.1709109686629;
        Wed, 28 Feb 2024 00:41:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1acd:b0:33d:82a6:706c with SMTP id
 i13-20020a0560001acd00b0033d82a6706cls206882wry.0.-pod-prod-02-eu; Wed, 28
 Feb 2024 00:41:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVN7w4mxsBUlzHUf2gbhRdkTErUNSzmtT3Dcg87g1R92yFqaQMUif69CsDKhLYQrWDMszp+yCMaQbh1llYOPVBVCplVLBYHllG8Hw==
X-Received: by 2002:a5d:4841:0:b0:33d:804f:5ea3 with SMTP id n1-20020a5d4841000000b0033d804f5ea3mr7929493wrs.69.1709109684939;
        Wed, 28 Feb 2024 00:41:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709109684; cv=none;
        d=google.com; s=arc-20160816;
        b=Uh6a9JR4Xz1mHcQbxF99wAo3g5Dv+Qa3Hen46uys1IzzCLJCpiOVDNmmDNJu/lgIQ+
         18BI3ZvGY5U5+zd35f0h/CH/qkTGdirT1w6aYdXcKPEisQLKkCZKC+8NADEcT6Pk3U5t
         62XTQRe5PnbBa9topqEf+xO4HDkaA00hNiA9pmfyC6Ojj5uTneDsm3Avo55ngxK31+V2
         8xKga/MZzJ4P6t8tw7qQyxVdKpfJOBxyCgB359QthCN57/QSTvG0pdNP0Bjq/36V64VK
         ngyZloifpbQazo9cNCktTcVdwf9zjNFsHFnhmrVbn+V/vriAbVKKVKiIjvCMaFuBxCEs
         neCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=IbyCcmaBlZljStHMFxVLjYUCEfDtYTJa/CPT8Hf97G0=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=XhbKk5ptiOrUNWRpESphKU6Opg7w9lkCSmBga+JmhR44ffzx0pClw/tMWlJLchSKC5
         14Blll1rz1tLbX3vPq/mRfLMU/wWbxU510byU1rFZluuH+RZLx1wV/SLtcu4wNLJUnr3
         7uSMX+9lv9cYpgSDZD6NtV9bu0QjO+NxDSyS6c9i3ypcZxjSUetU2BBVP83ZRX4EJs0F
         CZilpnbfrQUEXbtNkS6HG1lI1jYPTee4B1L2cb9zccb0AAHGEgr1ZvffKG1K3hfQFmwh
         GRqhVs9/upjxv0DZpFsaUGbRMP5kdl7cHRAhmjmeUK5lJZDAJzTqeReBqTp0NYbJ7WNM
         /e2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id p16-20020a5d68d0000000b0033cddf15870si590119wrw.6.2024.02.28.00.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Feb 2024 00:41:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 475AE2262E;
	Wed, 28 Feb 2024 08:41:24 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A0FBD13A58;
	Wed, 28 Feb 2024 08:41:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Ou/VJrPx3mVlIAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 28 Feb 2024 08:41:23 +0000
Message-ID: <b62d2ace-4619-40ac-8536-c5626e95d87b@suse.cz>
Date: Wed, 28 Feb 2024 09:41:23 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
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
 <20240221194052.927623-15-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-15-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-2.21 / 50.00];
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
	 BAYES_HAM(-0.71)[83.49%];
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
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Spam-Score: -2.21
X-Rspamd-Queue-Id: 475AE2262E
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=phMwb3Dm;       dkim=neutral
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

Another thing I noticed, dunno how critical

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> +{
> +	struct alloc_tag *tag;
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> +#endif
> +	if (!ref || !ref->ct)
> +		return;

This is quite careful.

> +
> +	tag = ct_to_alloc_tag(ref->ct);
> +
> +	this_cpu_sub(tag->counters->bytes, bytes);
> +	this_cpu_dec(tag->counters->calls);
> +
> +	ref->ct = NULL;
> +}
> +
> +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> +{
> +	__alloc_tag_sub(ref, bytes);
> +}
> +
> +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
> +{
> +	__alloc_tag_sub(ref, bytes);
> +}
> +
> +static inline void alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag *tag)
> +{
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +	WARN_ONCE(ref && ref->ct,
> +		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
> +		  ref->ct->filename, ref->ct->lineno);
> +
> +	WARN_ONCE(!tag, "current->alloc_tag not set");
> +#endif
> +	if (!ref || !tag)
> +		return;

This too.

> +
> +	ref->ct = &tag->ct;
> +	/*
> +	 * We need in increment the call counter every time we have a new
> +	 * allocation or when we split a large allocation into smaller ones.
> +	 * Each new reference for every sub-allocation needs to increment call
> +	 * counter because when we free each part the counter will be decremented.
> +	 */
> +	this_cpu_inc(tag->counters->calls);
> +}
> +
> +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
> +{
> +	alloc_tag_ref_set(ref, tag);

We might have returned from alloc_tag_ref_set() due to !tag

> +	this_cpu_add(tag->counters->bytes, bytes);

But here we still assume it's valid.

> +}
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b62d2ace-4619-40ac-8536-c5626e95d87b%40suse.cz.
