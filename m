Return-Path: <kasan-dev+bncBCKMR55PYIGBBYE5ZCRAMGQEGIVU5CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F03BF6F51C4
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:36:01 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-50bcaec14c2sf1486304a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:36:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683099361; cv=pass;
        d=google.com; s=arc-20160816;
        b=o24le3TgGGHXbE7LACb6iJNmwQL0x6B3erESm8wNJkyycJW+uRQOjD490aWHxFJpYy
         KuTci52KGOVxh7aBXZP9Ly0XIUU9WK4Pn/0nadHmc9pcyZ7vSFWofnJ28XbMhmVaz+BJ
         +JW2aSXQ1Ty/dGL5yoC4J0qhQaJtEiR4O99w1RP9EwsDeGaiUtJGBmjxDOfl5xXffhqi
         oVGxa6PEYhIF1QHt6L5OdJzJcb8FhS41Busd0WegyTE2rYTUwcAq8XONedPC5Fk4c6Ff
         2mUmy6dcOvAhxVgFMwPfplpSExtZwV3ZomaR93UY0rxq3Bad7V03BwVtucOHXuwr6m/5
         kiRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dnKGDYujTqd9eBcCKwvXAn3gLt1F/2Zb06MeWPu3+rU=;
        b=CPIKjeGVr/RTGdgwYag+H+Wjz9no1wWkO2JSDSfgnYfy9C75671M6bxQUqjGXIJ5Bk
         Lw8DHl/S1NUVDMOC/HL5ITvWXNP6v1/E6ePO/UBq/ptQFtnDxqblHE4jnfXcGm7yavn+
         UtMVvmYbtgESL8bOzN9dyoKGowzsVni6AcHc8Hzfv2Y+XGYZNiMVP1Awi812XVaKenrZ
         HHFcbR0xR2b2LsY5N2GumW+Ezcnk6AiK3MG0wWPFZgofk0jl0tGTc89v9u06aLiXE5KU
         ulEio4aCPfCs6o6j2MH9z5wO1o/N340Q8JJngbMDkORme8a9/bJw3SL6NjjnsYcfFu3C
         jkVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=A1RUCh5E;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683099361; x=1685691361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dnKGDYujTqd9eBcCKwvXAn3gLt1F/2Zb06MeWPu3+rU=;
        b=QzUaoy0XmlKVv4Y6/hsLUvJsRW9WwIYEQ5OZ/f537Z1GTC508ACSJL7mejQW+b7X2s
         J/1sKWHWmHslk9ho55RKIhzxvZGUEucRYK/CSl0Gm1IFgCrfR3K6urCsaHBlEu5OSH0T
         Yb4l348XAicrppVeUqILwM12bWsV5e1yZy/UF5xDaEFqhyzjW9eJkkEgsNXTtv43X0c+
         BPKdJoNbT4VDzFfrgEuAGm8uN6QD9nEK3HypYz9twaeElrkv23FYiztJrwwVuKAuQ4Fi
         jNN9Njy1SyLyEy+oWk7dzzn7eOomFruXMPf43EL0pCL6C2G5G1jZlN6qrr+5DZegAPq+
         13jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683099361; x=1685691361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dnKGDYujTqd9eBcCKwvXAn3gLt1F/2Zb06MeWPu3+rU=;
        b=IvYbJoRrcDf/ZO8sZ3M9jMgNEEcOQjC2TqvnCGOplQV63iAFbrOnv+WchY1hJWxFgz
         YJ9WRvVoQxaINDMoa0QX9succbnKIS1Vqj7CYjoPRrWFeQigA6Y+EmAOklaL2b6LslH2
         RhcdFod33gHrPhb253RWARwAPtz5gkc2Mnn3/KHsBfuuc9qKTDL2MoLl8T4jG6U4nM7e
         ePRxji4B3Zn+8LuR0GhwvMc0F48vuGK6DdNHLYNugbFJc2BQOhGLmKXjy/m6lg4nvcEh
         SzSzRoQnvIocJHMnuF5YoJ9gr3tb2WQC5jx0ufIN1Bj07BgZ25Zg12z8MF4lvvTR1cWt
         W2KQ==
X-Gm-Message-State: AC+VfDzuT12XgYRsZLIT1z78fhVPNb3lExMIWtN7LJZeJnzqiuKzG71Z
	/o00cy7Xi1fFxx3YE5iNE3w=
X-Google-Smtp-Source: ACHHUZ6QuhoUVQ23uCqJNkJNq7E3XJIEffzFvw4l7cRr0uiaKYYarNFsEYBlVS+xyjVkyPBvlu/h4g==
X-Received: by 2002:a50:8e01:0:b0:50b:c27a:3892 with SMTP id 1-20020a508e01000000b0050bc27a3892mr469295edw.2.1683099361178;
        Wed, 03 May 2023 00:36:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2358:b0:957:12a6:35c0 with SMTP id
 m24-20020a170906235800b0095712a635c0ls5752589eja.10.-pod-prod-gmail; Wed, 03
 May 2023 00:35:59 -0700 (PDT)
X-Received: by 2002:a17:907:846:b0:94f:1a23:2f1d with SMTP id ww6-20020a170907084600b0094f1a232f1dmr3140881ejb.64.1683099359715;
        Wed, 03 May 2023 00:35:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683099359; cv=none;
        d=google.com; s=arc-20160816;
        b=PIe/7UH6Tg3f/RVOva9MhxSlzg0Lsbp6hyZDWa4wCkd7SYvN958fJ0uf5iTVLkGT6o
         JZrV+I3plR3syUtffIqHbEF+SwQoCqcc1Kw9jQh1KO7ljKrTd1t2d62XHBz1XMWgJGlU
         BCLjkkfL/DLZUEQkFMzpYjgHPephXPLyxrnOGQTmM4v6jsC/F5YAWM0qDwzl2cZH5Myw
         DYTdzWzdXzHqQN524ppGhPbbJirciZxt6XaCqXQg5Y2ymtFlsTU/rx3Ph9UFfJwByYkW
         zZ2kqo+1RzqnxueDZpEiu2aZgx6fTc19aUJnD52VS56yGmDHZWD9R/dk7WTeSs9b47Zi
         8Q4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=i3Hzbp6Fc0h0hj5rYtAeMr0Bup0FedFGgjm/ljEsba4=;
        b=um9HJQ3qfx0GJJbr4lrAv0BkIzEdd0KM3qN0QchJz4nGa5hQFJx3ir8QNoeF/PqDTG
         XSDskJGNbZWM3oYQ0JSzzUA4bHdj1UlAXk2DqL1xaxRj6XiRnhP7T0RU7FEzyh6aq169
         VRvba5lEKqcMdqulkYkYUILd0QC8c5jl2lk3MqQ+BU1xBU8LvhyRhozphBw773ltUE3q
         dHjnLOcZlJJC+2/m4rstAPO+Qfw1+8CfRvsxrUEcCH7AMAgtJlfuGyv7v0CGi+WkWDm+
         Ei42pXEDMyMGQjzzS6RKc5vatyw/e8xQMkEWUK/YSMSuvpOgEEsFrz3MjYr9B2rtfcf9
         SmOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=A1RUCh5E;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id hd41-20020a17090796a900b0096330a0cb46si258683ejc.2.2023.05.03.00.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:35:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 481782006F;
	Wed,  3 May 2023 07:35:59 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0FDBE1331F;
	Wed,  3 May 2023 07:35:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id M6TzAt8OUmR+UgAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 03 May 2023 07:35:59 +0000
Date: Wed, 3 May 2023 09:35:58 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
Message-ID: <ZFIO3tXCbmTn53uv@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-35-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230501165450.15352-35-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=A1RUCh5E;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 01-05-23 09:54:44, Suren Baghdasaryan wrote:
[...]
> +static inline void add_ctx(struct codetag_ctx *ctx,
> +			   struct codetag_with_ctx *ctc)
> +{
> +	kref_init(&ctx->refcount);
> +	spin_lock(&ctc->ctx_lock);
> +	ctx->flags = CTC_FLAG_CTX_PTR;
> +	ctx->ctc = ctc;
> +	list_add_tail(&ctx->node, &ctc->ctx_head);
> +	spin_unlock(&ctc->ctx_lock);

AFAIU every single tracked allocation will get its own codetag_ctx.
There is no aggregation per allocation site or anything else. This looks
like a scalability and a memory overhead red flag to me.

> +}
> +
> +static inline void rem_ctx(struct codetag_ctx *ctx,
> +			   void (*free_ctx)(struct kref *refcount))
> +{
> +	struct codetag_with_ctx *ctc = ctx->ctc;
> +
> +	spin_lock(&ctc->ctx_lock);

This could deadlock when allocator is called from the IRQ context.

> +	/* ctx might have been removed while we were using it */
> +	if (!list_empty(&ctx->node))
> +		list_del_init(&ctx->node);
> +	spin_unlock(&ctc->ctx_lock);
> +	kref_put(&ctx->refcount, free_ctx);
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFIO3tXCbmTn53uv%40dhcp22.suse.cz.
