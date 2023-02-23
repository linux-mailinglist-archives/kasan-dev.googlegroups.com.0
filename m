Return-Path: <kasan-dev+bncBAABB2PT32PQMGQELXYYZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10CF86A101E
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 20:09:31 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 10-20020a05651c12ca00b0028fd85f2e0asf3745989lje.22
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 11:09:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677179370; cv=pass;
        d=google.com; s=arc-20160816;
        b=efY9mHIOPIZXcnHopJCy4p6XenLq5WkbobCjpngNf2Y4kADoJ5sssR6O/MiOMyUzSk
         Et6B6X29FLw6gYwt1QezdfjIi+4mxvGWbU3TG16LR0urH93o4WeCIRq564DqDteqFXNb
         DgF82V77YtA4IcVXKLiiCL+L8fNWPhY3SgICcYuBw4+85yNkIGPddej2rqmDEnSJuA3J
         D6UxDW5G14/lCGr2j7wAvx2gwcsUllfp6Yf4YUq/KZn8Ua7a8+gUicBFayZvSBw6fjsB
         y/vbyheYjg8kKjQzYb6v6N4Zn0/CRwnpYQxoCw8cW2edtWjaZ9uXKjQbmKlKeYJzbYvw
         fL7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=kgWzPhQjnbFb6JeVNORcVB9Uo61aj4hybJHBIbgsuQY=;
        b=GjqBgvBo9kFEOJLpoOpGUtCxrmhXB6iAkkVGeHUBECFEJ+ZxD2iTUm+kRdDPzWL416
         FCQyEIKU19sUqLiW+uf7FjLe4Aq3U3C1hzvDw/Yb8LJwJjVcuzT4jieBKY/qKVOEA/iq
         eP4OjNrrStq9/9fo7Ap0Dtk4abQwbuiVxA7idUbhF1lgu6uj+0gcv9F654lBblc/MLs4
         VeDp3xTEx3YP4UEkwN/k8XGsEN+ynOr3dWEErcnoPtnpB4+P4qHWP8qOCoW5ScNw6s7v
         c0Gk1p5qxRZTctTC9MvuRSeZwggxVwJEh/Bskp+JrXoLJoSjwXenDTjyR7XePwv3j4vI
         PIlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=H3TNPi0F;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kgWzPhQjnbFb6JeVNORcVB9Uo61aj4hybJHBIbgsuQY=;
        b=qlUuZcrEZQz7MgZNHD6PrdUk4Zq/HEzctukazKxAp8jBdVbH9+kYh3dBAbQv2MrHT8
         9/BwSPAFHFo+xz/nakjPFkGZZnyfAKWiFMgscCIOL/PZSFI5/Bq0G9WGLXWmaMpMrXGF
         rQPdYtPW4ExEyrHwzr8WWzTltQyOoU4jjeV2KJBi7BSUi92nNI7fjgjrMO4cH2Qk/IOe
         bwLxJ/XzPlBXJ9plNsOJ9tDGu9b5oCjbm4wjVP284ClLABfLFKOZyJrnR5LQZEVa3kcL
         ybg44R82wHHkEguWtEjQWePT1repiMaZpiLbzW9eUozIsWd1wxWwq7d83yhuTUnJmBfp
         YX/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kgWzPhQjnbFb6JeVNORcVB9Uo61aj4hybJHBIbgsuQY=;
        b=XxbRN47Daov1quS58QdpAVWBvqv5qPSr4Tckv81LRQ38lqTmOzGRjkvYkr5CTLNQtI
         gxZjPSGKF7hWlRgCqHrq35huttRKkjUiuDNgnDCyu7L6hv2Z8qITU4joCKgeZhTaUi4E
         CWxpI3pClLYcUznX3rovUKRaoRF4C1Yz6u/asm/EXSSQRKFCeZQJe5rRHeT3F1yNo+qK
         +s6IsKbQsbkJxrVDJIh9y/GjfJcpkO7n1cT28dQU8oy6z0mwggUqtLZUrfntwiJvN9Uu
         2Q7+ejyzRphpOFFNPK35q7juSaOybSVsiI532sLmTvTMbgr1pkOlD+mdFDr0cMmpgR1K
         BjQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXkD9/aL0uJ0MolXaXh1Z10BUBTtlc/rSmqAG/sobzgNxOCo8SK
	7rB+ROnd9kJepRuc6stuTOc=
X-Google-Smtp-Source: AK7set9EYpW6+wZMw0+aUWsvMNLUYu+s8XzTpEcl3nSI6Gr5ufsHk53LooH7rCY+BXKlZUJBflVo4Q==
X-Received: by 2002:ac2:44b2:0:b0:4db:17d2:8aea with SMTP id c18-20020ac244b2000000b004db17d28aeamr4170284lfm.11.1677179369686;
        Thu, 23 Feb 2023 11:09:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4024:b0:4dd:8403:13fe with SMTP id
 br36-20020a056512402400b004dd840313fels310894lfb.3.-pod-prod-gmail; Thu, 23
 Feb 2023 11:09:28 -0800 (PST)
X-Received: by 2002:ac2:4849:0:b0:4d8:4ff9:a2fa with SMTP id 9-20020ac24849000000b004d84ff9a2famr4301343lfy.60.1677179368406;
        Thu, 23 Feb 2023 11:09:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677179368; cv=none;
        d=google.com; s=arc-20160816;
        b=zKL01XXyw90nh3KsZGifZcFieLBhxqIq8ZYbTpZ1+v0b5faTwZSa9CN5Cklp4mys4G
         07pC1YdYPkVnG9zBRVlT5x7dCEo9zU/VfbCW/fG5IDOWjKrNkXBlJMEhPYeKPph22Hfg
         p/gg7Gn4JxTpjTElEMP8A1lfvAENbJAteQOv9PEr6jhiW4qKS4+CUZUItIHTgE6x8Ht3
         ouZCQpmV/93ckakDyeOFDTWTaKefNOhbv3Dq1fmO5w1kOJSQPaQmv1G1dVfvv6t8ZCZz
         BsnieiyTxv3dfmHA/eHV/8Nb4Nk1gI1p0dh3DYwRDSWhqkh8d2Y5ZzViyKcFuSkFtqEQ
         3CSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=R6BDDmrkkHAaryDO214Xsq4JWamUS2WCaTo7R6jDDQI=;
        b=rbCBPau3+iO67qeGbxqnk8tVk8q3AFHmrpFDCa21e0YVoWDOuJRAfaES2OYHT6SVfV
         jbK2G+jQGo2lch7xXuxitHHISK2EFkBS2ggtH45Pe1QPLDamRVIRFim+L3yEtygHrPnI
         U49tCMjATTdtwoUAByaQJHRPxeNQ9QvAOAlW3yw4UrQRLS7XONDNDj441ErC7KQTcK2c
         pWO6OwpJTj+0j3CSJEDXMaU/563axhj8KYM6rl0jee0i99NP+kDovtbrmwJeJi28Couh
         TrMCiuO/Uw8/kBSF0kWkLPquDoEqFXe/M9SgWJiliaBr0VVpaMyy9AFYTODCdAAnhHa+
         xP9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=H3TNPi0F;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id d22-20020a196b16000000b004dd8416c0d6si408675lfa.0.2023.02.23.11.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Feb 2023 11:09:28 -0800 (PST)
Received-SPF: pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9B2A934971;
	Thu, 23 Feb 2023 19:09:27 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2DC6613928;
	Thu, 23 Feb 2023 19:09:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id EQYtOua592OENwAAMHmgww
	(envelope-from <krisman@suse.de>); Thu, 23 Feb 2023 19:09:26 +0000
From: Gabriel Krisman Bertazi <krisman@suse.de>
To: Breno Leitao <leitao@debian.org>
Cc: axboe@kernel.dk,  asml.silence@gmail.com,  io-uring@vger.kernel.org,
  linux-kernel@vger.kernel.org,  gustavold@meta.com,  leit@meta.com,
  kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 2/2] io_uring: Add KASAN support for alloc_caches
References: <20230223164353.2839177-1-leitao@debian.org>
	<20230223164353.2839177-3-leitao@debian.org>
Date: Thu, 23 Feb 2023 16:09:24 -0300
In-Reply-To: <20230223164353.2839177-3-leitao@debian.org> (Breno Leitao's
	message of "Thu, 23 Feb 2023 08:43:53 -0800")
Message-ID: <87sfewryfv.fsf@suse.de>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: krisman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=H3TNPi0F;       dkim=neutral
 (no key) header.i=@suse.de;       spf=pass (google.com: domain of
 krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender)
 smtp.mailfrom=krisman@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

Breno Leitao <leitao@debian.org> writes:

> Add support for KASAN in the alloc_caches (apoll and netmsg_cache).
> Thus, if something touches the unused caches, it will raise a KASAN
> warning/exception.
>
> It poisons the object when the object is put to the cache, and unpoisons
> it when the object is gotten or freed.
>
> Signed-off-by: Breno Leitao <leitao@debian.org>
> ---
>  include/linux/io_uring_types.h | 1 +
>  io_uring/alloc_cache.h         | 6 +++++-
>  io_uring/io_uring.c            | 4 ++--
>  io_uring/net.h                 | 5 ++++-
>  4 files changed, 12 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/io_uring_types.h b/include/linux/io_uring_types.h
> index efa66b6c32c9..35ebcfb46047 100644
> --- a/include/linux/io_uring_types.h
> +++ b/include/linux/io_uring_types.h
> @@ -190,6 +190,7 @@ struct io_ev_fd {
>  struct io_alloc_cache {
>  	struct io_wq_work_node	list;
>  	unsigned int		nr_cached;
> +	size_t			elem_size;
>  };
>  
>  struct io_ring_ctx {
> diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
> index 301855e94309..3aba7b356320 100644
> --- a/io_uring/alloc_cache.h
> +++ b/io_uring/alloc_cache.h
> @@ -16,6 +16,8 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
>  	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
>  		cache->nr_cached++;
>  		wq_stack_add_head(&entry->node, &cache->list);
> +		/* KASAN poisons object */
> +		kasan_slab_free_mempool(entry);
>  		return true;
>  	}
>  	return false;
> @@ -27,6 +29,7 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
>  		struct io_cache_entry *entry;
>  
>  		entry = container_of(cache->list.next, struct io_cache_entry, node);
> +		kasan_unpoison_range(entry, cache->elem_size);

I kind of worry there is no type checking at the same time we are
unpoisoning a constant-size range.  Seems easy to misuse the API.  But it
does look much better now with elem_size cached inside io_alloc_cache.

>  
> -#if defined(CONFIG_NET)
>  struct io_async_msghdr {
> +#if defined(CONFIG_NET)
>  	union {
>  		struct iovec		fast_iov[UIO_FASTIOV];
>  		struct {
> @@ -22,8 +22,11 @@ struct io_async_msghdr {
>  	struct sockaddr __user		*uaddr;
>  	struct msghdr			msg;
>  	struct sockaddr_storage		addr;
> +#endif
>  };
>  
> +#if defined(CONFIG_NET)
> +

Nit, but you could have added an empty definition in the #else section
that already exists in the file, or just guarded the caching code
entirely when CONFIG_NET=n.

Just nits, and overall it is good to have this KASAN support!

Reviewed-by: Gabriel Krisman Bertazi <krisman@suse.de>

-- 
Gabriel Krisman Bertazi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sfewryfv.fsf%40suse.de.
