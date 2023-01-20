Return-Path: <kasan-dev+bncBCX7HX6VTEARB5G5VKPAMGQEIAGNXGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6511F67582E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 16:10:45 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id o11-20020adf8b8b000000b002be143c4827sf999454wra.19
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 07:10:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674227445; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OTMFL2X1Qxeq5sHk0S3o7bxWnFQmOkzfF0UCffgIF3ms+xP/0pSXD8SYcz5P/RqM9
         4ubZrR3U5kFnWGudJa2UVr34RRlomFyIhHRR64ctnqjwRpJoFkzDutWzXT3g23etpd75
         3pZfj3CFP/tZG7S2OsE7agBkafe4YVkPzbml9ZUr8T6E/Si25W9rAVS4+iCrVgyTsUIk
         7FnPz6oh3x8Vj+oYvnh0TqW2TQ7ClUHrayq1TbnRqWMCoLgwnDFRZ65Ogm7jF+kvsu14
         VRMexe38GIzuvb1+fnh4fZkxnLPPB6TBn14Dgoh8B/4SBr2XecgYmIsIhW/RJsJ/V70T
         VKNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=lS/l8isji4bjyLNQ+cDIbvHW9HlT3yzgtfeL5eytCaw=;
        b=nBvwCJBJHh7opJoPyLbXGCoNC7R73eF6OXQRBvj4P/xRaSGa1XtuteO4dLvSOMA6XC
         qnDhEJR7mI8bDe/ZBJjeWJb7VAQse6B5pikxg1jtcLm65heeAyBZtDgKJnNjqzMrIVIj
         KnWnNDYNtx7ppWuFsWLqnp7XldJ76SaK/zJSP3QHSMOUPGxLORPSQEoE0ai3QH8L2C45
         Vz/vO4426Cqhk4XPwcGaTdK8aN66hcIOePmB6zPRcNlYAd8zeCp7V616MMB9wlHnTb3w
         /YyNoVHHOpYpryyDB/j78emLTfgeePNK0BZhAfuxziaxEfecLhmYD1U027J/GRxJX0pb
         HIxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aSIyqU38;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lS/l8isji4bjyLNQ+cDIbvHW9HlT3yzgtfeL5eytCaw=;
        b=g7eXFkjwc5erOo8pUD/wxbOoJm431UlSHOLQPAYj+GQ77FxR0ZMBJV4CXyls8KMmOn
         3GY2iHRtohatDGz+M2FymsNHYDFYyreJNuSxLYr094ZLnHAMpTCUWPCajVuW4An9ld8b
         p+mpxqnonxQ9KYeGDPMRt5cpn3haXO6gOmyK1UEGnSHnw1ImEP+ApNA1cnnZyN1aQx7A
         gk/idYj9fhRKoC31AjxSeMcwEspINBYOWVYcCSy00KKkbzMSG7TDFWJDLdlV1JZ2HiZc
         C7E80NgkErFU1rsMVIymjzvP1hKX4KU5T9hNSRvdWMZ4TJBi2nRfrGk9cF1PvSD51F+V
         P9pg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lS/l8isji4bjyLNQ+cDIbvHW9HlT3yzgtfeL5eytCaw=;
        b=Nw26cMitcr6Qgq7PY6hzHRa5evVLuWgNo/yphBVSne7LQWXPTQDHa9JoO7Z9DDnYOL
         W2yP/hibnapvhA7zlDwkC1Z29RlJ+mBLhbRFFQcDsE4igbbsU/SxOzAo04W+wM0lW5Xr
         pKScH2FMoQJCLHO+I4wZujegEFFDSsQMAwVzFvB9acNTdll89IWqe6vqhwTPBE4iAvC+
         K9Jdz+XNOeSy50YsK049QGAjbMlhw1yuIdnLdGjwYtNFwQgI5qhfNyA/KqYBYAhlY3Ne
         Ro6pAW5T05BYq1RbTFsLiGxtJatcrVcREVOm9eTRplXjISKZinMTia84BNj5j9IxOYdt
         Q3vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lS/l8isji4bjyLNQ+cDIbvHW9HlT3yzgtfeL5eytCaw=;
        b=PgCaz/mibNqEnIAcKRuPXSlfkrIm/JYCDelWegekeW524tstuLmeysB41+emvBMJ9E
         7QihMj2EZq/DKAMBxk4RkFOJbP18Eg1f/Sc2p1Wo3RF9Q9lPe3K3HftlU1/KIPLKJjKT
         HlZIhIJHulP57SWGCckpSf3bl26Zvyvp6obBOsFrP7pTA8Mnl0cps47cj/uvumo2rLyX
         +BujGmP/pgJaIfqM6W3kY2O8gq9Y9Rv5QFT/HxWjDjT3RAcoJpcV1hxIVMfbo6f5/w25
         4gAJidYe9FhIXQgo+NdASin4UxYIqKGdXV+X11Wi91F8plRyL2+S6dcckunDTEJBjdNK
         dqMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koIIEsa+D2UOtQYl0vQrnSW3sa+1LnRKEtaR+fGYYpo4LqlQMjH
	DnNO8LVj26fWMPOlY00+bbw=
X-Google-Smtp-Source: AMrXdXsrE2sGlesEbCnOSzTi/cz5xc5CEyBr15lQf3XQRNx8AHzK6+ybUe6o2LJaa0bxp0+6QFJf0w==
X-Received: by 2002:a5d:4b47:0:b0:24f:376e:4fda with SMTP id w7-20020a5d4b47000000b0024f376e4fdamr834602wrs.538.1674227444760;
        Fri, 20 Jan 2023 07:10:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2317:b0:3cf:afd2:ab84 with SMTP id
 23-20020a05600c231700b003cfafd2ab84ls2806877wmo.2.-pod-control-gmail; Fri, 20
 Jan 2023 07:10:43 -0800 (PST)
X-Received: by 2002:a7b:c5d6:0:b0:3d9:fb89:4e3d with SMTP id n22-20020a7bc5d6000000b003d9fb894e3dmr15340454wmk.28.1674227443296;
        Fri, 20 Jan 2023 07:10:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674227443; cv=none;
        d=google.com; s=arc-20160816;
        b=Fwf5T83/Ko7nozhVMGFOMaA62RH68+rF3zkNB1PekWm95GwQmHXsLxMd8dFF5eu1jg
         921LGKn7sZLSBP8Hqu1swuP03Jgi5sZCGNAWR9nB8Y0PT7rbHv5yMxVqsFM600K2AmUY
         XmVQ73TX9MNqv5u28H5Vkt1pjaT55GA2oYRcAosc/T246No0awZ5KFqirKV6telJNHz6
         K3MZLE2Kyx+19Bn/RXjD8NkkxgdPwgf+gXqSTRsglpYLtnSsRH9SWY7T0EXrI8okde7a
         puo0YkdHk4gBEWNo+mpbEtsmWZPTRNZHt8jrSOBgBG5ajIk6InN2nSUeEIP+oDUjpB4X
         AInQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=itlZq4jszddGqsEVp43yTFiJ5AKOmLAYbdl8HkGi1kU=;
        b=R8KUgikNd5/p2eS5aJMfFtiWLzRJPjVXBOo6smbIGa4MO/nQvtLObtMcoAcuuSIzXb
         GQsc9Fkhxft5zSFEzknPzOdL9bSJl/pHqbqPKKkHjoT7uB4l88/s7ykiKfMwchJpL1EN
         6EZdaZ3zyH27qaT8P610ozyIUYuIFSqgCNYf2OQQlievdAsw5DYg+BwbPI8IhcEhlJXs
         PcEQSG6W/p+LuEw3f20C/Jwp4XKptSF/zc5D0tDtwBKUQHbcfaMMUNK5LsEmIQz5CCZZ
         6XuenCWleaOHQdKK2xYe+R9JoMEgqvdFJMOPPVbxQV32kOO/mj4eRa03Ae+hn0R0vSzS
         Pl6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aSIyqU38;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id bd10-20020a05600c1f0a00b003d9dfe01039si511952wmb.4.2023.01.20.07.10.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 07:10:43 -0800 (PST)
Received-SPF: pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id mg12so14731193ejc.5
        for <kasan-dev@googlegroups.com>; Fri, 20 Jan 2023 07:10:43 -0800 (PST)
X-Received: by 2002:a17:906:1307:b0:803:4549:300b with SMTP id w7-20020a170906130700b008034549300bmr17092233ejb.19.1674227442899;
        Fri, 20 Jan 2023 07:10:42 -0800 (PST)
Received: from ?IPV6:2620:10d:c096:310::26ef? ([2620:10d:c092:600::2:c4f8])
        by smtp.gmail.com with ESMTPSA id vw22-20020a170907059600b0084d43def70esm6445267ejb.25.2023.01.20.07.10.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 07:10:42 -0800 (PST)
Message-ID: <a0f75aa2-34dc-e3a8-c9fe-11f88412ef93@gmail.com>
Date: Fri, 20 Jan 2023 15:09:51 +0000
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH] io_uring: Enable KASAN for request cache
To: Breno Leitao <leitao@debian.org>, axboe@kernel.dk,
 io-uring@vger.kernel.org
Cc: kasan-dev@googlegroups.com, leit@fb.com, linux-kernel@vger.kernel.org
References: <20230118155630.2762921-1-leitao@debian.org>
Content-Language: en-US
From: Pavel Begunkov <asml.silence@gmail.com>
In-Reply-To: <20230118155630.2762921-1-leitao@debian.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: asml.Silence@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aSIyqU38;       spf=pass
 (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 1/18/23 15:56, Breno Leitao wrote:
> Every io_uring request is represented by struct io_kiocb, which is
> cached locally by io_uring (not SLAB/SLUB) in the list called
> submit_state.freelist. This patch simply enabled KASAN for this free
> list.
> 
> This list is initially created by KMEM_CACHE, but later, managed by
> io_uring. This patch basically poisons the objects that are not used
> (i.e., they are the free list), and unpoisons it when the object is
> allocated/removed from the list.
> 
> Touching these poisoned objects while in the freelist will cause a KASAN
> warning.

Doesn't apply cleanly to for-6.3/io_uring, but otherwise looks good

Reviewed-by: Pavel Begunkov <asml.silence@gmail.com>

  
> Suggested-by: Jens Axboe <axboe@kernel.dk>
> Signed-off-by: Breno Leitao <leitao@debian.org>
> ---
>   io_uring/io_uring.c |  3 ++-
>   io_uring/io_uring.h | 11 ++++++++---
>   2 files changed, 10 insertions(+), 4 deletions(-)
> 
> diff --git a/io_uring/io_uring.c b/io_uring/io_uring.c
> index 2ac1cd8d23ea..8cc0f12034d1 100644
> --- a/io_uring/io_uring.c
> +++ b/io_uring/io_uring.c
> @@ -151,7 +151,7 @@ static void io_move_task_work_from_local(struct io_ring_ctx *ctx);
>   static void __io_submit_flush_completions(struct io_ring_ctx *ctx);
>   static __cold void io_fallback_tw(struct io_uring_task *tctx);
>   
> -static struct kmem_cache *req_cachep;
> +struct kmem_cache *req_cachep;
>   
>   struct sock *io_uring_get_socket(struct file *file)
>   {
> @@ -230,6 +230,7 @@ static inline void req_fail_link_node(struct io_kiocb *req, int res)
>   static inline void io_req_add_to_cache(struct io_kiocb *req, struct io_ring_ctx *ctx)
>   {
>   	wq_stack_add_head(&req->comp_list, &ctx->submit_state.free_list);
> +	kasan_poison_object_data(req_cachep, req);
>   }
>   
>   static __cold void io_ring_ctx_ref_free(struct percpu_ref *ref)
> diff --git a/io_uring/io_uring.h b/io_uring/io_uring.h
> index ab4b2a1c3b7e..0ccf62a19b65 100644
> --- a/io_uring/io_uring.h
> +++ b/io_uring/io_uring.h
> @@ -3,6 +3,7 @@
>   
>   #include <linux/errno.h>
>   #include <linux/lockdep.h>
> +#include <linux/kasan.h>
>   #include <linux/io_uring_types.h>
>   #include <uapi/linux/eventpoll.h>
>   #include "io-wq.h"
> @@ -379,12 +380,16 @@ static inline bool io_alloc_req_refill(struct io_ring_ctx *ctx)
>   	return true;
>   }
>   
> +extern struct kmem_cache *req_cachep;
> +
>   static inline struct io_kiocb *io_alloc_req(struct io_ring_ctx *ctx)
>   {
> -	struct io_wq_work_node *node;
> +	struct io_kiocb *req;
>   
> -	node = wq_stack_extract(&ctx->submit_state.free_list);
> -	return container_of(node, struct io_kiocb, comp_list);
> +	req = container_of(ctx->submit_state.free_list.next, struct io_kiocb, comp_list);
> +	kasan_unpoison_object_data(req_cachep, req);
> +	wq_stack_extract(&ctx->submit_state.free_list);
> +	return req;
>   }
>   
>   static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)

-- 
Pavel Begunkov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0f75aa2-34dc-e3a8-c9fe-11f88412ef93%40gmail.com.
