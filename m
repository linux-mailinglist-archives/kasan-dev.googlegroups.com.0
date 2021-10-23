Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQNR2GFQMGQELLIY2XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A7C714384CA
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 20:47:30 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id x17-20020a544011000000b00298d5769310sf4419564oie.12
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 11:47:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635014849; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNvIstDN+kwp/sLy5DHr2vmruu4wLwZ6HDjaL3I/MK66QBH9w5zX0jsO2t97MOV01z
         WfuyQ/ak6uhannGn58rBLfrt6IT8pGGxnqGOA54e8CsOOwZV0xlXL1ZEB4P7/vlBRNlH
         5Ik5CFVjFQ6LmOxmGkGukXeHfhZ4ai5VlhbmKN2/DldG60tGuiGxz73cn/UL2tovoJXv
         7oTT213ypSAHI7oAF9jDiqG6O4YI9uWnXACcFOipudsdFt75yQvja5uvClrXDYvMFU0c
         1I0v32axYHIqz18zdtXu48Bwv2IjHPVtK7nRzt/cWjtDRoHo2AWTL51c+5XtIoaZcBE8
         wYEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B3orqF37a0ojB4k1+EGM9ghKO/SnjtNIKKtLu4ffboQ=;
        b=GcDy/sjYqu2bancFDqMgeK7jK+LZJOojzwqDFrtGj1hqu1efeTzRU219Gy6/1P1nYT
         MrWNJObWaj1lglM6zTeH25G2afeGaKWMyLPNccuu0HDClqDSczdyKA9qthqsISHwQ7ZE
         ibZLZTusO6IuLRR3JbnRQM4kDvWLuJKXT14dg2HJEjy9i2pEKBHb06GBekwCRG7biiaT
         y5Lk4rTNlZYUR3RrlxduOW7MBAnmna3ET5DdQSduVw4xk7VNpZibDDgyoDeauhhDi1K/
         FSyS714nx30867bTWKlahUTzajLwUi5ck4ywoOew38MuJfdi/Sx6eehsffLAPU/M3rPi
         KY8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bVOldoUU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3orqF37a0ojB4k1+EGM9ghKO/SnjtNIKKtLu4ffboQ=;
        b=p5P+U3HkSHVDvzj0c8G8j5yS3T61J+E+HuqSZhAT0AgzGRpia/0a4QGQft8Up5bazX
         AWUFTB6I/KtUhtrg8wPjRnEqWAd6BaCJpPQz7Ay8c33bHDgABRa2BiUr2e8tDrPhXH+I
         YmdlNv2I26pcn/e6dncJTbfwVo06RhNfP+I68aA0T0b/Mwwu7Az8mnry+OBi+rfx1SQI
         BpXiuiWZ79M1q3PKdx7TtqDL7Y9WypW1H5IfhoO/lQm+g+zXdZqKjiYVIlNeIPzAlPw/
         VTrjPlhMOyOQzUG4Y+1CQLzCrYYywP/QEA+akdV2wXS7LZ5HM8DPelgEe5Lbt9dVVZWl
         TdRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3orqF37a0ojB4k1+EGM9ghKO/SnjtNIKKtLu4ffboQ=;
        b=WD92t8PE3zfN/WXodUIOBP81MkQJzzoW26PAEdwXDW2KmyYvBa9mhlgzQXTJ2BGfEZ
         G2MrC+Rkd3rV8JS7ts3ENXxdYpCxDtri8CdqB1HZVxoKaDzjKn/N0haGR5ZkVHfbzEi+
         HPVTHa9jaiAPmwbhEhKl8Qm1WX0Gha7EwpAKApwwT0yd2Qqa3jqEH6wXS+5KzwOznD54
         8A8gvNLBesCn7+tqibL3mktUOU8/my+zm2Mo/3eQFkXHolrHiX8ajVLFC8BaiQbbqraf
         t/31YGsr9jeimftTm1qv0RYJtdPQJFpMJdRQCj4mItEFCmXk3eqM3fxL/4F2rInToMPT
         FVyw==
X-Gm-Message-State: AOAM533PAB68yW9tEk+HhDR9Y9ChCuw7Lshw8MyDZjFDbimNJjpEY4Uo
	w6zv3mdXGjrkZ0giGpeHZf0=
X-Google-Smtp-Source: ABdhPJxdmCcL+XW3MP/bK/B9kTAMsuYhB3JIulZ3bY42bifB/KEd/hwzZd7WOy52kR8LUg1guherCw==
X-Received: by 2002:a05:6808:110:: with SMTP id b16mr5276841oie.7.1635014849461;
        Sat, 23 Oct 2021 11:47:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2812:: with SMTP id 18ls3543569oix.6.gmail; Sat, 23 Oct
 2021 11:47:29 -0700 (PDT)
X-Received: by 2002:aca:3e86:: with SMTP id l128mr5296389oia.111.1635014849151;
        Sat, 23 Oct 2021 11:47:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635014849; cv=none;
        d=google.com; s=arc-20160816;
        b=PRB0s+KpYfi9lPOvokJfpmIBdShKmvqw3jqyFfc4gLb9XwxjL1t5XtDlr9RsfsATeP
         fuGW/8D+P0+Rynb0YzRdYJu/1mTqisADAQqz10U1PyaRURph+7xWNkBEMX9UR5y3mvcx
         vEduYdKua53DKTwsn1P1O6LnCmhXt+ZxtiMsS8xW84CJiKu6qQPmboYwbDBFoMOgcVou
         KN7lqpMwdqd4FWDLMtJiouk9A7dzPhKJUx/RkHwiSDD6EKlnaSOePZsy60RKze0nl90B
         t/UnJxr4Qvuw84E9NcZ7rJZacdBLNwV1l0xosoFNqt1GKKXF8VN/xuJa9OCqI/BEljZX
         zS7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7m875e4gGbT9nJQnt7puIjT90v2deLXARSSVrDwAsaE=;
        b=L6BZ0IXDTjos9twjBT8ApjEPR59yrAr8uken4NFdBUCwCiUSNegiHl7bI3yJ4jczs4
         kAnk1H7sRNCSRQN49hA9ha5wt+enmFiJ+6bWi+r6Hc/8TP/sQu7XglfnPMP1oJh4FDNc
         Knrxlhmdt2xIVb1Ls4vtNlBi1aO2+Nt/r5O9hWCWgKPy5gQr4MYoC0YSE1ALR34g76Gr
         EPlSQMEAHPFB+Jgmb/VqNJTwKY6q6Q53guQhnOFDJHBXy45keS9NyL6CBpVXdYp+Tz2/
         akgFBqZnttP2Gkk85aB1h1WFjcwnOXZsnHRHUzRaveDYKqHOfskZFJ34QSUvpqmw7e4Y
         ti0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bVOldoUU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id r130si979246oig.2.2021.10.23.11.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Oct 2021 11:47:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id g125so9442386oif.9
        for <kasan-dev@googlegroups.com>; Sat, 23 Oct 2021 11:47:29 -0700 (PDT)
X-Received: by 2002:a05:6808:6ce:: with SMTP id m14mr5291817oih.134.1635014848757;
 Sat, 23 Oct 2021 11:47:28 -0700 (PDT)
MIME-Version: 1.0
References: <20211023171802.4693-1-cyeaa@connect.ust.hk>
In-Reply-To: <20211023171802.4693-1-cyeaa@connect.ust.hk>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 23 Oct 2021 20:47:17 +0200
Message-ID: <CANpmjNP8uAexEZ3Qa-GfBfX6V8tAd7NK0vt3T3Xjh4CkzxfS-g@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: fix null pointer dereference on pointer meta
To: Chengfeng Ye <cyeaa@connect.ust.hk>
Cc: glider@google.com, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bVOldoUU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, 23 Oct 2021 at 19:20, Chengfeng Ye <cyeaa@connect.ust.hk> wrote:
> The pointer meta return from addr_to_metadata could be null, so
> there is a potential null pointer dereference issue. Fix this
> by adding a null check before dereference.
>
> Fixes: 0ce20dd8 ("mm: add Kernel Electric-Fence infrastructure")
> Signed-off-by: Chengfeng Ye <cyeaa@connect.ust.hk>
> ---
>  mm/kfence/core.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 7a97db8bc8e7..7d2ec787e921 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -811,7 +811,7 @@ void __kfence_free(void *addr)
>          * objects once it has been freed. meta->cache may be NULL if the cache
>          * was destroyed.
>          */
> -       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
> +       if (unlikely(meta && meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
>                 call_rcu(&meta->rcu_head, rcu_guarded_free);
>         else
>                 kfence_guarded_free(addr, meta, false);

Sorry -- Nack. What bug did you encounter?

Please see [1], and I'm afraid this attempt makes even less sense
because if it were (hypothetically) NULL like you say we just call
kfence_guarded_free() and crash there.

[1] https://lkml.kernel.org/r/CANpmjNMcgUsdvXrvQHn+-y1w-z-6QAS+WJ27RB2DCnVxORRcuw@mail.gmail.com

However, what I wrote in [1] equally applies here:

> [...]
> Adding a check like this could also hide genuine bugs, as meta should
> never be NULL in __kfence_free(). If it is, we'd like to see a crash.
>
> Did you read kfence_free() in include/linux/kfence.h? It already
> prevents __kfence_free() being called with a non-KFENCE address.
>
> Without a more thorough explanation, Nack.

May I ask which static analysis tool keeps flagging this?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8uAexEZ3Qa-GfBfX6V8tAd7NK0vt3T3Xjh4CkzxfS-g%40mail.gmail.com.
