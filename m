Return-Path: <kasan-dev+bncBCT453EYWEJBBVHC4CAAMGQEUELFALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BFA9B30ACFF
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 17:50:28 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id s18sf10721435wrf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 08:50:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612198228; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqGSZiKi2nmSUu/ZqzKpJVvnTQMM00YebUcCpq8iUZWTqSa9kmMVcgNspzsg9sX0cY
         Dq4YNG3qjzxVdOfZAdBkuoP/htes2xIyZ2RVxxg41GZ+S9AnSPv0q8Sbu0+msCgN+GYS
         TMwBKAIk7o1rEnPCiBZ6OrKPYEZFeu74qxY50K/Fr8NA1HSMG0iDnh6qAn6d8fPfpzRM
         29heQ4B2YnZ05BhhusC1xbzrWbCTGj7hteGFJ8feRzUi4dG78pYxkn0gp5aT19MZvL/1
         2NMw2TBqFWjET4kdhdRC2XC076i+3x3vlUMBi/d3Je9Bp0qbkj50LdKErdDaE2HLsYxF
         GW1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mTQ3hQGBN3kj/ifbIi4o5OrI8MGfjm8knq8Jcu6a/Io=;
        b=Ds0AQE59CXHIDGi5rpV/ZtNqCJqxJUI12hG/zfps+QjUUyrwtiD+6KpKVVOV/XFiSv
         wecpE4ezUZkI/OYjS8bah+50gzl0sKRZjtPefMA1ynfFB+E0iVegsRIHvOm4iP3Fxtv0
         PeLqXe+VU/nUtsvkXspObPE3zBiUhDXkySRGbv092ctO/58YR+Kwz9m4Ssp1NiE0Ud57
         RhjI8rP6XtorUecf6ql48n9CTlrn6dhqxk4qKZRXA4/fDAl1kP8JoWRdd5U9UmEGwXq8
         Ftt0fYpGvUDmssPJzY5njMkQL9VUgk2KMK90/p1KIHzOs6VplSRW7p4qzz2iGUWTVFbs
         rTQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YYB38wSZ;
       spf=pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mTQ3hQGBN3kj/ifbIi4o5OrI8MGfjm8knq8Jcu6a/Io=;
        b=OpMaX3rOnbou4VFr41W1MDIeiBne4YRCwwf16Q1r3RtvPu2SKaaxs23Iyu44tvr4Ai
         ODlPIzkwHNEVnoeD0njxH78ohOUU01fKPUQltQTJ6dyc3Qhn2l2rmsspL/y0GPGTJDX7
         zQ6vnD+M2R9OS21gd3pD78Vfm8oh5i8jEvXrsdvpxcabWdeTF6sJpEteBb8iuUuVLnsl
         ddcg9byISU/AZT/+nqVbQevFFFdsRKAodXYQZlPeLnVLq6GpiplXbLnSbQI4SORtdNKR
         mtHiaMywX44qpdtr9fmXywj1JeYyLC6zvlYp/f4HoltbDUt+TcBoHK4UsHAeD+8/0vO3
         OXKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mTQ3hQGBN3kj/ifbIi4o5OrI8MGfjm8knq8Jcu6a/Io=;
        b=ZbfZJGQYbtiPyrvPrQ6R2w2UQ8n9CYDBEgu/sahDCyCojZxbddeulDPeoJqbn6mx9i
         dK7guBJZ2f1ZxKqby86lOC2f5dk7VDSl1/CnpQQrLLFi3bMESGR3bhCsxuchWJOR/ghI
         hl3QCcsClVEiYtll97RIjE1zEmgsVAt/PnEZRvDGMViQBGYyiANbClN63Jqny8BAMA7Z
         86d91rVwm7Uf5Ifiapn0FET+w3lskMApLMrKsuIFyhb0JiokT1u2Xsj88iuw7pxgGElZ
         5yooW7RR4u+tGmo9rWTPEcVvO2WssFAP7ymDLR7MbQktfON5R33P2XPef+OtyMrcTXBo
         Z31g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mTQ3hQGBN3kj/ifbIi4o5OrI8MGfjm8knq8Jcu6a/Io=;
        b=udXfwGIRQd2Yk+YmsWhr3rL9LOVMln9qcP6byJtn54VTZbTAicHHZ1d2UAz17Cscdb
         8PUqf6LsV6d1Pi8Gi/9yHN5vf6It8kGo7KOq3Xkam26nUo6AqoCFeY3Hrz8jC/qjynhd
         25oWp00kbMzNEqErI5UpxkWah+bG17rx3RVxOEmIMhySNWQlncHiaOH/uOHFFaMmBCc6
         dMNyc42OlitObxi7M9wV5ICV9SRob5i7NNWyy088Pd6ww8+gN4hS6FRvDOrTXzxV2NgW
         pdvAnix/93zZ0eH+2/By3NXWJzH1Ljrb921sa+Zv5zWihLrl8MAc5f+XrC0G+V8GUT3I
         AfDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yQwt/mhJrboCsMkh22I9oPZMXuI73NIDSOqrgXBY467R6Q+9M
	OQhnmqt5YiLK+VwWrFNuYAQ=
X-Google-Smtp-Source: ABdhPJwP1HfGQUchJx7E61ivCMZsCpP6U8Eps5V8DxG2dHvCiYVwCdZI5yAKlLxZXNs9roYf805+Cw==
X-Received: by 2002:adf:e807:: with SMTP id o7mr19922331wrm.308.1612198228572;
        Mon, 01 Feb 2021 08:50:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f852:: with SMTP id d18ls9862144wrq.2.gmail; Mon, 01 Feb
 2021 08:50:27 -0800 (PST)
X-Received: by 2002:a5d:5384:: with SMTP id d4mr18367557wrv.177.1612198227667;
        Mon, 01 Feb 2021 08:50:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612198227; cv=none;
        d=google.com; s=arc-20160816;
        b=QdFWw25EFMepsPoKo5gRWCPOcHBipdfuMXhHxn0Blq5QrhpDOtzSAMDfQft3Fvmsgy
         e1qqTB29gD+ehYcpmWbLH6Fx1jxRed5GyLmMTxnybyK+tvWvSZ8uX9EsZjSa9+pKZfzP
         FKwstdxdWsRSmgIJI/AWFcQ0f4er1EYZAmLajzMnPo3ZZwP2OMpUvK1fk8r6snCvQ2wJ
         kE9ZttUEhBwYhnYsUfAoHbWVqYqNX4T4xh5mExk9dLG05Qcrx5w7o/xnuuJDmLNm9trs
         TXKL4aUzFhRpiNhojvFl9w2tKjmFgvk3N4A0KpZ5BV5OtIRXk8fxrHacoFymakTAUQiA
         rRBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=28aWbeuxYU/d3zJdSw4FejdOSZ9mEcviBMdx8cpNqHs=;
        b=UZ7ow2XlkRYp6I5+QUMppTlPrvn4k/9mLwXxvyBtItnztcNlPSOGBPLA7wWbbiLtIQ
         +Om2cFIdyUyedM9LJ3xdXzgjYqDCJ7oGFMa2XScIOYLUFJlvsBKiNp0ZJVQRVZvqOFz2
         NX0D+lSfKvfGHDx8HbHOiQfZDgseUsXpDPRjF+QPkcBRNpkS4P3hyer2BM9rtMrVfExx
         hkC/A6xhizCJ3jAP+g8Npi2FHMe2YpvbmgrtyyCb/SJNu12TWbnKvLqSl9RhhfyrAj+e
         S948OZrqR0F/nP/XZKHcO6zKz6mtSwClzS7ojhN9w6BdksY42m7uv5r9VJ3RaS0//kAV
         b0Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YYB38wSZ;
       spf=pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id z188si1207571wmc.1.2021.02.01.08.50.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 08:50:27 -0800 (PST)
Received-SPF: pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id kg20so25455671ejc.4
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 08:50:27 -0800 (PST)
X-Received: by 2002:a17:906:719:: with SMTP id y25mr11628409ejb.180.1612198227459;
 Mon, 01 Feb 2021 08:50:27 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com>
In-Reply-To: <20210201160420.2826895-1-elver@google.com>
From: Christoph Paasch <christoph.paasch@gmail.com>
Date: Mon, 1 Feb 2021 08:50:16 -0800
Message-ID: <CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j+gZxAc8VESZg@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	David Miller <davem@davemloft.net>, kuba@kernel.org, 
	Jonathan Lemon <jonathan.lemon@gmail.com>, Willem de Bruijn <willemb@google.com>, linmiaohe@huawei.com, 
	gnault@redhat.com, dseok.yi@samsung.com, kyk.segfault@gmail.com, 
	Al Viro <viro@zeniv.linux.org.uk>, netdev <netdev@vger.kernel.org>, glider@google.com, 
	syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: christoph.paasch@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=YYB38wSZ;       spf=pass
 (google.com: domain of christoph.paasch@gmail.com designates
 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Feb 1, 2021 at 8:09 AM Marco Elver <elver@google.com> wrote:
>
> Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
> cloning an skb, save and restore truesize after pskb_expand_head(). This
> can occur if the allocator decides to service an allocation of the same
> size differently (e.g. use a different size class, or pass the
> allocation on to KFENCE).
>
> Because truesize is used for bookkeeping (such as sk_wmem_queued), a
> modified truesize of a cloned skb may result in corrupt bookkeeping and
> relevant warnings (such as in sk_stream_kill_queues()).
>
> Link: https://lkml.kernel.org/r/X9JR/J6dMMOy1obu@elver.google.com
> Reported-by: syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com
> Suggested-by: Eric Dumazet <edumazet@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  net/core/skbuff.c | 14 +++++++++++++-
>  1 file changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index 2af12f7e170c..3787093239f5 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -3289,7 +3289,19 @@ EXPORT_SYMBOL(skb_split);
>   */
>  static int skb_prepare_for_shift(struct sk_buff *skb)
>  {
> -       return skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
> +       int ret = 0;
> +
> +       if (skb_cloned(skb)) {
> +               /* Save and restore truesize: pskb_expand_head() may reallocate
> +                * memory where ksize(kmalloc(S)) != ksize(kmalloc(S)), but we
> +                * cannot change truesize at this point.
> +                */
> +               unsigned int save_truesize = skb->truesize;
> +
> +               ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
> +               skb->truesize = save_truesize;
> +       }
> +       return ret;

just a few days ago we found out that this also fixes a syzkaller
issue on MPTCP (https://github.com/multipath-tcp/mptcp_net-next/issues/136).
I confirmed that this patch fixes the issue for us as well:

Tested-by: Christoph Paasch <christoph.paasch@gmail.com>





>  }
>
>  /**
>
> base-commit: 14e8e0f6008865d823a8184a276702a6c3cbef3d
> --
> 2.30.0.365.g02bc693789-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j%2BgZxAc8VESZg%40mail.gmail.com.
