Return-Path: <kasan-dev+bncBCT4XGV33UIBBTN44GPAMGQEKMWTSKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49B87682081
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 01:18:22 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id j20-20020a05600c1c1400b003dc5dd44c0csf1644756wms.8
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 16:18:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675124301; cv=pass;
        d=google.com; s=arc-20160816;
        b=NP8Hon8S+1e3TX8TGa980PPFmtQF8KmFBanmsnkzOT5m6U6QXUKvMgRCmYFuSnNf7f
         8ErdvYVo/mihwfaDUnfVXoWr5Uz/tTOerRzRc/K5zUQObsoalpRKPnoNXCHzLiPBGGKJ
         0bJzgP6FxyuVOJCQQcu6nxw1PBu8lzOF+MRQYBSjelI1oJvEtemXj0uPO5oLYK8SCSgf
         KCFE3hfd/R9AqBj1cm3CJBbCvMitq2gBi3HzpBvXfwgW9Ol70Cgh55xwP2qqmZyiEO0F
         IjLB7k6OiRdAw6JtZEBooj6sz2ZoEu37jS0Lym72gCuW2wiAu4AanYZN0+YnFChvpfYq
         dE2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=trQdXnvNzfTnkL0rzIMHJntjjLhvX2ZMETlcFnuPgBo=;
        b=dPjxBcFbFEbU2g6aEidT/i2Tt8lUxb3smWhQiL2NMo8pPfxzXarR7jKHzopbzyieyK
         6haoEj13kudFZZC9neRN7ZbIOEkrCg91ajFGpbvt0BaL5xGYgKLoDboawq0bj27Ymvzl
         X4+TSlL6fqgwYvkm/E8+bIcJDwSjV3gTtXg5HvKqUn3QvvsGthW5I6V26cD0FgdhxFcw
         hknod9ykheIHi4nQd0vplioycMGCY58rLvGw+n8oO1ASaHLmJDY4r8QLm8Aziy2wi+t8
         HWC4cqk12viG27SyTz2+6CmJExBTNDQwxufjN0DstCt2VU/rLyyRWWPGHwUIQORlmQmf
         20Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KKWH2oaf;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=trQdXnvNzfTnkL0rzIMHJntjjLhvX2ZMETlcFnuPgBo=;
        b=l4Bxss3KsKGC+IkWQWL5+6GmuLanumMy4F+TgE4ZHC5MWyXtTrS5StafjGeUkjpLqf
         7lSZ8478TpBfOoDc1VKmPrUVTTOs1p5ZITxvfQyV7tPCYL+ms6jy8WYo3MOxisiev0c7
         DX7Y4qkhX5ehwH2Y446OIxKN/e9T/YdTmwVkHPmP8POJA+CDZ/aVeLiZHkHfSGRRia4R
         IV7Sgdg+6ZBP509/+wfwMmD9miR21fDc7YPCDt8/woFCtUUUFTmt3zYz+7YClGWtVvLD
         ROWPJQjq1BvCa7TiuZl6D3NxF4aLmgp8GmG7N8/xvPkDk/8YYwHOlDoxAnvrgIKSKlY7
         Nyww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=trQdXnvNzfTnkL0rzIMHJntjjLhvX2ZMETlcFnuPgBo=;
        b=gXmRGO6w8q0CN2mGFqmJtGtvmxI/txOyXMcNTW0jrCiWA0hwpu7kzq457wfSJxxthA
         w2HH4FF4eG/SRG5/jhdDQdfIovrKnyxm/86wDPFAxs1WwQmohlsesEBDzJuTmLW81ygF
         74QWBI8Ottn/Vv4Ud/ppjO+T8bXG/CqocmTVsfxxuC3YFVSFZP9nM+zvOg8OgK3VqD0s
         iqITBhnBhv4/TZJkLaDp6TnDyt79Vx5oCZCnPVIxiNO5CaKgfzokLAWRc/p1jP+fUnLp
         R3sOiswd82/s+6NuwuW59IIlClF0X2eC4ueJEs20YQiklFyjDUXwBngOhLkNNz7LqozX
         d16Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX6hQzDjDokRJiAjnvFixfzmu+ozNZDTGx9NdVSNa5i+G8vcPJ8
	ig/D/5+z7FHBF88QcyLG8ug=
X-Google-Smtp-Source: AK7set8ydyrqNUb1p+Ks7pvfSgU92vYStz9MDNsawn9QmkyooDcI7HKZxm52WLZUbs3DSR/MWjEiIw==
X-Received: by 2002:adf:fc4e:0:b0:2bf:dcdc:afbb with SMTP id e14-20020adffc4e000000b002bfdcdcafbbmr275309wrs.642.1675124301562;
        Mon, 30 Jan 2023 16:18:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d06:b0:3cf:9be3:73dd with SMTP id
 bh6-20020a05600c3d0600b003cf9be373ddls3589436wmb.3.-pod-canary-gmail; Mon, 30
 Jan 2023 16:18:20 -0800 (PST)
X-Received: by 2002:a05:600c:3583:b0:3d2:2d2a:d581 with SMTP id p3-20020a05600c358300b003d22d2ad581mr52502778wmq.30.1675124300023;
        Mon, 30 Jan 2023 16:18:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675124300; cv=none;
        d=google.com; s=arc-20160816;
        b=kmEWWH8Ugo8v2SbgIMmkEDBi4G3dYZ6BSXGwec267D6ECi3WC75jedp9+dKKqB95hY
         WzcitG40jnwFFBYSo6WuUm4qjfCdaQe+Myr4aWgF0y0wCvwlaSzePMWSDIorQEAARhvy
         9vAyM68NY6MAZnRs9AKDTzuDS2wQxLqAx0ILmYBQfP16TD9guKvmN2f0D7lwRW+Ffziq
         9O9DD0PSjka0nPtEFzWZySYtfE7FXlAg/Fm4A6eQaeNOq2nPUXcSS4UJHjJIXx8INX1q
         sw6xuzvOMHHNGlkifTdpMEBmx6GZPPp3PNaiSnguSbqS+D3ozy4sbbyYtWPPF+trg7v9
         vyAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ldMPaa+Sh8bkY27kP/AAnSF8lbeVmvSDT6aZJNThBkc=;
        b=uyLr1saAgw1faI9dPACb6UkPaPDs670C+0kscM984V/ZO/QTOlqrkfxCZ6Rx6Y5kpn
         /GJLnArP425E7R7+wEDZObPrTEl7x5TaCZBgh8EA6YhOiYQl242D4v64mToHZl7We7hf
         zYEl7ez2bfUqmImhPmupxzzTvDaTEcSDUQotBENvHWIoX+Mm+anP+t5XWQKwlgyU/GHK
         QNS3UCK7YwDpv5ni5DvspAUt1RvvCrQnsHJZFe1L+PuTmRzKUyGkOYuS685LdkkW8LrB
         nH0vzJU2M1aFwxC3IwRaartXXIkbSrhS3fTLUqDw9rJ6JFTgnKBjICGFDsN7HHDRZfiL
         ZRSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KKWH2oaf;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id m18-20020adfdc52000000b002bfc35954dasi699787wrj.7.2023.01.30.16.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jan 2023 16:18:19 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 876C5B818BD;
	Tue, 31 Jan 2023 00:18:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DD241C433D2;
	Tue, 31 Jan 2023 00:18:17 +0000 (UTC)
Date: Mon, 30 Jan 2023 16:18:17 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in
 init_stack_slab
Message-Id: <20230130161817.a13365bca60543e34da27f48@linux-foundation.org>
In-Reply-To: <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
	<9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=KKWH2oaf;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 30 Jan 2023 21:49:25 +0100 andrey.konovalov@linux.dev wrote:

> In commit 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in
> stack_slabs"), init_stack_slab was changed to only use preallocated
> memory for the next slab if the slab number limit is not reached.
> However, setting next_slab_inited was not moved together with updating
> stack_slabs.
> 
> Set next_slab_inited only if the preallocated memory was used for the
> next slab.

Please provide a full description of the user-visible runtime effects
of the bug (always always).

I'll add the cc:stable (per your comments in the [0/N] cover letter),
but it's more reliable to add it to the changelog yourself.

As to when I upstream this: don't know - that depends on the
user-visible-effects thing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230130161817.a13365bca60543e34da27f48%40linux-foundation.org.
