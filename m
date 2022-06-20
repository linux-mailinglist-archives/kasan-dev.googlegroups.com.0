Return-Path: <kasan-dev+bncBCMIZB7QWENRBRODYGKQMGQEOHYDUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B4C8C5517F8
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 14:02:14 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id w8-20020adfde88000000b00213b7fa3a37sf2419559wrl.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 05:02:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655726534; cv=pass;
        d=google.com; s=arc-20160816;
        b=czjBJSRxdW0FkZWL/64il1MIHVS6Z+c00TZPhXX5a76LmYQbVjKlhaihGpi61aVP30
         DALL6GR3cg/m5oSLrltlK/hNuUNckriTO/ooiyc17yOn8sipjkJQ3vMH/N8K5q1QohLb
         REN5ae7H6fxrdMIq4EjZqrOdBsiuiCpeHypB72lHPz6VyBIDy7rEBE+cR0ksLic6uISa
         BYAVLqbnIIvYH22KL8w2sEECAhk+IdTQ+Zbdp/t8h/h0OtqOwXJ4whillZjC/n5J/FUo
         nqYB/dP+DiJqItgHn/AcFRqXZr2PJzf6Bg8soTJYZlMuVx/e8OJ1x6LgvKVYdLfBR8Dm
         Bajw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pHYNXZnhUD/EGGeOkHUvcciV+wNMhmXCXK4iDuKKc8U=;
        b=JM4lAzPBGoso22E2WfwzxTZ+Wl7exuuCf361HfktDWiN9V/9W/8RiOVG0jTKR90Tpb
         g0dbDi9MNDXXIr8YmEd3owvYsq8jrcoYeHY3jMLGMyo8x+CB1DSQ9rpjnTB4Cn1V0B1B
         jQDiWvNsthyWj0MXFuE/dsduZq4+jBnw8BXFMU9YkY4WvTFNLcnlm5o0xjSvGi8b8DxK
         VELL4+RMVHTh1gRLZcsMarggvOeQf9IB4QNA4Wk/3AklZ2boDJhXCOb5mav5qylI5Zc2
         IZ70mskfkG+D3PTaQkov7eXl1hSxfIpvFBi3qk/igH/69wSZL4kciGCAEcnU1wgzXTku
         zsNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sXqeUBSq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pHYNXZnhUD/EGGeOkHUvcciV+wNMhmXCXK4iDuKKc8U=;
        b=iW72v6MD6CySeFHoDSytsug8jWXv1/VPzpqbKNGlxij6MXHXBsBzCwrMHh9w3Np9Wl
         1yK4o6WJUGhqKfv5MS3j/qYNwwd3z6bBpnhxNtwG1vJthY3e8+og83Z/moIiUojMVZnT
         dVo5Tm9abELvOYbOyZvAzR34dLfH5uFmzqztMpb98gWSJrPwt8x0oOh6Cnp4jjI/7jJ0
         3s9yyolPaUOFDU0CVmLqV+Fu9SfaLbI3fS+3bUz7wVoo2Nd1X0J2t+gcYK0r1L/TgINf
         Hcn7+3PtjchhDJ7kpYpYkk0cIS+EGuPidnQIa3bD+vFzAjjVgkzut28AfW7W3Ee3MVDz
         uuJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pHYNXZnhUD/EGGeOkHUvcciV+wNMhmXCXK4iDuKKc8U=;
        b=ECpO5l/12kIKNFTqsiElf30DLt9M1e937IOsLhJCWQBug6qh67jSmFlbutuh85z09H
         2t1BZ7KBjI5nEmHhDUWhu9d6J0sWZ5D4OSXjqsHYCoBZ2CE8GjS+m00AXiTOjd8g3+9o
         8hKYrZIbTxGEnymv+W7PktoTwxKzYSQVw+iXmj/HDtMfFYC+cAOZlpVBSJJStt363PVp
         aiSGGXaep4ncBuEDQUjBzIhFiBr4g/7xVkbGBIhV7RNe9DwQ7D+Y66DUF+0uJWVW0phn
         r9YqITP3aTLenuNSvydB71gBwsFymlkpQWv4VJv2oELz6Ts/6kQzzDbf4UFzT98ppddW
         jbWg==
X-Gm-Message-State: AOAM531BRipgzMslZ9IVu3h7IjNE6t71C09RMT13X+NCqJRCH1D+SlYg
	BUTYloCpAWBAswHn0RvCJPg=
X-Google-Smtp-Source: ABdhPJzoPTZuXJVFjNFmsO4v4tvss86IkZdXSNwpEJ6fvNhseltcO+Qf0Auk5MX2UpLFGtu8PMKPag==
X-Received: by 2002:a1c:7411:0:b0:39c:8e4c:9704 with SMTP id p17-20020a1c7411000000b0039c8e4c9704mr35096706wmc.52.1655726534108;
        Mon, 20 Jun 2022 05:02:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls5433474wmq.0.canary-gmail; Mon, 20 Jun
 2022 05:02:13 -0700 (PDT)
X-Received: by 2002:a05:600c:1547:b0:39c:804c:dc23 with SMTP id f7-20020a05600c154700b0039c804cdc23mr24556031wmg.23.1655726533124;
        Mon, 20 Jun 2022 05:02:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655726533; cv=none;
        d=google.com; s=arc-20160816;
        b=uNpaPBER1F1bdOM4QGHohMT12lHk+9CeTaMLcnYZ97qVBZIx2Ygu10DNqNt1lsDY2a
         +xWAVJGbs+2oF3+1D+iuQh7F5Mj+d+wXypl8RNsvyFiUOUg+gp3p+g21Xe6eNbLe4dc0
         E3f7RnjhrnX3hqIXzvlxPYejTPd4nobHjGgI0ef1n+XtVFmCzoaRj5G21LdNIpn3dae0
         r/BH3ZJU9SPGe6Gzdaqs9sEOT64bn3egn8yBE/9vajMevcIUuHbvSINlFyVwjpYDDjV/
         BFMoU+HfAxma7lPRtBk9hEC3pO1HX0JsqlQvESBi7a8hZL1vV0eMERVmRJxOmhNvkt9/
         /IQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BLIpOQctpgnjuRGoLORv+IdWppOjSjpJpZ0mv6ogIJE=;
        b=mD7/43AK8v8yJoJbe5UvehFFPhk10ReaY8z5cca87RAOWSSjG9tnlW8fwXXSqlAX7T
         aCAbOUp+NRBRKBkXSBz/n5REBZqNVkBgz1uSird2Qf3kpVF+ZFwELXrVJD0yZrcmmJ1q
         WjWZ10iyWJo2AgIUVDg1Q01lpWTvKBUtN4xzwfG83gVX/2c1Rh1RzvdUrNRmg7GzmZV2
         Q7JIERY1xUExU8S6nNN15+BInRqujkZLGWaWB4rNsc0wokaY/M9CW5eKn2EI3xTlBaBZ
         ypLvN1wTOJOS4SASsl9GjiFZeotJjCsbGlr+5Zqp/dXtQ0hN5rq7RM0oJ+Y5EE2B10Uh
         ow6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sXqeUBSq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id p17-20020a05600c1d9100b0039eec2f6f8asi417675wms.0.2022.06.20.05.02.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 05:02:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id n15so16554ljg.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 05:02:13 -0700 (PDT)
X-Received: by 2002:a2e:808e:0:b0:255:be23:1372 with SMTP id
 i14-20020a2e808e000000b00255be231372mr11347409ljg.4.1655726532388; Mon, 20
 Jun 2022 05:02:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220527113706.24870-1-vbabka@suse.cz> <20220527113706.24870-2-vbabka@suse.cz>
 <CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com> <93bf8148-ecc1-75fb-423b-2a76c7252c4e@suse.cz>
In-Reply-To: <93bf8148-ecc1-75fb-423b-2a76c7252c4e@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 14:02:00 +0200
Message-ID: <CACT4Y+ZOaVz_EUa-KuMU392Q_TokCpQLv7schd1kXQ_bB_02nA@mail.gmail.com>
Subject: Re: [RFC PATCH 1/1] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER
 with automatic sizing
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sXqeUBSq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 20 Jun 2022 at 14:00, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 5/27/22 14:02, Dmitry Vyukov wrote:
> > On Fri, 27 May 2022 at 13:37, Vlastimil Babka <vbabka@suse.cz> wrote:
> >>
> >> As Linus explained [1], setting the stackdepot hash table size as a
> >> config option is suboptimal, especially as stackdepot becomes a
> >> dependency of less specialized subsystems than initially (e.g. DRM,
> >> networking, SLUB_DEBUG):
> >>
> >> : (a) it introduces a new compile-time question that isn't sane to ask
> >> : a regular user, but is now exposed to regular users.
> >>
> >> : (b) this by default uses 1MB of memory for a feature that didn't in
> >> : the past, so now if you have small machines you need to make sure you
> >> : make a special kernel config for them.
> >>
> >> Ideally we would employ rhashtable for fully automatic resizing, which
> >> should be feasible for many of the new users, but problematic for the
> >> original users with restricted context that call __stack_depot_save()
> >> with can_alloc == false, i.e. KASAN.
> >>
> >> However we can easily remove the config option and scale the hash table
> >> automatically with system memory. The STACK_HASH_MASK constant becomes
> >> stack_hash_mask variable and is used only in one mask operation, so the
> >> overhead should be negligible to none. For early allocation we can
> >> employ the existing alloc_large_system_hash() function and perform
> >> similar scaling for the late allocation.
> >>
> >> The existing limits of the config option (between 4k and 1M buckets)
> >> are preserved, and scaling factor is set to one bucket per 16kB memory
> >> so on 64bit the max 1M buckets (8MB memory) is achieved with 16GB
> >> system, while a 1GB system will use 512kB.
> >
> > Hi Vlastimil,
> >
> > We use KASAN with VMs with 2GB of memory.
> > If I did the math correctly this will result in 128K entries, while
> > currently we have CONFIG_STACK_HASH_ORDER=20 even for arm32.
> > I am actually not sure how full the table gets, but we can fuzz a
> > large kernel for up to an hour, so we can get lots of stacks (we were
> > the only known users who routinely overflowed default LOCKDEP tables
> > :)).
>
> Aha, good to know the order of 20 has some real use case then :)
>
> > I am not opposed to this in general. And I understand that KASAN Is
> > different from the other users.
> > What do you think re allowing CONFIG_STACK_HASH_ORDER=0/is not set
> > which will mean auto-size, but keeping ability to set exact size as
> > well?
> > Or alternatively auto-size if KASAN is not enabled and use a large
> > table otherwise? But I am not sure if anybody used
> > CONFIG_STACK_HASH_ORDER to reduce the default size with KASAN...
>
> Well if you're unsure and nobody else requested it so far, we could try
> setting it to 20 when KASAN is enabled, and autosize otherwise. If somebody
> comes up with a use-case for the boot-time parameter override (instead of
> CONFIG_), we can add it then?
> >> If needed, the automatic scaling could be complemented with a boot-time
> >> kernel parameter, but it feels pointless to add it without a specific
> >> use case.

Works for me.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZOaVz_EUa-KuMU392Q_TokCpQLv7schd1kXQ_bB_02nA%40mail.gmail.com.
