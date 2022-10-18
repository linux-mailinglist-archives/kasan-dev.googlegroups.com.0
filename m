Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNEGXONAMGQEXF7LEKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 461EE602F66
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 17:16:06 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id n12-20020a1f270c000000b003a2e234386dsf2489912vkn.23
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 08:16:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666106165; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnYdtn6C56YVbeG0A+CjHWnjo42mW3pPMtebP8007ZngDlcSdyR27el6IKYqxPGi6b
         GLmqfpwYKTPygaOyMGn+64JkkNQ+QILE7RAd5DhHlM3ZhJkbdqcCLSTw5Xpyl5nk3ZJJ
         oyOFmaCagcfl9opyTMnACA8sqNYVU/Fhr4SIAoMVcijUz7QaQO2upy8JbXJ+hvU+rYje
         Gl7sY+AvMOajhaldVvbcpo0Ufp2U/fzrp/ulXM1ohGPnqx+9f+kXdskP6/hKvAuDZ7S/
         TKTGDMEBqp0m4Hhz2yWo9EI5JjW0+rj0en99XvNBvnq+wzK3it8167wQdK/V99JaNVx/
         HgRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/PH8+sa1sasyW2UX5Dw0H5z8VlfKn7IgULASAxF5+7k=;
        b=QkE4Ly4o9HZX0yuuQQ73xrI4CUgnrgOdz6jM76WaC6v7KPIkvb+3GCGq5XQzmsj2Ps
         q/JQeKaSGi9IELcBJOAZMKwSN2OQn099CjXjdQ/nboo6DLQiFahEnx6zrNefXedeWNzx
         OiV7tk98tGYRkyQPJKxkm9nLVNv/OAO6ggVMaHUkZ5dXvuZewqw6ggwkjy1BeHbN4lQZ
         /5jLKRN2zO6ED5fQ4jSQbHm7Xll3WFC5iyAq+EjipRXrK5Glbgie+V0gWD8JbjLWidmJ
         678PHmzImUbWWh6XlkzqQjSk8E5r2gG+W+lrpLfYDHMA6zgtTCE4X3j6lcYrz+qp7nNi
         d/fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pEWnSzUO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/PH8+sa1sasyW2UX5Dw0H5z8VlfKn7IgULASAxF5+7k=;
        b=k83mVDvt6StAUCLVxaDhHwGhXBsBtjizwno4pTNEdlIh5de+dUWZAPmGuzeCXb+Nsg
         o6LTwEG+2vOUayjo2jdvc3nM4ePljX33eljHb9Zrp4Ct8KHeLTO7z684wI7aoS/N5kkN
         qrfRBQa0Zd+22pyLTry5CYPoQcRym4MpgNKnxnZHb5YgDmyonOx9JVM6RVXjz2SgDE65
         IBW5gajTcI7OYGcGSkx7BHBeDGXeZS5RKWrqrYcy5iwwn5Z7A+rufARCqS6pLsx1FXNT
         iGCt6E3A68QB6NKcNNUR4Zs+tutDJVSw04ClTs1G+XQmCEVCTc6cwUHHUX2cL6zYKDLr
         4I9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/PH8+sa1sasyW2UX5Dw0H5z8VlfKn7IgULASAxF5+7k=;
        b=ElmJze83fkEOPpRglbA3JA+DcGgTEXT5s1kMVLii4kt+aOSHi5b4S+45VDwJkIuAdj
         GvbYFLUU5Q3ePGro/v4h+K7/2wUXZnDiVolljenW7Smn8BIz+wWprAgjTngl5DbE3PuY
         SNCjRkDZyCV601u1fG9SH6V/v5Wwm3VEWLR3i1xJr1zGSpjAx+qlq5KK8E08QeAIDzNf
         s2LzY5MNaHBfoEyyb9Mkj9mioUw3Mmevekqj7+lEw4ifbuh/nm+yKJWoWkGJV8jZpgaQ
         tkgfobso6Z1nPk4kp9akceps6eFJsmvPyt1MQ0IjWYku8rpI2SqRkLZ/I/7mfYhWs9R9
         +T6w==
X-Gm-Message-State: ACrzQf0KO8XX2hmSTMa4ANvBzdqkdSmsiWPZnvQckaIGa6Ka5E5+Uotm
	G9J1Vxyt1B3vysv6AMLtci8=
X-Google-Smtp-Source: AMsMyM5R45gNtjqt4g6IMhNdsZJmfRVATbGHZDyD54tZCXq7w7nJVnM9IPqFbQIyrSxT6OHv7SSuVg==
X-Received: by 2002:a05:6102:b08:b0:3a7:ce2b:31e9 with SMTP id b8-20020a0561020b0800b003a7ce2b31e9mr1763354vst.22.1666106164869;
        Tue, 18 Oct 2022 08:16:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7352:0:b0:3de:e55f:dc41 with SMTP id k18-20020ab07352000000b003dee55fdc41ls1136303uap.6.-pod-prod-gmail;
 Tue, 18 Oct 2022 08:16:03 -0700 (PDT)
X-Received: by 2002:ab0:541:0:b0:3c6:49e8:3580 with SMTP id 59-20020ab00541000000b003c649e83580mr2003100uax.103.1666106163802;
        Tue, 18 Oct 2022 08:16:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666106163; cv=none;
        d=google.com; s=arc-20160816;
        b=V+i61o0NhqqI1bZiZK8kkmS7yojrl/F08wGH+iWjpvb8sOKlbJsR+iLy/3sZxh9w3F
         yjokLYXqOnVionSM36OFNMC00ZnMmxQzSlV65KPkBvrFKDfdpIp/EheHHZSVg7fjhxtX
         9Vyz50jJgR06yHHLeHmLcAM15XE8U4j9Vpiq854EX/a3adOOV4MsMtFwvhF0a9jqIXE8
         JPWSqofq74L8VP7ehNd7BRm1cEpTD2OnEnq++D3+ia8oBYsazWvPDsBKObhaLiPNcf1G
         5uOpFQtdno0rnNhXZoZpsICZ34sMobB/S57bsXISAWpZHGE9dhfYZqYl3xTvefbKY+uu
         RZFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hC5+H9wThte8MY69gIx2xqsknF0ksS14sajV6ZapONA=;
        b=m6ZRPsAlHZ+/MxZfG53+iMO5H53UJHAs0nS6NPfkpnRN9AZ5JeVKwmCcNcsmZTvntp
         +pJJeZYi5MilL9SA8HWVg9eTCZzbnTbknk+bQJ8zGpDdQial0tAsVmrSOVYD03caiXgj
         8QkzJPxcqP+FFU3z+dYYVtl32kQlBxTEwlx2oIfAYJsO4ACF6dXVxJScCu3brGZjbu1M
         /RhShqosv3ZbbrX2ozDq/EQKupls+M4hpw6rS3Yh1A/VvV2777vvsram7wy8IL0x2F8W
         Kpvwo5x5mxWc7dF09tO58Xo+9MRb/CNbatDo0VyGdmpxDuv4v+MrC4wmWxjP3B+1it1V
         5/wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pEWnSzUO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id w68-20020a1f3047000000b003aeca8bc36dsi745098vkw.3.2022.10.18.08.16.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Oct 2022 08:16:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-35ceeae764dso140340647b3.4
        for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 08:16:03 -0700 (PDT)
X-Received: by 2002:a81:984a:0:b0:360:daaa:1edf with SMTP id
 p71-20020a81984a000000b00360daaa1edfmr2897339ywg.238.1666106163327; Tue, 18
 Oct 2022 08:16:03 -0700 (PDT)
MIME-Version: 1.0
References: <20221018102254.2424506-1-ryasuoka@redhat.com>
In-Reply-To: <20221018102254.2424506-1-ryasuoka@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Oct 2022 08:15:26 -0700
Message-ID: <CANpmjNMoZ6X-bPHg3pfWrnBfP-khpwXNvHxxrwXf2R27_PuSZA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Fix trivial typo in Kconfig help comments
To: Ryosuke Yasuoka <ryasuoka@redhat.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	trix@redhat.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pEWnSzUO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Tue, 18 Oct 2022 at 03:23, Ryosuke Yasuoka <ryasuoka@redhat.com> wrote:
>
> Fix trivial typo in Kconfig help comments in KCSAN_SKIP_WATCH and
> KCSAN_SKIP_WATCH_RANDOMIZE
>
> Signed-off-by: Ryosuke Yasuoka <ryasuoka@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks.

> ---
>  lib/Kconfig.kcsan | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 47a693c45864..375575a5a0e3 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -125,7 +125,7 @@ config KCSAN_SKIP_WATCH
>         default 4000
>         help
>           The number of per-CPU memory operations to skip, before another
> -         watchpoint is set up, i.e. one in KCSAN_WATCH_SKIP per-CPU
> +         watchpoint is set up, i.e. one in KCSAN_SKIP_WATCH per-CPU
>           memory operations are used to set up a watchpoint. A smaller value
>           results in more aggressive race detection, whereas a larger value
>           improves system performance at the cost of missing some races.
> @@ -135,8 +135,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>         default y
>         help
>           If instruction skip count should be randomized, where the maximum is
> -         KCSAN_WATCH_SKIP. If false, the chosen value is always
> -         KCSAN_WATCH_SKIP.
> +         KCSAN_SKIP_WATCH. If false, the chosen value is always
> +         KCSAN_SKIP_WATCH.
>
>  config KCSAN_INTERRUPT_WATCHER
>         bool "Interruptible watchers" if !KCSAN_STRICT
> --
> 2.37.3
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMoZ6X-bPHg3pfWrnBfP-khpwXNvHxxrwXf2R27_PuSZA%40mail.gmail.com.
