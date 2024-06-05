Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX5UQCZQMGQETVJ3WAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id F26BB8FC53F
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jun 2024 09:57:20 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-43fb0949d28sf12136941cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jun 2024 00:57:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717574239; cv=pass;
        d=google.com; s=arc-20160816;
        b=fuhX9oN70xt8XUBIwRC+7IhXBYa83yDMOXNY1TFpaMCOFmq5jjpIKKQ110427O1BZ2
         7CL0tzWTrNU40O9fyRZyv/kVREdjdw9fckg085VEBqhqqgcOsLv9+l3uyN1pGr0/xBRD
         soC5YjMFfJp92KDFFKS4MP1/R9dGbtbbhnP6xF1UcA2QQnHatmwi8XwJ2iM4D36/YqhY
         4OGaSa9FZTVTuj53yq37Ks7fVzt3TGEwmJRIJBgsFPjNxP52Lqi0hPBWUqWgvHU0LnQ0
         9IKuGqrLXGroM8MwalL3/hh2Ky6YBLJLIiLaOV7C8+KRNUI4hq46km5Z+dq0Mjm+ZjFr
         ymiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oQ5ODUy/vA8rcJwZmK3okgrzgvp/tobqJciCkUAvz08=;
        fh=/ZPXTpEJoKMyKdd9stKAno88MjyNqtuP6dgnrlGa3BE=;
        b=mxVGM67PJkr9TEEq5OppIUOqmkMdsw5epi8sG38V/EugiY0QoDeskKYNP+NggS+peI
         nnWgXHY9xfuiZs4isWb4RKeLLCRPur6p5Z8V93EYE24hMAX/xy4t3mSFnDw3th1GC/Rd
         Pb6pxa9neN+c5RqGmDmYwAAKwvzB9xhngvU+78kddFgUbrsX6fjS1+w4BSDMWBFNbz4S
         TV9ZD9Ej9+wmfWuvLhkC4luTnOaJJdyL8PeWe07SOItUDKoBlxGQSEEjReMT/VH97LAA
         CWF+rXDFqEmFDVWFIrbclcqjWGSVnknsVQTJFRHMFVO7jeZUwhFEKvcNdhMRKWKZ+GCv
         Xbcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q7tbX2CT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717574239; x=1718179039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oQ5ODUy/vA8rcJwZmK3okgrzgvp/tobqJciCkUAvz08=;
        b=tgeI4xSYYgIHyz45+Z9qZBHl64MORPxnh4FZujBfnnd94NfKWcCojr3tZdnSn2E3WM
         MAC+WHzoolixFjjPmaaIcc7kswYoFztsR+S/OBNmH83Aki1ieGtGHYGzZLrYeTBYG6TU
         VMZ1b5Z2b6vC/dW8WA6A9oQFRWoFSRPl2cYgB+RjBcb65Sh7n2XEkq2RatbtnFi4L896
         A36xi66Tx5QIHZqIqYutzfgCvGRcwygcQDsfeBhYmUwOdDpu7nr1ylbInYVTrYZKQzrq
         aI0v93fxkS5n9/GRZOV56e6A697UNb+TFktgu+DKfh4ABvckAbFugFdioGO4vLbOR1Jz
         KhTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717574239; x=1718179039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oQ5ODUy/vA8rcJwZmK3okgrzgvp/tobqJciCkUAvz08=;
        b=erdO8YTAPEfAV6uG8/5WSQE+GKovdATog6uhuUAM6N/pJE3J6Gl+9Ea3UWXNBA+gh4
         FXx9sk5DOTAmUF5EnLG3+TAcrKa7OvaLIELDCVarDIVHtKvZHbLWArM7ERZFeddWfm0D
         JP+XqvRqlO0oiNGvf+SZk3pSerWgGS+sb3UT3jphcTF3iKSymyJYmZGAqeKbQ25comYG
         tbWFk2ZHdhscavpoyUC9760Uih44TjqK2RAbQNC+m5wWay5Mwl6NS1Ap03Wig/R7cRcS
         fQnlzquMKJYaqWgW3gkkfmdUbPckGAu6gtxAjbUnLIgFVe21HOkwmzsigH+fXfsP1QD1
         HwMw==
X-Forwarded-Encrypted: i=2; AJvYcCVTtZ73sVot7U9OXOR3q1HArIeQnL9vgWWyBsxUpAL2kMISSpuw+ZCIu3QbKMlZ/dZXU9iBcaDhxeSGYYv0Jg6GDrGWSeEvig==
X-Gm-Message-State: AOJu0Yw5wQ4GGYWphSmR0KLRWBjb27iztEol4zcxHmYa7K1BXf+jA34r
	ii1f8Mey0wUtNchIB/btrDW437i+OxaeiCU1gcalXWNzNOrgE/F3
X-Google-Smtp-Source: AGHT+IG5Un3Qs+66cKpWQ7lCN3DzlynymG4/4N63dTVH4rY/M+absYFp6Dv7035C12qFls9vyyAkCA==
X-Received: by 2002:a05:6214:2aa7:b0:6af:45d7:fc8 with SMTP id 6a1803df08f44-6aff72c1584mr81137566d6.17.1717574239507;
        Wed, 05 Jun 2024 00:57:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2269:b0:69b:a44:bb68 with SMTP id
 6a1803df08f44-6ae0ba3eec3ls7627496d6.0.-pod-prod-00-us; Wed, 05 Jun 2024
 00:57:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoUgu3YQd00X5mWZJbNot2SwMdvukeHzPEIkls30t+uSTwEuCd1239OxQ7ogkSxtD3H69rksErLxy8cMVzofldHCMB9oz1J1Ecfw==
X-Received: by 2002:a05:6102:f0d:b0:48b:c32e:2185 with SMTP id ada2fe7eead31-48bf22bc577mr5600107137.9.1717574237860;
        Wed, 05 Jun 2024 00:57:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717574237; cv=none;
        d=google.com; s=arc-20160816;
        b=dY+ZdjvIFpWulqaoMw+8+Lt+YFqYkXG6TA/9PkJhrEMqy3HEd1ctOkro/bbTCjkOg4
         0S5DHF+F+u7h0q9dSKwm79MHrV0NXGuTSd/zDMZIySwiwwxpYfAy9Z/ymx6bhMYKI1Rx
         Nrx1Ojcn95Dj8XHQtHT+SNIwOO3fnVxSju4Bx+toeHHvt3GDJEgxFY5WQ25CmwiZ5L/l
         97bF/F82NyVzrSkNebAg894XSezHr5xC8guEHUuRmVBHD9Lc9M7N49AguFulUyyS6mtc
         MyqxxD01gWPPTwBZYg6yPWpfJeetSimHmoyRBmlaRMePtemBu47vkjVYh07TBzoAJFbu
         jrTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K7HNwq80CUl9euhXBEKTrmHO/OrgPhpji/JBSWvl19w=;
        fh=mEFopjXRiYeJGGYGYdnvyp6jcA7+DK+udQMl0tjffXw=;
        b=o1kCe8u1AK72ikg/MkSWauzbfD3/fLGMGMvMycHi5XynKw9PzDL587GOX+9RTFV0oZ
         SkF0q9/O30rtBPbk+7FA49GF5yNFHMo+ep/EgvRh3hCJsSE/ZIdHhrhKaWViUhpqjIAQ
         itqOfryDGBXQVgRrAON/EaqIufME2BWikztNu/edwyAf40lobqdsQSrFHh+YrYeNo+na
         q9ma0EP0jy/4WeRY42WC79gj6H4XJA74kF1xy0zWmsvnVpo5xnno5pvVNhnBnPdrC6qn
         B9Xr+G97AQqEatIr/T6e83oGWdcSTJiFWSGlm95FwIICzRjn3xdB+oxsT+JHW58RkRCe
         w0gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q7tbX2CT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80adf1f884asi563760241.2.2024.06.05.00.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Jun 2024 00:57:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id 71dfb90a1353d-4eb0ae42c7bso340794e0c.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Jun 2024 00:57:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVl8bpX48nDvgHlOq12HL30Zs0/hiFXoRNlteHZ+iJoZSxqOiaVusYtFiP7AYjFNdVpbCh0Ca9MqjQh/2Qz162ne9MD9qr3av4bvA==
X-Received: by 2002:a05:6122:a18:b0:4eb:e37:2d19 with SMTP id
 71dfb90a1353d-4eb2bc01ecfmr4739547e0c.1.1717574237255; Wed, 05 Jun 2024
 00:57:17 -0700 (PDT)
MIME-Version: 1.0
References: <e14ba19e-53aa-4ec1-b58d-6444ffec07c6@paulmck-laptop> <20240604223633.2371664-2-paulmck@kernel.org>
In-Reply-To: <20240604223633.2371664-2-paulmck@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Jun 2024 09:56:41 +0200
Message-ID: <CANpmjNOLuAZfjiNZqZ8zUrziOUiXw-7zOxRpOrwqYP_rgrEgJw@mail.gmail.com>
Subject: Re: [PATCH rcu 2/4] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: rcu@vger.kernel.org, linux-kernel@vger.kernel.org, kernel-team@meta.com, 
	rostedt@goodmis.org, Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q7tbX2CT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Wed, 5 Jun 2024 at 00:36, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On powerpc systems, spinlock acquisition does not order prior stores
> against later loads.  This means that this statement:
>
>         rfcp->rfc_next = NULL;
>
> Can be reordered to follow this statement:
>
>         WRITE_ONCE(*rfcpp, rfcp);
>
> Which is then a data race with rcu_torture_fwd_prog_cr(), specifically,
> this statement:
>
>         rfcpn = READ_ONCE(rfcp->rfc_next)
>
> KCSAN located this data race, which represents a real failure on powerpc.
>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: <kasan-dev@googlegroups.com>

Nice find - was this found by KCSAN's weak memory modeling, i.e. the
report showed you that a reordered access resulted in a data race?

Acked-by: Marco Elver <elver@google.com>

> ---
>  kernel/rcu/rcutorture.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
> index 44cc455e1b615..cafe047d046e8 100644
> --- a/kernel/rcu/rcutorture.c
> +++ b/kernel/rcu/rcutorture.c
> @@ -2630,7 +2630,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
>         spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
>         rfcpp = rfp->rcu_fwd_cb_tail;
>         rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
> -       WRITE_ONCE(*rfcpp, rfcp);
> +       smp_store_release(rfcpp, rfcp);
>         WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
>         i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
>         if (i >= ARRAY_SIZE(rfp->n_launders_hist))
> --
> 2.40.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOLuAZfjiNZqZ8zUrziOUiXw-7zOxRpOrwqYP_rgrEgJw%40mail.gmail.com.
