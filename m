Return-Path: <kasan-dev+bncBCLI747UVAFRBXWRY6MQMGQEGE4VUFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BC655EAEEF
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:01:04 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id bm21-20020a05620a199500b006cf6a722b16sf5543479qkb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:01:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664215263; cv=pass;
        d=google.com; s=arc-20160816;
        b=tyH9iisPWgl7jtLfnPfh5u2zMHVWMmndVUObsGvCs7N2S/ZaH9B6j7AfX6TchENKS7
         SHCYJ4nN+kr27Eh+de7hgUeobhDywtbjjxbR5SlsSne6yFcAo+9AwPDXrN1azZ8A9TXW
         rHFmfWLbqNEFwG9M5eyGtE/Xf15LBw1AlhxzVOSBu3XyLl/Fk5FjZOQEaTvnwLtebIu3
         euHUzQH7V/bUOfDklJxfKipwKMNfno0MWFW5wlDdAiIhxLQSfxPHLya6G17JcdQSxx16
         mH3rbXBqzuAVtir7mxJAvjPaPF2v66MezoXq9VIjVqMwikZ+2w6cRROAj6kYwW2iOVNn
         LxAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JMlq+e04Ryv5XoddeCVKW84NwdXddYomF0wB+Km+02E=;
        b=al90p13ZjdtY4zYiK3RjYLXYnclwvy1WMNNL/cZyJ9ChVyZipu3UXrrJSPB/Idi028
         l5Jruoif+DVtZCr+R8yFabNcgWdStYKTbIBnkrZRj5hOn9qhH5Ay8N/FCoXemQEethEs
         iqKPZQfajzJSFE3oxdVfgHBbQDnChDQrfXlyx6yTW1JxL9wR3fVheQ6+fSmAXGVhXVsD
         NcHS9mYyj9EUzMRhvEYVGB68M8gWBUN8CF9Eu1hLdYT+brCFrOn6+6ukS45G6gdYika9
         3jHAayxFDxEyto9csZAxxGildr3KnkjLMGfUB7GdLMj+ETlM3c3zkLfQGn4VLJslxsoc
         ykBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GAdNh5p5;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=JMlq+e04Ryv5XoddeCVKW84NwdXddYomF0wB+Km+02E=;
        b=BzdP0XqJNfPtXKPWxAzUsMUS0icxT0G1tzZ9OmiFfmDZ04wn+i+JCR8maNW9DDPqCA
         8JILgAJT+lSC/geEcqVcWcCGF5HywMlXz0kyG1GWUss7j6FcIz+l0R8PrP0xgkXfGncO
         OVbTbBGxjWCNgaygRx7/jEFNgG95tGfUL/CuF0AvsHrLmoG9JJn6x9tEvOoIZqvHzhy4
         yKUTZpMv63eBTmNM8rwvG9w8YFlhkPyu4WTEy72VXSiRE1NT22ZjJV1wTUxgdvgvLIMA
         N2QQ1oo6ebFgsPEPqs1OjZ4yB2dSBVAIWAdBs7Vjl600YceFdE/uVMPzRYH0vXZN3W/C
         ndkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=JMlq+e04Ryv5XoddeCVKW84NwdXddYomF0wB+Km+02E=;
        b=W357NxLYwDwEvyo2Vfq/K2DLHcn/BCTcj1y3eM0PJqA9nqkYsrnN7RSBXryOdqXiJr
         mRDjcwWHU9Jtz0OKnphh8IriK0p0Lz1UboUpUFu5cwXAs2V8CTtbd9LCWAGeojda6/O4
         pmiWVDxH8DoPuEVWuHMHDDAJzvQweewwL0EIg70Ky6SMA9lcYjK2Gfneqou9YhQsVKSc
         +h2zvMVUoyoBwW5OXcaJNvBIhFt5pDfiFaEDATC6HWl0oGNnWW0BDLW3tsbFqL/qhWWH
         r13Rby/oO8RDEhzF3cl/0iJpmDVJwLayLL38bQt01lNHy2+OrGkdSHFUXs2V8pvHU28b
         ZFEg==
X-Gm-Message-State: ACrzQf1xnqRMqDbu4Byoi/H9Yx4Z6Qr9oLVWwA6icfvEMGVjRw9kAABf
	WEun6y/9JQQXPV+TE/ac49g=
X-Google-Smtp-Source: AMsMyM7A8AGJcA9Kj1954ujE11Y7svMUuOKOv1Zgjo3PvlSAeX32qETT+ah+3cVSdy4rlGJRYidCzg==
X-Received: by 2002:a05:620a:f11:b0:6bc:52e7:9058 with SMTP id v17-20020a05620a0f1100b006bc52e79058mr15425682qkl.738.1664215263061;
        Mon, 26 Sep 2022 11:01:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:301:b0:6ba:dab3:232f with SMTP id
 s1-20020a05620a030100b006badab3232fls166456qkm.5.-pod-prod-gmail; Mon, 26 Sep
 2022 11:01:02 -0700 (PDT)
X-Received: by 2002:ae9:e410:0:b0:6cb:e230:8df8 with SMTP id q16-20020ae9e410000000b006cbe2308df8mr14712947qkc.132.1664215262603;
        Mon, 26 Sep 2022 11:01:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664215262; cv=none;
        d=google.com; s=arc-20160816;
        b=PUBb8bgBLiSwUF58I7lKitFJdJTXnFS0LqFRxnpwucKgWqFxjn7U/Dh+UObCqJv0U7
         7osWHNcTSl8Rzji78OhAJ7DvvbIaA/P8QCczrNOlWPrYL2F5sRMkRyw+LatRGAOalalO
         vbKi3lq4LsJ8rAOT4zYe547VeeijaMi+Ohcwc8Q1TonNu6hHarOiXSyOkqezBi5zBxa6
         lGuZFCl9fIywXx83QOcSoXZs7tF+iFWyYJAu1BbTIjiSF/p8IGfKOpTZvVRvhPMwwOmR
         DHYr2WiwxTvBLYHQwOWAmDQIbeyiyRm+ic47vTirtvTFB+6G/zPWLgKbh2NeAqD/G7y6
         hDCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3fqmX1fGvmrW/V78V29PtY6EDY/9r+yH6mZlEbPEwnU=;
        b=L+wAm9owwPp83SEq8D3sW+7djRG7btY22bT/uih29b6qtQEeeAD9BgkbT0TtUHEiZ8
         JEzFzOgZ/8Ujqh2JqTod0mXzCEjf+PINXoJifCot5m2s25WS78N2pRVABvCtWEfSFthY
         YyIR73slAnLgqmcXSSRS4BbzudJ04Ft/RfL0w1DqtIFwnwJAzRvpiuLGGyoTcjW+mPpQ
         Apy13m1JfsqA/p6Pg/4uEaV+S4SYDj4yEXO0Hs4JMNQknk4XoTJ4F9phf/vsWMaCq3u+
         B0SvlkKFAwsfrfGqfl/SBzvAqYiMPZmq/l9CYCyp/NcqjIpCEsj5ftD36Ab+YkUkdyNT
         /ZXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GAdNh5p5;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id a23-20020ac84d97000000b0035baed984fesi689460qtw.5.2022.09.26.11.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:01:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1C20061132
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:01:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 505FDC433D6
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:01:01 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 7c5833de (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 26 Sep 2022 18:00:58 +0000 (UTC)
Received: by mail-vs1-f43.google.com with SMTP id d187so7364803vsd.6
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 11:00:58 -0700 (PDT)
X-Received: by 2002:a05:6102:1481:b0:39a:67f5:3096 with SMTP id
 d1-20020a056102148100b0039a67f53096mr8863071vsv.70.1664215258068; Mon, 26 Sep
 2022 11:00:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220926171223.1483213-1-Jason@zx2c4.com> <CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
In-Reply-To: <CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 20:00:47 +0200
X-Gmail-Original-Message-ID: <CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com>
Message-ID: <CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com>
Subject: Re: [PATCH] kfence: use better stack hash seed
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=GAdNh5p5;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Mon, Sep 26, 2022 at 7:35 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 26 Sept 2022 at 19:12, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> >
> > As of [1], the RNG will have incorporated both a cycle counter value and
> > RDRAND, in addition to various other environmental noise. Therefore,
> > using get_random_u32() will supply a stronger seed than simply using
> > random_get_entropy(). N.B.: random_get_entropy() should be considered an
> > internal API of random.c and not generally consumed.
> >
> > [1] https://git.kernel.org/crng/random/c/c6c739b0
> >
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Assuming this patch goes after [1].

Do you want me to queue it up in my tree to ensure that? Or would you
like to take it and just rely on me sending my PULL at the start of
the window?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV%3D01b1Lt3U7ow%40mail.gmail.com.
