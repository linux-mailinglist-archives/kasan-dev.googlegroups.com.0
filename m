Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPOO5K7AMGQEB4GK5YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 607EBA68AFB
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 12:15:11 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e6372ccd355sf9365185276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 04:15:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742382910; cv=pass;
        d=google.com; s=arc-20240605;
        b=azkdFgPPb5tHoYZfgMIEK1RJSDIklwOipzc9JzuD581tFjkWNNQUm3kyuVWhn4wvtH
         jFgncsJMk9dyqYPxy6aRdZztdikzpHZ0TPt0DX8KXCHMcqQxo3lNyYkLPz9dln7Pg9wy
         vTHMIB2IdWNDFBn3FgOBJ+JfNCM5xRObkRfO0vUBc8J9sbSm8QXk/sJUbGwAh2O78mvq
         mZTl4THvjhsq3vdCueuBAGN1spfXJKnbXSb22pn28i45Tjt2RhNvxCf2YdTVnC2WkdIf
         vi0vaIFgR54fMQHthjipAguYtUvqJgBd9Zluq8D3Kwcxty5G8C+3sA+JSv1bOWxY0Orj
         Kkig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3PTLuqwQMEXen/32vOS4whCibshNyIdq8UJn9up2Bo4=;
        fh=qe3shpHQfYzn0t2AjN2tlFcFPO04havIbBCw558N4nw=;
        b=Zo+S3s4os/FD3HxEvqvoNOQVpinTZIW7OHWMclnFGg5hu5vAzg679qcnFXURHpo1NW
         IvbW8KnCGsQd/0Wpf2WhaWLOQsWTTop0cfEQ1b70Eey7QizlJG9EojXlwDKM/NsPHOim
         YqpaTrG7G1jxjGD3JgWxoyLpW4L63FgTfcCioUbxci98KhIFIIiyO5Yri/LUMA4Rl05n
         4lmyJqHPB7A8jhlrgsNfgX9U9TOJLDCJgbeCwMHgn4tDEjrbL9em1Ap4BZsJ3dRgkOGq
         Wm3zPrW1eQtviXXuIJ/CEZvhJxzqpbAS8PhcGuiyJ8KQBDCGJIZ57rRHABTU45jSncP1
         fg4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HEZHoZ4y;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742382910; x=1742987710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3PTLuqwQMEXen/32vOS4whCibshNyIdq8UJn9up2Bo4=;
        b=dGQF5oXAXsRFou3ErDByYYd1zQKaCHfSDRfuudR6UpQYLMIavEdIQPLWCfp0Je66PJ
         Gtjh28nHzVh9+obfQ8t8Ef/ecXTxVIwtrcJq6iBmMCGAw3WJKdIJVHuph5jCaVNn7RZ3
         3/H4NdChwJsomEBUg7k5UHeVyrJfnmu0v7JWjLz+ELJevUY/CPoiPyJqFCNLW5lMyhhB
         db00kDKaNztazluR4mkGjnJvLA4p1L7vA3AkB7LujufOT0Z1MgsUbPvyCBldatkwBZP7
         r1m+aQgOvJ3xZO4YEx/ROdeq7Z3sk0FLEE6gzdV3zYxNb7WeebkZZfior2nvInyxX2p3
         MUXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742382910; x=1742987710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3PTLuqwQMEXen/32vOS4whCibshNyIdq8UJn9up2Bo4=;
        b=vPMcnLhsbEKYApzu2J+svpF6jit0ELlp6PKDMf5GBsRch+MRvjxmkM6OVC6BxpVwER
         xRgQApQ+6Am6rpu6bJ61/TQqbw/N12vDoV0B+iDxRehLCH7VhJZRb4R9bVQFxeVJawqs
         GdXahOsuXja5aNl+23VqBoQO+KzDah3vuFp9zOHAbCOlWZ6lu5PwebdcOVZsVNaMeMtS
         HTWJAxuALL8PyTx2cjF1vZmIN+XA2bem2BnoTkcSYXGEDA4CuDD65yghSKXGys9xXkmK
         R4ZPo5emwRMEIHDsdn5pruCLzZhshIOK2upVOYOL95X0v5x0ssEEvmYQ6EEMd0QBqQg+
         YJSg==
X-Forwarded-Encrypted: i=2; AJvYcCX3Vw4F7udQwdsU+48GD9h7TWGC0fUrDUFiI9zai09SaaVr3jDwVq+k3RcdzGMe/6TUhg7kpQ==@lfdr.de
X-Gm-Message-State: AOJu0YxP7POKhgaT1uI60VV/O7nLa0FGFN+o47zE7jNy8Cyt+R5fWB1L
	WxJPuNYdQftI5phy6tBzQUOsEZIDbOmsNZ0KbUcnRE1rN1fcu03n
X-Google-Smtp-Source: AGHT+IGxxqTUlXL9pKyFyoqHjVppq7TQ9TA97Kz4wTWUJDdoVxmjertPIdq/0ZEIUL3kd9efx2Fh9A==
X-Received: by 2002:a05:6902:c0a:b0:e60:a6a0:f5b4 with SMTP id 3f1490d57ef6-e667b39f5bfmr2510493276.9.1742382909842;
        Wed, 19 Mar 2025 04:15:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJKN/e+mwFx+jNycXPo6ONUoB7Ueks8+K54VO0J3pNrPQ==
Received: by 2002:a25:d311:0:b0:e65:a34b:b3a9 with SMTP id 3f1490d57ef6-e666e31d320ls1655614276.1.-pod-prod-04-us;
 Wed, 19 Mar 2025 04:15:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW15O4U9LnKzMD2VlcG2bEORgk92m6XvSw+lc2zq7s7wtl6M+M7RcC68NP03/hf3if4ryS6qhurpkc=@googlegroups.com
X-Received: by 2002:a05:6902:100b:b0:e60:aa39:11f2 with SMTP id 3f1490d57ef6-e667b440cd0mr2339932276.32.1742382908757;
        Wed, 19 Mar 2025 04:15:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742382908; cv=none;
        d=google.com; s=arc-20240605;
        b=WCjlC9GUEktzkzwtz51eI4IB6RwhrkKgAhj7UXQQgfd9UcuHxiQj61NUzbNnBSjt8n
         F+2Hwhoa2jHeymHbBpCBSFsQB679G1sAhB/IuSVqjQegEgKcGRLZkiwBLehToIlmULcj
         MQiJxQ4QC99QzkI6PqAOFE7qSOCAW6cT+AOpvV8xPY/b4UOVoNdI6tpgTYB12Q6O8Sgb
         dGO/6ctH9BO86qzPN38WGGIlpB5LYKV57ZCOxg+Je+k8qM1maf4F29v75pcPvI7ABfCl
         qxNxCZFz1N7a28MbkhC+Qmvr0jX2v8k3IR04YC/fNAs35rQZyQGmY3Ox9usEvVJ8UR3J
         uQ7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SsTRQtNicpw9yE35cWE+9viCfNPPTzsLXfwFgYLTGpM=;
        fh=Rtr71Y7Y1qHTN8LC6uqvP4ssdJBRyeJynaUjt+Q47mE=;
        b=IJ6rvnYHtLgEUQtq4Ym4cSGNun8qYDynnvlh2Nag8mQBpEhfWSGo/WLi+iUENmcd/j
         5Ec1viUH1tk72VKN2s2pAdcwOsDz4DWLY93hPc0yI+Nc9ks4WtKbYPYAAkaHAtAbNFur
         lrj7osldwJpmCKaaNGwSsJ6IC6+ogNd+u+VUeZKeLWEF/yFxM7sixEV7Num0zlR6pyTx
         U7PAUZjiZHA3LrfaR7HTp8zsTKL3esfcq6ZKkcwjiIKNRQ5+dVduER1l10b0f6k2wEad
         5SH9y+FSxtu6XmdtJUT1N7Utvykesp18lllB1WKwDAl6mo+fhf85dBwZbQtACUBX6uuQ
         OkNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HEZHoZ4y;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e63e6c142cfsi645458276.2.2025.03.19.04.15.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 04:15:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-6eafac1f047so51808126d6.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 04:15:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXb7HU67WOaEgdgEKjwBcz1eRQxVqkzg22sISBT8gW2Bq3FH6EqFPH9UTv++Gc3E8RHWx4bnzHsmxw=@googlegroups.com
X-Gm-Gg: ASbGnctUN7vi+Ft2wqu895R9p3KIYFWhJu3giBG7M8vVye5l6UUdomlHkr6/JpejmOO
	FTrz0qpx9qLFTNd2xfFHO2hacLBor34tYFDtG/P8p/G9v9afCwbd6m4j4idmTNmOayRBsr44MZv
	Vi8gAYfs/TbxnmVh3hRWaGMSjIOI0U9t43hcOr7rWrI31H+ZHTrbGqQPj9bnU=
X-Received: by 2002:a05:6214:27ec:b0:6e8:9021:9090 with SMTP id
 6a1803df08f44-6eb293b1dffmr35547506d6.26.1742382908256; Wed, 19 Mar 2025
 04:15:08 -0700 (PDT)
MIME-Version: 1.0
References: <CAD14+f36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ@mail.gmail.com>
In-Reply-To: <CAD14+f36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Mar 2025 12:14:30 +0100
X-Gm-Features: AQ5f1JoPTh07skx436QUCl8B33vohTUp-gqAI_mxw2n-tEsWtbxSjo7-RvXFxrQ
Message-ID: <CAG_fn=UTcvhT5=GOd0ouFCAqaEGo395En1--0bf7Ds=GTBxC-g@mail.gmail.com>
Subject: Re: What needs to be done for enabling KMSAN on arm64?
To: Juhyung Park <qkrwngud825@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HEZHoZ4y;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Mar 6, 2025 at 10:31=E2=80=AFPM Juhyung Park <qkrwngud825@gmail.com=
> wrote:
>
> Hi everyone,
>
> Since Android kernels enable memory zeroing by default [1], any downstrea=
m forks that want to disable memory zeroing for performance reasons need to=
 manually fix quite a lot of uninitialized memory usage.
>
> Some are especially hard to track down that involve userspace daemon erro=
ring out or IOMMU faults.
>
> KASAN and -W(maybe-)uninitialized are both limited in catching uninitiali=
zed memory usage. KMSAN seems like the perfect solution for this, and yet i=
t's not ported to arm64 yet.
>
> This was first asked in 2019 [2], and I thought it'd be worth asking agai=
n in 2025.
>
> Are there any (wip) progress in arm64? Can we ask upstream for KMSAN arm6=
4 enablement?

Hi Juhyung,

Sorry for the late reply.

So far there's been no work on KMSAN support for arm64. There were
some requests, but given that Android is initializing the memory by
default, those were considered low-priority for us.

If you want to contribute to this, you can take a look at the s390
port done by Ilya Leoshkevich:
https://lore.kernel.org/linux-mm/20240621113706.315500-9-iii@linux.ibm.com/=
T/

Feel free to ask further questions, we'll be happy to answer them.

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUTcvhT5%3DGOd0ouFCAqaEGo395En1--0bf7Ds%3DGTBxC-g%40mail.gmail.com.
