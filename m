Return-Path: <kasan-dev+bncBDW2JDUY5AORBSFHWS4AMGQEV55H63Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 88C3C99CAB2
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 14:51:22 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4311a383111sf19863025e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:51:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728910282; cv=pass;
        d=google.com; s=arc-20240605;
        b=V83jV+Tt7kGLWD837AZaEqpkFrTWV188eyJsDNXsllEsnNGCB95n9PB/nH05nddcpE
         YnpKJvdarBxJ3aIjqoMadn2mB4Eja1Pr4DWzOyKs9cKqiOXvNe3faXL3MyToETCfXtPO
         DJt+xNS7HbJ7J0j+uFDHdyXxm9L5cXDCW9m+jnfCwfbNMK1tkpD3HHpXpnIlx41F+c/8
         JizbZe4yFFsUam1v1nKorP3bcqwFwZ2Jn/cln3tbNLtNLe55yMez/MZP2MSaPlfg8kkL
         NiGHgE0w9aa/U1289XmmjGRboHEiYX7QXKNyv/VmF5ag77idWxYOkegcDehJS5oPYnNR
         UW1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/i/O4WzxuRMmtpJmw/5+6P4dq/9HYLLgL7M0odgN1sA=;
        fh=Q38yJ/EEH0gByhKsyoWYeMASUGKBLMW6tqx6Y5PXLjw=;
        b=QKQQEPJPphB20KvNM97f16WlUEkEjapRNwWBgBuThXTv4d9JgDVRX3dqA7dbQ5wVNX
         pNSGs1Z0+9+pe5hZbo2C5P+zk8JcGZGka9gkGdhb8VVa6kQu0M9X1fgrvGYBgENipH64
         2g4UdaTs6m10KnhH5MPE9bKxUc5p4Xx4zbKf/ffAZpuUZE6nQt4/gPLPyvsuCNUjGdSN
         +3woG7wk3QnnJRqFq0p3THlL9496Wsd+yz2b7g/vU7C6mxjaU4AagT0IVZ9hFx8XI0l4
         R+iicK/EoGXkKWuJ6S+u2bbh+PCmg4Afm7zuUuueXfdH5kzesyOH7R0qszSTQNJmuVp5
         u+pA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUJpsBaQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728910282; x=1729515082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/i/O4WzxuRMmtpJmw/5+6P4dq/9HYLLgL7M0odgN1sA=;
        b=wTTA3j1f13RTydDrQ0nOShJLUcL2PSeQi+XBCK15Iamqlir29g8Sv5PMQReG3xa0vg
         DFTIFI1uYX7DidcqeR0VJlz1uAUZzyUhHPQci9bgK5XUH6NC8DTDCzmM6fQWolYT9Lyu
         G1of2w7scJzr4N12Ac614ZXt8iHmWgWdvAGMmFLi0S5m3vUgoNI8gFjoS303K+Wo1vWq
         LNRYRKpxIBjFSWQkVKUvhhCpgs7YQF1Muv+/9dYdD7sUOXMFdtN6IhdOnQzJmSJ/3YWW
         C4NnR91QXA5QPEBX42EtER5gi2NLPO+r8nWKy6JAoOEcnmGabuy860TvzZVq3hZX0m1D
         N8Zg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728910282; x=1729515082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/i/O4WzxuRMmtpJmw/5+6P4dq/9HYLLgL7M0odgN1sA=;
        b=Z/xxb212Ca2LXjEYejc9zizL/8O6n1T2+qxPezTn+gBVrKIrGH2JppMceyteuz5I1S
         OMhrYy5EVrV0yJv0/c97IPYZCQWXeBliQ86yRiWd7PVcJorn6DRPeygXpS17g+1TGpz1
         g12RmI1mboSdBamr356Fxre+i7Tj/f8H7CLpLUvjMoiQUoTmNunTJGewieZW8nmMeK3K
         CeYl0HJufmZ1BdzVZvbFZAfWn+9vHItD5W/8MIcnh44pyi3pRG3Uvqd/hEmuSjO4KJ6u
         CtAUYXdz2Drr5vRsP4rOWKk42+T14ctyyXHAVqXlk1WLXZ+JN32pWDWLH1mtXcNoYjiP
         fw1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728910282; x=1729515082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/i/O4WzxuRMmtpJmw/5+6P4dq/9HYLLgL7M0odgN1sA=;
        b=kEWgwoQttxtB2ypeY7MsyuF7VaNjN0VPdS9GDGJjbQAAwD6/B/DuQ03+BlCc77RoSK
         T7oFPGgqrFZsFYZO7VB61agKugXKkzxgbYPakg/CAeee1YSGwCR/OTXGGpJU9TUR97mB
         YO+neyHN0OxLD7naWZqW3C9iXqfoIFoIi9EFzi8w/DJRXh3L+rWzqv7JQBQkn+szO+Lq
         59P+OaatmyN1MLmlx0OHnt6qbcF8JsOmOWQnWbh97RkLQ9uT1ZN57dtYSp3yjA92nr9A
         9CAYnPI9lbkiDnmkwuXWr5Oiek74yKEEMZwmINnzNStbcRu0rAN1tmFJq4vMrdERlPUS
         cyGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVD7KbUtsMAd5eMHfghGq++nuljttj6mf6S/0SCz7U+g0ekNa49SUuo+nBm9bJ7raRnpMvtxg==@lfdr.de
X-Gm-Message-State: AOJu0YytUHJzaEFz92txWd8CkHbmHxA+XtkVw4A2V5Qje+aXmdVU690N
	zoJlzp0SXeMd35HZNbIJZLtZTUoSSOPTbWp2EFr+iPB3gZEEvNk+
X-Google-Smtp-Source: AGHT+IFcTO9/eSdKeYVUzaAmU7bIHzEKY/ty2OGXPUROP5HyWTZqW7nnbmfHMW1DsLTnU2uKvqlJMw==
X-Received: by 2002:a05:600c:1d0b:b0:42f:8fcd:486c with SMTP id 5b1f17b1804b1-4312561a417mr70303105e9.33.1728910281194;
        Mon, 14 Oct 2024 05:51:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8a:b0:431:1413:6f32 with SMTP id
 5b1f17b1804b1-43115ff796dls15186895e9.1.-pod-prod-04-eu; Mon, 14 Oct 2024
 05:51:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUm9ShOhVwiB1VNYTl16CgfF6qFrHL14NkRexpLszpBjr7Gh0DphvZJdCgL0kicDPpVJuicYyPDqaY=@googlegroups.com
X-Received: by 2002:a05:600c:1ca3:b0:42f:7ed4:4c25 with SMTP id 5b1f17b1804b1-431255ddb61mr76805265e9.14.1728910279130;
        Mon, 14 Oct 2024 05:51:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728910279; cv=none;
        d=google.com; s=arc-20240605;
        b=dVo8v33F4a50B6OOIu7DR1DMr3XjA28ptLqjwYU84qaymwYU6bm9kwGpuKFZb99mAt
         6NiFcKcBwyZcslcexVbhZZPkgnr6uhIybzcfZumkYXXu3PYdHdP6xQZSBHqwYWCogckE
         /tm+9MXqpaLaDbChqJCUGbBFQUeL5ZBvEp/34AS16pv2SmGha/PyRojRK9ILHBl9W2Rb
         qGZhtepIgJVjbj/oZi3C+WxmQL37YjY4BuiwyTfmfWvd/qdagF5CyQ+9Tl75ZnNxpaDi
         33HfMvGUxKXtMuKzlLEEgpCta0MFfl87wAIxMe24AGH9kx+WQRN3oJQKNGCyaKTbH4E9
         a8Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LTj+KrwAbzaTCdU6CLaQDg0rSRCy4G4QoJfQLN+pOnw=;
        fh=EpSytBY4zxy8Ez4PCHiYsaZwjn9a2Fagb78tmppvI5I=;
        b=CVCgqUS/CcNCsdfAxWNjeFr4AHi8ssetp6tNNCPn1rMdyxP0L7eIqK3f96XtMK5MX1
         fr7d0AI5Kpnih/w3ycqJuFDq3qVq+xK7T6NLNy0Hs3QqqYk3fLZ5hhxdFOQFN/6AVY3m
         WNkbDQZ+/cei4HOT1StgSFF4GgeeElUSc7JGwXQf+lIR7/4ophNs0DpD2DQEAd9Ff1oE
         n5Ka88izBFcLJYL0XYQKTnthJcwlvNL74Wmn58KbfJn1uQsAwPruI6ImSvHIQIFA0cHG
         y0r2hv+tsSPy3UiMDL5zZ5CHw22zRBHAiTVLLlC4Jqyxijh6qUcWf4bZqxmvHVrKMXh3
         KDDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUJpsBaQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43055b3f3bdsi7021625e9.0.2024.10.14.05.51.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 05:51:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-4311695c6c2so32164105e9.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 05:51:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX8Xsbc0jGUi/IfdEvM1iSNRxfGnZENTZ+apQqcV3V3EdIKwnUAhB2MSh/dEe8pq1xOS7GwBUk1ou0=@googlegroups.com
X-Received: by 2002:a05:600c:8714:b0:430:57f2:baef with SMTP id
 5b1f17b1804b1-4312561a03amr80486185e9.32.1728910278570; Mon, 14 Oct 2024
 05:51:18 -0700 (PDT)
MIME-Version: 1.0
References: <20241012225524.117871-1-andrey.konovalov@linux.dev> <CACT4Y+YS4UTMwk_j+Fjah3bCQd0zFcr2XqsUJ5K8HC991Soyhg@mail.gmail.com>
In-Reply-To: <CACT4Y+YS4UTMwk_j+Fjah3bCQd0zFcr2XqsUJ5K8HC991Soyhg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 14 Oct 2024 14:51:07 +0200
Message-ID: <CA+fCnZfkurMxTyf0ivF8uffeO+S0piqFuZ975SSxmjr_V2OrHg@mail.gmail.com>
Subject: Re: [PATCH] MAINTAINERS: kasan, kcov: add bugzilla links
To: Dmitry Vyukov <dvyukov@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nUJpsBaQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 14, 2024 at 10:08=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
>
> On Sun, 13 Oct 2024 at 00:55, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > Add links to the Bugzilla component that's used to track KASAN and KCOV
> > issues.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> > ---
> >  MAINTAINERS | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/MAINTAINERS b/MAINTAINERS
> > index 7ad507f49324a..c9b6fc55f84a6 100644
> > --- a/MAINTAINERS
> > +++ b/MAINTAINERS
> > @@ -12242,6 +12242,7 @@ R:      Dmitry Vyukov <dvyukov@google.com>
> >  R:     Vincenzo Frascino <vincenzo.frascino@arm.com>
> >  L:     kasan-dev@googlegroups.com
> >  S:     Maintained
> > +B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&=
product=3DMemory%20Management
>
> Do we want a link to buglist.cgi, or to enter_bug.cgi, or both? =F0=9F=A4=
=94

I think buglist.cgi makes more sense - people can check the list of
existing bugs before filing a new one. Finding a link to the right
enter_bug.cgi page once you know the component name should not be hard
(but IMO Bugzilla should just provide that link when viewing bugs for
a component).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfkurMxTyf0ivF8uffeO%2BS0piqFuZ975SSxmjr_V2OrHg%40mail.gm=
ail.com.
