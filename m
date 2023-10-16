Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW6KWOUQMGQE5HN7UVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id D5A887CA073
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 09:25:17 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-27d0e74da98sf3076043a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 00:25:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697441116; cv=pass;
        d=google.com; s=arc-20160816;
        b=FD8FUxITucyLa2bS7MFpVBv0v40S7AFF8EnSwkCjZ7atC2thkk0ujacy3Ibxd+DOfG
         giESO0PQaXRZk+fpSjE2AAtYqlfdxItzfHFHNxN9XXPCTVPWfnD8TzBI+zy2m/5rALkG
         jAm/IfBlakDmUqNzZiUgHfOVWqsdPDA/XRPkl77TDgUORe8Uih/fZNJdaXzieodIXdFz
         aTvkUV4ovyeBNMOSneJU+ZMAPlVlgrnv2ut7BFAgUbdY1RkLuAvp0jcMNaTTuz/SbtIW
         mrDA+Aa6QcFZe74B+vj7ahIkNpaoc/YG0+puu4qUhyle6fU4yZvDTMkswiUfezh+w3QH
         BSNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IeGA8dHf8/DkZ2u7GWW5KLW69sFmyEoP6LuWsTkBGpo=;
        fh=o7j3g/q31jIib6BlUkVe9tNKCoo8Apz9BzqHyz/4Kpk=;
        b=M3Z0oGdwrs7XZArTrdki4Xim1Blz5wHlG5wSW6nhKQaLFr1muaYj4oh6ebvDfeKS1o
         +00SEI/8UTLzcUUEeCExlVXUfBj/Vp7UQdGdJ4dZZoT8JnX+puUr5FUgDsQslnw+6lup
         jywdvXDl7XXMjJHyZd6HOkk9nWNL7/LHOF9uesElBlicj4guFF8+87zT9c4EHnXXSpTY
         J8Cfz9X4NUKo6aTUK9w7sOvXryglMm/YB186KnDrpDosPjktLVyNOHTiZ50ryLMxVl9I
         C9zzv1RxdN85C9Sbywox6XmOVpn6oTNE1G/rFOXuyrqEjctC3E7qtrsHLlVz1fBErIkH
         MGLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GuSak891;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697441116; x=1698045916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IeGA8dHf8/DkZ2u7GWW5KLW69sFmyEoP6LuWsTkBGpo=;
        b=DawabhTxucYrcwXt4bc7WsAEwHkvfPYbP/sphVIsFdd6n5oIyGc1y26xH3MFDW3pCf
         hDRQYOSfSSUhvmVJAxKX/HNAuGobzimsBSY9nN4qMfDAWLDB44c64xp5MPm76TH/fMnd
         pvxUm5osb9XZRdj/NRPPy3rAL2liTwponC6N2W9BXAM/1fbOZXJo25M1NTTe4I36Pyv9
         P46mXK/p7ykQ+hnNsDiWEqPTTVUhvRyeIvLSJjg73Z79mPKuhBfqVJPfMV4mjnWhTbVN
         0CsQrPKATUTKmCu4wrYKC8ts4o/jL/wJZwIRRf7RlcAs+K8Qui9kzo3xjHBWqGcSmzd3
         t9Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697441116; x=1698045916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IeGA8dHf8/DkZ2u7GWW5KLW69sFmyEoP6LuWsTkBGpo=;
        b=qhoP93XyLArVBNh6fD1qbB67cMrt+bkkLvWqxPS/GuJ8MnoyZXY7SOqqHV0XMnQYvB
         VrktFWmIPuMeGE6txaKvDsrJvurhaweQFv+vNP4iVOGcXssIXRP7AgwEUuiDNdTccIMN
         Z2CEVguHENGH+FVUcETRkBwLp6y/0ouRGRK0scUWIvrclhN9R0YgyBtR3ftcAy4//Az/
         spgSUOKMx3ZqK31AM+o6nXD4IYLWuOP6lNZOCEFrtWDi0IkRe+j4dIXx7uUaZ9DXu2yh
         udvVvx2AtjKtW+rlv/CKgPSYTl5vWJbpoRORnisuE7YJrTuu/WxIqoZBb3PqM4IsfzLx
         q/3A==
X-Gm-Message-State: AOJu0YzWqzfOGEdZ74TI2iw25mVckuxaLmmaiDu2ZI0kUv33VRXTlGO9
	Cjoo/26jVKCjQNzpG+JgVJ4=
X-Google-Smtp-Source: AGHT+IGc7ur+q3MyYB6StOi6CXK94Pkv8eUSMhlQLKpeZZGu3e504PcTD1ghNu4Y2Hf9Z25UFgT05g==
X-Received: by 2002:a17:90b:3d8d:b0:27d:98f3:21a5 with SMTP id pq13-20020a17090b3d8d00b0027d98f321a5mr1026494pjb.24.1697441115751;
        Mon, 16 Oct 2023 00:25:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d8f:b0:278:36c5:4255 with SMTP id
 pq15-20020a17090b3d8f00b0027836c54255ls828725pjb.1.-pod-prod-02-us; Mon, 16
 Oct 2023 00:25:14 -0700 (PDT)
X-Received: by 2002:a17:90a:3de6:b0:26d:17da:5e9f with SMTP id i93-20020a17090a3de600b0026d17da5e9fmr28002891pjc.1.1697441114672;
        Mon, 16 Oct 2023 00:25:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697441114; cv=none;
        d=google.com; s=arc-20160816;
        b=Vfio7Y2QCyTOwr/NzldjZfu+ip6Tncm9fyuXOtzIchDWegszWQW4ZPUlm2/ePH2xfd
         t6AnTIai24yUcaHyywLbEmaH43RnEEOhKm9iCXJr0IV/Nziw8soIxOS+fv5WVL8KT83I
         UsVItNfkb10uSP/4RrTOKDfL9tMQ+dj4izZdjSqVUPGWdplXR4jLWwhtgzihtN2hbxrI
         njg8tKttBxTtZta7n8bpwkrtqvyga/I9FImuD/Luiu4GLXiuvhw2evukqqSaHTiK/0zv
         jOpKBgpZzuA24dKxaUBRX6dM858AZDIhfdu4n3MsdXEGT9e4M2Z70JFiGP6jL3hDp+wB
         9fSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Aaq5gGSXXFhrvTLVP4/6JBiex67TLmoZv6JITqT6ub0=;
        fh=o7j3g/q31jIib6BlUkVe9tNKCoo8Apz9BzqHyz/4Kpk=;
        b=qpuFPp4OnXRH2gF5OPsI9Ks2+6qlagiY1VJT8huX+EUH0bdUXMmze6sbcVx3naXIuN
         E/V3LW3r3IB4XD/FzYynBQgeoIksePMpEuXHkU1XGzk8mCwjkNRIzcpVEt2wkVWv/kzf
         tgiqLYg5aqbQ6GAhrHnRdHeFZWBaA+n7t3gA5gVVOCQuR3EFm5D+u1gdcYSnnN3o3dT6
         0Ky/hGuWHhzWim0K2v0NmosucTByUWcxfLLCYke6k56Pa13PmWM/2BtTQzxFN5UCPij4
         NQSH8Ic7suFxv3rVSyt+dkRly4Rwdeb78z7StGxVw+5n9ea+qm9OciUDDNUq5At0iLu2
         flwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GuSak891;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id y8-20020a17090a86c800b0027d0d9abe6esi341912pjv.3.2023.10.16.00.25.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Oct 2023 00:25:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id ada2fe7eead31-457c82cd837so956593137.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Oct 2023 00:25:14 -0700 (PDT)
X-Received: by 2002:a67:e00b:0:b0:457:c052:1949 with SMTP id
 c11-20020a67e00b000000b00457c0521949mr6953894vsl.25.1697441113556; Mon, 16
 Oct 2023 00:25:13 -0700 (PDT)
MIME-Version: 1.0
References: <20231015202650.85777-1-pedro.falcato@gmail.com> <CAKbZUD01au=HoDe=yXSLtxJgYdivZccqqBfpmnmQ04R1Y1orvg@mail.gmail.com>
In-Reply-To: <CAKbZUD01au=HoDe=yXSLtxJgYdivZccqqBfpmnmQ04R1Y1orvg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Oct 2023 09:24:37 +0200
Message-ID: <CANpmjNNq9X+n=WFsa-p31gKJG5vLH6PXGmLt0eEmWoHwMN0scg@mail.gmail.com>
Subject: Re: [PATCH] mm: kmsan: Panic on failure to allocate early boot metadata
To: Pedro Falcato <pedro.falcato@gmail.com>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GuSak891;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as
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

On Sun, 15 Oct 2023 at 22:35, Pedro Falcato <pedro.falcato@gmail.com> wrote=
:
>
> On Sun, Oct 15, 2023 at 9:26=E2=80=AFPM Pedro Falcato <pedro.falcato@gmai=
l.com> wrote:
> >
> > Given large enough allocations and a machine with low enough memory (i.=
e
> > a default QEMU VM), it's entirely possible that
> > kmsan_init_alloc_meta_for_range's shadow+origin allocation fails.
>
> Ugh, forgot to run checkpatch.pl until it was too late :/
>
> > Instead of eating a NULL deref kernel oops, check explicitly for memblo=
ck_alloc()
>
> If there's no need for a v2, please wrap the above line and...

Probably easier to send v2.

Otherwise looks good.

> > failure and panic with a nice error message.
> >
> > Signed-off-by: Pedro Falcato <pedro.falcato@gmail.com>
> > ---
> >  mm/kmsan/shadow.c | 10 ++++++++--
> >  1 file changed, 8 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> > index 87318f9170f..3dae3d9c0b3 100644
> > --- a/mm/kmsan/shadow.c
> > +++ b/mm/kmsan/shadow.c
> > @@ -285,12 +285,18 @@ void __init kmsan_init_alloc_meta_for_range(void =
*start, void *end)
> >         size =3D PAGE_ALIGN((u64)end - (u64)start);
> >         shadow =3D memblock_alloc(size, PAGE_SIZE);
> >         origin =3D memblock_alloc(size, PAGE_SIZE);
> > +
> > +       if (!shadow || !origin)
> > +               panic("%s: Failed to allocate metadata memory for early=
 boot range "
> > +                     "of size %llu",
>
> unwrap this string like this:
>     "%s: Failed to allocate metadata memory for early boot range of size =
%llu",
>
> Silly mistake...
>
> --
> Pedro

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNq9X%2Bn%3DWFsa-p31gKJG5vLH6PXGmLt0eEmWoHwMN0scg%40mail.gm=
ail.com.
