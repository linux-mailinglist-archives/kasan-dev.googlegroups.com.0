Return-Path: <kasan-dev+bncBCMIZB7QWENRBENXWS4AMGQENUHH3YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E6D899CB86
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 15:24:35 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43056c979c9sf26452295e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 06:24:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728912274; cv=pass;
        d=google.com; s=arc-20240605;
        b=krMMlrzB1Ic7QDbSr6+bXepEeylctm7ZBDwzeoEvTXwyMjlfWpjDhQvdyoNXouLM9z
         7olZKs6TLGIhf1myigtBuKvsPWaan7opHJOoyvOT6vQrQmtJmD7ME3wTBe+kvb5GIxsQ
         S8CzzkllcHRkojGGoL57HC/jkwP4gqxkg8yhosMQ/WlKI3EkzDv0m243C+YsFcmNH1ul
         ZDRObonn7kfeSlAVFmASpm4nyOd7oRknvpLcLPZgVIz957p9BwMRYHN7xJqkhhjNIRzF
         rhm8Tgg5RkQFvZa7dsjmgbcvQQ4/1c0JvhMgjNqF3QPPVCfsErfGAPUaDGdvOP5Bvy93
         IoDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Iy+OQRljytiWFgM7dWpkxpUzwUktBHp6w5os7FVEN60=;
        fh=q5hKYi8bMzgewSzxxCLg4/Co5EGsynTJdErrGU+SItI=;
        b=KwzCaQdTTDegh0i8vZdFfEehugrOtba8tP3O3F/wgP/wHhCfO8sBayg8Do77I6SLdp
         AJNsatwL/xXKYG+ikSbbADJPt2jAwJwMw2/5yB5R2fA2XVkCTV0r0BqNuDYiB9FnIVMW
         5M2SpZyTH4QSkZEAYGdg5r7LpeLF211OjPTnc5844tBgYPkzuDcC27TwaQ5AY8C3D/3r
         8Txi92i9dOlTMqAq6TJQyfpKh+an+c6zGPIyn5K8/e/w80Bgw9bSr1/4g0quOjmPJci7
         nZQqX5WC3CpWGVOoO4ApU2N488X6xMvE+Dpjc2hOzyEil+4yhdG2GCzj7CPT0x3eH5E5
         HNOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ViTfFQJo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728912274; x=1729517074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Iy+OQRljytiWFgM7dWpkxpUzwUktBHp6w5os7FVEN60=;
        b=RN3DsXXLY7cCvaTiwGW1TpsuuJnXtjdxDaFbWmTlYspY+IyEgOdigvJVBp8fyPiCwK
         VPNTle6eo389Wx9m0uUKYe+/i3az4n7+C45+ZdaBSrinFAl0OiTpn+kYDv6LbkxTUI8t
         3X6M6P8VTw7kSl7JxBNPN0NwmrJPcQ+Ej7DXFffd8OR4ivUV9EUp3m2OKjdF/wVbc+Hj
         GzwlAF84kjOg+6ol/7CeWwiYgHAJ50lVCcn26+7zxPMF1VRGQY5yJ0+eL5C7LvgtsHC9
         J6ox0anrVgoxlFElsGjdKcm2RtrJVIjz35HiNo5MixW75oMnXEDStjuBi+NW+ymoRfQY
         psrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728912274; x=1729517074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Iy+OQRljytiWFgM7dWpkxpUzwUktBHp6w5os7FVEN60=;
        b=Z1UK/3+7hh/FWmw8iPZQjDYhrFvK4Skv4jPj2La+GT2WacgJGmOAL0qJowK9dxp7O4
         aRdzB0LudhYoJpiFYY8Qd1opOtlEawC+JU7wq2Tg2TVb1gGYu6Mnjp2pZHKZ8FZuTNq/
         G2mlNfd+cQgCssrIRjhCc6WAshtQNnRe/6Q/A/lS/DD2KHmwLU6lXCQmz/QMm+pl61Pv
         FMDXqR+vBD6sqrVkNVqYTnA1c+DnOZf4WHMnJLguYmH8jt7pd2POAr1tIK0osQoA0+2b
         tRfKkddfp7tDm1ZTU5eJdO4d492Lqn+qZPN2iY6YAcIcsfApmfxB+whdq33Jv9ZpWiy2
         USYQ==
X-Forwarded-Encrypted: i=2; AJvYcCUW1fI6ZAPWElt/OaflDKT0KpA4Jyect+eBrvqZzBhe+V55KmMLjj4Q+O0vVdjA8mN9jrbDxA==@lfdr.de
X-Gm-Message-State: AOJu0Ywq7cN6kEfLAxuhNj9WwjmF4QAg0OcJ7RyIJMBDkd4znQ8nS6J8
	DsG7XXXY7/rnQke/UclOtOb6kNBN3S8pWY+RgNod9eimZxOLrhw2
X-Google-Smtp-Source: AGHT+IHZD65fZVYjNsp/30MR6T3m9LgPg4QcjuL4jkT8N4Til37b8ToghZsYoexxKk81AvDFkyZbPw==
X-Received: by 2002:a05:600c:4fd4:b0:42c:e0da:f15c with SMTP id 5b1f17b1804b1-4311dee6b2dmr89833575e9.20.1728912273300;
        Mon, 14 Oct 2024 06:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c28:b0:431:11e7:f13b with SMTP id
 5b1f17b1804b1-4311600aa78ls6840815e9.2.-pod-prod-07-eu; Mon, 14 Oct 2024
 06:24:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUB1Yj3Pr32QObvP2SYp8d+JBilFP0tf05jiqWpHWexFWZPI8TI7AD49zV1b+Ahr378J5WqdmNTFqA=@googlegroups.com
X-Received: by 2002:a5d:56c8:0:b0:37c:cdbf:2cbe with SMTP id ffacd0b85a97d-37d5520586emr7326391f8f.23.1728912271476;
        Mon, 14 Oct 2024 06:24:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728912271; cv=none;
        d=google.com; s=arc-20240605;
        b=VECTn7O/7Lkw4RnEcSWMvvux4+odqh66myoVZfj1a9KIyZzGrBJz8/ida0BbHSZy2K
         OC6ATI2B2thF04V470Bn8/I5z9GdI9Kk1I7LsEDvA4ktGCxiKEGdOxhUZJbXdWHP7YOh
         o+H8/nRTbFUJi7GyBWtMLQC19FJh+0sAWpzn1mHTsrqlCmgPEKBs2EE9M5aB0W5enZal
         LJYP0ekQMNxByg76P6d+jIMpFxLRXxa9zaN44fn3PDGWtMzGjg5Qxct0rSAWuN9aGDX5
         z/k2RMl3RM9KrklJJr6UqrHT7J9ELpv3BeHWypp8892eNyipHZm9Wq2qo6EvlS+0kf6j
         //cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=n5KhJAw2py2gNyB51ij4Ahm4Pf+WITFslqbmQTWMfBg=;
        fh=yaoLzokL3FKY2RlVu9JrFJj9JrvF6FQ6Ml2QcS7Bvbo=;
        b=Yue22SDKz6Zax1XsyScMjd0DC3Z355BXqitn3BusoOoWyCN0L4q0CBsVuPLQnssQ2J
         xzmGrQvYSy+4N5E/HnrnA7krIJJ6Pv2ROKYc5hkeND6TbH/2u+JdFRTb44qZ5ALNuGjW
         cRdjE1bm8bgpTLSKt++580JARowdCTUGR1bKs4mjTBdJ7YYAPMA9UWKMlgGM3zF1Gsyz
         zfbHtwtldo/aiyt5Kbk09W/y5iMb5/BRqUg+hP65TR4TJrHVK1Ve7rUmuNyxO1UGVGER
         49mq3Sl8lsziIQl0kHprUMwmgs1i6jvdk98juxT07n/Qc1AOBxaoq8411LOMgpfRoaLX
         ORUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ViTfFQJo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b9157a8si148930f8f.8.2024.10.14.06.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 06:24:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-2fb57f97d75so4531641fa.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 06:24:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjoAOMJhLXpFXbv/RL52fDqdQKgE4sZnAdr6oyjKU2/tB8tC4Z1xi8Mr8H2SiYwHbrEshMdSP9OXE=@googlegroups.com
X-Received: by 2002:a2e:b8c1:0:b0:2f7:90b8:644e with SMTP id
 38308e7fff4ca-2fb326ff6b6mr53795831fa.1.1728912270535; Mon, 14 Oct 2024
 06:24:30 -0700 (PDT)
MIME-Version: 1.0
References: <20241012225524.117871-1-andrey.konovalov@linux.dev>
 <CACT4Y+YS4UTMwk_j+Fjah3bCQd0zFcr2XqsUJ5K8HC991Soyhg@mail.gmail.com> <CA+fCnZfkurMxTyf0ivF8uffeO+S0piqFuZ975SSxmjr_V2OrHg@mail.gmail.com>
In-Reply-To: <CA+fCnZfkurMxTyf0ivF8uffeO+S0piqFuZ975SSxmjr_V2OrHg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2024 15:24:15 +0200
Message-ID: <CACT4Y+aPjTmFRA58ewiHOaxUFxh1w_OwHj00GRjuPSBgA9ZyCw@mail.gmail.com>
Subject: Re: [PATCH] MAINTAINERS: kasan, kcov: add bugzilla links
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ViTfFQJo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 14 Oct 2024 at 14:51, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Mon, Oct 14, 2024 at 10:08=E2=80=AFAM Dmitry Vyukov <dvyukov@google.co=
m> wrote:
> >
> > On Sun, 13 Oct 2024 at 00:55, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@gmail.com>
> > >
> > > Add links to the Bugzilla component that's used to track KASAN and KC=
OV
> > > issues.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> > > ---
> > >  MAINTAINERS | 2 ++
> > >  1 file changed, 2 insertions(+)
> > >
> > > diff --git a/MAINTAINERS b/MAINTAINERS
> > > index 7ad507f49324a..c9b6fc55f84a6 100644
> > > --- a/MAINTAINERS
> > > +++ b/MAINTAINERS
> > > @@ -12242,6 +12242,7 @@ R:      Dmitry Vyukov <dvyukov@google.com>
> > >  R:     Vincenzo Frascino <vincenzo.frascino@arm.com>
> > >  L:     kasan-dev@googlegroups.com
> > >  S:     Maintained
> > > +B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizer=
s&product=3DMemory%20Management
> >
> > Do we want a link to buglist.cgi, or to enter_bug.cgi, or both? =F0=9F=
=A4=94
>
> I think buglist.cgi makes more sense - people can check the list of
> existing bugs before filing a new one. Finding a link to the right
> enter_bug.cgi page once you know the component name should not be hard
> (but IMO Bugzilla should just provide that link when viewing bugs for
> a component).

then
Acked-by: Dmitry Vyukov <dvyukov@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaPjTmFRA58ewiHOaxUFxh1w_OwHj00GRjuPSBgA9ZyCw%40mail.gmai=
l.com.
