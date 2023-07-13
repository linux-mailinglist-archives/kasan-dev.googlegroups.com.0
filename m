Return-Path: <kasan-dev+bncBAABBLP5XWSQMGQELF6FZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D39E751784
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 06:33:51 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-66a4c89bbb1sf280252b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 21:33:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689222829; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZZEEdKXFJNgIJW2Co5UIikvL3959kJdd9bdD4oc4/QixyuUxUlPs/lajHauxHMYnR
         Z+47+DYS6/cn+8i0yAC7EGMnqoCNr9iREL8NsCf74jrQ1cfhyUKA1jQsqmsO7fZdbwDI
         DXnDGgLylD0OAoJTYz2YH7a/EMhSOgdg7DHOVKhniHGolTfwxNQiyGEzCs/fvfpXtELA
         /gm/2yqChDfygSVSTtgGSOtzMj5VFjTmYuRTEPEYHlD4iH5NjYR0hD9HOrjsodP3UY1K
         47spCaVGsOkqjplaq5gA93weBNTqHfCGEW59KPB3KUX19tA0XDe8Sy4Bs5R06+FszWhW
         FgBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=CJ8Yme+rTdrqEDpBVwmDvXMH6RASG1VQ9sCxgG7Vc48=;
        fh=+HwCTq7igZ/G6QDwXAugMgOXkLQNXups/t3yc1eUJj0=;
        b=Lbor7v+6PUdClW6a+a/bLTUCcOo2jGYArQEIai70qbFNWOcS54sEVWsd0Ky+r32vPC
         +LMJ4Rom/rtv9F5siXAmzBEkH0wXxsa43MuSuD+Cx582/QHrkHTv53ysy8/sBWoNJnM+
         Zkr7XeWGRvQ9XnPEskoRD0V5Nzthz6GPexprKmBeauCOtNJ8yYtISNk56B/XtC+rcMBa
         57vZ5wl+MCL2VqrTUnF2+D1TLWxu+zwit7o0zEChQwR/FDVStLw8f5YzR1sI+lkaZEHb
         gaieV0VL0MwaNXX3rlBr+TEakrkQaEVM9LJTN1NBxTowI4A6/GiEWI7GhTb2ETFrwsyL
         8rMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7llqEy2;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689222829; x=1691814829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CJ8Yme+rTdrqEDpBVwmDvXMH6RASG1VQ9sCxgG7Vc48=;
        b=Z8uudbsBV3pzaep97aqIKxSlzar6+Mp1ucqysiHkmE4CP/c06fgLDcv8yBUa2rKhrB
         HaOFyFRw32VMEnYZRe5GKVf10JAIsCXtYzduYjzYRCWokLr7Jc2ZKGpQUAcW5rqUWzG6
         fuT67k6ry/qoNShyvVmmWujveZoFsAGvSKvqvPOf90+tzTEBvSHpC7E7hH6G4bzVV1HW
         XVF5nDWROJHkjZhgeUWGa40I4HDA9L3xLPcqs1WM3Ig2TcFoGaTea5V6LupmiucsMrDt
         K0U+6hScp1Bp1KOaoKsIcZTEHDRV5qYUrY+a0oxFPujLDxSRM9X04mR1zIZXmQyxqr8K
         1XRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689222829; x=1691814829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CJ8Yme+rTdrqEDpBVwmDvXMH6RASG1VQ9sCxgG7Vc48=;
        b=iJzFs46D6VgfQYDepO8ATaUDxBdJgJRcA43WdGSfOv6CpVvp3xz2YIc8EsarXn8yok
         6VtSoU6E7znNmieYkhxBaTJzwcY00X0upHeWJfLiuhiszL7Ya+aVB+QwL4fEcqcvaaj0
         ZWrgIBAgzj5r1nmgV2a637fCN0zrnb5x2/2kmkCA5XkLHP/KwwxadUwgTHA561YoZcic
         kEiZGkLgek0Ll5tKGD2pFK8sySbQi0ApGJDIM/3MTWRqWdQqq+xNY5NeQgFcR4bIgV/b
         jo9+NG3hnI6QQgNT8+eNN4+YQXKc0zpCjbVegeQA4Bc6efO8JPsIBtXQd0XcN6rpdQc+
         TkBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYS4J/kzCSCUjyeYy/bIdY5D0Km/0H+EjSZZY03gTtbA5XPXMeh
	+Mkg6IeQTsHYgNJTywLlgPw=
X-Google-Smtp-Source: APBJJlFVNiEFyWqifAJo+TSxFwdpIixsPm4tdEy2xWemBoNjMlQbrTuylTKYnKXUdbsBFLdJVUvqoA==
X-Received: by 2002:a05:6a00:148b:b0:681:50fd:2b98 with SMTP id v11-20020a056a00148b00b0068150fd2b98mr888004pfu.31.1689222829559;
        Wed, 12 Jul 2023 21:33:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9d8f:0:b0:669:ebfa:6b19 with SMTP id f15-20020aa79d8f000000b00669ebfa6b19ls239564pfq.2.-pod-prod-03-us;
 Wed, 12 Jul 2023 21:33:48 -0700 (PDT)
X-Received: by 2002:a05:6a00:2451:b0:682:4c9f:aa0 with SMTP id d17-20020a056a00245100b006824c9f0aa0mr746084pfj.29.1689222828872;
        Wed, 12 Jul 2023 21:33:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689222828; cv=none;
        d=google.com; s=arc-20160816;
        b=hamzoQecGgRKAMN53MV41NF4de+CQErNEwRZIuEMH/D0FH97qHt2LM1T73X30mIkmG
         iZNsAytZ1vqdmiuahcEXBb9+WwPp9ADms1fcUe/8ngSZniv1935aVdEipmkBoVxXO901
         KYVzDkw93tI6DyBH4aN7l/5vRs3eNLUAfvNZjtoSbNJ1uBWIivzepn33WlfNsjD73n+j
         GEzxwme4C5XeW7ejp2RCF4fc/Uqcni93mSbB2/HBHWixdw9FfZZoBBboclycjnh+ScUZ
         MFTpYIzDKehACXt+wFk6XEUXszaUIsGrizkqbCXtdnfid0z0CqIT3Bo51tiEdZ1AxNoa
         M4KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lIKt4WxOlzgjXowH4yh6E/rVYczRMm4JhgFuHiZB32w=;
        fh=+HwCTq7igZ/G6QDwXAugMgOXkLQNXups/t3yc1eUJj0=;
        b=eeivXNCluhoZhGXORptZcI/uHjw6Cb6LByouBmxF9PX8evlfExVZeEEJBJcFO0koYK
         l3C5dPH8hA2eDjaxDHJWOBRU+F9hoc8TdGu+N7SF7+Ee9yWaj6YUZbXsUHcm7N9GY4s9
         B85u1G/w99llAuAtBmY0A1DQbT+z/NK5dRgXcbJZnAp2qV6q3lpI19hlM9VbwiHpWcAD
         zvYRPvFh24kl6MoAdwzy0zt2f872VkX/8DhZzpdMKrKcellaOUSX2DJdAst+TuL1ro5D
         Zf70HrbDV5elrKp/SAUMquPUR6EpLxygsWZG79qVUUrOalabZp9QuDtipgteTzLPbGdE
         ZDMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7llqEy2;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ay35-20020a056a00302300b00682537b2c0fsi610073pfb.2.2023.07.12.21.33.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Jul 2023 21:33:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3CFD960C4B
	for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 04:33:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4072C433C7
	for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 04:33:47 +0000 (UTC)
Received: by mail-ed1-f41.google.com with SMTP id 4fb4d7f45d1cf-51fe084cf3cso252677a12.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 21:33:47 -0700 (PDT)
X-Received: by 2002:aa7:d34a:0:b0:51d:9ec4:9616 with SMTP id
 m10-20020aa7d34a000000b0051d9ec49616mr597329edr.28.1689222825887; Wed, 12 Jul
 2023 21:33:45 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn> <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
In-Reply-To: <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Thu, 13 Jul 2023 12:33:33 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
Message-ID: <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Huacai Chen <chenhuacai@loongson.cn>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a7llqEy2;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Andrey,

On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>
> On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@loongson=
.cn> wrote:
> >
> > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for memset()/
> > memcpy()/memmove() if instrumentation is needed. This is the default
> > behavior but some archs pass -ffreestanding which implies -fno-builtin,
> > and then causes some kasan tests fail. So we remove -ffreestanding for
> > kasan tests.
>
> Could you clarify on which architecture you observed tests failures?
Observed on LoongArch [1], KASAN for LoongArch was planned to be
merged in 6.5, but at the last minute I found some tests fail with
GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches are
dropped. After some debugging we found the root cause is
-ffreestanding.

[1] https://github.com/chenhuacai/linux/commit/af2da91541a8899b502bece9b1fd=
e225b71f37a8

Huacai
>
> >
> > Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
> > ---
> >  mm/kasan/Makefile | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index 7634dd2a6128..edd1977a6b88 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -45,7 +45,9 @@ CFLAGS_KASAN_TEST +=3D -fno-builtin
> >  endif
> >
> >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
> >
> >  obj-y :=3D common.o report.o
> >  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o sha=
dow.o quarantine.o
> > --
> > 2.39.3
>
> +Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q%40mail.gmail.=
com.
