Return-Path: <kasan-dev+bncBC7OBJGL2MHBB77Y36SQMGQEOURUIOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id BB85575992E
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 17:08:48 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-51dd0857366sf34304a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 08:08:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689779328; cv=pass;
        d=google.com; s=arc-20160816;
        b=gSXfGilONPfsnA872ocWfJQFoyqLkKzPiPH6FEdkkjK7mDrnVDT62XlwMZwMse1MD4
         dt5X4umYppJzwdDiDTZ1qzk/PjOxZq/6CXZ9+Ww8O/F7anjpoDlVe3l91gv+0t7d6UD1
         5dDhJmuZMFWQ1dk2rII1wdKMWd5k4OOZtXLKiNkWcKH9AmuToFnS7qQdUCylwVnMaz5V
         cD6czqpR4ZT5NE19TCeQOo+8LyQNIvaqPWOEk+Z2KmJgllXkjGAE0dw/H0UNbZ7L4tO9
         HxEZnxEK9lvFqOz3pByVFai0hHdmcp0TjP27HfAlwES3Xzgu/vooIFmNZnlBdIAyoaxS
         URwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Dun6HyBA+4qOM7gwVhh0OFY7Z64Pa9Q+sxXtVFS666g=;
        fh=8Ik4Quv1TSQKusiYrZ6hVtPjp9SPy/TlkMAgOqAcuc4=;
        b=qa0o1a90rfjg70d4dzMCyKzd2zF61oKdGqqZ4GxuvNWDGyvlBoiSoYaFQ8yXSQLcdA
         y3i+z2OOvHTwOxzzDq+HJBbG7qnKzieJiTcKD6kgQh9E7QnP8fLYaE9E9OsWtua7zvpf
         1sgm9/Of48N4XwWeyumoK+mNe70oz9HYtfVX1usx1dsi/ce67wW7zNuGAjC9QyHPGSp/
         KCijFw8mrncpDT2pvskqzS35NmT6OmNeYRNhne3p7vBcigoJwfUoib0wi09S/ALYhkaR
         I0qtLeNZq4tL/F9cGqHy8b54p5zsdrAkxDDz68u43TcjrYkfRHFQLrYhqQZD9vrqyXDX
         csuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=k6Dzz3u+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689779328; x=1692371328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Dun6HyBA+4qOM7gwVhh0OFY7Z64Pa9Q+sxXtVFS666g=;
        b=h/rO4NCDNzzSMfCH1nYEcmyEhm9XPyDOgPpa1nsooJhvugNaTr6L4y6tZ9NMVZXUtC
         r3xLj5sJNj34dtRwklsDk23VAJRgmVnzMDZEP0OSa2g08qZYRseRZGrOUtMQ+W0ovug1
         6cu51EspPqd+8iTredXrscFFl8l/f/oTdaVpsoNQIb+daDzBdoBo5fZYx7Q7J0WZE+zF
         AwY0p+9CYIvPqKDPYtgOADginOhD0EV+VYHZ9LrXmQxLqgtYT+TsbUbeL/SoIBFWt1t8
         689FF3pPokG8MDDMZlKjyTTWOUf4m3wyjqO9UB4yp8sOJWM7RS2At86ovHTkKQtX6grl
         NIEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689779328; x=1692371328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Dun6HyBA+4qOM7gwVhh0OFY7Z64Pa9Q+sxXtVFS666g=;
        b=YNTqMiYcL/RJDMqHm8Qxd2MGBqed1WLPpeouxe0LtwNnWNHQAtnGV7nsiRsTDVKUeZ
         U+dSsrFkPFOtOJz/zDb6Sn0aFm+qDqAeNYydAFXngMWyYJxQsvfXqMVvBkyoiODydhZS
         z7jsH+51YZmsDboKDDpO4hwsxlUFcKU9C92sLxZXb1ynuUuk+ejLwK8qpnKZtpEhKaqK
         +aVslV6HsEleIxU+rIRHRuHhBb4BNI1FfcaAR2CMkfVV3YAdwz9qcpVcm+K9IiC3bAOG
         WWl5Ugm6LPZ/gGWsdA+N651NJ55uSxneDdewnTi503gtybtk2Uy0Ha9zcWyO0pNezp7g
         JLsg==
X-Gm-Message-State: ABy/qLZ/+bycRz9viJYUwAukJY01dddVQBgaRmNZwL+gP31WbeAGtFvQ
	ENtbFLwKX7qeX14APnZpF2I=
X-Google-Smtp-Source: APBJJlG2SyTrNgmmlcp/nV/hDBVdcbX5bpcAWzGppmea/eeGTMGxnKDRC9694fSEYCOsnbnqbQqB9A==
X-Received: by 2002:a50:a6c6:0:b0:514:92e4:ab9f with SMTP id f6-20020a50a6c6000000b0051492e4ab9fmr252838edc.7.1689779327706;
        Wed, 19 Jul 2023 08:08:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4f41:0:b0:4f3:b4d4:13d6 with SMTP id a1-20020a194f41000000b004f3b4d413d6ls46216lfk.1.-pod-prod-01-eu;
 Wed, 19 Jul 2023 08:08:45 -0700 (PDT)
X-Received: by 2002:ac2:51bb:0:b0:4f8:770f:1b08 with SMTP id f27-20020ac251bb000000b004f8770f1b08mr146734lfk.13.1689779325603;
        Wed, 19 Jul 2023 08:08:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689779325; cv=none;
        d=google.com; s=arc-20160816;
        b=uww2xKgOcEOz1JUvssknPSGVOwlycEfPNfx6xl4ZLJk/7XqaHJ08cvwTcBCHCE/cR3
         wtQKb7vRyHVcDPhiP+FqPvKjGut5nmNtIRBl6WB43NinDTvjeecrBUZ+YgYm4D6WnuMZ
         EWIcfAgKJt9oHAjDgqcF/pM/V0IBdgnm0dflz5P8iuN+L0UxYfXRPEsqh/OuAtM/9552
         +4pVpXyZQkiXOd13TFXTymDhgNn64YDxsKNdF4B/FspAifChuLq4GJTp0o2vDzrTt8tS
         x2X9p2dLuf6RkaSMmzQElre0WjEWj8f7XmvSC4WVAeqbqWSVGAtfT0J4yOq6XB+Bjg8n
         MjCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MFOc8wXCTX40R5n/QN5jnRi3zJ4EfVz1XUBftc9gujI=;
        fh=Cbn23tLfZFHF0UqLQ8NZe+SM4ifhEz0ZjangmG9BZqc=;
        b=QrzZ8uMTRfBZlq7hMIzXk6eIrEJbJgosoTi22UHGMdndLsbFoZ21OR8pThsBM/eKXP
         pruYJNDVKfD+L2jH9prqX2pZeEklaRp+Uo1jaS9Yr44+TQ88GSUMhubTckp8cfhCGqIh
         KBCOh3qatl8nuO+12ofUAW8BGG9c7iYYlLVOYy6HyDcM7X+dMbDyKPJwt0iS+zW/a0Zi
         +bTw46gcWJ2Bi1FhE5pibGQQf8RuFxGNZk4f5zdwUhd1pu3ND/dmETE+49pyX9jodnpw
         sSmyMLapg0jQnw1jirE/Pj7tTn+v7zL1Wi3cF4Ea150PnH2j/x/wUDtsuqUolS0j7Ctd
         11cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=k6Dzz3u+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id l2-20020a05600c1d0200b003fc3b03e535si89115wms.1.2023.07.19.08.08.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Jul 2023 08:08:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-4fa48b5dc2eso11851782e87.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 08:08:45 -0700 (PDT)
X-Received: by 2002:a19:5f1e:0:b0:4fb:77d6:89c3 with SMTP id
 t30-20020a195f1e000000b004fb77d689c3mr134036lfb.12.1689779324718; Wed, 19 Jul
 2023 08:08:44 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-4-lienze@kylinos.cn>
 <CANpmjNOHL8EMP+E9w5wxMJ+PUbxYZh2DMaEocfHP1ATQn64+ng@mail.gmail.com> <CAAhV-H7Ca08Aj1y5HHUsUreOdBTQwVu=H+3nFOUjiUiq5aR76g@mail.gmail.com>
In-Reply-To: <CAAhV-H7Ca08Aj1y5HHUsUreOdBTQwVu=H+3nFOUjiUiq5aR76g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Jul 2023 17:08:07 +0200
Message-ID: <CANpmjNNKa7yevuGeOOHtABGiSxF+8GQQudf6_9-CwT4aYD=6=w@mail.gmail.com>
Subject: Re: [PATCH 3/4] KFENCE: Deferring the assignment of the local
 variable addr
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Enze Li <lienze@kylinos.cn>, kernel@xen0n.name, loongarch@lists.linux.dev, 
	glider@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=k6Dzz3u+;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12e as
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

On Wed, 19 Jul 2023 at 17:06, Huacai Chen <chenhuacai@kernel.org> wrote:
>
> Hi, Marco,
>
> On Wed, Jul 19, 2023 at 6:55=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Wed, 19 Jul 2023 at 10:28, Enze Li <lienze@kylinos.cn> wrote:
> > >
> > > The LoongArch architecture is different from other architectures.
> > > It needs to update __kfence_pool during arch_kfence_init_pool.
> > >
> > > This patch modifies the assignment location of the local variable add=
r
> > > in the kfence_init_pool function to support the case of updating
> > > __kfence_pool in arch_kfence_init_pool.
> > >
> > > Signed-off-by: Enze Li <lienze@kylinos.cn>
> >
> > I think it's fair to allow this use case.
> >
> > However, please make sure that when your arch_kfence_init_pool()
> > fails, it is still possible to free the memblock allocated memory
> > properly.
> >
> > Acked-by: Marco Elver <elver@google.com>
> Does Acked-by means this patch can go through loongarch tree together
> with other patches? If this patch should go through kfence tree, then
> the others should wait for some time.

It can go through loongarch tree. I don't think there are conflicts
with -mm around the patch's location right now.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNKa7yevuGeOOHtABGiSxF%2B8GQQudf6_9-CwT4aYD%3D6%3Dw%40mail.=
gmail.com.
