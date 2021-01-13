Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRGB7T7QKGQEQUKIMSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E5E62F5002
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:33:10 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id l185sf1128914oig.17
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:33:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555589; cv=pass;
        d=google.com; s=arc-20160816;
        b=pMV7Bu1rmxeY7i3e5MF2GA73DzmvqzPC5kHNroSbClvET85yz0osAB+lO3GAz+OHRM
         UdZSlzVXVgNBiAuapa1Lzy/aAbfZTBIb3BSzWIr6IHLjeGISQkxXMhCsMjk+ubiLL3Vk
         5cnlyqAp8GTFXUQ5+cd/XoPJ2krPTV2Wxmj6FUXEukli+9QUm/HN1GxPRGLVruKR7k4+
         1+hkaJWNd7j0uHgRuJ/Sw6WGVdc8k6JLPcL2gKEMikEMWjAXwwgwRty924elwwUW8qTW
         0zVvhYSE0UkIRLPQmOFRT9bhiPGekEz2zDjtd0SFEurmgy5skPbCyE2yVG5GBvL/W/q3
         ke7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YwZRHJ/bMyTknJR0XgfvSRCkSoyuSz17ULMzq0VyNP0=;
        b=goyw67/8I+gD0odxEBh91b2oMR953k7VJ3sUT/HFHPlaRvhUwn8ZsXGs84bPvuHApP
         xPEYDOH+NL4OWDJepvWQzYLGcsq3aE+ezxHtnuqcfGwtfNpWQMHvl6evwILEwhEYYJPe
         TyTCdWmgxgjDrjqNxc7QNtMoxW8ff7IqNFOw1fRH5gNFsJzHchYkCqvxoW99kYs1l9iz
         co3op+aNb7LU9AGO+EIir0jIbxu4Adni+78WMjwELK+BAqM+G9FpceGndo0OXTRW9Zrw
         u2tcDrtuWC7y/Vq9Hs2+Bcd+WB82mEWWkvdUUvwbPEU8fs868BjjatDJ0p4BKyfpd9Yv
         Hilg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YGT1jcFI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YwZRHJ/bMyTknJR0XgfvSRCkSoyuSz17ULMzq0VyNP0=;
        b=MHtfe5AyhYDzjzkPkRpxaO6bCpBtf1FrV8bDr35FK2Do3zSphI9bmbeOEU1TDBpQ2S
         mVz5BffrxcdW1IsrBYHKyxfcKnpmlhO+n26E1Q9MehOrE/HTfROifH2eCWjnrernJaAs
         e3Kl44zNdNEZrX/0B9GPAAipajkMEhMUVmctowK/5JZhYdu7RpwTvhAJ+R0Nt5MXNuL0
         HnpYTtY/oDN38oQMPGFtaFacNV3qJ++HIvzvpXgd6yHkLoOANTqmCR4mlrz6ElirGDa5
         zMqqa5SApK0vUzDlyp0P2ZOhnwN9kZcyRcz1ZpVNYldBY3fSDFGnFkx9Qj8mMGvvQNj9
         tDVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YwZRHJ/bMyTknJR0XgfvSRCkSoyuSz17ULMzq0VyNP0=;
        b=aVUNLmd4t2fV4aaruzexZUKGviB8F9epkE+N9SXuhDkYqTGxbYZT1s3srmAcS8aeKp
         zoIMd8cUdY+IAC5YsdU7J8jcQe3/P3h0DfMa5Uv6kX8kVtGrYxeMbgBk1JysQxCA9BqS
         gp8ifXkaBdkw7LyONAD0qyC+OV+Zq/rRHVTC0UKJilFwnoOuApmhMaSLg6TCgIRovIyf
         aehXb8dy9PRDv7DYqV9/YU7g5r3VZFIZJBgFmoxEbJJ63p5zpuPzyMYtPOeNl9eaZNCv
         rg2Dn4kt3x8YMSZMWKRMh00rAKrMDMfxHpF2aZBkh7Y5orBgrWd+WBTa3WO/mu2WT0y4
         ilIA==
X-Gm-Message-State: AOAM533muO/THE+whLK+byioFUkXkWMzc8zgfBW/tbgXE466LyRBlYaw
	+au6+K3hqdHDNdIl/rfjtEA=
X-Google-Smtp-Source: ABdhPJxY/oszDuQbOhEMSO4JX9ESO8ogGpi/XQuuG8FSgjlOOfGjByxot0D+pmYn9QABt3Yzc8VCfA==
X-Received: by 2002:a9d:64c1:: with SMTP id n1mr1816915otl.60.1610555588918;
        Wed, 13 Jan 2021 08:33:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:7ce:: with SMTP id f14ls677737oij.5.gmail; Wed, 13
 Jan 2021 08:33:08 -0800 (PST)
X-Received: by 2002:aca:1a06:: with SMTP id a6mr49216oia.29.1610555588599;
        Wed, 13 Jan 2021 08:33:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555588; cv=none;
        d=google.com; s=arc-20160816;
        b=0X8ajz0/OR8OKx0ottAppwpTcFosoyKzibrcmx0aTOtGT960WKuVibej06bdKCkzN4
         rHT49p8LOd8cayTPZZ9F0N8R9YMBU46yZsUABBn/Xwr+a1cU82FibbrCdrSFXWmG571J
         dRMZU/pPmOZuoXemV6J9q4tPiI5TkBiqrD9n1IRHa9M0spq4FFRItjE1+/wW9b/Jmr5y
         o1WxHmm8tDHdeISSRbXNX8DHFdpnEbMmrXJp6wSrpUDbIMsD0gBIZZgY05RprcQ6ceAn
         KxvcIkxO4K/bsgXfS13sKIJIDSU2uC5en/PIGNRZURCkae3w3Dc3m1xCkHRwdMGkWWHS
         iH3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Yukq8DLGoUwetcyUpU1xVWQNvOKdjhm4xJiehIsqbBA=;
        b=auIpM7ACGetp+6o9xg5sf2vjSf4Lgdx+ZWK+/GRhzicTZQBS59vKrTQkjrKA5Bqi6r
         Ckc4bHcdUyc3/wUHxNjy6nRcO8x+EcxY2AFc4e4VqtTsKEwqJuGxvbwGCaIs7zlJBeyy
         X3WSwv+0CQapjIfia2ey0Ja5HPBei8XQKbfD9GsI6qGmWzHJFsb/Ikofg06NaVtpGNYU
         SPvvXYts6VCVP0s4CMJevJzYwyTeqDEmKaxad3YH7vYlaahuv0xxEmwaEgJfQn9oiO9l
         DM4+7vN2mD552jVwfxvrKz1Ct4Bz9C47FFL91yCtVKxmqP+Gjewk1Qecy8XsAY3jdcCW
         hIgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YGT1jcFI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id x20si304661oot.1.2021.01.13.08.33.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:33:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id d14so2431571qkc.13
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:33:08 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr2927473qke.352.1610555587689;
 Wed, 13 Jan 2021 08:33:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl@google.com>
In-Reply-To: <1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:32:55 +0100
Message-ID: <CAG_fn=X+wtO3tABhJD-Bigx1QHmLu_21_VaEkS9Qsp=EsGS0FQ@mail.gmail.com>
Subject: Re: [PATCH v2 09/14] kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YGT1jcFI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jan 13, 2021 at 5:22 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> In the kmalloc_uaf2() test, the pointers to the two allocated memory
> blocks might happen to be the same, and the test will fail. With the
> software tag-based mode, the probability of the that is 1/254, so it's
> hard to observe the failure. For the hardware tag-based mode though,
> the probablity is 1/14, which is quite noticable.
>
> Allow up to 16 attempts at generating different tags for the tag-based
> modes.
>
> Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb0743=
4a300bf36388d55
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  lib/test_kasan.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 283feda9882a..a1a35d75ee1e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -382,7 +382,9 @@ static void kmalloc_uaf2(struct kunit *test)
>  {
>         char *ptr1, *ptr2;
>         size_t size =3D 43;
> +       int counter =3D 0;
>
> +again:
>         ptr1 =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
> @@ -391,6 +393,15 @@ static void kmalloc_uaf2(struct kunit *test)
>         ptr2 =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>
> +       /*
> +        * For tag-based KASAN ptr1 and ptr2 tags might happen to be the =
same.
> +        * Allow up to 16 attempts at generating different tags.
> +        */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 =3D=3D ptr2 && coun=
ter++ < 16) {
> +               kfree(ptr2);
> +               goto again;
> +       }
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] =3D 'x');
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyk=
nvl%40google.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX%2BwtO3tABhJD-Bigx1QHmLu_21_VaEkS9Qsp%3DEsGS0FQ%40mail.=
gmail.com.
