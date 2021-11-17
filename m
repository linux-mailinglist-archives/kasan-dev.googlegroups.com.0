Return-Path: <kasan-dev+bncBCQJP74GSUDRBKH42KGAMGQEQ6L3XGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F40764542B4
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 09:32:41 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id a14-20020a927f0e000000b002597075cb35sf1250116ild.18
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 00:32:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637137960; cv=pass;
        d=google.com; s=arc-20160816;
        b=thVyLoUM/96Gmi0iwzh+g8iiRz7Y00fatvnI1K73pUQ0tc5pVemAjkN/2XY4G3jkc6
         pks7Dk9AMludhwqwHZQdyFm22LpVc7OONqCPZhs9qM/FrFbXc9RnswKwR3FKP9htyqte
         ArMQp/F4f+66NtaZa/R/xPCToEilPlXFIN8LItIBEfevFzjyEzH+BwBcXwCqcC915SRN
         avsYR++gzbpic02oZMtTG9d4RutYkx5TJUidl8EX8udL9GauOiLLYTB8qLbcaFRh7M+d
         N9pbx6TIEuOOCfxvlRnvlXTToGX9/dIuMiuB/b/Qs3oie54mdpqh+N2gjG11/CR4vTxq
         UzPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=lM/RYnf3ptJD6f8lG0VKv8ZrMlnRhE8XhjtUWinFIsM=;
        b=USALBl9HA8cgw9BDvJDUyd6UkAWgMGAQCXKzto34uuUAILnVhr46ZPO0eCQaKck9pY
         uY6T8nj4SIv+YBmJp1sG45hG8suM9L7idkUnFNp7DhQcFwfNzamD+/LcbWdI4LY34wz3
         s+gJqcGZ9Ionu0JnHn36A2Pfp7aeTLgl0Mr3iR+kwvB0VkwK7v4O5pBDPFIpqEX0MyOv
         Pr65Eg2IJ9Baf7joOodDNckpNhfgVd1zHFH1OELTVEMqUqQ7h/CYosjKIAz5unwVmIVR
         uM9mQ/LR/1n9as9RnyLr6YulJ1Bz+zAP4wfGnIYiu87q0Br3Pq3VkQvGCweqWLF7Xm4Q
         TV4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.46 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lM/RYnf3ptJD6f8lG0VKv8ZrMlnRhE8XhjtUWinFIsM=;
        b=ImpMI6T80uVLckZBf9r+Fp069Aa1u6prhzHFnPie6VAx0ez4BS4JUZRpaM3m5N8m20
         wb8NM282p8fG8K73VVMvdiiu7PGHdZCLhxZq3WOthzG3V6qb7WhvqSMN8rUCRIAHAI21
         pTElYW8ALcnWiTC41lI8v/9bLKUWME4688lq1NcLfEmf3i+DBGos91ZPWgKa1TUOUTRc
         jagD3dAUSAZRPSKB+yD5GJHCFAMSfWvTpD+Y+OrppBFiYku7ur1fPdbNPSVDVRjRFCGF
         yFWybP1dvy9mOrVf7b8Bzxz7YgtD/F/eqNNCcecc3e+7r4mtcpU6WO6RRy8Q4F6KTp1y
         LgkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lM/RYnf3ptJD6f8lG0VKv8ZrMlnRhE8XhjtUWinFIsM=;
        b=oXDtadx6kA/tvA1WiVQY9YrTmwq5+XS4DH3wGomZPX6j9LwZTP61Aa2s95uJSPalrO
         kcw4vwSD5GP2ihBJVc0YrGLEizuyGCudClI8OOlV0S6eS5RvzmSi+TLlh3s6c5d30tvn
         CSx/ZM9vQPzLrYvYpd8aLbJLZQ5UyeadzFR60xNoSTF/Fnw1arvAqKUmXs4QgY7TWOfa
         HVAd3vIq1ZWfxF4R0QY0jH4kIIepyfmu/jFSII8eyGREqW8mCWN8GBt3khout76xTvjN
         YB/D9/Hf/jSPCFmw6RA019MqPYRExDnFAFBQvM4c0ehZTz1fljMKySMdyiDUFi54cD98
         KHvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531p1x4avqJhNGjoJ3c5woMNNsIhoxRtOPkLDKlJxfihP/0By3zn
	1mD5xWzHovjFyCJCLrbVH9A=
X-Google-Smtp-Source: ABdhPJw4LO3WSaLqeHyqLu0LoQRIouWbVz2jla/oRCkI0+raajlvxKP8acSXmcDlNPUR+FvsD6Erkw==
X-Received: by 2002:a05:6638:1685:: with SMTP id f5mr11490139jat.132.1637137960692;
        Wed, 17 Nov 2021 00:32:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1404:: with SMTP id n4ls3566770ilo.6.gmail; Wed, 17
 Nov 2021 00:32:40 -0800 (PST)
X-Received: by 2002:a92:d706:: with SMTP id m6mr8540083iln.155.1637137960361;
        Wed, 17 Nov 2021 00:32:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637137960; cv=none;
        d=google.com; s=arc-20160816;
        b=NoAurHZnJIcTbVcrI7BcbdeqT+vVMDqmfQw5Y9ijOrgHLxHYPeDwo9rwR7GBGCaPBZ
         LokjsHEukyk6hTFoE1YHwRUxj4sm8Vtq1nr819sGMZE54VIk/GOlRoMuZxbc33VgROkx
         3DMWKltVzYykwPky7gkY4TIKs9YA/lhDSHYgJQ13+jzXrpek5wn1+WTSfwf4B0Qjtw0y
         W8hrRTmP0LaypZOGf0y0yTNsUUCpCCkY5cAQtW570CBruB/lpyxAXcZTF5hsRq/mxYRt
         JFEEBM6dRXi43H8gynbJZHSe1Q4DJGsLWRXEhrZgzCc34H6/LJHYt1tXi2N8eU/EWcXj
         XA7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=pLki4VXVNEgH7BpAr7thCy6liKqtc8dZxgXibG/LDtU=;
        b=0gGMMxfIr+D4TB/HMsBqC8HRSODnKSY3WquIfi54K4OzFN3An3xYU76YOSB/7nH3Zq
         2CGlgtFyl/Zr6NiSaiPu/83erYXRnPITfkEW6LJQIfb9EJp65Zi/ZNvDc3s58Sw7QfPC
         1HApiq/I51rwfSPdejaafE9Jui/yVRVUXe6VEavFJpGD0gVXMy5cT5GHRyKGgqgRNYfw
         r9iL2VHBZSq0OxK2+Lt/ta6S4SFEaThNR1cfIRwIMJkR3vOjCa2mM511bhkU+o+fZykr
         shYxJJzDc+iJLnVG1E30SQu7WOoFo+sXwrqtfw06I4QUws9SYDlJWGTR+5ve5SQMpro6
         K2lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.46 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-ot1-f46.google.com (mail-ot1-f46.google.com. [209.85.210.46])
        by gmr-mx.google.com with ESMTPS id a12si902967ilv.2.2021.11.17.00.32.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 00:32:40 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.46 as permitted sender) client-ip=209.85.210.46;
Received: by mail-ot1-f46.google.com with SMTP id a23-20020a9d4717000000b0056c15d6d0caso3361720otf.12
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 00:32:40 -0800 (PST)
X-Received: by 2002:a9d:61c1:: with SMTP id h1mr12212943otk.27.1637137959931;
        Wed, 17 Nov 2021 00:32:39 -0800 (PST)
Received: from mail-oo1-f42.google.com (mail-oo1-f42.google.com. [209.85.161.42])
        by smtp.gmail.com with ESMTPSA id n67sm4527234oib.42.2021.11.17.00.32.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 00:32:39 -0800 (PST)
Received: by mail-oo1-f42.google.com with SMTP id p2-20020a4adfc2000000b002c2676904fdso789565ood.13
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 00:32:39 -0800 (PST)
X-Received: by 2002:a9f:2431:: with SMTP id 46mr20823663uaq.114.1637137464301;
 Wed, 17 Nov 2021 00:24:24 -0800 (PST)
MIME-Version: 1.0
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de> <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
 <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org> <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
In-Reply-To: <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Wed, 17 Nov 2021 09:24:12 +0100
X-Gmail-Original-Message-ID: <CAMuHMdWgGz5FSidaGpp8YRRSnJfwdP4-wOkXdVx+mydXnMAXHQ@mail.gmail.com>
Message-ID: <CAMuHMdWgGz5FSidaGpp8YRRSnJfwdP4-wOkXdVx+mydXnMAXHQ@mail.gmail.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
To: Nick Terrell <terrelln@fb.com>
Cc: Randy Dunlap <rdunlap@infradead.org>, Helge Deller <deller@gmx.de>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Rob Clark <robdclark@gmail.com>, 
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>, 
	Anton Altaparmakov <anton@tuxera.com>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, 
	Sergio Paracuellos <sergio.paracuellos@gmail.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Joey Gouly <joey.gouly@arm.com>, Stan Skowronek <stan@corellium.com>, 
	Hector Martin <marcan@marcan.st>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	=?UTF-8?Q?Andr=C3=A9_Almeida?= <andrealmeid@collabora.com>, 
	Peter Zijlstra <peterz@infradead.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>, Parisc List <linux-parisc@vger.kernel.org>, 
	linux-arm-msm <linux-arm-msm@vger.kernel.org>, 
	DRI Development <dri-devel@lists.freedesktop.org>, 
	"linux-ntfs-dev@lists.sourceforge.net" <linux-ntfs-dev@lists.sourceforge.net>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>, linux-pci <linux-pci@vger.kernel.org>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.210.46
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Nick,

On Wed, Nov 17, 2021 at 3:20 AM Nick Terrell <terrelln@fb.com> wrote:
> > On Nov 16, 2021, at 6:05 PM, Randy Dunlap <rdunlap@infradead.org> wrote=
:
> > On 11/16/21 5:59 PM, Nick Terrell wrote:
> >> I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed=
 that it
> >> isn't strictly necessary to send the patches to the mailing list
> >> for bug fixes, but its already done, so I=E2=80=99ll wait and see if t=
here
> >> is any feedback.
> >
> > IMO several (or many more) people would disagree with that.
> >
> > "strictly?"  OK, it's probably possible that almost any patch
> > could be merged without being on a mailing list, but it's not
> > desirable (except in the case of "security" patches).
>
> Good to know! Thanks for the advice, I wasn=E2=80=99t really sure what
> the best practice is for sending patches to your own tree, as I
> didn't see anything about it in the maintainer guide.

All patches must be sent to public mailing lists for review.
You might get away with not doing that for a simple and trivial fix,
but be prepared to end up on people's "special" lists if you did get
it wrong.

We are Legion. We do not forgive. We do not forget ;-)

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdWgGz5FSidaGpp8YRRSnJfwdP4-wOkXdVx%2BmydXnMAXHQ%40mail.gmai=
l.com.
