Return-Path: <kasan-dev+bncBDEKVJM7XAHRBU7BUKBAMGQEBS6VJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A8148333BA3
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 12:43:16 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id j194sf5735609lfj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 03:43:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615376596; cv=pass;
        d=google.com; s=arc-20160816;
        b=grapgReXsPrtHLEwkCm252zYoTDvtFCkRAFcSX+cY9irn5Lc2nW48wzWo8GEsbzZKn
         Oan4DR1TgoCgFmJFIDUHwbr2apS82W0zM/gBwuSaEJLgbsxu80IDF37WYlGp9Bp/2aTK
         F3K5brl5t4HqB2fyN/1BQ2SLwJHBgWh/aINCx2xOip+wcEX9fVE5JNLBWGVBFvcbGnpq
         DXHcJBZ1KOKQZ5mbyla3PLWISQi3ZDs1R0iY/nzYUtMQrzIoC0FVbJoVjC5GPmKPDVt0
         7TkWD7Us9wJXl0Flk5x7szr+3DtNOh+5fPCt1YkdLz2vJajFynHtA30vs2ThW1Lgd7pj
         ljkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=Alv/PSRiPx9d26asEAodhkJeTpovsN/ol4Xwgyn+Ms0=;
        b=Bb9DWwYiggX8FPcGsDZ9OBFd6ADF4QKQiQlolnTsqOO9rNhcu8Dw2+K10zsvp9mAwr
         hdmdHJ+1lG47m+sPCAsgt25/1jwifom0jSN3gPv8XxNWs5BKF0Hb/GaKBY4OrhEPZcaJ
         +uifSLGHbOZUHQNJobf8oyRaFPPev0wVRDfdvBzgo3m1Mx2rUQkSz7wPX4SvZc1fWHqO
         uP/gGGzDPADjxxCHVigvPTQ8mqODgGg+R16BQ77zCyZ/mvfI8WzE9ZW/yRw//JhFoNUZ
         n9IrYx0xdVB3uQcOX85aDuM2QN1gf4kKwop81zNh9NWHAsM1e7safGuqUiiBgehDh2U5
         XIlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Alv/PSRiPx9d26asEAodhkJeTpovsN/ol4Xwgyn+Ms0=;
        b=Hea6ASXr22GyMks3EPlIVQiB571ji1tKvOBeEmqJLDlfoHv96zRvX+kZsVeAxsIkIR
         Xue2x0EyFndhgHlcinvgLDxOsYeM26y952Us5NfyfcUMnA2bUV69V4CcdswboWo9Qbyy
         9NEinljvzi3g9LjMnxUP1ere1+J+UXNuWK37Q2Ij6gWVbRkhAal+Dl5838kBeTY0nB3a
         Jotlrqvr406vTjMMKSs/1KqjZzG8tmHGXkdDFcTxq0uEV3dShng/NRCGpq54pMOjVUUe
         kurDWFmdy4z7ao9h1XyGP95n1cg9qgKd8f7V5vNkvJkyDoJCi8Q0DNJfn+GpuzRaT0CK
         LFtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Alv/PSRiPx9d26asEAodhkJeTpovsN/ol4Xwgyn+Ms0=;
        b=G62V/RDgMbZtQBTchu/KRoUbhBJzfV00SegGVzDBaRxNuNoPqV5T4hIg0XKXc6F1vG
         G1qrJRgPdxTbzCZyNh3X0IGwfnqnxG6CFW/FcrW0G4nYVwUiEytBh+SxTivNK+gMmysz
         TLgHwI5t2A6nI4Y9/v+AnIfuYMMsQhvroDTCEoFW6Tf41fvr9mVYhsboayP42ISKno0C
         7kOGL4StT/oISk8B7sccMP7JGGLP16jpdhQukCVcPaF3DMl/sSknEk6MHWS8LcK0oTOx
         B+hfRPdPbumeEvry2BP6/n2umSE9oqHQuKOkbaAuiLkFVxaiaryVkQ81nKVuz+2g7pLE
         nT8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mGOVpMI601Ceo56DJTx0+AW05iX051xh0B5dhishDnZlaOB1P
	Jz8RkjVHOkzXmwYOoDpzumY=
X-Google-Smtp-Source: ABdhPJz02OzVoZeoxD/qjPDARt4pWIYXLqY8UE5R6eq4yp1miWUT+nP5GGIufyXNU36ClXt4Gn3aSw==
X-Received: by 2002:ac2:4a7c:: with SMTP id q28mr1872790lfp.154.1615376596210;
        Wed, 10 Mar 2021 03:43:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1261771lfu.3.gmail; Wed,
 10 Mar 2021 03:43:15 -0800 (PST)
X-Received: by 2002:a05:6512:398d:: with SMTP id j13mr1732862lfu.41.1615376595177;
        Wed, 10 Mar 2021 03:43:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615376595; cv=none;
        d=google.com; s=arc-20160816;
        b=zdPcvadD3t/NN1Hpk2fRgaD62I2djAgYRpis1wOVqpKrsPLEV1TmGhzfDUzpvhXfTQ
         lQfD0c94FoZAKndDi04k0W35WgUxq8FWZNvCwTqUJQrWbb1BhNXkezQl8gqIgUdFrvaF
         FyCZPXB3Q6mmliIID0OFPi5rI6F68pLg6qqkMaG7c6zPoAn+7+C+kDLm5A4/GGY0+3ag
         KnxM50zxvev8EwoMRtn2WuDjIa4bbIpbv4XRsPgaIli5BbUlkayBMNFZ4AAJVxN163/p
         IHn26CZrogXGyfMZtFxECVRXIWs6jbwRFj4/wbGVEDsMEVu9SszpJG9FiaxAx5WheZHH
         qREw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=heF50RSNOmdQFoeHNZWVqjhGzZ0sh98hvrUWLPihqWo=;
        b=Ytas7o9QVQLh6lCBwePMSw0naVFf4PJMPA9Zde2qdF/zBKQRPkfw4olZlZqYg7DLGW
         RMflPw73HhNqHitbWgOT0pr01y+KMJ6F8kKvyfD9riMueIqMZS40nyxS0STc3JN539cu
         LvgLKhO6RtHtTLAPKAPwBtf6tY8PrGhejU7Bd33vC1aXFAgMQhhYAHng+4GCuB3yhaB/
         vv7dTn/f7z1NezuFTlyxttvQpzw4yWHrIGpkj4HtM0A3UyX2qb7NDmyhAEhE1DhBgF2D
         FWgtvuTYH63/MbtcHpuwsN1AQZ+LyHuNfmMy1K50pTyLgTP8hh4XDsLHXqC959KZ7cmU
         TrkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.73])
        by gmr-mx.google.com with ESMTPS id 63si464814lfd.1.2021.03.10.03.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Mar 2021 03:43:15 -0800 (PST)
Received-SPF: neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.73;
Received: from mail-oi1-f182.google.com ([209.85.167.182]) by
 mrelayeu.kundenserver.de (mreue109 [213.165.67.113]) with ESMTPSA (Nemesis)
 id 1MY60J-1lElEl0nRl-00YQj6 for <kasan-dev@googlegroups.com>; Wed, 10 Mar
 2021 12:43:14 +0100
Received: by mail-oi1-f182.google.com with SMTP id u6so11409484oic.2
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 03:43:13 -0800 (PST)
X-Received: by 2002:a05:6808:3d9:: with SMTP id o25mr2139659oie.4.1615376592865;
 Wed, 10 Mar 2021 03:43:12 -0800 (PST)
MIME-Version: 1.0
References: <20210225080453.1314-1-alex@ghiti.fr> <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com> <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
In-Reply-To: <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 10 Mar 2021 12:42:56 +0100
X-Gmail-Original-Message-ID: <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
Message-ID: <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Alex Ghiti <alex@ghiti.fr>
Cc: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linus Walleij <linus.walleij@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:MvKCVZ93uudB/SUGjsYfhU3UmpWgAZjRApEbbojCQGH2Xbn9KxF
 9RA30dIJWm+OyjVBNpqOTJpQ1sMucqgxoIAwnHZvq3CqOPzQUlm3VT84pnZfYrMUBbOo+rN
 VQ4Vg3fbhhK/Bssq1MzsxXeShMfM2jjXDIm32qw6L7Y2XMs0QQSic+bLPPqI78kgwP8HXaH
 L5vEjdhyuLp/NGSS0yN3w==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:uYdxYcGThOk=:CyAh7mdPlo+o2wimcQjdYf
 Qn+qiekjWR4B2wnAR8/FdevKPehvEJE2E+UqwqxNyz7kcaZFacv54DYSnGJe3zGi9lZgWM6SQ
 ZkLbfFhzealBHvfZgnAjIoUFsZToJHHQOL586FC/pynyJLLB5vgpCkb//+P2M3/CpHlM3b++K
 s8LFG3NaaOMNDWF5qR/Mnwe+KaemBBNnJ1c1MWpGPWLPWVGxWSCWu0QVr7AQmPOHHfxovOv9Z
 LITiF6uLjLots0QrJctMfHVpM3V2/aO/W/0VdZb1HZ4yFeUtvXdAkI8kAhH9p24S5bsu+uXlx
 ELg3chrCaOoyNx35yVt3nY3vyB0KLTCbNOKSa2WEdNqAA9CDha+kVbYnqntx7wgVjVP1iD/jM
 QCf7vtAfJVg37Jy2ejL5ueY+IdbgViy25QADQH6+44FHjl/0JnxiUvdb/Uh/pnUCiaA/X2VQc
 thwqLHUGDDJ+Wt1TI2GZrNPPIt/gOESf2HmWu9ls4MZkEmk/LXcRb5MiFpK+qK+hGKWETTEnp
 9lhWsAbScjfTPda+eLhbODErB3V3XwUV0ohl3k0AQlI7rS6jwOL6l1kZ3UR+KdKIw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.73 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Thu, Feb 25, 2021 at 12:56 PM Alex Ghiti <alex@ghiti.fr> wrote:
>
> Le 2/25/21 =C3=A0 5:34 AM, David Hildenbrand a =C3=A9crit :
> >                   |            |                  |         |> +
> > ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
> >> +   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixma=
p
> >> +   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI i=
o
> >> +   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemm=
ap
> >> +   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB |
> >> vmalloc/ioremap space
> >> +   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB |
> >> direct mapping of all physical memory
> >
> > ^ So you could never ever have more than 126 GB, correct?
> >
> > I assume that's nothing new.
> >
>
> Before this patch, the limit was 128GB, so in my sense, there is nothing
> new. If ever we want to increase that limit, we'll just have to lower
> PAGE_OFFSET, there is still some unused virtual addresses after kasan
> for example.

Linus Walleij is looking into changing the arm32 code to have the kernel
direct map inside of the vmalloc area, which would be another place
that you could use here. It would be nice to not have too many different
ways of doing this, but I'm not sure how hard it would be to rework your
code, or if there are any downsides of doing this.

        Arnd

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU%3Dh4g%40mail.gmai=
l.com.
