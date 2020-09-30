Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGE42L5QKGQE3RAPS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 33E8827EA59
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 15:54:33 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id fx20sf824751ejb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 06:54:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601474073; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGUvN5rpRcBsegvVTuVGQ+vTW7qzZiF/kTA41OG72xBTu1b5GKrkTiG7vtf+ZC1H78
         HQMLxTJxsxLcaOtTaPRK4xZFTagszAmzU1Sl/CAyUWRAJqlSBKbwQ32vg+m5DHH9Bfrv
         edPOsPT8Zn/Ropdrc5U6yPArINQseLaOJpPDZG5xxyjytZjLWXfVjrtqtPDJvsF9AOXu
         BwzKAzinR6fDfZeBe0inRF3lwnngO7RqpU4mCMKk5AHp1HjVhtDhldJUd9Rs9O/KrX9t
         XnYGSMf02ZXfN74wEkk8VDbfIZxQ8kTi6yNwbK/RlkMzbosxidWUbCC1OlC7W8suvd7x
         gkqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=22kfHdPnu1XrddRXn4q4DCtPRr4UCQz4cPqG+dI2+G4=;
        b=Xcy32zaRC7g6+GoE8Vvh2Vcl6+YJQTLdugZwkXeqBlhBDYuboKX2Vo8Bpk4vDcqrQC
         xgzeG4WJeDbDGtVnjUD+nJNSnfVnyVbc3VVGAtKOALStDrX69ZwrIWoJjTQ1aTChkYNt
         Xc7e8nddTJXxheKvWxD+2S7M7KlNGsn05wNKxO/Ki7GhiEUuj3PqQJwwaVJ3htDQ01XR
         YyLtl7UNJbBWYgoJ71l0ACGReGRGH2yNB7Q4RkCXT85tBvVJs4B0SKMLGxaFEn42FRuU
         2i2GP9+FzxsjtZJrvbJGCfigcDcx2vFpj+73ZclG51CT4dw8BFz85pPp9/Zv79Bkj241
         3dvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iXcqO8jt;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=22kfHdPnu1XrddRXn4q4DCtPRr4UCQz4cPqG+dI2+G4=;
        b=XrElepztdfZm1vJP/oIoboifQW0QH50DRsx2ZrWU7mu4s45oZsNEs3qqM+PfTY8Dsw
         0+X8SwDekpz3fbeGWnrn1sbpOZO04FPp4IrfJunNBnuQQfEmm3R4y+/CkVykcHl4/365
         m5PCujx21xmdYLtJVz2F/u0yDSxMvJEXTbMhk2avrFKIgB4w5k097vwoCE1Hg6DVihOB
         dnCYSRTiWIoa78EGtZz6DgZs8wTxe5JkXhTEc6KNiQHKSPMj7ErJu4MVqgHcSNN6lIId
         0O27WuirnavVrIGwIS649o9gOteVS6x1/x41KBB/KrYAh5uKMOfw8R4lVnzc77V3sHXq
         G6MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=22kfHdPnu1XrddRXn4q4DCtPRr4UCQz4cPqG+dI2+G4=;
        b=qhEWO27U+5JL4KR5zr9ziJOh9Wpx+yBryAUq2YdfZPNDvgMNWjHmTdHiFCDmTmZ8o6
         hg42gRZWnWvwLB70At/FkJJuQmgUraQlmUEBbxGxVCks5LY1WVPrS/nNOQTLP8mW3JbE
         3JdjXBoEEC0gNTi7ZbboY99ImWqY1zW8Av8XvEiBNPf1itDSTAkXYrX0Sca1XyqTee+9
         w86IZPUzN3/tDNh+m7o3uxavjT8teM4hWlpfX5DuRSV2L1LkJ0ztuwjvY+oaAgSs1zSB
         WjXCJ5Q/G7UDn/0fMJbvvm8o1pK47v20P0qsvsmHRQtq1AQNonHbDNqsEmoirTRKm3zS
         XQfQ==
X-Gm-Message-State: AOAM533DvSDZ6Rz4RDbreJB/l5Ev14CmWR6sQHELz0phuv5wtZy6xUQm
	FwLpjIFA9p7/7z+P+Hh+/Mg=
X-Google-Smtp-Source: ABdhPJwdL5vKnvXtb0R+AvDsgsu+2KKuXxWbrrrA87i2L8ADIHTLeZOhw3GnndtF6aD8jUs8k1XpqA==
X-Received: by 2002:a17:906:3955:: with SMTP id g21mr2943740eje.69.1601474072869;
        Wed, 30 Sep 2020 06:54:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:387:: with SMTP id ss7ls903467ejb.5.gmail; Wed, 30
 Sep 2020 06:54:32 -0700 (PDT)
X-Received: by 2002:a17:906:5046:: with SMTP id e6mr3015331ejk.449.1601474071912;
        Wed, 30 Sep 2020 06:54:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601474071; cv=none;
        d=google.com; s=arc-20160816;
        b=ZF+bUD120fRj5xOkLMSEusZBzLB3gwRccdNCsMuCMCQQyWRORkMmOecPr2Rw88k9fn
         q+U57TQoOzsurHzLHipUAAehu1naSvzWJJqV44L/R3DXiyUjFmAERBgnPfsyzqdRvMKX
         wK5XMIAHtfbXQNSkOq/oOYnD9x4nrBmZy6MPd7HxsoMqq1yJ7uf15pH1DW2raPs9gsvu
         zP8tgtCIE4eKUTFnKk0EOw5JCNESrqarNJBIAjCgDTes0LSAmn25KIJ+WXSDjt1awCaQ
         sAKIOx+3z1jKbHaPqrZ8neLQfbLBoc16CfHPZuUnDGV8u6N43zhYT+T4c3bTwH3pN3xf
         L37w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=q8DDytpQ/TiymCD5YvwxUqIXcBVmOr1JEDKJeB/dQmA=;
        b=CndP+RfrSyTCdrDdTWUboSvKgZdhvEWdb44QF8+NtBaUjuS/2/iSqy8AQldaSxdqPu
         Ai3mZBfbGzWZX9T3MA+dBVjXhaay5dBzkKzpDzaq1PeheMjxKCmaRwFR9zjdQVSgYh8C
         9sJ8w5ok05c4xWeYOONeDo65mEROKSFPlKkwGoY9wAuzQgucW9NMm1ElvVVwnnyrnVe5
         b78Aal2Z9MjNTn0WUdYy+bD6sqQzu3kYWoLcx6gc5qAy/ojCW1nkKu+D4Ses0V7TITZn
         beR3jBZA9A7gt00yAmQpCy7sX1P2RVKr1AqkJrouGnQClll6dlMAitbrt4uwp1H4IdQ6
         kwxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iXcqO8jt;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id k6si52623eds.3.2020.09.30.06.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Sep 2020 06:54:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id e17so1811303wme.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Sep 2020 06:54:31 -0700 (PDT)
X-Received: by 2002:a1c:a593:: with SMTP id o141mr3279741wme.88.1601474071394;
 Wed, 30 Sep 2020 06:54:31 -0700 (PDT)
MIME-Version: 1.0
References: <644ba54f-20b5-5864-9c1b-e273c637834c@gmail.com>
 <CANpmjNNBGjjJyv+6QZm9hm=vQ3vHuAOTRYDs-T25X91AQxxyyw@mail.gmail.com>
 <626733c1-7e1b-6e45-69db-f4d6cc67fe97@gmail.com> <1fe27f01-d54c-6237-c91a-3731c84e9d33@gmail.com>
 <CANpmjNOQg53dAwuZd4m29vc+cdizFZA-Dgf6DEOJ_=5UR4G+UQ@mail.gmail.com>
In-Reply-To: <CANpmjNOQg53dAwuZd4m29vc+cdizFZA-Dgf6DEOJ_=5UR4G+UQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Sep 2020 15:54:19 +0200
Message-ID: <CAG_fn=XvDEyD+_sWBnXOcvWymhfCGkKwSPtbbUYnsUpSZ3Wx6Q@mail.gmail.com>
Subject: Re: [v4,01/11] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andy Lavr <andy.lavr@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iXcqO8jt;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
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

Can you please also share your config? Thanks!

On Wed, Sep 30, 2020 at 3:39 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 30 Sep 2020 at 15:31, Andy Lavr <andy.lavr@gmail.com> wrote:
> >
> > Hey,
> >
> >
> > So, build linux-next 20200929 + patch KFENCE  (Clang 12 + LTO + IAS)
> >
> >
> > If CONFIG_SLUB=3Dy then kernel TRAP, TRAP... HALTED no write log... (
> >
> >
> > If CONFIG_SLAB=3Dy then kernel boot fine, if start kde then TRAP and HA=
LTED.
> >
> >
> > Attached all log.
>
> Nice, thanks for testing!
>
> Does this also happen with Clang 11 or GCC 10? I know Clang 12 caused
> some inexplicable problems for me a couple weeks ago, and switching
> compiler solved it.
>
> Thanks,
> -- Marco
>
> > 29.09.2020 17:48, Andy Lavr =D0=BF=D0=B8=D1=88=D0=B5=D1=82:
> > >
> > > Thanks, I understand. I will build linux-next + KFENCE and will repor=
t
> > > the result.
> > >
> > >
> > > 29.09.2020 17:30, Marco Elver =D0=BF=D0=B8=D1=88=D0=B5=D1=82:
> > >> [+Cc kasan-dev, Alexander]
> > >>
> > >> On Tue, 29 Sep 2020 at 19:22, Andy Lavr <andy.lavr@gmail.com> wrote:
> > >>> Hey,
> > >>>
> > >>>
> > >>> https://lore.kernel.org/patchwork/patch/1314588/
> > >>>
> > >>> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git=
/commit/?id=3D6ba0efa46047936afa81460489cfd24bc95dd863
> > >>>
> > >>>
> > >>>
> > >>> And how will this work together?
> > >> KFENCE is for heap memory only. We do not touch the stack or rely on
> > >> any of the features mentioned in that commit.
> > >>
> > >> Or was it something else?
> > >>
> > >> Thanks,
> > >> -- Marco
> > >



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
kasan-dev/CAG_fn%3DXvDEyD%2B_sWBnXOcvWymhfCGkKwSPtbbUYnsUpSZ3Wx6Q%40mail.gm=
ail.com.
