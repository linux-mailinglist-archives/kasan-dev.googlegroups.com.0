Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNHAUTDAMGQEJBG57MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id EC439B59267
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:39:02 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-3332e6e2f3bsf1081714fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:39:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758015541; cv=pass;
        d=google.com; s=arc-20240605;
        b=LhFjnMSyfXoGkNgWXZA7qjwI4MvH85nq2YnyacSfbiKZ9K3JtOJyx25szmUGeNSjtG
         ko8dQwj+YJ1JwybTC/wOXDCmM9C1nEI/vhGlEEjADRIW/ofd9zTs6fY7w7lf9uLBfT+q
         Y9UMjIyLHW06cI1hu4WNdUY5/TBiO6cdpH29yQLsiFTtQZuFmVjxlfYGTOy7bWJPXtyA
         4gDMcSkX//oTmql1ZDzb5Ek+y4aCmNbvQUWMFB7RBLpSk5WjSeAsUK2/xHS2RdboZYBh
         t4w+77LVacnUXhk8Zda5SeZj7cEstBM/zHhqAWJwZKeQVhE7laNcCGZUapsVLIQFom/6
         thPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q13o/DY1FlWKHqvBq9Zb/eyxrn/g/KdWdUMokDH3tZY=;
        fh=aV11zKmCNbnIG86be8NaVOKCi4YR5G+8GbS00dZ9Bjc=;
        b=ER19Q9UJ6l0B04V7qSdjY+AQth+tPn/JahG1592ylAQwlH04zRkCNPQCoG4pUrkAka
         deXSe/OXZ3bBTrCJ7sqcDCBTuK3lR0sGXrSg3bMiBObhXb1uBMiyw02trBDPHNZYuRAa
         o9Y+vs3WZTwNIiIuvMP8Y9vXb04Pd/rNyYZicDFjfXYDL5v6HjNdGD2GaiNqu4HIEXiy
         E+GRnMxy3ZFLbAXI4hJBodz4JAGjdqERv/8DlTriKDDCh06KXo4Hf9ZvgT42yllcBIbd
         ZfXZ31FECbXhNYTyMYnt/OudIcHwkpVZo0zltF+ps8aWvpts8pPQP7/wynjYs78ayz3/
         ExsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BGN2hCf5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758015541; x=1758620341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q13o/DY1FlWKHqvBq9Zb/eyxrn/g/KdWdUMokDH3tZY=;
        b=v8CTfnVHh9gr4TYfAOErNuw+t0WWM961d5YA1Wmzf8uVmkaFqmdgfgoPLRMDbH7Xdy
         j8Da/MR9uTDKYhYrkVHgWLu+YhTovfPp31jP/C3ufMqEY9EBoU2sf/6nq09Y9AGYiKR9
         L99DVxwSqmdGDuOxixtfBCCy84YUpDMMYJP7YEjlS/lL262LdrnOpuyHXxVGJBQ441EF
         D7L4apRHLbDQoXW5jw5Gxpm3CW+PBwiuL2yHgg81oPCQ6IC83pFUUWqrYh9R0wwkZRiZ
         xLY6i2H7OlM3NuiPilDbBNs3Souf2aIrJciSdSkAnQIbPZW//2CPHf9Sh91HyZGEeIoo
         BdHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758015541; x=1758620341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=q13o/DY1FlWKHqvBq9Zb/eyxrn/g/KdWdUMokDH3tZY=;
        b=wsF1XIB2vuAorZpKNM5wkIcK+NpZjxSMJd+UnugFxeSifmowMYHeLmIpDVPu9KTwJb
         N+lZck/ePdWZ5gt4Goy9O5Ex+TJ68+zk7yaNTaBHx3SSmvJ31qhW6PjVwETZoMKK+/+6
         3ZVl8dpb5BwledF/jaNFr9migCrbMwq0RWJWb7uioINHazG4AIOwM7TVz0DePO0v/n3v
         ZMzuD1Wbxdm+p2FcqRNLuPi5UIhYY8KTABP+zsom7W+adXNqsvPvARtbLcM+2HWzW/ei
         0k/xyr4Wal7SeT1OUf/81m5Py0B7mjIm4ApnQO1bYIQv5d89XVbQ6wpO1++C7pCbEXE7
         yN/Q==
X-Forwarded-Encrypted: i=2; AJvYcCW5jF78+3RXO3lZGsPGenBwaozbUugF9eu3WAP06cqesBdbOesdV8bDI+yTlznwt9MCWe9JKg==@lfdr.de
X-Gm-Message-State: AOJu0YyXGqfuPXeCCCrXWfk5i+kdVi+3WRV+ZY7Adm3bYdTWiHt/NCcJ
	I4LcWz7wEbjB2MtNUJioChl6gEfdJ30RKGVzTMAZVHD+CsEk8IYcE8lY
X-Google-Smtp-Source: AGHT+IEqWTsOg1syp5qTSp9wrZtmAdykReyntd4HFNL4IK67S0Lky6uzXYDDK4hNwIDXSdqEwvPPAg==
X-Received: by 2002:a05:6870:d185:b0:315:2bda:851d with SMTP id 586e51a60fabf-3345473f2a6mr879390fac.22.1758015541283;
        Tue, 16 Sep 2025 02:39:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfBPm12wtuc217Ht7G4bjLNd3wN7mZlWWN4LR8Vx8y8yA==
Received: by 2002:a05:6870:2e83:b0:32b:b1dc:4a51 with SMTP id
 586e51a60fabf-32d021d57a1ls1443019fac.0.-pod-prod-00-us; Tue, 16 Sep 2025
 02:39:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUS8g9cOpBbNorJtgxlvs0FJ5o59XLhkrqgjHl3a48Yve5OCkbayhywADBhEADk2zuf/2YV0VWTKZk=@googlegroups.com
X-Received: by 2002:a05:6870:5249:b0:2d5:2dfd:e11c with SMTP id 586e51a60fabf-33452280314mr786375fac.7.1758015540300;
        Tue, 16 Sep 2025 02:39:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758015540; cv=none;
        d=google.com; s=arc-20240605;
        b=ky57RZgPn26KIMj2ujOsUDuNEvM0vZqi6pzupzo3t8vN69H4duZHM3TMRic7iNGh5E
         7IgNnG0K8v6ca0W2WWL+VeoVs71dMWMIjdN6z5JVEPqj/DWFN9LUEnytgW7WT9763NN/
         0Iux1DGkA/G0FdvSDg8+D+KxCPBfyouA1wv/cfS3gjYRaQ5cdRciZNAFe4+WDUIWQnZz
         FZGx9V58rHgXtsksoGe1aK8xOQHT/BVAQ5rBlRRjzTFs3efeu33l4OF7+hmX6mkXhynf
         MhgF1m5Jcl2F6VFWDlyaex++Ho9O7DiEW1fLdyp3hv/ctOzFyQBouQq15P8bLpj0X8yF
         jPng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UMmgtmyqL3pSVlf5uAfBg8YLZnU4eepFksA8tWxfUtY=;
        fh=uaNxH9G7SW7Anjh6MFp35kt0UPijPDmCNWxRMBUj8gQ=;
        b=WnbWZPbCq8TruOO5AtDNMcI2x//JmRXcl9fSpou/xKcFtiPP7rE+DyF4WP+b1MoOPr
         7tDerRuS+7NDp43aMptgbtZLjHetPQ4MJdhM3cR3J8kM4QrxgWrQ82HnmEfO0o+EvlkV
         PsIgIpBNP0ZfM/QnXbuhGNEFr7KpELCa9iNU7SLdpQbiyt4eLTD2cgtPoxXrXiHBlzW9
         9xhofmk1Wy6P1HOFkHzM2HiAwIpr8nCRS3gD2lm1+wIpYsxtUl3UQ3PJ3CuauMjTA1cU
         wz2S0sRHbZUe4Itncg2+KnQfw78uxEN4AwBwk1oJUbi14W4OI/0xvwVHCAV9PPTTQcSt
         ShzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BGN2hCf5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-32d3515f633si639990fac.4.2025.09.16.02.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:39:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id af79cd13be357-82884bb66d6so277157985a.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:39:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwv2hNkQJzqbUg30ocX4fuNPDlimcJ40f8zAmPb95WvYIR1jtuG+fWLrbPSWXedtAOpjU2ffCOKY8=@googlegroups.com
X-Gm-Gg: ASbGncs3tmn3JAOXYhEHb+XybmOH0bGrDQh0uFYfHn3IecmqtP46KPZVrY+4HzXBeZU
	83sdyZx0GaJaw6EaF/vQc0cQfcitHsbLXaq9c/gCpgTSEWQL3XTQxLwtUrJc7QVVWK67OPuQwil
	YJbiCEwBcR9FlWnqAtXR0j9PjyyphPMtOZK1Y+Trs+hZW6idHEerv0OSTXXPANlRwzIwHMPxJ1A
	e+jTeYp23fWkIb2YKGrpOxLXH4EAOy1NN8jz1JyrBKCFtl9Ftdlg3c=
X-Received: by 2002:a05:620a:17a8:b0:805:d2df:54b2 with SMTP id
 af79cd13be357-82b9be9cb55mr140912985a.6.1758015539317; Tue, 16 Sep 2025
 02:38:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-11-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-11-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 11:38:22 +0200
X-Gm-Features: AS18NWDPNjOn1tpd4dh2PjA_D9sETIOVojzQySxiayXszkU2oRRijwgocF7cJt0
Message-ID: <CAG_fn=U-pYHi7R3Bq0zd_n7uzaw1vkL1RM=oyF1Or1Ovx_q1Tw@mail.gmail.com>
Subject: Re: [PATCH v1 10/10] MAINTAINERS: add maintainer information for KFuzzTest
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BGN2hCf5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as
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

On Tue, Sep 16, 2025 at 11:01=E2=80=AFAM Ethan Graham
<ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add myself as maintainer and Alexander Potapenko as reviewer for
> KFuzzTest.

This patch is missing your Signed-off-by: tag.

Otherwise:

Acked-by: Alexander Potapenko <glider@google.com>
> ---
>  MAINTAINERS | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 6dcfbd11efef..14972e3e9d6a 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13641,6 +13641,14 @@ F:     include/linux/kfifo.h
>  F:     lib/kfifo.c
>  F:     samples/kfifo/
>
> +KFUZZTEST
> +M:  Ethan Graham <ethan.w.s.graham@gmail.com>
> +R:  Alexander Potapenko <glider@google.com>
> +F:  include/linux/kfuzztest.h
> +F:  lib/kfuzztest/
> +F:  Documentation/dev-tools/kfuzztest.rst
> +F:  tools/kfuzztest-bridge/
> +
>  KGDB / KDB /debug_core
>  M:     Jason Wessel <jason.wessel@windriver.com>
>  M:     Daniel Thompson <danielt@kernel.org>
> --
> 2.51.0.384.g4c02a37b29-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU-pYHi7R3Bq0zd_n7uzaw1vkL1RM%3DoyF1Or1Ovx_q1Tw%40mail.gmail.com.
