Return-Path: <kasan-dev+bncBDE6RCFOWIARBGPJ3GTAMGQETQ5W6EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 31C80779673
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 19:49:15 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-40fedf8472bsf27174721cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 10:49:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691776154; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAZ2VljKyUhx5PEas6rbRXWDfCfwfGR3Vd6HscwPwj6DaQI1zLXxShatZnGITr0JjY
         V9YX/xHhNlEndyqfuV/LTTDAjEefrDU9qzWS/qs5Y9f/I66k0INvQp5s6MYY41lT6lQW
         d7eyyy1BNn3GAzCe9h2Db5wU7Cf/cSG75SmRzrqYmIndzN4y2HUbZpspSjRWlRD+mRkt
         irB+0oOpd0GU6QfZ7lkiGVVSSrQHa/zKcJVubppHZMCzFqRHTdbATZSNCpOTF9bfPRAg
         chBA9VtlAi93CuV07msUS7VgBuA0UyNEs0HXjlwagiR1973m1GPx4PypORf7WUYjOQuf
         9csw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=/1jXqmqFJEr60V8ws5JXknzKDp5HSX1NEFx+bp6yVHU=;
        fh=zILISoE7VGbbu3UWaxFKiQ0mR6vgTFPbNdpozRo0CFI=;
        b=jAbDRwMSYwq7TsbrBpjf9n71O3sF7GqOxfTQ9grl9qPIHvP+a6UbpAYn94eX1bz/c/
         V40t4JMLy5jnZD7pNyw1qKcgukeAxBzO6puGVj29j1BVSe7Pr4Wsi5jA/GfxYDbdzdDW
         JYnRRY5x177DuSBZbO9U7oGy9CxiuXJ4S6yQQee6yR2FjRq7nTHNqxjZl0m3wBqvq9kU
         Wm3h0uIwtD8OJcbp9ljuJ3U/kqJ4NGHA1ryPD9MDCP/kiF8PASxoVEpFGb5WAnW32jm7
         fdwGrhswwlRFch3Sx2Pnqt0VrEEk1OaFg70eef9g+6V+bTaIlJIRyKPyFq6NZC/8Nml0
         tg5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Q1ZYrwwh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691776154; x=1692380954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/1jXqmqFJEr60V8ws5JXknzKDp5HSX1NEFx+bp6yVHU=;
        b=MtX8yZrtPDAuAAmmd7Q00jLNYfB838M5GT8+IafkiNUhnIFZphTG6rjCNa//WHpcxk
         4RG8t/8otnrTbRERah6QxcarpwIm2U9vByCGxGaydK5wSD8HUvhWU7SLBaB32s9vLAHd
         /+EDYniGSaFrxCJkao6lUr9ZqfubxwLjbGVOqOXPQC/oDUW20RXtl5J8OFA++aXWAMVJ
         eTNsmR2YjfIsOQnfZ8dTSJWavMYILsxxu76Y2jOMIaVTKnQTsIDY/O+lObqE7mH/05bt
         2UQveHb++u8PS2OmjqeEdtjdItl42R2b+Y3S2mqBXjVa6E0F9wWsMctMBE+C5gaJSXeG
         8BEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691776154; x=1692380954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/1jXqmqFJEr60V8ws5JXknzKDp5HSX1NEFx+bp6yVHU=;
        b=ZeR5fPzkp9Iv5Hm1uhxshqvlbrJJsDCXcjOROCU/sDYLD4Q5GVWcUY6E52FYHajV1c
         0CKMIwXEqgbJDvoFWIjg//pCZdSlkZ4IPNJUuN5+04ofrt2grQQT2+TDuwlVg/zSlPyP
         U4K/Mm//N3Ad84Y/17KZe64EcRhgkHgJUbYo/ZJro5wQwomjDiMwfCQ4djkGbt48xaTV
         QXdkcN6jJ46hxYJqf832NRW2LmwrbWxWG8kV846hDlJkvtHwA9GNFkGCff+zgL2fjtto
         uFbBT6ZpMk5bBrvfKjv9RiSG6a4jmuaNaYZNu39XjVqav8Ro+xWA1tO8K+dxzKFI8UtK
         XufA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyl12bbAHN7O36aTzWBfIBI+4N7orWx5fN5425oNeWaQX20FPXq
	lGsptjdz5Dr4bICGd3v271w=
X-Google-Smtp-Source: AGHT+IECEQJIMT2ZpoVfJqf72abKQztg6gKRFwuoZzYXOx91HEJ/hKQy6Q6XM7vtfK26DhD3aMWxYw==
X-Received: by 2002:a05:622a:1194:b0:40c:82f:b66c with SMTP id m20-20020a05622a119400b0040c082fb66cmr3443473qtk.34.1691776153727;
        Fri, 11 Aug 2023 10:49:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4555:0:b0:403:99fb:6d61 with SMTP id z21-20020ac84555000000b0040399fb6d61ls2702090qtn.0.-pod-prod-02-us;
 Fri, 11 Aug 2023 10:49:13 -0700 (PDT)
X-Received: by 2002:a05:622a:11d2:b0:405:46e5:be3a with SMTP id n18-20020a05622a11d200b0040546e5be3amr3975136qtk.49.1691776152904;
        Fri, 11 Aug 2023 10:49:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691776152; cv=none;
        d=google.com; s=arc-20160816;
        b=zlGtuvbSXRLw9659Qr4KdGLb3OjDRjWy/dUn4XjyFoDAO1g392NygiRHcxABYxtkKd
         QPByBSb4TBB/IJL0tCzkTAb83rpp68/HBH5SdbECch5UrYI720adwgeNpz0Wk89cuiBQ
         whqK+7pg8zX1ua61QG1VXBiaC863gH6oNtyW7C5RRXL24Ls1+1EsAKDikVNAnS0m5xDA
         mZTDEdlGCFS9TvzxEyOatmaJZWwYxuGGrWNo1flCyItCpOWf2wE1vDK4pQ1+uOmz2oJI
         nODpEuEUVpgqgnYuelesn5bkT/loKeIN4cHet2D4XyfarX9H+TZ81oh9sdmQEDr0o93d
         Qm/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IUwS78/plVVa6OoEj+AWgYgZJxdiiaMtOa1TwsZ9DQw=;
        fh=zILISoE7VGbbu3UWaxFKiQ0mR6vgTFPbNdpozRo0CFI=;
        b=qvNDT8ylc8Gfkm11vnBID5mu6NzKXwT7RxADPR951GZZy63yqiI45SNj4jr/W/RnoF
         0Ymxj062Ey4nLqjRx+/P/tD2XQjvdL9eiLXVkZTZ73b2M2DmlN6Mg7x/dfoiPV3U0E1C
         OhEesPedIipamh6Q9v7L1JcrSkiG7ySCCAQ4bzizEKyBpW63gWQqicG22XZy0EtXyrpq
         Oy5vI3QYGB2HPE5Sc6DJDC6Nm9T2HeMSIveVEU8SWu0qXIiJYfKGS97KnLhFM8XWSsX0
         /LzEwEvClMPw6R/9jhJV5ePbgbVDkAYXmkFGtIxaOh6OdU6oKuL59scYFZMnfKo8yUqU
         um1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Q1ZYrwwh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id ck4-20020a05622a230400b0040fda65c1e1si655089qtb.3.2023.08.11.10.49.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 10:49:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 3f1490d57ef6-d4364cf8be3so2118395276.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 10:49:12 -0700 (PDT)
X-Received: by 2002:a25:e910:0:b0:c60:982f:680c with SMTP id
 n16-20020a25e910000000b00c60982f680cmr2199874ybd.63.1691776152522; Fri, 11
 Aug 2023 10:49:12 -0700 (PDT)
MIME-Version: 1.0
References: <20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org> <ZNY7PvtP0jI1/xF1@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
In-Reply-To: <ZNY7PvtP0jI1/xF1@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 11 Aug 2023 19:49:01 +0200
Message-ID: <CACRpkda2H_Ls7FT-GPkM2HLci0rLomwcP+Y5e7CJgXtT2NxJqA@mail.gmail.com>
Subject: Re: [PATCH] s390/mm: Make virt_to_pfn() a static inline
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Gerald Schaefer <gerald.schaefer@linux.ibm.com>, 
	Vineeth Vijayan <vneethv@linux.ibm.com>, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Q1ZYrwwh;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, Aug 11, 2023 at 3:44=E2=80=AFPM Alexander Gordeev
<agordeev@linux.ibm.com> wrote:

> Funnily enough, except drivers/s390/char/vmcp.c none of affected
> code pieces below is an offender. But anyway, to me it looks like
> a nice improvement.

I'm puzzled, vmcp.c is a char * so actually not an offender
(I am trying to push a version without casting to the compile farm),
the rest are unsigned long passed to the function which now
(after my change) has const void * as argument?

Example:

> > @@ -90,7 +90,7 @@ static long cmm_alloc_pages(long nr, long *counter,

unsigned long addr;

> > +             diag10_range(virt_to_pfn((void *)addr), 1);

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkda2H_Ls7FT-GPkM2HLci0rLomwcP%2BY5e7CJgXtT2NxJqA%40mail.gmai=
l.com.
