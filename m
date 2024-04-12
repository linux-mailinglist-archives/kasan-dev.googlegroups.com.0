Return-Path: <kasan-dev+bncBDE6RCFOWIARBPXF4OYAMGQEZFMZBZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 131F08A296E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 10:37:20 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4345ca45777sf118801cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 01:37:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712911039; cv=pass;
        d=google.com; s=arc-20160816;
        b=QNIGVTFQr3Sdv3ER89s6L/She3o8BGy/Veeh2ZLrg0FAXwI7N8hyD3ux0AvEGwmHrN
         DstjqdH+mNVUXaFjE34f0yAzt7y6h4LU8aJDZWY8/MD4KB4DXPrb83hyZDZtBfr1OWZa
         vC7GrGPtPjLZHgDBrux/77RKwdPfksHxbbiw4HD+dyyFd1p/t4kyseWa7IME051K01Lg
         hWjc1rkNSvtuXeTrxLRwHqbgN9oaC766Nw4lrVARY10JY63QSWNbv8fRy3xzN9Ct6xL7
         DJbPxWKDcG04kSVC3hRglJWJmdtkD2HRGOaOSHX6kB826h0pz5tmFJ3VSQzWzMwfoN1v
         N2/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=8tkS4s5yw+Ob2HtvhXNEyd08nhOHsoBGfn9JlJuqoqg=;
        fh=uqwhGKN1uoCh53dehphngh5ywQZrJ9jwA/d6v0pHsqU=;
        b=FYXCAmHHjmRA65mulYm6MUjq7OPDZ4yIQteOwZFh0r3FlshtntZu5+VEMmPXNbfM2k
         4F+wFPJdEWDtNtcP55xU7ZFH3HODSzxrz6Ry0dIIt8mZSjdrICs+aElaIJjNxXnBrVxs
         +9F/f9xQg46Y8R89GvqrMwP3z1TTsTH8T6Lau8voMcCmSaAicjQO3c8wOnf1HrDa30gl
         +r92wumStfs3wqBi7sxsuOsTl88TAesdS9fJ0lnlKmjflGSz3uAxh/w4k8SduVX9WFBt
         BNWAsKeiBcw3soTA53gCpllFcVTU4GFi32jk02maiLE2nFvyCAZZjgLF037VuD9mOFee
         QEhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=u8a+QHqq;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712911039; x=1713515839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8tkS4s5yw+Ob2HtvhXNEyd08nhOHsoBGfn9JlJuqoqg=;
        b=esYoHpgUUpnd29yesOxnmLYvO6qbBF3OPfz0TR58gBFliqqaqOxX4hrKdPlphQVNie
         SLXp46XLqauNS4bT9QhY2fZ7Cxv7oSdSAwrs1KoR6SHsUcriThTTGp7RsdHECryvly50
         3nWltzbdm62IUN8rf7elHmvmaysE7F9dozO+Q8XhLi+5bcscr/XwqkbOTLyTqhvJt+mW
         Ip00maQMDrUWHQiiPNy4Pfm2+0LfXEqCRgFyFVhkjgWAbxxOdKs0gt6993BZSoWaBUoc
         fTD0WwAd2t68MKFhb+xlpVqnnLu6l8gqif0DIgcCV7jknnZNAAgL/yLGPkEEYwwxWAPn
         FAEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712911039; x=1713515839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8tkS4s5yw+Ob2HtvhXNEyd08nhOHsoBGfn9JlJuqoqg=;
        b=xAKQGuNCxGFM4cTgTyj8sM8x5oquk4/g9s8nDKe7OzZ7UdH67o1D2+sQmQddmP1MAP
         dhEy0rzpDwhq8Rdd4neWyuP9JvdDk5rWvSIiELI2+A7qdW8zyMa0/TDb1yQycZc+b8IK
         WF2+FPQ9vY6fuZU/TSWfJkbyI9MgjiDIGMQA2Ruwtv8fOxPifkPKxG6nijiZNQ89twsZ
         z3bkup76JzMCvun3ZJVQCH4ZFz0GWdoJQXUNmz9UL7dbfj6pd9LUfQ80QwTpg7B2mwKq
         8mikQxdgZh5L7409xT2ojqHzofTZwhnTqX8g54UdQb90uFwN4rqdAeuRulk0qAoygG8Y
         oEhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0BmosO7aqeEr8o9hww50ieih9JcIvAd8s0Zbb/hy4exOrG5Z7MvViPjXZsFVG7ZpoVIgTb3zLaC4hZULrJd13b+E5V4bJ1w==
X-Gm-Message-State: AOJu0YxgYe+WHeEpioeWZYKIlng7W7RoJAf8yKfrnQTXAG1jIzNwCj4f
	CylOGoOZMmFYDf9qkDvH3Dss0QKzVpewSwpuGbvPus6C45z7UHOT
X-Google-Smtp-Source: AGHT+IHD/RnD7IJRnNlb8wdm2rSZvcBOrSqEUyG+PQF0dVWKJZJQBQnivOf17cAOwy1nBqkt3akc8A==
X-Received: by 2002:a05:622a:4c12:b0:432:b544:c38c with SMTP id ey18-20020a05622a4c1200b00432b544c38cmr145727qtb.21.1712911038695;
        Fri, 12 Apr 2024 01:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:f0c:b0:699:2bb2:2b88 with SMTP id
 gw12-20020a0562140f0c00b006992bb22b88ls838441qvb.0.-pod-prod-02-us; Fri, 12
 Apr 2024 01:37:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlOKi06zNbhVWo6YK2GTtUZ25UakFo+XI5HTq1vIum83whgTEaDnY34HSAdGKkthIbFF6wPyQykJHThUtgIH8lCH1T8Cuam+AW6A==
X-Received: by 2002:a05:6102:6cb:b0:47a:237f:d12e with SMTP id m11-20020a05610206cb00b0047a237fd12emr2609364vsg.9.1712911037953;
        Fri, 12 Apr 2024 01:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712911037; cv=none;
        d=google.com; s=arc-20160816;
        b=zeugOR5/OJDG3Uf0JMbMYmUglkDt/vm8w+5pJX8z6rVO5U2MGX+T9t+d3eHDqUA/vU
         HnHwlINjN9GKvYkbmuudGMNdGGDMYA+HF4hf+Y+ecrR3NhNwmC0m8DjC0yeizQl/v/Rf
         T/aWX7QpxeTU3o2cCQZBk049JyguBatQ23gJ25GDn4dDPSwKhF+0syKttk8eVprC84gW
         4aA44SiPnT5kzCef1GElYto/sEgzTYcB65KtapTY6S4t3nTBx9DoT9u4zypCq2eQq61B
         tqVew2QcVpMpT/NQNy4AjSD+jZn5yTcHDJhbwUC+DZCZe/WDPQqBUtQ2jaACf9FDWcB9
         QYIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UXhULSRsCjHCssdtYJT1cvp74SqjokSLuEvNUkZIlH8=;
        fh=LuT/Ou9mra27/dvY4kJqNQGFmie8xvgvMxy8eQDBIQY=;
        b=TDBPdBEIWIe1u8YURSOX7mCCh+90uHZhltxGP4gZ23YiVIK8jn5GPS4Q4mu/bB/U48
         gh4iZGwvJficgcq7dUiQmWqZ6AM54WFxEvXEweXuQaOm/ptrEhfmxRA55dYeDoiukMqb
         mW16XRzi98f2Ti3aOAJ6kU+/wGIBF7EZL2HSpZnduNQo5pbTUfkHBQADvB8Fp9O8WW8v
         ceVIQ76QdmqBWEpy+6qDPwaVeV7wkBk3BguPnfDTRXZ24UKlnet7H1GZeUOarxO/B+2m
         0RfbsDRnBvGrFvpjS0wG+s1TcC9lN2tsWvOwBM/ApTNlbIBrzSN6/3vV8Dkqv0pbSwd3
         bZLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=u8a+QHqq;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id d22-20020a67c496000000b0047864b25a8dsi262086vsk.2.2024.04.12.01.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Apr 2024 01:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dcd9e34430cso695145276.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Apr 2024 01:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX19OL8sANoP/RAWIXtquabWc0zIr/8NogX58SAQE+MqXHeBeGYdNotTbEFjyBl2Eeik34kMooQp38251KTWUUOOlZnq+KLi1217w==
X-Received: by 2002:a25:c70a:0:b0:de1:133b:5053 with SMTP id
 w10-20020a25c70a000000b00de1133b5053mr1898633ybe.20.1712911037446; Fri, 12
 Apr 2024 01:37:17 -0700 (PDT)
MIME-Version: 1.0
References: <20240410073044.23294-1-boy.wu@mediatek.com>
In-Reply-To: <20240410073044.23294-1-boy.wu@mediatek.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 12 Apr 2024 10:37:06 +0200
Message-ID: <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
To: "boy.wu" <boy.wu@mediatek.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Russell King <linux@armlinux.org.uk>, 
	Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mediatek@lists.infradead.org, Iverlin Wang <iverlin.wang@mediatek.com>, 
	Light Chen <light.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=u8a+QHqq;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com> wrote:

> From: Boy Wu <boy.wu@mediatek.com>
>
> We found below OOB crash:

Thanks for digging in!

Pleas put this patch into Russell's patch tracker so he can apply it:
https://www.armlinux.org.uk/developer/patches/

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdZ5iK%2BLnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q%40mail.gmai=
l.com.
