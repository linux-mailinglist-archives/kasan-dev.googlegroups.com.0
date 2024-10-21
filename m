Return-Path: <kasan-dev+bncBDE6RCFOWIARBKE23G4AMGQEDMNVEZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EF0A9A68E9
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 14:46:35 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2fb384663aasf25570111fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 05:46:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729514794; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pm+25oCg9022bM7v1eNQ2XVGnkLcMFP7vthnN9EX08hc05PVC+uxL2PlT6MBBdkvqu
         Etut4bC6+OinAH/RUzLq0h62XOUlZzTjgawWPFSOwoRUC/IGZheiGsIwNBN0pvXa9QnU
         K/w2GQ+SD/PFsWqz6t279UxMqoDMGrUcsRVCN5JFpLa0TiwRDBm9aZqYxN6qbmn2O+AF
         Vl5Wgf1q/80SkGteUNGa+6t8kkUzyDke5RrewVSCrpOw4Gew1hYiK7IqgRhOnbPh/XPf
         JBIPbkVrrF+sny4x9cweZWEhQSs16/A8XklLlrBdAB3ZtJ2wCd7+tUJsf5mBPUnv28Dw
         +EsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=iAhkniaC3Z6YRg1tlYOm3oz9tqGEDT52K0P+Ic+8syc=;
        fh=Dc2ZI3SVdOOOOROTpSzodXOsbdJEBg+e3dOsSauwjJw=;
        b=G4zw9Ok8C95oSMUbpkYMMGvxWuqkUqBwQDv6Wz7xERXIITaUijpX/jFuSlwyvYTLUv
         FKlpZuWmuRVcBYX6obZtyvqjLjX2vrFEBdFaf7mbfT1n2Gsk3d5Vo1n8SLr8H7aZHvFw
         brZUgMYFhFCRkMGnh8OgLjsDSnSEdXBmV5ini2b4Sp0ep5chtR0XKxD30t3V4myAZxaU
         nM1sH0D2ckca6gSv3e2af0Uf/bZ0mntYfgN3PV2zhOvmYK21qqiRaaTR3WAdSNWI37hy
         FWjQ64+5g2frvLGcWWdfDSuT6qQWUyw/FFZ3/4OGqbro7ByzQR/DqZMr7su1qmAIC+k0
         b/Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=iETlyU5L;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729514794; x=1730119594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iAhkniaC3Z6YRg1tlYOm3oz9tqGEDT52K0P+Ic+8syc=;
        b=DD0TpqO3frhB6rt7GYPQvS63AMKWZAPhhAVIcoTfAY68Jvyo7b3PkbnFO5haLLJZMp
         8RdiBPBvNlk/UOgVC0KG5lxLue7k+gzbgG/mJbfBU+Bv4W7XsPBKBNejMu6rKfYVrpLH
         sdB/BYXoTK+3GaUtGSBh2Ql0rhm0uqeawfQbca9pK4796QhryLprujn22o2acuTtyHa8
         Hi0g3dRDGj2WftpHMDPlqJX53Bzsgv5zFkKaH9CUQUSKuA/JV2WjRRNNn69/mxmqKPH6
         eBvANIuOQEVwzd+MUwV+G4kzi7ea/lDAOxHl3MgvVu6e0ndACKkjGUzLkSiThduYTuNy
         m1cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729514794; x=1730119594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iAhkniaC3Z6YRg1tlYOm3oz9tqGEDT52K0P+Ic+8syc=;
        b=cKSr/mKxc3AgRYuljv5jZO0srfMUFMLeblyrTjker+3Nu/Gg3hjwrvhIi6pSPxiSra
         IdZ/iguUMRpyMdfKjOFnD6eN4OVZbEg1FecaJ78dJ66g9G9h/yhKbmRs9+RVWwZwflnR
         E0jVG9khojCHX/dWJ0uFK6P1VexM1/nKTyBLiQgITqsSn/r6n097A6TpAbTsm0Nh5jMe
         fg7jy0Jlqh+pucMkZZMyUhNRgZ3NVCcpbQChfFy1CFd5vf3YgoT3Cf8bI2mEfGBPGzsZ
         MADaTINHqbJrJiWB+Q2I5cIvBdDfMDOxvxPqWHomF2KFUTlffipIAFcnCeglfrh68XSk
         ke5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqS6zTQ7v/ZIpCcoUIiXERWyFMR8cBANU6+JhJehURq0afcnSg02+ta49riXBW2ZqQcnVZ5A==@lfdr.de
X-Gm-Message-State: AOJu0Yz0RGJfBgOkhoFjbuj1SCdETotT1g3TBidqnIN57dZAgKzLEayL
	wWG4MEkNEPWeD13CMfq2SVTsUmtUSneYVFKpvlRvrlNlZDf298NL
X-Google-Smtp-Source: AGHT+IFrDU9+0T3T7Zn0f7J2L73FPHFIrBSnV2wfSqvuxXuFWOexuzykFbD+gyAmXLA7gNczKs6fXQ==
X-Received: by 2002:a05:651c:2114:b0:2fb:4b0d:9070 with SMTP id 38308e7fff4ca-2fb82ba14d7mr39687461fa.10.1729514793004;
        Mon, 21 Oct 2024 05:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a45:0:b0:2fb:4dc3:c903 with SMTP id 38308e7fff4ca-2fb6d6b5addls7425381fa.1.-pod-prod-00-eu;
 Mon, 21 Oct 2024 05:46:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDePyF/VHqzqLJYIl4UjYzDForvd8JQCjYwIHWtlSOzYo1kSlHL8km4RBCY+9Eei1BOyfqulT1lZA=@googlegroups.com
X-Received: by 2002:a2e:a78a:0:b0:2fa:d464:32d3 with SMTP id 38308e7fff4ca-2fb6dc9d40bmr45376021fa.20.1729514790894;
        Mon, 21 Oct 2024 05:46:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729514790; cv=none;
        d=google.com; s=arc-20240605;
        b=LO5PB3MeWNu2dz/9wN8NMyJHvIrhE8t69oA23agRhTeuvBvWa+hwXzQDJSZ9iJZBym
         HA44aoOajNe546lO3UHiclb+/f7JGOlBWNcUTvRdq54B3wvdexX/qH3hTcMnRrkvw/b9
         Pq5lv8czrIStTZx3JmqZwbjpMImhxf6qJPZcGpMrqL1VU6at/HW4s+ZeWVUr+PqqfNj1
         nkCikgVW69IjvspYLZ7V5wzrMSfHQQ/WwIf/nJOtopgg+yMeDZ4FAISabsFinBVKSQtN
         pcHlWxFM2AGrjBtXHtt/7KzbT1IY/xD6yeKb3keR/9pQjXYkxJoiFxeqW8MN1T/rIWU1
         K4nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=00OOYAye7Y8Jmp2eoWZbqWaZ8JNNBAOvgechpLDPNLM=;
        fh=kx5+CTonPzt3+f9DjOhhl1W7zCGI1DDeJI7jwdhzrIw=;
        b=fUsczTleGUR6R+MlLDZelSBtG48f7Dzix7YP5kpe0Ysf/eElJDLHstW77HZjQtvwDQ
         K5LOqIUJJlzIDj9TkrHzOVssMSVuohhEPYvxMhw0Zghttu5e04oFBI0eQgECpXaOU/HK
         gcRoiyaz+QJ4tqMMJBNa25NxWi/a6qNhzJGBW/VOkuLb4KU/PbUCqYBDpV0ScLS6+dmX
         yCnwNfQp21njGvicwOXITluibDJ3cK5jWivSBWwHMs83Nm6bIRu87DgEeUDiG8Mf6unO
         nWUBOM3NAiWPrHtBpMBubM95M1nmUaZkiFy57U+RsFd4wMGwtihuRydljO6y8NzAzx/A
         +L8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=iETlyU5L;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb9ae59faesi592351fa.7.2024.10.21.05.46.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 05:46:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-539fe02c386so5390597e87.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 05:46:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVDTCsDhWF0DVnrMfhuYHWay6DHePulOWTJN7UBE8bjYGkc1Sanu1wVyk99/PjKilIkfQlicAn/QU=@googlegroups.com
X-Received: by 2002:a05:6512:1392:b0:539:e67e:7db8 with SMTP id
 2adb3069b0e04-53a0c6ae65bmr4990352e87.12.1729514790318; Mon, 21 Oct 2024
 05:46:30 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com> <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
In-Reply-To: <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 21 Oct 2024 14:46:18 +0200
Message-ID: <CACRpkdaiwt3aHmRKbR5e-hbd3VpR_Zxd95N3CmcAtFV-mjw_tg@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Russell King <linux@armlinux.org.uk>, Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Antonio Borneo <antonio.borneo@foss.st.com>, linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=iETlyU5L;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 21, 2024 at 2:12=E2=80=AFPM Clement LE GOFFIC
<clement.legoffic@foss.st.com> wrote:

> I saw your email about Melon's patch targeting the same subject.
> If we don't enable KASAN either you patch or Melon's one do not compile.
>
> [...]
> +       if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> [...]
>
> Should be replaced with an #ifdef directive.
> `kasan_mem_to_shadow` symbol is hiden behind :
>
> include/linux/kasan.h:32:#if defined(CONFIG_KASAN_GENERIC) ||
> defined(CONFIG_KASAN_SW_TAGS)
>
> So symbol doesn't exist without KASAN enabled.

Yeah sorry for missing this. :(

The absence of stubs in the Kasan header makes it necessary to rely
on ifdefs.

I will fold the ideas from Melon's patch into mine and also develop
a version that works with ifdefs.

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdaiwt3aHmRKbR5e-hbd3VpR_Zxd95N3CmcAtFV-mjw_tg%40mail.gmail.=
com.
