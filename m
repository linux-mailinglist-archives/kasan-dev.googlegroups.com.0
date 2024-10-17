Return-Path: <kasan-dev+bncBDE6RCFOWIARB5V5YW4AMGQEOK2VWTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9622B9A2D00
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 21:01:12 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-539fbbadca7sf1109387e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 12:01:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729191672; cv=pass;
        d=google.com; s=arc-20240605;
        b=gYKuluJVzZUgBPyzzX6+syLiZRPeaLeMRWvWcMGn4tNKfo0wek5r5Iqzv8/aZoOEgU
         sqESC4KRhpjpjmdHXcqX5XbPKialH51tPVhzVPcHyMbV4LDapJUHwLb6rf1Ubpez6bKl
         olZDYljNzVmLQpyiSijIP0kY58UL5M1mK+DLz9P16Mfhx3gTx/5lHNYsp/4/H7yOYxqQ
         IfH93+ch/54PF6KSFFk0fVj3YVCr0MjfnAFSXtDBWgVJuwRPGJpdX3S4FUqhc7ugqXko
         JzGhOEGLjCpFDCSMsWGw/hiO85AgZRsd8q5unv7hW7cZVthdtc+8QBWdsoq2c4BxPHEW
         wgPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=xgcBc5uPK5zq1y7++eyWRyGf0bIvPV0LQPiTzM5XakA=;
        fh=A+oZykR6jxpR15GNwj92M3Ihf43h5bFWmpBKR1P9xhw=;
        b=h+CWVFxFCyquaFOIkMNRqaUvyzyFD8INSTZRCRQ8nkH1+gBrxpQFZZ40f5/pDAHdPE
         vznVjsXCae7yiZz+g9KE39dD0LtclKE6tPPw3hQIAWn9S8KOyiHL7UCgsdAA/KKeiI/Z
         eLm8QI/cHIDikqnGsLh3L5a2CTuDj/G94VsgefE/2yRepeqL1cfuj2rG8cCBtZ9IDdTn
         TD+Apcgn75TimpakOnM1GKyie7p5fj7LtPqmL0/Puwr8kWX+AtVqdi9bIk4fzdDepk+K
         DBDuFM4xnFLoCx/XyG2UNL+J3HWpclmFJv7tgHTavbp8vhLcSjr81B+mLxsWJUsQMMdG
         a53g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=o5VtP8dU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729191672; x=1729796472; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xgcBc5uPK5zq1y7++eyWRyGf0bIvPV0LQPiTzM5XakA=;
        b=PdMUdMNuMmlVAcOFsD4spxe3PFrcWTvBhw48oo6xFwduKbS4K04/qde1nrHKtz7nnY
         /YnM3VFVpOzLQm5LddS7h+uNOgKv0NfhjXTaTpSZfOBnNHYPOMZHw5YWWd4bPzXE5wdt
         x+qLsnSFvoPV3TkmGPBx5d9oqXdArBQo8KDaL2z/Ay++i+KUxMm95lYJYMwQA7KnWkvS
         OmLJbF44BIqPrbpH/APks6aTO2hN7rSPxYUpoodK1dR9OQxeCRg8HpDzMRRouNZU7WQX
         Q7MIao1NMJBHf66bbS0zEy6JvXXzxcpFknUAic1hmqpauHF6nLgyvdMKx8RoGyb47/Q9
         nUdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729191672; x=1729796472;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xgcBc5uPK5zq1y7++eyWRyGf0bIvPV0LQPiTzM5XakA=;
        b=RiNWh+/MFcs1dF44P6mKGA9BS58IG2CuS5HieLbQVuJ4f2ArwigmArxbCvbbBpSKfL
         +mMFhjHaHy54nEPO3tZ5uwFdM+MOlFAsuqC2s9gN6QGJF2osEBPf4uox1nZohwIEN1Pt
         tsJeJTA474Hqy9momEffd0SavE5YG/vTCA9vzLPp3OKRPJES3R2QisFla0YP4F9sryd+
         GvIKwPYsmLBFeifKLzhKp19lMc9bUPZl9+oe4rS6vPK+16Fmjp779R3e1sBxrTb8uco1
         nu6qryx2aHMfBeISoqFf9NV/uwEeB9jtsMkjTbjJMcU99ebC6lpawfZ3MRITx3rRD5up
         JBrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmf0FkIYY30Dp/ozyDtDL6QRyBV7keTwDR3moH+rU3TWYSJpyG7dBmfXtichyjCifzXRZPDw==@lfdr.de
X-Gm-Message-State: AOJu0YyeCv5MpbqmCDM7JNMoe603299QMSu128CKY3cRvyEZo3OkJjS/
	OHnUMkqsfsq8A2nrvfUlcTQF71KyoD4LsM59AJav6ngVIHfYOM8L
X-Google-Smtp-Source: AGHT+IGbp8dgQRHHeF2JGlkCoEx+2Il3h0zXWsHxfochL8aH+u4H8rKDkSAGHppjFLATEGTYpU+7Ew==
X-Received: by 2002:a05:6512:31cb:b0:539:fbd4:9c9a with SMTP id 2adb3069b0e04-539fbd49d3fmr8783348e87.35.1729191671000;
        Thu, 17 Oct 2024 12:01:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:31c2:b0:539:fc31:fc7b with SMTP id
 2adb3069b0e04-53a0c5c3ccels722892e87.0.-pod-prod-02-eu; Thu, 17 Oct 2024
 12:01:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWW4LwQKJZdiEs6GiL2IB8ud8PBDzoGgkW5GDlxFrtNByLZp5XSycGbo+14ONL/kGAqOurgjSGPiyM=@googlegroups.com
X-Received: by 2002:a05:6512:b83:b0:536:53f0:2f8e with SMTP id 2adb3069b0e04-539da58bcd3mr11921686e87.37.1729191668869;
        Thu, 17 Oct 2024 12:01:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729191668; cv=none;
        d=google.com; s=arc-20240605;
        b=HMLKofyU1yBaEuxtvfI8KY3Mk5i3rI3xGcA5qJ5Jjdvii38lwwdW8OfjM9yxaF3VMR
         tp6QAb9l0SknALgIyBGEKZV0xupDYUYtT3VRrshZ9Yc9/SZ+cr37B/gczqUz63X9Z5TI
         mF4VdLX3fuvoxMblbu1Ku6T5DIl81mVxWVua8WR9xtaETcTf8sguNW9t8kO8qZ4r6X6Q
         R5vuCXMMIgBiMeqNeTou4cudPaRkkRvKQZIzocLXkoMYOmdiIZdwSlar7neTgVtMCLkE
         1layb3tQ7/QQtuo3ZR/x6Ft3rdP+OTJ5WyhU9ElABlKM9/CkFgnywQsKfD0Lovb0j4kd
         Jzug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lU3mObs7ZaU0oOzXWh6lZdlXzB4eGdGSPMvLDf83xnY=;
        fh=J1PWidvm2KgMDVPMv809vVIDuPl2fjQxGwC1YYXiZlo=;
        b=knGq+YGC1AQBFJzu7XoCwWLLFhfDX9T1FAmJthcKJfF4REh0OTbkZ6BB0GQOvchanp
         yTDnRa7Zvr5bC4KNaZ3mFecYZNacCCkiJ3FifK7EaIViVKH7F0ZR5Lt51wg7jude08p4
         pTBTbUleyIi8bpYJ9EChkwfgS/jrR7Z9h9sc2khu6L6rMR6OTe+nuCjUrIFR4iJw3Nky
         9pDxQngWma50Mpicj4x7KdCAkVfcli/mHTlnWTnXupKyQmVHYBlOWrSccQRRcUR5rZ/D
         8zK5IpRQlX2atewqvvE7QcEvkahZehoLGuie3tnrzX640U7+XGcT2rCztN6q2Z5Mfpb5
         DitA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=o5VtP8dU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431606c46f5si136915e9.1.2024.10.17.12.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2024 12:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-2fb3debdc09so12057351fa.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 12:01:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1j/jdpSgDpdd41yfBjdja8XcSNyXGtPKHZoRyvkqzA67ROjFan045I5WN60+S2kUsTfhjNRUbemQ=@googlegroups.com
X-Received: by 2002:a05:651c:b25:b0:2fb:5740:9f9a with SMTP id
 38308e7fff4ca-2fb5740a18dmr82304681fa.29.1729191667969; Thu, 17 Oct 2024
 12:01:07 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org> <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com>
In-Reply-To: <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 17 Oct 2024 21:00:55 +0200
Message-ID: <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: Russell King <linux@armlinux.org.uk>, Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Antonio Borneo <antonio.borneo@foss.st.com>, linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=o5VtP8dU;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Thu, Oct 17, 2024 at 4:22=E2=80=AFPM Clement LE GOFFIC
<clement.legoffic@foss.st.com> wrote:
>
> On 10/17/24 14:59, Linus Walleij wrote:
> > [...]
> >
> > +static unsigned long arm_kasan_mem_to_shadow(unsigned long addr)
> > +{
> > +     return (unsigned long)kasan_mem_to_shadow((void *)addr);
> > +}
> > +
>
> `kasan_mem_to_shadow` function symbol is only exported with :
> CONFIG_KASAN_GENERIC or defined(CONFIG_KASAN_SW_TAGS) from kasan.h
>
> To me, the if condition you added below should be expanded with those
> two macros.
(...)
> > +             if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {

Let's check this with the KASAN authors, I think looking for
CONFIG_KASAN_VMALLOC
should be enough as it is inside the if KASAN clause in
lib/Kconfig.kasan, i.e. the symbol KASAN must be enabled for
CONFIG_KASAN_VMALLOC to be enabled, and if KASAN is enabled
then either KASAN_GENERIC or KASAN_SW_TAGS is enabled
(the third option KASAN_HW_TAGS, also known as memory tagging
is only available on ARM64 and we are not ARM64.)

But I might be wrong! Kconfig regularly bites me in the foot...

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio%2BhVP52OBAJP0A%40mail.gmai=
l.com.
