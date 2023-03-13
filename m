Return-Path: <kasan-dev+bncBCSL7B6LWYHBBVGPXSQAMGQE4PIWZJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B66226B7931
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 14:40:37 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id y9-20020a056512044900b004b4b8aabd0csf3604366lfk.16
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 06:40:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678714837; cv=pass;
        d=google.com; s=arc-20160816;
        b=AfVlpgj9AWyGoKzGQKQNubBlJQXijd49XSPrBZwJWnR2Bx7UgpfXVHOS3eoGt1Iaib
         G1OoAvzOrN/na5FfD5qikI6KhB3GHqTpn5X70q+XTzndUGwUrkngR4TgOlhLRc1+nVnN
         AsGaLkb7GCYodkrJUh8/xF/p7TbnXWkPw81xUm8jPjd4c4Pk72/fUNC6sDEhEHyBl55Y
         oxVPuBng/JrQXXHfM+2zUg2xg+BtURxQLEJqN43Wk2JnmTS8hOnA9ZyZZ0nzqKzLGRGc
         EmL2+KDiQiXTs/tic2Dpz+moFprDddy3/EcxGtNbihfHURFH3JHD26GD3bL+cu2DFQXa
         qsEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vaT2UMMzENBtoxiIE8NcDZL34ew+eIJD9NnllRH2Ojw=;
        b=f919tthHTVWseSxY1+M5gObIIhRqKUnJPHFZziYy7e3rq2OfhmY8LTVZnowrUIsioS
         RbyQaIALcrlpxijp5mc7KwFrF8J79doAIe60aLHihNSkAN99TLmToAkOwloS98+HHn7S
         3IndhgqCM9H5k9UZVJMZTfv+P71RYsSbZm7Inh1EO0LW8WAPEV0poOmRneUsyMie6Qg/
         7/iBtGloENaRqwkmgQiak7854v64U9V06sIBL0cI2h6D3a+cs5LVKDoV+9puJ3Fxi2yG
         vrS2UHuOXVvDWN8VSHUDULo+i1JQdVXDGjgwVO+TCyO1uBZbZQU7AjvTV628ZwtwE4lO
         1tqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=a+yJWnEl;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678714837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vaT2UMMzENBtoxiIE8NcDZL34ew+eIJD9NnllRH2Ojw=;
        b=aY05ZjAZ6vgJkFPa+WQkdI3o1vm3J6k6IZuHjlpZFc8JPz/wCPUKj6QyST0mLeLBdS
         MC7IqGY7zgcxTQxSiHRR7d4FpRakGeV0t3og8AJD1iBvIKIJgWJQAwxgQideWpbOx6ae
         AnbaJ2CS6K96Y8Tn4I9VCfdWLLn5MsGtdXZYc0xt/Jnp6QerfIcRvqMBmVy6rgX0Zr5F
         CwTwbswSQOiu3WhBIWx9pOmCjEE0eZQGMfb1m0SEvup/O28ucTSXUVxlj7L7fJPy+e7R
         +70sxgyD9LUQScoaWDvsQnn4yPxaKqPVb4B31w8oU30SLRTZE8BPPC+Zv1Jxl3WK6nBH
         VOcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678714837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vaT2UMMzENBtoxiIE8NcDZL34ew+eIJD9NnllRH2Ojw=;
        b=Q2GYPAn3R7oLW7mzf4K+3pnC/oNTgYJeaTme9cuqSTMcVxNMpLLWuRWmRTJlDJAu4T
         0swswU9sIZ5BCgbhPrMy/vU+E34FRAo/aeyvZpo01fTYWPN7D0Cw2jva5q2QL3DLOMzm
         KDJL7CqcG4t7Tl0X9do7NZFrmfsHRnYFqxDxGp0d9LGwUyAYZhn25LQm1gf99piVX+2Z
         yafwNXHrZyvTxleJ0f07BbYBIEZTpgKrC1gLhS6TWHN6RcvchfQKT5xBq0KzDrPtmHzR
         0NskGnT823JNFPEGEN/7/Z5YqTAev+vLaIIUtSevH3z/yOOZVUZHjU0vVq68bTkWqFFw
         3Egg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678714837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=vaT2UMMzENBtoxiIE8NcDZL34ew+eIJD9NnllRH2Ojw=;
        b=C4470JHQELNhbIZSVGbx1eegB0dzIWSuJ/Hv8lAC/i0HqYEAIWeGI6Emb4Y97pp/aj
         VCfHZdxytMvA/BRDsV5suUnRkLjVaTMMOLCY8d0tJ104wlEPV/M789CLCeAE7i/sym5Q
         mvstBBiKTWIdciHe8Nn0yXJmINX9HwrLYG4nxrHvAj0Nuyq2PcGCUdCuurhQaYM5rkrD
         i7LCxTTtDvjLBdT1rmIN2o9PLyYQLooqtHuALHCqJ7jpcLZ5dAC58OasCEBcC/Klo1Hl
         gdjQTp8jneo+GSxj++iMFuORlojbsWGvF5sRwwhXIzweVIgPWGv2Abh54KZcP42oZRiH
         AAmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXzOysaOls3hHOiz8Z7TVhb0VHjDodLcMpWZqxZHn2kbLUUd5G0
	wy+9nP76PzlYZP0+E4U0BVQ=
X-Google-Smtp-Source: AK7set9QsbhootjzPSbZWnhybMlqaP+8Bc5PqYOVL0RMxrZq/44jmm6Q5SxcMVm5hvajirHRypb67w==
X-Received: by 2002:ac2:43d0:0:b0:4db:f0a:d574 with SMTP id u16-20020ac243d0000000b004db0f0ad574mr10344686lfl.7.1678714836714;
        Mon, 13 Mar 2023 06:40:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d05:b0:4db:51a5:d2e8 with SMTP id
 d5-20020a0565123d0500b004db51a5d2e8ls40414lfv.2.-pod-prod-gmail; Mon, 13 Mar
 2023 06:40:35 -0700 (PDT)
X-Received: by 2002:a05:6512:204:b0:4db:a19:6dfe with SMTP id a4-20020a056512020400b004db0a196dfemr9303673lfo.26.1678714834960;
        Mon, 13 Mar 2023 06:40:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678714834; cv=none;
        d=google.com; s=arc-20160816;
        b=BXFpFEKJoyq3b1c3iA5jsjTLsWTwcY+P9oDwTOlnC14i2UFyb4QumGCSESBl/KKidP
         g2ggGaDLobPguBDTb31htPAABRoUjRcfqpo/b3H2pMm8nz9nmxf0E0vc7U/Tot8k5cjT
         iPnXF53xiuumH7xLre/2qI/yUJFcs5gjKzcfcovpIK65gbh4OpfQV5pLV1L5YAnkiruH
         cioMBLctZ4mGqy7OJJxHjBwYORcPPs+2TKBe3jVQVSubYiOA5Klst4WAiA9bjifG28PH
         RNFh7HftvKZCzIt7a2RorZ5KZruP398WsyP+yCLbIZ8i2nN9wrhGwddJqnK3fuU4G3bp
         S2TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=31bIBBam0f6kecXsPhvAYb/shqew87ztMsMZCGP7Fyo=;
        b=JFpOTf9XO6S072RmAGbCztf/IiS8jvDvCbgTCdU69R9ij6nljRh81L1R/88nClYsSX
         DaOnhQ6sr2quPi0/Cc93lDeECDyK/i7fIqA6v2MqCqya5Hp6fQQTAkYfLpqNXgIy43Xp
         cW2GYuFdSnpJZlEP9uHkfZPxoitMDIfFXM1iJlhBENG4ydLwQ6/qx4ceLooJaHNeW9xT
         QiniVeQFbsDYrn870oIz2beT3NNh6h5wdGIpBmb/IUT2yysO1cCkOIOd3PB1forQejD/
         JvrH/vgRq+sx4wnE0OZw98KB0oDmx2KCdi2S+jIaE4Zkxe/4y6l8ifMOLuCKBmO//SeD
         8Nfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=a+yJWnEl;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id m13-20020a0565120a8d00b004dc7d884e8fsi344027lfu.6.2023.03.13.06.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Mar 2023 06:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id o38-20020a05600c512600b003e8320d1c11so7371314wms.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Mar 2023 06:40:34 -0700 (PDT)
X-Received: by 2002:a7b:c843:0:b0:3eb:3e75:5db2 with SMTP id
 c3-20020a7bc843000000b003eb3e755db2mr2468540wml.2.1678714834218; Mon, 13 Mar
 2023 06:40:34 -0700 (PDT)
MIME-Version: 1.0
References: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
 <CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com> <20230313094127.3cqsnmngbdegbe6o@blackpad>
In-Reply-To: <20230313094127.3cqsnmngbdegbe6o@blackpad>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Mon, 13 Mar 2023 14:40:33 +0100
Message-ID: <CAPAsAGzYSi_mCy64rFH=o+m8eT-A9ffttsFO9Wx94=nsj+Q8Jg@mail.gmail.com>
Subject: Re: KASLR vs. KASAN on x86
To: =?UTF-8?Q?Michal_Koutn=C3=BD?= <mkoutny@suse.com>
Cc: Dave Hansen <dave.hansen@intel.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>, Thomas Garnier <thgarnie@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=a+yJWnEl;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 13, 2023 at 10:41=E2=80=AFAM Michal Koutn=C3=BD <mkoutny@suse.c=
om> wrote:
>
> On Wed, Mar 08, 2023 at 06:24:05PM +0100, Andrey Ryabinin <ryabinin.a.a@g=
mail.com> wrote:
> > So the vmemmap_base and probably some part of vmalloc could easily end
> > up in KASAN shadow.
>
> Would it help to (conditionally) reduce vaddr_end to the beginning of
> KASAN shadow memory?
> (I'm not that familiar with KASAN, so IOW, would KASAN handle
> randomized: linear mapping (__PAGE_OFFSET), vmalloc (VMALLOC_START) and
> vmemmap (VMEMMAP_START) in that smaller range.)
>

Yes, with the vaddr_end =3D KASAN_SHADOW_START  it should work,
 kaslr_memory_enabled() can be removed in favor of just the kaslr_enabled()

> Thanks,
> Michal

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPAsAGzYSi_mCy64rFH%3Do%2Bm8eT-A9ffttsFO9Wx94%3Dnsj%2BQ8Jg%40mai=
l.gmail.com.
