Return-Path: <kasan-dev+bncBDE6RCFOWIARBRPDTKAAMGQEEFKK4MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7B142FB539
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:17:41 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id z188sf599515wme.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:17:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611051461; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wn00zWtAsGK4iK2K9dmbQ1S8W7jqKhtGPacMEpm7ASdSOJTl973Kc63VdBgHVnvw7Q
         BtUPZjcMXDzgdU6qWvPeV6B5ngSOaaAKSty9pX5eA4SFV9eoKcdK6xmXia1qfIK5WBZ2
         wcmS/cOTt5lyT5pLM/Wbk4vA0r/a0cs4Fd4E0z1wczMxoRy2XHzQCRrgiY7Uf4Zd/d/9
         32V5ZLFLwb2OLVKYWuHcP7+CLbiqp4+3ddeKS51vLWPsGAUYHRM9Nli/qpvofJwl1dt2
         SeZjoCRTDam1SUUyizCZ3+iKq+AwVtAc/Z6Q1x0aF5Ejyrbpc7BvuE4GwGhQO7F/k/QH
         L+Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=J6xdeFBMjoBPInuNaio2D4oW9KNVA8xe18D+wFpFNwQ=;
        b=0bNciEoM7YbPwVuzMfF6SEn7zduEHwV0pglBLQo/Lr7uaVsviYsv9iOAZ0yBYgcosn
         +PIo0FNEuSvrtswRxvCAm/xR4dFdjhhQSd0BrN4rDe8aV5DqQX18NnUjx7sBTYDxpNCB
         F2xGMnAMjoabAXggARdV1/8FfgodhSpY7VcOEpPLUHtsBQSAcPJ/JPWLC3MR0g9qZueH
         4Jg+WqXyTCbgWGuPlT/WMgtSkAOe0DCWpznraFSCt65Dza7ncpDTx+wyvuAePBrYDu5e
         emgCyadepv3MF72OtUJ+o2MyrFjHhjCfUAWru+kEx4gk8nCi/tU1h5ieDrNUYyMHIj3F
         Hv2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Oe9kkaCo;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J6xdeFBMjoBPInuNaio2D4oW9KNVA8xe18D+wFpFNwQ=;
        b=XBoV08JDgX0OnBfES6AGNG7fiG2DhjgalxrWyAXGyNMKB91JNMuymg9+qyA1h7Tud5
         ni7wRpfrkbxYkzSMj68vZTXLY8ZPNsbYUAApOk/NW49QiWRyxTDjsvM2PBdLH0/Tvp2i
         o1CmYH6ZRNBjoW4D+uyB6CaK+OANnAxmh+tmZEVwvUXd01395qjTOLnw5k2w3Ui4UUUi
         QrvhEtdgA3PLOhBa4F7tcTeVZy7kV/sgiWzfK9R2L3gJ/qVbdVt6rJAlmuSA6Fc/17tW
         +XbR/VyxpfA1BXOJi6U3acjZdiNGR9rjQrxOb8mSAF5arrsQISpRCrs+VAs7OLJcI4b2
         MDQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J6xdeFBMjoBPInuNaio2D4oW9KNVA8xe18D+wFpFNwQ=;
        b=ZegiaKAdLPUqDq1u4V7JMxqXHR9Zq9ykBOFdHtzwir7horXR7hoKeqwZ48hkWmVu0z
         BK/1ZvWpQu7HBC0vjrFPU/EclQVha1JjLGdG83d3XVNWzZYFfRnW08fC/k+vw8lNpb34
         TWtgw9znjv0+tpiyA78kip1p0XRoVEhl27laOernEZjwr0xCy1yFjw75Q2/G5vXiqnby
         KLNPYHPpj/krgYw76DsAjG8JzcO4ZyPs0Qc+JKovimrXljNdhFkV81b0R0L/ylV++GYn
         erozaIRV617fGP/uavDm4VYgP35E7DhKNi8GELmlIkAvWNhhUVkHTg51lnxpYIBawVpw
         Lg1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318rTzkBX3DH0VmaIBjOTXbvC+O2AUeWVgiC+NXuj6s9jmobCUK
	jhCobVTIU7Fq7uK9FTGX10U=
X-Google-Smtp-Source: ABdhPJzYpzRETNbGk40n6fCfHz0iYNpfTJj0JiffVNavCs1bS5G6nLKhlXsLoNn2LXmrIeA7PP9Ieg==
X-Received: by 2002:a1c:149:: with SMTP id 70mr2724668wmb.165.1611051461664;
        Tue, 19 Jan 2021 02:17:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ed1:: with SMTP id g17ls6327722wmq.1.gmail; Tue,
 19 Jan 2021 02:17:40 -0800 (PST)
X-Received: by 2002:a1c:e309:: with SMTP id a9mr3371957wmh.181.1611051460882;
        Tue, 19 Jan 2021 02:17:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611051460; cv=none;
        d=google.com; s=arc-20160816;
        b=sBFXM8U7+d6gvWGYwxVgBfMMi6f+RlwNyxEHa/2QY+/jwhuKfldDCvOpHQvNYxBv8N
         RhXNfeQn2qU7LZiLR99WR+RfaPVdtEZR4m4UxHe4m68zD+ddJ9arezWbV+LCkgzc7zN6
         86+o7+/hVCWsYyEI60ynOoCWLuP+lF9HeakaSNa5hsIhbHwm3bjaYE4RSOntuYDhg7vh
         /4c1ujvgxXpa61wGaqkY3p96HviOoW6b2MP/FiZJQTsQuaPg0rUS1GrSdQg0Bh4opVZT
         6jnhIDUmwIGkp21xQuTECIIWEsbpbP1s16JAaaDEsTXGLgfceiAibSacqmodPpDMgDEG
         Lebg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GKHfuMGVBMdxCBJ9Z9ysX5c/8iICEWw8PEJ7Cmu7z+o=;
        b=miGq0LtbizSx7GM4dmSVqBK9NG2mEoBjohLzoI/Ji8OKGYrdtlblCH7aL0PCm4wA7E
         knKe2D2znZQujNeR6e024zc3GJYVRDmEdI7xrCUwJUJMnluvgLtR+SS0/otSXrbDSUhC
         jKSm5/wjtklsj/WxPrVkvIEco67nMKumPHVLHiLWAipHAX/gxy3OXh2y8yc1GWY4gHSa
         2JiwWDF6ZbAp/S1ushtwtDeh9WW9uBxklkhWY+Fc8EnaomGBCeOy7medY0M4rPQuhI4u
         EYug8mqKhtv3veMUTIwz6BSmlmLZXkmhvQhrzK9Qaiy2ryh815g3b8poiIlSVIrEp1k1
         VnrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Oe9kkaCo;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id m2si137085wmm.2.2021.01.19.02.17.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:17:40 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id u21so21315635lja.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:17:40 -0800 (PST)
X-Received: by 2002:a2e:b047:: with SMTP id d7mr1520214ljl.467.1611051460614;
 Tue, 19 Jan 2021 02:17:40 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com> <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
In-Reply-To: <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 11:17:29 +0100
Message-ID: <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Krzysztof Kozlowski <krzk@kernel.org>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Oe9kkaCo;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Tue, Jan 19, 2021 at 11:04 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> > You could also try other QEMU machine (I don't know many of them, some
> > time ago I was using exynos defconfig on smdkc210, but without KASAN).
>
> vexpress-a15 seems to be the most widely used and more maintained. It
> works without KASAN. Is there a reason to switch to something else?

Vexpress A15 is as good as any.

It can however be compiled in two different ways depending on whether
you use LPAE or not, and the defconfig does not use LPAE.
By setting CONFIG_ARM_LPAE you more or less activate a totally
different MMU on the same machine, and those are the two
MMUs used by ARM32 systems, so I would test these two.

The other interesting Qemu target that is and was used a lot is
Versatile, versatile_defconfig. This is an older ARMv5 (ARM926EJ-S)
CPU core with less memory, but the MMU should be behaving the same
as vanilla Vexpress.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdb%2Bu1zs3y5r2N%3DP7O0xsJerYJ3Dp9s2-%3DkAzw_s2AUMMw%40mail.gmail.com.
