Return-Path: <kasan-dev+bncBDW2JDUY5AORBSMXWW6QMGQEE27XYNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B432AA334BB
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 02:32:59 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-54506cf0c44sf164983e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:32:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739410379; cv=pass;
        d=google.com; s=arc-20240605;
        b=hxm12eGhV+Agce67UyG4zAO6LUqcywC+b0Ike0CxQ/+TouG5dBONuUXiGokrqDoqKR
         9vjzJPC/II2nq/RpcIOt+/znzuByrK3wpgc+V32oP11ayxARNh5OtwK5hx2xCR/0V6No
         FmhPg16zeu4n3R3JOq0ewT93MN4cxq0Oqc9CBJThKPigKCKNIsm6+qebviFTm4re5caj
         g9C+FVloFjkYlEeq7Egbt/w9DlpFl/iQtDg7Kz9w0lY92K8eYm3+Hxp78dRx0NSO3EcU
         Q2MZTC/L2OCaMO8+auVPhRtI2nY5q6sW/hSj+AyBgCROqcWvRzj/SDVeQom/Qwi9HoXf
         oMFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qvJSeAyWDZSNiiTdrAZ1gga2fB1kLTrdeE0oIrErhtQ=;
        fh=GQ7pc8S/18Qoxwq/ck8ZV3ymprjMDL1i9loRYe96Qzc=;
        b=fQkpoj9eJBmXiRbO6uQ324Oo+8Y6k44HHdg7wU9X8fpcy5/9cEl4VEfPDBjrKU9eig
         Ow8BqoUIglQVMiQp3SBEqb9GfmrFSE3ekVAlIWyQZiC+dRQavZd5NZQkA7MRE6yNnhMq
         RcmKha2gw5GZeruLcnqYuPxrQ6Eo7/TxieSFtGbErkCkPgMsHGMxxLyOjkkAe9xo41TD
         lBUS8577Pp0fNNvIcLrjpQKWR4+SQHVpHLWgV5QnP3fS6VIgk7S/LD/eaWIrVXy+Fhx+
         tZ6JDHYwoZxALBbJkqU2F8RpJIbsva6fX+LjS9LDDFKNpaB5Bdyf44QmJhFe3uygG1UM
         j8jQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gdRaZx2K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739410379; x=1740015179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qvJSeAyWDZSNiiTdrAZ1gga2fB1kLTrdeE0oIrErhtQ=;
        b=sdalC8RYWPwHMZ7v8n5c2PKQuJQX42sSpmMAh+s1ftDnL/7VvaETfhUgaRaqP2TEvm
         vNXtlU74xZCsPSiT/ecqov0Cgarf/IRByHtefp2cGmxjoctDGJrixCX95S+KxNUF8BTL
         wDFFynb0vyeyD1wY8zB143I/e6BV8ReCGRhfOXcXhIDq7Sb9c4Ltl8aCSXQ/xw04Ytbn
         5PZP7UmsERkwYQhXI/BoujfiVbpzhLTASuCHDeEyrZTwWK2o53wtlYZKGcsInua/D9QC
         +DlNBW51BNYKZGv3Nr2wWC+EhzFjxtaGuP60Sl2DrmEFKyEjUs+UOswI9b596vy0DgI+
         V7OQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739410379; x=1740015179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qvJSeAyWDZSNiiTdrAZ1gga2fB1kLTrdeE0oIrErhtQ=;
        b=jq+ushLn9cOsSgHwFVDvK/WUyJdAX/kuwaGUFB6vzLCa9wVukdHRgSUaIw/sD9lOcO
         WUrG7omyMESkuwr66dlRPP1pr5nDqMoXQJ722dCoJZxaXENow61pJ/0chTjfEe77jGdu
         wkYqcwBccdXM3lXnXtOjI0xMljCTPxRwZw7cnb5Gl8PfUOGOOaCGKoHZkveF+LcmscaE
         c7CeQEIYM88G8ba0yX/jFZWNBHUQKk7jQxRHHwU4F43jOCoIBUdw3eNCtupj5/+T35qZ
         Hx5s2yJ4f6WDyFsDHj255bsJWzZnzjfA0Qw67Ib50L2M4/OGoUQKEJhYZt/Pi6r+zAhh
         5J3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739410379; x=1740015179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qvJSeAyWDZSNiiTdrAZ1gga2fB1kLTrdeE0oIrErhtQ=;
        b=n6kqTVvETDlCFFLILInb8yPb2QIRZXqKQhglLI4BpX6knDk6P3dYiCSlZCd714AczO
         8S7RwQxzq7p6CzqkeLF0+c2S/XbxiLLKrBbN92MC41U20awxH98TWzZhroJvCP1AEQyv
         ZgWVRmMJAWkWyxJ3m830hut/i/k+SrHabL7bepBcR1OzOEyONA8s6RkT2nnqlmjz7m0c
         8jTuoAQ/6ZGzhjjuy+vqHo45oKn1mzeRLpc4vSt7aqLJlW2V7WsyjOCnFdbdr8YnrZt3
         1ErMAoR5D26UCFLYnR5f3NNyuSQXLtFPTisPSLjdE8BEL9xU98YljIQoK3HSqTiMluta
         66Sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFH42obqNKaT/hBnKtqs259v0s6MprDWlH/aoQsrVJVQ17nG20ccFWepImV/OMYKfzTX5oeA==@lfdr.de
X-Gm-Message-State: AOJu0YxEJpSA0sqGZhZd9vW7miOrG3vvvo/n8XkjA24bpM2rwUvKtDim
	lmqPvKs7fNuSyUSf+VSJk2ZySbB+fOzeQt/5BppBYA9v2l37+j4E
X-Google-Smtp-Source: AGHT+IFq2pOC0Xuo+Bz3aC46Z1uj8uCG4z7G/6Y1GRTp+4PvhHXi2C4WOSWpsJkotqfacuc3m3MXkg==
X-Received: by 2002:a05:6512:1287:b0:542:63a8:3938 with SMTP id 2adb3069b0e04-5451dd92fc2mr375194e87.20.1739410378348;
        Wed, 12 Feb 2025 17:32:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGje6x6dMwH2/aFuit6Agr4RTMXIJrZQYyJckxirD9Vhw==
Received: by 2002:a19:ca13:0:b0:545:508:7851 with SMTP id 2adb3069b0e04-5451dccdfecls58320e87.0.-pod-prod-04-eu;
 Wed, 12 Feb 2025 17:32:56 -0800 (PST)
X-Received: by 2002:a05:6512:1382:b0:545:3dd:aa5f with SMTP id 2adb3069b0e04-5451ddd665amr313653e87.36.1739410375843;
        Wed, 12 Feb 2025 17:32:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739410375; cv=none;
        d=google.com; s=arc-20240605;
        b=EAsX4hhC0wwJ4dyHIGNHTTIxpVwsuuGjpMDoeXNHl73xzUB+LQMQFZXcbVEjQsaP+g
         UBiLkvpw3qCMb+lu8kxVeeiDeGtLiCjQIejTnRjz86abWUXoOXsFskEy+YGMQNNvSkgj
         Zf27pt2VaXz/46MvM1A37IUtnAQtpE1N52cx4sWB9cdDnZJfiqo8Prt0dV8+2c+Z4O9s
         kxdFJg3P+/EJKShJ+/LmmI3vKuAkCooqS/VDuu4MdNmt6Evcih5JIHBoEkDOhmbEMixd
         Vs7fUtWxtvlKoLh8bPgoScSXh8/nA1yVhUPU+qc+NxEPWnVBAY1ceN8CHtmlB4wIr4qV
         IE1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MorJX6FLTAyZ3zbA15UIIV+F+hkcbixGRjlCL+jEAj8=;
        fh=1mxylxmCvH3RODLDZuEalgDavV+/oeMCVdfXzxNoXhw=;
        b=L+e/9tOCi2nFIMg91o8gM2x2owHKmzYDrJC80z2JD5Yp9bWa3JgEX4NneHkmR6Sxl+
         vXBvniGtj+QfuSYdGXmXKJhfjt2GzAi4EgBmD+oMgX5y9ohuzIgcBSoa50fvhNJgCRPn
         E3FLGLP2lQTez7le1zYSQvTzGbAFxNJdRgExaJo7er/QSJu2X1FDgO3pR17oU8IqoapM
         /9i0SeUb6APvK5/9S0ZHXwlqJJvoiE3/jxjTQdR/xoWc2JsnGqjf4DgN/pY+tB1uoCN+
         PBW1docNXghcqEV2gzAg8wHfD+jJjunsaGiOLh5ceWpZrJ7BMXzz1z9Kj7wKAy/VdGqS
         tjug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gdRaZx2K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5451f136402si6266e87.10.2025.02.12.17.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 17:32:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-38dd0dc21b2so132629f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 17:32:55 -0800 (PST)
X-Gm-Gg: ASbGncuce3f44oqYjzOX+4zfp2mZQazcG3dnrhXHx7c3/6OdoEg/qDENJ8JgiulXsk4
	lQwFwbqzdTA6Ff/7CgTfFXG6gYHvEndpe7eB6jZJAlsYopHV8Krwr1Z1OFsNkNSAoUVFCZgFyRH
	M=
X-Received: by 2002:a05:6000:1849:b0:38d:e401:fd61 with SMTP id
 ffacd0b85a97d-38f2451a394mr1170945f8f.49.1739410375152; Wed, 12 Feb 2025
 17:32:55 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNOuK8XPDbZtsL5nGnXb1d1yfE3h1z7Q4tSMezSHi3QCbA@mail.gmail.com>
In-Reply-To: <CANpmjNOuK8XPDbZtsL5nGnXb1d1yfE3h1z7Q4tSMezSHi3QCbA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 13 Feb 2025 02:32:44 +0100
X-Gm-Features: AWEUYZmdM5HzDdNkr4STov1N5rJKfateOZgtGCyXNNSsgbLMpEezZU4OOocU3AM
Message-ID: <CA+fCnZc9yaiZbg-fAfir_zoFQDMROXm17RCbiLZ=J+H=mfEWfA@mail.gmail.com>
Subject: Re: Does KASAN_OUTLINE do anything?
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gdRaZx2K;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hi Marco,

Yeah, I don't think there's any specific reason to have both. Except
maybe seeing "CONFIG_KASAN_OUTLINE=3Dy" in the config file is more
explicit than seeing "CONFIG_KASAN_INLINE is not defined"

Thanks!

On Wed, Feb 12, 2025 at 11:44=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> Hi Andrey,
>
> In a recent kernel:
>
> % git grep KASAN_OUTLINE
> Documentation/dev-tools/kasan.rst:For the software modes, also choose
> between ``CONFIG_KASAN_OUTLINE`` and
> ...
> lib/Kconfig.kasan:config KASAN_OUTLINE
> lib/Kconfig.kasan:        each memory access. Faster than
> KASAN_OUTLINE (gives ~x2 boost for
> mm/kasan/kasan.h:#elif !defined(CONFIG_KASAN_GENERIC) ||
> !defined(CONFIG_KASAN_OUTLINE)
>
> Why do we have CONFIG_KASAN_OUTLINE?
> Could we just do
> s/defined(CONFIG_KASAN_OUTLINE)/!defined(CONFIG_KASAN_INLINE)/ ?
>
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZc9yaiZbg-fAfir_zoFQDMROXm17RCbiLZ%3DJ%2BH%3DmfEWfA%40mail.gmail.com=
.
