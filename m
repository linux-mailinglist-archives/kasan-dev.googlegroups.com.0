Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NIZO6AMGQEL4GI6KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id C5546A1AD62
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 00:44:59 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5f4d603fa7asf992746eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 15:44:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737675898; cv=pass;
        d=google.com; s=arc-20240605;
        b=I2EwyCRmE9QVuw1yn9k6P2H266KxaPnSZ5Z7ny5gj03B4QrmMuPsL/YxCqBOBF+Ttd
         woHBlyvUNplrxzoK5mbd2FtQGICdQT+Y3GQHVD1/hnNtr/IqkGV3UOaRVXx9huIPc0Sw
         jYCbmlEatoUPECQD1wrS7p7y7xq06AVbuKqpPZ2j5MJjxvGNqqVrCPJvHONxOok1CiDu
         Z1JrcmsoWCK1va7ABDdo+3N9zrEIsAAI5bJPZ8JRyXZHJw9MDpE+lfb3HB+f+hYT+lSF
         GjWV48et8RlOc0fM69kTntmT1yyRij5+Wg80LjL6O2uJmWKC2H++FhkJ5vEZQolp60vU
         WQBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AePtbN6gk0hc3bbPaUauvO92B/9A68cmz7cOD51Royc=;
        fh=228E3uYed5RcsrUJ3D5VnPr8AQja5uZlq3PVSgo2daA=;
        b=jAL3ba44AVLH+V3nAegm6asg1y6+1EUQIiuwbPi52dBJIB1O6ai1PZlqvMwmZ2pVRT
         So72BJJtd0QEDQbkLxrKi655iHpqzjs6HzU/IjVx4qcd/QDWH8VQkA5L5EFxBqnxSO+I
         AO0DKD2Dr57LDZMYDjj8XS07yNXiP5ZmRLup6kB2RoPYdZse4pj7OOZSwNay/gIv1zxK
         nrukHizJKKrfrAzI0nUlsdig/hBaEYYSQeygWFzRvW8TsO9Ersd0wmKjs8heTSCzp3oc
         /0gJC5fWXfJ0CX7AHdJVryjBC+plIBROn+WW0lRFpMadtNKKcqtnxHdEoX1ZEwPj3Aat
         nQ+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HPbL8M+4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737675898; x=1738280698; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AePtbN6gk0hc3bbPaUauvO92B/9A68cmz7cOD51Royc=;
        b=WsJTHS65PYZQYznvFWIewoALq+GCRIkqe1vT2xMrMvC/LjiEJ5nNNjzdjsNFaDASC4
         M6cdq+I9Nq2C0KfEQSvh3lhX7OhaZkUF8iuwlwYkXuFzd5dWeWHG74/lbY8vwO/dn7NQ
         TCfiW3BuEM6w+6+hb4sE6opBC5tdR9LAuxwrxSQMsxjzBnLZdOEucQYlN545JdWi+AIL
         DAkPYwmN+ZL+cz6zyds2PTeQUoBKehfcIMVvN0x/lF09jchVgRaP7BbsWQqWWaQl4vjs
         Y/OYAQWvWt1/aGIT1vuTCoOCyt8inL2K8g+Mwd96pUGl5B4yxQEaOlaZ+0SmodV2tGip
         f/vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737675898; x=1738280698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AePtbN6gk0hc3bbPaUauvO92B/9A68cmz7cOD51Royc=;
        b=f2pBfftVqPs247Gj0qAMpxPDE1hoDT9rpXqRpd6PdVrtj8oS5ezxryK44tOVjpb6ut
         +KAPvviPr2hmQg51Wom1yNFdFsfJcM6ukl2wJUSNIvdq/PcIX1txpZLMnWmlBRHZO/+3
         ac7ptLQYL2wIgQ0Jc0Tjmt3CR3SirCtK7Tj+eZOcd7xVaHM9YZmsq85Gyz31ZD4y3wCs
         sL6QqBJixtwI2MDG2JdXNUTng2DwjMYtNcz4i+BjMq2FODknIBkUfoSBVVhyAIB7LV9p
         ffbfEloAQafNfQVxykk1Vm0KNM/KuN5MxCrCGTgA649sTH7rW2AmsFR66YvpgwR33HXi
         Uf7w==
X-Forwarded-Encrypted: i=2; AJvYcCVDlp1YGhVzP75jZfW1HPmTr6bVRFAeBoGZY4A4iKVYH9BGkMXFYY9E8HCKUdMyp5jQxzM4QA==@lfdr.de
X-Gm-Message-State: AOJu0YyonfoWr2GhgRRRyIeZOOzWOlp3wcyCljO8GSubg/rML2UNUlHj
	r+k2/E5uKhxG8Zs9QpA8Wd2LghISJkD/q5TBhxsWVJ5fGMEWOJuN
X-Google-Smtp-Source: AGHT+IHwA0CYX8nrYt2n2rCRCTGrabaG1mM67aioa8AfKwRB/LySEcG+JyqFKzYBTXFjiuiKcgjRnA==
X-Received: by 2002:a05:6820:4c18:b0:5fa:840b:19aa with SMTP id 006d021491bc7-5fa840b1c72mr2609869eaf.4.1737675898127;
        Thu, 23 Jan 2025 15:44:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dcca:0:b0:5f6:3b94:5b6b with SMTP id 006d021491bc7-5fa80263c6dls605096eaf.0.-pod-prod-05-us;
 Thu, 23 Jan 2025 15:44:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUPFpmskwirz51IT3HswkveqogzNLxth4pNxmeL4sjN4f96cS2qu9FygH52p2t2oEvXjj4BaUnPeuM=@googlegroups.com
X-Received: by 2002:a05:6808:8214:b0:3ea:6586:9613 with SMTP id 5614622812f47-3f19fe06c04mr13580183b6e.32.1737675897066;
        Thu, 23 Jan 2025 15:44:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737675897; cv=none;
        d=google.com; s=arc-20240605;
        b=ja6knAoZRwkPUlQFx7cAQ/FmVPwnyf70gf1cEpmW63IgYxIkLD1+Pn2Chty1gfNxZf
         oXh3HCnvY4QrO7pXGM9SlKe7RJr1JT/i1UT1h/JTFUHrQUh7QjLNlWgv0Odp59ulMoZo
         TATweAk9VE+livt2cjqNBJNcFTIInKEP8gDFm+JjQdbj43bzE4SvqTghpAGI9CLG4RBU
         dvYUghynT72l2nixQfI+Gtn2kM6tCOXau4HtwrRhb7B/oyyv3n1zBlWxCdYRvMPY7Om5
         7v7Vj51q2xVD4kgUFRvC40+CRbHCONfsJIHwAXbeK260CYIDAeHK6LK/ACfKTUCh5A9a
         2zsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A0ETzY+h7Rvd+LbZPMucT42xXHGbgsKSuCz/4EBdLD8=;
        fh=Wm/qMSQx34nSxX3d2TlqrhPcl86BZWuP28V+5Yag85Q=;
        b=Uhwjf0wtV/bSZDanjc/X+9Ukn1vtBjwXo8eHPAMHtl6jdr61qFiZGtlaBspZnl2pJF
         mDvUD6gPJXuRnkfFQhSpaASO/P2BLSLCX2y+MpgWOS55U0IqcXMLEKTtx378A23qZ0dG
         GkPL2KWFsBTedslNoztdhOLqRqMe6TrgTeMuWZGulUgSorsrLvG5LCXVrGjTMsvN1bri
         xf5HLwStFQFMQSkoMJLnDQFEFCZjSuDpdMR3Nh4sxlXlv9csnF4Qk5taHv58NaBte6Gr
         ipdKnhsYdhYCubrqLwZJSuJZlv4Iav4AGzobhWZA/GTvaE7oez3tX7jy2n5JliPwXa51
         oupQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HPbL8M+4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f1f09a3255si28766b6e.5.2025.01.23.15.44.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Jan 2025 15:44:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-2ef28f07dbaso2299932a91.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Jan 2025 15:44:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/ctRi1fZhXmL7bwS8cbZtE0DalEquhQCNCyQvyxRgI4vdrk32u7W+BeSEdLOdrzAs4dMSx/FbbOY=@googlegroups.com
X-Gm-Gg: ASbGncs1ffcms+Tq1w3HSJ6dFDaWlbtp354K0aEM462MaCd2i0R1XJ3Bc08WvDz/VS5
	rJ0U80fXCx6wxJmcTzKRdUCi2SRvJDho+oWbcro2cpvUHAqUOpoR+E079RnsfSHOqgPGy59VujN
	miqGI7AgbPdoCxZvyzBQ==
X-Received: by 2002:a17:90b:534b:b0:2ee:d35c:39ab with SMTP id
 98e67ed59e1d1-2f782d4ed15mr35040211a91.22.1737675896115; Thu, 23 Jan 2025
 15:44:56 -0800 (PST)
MIME-Version: 1.0
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
In-Reply-To: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jan 2025 00:44:19 +0100
X-Gm-Features: AbW1kvbdh3sgF_a89-h8Hs6yMK2YACQJdSakSNMeMPjw3tBzcyjXOx-8lYtQOvQ
Message-ID: <CANpmjNM04i3bNYJXYP8aEKy_-o=MTiW-eBEb9NmzpHoaTxwQTg@mail.gmail.com>
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
To: cl@gentwo.org
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Yang Shi <shy828301@gmail.com>, Huang Shijie <shijie@os.amperecomputing.com>, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HPbL8M+4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 23 Jan 2025 at 23:44, Christoph Lameter via B4 Relay
<devnull+cl.gentwo.org@kernel.org> wrote:
>
> From: Christoph Lameter <cl@linux.com>
>
> KFENCE manages its own pools and redirects regular memory allocations
> to those pools in a sporadic way. The usual memory allocator features
> like NUMA, memory policies and pfmemalloc are not supported.
> This means that one gets surprising object placement with KFENCE that
> may impact performance on some NUMA systems.
>
> Update the description and make KFENCE depend on VM debugging
> having been enabled.

While the documentation updates are fine with me, the Kconfig change
seems overly drastic. What's the motivation? CONFIG_KFENCE is not
enabled by default, and if there's a problem users are free to either
not select it in the first place, or if you cannot unset CONFIG_KFENCE
because you have a prebuilt kernel, set 'kfence.sample_interval=0' in
the kernel cmdline. More commentary below.

> Signed-off-by: Christoph Lameter <cl@linux.com>
> ---
>  Documentation/dev-tools/kfence.rst |  4 +++-
>  lib/Kconfig.kfence                 | 10 ++++++----
>  2 files changed, 9 insertions(+), 5 deletions(-)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> index 541899353865..27150780d6f5 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
>  error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
>  invalid-free errors.
>
> -KFENCE is designed to be enabled in production kernels, and has near zero
> +KFENCE is designed to be low overhead but does not implememnt the typical

s/implememnt/implement/

> +memory allocation features for its samples like memory policies, NUMA and
> +management of emergency memory pools. It has near zero
>  performance overhead. Compared to KASAN, KFENCE trades performance for
>  precision. The main motivation behind KFENCE's design, is that with enough
>  total uptime KFENCE will detect bugs in code paths not typically exercised by
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 6fbbebec683a..48d2a6a1be08 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -5,14 +5,14 @@ config HAVE_ARCH_KFENCE
>
>  menuconfig KFENCE
>         bool "KFENCE: low-overhead sampling-based memory safety error detector"
> -       depends on HAVE_ARCH_KFENCE
> +       depends on HAVE_ARCH_KFENCE && DEBUG_VM

This is not going to work. There are plenty deployments of KFENCE in
kernels that do not enable DEBUG_VM, and this will silently disable
KFENCE once those kernels upgrade. And enabling DEBUG_VM is not what
anybody wants, because enabling DEBUG_VM adds features significantly
more expensive than KFENCE, even if disabled they pull in code and
increase .text size.

Nack with the dependency on DEBUG_VM. The documentation change is fine.

>         select STACKTRACE
>         select IRQ_WORK
>         help
>           KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
>           access, use-after-free, and invalid-free errors. KFENCE is designed
> -         to have negligible cost to permit enabling it in production
> -         environments.
> +         to have negligible cost. KFENCE does not support NUMA features
> +         and other memory allocator features for it sample allocations.

s/sample/samples/

>           See <file:Documentation/dev-tools/kfence.rst> for more details.
>
> @@ -21,7 +21,9 @@ menuconfig KFENCE
>           detect, albeit at very different performance profiles. If you can
>           afford to use KASAN, continue using KASAN, for example in test
>           environments. If your kernel targets production use, and cannot
> -         enable KASAN due to its cost, consider using KFENCE.
> +         enable KASAN due to its cost and you are not using NUMA and have
> +         no use of the memory reserve logic of the memory allocators,
> +         consider using KFENCE.

That's just repetition from above, and I think the point here is just
that if you run tests but can't use KASAN, consider KFENCE. In those
cases, users typically would use much higher sampling rates that
_will_ have somewhat noticeable performance impact.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM04i3bNYJXYP8aEKy_-o%3DMTiW-eBEb9NmzpHoaTxwQTg%40mail.gmail.com.
