Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVZYT7AKGQEGBP7HFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id ACB322D4977
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:51:19 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id z68sf1655032pfc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:51:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607539878; cv=pass;
        d=google.com; s=arc-20160816;
        b=pOTaZHsh+O6mPftRuz5w7HOr7VQdOloDEeyRzHl4q8cvJTjduJP0veJMBzqe+OmyzD
         PwhdSCDA/fCdQv4nxSp+wvTekkLFffEDDKfmodIsqR1kqxDatXivKSU48AOvUY7Lmh/E
         Dih7e1NGXS+ycocVDiHUV4lQS/PMQVmq1nLjSV2/sR4iLtC9kywbUGR57JM0gQ2Tyfje
         g/JpTRBVBhy3Vxh4RG3E31kV/8Aa+GdLQ0lKwRoFP9+jp6XbWlskPlPP62NR/5XLs9NR
         cRux+1SknlA6Z7OoNX35nIJBq313vs7Nni57GYjMc3up+DhvM3B5ah83e552QVoBcexD
         Neyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XPROPzxpKDCjJUWZM61vEYYmBtr6algjJLmFrzzjXYo=;
        b=zd5opsuCmcr97ZIwnyAS8qp+fRKQdslTiuWgE2BNWJJEcGhB49G+fxq1PAx5cXkTiq
         ZBOBUyDbcdvSqP0NCIGABbdVBMVjOo1LogcSxIvZLyTxMOYo4Br6r5ZiP/vF8kg/9m/l
         LX8dm2/xcExooLtwGxG6sYGBVmbpnOuC/En4xQkJHoM8YRXHEW18uXYQ6N3eGYUs8Md6
         ZztQEsi2jnFb+saiHzNT7EiIUVjWO40GLeIYqbdtKWv2Wkz4IKQoAucCYwZ/6oZSELGf
         pdWTHsqsdF4yGTPEKm8Yq5S+c+jvIT/tv7uXmH90RwIPac5xBnKtX4DU/36qRtTpB90J
         zOOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hc+1o93c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XPROPzxpKDCjJUWZM61vEYYmBtr6algjJLmFrzzjXYo=;
        b=M+ne3YtYkzq5ibvSmknMrZjyjEOSW3a712rQjN4/xaQmy+Qsve2u+7nucG0m2ZlR10
         gwXavpy+F83skFLU3F2i2Avt54qDIRfTlZ0bjGDAEvU5JlpE0aV7B5qAo12j3XxgWAws
         b4txVD4+QCA46ryAyKVSrH9IU/2sdrGJibKfz22RsAIiuuFmSWnJXN0viQiD2nRaBx09
         JJHhqf0AbQxHdcmTYSpIr/6RIdgOc+3HUW96TIL7Z5V241vJR1GvNAyJzIVRPuhD/zh9
         zQyVUAYAjSEWQwmGLXeSKSmTDQLWgUjz7muqLkxETMxj2vCjgM9s5uO3uHrZbk+IzVU1
         iAQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XPROPzxpKDCjJUWZM61vEYYmBtr6algjJLmFrzzjXYo=;
        b=H5SZQ0jsRvUZ/LZK8yaJTxHqYdV+YV+F2J8+ibHmUxPeK2Szm7+1fNF5bzZfXStnk/
         xa8XRSrnJUhS25dqHo9W3670h3hRM/pgZzfC9mLbV6zWSq6pEoQTlV6fiX7IhMowOn81
         hAt77KmUbNTr/vrr8Nj/2V77wl9E+CqeA/hPIP7tya8jn99U/+vqRiVbmOLzYeNoUW6y
         6YA07UnDwh1Sz0nj7Qqjgypr/skAOxsyFJt6sfG5UtDhjOUeA6Av/g6BR5kOD+C0mVV4
         Oc2g9og02MHTeqp6yhUnAtzkRvx/PMuDIZNWGPC/DsEa+55sRkNjai9lInnOrLRQad/S
         uznQ==
X-Gm-Message-State: AOAM533yuDSwzIEWujA/rTkv8Hw0on/oiOpHkLTCGkzDDFe7OLAjzlA3
	HiyZM4TGOqgqxqOo49ql0x8=
X-Google-Smtp-Source: ABdhPJxD1312BuF6JQNVmZ0PC0EA7av6x6Ovx6RtR3jqzUaePhzbCfdhgrlTtwu8Liry0Ex1vl1NuA==
X-Received: by 2002:a62:7693:0:b029:19d:92fb:4ec1 with SMTP id r141-20020a6276930000b029019d92fb4ec1mr3514879pfc.4.1607539878439;
        Wed, 09 Dec 2020 10:51:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b82:: with SMTP id y2ls1247146plp.5.gmail; Wed, 09
 Dec 2020 10:51:17 -0800 (PST)
X-Received: by 2002:a17:902:24b:b029:d6:cd52:61e3 with SMTP id 69-20020a170902024bb02900d6cd5261e3mr3273020plc.2.1607539877843;
        Wed, 09 Dec 2020 10:51:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607539877; cv=none;
        d=google.com; s=arc-20160816;
        b=p/jjHZ8RNq9ExMaC/LLA/hizTM2yYhP2mJs8PVYSXZmiHJKv06uXDHbUaEh7pyj5BH
         SE5Bmr7jo/fkkL7SRPQx0GMeTeZkScp91C/bTF5j6mDAx/ZU52oGne0e6bgfYmnZ6qEJ
         C1UKx3/PKDdFZ9B7bYqjV4f3Cwv20RVisTNpfvXZ3OYol7wmDlW/ORpb8GOUccqF4KrV
         s0AP5Sm0lS6mtBztOdmcXiM0QP8yH+JIuaE2qo0Xn9MGUk5FbMkny4HSyJntlW7VhV8z
         NIsT1wBA5NujRmDBQ9NnEhygz4Lv10H8/ss6sGl5YyNMJZumArxba7GjtqXczXtM4Nic
         ADaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YT5BHJcxpuXHRj14Xs4MOizg/4PTRYgUUf1aSMIZM3Y=;
        b=SATmbgPOIGvLQ+Ft3M13khGsMLughZ+nQgwbF5sXgtz2NGa+agYsKZ+U6Gd8U0qxFZ
         YtTArTsLLX37PVIUCiW6AtmpAk1aITWth+THyzHKMMeQa5xBhMdQhDxDC0RsEhSrZpgg
         FGz8Lj6XuLnxinvCcnZJ2IfFkjJxTsSO8tspmzuaLGJdaBX2iVzNwGOH/TSECE90UgSy
         6loAiJ2VtaQdFe7Kjs91OQpT6p1rW0nY6a7RQk+d+jQyAPyUaOLCg/V+bgZxqK3jUJBx
         CcvdRmtTlaiUf95fqlwpeYFbnhXjI4hFIvCQqYRJDzDAeiXxi2EY6Js7nA1KInqHrZs4
         H6yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hc+1o93c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id z10si193314plk.0.2020.12.09.10.51.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:51:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id b18so2409713ots.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:51:17 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr3011278otn.233.1607539877102;
 Wed, 09 Dec 2020 10:51:17 -0800 (PST)
MIME-Version: 1.0
References: <cover.1607537948.git.andreyknvl@google.com> <a6287f2b9836ba88132341766d85810096e27b8e.1607537948.git.andreyknvl@google.com>
In-Reply-To: <a6287f2b9836ba88132341766d85810096e27b8e.1607537948.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 19:51:05 +0100
Message-ID: <CANpmjNM9suHQY-uQN9g5h=Vdv2wotDKNdcnHM=-RTtEb2sCZTA@mail.gmail.com>
Subject: Re: [PATCH mm 2/2] Revert "kasan, arm64: don't allow SW_TAGS with ARM64_MTE"
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Hc+1o93c;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 9 Dec 2020 at 19:24, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This reverts "kasan, arm64: don't allow SW_TAGS with ARM64_MTE".
>
> In earlier versions on the hardware tag-based KASAN patchset in-kernel
> MTE used to be always enabled when CONFIG_ARM64_MTE is on. This caused
> conflicts with the software tag-based KASAN mode.
>
> This is no logner the case: in-kernel MTE is never enabled unless the
> CONFIG_KASAN_HW_TAGS is enabled, so there are no more conflicts with
> CONFIG_KASAN_SW_TAGS.
>
> Allow CONFIG_KASAN_SW_TAGS to be enabled even when CONFIG_ARM64_MTE is
> enabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  arch/arm64/Kconfig | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 6fefab9041d8..62a7668976a2 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -135,7 +135,7 @@ config ARM64
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> -       select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
> +       select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
>         select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
>         select HAVE_ARCH_KFENCE
>         select HAVE_ARCH_KGDB
> --
> 2.29.2.576.ga3fc446d84-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM9suHQY-uQN9g5h%3DVdv2wotDKNdcnHM%3D-RTtEb2sCZTA%40mail.gmail.com.
