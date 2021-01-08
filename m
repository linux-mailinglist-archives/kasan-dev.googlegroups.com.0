Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG6J4L7QKGQE777XZYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E37652EF755
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:29:48 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id e4sf7526821oii.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:29:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610130587; cv=pass;
        d=google.com; s=arc-20160816;
        b=u07PRznqUBJavg7kq5pnVMO4HJlgqeGypZiCr2YUW/TbvDFx3zXNyapPuuMZcQh/Fd
         ktSHhBMwRsjl8OWRJBFQDIO+2e5LhEry6x3b516QI73C+Q1IKN2DrFU0b2hCvemtfbct
         VgRwYeaXnfJVCRVkgmTNwm5w7cYBT9yp299YgRcnsZa4JBYb3dL2T89rYb3P+oSunQaM
         yf08udDcwoCp1drWj1/deGxF+YbcE/9CasCbd5Rs+YOgKElkdoGyLwKlsmAIVdkVhJDB
         gKaiV7yGQIyfeoySpdl2hwXTswqBz2p631DQsYtDr0Cj5HXrP9YPB3sncX0Eg6t2sFzf
         Q9Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zo9ZPXwmO3th5tU1iAEU3RPTfXbMjnzGFD9Nu2a/L68=;
        b=bMUU1gwsDtgLtiZm2HmCxm5x25jtD0LSc+mCNTDVQilYzpHs87EjfLTJkuDEi/MwPA
         3rNavd6tkAss2e77aIqnm5AevA+iE5s5/uygqGXbn+PK7M+6Y3TRiK/MObV+uJtujm2h
         5gXavuCtbdUeQuNcCpaEUiaMWaqzKO0dwguBK7zqu0pzyTUvIbkQFU+3Fx7oRFlwsXmr
         W49ZppQ+AzSSwyRo+kUzJrlkWRhQjH8ILvc3eiTyfM+HvP30enCATgLGHl0o8Ep0Y19g
         SHZY3F/8JDFe8jIPejHDXbjlNGwSAoJvfl5ZMcS5VTF/XnbHvvcKkfEceFpedSw10516
         CTLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y0K7rPxt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zo9ZPXwmO3th5tU1iAEU3RPTfXbMjnzGFD9Nu2a/L68=;
        b=mA/6uY3TwbxpPR+Ndj3zDfsKwzUU+0QoKhVKIOi+XnBDe1N2iB8pUt1XrLvBp8I2HO
         Hoi+SxDNAbQxSM1f031o857wL5HB+ocYHMMYgzxvlTy55QX0iXhAJjYlBDUyU9JHOcYI
         uK/pPigSltrKGUHm5xOYDopH/pzYJMj5zZJMeRE4tpNyxDq87R8qzmLT1HWvVjU7+Sxl
         4xoG+KtNnpbIhgtY4SGhY6l0rJUyVyOgVtCmswW9uqdbAMOOz4LEULeiDm8YZW/S1ZiU
         4qq3MDnJJnsA+VoCoyp4KvAJTbMw8vXyciwIlTSzjhJugALR7i5jC2+4VOJW7VrmakeM
         UbzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zo9ZPXwmO3th5tU1iAEU3RPTfXbMjnzGFD9Nu2a/L68=;
        b=UzbmD5BQdGMg4nkRjTZDvk4xvMmQNkBB0D5mORmKZCd+FZ+SR31ehDjL58gfe9vvda
         BNXUAUQgAShUVU7gZYt+II1pNgZzXRc9d0dw6fu8vhL7eJZ67v+ZJP48fCznF36InisG
         +92cuVZGwPTp//GmNPL5xBIZfzbj0heH2imYBeAmCwXq+MIlcZIXim252JGcMS3hg18G
         jrbdBRl2t/dZ+UvpxXtegcXb26lZDj5IMjDMfy6fA7B5AsONyD4FN5yH/MZunwVqffwR
         1GOn1lhoPNxAyTIyfWfFdMn+otx70vz356c/0LbZk0JYonbT2W/aFnRCOj2opPOue972
         ZdAA==
X-Gm-Message-State: AOAM530sQkh6I8oJ4vxSRDpJCH9IJtc/yJO3+ULhCqXu72u1BSnkO+u5
	fMm2bpOYP4JyTf5XzkV+S6g=
X-Google-Smtp-Source: ABdhPJyEaCWjzqK5XalLg4Crz2x4THVk8N4heOKG7pQ68f5WcYNomOnu6PwUJKjQK2lghuzRNKOFoA==
X-Received: by 2002:a9d:46b:: with SMTP id 98mr3586149otc.200.1610130587462;
        Fri, 08 Jan 2021 10:29:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:140e:: with SMTP id v14ls3214224otp.4.gmail; Fri,
 08 Jan 2021 10:29:47 -0800 (PST)
X-Received: by 2002:a05:6830:22db:: with SMTP id q27mr3299896otc.19.1610130587149;
        Fri, 08 Jan 2021 10:29:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610130587; cv=none;
        d=google.com; s=arc-20160816;
        b=Iq+MJakP2c9HZES1ttSyNVSIaPnLBYBD3bZ+5KKuidYNlSxKJjAZsF0NyNRjG1fyUI
         +KjyvhV+5KXOrevvNLZZfW72J4S3/XBlPpgsi0rKlUHL6MxCL4/jejpOTG+sMnSSPq7n
         q3PgstDwx3H/+PyNl/pi0z2BZCMXWlSyxi7xjzL/k4bEe/tqV2nQndMuxx74va52vSKj
         uBD+8byII6cQsZh0RTVDCaOx/ba0qd6xqXsl8PUbQg+Lz6hBRjK0KDqrmCa4Y4MTRmxz
         6rXFramuvBiHMf8UtesOAmQENehS1qCG1I4onFr81Skai0TrhhyScnNcEwNUDTau631/
         jRkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ImNmyS8KVcMriGTOlK4oD0X1A4b7wVMix0T8JHsJDBw=;
        b=QOGyz1e+Cuf/3ajs3aaBIMsxbxZz/0IHmUMuTwIXb17kPFimh4FAaBEc70yGI3CSti
         PmcoSqBC+lCvLxXpgUr1EyMCI9vKhhLWVxqtnWh7+mZd4rCs3uSj1A7dRivfsBMzqMk7
         qfSgEOLFBpI81qRKkkTn0sx4T+2TgNec7wfSgNU6H3zBeCzGDyg9KD3hb9g50QyL2u5h
         LmOzZynjq+PFpW0pBZor4M/zWSnjU7heRdIq1HrUx/3MUsj/cSJ9wAHkq//hBvkeHw4v
         sq6BSCVmOOR0ubzhkRfIqjJi/fwkR86RWbDkYGXuP13hkMDnOSHvBBOdauYZZQV4v81F
         +W0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y0K7rPxt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id u25si1086330oic.0.2021.01.08.10.29.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:29:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id i5so8167716pgo.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:29:47 -0800 (PST)
X-Received: by 2002:a62:14c4:0:b029:19d:d3f5:c304 with SMTP id
 187-20020a6214c40000b029019dd3f5c304mr4738308pfu.55.1610130586296; Fri, 08
 Jan 2021 10:29:46 -0800 (PST)
MIME-Version: 1.0
References: <20210103171137.153834-1-lecopzer@gmail.com> <20210103171137.153834-4-lecopzer@gmail.com>
In-Reply-To: <20210103171137.153834-4-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:29:35 +0100
Message-ID: <CAAeHK+wc-DU2pUma43JtomOSy0Z6smGKwQoG_R+uKzByu3oZ9w@mail.gmail.com>
Subject: Re: [PATCH 3/3] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y0K7rPxt;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sun, Jan 3, 2021 at 6:13 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> Now I have no device to test for HW_TAG, so keep it not selected
> until someone can test this.
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm64/Kconfig | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 05e17351e4f3..29ab35aab59e 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -136,6 +136,7 @@ config ARM64
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> +       select HAVE_ARCH_KASAN_VMALLOC if (HAVE_ARCH_KASAN && !KASAN_HW_TAGS)

KASAN_VMALLOC currently "depends on" KASAN_GENERIC. I think we should
either do "HAVE_ARCH_KASAN && KASAN_GENERIC" here as well, or just do
"if HAVE_ARCH_KASAN".

>         select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
>         select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
>         select HAVE_ARCH_KGDB
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103171137.153834-4-lecopzer%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwc-DU2pUma43JtomOSy0Z6smGKwQoG_R%2BuKzByu3oZ9w%40mail.gmail.com.
