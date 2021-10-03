Return-Path: <kasan-dev+bncBDW2JDUY5AORBG6Y46FAMGQEX2XZZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 70286420321
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 19:45:00 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id l18-20020a056214039200b0037e4da8b408sf16756051qvy.6
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 10:45:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633283099; cv=pass;
        d=google.com; s=arc-20160816;
        b=XLW31xSQq5ngwP1cet3t4Y+Lp1UL7dJagmz+Ecr0PTwaW3MP9+ejcZb6xhbbz+31UJ
         MoLK14Rbba8pjHUvs8+toKIGX1kFGLIy9IbCtmCqSyu+KzECAKpvO1UnBqgjLNbXPoHH
         nangjIwxfErDfLAxHEaHmojWRf0PLvdiXlH+QTx4SX6ZVBzJ869SLpCBWNpd1ZmDTJWz
         USUn7mCSpaX6jRqBRskJNPeqEPQyRnybG8PyjEyVZ2XzHtnbp47nVBnij1gw20Jj9R5A
         x1OhGroKC88p22lWx5REJryYOo+wwJERBKTsN1jrdXoKNVp814qhV+VUX7JLhJdqNWI+
         FdvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+K24EAypLINoKUHj5dt4taMYMHxS81UqDmCMRuZD5i4=;
        b=fikHVx9MbR/38o4Wxmmx082Pv1WJ2aPBMo2NiLmuDEuv99BQjFS3EnzP+3aoD2KmtS
         FXvUV4y0LHihhpZMd27hVBi0275v0Dk3oS+appomX1PZc9QUayIjcr78XvT2JGmbWGmF
         xOL+hXNQ0nT9521xHsVT1N4TkthZdpZyoVCQc8yeFyhVhn7+8nTPDZocST2WveiJLnBM
         Se3WdttW6Xf/LZF+Tttq6ed4bgoC3IgPO/PEaHyl8WXiFKoUvaiwVsTYzK/Qn45WunDq
         XXrw1b/7cWF44Ob6RA+XCA7ZDX8ovERGP6trUGNACbZajiAmoAJwZTSRKFCpXA+tdXX7
         oYZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ljhVUGUp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+K24EAypLINoKUHj5dt4taMYMHxS81UqDmCMRuZD5i4=;
        b=WpmTtlHHx6q77eXK4gVRNpeoQaELOG+eFzuRCDVBu40pFedwspTvsNN6QschpvonY8
         R43ciNyWSPYV1/PwkwCrLVFZpBkMrHvdq/YjQ8aY51A5VbsDJAFZx15JV7npMkfl7SCs
         XLHcpjHwJmgVffKzyYz1O8Oey+X2hRjC7uKP29Y/+dNXZhV8Y5t9njS7Djr18zE/rBhZ
         q2a8usdpdYnxU5YHOOGDuCGk7H1SWHyN530UfUjLawM4Iwz0tX+hP5MuWyz96ENxsaky
         eHNJbLD1HDbecnyrnMk7pJySpBI27R86u54IXOhigAv9ms6VqGDLmyD3Ryt4clN/k2MM
         /nPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+K24EAypLINoKUHj5dt4taMYMHxS81UqDmCMRuZD5i4=;
        b=Lj/qdQYY10FDHjQLxK3qHYWHfq8dccBykr9eFBfBv41IZ0gZJQP1lUQ7lVhgn6yS9T
         NMrEalZPUcmNJGJIWNKgdup19Vt8AJqCpT4zamKx1gQHNtU3IhtaozXP+5P3g92pK6vR
         803osRx3dgyUAosUbBXNX995UNoEAID/2ooYv9F1SyB6cjOjEEbbZTnfANjYiqb7yjMs
         L5elr94BNQQk/C/QOXd8YTOFjudpG4yjh/fEhJMiviJmhMgGTQ4BKw6hm5XLTIrRcemP
         xKfsU8sUH1Qq9Z62uhvN0xXmiB5hqzg7UmKRQFYZekLfOHDRhRAazpPcFGCdPm19sT3Y
         MgVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+K24EAypLINoKUHj5dt4taMYMHxS81UqDmCMRuZD5i4=;
        b=d1eSHwm4lW3BwOtHRwvSjuXJswb/OdhXirBukD1sUhySNo+wJRmqSaaHw/O4qVn3t/
         8jAZJDxRRROqhsjzEbPexikKBJ1BtiVUjHK2VbXTgCUv1gKnCtFVWo0xDJzTasToU2sZ
         oikfMTaHmLQIivj4a/HwuuaSwaMKRC4ZSQo8kcZ1UGVidoUAyzmjozywbaIhOgoV2UO0
         S8iPP+qolw1/3yk1T2ZQkOrbB7chhm160DFRky462rPcwtvJvRpqzx03Rabad6CHYAnk
         axjimM0/dgI2IKWCngSoDo507ndCasMpSjLSBhSiaKVhmcCauGXOLaAAq5F24E4R/34X
         DILw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332Qdo5NVifV+pQERr2QSx/egUyec9Md9Erc8S2sVhLiy8QrKh2
	bZTFwM4+Ndg9OOCvi+YwCcU=
X-Google-Smtp-Source: ABdhPJzbofpZ4jWUFVR2wfjmNql8J4zHeWriaI5r4j5qHtkDlsVAM2tqwC2D7wsrlbXBLaun7MjfRg==
X-Received: by 2002:a05:6214:194b:: with SMTP id q11mr9867656qvk.38.1633283099442;
        Sun, 03 Oct 2021 10:44:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1986:: with SMTP id u6ls9223025qtc.2.gmail; Sun, 03
 Oct 2021 10:44:59 -0700 (PDT)
X-Received: by 2002:ac8:411d:: with SMTP id q29mr9491634qtl.349.1633283099018;
        Sun, 03 Oct 2021 10:44:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633283099; cv=none;
        d=google.com; s=arc-20160816;
        b=Bry788nYPdiXqGLPIeg2WfpthG0rkWxRjI+VAk1moN2SbuWA6T6twU6Q3TfkMhv3U1
         ibBUk8mHK1N/msIf+LRrCmMYUyX7+X+KJTsWD4EX8soDZoxS1tHv1Zj38tP1kMccWrrm
         k/S0hayYkmLWLZW73k7gU9I8OTCX/NrWmcXVBRz2JEOI8L5IaPzP/vuwRa67zQx4tEn5
         tmimDJoo3iBej1ZrUa/pZKHgiq4aCwroPqBwy96PTzZEZ3uXjBMNP+IYjXD54F+H0lFo
         iKf9KioZ37ZclqYQ/HMdimHdzKJhn5W29hPnCscqCpc0n99AnZSQGmmIp+PVw+JnKxAF
         mPQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mp4gE8Pdgp9F3QsQ+TI83mCss9lxb0cc4P5dIGC4QWc=;
        b=StWFfcESO0+l5XfWYX1v6zuCP883E2Dsfwgh6TzJO9hBXpvNIcJDXfNCvwE8yndi/8
         Jm+zBKpF1L4Qb+X83jfN1BRJ9movUgox2zeiWuZuCoHabuJkvgEa7a5eZZNUQeMK/YLd
         Oi9WvWROz8VirDUx0djozJUhzyqD75kZCW9jxlPFcFe/lDvRIFjkxp6KsDIjbIFyFVQU
         6QBJeEzKXbfzKzkNN7cJpSvL/ueTt2RAcA6IhVGmXDkpGatx3hAHqgofVlq7DVvYzP3u
         Es3K2LtBjnOZuWa9NnElr9OzXDlELvoOn3BSRf8pI9x48oTZ8XKLdCbKws8IK5C4SlFT
         /gZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ljhVUGUp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id o14si897591qtl.4.2021.10.03.10.44.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 10:44:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id j2so3516223ilo.10
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 10:44:58 -0700 (PDT)
X-Received: by 2002:a05:6e02:1d1e:: with SMTP id i30mr6971309ila.248.1633283098568;
 Sun, 03 Oct 2021 10:44:58 -0700 (PDT)
MIME-Version: 1.0
References: <20210910084240.1215803-1-elver@google.com>
In-Reply-To: <20210910084240.1215803-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 19:44:48 +0200
Message-ID: <CA+fCnZe=Wuj7bR77nUoWs6PSUJE4rFLpJabQbJKE=Wn24_Viow@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix Kconfig check of CC_HAS_WORKING_NOSANITIZE_ADDRESS
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ljhVUGUp;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Sep 10, 2021 at 10:42 AM Marco Elver <elver@google.com> wrote:
>
> In the main KASAN config option CC_HAS_WORKING_NOSANITIZE_ADDRESS is
> checked for instrumentation-based modes. However, if
> HAVE_ARCH_KASAN_HW_TAGS is true all modes may still be selected.
>
> To fix, also make the software modes depend on
> CC_HAS_WORKING_NOSANITIZE_ADDRESS.
>
> Fixes: 6a63a63ff1ac ("kasan: introduce CONFIG_KASAN_HW_TAGS")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/Kconfig.kasan | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 1e2d10f86011..cdc842d090db 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -66,6 +66,7 @@ choice
>  config KASAN_GENERIC
>         bool "Generic mode"
>         depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
> +       depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
>         select SLUB_DEBUG if SLUB
>         select CONSTRUCTORS
>         help
> @@ -86,6 +87,7 @@ config KASAN_GENERIC
>  config KASAN_SW_TAGS
>         bool "Software tag-based mode"
>         depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> +       depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
>         select SLUB_DEBUG if SLUB
>         select CONSTRUCTORS
>         help
> --
> 2.33.0.309.g3052b89438-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe%3DWuj7bR77nUoWs6PSUJE4rFLpJabQbJKE%3DWn24_Viow%40mail.gmail.com.
