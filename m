Return-Path: <kasan-dev+bncBD63HSEZTUIBB4PEUP6QKGQE3UQCVAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 083F42AB1D0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 08:40:35 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id k10sf3693449pfh.17
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Nov 2020 23:40:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604907633; cv=pass;
        d=google.com; s=arc-20160816;
        b=sjSoz+ySZUZAxdav9Bd4M1C7cZ7UzpGHHeKKrlVeIOkPGyEQ25Kj8bgkDrlPjSavhA
         yb0foUeNY4tkpHzwOt4fzHiuBhGlTYVxYQl9qkZnSV9EPXMDOMOTLYENQ+1OWJmPzbdk
         xH6UFxkQt8eq1eHLXyMIbHepj1f1SoQ8RuGAfFLMoY7qRoLC0Il3FtJJXqHsL6bVqDeh
         if0PNSipDysTFKl/uMDOo+dOkmZo1T4DXY5BWoA643ynG27roHj/CTNPCXL3TEDfcvjc
         nNwI02cVWoswpmy6ufWZeIXbWrjgpS8fGFUdk2HOm+7iB1zZ92shuUXmNakwVyq1S2CL
         9CQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=4mkn8k8mSNJ5lQ9AmRXrhfCYQnAVAYVdu2LiaH+LXsc=;
        b=ZbO44Xy9SqMpzMNLgMeIDRUwWxGZp8sqXdzIq5cX4hFMx7KLy0PZ9PElLoXyfx2Fs3
         S7o87WWScreAwC9cHOC6NEdD/Y3zAvIPRAda+wH+Nig6592WKaRNtJ17PSPPgvhp6Qm1
         wyZXcUQ3j6P4YXnPGDfO6/OSggeKIp4VFqRxHncTHQxlblAlz/TUjqW6hwTxK/VSQ3ZS
         /PiPHuEYUlfMyDuzhQ78/0Tk4N/THsx0673nkfJISrrHt/Vdv5UDZjxYBfce4ougSDGK
         8qHDcStaxkntegP9sVsL6JgFMkF4guthgP+MuGMQfVmYQsu2y4EadDyyy9RFjLA+qRFy
         BlZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DEDESS5U;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4mkn8k8mSNJ5lQ9AmRXrhfCYQnAVAYVdu2LiaH+LXsc=;
        b=MPeFtD6jBPJWchADJt4qg97kcWbiRGq1YeKmYAR4WU4dTwRovma0W+oZHCDmcs3Suf
         ZocshYvdtYThoFxQuR5/bPWAcDb4Y1Kh4JoTtdIjFXrBc5WBTxjhuydOrhazwEWOte3P
         vVaNAjaeccWiK4sYZleE7Nh6AfJIiKi9kSWd2HB8fWqdYgTxKA2z1jsLpAkqMTQu7wuz
         d0zbAmwP5veKMHbKvYqTsn8Wqnpt9XYmmFTIF8XJMd1LThySgR418xeTUYWXCAhhF6PT
         /9DC/4izjsRUddgTocSEkCqzJyr5UA9k4Pd2tgbmTHW922N55noGiF85Cs4nS6qU072N
         GUyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4mkn8k8mSNJ5lQ9AmRXrhfCYQnAVAYVdu2LiaH+LXsc=;
        b=CYtQjEYZR+xDMQme8EThpjIVO5yL6tId29mx6oCYFFc6oj7IgKFtzZEFYAYVMOzf4F
         9ULxcmMjd6m39vBR8eorsqGapa7CVyJkHcbFxavMv3P9+9kg6IqKWoP9EtByDdTZT/8R
         9Q8ZxzLpc4IRXAcVlwaSCbRyLix2261y8bxan/Wyea6dm2NtQ/pAwRgmoMLmCgo3OsLF
         ufRxNgfgqgS2HeXoR+gZHYUrC6TFPDNNoTrYN9jxZ4zi0umk90Ui5rOXN/z71ZCHFSws
         ihBYlf2b/4Y+0E9WBiY6gtdFhstPwIf0ReFKBaqizhuWCq7M98hjhUHR8cy5tMjvB74y
         sanQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301Nw8WlIH9ksm4tYJIpFsdHDNKDD/GR6l9H/ecHaXFuwyYBQJF
	k7WH43iepscCBHGMFhzFvm4=
X-Google-Smtp-Source: ABdhPJxs3yndlOlqI6Aco/doJPUGKDZksLmoi/RvnW3AOjXY7H3oUdBhfNAR9zDKBkKEZcE239fseg==
X-Received: by 2002:a17:90a:4281:: with SMTP id p1mr12377126pjg.87.1604907633362;
        Sun, 08 Nov 2020 23:40:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3712:: with SMTP id mg18ls1411992pjb.2.gmail; Sun,
 08 Nov 2020 23:40:32 -0800 (PST)
X-Received: by 2002:a17:90a:fa4:: with SMTP id 33mr12280527pjz.47.1604907632866;
        Sun, 08 Nov 2020 23:40:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604907632; cv=none;
        d=google.com; s=arc-20160816;
        b=n1dkSVm/CJvUz2xdjO/GY/k+fyTHT55A5Mk9H/QOvUTaAUAQPpwMnZyR4KEgTJohQ4
         T5RRO0L2BX/PZQnLFzW4YsHhejgUl36JPHtC9XcmyNA5MiuK1X7qm3UCDi8dwTFOD2Xf
         zIJvJ9QwAuEO3Hz61Gmx1HUbyBa4Jsl7zCFSwXp77zKDj/J+fqF7ALk1ExuLadHEgq8m
         CIVWCGCtvabYTMkar0+nYTtoSBh0GiSOSn2H2DygMCl+1svidr1ehK1cGtmbyCO4m+lb
         YBGSyacd1ObAi/dCBQAPinDAJRudMVhLZDtMf8vXuiwrhGYrL5d83XbNGVRmrC7yjwvw
         84KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wNK2wV97qqTJzMeZQmuACzieonFnynXDGPHIieIbSXg=;
        b=N+YMupyCJcaVoMVbYYBqF47EOjq4tLwDYwvRiBYMGs5CydC/ovi/gqdFI8uTsZuFud
         W1TITytnacQ+vwztWf6Z2Z4sY6ig1i2mOsCYtrfgQnCarpoBFxp16AEtjIRQCNIqMQT0
         wVovwV0XHtu7bbFXSSQXxn/XyeKy352tVW+8JzGnHfK3LGS/UoJJbVh6b573/XGYBvV4
         aslsKsWsmhMx2Yt20gjRncgPP2Fb/KxCq41GgzscBqYZEZnxCBc2htiezIzNrS+mWFEp
         gp73hMwoKpqqnuKciIgzOhRPys2N1f7qhqCk07Hb5eBdv/jp1hB1NKCa0sK+SbvI/jRz
         sJFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DEDESS5U;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m62si616396pgm.2.2020.11.08.23.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Nov 2020 23:40:32 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f47.google.com (mail-ot1-f47.google.com [209.85.210.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 44040221FE
	for <kasan-dev@googlegroups.com>; Mon,  9 Nov 2020 07:40:32 +0000 (UTC)
Received: by mail-ot1-f47.google.com with SMTP id 79so8031802otc.7
        for <kasan-dev@googlegroups.com>; Sun, 08 Nov 2020 23:40:32 -0800 (PST)
X-Received: by 2002:a9d:62c1:: with SMTP id z1mr9182745otk.108.1604907631229;
 Sun, 08 Nov 2020 23:40:31 -0800 (PST)
MIME-Version: 1.0
References: <20201108222156.GA1049451@ubuntu-m3-large-x86> <20201109001712.3384097-1-natechancellor@gmail.com>
In-Reply-To: <20201109001712.3384097-1-natechancellor@gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 9 Nov 2020 08:40:19 +0100
X-Gmail-Original-Message-ID: <CAMj1kXEVX7za8JM3_STCeS8-j7WcvYq_vtUU7Or=yT+T9Jj7vw@mail.gmail.com>
Message-ID: <CAMj1kXEVX7za8JM3_STCeS8-j7WcvYq_vtUU7Or=yT+T9Jj7vw@mail.gmail.com>
Subject: Re: [PATCH] ARM: boot: Quote aliased symbol names in string.c
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Abbott Liu <liuwenliang@huawei.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Florian Fainelli <f.fainelli@gmail.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Joe Perches <joe@perches.com>, Russell King <linux@armlinux.org.uk>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	=?UTF-8?Q?Valdis_Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DEDESS5U;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, 9 Nov 2020 at 01:19, Nathan Chancellor <natechancellor@gmail.com> w=
rote:
>
> Patch "treewide: Remove stringification from __alias macro definition"
> causes arguments to __alias to no longer be quoted automatically, which
> breaks CONFIG_KASAN on ARM after commit d6d51a96c7d6 ("ARM: 9014/2:
> Replace string mem* functions for KASan"):
>
> arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias' argument=
 not a string
>    24 | void *__memcpy(void *__dest, __const void *__src, size_t __n) __a=
lias(memcpy);
>       | ^~~~
> arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias' argument=
 not a string
>    25 | void *__memmove(void *__dest, __const void *__src, size_t count) =
__alias(memmove);
>       | ^~~~
> arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias' argument=
 not a string
>    26 | void *__memset(void *s, int c, size_t count) __alias(memset);
>       | ^~~~
> make[3]: *** [scripts/Makefile.build:283: arch/arm/boot/compressed/string=
.o] Error 1
>
> Quote the names like the treewide patch does so there is no more error.
>
> Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
> Reported-by: Valdis Kl=C4=93tnieks <valdis.kletnieks@vt.edu>
> Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>

Acked-by: Ard Biesheuvel <ardb@kernel.org>

> ---
>
> Hi Andrew,
>
> Stephen said I should send this along to you so that it can be applied
> as part of the post -next series. Please let me know if you need any
> more information or clarification, I tried to document it succinctly in
> the commit message.
>
> Cheers,
> Nathan
>
>  arch/arm/boot/compressed/string.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed=
/string.c
> index 8c0fa276d994..cc6198f8a348 100644
> --- a/arch/arm/boot/compressed/string.c
> +++ b/arch/arm/boot/compressed/string.c
> @@ -21,9 +21,9 @@
>  #undef memcpy
>  #undef memmove
>  #undef memset
> -void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(me=
mcpy);
> -void *__memmove(void *__dest, __const void *__src, size_t count) __alias=
(memmove);
> -void *__memset(void *s, int c, size_t count) __alias(memset);
> +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("m=
emcpy");
> +void *__memmove(void *__dest, __const void *__src, size_t count) __alias=
("memmove");
> +void *__memset(void *s, int c, size_t count) __alias("memset");
>  #endif
>
>  void *memcpy(void *__dest, __const void *__src, size_t __n)
> --
> 2.29.2
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMj1kXEVX7za8JM3_STCeS8-j7WcvYq_vtUU7Or%3DyT%2BT9Jj7vw%40mail.gm=
ail.com.
