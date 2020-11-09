Return-Path: <kasan-dev+bncBDE6RCFOWIARBH6RUX6QKGQE66N6EJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8D92AC072
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 17:04:48 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id j9sf2086152ljb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 08:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604937888; cv=pass;
        d=google.com; s=arc-20160816;
        b=gdeZO6L6dmmoQuO9DzuBHvFr67IJhfw3hms3YULsSexu+Hz/vNZlNVMt54jsGL3QVH
         QuUU5cYb63aj9F1Zi48KQjMA7F16n/SIfAAnfctRuJO9Jyjj9WQO3/ztKy3A2YSi1qy7
         yYu2xNWt7PJBO+xntPEAgFTVZLdBK1wRu8OrxAaDGx/OsMZ9nE3n8QL/BTGEVArfJO2+
         JNHjLjbJBCQnwssqIFhz3gAKRbYuggdxiMFuo34ZN5Wxie4Pm2h1WpXFMxrRuWrKxBg8
         /Ql2bIGHcbxWabFOnSL7CgQzRs/9Ua6Djy835y0kDwSQMtm4agmZtVaIJ0XKIdIz6cBi
         kSEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=QyJ4qqSvqLl5xBh27eUPajsPjZ6tNLcL4Kwk7JEJVkQ=;
        b=yecdjw6xeqJTGcjx4w1H5ofnwSBynH20qKY5xPD5qp3VVYgBEsT0XfzzJLhdcVA+BY
         uOyi5n+Z6xMSXlcK2TdgZ0lV2n2M1WWnhzIljnEn6XQpuNKuA2Jz8khOTBC6dRienRfn
         CoKC9RrDzy4FgQNbAwaKSMhEKpp4hBxQIVNckvBleH5pxB9+KqflDwXpNW1gNzeO1TKk
         XPJSO4bv5yzH5fWVSy6H3zA8tTATOmYNoeQ5d6gf0PyXlpVq7l/HLWgp/DbF5WTc6e2k
         DNn3YwcobF9uizDyTCNhN2EWH/xmz3Jd5Mg1CpiccOe/XbYxgquzYuxbF7b8ypY1FGc3
         S2fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=DhfVSYyt;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QyJ4qqSvqLl5xBh27eUPajsPjZ6tNLcL4Kwk7JEJVkQ=;
        b=Y6T9Xos27IXqTl8wm/4P/meQUqKK3MgTYvgjiuPkpSELZ7LBJw95a2M211vn4Z+Tc7
         4bMqclNOFFWhF62b7ULW3lU7+Yk234IWnL2VGgdRDejac/CQ8U8WMN/APyRE+3HoHrB5
         FXNGX150ecpBJCEK52N4saeCZu3uPA10b5EPXuLS4WcpJjAqTXmS6zWYAcQjm0T5pI8u
         dFJK3BVejU56Tpf5Hm/M83GO7pyesNQQlmM/aoVccc77ZsY5DFpnq6Q7D8rkpXaqcbOH
         kq0HXjA8ZIQIO7BgwdAwQ0nJbluX8cLNYe8IVYbldwckwSniS4NysYE5rcHpcJVly/hP
         zsgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QyJ4qqSvqLl5xBh27eUPajsPjZ6tNLcL4Kwk7JEJVkQ=;
        b=XYWyUwpRv/BSM71ATITaduB23VIbCZyu7sHL2D4ung9mcNQIy/RAGfManxGuSYdha0
         c7wNdD+NmSUdCTJ+6kKAUfjb4klo+l4lEd59/KOV9qqivZgYYCJ1pFzo3MzqFY3VZ7sz
         362W7r8+8lV8wuXygFFmhNCiqHRzqeS1hc8lDxDTKsqtTZnwwYipL7q7rMGFT8MN7ePE
         vqVXNSHwJjYarpqIV0UCRx8WoOn3oWRclbPKHiG+NKEDov3rAnYm6BbtBYVylrFqJtug
         HHtMBN6nAamfjvN7KKqMSEEgwdZBkk7Zbelt6z6IIhUVI+BymTC6FFGkoUSshX2tEgb6
         3Rlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335IOfX035aNfUnIDC2X/FDAJvzkESPmsoJ8EjoZaUdRKA5wkx1
	WMpUSDL5vHyzHYvkaJ8jUwA=
X-Google-Smtp-Source: ABdhPJzISjJsKKr4re8vlyvi6m5LBl2yQ62Fv/BK9BUodIIo7FjqRfEoFaIVowRdcaqDD6/1l0cNgg==
X-Received: by 2002:ac2:5462:: with SMTP id e2mr4180892lfn.552.1604937887970;
        Mon, 09 Nov 2020 08:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls4011809lfa.2.gmail; Mon, 09 Nov
 2020 08:04:47 -0800 (PST)
X-Received: by 2002:a19:7102:: with SMTP id m2mr5494626lfc.461.1604937886941;
        Mon, 09 Nov 2020 08:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604937886; cv=none;
        d=google.com; s=arc-20160816;
        b=Kuk0sjeHUarwkBG6M1uJ8INS6b89oqh6cXGHKYylF4jKtMzW1/4E+9JOPhZwbkMIq0
         vqmXN7WwvJWWDQleq55VQK/g3PKNE1VeVMrTgPI/+AuS7EnPM5EbDYKdx7k1Xea6ND4d
         YMnOULEgVI4MIq7VHvEV6TKOHSF/4Znr7TKZHXQq6yC0exzNLvpkGhQOR60lm6ZJtscv
         0/XcBGlRChXFRTR95ewbQTUxFppsRByTjieBMcYwKkLw+cenEEXv9XFJtpv2nfE2r+em
         bnLsxsa/NT+tdHC+IVWI2RzGRfmbaTwCpc5zlc097tz4q5HyRV7hYHVCcSwuOhe4swsV
         G4mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jeP73yjot5P5PYYoDTHv8FWcNF9fYzo7D6kb+Sl6j0A=;
        b=oE+4gGhwePPmXBZoeARNato8fDD/FK86H2rHh+Nex2hbvDDU7h0Aeh29qkn3PNgjQ4
         Iup+ccsoK/96tHZCYJZ9WqyVO4yATfaIuWGgdzwNnV5UFyl2tzdGWbhVbG/tcbfIC8er
         EMeD0sODRTuVpr5S9ZJmsxf5lLrxwZg5nQEAl1hUhHW9sbMAWeK84uteo15NtKOQGRah
         W8BQdgwTkqhBX4CqT3paztR/wFqUqZqzKf6sXmdwxHu86ftFMY4KTj7jvhWpDGODa6yw
         OFMajyt6ZJxg9MYZ7yTmITE2auvU/tu5hVjgdSO9qH51J4b5fQNGG/Se59o9EQemQucX
         K33Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=DhfVSYyt;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id 26si330260lfr.13.2020.11.09.08.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Nov 2020 08:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id f11so6880033lfs.3
        for <kasan-dev@googlegroups.com>; Mon, 09 Nov 2020 08:04:46 -0800 (PST)
X-Received: by 2002:a19:ca05:: with SMTP id a5mr2891098lfg.571.1604937886671;
 Mon, 09 Nov 2020 08:04:46 -0800 (PST)
MIME-Version: 1.0
References: <20201108222156.GA1049451@ubuntu-m3-large-x86> <20201109001712.3384097-1-natechancellor@gmail.com>
In-Reply-To: <20201109001712.3384097-1-natechancellor@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 9 Nov 2020 17:04:35 +0100
Message-ID: <CACRpkdZV3nPZ29MmKXfw87eL+3CcOXC5LTeQf5WuLRsrJeEKLA@mail.gmail.com>
Subject: Re: [PATCH] ARM: boot: Quote aliased symbol names in string.c
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Abbott Liu <liuwenliang@huawei.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, Joe Perches <joe@perches.com>, 
	Russell King <linux@armlinux.org.uk>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Next Mailing List <linux-next@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	=?UTF-8?Q?Valdis_Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=DhfVSYyt;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Mon, Nov 9, 2020 at 1:19 AM Nathan Chancellor
<natechancellor@gmail.com> wrote:

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

Reviewed-by: Linus Walleij <linus.walleij@linaro.org>

> Hi Andrew,
>
> Stephen said I should send this along to you so that it can be applied
> as part of the post -next series. Please let me know if you need any
> more information or clarification, I tried to document it succinctly in
> the commit message.

I wasn't even aware that there was such a thing as post-next.

Thanks,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdZV3nPZ29MmKXfw87eL%2B3CcOXC5LTeQf5WuLRsrJeEKLA%40mail.gmai=
l.com.
