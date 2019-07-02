Return-Path: <kasan-dev+bncBDE6RCFOWIARBQUN57UAKGQERCQBD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 19FAD5D7B3
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2019 23:04:03 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id m8sf1427818lfl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 14:04:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562101442; cv=pass;
        d=google.com; s=arc-20160816;
        b=keozR7Z8YTLIfmCjRd2iNO/vE9fo2029R4dzRd2wqzxpw0PZHMbsjRUF1DwFxCFnjg
         N18hsZk+sIp9fZwmB+6jxjnwYpx6p8Nluy70eYhNKcWfPbEvNi0yME351PSroICQ9885
         vGNwcs2s9ShpNIhZUFWYeWb6KjaTKcwkWL2Y+cEYG6H3+yweqFBtHM9OykJ1csgWlYzB
         RnwUyhPyBCEfi2ouXE4upBvcsbQnGJq+CjkRXMK8YP1uq3bPcY0xNHDUFVYhQS8cq2V8
         emVRzwWS09L7XJ61ShV4D90R5B/XA1sIS3x7pxFcU3PiRl73z6Ao4nPW+D0geMNPimyl
         2gsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TYcMLPT/3Gtpsdk4W829XrJ7kreUOsV9j4MR94ciI7k=;
        b=tgzh1z7SmimIPh8RfZxb+qy14FWlRUqEWpB44oa/zqefUmbxGYqt48iJ6JveWhfjbx
         Rhp4Btx+gk44NuCghzRhZIQCSfbXAYQvfiysg/xvTu7HtRLnL7mJDkZSzXcralb73Jx9
         SrROWBe4kG+jrnvkbAp0igvKc9dF3X8936mA045M1ip4ZJ1deSDaZ94m3L7su92ACL9u
         m5EGJUDxoAAKUTM8GPnHysBLpi9VP0rUHitP5E7ICKClxfPtMpWAKnt0jgw9C89E41JS
         QbneX96Sr00pbazgyC9URM9X6zvn5bwN7zluz85lISbp2U1jU8oDqT935EDEh8Xtisu1
         Dlgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WU9xE1Va;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TYcMLPT/3Gtpsdk4W829XrJ7kreUOsV9j4MR94ciI7k=;
        b=AMXUpOVC0Pe4o5hN8kYPg4AM0zROwQ5d/7Y5vDjJ/pkpcx5f9p49qlpo3coFtH6VHn
         c6n61FjODMHZ4wLZqyQnan/+OdUGhl1qky+Sn6h5a36ZP6i8Gt7lUYRCSUQHapAHpO6M
         Y4KVpfJ0hcHdAzQRosagv8GnXBjFe5uns6ErNGr5hNc3VdQF7MtZOONG0Ha+IfEVc2/b
         hqvhv+lk6ZEE8R5FGt9bQUhkUG6m95+2Z/S7uB22Dn4UDe0lYf5L4tisU639VlmGkRTe
         5qTDWHhiRyVHEO8oZryf54Js3Xu0m67HQgGXeYNcYbyWaHnIjePb9RYNC0T3sanlQevy
         WX+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TYcMLPT/3Gtpsdk4W829XrJ7kreUOsV9j4MR94ciI7k=;
        b=b8/v+dERjrqcEiiJnVgEP5Sfn0SC2J40MJNpWXypknOHfCh8Dw2RxN+JZP0M6+SLCU
         onvC04PU8AKr3rUQvlL3fC4573yDeAzyq3FzECg6AUiCUOUItESGrnH30HPfdGuE19Jh
         Nxc05U/eCEXq+AVtUg4mxCN5WcHZy8TqzHLsV6ZkpEgQEz3uKpktRtMR0WXuTcYiPLvR
         zSKW4x8PCT542gyEtxeF0MoonxC3oDk/eVBQ+Mpv/8VmblI3weOAhVy/W+QFSSoBw0BN
         Uyebznl7wtmxRo0uAJDWj56Td3TXL6XA7D8P6iInoJUKFMdF4/VHENYyr5jPZ5bit3tk
         S7nQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVupysLkU+lksCHMtWWXn9k+6hYv+tM4f0QP/C4fJpTHRr5CjhK
	AGH+TyFf/PukP3TuFG5RSb0=
X-Google-Smtp-Source: APXvYqynSc+T+JywLhPTs7CrT6Z6ssal2WBmRg2tld5g8yvp4sHBkDwE1OsEINnF37LD95YwVxu+TQ==
X-Received: by 2002:a2e:9788:: with SMTP id y8mr18573201lji.41.1562101442682;
        Tue, 02 Jul 2019 14:04:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9445:: with SMTP id o5ls2737ljh.9.gmail; Tue, 02 Jul
 2019 14:04:02 -0700 (PDT)
X-Received: by 2002:a2e:89d0:: with SMTP id c16mr18027397ljk.219.1562101442256;
        Tue, 02 Jul 2019 14:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562101442; cv=none;
        d=google.com; s=arc-20160816;
        b=Osm3bemRxwJM1c/7CjBHHYBI9SUu1uF9Dm+9WCnZa92HKTCyjI70sGx0D6GCCE7XOJ
         72XtxRoyOssoX45YDVhxvHIO3K6f726M9zEOo3t5PcgZo7rrhY8NwPszzWJGTpJj7OJT
         i7JKRODmlQOkHxea8h1lLSwPC9MepX28oYX2KfuPuX5ZgrZvI27jbO0yquKW0R1/OOTd
         /qO24fwKQibRxGuobOlPPhVL3VeDaDb5b1ie55wBcZvfxZ2ynE7cRpVKTTiN/xuq4jCr
         QTjDpzC6Z0dv+ccOodPvI+NNXtgd1zY2GFy2tT+2uFhykjoCrT7KcfI1gfSjR5cBwEaO
         YuYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BWuzzOxwUVGbMCvFD/kQRaZgbqg2U0ttqAGoU0tIxDc=;
        b=enspnmBjNflK8VLA/zFEl27SffIGOXwi0BuPkwINMqrNh2aznwBoyga7rpD0pHmG8e
         0hTyndJ3XaBC9/tfw8o8V5l7rcMZIAKssnxnZ3Kqqe+/dJ3uAHEPX9M0LaYA9+kRP2tw
         ddr0UM7BXe8qPLyGO896eDFOddUrbBf+YAGPaEGpXMDQV4CyjoR2CY4JGYTEr2iXOrbE
         o8FAwYTO/bLclG2SnY+h6I7mRSuGBsNyRTEKEEmcTMIKH8/L8aCcmo2kYOEsYq0nk9jQ
         PHGfY/MlR9gq0MyUp2OEWQgfhNfmcQSc7u5ZAZizg5G0FbQv4qId2C41WUHH3xjWC4Ta
         zcpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WU9xE1Va;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id f26si4084lfp.5.2019.07.02.14.04.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 14:04:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id p197so140445lfa.2
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 14:04:02 -0700 (PDT)
X-Received: by 2002:a19:dc0d:: with SMTP id t13mr1324771lfg.152.1562101441838;
 Tue, 02 Jul 2019 14:04:01 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20190617221134.9930-2-f.fainelli@gmail.com>
In-Reply-To: <20190617221134.9930-2-f.fainelli@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 2 Jul 2019 23:03:50 +0200
Message-ID: <CACRpkdZGqiiax2m5L1y3=Enw0Q5cLc-idAQNae34uenf-drHDw@mail.gmail.com>
Subject: Re: [PATCH v6 1/6] ARM: Add TTBR operator for kasan_init
To: Florian Fainelli <f.fainelli@gmail.com>, Russell King <rmk+kernel@armlinux.org.uk>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Russell King <linux@armlinux.org.uk>, christoffer.dall@arm.com, 
	Marc Zyngier <marc.zyngier@arm.com>, Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, jinb.park7@gmail.com, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Rob Landley <rob@landley.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Masahiro Yamada <yamada.masahiro@socionext.com>, 
	Thomas Gleixner <tglx@linutronix.de>, thgarnie@google.com, 
	David Howells <dhowells@redhat.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Andre Przywara <andre.przywara@arm.com>, julien.thierry@arm.com, drjones@redhat.com, 
	philip@cog.systems, mhocko@suse.com, kirill.shutemov@linux.intel.com, 
	kasan-dev@googlegroups.com, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kvmarm@lists.cs.columbia.edu, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=WU9xE1Va;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

Hi Florian!

thanks for your patch!

On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:

> From: Abbott Liu <liuwenliang@huawei.com>
>
> The purpose of this patch is to provide set_ttbr0/get_ttbr0 to
> kasan_init function. The definitions of cp15 registers should be in
> arch/arm/include/asm/cp15.h rather than arch/arm/include/asm/kvm_hyp.h,
> so move them.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Reported-by: Marc Zyngier <marc.zyngier@arm.com>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>

> +#include <linux/stringify.h>

What is this for? I think it can be dropped.

This stuff adding a whole bunch of accessors:

> +static inline void set_par(u64 val)
> +{
> +       if (IS_ENABLED(CONFIG_ARM_LPAE))
> +               write_sysreg(val, PAR_64);
> +       else
> +               write_sysreg(val, PAR_32);
> +}

Can we put that in a separate patch since it is not
adding any users, so this is a pure refactoring patch for
the current code?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZGqiiax2m5L1y3%3DEnw0Q5cLc-idAQNae34uenf-drHDw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
