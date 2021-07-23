Return-Path: <kasan-dev+bncBDE6RCFOWIARB74P5WDQMGQEF36QKAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AA0B13D4326
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Jul 2021 00:51:44 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id u4-20020a05651220c4b02903606e832f3asf989231lfr.14
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jul 2021 15:51:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627080704; cv=pass;
        d=google.com; s=arc-20160816;
        b=sGCsZ+tVPyUPBSC8kfbBY8DnHSGpI9ZqwCW+kDjx1pjVpNsEDS+szavqvSNMcAcEGp
         /e44znxB/tUMJSZaAMSs2OkEr1RStz69dKaFYbmcyhtr3ZiMflDbjvpZdqyzA2Sj5T6w
         42Bg+ApmLEFr4KFnQTczPxRvoKMcweudw7mDK2B64WyDj4hRYy+7JJ2fVaVeynkZrLs9
         wZJ5s8cn/6WbZlVDnRDUrvmjs7I9GViPcz5mVohzrLl7GJGleMz/oNktKs1puri3CAbZ
         lLhQHlxL0XM+IhUVbJRyo76cB/ybp/U3BjRt6fAudWzYDPZv6HK28p0HzdOWwYLLGFhc
         5kDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=r6o0yrqvGvBfkfk1/r3Uo6MNgk4xdSF8ackyQzuBeGI=;
        b=ENzcZe4qo6UojwovkKxSgPXtivaAUeZCWIoHQZLrvwQeOd4vRSv8yGjkd2RxdJDgLW
         4f1dtExIivc99ApSMsIywuWkAvLFZwNAyrW1nSAIE/Py05/yA6em6b9qUqgYXsuDYiDu
         tmZv2xU8frzdh1aAALAuuIvQYrU+UIAI2rkwQWtPO4pM7oF+YH0ZxRErx4bNP9RkAUFk
         IPTW/26oQw8usrbcVG90YJJZDfE1SmAwqrn8UtfPYNWSHClu27lmpM17dw1Vv7iZaX3W
         KPRpMAPQ0z+09pL222sWAr5R/BBTCln0wF/wDMgfcRpjDNlsxDt4f4IAaWO9QcQZs14L
         6VFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=e94pb9KK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r6o0yrqvGvBfkfk1/r3Uo6MNgk4xdSF8ackyQzuBeGI=;
        b=IMn6Gaj4uEtHwTfIyG+NFiAQ6HpXzGieBjutLYYe13svnNqpifqEsu1J32nuMC5I2C
         5lbAe8BD2WHGFq1iyXiiSOogmPl42lqlyMDVvFzetBZcrbYheju4g+QuEhkymhlhnlTH
         MBbQwlA4Ixf5hNqiir5aLsOOvytV4zVYHoYyootrsLkT8aGHP7WH95UioYXxRudFcyx0
         AjCSj1307MNYmDFRjMTyaM1+JP4dl26p3zCITEZ1nQxpqDLD1ikYzQ3525/i/EKg6cCo
         oasNBzykBY5yaWimPCWSJxrqFL/9NzwrmaKfo/JVngOEBYBJnYlKUJYPedEJxYX1W1BP
         h1wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r6o0yrqvGvBfkfk1/r3Uo6MNgk4xdSF8ackyQzuBeGI=;
        b=f2lM29hyCiHVdyhO7IzqRFRxUHLWsBg+IJOIxI5jJQ7DY5sxGSDEGS+6YDWfShedEl
         p4LXeKZVClYmFk4k78+ZdGzhElzZelh3G84m1rcGSNf7NVUYSZmnelc16NdV/UXpP2/7
         cHAizzLLqyjqm+aNqwyEuvQzOPmv67xKmBR9NjxdBev3TIS7Dezcf4inlNl+nKkarJLG
         iPZM22vgAsdLpPIL2KJFEAQL+fB6Re9C+iGFBHVHBcxSX2zp7J6CHrzUO3PTyrc9MiYx
         H42bE9AV5A2K+Pd41vorLMxlgPMC9SjKjh6zFWCqiRPpGU2a4bVrQqpJbrGX2mdrJpJm
         DAjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HDMRQI40v8h9oliUYUn/WFb33jq05XKNpAAlgplahepnn06wK
	YU4shXQQpk3U9ylw1EwO2bQ=
X-Google-Smtp-Source: ABdhPJw2l4m3D6ZYF87nk2LXsOGq9XdrHvPL+vICSPA5rMvC/fN+fKV4+KaTAHa6j5Cmzaj8EIrj0g==
X-Received: by 2002:a05:6512:1327:: with SMTP id x39mr4628425lfu.37.1627080704215;
        Fri, 23 Jul 2021 15:51:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls2254747lfi.2.gmail; Fri, 23 Jul
 2021 15:51:43 -0700 (PDT)
X-Received: by 2002:a05:6512:2388:: with SMTP id c8mr4340896lfv.201.1627080703166;
        Fri, 23 Jul 2021 15:51:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627080703; cv=none;
        d=google.com; s=arc-20160816;
        b=BDB+C8tdu2icm/oY7LNbLuN+vsP40XYckH9GiGcBG0e5PoCqWBS9qqNnmsoFaomFfC
         Ruw2IEQZlecsSjl6UDDhQhB9N2muKluWHmppNQWPhTJq03QfJOpcMT+y+jfxEut1yXnI
         /WhiP2UUBdO278JN7RcU+XVP3fSYpF5Rl26rFkExUThTUfJWArId8QXm2gsu+gb1hb7V
         r8APm9AigfKesCLHWNvnGtN9CEzcdqzUeTbB0yKJ1g+dZvuhSEuLYvtBaqA4eV8UXBCT
         pRyESdJCYdQYdOjoiXtHHA7bBCB1t3N5bQTLs2CnuL1p54p7ufnlRGWIkQXtWgTHhfd+
         KXrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4HCYw5NOde3g0l5ZK6C4CEhaJpOnGk3xLhiohruDlKI=;
        b=IqzEQX92mawu8LII3FuO4x1eXV3wtHmrCqva2AQ24nR1YOKnClHq+I3vH6CcVeoTrc
         MNIVno6g9ZP9CM3JWFDuP6WqeH9GFVMe3fJ4XBbTRdvXWHsS493B/yKulHA+2DIZt9cP
         ELWxw7bP4MW0EXs4EyfjU/1LYw4e+bxEqf+Xm1C5NMz5tSuDrpVf/hQk7I6dejAxvrio
         I2gxCFLkqZiR5jrU/ag2OeZ6/nQ9p+dHKyvlKWHZ3/tG1PCc95Tdug1pHKd9F5Z1KCHM
         zojEanpS/4C4VBxHnWrXXm2md/PVeT6CdYEz6cg3cl0AbQXNd15BoZ5WzBuBMid8BFie
         qQiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=e94pb9KK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id z24si1441853lfq.5.2021.07.23.15.51.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jul 2021 15:51:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id h9so3483385ljq.8
        for <kasan-dev@googlegroups.com>; Fri, 23 Jul 2021 15:51:43 -0700 (PDT)
X-Received: by 2002:a05:651c:160e:: with SMTP id f14mr4710051ljq.273.1627080702856;
 Fri, 23 Jul 2021 15:51:42 -0700 (PDT)
MIME-Version: 1.0
References: <20210721151706.2439073-1-arnd@kernel.org>
In-Reply-To: <20210721151706.2439073-1-arnd@kernel.org>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sat, 24 Jul 2021 00:51:32 +0200
Message-ID: <CACRpkdb3DMvof3-xdtss0Pc6KM36pJA-iy=WhvtNVnsDpeJ24Q@mail.gmail.com>
Subject: Re: [PATCH] ARM: kasan: work around LPAE build warning
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Russell King <linux@armlinux.org.uk>, 
	Ard Biesheuvel <ardb@kernel.org>, Mike Rapoport <rppt@kernel.org>, Abbott Liu <liuwenliang@huawei.com>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florian Fainelli <f.fainelli@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=e94pb9KK;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Wed, Jul 21, 2021 at 5:17 PM Arnd Bergmann <arnd@kernel.org> wrote:

> From: Arnd Bergmann <arnd@arndb.de>
>
> pgd_page_vaddr() returns an 'unsigned long' address, causing a warning
> with the memcpy() call in kasan_init():
>
> arch/arm/mm/kasan_init.c: In function 'kasan_init':
> include/asm-generic/pgtable-nop4d.h:44:50: error: passing argument 2 of '__memcpy' makes pointer from integer without a cast [-Werror=int-conversion]
>    44 | #define pgd_page_vaddr(pgd)                     ((unsigned long)(p4d_pgtable((p4d_t){ pgd })))
>       |                                                 ~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>       |                                                  |
>       |                                                  long unsigned int
> arch/arm/include/asm/string.h:58:45: note: in definition of macro 'memcpy'
>    58 | #define memcpy(dst, src, len) __memcpy(dst, src, len)
>       |                                             ^~~
> arch/arm/mm/kasan_init.c:229:16: note: in expansion of macro 'pgd_page_vaddr'
>   229 |                pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
>       |                ^~~~~~~~~~~~~~
> arch/arm/include/asm/string.h:21:47: note: expected 'const void *' but argument is of type 'long unsigned int'
>    21 | extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
>       |                                   ~~~~~~~~~~~~^~~
>
> Avoid this by adding an explicit typecast.
>
> Fixes: 5615f69bc209 ("ARM: 9016/2: Initialize the mapping of KASan shadow memory")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

I can't think of anything better.
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>

Will you add this patch to Russell's patch tracker?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdb3DMvof3-xdtss0Pc6KM36pJA-iy%3DWhvtNVnsDpeJ24Q%40mail.gmail.com.
