Return-Path: <kasan-dev+bncBDE6RCFOWIARBBVIRXUQKGQEJQ7SNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F9636207F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 16:32:39 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id m2sf1368334ljj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 07:32:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562596358; cv=pass;
        d=google.com; s=arc-20160816;
        b=jVYH+59fONW1NcZRmZDZuItIpemcjQ7wQe1g6iTIus/5S3NsvfQ/taC9BvfN8F5GW9
         IeTVfbyh5vsJAxmHPbOTwkZYJ0g5gLiw9a/UyCYOpDKXsjX43KVC9wzFpNCYoaR2psQT
         avvsAcW94DxNpL2TcexkKzbwdVjuRP9pTzaTJA6pnc3ekHYkmnpC4BwVYV6DrFNpJwPH
         AkmFHR2H0diM6DLbmzitTLhjZf5S5EyIc5hhf6V4T6BDIrQQWOMUrBhKev3YC+ZODVQQ
         OPiDijRrpokhRgswLKOQgxh6fmB2F1oS7L/syo0OBqeVotU7UKAotRlBfNGQP4d8g1DX
         tKnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=iYQ1UEl34Z+C07eEsN+Phw/ntxaG2aU3YorX6xdZjKY=;
        b=yXuPvmd6kKTtph07xWJhepLtNS4GbHNKlKU7P21WhJHfAAtj/BS9rQKZ+ilbSBhT1X
         sreRBvws3FPr/etWsf+SHpQiC17yA60cvvxIHGXbBbXpXCj9a08pSdYkUxJpieTdo7ua
         7CaZsKi36bAsBx6sc2x2gsoRiidV0Eqzj4snoNqoS5twvxuYq5K/LthKqEB7y0yI/DF/
         uelqmd4wczCHuHHHsqF100YIdDawbWn9O64H7AkuCsBd3H09jjKUBoA4A1tLXpss+tcr
         e/vqCuvCWhqTFMqctj7SXGE53nTB5OKM491TV/jCfYjjExCmhGLfyrw+RQwi9YEAady4
         d4/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=yFqK2Fa5;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYQ1UEl34Z+C07eEsN+Phw/ntxaG2aU3YorX6xdZjKY=;
        b=au/RvQ3GL4Ut6xkWznxGvYJ+HOP7kcwLeQrfidF2l/9EUxKBovdHuBiZdivLnc6REe
         ARr1lC6oy8EnrM3YSOyUhVpL9y0WbVdmZ4rkUQ32mTLRD+S8+8QWRpyr9wajz89k2kwX
         6dstis7btPIO+8kLdppBRGs2RffWxILaC+7Xi9v//xf4tZzAbSjcbD2GyQLzp0TucIm4
         sVl1WvfuDwo6oCozCmRuuxt4qUmcqpVUFy1KFGnb2XFw8CLGoETOeU7e4BmlVIVUzQet
         s3uEy+MqWrZe20ShNpopfOyWF8tTpLWkSot1x5FQ9xSnNSsYob8E2Al10gUtQknv+CFZ
         TUUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYQ1UEl34Z+C07eEsN+Phw/ntxaG2aU3YorX6xdZjKY=;
        b=uDRvFCRMCHHwEz4iXi5gPeb+lAG6uzxeihYobMV0B69dVYmVxviXpr/pEcfQ9sUquh
         5eNRAB5zDx+oikqX6doBXt7Rm22D41tnb23fgSTpa6Wm0LOqgZ8uS+nVakk/X5GEzwgA
         VE5Vlob9MfKUq3bWSHpQQMyO3uZk8pUUcgbBsyg+xLwkbgvlVZcT531Lg7oB/iN47+rI
         TQViQyEFpS6mkaL5KZ7zar9i0QuZdFPpZX0ItzEhnL24X82CO8vUIubWxAqRcJ6QnX5Q
         +To6hZObGBsDAT3ae06/3HnazCCWMDGzvquVS1T+3YJJAB3GTFKklFydXWTbNrW2Ti2j
         AIeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX4JNz78xufU1G3lyXQQ8TIX+XW03h3QnKYez2PWd/vxdyhsOZr
	E36SF6OQOFLnG9zaIwhPz38=
X-Google-Smtp-Source: APXvYqxzoCdBtaMqMYpwpbiaiPd3J/GbOtZ9SlXTNY7X6aeRyAcRZVfXnWU2JT5a5ZALnlPYzfwOnA==
X-Received: by 2002:a2e:7315:: with SMTP id o21mr10469119ljc.3.1562596358682;
        Mon, 08 Jul 2019 07:32:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:553:: with SMTP id 80ls1896347ljf.4.gmail; Mon, 08 Jul
 2019 07:32:38 -0700 (PDT)
X-Received: by 2002:a2e:9c19:: with SMTP id s25mr10307278lji.188.1562596358080;
        Mon, 08 Jul 2019 07:32:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562596358; cv=none;
        d=google.com; s=arc-20160816;
        b=Eh1V8L0fZeXAH8Bb+hJBHvZX8PoTe4fxs9uNfU58Qh+BOU2KiWGhCN9wVwq77Vx4F1
         HiWS6Eh9ktWiPoF/hA42S50UGB9A3oAntLNYGn6ri7WZgv905qFNULkvqG7tdxFZ9b8o
         L2zn7UH2lLJmjPQsP0Bn1/QLRY548Cr6JUsUhlVqRsXtEpZaB7aX+xJnNF4jQugvC6kA
         OIUY0DKuBCgjzMVO+LqfFRiqDVwZgiMJ9wrwdY8mVKID5nVNIaSfUsM24XQbjTU2qzU/
         EZ9jV9TmazvWj5ziZaXYMhoJUKxLdl33ddIjUQ/LI1qZ7KI58bpJau0Ys7BjXsNaXXbg
         99Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WAw/aU6LZwIL6FVu56mHN3vVX8j9GNHFwvAGIAISsSo=;
        b=I3b++G2u2LRooaQlg6Vn8MhzI5LSvuXaBxFTnNbrgwwoKO/PuuYmZq3ilNz98Vy/8N
         SGlHMZJQyeU/OMbAOUzOH2bR9npFnoMudDcH4ZYto3QwpceEWrJHB7idhBvJ5J1COmdP
         ozWnk7Gi5oT6Qu33Jl2g7OiXxuOZZawMJ60Ca9z6rKMbE3ZSTgVB3jhDhtS9LufLdeX5
         C2EnocRJ0EDOPKQ2rQICxhfT9uFbyYnIy/bEJQPjmGLfKhrr30ERg4BkZt5b1t/mnDr7
         bbfgk+189ZMtwukUGPTuxy5RaQveE16hl2UhM2cEq73AUS0flQh6/TFccITsF2d0Nxw7
         LBxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=yFqK2Fa5;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id q11si1094800ljg.2.2019.07.08.07.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 07:32:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id x25so9409213ljh.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 07:32:37 -0700 (PDT)
X-Received: by 2002:a2e:9593:: with SMTP id w19mr7413475ljh.69.1562596357740;
 Mon, 08 Jul 2019 07:32:37 -0700 (PDT)
MIME-Version: 1.0
References: <20190703205527.955320-1-arnd@arndb.de> <20190703205527.955320-2-arnd@arndb.de>
In-Reply-To: <20190703205527.955320-2-arnd@arndb.de>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 8 Jul 2019 16:32:26 +0200
Message-ID: <CACRpkdYnuSqiYBPMe_+u6dx_X1zSYKCnCtFznWtxkMf-BGBwjA@mail.gmail.com>
Subject: Re: [PATCH 2/3] kasan: disable CONFIG_KASAN_STACK with clang on arm32
To: Arnd Bergmann <arnd@arndb.de>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Masahiro Yamada <yamada.masahiro@socionext.com>, 
	Michal Marek <michal.lkml@markovi.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will@kernel.org>, 
	linux-kbuild <linux-kbuild@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=yFqK2Fa5;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Wed, Jul 3, 2019 at 10:56 PM Arnd Bergmann <arnd@arndb.de> wrote:

> The CONFIG_KASAN_STACK symbol tells us whether we should be using the
> asan-stack=1 parameter. On clang-8, this causes explosive kernel stack
> frame growth, so it is currently disabled, hopefully to be turned back
> on when a future clang version is fixed. Examples include
>
> drivers/media/dvb-frontends/mb86a20s.c:1942:12: error: stack frame size of 4128 bytes in function
> drivers/net/wireless/atmel/atmel.c:1307:5: error: stack frame size of 4928 bytes in function 'atmel_open'
> drivers/gpu/drm/nouveau/nvkm/subdev/fb/ramgk104.c:1521:1: error: stack frame size of 5440 bytes in function
> drivers/media/i2c/mt9t112.c:670:12: error: stack frame size of 9344 bytes in function 'mt9t112_init_camera'
> drivers/video/fbdev/omap2/omapfb/displays/panel-tpo-td028ttec1.c:185:12: error: stack frame size of 10048 bytes
>
> For the 32-bit ARM build, the logic I introduced earlier does
> not work because $(CFLAGS_KASAN_SHADOW) is empty, and we don't add
> those flags.
>
> Moving the asan-stack= parameter down fixes this. No idea of any
> of the other parameters should also be moved though.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

For some reason the RealView doesn't boot after this patch. Trying to figure
out why.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYnuSqiYBPMe_%2Bu6dx_X1zSYKCnCtFznWtxkMf-BGBwjA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
