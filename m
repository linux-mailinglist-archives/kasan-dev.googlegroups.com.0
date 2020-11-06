Return-Path: <kasan-dev+bncBDE6RCFOWIARBHVDSX6QKGQE7XCKKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ACD12A970F
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 14:37:34 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id x16sf479875wrg.7
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 05:37:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604669854; cv=pass;
        d=google.com; s=arc-20160816;
        b=agLwpZHeyEutWFs6w215cbiLX5ZmI2+raWV/kqQGHgYnmuSscwWYaYaVwZkCmfq+bW
         vVGh5rkl9lSmob5fTZr0lvmMGvgzKtwnSTdLXg6W92tm399rJBXAAm+m0vGhfJe2nov5
         9/afRLEHFKzWoEcUPPqpxNJqURco67wTZvekiSbA0fu46U+X3DuwtTsXg4omWVhi5sLW
         H2/QdW4cu75h8u/ir4Dw81CrZF0jANDJWTVHdMc8sz4Y6xteeYxUtrWUfhOLPqgZU/Lh
         7v2wpGaOtlDESfYPbuXbFjQ+EDAmXsFzr8wZKktRH42fG9xkfuCj1BC7EG/YDH/pjXdI
         54Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=n8XXqCw4dOruXWZ4CrAKwuSM2EkYo4whxaZ+J0BckwM=;
        b=q72i3jvXJqpDyEvxBk/dyzWCYb+HSmQR4YPnmuHbp2WKyryTCIs33DKwz/ydWMDELz
         xkD3E8kTYtxO2toZae4qvSEa6q6Okwo1em2m5BCRR/HAKo8XxGdpPMLPClcpD5mF9uRM
         +M4cSYJRIdEOqP1vhWSm+qaBcy7aS1NJaVokp2m1OAIvOjKC1cvc5uhG5GzSK0NShsUV
         QRapmNWoTJTwQuApu+lK1WBq8SIc4coYFpQ3VVmBYTfWV5houWSp3ZBRHjVg7cqCu8So
         zIfAl85YJrpchjfVxJlGoOS0Etm9NOSf4tBLWxCUNpymUEoiBKAI43zF1gFl3DRNIpOg
         g7GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=u5oG+XvG;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n8XXqCw4dOruXWZ4CrAKwuSM2EkYo4whxaZ+J0BckwM=;
        b=n9gbDkz2KD7Kf93RJCT7FKE5kmOPfLS9UWJJVZ/l0Dg0DCogBSsK0RHkjvW8fUosWS
         To6pJfvGaVpPXheeQ9cs7s6UObUH/39m+Q7FG5MrIABa/D+hyo8ElDFZruF/2t0dp4Yf
         5TdpoWsh1p/TtD7xJXRU2dQuKcgF3hJ3gROh8eisFeU867o0fQM+BCoeR7Dx81WOyhim
         QQFrlx2lAIP6uRetX4IidkGkpxZVsJAxmtfONjw27R6P5+os+xagb4ABC0MYxcPuIMQE
         kt34+BZHRw4cxxtcyLcDPmPdRvBiA3D4AbaM+T11s39FVV9G85dKMaBjy02YnwefJhlW
         K54A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n8XXqCw4dOruXWZ4CrAKwuSM2EkYo4whxaZ+J0BckwM=;
        b=gYLUpOAtHiCq2pXE/X8zCpBwBgeWXg/Vu6UfJ9VGJaqCDQRzZHH07cZOTlBu7YW2M4
         vyTEPPFkJdawlgHSe+HflxOynnYmixx9zFiWeg1t1GcZOe5CTBX5sCc28kbA8zXgINNY
         zfQDkFDv5NekL2oBqMZh65nD3Bf8GBkB4JFsRLiJtaxqglsML4PUtOGAyVyoPbI3l9wM
         pU41JKW17quknJS5sV2Oveo7r/5ULo7gK0Mu97Q9EkfERdiPRzShnzdpYtBxlbmh/3fz
         lcZ/xpZYUCsku2f5DaG2uCQBtUJ8nvWXNZFHCGpnm4HNi5a1ZF3lKo+DDzQjhB/edu96
         pkxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531067+XqWrYjhrxswC8nfneAoxlXmEiBlOYveyCIKsSii/HBS2K
	tM+sjWMBlvNkXKVhB5VeTy4=
X-Google-Smtp-Source: ABdhPJxU5n/RfXXltqwFyNOczR27rN2InOZe0Vpo6qyhcbNZ9IKXyyO2n7PPe/UKpV3PwQPLYjbGIg==
X-Received: by 2002:a1c:790b:: with SMTP id l11mr2651840wme.53.1604669854183;
        Fri, 06 Nov 2020 05:37:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf33:: with SMTP id m19ls761509wmg.1.gmail; Fri, 06 Nov
 2020 05:37:33 -0800 (PST)
X-Received: by 2002:a7b:c255:: with SMTP id b21mr2681636wmj.72.1604669853336;
        Fri, 06 Nov 2020 05:37:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604669853; cv=none;
        d=google.com; s=arc-20160816;
        b=hbiPcoLV84BTHQZSBHvowE5yHWQPo/OO/NDBFTEcdlOAen9g7gke4jihp3w2j3zRF4
         hBY2mUIysY/8pCIurT8ZJM0YauGPh09V5A9EEJPjS3Xop809U0R74yuVqiz240lzGHAn
         U/gAu2TgMIAQT3DPeVMQ75goI994NeuJjqTh+Jrtvf8VSxPoUe7g7c97nQzusD/Nv6Lb
         TOU8l8GbBELwY2IgRi4bZgAXx3I2W//XXJgqmbZbwipfZurO/5krQwpf24bYUZB9rRA/
         eEmytd9QWCaEaC3IiLeJHIGiCbgYY/VEBiP/tvbVcKs8qskK2nleEGw3KFzNiVB3u9/j
         PmDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1d9mjFc0ki/4lcF4Gjq/ke9oRs4vU8scTXfsKfjB4Zc=;
        b=BCw9TIjW6wB9GPk8O2VN43uVRjK54zaz/QFhX8itAoQaZk/rA3QxPxbf5INJT5DtSD
         ugmb3Ypuge8tSZ/RG/TUz/LJugREZSx+xDa3/FGNCmJgrk0pyINB8mr2F4IQekBSo5yq
         yHL0Q5NdjsDaDw7kKdH8YB2at5nUo/nw7C2U1miCf4TN101aCEMXK/5/TErGFFNQK537
         4uRBtacJjnE/z0N2c3fZWjSereOM0vDjDqzsMnZDi+4vSFPDt5cLPxylQNLor+oozl+J
         I2d/kogPFvQvDymGfzofxxSsds5N/jwwqxw5rttGNDvRY33iKG1Gs5L6lZTluyVkI2mo
         4k7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=u5oG+XvG;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id w6si75924wmk.2.2020.11.06.05.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 05:37:33 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id v19so1388127lji.5
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 05:37:33 -0800 (PST)
X-Received: by 2002:a2e:8604:: with SMTP id a4mr178992lji.100.1604669852790;
 Fri, 06 Nov 2020 05:37:32 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com> <20201106094434.GA3268933@ubuntu-m3-large-x86>
In-Reply-To: <20201106094434.GA3268933@ubuntu-m3-large-x86>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 6 Nov 2020 14:37:21 +0100
Message-ID: <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=u5oG+XvG;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Fri, Nov 6, 2020 at 10:44 AM Nathan Chancellor
<natechancellor@gmail.com> wrote:
> On Fri, Nov 06, 2020 at 09:28:09AM +0100, Ard Biesheuvel wrote:

> > AFAIK there is an incompatible change in -next to change the
> > definition of the __alias() macro
>
> Indeed. The following diff needs to be applied as a fixup to
> treewide-remove-stringification-from-__alias-macro-definition.patch in
> mmotm.
>
> Cheers,
> Nathan
>
> diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
> index 8c0fa276d994..cc6198f8a348 100644
> --- a/arch/arm/boot/compressed/string.c
> +++ b/arch/arm/boot/compressed/string.c
> @@ -21,9 +21,9 @@
>  #undef memcpy
>  #undef memmove
>  #undef memset
> -void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> -void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
> -void *__memset(void *s, int c, size_t count) __alias(memset);
> +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("memcpy");
> +void *__memmove(void *__dest, __const void *__src, size_t count) __alias("memmove");
> +void *__memset(void *s, int c, size_t count) __alias("memset");
>  #endif
>
>  void *memcpy(void *__dest, __const void *__src, size_t __n)

Aha. So shall we submit this to Russell? I figure that his git will not
build *without* the changes from mmotm?

That tree isn't using git either is it?

Is this one of those cases where we should ask Stephen R
to carry this patch on top of -next until the merge window?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdaBnLsQB-b8fYaXGV%3D_i2y7pyEaVX%3D8pCAdjPEVHtqV4Q%40mail.gmail.com.
