Return-Path: <kasan-dev+bncBD63HSEZTUIBBJ4SST6QKGQEOUGBNVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC5792A9144
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 09:28:24 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id 144sf607408pfv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 00:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604651303; cv=pass;
        d=google.com; s=arc-20160816;
        b=bhznuM3yHyUzRKNweZwQzYp46M1Uivg5eVGYSEDt4p3HhwDydqH45o9xM0mHoT5LuS
         j3aNcJ4BHZatJzicz3FccC+IJqZETsZU4zFMHcRK9dPXpXeEa6kXs21rGseuuo/1gLVq
         L73cJn3fepXgqprySaC8eFFn2/KzDQ0rRHkyOTvrI/sPVIWM9qwO2fDGn0J3BHhN3sB+
         u294X4Ig4s8blHKkYvWd/5oa1K8t4hgDKftG4xgnHuJYto+Ov9WiBXj25QDhXukOJB+k
         AfRtU3098GLxwS6R31aEaIiFXAn9Zstewf7lVIifcHR9BiOTqFmyXPFU1RJZkKzX5Uq3
         BLww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=l2jri+AUdiG2QJavt/xc7yyw2RMMZwadIbt0gm8ODvU=;
        b=g4aYUqyI1fCjUyKKDUMREfMucJMm96ERfF+hmJL/xm6I7H+tT0SK3AH3hkAIcuCYrH
         vFtJldFFgNLGGegUotpukwKD2gSX93X9LoWC1G7gm6bYT/nTsjXj/Vz7T49KV1MGDvnh
         bpm3B/2z2nJhKMLv+k4GaIVTw/Ekp5pCjBGyaUbKuWCxrGDOFv9c1q4iOQRWtggzk2l1
         td5w9vd++8YYKoB+tkQ2yed0kjLaI+zdFmem9nJ9dXjkEQr1S+a1nIkYo9SlE9OpRlXF
         jYmnYwqQU3rLd/lWvXylb0TWtxjm8IPdcz/Pwidfre8hH9fOl9kgliBulSjP8GDxlO7J
         sgVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Fw9Lu2Dm;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l2jri+AUdiG2QJavt/xc7yyw2RMMZwadIbt0gm8ODvU=;
        b=ilWYOMhugJTavDqh7yu2SqCagTiZsGeP79BonRwErhES+GysDsw+yTydwFqrR3lXDd
         Vq32XLgFkjKuEZp8z+/6ZIlByai85tSzQAKUbGg7pD8OS1Ljjyaiy1Gdu5KvsAuO1+9o
         61e7CDaGzJQk7qspIWeLPPdKdHUt8J4z2lynj9HYKQQ3eb8ubQx5Fj5wA0cpsMkfH3Pr
         0w/Ul00z7VcSQfvQkyFlfSspQsJj/m/hm4YPw8G+vQvIC8sIPon3B8bEpF2mgkezvW0a
         vdGpdQERG2aLerWQwM8nQZlFk5tcJFa1UvBMNuPI85NtH7EmLnyLnvuRSwSVD5Wz7C6A
         hXIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l2jri+AUdiG2QJavt/xc7yyw2RMMZwadIbt0gm8ODvU=;
        b=E/arBVn2yhgyR47HYIj6oOrqqAa7OlWpoB35y2bRfFPPgvFs+8SlTsvPwcTzCFTkB9
         76qjrZa+ivFE/+q3Ws2SW2Hmm03pFV41lRj/yn4Enr5KFMLFpX2agNrdwOTBoEFe0jYu
         /yJ0JVnXkrYKdgM0gljxojmJGH3TtoXBMvUrJ6w+HlQgZs86CO6SfuU8jby/ty+W1fz+
         kzwtusTdTilfaE3oUeSZpnogJKL+mwQRkxR3y3MTgoueRE8vQGrX9M4/SHK2KpX4EZPP
         790aIi9GaWKQ98KugLVNYSI918ZXqgkqdhAdAx3bFpyA3cU9jnGfeKHH38HKOUe9YxPo
         EvWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fM7vU8cXuHucE+YP05vyhSY1NjqlrD5/RZkbkbEfLrZniU0+a
	HOcbZmF9LemVaDLNUzYAy9E=
X-Google-Smtp-Source: ABdhPJw5qsilC3TEISHbD8A/TrTD9f3QueRxf6nogHYd+cX4QHmOQtIOoXsaoXLYqTUL+js0UBbjcA==
X-Received: by 2002:a63:5b63:: with SMTP id l35mr913188pgm.70.1604651303577;
        Fri, 06 Nov 2020 00:28:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:231e:: with SMTP id j30ls268374pgj.1.gmail; Fri, 06 Nov
 2020 00:28:23 -0800 (PST)
X-Received: by 2002:aa7:9f9a:0:b029:18b:a203:3146 with SMTP id z26-20020aa79f9a0000b029018ba2033146mr1053631pfr.36.1604651303057;
        Fri, 06 Nov 2020 00:28:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604651303; cv=none;
        d=google.com; s=arc-20160816;
        b=y2C9hOthQrWhw5ogVTT5HACsHB9WgtOF4U0NtPS0CJ8tqCVQH4vk722QWauVnPlVOO
         kiCr+YXFov0LOoAnfqwVwatMFxHlyXnIMtmZ60NtMDEaOU+CJEd73XCe82Dz3ttN0gO5
         CdtkoGyqZYg4HWC6iP3UriFtnEd9swBksWr5o8TYXPh+40gUd5svwRQEoQ9yavcmuBXC
         7V7O/VNYFTdnYM4BR73fw0ym8AgbPGWdmQ96uFUvOYmpJkldqy31XOAwE2wHeoyCPJXc
         7MdCUtwI43rnbDwVbPPOKhyykVmTAbaH0hpB/ORl5XVE8l4swZdMrUEpLVg6iQW5aK1v
         nA0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NKxpY+qPJl/dXD+Nr4KY87UneExT9BghV7najG0ZuW4=;
        b=xAOUhPhlVqfQwmA1PW8QnKeE4suK+elnmczjllToiZpQxCbIacw3SnzsIaJJCpuESf
         AqBm/Hv4DXbKy31GsFa0vdNGePM3spjRsdM+/MEy301zzyBFwqGxrnSdMwJbLPkOS3Av
         /bJJIR46fVX42BcmGB6JdU/eltnejtacS+Akd+Y9tZVmU48VrrB/SpLvMNAYy7xGOyCw
         qxRKLl1mgcapGp+bOaSig880I3tiCuCuIfS2zdsu10w8FGAOAgB4Ya/JG1hVLg0bkpmZ
         qW5/YmRBD8Bgex8vBgnmrN+c0X8Nw34WQl+7RLiLeXyWSG9BiPM28H6lidT+HoeVFd/g
         vTQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Fw9Lu2Dm;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si49433pjj.2.2020.11.06.00.28.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 00:28:22 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f46.google.com (mail-ot1-f46.google.com [209.85.210.46])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F3B4A22201
	for <kasan-dev@googlegroups.com>; Fri,  6 Nov 2020 08:28:21 +0000 (UTC)
Received: by mail-ot1-f46.google.com with SMTP id g19so540379otp.13
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 00:28:21 -0800 (PST)
X-Received: by 2002:a05:6830:115a:: with SMTP id x26mr453687otq.77.1604651301053;
 Fri, 06 Nov 2020 00:28:21 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
In-Reply-To: <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 6 Nov 2020 09:28:09 +0100
X-Gmail-Original-Message-ID: <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
Message-ID: <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Fw9Lu2Dm;       spf=pass
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

On Fri, 6 Nov 2020 at 09:26, Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Fri, Nov 6, 2020 at 8:49 AM Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> > arm KASAN build failure noticed on linux next 20201106 tag.
> > gcc: 9.x
> >
> > Build error:
> > ---------------
> > arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias'
> > argument not a string
> >    24 | void *__memcpy(void *__dest, __const void *__src, size_t __n)
> > __alias(memcpy);
> >       | ^~~~
> > arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias'
> > argument not a string
> >    25 | void *__memmove(void *__dest, __const void *__src, size_t
> > count) __alias(memmove);
> >       | ^~~~
> > arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias'
> > argument not a string
> >    26 | void *__memset(void *s, int c, size_t count) __alias(memset);
> >       | ^~~~
> >
> > Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
> >
> > Build details link,
> > https://builds.tuxbuild.com/1juBs4tXRA6Cwhd1Qnhh4vzCtDx/
>
> This looks like a randconfig build.
>
> Please drill down and try to report which combination of config
> options that give rise to this problem so we have a chance of
> amending it.
>

AFAIK there is an incompatible change in -next to change the
definition of the __alias() macro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFTbPL6J%2Bp7LucwP-%2BeJhk7aeFFjhJdLW_ktRX%3DKiaoWQ%40mail.gmail.com.
