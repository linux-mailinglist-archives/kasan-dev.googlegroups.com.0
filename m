Return-Path: <kasan-dev+bncBDE6RCFOWIARBVEO57UAKGQETHF6Y2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60F045D7BF
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2019 23:06:29 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id j22sf3758433ljb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 14:06:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562101589; cv=pass;
        d=google.com; s=arc-20160816;
        b=gXAXfV+mlYxqtIA0LZDIKO7m5dyxTNaZMlhUuvUc2TJFecdp/oNsI41TqI3tJdBWon
         cKHJQpqsizQlj5lbPrFv2Fp/dgwHkfnu8NLqYttSKyNAe47AQLfGuAD54Es6h8Q4T5Dh
         bwCFevBVyfb6UNO8r0JUhWVJjRnMCwcWO1lBxqpf32elL4+PJnfMgbcDiLIo3HP+o+gC
         xjnGYrDG8818ooJs2t9CcMX3Yc8vb8Wq7kIYdi3Qj0QHqKIJMb61c0FXbRpOcltymKkf
         7syPKkTYwcjlNVDfHdfVP4PkoO2as42MJHKptZjrRSvTun8lthbuKu7f4MTP6Z74IYJq
         vJMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JdowkPheC8WDapnbpu3jvmVLvmfDKiqb/0Mg+uirDAM=;
        b=HDGef616hYKcgiCbA+TaKA68BH97eTPB37/LmV6Nz3QIq2+E4lqlCgY/JpHvZ9W9y4
         ShwPmwYsMojyZq4g59fKkDbEZjhddUFH9ouAR7vvvikZBmkmqVtCEghMOhhlFuDvz2B0
         mkXMKm+8Zhdg9jV8pnvpwrZfuG18oZTw6VkXIA6U1WqbdBmycmzI/7TxjDJ9RaVAYoQp
         Ojl3NZLjjRT+Bm00+h7K8bGVu/0zQjk+6MmFvzgcG0h0BUKad8Kn9UvoyKhWGq3c/nrL
         jq8DjZd0M70qyMi4BuM6XSTssZUU9+lzSgIDK/jOkgohmgy6Xy+yVDgJYduxvUn1qo4F
         7ZEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="S/9wjNxz";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JdowkPheC8WDapnbpu3jvmVLvmfDKiqb/0Mg+uirDAM=;
        b=BIT8t5PGKFUlkZuEJgneA8dgpAvOXdX1qZS2gHtZxLGkUUoL05ATJpLG12gESS2SFu
         Rk68FQ4lCnVvvoryM/hBGsxBIRI1l2oFEM4IiHGlnYTvK0eid6ZDxeizqWkH1BaL7cJ8
         Ys0+kdVseOmH6iK51BqssamoUnPkKErUd3mLse7R1MQoHnNKxlNGmqek5DuE34wmE1EZ
         GCooqUD6XtlNqXqlGtjUb36rIKLLYijil4rFRGPC/LaSXG/7LTVJUa+2u8LAXyWlXiyM
         1j/tlK+DYdIDoKFCWxPDF3ASh1oTFEqUyQHqzLb0G8M8IpctDXm2PMvGY68SutbZsXuV
         y94A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JdowkPheC8WDapnbpu3jvmVLvmfDKiqb/0Mg+uirDAM=;
        b=lkix8ysQzLeE2kT0l05hw3NJLwI9BhZIBPmvvhcYMIlxbocgLT2MZRrU5BBK2OY2et
         6Wf4d8WhtEPz0+AkhGHFnuBmK8dAnP1Xv+AhjYiHC0pFkTVXC0YeQgjb2x0zapOHPBVr
         VeR8QRNXZ1cpZ67n0Q3HuvjDAwbvSZ/m0Qdny3OKHODb7NIpswRM9MkRhXqc0QMbmSAm
         kWc6vSt2z2GsY+D5wgrWMqL5klN4edn1UA1abLd9rc1dXUqh35rNmR1qbRNWTCV0cSah
         WZTyEw+LnZL+xeZlastqaa6Af1rP8k/ur9R3/aFwL5BBmKIv8tvqbkxhFCSkW8SnwDsb
         p0lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWPC/usP7xVoe3OB4RZ6eAcC9d4Ek77kgDUNJeFQRHj3BVn5iIj
	HG9J4Sp9L70UgeS39LRMz+M=
X-Google-Smtp-Source: APXvYqw3vdKPqWsn/6bbfwFPMlrXmI9QtOFB0ULr2llxfn2QBjR22lAJEtNcSCXvdlNYCjLK3gGCag==
X-Received: by 2002:a2e:9a58:: with SMTP id k24mr18564365ljj.165.1562101589018;
        Tue, 02 Jul 2019 14:06:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9445:: with SMTP id o5ls3463ljh.9.gmail; Tue, 02 Jul
 2019 14:06:28 -0700 (PDT)
X-Received: by 2002:a2e:989a:: with SMTP id b26mr1685424ljj.31.1562101588744;
        Tue, 02 Jul 2019 14:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562101588; cv=none;
        d=google.com; s=arc-20160816;
        b=QPc9KcydAtnqhUVqxwJY0riCtF+rHM56oCwXFw2HqWwzgSeWCSDxTnzG5xvO1IFDZN
         U7zXb04nKDbQxFrjGvY/qnQNzxkWkWdjCdMNp7WMXT969+Omjc0pVthzW89GX3e3v+Zi
         1gqa1vdI/d9AW+gaTQN/RaYcZqLjziJBUFVVtBWrO6MhhRIw0HpQmgtW1kpUkTAtWyXd
         CfEOE2WDzn4tKO7PUwYQqrFizjRT9Ge66oDv9katTLjW3FyjKtxDtrJ5GeJy39L4YNto
         Od2A/zdMPtjdTn+rkkJ3sS76tlQeJkQIx6xBCuXj8tffYJpRckaer05IWoFyiQtPaRPE
         8Vnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=16juguPwtTD1vWpUNQpyIYEAEOADqNOzx5F+yEENpfM=;
        b=i6N0X+1ZgvadVoKZCxYTER86kJ8gwtYyoDLntcFxSYHNSq1WAaKnkhhTWTAkw820mB
         20wKBFmFB+cigB8dYcFMR450yqRgt11p6Pz5RTMW8WFCqxA/gXhDcU3ZBF8x+LH3q0zf
         JgibenmIaBe9h/1Yua7xaCxn1SpQRMDZSugM5tYP1nT8Ro7EkT1OmyylbZqlYjzTV2HB
         azGJJO3rzzsf8/vbeqCnKAqnOTgxyp1HBBtiD+Hdrej7xL07Uhe3lkErzD0ETFOkAps0
         F/GAAPZ7qSClYVT4Et6VennlrQT7FEBQ4hc3uzAcc5hv0uBwBa0vgziCdjQsrYKrslOC
         woYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="S/9wjNxz";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id w22si9200lfl.3.2019.07.02.14.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 14:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id m23so18391505lje.12
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 14:06:28 -0700 (PDT)
X-Received: by 2002:a2e:a0cf:: with SMTP id f15mr18775412ljm.180.1562101588459;
 Tue, 02 Jul 2019 14:06:28 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com>
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 2 Jul 2019 23:06:16 +0200
Message-ID: <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Russell King <linux@armlinux.org.uk>, christoffer.dall@arm.com, 
	Marc Zyngier <marc.zyngier@arm.com>, Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, jinb.park7@gmail.com, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne <pombredanne@nexb.com>, liuwenliang@huawei.com, 
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
 header.i=@linaro.org header.s=google header.b="S/9wjNxz";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

Hi Florian,

On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:

> Abbott submitted a v5 about a year ago here:
>
> and the series was not picked up since then, so I rebased it against
> v5.2-rc4 and re-tested it on a Brahma-B53 (ARMv8 running AArch32 mode)
> and Brahma-B15, both LPAE and test-kasan is consistent with the ARM64
> counter part.
>
> We were in a fairly good shape last time with a few different people
> having tested it, so I am hoping we can get that included for 5.4 if
> everything goes well.

Thanks for picking this up. I was trying out KASan in the past,
got sidetracked and honestly lost interest a bit because it was
boring. But I do realize that it is really neat, so I will try to help
out with some review and test on a bunch of hardware I have.

At one point I even had this running on the ARMv4 SA1100
(no joke!) and if I recall correctly, I got stuck because of things
that might very well have been related to using a very fragile
Arm testchip that later broke down completely in the l2cache
when we added the spectre/meltdown fixes.

I start reviewing and testing.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
