Return-Path: <kasan-dev+bncBCU4TIPXUUFRBDV7SOGQMGQEAG7TNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D1FD46179C
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 15:11:27 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf6012087lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 06:11:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638195087; cv=pass;
        d=google.com; s=arc-20160816;
        b=DSPgXZAjB9z0WoCIRM7cq0JtQgfWlkeYpW0csTw6vnGOTKMnoKqtPusyFvUzSck9c0
         K3q7wfNGo5esdFXEEDJgyP5on7WvleRcPjzrnEYDkN6hKCclqMSENzG4rndQqMCIkcr2
         WA9CMrBkqwdDCo9p/KucA65FXdTZnQDLLY1S6Vw8oqi43tgojbGvhVhgoMHcTmq/f+dM
         XqwO/99oDcX99Jb4r9TCiugyX0Tw1nod1v/UUtVRInUa/bVgSM3Gh7BnKPupyfY5hCQo
         fhOGEMt3VbAukoJD1y6bwKv8oCNXcf34vaDbSfMunzU+6VhdD0+xu2jjdECGUrlnjwrQ
         lXHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=RI6FtKsLdItNE6U19Y9JLWK4JVKao9nPetzwsf92LcE=;
        b=0yCXAsynqZGp+4Wejr0UBff+IaLLR4266ndgKdsut7KddDHq6W6TnGDBcT0yaCiL1g
         xAR6yJfUSkH6hBzvZDCzsufktDwVx9ibDoW3DiFuNVWt9YAH2G8RU0pJ9g6DyB/x+PJX
         t3pYoeUivCLPXwbotE5+a3pLTUHhwADz3JtNMOmpKcdV/PUEm2TBDWdFfTuyf2wetqwC
         n5hJOrEULCy683tMiLmXYUJSn+ABzXdmPPeQ82YefrCOh+8ebShQuoTDN4Uo7IqKJ0eN
         1/19h905TvvTJQO5wtxCRdLPa8uOWZiEywKrlhVM8GVF4GrMXjdGEiOxyLwrVGlRESl1
         ajXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iNUsntFy;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RI6FtKsLdItNE6U19Y9JLWK4JVKao9nPetzwsf92LcE=;
        b=MM8vrIznp1X/jhcY+LGZ9+n3EydWNSCD6c8uwwh+yWIepgC+R+QcOmwFovfk/G3pjj
         0hiWqzzUtYSPx7TCV7gyTPi67wlCj42KrqceqP40B4XbHptK6NLqZOw7gnWeqX0rXPlN
         Q3pADNOgfJ3tAH4w5ILyVjeiOvqkdKj+MM0+Mo+7zIjg036UD+oKH731qw92bt1lGohZ
         zo7w26zgbRhcSF0INvJlNLqljOt32cQHZeSou8oR144afXlzEGvIsneoIA+0MWFj2pze
         2ZcBFIiP21jVL/QweE1mcZqDxDF4RvEr7QoCc193LHDNddd/Hzra54vsBV5UFYPb/+k4
         IBKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RI6FtKsLdItNE6U19Y9JLWK4JVKao9nPetzwsf92LcE=;
        b=FssVmEqBNoQaRne+5Sn0ef8qD+Hj1G5hvc/6TZnxfcHO1otXMiNJPAgfmUGJANFuoA
         HRcSSxAExt9eC/SotNVSQ0wzx/7MsCmfXuUu4K7yIZXsWFqd27pvM4bBQtTA6fr9f+op
         dqYJGnyO+CuWFshSgGr2sUUp/SF583F8m40r2s8U0teoJu9agIWbP7nyP6wWtU2ykVRV
         9CkCRLAwqJapq+Qxq63dkoQPSDcPbhDRZM64Ku4g1VRfcaX5/fkqyVuclGdeCPH/eo+p
         JdMl5cW/vOIjwEJ7adlnGfcycfYLgccwBsRbPCKeXfExKfVlmDZIy3rD3qC+b2vvX2Lb
         kYig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/JkIYsqTLD3kgRgJymWqppXN9c4zc7ngw0QG6JVbYEaKIBnCk
	BMWaOAfUQjZTpC4mnYCBLYA=
X-Google-Smtp-Source: ABdhPJw7WSqqdsicqhWX0WlVcUDfqnm8lYutLvFJ3bHKTRrAEb/ZWYhxvkIS1ZThUAuNH6g7rGvE4w==
X-Received: by 2002:a05:6512:eaa:: with SMTP id bi42mr48072817lfb.52.1638195086901;
        Mon, 29 Nov 2021 06:11:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:201a:: with SMTP id s26ls1916448ljo.5.gmail; Mon,
 29 Nov 2021 06:11:25 -0800 (PST)
X-Received: by 2002:a2e:b6c5:: with SMTP id m5mr49177997ljo.469.1638195085781;
        Mon, 29 Nov 2021 06:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638195085; cv=none;
        d=google.com; s=arc-20160816;
        b=Klq0Q/HO8qrlDMNZrDkHctRAydiXUsvSts/l6mRba9wXz9XlY9OfnHBzTmWTUgK5Zk
         GEbXSCujGRz1q5C2vImgHlZ41g96JaalY6/4KTOK+s3ErFWvcZG7BqT5TjfMU5VUoY1a
         wZYt6TauMPEa4EMCxNKhks7AAWucXkeHY4PPKCfiBOcptOHUrBiQGujLRdc3kdHc2jdh
         xqyBWeO+5u6aFV6NZoA/lxQ6ty1Vsb3Vwp//KXk+b4LvcCqa/EK+xNNYFadIRl1CHiMO
         MYOjbmlp7zc+4YUKAaAhP5SabMJ18M1O7OeoUnTv8+qTBxk3QJ++PIMpAyF64eYD4yeI
         v3jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QrKGDHi0GyYnFuCQDx3VJqhQ96eJqq65sQ8zhUphr18=;
        b=icNyoAka9BJNQ3qFh20thlO93lJnhM4QKl4yAXydD4lv0NoC0cBCGwg6MQgoiivru6
         VM8Slo/zZSyQhJKHkmvv5DIpQceRDxy5J6IUiqY6Ju/UFpuYwQOpOL2Kxql6/X8F2Chy
         4/NlgEMqQSNaV7/cHytEhvNdW15i/Ky0ZuX39HW9idIL5BlF3NZSvLWYXDnZ6uZBfIaY
         ito6RXxtT6yd7kF5SUltqIAWT9Tqnrnq3l1xQpDpjHTRB6t00NwvO68Fn6kZuINsU5uk
         qjKi8qKs+6FGTJ0Z+f536U2XKFoPlHzqG4C6znURFeU4N5TgRv7CBNXrvk/93zNfD38Q
         J6sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iNUsntFy;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x65si1065421lff.10.2021.11.29.06.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Nov 2021 06:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DD6F86153B
	for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 14:11:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 54BF0C53FCF
	for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 14:11:23 +0000 (UTC)
Received: by mail-ot1-f44.google.com with SMTP id v15-20020a9d604f000000b0056cdb373b82so25654558otj.7
        for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 06:11:23 -0800 (PST)
X-Received: by 2002:a05:6830:1514:: with SMTP id k20mr43746692otp.147.1638195082500;
 Mon, 29 Nov 2021 06:11:22 -0800 (PST)
MIME-Version: 1.0
References: <CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A@mail.gmail.com>
 <CACT4Y+Z7bD62SkYGQH2tXV0Zx2MFojYoZzA2R+4J-CrXa6siMw@mail.gmail.com> <CA+fCnZcUEVDWZTUvD+mbe2OrnrpJCC_OB66YMvbZYak8sKg7cw@mail.gmail.com>
In-Reply-To: <CA+fCnZcUEVDWZTUvD+mbe2OrnrpJCC_OB66YMvbZYak8sKg7cw@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 29 Nov 2021 15:11:11 +0100
X-Gmail-Original-Message-ID: <CAMj1kXH7D-0bhv79cRPergquC8-ryCi7YvTokHSaJ14ZHd_F8w@mail.gmail.com>
Message-ID: <CAMj1kXH7D-0bhv79cRPergquC8-ryCi7YvTokHSaJ14ZHd_F8w@mail.gmail.com>
Subject: Re: KASAN Arm: global-out-of-bounds in load_module
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-kernel <linux-kernel@vger.kernel.org>, 
	Linus Walleij <linus.walleij@linaro.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iNUsntFy;       spf=pass
 (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted
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

On Mon, 29 Nov 2021 at 13:56, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Nov 29, 2021 at 7:37 AM 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Sun, 28 Nov 2021 at 01:43, Miguel Ojeda
> > <miguel.ojeda.sandonis@gmail.com> wrote:
> > >
> > > Hi KASAN / Arm folks,
> > >
> > > I noticed in our CI that inserting and removing a module, and then
> > > inserting it again, e.g.:
> > >
> > >     insmod bcm2835_thermal.ko
> > >     rmmod bcm2835_thermal.ko
> > >     insmod bcm2835_thermal.ko
> > >
> > > deterministically triggers the report below in v5.16-rc2. I also tried
> > > it on v5.12 to see if it was a recent thing, but same story.
> > >
> > > I could find this other report from May, which may be related:
> > > https://lore.kernel.org/lkml/20210510202653.gjvqsxacw3hcxfvr@pengutronix.de/
> > >
> > > Cheers,
> > > Miguel
> >
> > HI Miguel,
> >
> > 0xf9 is redzone for global variables:
> > #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
> >
> > I would assume this is caused by not clearing shadow of unloaded
> > modules, so that the next module loaded hits these leftover redzones.
>
> Hi Miguel,
>
> Adding to what Dmitry mentioned:
>
> The code that's responsible for allocating&clearing/freeing shadow for
> modules is at the very end of mm/kasan/shadow.c. It's only required
> when CONFIG_KASAN_VMALLOC is not supported/enabled.
>
> As 32-bit arm doesn't select HAVE_ARCH_KASAN_VMALLOC, perhaps it needs
> something along the lines of what kasan_module_alloc() does with
> regards to clearing shadow? I assume arm doesn't call that function
> directly due to a different shadow allocation scheme.
>

Side note: vmap'ed stacks support is being added to ARM,  so it would
be worth it to investigate whether we can support
HAVE_ARCH_KASAN_VMALLOC on ARM as well, otherwise we cannot enable
vmap'ed stacks and KASAN at the same time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXH7D-0bhv79cRPergquC8-ryCi7YvTokHSaJ14ZHd_F8w%40mail.gmail.com.
