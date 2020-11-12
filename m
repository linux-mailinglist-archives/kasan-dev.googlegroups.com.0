Return-Path: <kasan-dev+bncBD63HSEZTUIBBYU6WX6QKGQEPS27OJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 82FC12B081A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 16:06:11 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id z9sf550361uao.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:06:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605193570; cv=pass;
        d=google.com; s=arc-20160816;
        b=wwj22KlRs9dtKkaGc+QEo2daknO99uipkGqmaMLa9cKuunVF3CNJ2y1VETW4Qfnuvm
         Lbv3WDXdGEAgRMCsLxO/ARJDBrkuFNwihgJNZdWyirhRnu+2hFy6F08ClToyyQE6EUnN
         B5IJNlnq8R1ZDMmpDO8rvyCteX9Hbskl2v4PSrEvA9yoGgROT8LNiYpwICCOJcJy1+oW
         tVNFU31qaA64VrWQtJ6YCs3j7w3NPw700zUTv0PvmHMmsdFUsfyqL1uM1y8El74sBp5m
         XnWaYOSKWxiNX2G9RnV11D/79WznhiD62G4Y8GfACLPoYOADyQ0LLCSxMKLRXqbfHvwG
         +TMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Ar6Lj9DlklSILqbYbzj8nFsjiPGB5l4U52BmsOm2LUs=;
        b=fK1pddL62GD8/6a4Tf5zEnOO9+Gwb0hDC4RfTb6WTXXZ7Ldf71hriS/3oTOSRPChtN
         ztmLXx+PfBKOxujmhsia6xWwtwEg8c4sLcOGHBa7iMSSZRE7CPk3GdWm64yveJmf4uXo
         g88aGf6O4nyVgzr7/CCOOZEvb1tQo4/p9lT3WYbeLtHz1dzIPDhrZxsuPsKfdxHCpglE
         ea4wJiQVD5nMAXIAIaEb6xm66VDOBQ4BV7hXkuAibyW/tucV/SJ9ucSN+T6sULpKzrRn
         7AuRz3ecBVmo6nkIF2RV2uoXcPBWC4Krrdd2AEOj8SxEZbAAaW9yfzeXyDPCjEOPYZ3j
         WPCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PCFjBPUc;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ar6Lj9DlklSILqbYbzj8nFsjiPGB5l4U52BmsOm2LUs=;
        b=MTy7v2l0oMsclIzM9YkTLR2Aie3ZzJS/B/2aFPDCt4Chvz41SGWp7b11hPgU58fOb7
         CTIgwAQfbt6TeRBgIt3H85GY4DRD8N2yLTkpzJv50Hej1tJbzjtexQEQbEa9HtvtgDL3
         4FttvUEV/Ab8vjsqubvOf6I/oSnoTRAlrubaGurlqe/Q9UKx1Nsck5Gwoiy7BYDbgBE4
         V/F7LXQEYDOBdCyUO3lbnL2BXnh3qVGoDy2UwrxgbY0hrSiK41eOH0se91sjNMHD4Zpw
         2Dyyw8eAT3EOIgWr3iiSU3BqDYC2gEgdY/p8FgWtY96M1RPnbZXrjHxnHLWSPwDCdbr6
         cECw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ar6Lj9DlklSILqbYbzj8nFsjiPGB5l4U52BmsOm2LUs=;
        b=iMCdL3InSXka4kCgTr8wSvESNl2d8Zo3ERUNWKPuz2HcyF5f6CgAr410SthMvBDTOJ
         2cIVyMphoBlbYgK0/iwRhxYrgdD4qracjYirsw9wy4c7qZ74w4FURy/mM956w3wYqivz
         ifAe8FOCFo0+BIMkKidupwJJ/r6VLjw5WqU9gDqfIw7v0aQfl3tJ2Mh4hUomrsopMKCu
         uNZmjNKeKrkTYCRLZo1dQzvHIvLmzIMF3F5IudKNtRmkkydcQljbtgCccUW7LMZ7TP5b
         W+wsOLqFAkh5NQP0Oz0kGziiM4qoshHflMRiS2Fk6ICee6iSM92vOT0OffyFULODNEz7
         nYTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Tp2uTK9ppoU3ZOd8t9ggq85q55IKTIwRJs21kQYiNKcQeVVq0
	s3fJK/9wGK8bhbWA+1d58Wc=
X-Google-Smtp-Source: ABdhPJxWgXzv5SkrcsHKsUz9XLSq3CzLGAUAv/v0BWcME0ERz+/+Anpm0ZEUvJ/1aULA606QLlq2Ow==
X-Received: by 2002:a05:6102:2439:: with SMTP id l25mr74622vsi.44.1605193570575;
        Thu, 12 Nov 2020 07:06:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe4a:: with SMTP id m10ls466333vsr.8.gmail; Thu, 12 Nov
 2020 07:06:10 -0800 (PST)
X-Received: by 2002:a67:ee94:: with SMTP id n20mr37666vsp.21.1605193569967;
        Thu, 12 Nov 2020 07:06:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605193569; cv=none;
        d=google.com; s=arc-20160816;
        b=kYFq6i09QU2JXjvUVeRTGWUU3RMql1Q8+X0ku2RQ+cKyy7YP4AtJ9pjzORh9TgKWVf
         KyIx1rhbUL6fRdL6aOOIUBNMqzeKji0XZIRBZLzLuPgZLgZ7bSk/Zx/swoAjVazpl7FZ
         eun+c5cs9D4wCiQiyHk/btxnrcNVyFGNh+RsQXzuGDVgY0Stc8sY6Rjyy6pS91Zkbq7b
         0bamnEo/GxDQZOkgnydQ/iS05WaoFCcZngg34i9WUqvZziv7t66q+VqybXc99p3iokAN
         mKnBQ2P2cMKtRZyWiLuhXYUYwxHwS9ZHCK4S7wnZM2X43otGd0cdum6Vdm84LLMMt0sw
         9Zrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=68MTbW7WwBoKihcC75GaGH0Pba4DW+94yL9i/0BBZ/A=;
        b=A4Vav0kF9YbHHQ2N9bcTFU/efZjVSvYrNdToOg9jBk7FW0//4gm56C8Syrc15ZmgXM
         St2M2clTdCUhkO+59beRIhv74Rh/4eBPPd6dcaw8F2X8K7X0jEAVr0ifvKwF4TqAdpEJ
         Zh6ri4+vuXB907cCAqigTU3aRtT2GYMU0IWFTDibI10LDLHdGKAFu6V/MUv7x/bEis7Q
         IHl+PInZ3t8DA5X+pg0VwIAVZvjpSidpxIdYt4jQmJsXhJ8D+c8b2ej2aa6yI6nP8vqf
         NI/qkPdiPqYbS4Nu8OUaaCZpEUPn5LnPPT4Y9sDyHHSK9x/5TG6mUnDNM2J63OKqc/8R
         YFUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PCFjBPUc;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s4si443056vsm.1.2020.11.12.07.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 07:06:09 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f180.google.com (mail-oi1-f180.google.com [209.85.167.180])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6A7BC22240
	for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 15:06:08 +0000 (UTC)
Received: by mail-oi1-f180.google.com with SMTP id q206so6643219oif.13
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 07:06:08 -0800 (PST)
X-Received: by 2002:aca:c60c:: with SMTP id w12mr36803oif.174.1605193565506;
 Thu, 12 Nov 2020 07:06:05 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk> <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
 <20201109160643.GY1551@shell.armlinux.org.uk> <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
 <CACRpkdZ1PwT13-mdPBw=ATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg@mail.gmail.com>
In-Reply-To: <CACRpkdZ1PwT13-mdPBw=ATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Thu, 12 Nov 2020 16:05:52 +0100
X-Gmail-Original-Message-ID: <CAMj1kXGXPnC8k2MRxVzCtGu4X=nZ8yHg7F3NUM8S_9xMxreA9Q@mail.gmail.com>
Message-ID: <CAMj1kXGXPnC8k2MRxVzCtGu4X=nZ8yHg7F3NUM8S_9xMxreA9Q@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Nathan Chancellor <natechancellor@gmail.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Florian Fainelli <f.fainelli@gmail.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	Abbott Liu <liuwenliang@huawei.com>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PCFjBPUc;       spf=pass
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

On Thu, 12 Nov 2020 at 14:51, Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Tue, Nov 10, 2020 at 1:05 PM Ard Biesheuvel <ardb@kernel.org> wrote:
> > On Mon, 9 Nov 2020 at 17:07, Russell King - ARM Linux admin
> > <linux@armlinux.org.uk> wrote:
> > >
> > > On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> > > > On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> > > > <linux@armlinux.org.uk> wrote:
> > > > > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> > > >
> > > > > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > > > > build *without* the changes from mmotm?
> > > > > >
> > > > > > That tree isn't using git either is it?
> > > > > >
> > > > > > Is this one of those cases where we should ask Stephen R
> > > > > > to carry this patch on top of -next until the merge window?
> > > > >
> > > > > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > > > > until the following merge window, and queue up the non-conflicing
> > > > > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > > > > and the conflicting patches along with 9017/2 in the following
> > > > > merge window.
> > > > >
> > > > > That means delaying KASan enablement another three months or so,
> > > > > but should result in less headaches about how to avoid build
> > > > > breakage with different bits going through different trees.
> > > > >
> > > > > Comments?
> > > >
> > > > I suppose I would survive deferring it. Or we could merge the
> > > > smaller enablement patch towards the end of the merge
> > > > window once the MM changes are in.
> > > >
> > > > If it is just *one* patch in the MM tree I suppose we could also
> > > > just apply that one patch also to the ARM tree, and then this
> > > > fixup on top. It does look a bit convoluted in the git history with
> > > > two hashes and the same patch twice, but it's what I've done
> > > > at times when there was no other choice that doing that or
> > > > deferring development. It works as long as the patches are
> > > > textually identical: git will cope.
> > >
> > > I thought there was a problem that if I applied the fix then my tree
> > > no longer builds without the changes in -mm?
> > >
> >
> > Indeed. Someone is changing the __alias() wrappers [for no good reason
> > afaict] in a way that does not allow for new users of those wrappers
> > to come in concurrently.
> >
> > Hency my suggestion to switch to the raw __attribute__((alias("..")))
> > notation for the time being, and switch back to __alias() somewhere
> > after v5.11-rc1.
> >
> > Or we might add this to the file in question
> >
> > #undef __alias
> > #define __alias(symbol) __attribute__((__alias__(symbol)))
> >
> > and switch to the quoted versions of the identifier. Then we can just
> > drop these two lines again later, after v5.11-rc1
>
> I was under the impression that there was some "post-next"
> trick that mmot apply this patch after -next has been merged
> so it's solved now?
>

Yes, it appears that [0] has been picked up, I guess we weren't cc'ed
on the version that was sent to akpm [which is fine btw, although a
followup reply here that things are all good now would have been
appreciated]


https://lore.kernel.org/linux-arm-kernel/20201109001712.3384097-1-natechancellor@gmail.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGXPnC8k2MRxVzCtGu4X%3DnZ8yHg7F3NUM8S_9xMxreA9Q%40mail.gmail.com.
