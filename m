Return-Path: <kasan-dev+bncBD63HSEZTUIBB54DVL6QKGQEPQGCKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id ABA602AD5D9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 13:05:12 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id p3sf6450863plq.21
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 04:05:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605009911; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jssg9T6e3NzXA6nKiQR9IcUzcOI4HtztEbVb+MCnCCCYfd1lXqGBNMpb7CXbExinJO
         tmS9vw/0q//A+AYk946z9biwTpLbPMefUVikMsDFWEDnXWAzKVNEP1yOhdV3Q/PZ2ZCZ
         LdaxZivqZowzda/Q91kvXvaG8PQbR5LEXkhYZ2fVqcx+kSxCMRjBH3/oCTTf/VOHyLml
         k040um+pKPlOCsuJf0cElYM/XupKdA08Bz2GlTVyIuvmrEKVtdw+2JIAphtQxPRwffhI
         ovi24WGYSQ8bivxjHqWw7M3EDHAhwUoXcR4ivmGOKep7W7z+hQZ+WQ/HoSF2L7xcYmWn
         Y5Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=dyQXkyHux1XDam7UK6zpAdUDe8b6rEqE880Gf4JPQcE=;
        b=XvDu8uDCy+UV/JT/0j2n6DXg4Lz6PsMq6/Z3i5EIvr5AKpWqbsGtHYFnmVcA/7M8kU
         UAXoRpbrUBXM3BRSevOOgQIWPONkamGgOyGRdwyNCYAH4rY6UbhukwWeidr1QQ0hJbjQ
         Q9j51t4K1Eye/YKF3fMSIrPyT3/H16bu2sVUow2YW11hOkQhTytjTqSJ+HjZEHBN0UY6
         k5ihHOfl9N0Y5YiJzhtE8mFFL9JhKKQxY4B3DRIj54aZqcQqgjIJhEp8jCa1NYRXIRh+
         hYu8tg5MxE0VTwnMGaucUCc/UdAkR3hTKIbvcBbzad0QB2ciUxlbbkyGDiimzZlp9TPv
         Vfmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gzwnYvai;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dyQXkyHux1XDam7UK6zpAdUDe8b6rEqE880Gf4JPQcE=;
        b=ptllu/gzznl4qFC2SsPBW+hIa/AGchpINGGFfTEWfpyoIrNzSwONkIoDXnP04k955Z
         x8OV8pjQdrQgdDt9gtqKTeoQ9qgn+P+VDdKAoVdw4+SjSeFO+qQIjjJOPZEtj+nVLZO7
         krXSdfYRZbQjuUCyCRzjOSwIIFpzzSJWgKAo7XjaxVJt49ooLEqKFxCXCqS0K1nVAhFm
         YTtaVEOOBEGGdYLSy5sk2C2COjEr0To+AsSNswhOL2F4PaPrZOfh0D14S+D2doTRx1DO
         kZCHfzlmln2lXPFahU/Akutuq3CzawwBdrMIz12idCDUHf31MGUhB6oEuNkeKTSMeIbp
         A3tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dyQXkyHux1XDam7UK6zpAdUDe8b6rEqE880Gf4JPQcE=;
        b=aZRktYrUbTIt1Zm/ODvMQB2knrtqrU0HeouzjOGBZBNVf2FvvZljpRQD2WnmPZ/zRU
         UIGWasrhZ3Tz+uOmpw/iQhI+8asD45BdICuLRqpg8oXvV/BdOMPKE/7PEBxPmqI/aTYf
         +JQv15dKK244nCXV7MRLufIPFyFbWUnqt8EiMT4kN97FUz24KdbF3N/CcdSdZxOISnSv
         4Lgkj/VT432x0/Id5UiSoitju2Z864DgAnypNsw7KBVcJJl0xwVaRomyLrQLHaJBY87y
         GX4H0bGAUKv/x5ODmdrmRr9x+CH1NGP1U3TgGjWUCNIzlo0xH+xFBDrXUvX4Jsx9P7oN
         K2mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eiQzUPGwHcI7LBKdYbyPLdPnLwHStR4U7UIz7/hOsggM0m0YL
	zOGcG+cM24p3Bq6omA7YRnk=
X-Google-Smtp-Source: ABdhPJzxMZOEvWih7uprMcC7kVZYPeBZetO+AiJcvX2rcVw6lDZ7SgvgxsAU9VMGT7o39BEHM0YKzg==
X-Received: by 2002:a17:902:6b45:b029:d6:c43e:ad13 with SMTP id g5-20020a1709026b45b02900d6c43ead13mr16572159plt.77.1605009911171;
        Tue, 10 Nov 2020 04:05:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd46:: with SMTP id b6ls5212784plx.10.gmail; Tue, 10
 Nov 2020 04:05:10 -0800 (PST)
X-Received: by 2002:a17:90a:2904:: with SMTP id g4mr4994177pjd.102.1605009910627;
        Tue, 10 Nov 2020 04:05:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605009910; cv=none;
        d=google.com; s=arc-20160816;
        b=jO4lc2b270P5X0zKx3ojXEMajDKskEj62leobuc9AWB+8Yd3QhmukG5W9Osbyoplwx
         6JkBlx/t/XTmwH52jzYvqBbTK76vI3HZ7VoGIrfU4CxDwH3Z6zTritDTcXDQ9s+MEX8X
         +2uVW68idmnGxDgHhw6IoC13tnpziDvQNPcky/KKmgrhbo+0bX08tPbOk74Pg0+g5DOJ
         4iNCCRxfclDKqPtxBkcSC13V6jEKuRJEKf1/7TSBpHHZOYbVYzVsELY5FF2vd2Ou6XEy
         fdshlV7z6IgpB0FoR1tgilXNxco13bQeSwJJvlV/FYdXu6qR+LVaFxZNo3OsppPyNy8H
         vh/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NjacH6bkcOERzYDNFL45MT7Ds4rqSNazlK8WgXpbazs=;
        b=try5oaiB1SIO39PTJxOv30E5gEwWoetoFCstQtb0apMLHVzAKsLh3C+tdxBIQGaWfW
         yvdoyFQ8fN+piKHJOPE7/JwWVdduRAKifmgvY9KHJqmw+aoLlyQKH29oA4aosIReZ98t
         mVnIgaTie0jVjh7U6SW36yVU/9ZL0oxAJjD8uoHsaPbO1953cSodYiSvb7BtjkhlEtTG
         zEty9QGC7fnK2xw8ksa9G5/qxINLprY+hId6T06e7bTNXAp5fLrCGmNt+tOxZr4ADDQI
         lYai78MgsRhKMKOFciPbQbyPVav1503ZIPdwOhDCssx/pSZxnDtSTfDTQae9Awfo4QTl
         mlNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gzwnYvai;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m62si952081pgm.2.2020.11.10.04.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Nov 2020 04:05:10 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f171.google.com (mail-oi1-f171.google.com [209.85.167.171])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0ACF420795
	for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 12:05:10 +0000 (UTC)
Received: by mail-oi1-f171.google.com with SMTP id m17so14033314oie.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 04:05:10 -0800 (PST)
X-Received: by 2002:aca:d583:: with SMTP id m125mr2309350oig.47.1605009909177;
 Tue, 10 Nov 2020 04:05:09 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk> <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
 <20201109160643.GY1551@shell.armlinux.org.uk>
In-Reply-To: <20201109160643.GY1551@shell.armlinux.org.uk>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 10 Nov 2020 13:04:57 +0100
X-Gmail-Original-Message-ID: <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
Message-ID: <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>, Nathan Chancellor <natechancellor@gmail.com>, 
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
 header.i=@kernel.org header.s=default header.b=gzwnYvai;       spf=pass
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

On Mon, 9 Nov 2020 at 17:07, Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> > On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> > <linux@armlinux.org.uk> wrote:
> > > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> >
> > > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > > build *without* the changes from mmotm?
> > > >
> > > > That tree isn't using git either is it?
> > > >
> > > > Is this one of those cases where we should ask Stephen R
> > > > to carry this patch on top of -next until the merge window?
> > >
> > > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > > until the following merge window, and queue up the non-conflicing
> > > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > > and the conflicting patches along with 9017/2 in the following
> > > merge window.
> > >
> > > That means delaying KASan enablement another three months or so,
> > > but should result in less headaches about how to avoid build
> > > breakage with different bits going through different trees.
> > >
> > > Comments?
> >
> > I suppose I would survive deferring it. Or we could merge the
> > smaller enablement patch towards the end of the merge
> > window once the MM changes are in.
> >
> > If it is just *one* patch in the MM tree I suppose we could also
> > just apply that one patch also to the ARM tree, and then this
> > fixup on top. It does look a bit convoluted in the git history with
> > two hashes and the same patch twice, but it's what I've done
> > at times when there was no other choice that doing that or
> > deferring development. It works as long as the patches are
> > textually identical: git will cope.
>
> I thought there was a problem that if I applied the fix then my tree
> no longer builds without the changes in -mm?
>

Indeed. Someone is changing the __alias() wrappers [for no good reason
afaict] in a way that does not allow for new users of those wrappers
to come in concurrently.

Hency my suggestion to switch to the raw __attribute__((alias("..")))
notation for the time being, and switch back to __alias() somewhere
after v5.11-rc1.

Or we might add this to the file in question

#undef __alias
#define __alias(symbol) __attribute__((__alias__(symbol)))

and switch to the quoted versions of the identifier. Then we can just
drop these two lines again later, after v5.11-rc1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe%2BA%40mail.gmail.com.
