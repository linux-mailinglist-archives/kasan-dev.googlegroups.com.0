Return-Path: <kasan-dev+bncBD4NDKWHQYDRBXFCS36QKGQE4D25DQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D2272A9BA4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 19:09:33 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id m3sf162868uak.9
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 10:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604686172; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0mZh11VMH+oGBGIoULJLRfgRcE5WpOMKlAXXR6/PDuy1+ughzT/661eCer2PiMrG7
         K1oweozRxVCz2SdpQt4zNYJE+N6pF+CpXWjc7rzHS7JcA7YBv2+Z501HwrmIoo592pZ/
         E66SU28FdVQkte2QSSbXfizfMdZGcB2JTihsx8272WKpdvamsiJGMqNDKepxDVTjWHUQ
         v1JppOEPMKBlmVRb9tI1WVQai8kiYcBbBJCnDldlGr1Bxh4eyY42bCMTg4QYqkfnTDq+
         fym/yD0jabNHvtI1BJhitLY11FmdM01DNvonZrG56dxwPTToukLZ+l0+IM5tMdl3/Brq
         jv9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=NRFWUg9aRdn1P+7rHWkbH3hp7KgG6Y3PHhZCu/h1QEA=;
        b=BKNSCB+NjPMbix2vSzNpYhaeLcXLr0uddFdkBYVOBCQgHV2WlnylkceWKAiYEbES1X
         bR8ugKVrmRrzzRUXucnmcECTki8sVYkoAjKGnLzG5TjI3TQIW0WE48L4Dz4nhQeuSXAH
         rSYLgFezlL5x1YCYQup6QYFHk9pygJfkyGnGdVwwCvxvB/FzHReGdpHu1tcgjlNWACqt
         cYfSgtcZUwhU7meYB1DrTJREJ82jDMNRGLY6TLdCKKI6x4HvUo91rR9lSiy890QvMOdB
         4FwM8Kw1mGXlSklrSka1+7qzTdy1n9cr53y2V+Ux4VtOz8evInFcXYeNXzy5DwDHt2iQ
         NueQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O88uSA+p;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NRFWUg9aRdn1P+7rHWkbH3hp7KgG6Y3PHhZCu/h1QEA=;
        b=KDZDfXukbhGS8mwTYXmbJzkX26igOBPN4H0ZQVYKwrirorQ5n69vpHk/gl8L5yaCjN
         4p/Q8QWA/CbmmyegHtoOiz5Q1HE1sLVRdNQrpEokcT64C9RqgNF8eB+I+c7qEK5LLqFN
         lm52I3imV3Qu+wTZt8Est2HpsRzuiWRYh0d4yLOgE6qDpgti0lENEjN9045VuXqVy8TQ
         PNgLmdpYbw9pRVmqTo9upBCN34vxHYL7hJ39h6ae62Ay36wSt8pRZhBPx0jhv1Pm+3zw
         ouR3fpy1ThXftoh6Wcd7EDZ4cAIJxqCUce/Oj76jOr5bdOuifUT3FeMv62Vpj6RuwoDj
         DOKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NRFWUg9aRdn1P+7rHWkbH3hp7KgG6Y3PHhZCu/h1QEA=;
        b=V4rAoq409CQnwtUewPr8VzgfarmtRa4+JwwggCPBou6WbV5MrPtZFF7m0QFQ53WHjy
         Up1Ig5wndi/LYyXu3S8rpw9yE/OBJ+TINEr+mv8CZbng1c1YF+DpQx9PxjTo5kPzuTxt
         GjulpnxIpGHSNDYb6JFOvsEwqkDll377oVxTxAueDTUV8OxXrzJ5imrJlDYXUiNmKI5C
         ayMEPQYCAZ5ZMPEHzxGWJt8b3kidGgesOD/yTOAMNTjVthZFWiXv9hKoF6t6mnN0qJCb
         3B7Zv3mqC1QEOLRWvXCk48wizHE29r+E/zYzHfcbjz8hR7Ms7YNjSXHVZWkEIKUe3eLa
         hOFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NRFWUg9aRdn1P+7rHWkbH3hp7KgG6Y3PHhZCu/h1QEA=;
        b=TpbRR6apS2xn/vXDGtVnAhauDZ22b6EC2J/TB8YZ8tOoCYhP1s4GD1YqKYwnD950hs
         ESScyjE9Y6IBOe3065Ibivv7OckH9Je1HT7mLvYqDy/mrX68nrODiVS1lXaRRj+A6aat
         tre3UHlCAqqcXhJH+Q36D09uR8nEuJXgB3GKpbEM52B4wpUK9aC6Nk5iw0giDGuGKooK
         XZRFdxwWCHsQGuxTYno7y4CVMnPh3rAuB2qJZgqg1HS51VK4Et1avjI2WBPttlTAIm4+
         HpAdXAWhqGQDOZWoeHTacJBo1C7yHNu6pNPNtwDDCwixiPuJf/OVyx81sn4yOVY7odSG
         ZcYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yg2h5gXHuyQBg2VKt1aUe4MA57lPxlexXterlcfm7zXcYoKhq
	3yLm9BFADVvzVWCRNSBslz0=
X-Google-Smtp-Source: ABdhPJx6lyx/2daYCwFV+izjSRXil+SgpVM94ejv16KC/4qHneBq2Q9D1FIfWfth4m8hResnpgU5jw==
X-Received: by 2002:a67:8dc4:: with SMTP id p187mr2100213vsd.22.1604686172225;
        Fri, 06 Nov 2020 10:09:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1145:: with SMTP id 66ls102839vkr.2.gmail; Fri, 06 Nov
 2020 10:09:31 -0800 (PST)
X-Received: by 2002:a1f:ab97:: with SMTP id u145mr1946392vke.12.1604686171766;
        Fri, 06 Nov 2020 10:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604686171; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8PsrLbGAvPGSdvJDKbiQ7Y0GwyyqtsKXTlVG5r3K2olqIIRjCcVuPqfhP701I+/wG
         fUZTvAV7ItY6NZFxNXU9ytXKfAZBg+XHcpCiAIFzmyAqFFNrU4dm8GK2ojC1iCHbv/SX
         w53hAabuPXkIzTV1LzLc+cvGh7P6IM+HGl44gkNg8EivdHj/Stvu1lHN4KI1XG5xCJyc
         QC4WNWZQVayaDwFLBTMUyrUSRqjk2mnI+9srK/4jM14+kgIeRS4OHZ3lUC5xCFTnqjag
         +ibK13WiD1Oml/lgqNBwWLZr1G14qATuXUPKBQCVEFc11HTeGFCD0Bt3kaqvN6z7kaBD
         uTjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xthdb0sB+nBkUrNgfEbY4fZLBO1/mKnLmjZCET3QDvM=;
        b=clzH0iNQjZ1uKgFoTXBljpx0VtBaRjyso6D4idLc8pgxDkYzBNG7tNFfCT9E6LzPR7
         m4IrTv7ACSizf9G39LYeSw65cwqOolSJMk5TaJbZVxspUPyb9hjZX+qQMBohq9LWebbj
         fogSOEomyxG5FwonXXhOIBXdWoIiCbAUi2/YDGtf19xYJF+Ewij/qksSMWMqlvy/Ksl/
         1WLps7tEgtbmquNbI7rxnmIY8c3NBz77Nnqytc000tDAAx65g0a0vsVEBtFX7maApYY3
         WGH5gPPPQLKyet22vtHGQUexOX8eBxTXGq5n9/b0ovKGQ6KOo0+avNNTB8z/n7qJourF
         2ctA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O88uSA+p;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id v18si103035uat.0.2020.11.06.10.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 10:09:31 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id h12so1378772qtc.9
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 10:09:31 -0800 (PST)
X-Received: by 2002:aed:32c7:: with SMTP id z65mr2713718qtd.266.1604686171309;
        Fri, 06 Nov 2020 10:09:31 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id p8sm1067648qtc.37.2020.11.06.10.09.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 10:09:30 -0800 (PST)
Date: Fri, 6 Nov 2020 11:09:29 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Arnd Bergmann <arnd@arndb.de>, Abbott Liu <liuwenliang@huawei.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Linux-Next Mailing List <linux-next@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
Message-ID: <20201106180929.GD2959494@ubuntu-m3-large-x86>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org>
 <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86>
 <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201106151554.GU1551@shell.armlinux.org.uk>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=O88uSA+p;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Nov 06, 2020 at 03:15:54PM +0000, Russell King - ARM Linux admin wrote:
> On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> > On Fri, Nov 6, 2020 at 10:44 AM Nathan Chancellor
> > <natechancellor@gmail.com> wrote:
> > > On Fri, Nov 06, 2020 at 09:28:09AM +0100, Ard Biesheuvel wrote:
> > 
> > > > AFAIK there is an incompatible change in -next to change the
> > > > definition of the __alias() macro
> > >
> > > Indeed. The following diff needs to be applied as a fixup to
> > > treewide-remove-stringification-from-__alias-macro-definition.patch in
> > > mmotm.
> > >
> > > Cheers,
> > > Nathan
> > >
> > > diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
> > > index 8c0fa276d994..cc6198f8a348 100644
> > > --- a/arch/arm/boot/compressed/string.c
> > > +++ b/arch/arm/boot/compressed/string.c
> > > @@ -21,9 +21,9 @@
> > >  #undef memcpy
> > >  #undef memmove
> > >  #undef memset
> > > -void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> > > -void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
> > > -void *__memset(void *s, int c, size_t count) __alias(memset);
> > > +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("memcpy");
> > > +void *__memmove(void *__dest, __const void *__src, size_t count) __alias("memmove");
> > > +void *__memset(void *s, int c, size_t count) __alias("memset");
> > >  #endif
> > >
> > >  void *memcpy(void *__dest, __const void *__src, size_t __n)
> > 
> > Aha. So shall we submit this to Russell? I figure that his git will not
> > build *without* the changes from mmotm?

Yeah, I do not think that you can apply that diff to Russell's tree
without the patch from -mm.

> > That tree isn't using git either is it?
> > 
> > Is this one of those cases where we should ask Stephen R
> > to carry this patch on top of -next until the merge window?

I believe so, I do not think Stephen has any issues with carrying that
diff to keep everything building properly (although I won't speak for
him heh).

> Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> until the following merge window, and queue up the non-conflicing
> ARM KASan fixes in my "misc" branch along with the rest of KASan,
> and the conflicting patches along with 9017/2 in the following
> merge window.
> 
> That means delaying KASan enablement another three months or so,
> but should result in less headaches about how to avoid build
> breakage with different bits going through different trees.
> 
> Comments?

That could certainly work but as far as I am aware, that is really the
only breakage. In theory, Andrew could just hold off on sending that
patch until after yours is merged into Linus' tree so that it could be
added to that patch and everything stays building properly. Requires a
minor amount of coordination but that would avoid delaying KASAN
enablement for three months. I do not have any preference since this is
not my code.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106180929.GD2959494%40ubuntu-m3-large-x86.
