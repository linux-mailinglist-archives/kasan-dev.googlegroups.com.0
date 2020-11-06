Return-Path: <kasan-dev+bncBD63HSEZTUIBBY6SSX6QKGQEG7ILY2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 49CE42A9869
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 16:19:00 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id a126sf2001152ybb.11
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 07:19:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604675939; cv=pass;
        d=google.com; s=arc-20160816;
        b=eVKc01zJspEd9lu1IPi61tjSGTms+kuUbVNSpnPmsa5G4Da6Qu7xU+i9D0leSxgZKi
         kQr6I6xlnff/diflr1pPvB4QGHUFYzwpLsolq0gC1DGWlUndRR4Y05kOyt3V/HSCFyP6
         6+4o5mOh80LG9cOEtnuf0PeRontGSjXc4/j6pANOuIe4xx6Pe8I8CPhclfwtCTwTry7x
         TS5GupRYLIH9xoY1dnjst0X6X9U/zJOr3PB3v3TAcS9Xw6ypaw+qP7cgFXrohSJU6TwI
         GhN/h8InoDp3JY8q/HB4Nmn9yG0F3b4QQrRGa5jZ/0xtLjb1oMf2/fQRrSuyoaaXWKzc
         ipBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=RRn5G/57hJs2jR1fcnUYXKXvG/rmJSPLwJ3Q5R+eIeY=;
        b=atpIRiRucC+OKy2mU7HcJRVnc/GBllGulL6zHM5yFu6wlFtuSEnalsZk+iZecqmuGk
         +vhughcrbtq6Y/ltGIvr6tGN+1G8gcuguQOHPKFHT77ruC2mR4hbGL0PD1lA6MiAUqr0
         BBcEtd/pj4b3A7c0Z9kMlBcbbLHoQUb7JcH47dpJL3mU2qz7JD4XEa797lcZAPZ4n+gb
         hSwArVdq0tRgdx5FDoehWxty8vrKbn5QM82yjSqiNBUppo704j7E+uDyaj+iEsyvLERA
         j8atFrW9PMsncdO20GlvrWGyTvkopnuGwVAuGZzFSOFa3XIvFwukm7l33lgGA3pCBpFD
         TcuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HK+nBRdr;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RRn5G/57hJs2jR1fcnUYXKXvG/rmJSPLwJ3Q5R+eIeY=;
        b=k+e2F7dRH2kzgyDVpV9lL2sYwvin6l1ndHqhYMW8ekNWUEPmrB8IP9XY2JX5SPiv6d
         7BJ5i7UDSZABp9KSCsR+1zl/XnRDvX/IY/1BClnVh+u6SHA/Gpgz6XoiPc0ZPNqAXZ4f
         V2OOK5SldQU4BvH5K3ceMKn4FJrn5mvoaulGDBbhgcgJ9tLkq8JmozsSRiB+nTqt/sWs
         x7wsev/BH0+mnOjF/0MzCu+BuDLqC6DBYlfJlTP5Fgct7hILGePaXF+p809k8216d9mE
         0FA8YRO/nNYIDNwHJiIiHq/MyyHl8AUbQwGr3LzTjbFOFWLTApu9Smd4JXllskYmaq/Z
         6NDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RRn5G/57hJs2jR1fcnUYXKXvG/rmJSPLwJ3Q5R+eIeY=;
        b=ufEi/Y3xxicKK2ay1vXShR9kQ17CaNlahZYX6MyoudS9bRJsiPJHKUjWh4hzXZ5vR2
         e397ZclR4hUbN+3Vrl3NiG0pc7kQE+vawYsG0UizApRFwl1+KOpI2DpvfnYRzvBJfBpR
         mC84A/r4JzM4yHP7BTIXSOhDW/H3E8fqr0SOlC2VNXMEJmz2pvTzSl3N6HVN5SeBEHrN
         nBj4+/ZfDR/b+wr7Q3X6SYADXaPSlZA8nA0NN0o5Aw/a7PHYMmvhzGBGyDhMjI8/ALXn
         b34lou+xchHhYnhgSUJUxDN7C4NjrX/J43FTAq4E4K7zp0DeQE1rNBgNw8PKvVg6xUvZ
         F16g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TGfCDf4hiRDb+k1rPiU68hsJhlx2gG6Ypf5VpEh76hVNCu0Wy
	YCvRpO4rL2Mjl4FFdDHxgLQ=
X-Google-Smtp-Source: ABdhPJyEJO/Pix/604Cq3X4YFTNJsNu2k+oIjEmxHSsbkhPKiskk958oz53894pmluG2kIEAyU6h1A==
X-Received: by 2002:a5b:588:: with SMTP id l8mr3471439ybp.42.1604675939360;
        Fri, 06 Nov 2020 07:18:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:e81:: with SMTP id z1ls878511ybr.11.gmail; Fri, 06 Nov
 2020 07:18:58 -0800 (PST)
X-Received: by 2002:a05:6902:4e7:: with SMTP id w7mr3468397ybs.190.1604675938817;
        Fri, 06 Nov 2020 07:18:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604675938; cv=none;
        d=google.com; s=arc-20160816;
        b=Wn0i02ywJC04jNx4pl+J2kNjBF1SGMm5Ao2sNLkooci/YNCCF6VJaPUJ5sb+TdNDJC
         4pYK+32m+ZMuc0P2Of6/SLxmaHOITORVLcn+lqXZzirFqplloYuwOmplskZeIfFKCFPH
         dEwXLloFBKAcyncT5s5Lcm9jvw+FehshLsw1BodicII4BbX085zXOchxXJJnLOSPxQkA
         xKIxzq8aKI3/L/UtWd3obprVAcpZpXoIEUSMeyMx6OL9WRCdpnKEdflVfULTOQCs0PaW
         PI3z9rM3iCnYf+N23jB5AlUjZGcCc8Kweu5pzXkpn6UzaPf+6IuvTG5oN28b2BZfVErO
         Lavg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xOMKg6qmKijl9J5/rnvnQJY62Sy8tMucIWTj9G+mVxI=;
        b=v8CBHe9FCFjkdt3oStbr9QB2JH5nxt2vpWVLpVfi7NPmDq0lJkWp2YQCSeSWl/UmUT
         lnfjKnIu1yLqIpO/50tTROo8dVDl0M4x+Dr2vA2+M4FE1RRHBnBW4uCn5mK0/vWHYx+h
         iMMlGqylJGvzWRo8a+zP0Zz0UcPJHHBW3S5uny+3by6o82CJ62T/JKvB1LlutgnbIWM3
         K3Vo0e2zlwjcy9LUWU8xRTLHMGnvQ69hKbqiYJxenAPLwlA9oWa9RL42Ux6lgpj9SVTD
         5LvVPx19/Od5RfoAtNVl5LWsYQYTMV98ErcjUH+5zHwUlgTadkCHqX7RTV/UJQaCd4dw
         4YIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HK+nBRdr;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q4si131479ybk.3.2020.11.06.07.18.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 07:18:58 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f182.google.com (mail-oi1-f182.google.com [209.85.167.182])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6AB3F2224B
	for <kasan-dev@googlegroups.com>; Fri,  6 Nov 2020 15:18:57 +0000 (UTC)
Received: by mail-oi1-f182.google.com with SMTP id o25so796170oie.5
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 07:18:57 -0800 (PST)
X-Received: by 2002:aca:5c82:: with SMTP id q124mr1427723oib.33.1604675936524;
 Fri, 06 Nov 2020 07:18:56 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk>
In-Reply-To: <20201106151554.GU1551@shell.armlinux.org.uk>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 6 Nov 2020 16:18:43 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHoKOTtzB645EYZzGtt2tJaZS15Hzn+yoeV3_Ffer_DQw@mail.gmail.com>
Message-ID: <CAMj1kXHoKOTtzB645EYZzGtt2tJaZS15Hzn+yoeV3_Ffer_DQw@mail.gmail.com>
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
 header.i=@kernel.org header.s=default header.b=HK+nBRdr;       spf=pass
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

On Fri, 6 Nov 2020 at 16:16, Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
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
> >
> > That tree isn't using git either is it?
> >
> > Is this one of those cases where we should ask Stephen R
> > to carry this patch on top of -next until the merge window?
>
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
>

Alternatively, we could simply switch these to the bare
__attribute__((alias(".."))) syntax now, and revert that change again
one cycle later.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHoKOTtzB645EYZzGtt2tJaZS15Hzn%2ByoeV3_Ffer_DQw%40mail.gmail.com.
