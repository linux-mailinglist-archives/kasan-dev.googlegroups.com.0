Return-Path: <kasan-dev+bncBCXO5E6EQQFBBWVCW6FQMGQEDELJ2NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E96F432808
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 21:56:11 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id y18-20020a25a092000000b005bddb39f160sf20010593ybh.10
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 12:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634586970; cv=pass;
        d=google.com; s=arc-20160816;
        b=FUjR0IOiEcOqj6U4PpakicmtGxX5D2t/AO1Xv9WMxOLlqqo4Pzsh7/LaahtDf399Wc
         O/tJbmZ0WKa33Uzmd5mCUPVLs+FrzsNjvbLxW8KRJKf0FvNHWYRk3PSjNmRzJIpLpydg
         nurUBGMQGC3I7pLINnhgjiNDJuOq5/WKha6Yuurs0jc0zV3oyCcILQJEnvqfQZyFT7gZ
         uYUt6czW7AnQ4exhSpZcKRcOb3R3Zsu9SHfJZ1ir2djxJ2Cg6WHdPSGQsMOg2gHQqBFn
         GU2ImzLuHXp82RNIWbJsNqrhqiwfP7ZQYW3ef0dAsJEwNQd+zrof0rET22Ue7Db/OnD6
         /dWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Fme+1nYr8I9VAsr4bhPO8DF4FX5dgFe0TkTMVqCzrzg=;
        b=oHsSGEEdGEtPkcWSjIsQf18oT3bmLT4G+nVrXBKZKug4aE4NVMEgM4dNuWsgJncaBW
         vMY6VDgjouZ3OIKmEBmiYgTgUhp/nfIhcYDZnsfdXiKwu6o5Km9YQ+P1PmAxVvfMlroh
         SNMFqmm+UWfPkZdtiU6DOGvQ2tCFNysUmS1zw2QV5ScdXVR4P2Rwc78IKWl1OdwHiH7T
         WIV461BBlSc+1HS+vWVMlScVzV7KxpdupK+WTuz1gYpxxMet3CpkWubJrPPOGrJGwv8S
         Iu45oYTFUw9WBEfGiwAnGTatGkyIYxb2RnNj2d03yICwrTw3HL7/q6woqaszAlv0Nc8F
         Z8CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qga3VIFH;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fme+1nYr8I9VAsr4bhPO8DF4FX5dgFe0TkTMVqCzrzg=;
        b=LYphEFSw/xnFCIpc6a8fPpn+bdyacOWZhPK0SZJ1Pehn0rwKYYBer7Z3WaFzU9ronn
         Hzma/HW6qsVSgTd1/dTp7FKbZLvvP+MU5acJMUkt4KP0ocGfCJBKwBtixCMTnWP/QBN5
         vOQ+tVM+wXmtnQTqSwKSzcweQxTkIS002Uw2NIw6trgiyBkowOsrYmeWV4YhBn9r7296
         WfNv/419wbAyP4lYUAVbD0N4qNaI4Ru0I7Fl+UOz5AakvXWnESAupjKAcGOeXppxAP2J
         jrrJs5Cgw3IzyWQzsPhjy6AtuUl0bnV4Y1Rs72CiKjP4IiwGs8KRcG6mIChVPGn4aZT3
         bLgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fme+1nYr8I9VAsr4bhPO8DF4FX5dgFe0TkTMVqCzrzg=;
        b=nL8IXE9T1SSjNzAvdFDJ+T0rMprXE4Rh7i3DIa2dye5fEqhpXx25svQGeXYT3VbMjO
         aW/qCHGEyVL/+bTu94Ughtyp8/QwyCCh0UIOLTDESo2OowCscfvG3B1C9o7i1b+UOhKN
         t4DmctVgG8xYJmq3IS1qP2YUflxuGpH3HFO1XOFqhJb4cyYrkAAG04Mz6x2jAynMI8tb
         jnuCNPLxYZassZvnUHmkx3m1fnkxK6syYZg45+/6+VSDE8EEpljN4kKzMHBNW6ifRoUa
         qYIb8K+ne65ZFgI51GfAhWaByVQ7zOz92SqLRzHidBcJKoxROQAD7HhsJjuUHnV0OJaM
         Bspw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nTbuDW3GzbQnFcwucaM9tD0FdMQr5gHtQyG3dsGrL2m5aOZEb
	EbCsA387NjP6L9UbQDtRviA=
X-Google-Smtp-Source: ABdhPJzaa0bYnYXFEDvYV7GHvUus4alaodQgQaT2ERQ6JQ4wqhEUzLeE2BUxGqH5SMs50/6VUr9Nfg==
X-Received: by 2002:a25:e652:: with SMTP id d79mr32264096ybh.291.1634586970671;
        Mon, 18 Oct 2021 12:56:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a88:: with SMTP id q130ls3044037ybq.2.gmail; Mon, 18
 Oct 2021 12:56:10 -0700 (PDT)
X-Received: by 2002:a25:1b8a:: with SMTP id b132mr30927503ybb.535.1634586970228;
        Mon, 18 Oct 2021 12:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634586970; cv=none;
        d=google.com; s=arc-20160816;
        b=nd49CCiuVAcCt+hD1ehY6QGC9BCO/bUto089lGw17ox2Ybd3gWMHqc9nuLeY3ov3nY
         GhaIC8CHh3GRqVRQ8KImwh6wYZE45w7V5gm/vH2CTk56yCG5lSgJnNldouHW4/7qKse7
         69aDvr9xtP6jICIkpEEgX1I4B31XGIxb8QsX0L30LZqIqTPlMTtjNGYsl4Qk497eNloa
         xCKo2ShOf4SaxjOQgW7Xs1PT7BZXMMGQeh5QJj6CmQ08bNj26aBVZkIYWCutLC3TD/E6
         PjFvENcqS3ngKVL3YgBiake9W1whUatB4xVRXZhLnTjofkyxk/kHiv+Jt7rz6JSAwkvd
         2BVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RUI1//kTZh5Jz85cuKNi90j4/yk87eUqxQKcoY0Sqm0=;
        b=Obhd94/NXZKILQndU85Db/oPpvbxBxkiX4AOOjcSFTbP1SBuekGiOpup8QKZaY7qbN
         k/JZhR2jLBH1D8DN/pWkB8EJCUpM3UfYisXjWk8zLsm3LBga20OgATqJjWqCLubk6CGC
         /BYKxeDHvba9/GKsDcSctju5lxcu0ZoyVIazsIqh00bAoLJo1/UvzTf9GzB5yTZ0E7WE
         tQqSMFlaNhyj0aCYXzZnw0iV2mXx9U6q8YxOfPyFO9vmg2kpXR3Qly9AXRUov0YpiO9I
         o7gq3qWnS0WRoNA+XqImStTHI/hQIPrG25tUCUrOrudJHVODkudoJKpHj0/zKcmq/I5+
         AarQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qga3VIFH;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t13si1126554ybu.2.2021.10.18.12.56.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Oct 2021 12:56:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 43A76610C7
	for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 19:56:09 +0000 (UTC)
Received: by mail-wr1-f49.google.com with SMTP id o20so43516726wro.3
        for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 12:56:09 -0700 (PDT)
X-Received: by 2002:adf:a3da:: with SMTP id m26mr37629747wrb.336.1634586967765;
 Mon, 18 Oct 2021 12:56:07 -0700 (PDT)
MIME-Version: 1.0
References: <20211013150025.2875883-1-arnd@kernel.org> <202110181245.499CB7594B@keescook>
In-Reply-To: <202110181245.499CB7594B@keescook>
From: Arnd Bergmann <arnd@kernel.org>
Date: Mon, 18 Oct 2021 21:55:51 +0200
X-Gmail-Original-Message-ID: <CAK8P3a0huVQ+pGgHFNeeoOPAwP4+KiDfBYokVzQ=fUM-QJ+H+w@mail.gmail.com>
Message-ID: <CAK8P3a0huVQ+pGgHFNeeoOPAwP4+KiDfBYokVzQ=fUM-QJ+H+w@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
To: Kees Cook <keescook@chromium.org>
Cc: linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Arnd Bergmann <arnd@arndb.de>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Patricia Alfonso <trishalfonso@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qga3VIFH;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Mon, Oct 18, 2021 at 9:47 PM Kees Cook <keescook@chromium.org> wrote:
> On Wed, Oct 13, 2021 at 05:00:05PM +0200, Arnd Bergmann wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > Calling memcmp() and memchr() with an intentional buffer overflow
> > is now caught at compile time:
> >
> > In function 'memcmp',
> >     inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
> > include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> >   263 |                         __read_overflow();
> >       |                         ^~~~~~~~~~~~~~~~~
> > In function 'memchr',
> >     inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
> > include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> >   277 |                 __read_overflow();
> >       |                 ^~~~~~~~~~~~~~~~~
> >
> > Change the kasan tests to wrap those inside of a noinline function
> > to prevent the compiler from noticing the bug and let kasan find
> > it at runtime.
>
> Is this with W=1 ? I had explicitly disabled the read overflows for
> "phase 1" of the overflow restriction tightening...

I have a somewhat modified source tree that builds cleanly with W=1 after
disabling all the noisy ones, so this is probably one that I would not have
seen without it.

> (And what do you think of using OPTIMIZER_HIDE_VAR() instead[1]?
>
> [1] https://lore.kernel.org/linux-hardening/20211006181544.1670992-1-keescook@chromium.org/T/#u

Yes, that is probably better. I can try updating the patch tomorrow,
unless you do it first.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a0huVQ%2BpGgHFNeeoOPAwP4%2BKiDfBYokVzQ%3DfUM-QJ%2BH%2Bw%40mail.gmail.com.
