Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZOQZ74QKGQEMVZ5SDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 73D252429EC
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 15:02:31 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id y10sf1561335plp.6
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 06:02:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597237350; cv=pass;
        d=google.com; s=arc-20160816;
        b=GTLCYLr9QwZq8CxTkiOI9wxfM4mpZg0FUdxi3HounVgIFkrAIjiM7hI2+8GU6iXBjO
         o+SM7yJX1ffcf8Vj6f0pCiTgTdiQMTAPGP5GOMA/e4MCGCgI80S+PmlyUYMmPtaiIfyk
         lSX/QcRqksICV391M/2QpMfjWyThC6dZGWol9MBYO8P3q69r/EtHiS5LvwFc6QmLG6VE
         fSyrkN1NrTLsF+Ya4ijsH2F4lCwpqfLk9fAtX1WWlPc2T36P1NCiy8j2nY5gr4fmxzIM
         ClpPalG18wwq3CaWp7UNTwhF+9th7lvMo90Q3qyWxe9QQwx4VH/5ungu+dAg5D/G1iw7
         02DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gHyoV8Mxwb/fLGX5InfbVvWzvpC7oSjhnWSvks77jpw=;
        b=DXfF616xBSb21Su3SdZEgRfuGl80AdF6hIuU6bUZjkZeSHSJmPUn6FBvl/txNwh0lT
         XkQUF/7FmujoMdp3opHgwt+cgt+xacyizOSvvfuKh6dDZA8NYBW0H5D9LdthgQ1NnwDw
         1qhLz5POx/jXNBdGFJtTAs3ArQhCHgd1V3WH4osStDSEiqZhAr++UueJ6XWevE9PjB9Z
         ZeEbR/RLtNhy4LY+Y149p0tOa1/OcxE+2F5nHuSWqrw++W0V3/8R+pBBgTHjnb4nBhEV
         PcPJFz2Db7sjV+37vQm26V4OkOIg0GXj9R/o3F1aDXRSCGlU4oxy8Vu69aSTqiDp4LIS
         +3gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ejh9JhTd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gHyoV8Mxwb/fLGX5InfbVvWzvpC7oSjhnWSvks77jpw=;
        b=bJ/4PMuT7WZB5yBMIVxZdeihWUk6coYPrnfl1mTHa461gmYLj55Uwl1/SXIrYMvp8R
         e+4alj4biojV1ZTdoPi6hUdj8deLM699WIj+mFhCFa/LN1lY+tkvoVOu4v/Ej0UHNCvk
         XaAqqQJHBra1QRwjorDBY7KHiOOiyvNbTtnNru9MiWXXmEjuMj4J1dNM2a6sL77UcPPG
         w5A70e38Q39gmUxb0a5DPSV6X8x8NwkmGn7CxV1M6XHvXI77p1en5Q5+h4t11oCM0xJO
         ydPbQdFYqCgtcmG97jDh3/LgaP2RqbH0jUBjDA5eATh6/hUh+kZuN6/QbGSgnkyh7+bx
         bKow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gHyoV8Mxwb/fLGX5InfbVvWzvpC7oSjhnWSvks77jpw=;
        b=mP+d75QuL7FKJ+BPmIKZ9FYbkEzfY8aShEOhKeewLC8NAovER4xuL7SF0zE91Esu+H
         MLJEX6P+Y2EqNEnx7aoGepwUEA8E+DlI1St3bp4YI4mP9n19FCtBqV2SXgMcdlzATwJl
         ZsNel3rf+MmWF+Pcm/Blr91VTMFX6JwzQbYA4cz+hC3MXG366BJ86+6WZwgOgDzhgVdl
         bHFn1GgInmTH6fzCEBwrkQ5uIJjwHzEkuWNWlJRjGDivWkmXx8a7Wo+G2rsa0+oeLIie
         lYvA+T2H+bitI25j6dRiqmLxFUXnJzt00NOdtMJ66VeNU1hrdMTTbOQyFZ5zswbN0y6l
         sG3A==
X-Gm-Message-State: AOAM530ycm8ftNZ1zaSUl2PAR7Qho4FjWRDigzicJOp+u8jiOZxczffp
	/qLxjg6lG8DVGvIb5ipvzeY=
X-Google-Smtp-Source: ABdhPJwSG6jRmy/sBYCHT0VkFlbfIorQfsMjx2lGmg1eovg8fyWMobSdxjdP4glMh2AIgOwpgF/cVg==
X-Received: by 2002:a17:90b:154:: with SMTP id em20mr6384413pjb.173.1597237349632;
        Wed, 12 Aug 2020 06:02:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:442:: with SMTP id 60ls966320ple.4.gmail; Wed, 12
 Aug 2020 06:02:29 -0700 (PDT)
X-Received: by 2002:a17:902:b193:: with SMTP id s19mr5127915plr.72.1597237348642;
        Wed, 12 Aug 2020 06:02:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597237348; cv=none;
        d=google.com; s=arc-20160816;
        b=JZecwXXtMVVMyTPxgQ1rsjtEwzV9XBdKLV1CPaG8cGQWVA80VENqYMeKQIjcAJ1qVD
         Xoov8yDz0Zxr/TlEpthVlZJUZkkiNOo4aszJG0mFvPLy8MI1dUDuW/SgEbRHvgevVpPp
         WL2nicJeQX0hbQ1LddNcKlFpQYoiL0DR72CELD9ELkGx/yXrsFau0/TbiIKOxNHMXyNO
         VS3xml0tEhYuFqP/QWCGbHiAAYOheBAXRva2iC7vBxlj7X/Gt+osVtV6iMtr2SuNvQyt
         esGGvP9BuO1O+Aifz7zcktKasJeWGqqqZlr86pSmVdl8qlyykBphEkyDmrNx1xVpZn5Z
         f/IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/FYTOQHYFNoSSfeNhMyajUD/P2m5h59FWjXl7Kq1d4Y=;
        b=leNvHwTLe5p8pHsZ06/8Yi8eTQnpY1583BwPrN1EdELcX7kUwN7GN35OT6BasIJk+h
         e8Ad+10+gQxoKn1mbgbGHVYGqth/pB8n3AK99FQwpw55rCcAgH7gZGu3X6aG4UyuiCPB
         I0+IhmQmFiuyCV2cR1clOpakanFamCKuz9GTwPCXiy66IJQeSQ4/D1je/tQsGvx6DRlo
         qCjqiRUFn9xFgQUz/6cbB2JihaUCKA41HlDlHycBxejR/Nh4pakVso9+N19MHmfBTIpR
         vPtccvOVaZtg2CBraGHGusYClzmZMCCuTZKiIMxt8B1RAcMVHffbN+mGf/hIE5tsbLWJ
         sFrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ejh9JhTd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v127si56089pfc.0.2020.08.12.06.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Aug 2020 06:02:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id x24so1842816otp.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Aug 2020 06:02:28 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr9650285otc.233.1597237346320;
 Wed, 12 Aug 2020 06:02:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200810080625.1428045-1-elver@google.com>
In-Reply-To: <20200810080625.1428045-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Aug 2020 15:02:14 +0200
Message-ID: <CANpmjNP5WpDyfXDc=v6cerd5=GpKyCmBKAKH+6qLT6JrBGPqnw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Optimize debugfs stats counters
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ejh9JhTd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 10 Aug 2020 at 10:06, Marco Elver <elver@google.com> wrote:
> Remove kcsan_counter_inc/dec() functions, as they perform no other
> logic, and are no longer needed.
>
> This avoids several calls in kcsan_setup_watchpoint() and
> kcsan_found_watchpoint(), as well as lets the compiler warn us about
> potential out-of-bounds accesses as the array's size is known at all
> usage sites at compile-time.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/core.c    | 22 +++++++++++-----------
>  kernel/kcsan/debugfs.c | 21 +++++----------------
>  kernel/kcsan/kcsan.h   | 12 ++++++------
>  kernel/kcsan/report.c  |  2 +-
>  4 files changed, 23 insertions(+), 34 deletions(-)

Hi Paul,

I think this one is good to apply. I do not expect conflicts with current -rcu.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP5WpDyfXDc%3Dv6cerd5%3DGpKyCmBKAKH%2B6qLT6JrBGPqnw%40mail.gmail.com.
