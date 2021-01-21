Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKHGUWAAMGQEHXL4NPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 049C72FE9F5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 13:27:22 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id t206sf781166oib.5
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 04:27:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611232041; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrB45CnCC2i2JHqVt99vn5v8qW46FQkGFRYMR5o4QiriD1dSAcdFrXmqHa8cg11wF5
         uiMZ8FYH7cIPeRTP6ziekf9/ONO3L0xwpoKg4EkexnyuCN0UZ/w4aOjmPoOq/aX3m6XR
         kJWxwnND6IzDdPx3RMFuPfrTsVkKSOz47sXLrbidSPzTvmmLUhVEG0MMkOyXuFbQK/uh
         bzTzlJAplxYRveNRNO9AofimXLOkI6k3mEuol3K0EvN06yk99dwnZBh1nCCbqxIUrcy4
         i1pDtjjIg+uhgfhNBCb8XT6wYwLurMi7qOq4AfzxpJ/MBJ80cm5rl8roZYBjdUp0IsW8
         mCFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zQZhH4N8QAd53agd5XZM606CHlL+1A3y9Rrc/0KRx6s=;
        b=k1DyE3SFzK4Ur3seiMWtKcckry70Vk7YClQXq6IHl2L4UhsCEkfjbaDHTJJhMMONDa
         HR2UnowgpGN0WMVToW3bHKQNtzdricn+XyxBtggoiZgA+5UEpsNpvvaoRSHBc9/NPkQ1
         anGJ17bad0x3Aaylu3cOB+xAXNNdupXSdmddQCt+sL8+lJmuIPwfPxFJyg/3+0MrJU5M
         HEBoftZ9WcBQCixBTtqRIt3GIFjblzYEdQtnbGOY1SofYJKPgFgK09Lnp6h43Ypo7mWt
         ejGy9nAidTAovN/PoplJXoNUi9FJcSxFN9ogS5YkHm3Jrg2AMqteUpH/JLaHASdCuuj4
         O54Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/9WTD9b";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQZhH4N8QAd53agd5XZM606CHlL+1A3y9Rrc/0KRx6s=;
        b=pycK3qX0CyD0wjuIjf4ameQm8m51gHjNdkLtkurk4erkjK8fBcVGtKOeE+UDiHS7F0
         nlFJ8mjG6oh2zcNc3wQ8m5ChOfS8WppcIXlm4VosxQanDb7Ia9M/lzE2kYtRrQWxOhwY
         q6T69hXFNZSR4N49vCTnTyBrhHEA7XWvyLkNFV6LVFzx6WxWf03/aAchS5VW8qVBHC8p
         hOqzU1GdPGBjF4QsvGkiJB2iAI5QwKthJfEM6ugUnvnKFeAnLSqrv7mjKxuy4gVJSU84
         twVcXUL+5ibu0W9st4++j+TqS1lV6u2sowhg7RgNe2cGWQQ6pvpc4BR8K13+sOd+sER6
         0QJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQZhH4N8QAd53agd5XZM606CHlL+1A3y9Rrc/0KRx6s=;
        b=c6CMcTCdt+1+rtGOfY7s4mZJiE3Ozj38zsumKE+Wf2Tj2+vY57hReHp6pKxzDgjp42
         uiUzT9w9mYbt6D6lBJML6lv1+CC0SRe+wx/oPHXLvtz4vgOBmo0s1+7QRFmDt8TWI1p7
         UPncADI+fkBbKYbNLQGfRWZXeitvGCN/68lqQekriAi9N2KGFUpMyTTC+kN4eu+3oALn
         7q2FYQGZNX4xagKTEEG+Rbw8XhGFecoXDUg+ZaLQLXHdd+WL3Swl4bay9K34Kn/FDJTy
         puY+lmJYaaDP5lNMRJmCCM3uwV+A268908NgWI1XCh0Cbj83RDmWLN2K90K4FkYHWkth
         e93g==
X-Gm-Message-State: AOAM531j+nS0f0XMiJD588ynHy6eEAhtdcJ21gyc+SZ3n0X/5geWCPdG
	GfnZ8PgaA2RSQCdgJGSOqcI=
X-Google-Smtp-Source: ABdhPJwMa94pn4wUkK4JUnm7gdnvIlUe1hM7T43SxFs9IU9cIzy1YnFDJ8GebDQPij2bpsrZ8utKqg==
X-Received: by 2002:aca:4e4f:: with SMTP id c76mr5767204oib.167.1611232040856;
        Thu, 21 Jan 2021 04:27:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:69c2:: with SMTP id v2ls489893oto.5.gmail; Thu, 21 Jan
 2021 04:27:20 -0800 (PST)
X-Received: by 2002:a9d:784a:: with SMTP id c10mr4187853otm.132.1611232040560;
        Thu, 21 Jan 2021 04:27:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611232040; cv=none;
        d=google.com; s=arc-20160816;
        b=ieeTn09QFsJPe+Fk5scqUZXwhfalV1Enl7hjPvr5Kd0kT3rvog4TmxTyzG0V7dyK5U
         PvutcPHZJE+kvjL/9SE0Xp83kXhE8fQCl14p6bP6pFqpC78+8xstHrkOVd9uwc+wlb3n
         cMsvWJ1HetgupRa7D3g+ub3S6esbYEY11+GJ7OBB71Im3wjbbgJXcQz6dZ+8K6RJKjmI
         win0jlY1FdnFyKabuhP5ZVuAzYkJz2kpF8FyC721IlzUFI8s4gYHJYqNr2OeD6cwwamG
         BZ9aU6iX2UF9Jh6wrIIXjW9lQ46owXDS8GDQYKVGfmvkfcUyvCSh9W8H78PWS6Fd62Cj
         VdQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hU5q0Sko1dtjWyl3dPZ2Wmvya1h/lMcf2ondb1RlKrA=;
        b=CDDx99NzZpWshpngFxVqVUcdXzGxMtis/A1EpXrBtZtAGirTD0Ts2aTbmvbi+hd9zu
         uXcxsK9+C/BEdIiQZ2ayQgoq4kjMgwnGOiDAxAxCi4+Bszv/9S0UxB21Kj3ExrNMkUwX
         UBNL3ve0oVPyYC5H4qjYTouCBu8pS+DTDU0Ix9O6uHaD3IVulZTRdO8lzddu4Af3VffL
         eg53TqeJHd4srJS2STEhHvjgsRqej38WlJItDoXyjRKJb2SgRk/F1gGjlbudzb4U+lRa
         C/NMw06sIMmLhRZ9LwGsPQ3ozD8YWURwUvvAXE1nly2zYaiYIM2XSzW2PYoHPuG//AZE
         3ETg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/9WTD9b";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id e6si73843oie.2.2021.01.21.04.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 04:27:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id t29so1386792pfg.11
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 04:27:20 -0800 (PST)
X-Received: by 2002:a62:5c4:0:b029:1ba:9b0a:3166 with SMTP id
 187-20020a6205c40000b02901ba9b0a3166mr8580075pff.55.1611232039810; Thu, 21
 Jan 2021 04:27:19 -0800 (PST)
MIME-Version: 1.0
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia> <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
 <CAAeHK+yrPEaHe=ifhhP2BYPCCo1zuqsH-in4qTfMqNYCh-yxWw@mail.gmail.com> <773e84d1-2650-dfc8-6eff-23842b015dcd@arm.com>
In-Reply-To: <773e84d1-2650-dfc8-6eff-23842b015dcd@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 13:27:08 +0100
Message-ID: <CAAeHK+yV_w3KKWg1bY-Kk=QGGR-=yT=9Ez-XOchY6XOA+h4T3Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="V/9WTD9b";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Jan 21, 2021 at 12:30 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/19/21 8:56 PM, Andrey Konovalov wrote:
> >>      return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
> > Do we need is_vmalloc_addr()? As we don't yet have vmalloc support for HW_TAGS.
>
> It is not necessary but it does not hurt, since we are going to add vmalloc
> anyway at some point, I would keep it here.

OK, let's keep it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByV_w3KKWg1bY-Kk%3DQGGR-%3DyT%3D9Ez-XOchY6XOA%2Bh4T3Q%40mail.gmail.com.
