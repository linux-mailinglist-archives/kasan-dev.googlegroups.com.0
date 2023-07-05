Return-Path: <kasan-dev+bncBDW2JDUY5AORBWG3SWSQMGQEKB3325Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B87537484CA
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jul 2023 15:19:21 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3460815fdc9sf1398085ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jul 2023 06:19:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688563160; cv=pass;
        d=google.com; s=arc-20160816;
        b=OU2/ZSH/pfy1P8siPB5J/m3oy+Nr4GWzrlm/2rEU5Js510vZuJ/F0PRrffOhADPwOp
         ejTnQinA+H8LkJ94onHDdp3YsRTQKms4dOzhRqaIn3o3AOMRj8RKawOZX4haQ1Nx/16n
         Tk2r4yQJSxZc2bcpA0HxsI4hv/flukdKUGlJkNdgWlJHLGdq/der73Z6lak6/yYHGOja
         DtvG+k6LKHleaLA6GxFcFUyvmZJfCO8XUjCYB11Wygup/jPzwx4bTc6FrsOBNUTm5MJa
         GoB6qbOH3qQvagZSr5SLRlm9EDgQ7XpZj0ArW3X7a4T4hwdmNPHy0Ehie/2VqeYe3EYJ
         rwgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MgeneKSzQVT6oRhPJWdm2xdVeHd7MzJMWVr2ou5cE1Y=;
        fh=h7O7Lj1ilIR3bB3Qcw1DLNczxx+zkH5pMpQTEDWyego=;
        b=BaGh+HnBg/83bbdA0Lf1lCbGckJzA77WgYkygBDODeDhl0vloL85tBwq2UAHKwaM3e
         xQkcgPEGCNG9yU+QFnGGtxRGC/hN42kXP1s1aA/3QPbLJw365Oa47QP6tebL+s6/7Les
         AUBpb+EZwrePnxjrsXsU7WSmoE7w5Y8S5IBafLcEgbBBNBkMRRP2V/D0MqfMVb9Ets1c
         doCCmWpxSTAfx+nUWtANlcVYcQCUVXDgC6FvrsEBtPA8+TI62u/uf6Q6/fKpMG9B9L6+
         pI+1qiKZfdRrhjVr54DssHrnczGFlC06tRAOZ+VbOzwUXzuRBNaGKzuHyT3xq6ruDu43
         AaFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=asQQxGjG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688563160; x=1691155160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MgeneKSzQVT6oRhPJWdm2xdVeHd7MzJMWVr2ou5cE1Y=;
        b=TdKrNLyFTtpJ9Bx2EtZ/EgyulS2CXLs/9jEmkMX14rgVJjDnb43RIVRBk/6yFXCIG/
         lVH0b1D2nn0t6X0raobDdPn7sAqu035yx0/P1HOUbmKhfv15BCrgohlSbNmsv3QutVM0
         jeyQ52knN7gsc1RiyHB+737KIhI7hfGuWUWVqSwAPXPwoo42J5tU241jQ+L/jrk700kS
         hSsviE9j0EQZGd2Fq/3xGBzbVKFesrFzE+9mC9mu6WtxPNgFnIpj26Je+ud5cXgwxD8k
         ychBSXnle6j9mEZx6YBIzSPzhnBw9W8V1gMUQtsO29XsLU4l4XM1Z+/5dZ1enThPcPBW
         hbHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1688563160; x=1691155160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MgeneKSzQVT6oRhPJWdm2xdVeHd7MzJMWVr2ou5cE1Y=;
        b=Zfgxpl+zlBe/bA6Kb4/NcMC4ajJr/M5GQXVC82Ym3Slw6Q9wZ/esjnF07xxDpbEgS6
         oAYVN3ynJmF8wgC0TNMU5yKgabGSaGSGoZGNgemvKLxcYCMBSCavGpIGg9jGqusKyZHY
         xkUhriN5h6o85R39DJmKcX+v8I7WuxTha3bqktYxvCv8XbC/+n72HwE8o5QyL7VjBWMx
         VLUZHSbXJ9ndP+icA4qVzIg5Ujix1vva4l6mK5Xq7Wir8citn5nICineRMzuELWMLp5F
         W1dMsDF8OKIWGyrhZBiU7S0ZTLP+FXfjXmpGU08ih96218Sspz3TEnjFPI9FZoWyqcK1
         h1dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688563160; x=1691155160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MgeneKSzQVT6oRhPJWdm2xdVeHd7MzJMWVr2ou5cE1Y=;
        b=YK4QsWvOPjWqWwxqFEE3GaYzyTJkJIL56Bt269ynatj5fqeBwXxwvWns95bj8SkDlJ
         nRnyNjoLjfTXMP+YHimhkJVXqd67JSrwpAhbm8sb+UcBDwxYq+5EGqI7Y1h8FSJOSOua
         9jIcOqhaXYOBu59Tw8zzVGaPB1EWlPugz+BqL1igvWT8q+sshjdV23jqbgYEtGCkOk00
         Q936x8uFLWmTgDOdCYi5hxK+QwWT/dKj+uI1DAh3MTBGhJ8Ba78+RmAPERW4PmTQxxri
         +lqsXuPlA1eYwyRauUOCMmeQsHxlNQVJVc62MTtNTOGElUb1JJJ44OHOOLjCH2PdXn/j
         xGUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZ7cX+Sm5+JKkHaGAGvtbseVyBrSnijeMib9XY60xj5nSp+8al9
	2zHjPoCV4U3+ubUq+VQjkwQ=
X-Google-Smtp-Source: APBJJlFH647fTI1KJOipoPAbtYoGaGPqV9QwkmDkkIK2wQHMqPGKrQqQQYzy/kOIHxVgZlBnXDuWZQ==
X-Received: by 2002:a05:6e02:609:b0:346:14df:1d1a with SMTP id t9-20020a056e02060900b0034614df1d1amr1567135ils.13.1688563160447;
        Wed, 05 Jul 2023 06:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c265:0:b0:33f:c677:ac25 with SMTP id h5-20020a92c265000000b0033fc677ac25ls1501833ild.1.-pod-prod-00-us;
 Wed, 05 Jul 2023 06:19:19 -0700 (PDT)
X-Received: by 2002:a05:6602:3990:b0:783:42bc:cc5f with SMTP id bw16-20020a056602399000b0078342bccc5fmr1610876iob.8.1688563159834;
        Wed, 05 Jul 2023 06:19:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688563159; cv=none;
        d=google.com; s=arc-20160816;
        b=J11cb6/QTP1h0faepwLy2hbw2hUAJPEVdRIyh67YPT8aaFD0Xa/LuRwKb4zKJVKLzR
         N+oxfZw8K/YKuN+0TgJ8rCa1ZJI1Sxs9QLkeN6Gzc7jZaBQaVg2e0qWZr7hWFNXot81h
         Dz6wrWWwN6fukIY3FHfG5m1JazDdMmvGn5EnKv/THBiiG6I/DiXiUK2F0ALi5zR82/FR
         tU9wWVetI/uI5yxQltgPolzGIS9Q6TlwyetJCRkhvvx+/+PfFvCRidG3NYBSD5+n6/4X
         +CdfxmYX25ZxITGQavvR6ppcLjrynBlgtlgtfhQipkpWzXxAq7SjjUgkEb6OWaZLJ3cg
         UrTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dHD+gumzoWP+nl3VtSqoKGEKW4lPTUyBTvzSxtXSgic=;
        fh=FLheBl7U4mnapEuAMbtrMgsVTss+N7v7WP+2Ls5tmtE=;
        b=Zbz+hk2i7X6miFhGZey3SAZjgh6GChySaOghpYBc8XdJ733PiqVeIdD87Ef7g5VwsF
         2ktRjq47UPL9uWaT0x/frZ0AQX9vOVEyiVeyRueplq2wZnQ/evpBx6Zm1G2FzsVyTY5g
         7akHoluye1EXcYoRj66We8XZrww2B38/tbrIgMHdyWReBsKg30F8h1MUPllhQdOlPzS7
         W+wvM0GZPegCs/hyQECkfnK5x9oO0DN5TdtPgIfv1UM19uxfvxr1/3PGY/B/FWIHNqnx
         ZTeX2MfPzB2odNswvuTrbzfWzL3lBD2dMxxB5PKOQtjO4d4Bn7x7GSDt8SFqBwO/E0f6
         CwVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=asQQxGjG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id cs14-20020a056638470e00b0042a49b96029si1807474jab.2.2023.07.05.06.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Jul 2023 06:19:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1b852785a65so5257835ad.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Jul 2023 06:19:19 -0700 (PDT)
X-Received: by 2002:a17:903:228d:b0:1b8:8d48:958d with SMTP id
 b13-20020a170903228d00b001b88d48958dmr3547209plh.1.1688563157269; Wed, 05 Jul
 2023 06:19:17 -0700 (PDT)
MIME-Version: 1.0
References: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
 <CANpmjNO+spktteYZezk7PGLFOyoeuFyziKiU-1GXbpeyKLZLPg@mail.gmail.com>
In-Reply-To: <CANpmjNO+spktteYZezk7PGLFOyoeuFyziKiU-1GXbpeyKLZLPg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 5 Jul 2023 15:19:06 +0200
Message-ID: <CA+fCnZenzRuxS4qjzFiYm05zNxHBSAkTUK7-1zixXXDUQb3g3w@mail.gmail.com>
Subject: Re: [PATCH] kasan, slub: fix HW_TAGS zeroing with slub_debug
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Feng Tang <feng.tang@intel.com>, stable@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=asQQxGjG;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jul 5, 2023 at 2:51=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Wed, 5 Jul 2023 at 14:44, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
> > kmalloc space than requested") added precise kmalloc redzone poisoning
> > to the slub_debug functionality.
> >
> > However, this commit didn't account for HW_TAGS KASAN fully initializin=
g
> > the object via its built-in memory initialization feature. Even though
> > HW_TAGS KASAN memory initialization contains special memory initializat=
ion
> > handling for when slub_debug is enabled, it does not account for in-obj=
ect
> > slub_debug redzones. As a result, HW_TAGS KASAN can overwrite these
> > redzones and cause false-positive slub_debug reports.
> >
> > To fix the issue, avoid HW_TAGS KASAN memory initialization when slub_d=
ebug
> > is enabled altogether. Implement this by moving the __slub_debug_enable=
d
> > check to slab_post_alloc_hook. Common slab code seems like a more
> > appropriate place for a slub_debug check anyway.
> >
> > Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated =
kmalloc space than requested")
> > Cc: <stable@vger.kernel.org>
> > Reported-by: Mark Rutland <mark.rutland@arm.com>
>
> Is it fixing this issue:
>
>   https://lore.kernel.org/all/20230628154714.GB22090@willie-the-truck/

Yes, my bad, messed up the Reported-by tag. The correct one should be:

Reported-by: Will Deacon <will@kernel.org>

> Other than the question above, it looks sane:
>
> Acked-by: Marco Elver <elver@google.com>

Thank you, Marco!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZenzRuxS4qjzFiYm05zNxHBSAkTUK7-1zixXXDUQb3g3w%40mail.gmai=
l.com.
