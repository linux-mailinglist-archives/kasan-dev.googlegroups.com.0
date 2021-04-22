Return-Path: <kasan-dev+bncBDW2JDUY5AORBBVCQ2CAMGQEDHXXBZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B1CC23682F4
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 17:06:46 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id o4-20020a0564024384b0290378d45ecf57sf17055360edc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 08:06:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619104006; cv=pass;
        d=google.com; s=arc-20160816;
        b=q0TTF6ceqE1P/ZPvQnouhNhmPecIfavM6tJ7Ji/Vjhp2fHuoS5vC8EjOSQuiivy0ko
         xYnU7Ct2u4O9G6pFnGjDER+i3n18mgElWj/OkRHpddgs5vvdJ0thsCccaMX7WyQ7LQln
         oAhAB29PRKtOL8c8Rtv4jJta8Drc/7pg9oUCF7uj2ocopiEYlEHJEi0aTjsUpEbsUwWR
         xrgaLxfeuExS0gqiHQUR9FTxLzoLUNcVZsg86P+6xBVdlJ1SCs/K1ktLDAzIEuCR5gRK
         /nK4QtbCG2q84B0+hS9htilWgVQuemshVSNSsIMSQ8k+AVrWXxu9y23dgVnmkxL6thpz
         ek6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lhxpbQ3yrT3pxp1fn7OYa6gPJIySdxzJIeAD2VJ+yKA=;
        b=fbzqSh2GLnH/armaFBUXe9fqVGVWR/u2Cr3z7vjoH0KpUpN3hzodF2S9osrdWnFLm0
         FstmMqoRwMfyRPpCD0YgiadfYxbfxZCOxC1JrXEmHYeA3YJ7LiyUqe5JReiEvvRuR6PN
         vNbuji0khuxa9x2w2pr7jN/kJ2UdJDqXRJi6hTuzmZ2zvkafEsJ+8XQTdsJxbILNXleb
         mhCBXqhS66amDLxtcVX5G4BtH06Q5uOnWC+J1slQ9ZU0JVrvo6o3EywZ6ZCaTG9UH1ML
         2bb2xmdOkZ0n5xnvtsvTktYUtbCEaNAiBBZeYl6qZwR+jCEgt0VRh+1gEqTTdwKrBDib
         Pd0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YwpW4PO5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhxpbQ3yrT3pxp1fn7OYa6gPJIySdxzJIeAD2VJ+yKA=;
        b=ovnh/zdvP8JtS1tFs0RVpVsfDTP8GI3ENNtc/eY4NZYk3E6BSXcyCMi3pEjIqjGm4n
         cVcoRBZoIWuK/sChfdyglZBdsoV/xHXKwOyFodzLa3dOOnka21KiyFm67UCCNuNjEJ8w
         1nO1KdORuuMxgRGdo0yPqEO36iWnXBYx/yuAldZaUG98WhiVoVdTJbvGp6Ccc5v78plI
         qqLNu3AST6wqmn5QT/WBHqUXatRtF2vEpPlt/RHf1alhJEfDwwKgZrrzU9YVidHstEM4
         L8A89ng1KBTBdrtaGz6Vyj2crMQV/xOCgfHcaH6As0WBHs3pPKF8vL6cJPs4v1AaJGKs
         5dWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhxpbQ3yrT3pxp1fn7OYa6gPJIySdxzJIeAD2VJ+yKA=;
        b=bOY5b/qwH8XyzkEw6d33w4BpW3wnmDw1TWw9a6We9Plr9LjDyDbOfH6nMjkHnjHpOG
         Hc1tmDZDGKv+kOC20mC83NvDZIRfhNvNPhsGNKAJTP54uj9kgUILd4JQjtY2dwbZQE7D
         cnYDlZANaRSxRRihdeOhF7dStWuJ8OXKeNqngKUcCMRUnu7hEbpYBa04BdERHKOzJy4X
         rWxh5ymdhzacZuPT9SEEUixNZOr6oiI6kRbv25Gp2I3HGbtmaHUA0OuZFpPVcxAhrsO6
         dexNN2E3q20KYkkJX9tklTWTQgiC5xXDcD73py+/w9rVORozanPBgs46VR0OEGCcl8Y7
         JKmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhxpbQ3yrT3pxp1fn7OYa6gPJIySdxzJIeAD2VJ+yKA=;
        b=EAj0DkLgm3JI2YK4LBaalsa4BcEGwX8X4vzmX528S1fvUKxu1FH8su0JtX2T0y0p/b
         yC9reBXKl7+Ify53YSWOpGROAMPCx7baslP0z9Ripm+ArjeCHLjeBh/yMCGSC6o5qFgF
         ma4niC6baHX7gHjhFK6phgDM/TqIrr+bG3vkzSMW7jNjgG/V7HgVxGIlp68XVSKE7Kqk
         mInVFRJXdMymlDc2rkdjEh+1uMOmxb1NEsWKtCSktiuI5iXfkxQ4oA8LE4Q0lsMWQcY+
         SL9RByDpTFZUCw50SAmc5gYzaDc8JNHrBhQDDUkBNNdHI5+O8o2A9YC5Y+T1pILFUDwQ
         sCow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329bdD0g4BhCmoxbhtZtavUU8FIXnPyHXHkWJOQx9WuUlPIrl1A
	e4MHZeOUMBUngkMI+pYuoDE=
X-Google-Smtp-Source: ABdhPJxTJnJIbC5QD+yDW9+Xje9hEqAZE4lHiNO8UFPAfU8AR9KAHUKL7+CpUz4rf5U5z+JsZxqQ2A==
X-Received: by 2002:a05:6402:2216:: with SMTP id cq22mr4460265edb.265.1619104006517;
        Thu, 22 Apr 2021 08:06:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:970c:: with SMTP id k12ls2971470ejx.1.gmail; Thu, 22
 Apr 2021 08:06:45 -0700 (PDT)
X-Received: by 2002:a17:906:c148:: with SMTP id dp8mr3877751ejc.193.1619104005670;
        Thu, 22 Apr 2021 08:06:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619104005; cv=none;
        d=google.com; s=arc-20160816;
        b=sp/u+KMK4HoKlwffeaqntjAg+bVN4Vw2YS6bk+3jwpPdD5iSGkdN+htMiAfYt+rTnt
         bown+tOOFfiZi2OTuysLkimJxZHAsfJ5jE9hDInjZHaP0GIF6T6jQcSUWgcQZETgxZrd
         Kx+Fb11Xn+M08D+tyLwGabgEwZioZMmBgQH5oFxLTynf9T1p/BpMF2i2Qxpq1GVQm1N1
         OsN/qGi9fONJZFntCleo7rymYzIi3xoiHv263L0su1fCnyA/w6kL1hpVXTMYeQP9ufC5
         loaTOCMVxnrwhh3/ElftFJJnO7Zt8fNJFQbr9SPocltJ49GmN5sM8vAghSCnSX0WXxy8
         trzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aiWM9rp85vgyV36ASLFY/jLiQfSBITIqRxoGkPrE4Iw=;
        b=ilD3Wnj5+tPiFkr4pybCGKz8G1dX7Lbu7a73zbKSrJIdoHCTnlxiaE4IW43XX0OERd
         JxkGHXiX4v0swCcc9ORqM+TIF+ZwOc0DYprpTaD8hndQFZqRAWeiNiZTIJk1rZWUFsyN
         TdUXgydXkvi1oNCdkY8rJWuSN2Wc+TB1i1IMf6wMc834lAE7IRBU7elvr1ZqwwRuaZt4
         q2TIvnlRlNEtwq+TRu6ObYlEmpabf+LFqmfqdxElhrnCZYDrXIrwj7zD7OkUxli/Jrqa
         j2b313byCg/Vg0nyddw5bBHLeNu8gojuyib8UwXoxzP3bUq2xf6RyG6TNS3JaU8DyCeH
         F4QQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YwpW4PO5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id d24si454955edy.0.2021.04.22.08.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 08:06:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id d21so33795506edv.9
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 08:06:45 -0700 (PDT)
X-Received: by 2002:aa7:d541:: with SMTP id u1mr4497795edr.95.1619104005534;
 Thu, 22 Apr 2021 08:06:45 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcas5p2.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com> <CANpmjNOT7xVbv4P1n3X24-HH8VMBs7Ny33DFYbzjO6Gqza2mZA@mail.gmail.com>
In-Reply-To: <CANpmjNOT7xVbv4P1n3X24-HH8VMBs7Ny33DFYbzjO6Gqza2mZA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 22 Apr 2021 17:06:34 +0200
Message-ID: <CA+fCnZegOsHtWJy2QmVe=y_WHwi5WHFRfHLR6P9SHjX5c-9G7g@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: avoid duplicate KASAN issues from reporting
To: Marco Elver <elver@google.com>, Maninder Singh <maninder1.s@samsung.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	a.sahrawat@samsung.com, Vaneet Narang <v.narang@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=YwpW4PO5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52a
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

On Thu, Apr 22, 2021 at 4:10 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 22 Apr 2021 at 11:17, Maninder Singh <maninder1.s@samsung.com> wrote:
> >
> > when KASAN multishot is ON and some buggy code hits same code path
> > of KASAN issue repetetively, it can flood logs on console.
> >
> > Check for allocaton, free and backtrace path at time of KASAN error,
> > if these are same then it is duplicate error and avoid these prints
> > from KASAN.
>
> On a more fundamental level, I think this sort of filtering is the
> wrong solution to your problem. One reason why it's good that
> multishot is off by default is, because _every_ KASAN report is
> critical and can destabilize the system. Therefore, any report after
> the first one might be completely bogus, because the system is in a
> potentially bad state and its behaviour might be completely random.
>
> The correct solution is to not leave the system running, fix the first
> bug found, continue; rinse and repeat. Therefore, this patch adds a
> lot of code for little benefit.

I agree with Marco here.

It doesn't make sense to have this deduplication code in the kernel
anyway. If you want unique reports, write a userspace script that
parses dmesg and groups the reports.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZegOsHtWJy2QmVe%3Dy_WHwi5WHFRfHLR6P9SHjX5c-9G7g%40mail.gmail.com.
