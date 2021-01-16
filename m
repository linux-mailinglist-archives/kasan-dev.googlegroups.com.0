Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ7HROAAMGQED3HGFRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 037512F8D87
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 15:09:45 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id h1sf10913476qvr.7
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:09:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610806183; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMSQISORLQQHR18fkAl7cpP9djiV8tQd8I873L1LC5ct3toZCJS4rJMXgDMQHnw7M0
         zfIvoDCBfuS70YvOOZXnzeVPtAflHJ/95FAgv202NQnDpuhaFam747qwJ5MWZlO+7Qer
         ZKV0tlIiLNa7uyTIQAodlDQPPOxV94TUkSOlegpMDOKxudweS1+N+ShbCgXL+4UI2rss
         zjNZBMdWzJJZZa65QQQtNEGMdkyJ7UALxeGohvu+VwSJONI5Ng/C23tzrup6fmOIFJVe
         BDAH8/5CiCIhBNu6gYr5xzcSkFvQn43Qq8owzWImcv/mYilXPa0AqBCzyQ1NDFgCR73n
         S4qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1qwcCNynLe2TBwwWCuJYutytaqVNnXW1HUdN36a5N6A=;
        b=HhZbsXtDgk2wl46nI7DPaz5duhKbHIsYjlmxYvrw3VVJjGCVRhTftVfXs/RmQBMhBd
         aPo4NATpuEAMyv4XGFs/EryQWif1axDjpiteXgDkEyImP416JvMDYEt5mBHNEhq9Ze+l
         mTUAvXG2c0fcSLvSiRJ478konrXXzyocsVmL1QnFrzS7bd5slWnnhOyytz4YL5PgQWp3
         6jR31wtPpztd72goFZCngFg3HqP1QUzEg2b8XzXu9RkYzQjaPRdM3behP7y+mogrmPGi
         /23XA12AUC45PMKviDB47bfSASBLwkCi9f2YkCJ0Q6fqWm2Xh9+cxQ4KVkk3PS54lHGI
         2CYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vYrM/XUA";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qwcCNynLe2TBwwWCuJYutytaqVNnXW1HUdN36a5N6A=;
        b=c6Cn3yue+ISTahiKGvZJTPP9NrEujAgM0cLrtvDfvoxog40TnQ7/UOm3GmR9/zYMZ8
         SSypZsviFmuWygt2Z3XiW0U08nJcHMLxgOShHwRih/+nNAlA1CQWK+h1qKeLpOkXoXBE
         coCN6hVkvZO3Q95vHqrv6YDVoi+9pzWLeZ996bSoMnGNzUxQCxhN1n4c6yLMDBx9e9qa
         Hv1q2v0xxNPM1qPC36KR03i/cOqPGfrlmdaqU63Mma9skGmnbf1zLESWFpBsxiVXqoxY
         /uYCNU31T9hWi0zdNDY2zDvYRlk5c729pg8MtCfeorQvAjY5YBH08+m+O72PTy+AHlNz
         w9cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qwcCNynLe2TBwwWCuJYutytaqVNnXW1HUdN36a5N6A=;
        b=jbZXBt345y40ETJtIwQBEn/k8M4mfVhj76LUEglVmIIzMF5JUSrV9sL9ARa72J8egb
         JCWNTrXhnx31oKISKTIjxtN3cYqLRR0k1zYJvHO4Tq6e9ArCKiqAYYKkHMAcbhMVor0w
         XfdWhbeN9GtI7KshAdfNo/if4/r6NDf4++AeNq9wg99NBLsb58Szaajd7U3BxSPDXYhv
         UVanGXI5SZkqb3EZy7UjSl7N1p6oNUVko0sZoHfpHO3ZKn/eBkmkH7ivfgZIZXB3cvTg
         sIuyHC7AIvkURcJ4Rqpm9hK+rZc88SxCHEykSpYN4WMv4kUx6PweqBCIrT5THolfnkPM
         feCA==
X-Gm-Message-State: AOAM533gHa+oC36UD8vYB6tQ/faJnu0YxL+hIeYXcaoiiN9DyuvrRacu
	/oLK3v/sY8Z5sxCEtyGm0Tg=
X-Google-Smtp-Source: ABdhPJzzY2luC4SDvqXZqZE3a2A9+fkD4WRpLXbw94L8ZiV/dY16BzZf5pzBkfN1Xx6b3ioH2sIXSw==
X-Received: by 2002:aed:3bfb:: with SMTP id s56mr16143619qte.109.1610806183779;
        Sat, 16 Jan 2021 06:09:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f501:: with SMTP id o1ls6237110qkg.6.gmail; Sat, 16 Jan
 2021 06:09:43 -0800 (PST)
X-Received: by 2002:a37:8fc3:: with SMTP id r186mr17092961qkd.228.1610806183303;
        Sat, 16 Jan 2021 06:09:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610806183; cv=none;
        d=google.com; s=arc-20160816;
        b=tpDvLn9ymT1wu0+5yZDXGmG5/dTShb6+vC0AQ7Jca6hyBtfI/VNIXNRrUZrIVEiUBF
         vENfQNrmn6ZRePbKr6ClW12dww6w1wBi2vhbaoC6cWG6kka2gUW+/aCKjjcPsoWGpkRT
         okRWUIPOSN50u3dKaCOFXggWGiQVJZWxXVYZqlxMU8vg6bUAjh+y147inj2xdy9sQF9u
         /g6+9gj/04dMI3zflBQo/Z/nwuU7tnkASaJsZYQkxd0uhblMrxSA5OZzKFf4HhbL0kPY
         /3JwTKAYedTJG+xNd7BgrRlTORs81qlz23QTJuKa9AIEefR9/gLOYj2HIDi0hwdHXRSw
         JnEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uFVX+DeCBEJmZ4NDpg1ld7xFOp/fCxGCVOO/JOHrLKI=;
        b=XtYwlDvpGgnrv8dPAonoLBdsayK6znn7MvPMaQrmtvMdBbAV6z4+3tU7ycqGe9tQNi
         u/rpkE+87p4n4E353z4hAJQzlWSChYDaARLdK7zWGYbvITTgIxkCsfkACA22fN/goh9m
         wUUV4QOQHzi1p9p5wkK2tQ0sS3W3UvqVY+0VXicoHdFfFbzkie5EWhGDTwt+S70HOx96
         F/EsZ5YIQrSrdVZxOwjs98LCsNoiUTnJZmew716OIQhJvopDcGHaLiE88KRcA16kedQ8
         LuiuJ8MEHENC1mGPdVMvzTSlTxGDcVqBTuzrGJq6jROFfPVHzLn7YhSsEn2H6IlfP+fz
         r1Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vYrM/XUA";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id z94si1627792qtc.0.2021.01.16.06.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Jan 2021 06:09:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id c132so7954769pga.3
        for <kasan-dev@googlegroups.com>; Sat, 16 Jan 2021 06:09:43 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr17504790pfh.24.1610806182375; Sat, 16
 Jan 2021 06:09:42 -0800 (PST)
MIME-Version: 1.0
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com> <20210115150811.GA44111@C02TD0UTHF1T.local>
 <ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6@arm.com>
In-Reply-To: <ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Jan 2021 15:09:31 +0100
Message-ID: <CAAeHK+x36J6a4GOpEpff0BKwCKgFTuRsGiyXyScRek3hVAbSJA@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="vYrM/XUA";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e
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

On Sat, Jan 16, 2021 at 2:43 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
> On 1/15/21 3:08 PM, Mark Rutland wrote:
> > On Fri, Jan 15, 2021 at 12:00:40PM +0000, Vincenzo Frascino wrote:
> >> Architectures supported by KASAN HW can provide a light mode of
> >> execution. On an MTE enabled arm64 hw for example this can be identified
> >> with the asynch mode of execution.
> >> In this mode, if a tag check fault occurs, the TFSR_EL1 register is
> >> updated asynchronously. The kernel checks the corresponding bits
> >> periodically.
> >
> > What's the expected usage of this relative to prod, given that this has
> > to be chosen at boot time? When/where is this expected to be used
> > relative to prod mode?

Hi Mark,

Sync + no panic (what is called prod right now) + logging is for the
initial MTE integration stage as causing panics is risky. There's no
way to know how often MTE-detected bugs will happen during normal
usage as the kernel is buggy.

Eventually, we're hoping to switch to sync + panic to allow MTE to act
as a security mitigation. For devices where the slowdown caused by
sync is untolerable, there'll be an option to use async, which is
significantly faster. The exact perf numbers are yet to be measured
properly, I'll share them with one of the future patches.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx36J6a4GOpEpff0BKwCKgFTuRsGiyXyScRek3hVAbSJA%40mail.gmail.com.
