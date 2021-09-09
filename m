Return-Path: <kasan-dev+bncBCXO5E6EQQFBBXGS46EQMGQEG5V4JVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id B33F84048CF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 13:00:45 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 41-20020a17090a0fac00b00195a5a61ab8sf1136482pjz.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 04:00:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631185244; cv=pass;
        d=google.com; s=arc-20160816;
        b=wNbnpXbEZOnIRRR7pmcwoHoKHZcXH5ZhJeSquJIc+09H4m3LsjKowEzMfp7hWE4vOe
         hMk1RtAvumgLFhQ1szSiXiixt8qjG3TNazqnd8ETN1n+K29kMjn+MBPVXOPmTbkq9L1E
         MgzbS7d1kpmM3BhbvDPHkKv8ZMgxS2slFsnuZ38UXfuth7jE+Rw7RIc9pof+1ON21Et2
         cBvChnpWPXjvHaLgI9dAUhEL2yqVGO/5+TjQW9fu0rP7hoSAbayBvZWdClL27C59D52h
         B32cJDBWzUzJGetbb6W+XQ46W1lGwdeaCiIqseIAd8j3Ry7odJTry8OJu025tI8g9bJO
         xpeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=O+8P3VuWtD5evril2Pi0y9pl20tN4rar65a8ahE7ogA=;
        b=ZN4k9vuFKUTvmiXx8/wtr7MvHwhxdE4hb5rC1iuyBcMf0c8drVfaEzCtmN8NvFJNe3
         092AybKfzKTQu+Fg5T9JfnDVzoVKLoFYwhdS13H/rvTYeHpAKNhdHOttM//pyI8ryI3M
         SztG4TCyfQtWd6prkBkXOdn73RPqPxANv6WAtW1XOhXIi2JHmuUQhheeQbwFTkWA3VM8
         aim1Eb7fUxtah3tHRs3P92fBOiWtNJARXTxDXGdANEfB3X8SoB4E8qjcDrM6Vqvs2sJA
         /6h/EI2qsF/iX/sbhYgL6BZMykqGZivjwGsbi2m/nOu81VDmMBwLipPr5Qf2DJ7PCAgP
         l54w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hHJKoNgk;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O+8P3VuWtD5evril2Pi0y9pl20tN4rar65a8ahE7ogA=;
        b=n8wJD/F65PlmueLb7pEyS0BASrblLMJtai9jieyfVm/x5COfRrpN3hw6+hFt4Uf+i8
         Ghn7b4OURaDDLMqqucqdEP5mGdVP1y9BzEunOHpQ+CxzbJh8u8o9nYzML8S/SOfuxf/a
         D+g6INugdtnxO4GtcZkx5q7HghFzdmk1/oZohCKkD7BGPSmAM9IeJ+HsUu+cqYtpRwhW
         l4KdJpnbgxGJ7KkeJj06gvDLyaFyqKyhpFeUSoT+Z0DTsNeLViTVkSsseb0lcrvhMquc
         ya+2m36dGV6ZkqlkYjofPaAoENpFQwSPreJxqJiVc9sRn9hFYQ4bq5HduyVLH3QqcEe0
         qWqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O+8P3VuWtD5evril2Pi0y9pl20tN4rar65a8ahE7ogA=;
        b=cCTK6Mt5eDmjM8rWNWG04zquY/UlVLYAp/8Q7Ku9JJYfiobQXiFYgLquUrbFN85HT5
         EKEQOVe7p+b+F6v+jrwKakj+OT9Bhjf2aVzzgLnUWRUpvOLwNU+3g3Qun3L4IwgwBq3W
         dPSn1azuQnM0CKF8U2YKaUZtUhCK5dQx1nKMGvDCMTq5PZ2Nbr/KlayxowePgh3OTjP4
         fUmbQdNNLVJd53Rb4zX/GfZaWyP5cgZyDVEn+iTpsd9NKMREz6dCe9Jd0CNteolA1Jlo
         AhgJQcv69h/bDFgXeWhmT5JOZb4IQnbVkOkLkA22X6Xw9D1MvqiealtBiUuib6Y01RRo
         6DsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G7f1SMYOjHGGZ4fiYd3Y7mO50QOlGrDOkj21G3OHLHcY0+ThK
	iDajVeTPBrlotGkzWYBacig=
X-Google-Smtp-Source: ABdhPJx+DHQdC/QwwewPF9BwBfoPm3NYF1c2miBQN2eZ43uhd+K5REXWzb5GRz6j4FMS0NZhqQ4B5w==
X-Received: by 2002:aa7:8058:0:b029:332:9da3:102d with SMTP id y24-20020aa780580000b02903329da3102dmr2605522pfm.21.1631185244352;
        Thu, 09 Sep 2021 04:00:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:830f:: with SMTP id h15ls805282pfe.6.gmail; Thu, 09 Sep
 2021 04:00:43 -0700 (PDT)
X-Received: by 2002:a65:404d:: with SMTP id h13mr2159562pgp.130.1631185243691;
        Thu, 09 Sep 2021 04:00:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631185243; cv=none;
        d=google.com; s=arc-20160816;
        b=GAW3l7BFMbiwZZuSR5VGtUMImpLNXXhA0oHeWiaf3zuNRSqRhTddMrzbbTN/yZF1yR
         hULzpodeITvYuPUEQvIHd7U+nvC+PhA1jAwqkTf8gqrzptcAsphjEhcxZYBWXtBH1NDH
         rZ0VXM6djjvuUfAs8JTzUe044cX+UcIKkC8rwyGcn2hAoH9buEON/YjRyA7xbhsDekTP
         sVHVEbXr9Pk84zqN4T5SAcIrBCRKEl2cuwCYypm6IXmNDef63dv1lD/Zf36cFbDSDouD
         j6TWSmKGyFzCEFtfTYMYAMk/zI33QRQPBHNIChOckGGYbnoUqqs13kxJLqFcxZs0X9W/
         8k6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OUWNlhiomjRaxpm6dcsZUbGnapcx4zxDdMNWiMgFVoc=;
        b=MdgPnVzEDDw4VbSC9sRqyADtWMfILgIxLM1Hdl1kzSOdDguVtUSrRN6zlkptyOefl3
         DiF2AGuW1g8FYcgRWZfxwooFOiuSHxZzbi2TZXXe25onkqizltx1OxMZf06+WweSo5NP
         fdFjrmx5BiJc4c8g8S2tWqLuudPI3rmN3B6PkdM39XNZ8vBgs1+vjjWp2TUZ3SBPC2oM
         ALoWptFQ9hT0kKKvMq9W6MTuUgNxsgq2exNu6ye73gziWd7IypIl2egFj0HqVln1u4gy
         EY1al9L97ooxLSQpvQpqJBZvOBzxymQJ3gI5fX20H+jXStpae4nESZv0qcdXNUSDaV0A
         BUow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hHJKoNgk;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si115006pjv.1.2021.09.09.04.00.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 04:00:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 615DC61186
	for <kasan-dev@googlegroups.com>; Thu,  9 Sep 2021 11:00:43 +0000 (UTC)
Received: by mail-wm1-f41.google.com with SMTP id j17-20020a05600c1c1100b002e754875260so1059489wms.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 04:00:43 -0700 (PDT)
X-Received: by 2002:a1c:4c14:: with SMTP id z20mr2344349wmf.82.1631185241984;
 Thu, 09 Sep 2021 04:00:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org> <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com>
In-Reply-To: <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Thu, 9 Sep 2021 13:00:25 +0200
X-Gmail-Original-Message-ID: <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com>
Message-ID: <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@infradead.org>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv <linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx list <amd-gfx@lists.freedesktop.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hHJKoNgk;       spf=pass
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

On Thu, Sep 9, 2021 at 12:54 PM Marco Elver <elver@google.com> wrote:
> On Thu, 9 Sept 2021 at 07:59, Christoph Hellwig <hch@infradead.org> wrote:
> > On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
> > > It'd be good to avoid. It has helped uncover build issues with KASAN in
> > > the past. Or at least make it dependent on the problematic architecture.
> > > For example if arm is a problem, something like this:
> >
> > I'm also seeing quite a few stack size warnings with KASAN on x86_64
> > without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
> > few warnings without KASAN, but with KASAN there are a lot more.
> > I'll try to find some time to dig into them.
>
> Right, this reminded me that we actually at least double the real
> stack size for KASAN builds, because it inherently requires more stack
> space. I think we need Wframe-larger-than to match that, otherwise
> we'll just keep having this problem:
>
> https://lkml.kernel.org/r/20210909104925.809674-1-elver@google.com

The problem with this is that it completely defeats the point of the
stack size warnings in allmodconfig kernels when they have KASAN
enabled and end up missing obvious code bugs in drivers that put
large structures on the stack. Let's not go there.

        Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1W-13f-qCykaaAiXAr%2BP_F%2BVhjsU-9Uu%3DkTPUeB4b26Q%40mail.gmail.com.
