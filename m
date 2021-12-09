Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCOQZGGQMGQEZ3G2AGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AB0846F4FB
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 21:33:15 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id bm27-20020a0568081a9b00b002bd445624cdsf4592124oib.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 12:33:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639081993; cv=pass;
        d=google.com; s=arc-20160816;
        b=W3kQSpssrS4kX6GUjccIEiEVtKDK+GmyKe2niASkLNHjXnqlTDO2AKV92aGuqwivht
         f3D2RdUCBxSYcjJxdw0g5kCjIrAa3ceN+CmBKcG6rdlc4Z6sOZiMDkJjnEwSVZ5SILNt
         k56GMRM9MfITnW3TMN8MJa41tftmJ/od7JjVuxaBxx2UWyBMK1R4cNLFWJKmy0XefpYM
         Q1VqnhG37V8KMaV6CqCVpdNDO2jXD+B3nzim7jMRCEKe4c2pbOUkGvj6ggV8H1r4ERD7
         goiNCX+h4uBy9wPY17BiDlNZ71xRS0/+ny6XI/bKvCN4NiWwPfSLLmVvoj0pbTYLUF/h
         GZFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BnFbi+PZpbsH3YV+Ax7LpEysLLXMxPdw+AgzjTMcSkc=;
        b=qGK8QLOLUcgFaulwtvUUQEhWOzoCg0kA63gAvdEzhcVIQxLFjZgc+afWcTuDMGBuz9
         jY4gdDCbbHpbTkBK+bFplbJLqFrwEYY0GjDCZoGyWJaC6cGJENknMzgScF0CBlyCOMsD
         Os73t3AzIip4LF87D6xt5LZ3gQ0I3gCQuO1rDq9JIGNYwDDSUhpsL9o1TotKFu1sjIFt
         UfQsFXRTMueDioBwq4cC5yeAZdaijvr/wOpiZQT4w64LQx/2+6L0KnP1TCFQDkseONd3
         GL1PRjmGT1fV05Ox458AwpTOzj0V1xin1to/ieDPS/N0EFTMLnDy6zcDQnr/L0+6qVSB
         +R0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GvTTIDuo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BnFbi+PZpbsH3YV+Ax7LpEysLLXMxPdw+AgzjTMcSkc=;
        b=VlDWG7tTTQArtUwNssECeWsplt3mGAUQ4fP+VI34KqYzDBJUxzHdFd6FUPZxuIaaWA
         H2NB6wqhtOnWSrbDxh+W7ukD6TZJe8vTrU/8ZZ1/3r0kF4apBopRs4N4YtdBvsvMbli8
         7Tx2A4WxWf86ZjTr3jQo6SnMtRPrZlc6AJSU1uu9ilfKx8wL//Wgi65SLU/45B3QPRKP
         3L7ZGoB6I1dbzBzj39MFHOzgJjg97sWmKV4c2IZA7XWPDaCdmxtMJhH5SyPzCKyy7/kB
         VL+Eppx966Vxv/qI/R/372E9oixYCePPH2Rj350g9oFW/ZwKhLPyrimp1JS2ocT/Mvt3
         h9YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BnFbi+PZpbsH3YV+Ax7LpEysLLXMxPdw+AgzjTMcSkc=;
        b=AgGQDWiBUVEOfBo/yzX3zKdsjwf7s+bbKpJwRsaZ/JYk0TIAuZUH9RTbYQtxNeDNFf
         nQeFYOXQ1qbPohyJX2w0+UIiyjVWKIQtPLHewnkAhUJ/cr+NOG6c4NENg3gDzHU3iSgl
         Ql3eqGaVqI2mLbcV02C9liaJddCweA2mEGOKw9w9+W03g2XohAJTXdEKNKB//fakssBo
         cAcxoNDxbXMaIuTKPUSM2hE5LZTk4sfUeaRdjuY3Kr7JchVdnhX8wZlUAo8hpftqKsLF
         yWmDD2ISQ+RhGvELD84Zhjws3YjQodqAj9QnozyC/zFrD+p1qz6mQ3+G1Jqh/qHDZuGS
         +ipQ==
X-Gm-Message-State: AOAM533bDwerd5AzWsYT56Pbqn19wswfWDyYPIKA/eE1n0hkIx/eHS0E
	8sZAdjzWlx7Gej/DwimeDVo=
X-Google-Smtp-Source: ABdhPJzAboTAWyUnJ1g3MU6R8NrF5R/orNOl09ZvOXIPJK2Q+JRJWCIlo+0050fZKA8tmixPV2BSvA==
X-Received: by 2002:a9d:824:: with SMTP id 33mr7374970oty.124.1639081993665;
        Thu, 09 Dec 2021 12:33:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:41d5:: with SMTP id o204ls2020782oia.9.gmail; Thu, 09
 Dec 2021 12:33:13 -0800 (PST)
X-Received: by 2002:a05:6808:114:: with SMTP id b20mr7793262oie.95.1639081993257;
        Thu, 09 Dec 2021 12:33:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639081993; cv=none;
        d=google.com; s=arc-20160816;
        b=OTqDCPz0ZEYVDCYuVN2/XbDVc2F+XHVHfNn+zwzkeaMEPuUzPcLMkh9kvHWP95hOHF
         d50NWq8X65S0TJ6WnLB5rxFeu1GOOTv2HmEaOpRoxQC7F8Vr16bATanMxzptCOMvEVRd
         GssIO4SibcRP8spkfvP/6G0AA3Sz73OQAmnl00wFFPazvXale+jN68A1MWolP01x3K+k
         3UqG3knhxpkAgumJcrcd/0XK4xUvGS8SnwRZq+UZswqri8fNwurAnSVPE/OprMystx1b
         hLk0WBxylYmvkAnB4E8Vpagvr3R5EJRGqp6+GRqbsWiUtiQ7/+Y5Ha5AuNkgGD3yB2+M
         JPNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kkfMK5PB8QI1XOoT83uXuffhKjgO17IGbJlqxB7Wwjw=;
        b=TStdNSsqimu8KW3taXWm4QSriNRngvylu/pHC+FQRAyxel79pUqJfH4fPVXYi+rBGG
         mPZT1cmwrc2mE2LvMnVouVv9gv2b/6Tt3X19mwVNy9XIgRwQsGiKPAhWZqaO4qOkpVAj
         76c7qEusFEgPZqwKut3ZMeZV/Ys44+aODrSma2LPirI9IFtWmEkHIMFypK3n+INORp/X
         t9OIX/480GRKPBPtjyQBwX4H6dEoNr8PLtabQjSYuMR6TrS+TWQQGrkpfLmfNLiQbiaX
         Y6xUh+ROmp7M7abzzZ9JQZ7b6qQ9xBaFxM+kTXbk8Zvt0+VDf0Rfg/fFtg8x3983wVvi
         SQ7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GvTTIDuo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id be25si91337oib.3.2021.12.09.12.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 12:33:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id m6so10379203oim.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 12:33:13 -0800 (PST)
X-Received: by 2002:a05:6808:1903:: with SMTP id bf3mr8384470oib.7.1639081992787;
 Thu, 09 Dec 2021 12:33:12 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <20211209201616.GU614@gate.crashing.org>
In-Reply-To: <20211209201616.GU614@gate.crashing.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 21:33:01 +0100
Message-ID: <CANpmjNN4OAA_DM_KNLGJah3fk-PaZktGjziiu8ztf6fevZy5ug@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Alexander Potapenko <glider@google.com>, Jann Horn <jannh@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GvTTIDuo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Thu, 9 Dec 2021 at 21:19, Segher Boessenkool
<segher@kernel.crashing.org> wrote:
>
> On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> > Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> > default since dcb7c0b9461c2, which is why this came on my radar. And
> > Clang also performs auto-init of allocas when auto-init is on
> > (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> > aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> > allocas.
>
> The space allocated by alloca is not an automatic variable, so of course
> it is not affected by this compiler flag.  And it should not, this flag
> is explicitly for *small fixed-size* stack variables (initialising
> others can be much too expensive).
>
> >       C. Introduce a new __builtin_alloca_uninitialized().
>
> That is completely backwards.  That is the normal behaviour of alloca
> already.  Also you can get __builtin_alloca inserted by the compiler
> (for a variable length array for example), and you typically do not want
> those initialised either, for the same reasons.

You're right, if we're strict about it, initializing allocas is
technically out-of-scope of that feature.

So, option D: Add a param to control this, and probably it shouldn't
do it by default. Let's see how far that gets then.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4OAA_DM_KNLGJah3fk-PaZktGjziiu8ztf6fevZy5ug%40mail.gmail.com.
