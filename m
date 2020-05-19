Return-Path: <kasan-dev+bncBC7OBJGL2MHBB245SH3AKGQEK3SGRJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 822E31DA374
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 23:26:04 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id s11sf346598uap.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 14:26:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589923563; cv=pass;
        d=google.com; s=arc-20160816;
        b=DtecxbMCLEdM7ZlTWEMmG4m4X8NUhx1W4MVGr128mREyy+qw8O1li8basZp+oDePuE
         XVXOwcgN6BP95TJOY4tpojtReToemQhdKP3a1ZS08VYQ3BPHc07cD1a5tObE4Bfn1IJp
         WKENsS5PVxjO8ErnWt8AG9rw+o6DwO33LnQb5g6pIt+0dkZnwtUdEER+DjKIWQHiYxej
         6EOyRgX1QpxZd52Ws5MsMIcojETp4kCospYJkubCHlgMAMwStJjWljjSO5Efpcm1BoKf
         KlSamHa+nt1UNGFM8/nL0XAB3QS7VLIv6Vo3kurFfWUVaxJEAiZU5EN3e1o7BYA0VgYF
         3OTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SbnvaaooGjcM/eGeTON2x7IPhGRjTnMZgTjBhZ5LhHc=;
        b=emtzVH+aZRUbddpovjpX12uJv5jpfYiTylWKg4Fot7PyKSKOQOdc0u12QOQZiNFlEM
         KBt4LOduUAOf7xpyQPqf8Nl1VbF5jld/j//uiH8VX07Slerl2m/TXeBxyK8EKwvmDuZh
         oqhX6sOp7PQAw8QcvYNwGJmgv0FVBLlYFBam/7XE9OwpIcYXhTQyA7HHeddL81f9vych
         rYTdGnpvpUVBUoHynMbD0fFFC0n9GL/8iMFSepPAkwcUXuWdr2i2DihQACFzJe9v8ROX
         BkvcgDLqBSsmsitWFNl33rjJSL5HjUhfiR9Kgeq4rfCR8qXop6YSneRUk8LejgYvfBY7
         +V9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOxhHUdF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbnvaaooGjcM/eGeTON2x7IPhGRjTnMZgTjBhZ5LhHc=;
        b=jHxEQiwUYO6f7vsS7Su7cLTvAX6Ll8VOruXkHVj+Rsijx+X58pdi/u/ASCSM+8MZyv
         HxtwzL9UOi0ovjb4leXzyhzTsj8QjTKSZZNLm+t/QeIPGKSEz8X9uOmPe7C98R1L30sf
         kpWFJWMEo9RPgu3DcgbB3qxOwEyL52zc9RX3GihH4EF1m6AGTZPReIQOuPwkMJ+Qxkht
         M7WAFNLFefdX2CIFLdrmrTKcETLvsPR+K93hnZXiAxCZ+RyC9+tIlP3lGwCoMzyX6bPZ
         s3X6bxitaAj4vZt1bi+UH/UZDqYfhY4+lxxYThOCiGQimoX4iADRVIjc48c6VbYmhId9
         ID0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbnvaaooGjcM/eGeTON2x7IPhGRjTnMZgTjBhZ5LhHc=;
        b=Dpm7xKcC7nrhMw4hQbJ1SLWjIUfA6bUbaZyIeInd4RfJVj4frNOWRativ24eIU9t5w
         sut54Kls7WKwyCIV9IriaAtuYP8NJ6q++gNWqidzVbB1OZJ0FPAkgf9wnTnNsdY5fq8D
         NFGG2SjIe6wBm+d6OnERv3ggvxnF8v3dj7s3DAnvFruuaJqEtR3oxNqdt1HN4H/NeuRo
         ZAHWjcmhUKTbdMzAgPufly5qjbPNTKVLWYyySH5C5wyXcRhRq9OTuefXNXZxZA2kU4X7
         /m5rTqzoDNJRgDJpx8GVPu35kiV5OExVZa5ux/mnYLVGRvvlRLqC0hYm4qsd7ZSB2V4m
         AeeQ==
X-Gm-Message-State: AOAM532bpS8sj5pQRO2l8g5Zm8gZ23sw6EudssLIIok4L9y/ZuumTvQn
	+wLFa6Ge14MB8Y5Z3liulLo=
X-Google-Smtp-Source: ABdhPJzqemvGbZS9FbpgARMQiGACC82J132rLfuDtLZr9gGUmESxire0Tw8oHs9QeIYBhYCkGFBjRw==
X-Received: by 2002:a67:edce:: with SMTP id e14mr1004567vsp.235.1589923563519;
        Tue, 19 May 2020 14:26:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:80cf:: with SMTP id b198ls77537vsd.3.gmail; Tue, 19 May
 2020 14:26:03 -0700 (PDT)
X-Received: by 2002:a67:6285:: with SMTP id w127mr1036102vsb.139.1589923563157;
        Tue, 19 May 2020 14:26:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589923563; cv=none;
        d=google.com; s=arc-20160816;
        b=W+uvTGV19z9j0ev8wpV3XeTfpQ7d0EWXqu5SE7JNLzyVwykE2G9xDXpNaynEiu+yrn
         ORdoiGVvk/l1h7Mw0AMh0hNVp+IgCfzf+I67u5/+txIeAKyqDtRkivvWHRT+j1sL0MUZ
         mlBoTyJnnTEucQE+u0+EkeRu6bXW+0u3BxY6CYXoEWLThbSIKlBrsaWnotikgmuYSjQw
         R/+nUtAo9XqH9JtOw8rGNu8cMpg3Xg2bYCxFpnhwJZPy6eOMaaNvVFOLTcAdkPEFb8mG
         VUfAK/WJ6U/gRegLD+IbFAJ2EWfnKkKVpd3NS56wUhxoGHy0f0/MDmJarQ1auobittsx
         nKEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8/DW1pZj1YNbWgzrr4MlM3GiIz1LA4FZ7zkZDxQ3+/E=;
        b=v2gJ6XiSiuHT9AgIGMf7OTPj5VM4H4qEb0ri2K4qtwC75jQqeTlXcbW0plgX5QMvsM
         yK8krRoA9mmLkmxB5vv2JQBWtpMgfoq/LUk1ra+aF3O8oBKQFtKsDRlOagQJx6B7JIYK
         +rAXuJIT8Y3XICFjH3Y1eqWkllJjE9LmQdNzE4uTJFFvZQNgicuobI4UGk1OHTw4JbbJ
         mfEMHusCl2XjrRu9bFiu6zmdoXJ4LWHrHf/hbS1+yO4U4IYi8/8XwGhhg3dS9UZULr17
         XqnQU6G0dYFUnDlpwjPI3JW3bWDu4xkVghcWqxL3chv/WCHQKRol/mF8FIsZ9fFeNClV
         lO4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOxhHUdF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id d24si95579vsk.2.2020.05.19.14.26.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 14:26:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id s198so1092892oie.6
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 14:26:03 -0700 (PDT)
X-Received: by 2002:aca:6747:: with SMTP id b7mr771179oiy.121.1589923561779;
 Tue, 19 May 2020 14:26:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200512183839.2373-1-elver@google.com> <20200512190910.GM2957@hirez.programming.kicks-ass.net>
 <CAG=TAF5S+n_W4KM9F8QuCisyV+s6_QA_gO70y6ckt=V7SS2BXw@mail.gmail.com>
In-Reply-To: <CAG=TAF5S+n_W4KM9F8QuCisyV+s6_QA_gO70y6ckt=V7SS2BXw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 23:25:50 +0200
Message-ID: <CANpmjNMxvMpr=KaJEoEeRMuS3PGZEyi-VkeSmNywpQTAzFMSVA@mail.gmail.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
To: Qian Cai <cai@lca.pw>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SOxhHUdF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Tue, 19 May 2020 at 23:10, Qian Cai <cai@lca.pw> wrote:
>
> On Tue, May 12, 2020 at 3:09 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Tue, May 12, 2020 at 08:38:39PM +0200, Marco Elver wrote:
> > > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > > index 741c93c62ecf..e902ca5de811 100644
> > > --- a/include/linux/compiler.h
> > > +++ b/include/linux/compiler.h
> > > @@ -224,13 +224,16 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> > >   * atomicity or dependency ordering guarantees. Note that this may result
> > >   * in tears!
> > >   */
> > > -#define __READ_ONCE(x)       (*(const volatile __unqual_scalar_typeof(x) *)&(x))
> > > +#define __READ_ONCE(x)                                                       \
> > > +({                                                                   \
> > > +     kcsan_check_atomic_read(&(x), sizeof(x));                       \
> > > +     data_race((*(const volatile __unqual_scalar_typeof(x) *)&(x))); \
> > > +})
> >
> > NAK
> >
> > This will actively insert instrumentation into __READ_ONCE() and I need
> > it to not have any.
>
> Any way to move this forward? Due to linux-next commit 6bcc8f459fe7
> (locking/atomics: Flip fallbacks and instrumentation), it triggers a
> lots of KCSAN warnings due to atomic ops are no longer marked.

This is no longer the right solution we believe due to the various
requirements that Peter also mentioned. See the discussion here:
    https://lkml.kernel.org/r/CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com

The new solution is here:
    https://lkml.kernel.org/r/20200515150338.190344-1-elver@google.com
While it's a little inconvenient that we'll require Clang 11
(currently available by building yourself from LLVM repo), but until
we get GCC fixed (my patch there still pending :-/), this is probably
the right solution going forward.   If possible, please do test!

Thanks,
-- Marco

> For
> example,
> [  197.318288][ T1041] write to 0xffff9302764ccc78 of 8 bytes by task
> 1048 on cpu 47:
> [  197.353119][ T1041]  down_read_trylock+0x9e/0x1e0
> atomic_long_set(&sem->owner, val);
> __rwsem_set_reader_owned at kernel/locking/rwsem.c:205
> (inlined by) rwsem_set_reader_owned at kernel/locking/rwsem.c:213
> (inlined by) __down_read_trylock at kernel/locking/rwsem.c:1373
> (inlined by) down_read_trylock at kernel/locking/rwsem.c:1517
> [  197.374641][ T1041]  page_lock_anon_vma_read+0x19d/0x3c0
> [  197.398894][ T1041]  rmap_walk_anon+0x30e/0x620
>
> [  197.924695][ T1041] read to 0xffff9302764ccc78 of 8 bytes by task
> 1041 on cpu 43:
> [  197.959501][ T1041]  up_read+0xb8/0x41a
> arch_atomic64_read at arch/x86/include/asm/atomic64_64.h:22
> (inlined by) atomic64_read at include/asm-generic/atomic-instrumented.h:838
> (inlined by) atomic_long_read at include/asm-generic/atomic-long.h:29
> (inlined by) rwsem_clear_reader_owned at kernel/locking/rwsem.c:242
> (inlined by) __up_read at kernel/locking/rwsem.c:1433
> (inlined by) up_read at kernel/locking/rwsem.c:1574
> [  197.977728][ T1041]  rmap_walk_anon+0x2f2/0x620
> [  197.999055][ T1041]  rmap_walk+0xb5/0xe0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMxvMpr%3DKaJEoEeRMuS3PGZEyi-VkeSmNywpQTAzFMSVA%40mail.gmail.com.
