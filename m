Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MD7L2QKGQEXBB7VAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id BD7E41D4D07
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 13:50:22 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id bk13sf1552998pjb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 04:50:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589543421; cv=pass;
        d=google.com; s=arc-20160816;
        b=FhR9Scl2/uYwNgm528JhY3wihzDBCcJh53HFNz7zTb61Y5s5BhI/5CrpYsUxEy/zUH
         eKkh8EyIlmQt8NRnMrL4bci1y2AJhbgWXb2w7mKd8JpqUyumEaYrIb0x7o5rAb/ftIzc
         BaRDtlPQ1E7rnOmHySJ8zV5QZrd8Pcqb1a832D+mS11+RnR1/5uZe5OXF2hGiAwgmtSX
         pwIcrNIrvo1U5dQL0MC0BG9PL/EQOduxcMnRcxe6hfdWHT/MBV00QkQyJoGrpKWYx9Q/
         3Kraj4YabO7/FkgpYErV3C4d62cHwAQVP+AGrbl1tr29WZqv61i1cv0P/c0RlYNJltvU
         VLpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i/+Lz66yORrz1QAldZjXCCTHaj58W83GDPDYLqCuFu8=;
        b=Ydkx8o7qPa1WZAM965aKOWt1ourfQYg/4ubRzqsmEHNf30emZ//FNSX9fLg1nN9FW/
         nl/JS3Gmhf8I1Zaxtclf0n91A5wqjB+AuDTZ3AKAQoB+oK8meQqF7Rn3iYf07QBaYfjD
         Q7fwp77KVfDnUTn3RtDzaZofsK+PYeL402+uGI+OKmGHQkgANY6Ljrq+p4wX2qXWRefO
         nQeU8i/qPQJIOi0ijviQgHTIA6SL2cYeLSy+bHBh31zS/bYSZxkO1yp1opaOwXvH5iIU
         SCm9PQ3+zw2L6hKvCpk3euGKX8CDsQGDfWIPDpX1tVut/YNvUOo8fASfwlkA1t0OU1Td
         GuKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pnq85h+m;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i/+Lz66yORrz1QAldZjXCCTHaj58W83GDPDYLqCuFu8=;
        b=pfw+2wtIrWmWnpclRroXrrPKXdMUEJJcPWjgxeXexmO67RXVgM9NaF0m84dGtO7h71
         rZNIJ2Fi0axpfsjgA9BZMyA1YVR5AzTOwF9/FiGMhraKDBLQJlcHvd7bP7/qeeneaIMq
         PU70cQ32qqAd+53gFqkZ6YJZ8+J83+t4+6j9dfvVsPePvpP96/xdkUd0e+sbPOOYv0Io
         zfIe/+YzH1wsxtWuI75iZORQfMV9yIZh9x8V3wtTfp3Sk1FsWoQjH6ocHcvliiRgy0PO
         VB45E6zdWw+mo0MAvKLYyR8sJ0s/Him60D2Qbt9NER5IutALyC8RCZvcVtiMye9Ifoc4
         X+Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i/+Lz66yORrz1QAldZjXCCTHaj58W83GDPDYLqCuFu8=;
        b=nvIRmKW2zjh6GsFOHjHtFiP63z2ohbU/w4g+f3rOW8FfRPUs49auQTJvtM0ca8YV5n
         lHTl5umM8xubU5YMXowCFK4Q9n+7DctQm4HRZET3Svy0sqH+s4DAZ8mgSr+40i5gIEC0
         GX1V6cX387tHZvXGHBAwiZZXz2KcmM/gkNTNfamsJCm5ugOoGdXb761N9+IU50Q/IREu
         HwALjn2wjnNYqhO3I2nz9RyzLCkEEuI68WielhZFR7W3SBVtctmPrI1fPKB9WDUZuq7q
         zi+SQ7J9ueM4CCbeDvustv4DVusbzrTvoJ8yU2qERxpodQeRNE3oX6/wQyX50JcGyqAp
         FZDQ==
X-Gm-Message-State: AOAM533hILBRyp98qlVfcVWKWO+6GWRpH6BJ3WIbQ/B0xaQ2ZtyOU4zW
	3owFhIV0VcLwkSFX5T+s5VY=
X-Google-Smtp-Source: ABdhPJyd01L+tSc3KUb2pJjx3O7dI54BN+6VjE/9npJO/d88qO5LnxsvF0Jt3ec5SI4tRDxWdohuUg==
X-Received: by 2002:a17:902:d913:: with SMTP id c19mr3115169plz.229.1589543421330;
        Fri, 15 May 2020 04:50:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d049:: with SMTP id s9ls700173pgi.5.gmail; Fri, 15 May
 2020 04:50:20 -0700 (PDT)
X-Received: by 2002:a62:7cd1:: with SMTP id x200mr3601328pfc.232.1589543420317;
        Fri, 15 May 2020 04:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589543420; cv=none;
        d=google.com; s=arc-20160816;
        b=sujGx/bTlAZDTEnQGYeNoPYwnM2ZoOuGKM9jcSnMqJPsDoLrdSLwqRPwke0YYXkz60
         +7rG9vgqw4zfjk+SZJTye0+DyWw2DFGDnx+5z6vu4UcJwZo5HlCFVfHoTI2gJhuwy2Ou
         LqGqDUvWVVJmTqi0tsmG2EgNsetv64RTcgGM41Vo9XmyqoTWBle4sx2XY04be+buvHEc
         kXWvSeTN6YasmwmiEiKGT3uGsJDzlf3yoNggLIkQarjRolvx1lBach/vBeidzQDbeILN
         Z45wMvEZSmGooiRYAhzTr3SrfltiNYUqbaMnJmAzvhZzVwet2p2YitDJDk+CxrLBD4W2
         bYfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZQ13A2cpcZsdZ6QsKqoq0bker+5ijocxW+VIm/CpPP4=;
        b=Wt7QZM54RabXRurwZXxHTnglgxojcRSD5svbosWiHot/7Tvlqx2Lxv7AlMWzrk6QGW
         1M/PsBD26gm0fu3Pv0W2KlqIzScS8IVLjWtI0bzjBazbW0+s7gdy6ANYp5K0rr/1iLob
         7r6I5mxdJ2IoyO3XdQSUdhkhY9zcUq1+O131lrWyN1cLHH4GKL1y0RtH13PQ+B4N0WXS
         iiQ3JaLRGHdzGIWxsQH88juqtmFSHos3G+xNskCvHmRfWz4/1MRiNxTDuIiZSXyeP20K
         dK7sY7x87jCtBkWJfR4/d8efITb+ZWpr1eqpgbqSKoiMB99vm5ixp5d3SMtrbnx5LWVA
         Pl/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pnq85h+m;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id l191si111117pfd.4.2020.05.15.04.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 04:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id i13so1928397oie.9
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 04:50:20 -0700 (PDT)
X-Received: by 2002:aca:3254:: with SMTP id y81mr1802505oiy.172.1589543419310;
 Fri, 15 May 2020 04:50:19 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
 <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
 <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com> <20200514191754.dawwxxiv4cqytn2u@treble>
In-Reply-To: <20200514191754.dawwxxiv4cqytn2u@treble>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 May 2020 13:50:07 +0200
Message-ID: <CANpmjNOoB36xu4iBwcOZ=RpjWEMwmqOX1tYU8+m285xXJDHRGg@mail.gmail.com>
Subject: Re: ORC unwinder with Clang
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pnq85h+m;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Thu, 14 May 2020 at 21:18, Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Thu, May 14, 2020 at 11:34:52AM -0700, Nick Desaulniers wrote:
> > > The stack traces of the races shown should all start with a
> > > "test_kernel_*" function, but do not. Then:
> > >
> > >   sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
> > > kernel/kcsan/kcsan-test.c
> > >
> > > which adds the disable_tail_calls attribute to all "test_kernel_*"
> > > functions, and the tests pass.
> >
> > That's a good lead to start with.  Do the tests pass with
> > UNWINDER_FRAME_POINTER rather than UNWINDER_ORC?  Rather than
> > blanketing the kernel with disable_tail_calls, the next steps I
> > recommend is to narrow down which function caller and callee
> > specifically trip up this test.  Maybe from there, we can take a look
> > at the unwind info from objtool that ORC consumes?
>
> After a function does a tail call, it's no longer on the stack, so
> there's no way for an unwinder to find it.

Right, if this is a general limitation of the unwinder, that's fair
enough. However, if we build a kernel where we want to have the full
stack-trace always available, would it be reasonable to assume we need
to build with -fno-optimize-sibling-calls? I can imagine that we'll
need this for the sanitizer builds, for compilation units that want to
be sanitized normally.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOoB36xu4iBwcOZ%3DRpjWEMwmqOX1tYU8%2Bm285xXJDHRGg%40mail.gmail.com.
