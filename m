Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAMW4TZAKGQEFSYJOTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E5E3B173764
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 13:43:46 +0100 (CET)
Received: by mail-yw1-xc40.google.com with SMTP id v190sf4560357ywc.9
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 04:43:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582893826; cv=pass;
        d=google.com; s=arc-20160816;
        b=fF+GFwCdyUl+lCqkMc7puwrKCQ6lZXbUErmhV0Y8422kuL4qzdWj3yWTZRAt9qfpV4
         ohgCVWNxMCqNCMN+KWIkP28P9EikUPnCGf2Fs647U73yYrsw42iAeu8Fxvf8SFhgOqyo
         GRgkRoTi3gnL8YriMEHsBwFzrs2mUDnONgqVxvZgrugJOaXuWE91Rh0YdHCJoB+GFvCn
         SbEHmJXC4qtsf2Z+FdLH9XnzZugTXSDAOiaWnAeaVkPZPbzGwlmd0tHPeYwqLwmhTv5d
         E2ADTg9nYgbkrQcttcQ/U4U+l8XkTeZukOeKSgOaJKlVH0a5rGOX6DAexaCfibPzjXTH
         EVag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hP+V/a+z59lv6HVf08g55qZ8/CdrSTH4dKfCbdLHpz0=;
        b=R++CWyyimZfB4wsnuJTEpeJFr+CojlyxsRitBMGcmHEETG5ZMeIdiH2kFUpb9Wup0i
         C444gj03wJ7uKAZZeYh5E71U575W03tbyapNVjZGOBvCcyVThoJc7Gt36YHYw3l0N2BL
         vV3LyXI8mf/KZac1wfCTB8HcsXVO9+4nJEru9td8651HU9BJO9R/bE4wwDmQekeC5e61
         eo0o1xqL5HOfNODuzQ3VdipM67Dfs/msSCeHzCnqdYmjfppQIaDcnxy10cldo+h0NrMN
         jTOJGstwVme9qYFPUAxFRx9qTR3BR+P96ho+X2dj8a8pg2nmEXeOWRvlBmMt8YZMjJ93
         nVWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qsOTrP3s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hP+V/a+z59lv6HVf08g55qZ8/CdrSTH4dKfCbdLHpz0=;
        b=FVf5NPQFWF3hsh0cJJ0JMECU/+UOOinlpYrY0w7SVNrrfjg16eHjqBY4YOpbD4kw1f
         N/v8IUq/dPEwc3kYEjwvNHpclLYMPBOS0cAB1HuIQ8VhAtYy8BTpnAV6g3dBGPJndwEd
         phWL8567MTVkypDU5l84g0E4eqdp7yhgSxpqt3QCk9KhyN44OHPs9iPDphBVjp/dOQjr
         GgAQViDPVjx/xb3NmRAOWNLayoMql3b1r/1sSf/BjhfExJf/RZwNGlRnYTSuyaXsduex
         /pvm23KhxGDRbNe46qFR8aDV0RtJJk/SM6GtoqUPBYtEZVyf01HAhPKlkPzyjgQh6s/3
         Xc4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hP+V/a+z59lv6HVf08g55qZ8/CdrSTH4dKfCbdLHpz0=;
        b=tNtaMll0mzYphVZy/DzKOUcry9xmGlWoNx7hbKx2vviN81HNJVBUDaryNYyUBnWg1l
         ic1jFkn4ALE6tJ28IqpaxAAVfe4j73NCi1nR+ki0sSOtikmh9/RtTS0LfCUNtAip9Frr
         ZAtY+nsiJqBNES145/7U2mpq5ErYKIHJzAW0THHTmB0NkFJvBWPQRzaZEDCr/R/uz9fi
         8eN1NSUzM00kEtxWcamUP8jMa1TIm1NEvochv5Pt/rr3ms0YaVu16nmXmrk7vs5x+R21
         8hKgpr2+h2k3og4/e2QffTI8OO1oeQmcQ+sXSc285z85a7kGMqBKSmVwUE6TBCYVYsIp
         f3Hg==
X-Gm-Message-State: APjAAAUaM2FqdvT2bg86wVQtvNH90GfTCuEU9fQbc7TTVM7sSk4rdjFa
	milM8lYoBViNPtaDvx6UXlk=
X-Google-Smtp-Source: APXvYqwAUW207UEGfENyUNTHd2UJYUGfMjxUQnJL5A0gHImAexn06ATnWOdzHWZ+f7AWqdtpf0PW3w==
X-Received: by 2002:a25:d145:: with SMTP id i66mr3513851ybg.248.1582893825875;
        Fri, 28 Feb 2020 04:43:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca87:: with SMTP id a129ls180224ybg.6.gmail; Fri, 28 Feb
 2020 04:43:45 -0800 (PST)
X-Received: by 2002:a25:ca86:: with SMTP id a128mr3383401ybg.164.1582893825512;
        Fri, 28 Feb 2020 04:43:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582893825; cv=none;
        d=google.com; s=arc-20160816;
        b=Yecu8NQ510mU1SK31TaIa9gQH3vX9BXRN63F3TBFX2K7TwfGmH4ZV85TGHYb4uMDKU
         4gMhJcqzIAl4/pnCW1YfgINnIBny34rfPRDlF7bixsLDhcAp7Ry41pSQs268rOdo2Bu0
         gwsKdfqUZ55DxQKgv6NMHlXHZgu2nS4p0AseotX+DSJoaW6ewHF/ioOBsD6dXkF5GSLb
         s8q3Qk98bzCCq+5hXS+pr1xSnL8bjtdarsTLGhtkJ+1igNylPBhgPsu2TbP8VqfE1uMw
         yz3+mmLu9fCCy7GFwJ3V5m9K7c/DI1zn03z3i8afqBxEIP5Fv/EacFg5M8Oe8AxMjdfl
         MAjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zfQoq+1M8fvl87X+Ubkvp6zzrnswmjJsf0b9A+26ex8=;
        b=zRsljbllmgprf6KLHlV1OaK9rtOC+rIFxpX0nBLZGyMxYt9lONaAW3nFHm5/iJ1yPh
         0fuxn3tcaT9wLaqjoqkHVTYoD3UA+FrHWoIR2p9bvXceXUhO18x/5to5yKi7ZibqMNPg
         TeMAJvSrhqnja2CY4gQEe+3ka6TL4IxwFLPCOGyEctTpjzFVjUTcurLqGlLcxNIpyeaI
         eiZn/KYcmc/PA84hnjz/lzEZeldjQL72Z7czZR2EdnOBCechqpb2ltZDcsuWXOaH+3Zg
         DwWxdCvu3cJpwfqQifgSwpgeGYO3AtRvM2QKxy1eOg/VLE0IQ/CTQaiDOqLWz2eEVQl5
         YThw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qsOTrP3s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id u71si267324ywe.1.2020.02.28.04.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 04:43:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id w6so2448184otk.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 04:43:45 -0800 (PST)
X-Received: by 2002:a9d:4e8a:: with SMTP id v10mr3370715otk.17.1582893823992;
 Fri, 28 Feb 2020 04:43:43 -0800 (PST)
MIME-Version: 1.0
References: <463BBB2A-8F9A-4CF1-80AE-677ACD21A3C6@lca.pw>
In-Reply-To: <463BBB2A-8F9A-4CF1-80AE-677ACD21A3C6@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 13:43:32 +0100
Message-ID: <CANpmjNNyQ0vGAsSXCLkLtjvEVbq3T5kNnsg+T3XV-qBPCZ8FHw@mail.gmail.com>
Subject: Re: [PATCH] mm/swap: annotate data races for lru_rotate_pvecs
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qsOTrP3s;       spf=pass
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

On Fri, 28 Feb 2020 at 12:30, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Feb 28, 2020, at 5:49 AM, Marco Elver <elver@google.com> wrote:
> >
> > Note that, the fact that the writer has local interrupts disabled for
> > the write is irrelevant because it's the interrupt that triggered
> > while the read was happening that led to the concurrent write.
>
> I was just to explain that concurrent writers are rather unlikely as people may ask.
>
> >
> > I assume you ran this with CONFIG_KCSAN_INTERRUPT_WATCHER=y?  The
> > option is disabled by default (see its help-text). I don't know if we
> > want to deal with data races due to interrupts right now, especially
> > those that just result in 'data_race' annotations. Thoughts?
>
> Yes, I somehow got quite a bit clean runs lately thanks to the fix/annotations efforts for the last a few weeks (still struggling with the flags things a bit), so I am naturally expanding the testing coverage here.
>
> Right now the bottleneck is rather some subsystem maintainers are not so keen to deal with data races (looking forward to seeing more education opportunities for all), but the MM subsystem is not one of them.

Sounds reasonable.  FWIW

Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyQ0vGAsSXCLkLtjvEVbq3T5kNnsg%2BT3XV-qBPCZ8FHw%40mail.gmail.com.
