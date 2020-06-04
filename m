Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYMI4P3AKGQEOCUSDPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DFB301EE1D8
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 11:52:34 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id x29sf267437ooc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 02:52:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591264353; cv=pass;
        d=google.com; s=arc-20160816;
        b=P/ga+D8RgcOfxKyxdeZ7HW+m4iTW1s84R8YR7Z32L43ybrQv2j6ZDK3ZcEG7VRkghz
         rnnZv6qYNW56gDXB7jQyWysj9dZDacWq4ZZU1rLG6UtuY08qexLSBUfPxwnHeH3/n+X0
         CznyZHbdeWNJobxbwrZnpkQM5MQWv5ZdmKIGhBXVHsW3WyhGKFnBpo3EjkpWgbS/zcVW
         ae4uGY5fvR638ig46X0HIsPtYYGVFQcqgygsq01c2SEwV79CwtE38KG36NattcaFxE6B
         3Ks+nGYJ6IXbZ8qnojKe8oxxgHyGG9mQxSnlufwhVWrxFUq7wHN8vX4FtEUt6xyR0ES/
         Chpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LnoQY+AEtxr5sue/fgKied9foIBK52jvaCdGL71pPwY=;
        b=hrm5fNuJIuG1NdB44fHC5J5cKIUy4GJ6os4fPQEJRF8PdYkgIG9SGqwQ9T9lgEa/bE
         V/jQugqKx/i3mVHqOFXzlL7YqzjBQWO6uC9dNaZBQM6c13jMC5B4ZLWmL8NQ3AZjzZTy
         ZDrYqRGt8Cxv30cRxj6hGQZgFOB4avkPkJMbNzdsgfs1plj6NmWzxjri1OFGXTPPD4Be
         SA5+ZdKiBAm348SalmSfPxt1Aw0g4/+Hu/MLtOQnQICbkeOdUZLT1bD/Evi0bwkOpPvp
         yXVUAFVqVQY1D+3JO8JpQrwufXmlHn4qyNnTsCRdupPjUIwnbj7LtCyYMHMSWHevUQSV
         4J6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E03wrYq2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnoQY+AEtxr5sue/fgKied9foIBK52jvaCdGL71pPwY=;
        b=A+qmRJVdiRQ1Lrg4Fi53TmNycwV9J4vwQze3CCHMh5f6xXipvBJtpGkMnjWHl8h/Od
         aoZ5QrKMzTlZKeH/4ng/6WJM1YCl810lHb6Stj4HrjuXnO3gjja+1tRJj3z1LgSaWqaH
         og06lh2Jq9EMqsQoy75y7hbA+fPtTxy/4lmFUt47TVQG2iYZTD6ZsUNfOR9+8lwMHiL8
         EUP0PcFzUM+lVrI22CU6watHwaNPHYkowM2kxmApY4WySfjqmeUSz6rcGwxa8jT+9ztF
         uGlMflIHpP3eTgqSjMkEGHV6zC2yu/fLM5dnAe4PFlyqEOGGkJMkOQLpSXFKEKcUBpBR
         EEqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnoQY+AEtxr5sue/fgKied9foIBK52jvaCdGL71pPwY=;
        b=a8oHjTHxE+oQOLGSZ9cCjUZEO7zPeQKAuAIpEEa3OWfV1/joEIelqGdhG24tNN83Jf
         5k4g1puVBh5e20iX9dPQakuLa9H5rkfBd0B2XSmxCXIVHKvcBJP17QjFvQYD2J7pqait
         pSdouk0FIJgfpMz+Oc/mgxXqr0yzOeEtHMMjTI8QmB6Cw3EpIced8CnqiUrMkRbLgYRC
         9E7Y1x1TT1gtTo2F7LJ+kIOEjAN+fPYRlcNv2Z131/h3R95c7H4fcGWQB3fSY6ywEYD4
         0dQHm3GC4b4Ouo3fSL9mEBXHIgQ5xAeUZdnZfZfJC8RJVLbJeSBvfb1j/M0vMM7TGWYF
         g0xA==
X-Gm-Message-State: AOAM5310IRU/48gKB5LkOfSPlUFPG7EZ8XChtarhKWj+OGpcJS589MJv
	a6D+raJCHzoVDJDj3dKsBlE=
X-Google-Smtp-Source: ABdhPJxsTsTGyMHkrp51eGfiodFXobNfCquo/If2DUJBcVqVVc8V54Gos/fKb3vMmVT/cZ2GdipsJA==
X-Received: by 2002:a9d:611c:: with SMTP id i28mr2918930otj.361.1591264353560;
        Thu, 04 Jun 2020 02:52:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:86a:: with SMTP id 97ls1227326oty.9.gmail; Thu, 04 Jun
 2020 02:52:33 -0700 (PDT)
X-Received: by 2002:a9d:560d:: with SMTP id e13mr3061002oti.55.1591264353235;
        Thu, 04 Jun 2020 02:52:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591264353; cv=none;
        d=google.com; s=arc-20160816;
        b=at30ftIzvQs5XAlHMvjm/oyMsFVUzUR7G6BctUjcsY5UzTYoTzMBrfgTHewYBx3OnN
         p3CZP+qcGJZOxwLsXA81HeECu+5Nk+ic7Q/YfVRl9h9bDDXl11jgMJTk7n8H1cZMKXsN
         hJkz/4kcJPum8c8WhK+YDW/RlB+OZTs1/ksShRtnBfUqspzD18B78YDqO1Hb7bmbxLxi
         pEsuDTJ3uKac2fOQ9q0yC2u86KovR7tf4KDfMWYAFvNhCiCLPA3exIS+oifj5ueI7hAc
         GrTInYvnAppE/Wd0GwgAbpu6ihw0BTE+l8p1jzsc55P1BblY6QR89Gih4J3Murt8TUfv
         +TAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dmgCAZztkKponFlSOj9eb5gBCC+mYH067uJY2h6tIxo=;
        b=s+3oyiTg0wuQPp2exbzmJEw2aLMcRgqEfYFube7CRHkfIcTgVNxckwRK9skCmUVzEj
         JHReloXhUiPzgQF/Du/z2HslZ3lH3yqCmgSndQHFjHtdeUb/BgKDQRwwxxJokaqiDIQM
         7t8pVXjcBVbdPIkzPPXI+3uedvgEu1i4cyTpyAYktw+nyWHUHWPt3rdrwwNZNyP0rziO
         RspCpqifVRP6Z/3jJbzWpGnmSmHmYDDtgxKSGVP22Gb0YgfVDwya0hw5He1hMTufgsUu
         fzFe4RtmE95cVi+YmQtilTTsbVNUrNGSvbhZTzyHmaIkoLjEO0jR9T/d+u/axXxWe8MI
         rA7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E03wrYq2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id u15si373729oth.5.2020.06.04.02.52.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 02:52:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id v3so1130289oot.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 02:52:33 -0700 (PDT)
X-Received: by 2002:a4a:b54b:: with SMTP id s11mr3156030ooo.14.1591264352701;
 Thu, 04 Jun 2020 02:52:32 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net> <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
 <20200603160722.GD2570@hirez.programming.kicks-ass.net> <20200603181638.GD2627@hirez.programming.kicks-ass.net>
 <CANpmjNPJ_vTyTYyrXxP2ei0caLo10niDo8PapdJj2s4-w_R3TA@mail.gmail.com> <CANpmjNMyC+KHTbLFSxojV_CTK60t3ayJHxtyH4AckeMD2hGCtg@mail.gmail.com>
In-Reply-To: <CANpmjNMyC+KHTbLFSxojV_CTK60t3ayJHxtyH4AckeMD2hGCtg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 11:52:18 +0200
Message-ID: <CANpmjNM48j4D7F+cgUrrof38d3nLuQjbW6pz3nTwxcZ5Q+GJqQ@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=E03wrYq2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Thu, 4 Jun 2020 at 08:00, Marco Elver <elver@google.com> wrote:
>
> On Wed, 3 Jun 2020 at 21:10, Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 3 Jun 2020 at 20:16, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Wed, Jun 03, 2020 at 06:07:22PM +0200, Peter Zijlstra wrote:
> > > > On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:
> > >
> > > > > With that in mind, you could whitelist "__ubsan_handle"-prefixed
> > > > > functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> > > > > case is quite rare, it might be reasonable.
> > > >
> > > > Yes, I think so. Let me go have dinner and then I'll try and do a patch
> > > > to that effect.
> > >
> > > Here's a slightly more radical patch, it unconditionally allows UBSAN.
> > >
> > > I've not actually boot tested this.. yet.
> > >
> > > ---
> > > Subject: x86/entry, ubsan, objtool: Whitelist __ubsan_handle_*()
> > > From: Peter Zijlstra <peterz@infradead.org>
> > > Date: Wed Jun  3 20:09:06 CEST 2020
> > >
> > > The UBSAN instrumentation only inserts external CALLs when things go
> > > 'BAD', much like WARN(). So treat them similar to WARN()s for noinstr,
> > > that is: allow them, at the risk of taking the machine down, to get
> > > their message out.
> > >
> > > Suggested-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> >
> > This is much cleaner, as it gets us UBSAN coverage back. Seems to work
> > fine for me (only lightly tested), so
> >
> > Acked-by: Marco Elver <elver@google.com>
> >
> > Thanks!
>
> I was thinking that if we remove __no_sanitize_undefined from noinstr,
> we can lift the hard compiler restriction for UBSAN because
> __no_sanitize_undefined isn't used anywhere. Turns out, that attribute
> isn't broken on GCC <= 7, so I've sent v2 of my series:
> https://lkml.kernel.org/r/20200604055811.247298-1-elver@google.com

Now that hopefully KASAN/KCSAN/UBSAN are fine, I'm looking at adding a
patch for KCOV:
https://lkml.kernel.org/r/20200604095057.259452-1-elver@google.com

Will that work?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM48j4D7F%2BcgUrrof38d3nLuQjbW6pz3nTwxcZ5Q%2BGJqQ%40mail.gmail.com.
