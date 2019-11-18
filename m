Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBMUTZPXAKGQEOPGJ3QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id D7CC810095A
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:41:23 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id a129sf11777138qkg.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:41:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574095282; cv=pass;
        d=google.com; s=arc-20160816;
        b=nhM40FmU82HGXXopg2bDN2srBVLGTBs3kHDUTHtvsqATAzxvNn/93tt5Drnd0y69d3
         pmDOoDBdU93vs8l7gNU8JwCF8VyRITVUdgjD8NXvzB78p1O0fLlP4at4O1QFRUt+7Vog
         O9Q3qYW+llJJcpkJYoA1/IjTqRaRMl89seqlGy0kzRHz+z6SQ7izk5WOD4YKEm7MKGUm
         jYfNJerdZ2in3eqm8eLttrKY/TSRZAWsB6QUKHaDsut/xQdN0uMiHvZZfoE5JxdrXmwb
         rmFDGonWXf6zx4U8j5nZMnJ5ER++lvp/KYRzd1JWJcxVHJFIuVw9cydL0ka6Z4xtkWi4
         I9Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fpG7tGYmZnhktT/enA/5dH/hM2fO+vSCNb5F65c/Pdk=;
        b=Fs1gboL+Tvn9ftjcetNS3q4im0VoJIZ4bTliPrEDCe9Kn0l4SklCxY6nsxh/SmnCXh
         ajlw3l+v55gu81VTTlE8trdy3L0y870JZKy8XwREmcUW2bUgDTP9Jsg0lkPM5mMuk8h6
         G4D+DTCINjX0/x4TKt/H8oJQ3ICI0qaDZFoxSqWbn5a27oKHRzJZNRspIB8hzDRCD38/
         rDAi6JT/pwsCabI3r9LzRetpmQiG3NMRiKjJZbIRU4ZG0I6PypoB2rwDVE3DvSkguOe9
         8+FYxW8x5hSmONGPlUOsO0GneHZ2GY1DnAk/+RAo+22rN7WRHsfJHo/goFavVaWUFbl9
         7rGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lt9VvdJq;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fpG7tGYmZnhktT/enA/5dH/hM2fO+vSCNb5F65c/Pdk=;
        b=SNxefEmgvHdXQB88zVjGHgYm4NtPETCHxny9TkiTbx3a9M4SyVS09VRIQ89HQlUVBt
         l5P3xuqClknj/qVBm7J3V510HQImKTtRuTc3GZgskUxJX+Y3HUJueFtJwroInUZabYU5
         WwyIpIKH+q4PkDj1gN+hYs14OwUq/mb4tltXsO/0w0H03Ai+/gdiqMt92Tooew1H3Dzl
         CM9ae+Gv6NrDxGDbLi1mv8CPcgdObDD7PWYzpKHsXahwo7O7E0BkTnUaFfbJDYivVaK6
         S0wAeCPm2F/XfTNDROtZVCCjKYt57Z07NdtK0yU/mYh+POtaOgW9ONEFV5e5trv1jgOR
         rT7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fpG7tGYmZnhktT/enA/5dH/hM2fO+vSCNb5F65c/Pdk=;
        b=LpQf6pt3AKphpgftFr8EWLjn/I0+uNQR1wFH8Ylg83n3X7PoPA+legBa0wNmTd+2HD
         a+Io3cLXQ3e8wpSp+uP23NVfRqhYEDBr26fkABsMZYYSUOw7l6JW25R/qIqpnTA1W3aG
         L+bhcETSZ9VC+WQT185Tgeyc6xsS9ELOI2MY6pNZycfz1DDQgDuqt72LO0tgG069l1Gm
         1W/SI6xX98M8eqS/M3NFrbQQlIyI+oVI0Jl26tNEfv0YoshccN3RY2J/cRDxfUw4sDtw
         6sAglXpOuIygzyiG8ITkcVzOVxXAMsd8oGuQ84xnAAO2CaOism7yhgB/4nNyWlYTW71t
         5eEA==
X-Gm-Message-State: APjAAAWQdsarNAPOevbfAO8vmwDC2tYW3P7QsBv+32o0/A5brFtb2umq
	PIL3V3kw46WOp6D+x0GyX2I=
X-Google-Smtp-Source: APXvYqyS8vwlu8TnDU2Rb1xMuiZbdFcKLQaZGIqPgCvo4vHKdTHCG8fuB+3NeLfRMPM+djHsJVp52A==
X-Received: by 2002:aed:212b:: with SMTP id 40mr27632003qtc.206.1574095282818;
        Mon, 18 Nov 2019 08:41:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:13b4:: with SMTP id h20ls2539916qvz.0.gmail; Mon,
 18 Nov 2019 08:41:22 -0800 (PST)
X-Received: by 2002:a0c:b446:: with SMTP id e6mr26897955qvf.159.1574095282171;
        Mon, 18 Nov 2019 08:41:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574095282; cv=none;
        d=google.com; s=arc-20160816;
        b=BnQgtPNEdryHLKqZZV4UDnAOWV2kEvRW4dwehhzwQK3Yf6x4jilTXpbmH36hYAlTWs
         Up/hDM2kXj4fV4VJQLR5QMnrcsOS6fJNQefFo1+0Aj+aOgHi4GYWCrMv6OVsIHRxzD9y
         F2Uxiy76MGJHpxCvBTvgy/FyS2EnaBegJjMIV29nekicwQM6Ao4YI6CSQQzGJLwVyGRh
         8Wn3bUNeRnRCvA5kAsjFuCv2Hhg02tc2kWVW3iGHTmbWgLjo/lJuuJ0ZmiJRFtNeaZja
         dKljYTfNj4gJ+ZKC3zyNKsoYIeHHsP3VVM9w4IuoerhYIBgM8K25/Xo5bI+Tm4JL0T+L
         NNDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vXwyD0ddcsazG3MxeN3cnLvJuWsUAB6zn4Igl6PaVxg=;
        b=MTLb9tHfWz/E771GPLT7lSjP9Ar9mawGLSIAGgJ+O42Ty3trVozEXxjttGFj4wq8a7
         cy1QOIrIyktq8Jc/djSJ7Cn5KakGCjhgFTny6D4T7V0grqPuvmyU0+BhK9sSv52d7Z3s
         nwNZKh6HR1+oTDg7TNVrFYUiUSKh/8qWGLT2hXNwExIzePV8ey/g54nSQfejLYmopRRw
         Ap+Ge7/qetmOsnVGnBSVM/NWlVB/rfQOXrnuohY/7Sfo+IrC6pKivOi1BLiRJ03quUFn
         R+sRh7K/5tAGqdANMNa0UboAW5PnA3KfWonj4NADgLdyqjateVH+C38fXTLeRjovvdBE
         sctw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lt9VvdJq;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v189si1063719qka.2.2019.11.18.08.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:41:22 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id b16so15061138otk.9
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 08:41:22 -0800 (PST)
X-Received: by 2002:a9d:4801:: with SMTP id c1mr164337otf.32.1574095281350;
 Mon, 18 Nov 2019 08:41:21 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic> <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com> <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
In-Reply-To: <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 17:40:55 +0100
Message-ID: <CAG48ez1=Zwaf4eNW_nKMrJ5DJ31eVLgcRuLPntwm17AT5yatjg@mail.gmail.com>
Subject: error attribution for stalls [was: [PATCH v2 2/3] x86/traps: Print
 non-canonical address on #GP]
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lt9VvdJq;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Mon, Nov 18, 2019 at 5:29 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Mon, Nov 18, 2019 at 5:20 PM 'Jann Horn' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > On Mon, Nov 18, 2019 at 5:03 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > This exact form will confuse syzkaller crash parsing for Linux kernel:
> > > https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L1347
> > > It expects a "general protection fault:" line for these crashes.
> > >
> > > A graceful way to update kernel crash messages would be to add more
> > > tests with the new format here:
> > > https://github.com/google/syzkaller/tree/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/testdata/linux/report
> > > Update parsing code. Roll out new version. Update all other testing
> > > systems that detect and parse kernel crashes. Then commit kernel
> > > changes.
[...]
> > > An unfortunate consequence of offloading testing to third-party systems...
> >
> > And of not having a standard way to signal "this line starts something
> > that should be reported as a bug"? Maybe as a longer-term idea, it'd
> > help to have some sort of extra prefix byte that the kernel can print
> > to say "here comes a bug report, first line should be the subject", or
> > something like that, similar to how we have loglevels...
>
> This would be great.
> Also a way to denote crash end.
> However we have lots of special logic for subjects, not sure if kernel
> could provide good subject:
> https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L537-L1588
> Probably it could, but it won't be completely trivial. E.g. if there
> is a stall inside of a timer function, it should give the name of the
> actual timer callback as identity ("stall in timer_subsystem_foo"). Or
> for syscalls we use more disambiguation b/c "in sys_ioclt" is not much
> different than saying "there is a bug in kernel" :)

Maybe I'm overthinking things, and maybe this is too much effort
relative to the benefit it brings, but here's a crazy idea:

For the specific case of stalls, it might help if the kernel could put
markers on the stack on the first stall warning (e.g. assuming that
ORC is enabled, by walking the stack and replacing all saved
instruction pointers with a pointer to some magic trampoline that
jumps back to the original caller using some sort of shadow stack),
then wait a few seconds, and then check how far on the stack the
markers have been cleared. Then hopefully you'd know exactly in which
function you're looping.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1%3DZwaf4eNW_nKMrJ5DJ31eVLgcRuLPntwm17AT5yatjg%40mail.gmail.com.
