Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF6H2HXAKGQEHC5GTCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E32D102E97
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 22:50:17 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id x17sf20583668ill.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 13:50:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574200215; cv=pass;
        d=google.com; s=arc-20160816;
        b=XH8xRxmmp7D0HDX5gqVvmehRVBXu8v8u274LrkfuA5N+C1HDX64U8mkFTroAV1gaXF
         VK/+t7OpJ171tt7nBpSqcWmxF4jRVI9Im8kUv7qsq4cRs4M4pjsJTCrXltrFebT0f1vB
         yImPuGJVbMgHp0TeNLs7SyCpou5c1/ysbt9uEKwFCjuEAhOk3GsyMXj8psv/J/C0WQ4k
         jPDkH3ouy/GUxtE0TNPc2sgpAp2NwaYU7CorpzZ2uJ3INNWmxe2A9evUxN+gBg8P0bJ3
         piJjUyhSqUi2JU4+vVTpJhSw888WbGS2pJ+z8gd8a+2Y3bkxj6lFJ+K2dFYmn4Y6xlJl
         r9CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vQR/T3nVYlzKUlUCmT7dqQAky6PP8OVmFCCw8gsadEg=;
        b=l8Cpchb+LF6aHg8VvN4gV3FhquOBbKcdW2bMbSOd49DrRtRZkIievLgB4Qq5zGbjoa
         POaG6ckQxtKf8hDep8mmR4Nkpi8bPRB01Srgp7pkz/bnmToL7udpvWytMZT1KiUrEr33
         UKrOBfr6/N3g4WKfaoggi+lqBiilwQb0p6n2K8P/q36ViaCenDVXiEK9tD7KMmCf8KXQ
         rVOEwnq0CA6VmYl2+dThVPfDuUzkkkWBrw+up1XkZmMhNMOwa5MBducaX/E1Rr3VnHaN
         9F1i2DPkjEydgtV+p62eeFikDc1iprJwUHFnjBGugyCX0F1M8IokORw3N0yln9U3aGFn
         67Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p5Cy99Po;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vQR/T3nVYlzKUlUCmT7dqQAky6PP8OVmFCCw8gsadEg=;
        b=OySvkMixjD6AqecQNRenODJiRMvf5+I07XNDfT1o4Ru3JKr+x9JBtN/eMcyhUIg5LB
         ai83q77rt5RCPaxAtWcMM3fMI3IJH0xmHNXPIKgxaQzOWBDW+85OgJtAK3MEkNvfosv6
         o7s4R4o8aKDLhHh/z5CNdIpUCIEW8UnfEsgmLGs6bBWqYegC45uvzNuH1AppbMHW92a5
         vsJ8DAvubvh5k7CBOgYWHniLunFz/jYELoYn7fyR84bmh+SODRyoCSJj4+iKBe2BSeEB
         yARA0Wx+IELq7fVBG50+1Mo0yPaeT8XNIfj+U+ZRTN4KwTLrJRmisYqciy6AnV/GRY8d
         lTWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vQR/T3nVYlzKUlUCmT7dqQAky6PP8OVmFCCw8gsadEg=;
        b=cGyoyX+Lh6jOa7H8nb8QUPhH6iDuQOcSUb5NVFDt5qgYLGCqI1xGToLS1VBerow9uD
         A0o3KBuwwVMIeBxsQ+rnBncJHOpMRMakuBX1b7tSB9pbj604lzqujR+l663zXEYJw7ig
         msMiYhEQShwxS8CNACh+QMUI8zEzMNac9jf7kgDRvcj9YpVGpY/NXpBRo+gnVTkZqeUZ
         7drSiqLTVlp+y7YVXcmF3/rbHMbN4lJLkiUAjxGyPHp2oYdg3zJ4heaT70GF6a1k1UOb
         XVPtD2SLx4ugzjCCzYTm5TrD0AgMHonY/D32N34QrtPhd3atfnwrthszCxh5CyV6CG+y
         HHNA==
X-Gm-Message-State: APjAAAU2KIDJAnkxPBqxJpQtON8HnqBnp2L0KFZJQE0jzulaRm6LK0Xm
	m5oL1wbsStTLZCiT2NQhFaw=
X-Google-Smtp-Source: APXvYqwLG7HcoC6KLxatwb2+rBoieCZ5MLdae+SbSJz2UlFJVV3bQCcX1HgVJeeUktlvZJ74Apj6+g==
X-Received: by 2002:a6b:f701:: with SMTP id k1mr21605680iog.260.1574200215703;
        Tue, 19 Nov 2019 13:50:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:606b:: with SMTP id d43ls6774jaf.6.gmail; Tue, 19 Nov
 2019 13:50:15 -0800 (PST)
X-Received: by 2002:a02:962c:: with SMTP id c41mr125433jai.74.1574200215303;
        Tue, 19 Nov 2019 13:50:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574200215; cv=none;
        d=google.com; s=arc-20160816;
        b=DGqwWkEZax2nCCQ4yfj+VXVEFlzdhM6Azo8rPNSLXX8wqX4vuRMklj9FZ54AOUSIYK
         81PYdC0ohkA75ncBw9J7Ofq1qomw33FwEOWSRVt0luaGBjDa1RrH0/m34cbQbDgXQcJL
         FIUpXUh3EEwvggxxO+C6I+2rOUYSpvaGw+Qodiyh5rF7a9w6NW90arlaxNCIWZID4dcr
         UjiW+prRjJjFq+/SYwQucksYZVemM79CbTg4iWm6ZRK/3AtdwV5WuMgmMfbWBMImjVpO
         s6vtlKUHWp7LI+E65JBFoCWBsTt/D3ENbaAAp4t9wBqe5GtX9YCZM7G60d5fyI3a5H90
         yUSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nChvbzLFSqXvxVpDffdnChqvN7oTXvHT1a3fMg3wbAY=;
        b=yg4gCIZon6nYB3jqKcen2uQPgnQ77InguQ2W07OcxACoHwFuxijZsK/nXMeHTgbqN7
         fOw9zGfNbmK/7IvM29tg+xZOeoYD0tT6nmCJ8cR5bIiXCpruAqqo060WQrFMt000l3TK
         +AOkoEhzzZEXmS3jgQzlFlLckhgMoE3LWFrKLkYBgMfQeudIumelaw1p0qSiPSArpm4h
         G/oPQ6Bv+grUmnNOBL1y7WQwSh9KlPwIVtv8dL+seGZP/Iw9Orj+5LV8pC78WbmgcsON
         t11cXLtq7nMTGaobBlc8Tllcu39GU+RKN7YKxJxULWQqz62QSdKz1LoM+TQqOqdWg6TF
         Krfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p5Cy99Po;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id 75si980001ilw.3.2019.11.19.13.50.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 13:50:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id a14so20500072oid.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 13:50:15 -0800 (PST)
X-Received: by 2002:aca:5413:: with SMTP id i19mr6343058oib.121.1574200214595;
 Tue, 19 Nov 2019 13:50:14 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <1574194379.9585.10.camel@lca.pw>
In-Reply-To: <1574194379.9585.10.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2019 22:50:02 +0100
Message-ID: <CANpmjNPynCwYc8-GKTreJ8HF81k14JAHZXLt0jQJr_d+ukL=6A@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
To: Qian Cai <cai@lca.pw>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p5Cy99Po;       spf=pass
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

On Tue, 19 Nov 2019 at 21:13, Qian Cai <cai@lca.pw> wrote:
>
> On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:
> > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > only enables KCSAN for x86, but we expect adding support for other
> > architectures is relatively straightforward (we are aware of
> > experimental ARM64 and POWER support).
>
> This does not allow the system to boot. Just hang forever at the end.
>
> https://cailca.github.io/files/dmesg.txt
>
> the config (dselect KASAN and select KCSAN with default options):
>
> https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

Thanks! That config enables lots of other debug code. I could
reproduce the hang. It's related to CONFIG_PROVE_LOCKING etc.

The problem is definitely not the fact that kcsan_setup_watchpoint
disables interrupts (tested by removing that code). Although lockdep
still complains here, and looking at the code in kcsan/core.c, I just
can't see how local_irq_restore cannot be called before returning (in
the stacktrace you provided, there is no kcsan function), and
interrupts should always be re-enabled. (Interrupts are only disabled
during delay in kcsan_setup_watchpoint.)

What I also notice is that this happens when the console starts
getting spammed with data-race reports (presumably because some extra
debug code has lots of data races according to KCSAN).

My guess is that some of the extra debug logic enabled in that config
is incompatible with KCSAN. However, so far I cannot tell where
exactly the problem is. For now the work-around would be not using
KCSAN with these extra debug options.  I will investigate more, but
nothing obviously wrong stands out..

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPynCwYc8-GKTreJ8HF81k14JAHZXLt0jQJr_d%2BukL%3D6A%40mail.gmail.com.
