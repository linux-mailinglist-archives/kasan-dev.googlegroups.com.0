Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNHXLXAKGQEP6XOWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id EE61CFDCE2
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 13:02:22 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id 6sf6220451qkc.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 04:02:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573819341; cv=pass;
        d=google.com; s=arc-20160816;
        b=LNSJmzuEiwRRw9Q3TYUa95AL9lYoaD1Fdo5cPgkcFbqQwj/jHcPOTLZ+Td4qZj4P/u
         ZmR9eFhX+ZX1XiZisE8OryvWHBOZZoCt8PiXQFxV5zvNru5JLqePB7OL+4a0jjnIA7Sj
         T35O/Q4PwNgtsjhEN4Gf9ozfTIwjBoW4TfJTyVkFq1EX8CJwML2XDTTgSEh3OlIynxxH
         JjvMm5ikklXJfSitxIKnlVzpB0geqQoxsZhJ/PuNwz5FEF0108Pe2VIt3QfCvlJ3oOyu
         W8/CUBA/UDB2JJnlDN17bNds03W/NTfgdGP9QN2FXpr8BHran5WolXuox3wMrNgh8MNL
         9cCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YbfT+L/ZY/hAeh+kx8mlU/hNG06LddnZjD3iP5Da0hI=;
        b=RD88fckn3vDxwL0R/ECTpOcFq9vKgJTO0PIDy3Vv846B6m+/6Agimt8NhEEY6Cey4Z
         87iIlezCvOJsqr99mCmoea0a3+ahO8Ijc9gM2zrmL28oIe33sQtQGAQVp9sxUKqKG9Xo
         R5XClHSyk/OdCZlGB7VWPxqSPwww/BpFjwN6dxGYP5Sj29gmBhBdE6fcBdRxRC6klMBF
         iRITG2lPFxFdWG4GrrS4pAtTJhFAS2ppCZTxkxc2Rc4Lk7sGpiSBbB8n5FbY1Vz4X3gc
         dHQybrI4bO1vnixxYMIBfHhYdlrHBeYLdNGh6fc/jIBiq7korG/Yul/vPAmNHe8n986r
         qWOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVJwYDJC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YbfT+L/ZY/hAeh+kx8mlU/hNG06LddnZjD3iP5Da0hI=;
        b=of4r29t0iKlkFPn12BCT1FbJp0UiIDEZqLkr7HKGc/HgB6JSDIFOEAn0AwWMK6NIX+
         f12sKoDdU09/jsb/kwI5Dw5S/rA218DZoApxlSulBbWvr+xQ0Lfe1HKwt9zn/7NYnWOI
         Aye9g3u3+soe7r7XGogQeOkVnwytdkKV/aD3U3Z4+d31nFAsaHLQgQOLWXTkYtO+WFtW
         RvBToCV33E/qX7XdHDzW858XKJInTuYvlPAkAoqJKV+MPHa3bVXoTkY0hx5+fY3BLa7T
         +nD6JJ7fZRNLOiRaogQuejV9n4WsprrLBDcsM94BM7Vk3KYREtuVCK4ewRdAcfdLnNOB
         tQww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YbfT+L/ZY/hAeh+kx8mlU/hNG06LddnZjD3iP5Da0hI=;
        b=QaLMTzFql2o7xhcr7E4hVksCAMubpkvOFpLEF6UdwG1LnHRNRQ4Qs4ha0syWJfpqLh
         Q/mwL7bC5O2p0s+kPgOC6AjjLmXRFWd+9Imd3rRRFefBzX+Mo7ljrHq+LQ2EyPBqY3No
         ArhMMdtjV9vGvrsaBNUBXFtiuB8dCkzw+XQ70zK/2NJdC7E3DFXrKbQPaLO+MNnitLwg
         4pPvxt7J0jHLVkFFrRulLEkDso8QGS47wokNmD+GeZhHHmiKEpqyHtis08Kd0FbMBikk
         LB3eLzqunq3HTJJJPD1jviKfZ0+6NFKq6HiBVfofazlZtCSMLm2kuQ1UvCqIA7TVpqMC
         hfiw==
X-Gm-Message-State: APjAAAWWqcGneCqJqTqgyRBNG7cbeVt358GnDrn8+/z04BGGEqt55wWy
	7Mc4YYh4o6TyLBKorZkhStE=
X-Google-Smtp-Source: APXvYqwqjrU1psqQVJV+PTkYTv5uRA80Cad4nKJyOfQuoVB9Qjjqv2qfrX5YP03JsUEb62WVj4O5SQ==
X-Received: by 2002:ad4:4770:: with SMTP id d16mr13010516qvx.92.1573819341601;
        Fri, 15 Nov 2019 04:02:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:341d:: with SMTP id u29ls2091393qtb.2.gmail; Fri, 15 Nov
 2019 04:02:21 -0800 (PST)
X-Received: by 2002:ac8:5445:: with SMTP id d5mr13136004qtq.19.1573819341240;
        Fri, 15 Nov 2019 04:02:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573819341; cv=none;
        d=google.com; s=arc-20160816;
        b=Ff6Yssx3EWhl+dsgD/lbzH0hvw7BzeLPJJgmS3VPvG19KA8JndgRrfrid5+S4lfify
         546cdkdRNBTzRgmY8qP4EMhIlgTK44j/SKIxpoejM7GnGIC3aAx1ShB5L5K1ftSKRdvG
         FS99WyJ0kBB3udlaTKmbWBh0iUYRUYT91EYFURyryX1r4raUnVrqDbUncQuzt+JlgKfD
         cr/tj5aV4TtjiMFfvTQOc2WK8x0A6UVkA1u61Fk0nvSC0OYBpzonJccaQCIjDbobm1IC
         0F2ktMjO2mT5xDIjQQGRN7Juybo072hVzWPSKyUrurYb3oIAZJJghSqcP2f+4I1UfVNb
         WOFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RRytg93FU7f6sfBrcqBa/NI8/4Q9Vec4eDf1e8YsiLA=;
        b=MjOsiJUuxBFCHvPXPtYOFknxGGMqAZivmhLnIHW5miJam+05aM2pbT/GPmJ/gUo+LE
         v2+GoRk9LKR3hQo02/zE+cGZmkxFRCqsDXoT6739S4uckLzJkPkUAnKKCE5/X5oVVhC/
         xmQQujSGioiR84xe3M0p4PFBPURUbNKVyOjQdLXpbRhNYIIvZsoOGbmX+zSGULQUgL+6
         ppoLctQamJNFzdLKEo7rT3bvFP0tXi5Ips0Cl6mv8frB8Wy7PhvEhDWyHUFEXKipa+2P
         B9Nw0rSnZ5DqcaRqaxHA3yW6RyxSBxbMq/YtQu+StrwESb4mcIXHCQrEp5zUHFpIxeyC
         T+lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVJwYDJC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id v189si566300qka.2.2019.11.15.04.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 04:02:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id l202so8430705oig.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 04:02:21 -0800 (PST)
X-Received: by 2002:aca:5413:: with SMTP id i19mr7842386oib.121.1573819340279;
 Fri, 15 Nov 2019 04:02:20 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com> <20191114221559.GS2865@paulmck-ThinkPad-P72>
In-Reply-To: <20191114221559.GS2865@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Nov 2019 13:02:08 +0100
Message-ID: <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
To: "Paul E. McKenney" <paulmck@kernel.org>
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
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nVJwYDJC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> >
> > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > only enables KCSAN for x86, but we expect adding support for other
> > > > architectures is relatively straightforward (we are aware of
> > > > experimental ARM64 and POWER support).
> > > >
> > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > integrated the feedback where possible:
> > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > >
> > > > The current list of known upstream fixes for data races found by KCSAN
> > > > can be found here:
> > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > >
> > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > including several articles that motivate why data races are dangerous
> > > > [1, 2], justifying a data race detector such as KCSAN.
> > > >
> > > > [1] https://lwn.net/Articles/793253/
> > > > [2] https://lwn.net/Articles/799218/
> > >
> > > I queued this and ran a quick rcutorture on it, which completed
> > > successfully with quite a few reports.
> >
> > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > you mentioned, we're fine with your assumption to targeting the next
> > (v5.6) merge window.
> >
> > I've just had a look at linux-next to check what a future rebase
> > requires:
> >
> > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > - bitops-instrumented.h was removed and split into 3 files, and needs
> >   re-inserting the instrumentation into the right places.
> >
> > Otherwise there are no issues. Let me know what you recommend.
>
> Sounds good!
>
> I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> approach is to fix any conflicts during that rebasing operation.
> Does that make sense, or would you prefer to send me a rebased stack at
> that point?  Either way is fine for me.

That's fine with me, thanks!  To avoid too much additional churn on
your end, I just replied to the bitops patch with a version that will
apply with the change to bitops-instrumented infrastructure.

Also considering the merge window, we had a discussion and there are
some arguments for targeting the v5.5 merge window:
- we'd unblock ARM and POWER ports;
- we'd unblock people wanting to use the data_race macro;
- we'd unblock syzbot just tracking upstream;
Unless there are strong reasons to not target v5.5, I leave it to you
if you think it's appropriate.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk%2Bk5UzRsXT0a0CtNorw%40mail.gmail.com.
