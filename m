Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXM5XHTQKGQEGTOR7ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 92FB42D8ED
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 11:20:30 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id h4sf1404736qtq.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 02:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559121629; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnXbdGKoRk888c8PX8RAnj9iwVmh+o268J8FK+bS5TC2tqq3gaq5Pe7so6kxajOAsV
         gt6wSiYLwbZotTc2ZSWycFFgjtMQ6HdraKyq25zaDodrYEr2+7pyDBp5EtWYEqe+ihyF
         +SC8BE5CNY2z5CpMJaVqlfU4qwEaL4ImPkvKJp8zyvmhkH1cHRi9fzPj5nr1fFcWpgU0
         fHhWoHjIfZbsW601FL1LgDA0kSfMmkejd2rzc9kSf87D5jXg9w2tbTHRF5qdYR3vE7OL
         XE9OuwxSDd0FA3Ma3R4CtWgL6DNHCIkaXReJBFmjQEjiPe0CO3PrdX6A3LuYfYK+h0Xp
         Cr9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=K6OgwpES9XwgkAmk6JvOGir221+ZA0vEEKLoJxHl558=;
        b=NYqvwpDiSfz3o2NkOyl6e/MHzPBKAqJZqqzrgpZ8b8nHrgmm5tr4o+3910LFF4jFcN
         uu4Khc7nTG/rcCbpGpPIyTl3yaQaihLhgfA6sSWTF9aE1npdj8+He6mwGHDnBXOmQui7
         s205qpIyGUWliav4MNQnjGc8MxL+AjbSh162LOYHEd2vywBjaB5YXw8Nzbu0P3Cq9hOQ
         xpMkW47cjlr+Hwsr0EGq2koCs0usfL47dy5uabkZMKJZqF6Y1bTCPdc5NukJrNLYct7C
         Xe0sFln5KB05n25KAn0ixN2c/hXa/7G8/dFrQ0Nd/CtacUDZQqhA8eJS6rvjipz0T5HE
         cWNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQZVTGNC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K6OgwpES9XwgkAmk6JvOGir221+ZA0vEEKLoJxHl558=;
        b=Szlpvi3hTkgvid0oEkWdRsDEOR+H+OB7NJx0BeiRhvcT/A5ItfHQtCOW/h3XD545Bk
         ZEREDjMn5zHarxGYoJlYTBzlDlRhEU3B3vcHizYjo3wp0p+rZBocnY7Vm4Y6w/h5vq58
         QAZCAt3zBXuJmq7B3vVZILY6KirW4ZNWaNBNafkaCKmQPq0AsAsZbA79lyQVHxX8HW4Y
         9dAuU3UMneCjxXaxDlSSzCfcS7XssJ5QyOaRKahveNFraZWpi+cFg4fF8LczEy/G7M+I
         2nxEy4v9rKcVULnBwyav7YWtzPTYREQEEOaz6olN4YC/foJIH7cnm2EtDHIlbXAO6tmw
         Mlbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K6OgwpES9XwgkAmk6JvOGir221+ZA0vEEKLoJxHl558=;
        b=I59lL4JU7e23w4rU5CRxeX3W9GwWyikR9jvDeXgMZ0wRbvGgpmminCQQRH9yXVRjCR
         qlR4XQMbIbpgp/ZsodRiXf7uvOcmYPxT1bgQrzuZIgXIXzk86PuljXV1TYi7mf1uiRCB
         9HosUiOt5Z4xB8ROHon5ooxOmdhEBdhz4iu5pn0LYc7eQ3r+TMhmMwKMZ41PyhiKJb6x
         IuzWobOU/90e/TVjJQE0XIxjaj/OFdX/gFhq78aGmOgqCSkjCnA/ZKM3BYlxreVQxOjW
         a0DsgFfb7vb2j8Yc/8ZViNiVl3c8Emzc6sdTjpO9/+g0rcH3f8vqtg4vpl9WvGmFgwiX
         Caog==
X-Gm-Message-State: APjAAAWwpecsR22sXaOdBvt0gGW7/zW+yqHMP+LwV3qMihkEtJabNyfc
	Lc+WWxBWyXvpKLfy+c7AFfM=
X-Google-Smtp-Source: APXvYqwaCXTfNm6Ta5O5R37t+uot036aTYtbi+ST/bnXzl9RExFzBMHh+cINsGhxaao6XBFUPP5FGA==
X-Received: by 2002:a0c:e6c7:: with SMTP id l7mr36133777qvn.237.1559121629463;
        Wed, 29 May 2019 02:20:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4d44:: with SMTP id a65ls461464qkb.12.gmail; Wed, 29 May
 2019 02:20:29 -0700 (PDT)
X-Received: by 2002:a37:ad12:: with SMTP id f18mr8244851qkm.3.1559121629215;
        Wed, 29 May 2019 02:20:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559121629; cv=none;
        d=google.com; s=arc-20160816;
        b=f8mIag7s+CVJ0WWU0tqzup7jJdBryDiVGa32huMMzLBYlM1Q4TXgpyZDWu3cpbGBMd
         Yns4Vnpi7n/CtXz/U6F1XK2HY4iHvB57aSvmYSweUck4OxwOKoh7+UltfzBjevf04jE6
         76ocM0iyolvjrukqstlv37PKTRwl1Nyczn9qvJUlkZsKakfMSV2Ow6VXDNxCqfWYWtEd
         hA7nogauAgqmFrzsDsE1dKgoZ720W8Lm+pupaXNzYjpvn/rSxUt8vjs1mSIJ+aktVkgJ
         ObHGyWg8bbEc8qf4IMJCNxommabgakxgouAqBXF3/zYX9WuapljPGOTpM+v7NeLMHdaB
         +wdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tOlYVVLvf1bFW7DEqIy65vvXcvlYUsyO7Mq7IqL0SoQ=;
        b=xmkn7YjrBqZAJRNAJnCcZx8TFwQcqzywdVBsH7tHGlqOC9CIllFqPAeeU9yv9BLaS7
         e/3YxJA+PNADRbJrzvAwYUQoO5ww2eGzmJTVpjllrVt8i9SOQVUDWd8Gp/l376y2ictl
         eIz1OyJPndkpuxJ6Iaf/MPMVN5PTnA0+iGh5hEgwWxK4qwd4tqvk/f3rFQxRLm3S6kEr
         ptLibdCvYn4UH9wNM8mn2A28HjfksWy18ir91qameoJaHBkdq/Ye7tUbG6UUcNPmmhkZ
         1AdemU1q7xfmZu4xjerRehBVjEF5X88OdxQM2NiygTMNc04amnq0mijFX15+QP6CaID9
         cNqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQZVTGNC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id y20si511905qka.0.2019.05.29.02.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 02:20:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id n14so1335109otk.2
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 02:20:29 -0700 (PDT)
X-Received: by 2002:a9d:6f8a:: with SMTP id h10mr28904206otq.2.1559121628572;
 Wed, 29 May 2019 02:20:28 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com> <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
In-Reply-To: <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 11:20:17 +0200
Message-ID: <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QQZVTGNC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Wed, 29 May 2019 at 10:53, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, May 28, 2019 at 6:50 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Tue, May 28, 2019 at 06:32:58PM +0200, Marco Elver wrote:
> > > This adds a new header to asm-generic to allow optionally instrumenting
> > > architecture-specific asm implementations of bitops.
> > >
> > > This change includes the required change for x86 as reference and
> > > changes the kernel API doc to point to bitops-instrumented.h instead.
> > > Rationale: the functions in x86's bitops.h are no longer the kernel API
> > > functions, but instead the arch_ prefixed functions, which are then
> > > instrumented via bitops-instrumented.h.
> > >
> > > Other architectures can similarly add support for asm implementations of
> > > bitops.
> > >
> > > The documentation text has been copied/moved, and *no* changes to it
> > > have been made in this patch.
> > >
> > > Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> > >
> > > Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  Documentation/core-api/kernel-api.rst     |   2 +-
> > >  arch/x86/include/asm/bitops.h             | 210 ++++----------
> > >  include/asm-generic/bitops-instrumented.h | 327 ++++++++++++++++++++++
> > >  3 files changed, 380 insertions(+), 159 deletions(-)
> > >  create mode 100644 include/asm-generic/bitops-instrumented.h
> >
> > [...]
> >
> > > +#if !defined(BITOPS_INSTRUMENT_RANGE)
> > > +/*
> > > + * This may be defined by an arch's bitops.h, in case bitops do not operate on
> > > + * single bytes only. The default version here is conservative and assumes that
> > > + * bitops operate only on the byte with the target bit.
> > > + */
> > > +#define BITOPS_INSTRUMENT_RANGE(addr, nr)                                  \
> > > +     (const volatile char *)(addr) + ((nr) / BITS_PER_BYTE), 1
> > > +#endif
> >
> > I was under the impression that logically, all the bitops operated on
> > the entire long the bit happend to be contained in, so checking the
> > entire long would make more sense to me.
> >
> > FWIW, arm64's atomic bit ops are all implemented atop of atomic_long_*
> > functions, which are instrumented, and always checks at the granularity
> > of a long. I haven't seen splats from that when fuzzing with Syzkaller.
> >
> > Are you seeing bugs without this?
>
> bitops are not instrumented on x86 at all at the moment, so we have
> not seen any splats. What we've seen are assorted crashes caused by
> previous silent memory corruptions by incorrect bitops :)
>
> Good point. If arm already does this, I guess we also need to check
> whole long's.

For the default, we decided to err on the conservative side for now,
since it seems that e.g. x86 operates only on the byte the bit is on.
Other architectures that need bitops-instrumented.h may redefine
BITOPS_INSTRUMENT_RANGE.

Let me know what you prefer.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku%3Dv62GEGTig%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
