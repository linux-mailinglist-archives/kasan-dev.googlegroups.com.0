Return-Path: <kasan-dev+bncBCMIZB7QWENRBLX2YX2QKGQEAZQCVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D07D1C59FE
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 16:50:23 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id n28sf1113239vkl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 07:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588690222; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zu9BY4xd9Zwvc3vQ4eFFhXRDl0L5DisrFuoG5LzCebf/OhlmDmiL1LT5yNmPObRJGd
         W+iM+DNHF3uGwjGtNvGoIixbi364KNoX+8PC27BlFCWZpmublQOBSXdiGWZvRebXjDmF
         0vWAqc58cbGUVb4CTyePDUqCJUZj16EdkSctlj1Bj6rTgQXbn6UDm5BSPikiHbLifLmd
         T4FPPKzLL0bCODjb7QVIY2pBhejdXjRCotD4y3Ax4Xk/lXXs3d4zSLjkjhMZcdke1Yze
         vM2f/N7Go9op/aspFr7DDao5iqjtuCETyRABqYqLoV2Lom+iVonrLcp/Pk6bXNTgdO3r
         R2aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MQKsD1GtA//o9T00XnUcoaN9L77he6+SCaHC4VFO3JU=;
        b=DTmkMTJoPYqeqYP723/7HNw+gL7nNsvEe5bX38wCOStPly+T38nQdykT93g6ncnOdB
         YyZcM4Ra7gcR11B/3m50fDWPiLC1zuJeW0WH4iyKMV8+5bdgmlDFQaX5HmiCj4sikje6
         xM+wRl4gyX95NjJv+TxFLiSTsS+/Qtk6iMPI3vDm5Ggp9roYbR7DzaBHrpGtwwAPFSgI
         wH/531r9iQ8GcjnMWOGoUDlJu4EjYXSp5wxnaNSxBX3FZXzyNFxhGEZTbARVG3dwQWTF
         UrAajN0f8mBddDmwJRjjyywQWBujMDAjwclwT4eRxbpev+xMyurpG0QFI63nqKxPYmSb
         2L/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zxm+Rr7l;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MQKsD1GtA//o9T00XnUcoaN9L77he6+SCaHC4VFO3JU=;
        b=TLQyp3u9Mwq2rG4lQZ6x8Eq1j4qOAm1cWfXTWjJykKPxyvTDGC+n7szPk7RyGn+v2G
         WMuT8kr7l8vPu3PRd54Zbwoiv3tSgIXxx12xWGi89M0YqqhTDPjrtJkprVIUXzXNnvYt
         VnUZoPtbsC3aM3LcRgKsQvqV4rPxTTGz+t1CNuUx5uDpuMFvhwjLEfXayUJZUR6ul0UT
         O9DewH0OfiIPkk1Pav5ID+YfIyP8w4eWasNMc3vW4ipdQHs1+X+vHoDEy+UzpLDaNoCB
         DO/r3TpRW76O8K3lqOgyuR+vHAeZ++mbVKcHqG8gmUwwYW6Lg9q8sYAHMSi0k+rqAN14
         3ZzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MQKsD1GtA//o9T00XnUcoaN9L77he6+SCaHC4VFO3JU=;
        b=ps/l7OyQEGjfmeYU41jsPFNuw5BmkEDQCE9UuGYbHbxCav0wpA64V/39Z1MZd/y4Qy
         YViDL85fBBtCfxl7/9Tm/bo2nQ07PtKDoTdcUDx/q8tTEfTGmyBoQ5FOwU1gAz5cRep9
         A51xR64Lqbvx/9u+BYVY7o000wscNatcKHOI7queR9xGE6VBvNTJlgWLc9+zyL2SYFtu
         rjQunJ4yedr1yTR/kQ9xRViI4d9+2v/eZcehm4pewJ7H/WC9KW7eMCUKnBOIDRt6Hobv
         B3gKT1ljyCm/8hE/u3d2xR8aVykqyUHeWYh6NP+bUoZDhrQoMTdr+WmJ8hfBnIdMcUnq
         FmOg==
X-Gm-Message-State: AGi0Pub84XkuIJGmWjwScxHmU5NAUPvIdgjzc7a0uh09aOnLOHEPKXAV
	db4ZCFUa4PC2nkBQqDf7/Ec=
X-Google-Smtp-Source: APiQypKl1yfEHs/FbK4j8C2mltYbJ+O6lsAFVCxKYHfPnSXpxk3d1pPIiV6pqt2qD2LpnueHsjHPUg==
X-Received: by 2002:ab0:142f:: with SMTP id b44mr2476577uae.113.1588690222293;
        Tue, 05 May 2020 07:50:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7f86:: with SMTP id a128ls346769vsd.8.gmail; Tue, 05 May
 2020 07:50:21 -0700 (PDT)
X-Received: by 2002:a67:fa50:: with SMTP id j16mr3382328vsq.44.1588690221883;
        Tue, 05 May 2020 07:50:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588690221; cv=none;
        d=google.com; s=arc-20160816;
        b=1D4kuPbQRvGJ/sq7KPpaoHTE+RYF1FHes7imKr0hv7jHgDR4n7InGsv+AtMVmUzmiI
         /bX+8hgV1HwgQ7Pvl7kXWuRzPUZw8TfB2W6ahjergQmJF1qYpFWcvfZPTdGYOn6UUA34
         telAsyNciwEng++AsDQTWhiwYR+C6FR13vTnmiModugTsGsY/l0gcxVMMzTtqk3r7NOQ
         AFmoaqQJKhQvTokf92Iino5FUZIIezDg0pMELdYVQ75GeISNRJjm/RkwfCF8m6+QvC1w
         7ATZra/jVE9CUuScA25SAp1EkViMamwfyTejQRgkCgTn8ndkoGpjxR89walAKYHL7Gkg
         W7Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7Pq81uf2psyNx4BKzdHn/TmsDqiXEasycTFHLZy0fzE=;
        b=OezIqCvJfjb9FtIsO8EWCCxS6dAG1ANtvduGEcOxTkGHjFi2RIBaW1od7lyCcram65
         5VhtXUi8aMYr6CZ+hqnGu4X/Wm9Q+xPj2COXiSuhonTFHrVv3JUQJm17+G2pARa+zvxu
         RZqDBa1XNBX5lR6kMZC2ULG8pUfus1Ki35NbSTLbB+IMx2ZeiejGgdFxOS54vHFZn1CK
         +BUiZ54RHDITW6+a63/VDmJR5pN8wGGUPOhDQtl/74rkh44DvEvbOxjjlPnxkxRQpBZM
         sWW2eeCKreYrAe9XdYM/gHH9oD3bzxhsNs1fEg88o+w/L1Qc4/B6xBTlk8K3OiuZEkeZ
         yG/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zxm+Rr7l;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id s64si212724vkg.1.2020.05.05.07.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 07:50:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id t8so1109156qvw.5
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 07:50:21 -0700 (PDT)
X-Received: by 2002:a0c:f8cf:: with SMTP id h15mr2976751qvo.22.1588690221148;
 Tue, 05 May 2020 07:50:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de> <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
In-Reply-To: <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 16:50:09 +0200
Message-ID: <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zxm+Rr7l;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 5, 2020 at 4:36 PM Marco Elver <elver@google.com> wrote:
> > Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> > with -fsanitize=bounds or with ubsan:
> >
> > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
> >
> > To avoid that case, add a Kconfig dependency. The dependency could
> > go either way, disabling CONFIG_KCOV or CONFIG_UBSAN_BOUNDS when the
> > other is set. I picked the second option here as this seems to have
> > a smaller impact on the resulting kernel.
> >
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> > ---
> >  lib/Kconfig.kcsan | 2 +-
> >  lib/Kconfig.ubsan | 1 +
> >  2 files changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index ea28245c6c1d..8f856c8828d5 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
> >
> >  menuconfig KCSAN
> >         bool "KCSAN: dynamic data race detector"
> > -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> > +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
>
> This also disables KCOV with GCC. Why does this not work with KCSAN?
>
> This is a huge problem for us, since syzbot requires KCOV. In fact
> I've always been building KCSAN kernels with CONFIG_KCOV=y (with GCC
> or Clang) and cannot reproduce the problem.
>
> >         select STACKTRACE
> >         help
> >           The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
> > diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> > index 929211039bac..f98ef029553e 100644
> > --- a/lib/Kconfig.ubsan
> > +++ b/lib/Kconfig.ubsan
> > @@ -29,6 +29,7 @@ config UBSAN_TRAP
> >  config UBSAN_BOUNDS
> >         bool "Perform array index bounds checking"
> >         default UBSAN
> > +       depends on !(CC_IS_CLANG && KCOV)
>
> Ditto, we really need KCOV for all sanitizers. I also just tried to
> reproduce the problem but can't.
>
> Which version of clang is causing this? I'm currently using Clang 9.
> My guess is that we should not fix this by disallowing KCOV, but
> rather make Clang work with these configs.
>
> Dmitry, can you comment?

FWIW I can reproduce both with clang:

$ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds
clang-11: warning: argument unused during compilation:
'-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]

$ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
clang-11: warning: argument unused during compilation:
'-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]

with both my disto's 9.0.1 and fresher 11.0.0
(7b80cb7cf45faf462d6193cc41c2cb7ad556600d.

But both work with gcc

$ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
$ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds

Is it a known issue in clang?

Can we somehow disable it only for clang and not gcc?

This will immediately break KCSAN on syzbot as it enables KCSAN and KCOV:
https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZpp%3D%2BJJedhMpunuUh832eJFu%2Baf-r8631Ar0kE2nv72A%40mail.gmail.com.
