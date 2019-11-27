Return-Path: <kasan-dev+bncBCMIZB7QWENRBLN37DXAKGQER5RXVWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DEBD10AAD2
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 07:54:39 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id t71sf380744ywe.14
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 22:54:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574837678; cv=pass;
        d=google.com; s=arc-20160816;
        b=e2U7Y2lrkIf1faK7MukN2w+YY1VssGvK7c9zOx+wIPzUth516j3jSO9usd96zrf+7K
         0EWfVVWhmVZv5baZakl16SV/6d4DuzY53euZO7UUfaHrwdC4P0yTw7BWphqQ4ralkEGL
         Xbkjyui9OuRjBoBT9PT1DrQtCMyGy0BnTkVyRTlLzrCRYmpnldUp3uiiJA6kZntjeWX8
         OxVV/nCOqPUjxd5b+aO2g3ev7j4ICuk/hvZ4awLN6Df9gHSsqbWsl+jkHeCYmvnD1xIA
         IpAEY8p1SUxwzH4mvcf4BbAlX+eYFApOpJZFuxFG59EuAqMuEXcwfz0slYzXuhaDrN5Q
         bOzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9ghXld59mJkFGvhZDfltjHf0In5t1wRqarVHQ6t2ErQ=;
        b=LP/zyZqgXcO7PG/zilp1BRjRf0qBYHllhx2+IqwAgLnJnwgYudn7uHJCAFqGNfTznT
         +kY4dMIDrkE3PFK+GlsZwFQrfyJhEyFBmm4NQ86tq63daBv3Et+Zj1F0VAXtD2ruIVIN
         G/8QuRlTwnTi1mFTUq7MJZ/OFZWaOBXOIVClACFBwCDowa15jS7L4cH7asVQCiHEWWQH
         c8tHsjD8Pwrxfex/IyQIaY6tg+faqJrd5/dW2D8q7X+44WlZ2ME447EWmBQL05szy7+j
         VWutDgCLtX04RFI5M7q69RwoXYMlTwkjnyYO+XKlMOAX5G2rjBMzuWq6Ejvu5EL7pTk3
         hjpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WDJzTUke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ghXld59mJkFGvhZDfltjHf0In5t1wRqarVHQ6t2ErQ=;
        b=Cb+8U7BLGlvYCqwB4TgBq4/eHGUePguWaJJ4HS8FA2iRS1grUVXSBz11uZOEsmQo32
         GmcW+gAPlm0EkAw5wPS5k3tdN5Lc0Bkv3pjHWoPfFY4P7weGaqeeivqeNJPxJRy3L4YU
         xIFTiIuAVWSKpXFFNrCLElCrxCo8zHhqgE2b4SIWaQC9V3czJ17P69clRQY1NbzxGYrt
         5fhUWm/mogqEpXmHqvgZf7YL3el4BqoTyl3Z+aT9hqABBub/FS4C5Q99gvb4JLeYT7Kq
         C4GZYFSZmKCf1u8qbzTrfo9VImSTFuZHz7fGsZymweYoHmeKBg+DhUDjN/FIvKW2gpAT
         9d6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ghXld59mJkFGvhZDfltjHf0In5t1wRqarVHQ6t2ErQ=;
        b=mX+YFw4nsA+2PPlHjH3Z0oOVCEK/N23ofO7AEldOvk3OLXo/yD04nCpUdIVC+aGz96
         ofMYznuLqPnLOMKSWPpZIeo3RJy3CGDjC7Lh/+5W2vwdtDEaHsuj/0bxqWC51wxag2fp
         Lu0YVfkrcPQLMIjy0lyLq0ZQUhN2DEpjYMBGvqVHbcicbxsRPpgM/zKpxAG796HE/Tr3
         tjjuk3Vy+bpFdqTXPtX7EGymVmTr2UjcagePOaTnGEG3egCmCTPPqstRYKvAjYsm0sBn
         7NGsnlo8BoJ/FvpF2ZaD7sUgqhchNl0M/XDXMWHVGniS/enl4zjMzpLHtt+uy1sOlWwj
         SLag==
X-Gm-Message-State: APjAAAXVHPQwgCyRpH4NC/9ID4awlYj4axbsYy1cPklKqRfNVg7aXQbc
	qcieTxmi8dUeHn/wgc7M0Jg=
X-Google-Smtp-Source: APXvYqyDSyXy2tURRt1v3StWomeY39265slGOn6+ULy+Xhdw4oXCt/LEg5FkQoVdCyGrhQYD7zfrbw==
X-Received: by 2002:a81:ad62:: with SMTP id l34mr1691082ywk.233.1574837677928;
        Tue, 26 Nov 2019 22:54:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:adcd:: with SMTP id d13ls3904179ybe.10.gmail; Tue, 26
 Nov 2019 22:54:37 -0800 (PST)
X-Received: by 2002:a25:aaa4:: with SMTP id t33mr32281818ybi.274.1574837677522;
        Tue, 26 Nov 2019 22:54:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574837677; cv=none;
        d=google.com; s=arc-20160816;
        b=iRvToFyM2CabXVmaecXPY+CSz8aQxxViLprYsCf325+6v8mx5nXX/NLEEmS1dB36J5
         ywCoYOLsT3Sqpn9aayWdB7iTzsAPHLebuYaOTLBq/MeDdagoa0HLAwkyP8F0xhhrK5WW
         21lDvzOONhmBXrfChlNmvLV0u+z1/rO8snUp3N0sNGLlHTKbVg6xgCjtsEgyDutEaH4D
         VP7yd2HOhsr7yIp4y4ulOmdHqbMllFzcQzoDaXKJP0jsjG9b8RcSxjPqdc6eNErvd4Mj
         F801fgD32/stnQoHeoghX5K9UFEML1OXItHGqU7VAWTmY4N0UaS11ReegaJSqbjt/A8l
         9EMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=legbFrQ1e9U1Xfdcs/id6e/zbRlR7gKK0zBNbirxTnU=;
        b=pbT1QWDKDVpFacSz0WRQG4tX0GIInOA5l2wcaBueiXdSAKuq9D/22RYzlDlCpGHVhg
         t9Fbxn3QPL9bBUXHx2ojv3TA+OOpAXBZ+fleiqGBtTwku7qWSgYXZfPKgfXZ6KADaGUc
         LiOzaBxF2WtdMpSBefzW5EyKYe/kV31wAZvzLBMBO3PTR5sh9TixARz8RQrkaHBuKnf9
         2oe7wRrUCsX/i3s42WcDLDIJ1BpSTmGDgRoAoHeO2OQSXav9HRP+cLf1MV5pC+0YH4w8
         CAmJyjMOu7iksVrUgDJ1jNvagmLya4ttY/IKCrwCwE0C2K4Xo7ucfaeWYQc1T25K8qBY
         iUAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WDJzTUke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id 5si567121ybl.1.2019.11.26.22.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 22:54:37 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id x14so8466800qvu.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 22:54:37 -0800 (PST)
X-Received: by 2002:a0c:c125:: with SMTP id f34mr3174396qvh.22.1574837676626;
 Tue, 26 Nov 2019 22:54:36 -0800 (PST)
MIME-Version: 1.0
References: <20191121181519.28637-1-keescook@chromium.org> <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
 <201911262134.ED9E60965@keescook>
In-Reply-To: <201911262134.ED9E60965@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Nov 2019 07:54:25 +0100
Message-ID: <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WDJzTUke;       spf=pass
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

On Wed, Nov 27, 2019 at 6:42 AM Kees Cook <keescook@chromium.org> wrote:
>
> On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> > On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> > >
> > > v2:
> > >     - clarify Kconfig help text (aryabinin)
> > >     - add reviewed-by
> > >     - aim series at akpm, which seems to be where ubsan goes through?
> > > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> > >
> > > This splits out the bounds checker so it can be individually used. This
> > > is expected to be enabled in Android and hopefully for syzbot. Includes
> > > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> > >
> > > -Kees
> >
> > +syzkaller mailing list
> >
> > This is great!
>
> BTW, can I consider this your Acked-by for these patches? :)
>
> > I wanted to enable UBSAN on syzbot for a long time. And it's
> > _probably_ not lots of work. But it was stuck on somebody actually
> > dedicating some time specifically for it.
>
> Do you have a general mechanism to test that syzkaller will actually
> pick up the kernel log splat of a new check?

Yes. That's one of the most important and critical parts of syzkaller :)
The tests for different types of bugs are here:
https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report

But have 3 for UBSAN, but they may be old and it would be useful to
have 1 example crash per bug type:

syzkaller$ grep UBSAN pkg/report/testdata/linux/report/*
pkg/report/testdata/linux/report/40:TITLE: UBSAN: Undefined behaviour
in drivers/usb/core/devio.c:LINE
pkg/report/testdata/linux/report/40:[    4.556972] UBSAN: Undefined
behaviour in drivers/usb/core/devio.c:1517:25
pkg/report/testdata/linux/report/41:TITLE: UBSAN: Undefined behaviour
in ./arch/x86/include/asm/atomic.h:LINE
pkg/report/testdata/linux/report/41:[    3.805453] UBSAN: Undefined
behaviour in ./arch/x86/include/asm/atomic.h:156:2
pkg/report/testdata/linux/report/42:TITLE: UBSAN: Undefined behaviour
in kernel/time/hrtimer.c:LINE
pkg/report/testdata/linux/report/42:[   50.583499] UBSAN: Undefined
behaviour in kernel/time/hrtimer.c:310:16

One of them is incomplete and is parsed as "corrupted kernel output"
(won't be reported):
https://github.com/google/syzkaller/blob/master/pkg/report/testdata/linux/report/42

Also I see that report parsing just takes the first line, which
includes file name, which is suboptimal (too long, can't report 2 bugs
in the same file). We seem to converge on "bug-type in function-name"
format.
The thing about bug titles is that it's harder to change them later.
If syzbot already reported 100 bugs and we change titles, it will
start re-reporting the old one after new names and the old ones will
look stale, yet they still relevant, just detected under different
name.
So we also need to get this part right before enabling.


> I noticed a few things
> about the ubsan handlers: they don't use any of the common "warn"
> infrastructure (neither does kasan from what I can see), and was missing
> a check for panic_on_warn (kasan has this, but does it incorrectly).

Yes, panic_on_warn we also need.

I will look at the patches again for Acked-by.

> I think kasan and ubsan should be reworked to use the common warn
> infrastructure, and at the very least, ubsan needs this:
>
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index e7d31735950d..a2535a62c9af 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -160,6 +160,17 @@ static void ubsan_epilogue(unsigned long *flags)
>                 "========================================\n");
>         spin_unlock_irqrestore(&report_lock, *flags);
>         current->in_ubsan--;
> +
> +       if (panic_on_warn) {
> +               /*
> +                * This thread may hit another WARN() in the panic path.
> +                * Resetting this prevents additional WARN() from panicking the
> +                * system on this thread.  Other threads are blocked by the
> +                * panic_mutex in panic().
> +                */
> +               panic_on_warn = 0;
> +               panic("panic_on_warn set ...\n");
> +       }
>  }
>
>  static void handle_overflow(struct overflow_data *data, void *lhs,
>
> > Kees, or anybody else interested, could you provide relevant configs
> > that (1) useful for kernel,
>
> As mentioned in the other email (but just to keep the note together with
> the other thoughts here) after this series, you'd want:
>
> CONFIG_UBSAN=y
> CONFIG_UBSAN_BOUNDS=y
> # CONFIG_UBSAN_MISC is not set
>
> > (2) we want 100% cleanliness,
>
> What do you mean here by "cleanliness"? It seems different from (3)
> about the test tripping a lot?
>
> > (3) don't
> > fire all the time even without fuzzing?
>
> I ran with the bounds checker enabled (and the above patch) under
> syzkaller for the weekend and saw 0 bounds checker reports.
>
> > Anything else required to
> > enable UBSAN? I don't see anything. syzbot uses gcc 8.something, which
> > I assume should be enough (but we can upgrade if necessary).
>
> As mentioned, gcc 8+ should be fine.
>
> --
> Kees Cook
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/201911262134.ED9E60965%40keescook.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg%40mail.gmail.com.
