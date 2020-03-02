Return-Path: <kasan-dev+bncBCF5XGNWYQBRB2MP6XZAKGQEZSWOBXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA0A317619B
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 18:52:42 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id j15sf279443qvp.21
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 09:52:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583171561; cv=pass;
        d=google.com; s=arc-20160816;
        b=onWoUxTrFqAuPAHDoYD2qkBtkIYDTSHRAL3FkAo8KVIX2fyxX93O2lU+Km+zoH2Kzt
         xq4akefIF0na2hG3u+5RQRCPcy5tL1iIMIKPVgjtSr3/2si2BACnsnRDOuS8OjZLAi9I
         0ck/wmYi/FcIjAJQsgVFzfWdj52Dr9f4gKF9NKuStoYmuQROcj4wX8ymFYfgbbt9OCp4
         HlQc0nne7paNhwWmQz1MjbXpB7lUrjx/buYQMmUJvFEmX7P6uAUMozbbKOTjOQP39mNr
         fEfXiGN83BDlj5P4gojnsO1pzjFKlej+qaoI/R0NQnBs6UTXM2nmI6iQfDMkeN+ZkOZe
         6qSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=9Zz6M7X8d3g36g2fztgL7xJtgXulUSq0mAceAoKI+Ks=;
        b=EyPGodZFBKLHcfhcY1CF/+vF+J9eoHLZEDI0/0Q+SUz7nax3OLNWQK6ANPtsieg8tr
         cDafJp2W6pLKB4cp/48Ji5EIGdvq2xdJwxqJ/PkxBAmlXM3OI6DSg5DLF7yodkwYEWwu
         OPDRUe6Om4CejJ40l0JVdqJy4dAlmL6/NCd4cn7VJOcnxOGiEcVrr2hwpXkFzIyHnD4t
         An5OvE3cZ5RmbfihtTCXG7Q2J06XLCTjfivck+nXHj6VO/Ba4wn32gzimkByYCVfG8Ue
         qwq6+MlLXKEEEihhZlMFNGPQ/X4FuA3xWPsUZ67UqEBHJYuakfyfv3cQkdcPigiEd4ta
         y00g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ob7ugNbo;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9Zz6M7X8d3g36g2fztgL7xJtgXulUSq0mAceAoKI+Ks=;
        b=jtnEkwcT7gvGeIPYHT2lgKdVKNXbwhqUE039Se4XYcyPKKtF8jmXVYBDETjl92bP6r
         kn0fTbXnrByzl5fSun111umW9mx7U/gVn5eXYLMWd9qETBN+4sCMucESFVn4hatFT/Jx
         Mk1+cci+GQ9xaJhPxs8sc6louWwyMSb5ZX0GTFGg/FMPXpXuzj/K3RKf8nxPFJm75kxA
         oq+o2iK3pN6tlLRlncM+QcN7EPxvu0m0iO3wZnOz7f3gSABK0HUll/Kj4wmYNCvUqCdx
         CW5adzqu/Km3003wcdC+5AdzX92huYLvE0Xk+Ta3zkF93uR2zhNa2VjYm0IXNp/6TqE0
         OM+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9Zz6M7X8d3g36g2fztgL7xJtgXulUSq0mAceAoKI+Ks=;
        b=JNAz2HbuZm755FPbiFXh9rBZ+oJ3d0HL7heqhHn2Od9qH5EVh0iiWPkxAbzlzIx095
         fU5IDkwokTEh9MYtoRtaJWxZ+NXa7MayVeKdMCsRhkeyEK+HjEBPR4Q515/Fg7Oo268b
         dDUNWjmLPDHMufdAlvAMzcb0ZEHra58n2lEgKgD/CUizFd3BYsqK7Ymk85W6louc4SfC
         7l6WSqaGr2Q4Unno6q12EfOgtvdN8soM0y4F0LUK/kbq4N7eHrwFqxkH/xzax8yP+ZI2
         5mD+P8E1CVMK941KFnXb+QRdMGqDr0lKhfqYRjfayWZlyWQW8ln4cwiDEr/KBDgufAhL
         r6JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2NW37cnMj9TKK+ncpAxUnygNK8kfUhWt+gm8ZMWMqS5Mp+r7Dy
	VY0NvXkXfcfEX48Elfq5a7g=
X-Google-Smtp-Source: ADFU+vub4h9NcR3c5XbZV1d0i4nNfqnmHLJv0iX+2ggiq156N4BYNKn10dAsYczDeHtszkVy1h2izw==
X-Received: by 2002:ac8:6f55:: with SMTP id n21mr807532qtv.285.1583171561770;
        Mon, 02 Mar 2020 09:52:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4fc2:: with SMTP id d185ls234396qkb.2.gmail; Mon, 02 Mar
 2020 09:52:41 -0800 (PST)
X-Received: by 2002:a37:c05:: with SMTP id 5mr462129qkm.120.1583171561450;
        Mon, 02 Mar 2020 09:52:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583171561; cv=none;
        d=google.com; s=arc-20160816;
        b=0ZU627nGcZFn2Wmu8cEEq5mJ+zpAG0STu50AXtCPKssgUK/Ij3dhd68Dqa4dJSQ3D9
         a0ljKOxjbzcH558ejuW6Z1P0IXsIPxKd1AYRd8WmYEij5BCcxa6NJyDZmwgXE1Mt/yYX
         j3vqGhdQqgvpDXmYaDWj1vh6Lq45OPIqwJ7ddwWbVlwkVBK0CdNxG78Oki3Rg90+Ejg+
         9Tsm3lhNLcOJevRzBEzCvPWRuAVl2Qi4UYYsBTz8wwHbkiiW4ZXRSqTyqlL2VT9sijvG
         z84u6Syvr+jiIlY7xRGAMunrxhvnc/yNNrSc+0Ef8JN/h3ix+dTY04PW/0nbuqIWvJwB
         TYWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1IOLrEITmD2P6VvJiuWxnVZVe415X+z+1kv5oi6Hs5w=;
        b=XKcVlbMvrLXLtP2h6CVP3M/T87RUxesWuKzFPDmpvolXUfVXZmbFBsiZhKVHluhhM7
         a4Ui10CzZe5wf/x9CV7Qf7Zct47qlV1FfU6amKyYLw5YXOuYdGF94hyVlPCpMovtZi7Y
         KkyjsOWSnrN+huic7BgSQk45RZODGPeYc4QQQu0loxbmeug1TMpugH/9jDubNoLi4vw+
         vvVWbVygGzgqCpP1ZxKaI0d+Dg9MHN0YkhLFP0mMfVV/l1BiYrieRlt5TTuvVnXEtcR5
         mrXLyL6Mf2TtJlogHTcY0tLnxOo2PRDYUBStg3HMBgPLi5WST9Uh/u/uHiYKT/ufx1xU
         Vr+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ob7ugNbo;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-yw1-xc41.google.com (mail-yw1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id s202si473426qke.3.2020.03.02.09.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 09:52:41 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-yw1-xc41.google.com with SMTP id t192so604386ywe.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 09:52:41 -0800 (PST)
X-Received: by 2002:a25:8446:: with SMTP id r6mr142146ybm.451.1583171559937;
        Mon, 02 Mar 2020 09:52:39 -0800 (PST)
Received: from mail-yw1-f45.google.com (mail-yw1-f45.google.com. [209.85.161.45])
        by smtp.gmail.com with ESMTPSA id h184sm7829788ywa.70.2020.03.02.09.52.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 09:52:37 -0800 (PST)
Received: by mail-yw1-f45.google.com with SMTP id x184so613810ywd.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 09:52:37 -0800 (PST)
X-Received: by 2002:a81:3888:: with SMTP id f130mr517632ywa.138.1583171556864;
 Mon, 02 Mar 2020 09:52:36 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com>
 <CAKFsvULZqJT3-NxYLsCaHpxemBCdyZN7nFTuQM40096UGqVzgQ@mail.gmail.com> <CACT4Y+YTNZRfKLH1=FibrtGj34MY=naDJY6GWVnpMvgShSLFhg@mail.gmail.com>
In-Reply-To: <CACT4Y+YTNZRfKLH1=FibrtGj34MY=naDJY6GWVnpMvgShSLFhg@mail.gmail.com>
From: Kees Cook <keescook@chromium.org>
Date: Mon, 2 Mar 2020 09:52:25 -0800
X-Gmail-Original-Message-ID: <CAGXu5jKbpbH4sm4sv-74iHa+VzWuvF5v3ci7R-KVt+StRpMESg@mail.gmail.com>
Message-ID: <CAGXu5jKbpbH4sm4sv-74iHa+VzWuvF5v3ci7R-KVt+StRpMESg@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Ob7ugNbo;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c41
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Sat, Feb 29, 2020 at 10:39 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Feb 29, 2020 at 2:56 AM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> > On Thu, Feb 27, 2020 at 6:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > .On Thu, Feb 27, 2020 at 3:44 AM Patricia Alfonso
> > > > -       pr_info("out-of-bounds in copy_from_user()\n");
> > > > -       unused = copy_from_user(kmem, usermem, size + 1);
> > >
> > > Why is all of this removed?
> > > Most of these tests are hard earned and test some special corner cases.
> > >
> > I just moved it inside IS_MODULE(CONFIG_TEST_KASAN) instead because I
> > don't think there is a way to rewrite this without it being a module.
>
> You mean these are unconditionally crashing the machine? If yes,
> please add a comment about this.
>
> Theoretically we could have a notion of "death tests" similar to gunit:
> https://stackoverflow.com/questions/3698718/what-are-google-test-death-tests
> KUnit test runner wrapper would need to spawn a separete process per
> each such test. Under non-KUnit test runner these should probably be
> disabled by default and only run if specifically requested (a-la
> --gunit_filter/--gunit_also_run_disabled_tests).
> Could also be used to test other things that unconditionally panic,
> e.g. +Kees may be happy for unit tests for some of the
> hardening/fortification features.
> I am not asking to bundle this with this change of course.

A bunch of LKDTM tests can kill the system too. I collected the list
when building the selftest script for LKDTM:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/lkdtm/tests.txt

I'm all for unittests (I have earlier kind-of-unit-tests in
lib/test_user_copy.c lib/test_overflow.c etc), but most of LKDTM is
designed to be full system-behavior testing ("does the system correct
BUG the current thread, when some deeper system state is violated?")

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGXu5jKbpbH4sm4sv-74iHa%2BVzWuvF5v3ci7R-KVt%2BStRpMESg%40mail.gmail.com.
