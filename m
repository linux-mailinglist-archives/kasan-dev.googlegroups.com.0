Return-Path: <kasan-dev+bncBD52JJ7JXILRBRETWGPQMGQEGT5I6OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 42703697493
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 03:56:06 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id f16-20020a5d8790000000b0073dfed277b3sf5486581ion.16
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 18:56:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676429765; cv=pass;
        d=google.com; s=arc-20160816;
        b=fE/BzEPlZiU2kPtyoeWEZilYbvOMfoNvxChNGGZ9TSt9yO5xnSW24NGeEcNDm4qacv
         Mn9NJsfh2G1ahvdimkQADwtiVd3y2MZceAA0aYC/P2YX+qCdRCnawVE/32Z/nF80vSoW
         pbypxNtGUvGsDYfkyakB0lguhjm6+6DFGP4gSLohYEw0S4Z/rPvuPBT10MY4ROo6bI84
         WClZjNnyH1JYLeDg2J/Nz31APTcPUeyW7E2X8hMd3AbQn/lBr2A4VKwA667B4uPRVAT2
         UC2oherxWpNcxlSYNOkykn9rAR5vozz+FLntKfTKhrpX/kRmW9PMelTY/imH5dKRliaQ
         Iwsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mml9Yq5xbB/cicb4eIOs3YKVj93cVh+WrCPl5D5miyk=;
        b=o/UmmkeDMfH7K8BPN6onXM0olEjwnNO/EuUOOhd+f5KUWl1gWapYNuZFB5fMj7katP
         xIvQ7r6Q8Uk4qZrJnWg2iKP2WpEBWy1I0YAVnL9H7yBYAdyNy+4BaGATmYFOweyj6z7V
         guZclAfZ9dpG5IfFiP49UAjYTrQoSdGd/qPOYdhJPx3Gn+2TS05X0pijKMVjpOR3Bx8T
         e9AeY2IHfcRcM+3rgT79cyVEKZnSS29acfbbks/iqDKDhL6Pa8/jAQ8dqB4kRs2je4Hn
         16M31sDv3XPu/i5vSQMxkuD7VOScucpaUmb5fzmOJYNd857TT/aDdLfETQhSntkf0yY6
         0gLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="A42/UHca";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mml9Yq5xbB/cicb4eIOs3YKVj93cVh+WrCPl5D5miyk=;
        b=iRxtaHT82kSYD4TdQAQduNgNRarjkuGJk9Fv2nxE+Sp7wVU9abZpVnzggwKtSHu6e/
         djTkYHLSyvkrMX4XJ/DbRWluPiIfTLYXq2AH3x084PcELgXYWfPV+Y5hdEZjFvD4Rk9i
         S7uGC5cyRf9ArKRwDdXzmW/v2Xvc6oh8ndnQ89fONuJB7qh1a05EwOLe5kItdRWV/Mmx
         Fue0d61ZdQzKXT1VBg5cMVotYC6Za2hd0Ru/CFeO8qBMHVUDbgMfsRw88uu9gSW2QIYQ
         4rvdNNiQJg8AMr7iHl+SnsAFfdJROMfWN7KgGfrbUTmHqNJOiX1YT5KApqhaDS8hTmPs
         BVCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mml9Yq5xbB/cicb4eIOs3YKVj93cVh+WrCPl5D5miyk=;
        b=FFCqoVg8Twbosjm4aylX1VKyJ4GkC6zN8DVMafGmnCFFtm+2wytIRKnAu4nG+nR++w
         kEci5faXL37fzSe1jU7qYuRDu2LaojbV39czIEkJKkn9lMWvehKk2oWF5td416fUmMm6
         OqEXpDgPrSEXiFc34UQgLQvv/3wJHZikqDPajgEHvRGkRhXgybRIdzmhq1AZPCd+VHA3
         kNs/wLshgAcmdY2TF0BxpThDTtUZfMdFwcRuqepARfAuK4SqdYoD6qn+0xaF6/jC4hED
         rsnmHMOHvErmyK1vBRDXaz5p5cJwUK/crgbdD6Nb3o7T5DuLRo64CWv63K586m/7Di0O
         GPeQ==
X-Gm-Message-State: AO0yUKV4bEA/g1NUBPdzGzIYJsYrfK78YyC4d9GcW4gkgCI2gWo2lTle
	geGmQwBbVk6CF2L6zcpPj3c=
X-Google-Smtp-Source: AK7set9Zikwp1ZXOV2D7VqStpwrfLIAmEr/p44M0cdI28fDuywxUJHo7lQu0XVMe4A+WQI5Bi++08Q==
X-Received: by 2002:a05:6e02:1a25:b0:315:3277:f05c with SMTP id g5-20020a056e021a2500b003153277f05cmr694089ile.0.1676429764792;
        Tue, 14 Feb 2023 18:56:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2907:0:b0:314:1891:45e5 with SMTP id l7-20020a922907000000b00314189145e5ls5772346ilg.5.-pod-prod-gmail;
 Tue, 14 Feb 2023 18:56:04 -0800 (PST)
X-Received: by 2002:a05:6e02:1baf:b0:315:56e7:7f39 with SMTP id n15-20020a056e021baf00b0031556e77f39mr936901ili.2.1676429764203;
        Tue, 14 Feb 2023 18:56:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676429764; cv=none;
        d=google.com; s=arc-20160816;
        b=D2RxYCm9EfYwg/r6RqGI1oYr7EEpM6rHaMEfMYMd17g46HHLzrRaoFTi/cjpVSmHNa
         mNqX8KZsIWAmCWGfOzW9skmTxXMABwGscREsIz+qwnNjv8Nq5WxdosfLGWJ7T62UNGXD
         BJ++Ws92fMPmz5BtRhVzqf/brzLS6pPsZ6vQY31BUggDkjW7Gsyno0l3ay0CxFpV1d++
         j39/J8gyG2k1jQJuRX88TNpo/IVeedUqOP+A8vQ9hWsnFzKBipltOvwDeqApPCW4uWz3
         bqJVus+RPg7hRA1j59Ud2nVqYjYlV4HReazA3wpLEKYMAkCzmnEOcRbWT4f/SLahytuH
         9fxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AMRBoKkOIVB/WviH4IgQy3fBGZ0k4cThtcao32eLZ1A=;
        b=e15UTC4xpuYC+fP0S4+jQj0isXjB/h6uhYxM0aK/blZIpMEYsZ7EP4CSEw2DXsM8Ja
         FF5hYD7tGtxbzAK8in8fKg2tYRxIYJoMZptgHLCpNHGYhmguhqCwLjxkJ1RroP/ul5tQ
         qAWl7qax/H6sZ+tcsi189QPxtQGVVo/Pw6ORZMMyZ8mba6xvEbayrxO6X/J09ak59inM
         TGQIUbkr7LnrkZv/8g/9rvoZ9pCkmUQVtNeXvm7jrLpWaQCD6BSQPqiWgtzlSsBPjRf+
         2EyBKXrVnfUxSoqHzg7n0JhgH3ZE152F/C4kiIYR/mR9/swXnUCGqz+ip2VL8QAfZ0Fx
         /YHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="A42/UHca";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id s13-20020a056638258d00b003c2b55913f9si2337202jat.3.2023.02.14.18.56.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Feb 2023 18:56:04 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id h5so1209221ilq.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Feb 2023 18:56:04 -0800 (PST)
X-Received: by 2002:a92:8e04:0:b0:310:9d77:6063 with SMTP id
 c4-20020a928e04000000b003109d776063mr267413ild.5.1676429763604; Tue, 14 Feb
 2023 18:56:03 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com> <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
In-Reply-To: <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Feb 2023 18:55:52 -0800
Message-ID: <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="A42/UHca";       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::133 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Mon, Feb 13, 2023 at 10:08 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 14 Feb 2023 at 02:21, Peter Collingbourne <pcc@google.com> wrote:
> >
> > On Tue, Oct 18, 2022 at 10:17 AM <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> > > to console tracepoints.
> > >
> > > This allows for two things:
> > >
> > > 1. Migrating tests that trigger a KASAN report in the context of a task
> > >    other than current to KUnit framework.
> > >    This is implemented in the patches that follow.
> > >
> > > 2. Parsing and matching the contents of KASAN reports.
> > >    This is not yet implemented.
> > >
> > > Reviewed-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > ---
> > >
> > > Changed v2->v3:
> > > - Rebased onto 6.1-rc1
> > >
> > > Changes v1->v2:
> > > - Remove kunit_kasan_status struct definition.
> > > ---
> > >  lib/Kconfig.kasan     |  2 +-
> > >  mm/kasan/kasan.h      |  8 ----
> > >  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
> > >  mm/kasan/report.c     | 31 ----------------
> > >  4 files changed, 63 insertions(+), 63 deletions(-)
> > >
> > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > index ca09b1cf8ee9..ba5b27962c34 100644
> > > --- a/lib/Kconfig.kasan
> > > +++ b/lib/Kconfig.kasan
> > > @@ -181,7 +181,7 @@ config KASAN_VMALLOC
> > >
> > >  config KASAN_KUNIT_TEST
> > >         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> > > -       depends on KASAN && KUNIT
> > > +       depends on KASAN && KUNIT && TRACEPOINTS
> >
> > My build script for a KASAN-enabled kernel does something like:
> >
> > make defconfig
> > scripts/config -e CONFIG_KUNIT -e CONFIG_KASAN -e CONFIG_KASAN_HW_TAGS
> > -e CONFIG_KASAN_KUNIT_TEST
> > yes '' | make syncconfig
> >
> > and after this change, the unit tests are no longer built. Should this
> > use "select TRACING" instead?
>
> I think we shouldn't select TRACING, which should only be selected by
> tracers. You'd need CONFIG_FTRACE=y.

Doesn't CONFIG_FTRACE=y mean "function tracing", i.e. function
entry/exit tracing using compiler instrumentation? As far as I can
tell, the KASAN tests do not make use of this feature. They only use
the kernel tracepoint infrastructure to trace the "console" tracepoint
defined in include/trace/events/printk.h, which is not associated with
function entry/exit.

I have yet to find any evidence that TRACING ought to only be selected
by tracers. As far as I can tell, TRACING appears to be the minimal
config required in order for it to be possible to trace pre-defined
(i.e. defined with TRACE_EVENT) tracepoints, which is all that KASAN
needs. (I also tried selecting TRACEPOINTS, but this led to a number
of link failures.) If select TRACING is only used by tracers, it could
just mean that only tracers are making use of this functionality
inside the kernel. From that perspective the KASAN tests can
themselves be considered a "tracer" (albeit a very specialized one).

If I locally revert the change to lib/Kconfig.kasan and add the
TRACING select, the KASAN tests pass when using my kernel build
script, which suggests that TRACING is all that is needed.

> Since FTRACE is rather big, we probably also shouldn't implicitly
> select it. Instead, at least when using kunit.py tool, we could add a
> mm/kasan/.kunitconfig like:
>
> CONFIG_KUNIT=y
> CONFIG_KASAN=y
> CONFIG_KASAN_KUNIT_TEST=y
> # Additional dependencies.
> CONFIG_FTRACE=y
>
> Which mirrors the KFENCE mm/kfence/.kunitconfig. But that doesn't help
> if you want to run it with something other than KUnit tool.

In any case, I'm not sure I'm in favor of adding yet another config
that folks need to know to enable in order to avoid silently disabling
the unit tests. Many developers will maintain their own scripts for
kernel development if the existing ones do not meet their needs. It's
possible that kunit.py will work out for me now (when I looked at it
before, it was useless for me because it only supported UML, but it
looks like it supports QEMU now), but there's no guarantee that it
will, so I might stick with my scripts for a while.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO6reT%2BMTmogLOrOVoNqzLH%2BfKmQ2JRAGy-tDOTLx-fpyw%40mail.gmail.com.
