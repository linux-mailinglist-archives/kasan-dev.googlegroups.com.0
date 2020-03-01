Return-Path: <kasan-dev+bncBCMIZB7QWENRBP5M5XZAKGQENYSQ7NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 67EAA174C0E
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 07:29:20 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id z39sf6325218qve.5
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 22:29:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583044159; cv=pass;
        d=google.com; s=arc-20160816;
        b=w9+58YmWON9W/XWmXGyn7r/YCsKJH5lI7ZA1Fbsx0kwkjGraSX/kuhW+qaCD6Zf5V3
         BxNiiH3jJKeufVWy2zbQ8VJezNlfQu49q45izvly9gk15dQeBPiFkIUgdHu5kVd2Qkti
         Zc8dbyP/G9IwNrUxgCcWx+JrnQ6cFL7d7Ma/oyxWbG7o+k9iWvAZwW5FL4n19wP2iN99
         ot7OpoUo6vHl18VOp9tl/jlz+aKY1gKJ5IeroksEEbRjTq4TggXE8SI675pMYEF9trM6
         hofWktg9Wepc6qbJd38pu9YOv2nzVf2s3Tl/0nPkffi2uRNpSNBLjiyTr8CYlvHXw4qt
         k+6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D81PPHQCLkJCrraC1gPL2jAfvHtYyBxBwe00zniiJyM=;
        b=q4xaFWNFulPtTYfh8F0qF8/5DasSZEfUSd/qu2khqeWd47BhokEDcaQ5LdLlqTMqbm
         H2svbfdVu050rTVzsrZ5RTi8n2XC4pQZxMmF2o56djyYJXP7fzJGHAMyGhSakqrmV98k
         4QM9wwOKhd46zE0lHgSFvZqr8rj4xHIiFq7o6b1+zYbhJJKLy+po5b+91GFqpCwkTsyK
         5cKyX183lg8cI6N1T0Wmnuts6icXKO/ugYlNUDkBeCAhsWI5vMyUEcHuUCckez/EAyvX
         0pPRfph5jpLr0AJimWS9izYhe09lYnRtMmOoKnuCogezCwgLDHmFWPAgUChEZ66n5ymi
         jJRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pCSbN2e3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D81PPHQCLkJCrraC1gPL2jAfvHtYyBxBwe00zniiJyM=;
        b=fAhDtd278rmV7nsx8Wn8z40rHCYjGLPLbwobgDOb0zmagT0YJPcL9VTWmOoIHFURSX
         sVX5mCpgkiyWKOb7es8aDrVwx3IRSxPxVJOyH6Qq+BbLalCyb7+Dr+8v6SZOTCLMZ59j
         5DFHTCi8VBgUs7LYXnLQaaxGbCL10e9rtF6jWrhiEaIYnukfSWhEOC1xhj0Kl+2Cbv5d
         qSQ1WzEXa7+nKsJ7DWPqQovYqwyCiA0FGhyYphMB7/JcoeJQDxBAMepUR/pP2+V5APdm
         tY2nO5VCHWa6dbyNliRcgfOWc4Hp82650kBoXtcfMpyz26WcdjQdVzZNIBw+VT5yHpke
         7chQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D81PPHQCLkJCrraC1gPL2jAfvHtYyBxBwe00zniiJyM=;
        b=QT7YDtTDe6rUPAArEJR1KxW6i9iEpEJjxIHLM/v3kW6prVLDP7Lw6df4rnzbBn8+ZS
         71lTW9UaVH69tthJVE+QOTp+aaXxxbEWchVM+RJ5MFxQFni8IX98koYeMKtN7/BHjR0B
         MhSqRLGIGTBu6fDpYsgh1qXcoRvEM1PkU++fASg2iKm0UcCzTOVmVzk4KBbl7QROqVcK
         But5rtMFuvFT5D7dol1XbhDFyg5tbry9MBQZUWl45aUMbnjvTy+RZTG5Q6bWh21bCC44
         IS/xyG689G/FHf97SHZjXK0ii1roWBlIS6iPwkoAYO9/vaA9wIFc7bOn2cRRCxEvKdsC
         VQRQ==
X-Gm-Message-State: APjAAAXkWLHc760uB5rpscdai3WFdcyU9VCTz7j69zUrHJ8WNtF1APL5
	ruQ5d7WC3Xii2RtXB5sBBp0=
X-Google-Smtp-Source: APXvYqwzbsYhw7npo/8x+6v9f4EMG2PvNgTSXSEf8zp0NL2leCMK9nJkGJ6TRr++es2FmXOrGnEnyQ==
X-Received: by 2002:ae9:e115:: with SMTP id g21mr11357403qkm.83.1583044159295;
        Sat, 29 Feb 2020 22:29:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3479:: with SMTP id v54ls3039882qtb.3.gmail; Sat, 29 Feb
 2020 22:29:19 -0800 (PST)
X-Received: by 2002:ac8:554b:: with SMTP id o11mr10934629qtr.36.1583044158984;
        Sat, 29 Feb 2020 22:29:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583044158; cv=none;
        d=google.com; s=arc-20160816;
        b=WaqUQGh0rOcLsgGo7lw2KcxcVYfyi/NVK29A3NNo2dfgmQbcvx6OteNdhB1kvBQ7Bd
         y4QMHNu/AibNFqQJw5HMRVJGdtjXutPx72VWB1wwVzq6Ve3nK6uYGYF4hKA42eIjiv2C
         H9u4SThd0TJftFci2YI4vTSBxd9bDHtqaj1BAopHii9RpRp9m/gzlR43ENqwSsitwnZ5
         IdNAeNuGKCOSIzavwibAR6yHZk5LT863qzJIdN6B/dnRD2jqglD03FnzipW9ii01WnCu
         2IcGS3a2PxXi6OQkCOvDDVgxr+EAGFH1v4zNP+ZxbFA8Da+TYnyeZrkfiex6xn+pzPJK
         OLjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UfUac2pOIQmqTpyyGG2W9XwtOZbpDu9LEjx7cpEyrZg=;
        b=tn7jUXVKX35hgcijVzk1f2CzEBdBJE8ywa1j/fAowO8dHCxmXRbPWVaVI97DXwzpHD
         yFFcNkJBAOJ1cNr0zXx/rquRrZEe4pxbPp3G50jlzTgFuM8EI9toI9Np+RjRJ/FMMDsC
         KxQfXOjLh9nJdjyozS3Vly0nrWZSzxF0mBZsNvRsH3zWT7fOTDFiq4MKyB24GCsIEp2F
         11cVcexAE+QUnoEYQEzxfq4okFJkX/5l8vy7pg/FToto2bUsqyfy3ATqjBZAngovQuXA
         NGsdLlzl2AaFihjly+OUQb8Jf+eQZWdhED1eSe6EPF8+t9FPLVkW47D1LZ1iQDr8iCvq
         K7Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pCSbN2e3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id 23si446621qks.6.2020.02.29.22.29.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 Feb 2020 22:29:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id e16so7123215qkl.6
        for <kasan-dev@googlegroups.com>; Sat, 29 Feb 2020 22:29:18 -0800 (PST)
X-Received: by 2002:a37:88b:: with SMTP id 133mr10838393qki.256.1583044158382;
 Sat, 29 Feb 2020 22:29:18 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
 <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
In-Reply-To: <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 1 Mar 2020 07:29:07 +0100
Message-ID: <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pCSbN2e3;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Sat, Feb 29, 2020 at 2:23 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
> >
> > On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Integrate KASAN into KUnit testing framework.
> > >  - Fail tests when KASAN reports an error that is not expected
> > >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > >  - KUnit struct added to current task to keep track of the current test
> > > from KASAN code
> > >  - Booleans representing if a KASAN report is expected and if a KASAN
> > >  report is found added to kunit struct
> > >  - This prints "line# has passed" or "line# has failed"
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > ---
> > > If anyone has any suggestions on how best to print the failure
> > > messages, please share!
> > >
> > > One issue I have found while testing this is the allocation fails in
> > > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > > does cause the test to fail on the KUnit side, as expected, but it
> > > seems to skip all the tests before this one because the output starts
> > > with this failure instead of with the first test, kmalloc_oob_right().
> >
> > I don't follow this... we don't check output in any way, so how does
> > output affect execution?...
> >
> I'm sorry. I think I was just reading the results wrong before - no
> wonder I was confused!
>
> I just recreated the error and it does work as expected.
>
> >
> > > --- a/tools/testing/kunit/kunit_kernel.py
> > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > >                 return True
> > >
> > >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > -               args.extend(['mem=256M'])
> > > +               args.extend(['mem=256M', 'kasan_multi_shot'])
> >
> > This is better done somewhere else (different default value if
> > KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> > Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> > to be a mandatory part now. This means people will always hit this, be
> > confused, figure out they need to flip the value, and only then be
> > able to run kunit+kasan.
> >
> I agree. Is the best way to do this with "bool multishot =
> kasan_save_enable_multi_shot();"  and
> "kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
> was done in the tests before?

This will fix KASAN tests, but not non-KASAN tests running under KUNIT
and triggering KASAN reports.
You set kasan_multi_shot for all KUNIT tests. I am reading this as
that we don't want to abort on the first test that triggered a KASAN
report. Or not?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY-zoiRfDWw6KJr1BJO_%3DyTpFsVaHMng5iaRn9HeJMNaw%40mail.gmail.com.
