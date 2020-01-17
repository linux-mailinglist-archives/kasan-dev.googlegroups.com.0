Return-Path: <kasan-dev+bncBCMIZB7QWENRB2MIQ3YQKGQEQU6SNJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BBB51406F9
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 10:54:50 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id g6sf15239006qvp.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 01:54:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579254889; cv=pass;
        d=google.com; s=arc-20160816;
        b=isMTXAC91UYbNWwsrOYiCwkIyuJFO7fgLrC/PfYyRAxHYDm7P7Outr6B/2jY0ZaVmu
         1xkxDB6SWM4fug7Y1bRdFL2CXJ+Pl8Ed9koRJOmbDAYsZdRj8JmdpUU5r4gX46G4XXd6
         F43+0iDy09jbqISUxMq0lxSJmpX7sTmybxkqOpQgvSX/yQBRRdseSYK81phBWG+wz5Gq
         1W0ZpHQK/LxDisu/BCkYnkdFODlNTNmOVs8HaI7Ecno0+Dissa8t+2r2PPuqvfs3vWe7
         k/U6nwy7hAQ3rm9sDwGyohUVDjQn/AUrCU2hqQyjL8tnnMyfU0NVy46tMzMzUHSd0t/Y
         GgVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MsyQyikrudP62oOq/O2OMoB/NnPXqtnQw7V88vOe8Aw=;
        b=A+tmim0p2UquaxH06MoJZ5HLah5OaDFTFGYSFzRr3DH4Yx1XJ6ArBabsd0LHwGpWuM
         CHQDF12Lg3I84TH1TPGFvw+ZYusWxxsS/FNeQ4J7S/1y5VpUVVbFR7NAKR1BshqHtlY8
         xUhcySylU5j9s3KQ9CTR4ri5RzPL27nJ3QbgjNstm7sqxsWh+T3sNe8SWbDEOUQdedsk
         pt0Mgq9/NYiloEAb6zQVxWfANxNN86AAdQ+DFkKMXOMofDiXx7fLLqi07+ql3gPJeUbV
         +62JjSjQyAF/PIyk1yo8P0nI+fB0gGWTR9Q0iSMm3QYXFKY6AtLpbg76kwXN/e13epoS
         WQiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=My897psD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MsyQyikrudP62oOq/O2OMoB/NnPXqtnQw7V88vOe8Aw=;
        b=gqybPN7xVGJ4yyxh9MuzvdZnJ2pKB9MyhWOOcefwwAzxiBhdFejx3mAzGTJcvLFjBw
         JHNHjbFhxhuF9f55epgnGGKG6usfP5WWuG3fWmuYp/9wv4mDOFUyUQ+tCQAQ4Epcnl12
         Cjbl82SR7Bfl5tVIbyUdgggTMKoNYG+7mFVaCYXaqTeFqQxIDdk2iqTJQajPCwcvS57v
         JaIikh67ue1WDgUXbKwTzmm9x5cmLQ87QP7gbVM3Z/AuVBWr2UfAARJJri8/5jFrQwCw
         3tyzGxnCoZeadXO8bxuvBdFgMxrMN1+PhKOxXWPKupMDwfuAZvRSPvHtc8bpSLIjQLl/
         h2Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MsyQyikrudP62oOq/O2OMoB/NnPXqtnQw7V88vOe8Aw=;
        b=uFBCo0gKWlNWFcNUPapZF5nLXq0nhYT77zxUGGkjyHgwKEH+ZSnWscO3QupX8Tp8rI
         vMuyMjSaKwspWpQBDVTiS9CBLxup/2IefoFOd5AMOsTqAsXTlQI4m0mDnL90iPQnt9Ag
         ap+aYGm2diPy+00YuSrtk9qyf8SXlAf8DhsclJ0Io5a1meI1T6ANi96Y6wvvp5vF/uA/
         NHroLnGTn2EeUx/gM9UYMA86UZaxLjczgiOMs5Ah2wxGxLHIJ9oOTNHpqc68hJ+fzbOt
         8AKU4d25/AumZou4Pj/2U8lhffOGxDxk5l8N3OhluCmrYdk+OTlBQg14y3rbv/uwgM9a
         VxZw==
X-Gm-Message-State: APjAAAVGqGq6G6BEe7Y1GRmfcZ1IWoMB0EjcEjvGSskkqeasf1NrXfZn
	rO1tprfkQvUO69+Ql0SsyPg=
X-Google-Smtp-Source: APXvYqw9HAi4JXIxL7YkDgnUotZ7MrfGnQ3Y55d9FL3dxKGwTexiMK9Wk8D0iqd07XH/ds7Nr25cGw==
X-Received: by 2002:ac8:6787:: with SMTP id b7mr6207336qtp.213.1579254889108;
        Fri, 17 Jan 2020 01:54:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e506:: with SMTP id w6ls6508908qkf.12.gmail; Fri, 17 Jan
 2020 01:54:48 -0800 (PST)
X-Received: by 2002:a05:620a:5ae:: with SMTP id q14mr33457051qkq.437.1579254888797;
        Fri, 17 Jan 2020 01:54:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579254888; cv=none;
        d=google.com; s=arc-20160816;
        b=IROeam691tj86Nb10cJn/2iHxn5vLrnxkVO/31u2OYq6xdcsIWdr3JSDBSLef4Dq7c
         GOi5gpqLRAXDolPA/7D8qw7T9Zn3We3J0pAqgeRgJx0LuD7/4gvHFsu5xHeQ3hlzBkIF
         ++3XPPmjYfLHkTWLw6WntUl2mC3teoclXs4uKq/z5XnDK+QGqentalworE00+um3UyPh
         MOC9/h3V7YEkWMDlFyiaFZMlApEgWR5zXfvIJLbfKu41PLy8LgJzlEhtArRqzvLp6Pz7
         tfwS0fHrowADglNl/zJ4dqSURYg5rUCejwr3zLA/1yYCgAIYMHNiiLDt1RQos8ocmQhS
         jX3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9kFTYGfEs/9SAwkwxZ+xsP/qfPJbE8uiwbZB2GtkwYs=;
        b=0/udT+M6uZa7ng6l2qTRdyHzjZoSt2fdVIVuDUGwIwiB/1+825nF6V2GRjsQyXvl7P
         vk9r9xy7060taukgrd0x4HR91BLQpx+b7YF3NW7MTZbJaZhu15QGxdaMugMVA+peQ/pt
         DNDTBodUcsSDDRv/3sEKNVCY7SrxN9yPXsmx7GNxQlwVl14sv6QGBI46QBTbf/AP/oAA
         7tDTR0oYlRGNXZciLawk7aoJg4+ZmJJAL/jxfEMvQzc6J4EdOccHmEX6AOUaXZIv1Lgy
         pFFkpMVxuomGQsXjx5eMAzz6ZE8XvVrvKow1W6BM1s8/qw5KYflV1cCwQEcjwzfaUyKD
         tT6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=My897psD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id r62si851747qkc.6.2020.01.17.01.54.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 01:54:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id t129so22081503qke.10
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 01:54:48 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr37884710qkk.8.1579254888242;
 Fri, 17 Jan 2020 01:54:48 -0800 (PST)
MIME-Version: 1.0
References: <20200116012321.26254-1-keescook@chromium.org> <20200116012321.26254-6-keescook@chromium.org>
 <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com> <202001161548.9E126B774F@keescook>
In-Reply-To: <202001161548.9E126B774F@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 10:54:36 +0100
Message-ID: <CACT4Y+Z9o4B37-sNU2582FBv_2+evgyKVbVo-OAufLrsney=wA@mail.gmail.com>
Subject: Re: [PATCH v3 5/6] kasan: Unset panic_on_warn before calling panic()
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Dan Carpenter <dan.carpenter@oracle.com>, "Gustavo A. R. Silva" <gustavo@embeddedor.com>, 
	Arnd Bergmann <arnd@arndb.de>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=My897psD;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Fri, Jan 17, 2020 at 12:49 AM Kees Cook <keescook@chromium.org> wrote:
>
> On Thu, Jan 16, 2020 at 06:23:01AM +0100, Dmitry Vyukov wrote:
> > On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
> > >
> > > As done in the full WARN() handler, panic_on_warn needs to be cleared
> > > before calling panic() to avoid recursive panics.
> > >
> > > Signed-off-by: Kees Cook <keescook@chromium.org>
> > > ---
> > >  mm/kasan/report.c | 10 +++++++++-
> > >  1 file changed, 9 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 621782100eaa..844554e78893 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
> > >         pr_err("==================================================================\n");
> > >         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> > >         spin_unlock_irqrestore(&report_lock, *flags);
> > > -       if (panic_on_warn)
> > > +       if (panic_on_warn) {
> > > +               /*
> > > +                * This thread may hit another WARN() in the panic path.
> > > +                * Resetting this prevents additional WARN() from panicking the
> > > +                * system on this thread.  Other threads are blocked by the
> > > +                * panic_mutex in panic().
> >
> > I don't understand part about other threads.
> > Other threads are not necessary inside of panic(). And in fact since
> > we reset panic_on_warn, they will not get there even if they should.
> > If I am reading this correctly, once one thread prints a warning and
> > is going to panic, other threads may now print infinite amounts of
> > warning and proceed past them freely. Why is this the behavior we
> > want?
>
> AIUI, the issue is the current thread hitting another WARN and blocking
> on trying to call panic again. WARNs encountered during the execution of
> panic() need to not attempt to call panic() again.

Yes, but the variable is global and affects other threads and the
comment talks about other threads, and that's the part I am confused
about (for both comment wording and the actual behavior). For the
"same thread hitting another warning" case we need a per-task flag or
something.

> -Kees
>
> >
> > > +                */
> > > +               panic_on_warn = 0;
> > >                 panic("panic_on_warn set ...\n");
> > > +       }
> > >         kasan_enable_current();
> > >  }
>
> --
> Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ9o4B37-sNU2582FBv_2%2BevgyKVbVo-OAufLrsney%3DwA%40mail.gmail.com.
