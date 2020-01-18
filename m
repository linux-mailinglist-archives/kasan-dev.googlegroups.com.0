Return-Path: <kasan-dev+bncBCMIZB7QWENRBHM3RPYQKGQE6R2AM3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C891416BE
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 10:19:27 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id t12sf15858721pgs.13
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 01:19:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579339165; cv=pass;
        d=google.com; s=arc-20160816;
        b=EcpGCiyDFwc5w3zh6gqXBRQP6iaK5y2R9ZVWUVSu6F2rVjtPu6m4YUWLzPiULfb+lR
         MSCg2F2bYn5VEaKFgAcSe7nWqyO3OB4fjc2KjPWGaWQzj1n+6s/jTbiKV1f72ofFYZV1
         LFOr433K1t7fmyaVYZTpOYukAGayN08nP7vekfJ+NRQoj+v5eOQ0LU2iGDCih/baXM18
         bJUL+A4GEm6se8BX3KlEnuY3jZo1YNNPzxWRdjLF2YUEjrzCkWeLqqdWtcd1Ig2EZR8/
         cBR8gcLS8yXt7eFo54yUYFEcI2+XdPnbx8xvyIcfJCRik8/CRf251gqEFtpaUis2uhls
         qAZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0Qf/Fiw6XsmS8oX1RUZ4TPBHEtZwHKORBh6cIvbFyA0=;
        b=msTfeUy49EEmA5YQm1HqcWa1FdtheQuOACxy6hh2zZv6qdx0oLpoc7wUT7jGt9gPa+
         ct7e7DL8ju542lOdL9zEPp8XTEc7FLSEjqERA9ea/zJlHxGQny6emOGO+nTG4P3FiOjM
         2CMTojEjTHwxGQkLbi//KbO2cyALOBlrTDEalHcz+z4uuq9l5w5pE5GEmR7DKpZsBeOC
         XAx1muFhPoRf+efY5b2rWqgyMpprGVQZ2HYOt6d4HChXIlSahSAZ5ugS+YJtRiE9cxHW
         HVXQ9kzafb0XdTJLfuwnfVB3W5IHQLGwfhSFRngLmR418xkPveleLqAfZZjPptHAqWN1
         O9yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r5Osyi+5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Qf/Fiw6XsmS8oX1RUZ4TPBHEtZwHKORBh6cIvbFyA0=;
        b=K7Zsw46GLzpZnpG205ejZ9FHd8m3r0VSjWiZo228roP0P3WfVGGwvW5LtOoevLIYCZ
         EvTWGJz33nnc9eyAM2jLm9PwPM6kDH/1FYEiH4Mwa5iG8zBTxsn3b63sLMUU11gJkVtN
         J4DSzjXRdA18FvrSi3ASR5MMp3LHHnedOld9qc9E7U3blWNVGEtuENj2oM7uhhH6+aee
         k3uiBO8/NYTobQhdUVR+mUu/jEpjBKwE1ev5KDNsz0ytedmR0qAGv/bUjbj1TQI5Mi4U
         HHaSu9TT5tI174aCvbda1gcmSDke9l85vsD0+EowaBacQIp2jBnAtfgsFjv0rvjDwiXU
         59Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Qf/Fiw6XsmS8oX1RUZ4TPBHEtZwHKORBh6cIvbFyA0=;
        b=AkHznbFK0Th3a1PcovqlotYK4aV+ltL9yiR6lV/NBqkZk942DKIsYwnCsuvbqljVCL
         DerpYxxc29tSrUpPegyIqFAHnImojiB93Q0bQbvVMgTW5MwdQ1To53jHTf9h/uLcY/xV
         A2apuK9hOrNRhHbiKKdtHiOKp0MWGsLAe1yzPINIAYePuhU4SW7DzeSE07AvzaX3+mqz
         /z8ANItXA58WmV8jnMKain5YtyXJyJeJ9pkAu10r3YZ7OGieBN6j6kOfTR/fs4QQDKdl
         xi91oVx120vLS34Uppvmt8lm12lwvaZv0Gd1LWD1bAC9b9BwL1HYRRhYFDdrrzfFSOtf
         1JlQ==
X-Gm-Message-State: APjAAAWf3p1v+wiBlQI4vfJHeS+ZTdpY220CZQi6MgL3NZzOLt2AMInF
	zK9XW3idW56daRZ+aUOyZak=
X-Google-Smtp-Source: APXvYqxXrn8UC5inXiBzwxkLfyWo8mpeZgkrUeibj2I913zFvYP3uS/43l1MGK6xms1YGBZlWY1WUQ==
X-Received: by 2002:a17:90a:8b84:: with SMTP id z4mr1224073pjn.1.1579339165467;
        Sat, 18 Jan 2020 01:19:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9887:: with SMTP id s7ls5499539plp.9.gmail; Sat, 18
 Jan 2020 01:19:25 -0800 (PST)
X-Received: by 2002:a17:90a:c243:: with SMTP id d3mr11155747pjx.124.1579339165087;
        Sat, 18 Jan 2020 01:19:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579339165; cv=none;
        d=google.com; s=arc-20160816;
        b=K6fNPURI6jNQvdlNlS3WL5vheZKallNu9E35kjItBE0aML3QKhl6NncpZCMYpxnJMv
         f13Kkezs9sBa7MkuXBAMFnop+k1upg+NMIVNcDVBQEH6fi07ujkP3P/N6ntlfkC8qvoh
         /rLS00ic1ko6HoF+Fu3b4B9lYpTKiNC6q5bN4BYgr4dPH1ah1/83Mk1+QnV7MZ+FXKyB
         n/Jq6V4QFhM4ekLZQohBFdX0sq/xUJLX2NmR6pDTxYVm9MZKPlJHP43ylWqxwjYWVn7v
         r3xnvX8/OU2juiolBlXZuxV+ML4iqv+daEV1ugkBk5GA+U0uUMxhum0xrQdNjSlv/nFI
         WRMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z7V6E0TDaKraOo9dTt7jhc6TLdoMlUlp/uyIAC+ZTcI=;
        b=YTjxH4encFaehfYUBRJ/EGQvb/DbsMB8LiVpR76FNnxAZUlk3xRgRRRrcjuGWvGefk
         ZgoyNsarTHEsrkl4UOMnXiam2KTLVbBrHNc7mzyyyfh/wThmC5yihXvbL0AsPQ5Wkkmz
         TqOUdyPsUaBFfoGUaBKYQtLhOMY/BkUZO4pNS+dnLCMiu6huNtTKR1zYfAkM2hzVEaXP
         hrDKkG3rcCN1rKsqcugFSoxW03Qr9S+ApMnqwc7Y1MFgo2ESJpBwcxKMWQnIcNIQqQeC
         dSzm4ZeL7CK4lvPG+JmustvrG0nAXRNVLHIsiMyomv6ONB7Emm8gQO/wStHnyUnw1b0W
         256w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r5Osyi+5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id 186si26773pgd.5.2020.01.18.01.19.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 01:19:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w8so9360297qts.11
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 01:19:25 -0800 (PST)
X-Received: by 2002:aed:3b6e:: with SMTP id q43mr11061878qte.57.1579339163936;
 Sat, 18 Jan 2020 01:19:23 -0800 (PST)
MIME-Version: 1.0
References: <20200116012321.26254-1-keescook@chromium.org> <20200116012321.26254-6-keescook@chromium.org>
 <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com>
 <202001161548.9E126B774F@keescook> <CACT4Y+Z9o4B37-sNU2582FBv_2+evgyKVbVo-OAufLrsney=wA@mail.gmail.com>
 <202001171317.5E3C106F@keescook>
In-Reply-To: <202001171317.5E3C106F@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 18 Jan 2020 10:19:12 +0100
Message-ID: <CACT4Y+ansnGK3woNmiZurj1eGfygbz7anxRqYe_VPs-_HE2u6g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=r5Osyi+5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, Jan 17, 2020 at 10:20 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Fri, Jan 17, 2020 at 10:54:36AM +0100, Dmitry Vyukov wrote:
> > On Fri, Jan 17, 2020 at 12:49 AM Kees Cook <keescook@chromium.org> wrote:
> > >
> > > On Thu, Jan 16, 2020 at 06:23:01AM +0100, Dmitry Vyukov wrote:
> > > > On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
> > > > >
> > > > > As done in the full WARN() handler, panic_on_warn needs to be cleared
> > > > > before calling panic() to avoid recursive panics.
> > > > >
> > > > > Signed-off-by: Kees Cook <keescook@chromium.org>
> > > > > ---
> > > > >  mm/kasan/report.c | 10 +++++++++-
> > > > >  1 file changed, 9 insertions(+), 1 deletion(-)
> > > > >
> > > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > > index 621782100eaa..844554e78893 100644
> > > > > --- a/mm/kasan/report.c
> > > > > +++ b/mm/kasan/report.c
> > > > > @@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
> > > > >         pr_err("==================================================================\n");
> > > > >         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> > > > >         spin_unlock_irqrestore(&report_lock, *flags);
> > > > > -       if (panic_on_warn)
> > > > > +       if (panic_on_warn) {
> > > > > +               /*
> > > > > +                * This thread may hit another WARN() in the panic path.
> > > > > +                * Resetting this prevents additional WARN() from panicking the
> > > > > +                * system on this thread.  Other threads are blocked by the
> > > > > +                * panic_mutex in panic().
> > > >
> > > > I don't understand part about other threads.
> > > > Other threads are not necessary inside of panic(). And in fact since
> > > > we reset panic_on_warn, they will not get there even if they should.
> > > > If I am reading this correctly, once one thread prints a warning and
> > > > is going to panic, other threads may now print infinite amounts of
> > > > warning and proceed past them freely. Why is this the behavior we
> > > > want?
> > >
> > > AIUI, the issue is the current thread hitting another WARN and blocking
> > > on trying to call panic again. WARNs encountered during the execution of
> > > panic() need to not attempt to call panic() again.
> >
> > Yes, but the variable is global and affects other threads and the
> > comment talks about other threads, and that's the part I am confused
> > about (for both comment wording and the actual behavior). For the
> > "same thread hitting another warning" case we need a per-task flag or
> > something.
>
> This is duplicating the common panic-on-warn logic (see the generic bug
> code), so I'd like to just have the same behavior between the three
> implementations of panic-on-warn (generic bug, kasan, ubsan), and then
> work to merge them into a common handler, and then perhaps fix the
> details of the behavior. I think it's more correct to allow the panicing
> thread to complete than to care about what the other threads are doing.
> Right now, a WARN within the panic code will either a) hang the machine,
> or b) not panic, allowing the rest of the threads to continue, maybe
> then hitting other WARNs and hanging. The generic bug code does not
> suffer from this.

I see. Then:

Acked-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BansnGK3woNmiZurj1eGfygbz7anxRqYe_VPs-_HE2u6g%40mail.gmail.com.
