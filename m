Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75UZD3QKGQE52LAVHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 25EB220557B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 17:06:40 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id y12sf5704563uao.13
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 08:06:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592924799; cv=pass;
        d=google.com; s=arc-20160816;
        b=WWbWu8knVzZv0M5oRNfpUT4q9WLzufF25Z/VwPJWfCChkIis+yrIXBt/bPFt1Tx56O
         BAsyYrjjWSqnLYzrvJh55UnkX3HfV07am+MpHY3XrBNDzEjCjKbTn7SfVBuXWHq79ZTB
         rtvMApJc1itz4mDNPHpxPW6PeBWKrTWzKJ1dxNn7/+PWXJYE43yUO+3aj11rwWplf2nq
         8NrQri50b2TMPjRbNNBcyfrvOUGOmCDJmuAoeU+kQzkJg/fq3iZ/rtrWXAdU98QglR2i
         txyfMZNyNwdzgHEVdqF7qaAv9wrcP79dSkd2jWmwrh141LBSizWLmUHmf13gS4Q7qnHi
         Hj8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0MP2UGZrYdgqyAGpLCwmO0pPiIiMyTQEhfFhjuAHFsc=;
        b=Zu+et02Irfjbm70M5xOmt9+0yHbZ17tIL/SnVTlUF8lXzFSGM7/2azbS1RkEpsMDLi
         EOF4UTRmETzVkB32nTWkvaaIdVqh21Ce7HdENJrCyCmiyCijSiXbTZvzGyst/x+5hkUp
         ld9msrwVtEu2AWPL3oQuShWtU3p5Ia0RgpZ3g/UwUCEASLpPA5f9Q2gFOiSBsC93G8C/
         5e/8azoeHdiSpKm9fJm+yPYwaiyN3Go4tAXLLH5u9yfiaDThYvbzgb1hcFOX0KqReKFY
         cv0K9t+lmYdyakVUdJatHlR1Tj9o22kZ81fY7iyhye5QMxcZ1q6MrP8yrdH+0o7JQFWE
         Pz4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FbKnzvpx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0MP2UGZrYdgqyAGpLCwmO0pPiIiMyTQEhfFhjuAHFsc=;
        b=HZjpzvqw9GkXwIT9xigsTCIIsjSdpybWkf/VTOjN40XIRqV1OnU6glbZb+qQMNaCdU
         BkhSnBvAh3eIQXOhtRHmQ+pS/rVCIkfMVFNUEBlMjxS/WRvetSMCIPJ1X8AM9mcDhybF
         GRnrIkN3h+JAYRVoMj8BjvzfR2IU7ve+P9BWwCWYnsAa7B7IB1iQKc6ekQe2JFI+OHJT
         Ftj3djKr6Ea125Q1hk3szn5FY9uT6XpRbFeQBNupFVGasCsHjN9xDUFZRfehBHH/GX8L
         G6kuD2HHYKC0fEiUwD2OhJxzYHn3ZevyA5ikufi4SYJR2+AZb6e8QPKD5ECNY+Efw7XO
         Kuzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0MP2UGZrYdgqyAGpLCwmO0pPiIiMyTQEhfFhjuAHFsc=;
        b=sqNH2xkga1QaDOSArqpzjBzGoFoZU9kXp4bkoyEckKL8xriB2Ls+0Pw2nxpgMdIVll
         /T8wSdsYE60JY5ZSUb7VCO2/eMbijpA6hI1l+h2xVXz4Bk8tz+IBJ7z8afVnWDbzlZRh
         yO4PnF4Wirh/0QhXo2FuSHcc5YIh+QSNBFIsx7zGEDkM6/I+bBULkOBpafto4nFebppo
         DnVnxd1vvSAfV30DVDwv8ei2SFXbgOHwcMU7Gp8swop/Cr+wkPrv4g+AhSjdsRk/A3Gx
         LvVAlROVialW5MrLwK66aGbZW37knqs6twzujKb2K0bFncyDechKoBZ6LKnNpxe012HN
         HzHQ==
X-Gm-Message-State: AOAM532b3eHKRwQWfrmVobYL3U1b82kJdUHpvx65kVV01V2z7MOg+V02
	uC8dV3BlA9+B77UitSqxS3I=
X-Google-Smtp-Source: ABdhPJwLtBo9z85FgzfIt/jA6QjJ+ibbJYg33LdWW099nHFHAESJ4KNojUEufN0VNqePG0iQXZatMA==
X-Received: by 2002:a05:6102:802:: with SMTP id g2mr9195654vsb.142.1592924799142;
        Tue, 23 Jun 2020 08:06:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9c01:: with SMTP id f1ls973469vke.9.gmail; Tue, 23 Jun
 2020 08:06:38 -0700 (PDT)
X-Received: by 2002:a1f:9946:: with SMTP id b67mr19834742vke.100.1592924798803;
        Tue, 23 Jun 2020 08:06:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592924798; cv=none;
        d=google.com; s=arc-20160816;
        b=CcA7rCmgkcmeVlzFxNUNsU20oVKa4hJ1vNs5Om/f6tcJ5uWly7Kw11oNA0i0Zb5nPj
         jTgZgMDsgN9nesclfoWq6PnEQ4ulN7x4RNFSlQ5ONAqF7OnPqjyJkhomSqbVi23rUfzN
         /hKVNp21GuhTMOrcFAIwRYhmMW04aTIqcOTqjYXu91Ui8OceHx9c6HAHc8pE6LMqzF9K
         OQg0jlbfdWdigTypSZUxRcHF5hdMwoGfx0XNjLUqgg67dutKrD2C76KA9W28sLTSS/QR
         m8pMiP/J+4e4A8uANBNSu00cvzQsNrsndHkYz2BB4qyQ+SOgniIzJ8kP5OYFBfvgT1KS
         HUVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=30jZZJyoCOJi08Aubf0/SfjQqMuFLP8B24XJpfK0XLQ=;
        b=ebq0sxKVYTx8CuflesDHFWBr9WLcij1PREEYt3JLdcjM8K+PGGA4O8lLcq1G0Tswaw
         HWsgUurf++z6D8HpPCswTgajn05KmpXiNdHYmDNkBLPW5TQT+q5NBCX/GWWfojLkqxGt
         GHVo+Hh7MQSnuatOy1jNQGgbL9t4sqi/p7wBVGwtk03S7nuoL8XXi78ZUVIHZpoaakBR
         UvtqOW42idjnMjZp51VTE825KLiOAfZf1MyHVPxN4iQkiwB5sEPNlJ0ChWjjSzLs6xur
         8f0F2V/wJn5NtoeRytfizH2r3JZCAv3zAqf4uavlZF7k9p8HX3WoBapVmmcAvAu/zGOj
         vaxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FbKnzvpx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id f12si917748vsr.0.2020.06.23.08.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 08:06:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id p82so8346437oif.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 08:06:38 -0700 (PDT)
X-Received: by 2002:aca:1205:: with SMTP id 5mr16939378ois.70.1592924798097;
 Tue, 23 Jun 2020 08:06:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200623004310.GA26995@paulmck-ThinkPad-P72> <CANpmjNOV=rGaDmvU+neSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA@mail.gmail.com>
 <20200623134309.GB9247@paulmck-ThinkPad-P72>
In-Reply-To: <20200623134309.GB9247@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 17:06:26 +0200
Message-ID: <CANpmjNO_2N5PB6MOQqEgpwNKmTtLrSNcY+-a2fVncESyjuO=Wg@mail.gmail.com>
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel-team@fb.com, Ingo Molnar <mingo@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>, Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FbKnzvpx;       spf=pass
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

On Tue, 23 Jun 2020 at 15:43, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Jun 23, 2020 at 08:31:15AM +0200, Marco Elver wrote:
> > On Tue, 23 Jun 2020 at 02:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > Hello!
> > >
> > > This series provides KCSAN updates:
> > >
> > > 1.      Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
> > >
> > > 2.      x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
> > >
> > > 3.      Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
> > >
> > > 4.      Add test suite, courtesy of Marco Elver.
> > >
> > > 5.      locking/osq_lock: Annotate a data race in osq_lock.
> > >
> > > 6.      Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
> > >
> > > 7.      Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
> > >
> > > 8.      Rename test.c to selftest.c, courtesy of Marco Elver.
> > >
> > > 9.      Remove existing special atomic rules, courtesy of Marco Elver.
> > >
> > > 10.     Add jiffies test to test suite, courtesy of Marco Elver.
> >
> > Do we want GCC support back for 5.9?
> >
> >    https://lkml.kernel.org/r/20200618093118.247375-1-elver@google.com
> >
> > I was hoping it could go into 5.9, because it makes a big difference
> > in terms of usability as it provides more compiler choice. The only
> > significant change for GCC support is the addition of the checking of
> > (CC_IS_GCC && (....)).
>
> Very good, I will rebase the following into the KCSAN branch for v5.9:
>
>         3e490e3 kcsan: Re-add GCC as a supported compiler
>         03296de kcsan: Simplify compiler flags
>         d831090 kcsan: Disable branch tracing in core runtime
>
> Please let me know if any other adjustments are needed.

Looks good to me, thank you!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO_2N5PB6MOQqEgpwNKmTtLrSNcY%2B-a2fVncESyjuO%3DWg%40mail.gmail.com.
