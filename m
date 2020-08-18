Return-Path: <kasan-dev+bncBAABBNUC6D4QKGQELOVFI2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55D6A248B89
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 18:26:31 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id z1sf14752996ilz.9
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 09:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597767990; cv=pass;
        d=google.com; s=arc-20160816;
        b=gp8e9umJTwvKFau4DKVfPS+sPKEZ7HuYW9p/gG2ELcUNAWE+SghKutat27cSXlzW2h
         cF37bnkRIWYXRlGkKP47cCenFr19L6YWf5s7Zo2GGy2dQ60qVctGI3uaBTsh/sQdv+FL
         UwOptmQtBdzus1ULT7jmXoJZxympVj3dxHx6mwGtDW89R8dAXd3zTsRxRD9DCBO5TmZt
         FG7Gp8rbmYxowOFnuKKia6NinkTny40GogimMNeE1s6eRhgIsi3DU9IAyEbP1d4M1Uhf
         ILaG1WGu0r4HlFf/nRoRwy0ugRB7F7NI6+Zxaa+r6U3pJTdrsL4Tcg26P93bogf+hKhW
         vFUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=qkM4lJ5SM84zCTwtycr5AyeRdlK00Ym2tzoVeSpf6UE=;
        b=gDc1B5b4+yn4iKdvGlV84yDyHLMe1pQlmQ5IlqEp9litBR2YKXCp3Vdzt/hbnaLSCM
         QvjLzg9hWh9j/LWajquEhdXyiToAvHdRx9jl2xNmKN5sI1/MzNuen2RvnB7iZHlp/YGf
         /u2sgc0sIOTf/JFaWC6wsKuY+Krj4JHnT8eGtT/11PjbkU7vwNnrD0udpPhmbA7JjlsV
         4J1TLB4Hk3zxUvYD4BxLzpoJLe8CVSvWbRoLn3Kv/nz/5h6OFx/c8LoY1s7A91wUnoTK
         3JveCwWMtftvfkvnZCsberTGOhrvVqtzUEyeeGayyKdnqsAknkw+rEBn8Ddb2vzkhCQj
         Re7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Reyv3GJb;
       spf=pass (google.com: domain of srs0=pqwx=b4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PqwX=B4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qkM4lJ5SM84zCTwtycr5AyeRdlK00Ym2tzoVeSpf6UE=;
        b=BjfX+xSwMk8YUoABMamQKA2kqwWOpXaNubGKzGqK/HRhSoTS7LFIEgBs4aVb9nC6x7
         exAfF16fXL+Xs3L8a/DE8brLKFDN8Wlg7TzqB5EONxv1FTHtBo5jCrg1NY7dIUlN53xx
         xxTs+Yv/a1MD4w2V9ooMSlwf9/KuTKg3/qOScZKasT6/fKBbpTG8pDKm43DoexQ9zSp/
         DlwB/Tpxu0rdMqbE7mWJMFcNQwBRZ8/LlPwvNmxGOl1aUbbiFB9k2iFfNrM+Z4zTcwcJ
         Q/9YS6sJEWKVoFQVT5lhyjLwg2VdWyaJrb52QZeEnQaNTsqUrim3SEEckC+83h++3T8T
         cb1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qkM4lJ5SM84zCTwtycr5AyeRdlK00Ym2tzoVeSpf6UE=;
        b=MKDJjDTVYzfcG0Pgk8TY57nrjbB2ETlgHuz1U0x/se3jAGaG5TJlV5DA3QWsQCNwif
         YArdz8VhDgydoeymYg/AtLzu6rNUh1duLGsb8Ivkxo3rPI9z8mMftYnVEOHtL6L5hiRt
         SZCibOKfu9DTOOhNiQpT8xiqbxE2npOTgmzb3vLYL5kesD79TZT8jPg48+crLXSU9SSg
         rwVWswRgN6k/tpnZQJ4PgQd9jtl3cohmYjH3W6EqLtnMipMQpHuDEk28X47fVcffh9oS
         VqZeuf4yknvCnVSFLHJabKfwhyHT042pzAMNPayN/RWTFzGhHNsuEyqMH10qtpeJ4OnB
         t7jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330NQpH4QgTp7p+fdFP3F/P6gaCBfdfjvSP6huWPCa0Ni4eZfYm
	zk85ldrAO3LVyybaL/Vp8x8=
X-Google-Smtp-Source: ABdhPJyOsT2XvPbRPbxD2lmwr8Xlc1kHPHWTDjdT/rRgj1CZ+G1pnDqMoOVyZsL4Nc8pQsSPACwrrQ==
X-Received: by 2002:a6b:c8ca:: with SMTP id y193mr16951092iof.62.1597767990288;
        Tue, 18 Aug 2020 09:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:8d10:: with SMTP id p16ls3271442iod.3.gmail; Tue, 18 Aug
 2020 09:26:29 -0700 (PDT)
X-Received: by 2002:a05:6602:26c1:: with SMTP id g1mr17096146ioo.10.1597767989832;
        Tue, 18 Aug 2020 09:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597767989; cv=none;
        d=google.com; s=arc-20160816;
        b=Y4PN7ZviFbKi9P8CnMVY+jVSNA/p2x5ODQYHGmCtqkFyOKdI/Uq40pO33lng/yNSGB
         AvnuV3TMa6dsiBN4ZBJ8mUidIbInK0NfjjRH8Z17ZdJUnUMxLFWtUEhDE6e3sPU/2TaT
         bFEfQyL38afjimwaHGP8IPzDdB0vnKU5X/U9Qob1qZbapeuSqNIv8I7R7IR/cyj71BI/
         Wv0oB8wgSQ3Zd9/4AMYZmTlvZb0o5xrjgl8J2aAI4XPp+2oNyuMDR+OUPJidxhoWVThS
         7InM9iII5fn6IEtOJA1AxnWeVWvs9CzsICVYJDlXtItca+31yPFTkX5ZrqXTG/yhR4n8
         aAHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=XSDfqCIibTXJuViNjXM/j6PL9nsPJ0ACoqEmexwpKYI=;
        b=pYVYaz1bya5c/5jnQHGdeK+aHQ6Qi4aqPtaET8HbqIMf5nnGOFRbVaxsV7kSFJa6OX
         eQ4qOTREQcYlOi/H+7dLrmAdu26ECtEwvmZAekX+mVfo376WtjWdCzBzwh0yL0Azko3U
         ivcElG0M7MbSlurQCkYla/RUEwEAbrMnAFHDAmM1oDbC2fL+sNGjiV2U4BGfIuw6FJaO
         nULXFlUjj7e+Ud/LPnKSNrOtb9JfGWUCTA759eis5wEZl5/rage74timHMg7sJkJkQK8
         UGEtc4eWFFdTiSqZ2lJCy+zHtmdqNkwAHgop3HIZXo48rFUOr3zLJrB1j29yCNXqjcPg
         LsgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Reyv3GJb;
       spf=pass (google.com: domain of srs0=pqwx=b4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PqwX=B4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t6si1107175ioi.1.2020.08.18.09.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Aug 2020 09:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pqwx=b4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 048802067C;
	Tue, 18 Aug 2020 16:26:29 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D84E535228F5; Tue, 18 Aug 2020 09:26:28 -0700 (PDT)
Date: Tue, 18 Aug 2020 09:26:28 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] bitops, kcsan: Partially revert instrumentation for
 non-atomic bitops
Message-ID: <20200818162628.GG27891@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200813163859.1542009-1-elver@google.com>
 <CANpmjNOvS2FbvAk+j8N0uSuUJgbi=L2_zfK_koOKvJCuys7r7Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOvS2FbvAk+j8N0uSuUJgbi=L2_zfK_koOKvJCuys7r7Q@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Reyv3GJb;       spf=pass
 (google.com: domain of srs0=pqwx=b4=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PqwX=B4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Aug 18, 2020 at 10:34:28AM +0200, Marco Elver wrote:
> On Thu, 13 Aug 2020 at 18:39, Marco Elver <elver@google.com> wrote:
> > Previous to the change to distinguish read-write accesses, when
> > CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
> > the non-atomic bitops as atomic. We want to partially revert to this
> > behaviour, but with one important distinction: report racing
> > modifications, since lost bits due to non-atomicity are certainly
> > possible.
> >
> > Given the operations here only modify a single bit, assuming
> > non-atomicity of the writer is sufficient may be reasonable for certain
> > usage (and follows the permissible nature of the "assume plain writes
> > atomic" rule). In other words:
> >
> >         1. We want non-atomic read-modify-write races to be reported;
> >            this is accomplished by kcsan_check_read(), where any
> >            concurrent write (atomic or not) will generate a report.
> >
> >         2. We do not want to report races with marked readers, but -do-
> >            want to report races with unmarked readers; this is
> >            accomplished by the instrument_write() ("assume atomic
> >            write" with Kconfig option set).
> >
> > With the above rules, when KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected,
> > it is hoped that KCSAN's reporting behaviour is better aligned with
> > current expected permissible usage for non-atomic bitops.
> >
> > Note that, a side-effect of not telling KCSAN that the accesses are
> > read-writes, is that this information is not displayed in the access
> > summary in the report. It is, however, visible in inline-expanded stack
> > traces. For now, it does not make sense to introduce yet another special
> > case to KCSAN's runtime, only to cater to the case here.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Will Deacon <will@kernel.org>
> > ---
> > As discussed, partially reverting behaviour for non-atomic bitops when
> > KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected.
> >
> > I'd like to avoid more special cases in KCSAN's runtime to cater to
> > cases like this, not only because it adds more complexity, but it
> > invites more special cases to be added. If there are other such
> > primitives, we likely have to do it on a case-by-case basis as well, and
> > justify carefully for each such case. But currently, as far as I can
> > tell, the bitops are truly special, simply because we do know each op
> > just touches a single bit.
> > ---
> >  .../bitops/instrumented-non-atomic.h          | 30 +++++++++++++++++--
> >  1 file changed, 27 insertions(+), 3 deletions(-)
> 
> Paul, if it looks good to you, feel free to pick it up.

Queued, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200818162628.GG27891%40paulmck-ThinkPad-P72.
