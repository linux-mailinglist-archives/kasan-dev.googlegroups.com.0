Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6GT6OLQMGQEH2CZNLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AF256596F4C
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 15:15:37 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id i12-20020a05610220cc00b0038a83e3bb42sf1550063vsr.10
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 06:15:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660742136; cv=pass;
        d=google.com; s=arc-20160816;
        b=PdSZzTIFRvC0gXX4q7ZJn+mOK9F++qyi+JWFeiNQNVMGdHa/8bfEDu1CwxD8nQnR8b
         XsFfvjLyr97TZPHFMDeWiy9W1sFvd4YZJAf5BJ1Q2Owmhe9dkyMkZzzZJttPBYBfu1qT
         NcFToa4Fpm1i1E0ju1u6oB3g/BahCbb8gSygc4K2HDZI7tx6PkUh3mfwHukrdEU4UjMH
         YuEEUiyXRiCdkHghICj6mz8LGmVEdHnh+AM2EHImjYs6bWIqulRLSKC46YORZKxbJKXy
         S+FjUcXk9K0To9svRqdfup0IM2Jtx0+DKXK3I70IOR+Of+emnwB5CQrZI43SZHAKxYgK
         WcFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MjhU60vRjFwjjrqWFJVUm5rQNuQbSsuX/13JZ+L7uIo=;
        b=jUI3PfRp8ERwWkvqTfaQjnbHKqDGsRUU1vud+pO1ILCfMgZIMiO2ISRCjefTkLESuq
         9TbbMrhmUgNAlxmukaBJ+cHzYspwCHBkPRARphQTqv5r2mw8jUjDgh1kIch5JwdrBtbc
         50jiw7W0QJA0cgIb1Dwf9DzQX+fSljUsySTm8gbDVhuMuYXs/+/OAMcna/zlPIVYR4c+
         EA69EXxwWuqsKFAFyFBEE+onU8ckM13JSiBxQEDAzbsObLGmWRdUhRVgyf8oUMKnUq6h
         ErsBvj+d678tNvGiSUdtc16E0jTsjjyZcqw3Uhlelz6YEHvVkTKJ2WPUIPhdLm0bwSbz
         HSsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ta7vQAWf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=MjhU60vRjFwjjrqWFJVUm5rQNuQbSsuX/13JZ+L7uIo=;
        b=C8FYz0RoAles77KB+XI8rFfazFcTSLFlXNXRJu70bJDWXPfO557+aRaFAkRqQp0B7P
         o+nZWJGZgzyOFZ7pqnlxy9tUVok3pyPY0HiwlILLmYctP97fNfdm8zs+uDdRSDemrnhq
         6+wyWclPEevHpc+enjiMO4K9TAH+4CMYw8Uvi6hDKlabYp0SIKUrEZ8KMPJOgc6ixlig
         Y1iIh5p2mMldLFAnhlzFABybTxw2ljmhtRViKuA1NCe+zQd8u256Stpe+VAqCmusmAH0
         N1FbYnCBtfSkNnz60oKFPEB8GdFJoxrWAsNz70wT9UrEK/F6gAmixHE1acPZJ0dFd7PX
         9h4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=MjhU60vRjFwjjrqWFJVUm5rQNuQbSsuX/13JZ+L7uIo=;
        b=pUfDT58dwn1zDhybjQlMlTROB6k//QAnbYJAcHly7kh8hPc1bUSEg0STMvlrTx59S3
         bE5OMJ/grcTrRlr9muxr/YpwQGCtZ0jfoU23xeJQEvm/WDZ9DB0Vd7FyzFIJDTy/Koru
         ALrtjEkZTfNkPsAqiaVL8rHr89YBNIKhikuDX0JDAdwkNfcfGoWmvkjT4lmHB97/Wkxy
         uU/565DuY+kpwylYyscKJijJeRPRgYwaGuLYjng5Hc9mYuu2RAFH+pTEWz4u/xKZeBwu
         ggYtAbD9BCqW8m57sExLJ/9caiEROsR4skzzfYDQiBChxiFtU2vv5CaW3RUEMpjW206N
         CHuw==
X-Gm-Message-State: ACgBeo1SHFFrVfcyFhFrOpqn3l2u7fdenWOxncj6DEChew3wecN0c/Lw
	PL3s7oDGBGqWqmFo2j03M98=
X-Google-Smtp-Source: AA6agR6KwhYZxtFbsKiPBPPZQPLylfzL4iQcqILOxDc6IuaXGLdtrNf7oj4HpAzp9ZLsbV7PAbHhhQ==
X-Received: by 2002:a67:d39e:0:b0:388:a905:7bec with SMTP id b30-20020a67d39e000000b00388a9057becmr10539323vsj.32.1660742136510;
        Wed, 17 Aug 2022 06:15:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d488:0:b0:388:1338:9e57 with SMTP id g8-20020a67d488000000b0038813389e57ls3737041vsj.2.-pod-prod-gmail;
 Wed, 17 Aug 2022 06:15:35 -0700 (PDT)
X-Received: by 2002:a67:ec47:0:b0:388:8294:10b4 with SMTP id z7-20020a67ec47000000b00388829410b4mr10435000vso.54.1660742135854;
        Wed, 17 Aug 2022 06:15:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660742135; cv=none;
        d=google.com; s=arc-20160816;
        b=v8Dc2MTG48KB43lMY1akputBPrGXmmpXzDTdCvaTqksfWIDGQzqAgl1IzGSxcXunm2
         s1BWJqnLjVRbBri1UTchHEl1Cv0Ja4ZF/aG3W/dxlmeLf1F21tjRoor+685utri9Y7yx
         0EMFLleP9X6i/5wlK4Q2hl++/uQy51suliSOrOL2SLOQ8fxoHOxKkN5ncHOm4FSgsyo7
         N8YbhKqmFJ6NqEwrUmYv8otIywsecPruOB4lBTJM+tMdmNCCKDd3EOX9jAtciz22J64D
         dTjyjSvWVPngOYNotDoUcM9ykfChs3U01mUXZHdyJ+8ruMDCzjYZdpAh1qJJwjfiBUh1
         dYuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4x9/R2mHqDBSBsINZoYzu53n4+/x9xPXewr5G0XEr34=;
        b=QIVJjpNxncFao3HTztdGKINv8f8YXwZE/jnXsAN7T25pkOi8DkzLR8HJcI9Oz23/06
         FtjCY5a4W2QCwTA4cRg2efrsYPblc3Vr0D1yDmc9Cna1GDOD+UEdX8wDYEBGTXaob/EK
         THzM4cNl8fOP5nfzE5nsBkavrhR8H4OcV2yqgWSg199y+lI/XB33ArIT0g0Kb7zQ1jkN
         k3xAfvQ4/ExeFSsYJKSrgB6uOnMz9yzh6s4IBjScMhGvjS2WZR4oMnHZ5/PghfEbKdKw
         6w1aqBRcvwF96dSx3doxOrlPXhhVZdlojybtm+Oz0tGGE9K+ShGrm11D5k+PKWYknzAh
         zjMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ta7vQAWf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id 192-20020a1f02c9000000b003774de773c3si854166vkc.5.2022.08.17.06.15.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Aug 2022 06:15:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-32a09b909f6so230106967b3.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Aug 2022 06:15:35 -0700 (PDT)
X-Received: by 2002:a5b:c8b:0:b0:688:ebe9:3d05 with SMTP id
 i11-20020a5b0c8b000000b00688ebe93d05mr12303544ybq.553.1660742130329; Wed, 17
 Aug 2022 06:15:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-12-elver@google.com>
 <YvznKYgRKjDRSMkT@worktop.programming.kicks-ass.net>
In-Reply-To: <YvznKYgRKjDRSMkT@worktop.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Aug 2022 15:14:54 +0200
Message-ID: <CANpmjNN1vv9oDpm1_c99tQKgWVVtXza++u1xcBVeb5mhx5eUHw@mail.gmail.com>
Subject: Re: [PATCH v3 11/14] perf/hw_breakpoint: Reduce contention with large
 number of tasks
To: Peter Zijlstra <peterz@infradead.org>
Cc: Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ta7vQAWf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as
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

On Wed, 17 Aug 2022 at 15:03, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Jul 04, 2022 at 05:05:11PM +0200, Marco Elver wrote:
> > +static bool bp_constraints_is_locked(struct perf_event *bp)
> > +{
> > +     struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> > +
> > +     return percpu_is_write_locked(&bp_cpuinfo_sem) ||
> > +            (tsk_mtx ? mutex_is_locked(tsk_mtx) :
> > +                       percpu_is_read_locked(&bp_cpuinfo_sem));
> > +}
>
> > @@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
> >   */
> >  int dbg_reserve_bp_slot(struct perf_event *bp)
> >  {
> > -     if (mutex_is_locked(&nr_bp_mutex))
> > +     int ret;
> > +
> > +     if (bp_constraints_is_locked(bp))
> >               return -1;
> >
> > -     return __reserve_bp_slot(bp, bp->attr.bp_type);
> > +     /* Locks aren't held; disable lockdep assert checking. */
> > +     lockdep_off();
> > +     ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> > +     lockdep_on();
> > +
> > +     return ret;
> >  }
> >
> >  int dbg_release_bp_slot(struct perf_event *bp)
> >  {
> > -     if (mutex_is_locked(&nr_bp_mutex))
> > +     if (bp_constraints_is_locked(bp))
> >               return -1;
> >
> > +     /* Locks aren't held; disable lockdep assert checking. */
> > +     lockdep_off();
> >       __release_bp_slot(bp, bp->attr.bp_type);
> > +     lockdep_on();
> >
> >       return 0;
> >  }
>
> Urggghhhh... this is horrible crap. That is, the current code is that
> and this makes it worse :/

Heh, yes and when I looked at it I really wanted to see if it can
change. But from what I can tell, when the kernel debugger is being
attached, the kernel does stop everything it does and we need the
horrible thing above to not deadlock. And these dbg_ functions are not
normally used, so I decided to leave it as-is. Suggestions?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1vv9oDpm1_c99tQKgWVVtXza%2B%2Bu1xcBVeb5mhx5eUHw%40mail.gmail.com.
