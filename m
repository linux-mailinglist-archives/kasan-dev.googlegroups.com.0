Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM4SWKMAMGQEOF2UCAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 05CEE5A4637
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 11:39:01 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id h12-20020a4ad28c000000b00448bee68970sf3473081oos.10
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 02:39:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661765939; cv=pass;
        d=google.com; s=arc-20160816;
        b=SXHm8n8G8PF0QXwe0auhS/yEDlyhxAUagRKrMxkH73zKgaYWDKk8+vgBHiIOwpu3vd
         sU5LZ1kOodM6JhLrGUWa9mfgi3chQT3m6vnpbpyqkNDuoUkq/yYgd9EigMzxNZgGlg7I
         ewfpOS+cV1+gA7Z9mCA9Vze1dorqZh80CcTtDYqPdsSdjee7Sbr06mGgrWPtiPqb/qsY
         puO3ZL4hZ+08r0C00AzJjOfsgFDO+LHv+Vqd7qudDTwjaxjUeBLf48kALu7FlAM3pHNV
         E+s7m/+822FS20tur/hJlFBiAae1sZu/I+SurwTqt9iwQ1dqgCnqpcgcDOgbdmu29B3B
         6i0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DQoQyGYcKTEgHz8DHYn4bCSy0A0pCwQD5KnALuM9sq8=;
        b=azBimadXQCzbUI87rBzuFFeWAbSlkW56HaW0hPMS6itvAofpdt/NvB8Eu3YIc7ZWQA
         uC5XNgdG5JOIRbjmv/w9TTfAEreOoiOwwzt+KqiaUEizq0gpKTcupEn2SG1HiD/bWSsl
         OOHl6/y4NutEdXa8E1SZKcXrnALVCM42oIUczR5TSOJXIZK+gOoX+9nWJbpYa+d5mERX
         OjmRGHDWgmTnOuqhonzgfEhesKHIG+doC6ZDDedmc7Tsjo0DvYwE2ujcJBaeH5EbW1xK
         IdtU7AqxtY7fF2pj/v8Jjj2NfPWXvTB+caHalxBIJcWXjW89IPS/nAzTygB+HdfXHxo5
         LHeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dx6bRQ4J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=DQoQyGYcKTEgHz8DHYn4bCSy0A0pCwQD5KnALuM9sq8=;
        b=jgdqBSaOHTKBeebZ2OQaiWDySq6HBuLovZNpPgj4QjlALV/WVteP9/TxG0ci6UsfI6
         o9WZZSgovvlL86mddW1sW4Y33LfwK+3R287wo3WgFZT3Fqkr1alOLQ4QUP58pX08tgXJ
         E5rUvv8HHODQR4blz/mLzVcgSW9DDlQEkBI07wXHlwaUgr7T4/Z/6sEV1D5ErkWz3lI7
         oliLhf1g+z+b0zuXfAM/bIaSYN1Y1BrSHeCAvIvCcV2QOYdOl9sIRUAJ2cX1iTjhoU8Y
         vRv8zGZiLW41xc3vwn9v2ocy+z6DVbytHuS+ZY2SUHWWrpiMqZEMm1JVVnQu/nnRdtqZ
         Sz6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=DQoQyGYcKTEgHz8DHYn4bCSy0A0pCwQD5KnALuM9sq8=;
        b=piMT7UAnrryw8bT12C50uIZcmQrc6hecinSm2ujaYsoa3E82WRuvF2tBBDVggI4AVt
         b2KY8EHg/odeDBYkpqvcsE0dME9KY07l+V6e+tUcdGP/XCI4+VRrmZ6VweLRBQL/XFoF
         +FrKncP/56e0v0I2Tnqm2WqRAeGXQtOCd3XjjENh3u+X/TwqIZmiyl2bsCooI/4T5eDa
         Vq3bpW4yxwZxHYXUqOnpHZkVMvN0EuuEcNNW/GXOBsTxV6fjwLCTFGleNZse6XtE1vrw
         C494ZrnO50530uxL0X5TT61INVVtXfGu9piBVkQteHuoEXYVr8OOp8tY1GFrzmRhpmtN
         0+xA==
X-Gm-Message-State: ACgBeo1pnrdlx4tD4wKe2tbjkwVw6WNcJIJ79A6iA1d2M5BQRv1GcK1R
	j98mtAzshf/Hfn0wCx+Ad3s=
X-Google-Smtp-Source: AA6agR6m73+laDsrKfRB4QVlva7AOJZ1n/pbJfLt/N9KIdaB+swk8vHoJPJ06OffzkDCLSRiBtH1dg==
X-Received: by 2002:a05:6870:b00a:b0:11e:3fc1:50e2 with SMTP id y10-20020a056870b00a00b0011e3fc150e2mr6915967oae.246.1661765939652;
        Mon, 29 Aug 2022 02:38:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4d8f:0:b0:335:3a6d:57e6 with SMTP id y15-20020a544d8f000000b003353a6d57e6ls2315401oix.6.-pod-prod-gmail;
 Mon, 29 Aug 2022 02:38:59 -0700 (PDT)
X-Received: by 2002:a05:6808:1412:b0:343:345:98ac with SMTP id w18-20020a056808141200b00343034598acmr6539627oiv.288.1661765939120;
        Mon, 29 Aug 2022 02:38:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661765939; cv=none;
        d=google.com; s=arc-20160816;
        b=O4q4EhTj0lF2ebjgeVMH+oCT6dsxf3mByvfD8LY96dr+yKCFdmlmrPn3BDlFg5XIQW
         GjglripZ8iKErjExcdj4ejrtlS5foxuCClib8exXyUQWDlWv4yO/0y1UqXHCpyL8eGgM
         vzzXkbY0mccrMsACcQ7a2Q8BPQQLOK8zSHKjvVpo7dYUYmLltpXEKK5v8/3yUAz4qx8B
         Mw8xwWAQG+nU8P8+dCPdV6quMmqR0iM/AwOjJYSNbJB660F03uonAIDv2sOrXPB7jjoF
         kUVGGa/hw1P3dl6HOrpS7Y8omN8HcO0UGWqpVsthyXovIPPl2L3dPneSyr7JlnKS18Ca
         p1Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GBvqua5cjMzjDQ/XgF9SZ1D4y+QsnVuyrt4amhV4btE=;
        b=BY8zSdxltTRo6oyPoTAm20tDPty4pKjJOhQ8eo4pEdgVluFU07VOKG/YwrIN9EBqc5
         7w8RiGaGB75L6qxgs4vuPGK30lBK+Mupb92bV+Vsy0Na/UZjV8DG7zcD6M+aLwMKGiJV
         hgyJjPuH0D95F05lajvY/+OcINCEAfnG/wbTZX5bt6a1co+zKaWLTmqF33nICgHofoO6
         ykjXnQ88TTYaJeOqtFHjmjdRHmA3MLNK59vTuGvkVzaIQ0ZduiijZPZzd2anrNpEjjMd
         sV6TE8zs+cMmeOvGyOQ63g+5efdxFWSPARs1bj6Wrku7NQB/2Txv148fDeGQW5CcyxsZ
         LkIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dx6bRQ4J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id u18-20020a056870f29200b0011ca4383bd6si767232oap.4.2022.08.29.02.38.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 02:38:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-3376851fe13so181157407b3.6
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 02:38:59 -0700 (PDT)
X-Received: by 2002:a81:4e04:0:b0:33d:c7dc:9e2b with SMTP id
 c4-20020a814e04000000b0033dc7dc9e2bmr8959772ywb.4.1661765938626; Mon, 29 Aug
 2022 02:38:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-12-elver@google.com>
 <YvznKYgRKjDRSMkT@worktop.programming.kicks-ass.net> <CANpmjNN1vv9oDpm1_c99tQKgWVVtXza++u1xcBVeb5mhx5eUHw@mail.gmail.com>
 <Ywx7CmbG+f+wg04z@hirez.programming.kicks-ass.net>
In-Reply-To: <Ywx7CmbG+f+wg04z@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Aug 2022 11:38:22 +0200
Message-ID: <CANpmjNPFnV2novubKKVmC7zJ8qi72QuRY6bWBEi5jrO_kkRBag@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=dx6bRQ4J;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Mon, 29 Aug 2022 at 10:38, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Aug 17, 2022 at 03:14:54PM +0200, Marco Elver wrote:
> > On Wed, 17 Aug 2022 at 15:03, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Mon, Jul 04, 2022 at 05:05:11PM +0200, Marco Elver wrote:
> > > > +static bool bp_constraints_is_locked(struct perf_event *bp)
> > > > +{
> > > > +     struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> > > > +
> > > > +     return percpu_is_write_locked(&bp_cpuinfo_sem) ||
> > > > +            (tsk_mtx ? mutex_is_locked(tsk_mtx) :
> > > > +                       percpu_is_read_locked(&bp_cpuinfo_sem));
> > > > +}
> > >
> > > > @@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
> > > >   */
> > > >  int dbg_reserve_bp_slot(struct perf_event *bp)
> > > >  {
> > > > -     if (mutex_is_locked(&nr_bp_mutex))
> > > > +     int ret;
> > > > +
> > > > +     if (bp_constraints_is_locked(bp))
> > > >               return -1;
> > > >
> > > > -     return __reserve_bp_slot(bp, bp->attr.bp_type);
> > > > +     /* Locks aren't held; disable lockdep assert checking. */
> > > > +     lockdep_off();
> > > > +     ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> > > > +     lockdep_on();
> > > > +
> > > > +     return ret;
> > > >  }
> > > >
> > > >  int dbg_release_bp_slot(struct perf_event *bp)
> > > >  {
> > > > -     if (mutex_is_locked(&nr_bp_mutex))
> > > > +     if (bp_constraints_is_locked(bp))
> > > >               return -1;
> > > >
> > > > +     /* Locks aren't held; disable lockdep assert checking. */
> > > > +     lockdep_off();
> > > >       __release_bp_slot(bp, bp->attr.bp_type);
> > > > +     lockdep_on();
> > > >
> > > >       return 0;
> > > >  }
> > >
> > > Urggghhhh... this is horrible crap. That is, the current code is that
> > > and this makes it worse :/
> >
> > Heh, yes and when I looked at it I really wanted to see if it can
> > change. But from what I can tell, when the kernel debugger is being
> > attached, the kernel does stop everything it does and we need the
> > horrible thing above to not deadlock. And these dbg_ functions are not
> > normally used, so I decided to leave it as-is. Suggestions?
>
> What context is this ran in? NMI should already have lockdep disabled.

kgdb can enter via kgdb_nmicall*() but also via
kgdb_handle_exception(), which isn't for NMI.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPFnV2novubKKVmC7zJ8qi72QuRY6bWBEi5jrO_kkRBag%40mail.gmail.com.
