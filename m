Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6L52LQMGQENQ2XZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 260B6595E1F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:12:50 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 185-20020a6218c2000000b0052d4852d3f6sf3781754pfy.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 07:12:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660659168; cv=pass;
        d=google.com; s=arc-20160816;
        b=FbmT2NI5d7ACY4GkkHTXePRON2nV4AjPwnoagbvVMMnEtAEr1nSp0b8opTLSuDn0lH
         C39oDkvNTqddduztf7OWux0qPxnlQaYQG8Mf4ZkCzL6kvL/EbdKNcR3J1j0C7Wg1fYvR
         TRtrbvnCix+NmB3f/Kc92u+a3pskBquEsrkMpO9WuspkS9Ue/D37XePXztDKphC+rBjL
         7APupnpSa7o/1955DSfeACS/sUo6zhbfY6yAG29bU8k2SHhO4Pe5+Pt6x1S4lH72BGiY
         tS2QxC1rTIwGjeYD2CksN0Q6xqKy+9QbUjazfOwKerkWGn7ve4COpJriQJx3fmTHQv2b
         f45w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0hazZR41/6O3Uu1IST3JuFd+ZShNHJaIhZJrSCC7Bk8=;
        b=UpwIYXvsvhqzHwwAX7MZfAgWBWyB2CJkRgSnlwzejAOn/5tpozRt8KSYhCkXNuk9yu
         1wza6+FO8m9UsydMLYEowlqPJ1aUBlZie8bCdmQtpJdrBYmwT8kU+m9Tp8aC7FipAPJc
         spNu4SSaqpZq8E4fNXg8tidPNvylaRu7vMtF68X14coIEoWpPhzGuaQjlUrkUOUnKRLH
         +HvkC0/K+kpJEZhB2SpHF6RcOcFRiIP9ODYEAQIlISJFoNelGpzlSyVm8b+W9XF9sogf
         wOnGwPi3lebMz7wnyzWroMJSUifKCd+V6YP/CLTPxCzpavdT/hcglK8dH0Cgaoziq0D8
         tyCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fDj6Fopp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=0hazZR41/6O3Uu1IST3JuFd+ZShNHJaIhZJrSCC7Bk8=;
        b=WsbgQFSL+HBdhyF4U7bUZGvbaWWJWKl+petLHTVl38DOmFHhTjl/hZDWOpjQfTcPHt
         Cd3n+YBOgsqx8CYVZHe9Fi/6vgzeecN9R8BpnGEkqT+PBo4PpAKEMvNYzhM61sLChso1
         QeU+GDyhIThcCui8/o4CpdIAGR9D7Y07YUn9EEyxv2UsiR3cRkSd8Q1tZ1t8RCh0/FTV
         3CvqFzrmbJ4fgot3LsUKlrCFe2Got7u7uGz2rCyvkk6eXlrjSJ0TPz8PgwRHsFr52p3v
         +ftcqSfQgB1gl+vTcBx8GM+hTXCw5saFGdIjhjzB2cOQg4rjFCqrR3UacDC6PpZuC5j7
         jb4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=0hazZR41/6O3Uu1IST3JuFd+ZShNHJaIhZJrSCC7Bk8=;
        b=woBxuHinPzJM4gKcEZ/txX33fQAjLiGvKug4bm3/3ELAqCpX8G/29E34L7w2frOnZ3
         1UkNirg5qNg04vT1nboEjgYv8micI284MxVLfDsajf7GUnyWXfmt3PKCbS1n+mHqpnRh
         H8IYhhs05bntwP9BlgSDGrJIYgGfTGn/A97metPfgvzlP3tyEf48vg10gR0GBUgR9x15
         XqmGdqjv/usGc1ueUHgbsTVhPteF5JQH/KmNhgRDn9HWG2zfuPdf7XqVoZUH1Kc4eQJ7
         FKYNuF7q/aMYbqfKMBLkOT9nHKKBERtYnewkwdOamlLPI/rf+P4q5O05hyRJnwB/aq7Q
         sGHg==
X-Gm-Message-State: ACgBeo1+c4ccAkjBp8C2k1rANUvTN37GO6odrRpEjuVo2O7CcsSE/F0j
	REXgcYzpv7kSbLRePyNDXyw=
X-Google-Smtp-Source: AA6agR6mvz5RNHSzsd5WbpM4qfblwELX2Q5iH/O1f6NxlK26/8Kpa9Tglvy/On5ic9VvcYSg8HRVGg==
X-Received: by 2002:a17:902:8305:b0:170:9fda:af45 with SMTP id bd5-20020a170902830500b001709fdaaf45mr22459367plb.57.1660659168090;
        Tue, 16 Aug 2022 07:12:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7787:b0:1f3:5f7e:7a34 with SMTP id
 v7-20020a17090a778700b001f35f7e7a34ls9257919pjk.2.-pod-control-gmail; Tue, 16
 Aug 2022 07:12:47 -0700 (PDT)
X-Received: by 2002:a17:90a:1188:b0:1fa:723e:88e0 with SMTP id e8-20020a17090a118800b001fa723e88e0mr13445554pja.73.1660659167265;
        Tue, 16 Aug 2022 07:12:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660659167; cv=none;
        d=google.com; s=arc-20160816;
        b=bdhdy2V3yJ98783n/O+oqbtIeS1Jy8YU1g4HuO8GIkmH+Tx5oNlWR5NUK3H4eZRWOl
         bVs/9xZx00rDrUyenVM41YStXx1NYX8nBvSlyDOPO12ZqdQ9AtISlcxQjPVI/5DWYyMy
         AtFx0Z8C/6jb3b+9LzdRK985SuMLsKDF1AUxG1Hhx1ZXZPKa55XQg2/ImNtmTSUL1MwV
         dNpwBK8eMgzdcKAIZw2GBKsnSVn72M43pEnr1Vgv+SeAydsdizYfe1Tu1ImcDOBr7CMo
         JVOoSOji+dxppoV1AmpQq47E9Un/DHacshKnSzQ5yOWhCDxKnmNJuAEMuoQyEhjRymk5
         +URw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vyh7nX6aNSNUE119qdiIIT/EoXittiyqJ3KmpoRb3JU=;
        b=g2i+8U75pFKYjQCmPzCViMD6kLJjafKDwGMWTd7kRoUhm6mmCcuW2r3CjHG2lYi8F5
         /WtN3AAEHy7ShcYOBC2DwHBO3SWvb0KuQmMEswMewSaS7dGLJC5QSmgeVYVcoIZqTy5F
         H78D7l+YpsXdvhaRuf0BkKNPulipCigqFM1Qk5AiLuAgvgKjOzK09OONMkqnbb9MhHQc
         5B0WHJ+Wpuegwdl0r0AjRRW7Hh7jx+FrcinwqLKU7kbZrWVAONyl+aJr3RXiua6lh0E4
         TkTN1BP4oocGOtt+9eQdOlcCSwIMmqDMJgMZrI1ykFo1tbLlscgkDW8egkdU4ZBAAFPz
         puKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fDj6Fopp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id x4-20020a626304000000b0052d63a7e841si543576pfb.4.2022.08.16.07.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 07:12:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-32fd97c199fso129380457b3.6
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 07:12:47 -0700 (PDT)
X-Received: by 2002:a25:490:0:b0:67c:22be:65db with SMTP id
 138-20020a250490000000b0067c22be65dbmr15094214ybe.16.1660659166737; Tue, 16
 Aug 2022 07:12:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <CANpmjNP0hPuhXmZmkX1ytCDh56LOAmxJjf7RyfxOvoaem=2d8Q@mail.gmail.com>
 <CAP-5=fXgYWuHKkfAxxTeAzTuq7PLwMd6UvBu+J+6tnqHwraSCA@mail.gmail.com>
In-Reply-To: <CAP-5=fXgYWuHKkfAxxTeAzTuq7PLwMd6UvBu+J+6tnqHwraSCA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Aug 2022 16:12:10 +0200
Message-ID: <CANpmjNOnRNKUTeSB9+LBTjG=2+BC=ox20ain1F8T1krS+ah9HA@mail.gmail.com>
Subject: Re: [PATCH v3 00/14] perf/hw_breakpoint: Optimize for thousands of tasks
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ian Rogers <irogers@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fDj6Fopp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as
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

On Wed, 20 Jul 2022 at 17:47, Ian Rogers <irogers@google.com> wrote:
> On Tue, Jul 12, 2022 at 6:41 AM Marco Elver <elver@google.com> wrote:
> > On Mon, 4 Jul 2022 at 17:05, Marco Elver <elver@google.com> wrote:
> > > The hw_breakpoint subsystem's code has seen little change in over 10
> > > years. In that time, systems with >100s of CPUs have become common,
> > > along with improvements to the perf subsystem: using breakpoints on
> > > thousands of concurrent tasks should be a supported usecase.
> > [...]
> > > Marco Elver (14):
> > >   perf/hw_breakpoint: Add KUnit test for constraints accounting
> > >   perf/hw_breakpoint: Provide hw_breakpoint_is_used() and use in test
> > >   perf/hw_breakpoint: Clean up headers
> > >   perf/hw_breakpoint: Optimize list of per-task breakpoints
> > >   perf/hw_breakpoint: Mark data __ro_after_init
> > >   perf/hw_breakpoint: Optimize constant number of breakpoint slots
> > >   perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
> > >   perf/hw_breakpoint: Remove useless code related to flexible
> > >     breakpoints
> > >   powerpc/hw_breakpoint: Avoid relying on caller synchronization
> > >   locking/percpu-rwsem: Add percpu_is_write_locked() and
> > >     percpu_is_read_locked()
> > >   perf/hw_breakpoint: Reduce contention with large number of tasks
> > >   perf/hw_breakpoint: Introduce bp_slots_histogram
> > >   perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent
> > >     task targets
> > >   perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task
> > >     targets
> > [...]
> >
> > This is ready from our side, and given the silence, assume it's ready
> > to pick up and/or have a maintainer take a look. Since this is mostly
> > kernel/events, would -tip/perf/core be appropriate?
>
> These are awesome improvements, I've added my acked-by to every
> change. I hope we can pull these changes, as you say, into tip.git
> perf/core and get them into 5.20.

These still apply cleanly to 6.0-rc1 and the test passes, but let me
know if I shall send a rebased version.

Thanks
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnRNKUTeSB9%2BLBTjG%3D2%2BBC%3Dox20ain1F8T1krS%2Bah9HA%40mail.gmail.com.
