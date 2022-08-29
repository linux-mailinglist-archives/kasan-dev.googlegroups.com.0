Return-Path: <kasan-dev+bncBDBK55H2UQKRBGHWWGMAMGQEENUSRNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F9385A4546
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 10:38:49 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id b12-20020a056402278c00b00447f2029741sf5001079ede.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 01:38:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661762329; cv=pass;
        d=google.com; s=arc-20160816;
        b=szq7+Sxvrb3gSCs5vX/xY/uoMOQfV7uY4Iuplh+rQzVbzckoLCsl+/NiGEcm8lSWlI
         nWWwXOZnOqwrCR64UnqGLYE6k9MueZT1ZEklrCmXJPFDZbvu/lekAl2m4cqV2MZZOw1U
         Dt93LWoSk8SC0i/G0miqS00Ojp45OwoocmlNhC2vbMGvcIv6BEDpy6sAc27ngxgrSis5
         sOXYZav63S5BP1Arxh7u9uv+AVOlfc8dcJJr0U4R7tBc2KxttuDoopMyAT9S3Fj88JYn
         bFUIVOrZ+n6nhnyAIRvkHfblKWAsnr3KOhEcKzK08DfEVJZ+E6goqpbcGjL37Rm73LAK
         lKtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Otp0s9X72j3a7jwhBcrgYNK7/WlcMhOEp1FmB8RLy/c=;
        b=gUan5Owf5ybY5Azo2XtoRamLffJt17069e2dKjcyV4C+gISeq+RLhuPAgHP2bbomGN
         9INq9SizhMxq+uluuj6yTLcpC7HrWyIaQZLtUEpMOJ+k6c5Fq0IzrK96pOfpvzVLyj37
         7Kuk/km0A5qpvdiVVjsx7gKVxLbBZ1k8c1en961diMeacMqTfYIKO2DgeSJE5632Bj4U
         gHFGap0ofHnyCiBZ2SU8FcIVfms/8DYMr21CHuoVx9e14hPkVGgCtTJoOjkFI19ccZiW
         9NUn758MYqLN0MNm07GvLGXcWs8ZFNQQgd8QaZ46LwSqFweF5TTfKrR6PowQWOkAcwNA
         aO9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=VnpBQLFt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=Otp0s9X72j3a7jwhBcrgYNK7/WlcMhOEp1FmB8RLy/c=;
        b=Ojd12UQd0ywYhSwFDbSqajWyagGak158Iw7eBEjUwbr9o5yaEmxIdWBVYui8pHjuo2
         CtORpVA+6eUVOiMUyfcgH3Jrh1BtQBMLUOM37dkQl2L+iJCmwd/VVVVybIgewFc8I2A5
         dTqzrVyFbptKHimZo/OaoUL3CFu4JnbwUuxhotBLoxffQTk63ChHqUXjXe+MgumjxdFZ
         XDQFy0Gmga08lpzFC3030cp6J9SEqo8SSU6F0rTiwSBgIGp+56UC/5z8HZ8tjinS2SAB
         LX1XY7Q8PBIssEceAr56d3uQSCk1uvgkNN0PtT3S42l6BeKmzWsqn3pzROeIHoRez1RQ
         0x1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=Otp0s9X72j3a7jwhBcrgYNK7/WlcMhOEp1FmB8RLy/c=;
        b=GHM/uf3kHmuYUpsuxz0953uZcIcwygvj6o0AJzZUgvzYp+aj6ZpH30WRcL2BGhdeXR
         jXmgn9SE2OKh40RzQqhSRfeDgPzyWeRfVU81941kUr+Ow1lN31t8KHrSpEWZ29HvgJL2
         IVNnFG37D/TssOjllE1ORIVKUOPr8Couj58H5cIrilH+8HMRuX2rWUmghKrfdnAUtN1y
         LeXHYKwpXiP4RwYlptTDfvXIduhUfzb8yTAnRIb6uIRezZmqZeT24rE22pYmL3wEvQES
         bz584FONmYKvWhLwha+vRd0rIQN4WPkn12I8Sd0HS3/y1qZvG1lCPmuhkllKxqdhta1n
         0nAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo218mHY8P29+wiowy9ejQ1tKXDq8KmsfH5LCl5nlut9a47pIAMl
	aZUKR+7JnzzT5/o3dCXVF4A=
X-Google-Smtp-Source: AA6agR4NPP5L1VzewxoOqXb40Yxa5xr7JGajaRqdvVBbU4f2eFNCZaWbsTKtv+7hQMITxvyN65G0OQ==
X-Received: by 2002:a05:6402:3d4:b0:447:86c6:3a26 with SMTP id t20-20020a05640203d400b0044786c63a26mr15937598edw.141.1661762328792;
        Mon, 29 Aug 2022 01:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:e0c7:b0:73d:75ed:a850 with SMTP id
 gl7-20020a170906e0c700b0073d75eda850ls4919140ejb.2.-pod-prod-gmail; Mon, 29
 Aug 2022 01:38:47 -0700 (PDT)
X-Received: by 2002:a17:907:75ec:b0:741:484b:3ca4 with SMTP id jz12-20020a17090775ec00b00741484b3ca4mr6523061ejc.316.1661762327518;
        Mon, 29 Aug 2022 01:38:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661762327; cv=none;
        d=google.com; s=arc-20160816;
        b=j3DTWAA5xmKhUcZ2FO/fkXYZ1lnPdQ1nFM5/O0iefjI/8TqivTfMBX/8dS78mbqPEk
         Ydz3Tt2EvdgYWX1otaa7QyonZD4m98w5nfv5bVwb0WfOrHgijKTS4vezV0UPhXkixAWe
         5V2OeDRAEH+HaAHts57bmCjs9JzN2u4bD06z24xCAnwVDZgdXypazn8yzbPzqCJiuSnF
         1MtJ9QxWk/XuDKx98XaTXAbHnacdDQuzcak1Az6HZNPOtwgS1wTmNmDNQUvnVQ/VQx27
         XXF4NpD/4f+9r6voY8r5JKUmgUfa+UjPHnaRwnAuM/Vdn4/S922ff5kOPZ16Vo+DSpIw
         lpdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=enW5V6g2WX8qHIsfLn2eVhcqKoAKV5YXSn+3ybsOepY=;
        b=ycVM9qDjNdMiy8dfQ769vApVKB2+160IY08/0X48K3+gkMvcqPaVjVytiiRnXQhuFD
         40n6Odl/9oUHkdb3T8PNVGzkd+FMkwTJmJHR9qs8BXPz/PD8n3BByC4NiJuFSVm7LrKQ
         d2zqLVBFJqDuNrplazpT2h7NuhzMb7RQOso/QzIyVhlCyBIrlD+t9M3nUjyHLrcyh4Nz
         L6xRJ2wmWsIzibwq44fqy9mc93O19ptXpFz5WabHtdiNBM0pgRarrqgEMS/vyRvVYLFm
         5bsD0N/p50hjBfXfY/eBGW2daLIdv7y07YeGREvnRy8SRyxKIjmkMiy/dhzq8ovkj3o0
         FIBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=VnpBQLFt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id y26-20020a50e61a000000b00443fc51752dsi352935edm.0.2022.08.29.01.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Aug 2022 01:38:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oSaI2-007RqX-4b; Mon, 29 Aug 2022 08:38:38 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 529D3300137;
	Mon, 29 Aug 2022 10:38:35 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0F059202547D2; Mon, 29 Aug 2022 10:38:35 +0200 (CEST)
Date: Mon, 29 Aug 2022 10:38:34 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 11/14] perf/hw_breakpoint: Reduce contention with
 large number of tasks
Message-ID: <Ywx7CmbG+f+wg04z@hirez.programming.kicks-ass.net>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-12-elver@google.com>
 <YvznKYgRKjDRSMkT@worktop.programming.kicks-ass.net>
 <CANpmjNN1vv9oDpm1_c99tQKgWVVtXza++u1xcBVeb5mhx5eUHw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN1vv9oDpm1_c99tQKgWVVtXza++u1xcBVeb5mhx5eUHw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=VnpBQLFt;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 17, 2022 at 03:14:54PM +0200, Marco Elver wrote:
> On Wed, 17 Aug 2022 at 15:03, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Mon, Jul 04, 2022 at 05:05:11PM +0200, Marco Elver wrote:
> > > +static bool bp_constraints_is_locked(struct perf_event *bp)
> > > +{
> > > +     struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> > > +
> > > +     return percpu_is_write_locked(&bp_cpuinfo_sem) ||
> > > +            (tsk_mtx ? mutex_is_locked(tsk_mtx) :
> > > +                       percpu_is_read_locked(&bp_cpuinfo_sem));
> > > +}
> >
> > > @@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
> > >   */
> > >  int dbg_reserve_bp_slot(struct perf_event *bp)
> > >  {
> > > -     if (mutex_is_locked(&nr_bp_mutex))
> > > +     int ret;
> > > +
> > > +     if (bp_constraints_is_locked(bp))
> > >               return -1;
> > >
> > > -     return __reserve_bp_slot(bp, bp->attr.bp_type);
> > > +     /* Locks aren't held; disable lockdep assert checking. */
> > > +     lockdep_off();
> > > +     ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> > > +     lockdep_on();
> > > +
> > > +     return ret;
> > >  }
> > >
> > >  int dbg_release_bp_slot(struct perf_event *bp)
> > >  {
> > > -     if (mutex_is_locked(&nr_bp_mutex))
> > > +     if (bp_constraints_is_locked(bp))
> > >               return -1;
> > >
> > > +     /* Locks aren't held; disable lockdep assert checking. */
> > > +     lockdep_off();
> > >       __release_bp_slot(bp, bp->attr.bp_type);
> > > +     lockdep_on();
> > >
> > >       return 0;
> > >  }
> >
> > Urggghhhh... this is horrible crap. That is, the current code is that
> > and this makes it worse :/
> 
> Heh, yes and when I looked at it I really wanted to see if it can
> change. But from what I can tell, when the kernel debugger is being
> attached, the kernel does stop everything it does and we need the
> horrible thing above to not deadlock. And these dbg_ functions are not
> normally used, so I decided to leave it as-is. Suggestions?

What context is this ran in? NMI should already have lockdep disabled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ywx7CmbG%2Bf%2Bwg04z%40hirez.programming.kicks-ass.net.
