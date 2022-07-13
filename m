Return-Path: <kasan-dev+bncBDZKHAFW3AGBBOGXXKLAMGQEZGO6X4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id F0DD0573551
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 13:25:44 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id i3-20020a056512318300b0047f86b47910sf4898074lfe.14
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 04:25:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657711544; cv=pass;
        d=google.com; s=arc-20160816;
        b=z3b267sDbFKf9ttP8iKpp0b6x4+yuHyacXuvQx8hIizedKXFNWjf23Dgws6Gs4vVPL
         lFe9T2PHE+SBlyukeZrG2+qZcilK5yIIz+rxLJQNV5gxqKQ43KKA2UO8ZkEQePkvzOTa
         RIIS/PcgMOKBSSR00yK8rbDbAUII4eBdmkDYyh1XfQ877VIo0XMyCaOsN0fpnIU3x2pr
         FbbVJnRgjuK+eQrsdzoLngrvh/vHcouYj43wxjvAHupzHQxO4ofHxWHOEV5VUzE89oY6
         yTs0cL3AnBPOzeMtRtsEHAauPp8vNP26WmXCd6i1xVmKcd38sJ5kNxQ8Hgwv0f1OxRRf
         EwKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6GAAiO1ZQjC0SQ/RFMxJZsrl958MtvIKHdcq/6zS9pw=;
        b=xPZRABHeVct3wVf+3f3lrt9MLuOp3ea0ke9c+onlQk3figbVwofh9O5G+m5khtV6p+
         9gNAdoR7i4J7kYV2kk3aBU2iI6Y9LuPTc7/5oxZxZXQDAh25Tr5iOWjHdsQQ79l7AgvB
         KONN+hYfAWLo3wT4ZfSZYMainFZpychFevpOZLIMGn3alRZsycNE52p0rCVgvCaZ8zRq
         GzcXV4Sg7O7ksqjPmYSy+nno65IYcajru/wQOyqxE1C6TG2T2pfPnSC4prlegKyn5/hz
         3E046aPOaNk70qak952y3149vnUD/XY5ruR2JzYoVsNOHX/LwhPzfZfFX+a1PV65UKgR
         rw6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=BDyRyl3O;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6GAAiO1ZQjC0SQ/RFMxJZsrl958MtvIKHdcq/6zS9pw=;
        b=JzOXtXj54ouu6uPP6sCth64fRbjUzYXdp+uOVq6jQAO2IIKLM8uImtW9S1ocxoEhWE
         Fr7UsVBTefZz56w/ahi1GA7rZaLrINFAirggGE2wwsqcrDQnXeGVHWjiDP5qdUtdaHaM
         zzKYI5AnjrJ3Mhx7i5cJU2YNTb3oi1wzDcwo/K4PVxvoJxjmERqY3m8EvnLJ8lKyhaFj
         VvotyZ9WT0+y5eqSRQ6zUpJNC5VDCYizpZDyHHChDqswIVhaCD2mNsBgWYDG1HbVBvlt
         tUsgTkZuVdojHkfX2G4xqwwBWpHLJ9dOnqWVtZLkGzJ8lEn1KZ5VkNLqPkpN+stDq4Zj
         Hotw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6GAAiO1ZQjC0SQ/RFMxJZsrl958MtvIKHdcq/6zS9pw=;
        b=KsUN6DTb/Z5jO+F6YScf0bDdBIW6qRK0Ofv/nadx94k3jMGTb94I6ehuVmsbf1NstT
         PPlU6dXnX57wMitt2sZrl0t3KZMIP8Fg9tyLGwU6BjDgTc/4eHf0eTs7bzGZoTwUj5BW
         Cc7pdV8stAtkNTB6S/Kv2m6eUgilD9xcHXxrkICCz8fF1aGJskY8uIFrb4uXWFPsO/2I
         cH14476ZG8JPubrtxU8PlvIOVNoNADPt0sQmSGY+Be5LNCR0DLIV3B40/PYgtl6Qxw0X
         F83FjgzfNeZg2K+Atpg5z2wt7Z5vJxFzp48ID/6dDLMZ34026FEQ2aZWwK+CHZ93hVRT
         TFEg==
X-Gm-Message-State: AJIora/MfkmLNGPJV+6TZP7gkcNypOFQd9fW/qxeOnhmrihhnkd1Nf29
	Cb4Pj83DdakTFZvQv5RAqbA=
X-Google-Smtp-Source: AGRyM1vaVOcK4JoSy6ekTKdbYCjMxl96227JK0f+yBBR5EFicW0RYTIK+S157ySiiEyWGFkhh27awg==
X-Received: by 2002:a05:6512:280d:b0:489:d766:5e3 with SMTP id cf13-20020a056512280d00b00489d76605e3mr1708607lfb.499.1657711544516;
        Wed, 13 Jul 2022 04:25:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a8a:b0:489:e73d:dffb with SMTP id
 m10-20020a0565120a8a00b00489e73ddffbls209399lfu.3.gmail; Wed, 13 Jul 2022
 04:25:43 -0700 (PDT)
X-Received: by 2002:a05:6512:3d06:b0:489:d0c2:649 with SMTP id d6-20020a0565123d0600b00489d0c20649mr1779848lfv.210.1657711543103;
        Wed, 13 Jul 2022 04:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657711543; cv=none;
        d=google.com; s=arc-20160816;
        b=lXrQs3y613gzF+GZZMUqmv3O/hDS8WZCWsoNJkba2TE//mnXY/9YYuYkOqGot0KmAx
         ahmBOceehWGgHhrIxAeR76sosr+YtG9TvTZK60IgPJjYijVfO28LGPRvUKUk8p56MayT
         DTMUyFg6vNo/kQ4YHVAA05Qd+4kCmmFdZdwsSWaBeuaLYt8J0QoETVUHskCetq719uZp
         zmnznHwk9XHn+OmVvEacrvbWy2f3WsLTbwMfbd6L1dGq9TSgb2yEkPCsVGIIp0PgsF6m
         ANOt7Qt/SA/ZZ8oPVjIg9K6sGQXV5RkNAaVttRyXGlgRtYWF9qgTrYM+Uktyx6q95F9t
         bjrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2hCUwWlyM97iRIwu5t9bviH/71g+A0D69fnhpOcSMiY=;
        b=HCHYqUQgXNeFHuVG1SX6+34lhL6oXPVSC0CtQWc17FFJI20+rXoZmWBB5qQC+4DL59
         EhK+JlTDbRykZw6VMthsM6tHYOuIjYPDDTJGGZlZCUjVUS3ADB/2S20H0lQTN0r2nCdz
         SXdQZJuSaT0AHwj/NRNAkSvOrkVLY31Xcf7V10aq53wcM4VY4TALfS/hJqTsMcStlSWk
         cam59zhlQzRmTDaMRmEoDlTaaF7PeKYIX+4J76M2ucVj38+asLhzgnpaUkj6636pcFsj
         /+3OH+fm7lo7xnQnoE406miJq/zfZV1v8kenc3yyNrECEdFWjW5TAtx4l+xr3nIqPcVX
         I0/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=BDyRyl3O;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id o13-20020a05651205cd00b0048858e79d43si503215lfo.10.2022.07.13.04.25.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Jul 2022 04:25:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 457D520021;
	Wed, 13 Jul 2022 11:25:42 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id AA0532C145;
	Wed, 13 Jul 2022 11:25:41 +0000 (UTC)
Date: Wed, 13 Jul 2022 13:25:41 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220713112541.GB2737@pathway.suse.cz>
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
 <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=BDyRyl3O;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Tue 2022-07-12 08:16:55, Paul E. McKenney wrote:
> On Tue, Jul 12, 2022 at 10:53:53AM -0400, Steven Rostedt wrote:
> > On Tue, 12 Jul 2022 06:49:16 -0700
> > "Paul E. McKenney" <paulmck@kernel.org> wrote:
> > 
> > > > I guess the question is, can we have printk() in such a place? Because this
> > > > tracepoint is attached to printk and where ever printk is done so is this
> > > > tracepoint.  
> > > 
> > > As I understand it, code in such a place should be labeled noinstr.
> > > Then the call to printk() would be complained about as an illegal
> > > noinstr-to-non-noinstr call.
> > > 
> > > But where exactly is that printk()?
> > 
> > Perhaps the fix is to remove the _rcuidle() from trace_console_rcuidle().
> > If printk() can never be called from noinstr (aka RCU not watching).
> 
> Maybe printk() is supposed to be invoked from noinstr.  It might be a
> special case in the tooling.  I have no idea.  ;-)

I think that it is ok to do _not_ support printk() in noinstr parts.

> However, the current SRCU read-side algorithm will tolerate being invoked
> from noinstr as long as it is not also an NMI handler.  Much though
> debugging tools might (or might not) complain.
> 
> Don't get me wrong, I can make SRCU tolerate being called while RCU is
> not watching.  It is not even all that complicated.  The cost is that
> architectures that have NMIs but do not have NMI-safe this_cpu*()
> operations have an SRCU reader switch from explicit smp_mb() and
> interrupt disabling to a cmpxchg() loop relying on the implicit barriers
> in cmpxchg().
> 
> For arm64, this was reportedly a win.

IMHO, the tracepoint in printk() is not worth slowing down other
important fast paths.

The tracepoint was moved into vprintk_store() in 5.19-rc1. It used
to be in console_unlock() before. The previous location was not
reliable by definition. Old messages might be overridden by new
ones before they reach console. Also messages in NMI context
used to be stored in per-CPU buffers. There was even bigger
risk that they would not reach the console.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220713112541.GB2737%40pathway.suse.cz.
