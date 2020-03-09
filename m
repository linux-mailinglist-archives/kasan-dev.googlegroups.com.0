Return-Path: <kasan-dev+bncBAABBJGNTLZQKGQE2GXYHYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A2A2C17E9FE
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 21:27:17 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id h8sf17445623ywi.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 13:27:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583785636; cv=pass;
        d=google.com; s=arc-20160816;
        b=uzsfUX+fS+B5Dra4AkEfKZ7Y2RNptMqRN9fY/r7zkVMq05OaN769mgPGKOKfvwJWpi
         h6KXU+LdXEmJAjjNAVoKNf8Mb43XvHJ38avT6thlq2lZsGfgZ1QQNEb0FEe61S0DtVO/
         6hkh57lw3/cBWo+KlKETb3jRF9U0vg2rIXvtCczQxQpzTXnb4vP7GuXj0SV0uEBchVh2
         Y+kDi0jUQvSXRh50z/ogR9USpjPWHLcYR6B6IOBhEIdppQIXMCrOva/3Yo8ocC3ZnRlS
         rp7oC3PBsWPSRf217eHD4pe823lIMs/aQJCUs8ooyBV7keGU9/oGBoGD/uISyXRt9nQg
         SeWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=x6oqY46GNIdGiREzqcwSU4/ei7eqT60So05sERi8AVM=;
        b=HwNP2T78lS0C+E7gWLae2YIvtLh/bdxGeXAw/Bw58VUnesLECkUaeu0UnyrC8k2G6b
         vSJBHrZ63FE1CSxCfzlf5wjxbET5lzqhc9gX7no6oqQ84QEQpzhI8WQynegPo7DR8ZTe
         j/OKjWlWDBq+vOI6KEUu44vRz8NTCLiLHsLeC+F7cj2+XsGJva4m8HYaXkWP/vMWpBzg
         D7eFe2ZDNxR9T5+uP+Ci58U/bHU8atcD/zx11UnjRTO95BllyrErPdscoKVKSsfawrgp
         B0WmQhGpV64u/iIhb5gUzCWWOxMF01myNQazQtUMF79rPvAhoUueOO1XaMtBImmBPKSm
         k40w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wKWOOwaE;
       spf=pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x6oqY46GNIdGiREzqcwSU4/ei7eqT60So05sERi8AVM=;
        b=BXLdv1WAHWIMWRXi8snPxZeCNksxX4wUpmwYX7IirXCKfrU4uQduMsCMKTy3Gg1ks4
         NMBGyQsd+1ql9t/LuY5RUseSbe8261Mzi3+bu0omOj4Wqc5ttFM6AD/A56oRhsorjZGG
         UFl2ATNKh+03ZaBNayCF7SRJ54g32e8r50iUXYW7Cc5OK2zBgEQc3inZ1K/5hQPXnzO/
         aaJ0ao836+tZjykWcfhLv6QyL1Gmi7ZakpoYnIHza6KNKQIbtl/rj1Efn/jnZP0Zd0Lj
         wZmsLOFdNUJhDMEIYXhfi/SzcRNO2pxcVgsPbEWp4OZr36c8FhJBDyzHCEyeVn2MYWK2
         1jrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x6oqY46GNIdGiREzqcwSU4/ei7eqT60So05sERi8AVM=;
        b=PdncoRafnx5r5h6FLo8v54LwxQYrFXuNhsHO8uz1C6B19G3WUPAmABQlE11rcYeYbl
         e2fd+QmgAsaXaiMA0lwH2GUBRw3gQaCUxKL5bOqV6JXC6f6331iiPutFJTDiM9BJiBB/
         GABkTNo/Dr2uh2vwMEhu5qTwH1+kUjZmC4oK6tflNzbxOquHWO6Yov6zPf+c3T7IAz73
         0ow2VFSEuorzJjRzbj0bfxKBnTofzYyg/p5uVXGEvgdu6TCsXhKtsUqkDSmwCrwUWDep
         FihXhkBtSOs267hX0AtBN6wjmOw6yS9HRsA9JbFHiOA1bdakONIghUquHnN3QaQD0EvA
         VRoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0upIf67e+hkEef7RrOJQg/JZNwsM2QHkxmsgXpk3vmPKlACT+C
	nKfZzpKDaSb9c57yU6yOKUY=
X-Google-Smtp-Source: ADFU+vtP4Ecuj+PQOp4HYSuSnky9J1Ykoi0OfSfvgVIUI+XpTW5AZF65CQMsf3BUTrzkI4V3BzR9SQ==
X-Received: by 2002:a25:6806:: with SMTP id d6mr11187444ybc.326.1583785636685;
        Mon, 09 Mar 2020 13:27:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ae04:: with SMTP id a4ls3013415ybj.10.gmail; Mon, 09 Mar
 2020 13:27:16 -0700 (PDT)
X-Received: by 2002:a25:6842:: with SMTP id d63mr20769598ybc.471.1583785636190;
        Mon, 09 Mar 2020 13:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583785636; cv=none;
        d=google.com; s=arc-20160816;
        b=otV+Nm+vCrKqRdHfIJXk0ff47A3szuBts+43XM/+1VhTn6meFencsocD3+05G0n5bN
         aBkcnWE+IEfIcnNHY0AI7yIAvkSvlnySkzY3wA1HOw9y+AL2bKbe9sLhGU5c/bhQ+fKW
         K8ejj1tOZ6bFwyneaaqC3Z7jxkzC9W7zmJsET5FbuLOwlz4VlhkqTBnWkZ7YgGDDXAGo
         rpjdfS4AhaKWWjqq4PNQWChSqPXXyPK/6g+olkMzepObvegfaw2jBmorWgeDSppg88WB
         e5WVMgbvdul/Lh97D4CCbqZe9g0qFHdkUDO38OoCKV2/rM6mX3owKw/K/K/0We/7h+VK
         wVhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=n5RAGSbBDZ7TFokXAqCOWUGjmnKu/3jYDsvs7r2ZxQg=;
        b=cqyZsL71AYKxZdKHbULp+63gHswxjBa9JOpJsbzWjYFPedLcL1WxPv4hx3UE3LXNXg
         XFw0L8/o4e1qZYJCXRuO+PNJkS/bmn0xZ14GI+HpDEcVOVwlUxXb15LIDmqYWRHVKiX5
         Z3jYkC36AgShOc2RdCghRixrUk8WU/08ol+gKnGd5LqVDb9H6rCOT2OXvKlcx4K/aF1a
         jEckg6XghK+HpZtoShWvwiv7+Kxx4MQjAUCUDCerZZPiKqFMD4qeF3p0a3qXLJmEEHL+
         oIhJYKkSWZOxwzrH1boeuy7JVTs+KEN5giLOFgfyW9m/jqM+zb29KX+kyro7pm9NAEJl
         r3CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wKWOOwaE;
       spf=pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l23si238370ywa.3.2020.03.09.13.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 13:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2675620409;
	Mon,  9 Mar 2020 20:27:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id EB47E3522730; Mon,  9 Mar 2020 13:27:14 -0700 (PDT)
Date: Mon, 9 Mar 2020 13:27:14 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw, boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 26/32] kcsan, trace: Make KCSAN compatible with
 tracing
Message-ID: <20200309202714.GT2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-26-paulmck@kernel.org>
 <20200309155722.49d6bb93@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200309155722.49d6bb93@gandalf.local.home>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wKWOOwaE;       spf=pass
 (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 09, 2020 at 03:57:22PM -0400, Steven Rostedt wrote:
> On Mon,  9 Mar 2020 12:04:14 -0700
> paulmck@kernel.org wrote:
> 
> > From: Marco Elver <elver@google.com>
> > 
> > Previously the system would lock up if ftrace was enabled together with
> > KCSAN. This is due to recursion on reporting if the tracer code is
> > instrumented with KCSAN.
> > 
> > To avoid this for all types of tracing, disable KCSAN instrumentation
> > for all of kernel/trace.
> > 
> > Furthermore, since KCSAN relies on udelay() to introduce delay, we have
> > to disable ftrace for udelay() (currently done for x86) in case KCSAN is
> > used together with lockdep and ftrace. The reason is that it may corrupt
> > lockdep IRQ flags tracing state due to a peculiar case of recursion
> > (details in Makefile comment).
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > Reported-by: Qian Cai <cai@lca.pw>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Steven Rostedt <rostedt@goodmis.org>
> 
> Acked-by: Steven Rostedt (VMware) <rostedt@goodmis.org>

Applied, thank you!

							Thanx, Paul

> -- Steve
> 
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > Tested-by: Qian Cai <cai@lca.pw>
> > ---
> >  arch/x86/lib/Makefile | 5 +++++
> >  kernel/kcsan/Makefile | 2 ++
> >  kernel/trace/Makefile | 3 +++
> >  3 files changed, 10 insertions(+)
> > 
> > diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
> > index 432a077..6110bce7 100644
> > --- a/arch/x86/lib/Makefile
> > +++ b/arch/x86/lib/Makefile
> > @@ -8,6 +8,11 @@ KCOV_INSTRUMENT_delay.o	:= n
> >  
> >  # KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
> >  KCSAN_SANITIZE_delay.o := n
> > +ifdef CONFIG_KCSAN
> > +# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
> > +# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
> > +CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
> > +endif
> >  
> >  # Early boot use of cmdline; don't instrument it
> >  ifdef CONFIG_AMD_MEM_ENCRYPT
> > diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> > index df6b779..d4999b3 100644
> > --- a/kernel/kcsan/Makefile
> > +++ b/kernel/kcsan/Makefile
> > @@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
> >  UBSAN_SANITIZE := n
> >  
> >  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> >  
> >  CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
> >  	$(call cc-option,-fno-stack-protector,)
> > diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> > index 0e63db6..9072486 100644
> > --- a/kernel/trace/Makefile
> > +++ b/kernel/trace/Makefile
> > @@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
> >  ORIG_CFLAGS := $(KBUILD_CFLAGS)
> >  KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
> >  
> > +# Avoid recursion due to instrumentation.
> > +KCSAN_SANITIZE := n
> > +
> >  ifdef CONFIG_FTRACE_SELFTEST
> >  # selftest needs instrumentation
> >  CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309202714.GT2935%40paulmck-ThinkPad-P72.
