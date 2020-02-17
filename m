Return-Path: <kasan-dev+bncBAABB2V4VTZAKGQEOTFLHGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54424161DC2
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2020 00:14:52 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id z79sf15525426ilf.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2020 15:14:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581981291; cv=pass;
        d=google.com; s=arc-20160816;
        b=BVPBiEcH7wIJlysWKo09YUE1wDKEvN2cryOP05CEHcwoKvdsn6s1H8aH1eOdx57/O9
         MXAKV7oAekn87AtDYyOoMS84CTa9kVDE81r7ieBr7shKPedXbMTS2W+jBomnV8nwZR0b
         ODV6i6qpMBxw1oj863sZEOYUKucFa6itXMeQ/VNs0r/z0QqDAIkVqkBdk4axiLf2sGCN
         m498Ybr/Hv70WhUObEu4XnDXYBoH/TxJn4rwEWTelX/3xcI1o7aOH0jwJkTJyD6mE0DN
         Xes2uVeH+5tbL5t5F7VLhj6EfXKjMDaDE22h4d1gPr4424xcl8D6AdZnDGkfL6c3dp1s
         V9sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=I7twxlPE4+5vDH4LFeZy6LHdgaafi9B7L9dBsYvceVA=;
        b=b+1mfkVww7YzGeNMkvAVZOf7f4/YAjbKx+z90uG2BNXwtS1yCpBbseDuCnUCovEVHj
         mkePs6CefAwJSbRJMjY6BUNnfAjrKsPC1xsp3HGahcIdJi1a+pMjmwN0ATyGydTA6raK
         91CsjWqam2V5wGmfTriMRKkziW1ytukm/AhNzraUIdOupcttSDcYLdTOE6PTJHcjPboj
         OtbNeZpgw6u7fLbe6e3n3b9648NNrzuvcukIIU9E/tiM1OENbDW4DBzz8I6TMUcM6SJk
         jW85BYm9odMAT9AQ/sxRVwlYzhs5q7L14RiEnltQvjZ4IF2+62TmYDdlXpQjqdTq/CWH
         6vsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0tIto54V;
       spf=pass (google.com: domain of srs0=8nzw=4f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8nzw=4F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I7twxlPE4+5vDH4LFeZy6LHdgaafi9B7L9dBsYvceVA=;
        b=MDlerHzta9r364ZkjLtArm2LiIiwgt/Xc4reBvdPN038NB7YzncEzPoKoCx6pp7Qif
         JNpbiYKPkRBpVKibL1GvIAiL0oc/aHBRuwaat/vuxMJy+hfQV95dOMgRqtLW66vriRdX
         vdHwHQxSiWcCCiWaZrFYhpc9Tpyq99726Fv3bF6kk0ZYPEvAj4Vg/Q6/F4htMAQTC/6Z
         8sHbdS+fQNrAFyOhS641PMIq/ZpV5FhoZkhxIcUTAZlW1irvPSJxgEMI3p5QAZBj2/cp
         fO//GkCL6VeNsyiZDDRgpl9giWDjC4HC9rrbIDegOmY4LKLQkENG6U5Y/cu7SecZLo8n
         9VTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I7twxlPE4+5vDH4LFeZy6LHdgaafi9B7L9dBsYvceVA=;
        b=OURpSV+iuI+b+0nzWtnF9DgaPqgHl3dVxMYwvye2aPsGINfo8Lci7kMnhETj+v44An
         e4YIw7E8wjKka5CEE5jUdMTRskDl5AmdSizj30rXutY2uOxJFF+pB+TG7qaB5tdS/RPi
         vGjzgTZG+H7bPNs+QJhm/uAsIjsckxQgT1RnW0I6LuNX5Ez0b8+74ol1v/WMXsn+c4iY
         rrnQ+tvlx585PGG28xsKPMRO0NBPACzWhU9ht8xlWlSaaRAwvpOjD7CNeRcGDoiY0RFr
         RvAasy7CFLv7Wus24idT+rWlpxkCMKWG/HbGr7Ntc6plqF2HA/YV9kHi/gO1dDOtpilr
         QdJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW6PHS2Om/OJbhC7eSUaVWOkHsdPg74Pb1Rz/4Am6gfH8lhRqdX
	+2Du+UwWjpwLzM8tVhAI104=
X-Google-Smtp-Source: APXvYqxiaQFQ8H4IZlXsbHOiEtUZp70GgXChEe0wq6yZ1t8Vmiv1Ag72QeTeJc1PF4Jv5dQ54xZayw==
X-Received: by 2002:a6b:c742:: with SMTP id x63mr13887669iof.162.1581981290989;
        Mon, 17 Feb 2020 15:14:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a791:: with SMTP id e17ls1176896jaj.3.gmail; Mon, 17 Feb
 2020 15:14:50 -0800 (PST)
X-Received: by 2002:a02:390a:: with SMTP id l10mr14390237jaa.42.1581981290633;
        Mon, 17 Feb 2020 15:14:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581981290; cv=none;
        d=google.com; s=arc-20160816;
        b=LKCDfVkc4nN6lZnVW+H+Hm5YtBrNxkwj5vsnReqSgvBJOsb+RUmtq3sXHR75UY3hSO
         WEQSU83oMXZCzG3yMAU8CTztVrK8XLhEbvVM/dqRcL1ClW1HslUy8rxlYcyzadGeethY
         TPE+gklwmUAlCw/dWr8dg3eoa1dsH/MTMwLek8VM+g74QHxzVg9M87+/QbuwOf2vhCHx
         KM/n0rdnV2v1nwdT0vcDUlMTF6A8DRBwE5WxDD/qffrEdtkXFUsuW8Y7Qur8636LJrLb
         9O+KFVg4bq0k0Qd22pt0cH/EJldODwHIsAHA6+LIOAQgXLCS9clk62W6y2/I2kD7qAuo
         pp6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=JoHzBJRJuq7JzPcDo3r0B7mAFUqN75U2piCXd0s5TP0=;
        b=ejBNfOKQNYYQ7cXqW78WHNr1F9Y+HmGrMuxbBNCyQQqluNe//fomxXrUA4uCI/lvZ5
         hfo0/TPDBNfB1AfQNwn9eQG4wfjA2GCowq7VkgIO7sTXhw0bVmW8jPiWp5cuawQcnycS
         +gKNX+O9KPIIiJsU3Ftzzk1whGyQPcHUJz+BEHt6BnrUkuXREAM1T67+Rss9+RBRz+eB
         In8ZCtudWHqrtN1kgUyLTAQjPidsaFfGmz42txDucRzT9iClegb/U+qZkHmL4OLz9wic
         geCG23Gd+Hmb+6cVS3UnhFJGjqArgRqaFtM1vqg9lAnzjrxEECmyi+irrXxACeC91Viv
         CNkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0tIto54V;
       spf=pass (google.com: domain of srs0=8nzw=4f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8nzw=4F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h4si87784ilf.3.2020.02.17.15.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Feb 2020 15:14:50 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8nzw=4f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id AF81E206E2;
	Mon, 17 Feb 2020 23:14:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 836F735227A8; Mon, 17 Feb 2020 15:14:49 -0800 (PST)
Date: Mon, 17 Feb 2020 15:14:49 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, rostedt@goodmis.org, mingo@redhat.com,
	x86@kernel.org
Subject: Re: [PATCH v2] kcsan, trace: Make KCSAN compatible with tracing
Message-ID: <20200217231449.GB2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200214211035.209972-1-elver@google.com>
 <20200214234004.GT2935@paulmck-ThinkPad-P72>
 <1581959174.7365.88.camel@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1581959174.7365.88.camel@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=0tIto54V;       spf=pass
 (google.com: domain of srs0=8nzw=4f=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8nzw=4F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Feb 17, 2020 at 12:06:14PM -0500, Qian Cai wrote:
> On Fri, 2020-02-14 at 15:40 -0800, Paul E. McKenney wrote:
> > On Fri, Feb 14, 2020 at 10:10:35PM +0100, Marco Elver wrote:
> > > Previously the system would lock up if ftrace was enabled together with
> > > KCSAN. This is due to recursion on reporting if the tracer code is
> > > instrumented with KCSAN.
> > > 
> > > To avoid this for all types of tracing, disable KCSAN instrumentation
> > > for all of kernel/trace.
> > > 
> > > Furthermore, since KCSAN relies on udelay() to introduce delay, we have
> > > to disable ftrace for udelay() (currently done for x86) in case KCSAN is
> > > used together with lockdep and ftrace. The reason is that it may corrupt
> > > lockdep IRQ flags tracing state due to a peculiar case of recursion
> > > (details in Makefile comment).
> > > 
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Reported-by: Qian Cai <cai@lca.pw>
> > > Cc: Paul E. McKenney <paulmck@kernel.org>
> > > Cc: Steven Rostedt <rostedt@goodmis.org>
> > 
> > Queued for review and further testing, thank you!
> > 
> > Qian, does this also fix things for you?
> 
> It works fine. Feel free to use,
> 
> Tested-by: Qian Cai <cai@lca.pw>

Applied, thank you!

							Thanx, Paul

> > > ---
> > > v2:
> > > *  Fix KCSAN+lockdep+ftrace compatibility.
> > > ---
> > >  arch/x86/lib/Makefile | 5 +++++
> > >  kernel/kcsan/Makefile | 2 ++
> > >  kernel/trace/Makefile | 3 +++
> > >  3 files changed, 10 insertions(+)
> > > 
> > > diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
> > > index 432a077056775..6110bce7237bd 100644
> > > --- a/arch/x86/lib/Makefile
> > > +++ b/arch/x86/lib/Makefile
> > > @@ -8,6 +8,11 @@ KCOV_INSTRUMENT_delay.o	:= n
> > >  
> > >  # KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
> > >  KCSAN_SANITIZE_delay.o := n
> > > +ifdef CONFIG_KCSAN
> > > +# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
> > > +# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
> > > +CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
> > > +endif
> > >  
> > >  # Early boot use of cmdline; don't instrument it
> > >  ifdef CONFIG_AMD_MEM_ENCRYPT
> > > diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> > > index df6b7799e4927..d4999b38d1be5 100644
> > > --- a/kernel/kcsan/Makefile
> > > +++ b/kernel/kcsan/Makefile
> > > @@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
> > >  UBSAN_SANITIZE := n
> > >  
> > >  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> > >  
> > >  CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
> > >  	$(call cc-option,-fno-stack-protector,)
> > > diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> > > index f9dcd19165fa2..6b601d88bf71e 100644
> > > --- a/kernel/trace/Makefile
> > > +++ b/kernel/trace/Makefile
> > > @@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
> > >  ORIG_CFLAGS := $(KBUILD_CFLAGS)
> > >  KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
> > >  
> > > +# Avoid recursion due to instrumentation.
> > > +KCSAN_SANITIZE := n
> > > +
> > >  ifdef CONFIG_FTRACE_SELFTEST
> > >  # selftest needs instrumentation
> > >  CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
> > > -- 
> > > 2.25.0.265.gbab2e86ba0-goog
> > > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200217231449.GB2935%40paulmck-ThinkPad-P72.
