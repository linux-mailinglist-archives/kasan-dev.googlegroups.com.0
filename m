Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBCEQVPZAKGQEAZMN45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B24B161873
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2020 18:06:18 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id j25sf7059375vkn.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2020 09:06:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581959177; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICU17XWghnu6CfmEnwa+rJHY4p8vvD8TkKbwA3GEnVFvFHBSUxlc2BpqdPwU+TVDBl
         vPvXvlNAssSF4MEmydyi4PSksLNkOoHuIvL2S+bHnVQnSIub0k+r9tTdoA83yL6VvST6
         1xGR6uT9XS2n58618nfibjqY8o6HUQ2N9mdIZiJKoiMJfMDqGmgJ5ghSRGWeKdtcwzKM
         lRWphKu8fTBvDkJPytD3AEQ1mKAvKXlCBIrCBzETHzLS5YUSrMDcEr8Mp/aiKcLtN5mw
         ue4Z512UNyX9/7R9bF8ZI+LM2mL7WbBjNVQsEXfE/U0FfO8a3C9QdmrKGetEBwGtC/wo
         NwEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=FV2axJZrsehGivfHqCLyDIaK6j+SgM7GE1eM/NrI6Xc=;
        b=wk1LZKzFsPXuXM6rwKSeJl4Dhw5qh3iYYu1TkLcKMAuseI0wTnlQQFNuhPjEdxJpV0
         hHnL8+0yI5TX7LIm6jsTJnwat5mDVt+KnjMJz2qPExN8OxP5ZArArs74Yg4EKK0xpyVw
         CUqDr1v1zUkJu6s942ipyoaPlIyuVKXB7mhSqh8dv/n8DFRxiQYuMGgGM/s+YGrRgxDF
         j/u2IUpq1nXlxZlF45tM9fR1FNTo9uDcLDvB4eVS8M+WwYX5mJ9aDjuOuEB5Hwm4T9lH
         bZRFmL7PKJpTr2ARZipczl6+I2XK5jK5Celh91f1V5Lml6HBQIVUezn8ij3f1wyKUOiZ
         GLsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ffd4dHge;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FV2axJZrsehGivfHqCLyDIaK6j+SgM7GE1eM/NrI6Xc=;
        b=aKbp8E+qZxMjsLsL+PiWBUktW+9Z3H1yVXQiKs4mSZd7fY1UUo/+cIJiMl4FwO9zAo
         mIfO7E/1y7QUN0/kGU70txJcDTWsB+FgyMct8x7UXLm3lpeAwy7MEbxnNzbBG0hrLIku
         FpyqmfiX7Q8XTcsbd1Ce/c5vN64keJG+JSMLg+iMeNeIPjjHl5ZBAcKFY8eUnm+Fxknf
         hXz5IHPHoh/xEPbR+3E0eWWF8jW8SSwKckV/lk6h6H1J7Z0kB1MewaOPtOCMl7jett6c
         U6JWLePQpM6tmfzNGG6okT/YTlMg4jJPFdh/9FxwEnLEEOw/ajYzLLp4G90AjS6nRwK1
         MeKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FV2axJZrsehGivfHqCLyDIaK6j+SgM7GE1eM/NrI6Xc=;
        b=f1iZZMpD+0Fld/JpyMWWBLRhZ9vQnzmCoEpl+un4VyZv1gaGveHQkbH2Jwjbca82MW
         VLX36PtTPzhzd7n965LgJzjRdK6h9en99DeqKem5tpxtqfk0jVFC6NB8EslJEU9utJVE
         eVpkVx1RUN2/RZcnInzRbQ2z+BZjPetMkF6KgsZ1KqBKGCGOooprjD9OByrWvCXWH2Ik
         r5i+OXJiqeAy8cgdL3biY5tKXPcNL4LXyf6i+8/cGcxvRdr0lPzu8Zs1d26nt0MeZj/A
         f7CY01zFeg7vRG8zfGqlRIbFCCyqLierB7r131KSmSUxdlIrz5tkmkxxHLj3KHdfcm9p
         OuGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWbQEl2FJ261CzFVlC/vJq9j7L1P1VnAZgQt9h8UNM4yIGv1++u
	QWeGgVd0Sa6UCGXqMAzSoto=
X-Google-Smtp-Source: APXvYqx3+QMUWgrzsmkDSNuEhHPEW+mMExZRRiL9rPn1VlK8U1APSxa9k2E+gT4YA82d4SVJZtp7DQ==
X-Received: by 2002:a67:ee59:: with SMTP id g25mr9020956vsp.186.1581959176914;
        Mon, 17 Feb 2020 09:06:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d38b:: with SMTP id b11ls1177496vsj.9.gmail; Mon, 17 Feb
 2020 09:06:16 -0800 (PST)
X-Received: by 2002:a67:ec4a:: with SMTP id z10mr8378371vso.73.1581959176531;
        Mon, 17 Feb 2020 09:06:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581959176; cv=none;
        d=google.com; s=arc-20160816;
        b=lJOOPDXCARa5sriCL7RpQMBeEMqk6TgjWAbIF+CwFQL+s2xEm550vSzCS0WWyQ5T+x
         TzXmw42i0oa0OrvuBEK+1fi0XTEKvTyUs7JGwcWL5fyKg3wnWpRgj1f+zre7O5L8MhHw
         7cMZo4hrGD8NrH8MmMqFARefFGHSeoVu2T7hh+CDI+pqqQ6QD/OmgUX2rqPdQu+Bpb2u
         otBMEjNcnZl7sSaYMtvU/a0RVRPIuxjIxuCGNUsvd/yawjGTTP4cH2453XNvTRN206Vv
         DB08txqL/GTQVHz98XH/uPtrQRSahvtPr79zaiyWyyNl/KfrKZ80g4AoC2f8OssXAvbF
         Ldtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=L6P6i8QYBtrRLDhCjXcjIS4jJjXwildK8xh5dBjAjQw=;
        b=abnaNRY2DNKsKWFBYL4jflN5oM3P1sTBqNlnFOUNcspu7FN04MiR8pg/b3lS6luwOF
         OlnNHTExzRnAnO5Z9YGmlHXH+c7DYYYcoF59lZ64aWrPTZlBLbXLph9oyQ9D4+j5LrDr
         VPAH2SGQum1G0pjx3mJJoLsuKEMdX/Dnnv9dMbxbzSfmEeogORGfZMnSwnLkGOodPGUm
         P35mAPYkU0tEsM+38OpHWkKYw6kb04Nhm6/AXGwlBNhMFTnXa0IaqZT8EgOdXWx7B9EZ
         xoU1MSNDkt0pNw+AiKO4Noyb84LRwkNjeeKrvTEzO3FR87lp5JXDvukdKQGxbOFl3k7u
         q/Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ffd4dHge;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id t76si60648vkb.1.2020.02.17.09.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2020 09:06:16 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id z3so7900104qvn.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2020 09:06:16 -0800 (PST)
X-Received: by 2002:a05:6214:707:: with SMTP id b7mr13001067qvz.97.1581959176043;
        Mon, 17 Feb 2020 09:06:16 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id w202sm514179qkb.89.2020.02.17.09.06.14
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Feb 2020 09:06:15 -0800 (PST)
Message-ID: <1581959174.7365.88.camel@lca.pw>
Subject: Re: [PATCH v2] kcsan, trace: Make KCSAN compatible with tracing
From: Qian Cai <cai@lca.pw>
To: paulmck@kernel.org, Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com, 
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 rostedt@goodmis.org,  mingo@redhat.com, x86@kernel.org
Date: Mon, 17 Feb 2020 12:06:14 -0500
In-Reply-To: <20200214234004.GT2935@paulmck-ThinkPad-P72>
References: <20200214211035.209972-1-elver@google.com>
	 <20200214234004.GT2935@paulmck-ThinkPad-P72>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ffd4dHge;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Fri, 2020-02-14 at 15:40 -0800, Paul E. McKenney wrote:
> On Fri, Feb 14, 2020 at 10:10:35PM +0100, Marco Elver wrote:
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
> Queued for review and further testing, thank you!
> 
> Qian, does this also fix things for you?

It works fine. Feel free to use,

Tested-by: Qian Cai <cai@lca.pw>

> 
> 							Thanx, Paul
> 
> > ---
> > v2:
> > *  Fix KCSAN+lockdep+ftrace compatibility.
> > ---
> >  arch/x86/lib/Makefile | 5 +++++
> >  kernel/kcsan/Makefile | 2 ++
> >  kernel/trace/Makefile | 3 +++
> >  3 files changed, 10 insertions(+)
> > 
> > diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
> > index 432a077056775..6110bce7237bd 100644
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
> > index df6b7799e4927..d4999b38d1be5 100644
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
> > index f9dcd19165fa2..6b601d88bf71e 100644
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
> > -- 
> > 2.25.0.265.gbab2e86ba0-goog
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1581959174.7365.88.camel%40lca.pw.
