Return-Path: <kasan-dev+bncBCU73AEHRQBBBHFM4D6QKGQEMCGPIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 834042BB4FB
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 20:16:45 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id 74sf8691282qki.12
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 11:16:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605899804; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZhx33YkXpGso0zcIRP6jaF7iD8is0t+9EjvDxsiehtVu0gMaGgReVU1vrfRd14mPh
         LavpXMN4WC0k7gTt9xfpUkdz3dWLYg88aEHT/gQd1M+h+V8jjCCr97ZYebdDamryb2l1
         qPsQTpH2FkgZE/tW9Mz/p8InlUGMBtnvbG7ObSwC61UXLhfoUilD4LwGbbtgOMRslPZH
         DsncQUEDVwX21NM1WUpGGpe4dVaxHbQI4TJKASxgX/v8pAzJrIxZ4Q4txw6Jma8clJZK
         agU+gtUAUoE7qzIS6fEOCE8c8ZApK+0GzDTEBZPZzs/75NOffkvw9AajTZVQydWqfR+b
         Bmrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1ZTIQwDgHZCzSUSdR7sLdFa4hEKU71N/gwMyAPu2Zkw=;
        b=JFiPQ+xjun98TV1zR8q7WjG5OEl0WWcZFJdb2zDgecc+RFUIHRzUZbREmshP9i12wm
         5LY2hCYiMKZfKn9MNk0r9fCnz+0z1RZMEVYyj+RknlUysh4l92P1fU8gsvC0/fIBv93C
         XJNDigRyZfPe8aCFpaJm6XNPAdv/T6mVS8LNtN9aXL4EgdDwgJ+SSMMOhIN4C4yeKni2
         PIeB2Ij014coCT4VJaGaAJ4AfY34I8YS/s6lk1Z0qrZaICsdAAzWOKwsoOEmlCLDQqBQ
         oEd4LVGFeVgAz/82/zLKFlFtncEMgmx7K+KB6R3lWjhFCDuwLTM1tRjDPKeBFh5BtvaR
         F9Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZTIQwDgHZCzSUSdR7sLdFa4hEKU71N/gwMyAPu2Zkw=;
        b=ngvXO0BnAziGPQewcfw1zAKHSoIhHznSDHkXVu1Th4EGCWp9k9syk0L2gwBjrdpMit
         jlmWsaNh6aZlNNAfomzHGKnjPKqJzMQ5g6mlbFWuMcZw1Ia4A8H51p13mLpo1DKGFAvh
         v6TK/c25ZQiaHQzlKQ1oFBUHuE1qr6QSy7QYjPrsaw9Ze0WumMvApgd0pnXou0DON496
         LaL/MSkqZ/crBHAgKJ3SvYXXjiXb370tNfVtbAYblwVZeoMBvAGoExw87YyTGWsAqyAs
         0un6EHxEqvFmsZgOaVKHvgpwE5pAHxV0p3Rv8UVBRA93NnqAXkvdkMuys5SjNh9u3UGy
         0UzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZTIQwDgHZCzSUSdR7sLdFa4hEKU71N/gwMyAPu2Zkw=;
        b=RipmLpfDZNnX40g4pgjGXy82hoahnIvLY0ecg6u+kj+JpPsu/1mq4fTsKFpZ61A5Qz
         R9C4A+b1RWfSHdVMcY4+AcgmII0unKw19xDSu47lOnmI2uPZrn1sBziP5uM4fwSwhiBi
         gvuclUszFPfFJ7yM4cpHi+O37EokEVglNDElWuvyUQ3BL+w7RiNonQ8fBl5yjmLFHyZ3
         2++4AMGblHfpP7Wry1JNNBmG32gk6nSzPt0MDZEGa/0el7TGdESIAPCQBLagUB4WKGj3
         JJv84DncC3ffgrUUJWOWjb27ZI0b+XKCx6rhOQgQVoZpoHMPk9aPwl2KfczmQ+D0Q/LO
         nazQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kuW/B8IuiMCxWj5tVAB4pLuHsSGmPC9FGhrPt/NSa474+QOmJ
	/nXcZl6m8VJwwAN1CtM6fqw=
X-Google-Smtp-Source: ABdhPJwbaKQiatok5C6BgxvDs+3X9tjRTH69Xj/HohVaVEFBYCIHsQohv1TlRjuVKcbQZL6uIm7qfQ==
X-Received: by 2002:a37:d8a:: with SMTP id 132mr18297473qkn.332.1605899804594;
        Fri, 20 Nov 2020 11:16:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a493:: with SMTP id n141ls3416608qke.8.gmail; Fri, 20
 Nov 2020 11:16:44 -0800 (PST)
X-Received: by 2002:a37:91c3:: with SMTP id t186mr18472315qkd.471.1605899804111;
        Fri, 20 Nov 2020 11:16:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605899804; cv=none;
        d=google.com; s=arc-20160816;
        b=zMJhQSJxcE3HyoOKfAZ/cqib5ZYzT37s0B+VoGjoNtLziuxIfPPonFnECbbesdZUD5
         3Wrs9r1dLkSghgcAwPutECySkVPrGafWruWnhNK5akaFtmaZx1iFHjq8D0PYgLtJ+f5c
         0SZd333Xnpxsm0jQPToXkw5vy9XZg5eMi6e0o7HR63PsvwEjavaQ85a1D4ftpArmU2WV
         jmBiYJVviwWGd9v0T6QTolSRLl0V7novXOVSFMWr3/YIrlNpsSHC29I7aNp/2ycv3CbR
         QBaf2fBnt8xovu09qig0lOmhpuxtnPcVj9zi6en0bHZwTQeo+W0rZQK2Ta8WXcXWvTFp
         TWBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=D6G+7Ias5/J/XsV+dk+kWrIUVBLS5Tt6028mgECth4Y=;
        b=V/KMO9vQeUGjqVVAV9zla/mySUSszc6mOMiiBqc9WfxcC6iVQlIcKKzWogooL65V9a
         KpPmcGjOV5yYrQqUYtVMuNm5BBAvdf1b26RoWp+61kJAlL8mseFWMXHCInnL3ePBqDqv
         sg/kBqtROIluSG8XNT8LMQ2JcQmn525oh26bGsxJE2f91GPVPP2rIW4ZWv7ujlj36ZMS
         ET9TKu00+QLOrTa+SShDMJkdxD/1GzVLfizdCsnvzl+ISOQ4e90QTaltYqAv9t0h67Vc
         PrDNm0i3/sey0xilDJ6JMFThtm7ZrnSp660fgzLDbf/OBNQkWXfzcxVp1uGJfDFxZ6Jt
         Dx8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g6si260909qtr.5.2020.11.20.11.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 11:16:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 308AD22240;
	Fri, 20 Nov 2020 19:16:41 +0000 (UTC)
Date: Fri, 20 Nov 2020 14:16:39 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>, linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120141639.3896a3c8@gandalf.local.home>
In-Reply-To: <20201120181737.GA3301774@elver.google.com>
References: <20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201119151409.GU1437@paulmck-ThinkPad-P72>
	<20201119170259.GA2134472@elver.google.com>
	<20201119184854.GY1437@paulmck-ThinkPad-P72>
	<20201119193819.GA2601289@elver.google.com>
	<20201119213512.GB1437@paulmck-ThinkPad-P72>
	<20201120141928.GB3120165@elver.google.com>
	<20201120102613.3d18b90e@gandalf.local.home>
	<20201120181737.GA3301774@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
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

On Fri, 20 Nov 2020 19:17:37 +0100
Marco Elver <elver@google.com> wrote:

> > > +++ b/kernel/rcu/Makefile
> > > @@ -3,6 +3,13 @@
> > >  # and is generally not a function of system call inputs.
> > >  KCOV_INSTRUMENT := n
> > >  
> > > +ifdef CONFIG_FUNCTION_TRACER
> > > +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> > > +endif
> > > +  
> > 
> > Can you narrow it down further? That is, do you really need all of the
> > above to stop the stalls?  
> 
> I tried to reduce it to 1 or combinations of 2 files only, but that
> didn't work.

I'm curious if this would help at all?


diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index 2a52f42f64b6..d020ecefd151 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -1094,7 +1094,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
  * if the current CPU is not in its idle loop or is in an interrupt or
  * NMI handler, return true.
  */
-bool rcu_is_watching(void)
+notrace bool rcu_is_watching(void)
 {
 	bool ret;
 
Although I don't see it in the recursion list.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120141639.3896a3c8%40gandalf.local.home.
