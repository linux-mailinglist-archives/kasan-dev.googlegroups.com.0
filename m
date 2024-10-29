Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXEUQW4QMGQEWYV7I2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CF029B5470
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 21:49:34 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5c930ca5d12sf219149a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 13:49:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730234974; cv=pass;
        d=google.com; s=arc-20240605;
        b=UIGm99n3tPcrWKK7v0GqpOjBZ5hdibXEkpXdQBWkHmudrYgfOXGAH0R+i8tGrZ76ZQ
         nJmnfOFigEBRTCzQTdJC5Rm1qNirGHb+3BVMLqX7vwwIg+aqV81nkcCCTcQny1M7Xy9m
         50uzch0LsOL7D4pZIwHyC3rkl1bcG5i8FMJuhR22pdPkT59m2FJ4cgA0AF9B4IXyiQol
         mdqfNTdrKbjY11dPOvijnsHiGNKALDMonzEsPUyYbHptqxW9nFAfVzBQUVPFIH9zjHAf
         6i15qmH5upNxEzhhg06ztZK+N/u/8Lr/Cqf0aLKcJKJQfL3ASMj9oycQ33wy7cFOETa5
         7VvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Mp5tqHUn4Ok/40Voh6zLNggvj//pvhjRmUzL5f7fw4E=;
        fh=tN5lTlrTYlbMJCzjacpAzvkw5Q5OEk+wB8C5JG55T0Q=;
        b=VQi4hhdGFzJyz2o3w15Yk7I5v/6Ikr+fMZlxpoSyFBcZv/m3Rom5uYgmgZDcUzXhli
         9xbQt0GzuSjdQ5/tIzIblChOOM2CFmAtJO+0AblC2g/4pEBmvOJD94wlpbwZ8A/AXw/z
         I6JadGF+blCdJu4h0KzCXeqdvFEfnsIPbX86b3mdrCD+tVN31jhH8gF+EbFSGwfND1O5
         eM+4Hq1kf33qngxqB2FNPYG8UYPaM2G8x5ZCjzcq4oR7D0QqzRjA5wzLNAMy/33jL8vj
         lPiyepKshT8NDKU9BAvhmRHCtqePPFcJHmw9JqB2lq6s55flziPFjlSnnwk0tar1xTyF
         WYSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=r8MzT7jT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730234974; x=1730839774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Mp5tqHUn4Ok/40Voh6zLNggvj//pvhjRmUzL5f7fw4E=;
        b=Vr2V+d0gMJuN5WTIppAsLGMauNFfgapagldWFr2am1xONSvvvLtYkhecYXtpoPWGg5
         bcH33O98JQUQN+so93nNeypCfNhbgx6LUslTkBH+LIWPT9WGv+ojnsD20slaljuPjqI6
         esgnY1yCYbHb5BeUrgUyYHFvYMsqP4ErerQwwB69i4fsFiAztXe25CJBqg/4602G1BIJ
         1IkNZ3/ZjfsxcsyIFdmMoWiFvXAOWn8WK63yAZ+AKDc550wxrwPOLHaX0/FH0LWW5swW
         Cw0AFNLNwyA9O0EH9nAFKwFKfOjYMCFjGnTCVIgg7fTG0FjpFbd77ohHUZPEEeKhis17
         kEww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730234974; x=1730839774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Mp5tqHUn4Ok/40Voh6zLNggvj//pvhjRmUzL5f7fw4E=;
        b=b53/+f1C1ejS5rGkI6/vNTSSyRqURIeEziq0xDjEJb9bfm9oPNMBuWLpWWVpGsor68
         Aeqrl1fKc73w5XyMykM4Vsna7m+Wb6AcWSBFZsvPnjoyJsuPE4xq0zkwcWAoeI2eT4Xw
         pyw3NBHWvI6RolZ5uVwAZTj2jWQIY/tYRrzDzFbWCn9cKwOFhNzIXlQmbasF1IBVc53M
         d/W+6YL1vo9Mn4+TMncfNdck14TpsnDLAcOWBLVgAfSdQUdVlAanWv2Fcc/qiwUI9+Ev
         obKlZixqu2x33yV7kD4ZAh+tJ4jRiWYZnSIq8Mec8kHp9bpW1JfJqraYHuFZp/NIu+AB
         KgAQ==
X-Forwarded-Encrypted: i=2; AJvYcCVe220uclGVfOaSNtwG0/z6OFyzz2j/IUVsAaIuISs8A99k+FvuWi1AAhlaSD4sB4oGLM39eQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw052AptY6Js+FaD9zWIfzB9eYBw6O2XdVFxA2eXaApjd56PXDL
	/WkjHlEih9SDVWMPvuEY4tocgQV5bEJwTELbWI10AtzfA4lD1dfX
X-Google-Smtp-Source: AGHT+IGBgIpYUKawA5pW3kpCoh41iqYWqeRtjrRp5cC33m004NLo59Z9JGsYQgsA3XjgsSGVJp4v/w==
X-Received: by 2002:a05:6402:1e92:b0:5c9:46a7:527 with SMTP id 4fb4d7f45d1cf-5cd2e354f09mr3579746a12.17.1730234973288;
        Tue, 29 Oct 2024 13:49:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:549:b0:5cb:b66f:8fd with SMTP id
 4fb4d7f45d1cf-5cbb66f0b4als203261a12.1.-pod-prod-00-eu; Tue, 29 Oct 2024
 13:49:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQ2SK+YhHJoLxGJpyOU5R4GLvDD4/BxkRVd06TXbP+ItsCHPPTVn3zA8nZ+kPwvpWaotG3xTrH5y4=@googlegroups.com
X-Received: by 2002:a05:6402:e9b:b0:5c8:93fe:3f7e with SMTP id 4fb4d7f45d1cf-5cd56438a0amr54417a12.11.1730234970700;
        Tue, 29 Oct 2024 13:49:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730234970; cv=none;
        d=google.com; s=arc-20240605;
        b=B5TQE8cEaE9hmDcG+GKkUG4xfRoVNdy+yecFj+eBi9n+HT4W17pFiMhz3bMWr10Jg4
         cLGiJRY4lg8hW3UWMiGeZlqVgwQgOdDOultgeLKcBtUuCVnWn9b/z32WUqjD165UMr6G
         S2k5b79h35VRJ5fiNOWKnv4W5XG+cP45TXzLP5y9nUrEXLg0Dcit+jTn5SM4ABboBp/H
         XgO1UA5uFV/wT9CDZQ3LPvHT5i7aa/ysuQFTr8QVb8+mEQOGrbjVx1U4JKFWG4L2ln7S
         42cvY9wWcRTmFHEE7WKzDPDHQRG5I3JNiFWuC+zMf5RB0xN6dzkHFa0ld/pHb//fL+9X
         XS1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sAvGabJbVQ0MLApUMZF9EFIEnk5suR68XuTbaLM5KAs=;
        fh=LOVuQYgKeBK6LBY3MvZrq+aHd2reqwhCEP0kqfIIoL0=;
        b=LFWklkH6zGAAmxCbCJqO0e1DKk9UC5UYuZRcrhXxL7egtO4Bk9p7gAnQyyHDw64hvd
         fnl5kqE6LFB6XCvTtfJC8WMH/q/dq6A1Ue6FO2hmHA3lOPVYQ3SHqgk7O4hQlPDawfUo
         MkxXtG9/bScIQBiSRdmOe1va/+Q+n6MwcrSNi3s2+JaYFlcjfYviAxEFjM9/kt5iYNpd
         T8CaJZ2x8oxse8/kh+w10XhBUJD7OR64eQThmmwCAelAkjhAx4WuN0sylimGkZse98a8
         V+s1nsYMmFU005Xgokc6DZlAZzo2kpJgNIxRoD6pL0bCof0W0Qc98+2bx7Bcv2Z4lfqN
         ZtYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=r8MzT7jT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cbb6314024si154447a12.3.2024.10.29.13.49.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Oct 2024 13:49:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-431616c23b5so1702995e9.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Oct 2024 13:49:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUjTxwwPCdHGlOMDsb/Of36hOa5IGLS7dsczUQ5Mfl332yJZ/SiG/iTr6xCKJ70+hAe0DEE+C7yj2Q=@googlegroups.com
X-Received: by 2002:a05:600c:3594:b0:431:9340:77e0 with SMTP id 5b1f17b1804b1-431b5727b99mr32087645e9.9.1730234970120;
        Tue, 29 Oct 2024 13:49:30 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:7cc7:9e06:a6d2:add7])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-431bd98e7e4sm305295e9.39.2024.10.29.13.49.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Oct 2024 13:49:28 -0700 (PDT)
Date: Tue, 29 Oct 2024 21:49:21 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <ZyFKUU1LpFfLrVXb@elver.google.com>
References: <20241029083658.1096492-1-elver@google.com>
 <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
 <20241029134641.GR9767@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241029134641.GR9767@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=r8MzT7jT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Oct 29, 2024 at 02:46PM +0100, Peter Zijlstra wrote:
> On Tue, Oct 29, 2024 at 02:05:38PM +0100, Marco Elver wrote:
> > On Tue, 29 Oct 2024 at 12:49, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Tue, Oct 29, 2024 at 09:36:29AM +0100, Marco Elver wrote:
> > > > Reviewing current raw_write_seqcount_latch() callers, the most common
> > > > patterns involve only few memory accesses, either a single plain C
> > > > assignment, or memcpy;
> > >
> > > Then I assume you've encountered latch_tree_{insert,erase}() in your
> > > travels, right?
> > 
> > Oops. That once certainly exceeds the "8 memory accesses".
> > 
> > > Also, I note that update_clock_read_data() seems to do things
> > > 'backwards' and will completely elide your proposed annotation.
> > 
> > Hmm, for the first access, yes. This particular oddity could be
> > "fixed" by surrounding the accesses by
> > kcsan_nestable_atomic_begin/end(). I don't know if it warrants adding
> > a raw_write_seqcount_latch_begin().
> > 
> > Preferences?
> 
> I *think* it is doable to flip it around to the 'normal' order, but
> given I've been near cross-eyed with a head-ache these past two days,
> I'm not going to attempt a patch for you, since I'm bound to get it
> wrong :/

Something like this?

------ >8 ------

Author: Marco Elver <elver@google.com>
Date:   Tue Oct 29 21:16:21 2024 +0100

    time/sched_clock: Swap update_clock_read_data() latch writes
    
    Swap the writes to the odd and even copies to make the writer critical
    section look like all other seqcount_latch writers.
    
    With that, we can also add the raw_write_seqcount_latch_end() to clearly
    denote the end of the writer section.
    
    Signed-off-by: Marco Elver <elver@google.com>

diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 68d6c1190ac7..311c90a0e86e 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -119,9 +119,6 @@ unsigned long long notrace sched_clock(void)
  */
 static void update_clock_read_data(struct clock_read_data *rd)
 {
-	/* update the backup (odd) copy with the new data */
-	cd.read_data[1] = *rd;
-
 	/* steer readers towards the odd copy */
 	raw_write_seqcount_latch(&cd.seq);
 
@@ -130,6 +127,11 @@ static void update_clock_read_data(struct clock_read_data *rd)
 
 	/* switch readers back to the even copy */
 	raw_write_seqcount_latch(&cd.seq);
+
+	/* update the backup (odd) copy with the new data */
+	cd.read_data[1] = *rd;
+
+	raw_write_seqcount_latch_end(&cd.seq);
 }
 
 /*

------ >8 ------

I also noticed your d16317de9b41 ("seqlock/latch: Provide
raw_read_seqcount_latch_retry()") to get rid of explicit instrumentation
in noinstr.

Not sure how to resolve that. We have that objtool support to erase
calls in noinstr code (is_profiling_func), but that's x86 only.

I could also make kcsan_atomic_next(0) noinstr compatible by checking if
the ret IP is in noinstr, and immediately return if it is.

Preferences?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZyFKUU1LpFfLrVXb%40elver.google.com.
