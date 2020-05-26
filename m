Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYFFWX3AKGQEARBC32I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F2B471E28DC
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 19:33:20 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id y23sf4578465lfy.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 10:33:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590514400; cv=pass;
        d=google.com; s=arc-20160816;
        b=l1xXwPrxhtm1E5DZuPBlZRVnKmAlaWcR39WJcu1/E2WD5CRRm71MZmbNvP86xgTxbO
         u65rtyK+SOST+kiv9JPaFvsfeq8MeF8V57MPLuRRKLPFvoMollWahqe1wzO6gxX15neu
         i8EI3OlzdpO++Dv8p9Tau388DlyZ9bv+3ApS7CME1iIkauugzHgZeZYtiHmLL/7OWbFB
         8Vvc+L+Mja7gw0JPEYqJHnLu9d7MZdSHp+rQU9UU7VJwJQCu61RK9pvCFt87caZ6I4q1
         LgFkSWczG40KT9cWnxoATdbJU/u9Qwixgzacyh23qjo8+xLxSg18ISkny/fxlTU9qAbm
         NHRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QAuS5PhDPa4PGaO+5fPb4zLkVLgnVtOQFb4dGQIey4I=;
        b=YNukbXQ9lNz6lMw5zyv80eMFnQamyKxB3Snm7rnbrks+ssDWXZytDw6ySPdmDnLUU6
         WpO/AEgOKGfmF9bOdIYFelQcdhC8gm151JLEvcU/62dIMYMo2dNjx2rG1XOgmWFmMKxl
         mN7nS263g0/MciCvUi9CxfUki7UMWPZ3YHZvLre70Z6jbhoK1nf3xhk9WR5VDj5dQPmo
         P2j+XrA7Nzo1c/+9VWJfG6UHxJYn1NEYCPILtR4S3h4yTNUpKYGcOOHnvIxVOUTnQ+YI
         lRkeavlazufu9CElS1I761J4KBfsSNOWrrse+zVd+xA6cT/vUeRoylejiVYiUzGR0+m1
         XfOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vNOLZx+V;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QAuS5PhDPa4PGaO+5fPb4zLkVLgnVtOQFb4dGQIey4I=;
        b=CdkUrkMzrGTLMxzxSVhxFs+AnfCHFlB8/xedU9KggqoCdxiuoan9MtjR7Mj7DoyHRa
         Z+MqjCYqzAASm9OvB+WL/DIfnTyYlplTjugSP/dSfgMp4PGyq8/2ae1DLW/QGBUTIjjS
         2eyrQ6b7B1U2JzkHuJq4VaLF3kY40tG8qcgIELel3fTiWkotvYCUtyUKFkn2B5JANc6W
         3gMJVmje8zwJb9JHYiCkTb7zLzBzqDd7a770UqbOHqfkbWw889WMaYBeAYZbnjP9rze0
         /8FiXIUPiV/sscA+9vLfSx23d+nkZknnkQ5WWq6C2cvyNO+y+1dwBKmEeKQddmt7fGxj
         7Rjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QAuS5PhDPa4PGaO+5fPb4zLkVLgnVtOQFb4dGQIey4I=;
        b=qmQOYgBgkvk6bX6wcX8ETTIyd17sOKMbfl1hYunE8jMmCL+67sEkqxvtWfTJ6tl46v
         Y2p9HF8aLZr2uUQA2cijDV0jMNz7mOopEheQBVij8OfjCtRAbDrUB7gm1B6pVBQbzPsf
         TRuRPluElFCo6NBXaL2KvY7uzxi7xcg3PVTyOg13qcib86uurEH2TPpRCH6RxGYoKvdD
         b2vGQX7xyLcSGKDebLb3/lLCwO+wFDJgE/96fuuXMdcJ+byI5hk2+c8ng5y85hEdGfkS
         4MbQVsS2DMBvXStwqHgs9KoAEbi9UPeIZdBTFM7VAI8K/vXi18tv8b4VrxVe3DOY4TWe
         mdoQ==
X-Gm-Message-State: AOAM532aEC6wuXZZwVFuGdH7nV+m0kQxDSsp9j397SYO1TxxcSGv46mR
	FYZMLs5a0KhPU253c/4emgg=
X-Google-Smtp-Source: ABdhPJwwYB4DOPcKJ1NQ2tpvPS5uzfUPiE6HJBdijrgGhwYD2wqvrhVqmX4ThUgZ3Im/1ZCphi99dg==
X-Received: by 2002:a05:651c:103a:: with SMTP id w26mr1121962ljm.403.1590514400392;
        Tue, 26 May 2020 10:33:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5d5:: with SMTP id g21ls2305052ljn.1.gmail; Tue, 26 May
 2020 10:33:19 -0700 (PDT)
X-Received: by 2002:a2e:a49b:: with SMTP id h27mr1092229lji.299.1590514399623;
        Tue, 26 May 2020 10:33:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590514399; cv=none;
        d=google.com; s=arc-20160816;
        b=njQ3R1REOs+mfSOjXZESmiW+438vmfQGdI+jtYwjQzEnZt6qIA7vk2bEWrRsTvMsBu
         kf+Ak4K0H+Hn2hiCby2w1Bzk5pfIlYJwFgp/LazYSOhy3UQ5CjHy7LPdtX4TmbZwX2Y3
         L4z7nCMGEgFOlpkMUs9BiJTxk/3ZTDNQOlQqdG9UBprIZ+YPaBeNfuvpc7Qi/DPAtvfv
         aCcGC09QvK+RC4sNCeBtJ6W0sSxm50wGj/b/3K2yvIUkcz2weeCGq1FvOzKHXENLEf9b
         9BcoDZDfQSNseKLFENHln5ASHCO9A62yz2cY22zIr7faH8oTtqTJSEfv6a/FOFyuYSlK
         ANRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sys0Nh8QzHuS5xSYWpqlM7xhUHriFZcWSU4k6Houjjc=;
        b=XeImal2HJdSZjX6FzfnwYsPpqL/JMrhs9WhhQhRP4RAEruEuRBdGlKLQlyCJH35LRi
         v+g+FZ9E189GGMiGSvMV1SSGkYn+DWpAqXljyKkNfK+FAQn8wFQ0z3pkHSQyv7w+RPB9
         FtcHG1CNjKeipvR7lRTBvHLYyHmG6kkFRvL3U0o7LO9tERCh2DuSyndvc5VVNAqYXq9i
         2UR3PcG0tOyFzidGu4IMlttF+VFLaN8X5nZBXOhF0kNEp1AGQTlgxXBRgDHIRr/3LKyY
         DeRCBDplIWiu8WK4ky5xXgHa0iDkU+FH22R+XmOiqGCrLkuZXXWUJjLDCWmjM4FxngS4
         phGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vNOLZx+V;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id o10si36859ljp.3.2020.05.26.10.33.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 May 2020 10:33:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id u13so370993wml.1
        for <kasan-dev@googlegroups.com>; Tue, 26 May 2020 10:33:19 -0700 (PDT)
X-Received: by 2002:a1c:4d11:: with SMTP id o17mr267995wmh.37.1590514398940;
        Tue, 26 May 2020 10:33:18 -0700 (PDT)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id e29sm525252wra.7.2020.05.26.10.33.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 May 2020 10:33:17 -0700 (PDT)
Date: Tue, 26 May 2020 19:33:12 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Will Deacon <will@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement
 expression
Message-ID: <20200526173312.GA30240@google.com>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck>
 <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vNOLZx+V;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Tue, 26 May 2020, Marco Elver wrote:

> On Tue, 26 May 2020 at 14:19, Arnd Bergmann <arnd@arndb.de> wrote:
> >
> > On Tue, May 26, 2020 at 2:02 PM Will Deacon <will@kernel.org> wrote:
> > > On Tue, May 26, 2020 at 12:42:16PM +0200, Arnd Bergmann wrote:
> > > >
> > > > I find this patch only solves half the problem: it's much faster than
> > > > without the
> > > > patch, but still much slower than the current mainline version. As far as I'm
> > > > concerned, I think the build speed regression compared to mainline is not yet
> > > > acceptable, and we should try harder.
> > > >
> > > > I have not looked too deeply at it yet, but this is what I found from looking
> > > > at a file in a randconfig build:
> > > >
> > > > Configuration: see https://pastebin.com/raw/R9erCwNj
> > >
> > > So this .config actually has KCSAN enabled. Do you still see the slowdown
> > > with that disabled?
> >
> > Yes, enabling or disabling KCSAN seems to make no difference to
> > compile speed in this config and source file, I still get the 12 seconds
> > preprocessing time and 9MB file size with KCSAN disabled, possibly
> > a few percent smaller/faster. I actually thought that CONFIG_FTRACE
> > had a bigger impact, but disabling that also just reduces the time
> > by a few percent rather than getting it down to the expected milliseconds.
> >
> > > Although not ideal, having a longer compiler time when
> > > the compiler is being asked to perform instrumentation doesn't seem like a
> > > show-stopper to me.
> >
> > I agree in general, but building an allyesconfig kernel is still an important
> > use case that should not take twice as long after a small kernel change
> > regardless of whether a new feature is used or not. (I have not actually
> > compared the overall build speed for allmodconfig, as this takes a really
> > long time at the moment)
> 
> Note that an 'allyesconfig' selects KASAN and not KCSAN by default.
> But I think that's not relevant, since KCSAN-specific code was removed
> from ONCEs. In general though, it is entirely expected that we have a
> bit longer compile times when we have the instrumentation passes
> enabled.
> 
> But as you pointed out, that's irrelevant, and the significant
> overhead is from parsing and pre-processing. FWIW, we can probably
> optimize Clang itself a bit:
> https://github.com/ClangBuiltLinux/linux/issues/1032#issuecomment-633712667

Found that optimizing __unqual_scalar_typeof makes a noticeable
difference. We could use C11's _Generic if the compiler supports it (and
all supported versions of Clang certainly do).

Could you verify if the below patch improves compile-times for you? E.g.
on fs/ocfs2/journal.c I was able to get ~40% compile-time speedup.

Thanks,
-- Marco

------ >8 ------

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 5faf68eae204..a529fa263906 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -245,7 +245,9 @@ struct ftrace_likely_data {
 /*
  * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
  *			       non-scalar types unchanged.
- *
+ */
+#if defined(CONFIG_CC_IS_GCC) && CONFIG_GCC_VERSION < 40900
+/*
  * We build this out of a couple of helper macros in a vain attempt to
  * help you keep your lunch down while reading it.
  */
@@ -267,6 +269,24 @@ struct ftrace_likely_data {
 			__pick_integer_type(x, int,				\
 				__pick_integer_type(x, long,			\
 					__pick_integer_type(x, long long, x))))))
+#else
+/*
+ * If supported, prefer C11 _Generic for better compile-times. As above, 'char'
+ * is not type-compatible with 'signed char', and we define a separate case.
+ */
+#define __scalar_type_to_expr_cases(type)				\
+		type: (type)0, unsigned type: (unsigned type)0
+
+#define __unqual_scalar_typeof(x) typeof(				\
+		_Generic((x),						\
+			 __scalar_type_to_expr_cases(char),		\
+			 signed char: (signed char)0,			\
+			 __scalar_type_to_expr_cases(short),		\
+			 __scalar_type_to_expr_cases(int),		\
+			 __scalar_type_to_expr_cases(long),		\
+			 __scalar_type_to_expr_cases(long long),	\
+			 default: (x)))
+#endif
 
 /* Is this type a native word size -- useful for atomic operations */
 #define __native_word(t) \

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200526173312.GA30240%40google.com.
