Return-Path: <kasan-dev+bncBCV5TUXXRUIBBH4NVH3QKGQEY74TERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E9F0C1FD244
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 18:36:48 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id w13sf1271955otq.13
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 09:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592411807; cv=pass;
        d=google.com; s=arc-20160816;
        b=dPujQnOBsBTXtTh1HqgfwQjdab5Dj4LtO2a0DUQqOnGmYvcsVPbHP0jkF83AP553Mz
         e9ByIL5CYEklpJwQdEKK59iSJz3DZfOgM/lnYeF+TZgTGZEOrzrgpYn0Ias+eZSyLBxg
         ZWI1weBYGoCl5oGdYuknK+AzgiYAjAnjYA7w6xryQdBhQFYz/pFCJ8QDH9XxKUjL8q5i
         g7LszvCOQwIHwie0xd+diPrF1an3E2MCL0626ZlBEHrzgF9owc/VjwrmC8ljo4D4U1Nw
         gmSHpixrb0Wcaa0rQ2D1TeXHnkYhTbSsllAsgV7MlJEYjVpOfVFaHqNJkZEGIjo7J3TB
         OStQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g1bfZFFRqXCsHObmQaVyjTtwvWtRCWVP8JDzaSce2QA=;
        b=bys9KkljJMF//n7zeOunysQ1e9Hn4QW4HPwgZWSm0/PVzwLgc598+k4bfRXRBrMgKk
         C23atDKyLJliHNwKk4tUE4zDyKt/O8EkuDusAnkm7TjmPKXU3zMxagvDCGU8dBsutRzb
         /WbfqfwGcD5IZ9BeWGIrKhw2p3xleSwIuVahyckScqKcSGAyMqVqpT/PRrptsSukyKvy
         MCSQrVUlOc4/D0nDuWAlg1TujZHL+h7EqxXvNGV7hfla5WwQCZnX5Z+00ffgPJRMfCLN
         q0S9pxuF5hKSghrEhs1I97PzSIbagJthTz8X5AOuEaFaF7sqTL+Y3id5XdIEHMyNvVch
         su9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=rqfiepsu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g1bfZFFRqXCsHObmQaVyjTtwvWtRCWVP8JDzaSce2QA=;
        b=fMsXDBqXrj07qx64EF6uSADCd2OAc/6RJiDHfCb0xHg+QGpYlAyKWKdgep2xWryNMu
         9p1eMWo3opbsnuAS60mJjDD1Xim7YTIFwf/9MuQzUiUTk4IZoKGBTNnQJb1BFOJIFaTi
         s9Xf5J/mRZdYYjLz9Ko3fvch7kQcwRd4O5ZdtX6pKeQ+rc9nNj+IVNxq1tE5HHh1Wdqc
         dRcKJLvhB17SWOoaQ+4T1hFlFdZD96qxDp+2/1cFugXRDNF+7+ilZnMl9aYnWftDyDhO
         3ABRx2yhQvjbKlMZBLJLxQ+cFHZxrJeufxe8lMz4U8dL7oJHciPs/2wcB5NQU7Q0dO1d
         Phrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g1bfZFFRqXCsHObmQaVyjTtwvWtRCWVP8JDzaSce2QA=;
        b=Fmo5lrP8oTRojy+/IvAPlaBwwSKvKvhkauf0cSRiIju+V//MT41dvkM2PgbdiC3wcJ
         wGWmVE+deD5d4YzpH+TBfpeqMbyEK9Tc2XwvR1PUVDnqCxD6ehjK7WnEX4SpZ31bGlxY
         Cx6RA9xU79VPw2G5Oa0nX26RKhxwHYfz6cANkLFOq/9GZndLC82+NCIcM7NSo3njFSeJ
         j5sgWS0KnRlEoSIoeXG6oCENVaQvdxkNC765kjd6JIb7IRejeD2rZU/NUDf4PCOZclIe
         BmVvhvurLHBfIZ+dJmWv8rI2XN/Dh9N+Tu8HsottWPe3jlAW3/yiuEFlA++dV75alrTL
         3wdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53251kOq3c7XhA5wf8ddwOGnarjs0bbMZbI+Dr7vRq1ZGDLHg45p
	ND2nSkLEjbWNwYRWZprUO60=
X-Google-Smtp-Source: ABdhPJwl6Dw1rWcbRAPYM4ocQY/EKKoCd3nJwX2JSB5wzO15u/vzpaJK36+G5H2vHmvPBXJphk9bmw==
X-Received: by 2002:a05:6830:124b:: with SMTP id s11mr7526410otp.202.1592411807697;
        Wed, 17 Jun 2020 09:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1446:: with SMTP id w6ls642009otp.8.gmail; Wed, 17
 Jun 2020 09:36:47 -0700 (PDT)
X-Received: by 2002:a05:6830:1391:: with SMTP id d17mr8175562otq.48.1592411807318;
        Wed, 17 Jun 2020 09:36:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592411807; cv=none;
        d=google.com; s=arc-20160816;
        b=ag988qXZUCEZdS8Ru4wnmzgGUNMpwQPjvWJhwr3uxGgCWtBPEyFzCoI+wCofYo95kJ
         266XIguShV5pb5czLAiRqoSsGNMPVmMdegHcgTG6axludFs+lGgd7Xs276artCBK79nu
         CEl7JVKN9wi0zgYAg/Sfv7ICSRncD1/5/5R5/9kVOKeqw1rLxd6fDwBb+EAlwqYqXqWl
         8De0r2EI3dZZ3WWmYJn2sddTkmaOWBPYXTCRWwtnX51YEd+9cUGoWCP1GKeG1CmDv9cX
         fmP7Qa/5MvJa6l4aRAfjvmlwJ53sUqhXGl8N5wQYln8hdWgO4N9gPVCasldt3pyfRDfn
         afBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tlT1YMQ39uBGe7lMvNKoVc7btUmDBldnB9RGq7PSmdU=;
        b=hU2UeqFlQ9xlRaEJxR/vmMm80uqdV1aEJo9D8N1CaDLQ87I7M5yJi059GyO0K8Mx4c
         KvvnTuK1zLVstFWKkXh5hW8eB9EuayllMNTzkg3AJh/4n1177BP6wrfkn06P0BxwclmM
         d7xx0sVpZ4ip7/Qj44OzKoC6XnuBb0FgWBN99XAZu90o+LssuqwQq7PYDbsmLl/DlO2W
         PpxUdcqB9qnLEHaZtQ9ZOGIXLv9pSQrhb9RMA6CpclkQA+djv0o3bSwkcePWx411ZKVH
         rI/zloUkUWRTgLPXAMnHbtZftJ6dIPmqY/kd46y52dITvwQYps3KwQTncZe9l83xYorv
         N+fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=rqfiepsu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id h13si38853otk.1.2020.06.17.09.36.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 09:36:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlb3G-0000tM-Mw; Wed, 17 Jun 2020 16:36:38 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0C32E3017B7;
	Wed, 17 Jun 2020 18:36:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id F0F372BA7AE07; Wed, 17 Jun 2020 18:36:35 +0200 (CEST)
Date: Wed, 17 Jun 2020 18:36:35 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>, ndesaulniers@google.com,
	Andy Lutomirski <luto@amacapital.net>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200617163635.GC576905@hirez.programming.kicks-ass.net>
References: <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
 <20200617144949.GA576905@hirez.programming.kicks-ass.net>
 <20200617151959.GB56208@elver.google.com>
 <20200617155517.GB576905@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617155517.GB576905@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=rqfiepsu;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 17, 2020 at 05:55:17PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 17, 2020 at 05:19:59PM +0200, Marco Elver wrote:
> 
> > > Does GCC (8, as per the new KASAN thing) have that
> > > __builtin_memcpy_inline() ?
> > 
> > No, sadly it doesn't. Only Clang 11. :-/
> > 
> > But using a call to __memcpy() somehow breaks with Clang+KCSAN. Yet,
> > it's not the memcpy that BUGs, but once again check_preemption_disabled
> > (which is noinstr!). Just adding calls anywhere here seems to results in
> > unpredictable behaviour. Are we running out of stack space?
> 
> Very likely, bad_iret is running on that entry_stack you found, and as
> you found, it is puny.
> 
> Andy wanted to make it a full page a while ago, so I suppose the
> question is do we do that now?

Andy suggested doing the full page; untested patches here:

  git://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git x86/entry


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617163635.GC576905%40hirez.programming.kicks-ass.net.
