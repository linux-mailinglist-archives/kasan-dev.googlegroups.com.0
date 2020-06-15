Return-Path: <kasan-dev+bncBCV5TUXXRUIBBU43T33QKGQEL7YSYUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE64D1F9B55
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:03:47 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id k12sf5140914lfg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:03:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592233427; cv=pass;
        d=google.com; s=arc-20160816;
        b=hSNFM4SGiUVDLs8YPoGWiL7qnqQlPS/JGY+vL0kV6Gmlyl9zRddoEnAs8/rezrVX3r
         tBWHZ9t4Vw6L/VlSFI+U3Sj8djxP6qHol5bY0e3I0QJaTMhgelqHiHXZWkVHQNPuc+nv
         ISvyp4zpI6HM6/oZmmtEgfTVD4ZzE7Q5LD/Bk99XutK63Vq9778QfedWAa2LwxIUVOFp
         79kjgrT6Nb56ZWrQQNY1Hk2fdSngFRQY4keAs45gSrp3fDJWkfmJuY4RpUaez8GJh9Nt
         lDAZP6O1JcoNSELQPafsmbbVjCIW921n4o9MTyhdGOC75W4Ezl8kgLLDvl/2WphI6Fe5
         G7Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nhLqMby2R/AX4p3KIeqo0ufOIW4bBemgtyQkbEJCk1o=;
        b=prgZJiDnQTiiTbG2rk4T7qd6Up5c2WQeGJAA50SDV+yH1GZg3OIKHOFqQe6R0uFp6s
         Zcin5eH7vKOd5qeCeOvS7u9/dUHqgr12sMgEK3wpay30HePMYhcRbmeJ260tN2JTFhSK
         jJwq4LqLyaDkbdH2C17+fubY5pWcd8VlRg1Dj7pRfKb5eHjcVsHKCknaGHFbQgrzOCL9
         LRNqXkSIpGY4WOA1CqqJErdslCAZj04UeVBiRkfS1kfqFD4wnBAVvT+IWmKlqH1hAu2a
         AIud0hZ2mLpk1HrQZjXpA76kcDkiY5Y4yHtz1Lrd70TDuGzXIN8cT3Pmlb+6oEW3iyi2
         IR4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="SFsU/76c";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nhLqMby2R/AX4p3KIeqo0ufOIW4bBemgtyQkbEJCk1o=;
        b=T5kZAFv8bLzQUWSi0sLh1KfNqE70TLfSNXM4FSRgQVO5rh2IlybVNnbDsC3WDqabJP
         cs4x8WbTZd5kfrwZgFuH4KxYMrTlpKaVBVU3+1XCLl3p1cD+URPX6exHR8t+Y6qmiKvv
         xGEj7JLqASl3kiOdOrSYKc/feIRiMcBl4ncdI7JBuB108tiSAJ6hOoW4O0g+4mmUxWNw
         XGqbujDaChEztE2obJlK7CLCUks4x4HtVWrenLqL3AvKI6ypQDkcJA1/VoZkUDbwo7Av
         rIx7Ao2I8Nb17DfO28Hn/vFjQMfivCjKdaMqSpAM/rFYEHBv58c6aTtd7XfdvF09kbsY
         JYRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nhLqMby2R/AX4p3KIeqo0ufOIW4bBemgtyQkbEJCk1o=;
        b=l9w40C7nqFTDY/6qA8IT0nqCSXh/sLNJDUtT2Px1U6m1q6qrzyemdLRTIye7h64Cn+
         avXJqreiW2UhWZke2f6Qta4IIuOSbR5NrnH01b5DVdj2MEh/T0MzIhIDZp3VzHgy0jUC
         bD1BUf8jPdcc17T86eSWZmiscVXU5Ak8/WSy8L5FKZLudB0pwfaCzMEiQMQtY1VjzPF+
         z/ak7sttFZYgRLrjcAbufGIb3OgbTBYJ60+EZD1aAplTYOEyvy68AanCijQVd8UE73XS
         W/7kVrKKjk6Z5bLUYvTC15oac5a/OB0kUEsVNVBitrS0GLsAIZpv4BDpD5OtSdEeb+HM
         1g/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mNTy478LMMGA4w8s5249ZRed8hg9p3ycfHbloZKf7in+6ACyl
	oEtpsBXti+bWLKcha7hpqmQ=
X-Google-Smtp-Source: ABdhPJzm9TnXYaUIhGveuTmqKlQZ4IUOK5AmGq3FEvGyAuRDlM/wAQZ10PlkNFRUy4JTrutVvmC0Fg==
X-Received: by 2002:a19:4945:: with SMTP id l5mr14023574lfj.12.1592233427342;
        Mon, 15 Jun 2020 08:03:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:be95:: with SMTP id o143ls118001lff.0.gmail; Mon, 15 Jun
 2020 08:03:46 -0700 (PDT)
X-Received: by 2002:ac2:4886:: with SMTP id x6mr14102106lfc.198.1592233426801;
        Mon, 15 Jun 2020 08:03:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592233426; cv=none;
        d=google.com; s=arc-20160816;
        b=KzFSQNk1LuohvwRrlQNEUOgGtErFBG7S7AbwlUpC5zfR0aRCy8xLSuJEExBVjvtpI5
         Yoxe9nkAPjzLv5CT56Zi89ATkPtwTPT1AeHcM+uSqCd++DkCo3+u1mKPWdqCrM2b2gpV
         DpNFZK7+pNz8Hy/f0K4uMLrI3cdZPYyrc9sJepUFeCGH/BuN1F4oHmPDN5ky0n5VwGXu
         jd6f/Cj7Gt3SUd4wdpFIomNLTtLmHaqebqtS6V6WEO6cjPE43AgH56aiGKvSG5jvHH0h
         /IHgPRRyxKTzJ/1uFuKbJSQODl5N3SJ7/jl8Jipw8UWny7KwD7IOXgFC4CZhvH5Snyl4
         tepA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jNEVxB8K8qkb0jxDWu2/VVQDIry1tExCa9xuuvd1cs0=;
        b=KsaIsejqdYu7ijlUkodjDNVHtWmojyaVK4wOZNT1F8DArGrHTUf7MGjxxjvpv9H0DQ
         Obaf9pdEf9AP/z425cD/cgg8v1S1fKoYr8DesmXKeKn9JIc4cAHFRrDrYfRAKZj2rQYD
         tuMuMZ7m0p1Da72Teu5qQ8m9Iqj2mwMBE8Qr1hoMVXniRQCQZiDR6Bh8YYRJKXWqabc0
         7jpTvAYg1ChdoJ3aydimNG32/TU5aMIjTCsXgb2rGuHNSr1pfXsAWl5uot03DIXNMoTD
         BQW2xNjZJWHhqtQJBJ2A0rhCHY8cTDhrUIf7U2MXLOCuMo2GfNIelp/wx1li3x9L1syI
         APjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="SFsU/76c";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id f16si1117119lfm.0.2020.06.15.08.03.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:03:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkqe1-0007MO-Lu; Mon, 15 Jun 2020 15:03:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D85B83003E1;
	Mon, 15 Jun 2020 17:03:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id BDCF2203C3763; Mon, 15 Jun 2020 17:03:27 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:03:27 +0200
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
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200615150327.GW2531@hirez.programming.kicks-ass.net>
References: <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615145336.GA220132@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="SFsU/76c";
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

On Mon, Jun 15, 2020 at 04:53:36PM +0200, Marco Elver wrote:
> On Mon, 15 Jun 2020, Peter Zijlstra wrote:
> 
> > On Mon, Jun 15, 2020 at 09:53:06AM +0200, Marco Elver wrote:
> > > 
> > > Disabling KCOV for smp_processor_id now moves the crash elsewhere. In
> > > the case of KASAN into its 'memcpy' wrapper, called after
> > > __this_cpu_read in fixup_bad_iret. This is making me suspicious,
> > > because it shouldn't be called from the noinstr functions.
> > 
> > With your .config, objtool complains about exactly that though:
> > 
> > vmlinux.o: warning: objtool: fixup_bad_iret()+0x8e: call to memcpy() leaves .noinstr.text section
> > 
> > The utterly gruesome thing below 'cures' that.
> 
> Is __memcpy() generally available? I think that bypasses KASAN and
> whatever else.

Yes, I think so. x86_64 needs lib/memcpy_64.S in .noinstr.text then. For
i386 it's an __always_inline inline-asm thing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615150327.GW2531%40hirez.programming.kicks-ass.net.
