Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUGD2XXAKGQEYN2WTJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0927104019
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 16:54:56 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id f8sf21475769wrq.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 07:54:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574265296; cv=pass;
        d=google.com; s=arc-20160816;
        b=G77U1qbWSZ04RcBU25lyVwuq4eszsYw4qpZJ8Z0Vld/JNE16Qwsjk7REoYNhnHsjO+
         d/wHeo7IVtR/yVtBOMcfzCf1tedJSwDrvbaaH+J3n59ylIgerViyrJjj8Hwstm31NLdG
         u8bFspJ0nBCxCcSnv3QK+bHhTqiHRZpk/c/x3PQMmIbOzR8Q3dn3Z/THT4LEMzk0DMpT
         wNpZUisqpGuUSNl1rfqpaqpnkZbdqJtbXm+A9jgspaXydKKDUfwnAc+y4ASW5U4h1UP8
         EWJ+5T4/0L8YhXkZpboTr132HbyPKZ0UDhJSZZ8nkLWBKo3w6oQ/USfiS7K3v9N1FAOn
         DSNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dXGCpPcyqVng/zyPVkEpifPpsr3qLOOPgKAXo0riYt4=;
        b=ZX3/jA6H4X9g3ftoT8suxtz7eFbYkTCCiQt69YS06Xyc/so04hR0iBs0jFykpvL7tA
         Uik5GZ/AD0SXEfsw2M0CYr1RKck25BvPNiHCL+6px6tLH4dBSc5BmvBbHIJ+Z1SoXp4K
         BCvuDizULpU7FNeEpVyAzYWdqC/m9YouoEfO6CveZj3+Cz+muYK7qvVL9ort8K6qW+Ou
         +2aIJeC+KFgQf2PX+U+tJjwRR92wcUkOBOB46/XwIUimXaVbr2ggngtoGXn31Dcg/Ken
         Suwzkjj79QI6aNjJIIc9Nk1SA7TCzYlhyJj6yHkKJ2ulP9P/MF4XENZ2AY8mawrCvsYy
         t+3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtMhRC6P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dXGCpPcyqVng/zyPVkEpifPpsr3qLOOPgKAXo0riYt4=;
        b=VyzDrD/A5RD2I51BKgSA7i5mJbu6IB4d3BsIzGl5RKD/5p7U1JcFbkcsqmmEFRPp8F
         1HF06FazcrVi5hlwJJYZxTRhNuCvvkdCxtaNK14KoKMLlpCq5+X0QMKEV/VhBx+hdNsU
         rozO53M5MWscOKW9H0StoRNIPEwTovNMQFBxmDDHbq1OhNv+6PaML0qrHuxuPk4sP/h5
         1NqoU9f4Tt69gieEOjCF+38kxL2YKPUxLjJhjWHvF8IMsZPa8gy4EDJcJeTtsf0VLCxS
         ZXo5JuNzLreTEFwjHDevDOdZ+aQx5Bf9NCEkUSpkrz3XEPdabSJQsz4Jka2ZWapPGja9
         cacQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dXGCpPcyqVng/zyPVkEpifPpsr3qLOOPgKAXo0riYt4=;
        b=A+mOsM1Y7Dz5r+40ohf1kPvQHvz386rY0EFzL84BCApKCl6fmDhdoe18oPcUU4DTBL
         eZ6/5zUExP25ukzKpIvOBmnQEei4MJbPE4JMeuMJs+MbG3XaQ98c1DnO9e8RZQ30JDTk
         1UZU+XheDvsn8sW2JAyi+8hc08eQyBk/ilnzv4V/6eLN4baED3cVJqsMcJgHxN65hiYC
         H4Y/DI1xvuzbegitLzt5DalZcQCLJmEH45RVhcUgUuA5lQi2O5ykK/mOgtnwHx/S20BH
         3XFmntdaSin7O5PRDdC47QVLEk0UxFEBWYTc/EWUvB1I6MzPsB+jpc/ipHNyd1fdi+Ez
         pZCg==
X-Gm-Message-State: APjAAAXBn2nRyGclgS2Ktgiuhr6WHM95z80VpW4kBd+bvGqiV/S3oSu4
	ye2tpMJHf8YbibHsO4HtvnQ=
X-Google-Smtp-Source: APXvYqxh/20uqlYuQ00fGbhFKzvSPzu2A7Zmn8/xK9fDz2bBfz/0CE/+VQGnWLppyEV3edvqsvtGXg==
X-Received: by 2002:a1c:731a:: with SMTP id d26mr3440213wmb.11.1574265296495;
        Wed, 20 Nov 2019 07:54:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e341:: with SMTP id n1ls119435wrj.8.gmail; Wed, 20 Nov
 2019 07:54:55 -0800 (PST)
X-Received: by 2002:a5d:6cb0:: with SMTP id a16mr4500607wra.194.1574265295747;
        Wed, 20 Nov 2019 07:54:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574265295; cv=none;
        d=google.com; s=arc-20160816;
        b=0kNU0hFP+7NtXcXmxH9d8Jf6ZnlG+0WhGapjq9bmcAaTcZmG6vRxMDSeaMMS7s/qPV
         NSH5x6uGu/pB9oMRIgE7OxZ4ZoEBRF/rzyQd5TYAZ8oiE8dinKPq1Q/DfyzBdwdSX6sG
         lPGm05GJIZfrlsn4L+cnryDnXQx73zi0iz+u/tpxC0NB7rI5RDUprFEDfoRKBjkcejJX
         sDzMswsgLD7j5YSRuzW8g5frpJmCmdHVr54D1dD93AZOdLgb+K8Gf0iRSgrhqhqrL1WW
         Xw5/EB64gUlhGqKQr8zPPoeNBDrtC+H380P/+qO5FTq5oCDaCqskgTBUBOSmiW4Qf+ZQ
         2X9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Pc/B5s8Op7DZcUpCkoozM2pKb7wkORn3PJUzQ+3VJls=;
        b=nfWA7M8bvvkAdAwqhOdefI4ZDXgf4lo/2A2MdkvtRClCoLSqLkbwMrF4fzVDTbtKpI
         QbDv6tDwEG+MUpK8SHtYw3/1DAY5kJqfNP8q81XUdwpzD3PcVnMrRflWwIMxGGKUuZVB
         EnkFfXzGeNyu/ALjPx8+5d7YXAWX9HGNRxcZX/B5YyClWhad2ax8WEeU+GB7l0fM8QjL
         qQ9xujmMY3yQeZjHRvt4d907gRxnAPURAQXX1dPC9ms8+QAQ7rYDuPz7Amq/AxMCq28I
         J9uzc+kalXqgDAeD9DF4Dd+4xDuySTL/n8xHlxcL2rxBtbI4amBB6VIs8LyfIT7I8iBN
         7+3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtMhRC6P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q73si194104wme.1.2019.11.20.07.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 07:54:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id z19so124004wmk.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 07:54:55 -0800 (PST)
X-Received: by 2002:a1c:38c3:: with SMTP id f186mr4147629wma.58.1574265294776;
        Wed, 20 Nov 2019 07:54:54 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id z6sm33020710wro.18.2019.11.20.07.54.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 07:54:53 -0800 (PST)
Date: Wed, 20 Nov 2019 16:54:48 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Qian Cai <cai@lca.pw>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Eric Dumazet <edumazet@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191120155448.GA21320@google.com>
References: <20191114180303.66955-1-elver@google.com>
 <1574194379.9585.10.camel@lca.pw>
 <CANpmjNPynCwYc8-GKTreJ8HF81k14JAHZXLt0jQJr_d+ukL=6A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPynCwYc8-GKTreJ8HF81k14JAHZXLt0jQJr_d+ukL=6A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jtMhRC6P;       spf=pass
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

On Tue, 19 Nov 2019, Marco Elver wrote:

> On Tue, 19 Nov 2019 at 21:13, Qian Cai <cai@lca.pw> wrote:
> >
> > On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:
> > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > only enables KCSAN for x86, but we expect adding support for other
> > > architectures is relatively straightforward (we are aware of
> > > experimental ARM64 and POWER support).
> >
> > This does not allow the system to boot. Just hang forever at the end.
> >
> > https://cailca.github.io/files/dmesg.txt
> >
> > the config (dselect KASAN and select KCSAN with default options):
> >
> > https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config
> 
> Thanks! That config enables lots of other debug code. I could
> reproduce the hang. It's related to CONFIG_PROVE_LOCKING etc.
> 
> The problem is definitely not the fact that kcsan_setup_watchpoint
> disables interrupts (tested by removing that code). Although lockdep
> still complains here, and looking at the code in kcsan/core.c, I just
> can't see how local_irq_restore cannot be called before returning (in
> the stacktrace you provided, there is no kcsan function), and
> interrupts should always be re-enabled. (Interrupts are only disabled
> during delay in kcsan_setup_watchpoint.)
> 
> What I also notice is that this happens when the console starts
> getting spammed with data-race reports (presumably because some extra
> debug code has lots of data races according to KCSAN).
> 
> My guess is that some of the extra debug logic enabled in that config
> is incompatible with KCSAN. However, so far I cannot tell where
> exactly the problem is. For now the work-around would be not using
> KCSAN with these extra debug options.  I will investigate more, but
> nothing obviously wrong stands out..

It seems that due to spinlock_debug.c containing data races, the console
gets spammed with reports. However, it's also possible to encounter
deadlock, e.g.  printk lock -> spinlock_debug -> KCSAN detects data race
-> kcsan_print_report() -> printk lock -> deadlock.

So the best thing is to fix the data races in spinlock_debug. I will
send a patch separately for you to test.

The issue that lockdep still reports inconsistency in IRQ flags tracing
I cannot yet say what the problem is. It seems that lockdep IRQ flags
tracing may have an issue with KCSAN for numerous reasons: let's say
lockdep and IRQ flags tracing code is instrumented, which then calls
into KCSAN, which disables/enables interrupts, but due to tracing calls
back into lockdep code. In other words, there may be some recursion
which corrupts hardirqs_enabled.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120155448.GA21320%40google.com.
