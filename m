Return-Path: <kasan-dev+bncBCV5TUXXRUIBBFWSZH4QKGQEBXCYNXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A7F6D241915
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 11:47:02 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id 5sf5349924wrc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 02:47:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597139222; cv=pass;
        d=google.com; s=arc-20160816;
        b=pfQ8e4imm4W43R8UpuZ1lqdbW9J8cfzhLzlEG9JZ+VOTh3932ZqnCesGVTl7b49l+Z
         hi9ATSq6W5coLDWwpajfqbrfK+pzFUA1iBGGTA77rFLkLqKzqMQZ44RCfUkeO8t2DCPG
         BzXXlDduQywzfY0b7uC/3fopLrDG6LXVVcJ1yLKSi6NAX6FhXnqn2d3IuLgIql7W79Ne
         gMlu/OjN3bk/THq7NhisEwRYLZ8NxA8e7PORFsvvliXYT/jrCN/bqOdn2eJqHS2cL9WM
         HUndYQLeRCiNhSYXSF3E+B2MBxisuFxymjW/rzJoyLLWDYBHFmXiT5jjk3iKlFKqvrBT
         oGig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=41sTfADu+mHqbSOS7zT5bu25H/ndBnqUuS05Bqz/+Bg=;
        b=u/xgUjVjVdy3kWbYJtj8KTHcblgx3D7FgoMhb6DKRp6BWLkKv/7V2GQ8FL98e7ghsx
         VoMEyng+3Y3WOO/cQKnEBCRr7Ewltqm5JrCBcni9brrEL4LC3EEkanrlpXKejUvMB2QE
         RNqFuMFTXQ/bzCX3hAGvsIk2ETTSXB3/+ZrcM8G8OzEIfP4twCWZfZrppacqAYnJHf+u
         z1bdUSL3mu7iHotkap/h3vXbsxT4EV5iODcY4/po8PINC2kPsrOVdw6knZKfq3aCiiBO
         PmtzHpS1yAz9qawl/J+FSYsbkGoQmOK9Qd5/1yLwj8y7pRc0NWMj5BNFzccZZxdVy+5v
         urFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=OsyDm2Ek;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=41sTfADu+mHqbSOS7zT5bu25H/ndBnqUuS05Bqz/+Bg=;
        b=IPi97ZGLBBCTDnnysc5zD4ovKmyLFVTRaU3Ywd9y7biA58mNGn/5yHKt/rdSMzHT7M
         gVkMBj077bZ7HTlpQcHHxPH9JLb1PFTwRWfoCLyB+IW0P++I7HHwmkPLPG7Wid+BPKl1
         lZ/KqyfPl97Ser2a/7Yel+MuH6EOeeFsDWSmF2ZRBsUpENDxhZpXWev3jCKUEQEpwpEl
         rgJojSlUuT3qtTqyfKmB7dRnwjDNgQxR5/U5vFKeTO7B2Pljt4wTMTaKRB2Dx7mTvddg
         yNZCX6eZdzGQPumetVDaCdu+QZWXjtokXhtt/b+IyPoFm06g17XTtB4jYYeEEyO+GcTZ
         XRZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=41sTfADu+mHqbSOS7zT5bu25H/ndBnqUuS05Bqz/+Bg=;
        b=CcQiWC8x/vru9oCwnQ7xh4n9mX0F1qhxjMdl7hVPhT9WUf93x5i5b7hYXhu6UiklD8
         GO6x7ZBEpqnoQHJysacjHBVj9993AZR3e1KPswXmynVJOOfvk0UgdFcxtWBndv0/apgq
         Dlu5e30GMC5tG7bz9Co5sIUWlsCi/urZrBfiTlICZc1hY9/OvGJt3zLJ2VWZt8VbbDHn
         eCwAjOd6BMMnb80xYe2kSFgdiFiXxTt3LTpztr8h4cqoUn06uSOkz54yG+TYBMEMPlgL
         moJOjyYnjJsu1yi7j/PtkejHXDItWeZYtadOS4hdwd7SzzkdxVesLElT8q0RcFHca8Ie
         hHCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530k51DC2iwHzoR8KiZn8toXvczEESgdz47DTg/TK5HhZrP5Xmq9
	B/IYq49G8smVrJBA+JKE3e4=
X-Google-Smtp-Source: ABdhPJy46MLcT9r2NxQ9Kl3s/a0bgaJTj8fb7CsRdX3COQSdoqHzQIaYe3rGbd38QvF8SLwElliRaw==
X-Received: by 2002:a1c:1d92:: with SMTP id d140mr3281003wmd.143.1597139222353;
        Tue, 11 Aug 2020 02:47:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b787:: with SMTP id h129ls729173wmf.3.canary-gmail; Tue,
 11 Aug 2020 02:47:01 -0700 (PDT)
X-Received: by 2002:a1c:e302:: with SMTP id a2mr3353057wmh.110.1597139221942;
        Tue, 11 Aug 2020 02:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597139221; cv=none;
        d=google.com; s=arc-20160816;
        b=Dsg/BaIOcI+6iWcKeSokXU9yK95pV2DFaCiWfuht07BG/bl5oQ3KYplsGJznb4Ovj9
         jb8jZhiFKmouvhIdKUud6ppvH/0i/KBAd8ax4AxBYDHEByJBtcCgvUvFUis6k/THRg0t
         oQxX8cXomdEVUc9f8uyONKOMdRfivlBJWfCpBV/yDFvf8GConeH1X+4o7GxvDmW6pxfi
         xcIPZ8bplMRUPf8Pmqbap6WrC9FxWar6aqcwOCVePdVcbvH7DSExCAYpl6wAxezZ9VHx
         9GgZFmXio3Pqnkab5D0YrgJvR4e0QX5PlB5QC2EJBsAxfn/Vx8U8oWJPib1MysICN+lo
         R9Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=hSl2P/kJe9MOyfzAv0UR68V5yutSEkdzNefSktLECT8=;
        b=BTjBrXg+4T8Sdx+P6dnwyb0UnFFKvWKQFhI5a17OPB/fD7wb4ru7+73AxmdJRr1zMI
         27DYmZv15NA5sZRXFVtwxfxNyZHQgn8rP6t2UqMbZhjzr4/k10TNQ6ADdCdx9wHocquP
         oIHhUKHHgH+nn64tnQDy/wobTJp260VOWz72KWe53qdoufhTVRRuLiyxOsd9sDqy8PLY
         4c8nkthhR4JnUNQDwY7YXol7+rxlGE4pW+nwrKpvBMRZuTnIN1dK1XQzMxG6KB7eQoib
         0F6eIibw7G1OKGRAyMDuKhjHk0HQp7rkTKYDDuzZCM2EFJupJiILdWErbVy7IEv7xuCF
         Eqvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=OsyDm2Ek;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id w6si153770wmk.2.2020.08.11.02.47.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Aug 2020 02:47:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5Qrs-000387-KS; Tue, 11 Aug 2020 09:46:53 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 660523003E5;
	Tue, 11 Aug 2020 11:46:51 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4D3E423FF6C69; Tue, 11 Aug 2020 11:46:51 +0200 (CEST)
Date: Tue, 11 Aug 2020 11:46:51 +0200
From: peterz@infradead.org
To: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>, Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200811094651.GH35926@hirez.programming.kicks-ass.net>
References: <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
 <20200811092054.GB2674@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200811092054.GB2674@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=OsyDm2Ek;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Aug 11, 2020 at 11:20:54AM +0200, peterz@infradead.org wrote:
> On Tue, Aug 11, 2020 at 10:38:50AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> > In case you don't want to do it I can send the patch for the Xen
> > variants.
>=20
> I might've opened a whole new can of worms here. I'm not sure we
> can/want to fix the entire fallout this release :/
>=20
> Let me ponder this a little, because the more I look at things, the more
> problems I keep finding... bah bah bah.

That is, most of these irq-tracking problem are new because commit:

  859d069ee1dd ("lockdep: Prepare for NMI IRQ state tracking")

changed irq-tracking to ignore the lockdep recursion count.

This then allows:

	lock_acquire()
	  raw_local_irq_save();
	  current->lockdep_recursion++;
	  trace_lock_acquire()
	   ... tracing ...
	     #PF under raw_local_irq_*()

	  __lock_acquire()
	    arch_spin_lock(&graph_lock)
	      pv-spinlock-wait()
	        local_irq_save() under raw_local_irq_*()

However afaict that just made a bad situation worse. There already were
issues, take for example:

  trace_clock_global()
    raw_local_irq_save();
    arch_spin_lock()
      pv-spinlock-wait
        local_irq_save()

And that has no lockdep_recursion to 'save' the say.

The tracing recursion does however avoid some of the obvious fails
there, like trace_clock calling into paravirt which then calls back into
tracing. But still, that would've caused IRQ tracking problems even with
the old code.

And in that respect, this is all the exact same problem as that other
set of patches has ( 20200807192336.405068898@infradead.org ).

Now, on the flip side, it does find actual problems, the trace_lock_*()
things were using RCU in RCU-disabled code, and here I found that
trace_clock_global() thinkg (and I suspect there's more of that).

But at this point I'm not entirelty sure how best to proceed... tracing
uses arch_spinlock_t, which means all spinlock implementations should be
notrace, but then that drops into paravirt and all hell breaks loose
because Hyper-V then calls into the APIC code etc.. etc..

At that rate we'll have the entire kernel marked notrace, and I'm fairly
sure that's not a solution either.

So let me once again see if I can't find a better solution for this all.
Clearly it needs one :/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200811094651.GH35926%40hirez.programming.kicks-ass.net.
