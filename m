Return-Path: <kasan-dev+bncBCS4VDMYRUNBBX7C7LFAMGQEB3ILHLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1534DCFFAFD
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 20:17:53 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88a2e9e09e6sf30499676d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 11:17:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767813472; cv=pass;
        d=google.com; s=arc-20240605;
        b=QMreYPvIJHEN7x3yd3icRxUeb13gsdZAt6bY2f49W3nTgehpwT4N0g9V7oUg31i54g
         Z1WUiEyoE2ybCQRxKTJAaHd6eANPDmeD5PKt0yhSucZg0Jr8PvJDVF8Uc6UWIPFLbqr2
         vUIOLgJtXSOVylV33Xkb8JTLIH351+MWL83MrnPu0slQ2OP1CZ78WU2wFHlUg1A4I4kh
         N9Dr2za2DVZugH55/H64jHmFTOJqVRwhjtv1WNItmhgCs25qXHyMpQvHGA9ShsMiBvB9
         3nYQ0Y3TUj+zmP1R7bmTJSxT0n4RAJ1oYE1vVBrI/8aF4U4vx0fKs0qx2flQTLkPANzG
         opHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=FO4R9UO4JHQD+QHvgMUBfbiU3Q6iLTlMKtvOUYKG/cA=;
        fh=mDrb/MHXPjVU1utV0Q+L9NudgD1FknhU1Ak9UWXJKM8=;
        b=YLMjQpo0djjqZoHXc+4fk2LrbStLOems/Q27KQg16vah7vq6Ybqbxjj0h4yjYTHytZ
         pgrOJ7DRoKWvyyx2b+Youcu/nwA3iQkLs6uLgX1o4ZRT+r/0eChv+ICMeVW2QQidwasb
         8BEFFbUI/9o38IGGiJ8Nvqd9aUPcYmNcOZjuaFFCQoI2ojV3spDg3leNf0KVkhIOHjAA
         gENZH1vww5rT98VOk+L+1ZTurEYgR5ZA8G1MeGKEp8Lo+/wcrAY3gV9jn+T4h/YRrliJ
         MWul9lKZlVzytmCKc4okmnnKrj0HjRwNYbAOdDXmmOqIHgTbbjWh+lKA3w7pJrjbCwBC
         A/Vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WT7SW+oW;
       spf=pass (google.com: domain of srs0=nqng=7m=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=nqng=7M=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767813472; x=1768418272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FO4R9UO4JHQD+QHvgMUBfbiU3Q6iLTlMKtvOUYKG/cA=;
        b=sX79+vqMNDHikjXScXbbfL8RZUZmeX2/D7J06ka01FY2wGtNm+JMmfia/hm5l7x6A9
         0yaoaJxiAVrZt9z1KlKyYYJzuftBI36Xs0IrPwJPwOF3D8eScsOkbPlNG0S3niI8s4b7
         og1yAisG8MGrJemJT7cIlcV5yjeGp7omX9xsl+zRNLuZSvPW6kUSsEptEP8yfSixJ/ZC
         rHLp6vrn6B3j2MD4pwUYxbTCDRlxKZcx3QzsolD3afCy7J2x0IIlp9c1JJXA6ZA2n+nT
         Nuvj0x148VJnayvtqGRYyRk9S5xdXCW/pVALljeKuKUkFf5xC5nBYIFMLE8WViClPgqK
         2ApA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767813472; x=1768418272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FO4R9UO4JHQD+QHvgMUBfbiU3Q6iLTlMKtvOUYKG/cA=;
        b=pvhJI+bt2B14amYzCOSmNUnA4hhPgioumqOhXCbic2p6W6lZXLIfSyjvCbQfmKeC8f
         fbpbMlSoq6lFJ1zFiolIkJ+ZPQVWRI0HySnqqoLfQlmeub3jXpDu/HFIPnErfIp2agOz
         QrWjL+4Gkpqmrpuuewe4bsX+RxXmKSV5WkDknSJ3Mf6xle7AtPjmnHQrdUUqOeF0M1jX
         xO+RvF/D417U8KEh5cQ5kIhHLeQlF1Dkdaakl7TJz/ShdxRqrkghzChOBPa1yaUhb+lp
         galC26OulsmXC+CmMBNRLpPsBi8V12UG9C7bXs9dASc5AgeTV3Y2QIZtUXnHD5M/kCIn
         lbug==
X-Forwarded-Encrypted: i=2; AJvYcCXBY8Unhrz0erwMOvBZUM5m6BtlXYKKiL32r8w27vygp2O2sEpmn57kKpyZlsRq/og/nkZN1A==@lfdr.de
X-Gm-Message-State: AOJu0YwcydXD2l4FW+bSc7nlsRARco7IX/XgOdz5FIUPVprCWB67In1w
	LEtpypO9EVWx4h12Ga5Zf2DkGKdAbSadKWwrIv0t59KsDez3Zg/ZRaDA
X-Google-Smtp-Source: AGHT+IFLcIiLQJHofrTVGZPYWk6JQmClwLJNhdz2G16MWXzP4Iiv0aqjiVUB21hn6L0nU7+fc9othA==
X-Received: by 2002:a05:6214:4907:b0:88a:3837:4981 with SMTP id 6a1803df08f44-890842d6eedmr50312316d6.65.1767813471601;
        Wed, 07 Jan 2026 11:17:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZO9MNlB2LIZ473/OcXZQ/LjRXLiDeqXy8kipx/SzKx0Q=="
Received: by 2002:a05:6214:cac:b0:888:57c0:3d18 with SMTP id
 6a1803df08f44-8907569dd51ls50439436d6.1.-pod-prod-04-us; Wed, 07 Jan 2026
 11:17:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVUH57vwrLxPgy2LMsuFHyUHeTGfHp/9B6zjNORgnV9/UaL11eUgN0/1MmkSY8tM8d3njsFKWad/o=@googlegroups.com
X-Received: by 2002:a05:6122:4b89:b0:55b:305b:4e26 with SMTP id 71dfb90a1353d-563480070a7mr1402158e0c.18.1767813470553;
        Wed, 07 Jan 2026 11:17:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767813470; cv=none;
        d=google.com; s=arc-20240605;
        b=kysFGbfc+qS7hsieS8Y1S15gPCvxtMxYhHgtsmfYN6egztz34hECTnlCyNx0mmzBY4
         fTFzihNX4Q4twU4qoX8vbGLtHi2OccoTb3PQvq033OdufRnGWYYZHTMoGEOPHDfCK1Pe
         ZpctlxFQwEPqCUiYZ0tTWmK7sCKDoBZ25YWKHF2SranIWFL2Vz/9oJYH8pZnaup0NGgD
         KMKoRHd3v0nByrc7xUx1IWkS57yxWD/hk/mma3dPVjbR2FfpRlnzmoZbixmbH9lvvG1J
         6/bmwzW0W96INLYVLYNEReVzMgtbQem/EY5rRrQRsOvkBvdXmtmpJIZVW8Mto11hcj5J
         Qrog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9zgx4q5hyau69tIgZgl//mOMTpmrD6yq0HBEGOQs49s=;
        fh=M91/4o6ZDmglamdio9PadT+TMBvC/sSSP6UJGcNQcHI=;
        b=WYQCN6yNX2GVroJvgJW/tKUzKg+0XFpCdhMXUBHAmzmZ0bW6SLR/Xd2q6drYA3inJB
         za9j0edYoSX3SxQetosjvf8WiFZHuo4vUjf8EblL9bbAdaVdXcPt4xXmFNeYxW241uzl
         6TfumKm+piU7thsJIzp3td2Ht+UXtBD8bd3d+0FtGnUpk0/8Fv7HfnVU86qZnznxLgUz
         +pkOlrGjPa+GNgsamH/5Jhd6aoubnYhpeIgILDP2Hr7gTILR3zpMJ1OiOEmUNQ4Q5uIa
         XudArZtPU21rgXv6+tggPSO85w6rYLSzT6QYxkXSSYijhR/4ma2Ho2PrzxQBTfZnnXId
         9yTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WT7SW+oW;
       spf=pass (google.com: domain of srs0=nqng=7m=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=nqng=7M=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5633b850669si118653e0c.2.2026.01.07.11.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 11:17:50 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=nqng=7m=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C78246000A;
	Wed,  7 Jan 2026 19:17:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 71A9EC4CEF1;
	Wed,  7 Jan 2026 19:17:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E32B1CE098B; Wed,  7 Jan 2026 11:17:48 -0800 (PST)
Date: Wed, 7 Jan 2026 11:17:48 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Gary Guo <gary@garyguo.net>,
	Will Deacon <will@kernel.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Matt Turner <mattst88@gmail.com>,
	Magnus Lindholm <linmag7@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Lyude Paul <lyude@redhat.com>, Thomas Gleixner <tglx@linutronix.de>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	John Stultz <jstultz@google.com>, Stephen Boyd <sboyd@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	linux-kernel@vger.kernel.org, linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/5] Add READ_ONCE and WRITE_ONCE to Rust
Message-ID: <be85a8be-2def-48b4-9bee-9c2a8c063608@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20251231-rwonce-v1-0-702a10b85278@google.com>
 <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com>
 <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local>
 <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local>
 <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
 <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
 <20260107084322.GC272712@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260107084322.GC272712@noisy.programming.kicks-ass.net>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WT7SW+oW;       spf=pass
 (google.com: domain of srs0=nqng=7m=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=nqng=7M=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Wed, Jan 07, 2026 at 09:43:22AM +0100, Peter Zijlstra wrote:
> On Tue, Jan 06, 2026 at 10:18:35AM -0800, Paul E. McKenney wrote:
> > On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> > > On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> > > 
> > > > Some C code believes a plain write to a properly aligned location is
> > > > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > > > it's recommended to assume such), and I guess that's the case for
> > > > hrtimer, if it's not much a trouble you can replace the plain write with
> > > > WRITE_ONCE() on C side ;-)
> > > 
> > > GCC used to provide this guarantee, some of the older code was written
> > > on that. GCC no longer provides that guarantee (there are known cases
> > > where it breaks and all that) and newer code should not rely on this.
> > > 
> > > All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.
> > 
> > Agreed!
> > 
> > In that vein, any objections to the patch shown below?
> 
> Not really; although it would of course be nice if that were accompanied
> with a pile of cleanup patches taking out the worst offenders or
> somesuch ;-)

Careful what you ask for.  You might get it...  ;-)

							Thanx, Paul

> > ------------------------------------------------------------------------
> > 
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 4ce4b0c0109cb..e827e24ab5d42 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -199,7 +199,7 @@ config KCSAN_WEAK_MEMORY
> >  
> >  config KCSAN_REPORT_VALUE_CHANGE_ONLY
> >  	bool "Only report races where watcher observed a data value change"
> > -	default y
> > +	default n
> >  	depends on !KCSAN_STRICT
> >  	help
> >  	  If enabled and a conflicting write is observed via a watchpoint, but
> > @@ -208,7 +208,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
> >  
> >  config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> >  	bool "Assume that plain aligned writes up to word size are atomic"
> > -	default y
> > +	default n
> >  	depends on !KCSAN_STRICT
> >  	help
> >  	  Assume that plain aligned writes up to word size are atomic by

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/be85a8be-2def-48b4-9bee-9c2a8c063608%40paulmck-laptop.
