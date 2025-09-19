Return-Path: <kasan-dev+bncBDUNBGN3R4KRBS6HWXDAMGQEVCACFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5593AB89CC4
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:08:14 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-350dc421109sf9097741fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:08:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758290893; cv=pass;
        d=google.com; s=arc-20240605;
        b=PQvBs8nJQiHllV2okGbIm6QTSzcSfel0yN8Oa8hP/8A7eNyn6InsvrEoNfnm/1B8EM
         pGJ40g4mETUH3icA6trJiygIw0Y2IaH4/4wFjyT+FglKu4nct2zxro8AcqxU7Itdsc+T
         D5TmbZ4Tt7BokUYo/Ty5kqsTzC9ERQDyrv9ea9cedBh+Lr/i1lvDQVS05fhhkoKg8wdm
         dM5pmbJEvUq6ct14tZ2tKhQ/G/mPpbVcu3ObC+2+b4Mkxz/i2Cfx2y1nofMZiVAQ4YVc
         U87ukqJQkX9n6IcyXbmqtmO9FSYKsxRBfnsn+o1Rt+UY0RzkFY/fbAtpIFEkB0b1SrJ2
         sEMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=WByh8xj85qMPk6gTtt2hx6f3IaB0/C9QPLFRoVXPj04=;
        fh=9lRA1KjAuIFrfc316TyM3k8bmQI9MBMuCz6uZswmrEs=;
        b=ezhsaNrN8rtOQHtJib1hemqOH7h+E3h43VF7ah5LsbC10BDVeUw7Z/3Nc+zyYghykx
         jnToY0LAH5MgdUTsYItDT7xtasPVye3C79s0Vy/nCdaNasEI/QAx0DyjXniJnW0k9+/t
         oyC3yNY0CZQFS8ehl2SSjtkf4LGvVFiRppwiynP5M2A8mrw+LY50/dN+SzTaPyVj44CC
         2xUzDmHbLKN+Z4usLHZ+jr8x9mt5o1efI3bvCIJ1jiOlFZ4dwz7epCauIiERzFM+uvyD
         qFaApiRcdM0vv8viPw2nZdyTrPGDoltuf0dcG1u/8ZXoGJlPm2GmLnG1u8Xe6BSihBbV
         9LJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758290893; x=1758895693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WByh8xj85qMPk6gTtt2hx6f3IaB0/C9QPLFRoVXPj04=;
        b=hSpRzAO1ipHzVecZLj7QkeZvxaBhkaTBPEKP5/9yPS3FHz+TfIDvKCRBjuuNatT4qi
         hXIUV00bF7qDbvmYZq2rvDkQMfCh1hPmmF/OkvAdRPv1mn3ps0Iohr2JkX3Mg/AXBuDO
         tc6fCX9ItcMKGedTYsequJZz0nwikP/ZNdwGt8p/yzT6jA/AuRjtfVYt/uJUF1GB9z+P
         OEV3oUlwDw1XpcA6RbhRCuuMBMSzySmgwaBGA27Vz62G8Wi8cqGf74eQKNC4aLL+7N06
         Wztpinu6YNXB6CMkVfmpasocW/RyLyRNC21mJrCunaEtdrfORjWi5GxyKibERjZDyUw0
         iXUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758290893; x=1758895693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=WByh8xj85qMPk6gTtt2hx6f3IaB0/C9QPLFRoVXPj04=;
        b=QQyDccc1IfdwDjA3ffQ57nZN+CXAumOKrwqzM2NnuDtGes5oAUJri9HPbuOeaOzE9r
         guim83AryXqzSZAhmQ/xau1wa2Xc3tJ9n3F4OrckiunLud6W7gISo5dIm5R35Rtq5lR7
         OMgLeWZCNkBYcU+JgdfLrG6Urt41MeAafjPd/vsA7Oxv/px4+phIjRoEZk+W4Syi90zU
         NLWA9D+Wwb7gxfUQF60LjJptS7GZjvGvMHbQaXuvaFdDRa1yIOrZrTTNzkPhYFD49dWO
         Vg66ipXD3WOJB37pvCX5NrcbHyAe2BU7FYLZL2W6hjWq7sVxVydKZX0WGhrt/HsZxcWb
         vWeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9tICn1K+vzS5F6VdAMthWV8HisUBchnkJTXyL09j0UK05W9Xy0d+O6XaYsrr6gUARyS/0YA==@lfdr.de
X-Gm-Message-State: AOJu0YzEAXr/qCilEvBjkFjn4SyVOVOD8IQzcSqmTpnrQYkneQ8flFj2
	aMkinKs7PluSzel5Xezj9b2ijJo1AC1PXxqHQY+r6j2t4+LM0p5PxB1s
X-Google-Smtp-Source: AGHT+IGnWeFvmNscJKR5VLeALJ+P754wFyTK87YMRLBkuS2VVEaO69oIRYBktDekzsQ+9w0TLZW4IQ==
X-Received: by 2002:a05:651c:3257:10b0:360:5e8d:c85f with SMTP id 38308e7fff4ca-3640eae2646mr8706161fa.0.1758290892194;
        Fri, 19 Sep 2025 07:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd51NQacdImWKmM+d5x44o9lxds2S1Zc++ehplRrBHn9Tw==
Received: by 2002:a05:6512:4047:20b0:577:6df3:c704 with SMTP id
 2adb3069b0e04-578cbffd5dfls571986e87.2.-pod-prod-06-eu; Fri, 19 Sep 2025
 07:08:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWReKo/s4BKysTSO0sA+Ge0oa7sZB1LGG6FcX4MAxuFmQAtPTRCg4A5wBwcQE3BCqxdgW6fhj4pGSQ=@googlegroups.com
X-Received: by 2002:a05:6512:1599:b0:57a:1846:df77 with SMTP id 2adb3069b0e04-57a1846e26cmr930779e87.40.1758290888650;
        Fri, 19 Sep 2025 07:08:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758290888; cv=none;
        d=google.com; s=arc-20240605;
        b=cLm8yBqWgrORz5boBfuVkuYZAVVlYbCWNda7CfAtO9GB9HMc3ft+AumWt5rXt2Mhyj
         6+tPb+yDQksvTlUghFVwOX+mddvj05ah1a+wLqXGgBILSN72M3tUOuA9EobhA+zLEeId
         UT8YairWdibtnMmx9RGMVi3WEheUvVMmoy0l/LHCEtLGIeTg+IdqoT5l0TmdL0NfcPjo
         zuPr9If4/L73uC2Yt4FQswym3xU119MTP4CVc0c1C5ea2WleMD+bZfh3dXwHPsP1enb2
         AxDQvL8I7sw9nqznz7lPVugg342iJoEA0wGu+IsImOIPwaKZfLuSkDFTZOcJAhrrKs7y
         oM0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uw1h0zqyCJ+MrI70fVNHHLekDspDIQEV+NKvDauH29Q=;
        fh=P5eIro9UGdx23XTNWTN5Twl8qouPrH7ygQJNKcnxUKg=;
        b=F4kFnWyR+mJzlPr1g933sDBqPfdMwrQ0BUNQNuTK0SPmxYQSimtpDuDLIu+aodYoBt
         AolZP7ykTGSIbTLYczSSBPsAD2ehn8M234rW0gofQiJH8JcA8XqYUjlTB7qA5lhseOUe
         1kMgNs3j+U9RKlGw3o/SQzCTE4Cf0zWHp+WUZpFa26psmmkEwniXtOfN+AwTtrX8WOf9
         hUPnB8qLSUeVnMsx0NzIjpVpxMhj7zbK9SUT7V17WwjS9ehzCGqVZQ2sWtg+KNHMW2RZ
         NscCPeQigSPg7tSSf/9prXMu5miYTGo+NLBBtVTqQDX0bwdfkU7XgCgLDoX7sKGli0do
         lNEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a7a8045asi91766e87.3.2025.09.19.07.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:08:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id BBAB368AA6; Fri, 19 Sep 2025 16:08:03 +0200 (CEST)
Date: Fri, 19 Sep 2025 16:08:03 +0200
From: Christoph Hellwig <hch@lst.de>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and
 Locking-Analysis
Message-ID: <20250919140803.GA23745@lst.de>
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de> <20250918174555.GA3366400@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250918174555.GA3366400@ax162>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

On Thu, Sep 18, 2025 at 10:45:55AM -0700, Nathan Chancellor wrote:
> On Thu, Sep 18, 2025 at 04:15:11PM +0200, Christoph Hellwig wrote:
> > On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > > A Clang version that supports `-Wthread-safety-pointer` and the new
> > > alias-analysis of capability pointers is required (from this version
> > > onwards):
> > > 
> > > 	https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
> > 
> > There's no chance to make say x86 pre-built binaries for that available?
> 
> I can use my existing kernel.org LLVM [1] build infrastructure to
> generate prebuilt x86 binaries. Just give me a bit to build and upload
> them. You may not be the only developer or maintainer who may want to
> play with this.

That did work, thanks.

I started to play around with that.  For the nvme code adding the
annotations was very simply, and I also started adding trivial
__guarded_by which instantly found issues.

For XFS it was a lot more work and I still see tons of compiler
warnings, which I'm not entirely sure how to address.  Right now I
see three major classes:

1) locks held over loop iterations like:

fs/xfs/xfs_extent_busy.c:573:26: warning: expecting spinlock 'xfs_group_hold(busyp->group)..xg_busy_extents->eb_lock' to be held at start of each loop [-Wthread-safety-analysis]
  573 |                 struct xfs_group        *xg = xfs_group_hold(busyp->group);
      |                                               ^
fs/xfs/xfs_extent_busy.c:577:3: note: spinlock acquired here
  577 |                 spin_lock(&eb->eb_lock);
      |                 ^

This is perfectly find code and needs some annotations, but I can't find
any good example.

2) Locks on returned objects, which can be NULL.  I.e., something
like crossover of __acquire_ret and __cond_acquires

3) Wrappers that take multiple locks conditionally

We have helpers that take different locks in the same object based on the
arguments like xfs_ilock() or those that take the same lock and a variable
number of objects like xfs_dqlockn based on input and sorting.  The
first are just historic and we might want to kill them, but the
sorting of objects to acquire locks in order thing is a pattern in
various places including the VFS, so we'll need some way to annotate it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919140803.GA23745%40lst.de.
