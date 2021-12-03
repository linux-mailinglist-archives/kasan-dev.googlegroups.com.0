Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXOWVKGQMGQE4RWKJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EFD3B4680CE
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 00:42:21 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id o18-20020a05600c511200b00332fa17a02esf1991658wms.5
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 15:42:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638574941; cv=pass;
        d=google.com; s=arc-20160816;
        b=DRj4K1CbnS3VduJ99pksp2Q0FIoQ+gj4HEcw7T745QGYwAOemgxkwe5DqFowXPv4M1
         NsnXzHGLpR/F4lLTFwDT8iwMKSkR5GdXkBiTp8gfkZMSFziRwY86mwDetWyw70qyg/z1
         VMONQbhmg4dgx6L7HSZ3qth2iFbWPGL+JyLK+eANAdsSTCtJd4BEs7wZjFiDpLKNCALS
         6Snss3H5u4Ew40pkja5zbhubISMT3c8FPnwHUN9UcSHqKHsDJPb53tlhZ3QSGCFQQsOk
         X44mfa1E0EeYEx1JwKolX7UgWminR8lPm3xboBgUb40/4EXg/AZn1mlJ3Vdwu4VAshqN
         pgdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=PXV7gMY+CukvQD12dOoLf9mf2KuKKkCzwWr9Q/BFGHk=;
        b=E8qFZQuA5LwqLYqgH3Bu8dNptc4c9Ry2H/BNYCAy66CWYx9IksM4bBgHjMbyEqcrmD
         KF6cGT0vWpQQrAGSqpaclsIgCAPbF9FbcBJlraIZWzZsH2RlZeftEk3bGmuq/rV7J2KN
         wTHAdnNnQNpRlNtgFUrcfhJm9VL/UwYzDNCVWDl5a2WKFtXJ8xURV+jffLKcqSDKtq3q
         jYup4ZNDCUpD2v+W8n+EltZdK04ulpKmp25NPWvQe/I2e6x6JEKZ23Bte43uOjNaVx8+
         R8M4MPmYAeKV93whSll1L+QUewsvfFLQI5gyHpHsm/0U74lY2V7Gt2Ci7FTBwQ7b7+WG
         kACQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d2lVgutR;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PXV7gMY+CukvQD12dOoLf9mf2KuKKkCzwWr9Q/BFGHk=;
        b=MQxOXxvPq4MOQ8+uw2xAcysqdPgbH+y8RaSssd1aSnAf9TP1BPO2VEtfmcdkQtdPjv
         Y4AJwy6Mr/qI2d+ro5dc9hnBQGWm+N03pLS1wFozUY2+LdU1ulUvN3rk5B+2MG3q1e6S
         qj94pRT8v4/Ir6mtXG4i9m9/F727cV0HBxv+/28LugFtL0qkiEb/TLbhwcLHxNf0pkmB
         U7dTTYRZm1S2wAPvPMU7xjilc6+T+LwSAzmMP27KUMbG2QXl9w3iyX7UFm6rmlfMHknk
         10qlj7z7YoL9bS/wNTcp23y00fqaikdAgOQu8pPIlNUPv59paSOAIiitqfFBR/slKKbf
         sTAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PXV7gMY+CukvQD12dOoLf9mf2KuKKkCzwWr9Q/BFGHk=;
        b=28LKrl/GcveCpN2UAg4vD4JVfHHvCg7Iv7OJ2M/IvVozpG+rlwm9mm/srPD1RkvW/h
         hJ38Se/UcIRai9efYw2ZGniXTA6/qxzLsKYt2vnZQ5c3TEXqFyRtpOt1GDqqm2ud/g0q
         GSyJgkOlUnXVF/Yq5RvaSymGsVJhEMD26OjGsvANW9N+3nkxnK6hF8UyEzRafQ2wGt4s
         1Bzb8sTycscs6NzbtUr6P43vfBTxZrUsdCXehV5dXQtAjKQ/GVf0WbLJF/2JRGXdlE/K
         CA2+LmJHw5iT4MhYL6pGDEsITlSjnI/vLDS6Rp+ka0HlH+3HKMNdYsXOPI9pgb1qtwIw
         IS/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HTD2Z5/mZqX2ken81Ho6jLod6+ys1VabXo5rNVzz3YY588ya2
	pCdw9jhzka5F0haCr9c1dwQ=
X-Google-Smtp-Source: ABdhPJzQkLTINooTWvd0t8MZcsxES2LO4woEFY9Nmg209IAZdUQfpVzJgaawomWbAG5c/LAiO+p4Wg==
X-Received: by 2002:a05:600c:210a:: with SMTP id u10mr18542338wml.33.1638574941763;
        Fri, 03 Dec 2021 15:42:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls134018wrr.0.gmail; Fri, 03 Dec
 2021 15:42:20 -0800 (PST)
X-Received: by 2002:adf:9e4b:: with SMTP id v11mr25586603wre.531.1638574940780;
        Fri, 03 Dec 2021 15:42:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638574940; cv=none;
        d=google.com; s=arc-20160816;
        b=pZEDxMd0uqAJsHGUoMiefOHH8dqgSaO2AXvRAmd8l95TjtvVSCyxuS1Jx4tBVzntyp
         IY7WvbtcmtcV4kkW8imKlMs56NI25B+oaB5b99zn/zn6lNnGtAR+k4Ducd5r5ti6WZcA
         dj9N8wfD5PNQ85+kB6YNa4O6+lqTFMYDvpUc4AiySi8eQstKCrQMI0KbdPv0mqiOXXsz
         0mUlC+CmtDKfPUb8aVWxro54e98Af99nyNMvFekUgKWeVtZ7HwHrTmN/89ctRCN/Njue
         w3vnAygnVhNvY4Z0gCDLrS1gAToNDrGfPlpjs5BWawCM2efkWCQbJqo8olrsGoSpuo85
         m18Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=G/U6VuVYn/OHYxdh46kgQ5kcodEbqB8gX+4VSwVW540=;
        b=rJN0Rfe2/utlzw8TBXgTzOlFa9IwXrDtGrNQcm2023MXT1Es+tArLbOxIZ7NPV2SfB
         bF6kardsUdiUO8J1fdFKR+ucl792Ibj/5TlUGfI0Js7jdimeXlXOFOfeIDsAMY2PRpu/
         vdimILOZP56gsAQ8EgFkgxgiVGz7+I0jTdwfXUpY6HRVRpmzwW0MkSlD9XVvvzDGDaCx
         VGYgSZaTYXwCqIs250B7cCMf8guV0OS5loViBRMmThdGl8LJLIgNnu7oiEV62J1/xEOW
         sfUCMyVJsJjuzlznQCuloD2xg5qt/NP8M+H9PUwJwYXtQNAp7+34RQJkL0A3F3Ev/+tM
         eAfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d2lVgutR;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id o29si699504wms.1.2021.12.03.15.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 15:42:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4ABD1B828C4;
	Fri,  3 Dec 2021 23:42:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 044B1C53FAD;
	Fri,  3 Dec 2021 23:42:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9BA865C1010; Fri,  3 Dec 2021 15:42:18 -0800 (PST)
Date: Fri, 3 Dec 2021 15:42:18 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
Message-ID: <20211203234218.GA3308268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com>
 <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
 <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=d2lVgutR;       spf=pass
 (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Dec 03, 2021 at 01:08:56PM -0800, Paul E. McKenney wrote:
> On Fri, Dec 03, 2021 at 08:50:20AM -0800, Paul E. McKenney wrote:
> > On Fri, Dec 03, 2021 at 09:56:45AM +0100, Marco Elver wrote:
> > > On Tue, Nov 30, 2021 at 12:44PM +0100, Marco Elver wrote:
> > > [...]
> > > > v3:
> > > > * Remove kcsan_noinstr hackery, since we now try to avoid adding any
> > > >   instrumentation to .noinstr.text in the first place.
> > > [...]
> > > 
> > > I missed some cleanups after changes from v2 to v3 -- the below cleanup
> > > is missing.
> > > 
> > > Full replacement patch attached.
> > 
> > I pulled this into -rcu with the other patches from your v3 post, thank
> > you all!
> 
> A few quick tests located the following:
> 
> [    0.635383] INFO: trying to register non-static key.
> [    0.635804] The code is fine but needs lockdep annotation, or maybe
> [    0.636194] you didn't initialize this object before use?
> [    0.636194] turning off the locking correctness validator.
> [    0.636194] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.16.0-rc1+ #3208
> [    0.636194] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014
> [    0.636194] Call Trace:
> [    0.636194]  <TASK>
> [    0.636194]  dump_stack_lvl+0x88/0xd8
> [    0.636194]  dump_stack+0x15/0x1b
> [    0.636194]  register_lock_class+0x6b3/0x840
> [    0.636194]  ? __this_cpu_preempt_check+0x1d/0x30
> [    0.636194]  __lock_acquire+0x81/0xee0
> [    0.636194]  ? lock_is_held_type+0xf1/0x160
> [    0.636194]  lock_acquire+0xce/0x230
> [    0.636194]  ? test_barrier+0x490/0x14c7
> [    0.636194]  ? lock_is_held_type+0xf1/0x160
> [    0.636194]  ? test_barrier+0x490/0x14c7
> [    0.636194]  _raw_spin_lock+0x36/0x50
> [    0.636194]  ? test_barrier+0x490/0x14c7
> [    0.636194]  ? kcsan_init+0xf/0x80
> [    0.636194]  test_barrier+0x490/0x14c7
> [    0.636194]  ? kcsan_debugfs_init+0x1f/0x1f
> [    0.636194]  kcsan_selftest+0x47/0xa0
> [    0.636194]  do_one_initcall+0x104/0x230
> [    0.636194]  ? rcu_read_lock_sched_held+0x5b/0xc0
> [    0.636194]  ? kernel_init+0x1c/0x200
> [    0.636194]  do_initcall_level+0xa5/0xb6
> [    0.636194]  do_initcalls+0x66/0x95
> [    0.636194]  do_basic_setup+0x1d/0x23
> [    0.636194]  kernel_init_freeable+0x254/0x2ed
> [    0.636194]  ? rest_init+0x290/0x290
> [    0.636194]  kernel_init+0x1c/0x200
> [    0.636194]  ? rest_init+0x290/0x290
> [    0.636194]  ret_from_fork+0x22/0x30
> [    0.636194]  </TASK>
> 
> When running without the new patch series, this splat does not appear.
> 
> Do I need a toolchain upgrade?  I see the Clang 14.0 in the cover letter,
> but that seems to apply only to non-x86 architectures.
> 
> $ clang-11 -v
> Ubuntu clang version 11.1.0-++20210805102428+1fdec59bffc1-1~exp1~20210805203044.169

And to further extend this bug report, the following patch suppresses
the error.

							Thanx, Paul

------------------------------------------------------------------------

commit d157b802f05bd12cf40bef7a73ca6914b85c865e
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Fri Dec 3 15:35:29 2021 -0800

    kcsan: selftest: Move test spinlock to static global
    
    Running the TREE01 or TREE02 rcutorture scenarios results in the
    following splat:
    
    ------------------------------------------------------------------------
    
     INFO: trying to register non-static key.
     The code is fine but needs lockdep annotation, or maybe
     you didn't initialize this object before use?
     turning off the locking correctness validator.
     CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.16.0-rc1+ #3208
     Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014
     Call Trace:
      <TASK>
      dump_stack_lvl+0x88/0xd8
      dump_stack+0x15/0x1b
      register_lock_class+0x6b3/0x840
      ? __this_cpu_preempt_check+0x1d/0x30
      __lock_acquire+0x81/0xee0
      ? lock_is_held_type+0xf1/0x160
      lock_acquire+0xce/0x230
      ? test_barrier+0x490/0x14c7
      ? lock_is_held_type+0xf1/0x160
      ? test_barrier+0x490/0x14c7
      _raw_spin_lock+0x36/0x50
      ? test_barrier+0x490/0x14c7
      ? kcsan_init+0xf/0x80
      test_barrier+0x490/0x14c7
      ? kcsan_debugfs_init+0x1f/0x1f
      kcsan_selftest+0x47/0xa0
      do_one_initcall+0x104/0x230
      ? rcu_read_lock_sched_held+0x5b/0xc0
      ? kernel_init+0x1c/0x200
      do_initcall_level+0xa5/0xb6
      do_initcalls+0x66/0x95
      do_basic_setup+0x1d/0x23
      kernel_init_freeable+0x254/0x2ed
      ? rest_init+0x290/0x290
      kernel_init+0x1c/0x200
      ? rest_init+0x290/0x290
      ret_from_fork+0x22/0x30
      </TASK>
    
    ------------------------------------------------------------------------
    
    This appears to be due to this line of code in kernel/kcsan/selftest.c:
    KCSAN_CHECK_READ_BARRIER(spin_unlock(&spinlock)), which operates on a
    spinlock allocated on the stack.  This shot-in-the-dark patch makes the
    spinlock instead be a static global, which suppresses the above splat.
    
    Fixes: 510b49b8d4c9 ("kcsan: selftest: Add test case to check memory barrier instrumentation")
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 08c6b84b9ebed..05d772c9fe933 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -108,6 +108,8 @@ static bool __init test_matching_access(void)
 	return true;
 }
 
+static DEFINE_SPINLOCK(test_barrier_spinlock);
+
 /*
  * Correct memory barrier instrumentation is critical to avoiding false
  * positives: simple test to check at boot certain barriers are always properly
@@ -122,7 +124,6 @@ static bool __init test_barrier(void)
 #endif
 	bool ret = true;
 	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
-	DEFINE_SPINLOCK(spinlock);
 	atomic_t dummy;
 	long test_var;
 
@@ -172,8 +173,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_READ_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_READ_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_barrier_spinlock);
+	KCSAN_CHECK_READ_BARRIER(spin_unlock(&test_barrier_spinlock));
 
 	KCSAN_CHECK_WRITE_BARRIER(mb());
 	KCSAN_CHECK_WRITE_BARRIER(wmb());
@@ -202,8 +203,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_WRITE_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_barrier_spinlock);
+	KCSAN_CHECK_WRITE_BARRIER(spin_unlock(&test_barrier_spinlock));
 
 	KCSAN_CHECK_RW_BARRIER(mb());
 	KCSAN_CHECK_RW_BARRIER(wmb());
@@ -235,8 +236,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_RW_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_RW_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_barrier_spinlock);
+	KCSAN_CHECK_RW_BARRIER(spin_unlock(&test_barrier_spinlock));
 
 	kcsan_nestable_atomic_end();
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203234218.GA3308268%40paulmck-ThinkPad-P17-Gen-1.
