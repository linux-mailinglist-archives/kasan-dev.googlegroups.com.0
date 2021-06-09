Return-Path: <kasan-dev+bncBCJZRXGY5YJBBV45QWDAMGQEJTJR5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A87A63A20C8
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 01:29:28 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id w1-20020a0568304101b02902fc17224cf5sf17268142ott.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 16:29:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623281367; cv=pass;
        d=google.com; s=arc-20160816;
        b=r1k5DeM3tG3HVJN713xICITql1JbsnjnibUi5gqo1JY4vVElklroBhBMuqnoyKRsxE
         iqXeEVBJqPE8pQ5wsTbqvl8Iwmv8/fO2cQgzdmSy3IlfF35ti7XYnH2VQN0uvKhJ4bvH
         0NlLE1J3+jhlZ4lV2ujwIxb14llbYnj9JZ4fjyKzQXMZB920Lh3e18tzk88AmPburYTJ
         gsxkrwMi5hwZxlYFfoptg4Kc3EGJNDFeQbp7RPcEgpSWdJJHFNDZTkpOwIrh+QGN80gz
         WgjgUv36cwjPWrRE9CBkMzgsYd8H8u8zczO7g+yvnb9z0KpFatF7JghbGKZXdeiHYdOx
         uMBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:sender:dkim-signature;
        bh=jXjtmOWpkiz3oiqN7xQDoJ25L1uKQ2qzX5hlLu9zB14=;
        b=ZJLX2rNe0ROSkdK+mQu69gQ5ke3f2tCONAHGp29aZuHy0+ZMZ6vcAZi+r4M3xZMbZo
         hv2XxIABUo9Uvrult9cTYZoQhvmJMZOamEDeTksP3zxHhQGuxXBbdpH5y+iPpCtPN7jR
         Q/XJXvVgjB1P1hxPWMiMg3ugXSBKVdMU0WMPTjQSgWuCqQVDkwBFsGvCtZf40iUU2f2K
         kjyyQ3+j1buRBM6fiPrYpoy265lgxO83GRMpUPAi4BED4r9uKYLz2yrbyt6n7nlfy/nt
         9OGMzms50Psy5WrmFadV24qf0C4haOaskwDaCvBfWig1T5XZ9kaYaOD8C/5XnznzGVo8
         Mp8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dPY8pUdo;
       spf=pass (google.com: domain of srs0=dcq8=ld=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Dcq8=LD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jXjtmOWpkiz3oiqN7xQDoJ25L1uKQ2qzX5hlLu9zB14=;
        b=dvvaIDXH8+335UR0R1FlMtfkEMpgq7m63JngFvFCSGddpAiQSX3ICcZ3oe1koTLD2r
         S8wWPoK4OOlOC4r9wYliElb0C+dRS32Xxv4SAG1dEHtktD0V0HdQQrqT3ffx6Wj9ZHt2
         CPoczdSzEemFVwOL2E8c1nrq9EvzRwNB0/7SPiTlbdzJt4abtMVPDpLyVCbvcjjgjKgg
         3X0ka2hcRK5HZUoBNh2UV4cvplg+N7kpXSBFKcBNQHa5lIkUx/Lw0SYBPT7Lll48ygRQ
         STAPrwcyPwWjZhYEZ9gfqa+ii53oTXymxpnjMTbZSRQ0SY7TRPw4gfP+KHzVk+/AcAws
         STog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jXjtmOWpkiz3oiqN7xQDoJ25L1uKQ2qzX5hlLu9zB14=;
        b=MCsHaaAT5bLeEIGaMjsVTXbMF4lpNpwZoJOX9GnUxpmlqYm52kmVHUJ+jFZxyVUJpn
         1+J5Rnzepa2A240WGIOvICJfvFfwxBikJ3LMB1Tvkzkr3kNiQxBpqAwFnJJXumcQRF7O
         e1JgpQL9DDGvrPYrLyvMJTFB8DMV/GuliW82LvdC3hccKfohTTkvKsZk2j1nYa+h3GQ1
         lyHEFQuNEBm1e/CIl9TjDnzFg3s5x3CLtuDsPYl4wboO3fqvMBLUkQY5fvYfMf/PR3tM
         hmN9mUMHod4d2tkEviXtiOKUXwS75YEyJAGVbjaCYRlw0dMTlc7RzjWl1ND8qt7RqIgp
         TU3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313mel3x9nwwAUYHdzmaMQ3uLTiXVcPfynojtGlF7maFbH1mlJz
	a/lP46/eeem/cIf6KJE5HqU=
X-Google-Smtp-Source: ABdhPJwvj7ExLlIXREwgkd8XKeIIgTYxMPc9cxxV5L1Ms6JBc37ZMosVWBj5ktweL/2BPOfNJE5DrA==
X-Received: by 2002:a9d:c64:: with SMTP id 91mr52190otr.130.1623281367446;
        Wed, 09 Jun 2021 16:29:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5754:: with SMTP id l81ls1237816oib.9.gmail; Wed, 09 Jun
 2021 16:29:27 -0700 (PDT)
X-Received: by 2002:a54:4e82:: with SMTP id c2mr8128373oiy.137.1623281367073;
        Wed, 09 Jun 2021 16:29:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623281367; cv=none;
        d=google.com; s=arc-20160816;
        b=SGBU6UQZUBhAjR6TLwYcr2PsX7RzSe/fK+YA1IYGKY0MCQYmOe0X1ZmXvwY6NaQ8kB
         YGsdf7/IgzrAuhjvEkjGLboiJ7GuGZt1VFNOWWgQz7G3g3KFdZt9QAHQvEWAuC+rCQb+
         43egeYL40SntHo31Ih5DxvVUIGb7QK9ARNYT1x3Uq5PdjWw9GQWi6327wvtVDR3YcPTQ
         i7lmxit1S7qqMxk0MmZV/WYlLaa6sQXras+GIq2vEeqkEJ1h4J/1XCTnlWzBZRANrkki
         yFV2qf8TbvmViPhDaGT/d9iQOCAdroa5Vg2s1djLJp3jt1XHpoUEztdJpYI666Bwa4+J
         I8gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=E7TyMxzaY260vvVzo2xeuLX4dRLh7W6TWrujVjLJwa0=;
        b=gkpPsAK64N0mD1UrPwUmr4QnXsI5uL3CZSSdeHyhD2+l0vSPgA28aJb9dU+qTGohXY
         oQcudZw6b2vJkqWEEHg2Q9o4vdqbWZec2gKmZUU/9Cee0rCB/2EPqlNZ8RFKQkJF0ZRS
         KX5WU9mxmJ8YXgdaQGyiFzFCITZxFeRhUwi3kcE6aXAq4cySjDwHOtSR2Mj98ABQBJSh
         +2uqBNPeB/tT88B5jH9vKRktF2bhy9dPsKPQp4AknB8uuIPInBD1NzIwc/SOv/JYMDwS
         psrcLZti/kBddUdFdJlLx47YRZj9b28AmGJCSLWt2xGgjyRQv2Bu3f633diP1VoYT0d4
         9zdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dPY8pUdo;
       spf=pass (google.com: domain of srs0=dcq8=ld=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Dcq8=LD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a25si147718otp.1.2021.06.09.16.29.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Jun 2021 16:29:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=dcq8=ld=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3A66E613EF;
	Wed,  9 Jun 2021 23:29:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0F8315C08D8; Wed,  9 Jun 2021 16:29:26 -0700 (PDT)
Date: Wed, 9 Jun 2021 16:29:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: eb@emlix.com, frederic@kernel.org, jbi.octave@gmail.com,
	maninder1.s@samsung.com, qiang.zhang@windriver.com,
	urezki@gmail.com, yury.norov@gmail.com, zhouzhouyi@gmail.com,
	mark.rutland@arm.com, elver@google.com, bjorn.topel@intel.com,
	akiyks@gmail.com, linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, tglx@linutronix.de
Subject: [GIT PULL tip/core/rcu] RCU, LKMM, and KCSAN commits for v5.14
Message-ID: <20210609232926.GA1715440@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dPY8pUdo;       spf=pass
 (google.com: domain of srs0=dcq8=ld=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Dcq8=LD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Ingo!

This pull request contains changes for RCU, KCSAN, and LKMM.  You can
pull the entire group using branch for-mingo.  Or, if you prefer, you
can pull them separately, using for-mingo-rcu to pull the RCU changes,
for-mingo-kcsan to pull the KCSAN changes, and for-mingo-lkmm to pull
the LKMM changes.

The changes are as follows:

1.	RCU changes (for-mingo-rcu):

	a.	Bitmap support for "all" as alias for all bits, and with
		modifiers allowed, courtesy of Yury Norov.  This change
		means that "rcu_nocbs=3Dall:1/2" would offload all the
		even-numbered CPUs regardless of the number of CPUs on
		the system.
		https://lore.kernel.org/lkml/20210511224115.GA2892092@paulmck-ThinkPad-P1=
7-Gen-1

	b.	Documentation updates.
		https://lore.kernel.org/lkml/20210511224402.GA2892361@paulmck-ThinkPad-P1=
7-Gen-1

	c.	Miscellaneous fixes.
		https://lore.kernel.org/lkml/20210511225241.GA2893003@paulmck-ThinkPad-P1=
7-Gen-1

	d.	kvfree_rcu updates, courtesy of Uladzislau Rezki and Zhang Qiang.
		https://lore.kernel.org/lkml/20210511225450.GA2893337@paulmck-ThinkPad-P1=
7-Gen-1

	e.	mm_dump_obj() updates, courtesy of Maninder Singh, acked
		by Vlastimil Babka.
		https://lore.kernel.org/lkml/20210511225744.GA2893615@paulmck-ThinkPad-P1=
7-Gen-1

	f.	RCU callback offloading updates, courtesy of Frederic
		Weisbecker and Ingo Molnar.  ;-)
		https://lore.kernel.org/lkml/20210511230244.GA2894061@paulmck-ThinkPad-P1=
7-Gen-1

	g.	SRCU updates, courtesy of Frederic Weisbecker.
		https://lore.kernel.org/lkml/20210511230720.GA2894512@paulmck-ThinkPad-P1=
7-Gen-1

	h.	Tasks-RCU updates.
		https://lore.kernel.org/lkml/20210511230924.GA2894768@paulmck-ThinkPad-P1=
7-Gen-1

	i.	Torture-test updates.
		https://lore.kernel.org/lkml/20210511231149.GA2895263@paulmck-ThinkPad-P1=
7-Gen-1

2.	Kernel concurrency sanitizer (KCSAN) updates from Marco Elver
	and Mark Rutland (for-mingo-kcsan).
	https://lore.kernel.org/lkml/20210511232324.GA2896130@paulmck-ThinkPad-P17=
-Gen-1

3.	Linux-kernel memory model (LKMM) updates courtesy of Bj=C3=B6rn T=C3=B6p=
el
	(for-mingo-lkmm).
	https://lore.kernel.org/lkml/20210305102823.415900-1-bjorn.topel@gmail.com

All of the commits in this pull request have been subjected to subjected
to the kbuild test robot and -next testing, and are available in the
git repository based on v5.13-rc1 at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git for-m=
ingo

for you to fetch changes up to 4b26c984195ecd203dd558226f2313b9582df851:

  Merge branch 'lkmm.2021.05.10c' into HEAD (2021-05-18 10:59:54 -0700)

----------------------------------------------------------------
Akira Yokosawa (1):
      kcsan: Use URL link for pointing access-marking.txt

Arnd Bergmann (1):
      kcsan: Fix debugfs initcall return type

Bj=C3=B6rn T=C3=B6pel (1):
      tools/memory-model: Fix smp_mb__after_spinlock() spelling

Frederic Weisbecker (17):
      doc: Fix diagram references in memory-ordering document
      rcu/nocb: Use the rcuog CPU's ->nocb_timer
      timer: Revert "timer: Add timer_curr_running()"
      srcu: Remove superfluous sdp->srcu_lock_count zero filling
      srcu: Remove superfluous ssp initialization for early callbacks
      srcu: Unconditionally embed struct lockdep_map
      srcu: Initialize SRCU after timers
      srcu: Fix broken node geometry after early ssp init
      torture: Correctly fetch number of CPUs for non-English languages
      rcu/nocb: Directly call __wake_nocb_gp() from bypass timer
      rcu/nocb: Allow de-offloading rdp leader
      rcu/nocb: Cancel nocb_timer upon nocb_gp wakeup
      rcu/nocb: Delete bypass_timer upon nocb_gp wakeup
      rcu/nocb: Only cancel nocb timer if not polling
      rcu/nocb: Prepare for fine-grained deferred wakeup
      rcu/nocb: Unify timers
      srcu: Early test SRCU polling start

Ingo Molnar (1):
      rcu: Fix various typos in comments

Jules Irenge (1):
      rcu: Add missing __releases() annotation

Maninder Singh (2):
      mm/slub: Fix backtrace of objects to handle redzone adjustment
      mm/slub: Add Support for free path information of an object

Marco Elver (1):
      kcsan: Document "value changed" line

Mark Rutland (8):
      kcsan: Simplify value change detection
      kcsan: Distinguish kcsan_report() calls
      kcsan: Refactor passing watchpoint/other_info
      kcsan: Fold panic() call into print_report()
      kcsan: Refactor access_info initialization
      kcsan: Remove reporting indirection
      kcsan: Remove kcsan_report_type
      kcsan: Report observed value changes

Paul E. McKenney (50):
      doc: Fix statement of RCU's memory-ordering requirements
      tools/rcu: Add drgn script to dump number of RCU callbacks
      rcu-tasks: Add block comment laying out RCU Tasks design
      rcu-tasks: Add block comment laying out RCU Rude design
      torture: Fix remaining erroneous torture.sh instance of $*
      torture: Add "scenarios" option to kvm.sh --dryrun parameter
      torture: Make kvm-again.sh use "scenarios" rather than "batches" file
      refscale: Allow CPU hotplug to be enabled
      rcuscale: Allow CPU hotplug to be enabled
      torture: Add kvm-remote.sh script for distributed rcutorture test run=
s
      refscale: Add acqrel, lock, and lock-irq
      rcutorture: Abstract read-lock-held checks
      torture: Fix grace-period rate output
      torture: Abstract end-of-run summary
      torture: Make kvm.sh use abstracted kvm-end-run-stats.sh
      torture:  Make the build machine control N in "make -jN"
      torture: Make kvm-find-errors.sh account for kvm-remote.sh
      rcutorture: Judge RCU priority boosting on grace periods, not callbac=
ks
      torture:  Set kvm.sh language to English
      rcutorture: Delay-based false positives for RCU priority boosting tes=
ts
      rcutorture: Consolidate rcu_torture_boost() timing and statistics
      rcutorture: Make rcu_torture_boost_failed() check for GP end
      rcutorture: Add BUSTED-BOOST to test RCU priority boosting tests
      rcutorture: Forgive RCU boost failures when CPUs don't pass through Q=
S
      rcutorture: Don't count CPU-stalled time against priority boosting
      torture: Make kvm-remote.sh account for network failure in pathname c=
hecks
      torture: Don't cap remote runs by build-system number of CPUs
      rcutorture: Move mem_dump_obj() tests into separate function
      rcu: Remove the unused rcu_irq_exit_preempt() function
      rcu: Invoke rcu_spawn_core_kthreads() from rcu_spawn_gp_kthread()
      rcu: Add ->rt_priority and ->gp_start to show_rcu_gp_kthreads() outpu=
t
      rcu: Add ->gp_max to show_rcu_gp_kthreads() output
      lockdep: Explicitly flag likely false-positive report
      rcu: Reject RCU_LOCKDEP_WARN() false positives
      rcu: Add quiescent states and boost states to show_rcu_gp_kthreads() =
output
      rcu: Make RCU priority boosting work on single-CPU rcu_node structure=
s
      rcu: Make show_rcu_gp_kthreads() dump rcu_node structures blocking GP
      rcu: Restrict RCU_STRICT_GRACE_PERIOD to at most four CPUs
      rcu: Make rcu_gp_cleanup() be noinline for tracing
      rcu: Point to documentation of ordering guarantees
      rcu: Don't penalize priority boosting when there is nothing to boost
      rcu: Create an unrcu_pointer() to remove __rcu from a pointer
      rcu: Improve comments describing RCU read-side critical sections
      rcu: Remove obsolete rcu_read_unlock() deadlock commentary
      rcu-tasks: Make ksoftirqd provide RCU Tasks quiescent states
      tasks-rcu: Make show_rcu_tasks_gp_kthreads() be static inline
      Merge branches 'bitmaprange.2021.05.10c', 'doc.2021.05.10c', 'fixes.2=
021.05.13a', 'kvfree_rcu.2021.05.10c', 'mmdumpobj.2021.05.10c', 'nocb.2021.=
05.12a', 'srcu.2021.05.12a', 'tasks.2021.05.18a' and 'torture.2021.05.10c' =
into HEAD
      kcsan: Add pointer to access-marking.txt to data_race() bullet
      Merge branch 'kcsan.2021.05.18a' into HEAD
      Merge branch 'lkmm.2021.05.10c' into HEAD

Rolf Eike Beer (1):
      rcu: Fix typo in comment: kthead -> kthread

Uladzislau Rezki (Sony) (6):
      kvfree_rcu: Use [READ/WRITE]_ONCE() macros to access to nr_bkv_objs
      kvfree_rcu: Add a bulk-list check when a scheduler is run
      kvfree_rcu: Update "monitor_todo" once a batch is started
      kvfree_rcu: Use kfree_rcu_monitor() instead of open-coded variant
      kvfree_rcu: Fix comments according to current code
      kvfree_rcu: Refactor kfree_rcu_monitor()

Yury Norov (2):
      bitmap_parse: Support 'all' semantics
      rcu/tree_plugin: Don't handle the case of 'all' CPU range

Zhang Qiang (1):
      kvfree_rcu: Release a page cache under memory pressure

Zhouyi Zhou (1):
      rcu: Improve tree.c comments and add code cleanups

 .../Memory-Ordering/Tree-RCU-Memory-Ordering.rst   |   6 +-
 Documentation/admin-guide/kernel-parameters.rst    |   5 +
 Documentation/admin-guide/kernel-parameters.txt    |   5 +
 Documentation/dev-tools/kcsan.rst                  |  93 +++---
 include/linux/rcupdate.h                           |  84 +++---
 include/linux/rcutiny.h                            |   1 -
 include/linux/rcutree.h                            |   1 -
 include/linux/srcu.h                               |   6 +
 include/linux/srcutree.h                           |   2 -
 include/linux/timer.h                              |   2 -
 include/trace/events/rcu.h                         |   1 +
 init/main.c                                        |   2 +
 kernel/kcsan/core.c                                |  53 ++--
 kernel/kcsan/debugfs.c                             |   3 +-
 kernel/kcsan/kcsan.h                               |  39 ++-
 kernel/kcsan/report.c                              | 169 +++++------
 kernel/locking/lockdep.c                           |   6 +-
 kernel/rcu/Kconfig.debug                           |   2 +-
 kernel/rcu/rcu.h                                   |  14 +-
 kernel/rcu/rcutorture.c                            | 315 +++++++++++------=
----
 kernel/rcu/refscale.c                              | 109 ++++++-
 kernel/rcu/srcutree.c                              |  28 +-
 kernel/rcu/sync.c                                  |   4 +-
 kernel/rcu/tasks.h                                 |  58 +++-
 kernel/rcu/tiny.c                                  |   1 -
 kernel/rcu/tree.c                                  | 313 +++++++++++------=
---
 kernel/rcu/tree.h                                  |  14 +-
 kernel/rcu/tree_plugin.h                           | 239 ++++++++--------
 kernel/rcu/tree_stall.h                            |  84 +++++-
 kernel/rcu/update.c                                |   8 +-
 kernel/time/timer.c                                |  14 -
 lib/bitmap.c                                       |   9 +
 lib/test_bitmap.c                                  |   7 +
 mm/oom_kill.c                                      |   2 +-
 mm/slab.h                                          |   1 +
 mm/slab_common.c                                   |  12 +-
 mm/slub.c                                          |   8 +
 mm/util.c                                          |   2 +-
 tools/memory-model/Documentation/explanation.txt   |   2 +-
 tools/rcu/rcu-cbs.py                               |  46 +++
 .../testing/selftests/rcutorture/bin/kvm-again.sh  |  33 +--
 .../testing/selftests/rcutorture/bin/kvm-build.sh  |   6 +-
 .../selftests/rcutorture/bin/kvm-end-run-stats.sh  |  40 +++
 .../selftests/rcutorture/bin/kvm-find-errors.sh    |   2 +-
 .../selftests/rcutorture/bin/kvm-recheck-rcu.sh    |   2 +-
 .../testing/selftests/rcutorture/bin/kvm-remote.sh | 249 ++++++++++++++++
 tools/testing/selftests/rcutorture/bin/kvm.sh      |  61 ++--
 tools/testing/selftests/rcutorture/bin/torture.sh  |   2 +-
 .../selftests/rcutorture/configs/rcu/BUSTED-BOOST  |  17 ++
 .../rcutorture/configs/rcu/BUSTED-BOOST.boot       |   8 +
 .../selftests/rcutorture/configs/rcuscale/TREE     |   2 +-
 .../selftests/rcutorture/configs/rcuscale/TREE54   |   2 +-
 .../rcutorture/configs/refscale/NOPREEMPT          |   2 +-
 .../selftests/rcutorture/configs/refscale/PREEMPT  |   2 +-
 .../rcutorture/formal/srcu-cbmc/src/locks.h        |   2 +-
 55 files changed, 1434 insertions(+), 766 deletions(-)
 create mode 100644 tools/rcu/rcu-cbs.py
 create mode 100755 tools/testing/selftests/rcutorture/bin/kvm-end-run-stat=
s.sh
 create mode 100755 tools/testing/selftests/rcutorture/bin/kvm-remote.sh
 create mode 100644 tools/testing/selftests/rcutorture/configs/rcu/BUSTED-B=
OOST
 create mode 100644 tools/testing/selftests/rcutorture/configs/rcu/BUSTED-B=
OOST.boot

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210609232926.GA1715440%40paulmck-ThinkPad-P17-Gen-1.
