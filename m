Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFHQ3XAKGQEN763OYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D6C3BF012D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 16:22:37 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id 125sf15780600iou.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 07:22:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572967356; cv=pass;
        d=google.com; s=arc-20160816;
        b=a4cX1PmYc5PiS9fShj2ng9tCkSDfwauSXMWNUwKU8XXxb0u6RNu8i9GycmrKBauFjn
         zVwEEI854Kzt1TBjehKduH5wqvz+5saRRBHnrW4iMEypMwWprzziAIJRpJgfLmKQr1KR
         kbFhFGMO5JiD8wp1bXYFOFITwGvUNO7PLA0FQjqiMBA4zZIHIz0Pnfz1DjMOX9uYe7U1
         0Zyc5YqR3J1fd4cI02cEhx1fKrgSboOAZa0ZSRrfPIGGEo+s3RwC28Cm9LoUi4xU8XtO
         P4msNl/am2//0gZf2mI4aZddYjxFtvOfe0u2IIiAUn0oydWXbG1AkeHjmq5SNuiKOzu0
         r4cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vn8xPAol8uNiIRJDRN1rD4sszlEODY10+Eo9Mft+zPo=;
        b=Woi4Rwm0zkCY+EdxrL6oc/fYoqCaPHRULstwp8kF2rWXVXHL10TUrT8ETLNXi5yTiH
         r7nBeSgBRE0g+0eJ7OCx5Qg5UMPDaNS4Tvzb2OeFt2/c3gv23oLQWE0ytKNwY1PjBxel
         AeI11rJ20ZtfDmK0Az0dSnNFpS/EDhB+LuXLpo/YCFffKZToSjZO5Z14oZav2ncgkzhE
         kf3x/xQLNoR650T4IXDMnMsyS2akC+XX1j8J7hUUCz5rAz+4JOgGByHWbOevGqEU5feN
         xm8AozWaHzYxEjrDWQ3rL8NLpn3RmZOCCkLymeXoU+S1dIQQPOtuocppSDciR9o1dgkF
         2Evg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=maXxEj94;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vn8xPAol8uNiIRJDRN1rD4sszlEODY10+Eo9Mft+zPo=;
        b=LMohBP4CHz04LohHg4c2kiZS5m69aODjCV3LL0aFUuz7UTyAIKsy2oD5w0fk9kuYZG
         NP7pTTA+nlO3YnYW2hWPaBvP2gOKegOTQ8XABCUfrAWKAJOiwurHCyi2brZrvRnAZ/Dg
         1DMpxSHUFpYlNPX3vky7EMJVODaA6WcL93vyCrs9vdf47wawcnb5YkqsEhlwbY+vweoT
         py7v/cVAGC3JPFEs5qsDOGPMpPP0jCynAyqTCK/tOACPa3000rIqH/UsZFououuWCsI0
         orGYVfQuP8iDIcN53fWOHwuPSAA2psbCkYRixuBC3Ox7flbdZyg17L6kTwjTFBSjqExG
         y6hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vn8xPAol8uNiIRJDRN1rD4sszlEODY10+Eo9Mft+zPo=;
        b=B+prTZTK8iFpKay6wROM3lgph8nTmap0pNiiG990b+IPKGUXmmKKZeEeWjeUbQBeLm
         UlKi1iT5qQipFEPZR1JrgEGBdmb40P2gw1QcR3PDln9++ZXR1wN1OabLs1R+pRj5ZzE7
         /x/lLzgWJjr67yOHKMvOcIm71uOGuZaSGe9Gr3Dz2HXp8Mu4PbHXD6ploBBFO04fZthj
         /pO1CLvenj0AisoaZVS+GFp0PIVQV4/eAo2HMSFf5TlwEfqfb4rCE5cyzbudrUvJh+bF
         LFTRCLt5rWjti2sRxNijIAxQxfIg618+TriBeizivIXqQnGLXf6VrtvGb8ufvopQKp1g
         aewQ==
X-Gm-Message-State: APjAAAXdPjkwUzWZggZ3cNe0p8Wi9axDoE6kNmzcvscU7YcO+iF8MLFc
	wJ40pP/pW5H7BDnNa8MmXWE=
X-Google-Smtp-Source: APXvYqxAPvUQAOdzLVGaqhDlxNSZNqdSgcTL1+3mW2w88xdEqigtur2XnIn7voSYqw/9840HqZ/iSQ==
X-Received: by 2002:a92:a308:: with SMTP id a8mr36186078ili.105.1572967356445;
        Tue, 05 Nov 2019 07:22:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7309:: with SMTP id o9ls3774915ilc.14.gmail; Tue, 05 Nov
 2019 07:22:35 -0800 (PST)
X-Received: by 2002:a92:8c1c:: with SMTP id o28mr33325670ild.34.1572967355917;
        Tue, 05 Nov 2019 07:22:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572967355; cv=none;
        d=google.com; s=arc-20160816;
        b=XVLflpC3iU54EGfziNMmCFON+xVjwQIa6z5i2OpQBjRLHqlkORTB0r+dMJt0sN6xA9
         RmHdg/fENoMOuTQzbkWOztPuYUHnfBa9vBoQPLXXgRYCv5niBAhlNK6fnmXtIqoNZAdy
         p5knu9ijsHQq+iTjJ4u39F+hsJHMXKQkLm1kGgbopjMMJdn+LgI7SKBhrECGfQaNnYea
         8OlSQaL4k8eg+52h8czos+zP4M/nuC6ta9zPdNy8nyY0ZPgRk+pmD4cl6sBBve+/B8m5
         g429QskvnVwtXXG+BT+YhdMf3i9IXYxdRi+cJfKZOaZ9R9Oz7KqnZ+7Q1CtiQIxJmsd2
         +JUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6n5lN3Fg3bcrd2szeJ48Ty9IGAr+TLatcqKpJTnbQ3g=;
        b=K6jqXyAiZzIFIWK3t5JCATrTP2j/FE2/HIzorEG/rhXt+LXLciZ8lX/XomTodknOIm
         LU97N6J/IdF+ioMH6ONEoP+sqmyx0uBPSPgYiEft5+501L03MHi1kF1KuBznP3pEqgOe
         HbIIWpJS0EzCKJXzmT/xXkqmgmPlpYRxBOfyVCYm+kFd3w1N7iIVKl09QzMzpxnFAm9S
         ag2YTM+GfCLCght+/27wv0sLrfbrkV9FvXqZdz4J2wEHdXii614PO6R//FHptMvpPimi
         hWMxXsTbSbx7evChwtCRiHcqr5t4COzbbxpvQzJ2rhvQmIuPIlfzcVsk+g3FAO03n5Dy
         UNcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=maXxEj94;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id y205si909971iof.2.2019.11.05.07.22.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2019 07:22:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id v24so12644308otp.5
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2019 07:22:35 -0800 (PST)
X-Received: by 2002:a05:6830:2308:: with SMTP id u8mr2369861ote.2.1572967354873;
 Tue, 05 Nov 2019 07:22:34 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-6-elver@google.com> <201911051950.7sv6Mqoe%lkp@intel.com>
In-Reply-To: <201911051950.7sv6Mqoe%lkp@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2019 16:22:23 +0100
Message-ID: <CANpmjNM2d03K9yZP4OzuEoWZQz_FcDfLHJ1VhqiPA6+2F0qjPA@mail.gmail.com>
Subject: Re: [PATCH v3 5/9] seqlock, kcsan: Add annotations for KCSAN
To: kbuild test robot <lkp@intel.com>
Cc: kbuild-all@lists.01.org, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=maXxEj94;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Tue, 5 Nov 2019 at 12:35, kbuild test robot <lkp@intel.com> wrote:
>
> Hi Marco,
>
> I love your patch! Perhaps something to improve:
>
> [auto build test WARNING on linus/master]
> [also build test WARNING on v5.4-rc6]
> [cannot apply to next-20191031]
> [if your patch is applied to the wrong git tree, please drop us a note to help
> improve the system. BTW, we also suggest to use '--base' option to specify the
> base tree in git format-patch, please see https://stackoverflow.com/a/37406982]
>
> url:    https://github.com/0day-ci/linux/commits/Marco-Elver/Add-Kernel-Concurrency-Sanitizer-KCSAN/20191105-002542
> base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git a99d8080aaf358d5d23581244e5da23b35e340b9
> reproduce:
>         # apt-get install sparse
>         # sparse version: v0.6.1-6-g57f8611-dirty
>         make ARCH=x86_64 allmodconfig
>         make C=1 CF='-fdiagnostic-prefix -D__CHECK_ENDIAN__'
>
> If you fix the issue, kindly add following tag
> Reported-by: kbuild test robot <lkp@intel.com>
>
>
> sparse warnings: (new ones prefixed by >>)
>
> >> include/linux/rcupdate.h:651:9: sparse: sparse: context imbalance in 'thread_group_cputime' - different lock contexts for basic block

This is a problem with sparse.

Without the patch series this warning is also generated, but sparse
seems to attribute it to the right file:
    kernel/sched/cputime.c:316:17: sparse: warning: context imbalance
in 'thread_group_cputime' - different lock contexts for basic block

Without the patch series, I observe that sparse also generates 5
warnings that it attributes to include/linux/rcupdate.h ("different
lock contexts for basic block") but the actual function is in a
different file.

In the function thread_group_cputime in kernel/sched/cputime.c, what
seems to happen is that a seq-reader critical section is contained
within an RCU reader critical section (sparse seems unhappy with this
pattern to begin with). The KCSAN patches add annotations to seqlock.h
which seems to somehow affect sparse to attribute the problem in
thread_group_cputime to rcupdate.h. Note that, the config does not
even enable KCSAN and all the annotations are no-ops (empty inline
functions).

So I do not think that I can change this patch to make sparse happy
here, since this problem already existed, only sparse somehow decided
to attribute the problem to rcupdate.h instead of cputime.c due to
subtle changes in the code.

Thanks,
-- Marco

> vim +/thread_group_cputime +651 include/linux/rcupdate.h
>
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  603
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  604  /*
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  605   * So where is rcu_write_lock()?  It does not exist, as there is no
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  606   * way for writers to lock out RCU readers.  This is a feature, not
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  607   * a bug -- this property is what provides RCU's performance benefits.
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  608   * Of course, writers must coordinate with each other.  The normal
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  609   * spinlock primitives work well for this, but any other technique may be
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  610   * used as well.  RCU does not care how the writers keep out of each
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  611   * others' way, as long as they do so.
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  612   */
> 3d76c082907e8f Paul E. McKenney    2009-09-28  613
> 3d76c082907e8f Paul E. McKenney    2009-09-28  614  /**
> ca5ecddfa8fcbd Paul E. McKenney    2010-04-28  615   * rcu_read_unlock() - marks the end of an RCU read-side critical section.
> 3d76c082907e8f Paul E. McKenney    2009-09-28  616   *
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  617   * In most situations, rcu_read_unlock() is immune from deadlock.
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  618   * However, in kernels built with CONFIG_RCU_BOOST, rcu_read_unlock()
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  619   * is responsible for deboosting, which it does via rt_mutex_unlock().
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  620   * Unfortunately, this function acquires the scheduler's runqueue and
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  621   * priority-inheritance spinlocks.  This means that deadlock could result
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  622   * if the caller of rcu_read_unlock() already holds one of these locks or
> ec84b27f9b3b56 Anna-Maria Gleixner 2018-05-25  623   * any lock that is ever acquired while holding them.
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  624   *
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  625   * That said, RCU readers are never priority boosted unless they were
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  626   * preempted.  Therefore, one way to avoid deadlock is to make sure
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  627   * that preemption never happens within any RCU read-side critical
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  628   * section whose outermost rcu_read_unlock() is called with one of
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  629   * rt_mutex_unlock()'s locks held.  Such preemption can be avoided in
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  630   * a number of ways, for example, by invoking preempt_disable() before
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  631   * critical section's outermost rcu_read_lock().
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  632   *
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  633   * Given that the set of locks acquired by rt_mutex_unlock() might change
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  634   * at any time, a somewhat more future-proofed approach is to make sure
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  635   * that that preemption never happens within any RCU read-side critical
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  636   * section whose outermost rcu_read_unlock() is called with irqs disabled.
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  637   * This approach relies on the fact that rt_mutex_unlock() currently only
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  638   * acquires irq-disabled locks.
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  639   *
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  640   * The second of these two approaches is best in most situations,
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  641   * however, the first approach can also be useful, at least to those
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  642   * developers willing to keep abreast of the set of locks acquired by
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  643   * rt_mutex_unlock().
> f27bc4873fa8b7 Paul E. McKenney    2014-05-04  644   *
> 3d76c082907e8f Paul E. McKenney    2009-09-28  645   * See rcu_read_lock() for more information.
> 3d76c082907e8f Paul E. McKenney    2009-09-28  646   */
> bc33f24bdca8b6 Paul E. McKenney    2009-08-22  647  static inline void rcu_read_unlock(void)
> bc33f24bdca8b6 Paul E. McKenney    2009-08-22  648  {
> f78f5b90c4ffa5 Paul E. McKenney    2015-06-18  649      RCU_LOCKDEP_WARN(!rcu_is_watching(),
> bde23c6892878e Heiko Carstens      2012-02-01  650                       "rcu_read_unlock() used illegally while idle");
> bc33f24bdca8b6 Paul E. McKenney    2009-08-22 @651      __release(RCU);
> bc33f24bdca8b6 Paul E. McKenney    2009-08-22  652      __rcu_read_unlock();
> d24209bb689e2c Paul E. McKenney    2015-01-21  653      rcu_lock_release(&rcu_lock_map); /* Keep acq info for rls diags. */
> bc33f24bdca8b6 Paul E. McKenney    2009-08-22  654  }
> ^1da177e4c3f41 Linus Torvalds      2005-04-16  655
>
> :::::: The code at line 651 was first introduced by commit
> :::::: bc33f24bdca8b6e97376e3a182ab69e6cdefa989 rcu: Consolidate sparse and lockdep declarations in include/linux/rcupdate.h
>
> :::::: TO: Paul E. McKenney <paulmck@linux.vnet.ibm.com>
> :::::: CC: Ingo Molnar <mingo@elte.hu>
>
> ---
> 0-DAY kernel test infrastructure                Open Source Technology Center
> https://lists.01.org/pipermail/kbuild-all                   Intel Corporation
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911051950.7sv6Mqoe%25lkp%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM2d03K9yZP4OzuEoWZQz_FcDfLHJ1VhqiPA6%2B2F0qjPA%40mail.gmail.com.
