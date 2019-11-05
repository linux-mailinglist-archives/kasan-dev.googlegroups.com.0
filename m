Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGF5QXXAKGQEHASEUMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 572D7EFC79
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 12:35:54 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id a3sf12674229pls.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 03:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572953752; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRO/+W5ESHXeaK/XldPjlQd8kBFg7mXfC/XjHFtHILqrhsCf/QX6TjuCPyGC1hRZWe
         t0cLFSeOmVuB0sImzV2BMTS+VJ6nF60YPnlrzwJSnhew8859TvFYnCsZcjOebG6N815t
         MEIO7g09Bo4qWvM4ngsWwyVvqqbNdRiXHWeD19AbknyZSPFOpoPpcw5CUQGn/CVd28H4
         HBC9XW30kBnDWVKqcYHPkKLLHR6u5S1beSjJlUIU7yHwqVZLrLEA6GkWL2JTmG5fcTFp
         lO1HOIwmlVUlitQXRLbilyRs4ycK9eCckdjBEaSWMD9QFpEUVXuXjqYzo6S9g7Ph0hsF
         Y1oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qcpngvQYkje6H+t8y5yjcbJERBIq4ZiMny6v9E/r1iE=;
        b=xK8cSE8eMVlmtppr8zTuPbZ88SjaPDDcMnDQShIj+oSmVSyoRS5eIzHHToa6Q9EaTh
         vCWLQUpygICi4y7GQyd+bHUJnz8NejkNz/C0K2g0z87szNS5oZCmfUB9OmNKsLOMezAt
         2zWiWo3feUbyZX9OyQEqJrxQgc+St+CvYQrVKRMow6RyXRjXegE9a3xSwLbQirzRpKh7
         ROH2VO2Hf3a+91qEjLFqKcVZY/JtH+NhnY1nKcVT8Dw3TLwiSLwOx4NYsORAiVz9QcNY
         FxslzLzrbiABlU+pS/Rlhd1b4Z4SF/+fPhIbHqMbNFGM2u2wrQBKmiccKF7n9fk8n2xK
         xIPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qcpngvQYkje6H+t8y5yjcbJERBIq4ZiMny6v9E/r1iE=;
        b=K137tS9z9LJ3uHrZrq+hAlzgQeP5QBGSejiTJInaqrjP5i7MAPhKU/XvmP07Rj8cle
         t6xuByfMBmhcES/ATJF1VUfkx8dIraEcxqbDOMyuhCcPV0VW5oC0xa/bdDMbpgshwlMb
         59+VawTsiNHioqDmxv/rTaLPJCRqGNqflKZezkz/POOTCsn9cQdc/1Kk9PI5GA/nqDix
         GwiCp07Qjm3PWI7OOvCTiLAAVPpS+MIJmY1ZNw9CMwEp3BvBwQeI++SA1wO2wuchjkN5
         xBBCXMEytyK3j+9zuuzSXg9/LyKrMxvN2PgKgTJLrtOnfwjUGkp/jd3ZMD6MLyZQfwp2
         Kxzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qcpngvQYkje6H+t8y5yjcbJERBIq4ZiMny6v9E/r1iE=;
        b=bfvzbxevJYgJf8pXzdZEIqnTg2rQ5wO/6wN0Si6dfgQLgMPYQi8jY0O3ptYDJSd77o
         kufIGOQxQG1s7XPZQI9KUeR+Fg0jvVBdbiBvwafuPGRzQyMcjhWJtmkWCOI8QvrCWWEh
         5d/Oylab5YvOVOpHCZYN1jh06hOIhaFqMxpD0hHyWy8gHE2xsjWzO1bvOTjgw9AM63Qs
         EmJMwvdNj/sDKnlZVnMb9WJzUY93whz/4jtyZzcZyQV6Najvk76TIoa16cXAF7lTZpSQ
         TqrOQIdWRx1tp45jSuox9/0toCNJ1fdqcrptst6r6PreZCn6o0ffi2dYm/3VKat8X+Uq
         VF5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWmhehvUv/FO4I9aRa9+N22I7TQ+1SZF/OtcTWsLuJOmt5OyNOz
	KdfxnBptt7pJbYJgp4cnUSs=
X-Google-Smtp-Source: APXvYqz5ybOzPzIYmJ5Lvch3JVTkJ1++EbsHgAf2HlcyBV7M4nqwoox/L8Q5DbjmzGvvKr5dTu510Q==
X-Received: by 2002:a17:90a:33ce:: with SMTP id n72mr6057712pjb.17.1572953752527;
        Tue, 05 Nov 2019 03:35:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:20a2:: with SMTP id f31ls793079pjg.0.gmail; Tue, 05
 Nov 2019 03:35:52 -0800 (PST)
X-Received: by 2002:a17:90a:c2:: with SMTP id v2mr5966131pjd.140.1572953752064;
        Tue, 05 Nov 2019 03:35:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572953752; cv=none;
        d=google.com; s=arc-20160816;
        b=TmTnxwaxLqHRyArP0O52KLLM88rGWkbWsG+rakvE9G1Svgs5VTbPXsGHWfrjvolLRI
         LVBTzOQ68nKSt9CZT948Idl/Mn+iaMS3Ti9lifAeFhwMy0yS9+tVpJSL7m3gBusy1LKo
         CTXfUULQnZQMLcFiJ+ID9ZfJm8ZidvgcRFcqvFmXkem5W+fUONM0HpHSKxvZ0whXx+HA
         8fO6oPB3iDZz246SEpSrfjwJn5IXduIw6JWHFf99QX18Mm5DmUixIyFcacJgBIgfkRzf
         uBpoFPxdRh6ugJUUN/E76/xXtZjIoxnqUPN/KytgaQBCmsZsrykjwzq9gmimsvDYzA4M
         pIvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ImCYw+8ieiTKgyxG/FS61mgV0NGEaPTACVVMz8muT9c=;
        b=GrOgxuqq9gCLqW4jTcVrBr29qe0IQu7efKN2mkf0yYN3jKKFl+g/WPq6q9ROnrYekO
         35vcmJoVmPH9T1qY8/34L2/F+ilu63apuBeZKl/shuFCqZU+8/hL+VqSHCJg2KzhgF/S
         8lrB5ww3O3TomX2SoBTPR1ETdR+Pyr31VHbkIjU1ZhgEmw8ABAH6AG/ndDavafvAwGt/
         JgZ9NzWXQVENKUN9e+HdTwszCQYCAZoQK8lD5a+MsvIHi2h3JR5JDZZPaeOsbC/82Vnt
         ku93wdQdBAeTTwUiYDoyBw10tO3P4Nq3iv3I30W+xO+0lt2WJXnVjgPKbnSxWusoFd2i
         p2fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id v18si75515pjn.1.2019.11.05.03.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Nov 2019 03:35:52 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga107.fm.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 05 Nov 2019 03:35:51 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.68,271,1569308400"; 
   d="scan'208";a="227068904"
Received: from lkp-server01.sh.intel.com (HELO lkp-server01) ([10.239.97.150])
  by fmsmga004.fm.intel.com with ESMTP; 05 Nov 2019 03:35:42 -0800
Received: from kbuild by lkp-server01 with local (Exim 4.89)
	(envelope-from <lkp@intel.com>)
	id 1iRx7b-000Fr1-O6; Tue, 05 Nov 2019 19:35:39 +0800
Date: Tue, 5 Nov 2019 19:35:15 +0800
From: kbuild test robot <lkp@intel.com>
To: Marco Elver <elver@google.com>
Cc: kbuild-all@lists.01.org, elver@google.com, akiyks@gmail.com,
	stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v3 5/9] seqlock, kcsan: Add annotations for KCSAN
Message-ID: <201911051950.7sv6Mqoe%lkp@intel.com>
References: <20191104142745.14722-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191104142745.14722-6-elver@google.com>
X-Patchwork-Hint: ignore
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

Hi Marco,

I love your patch! Perhaps something to improve:

[auto build test WARNING on linus/master]
[also build test WARNING on v5.4-rc6]
[cannot apply to next-20191031]
[if your patch is applied to the wrong git tree, please drop us a note to help
improve the system. BTW, we also suggest to use '--base' option to specify the
base tree in git format-patch, please see https://stackoverflow.com/a/37406982]

url:    https://github.com/0day-ci/linux/commits/Marco-Elver/Add-Kernel-Concurrency-Sanitizer-KCSAN/20191105-002542
base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git a99d8080aaf358d5d23581244e5da23b35e340b9
reproduce:
        # apt-get install sparse
        # sparse version: v0.6.1-6-g57f8611-dirty
        make ARCH=x86_64 allmodconfig
        make C=1 CF='-fdiagnostic-prefix -D__CHECK_ENDIAN__'

If you fix the issue, kindly add following tag
Reported-by: kbuild test robot <lkp@intel.com>


sparse warnings: (new ones prefixed by >>)

>> include/linux/rcupdate.h:651:9: sparse: sparse: context imbalance in 'thread_group_cputime' - different lock contexts for basic block

vim +/thread_group_cputime +651 include/linux/rcupdate.h

^1da177e4c3f41 Linus Torvalds      2005-04-16  603  
^1da177e4c3f41 Linus Torvalds      2005-04-16  604  /*
^1da177e4c3f41 Linus Torvalds      2005-04-16  605   * So where is rcu_write_lock()?  It does not exist, as there is no
^1da177e4c3f41 Linus Torvalds      2005-04-16  606   * way for writers to lock out RCU readers.  This is a feature, not
^1da177e4c3f41 Linus Torvalds      2005-04-16  607   * a bug -- this property is what provides RCU's performance benefits.
^1da177e4c3f41 Linus Torvalds      2005-04-16  608   * Of course, writers must coordinate with each other.  The normal
^1da177e4c3f41 Linus Torvalds      2005-04-16  609   * spinlock primitives work well for this, but any other technique may be
^1da177e4c3f41 Linus Torvalds      2005-04-16  610   * used as well.  RCU does not care how the writers keep out of each
^1da177e4c3f41 Linus Torvalds      2005-04-16  611   * others' way, as long as they do so.
^1da177e4c3f41 Linus Torvalds      2005-04-16  612   */
3d76c082907e8f Paul E. McKenney    2009-09-28  613  
3d76c082907e8f Paul E. McKenney    2009-09-28  614  /**
ca5ecddfa8fcbd Paul E. McKenney    2010-04-28  615   * rcu_read_unlock() - marks the end of an RCU read-side critical section.
3d76c082907e8f Paul E. McKenney    2009-09-28  616   *
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  617   * In most situations, rcu_read_unlock() is immune from deadlock.
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  618   * However, in kernels built with CONFIG_RCU_BOOST, rcu_read_unlock()
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  619   * is responsible for deboosting, which it does via rt_mutex_unlock().
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  620   * Unfortunately, this function acquires the scheduler's runqueue and
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  621   * priority-inheritance spinlocks.  This means that deadlock could result
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  622   * if the caller of rcu_read_unlock() already holds one of these locks or
ec84b27f9b3b56 Anna-Maria Gleixner 2018-05-25  623   * any lock that is ever acquired while holding them.
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  624   *
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  625   * That said, RCU readers are never priority boosted unless they were
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  626   * preempted.  Therefore, one way to avoid deadlock is to make sure
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  627   * that preemption never happens within any RCU read-side critical
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  628   * section whose outermost rcu_read_unlock() is called with one of
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  629   * rt_mutex_unlock()'s locks held.  Such preemption can be avoided in
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  630   * a number of ways, for example, by invoking preempt_disable() before
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  631   * critical section's outermost rcu_read_lock().
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  632   *
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  633   * Given that the set of locks acquired by rt_mutex_unlock() might change
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  634   * at any time, a somewhat more future-proofed approach is to make sure
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  635   * that that preemption never happens within any RCU read-side critical
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  636   * section whose outermost rcu_read_unlock() is called with irqs disabled.
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  637   * This approach relies on the fact that rt_mutex_unlock() currently only
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  638   * acquires irq-disabled locks.
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  639   *
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  640   * The second of these two approaches is best in most situations,
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  641   * however, the first approach can also be useful, at least to those
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  642   * developers willing to keep abreast of the set of locks acquired by
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  643   * rt_mutex_unlock().
f27bc4873fa8b7 Paul E. McKenney    2014-05-04  644   *
3d76c082907e8f Paul E. McKenney    2009-09-28  645   * See rcu_read_lock() for more information.
3d76c082907e8f Paul E. McKenney    2009-09-28  646   */
bc33f24bdca8b6 Paul E. McKenney    2009-08-22  647  static inline void rcu_read_unlock(void)
bc33f24bdca8b6 Paul E. McKenney    2009-08-22  648  {
f78f5b90c4ffa5 Paul E. McKenney    2015-06-18  649  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
bde23c6892878e Heiko Carstens      2012-02-01  650  			 "rcu_read_unlock() used illegally while idle");
bc33f24bdca8b6 Paul E. McKenney    2009-08-22 @651  	__release(RCU);
bc33f24bdca8b6 Paul E. McKenney    2009-08-22  652  	__rcu_read_unlock();
d24209bb689e2c Paul E. McKenney    2015-01-21  653  	rcu_lock_release(&rcu_lock_map); /* Keep acq info for rls diags. */
bc33f24bdca8b6 Paul E. McKenney    2009-08-22  654  }
^1da177e4c3f41 Linus Torvalds      2005-04-16  655  

:::::: The code at line 651 was first introduced by commit
:::::: bc33f24bdca8b6e97376e3a182ab69e6cdefa989 rcu: Consolidate sparse and lockdep declarations in include/linux/rcupdate.h

:::::: TO: Paul E. McKenney <paulmck@linux.vnet.ibm.com>
:::::: CC: Ingo Molnar <mingo@elte.hu>

---
0-DAY kernel test infrastructure                Open Source Technology Center
https://lists.01.org/pipermail/kbuild-all                   Intel Corporation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911051950.7sv6Mqoe%25lkp%40intel.com.
