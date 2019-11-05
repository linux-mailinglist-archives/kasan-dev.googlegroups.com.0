Return-Path: <kasan-dev+bncBAABBN4KQ3XAKGQE7RAS5LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id C4631EFF8C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 15:20:40 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id m189sf21351874qkc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 06:20:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572963639; cv=pass;
        d=google.com; s=arc-20160816;
        b=P4noCGitlC1FxHlbmUKYbIRPdjmvNOeLjjmgsvZF2aAKY0J0G94ESEoQRLeEbri6B3
         DUHk0ors7TGl04sYawslHmMJbcyXJqk+PIb2A9Kw+aJLebtTNfqK0sx/yK92o5exxjbM
         vuYPV19L55o+dh5t7JLHNrFKF5kbviLhmSIk63LSv7y1JTuoxoH87p7kFioZhaeBYIjM
         qr+fqMZJuY+T+WbI7bNsaOsiLReNjgfHShGwb7DTIBxfhW1+y/n3+dxyN+UdSBnbiapk
         Iid1/WfgXOaiXkArqct9olX9P4QSwIYzCIFzOGM/hY7jmF2SQi21ChOPR/Dj785M4sFK
         H7Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=sAWKOMQQWl+N0rHNyAUmBrapzy0NazOvQMnPwX/KB+U=;
        b=D9kXWmlgMdsm14LJpzvRM4+EMMQr971J9Z45XG2mQxTamN1STZPHsjUoPVolVpY5ci
         oGPrfZSuTpAX3brzrolAIlEc+e4OiFvA4ALDmaGT2xXaofqMH55qyl9d/KGDcV2/4oL4
         f10305VGYCFXWJLvuv8a924XTybO9x66SecILRMCBjV1yaxsulTwUBwhYTR8tc53IM+U
         PSv8Lh7aYtI61LfHBkz2QlVquQOI4ztJWaVl1KtzIz7hWBr/UM2O9d26LNuLZby9lcfN
         rTbocVpWS27SzqETiLpX4BVdh2MZ5Wla4ewm9kfQbKTSpQggLUtnXn6c791Oodc486R9
         qGyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LVMEw0wD;
       spf=pass (google.com: domain of srs0=4xi/=y5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4xI/=Y5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sAWKOMQQWl+N0rHNyAUmBrapzy0NazOvQMnPwX/KB+U=;
        b=UhW6w796ob6ZhTkcmfjWIkBEC4vzZSutXw0i342076Cuw4V6s4ZXB2ok/pAwRqMF73
         omzDFZWx0bs8dUSpncOKlSCdSkE7+F9fVAhOv0eitQt+PYtCqWS+fWaHWjMAY/OYwSqR
         INLfYEtLUTaZXxj3WtB0rskK+km+eDEaXkvX4Aqc+w5QD2Bv73aqy+RYkdOq6bKfONPY
         4HyAmg5I56ugD9NZVNnSVeUpyuGlMWN0Eb5JeSD4E96b2Do1/WhEQSqpoJMpXsgoGz9F
         oGKni8DJJiyEcNX191V5mMEzdxlhWaTPGLcouSVpPR9BQ7EPr+xhftaR+dcsWaRjWFwT
         zVkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sAWKOMQQWl+N0rHNyAUmBrapzy0NazOvQMnPwX/KB+U=;
        b=FJen6b0ct8NHSxYcqfkvlvCGFcbnUWd6WF9My0lWuaQK6LKjhCHC70J5LorQkYBNl4
         zJg5Pypp6QabsKqLlf4bdv9plmNEVh5wojUAGOOPoKvGoEyLLvbvFrUSxWObEluCidL0
         X7kGlxF7JQVNP1jfMNGm8xcJbKHRnSbRt0wfX3K1c+pl3nXPchG0/sd1+BmVgnaDA/8a
         CMrYzZQ1PWxzdxzEsRCx+zZeeL7w6YDHLcF/1+5DL97sjcEPZUhI15Br2IyiNEfxgpfJ
         fHr8YgmtDUcpvh4/AVXu1h+vJhBRhqaN9lvdsj9GdJ6Kz+OsH9GefiD6m/AsBFReDH+U
         8O0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXpQeieMjhTTigETb5x6NqVz6ScWWVX9+SIHiN4ykPV+xGyWOsK
	jw+pTkur2Rn66ZAoDEOKu0k=
X-Google-Smtp-Source: APXvYqxRtmyTpvcvX6F0rgKiXnc+it/FrCBwU2iuTCnXXyDK251b584XetWltKC18hUAKbbFyGhxVg==
X-Received: by 2002:a05:6214:12ac:: with SMTP id w12mr16327737qvu.44.1572963639424;
        Tue, 05 Nov 2019 06:20:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2f7a:: with SMTP id k55ls5348558qta.8.gmail; Tue, 05 Nov
 2019 06:20:39 -0800 (PST)
X-Received: by 2002:ac8:3968:: with SMTP id t37mr16321319qtb.37.1572963639117;
        Tue, 05 Nov 2019 06:20:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572963639; cv=none;
        d=google.com; s=arc-20160816;
        b=fgMoDLMbDRTb3OVXrWb3bOnrGRdKu25f+QdN/WC5dfBzy8BpmiuOEeyUMg7kl0Q1hh
         8sjyanr5NctsoVmDhzhqN6BCJSfNfhPhYS3qQzoSUY+y876Zdy1scEfs/q3EAfLdldNV
         eho6B1vNyZQgs6Xkc54Wb8r01AoizCsdR/hepHvuxEge5SGYKfMUxrLHC6vK5I9cKl3f
         VuYl5mTiZDS7IRwrqq36PAet/j6kK9c/jp0MazU/ziTkPrJxtzcHAP+dWyN1/4drOEN6
         db9DL3/5g2zcbBvdSQ5htjAigB57Zamjv4Tydghk5ZXQC6a23uChn7WfWECLjEDwVSB0
         0SxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=s4h3DhGeqCZ2J0vWvSQCVApuqbxcyxkZ4MjAI3DXYLU=;
        b=imOqKHNpmlTtGy7riA1kqCSY8i69jRrpLSTyesp66aTnAW/t4lt+si3AFS+og9CRTQ
         f1i6IL2tu9p01g399TpOJf3AknQTCuyM+CyybNgbqwWMobkpsJ+uR668T7wBXdTXH5ol
         43Su5C4LTLI694rY/henQx+/o043518cyd+L4bC+xkgTqWjJSBkrx6vI688cjVauxTm+
         DGUqqIM2YcRnKMb+SEbZhd83qrms9graN9tY/N3twCpXjoDYGv6Upn+m5mBgjwtnQ2Tb
         J0JcYS0AoR1sYmHfXFA95WzBXLUyCffIleRHX59SFlGeWrOCv0j0HYzxJvVFYEOBX9GV
         Kk8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LVMEw0wD;
       spf=pass (google.com: domain of srs0=4xi/=y5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4xI/=Y5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d189si1046745qkb.1.2019.11.05.06.20.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Nov 2019 06:20:39 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4xi/=y5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [109.144.209.237])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 92A83214D8;
	Tue,  5 Nov 2019 14:20:37 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A450B35227C0; Tue,  5 Nov 2019 06:20:35 -0800 (PST)
Date: Tue, 5 Nov 2019 06:20:35 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
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
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191105142035.GR20975@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191104142745.14722-1-elver@google.com>
 <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
 <20191104194658.GK20975@paulmck-ThinkPad-P72>
 <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=LVMEw0wD;       spf=pass
 (google.com: domain of srs0=4xi/=y5=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4xI/=Y5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Nov 05, 2019 at 12:10:56PM +0100, Marco Elver wrote:
> On Mon, 4 Nov 2019 at 20:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, Nov 04, 2019 at 07:41:30PM +0100, Marco Elver wrote:
> > > On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > KCSAN is a sampling watchpoint-based data-race detector. More details
> > > > > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > architectures is relatively straightforward (we are aware of
> > > > > experimental ARM64 and POWER support).
> > > > >
> > > > > To gather early feedback, we announced KCSAN back in September, and
> > > > > have integrated the feedback where possible:
> > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > >
> > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > including several articles that motivate why data-races are dangerous
> > > > > [1, 2], justifying a data-race detector such as KCSAN.
> > > > > [1] https://lwn.net/Articles/793253/
> > > > > [2] https://lwn.net/Articles/799218/
> > > > >
> > > > > The current list of known upstream fixes for data-races found by KCSAN
> > > > > can be found here:
> > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > >
> > > > Making this more accessible to more people seems like a good thing.
> > > > So, for the series:
> > > >
> > > > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> > >
> > > Much appreciated. Thanks, Paul!
> > >
> > > Any suggestions which tree this could eventually land in?
> >
> > I would guess that Dmitry might have some suggestions.
> 
> I checked and we're both unclear what the most obvious tree to land in
> is (the other sanitizers are mm related, which KCSAN is not).
> 
> One suggestion that comes to my mind is for KCSAN to go through the
> same tree (rcu?) as the LKMM due to their inherent relationship. Would
> that make most sense?

It works for me, though you guys have to continue to be the main
developers.  ;-)

I will go through the patches more carefully, and please look into the
kbuild test robot complaint.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> > >
> > > > > Changelog
> > > > > ---------
> > > > > v3:
> > > > > * Major changes:
> > > > >  - Add microbenchmark.
> > > > >  - Add instruction watchpoint skip randomization.
> > > > >  - Refactor API and core runtime fast-path and slow-path. Compared to
> > > > >    the previous version, with a default config and benchmarked using the
> > > > >    added microbenchmark, this version is 3.8x faster.
> > > > >  - Make __tsan_unaligned __alias of generic accesses.
> > > > >  - Rename kcsan_{begin,end}_atomic ->
> > > > >    kcsan_{nestable,flat}_atomic_{begin,end}
> > > > >  - For filter list in debugfs.c use kmalloc+krealloc instead of
> > > > >    kvmalloc.
> > > > >  - Split Documentation into separate patch.
> > > > >
> > > > > v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> > > > > * Major changes:
> > > > >  - Replace kcsan_check_access(.., {true, false}) with
> > > > >    kcsan_check_{read,write}.
> > > > >  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
> > > > >  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> > > > >    contexts.
> > > > >
> > > > > v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> > > > >
> > > > > Marco Elver (9):
> > > > >   kcsan: Add Kernel Concurrency Sanitizer infrastructure
> > > > >   kcsan: Add Documentation entry in dev-tools
> > > > >   objtool, kcsan: Add KCSAN runtime functions to whitelist
> > > > >   build, kcsan: Add KCSAN build exceptions
> > > > >   seqlock, kcsan: Add annotations for KCSAN
> > > > >   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
> > > > >   asm-generic, kcsan: Add KCSAN instrumentation for bitops
> > > > >   locking/atomics, kcsan: Add KCSAN instrumentation
> > > > >   x86, kcsan: Enable KCSAN for x86
> > > > >
> > > > >  Documentation/dev-tools/index.rst         |   1 +
> > > > >  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
> > > > >  MAINTAINERS                               |  11 +
> > > > >  Makefile                                  |   3 +-
> > > > >  arch/x86/Kconfig                          |   1 +
> > > > >  arch/x86/boot/Makefile                    |   2 +
> > > > >  arch/x86/boot/compressed/Makefile         |   2 +
> > > > >  arch/x86/entry/vdso/Makefile              |   3 +
> > > > >  arch/x86/include/asm/bitops.h             |   6 +-
> > > > >  arch/x86/kernel/Makefile                  |   7 +
> > > > >  arch/x86/kernel/cpu/Makefile              |   3 +
> > > > >  arch/x86/lib/Makefile                     |   4 +
> > > > >  arch/x86/mm/Makefile                      |   3 +
> > > > >  arch/x86/purgatory/Makefile               |   2 +
> > > > >  arch/x86/realmode/Makefile                |   3 +
> > > > >  arch/x86/realmode/rm/Makefile             |   3 +
> > > > >  drivers/firmware/efi/libstub/Makefile     |   2 +
> > > > >  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
> > > > >  include/asm-generic/bitops-instrumented.h |  18 +
> > > > >  include/linux/compiler-clang.h            |   9 +
> > > > >  include/linux/compiler-gcc.h              |   7 +
> > > > >  include/linux/compiler.h                  |  35 +-
> > > > >  include/linux/kcsan-checks.h              |  97 ++++
> > > > >  include/linux/kcsan.h                     | 115 +++++
> > > > >  include/linux/sched.h                     |   4 +
> > > > >  include/linux/seqlock.h                   |  51 +-
> > > > >  init/init_task.c                          |   8 +
> > > > >  init/main.c                               |   2 +
> > > > >  kernel/Makefile                           |   6 +
> > > > >  kernel/kcsan/Makefile                     |  11 +
> > > > >  kernel/kcsan/atomic.h                     |  27 ++
> > > > >  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
> > > > >  kernel/kcsan/debugfs.c                    | 275 +++++++++++
> > > > >  kernel/kcsan/encoding.h                   |  94 ++++
> > > > >  kernel/kcsan/kcsan.h                      | 131 +++++
> > > > >  kernel/kcsan/report.c                     | 306 ++++++++++++
> > > > >  kernel/kcsan/test.c                       | 121 +++++
> > > > >  kernel/sched/Makefile                     |   6 +
> > > > >  lib/Kconfig.debug                         |   2 +
> > > > >  lib/Kconfig.kcsan                         | 119 +++++
> > > > >  lib/Makefile                              |   3 +
> > > > >  mm/Makefile                               |   8 +
> > > > >  scripts/Makefile.kcsan                    |   6 +
> > > > >  scripts/Makefile.lib                      |  10 +
> > > > >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> > > > >  tools/objtool/check.c                     |  18 +
> > > > >  46 files changed, 2526 insertions(+), 206 deletions(-)
> > > > >  create mode 100644 Documentation/dev-tools/kcsan.rst
> > > > >  create mode 100644 include/linux/kcsan-checks.h
> > > > >  create mode 100644 include/linux/kcsan.h
> > > > >  create mode 100644 kernel/kcsan/Makefile
> > > > >  create mode 100644 kernel/kcsan/atomic.h
> > > > >  create mode 100644 kernel/kcsan/core.c
> > > > >  create mode 100644 kernel/kcsan/debugfs.c
> > > > >  create mode 100644 kernel/kcsan/encoding.h
> > > > >  create mode 100644 kernel/kcsan/kcsan.h
> > > > >  create mode 100644 kernel/kcsan/report.c
> > > > >  create mode 100644 kernel/kcsan/test.c
> > > > >  create mode 100644 lib/Kconfig.kcsan
> > > > >  create mode 100644 scripts/Makefile.kcsan
> > > > >
> > > > > --
> > > > > 2.24.0.rc1.363.gb1bccd3e3d-goog
> > > > >
> > > >
> > > > --
> > > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104194658.GK20975%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191105142035.GR20975%40paulmck-ThinkPad-P72.
