Return-Path: <kasan-dev+bncBCJZRXGY5YJBBMEL7OCAMGQEVRVGISQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 269EA380FFC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 20:47:14 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id g14-20020a056a00078eb02902d7e2fb2c06sf117423pfu.13
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 11:47:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621018033; cv=pass;
        d=google.com; s=arc-20160816;
        b=y+DcdHXG8KS/A6jB26OTIhxcYrvhkeqVGV6t/amTBtLDb/zrvnLTSsapyanImWI/c+
         iEQj9+BRAznHrXx7v+d/yWRhlepHVRPvgdlcFjmRsWRUKid38BRrTHRblLAlB9asQjdI
         E0j3KaFIIoTVEN6sFxWBloQn/Fopl/Ztb113ocpBYM2MdXLaJ+1+HQwwLfiqCqNkxosW
         pleELE3kGFT7hA8Ep/n5bPIKxEF9nxmchGudDMFk+hToDrwhmXxO7hmguIbn9V4Ut78U
         fCI4myieAc0cwSp1wCJ0bmSEdJ3g9JFP6kdzfukcGI1BK0fQPwUD5tnLNRNo+QvfMy1r
         7vqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ISL3ueocusNeGd8nzOURVluq0iz1R6J7vmUsEFSX6pA=;
        b=XctqZMD0yY1L8BKaHYi3wUL0T5rwIUlJI2LIKcbi2MkFm4bcDfC+7Js00UDCerLMc5
         pOa66rb5fybfXK4pAheZ87CSnZmvYxcCvP4fed0Z8UnjedI1qO8zoZcIo3XKSHEUJk4y
         fksTeBLN/D4lmmFbf/NNBuLIPm6pHd+9qqn7cppBr2/3nfz6Z+LFDaEN0VvhQMvelYMI
         Kt9WhKyJcB0I2+DNdacW/QW2/Wo4dW9lPA4pBoYBblLR9tLYO+vuIFAm3f/6hgMyhCh0
         xyR9cdW53cdU7cKyBJcDzl6BrpnT759cpUehljULzif/2lr2z4iA8YJXXZJIE/wktCFB
         jWMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DpoTAYYO;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ISL3ueocusNeGd8nzOURVluq0iz1R6J7vmUsEFSX6pA=;
        b=RNEM3eMVTV/uZwfZwLMFKfJBe9EXJYtLw5IAiwo+Im+9yBiVIM181jJV4vqWm3Ckw1
         K2Ycz7Q7a1DJmSb4eXzSGQcRUSdTHjL4s/aESAs49GK8SGpU/pHrNXkjebJ0dadZKUbS
         bpJNV+SuJwSblpmQwbl+o14eqpzEzYC2/3QkccoujqWt+fplwbh2ZylhW+0SUgO3U0M7
         0EY7NJ6DarGqbBdmRZAuFohXRuF32mLZN6KhiqS59VRHGhMFQpq7QObp9i6fUMwWV7Y7
         jS1h56TTm7QOFeXJuYzbzgfpkEWMeX5Yim3LRpCtvUROLvPA2YGCtO4nqngzBxtHo0l4
         CTuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ISL3ueocusNeGd8nzOURVluq0iz1R6J7vmUsEFSX6pA=;
        b=G/6hKA/9X5k7CG+ihjjeRCVdLZtXC8iQPMCAXo/E+FhVg9+yPkd7hLsV3cRz03wCWU
         uJ4wZKKwaHSSEZRfsKVGsJxgFdUS+hGJDFsU/mncrkOlsceTO3p7dAJLBBbQf16w4uOv
         1QW3oiYflBMDRw7wxBhmHbnnGLg4Bap6CPGT5Osos5lo/J/vOEz5UDHOD0dMNDNO/9/t
         Ezk/f2DG0KOEbLINKUHaR+BcS3gW7yKmB1OuVS7FvuhaKdeqFbcfG7Y345PgA0JgjdxU
         Dybq5aRxRHG1w7pzM/CWHJs/OBik4KceI1dS0lrihvsrJr9INzziqHGboz7aep95rMp9
         tglA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324l12+5rliGe/BePAaAnRE+jwN3TyxTHgDfMnz39cXMA320kN1
	yrN99P2GrihpLYcjP0hk+/4=
X-Google-Smtp-Source: ABdhPJx/sBctNTLG7tCeJddtPN/oCmN6wF+9Y90xAt+gmZumHZRZu5ijlShKJ793M2EdtBiFyXsIzA==
X-Received: by 2002:a62:65c7:0:b029:278:e19f:f838 with SMTP id z190-20020a6265c70000b0290278e19ff838mr47456562pfb.64.1621018032874;
        Fri, 14 May 2021 11:47:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:24d5:: with SMTP id d21ls605764pfv.1.gmail; Fri, 14
 May 2021 11:47:12 -0700 (PDT)
X-Received: by 2002:a63:3444:: with SMTP id b65mr123012pga.185.1621018032334;
        Fri, 14 May 2021 11:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621018032; cv=none;
        d=google.com; s=arc-20160816;
        b=0E5uPU41Ayi9wB6Yqeuqn8GRlNZsbj2dEIPGaL3hF6IpuNB/V1DAn/4Qx65w8GQhoN
         4Lzsi0rOcC2Fj5hFb4oUlMGvwTm52qTE+Pin4w5pgunORmW4uGMJ9dLlrVVSznFVfIbQ
         aPuE0E5j/DnrIjM1qQ+w8LyZCOtC4nLGXLP52GY3xaTR0Sx+VNX/0MCptj9yh9tJy+22
         M63AhEiiAMeOsPHnDzTrY9NtsR2+kKnkA1b+E287/rRwCRt+ndoEw5U5G1fKFOEveaZw
         kYS2a9GUeihDTWEoU8S98h7A4Vym47p0uPsp6igbOCpdxI46T98zq+aCL6VWIu9g53vQ
         p5TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bdUdpaEiz+YytJHN4bYm3ZadOlXgkbMx08f2dYDPoPU=;
        b=1KT/CeEEYZWJw9hDbEEIi3pz7mxrEIT5wM01D5B3P6aT84rSmnUzv376UZk2EohEMB
         M4IxDwtQk9fbPeSNGxJz2EYVUcCQsUSgkmfJ2J6fPLyfb//UC1mlwoj00QOu6KL9o1X0
         e+OalOZl+JCyyOJ7UVsQvIR08ggul6nWOOa24fF1BxbVupdu9N5SWcioOTKZugTucl0y
         ClWoXfsdUevh0gvgP+FPkrpHPOmcHour8DZSYerFFBTWbax5p7oxug1504AajWYqoobs
         TBc3T2AWeH0gH1olhiL/W6yVO5MDEOjkZjeiuZ96hGzNtalOrawTvN7z3atoYNOjBE3z
         tyfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DpoTAYYO;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b9si815390pfd.3.2021.05.14.11.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 11:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0A05B613C8;
	Fri, 14 May 2021 18:47:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id C88BF5C02A5; Fri, 14 May 2021 11:47:11 -0700 (PDT)
Date: Fri, 14 May 2021 11:47:11 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Hillf Danton <hdanton@sina.com>
Cc: Manfred Spraul <manfred@colorfullife.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210514184711.GK975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
 <20210514082918.971-1-hdanton@sina.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210514082918.971-1-hdanton@sina.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DpoTAYYO;       spf=pass
 (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 14, 2021 at 04:29:18PM +0800, Hillf Danton wrote:
> On Thu, 13 May 2021 15:01:27 Paul E. McKenney wrote:
> >On Thu, May 13, 2021 at 12:02:01PM -0700, Paul E. McKenney wrote:
> >> On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> >> > Hi Paul,
> >> > 
> >> > On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> >> > > On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
> >> > > > [...]
> >> > > > sma->use_global_lock is evaluated in sem_lock() twice:
> >> > > > 
> >> > > > >  ?????? /*
> >> > > > >  ???????? * Initial check for use_global_lock. Just an optimization,
> >> > > > >  ???????? * no locking, no memory barrier.
> >> > > > >  ???????? */
> >> > > > >  ??????? if (!sma->use_global_lock) {
> >> > > > Both sides of the if-clause handle possible data races.
> >> > > > 
> >> > > > Is
> >> > > > 
> >> > > >  ??? if (!data_race(sma->use_global_lock)) {
> >> > > > 
> >> > > > the correct thing to suppress the warning?
> >> > > Most likely READ_ONCE() rather than data_race(), but please see
> >> > > the end of this message.
> >> > 
> >> > Based on the document, I would say data_race() is sufficient:
> >> > 
> >> > I have replaced the code with "if (jiffies %2)", and it runs fine.
> >> 
> >> OK, but please note that "jiffies" is marked volatile, which prevents the
> >> compiler from fusing loads.  You just happen to be OK in this particular
> >> case, as described below.  Use of the "jiffies_64" non-volatile synonym
> >> for "jiffies" is better for this sort of checking.  But even so, just
> >> because a particular version of a particular compiler refrains from
> >> fusing loads in a particular situation does not mean that all future
> >> versions of all future compilers will behave so nicely.
> >> 
> >> Again, you are OK in this particular situation, as described below.
> >> 
> >> > Thus I don't see which evil things a compiler could do, ... .
> >> 
> >> Fair enough, and your example is covered by the section "Reads Feeding
> >> Into Error-Tolerant Heuristics".  The worst that the compiler can do is
> >> to force an unnecessary acquisition of the global lock.
> >> 
> >> This cannot cause incorrect execution, but could results in poor
> >> scalability.  This could be a problem is load fusing were possible, that
> >> is, if successes calls to this function were inlined and the compiler
> >> just reused the value initially loaded.
> >> 
> >> The reason that load fusing cannot happen in this case is that the
> >> load is immediately followed by a lock acquisition, which implies a
> >> barrier(), which prevents the compiler from fusing loads on opposite
> >> sides of that barrier().
> >> 
> >> > [...]
> >> > 
> >> > Does tools/memory-model/Documentation/access-marking.txt, shown below,
> >> > > help?
> >> > > 
> >> > [...]
> >> > > 	int foo;
> >> > > 	DEFINE_RWLOCK(foo_rwlock);
> >> > > 
> >> > > 	void update_foo(int newval)
> >> > > 	{
> >> > > 		write_lock(&foo_rwlock);
> >> > > 		foo = newval;
> >> > > 		do_something(newval);
> >> > > 		write_unlock(&foo_rwlock);
> >> > > 	}
> >> > > 
> >> > > 	int read_foo(void)
> >> > > 	{
> >> > > 		int ret;
> >> > > 
> >> > > 		read_lock(&foo_rwlock);
> >> > > 		do_something_else();
> >> > > 		ret = foo;
> >> > > 		read_unlock(&foo_rwlock);
> >> > > 		return ret;
> >> > > 	}
> >> > > 
> >> > > 	int read_foo_diagnostic(void)
> >> > > 	{
> >> > > 		return data_race(foo);
> >> > > 	}
> >> > 
> >> > The text didn't help, the example has helped:
> >> > 
> >> > It was not clear to me if I have to use data_race() both on the read and the
> >> > write side, or only on one side.
> >> > 
> >> > Based on this example: plain C may be paired with data_race(), there is no
> >> > need to mark both sides.
> >> 
> >> Actually, you just demonstrated that this example is quite misleading.
> >> That data_race() works only because the read is for diagnostic
> >> purposes.  I am queuing a commit with your Reported-by that makes
> >> read_foo_diagnostic() just do a pr_info(), like this:
> >> 
> >> 	void read_foo_diagnostic(void)
> >> 	{
> >> 		pr_info("Current value of foo: %d\n", data_race(foo));
> >> 	}
> >> 
> >> So thank you for that!
> >
> >And please see below for an example better illustrating your use case.
> >Anything messed up or missing?
> >
> >							Thanx, Paul
> >
> >------------------------------------------------------------------------
> >
> >commit b4287410ee93109501defc4695ccc29144e8f3a3
> >Author: Paul E. McKenney <paulmck@kernel.org>
> >Date:   Thu May 13 14:54:58 2021 -0700
> >
> >    tools/memory-model: Add example for heuristic lockless reads
> >    
> >    This commit adds example code for heuristic lockless reads, based loosely
> >    on the sem_lock() and sem_unlock() functions.
> >    
> >    Reported-by: Manfred Spraul <manfred@colorfullife.com>
> >    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> >
> >diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
> >index 58bff2619876..e4a20ebf565d 100644
> >--- a/tools/memory-model/Documentation/access-marking.txt
> >+++ b/tools/memory-model/Documentation/access-marking.txt
> >@@ -319,6 +319,98 @@ of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN to check for a buggy
> > concurrent lockless write.
> > 
> > 
> >+Lock-Protected Writes With Heuristic Lockless Reads
> >+---------------------------------------------------
> >+
> >+For another example, suppose that the code can normally make use of
> >+a per-data-structure lock, but there are times when a global lock is
> >+required.  These times are indicated via a global flag.  The code might
> >+look as follows, and is based loosely on sem_lock() and sem_unlock():
> >+
> >+	bool global_flag;
> >+	DEFINE_SPINLOCK(global_lock);
> >+	struct foo {
> >+		spinlock_t f_lock;
> >+		int f_data;
> >+	};
> >+
> >+	/* All foo structures are in the following array. */
> >+	int nfoo;
> >+	struct foo *foo_array;
> >+
> >+	void do_something_locked(struct foo *fp)
> >+	{
> >+		/* IMPORTANT: Heuristic plus spin_lock()! */
> >+		if (!data_race(global_flag)) {
> >+			spin_lock(&fp->f_lock);
> >+			if (!smp_load_acquire(&global_flag)) {
> >+				do_something(fp);
> >+				spin_unlock(&fp->f_lock);
> >+				return;
> >+			}
> >+			spin_unlock(&fp->f_lock);
> >+		}
> >+		spin_lock(&global_flag);
> >+		/* Lock held, thus global flag cannot change. */
> >+		if (!global_flag) {
> >+			spin_lock(&fp->f_lock);
> >+			spin_unlock(&global_flag);
> >+		}
> >+		do_something(fp);
> >+		if (global_flag)
> 
> The global flag may change without global lock held - we will likely have the
> wrong lock released if we can see the change.

Right you are!  I am adding a local variable to address this, thank you!

							Thanx, Paul

> >+			spin_unlock(&global_flag);
> >+		else
> >+			spin_lock(&fp->f_lock);
> >+	}
> >+
> >+	void begin_global(void)
> >+	{
> >+		int i;
> >+
> >+		spin_lock(&global_flag);
> >+		WRITE_ONCE(global_flag, true);
> >+		for (i = 0; i < nfoo; i++) {
> >+			/* Wait for pre-existing local locks. */
> >+			spin_lock(&fp->f_lock);
> >+			spin_unlock(&fp->f_lock);
> >+		}
> >+		spin_unlock(&global_flag);
> >+	}
> >+
> >+	void end_global(void)
> >+	{
> >+		spin_lock(&global_flag);
> >+		smp_store_release(&global_flag, false);
> >+		/* Pre-existing global lock acquisitions will recheck. */
> >+		spin_unlock(&global_flag);
> >+	}
> >+
> >+All code paths leading from the do_something_locked() function's first
> >+read from global_flag acquire a lock, so endless load fusing cannot
> >+happen.
> >+
> >+If the value read from global_flag is true, then global_flag is rechecked
> >+while holding global_lock, which prevents global_flag from changing.
> >+If this recheck finds that global_flag is now false, the acquisition
> >+of ->f_lock prior to the release of global_lock will result in any subsequent
> >+begin_global() invocation waiting to acquire ->f_lock.
> >+
> >+On the other hand, if the value read from global_flag is false, then
> >+global_flag, then rechecking under ->f_lock combined with synchronization
> >+with begin_global() guarantees than any erroneous read will cause the
> >+do_something_locked() function's first do_something() invocation to happen
> >+before begin_global() returns.  The combination of the smp_load_acquire()
> >+in do_something_locked() and the smp_store_release() in end_global()
> >+guarantees that either the do_something_locked() function's first
> >+do_something() invocation happens after the call to end_global() or that
> >+do_something_locked() acquires global_lock() and rechecks under the lock.
> >+
> >+For this to work, only those foo structures in foo_array[] may be
> >+passed to do_something_locked().  The reason for this is that the
> >+synchronization with begin_global() relies on momentarily locking each
> >+and every foo structure.
> >+
> >+
> > Lockless Reads and Writes
> > -------------------------
> > 
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210514184711.GK975577%40paulmck-ThinkPad-P17-Gen-1.
