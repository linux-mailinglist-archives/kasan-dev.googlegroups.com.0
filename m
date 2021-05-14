Return-Path: <kasan-dev+bncBCJZRXGY5YJBBDUP7OCAMGQEX6Q5E4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 005DE38101C
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 20:55:12 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id r184-20020a4a4ec10000b02901fcac00c417sf199287ooa.4
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 11:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621018511; cv=pass;
        d=google.com; s=arc-20160816;
        b=wXMKLvbn/X/Cn48IKcOLU5NPIqRVHoOaE/Sq4Ngu89GEuaia5EF0Ov+4katL3m4QKj
         tHJzSikWYeLA6bphu7tVnphHdySj22mX1G6aqlPcABwLnrzJGDfgGT7byQCCxk+gFUd6
         WFwgMh6uoujwmSh2VjPBSPUKgNYCuezk4nvKn0JmE9Nzt3QypRepDAcYuoYSUPEiKpid
         8btloQMhFvjr5i3KEQ6u3SReFiPtUdywllYgXvKsYyvHAsjrvnckgyiGjbSt5OZe3QDo
         KW98RervajaPqs6omqeuQE3bgqPYLTrf/htyjPi1+KALQR4qHrXWfNqQTpB8agPbUaAx
         ov3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nHvYFXG1j/qz+SA1A0BytdQF1iHp9RMPRDZd1N7I9Is=;
        b=zQTyyJgy3RQs0Q0/zIFPfqT2lpfa9O/j/U23M8kWDjR1gdJGPjSUIeXurSVaTkTp0l
         fQyyLTOE3xnW7O9BHac0CkLTvDFufuiaWrrAonUFvuATHUh5E1xSzLaS4arxs1bgH/3m
         XRIWDbqrZiHe3cCdWhamR7YKwDfLQBu/lf+Co6VdVAvThBCezaPs4h5j2FUMwMXUjVES
         FPlUegcrbtG5ej+UHQJFyd3xXIGtQEN/lHR0biSB5i5GTP2BjbuZ+hld1ien/7+clEye
         985cP44uRuzkiMXa0MTTyedANd5+UOiMHpixPHYuOB6utvSX+9js28z9gpPF0vtWAvjb
         z+Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T7oYhacX;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nHvYFXG1j/qz+SA1A0BytdQF1iHp9RMPRDZd1N7I9Is=;
        b=HnsWxUHEC4vKZpahQk3dl6cNiGKeMyu/NiQarZAj+5zSunjQA8ABzmnFaEesJGBv9u
         dDr+RlUx9mRc6BWLQR8fpWGhbHuMtpUPySQiw5YBk+Djhkmz91B22wxGBEaivu2NQk3x
         Qg8/dwNAKyYnPcEaEVUo4U8MrlRtVQUshicq3v3LWMBLVTczgrTClMVYBochrZH3kCoC
         yDsrczVFrZVgtgYx+Ulp/XKRA5kWE56nVJrHnny0gAoQmjnLzWA99hyh4QaFRU1j0Fnw
         OVopIFADE7K5Itag//Wu5NGe5sLB3JM9FrL4UVIqgSMQ8QKT3jGa9WAp2UMVtLxg/Bl3
         AYZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nHvYFXG1j/qz+SA1A0BytdQF1iHp9RMPRDZd1N7I9Is=;
        b=hThsDaJZnv6oyJFhR37UgV8wYhGQaDnH4oGukPjgj2vcCssFzYf+yv3PbCrOiozvoy
         dzKkasD1aU5dPWYe9Z6ZFeXpmjT5E4txc2My9EtdSMdhdmXkcRTJ/LtwPcBQy6LeiJqb
         bG0g9wiWijeAsFmR8Juyv/PM69rJBNfzstAIaIDwklpwvKfmF8P5fiIE9kP+qJkuupqd
         LEUT/3GyUPg4srzKbffExG9+vGfaKVAsiSd3Whc7bDwqEC5U/a6hn6RCAYMDmhUuKv44
         pqLiLb4ZeN8j59+vj2C8P36VIoXFJWPE30fzaQdKr1x8+J5nJmOuA0K4CYgKumgWTjI3
         Ljsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EPJGCcxq8lytXHWHLueSvbJW37pDtonj+t7XREx/YqSgza8ns
	8kp8Hy94vG2XxodFdOKUNjg=
X-Google-Smtp-Source: ABdhPJzL7ACy85xIeCkggAujyAM9YBIKsRTvyt7SzJxz/0jtxIP3aaZ5G7GSR+t1TkJjDiMcvRkRuw==
X-Received: by 2002:a9d:66cc:: with SMTP id t12mr29688483otm.14.1621018510968;
        Fri, 14 May 2021 11:55:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4392:: with SMTP id u18ls2645478oiv.1.gmail; Fri, 14 May
 2021 11:55:10 -0700 (PDT)
X-Received: by 2002:a05:6808:98f:: with SMTP id a15mr19467614oic.29.1621018510610;
        Fri, 14 May 2021 11:55:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621018510; cv=none;
        d=google.com; s=arc-20160816;
        b=wtxnCRhU4ttY4vR4LJxtBJPDuZQd0HcJI2YUaCGyOGvZ43kp4Wzatz8OCMBOI0kImG
         zumFOPj0vxjIPbOa9fsaM9pO5trazzUC7b8fjTBO62R4tYwC+XwBR19L5oRFsX38FgCS
         4X67WZR3qto6KKNPkdVvbNsAPHQhXLvvOvwEKuW16Ve8+Mkd/cDUU6X6k8wEEnjuPrt1
         3+3yri5OpwBkJIR6HuuDejZeX7MCyjxMkQDb1agBbok7n2dLx5PmLa+KhIQHju9LkGwg
         EOPmMkjV+JcWzlRob9RybEBVpxGs8Hp0gr4tmUhVrmAfkslA2xzZ7AGWPI2HPceSDU/a
         76bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=4GppsNyAncm7I4hz3dHEp+1e9vYj8LKXt+MKirFLlJI=;
        b=aohZUYz/OFF3NmKzpMHTLZGzrnjuaXMQ+kvp7zfNWVBYv2l0cRcThFKF8wazAEohlO
         qomMDeIJsAMTfXyJxRIIRcGHPbQqLGiaPOkyioQQe9ZEoTleDQNbOjqmTTPrm3wzTTbI
         XvoASSJl4ZebwFeefnrNBu+WqNIAKc3l0eVQW5X/Ndm73Bm6YqBTSjvEJUxjBG5Kj5cq
         W5XB73/CS9CiFrk4jFldUkw6cmP+Kj/c6T7wN4Knomg/i/kIWEYZqIQAZeW/sQMueR+C
         Q5tWpm4eO4Nko3w4I76sQxRIa0rSMy+oWItB9Ziz8GlDrXrIWjNsyhFqneb5eCNsNVLS
         K9qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T7oYhacX;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k4si670594oot.1.2021.05.14.11.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 11:55:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CC752611BD;
	Fri, 14 May 2021 18:55:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8EC505C02A5; Fri, 14 May 2021 11:55:09 -0700 (PDT)
Date: Fri, 14 May 2021 11:55:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210514185509.GL975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
 <20210513220127.GA3511242@paulmck-ThinkPad-P17-Gen-1>
 <8479a455-1813-fcee-a6ca-9fd0c2c6aabe@colorfullife.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <8479a455-1813-fcee-a6ca-9fd0c2c6aabe@colorfullife.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=T7oYhacX;       spf=pass
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

On Fri, May 14, 2021 at 06:01:37PM +0200, Manfred Spraul wrote:
> Hi Paul,
>=20
> On 5/14/21 12:01 AM, Paul E. McKenney wrote:
> > On Thu, May 13, 2021 at 12:02:01PM -0700, Paul E. McKenney wrote:
> > > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> > > > Hi Paul,
> > > >=20
> > > > On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> > > > > On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
> > > > > > [...]
> > > > > > sma->use_global_lock is evaluated in sem_lock() twice:
> > > > > >=20
> > > > > > >   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> > > > > > >   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial =
check for use_global_lock. Just an optimization,
> > > > > > >   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locki=
ng, no memory barrier.
> > > > > > >   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> > > > > > >   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_gl=
obal_lock) {
> > > > > > Both sides of the if-clause handle possible data races.
> > > > > >=20
> > > > > > Is
> > > > > >=20
> > > > > >   =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
> > > > > >=20
> > > > > > the correct thing to suppress the warning?
> > > > > Most likely READ_ONCE() rather than data_race(), but please see
> > > > > the end of this message.
> > > > Based on the document, I would say data_race() is sufficient:
> > > >=20
> > > > I have replaced the code with "if (jiffies %2)", and it runs fine.
> > > OK, but please note that "jiffies" is marked volatile, which prevents=
 the
> > > compiler from fusing loads.  You just happen to be OK in this particu=
lar
> > > case, as described below.  Use of the "jiffies_64" non-volatile synon=
ym
> > > for "jiffies" is better for this sort of checking.  But even so, just
> > > because a particular version of a particular compiler refrains from
> > > fusing loads in a particular situation does not mean that all future
> > > versions of all future compilers will behave so nicely.
> > >=20
> > > Again, you are OK in this particular situation, as described below.
> > >=20
> > > > Thus I don't see which evil things a compiler could do, ... .
> > > Fair enough, and your example is covered by the section "Reads Feedin=
g
> > > Into Error-Tolerant Heuristics".  The worst that the compiler can do =
is
> > > to force an unnecessary acquisition of the global lock.
> > >=20
> > > This cannot cause incorrect execution, but could results in poor
> > > scalability.  This could be a problem is load fusing were possible, t=
hat
> > > is, if successes calls to this function were inlined and the compiler
> > > just reused the value initially loaded.
> > >=20
> > > The reason that load fusing cannot happen in this case is that the
> > > load is immediately followed by a lock acquisition, which implies a
> > > barrier(), which prevents the compiler from fusing loads on opposite
> > > sides of that barrier().
> > >=20
> > > > [...]
> > > >=20
> > > > Does tools/memory-model/Documentation/access-marking.txt, shown bel=
ow,
> > > > > help?
> > > > >=20
> > > > [...]
> > > > > 	int foo;
> > > > > 	DEFINE_RWLOCK(foo_rwlock);
> > > > >=20
> > > > > 	void update_foo(int newval)
> > > > > 	{
> > > > > 		write_lock(&foo_rwlock);
> > > > > 		foo =3D newval;
> > > > > 		do_something(newval);
> > > > > 		write_unlock(&foo_rwlock);
> > > > > 	}
> > > > >=20
> > > > > 	int read_foo(void)
> > > > > 	{
> > > > > 		int ret;
> > > > >=20
> > > > > 		read_lock(&foo_rwlock);
> > > > > 		do_something_else();
> > > > > 		ret =3D foo;
> > > > > 		read_unlock(&foo_rwlock);
> > > > > 		return ret;
> > > > > 	}
> > > > >=20
> > > > > 	int read_foo_diagnostic(void)
> > > > > 	{
> > > > > 		return data_race(foo);
> > > > > 	}
> > > > The text didn't help, the example has helped:
> > > >=20
> > > > It was not clear to me if I have to use data_race() both on the rea=
d and the
> > > > write side, or only on one side.
> > > >=20
> > > > Based on this example: plain C may be paired with data_race(), ther=
e is no
> > > > need to mark both sides.
> > > Actually, you just demonstrated that this example is quite misleading=
.
> > > That data_race() works only because the read is for diagnostic
> > > purposes.  I am queuing a commit with your Reported-by that makes
> > > read_foo_diagnostic() just do a pr_info(), like this:
> > >=20
> > > 	void read_foo_diagnostic(void)
> > > 	{
> > > 		pr_info("Current value of foo: %d\n", data_race(foo));
> > > 	}
> > >=20
> > > So thank you for that!
> > And please see below for an example better illustrating your use case.
> > Anything messed up or missing?
> >=20
> > 							Thanx, Paul
> >=20
> > -----------------------------------------------------------------------=
-
> >=20
> > commit b4287410ee93109501defc4695ccc29144e8f3a3
> > Author: Paul E. McKenney <paulmck@kernel.org>
> > Date:   Thu May 13 14:54:58 2021 -0700
> >=20
> >      tools/memory-model: Add example for heuristic lockless reads
> >      This commit adds example code for heuristic lockless reads, based =
loosely
> >      on the sem_lock() and sem_unlock() functions.
>=20
> I would refer to nf_conntrack_all_lock() instead of sem_lock():
>=20
> nf_conntrack_all_lock() is far easier to read, and it contains the same
> heuristics

Sounds good, updated to nf_conntrack_lock(), nf_conntrack_all_lock(),
and nf_conntrack_all_unlock().

> >      Reported-by: Manfred Spraul <manfred@colorfullife.com>
> >      Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> >=20
> > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tool=
s/memory-model/Documentation/access-marking.txt
> > index 58bff2619876..e4a20ebf565d 100644
> > --- a/tools/memory-model/Documentation/access-marking.txt
> > +++ b/tools/memory-model/Documentation/access-marking.txt
> > @@ -319,6 +319,98 @@ of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN=
 to check for a buggy
> >   concurrent lockless write.
> > +Lock-Protected Writes With Heuristic Lockless Reads
> > +---------------------------------------------------
> > +
> > +For another example, suppose that the code can normally make use of
> > +a per-data-structure lock, but there are times when a global lock is
> > +required.  These times are indicated via a global flag.  The code migh=
t
> > +look as follows, and is based loosely on sem_lock() and sem_unlock():
> > +
> > +	bool global_flag;
> > +	DEFINE_SPINLOCK(global_lock);
> > +	struct foo {
> > +		spinlock_t f_lock;
> > +		int f_data;
> > +	};
> > +
> > +	/* All foo structures are in the following array. */
> > +	int nfoo;
> > +	struct foo *foo_array;
> > +
> > +	void do_something_locked(struct foo *fp)
> > +	{
> > +		/* IMPORTANT: Heuristic plus spin_lock()! */
> > +		if (!data_race(global_flag)) {
> > +			spin_lock(&fp->f_lock);
> > +			if (!smp_load_acquire(&global_flag)) {
> > +				do_something(fp);
> > +				spin_unlock(&fp->f_lock);
> > +				return;
> > +			}
> > +			spin_unlock(&fp->f_lock);
> > +		}
> > +		spin_lock(&global_flag);
> > +		/* Lock held, thus global flag cannot change. */
> > +		if (!global_flag) {
> > +			spin_lock(&fp->f_lock);
> > +			spin_unlock(&global_flag);
>=20
> spin_unlock(&global_lock), not &global_flag.
>=20
> That was the main results from the discussions a few years ago:
>=20
> Split global_lock and global_flag. Do not try to use
> spin_is_locked(&global_lock). Just add a flag. The 4 bytes are well
> invested.

Thank you for catching this typo!  It is now global_lock.

							Thanx, Paul

> > +		}
> > +		do_something(fp);
> > +		if (global_flag)
> > +			spin_unlock(&global_flag);
> &global_lock
> > +		else
> > +			spin_lock(&fp->f_lock);
> > +	}
> > +
> > +	void begin_global(void)
> > +	{
> > +		int i;
> > +
> > +		spin_lock(&global_flag);
> > +		WRITE_ONCE(global_flag, true);
> > +		for (i =3D 0; i < nfoo; i++) {
> > +			/* Wait for pre-existing local locks. */
> > +			spin_lock(&fp->f_lock);
> > +			spin_unlock(&fp->f_lock);
> > +		}
> > +		spin_unlock(&global_flag);
> > +	}
> > +
> > +	void end_global(void)
> > +	{
> > +		spin_lock(&global_flag);
> > +		smp_store_release(&global_flag, false);
> > +		/* Pre-existing global lock acquisitions will recheck. */
> > +		spin_unlock(&global_flag);
> > +	}
> > +
> > +All code paths leading from the do_something_locked() function's first
> > +read from global_flag acquire a lock, so endless load fusing cannot
> > +happen.
> > +
> > +If the value read from global_flag is true, then global_flag is rechec=
ked
> > +while holding global_lock, which prevents global_flag from changing.
> > +If this recheck finds that global_flag is now false, the acquisition
> > +of ->f_lock prior to the release of global_lock will result in any sub=
sequent
> > +begin_global() invocation waiting to acquire ->f_lock.
> > +
> > +On the other hand, if the value read from global_flag is false, then
> > +global_flag, then rechecking under ->f_lock combined with synchronizat=
ion
> > +with begin_global() guarantees than any erroneous read will cause the
> > +do_something_locked() function's first do_something() invocation to ha=
ppen
> > +before begin_global() returns.  The combination of the smp_load_acquir=
e()
> > +in do_something_locked() and the smp_store_release() in end_global()
> > +guarantees that either the do_something_locked() function's first
> > +do_something() invocation happens after the call to end_global() or th=
at
> > +do_something_locked() acquires global_lock() and rechecks under the lo=
ck.
> > +
> > +For this to work, only those foo structures in foo_array[] may be
> > +passed to do_something_locked().  The reason for this is that the
> > +synchronization with begin_global() relies on momentarily locking each
> > +and every foo structure.
> > +
> > +
> >   Lockless Reads and Writes
> >   -------------------------
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210514185509.GL975577%40paulmck-ThinkPad-P17-Gen-1.
