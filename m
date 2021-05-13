Return-Path: <kasan-dev+bncBCJZRXGY5YJBBN6D62CAMGQEM7KENCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A7CF837FFEF
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 00:01:29 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id t25-20020a62ea190000b0290229c92857besf18645734pfh.21
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 15:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620943288; cv=pass;
        d=google.com; s=arc-20160816;
        b=ikteSUuFPRYjRT/1/E2pMr6p5R51TUs/dHQkoI+lIv47jWCRmKtZA8kdyqV5BfHics
         7ATvGyR49sptzoLDTh+iIHap5tmgTXwC/vn7x19Fs9IHmoFS/CJjmiXo3e2bxqdvD0Pv
         7QDhV1DeOFErqZo0AZtTT+pfMDFGLp0btw0wXBNOYXsrlG4qQ3vQHCU1ScoijMWKL24t
         T6f+O0ePeCJqLdZFtPFuzUDM7UvI8radqbmzsksEzw3ipWICGDGO4vqdnZOW5SXT3u7V
         LWDyR+C/eo0/Y22qO0ZUzuP8t4ECA9IzYjwy/7ZfwqqMDUiL3DWJ7jLwfq89Ri7d0A84
         yLYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=msN31m/gMGNMIjh8/DYB0BFTSasVyFkDOMeOw9tD/40=;
        b=eJlLo8O6mlKpdc2HGG/3O4s547ohQK8AMjLI30t696y3cwoc+cHwz3aRoc66X2Q7ox
         BGQ6gQvFQPtSmJbkQfljLtByObPHhDjLIUOMTcuBMWFsFdDi5InEtP8eLuzOZpk51J/x
         fKnAGTEMVUYgeHa1B0BRWdXwyQ225fCIabN5WrTfgZB6EAqWynLNkGWEzQFhaa91sAIg
         9nxR8xSKSNTfpjU7Lt+BzvTFRu8FQpWWlh1kpHIkX95ml8BUlSOdoRL369/8y14h+Xo4
         P1r8YrPFxO++iTmGqN/oYV1W8jX9TqLbj1uuCS2BLomV9FyPdqmC9NB4C80eDDaP2cQ3
         h/Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bGR7MMaY;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=msN31m/gMGNMIjh8/DYB0BFTSasVyFkDOMeOw9tD/40=;
        b=FcwlvxnZSFgQ5QfdWdqpWgIbuJcIJYfYCc++SStrRayC9wsOMSVgaYQAz9oka/Y+Zl
         +CfDjhFv1W9mUJgMD1STcH3dqIAwYgZTXym5jgILw5wCX6ana6NnzZJ9Ld+ZBoxPoU4s
         v4pR9yhtI9fC5+/kCKrLNH3Uy2gRqPtS0tVaeCbz7dwUteLkLDk0u3PnUnToF9MZfY9D
         nZfqx88feKU+5zoRhtY/bvdbixdQuAj0yvgA/0qI2qx7DkiP4Zze5/YNg0C6zFvaDllU
         pev62RCsE6Vv+23gQuNybh0msoLFXTx025ONyKzu3s6EHMU+i0Y4KVAb84wr/Y4NwBZD
         K62g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=msN31m/gMGNMIjh8/DYB0BFTSasVyFkDOMeOw9tD/40=;
        b=YPkmjlfQbsyw2iBUY6ditghD6g+AX8xO0NUfxsns79yDc24/9Uwg62sARKAPOfgGik
         QLfTGn54LQ0N902AJoWPcZKEX/QiptF3EyCChSzFfouuO8mQtAiA6bP2t0gdBT9tWXAm
         Dyx2l1I+LjoeY/5jPughmXXzyzaUqmtD0vSzGmFBHFvmZMrqejdG6rPyleWiT+A7smPr
         lcverHNipoAWtejTPOAx1cAVmrIjxgCVsh+XJ8XSLmf52I4oF08HF7YNLhN9R4IfBfgD
         N/hd24gNUK78hF9Yvi6krkNn81J67RRXFImsfBTiZgc5lU+0GUfr0aRTzE5aPdO9S3qX
         o+oQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o/zXFZpNZccTrSkyMUoQvLY8TiIxEgivJt5HwviCkLylVdMeo
	0R0Zw+NfGlV0jK/skb7jNnA=
X-Google-Smtp-Source: ABdhPJwgnsUMvjvLHtRTpJGbr/H8xNWp3rDUMi511+JlsTUWwg4d6BGY9QpZy4QmwBIMeW7fpoegIQ==
X-Received: by 2002:a63:1109:: with SMTP id g9mr44084292pgl.88.1620943288288;
        Thu, 13 May 2021 15:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3014:: with SMTP id hg20ls6711685pjb.3.canary-gmail;
 Thu, 13 May 2021 15:01:27 -0700 (PDT)
X-Received: by 2002:a17:90b:8d5:: with SMTP id ds21mr7414772pjb.65.1620943287580;
        Thu, 13 May 2021 15:01:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620943287; cv=none;
        d=google.com; s=arc-20160816;
        b=C0ghHxj9BQEtw9GKYczbYeKhIbKXrxq0xlp9GVTalAa5WnWgm+/iwJJTYT3qtT24a5
         w5ctqvz4/N0jxD/eUqdk4dV7XHU0UcsuQKshvez0ZDQkKW4rAAWoFIz5f7PumVrCtiIK
         Ilrs9fAAbOADfHQyD51byltuOQSFBMQLvxt7YlyDBQEYxdIhcIwKQHq7vPm7g5h5TuyN
         kRe8eVjxWcMfJPbcGej7ZocFzOgbR3hOnNo0CUer1qv+6nO5H6aOps4KX/ZY0kKM9yCF
         KqP6/gmoUQaC7MSMgNUOYTiF+e6CKB3i5/W7NjWLqg3XGM2/4jHqQ99qzfH2E11eUufM
         Uxvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=XIUaOh4QMTFhofDxdrXR+6diyqGyYX9WmRSvEFjIiww=;
        b=HyRktJJ+6DwWBbP6R9En5i+Aa4FRKqnrxWYBzztmgt6TToLADLSHbhVRVYE0xVFcEw
         XElbr4S1MkduHBrqCI4LXTygTY1rrBoyFMYBu5A2K4yyvA6BQhaYo8vcMs5MAfNkGXP4
         Im0cVZ+UGbeg8o+E/5nrWgLDB/BUtGDvDioZj+z2LeY1jsaMftXEuDKfTVxCnJ4MgOng
         zzZSsvptPEHmdyYksJMflGK7LVHyqNC3LRzMqHdgI0ndJdGyTT8HvGt4q0+QBr1vDwnw
         ujUJVsf1lYMHh00sPEFJwpITUCVbRgQ7DrVaH0ZsXwXwFHgfqEgdp7pdId4yJ7763/g5
         SvDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bGR7MMaY;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n35si421869pfv.6.2021.05.13.15.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 May 2021 15:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4896F60FEE;
	Thu, 13 May 2021 22:01:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0FD6C5C036A; Thu, 13 May 2021 15:01:27 -0700 (PDT)
Date: Thu, 13 May 2021 15:01:27 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210513220127.GA3511242@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bGR7MMaY;       spf=pass
 (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, May 13, 2021 at 12:02:01PM -0700, Paul E. McKenney wrote:
> On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> > Hi Paul,
> >=20
> > On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> > > On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
> > > > [...]
> > > > sma->use_global_lock is evaluated in sem_lock() twice:
> > > >=20
> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial check=
 for use_global_lock. Just an optimization,
> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, n=
o memory barrier.
> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_=
lock) {
> > > > Both sides of the if-clause handle possible data races.
> > > >=20
> > > > Is
> > > >=20
> > > >  =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
> > > >=20
> > > > the correct thing to suppress the warning?
> > > Most likely READ_ONCE() rather than data_race(), but please see
> > > the end of this message.
> >=20
> > Based on the document, I would say data_race() is sufficient:
> >=20
> > I have replaced the code with "if (jiffies %2)", and it runs fine.
>=20
> OK, but please note that "jiffies" is marked volatile, which prevents the
> compiler from fusing loads.  You just happen to be OK in this particular
> case, as described below.  Use of the "jiffies_64" non-volatile synonym
> for "jiffies" is better for this sort of checking.  But even so, just
> because a particular version of a particular compiler refrains from
> fusing loads in a particular situation does not mean that all future
> versions of all future compilers will behave so nicely.
>=20
> Again, you are OK in this particular situation, as described below.
>=20
> > Thus I don't see which evil things a compiler could do, ... .
>=20
> Fair enough, and your example is covered by the section "Reads Feeding
> Into Error-Tolerant Heuristics".  The worst that the compiler can do is
> to force an unnecessary acquisition of the global lock.
>=20
> This cannot cause incorrect execution, but could results in poor
> scalability.  This could be a problem is load fusing were possible, that
> is, if successes calls to this function were inlined and the compiler
> just reused the value initially loaded.
>=20
> The reason that load fusing cannot happen in this case is that the
> load is immediately followed by a lock acquisition, which implies a
> barrier(), which prevents the compiler from fusing loads on opposite
> sides of that barrier().
>=20
> > [...]
> >=20
> > Does tools/memory-model/Documentation/access-marking.txt, shown below,
> > > help?
> > >=20
> > [...]
> > > 	int foo;
> > > 	DEFINE_RWLOCK(foo_rwlock);
> > >=20
> > > 	void update_foo(int newval)
> > > 	{
> > > 		write_lock(&foo_rwlock);
> > > 		foo =3D newval;
> > > 		do_something(newval);
> > > 		write_unlock(&foo_rwlock);
> > > 	}
> > >=20
> > > 	int read_foo(void)
> > > 	{
> > > 		int ret;
> > >=20
> > > 		read_lock(&foo_rwlock);
> > > 		do_something_else();
> > > 		ret =3D foo;
> > > 		read_unlock(&foo_rwlock);
> > > 		return ret;
> > > 	}
> > >=20
> > > 	int read_foo_diagnostic(void)
> > > 	{
> > > 		return data_race(foo);
> > > 	}
> >=20
> > The text didn't help, the example has helped:
> >=20
> > It was not clear to me if I have to use data_race() both on the read an=
d the
> > write side, or only on one side.
> >=20
> > Based on this example: plain C may be paired with data_race(), there is=
 no
> > need to mark both sides.
>=20
> Actually, you just demonstrated that this example is quite misleading.
> That data_race() works only because the read is for diagnostic
> purposes.  I am queuing a commit with your Reported-by that makes
> read_foo_diagnostic() just do a pr_info(), like this:
>=20
> 	void read_foo_diagnostic(void)
> 	{
> 		pr_info("Current value of foo: %d\n", data_race(foo));
> 	}
>=20
> So thank you for that!

And please see below for an example better illustrating your use case.
Anything messed up or missing?

							Thanx, Paul

------------------------------------------------------------------------

commit b4287410ee93109501defc4695ccc29144e8f3a3
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Thu May 13 14:54:58 2021 -0700

    tools/memory-model: Add example for heuristic lockless reads
   =20
    This commit adds example code for heuristic lockless reads, based loose=
ly
    on the sem_lock() and sem_unlock() functions.
   =20
    Reported-by: Manfred Spraul <manfred@colorfullife.com>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/me=
mory-model/Documentation/access-marking.txt
index 58bff2619876..e4a20ebf565d 100644
--- a/tools/memory-model/Documentation/access-marking.txt
+++ b/tools/memory-model/Documentation/access-marking.txt
@@ -319,6 +319,98 @@ of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN to =
check for a buggy
 concurrent lockless write.
=20
=20
+Lock-Protected Writes With Heuristic Lockless Reads
+---------------------------------------------------
+
+For another example, suppose that the code can normally make use of
+a per-data-structure lock, but there are times when a global lock is
+required.  These times are indicated via a global flag.  The code might
+look as follows, and is based loosely on sem_lock() and sem_unlock():
+
+	bool global_flag;
+	DEFINE_SPINLOCK(global_lock);
+	struct foo {
+		spinlock_t f_lock;
+		int f_data;
+	};
+
+	/* All foo structures are in the following array. */
+	int nfoo;
+	struct foo *foo_array;
+
+	void do_something_locked(struct foo *fp)
+	{
+		/* IMPORTANT: Heuristic plus spin_lock()! */
+		if (!data_race(global_flag)) {
+			spin_lock(&fp->f_lock);
+			if (!smp_load_acquire(&global_flag)) {
+				do_something(fp);
+				spin_unlock(&fp->f_lock);
+				return;
+			}
+			spin_unlock(&fp->f_lock);
+		}
+		spin_lock(&global_flag);
+		/* Lock held, thus global flag cannot change. */
+		if (!global_flag) {
+			spin_lock(&fp->f_lock);
+			spin_unlock(&global_flag);
+		}
+		do_something(fp);
+		if (global_flag)
+			spin_unlock(&global_flag);
+		else
+			spin_lock(&fp->f_lock);
+	}
+
+	void begin_global(void)
+	{
+		int i;
+
+		spin_lock(&global_flag);
+		WRITE_ONCE(global_flag, true);
+		for (i =3D 0; i < nfoo; i++) {
+			/* Wait for pre-existing local locks. */
+			spin_lock(&fp->f_lock);
+			spin_unlock(&fp->f_lock);
+		}
+		spin_unlock(&global_flag);
+	}
+
+	void end_global(void)
+	{
+		spin_lock(&global_flag);
+		smp_store_release(&global_flag, false);
+		/* Pre-existing global lock acquisitions will recheck. */
+		spin_unlock(&global_flag);
+	}
+
+All code paths leading from the do_something_locked() function's first
+read from global_flag acquire a lock, so endless load fusing cannot
+happen.
+
+If the value read from global_flag is true, then global_flag is rechecked
+while holding global_lock, which prevents global_flag from changing.
+If this recheck finds that global_flag is now false, the acquisition
+of ->f_lock prior to the release of global_lock will result in any subsequ=
ent
+begin_global() invocation waiting to acquire ->f_lock.
+
+On the other hand, if the value read from global_flag is false, then
+global_flag, then rechecking under ->f_lock combined with synchronization
+with begin_global() guarantees than any erroneous read will cause the
+do_something_locked() function's first do_something() invocation to happen
+before begin_global() returns.  The combination of the smp_load_acquire()
+in do_something_locked() and the smp_store_release() in end_global()
+guarantees that either the do_something_locked() function's first
+do_something() invocation happens after the call to end_global() or that
+do_something_locked() acquires global_lock() and rechecks under the lock.
+
+For this to work, only those foo structures in foo_array[] may be
+passed to do_something_locked().  The reason for this is that the
+synchronization with begin_global() relies on momentarily locking each
+and every foo structure.
+
+
 Lockless Reads and Writes
 -------------------------
=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210513220127.GA3511242%40paulmck-ThinkPad-P17-Gen-1.
