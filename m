Return-Path: <kasan-dev+bncBC2OPIG4UICBB37J7CCAMGQEVW4XDSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42065380544
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 10:29:37 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id w3-20020a170902d103b02900f057b7e766sf535556plw.13
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 01:29:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620980976; cv=pass;
        d=google.com; s=arc-20160816;
        b=LSCbWoc8bbgDvugV6xzBNV/+t56MsUgdNwM6EOfKadUO3GFae3YXT/3rWgkl5RDsBY
         VsU9GKDpJKfBI3g0CZ701nuJdQIjL5oJsXzYDBmSNJ8MLwzg9ddGpiPNi+XN8HrqRy9M
         K3hGkgtRWXCk1YwpKxR3BQPOVU9edHJ4/J2jBTNlQsf43T8CAerqTppDAAA/jVCAPGmE
         jZcyva96IChUFfxXFTVYbjmO70PdeeD/JqtNmiZ5IU9pK4DPZNgiPxEMrJpScoPpJIlH
         YMpq4pd/z2ye3fXTgq9qI35m93LE8FkUxEv5MspU3M0RtOe4OYmxWiMCmfJCTiTtt8t2
         GYqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=5vGB5I9ovliBsh/MBzdbdxrIPJ58XfQ5qNxcQoRHqt0=;
        b=cuLJURPcVzmYx9EGoV8D0QXwxvaGRDIYjQ/P7Y2/o0H69WPlyu2/+0Qjro3dx8/zZJ
         Fbm0JtKYDT8kJr8BCE36bEpHzdC4FZdO6LNeT2Yme6bt89VxWrpOkGrkpFnH25wTuFEt
         YFQ60ycpw3umiOHfkCdodcczTPKR9pOp7bO6Eum9WwMKgWdjwC6qnnsdMfZGR27D5uEI
         CI9NaBVj1u4NE/CG08UdOwZUpOIl05NY02cG5EWSP5m6UeMFkxDscTM2s2YNZY/cEXlK
         VQMAymcSk7Pk+d5xBu5Lt1StwU2+KgR1eQIyi4dO3QkRGA8HvCODKxToJC7uzdsNO1GU
         0V1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.23 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5vGB5I9ovliBsh/MBzdbdxrIPJ58XfQ5qNxcQoRHqt0=;
        b=a2kt+6a/QEVmgwuUf91D3q/AaY3Yv2Xd8+0qNH3s/gYjaNMQxckalpqrbwfScsNn28
         vT8B3Vz94FV7rb/GxdgXRWfUhXFJHuy06XgE2mj19WocMnYhjtDw6BHaYZGsKtxLDS98
         bwJKArEHOnxY7GCJF6WuP+qHc+NpOLKDnsj/9KRPkZThYSQcC6lux7W9B06C2WjUkMKJ
         K8AlfYty1TSoccoWwgONJL1IHXBc2q3FpX00Q2cPsKrssWsI74DHr7xhZeUWeI6OANCa
         ntzA9/pvSQbADVQ2jHghIV7EEI5I8KiYQojFr1aaANsLeJORkwCFuzBPaN+SYlNTqbF+
         chMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5vGB5I9ovliBsh/MBzdbdxrIPJ58XfQ5qNxcQoRHqt0=;
        b=CK7WnWlJrGfA7fx3LTsNkdShHNL42B3nTdZQxAkoZEKBrCGwW7NCDFdfiEQVBHkgh3
         8l5+S/2xOsNONOHHmWEGU+BLVWZ+OeKGEunt+HdkAIUyaZY0J/oPjSgmG6/Hh8EZqa02
         IMiLNVd9I1XOXovjMasI4ridpDsdwViz9AVHhPWY4cwsC9W+XiisrD1gn4Jylq8YiqD0
         RyQ86KSSUd6PVbgFKQvZRYJUtprXUBKeQ0gxGFmjGmAJhWtkgm04hBMjMA87zZ19bdEM
         zcuV5SrDxaxJlpJA4orbFmuXWrJAvV+wPaSwXZoZKB23D087mfFNCP8BopiGFcX36Xw4
         QTcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Qw5xLXChsJzkfrNqRyWLiFPxZw/kEcMDb7trQsnjntOBrRU0X
	ZizK136yCQgvpG/09o2mLIw=
X-Google-Smtp-Source: ABdhPJx+8y1GqLt/p2oWfi8n8YjkGGGq4NmefXGvRJQwA1gqLp38HDnQ2t5Uwtqfyf7uPMHDuyyk5g==
X-Received: by 2002:a17:902:8687:b029:ee:e239:18bf with SMTP id g7-20020a1709028687b02900eee23918bfmr16026452plo.56.1620980975708;
        Fri, 14 May 2021 01:29:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fc98:: with SMTP id ci24ls2183629pjb.0.canary-gmail;
 Fri, 14 May 2021 01:29:35 -0700 (PDT)
X-Received: by 2002:a17:90b:1a8b:: with SMTP id ng11mr10070263pjb.93.1620980975149;
        Fri, 14 May 2021 01:29:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620980975; cv=none;
        d=google.com; s=arc-20160816;
        b=jjANwjn+Tpw0sH7oCSQZuu3P9ZxeyNubYxDp0pbeEzxugaHEkPjoG5E9oKTiaeOmvu
         ZaocVGe6n1iJ6bIn0/mkkAtVujXtaNbWxfLoKXtwuy1BoLYg3FlAwUECa2mZFpSUBtEr
         F6ufbE86quKx7qI3Fn6DuH1uTKNQArh0fKyi/lDgVaM282lEX8WiSxKVsXJGtlnVvSu7
         gTrtQRBdqLg52jsj9ITXeRCRC4DAiI+BaeaaXzz0hq3DNu2UaGUGSetKqpLF2FnfaFjE
         YZ/MMsVDTHBOH0g89/acMbeksPFaIDEgNj6cLCG+sQd5XYFaOhSPqGgS8X/Or6tiz46k
         9BOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wHKQimufe36GZAoSWRyX4k4H4frZrX9SuQly5dKgZdw=;
        b=un+npr1ze5AlD/+rB5mijzVpwZr3M0TyR7AtO1s5wqjQQJmfENo2hPYkh8eXzzm979
         0cuNQO40ZlqiWb/rC+vh2W14bA3nL3Gltjru3MMEGXvBKA3dT4C1fN+OVxrWqdIvZZvm
         pA/hNIwifFomI6m/mNNIDdWCIeTwJhwqUY7jwduKYHcXWmplqUGVmVZ6++bxH51DyTxo
         eHzAZsiVBwfMya46IuLjL4KqWjKmfM261l8z16s/7awu3U86Q+j8FU7XtMQ02/ujfJQG
         nydEQocM6q4iarqnyWHQpVdwUacF4B9LhDQ3GeiKoqRS8J1o57bpRLwyiSMebtBBjTGx
         lEWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.23 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from r3-23.sinamail.sina.com.cn (r3-23.sinamail.sina.com.cn. [202.108.3.23])
        by gmr-mx.google.com with SMTP id f1si413638plt.3.2021.05.14.01.29.34
        for <kasan-dev@googlegroups.com>;
        Fri, 14 May 2021 01:29:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.23 as permitted sender) client-ip=202.108.3.23;
Received: from unknown (HELO localhost.localdomain)([221.199.207.227])
	by sina.com (172.16.97.23) with ESMTP
	id 609E34E4000152A0; Fri, 14 May 2021 16:29:26 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 36650854920200
From: Hillf Danton <hdanton@sina.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Manfred Spraul <manfred@colorfullife.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>,
	1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Date: Fri, 14 May 2021 16:29:18 +0800
Message-Id: <20210514082918.971-1-hdanton@sina.com>
In-Reply-To: <20210513220127.GA3511242@paulmck-ThinkPad-P17-Gen-1>
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com> <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1> <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com> <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.23 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
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

On Thu, 13 May 2021 15:01:27 Paul E. McKenney wrote:
>On Thu, May 13, 2021 at 12:02:01PM -0700, Paul E. McKenney wrote:
>> On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
>> > Hi Paul,
>> >=20
>> > On 5/12/21 10:17 PM, Paul E. McKenney wrote:
>> > > On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
>> > > > [...]
>> > > > sma->use_global_lock is evaluated in sem_lock() twice:
>> > > >=20
>> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial chec=
k for use_global_lock. Just an optimization,
>> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, =
no memory barrier.
>> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> > > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global=
_lock) {
>> > > > Both sides of the if-clause handle possible data races.
>> > > >=20
>> > > > Is
>> > > >=20
>> > > >  =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
>> > > >=20
>> > > > the correct thing to suppress the warning?
>> > > Most likely READ_ONCE() rather than data_race(), but please see
>> > > the end of this message.
>> >=20
>> > Based on the document, I would say data_race() is sufficient:
>> >=20
>> > I have replaced the code with "if (jiffies %2)", and it runs fine.
>>=20
>> OK, but please note that "jiffies" is marked volatile, which prevents th=
e
>> compiler from fusing loads.  You just happen to be OK in this particular
>> case, as described below.  Use of the "jiffies_64" non-volatile synonym
>> for "jiffies" is better for this sort of checking.  But even so, just
>> because a particular version of a particular compiler refrains from
>> fusing loads in a particular situation does not mean that all future
>> versions of all future compilers will behave so nicely.
>>=20
>> Again, you are OK in this particular situation, as described below.
>>=20
>> > Thus I don't see which evil things a compiler could do, ... .
>>=20
>> Fair enough, and your example is covered by the section "Reads Feeding
>> Into Error-Tolerant Heuristics".  The worst that the compiler can do is
>> to force an unnecessary acquisition of the global lock.
>>=20
>> This cannot cause incorrect execution, but could results in poor
>> scalability.  This could be a problem is load fusing were possible, that
>> is, if successes calls to this function were inlined and the compiler
>> just reused the value initially loaded.
>>=20
>> The reason that load fusing cannot happen in this case is that the
>> load is immediately followed by a lock acquisition, which implies a
>> barrier(), which prevents the compiler from fusing loads on opposite
>> sides of that barrier().
>>=20
>> > [...]
>> >=20
>> > Does tools/memory-model/Documentation/access-marking.txt, shown below,
>> > > help?
>> > >=20
>> > [...]
>> > > 	int foo;
>> > > 	DEFINE_RWLOCK(foo_rwlock);
>> > >=20
>> > > 	void update_foo(int newval)
>> > > 	{
>> > > 		write_lock(&foo_rwlock);
>> > > 		foo =3D newval;
>> > > 		do_something(newval);
>> > > 		write_unlock(&foo_rwlock);
>> > > 	}
>> > >=20
>> > > 	int read_foo(void)
>> > > 	{
>> > > 		int ret;
>> > >=20
>> > > 		read_lock(&foo_rwlock);
>> > > 		do_something_else();
>> > > 		ret =3D foo;
>> > > 		read_unlock(&foo_rwlock);
>> > > 		return ret;
>> > > 	}
>> > >=20
>> > > 	int read_foo_diagnostic(void)
>> > > 	{
>> > > 		return data_race(foo);
>> > > 	}
>> >=20
>> > The text didn't help, the example has helped:
>> >=20
>> > It was not clear to me if I have to use data_race() both on the read a=
nd the
>> > write side, or only on one side.
>> >=20
>> > Based on this example: plain C may be paired with data_race(), there i=
s no
>> > need to mark both sides.
>>=20
>> Actually, you just demonstrated that this example is quite misleading.
>> That data_race() works only because the read is for diagnostic
>> purposes.  I am queuing a commit with your Reported-by that makes
>> read_foo_diagnostic() just do a pr_info(), like this:
>>=20
>> 	void read_foo_diagnostic(void)
>> 	{
>> 		pr_info("Current value of foo: %d\n", data_race(foo));
>> 	}
>>=20
>> So thank you for that!
>
>And please see below for an example better illustrating your use case.
>Anything messed up or missing?
>
>							Thanx, Paul
>
>------------------------------------------------------------------------
>
>commit b4287410ee93109501defc4695ccc29144e8f3a3
>Author: Paul E. McKenney <paulmck@kernel.org>
>Date:   Thu May 13 14:54:58 2021 -0700
>
>    tools/memory-model: Add example for heuristic lockless reads
>   =20
>    This commit adds example code for heuristic lockless reads, based loos=
ely
>    on the sem_lock() and sem_unlock() functions.
>   =20
>    Reported-by: Manfred Spraul <manfred@colorfullife.com>
>    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>
>diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/m=
emory-model/Documentation/access-marking.txt
>index 58bff2619876..e4a20ebf565d 100644
>--- a/tools/memory-model/Documentation/access-marking.txt
>+++ b/tools/memory-model/Documentation/access-marking.txt
>@@ -319,6 +319,98 @@ of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN to=
 check for a buggy
> concurrent lockless write.
>=20
>=20
>+Lock-Protected Writes With Heuristic Lockless Reads
>+---------------------------------------------------
>+
>+For another example, suppose that the code can normally make use of
>+a per-data-structure lock, but there are times when a global lock is
>+required.  These times are indicated via a global flag.  The code might
>+look as follows, and is based loosely on sem_lock() and sem_unlock():
>+
>+	bool global_flag;
>+	DEFINE_SPINLOCK(global_lock);
>+	struct foo {
>+		spinlock_t f_lock;
>+		int f_data;
>+	};
>+
>+	/* All foo structures are in the following array. */
>+	int nfoo;
>+	struct foo *foo_array;
>+
>+	void do_something_locked(struct foo *fp)
>+	{
>+		/* IMPORTANT: Heuristic plus spin_lock()! */
>+		if (!data_race(global_flag)) {
>+			spin_lock(&fp->f_lock);
>+			if (!smp_load_acquire(&global_flag)) {
>+				do_something(fp);
>+				spin_unlock(&fp->f_lock);
>+				return;
>+			}
>+			spin_unlock(&fp->f_lock);
>+		}
>+		spin_lock(&global_flag);
>+		/* Lock held, thus global flag cannot change. */
>+		if (!global_flag) {
>+			spin_lock(&fp->f_lock);
>+			spin_unlock(&global_flag);
>+		}
>+		do_something(fp);
>+		if (global_flag)

The global flag may change without global lock held - we will likely have t=
he
wrong lock released if we can see the change.

>+			spin_unlock(&global_flag);
>+		else
>+			spin_lock(&fp->f_lock);
>+	}
>+
>+	void begin_global(void)
>+	{
>+		int i;
>+
>+		spin_lock(&global_flag);
>+		WRITE_ONCE(global_flag, true);
>+		for (i =3D 0; i < nfoo; i++) {
>+			/* Wait for pre-existing local locks. */
>+			spin_lock(&fp->f_lock);
>+			spin_unlock(&fp->f_lock);
>+		}
>+		spin_unlock(&global_flag);
>+	}
>+
>+	void end_global(void)
>+	{
>+		spin_lock(&global_flag);
>+		smp_store_release(&global_flag, false);
>+		/* Pre-existing global lock acquisitions will recheck. */
>+		spin_unlock(&global_flag);
>+	}
>+
>+All code paths leading from the do_something_locked() function's first
>+read from global_flag acquire a lock, so endless load fusing cannot
>+happen.
>+
>+If the value read from global_flag is true, then global_flag is rechecked
>+while holding global_lock, which prevents global_flag from changing.
>+If this recheck finds that global_flag is now false, the acquisition
>+of ->f_lock prior to the release of global_lock will result in any subseq=
uent
>+begin_global() invocation waiting to acquire ->f_lock.
>+
>+On the other hand, if the value read from global_flag is false, then
>+global_flag, then rechecking under ->f_lock combined with synchronization
>+with begin_global() guarantees than any erroneous read will cause the
>+do_something_locked() function's first do_something() invocation to happe=
n
>+before begin_global() returns.  The combination of the smp_load_acquire()
>+in do_something_locked() and the smp_store_release() in end_global()
>+guarantees that either the do_something_locked() function's first
>+do_something() invocation happens after the call to end_global() or that
>+do_something_locked() acquires global_lock() and rechecks under the lock.
>+
>+For this to work, only those foo structures in foo_array[] may be
>+passed to do_something_locked().  The reason for this is that the
>+synchronization with begin_global() relies on momentarily locking each
>+and every foo structure.
>+
>+
> Lockless Reads and Writes
> -------------------------
>=20
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210514082918.971-1-hdanton%40sina.com.
