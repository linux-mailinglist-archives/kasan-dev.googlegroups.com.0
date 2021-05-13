Return-Path: <kasan-dev+bncBCJZRXGY5YJBBK7P6WCAMGQEC2SCZ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 73C3137FDC0
	for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 21:02:04 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id b199-20020acafdd00000b02901eb1302ea4asf8884120oii.7
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 12:02:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620932523; cv=pass;
        d=google.com; s=arc-20160816;
        b=0aR3ve4WKkEaZFEz/Cl93QMAOi3QGvml3+EWzmUNmu8nR3jo/C+cjPDu+MQgQi/ffE
         JHPzB6KhKET79StAc3P7vVIZNvu7G/tx0CMNPoyK64HGP0Xtt4srCUa0l4hUCkhoXZUY
         7XL+elkN3DTML3/aIK2RPvU7uU6uzzqnP6FhK7PVZ3U7YLf8jDeLf9bQiS/SlQpoLarU
         15VS+YgncnLSfD5/F42VnZLDT/oDDo1cYVh4lCa84smcNLBW4exe76nERug/qsVyGCao
         H+F2SEEZDtPplTKMB1X5THmqqM7jLzVUArew/bAvR1qmMXLs/2J9zYgatlP0k9FqP9CW
         MOow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hdIa5fCdZoxQDaLDtApav7i+7eAPDPXX6AZzVIgBsk0=;
        b=yxbCRUj5Tin77p3N2Zsh1x8xbpCdLZFvSx8mj+xdPK6Ki1t3LvPPL9ufp9ROdhwHYO
         bnDu0hHkmON9zsXprOO5Im8fmynhMdPPz/HMLZ/H67iwKyy5ZYyI4zCHtfEm0f50YdUk
         xtvblhV/CnRbzzy4coeACaPe17AAMWBGBoUQzW2QcPXLPGsPWToEcPaRE4O/ZTg4G7u3
         tGXGwsfIpkAVlJwaicNjC9agfO6Zk9izK7ncXqD2UetSsPdy1U1SUgrkX+K2GLADnGHY
         fs+9PietZseXgh6V+q3dNXk8EeqOUBw8SjWbSuiA7iIzpWwFPjM9Gp0XpETMnEQcoEW+
         9BTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jrrQTre9;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hdIa5fCdZoxQDaLDtApav7i+7eAPDPXX6AZzVIgBsk0=;
        b=Bjcyx3UQLuo2N2GUW4pzlfAssUmwBnyfvzNldtsncI3LmASMMxZIgkWAOp0JDaPgNi
         Ndww6uwQYKbCubGyJwt49fhwba4vgi6wyIkayQ+4UGucXuBvvPQd3K+GG5xusHPcn+6V
         /bY59+fSKQ4YB+t+b57Rq3Ka1Z7Co9Z5tn5H38f5RsQv+mATaD6zrdZjj4wPXHuDkxhO
         Ht+BGAxL4DoRGTyf7h65ePQ4Q/J8jmTny0jOHBBqOpqvZgGfCoc7b6KGtFO19cw3EW4c
         xuXHI87sBl+RqvdIZBEe50jmgrVy1uMcSs2iqI/rgM7q46xGFXg/oCwddHzcT5+nxmT0
         cfQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hdIa5fCdZoxQDaLDtApav7i+7eAPDPXX6AZzVIgBsk0=;
        b=ZGjpOJE2lIDr+DjcYprgomfQgjQ2tXIZMZ+HtXoAoU71kdyG3KiVpHa464hZuTWdOo
         8kjNJdSZixO27cVxJRuUvOAA78EOq/FKZNLUmnpPj+YykUzhQfdpqxplp3cIYy0rrBOk
         VrkxRQnmxmdj9JCe0Eg99sIoK6FElxVDxKDyvSPwvzx5CvKsvBKlThIcSLEGdQwU+A6J
         gCIlFt2s5KzWXLRi1eXyeVs/+B4UYVCZcirslSJ4+ZXgS4aVEyJmZGTJgBrT/fT9hEFv
         NdY8t/a4oUjbr4xQ6ivPUtJVvYuIi8LiNgAN7GUOBTvUq6b5m9AIqZIzEJtVGo0yduu5
         FLCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319QlXzgWUqcpo9D40cdD39Grjncnq2bbzp+c9hRCKtueRc/rMj
	5h7i68BbgLNyhcIW4+lBcfc=
X-Google-Smtp-Source: ABdhPJwDpFNPl2cMbtxYugWpX0a/cMQ3xkC1PbSlvLMWh5P0F+1LVn0ha1/Sp/QGpt3UxF6Fm9br9w==
X-Received: by 2002:aca:dd86:: with SMTP id u128mr30454496oig.155.1620932523188;
        Thu, 13 May 2021 12:02:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7858:: with SMTP id c24ls1968592otm.6.gmail; Thu, 13 May
 2021 12:02:02 -0700 (PDT)
X-Received: by 2002:a9d:5a12:: with SMTP id v18mr10285944oth.306.1620932522809;
        Thu, 13 May 2021 12:02:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620932522; cv=none;
        d=google.com; s=arc-20160816;
        b=DgGh/5Ehk0HdGc5F722f7zNMvxzVOZfjDFwOgdfZk4XnNVfpLMaXEQckXSiyFp3A6K
         hyAX5anwxD/nxCPx8bRWtGMTbgaV6BMsIzflqrJIwkmQNF/hXOzEdAn5VS9t06lxH0kx
         G3A+Jftt5iqG5giYdWiggkJtc38dYYCaFfmDDcSkSDsy/xFmdD9f56d3l3g64r456jXi
         pmerydHHRZ3XhRfPUlHkIB84NjbaJTj2Kupkc5wwOLXT/4oXo1orxGHphphPZo777Onf
         ybI8+Cf4yjG7/YuhVkTxRtUaPF50AIuy4IF5LU1xj+IvdO1z4ryPKg1Em7xgheO+Hiov
         cd0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nv+nZ3Td+iQYudW3cnDXvrRRapWm5r+TKn1jbqR3yqU=;
        b=bJuCRSTxP2JANwMPSZWJ5/ozRXoaDeI6r0gK2yLNPpe8l4oLTHL2wxpyK8z2HnBaWN
         H5WwhKyhwCGDVcdewOK/M5lxKeOGfszK66GNPDekgMed4zTYhjA7qDs3e1CXmYDB1Jgn
         TP3v1Q1U/eulkHfvrppm8C2tw+jCGTKf5DRclMe/jsaoB23OhjN+gztQ+szj2NHDOUx5
         ahaGxtIs4c+fetJj/qpZ1sxbfyUQRh1N8lWgCfTS0G5+HczptjB6L9t2Qd4wRQu8uXZn
         K0ULPjQxsDFubpD8M6vXI9AsGFTOKWuk+HpFrthkh5uDOioLuI2o/KAayOvtI5HOt4p0
         8IaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jrrQTre9;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 4si330310oiy.5.2021.05.13.12.02.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 May 2021 12:02:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0614E61177;
	Thu, 13 May 2021 19:02:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id C42415C036A; Thu, 13 May 2021 12:02:01 -0700 (PDT)
Date: Thu, 13 May 2021 12:02:01 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jrrQTre9;       spf=pass
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

On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> Hi Paul,
>=20
> On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> > On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
> > > [...]
> > > sma->use_global_lock is evaluated in sem_lock() twice:
> > >=20
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial check f=
or use_global_lock. Just an optimization,
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, no =
memory barrier.
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lo=
ck) {
> > > Both sides of the if-clause handle possible data races.
> > >=20
> > > Is
> > >=20
> > >  =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
> > >=20
> > > the correct thing to suppress the warning?
> > Most likely READ_ONCE() rather than data_race(), but please see
> > the end of this message.
>=20
> Based on the document, I would say data_race() is sufficient:
>=20
> I have replaced the code with "if (jiffies %2)", and it runs fine.

OK, but please note that "jiffies" is marked volatile, which prevents the
compiler from fusing loads.  You just happen to be OK in this particular
case, as described below.  Use of the "jiffies_64" non-volatile synonym
for "jiffies" is better for this sort of checking.  But even so, just
because a particular version of a particular compiler refrains from
fusing loads in a particular situation does not mean that all future
versions of all future compilers will behave so nicely.

Again, you are OK in this particular situation, as described below.

> Thus I don't see which evil things a compiler could do, ... .

Fair enough, and your example is covered by the section "Reads Feeding
Into Error-Tolerant Heuristics".  The worst that the compiler can do is
to force an unnecessary acquisition of the global lock.

This cannot cause incorrect execution, but could results in poor
scalability.  This could be a problem is load fusing were possible, that
is, if successes calls to this function were inlined and the compiler
just reused the value initially loaded.

The reason that load fusing cannot happen in this case is that the
load is immediately followed by a lock acquisition, which implies a
barrier(), which prevents the compiler from fusing loads on opposite
sides of that barrier().

> [...]
>=20
> Does tools/memory-model/Documentation/access-marking.txt, shown below,
> > help?
> >=20
> [...]
> > 	int foo;
> > 	DEFINE_RWLOCK(foo_rwlock);
> >=20
> > 	void update_foo(int newval)
> > 	{
> > 		write_lock(&foo_rwlock);
> > 		foo =3D newval;
> > 		do_something(newval);
> > 		write_unlock(&foo_rwlock);
> > 	}
> >=20
> > 	int read_foo(void)
> > 	{
> > 		int ret;
> >=20
> > 		read_lock(&foo_rwlock);
> > 		do_something_else();
> > 		ret =3D foo;
> > 		read_unlock(&foo_rwlock);
> > 		return ret;
> > 	}
> >=20
> > 	int read_foo_diagnostic(void)
> > 	{
> > 		return data_race(foo);
> > 	}
>=20
> The text didn't help, the example has helped:
>=20
> It was not clear to me if I have to use data_race() both on the read and =
the
> write side, or only on one side.
>=20
> Based on this example: plain C may be paired with data_race(), there is n=
o
> need to mark both sides.

Actually, you just demonstrated that this example is quite misleading.
That data_race() works only because the read is for diagnostic
purposes.  I am queuing a commit with your Reported-by that makes
read_foo_diagnostic() just do a pr_info(), like this:

	void read_foo_diagnostic(void)
	{
		pr_info("Current value of foo: %d\n", data_race(foo));
	}

So thank you for that!

> Attached is a dummy change to ipc/sem.c, where I have added comments to
> every access.

Please see below.

> If data_race() is sufficient, then I think I have understood the rules, a=
nd
> I would recheck ipc/*.c and the netfilter code.
>=20
> --
>=20
> =C2=A0=C2=A0=C2=A0 Manfred
>=20
>=20

> diff --git a/ipc/sem.c b/ipc/sem.c
> index bf534c74293e..6026187f79f8 100644
> --- a/ipc/sem.c
> +++ b/ipc/sem.c
> @@ -87,6 +87,7 @@
>  #include <linux/sched/wake_q.h>
>  #include <linux/nospec.h>
>  #include <linux/rhashtable.h>
> +#include <linux/jiffies.h>
> =20
>  #include <linux/uaccess.h>
>  #include "util.h"
> @@ -336,20 +337,43 @@ static void complexmode_enter(struct sem_array *sma=
)
>  	int i;
>  	struct sem *sem;
> =20
> +	/* caller owns sem_perm.lock -> plain C access */
>  	if (sma->use_global_lock > 0)  {
>  		/*
>  		 * We are already in global lock mode.
>  		 * Nothing to do, just reset the
>  		 * counter until we return to simple mode.
>  		 */
> +		/* a change from a non-zero value to another
> +		 * non-zero value. Plain C is sufficient, as all
> +		 * readers either own sem_perm.lock or are using
> +		 * data_race() or smp_load_acquire().

This is OK, but only because all of the bits are confined to a byte.
If (say) 0x10000 and 0x0ffff were legal values, then store tearing could
result in a momentary zero when switching between them.  There has
been a claim that compilers should not tear stores, but there was
recently one that would do so when storing certain 32-bit constants.
And the standard does not prohibit tearing unmarked loads and stores,
even if all the value are confined to a single byte.  (But a compiler
that tore stores bit-at-a-time would be of questionable value on any of
the architectures that the Linux kernel support.)

> +		 */
>  		sma->use_global_lock =3D USE_GLOBAL_LOCK_HYSTERESIS;
>  		return;
>  	}
> +	/* Question: This pairs with the smp_load_acquire
> +	 * in sem_lock(), in a racy way:
> +	 * The reader in sem_lock() may see the new value
> +	 * immediately, ...
> +	 */
>  	sma->use_global_lock =3D USE_GLOBAL_LOCK_HYSTERESIS;

In my code, I would make this use WRITE_ONCE().  One fewer set of compiler
tricks to worry about.

>  	for (i =3D 0; i < sma->sem_nsems; i++) {
>  		sem =3D &sma->sems[i];
>  		spin_lock(&sem->lock);
> +		/* ..., or much later.
> +		 * But this is the latest possible time:
> +		 * sem_lock() owns one of the sem->lock locks
> +		 * when using smp_load_acquire(). Thus one of the
> +		 * spin_unlock()s in this loop is the _release for
> +		 * the plain C write above.
> +		 * My current understanding: Plain C is correct,
> +		 * as the reader is either using data_race() or
> +		 * smp_load_acquire(), or it is a trivial case
> +		 * of the reader owns sem_perm.lock - and we own
> +		 * that lock all the time.

Yes, once we release a given sem->lock, any future acquisitions of that
lock must see the new value of sma->use_global_lock.  If they get to
their sem->lock before we do, then the above spin_lock() acquisition
will wait for them.  This use of locks is an unusual form of RCU.  ;-)

(Grace-period latencies might be a bit long for actual RCU here.)

> +		 */
>  		spin_unlock(&sem->lock);
>  	}
>  }
> @@ -366,11 +390,21 @@ static void complexmode_tryleave(struct sem_array *=
sma)
>  		 */
>  		return;
>  	}
> +	/* sem_perm.lock owned, and all writes to sma->use_global_lock
> +	 * happen under that lock -> plain C

Other than the smp_store_release()?

> +	 */
>  	if (sma->use_global_lock =3D=3D 1) {
> =20
>  		/* See SEM_BARRIER_1 for purpose/pairing */
>  		smp_store_release(&sma->use_global_lock, 0);
>  	} else {
> +		/* the read side is maked -> plain C.

s/maked/marked/?

> +		 * Question: Old value 4, new value 3.
> +		 * If it might happen that the actual
> +		 * change is 4 -> 0 -> 3 (i.e. first:
> +		 * clear bit 2, then set bits 0&1, then
> +		 * this would break the algorithm.
> +		 * Is therefore WRITE_ONCE() required? */
>  		sma->use_global_lock--;

In my code, I would use WRITE_ONCE() here.

>  	}
>  }
> @@ -412,7 +446,20 @@ static inline int sem_lock(struct sem_array *sma, st=
ruct sembuf *sops,
>  	 * Initial check for use_global_lock. Just an optimization,
>  	 * no locking, no memory barrier.
>  	 */
> -	if (!sma->use_global_lock) {
> +#if 1
> +	/* the code works fine regardless of the returned value
> +	 * -> data_race().
> +	 */
> +	if (!data_race(sma->use_global_lock)) {
> +#else
> +	/* proof of the claim that the code always works:
> +	 * My benchmarks ran fine with this implementation :-)
> +	 */
> +	if (jiffies%2) {

As noted above, use of jiffies_64 would be more convincing because
jiffies is immune from load fusing and jiffies_64 is not.  But this
still does not constitute a proof.  You have instead only shown that a
given version of a given compiler does what you want.  ;-)

> +		pr_info("jiffies mod 2 is 1.\n");
> +	} else {
> +		pr_info("jiffies mod 2 is 0.\n");
> +#endif
>  		/*
>  		 * It appears that no complex operation is around.
>  		 * Acquire the per-semaphore lock.
> @@ -420,6 +467,11 @@ static inline int sem_lock(struct sem_array *sma, st=
ruct sembuf *sops,
>  		spin_lock(&sem->lock);
> =20
>  		/* see SEM_BARRIER_1 for purpose/pairing */
> +		/* sma->use_global_lock is written to with plain C
> +		 * within a spinlock protected region (but: another
> +		 * lock, not the sem->lock that we own). No need
> +		 * for data_race(), as we use smp_load_acquire().
> +		 */
>  		if (!smp_load_acquire(&sma->use_global_lock)) {
>  			/* fast path successful! */
>  			return sops->sem_num;
> @@ -430,6 +482,10 @@ static inline int sem_lock(struct sem_array *sma, st=
ruct sembuf *sops,
>  	/* slow path: acquire the full lock */
>  	ipc_lock_object(&sma->sem_perm);
> =20
> +	/* Trivial case: All writes to sma->use_global_lock happen under
> +	 * sma->sem_perm.lock. We own that lock, thus plain C access is
> +	 * correct.
> +	 */
>  	if (sma->use_global_lock =3D=3D 0) {
>  		/*
>  		 * The use_global_lock mode ended while we waited for

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210513190201.GE975577%40paulmck-ThinkPad-P17-Gen-1.
