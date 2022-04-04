Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBMWBVOJAMGQEVW5NHCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E01924F147E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Apr 2022 14:12:36 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h11-20020a0565123c8b00b0044b05b775cesf995203lfv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Apr 2022 05:12:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649074355; cv=pass;
        d=google.com; s=arc-20160816;
        b=OsKFGIjri9lU9fq5v0A/sB8Fgipk3Sjq1RUjtQNfAo9W6Cz/V/gpgDaSNqPKjcB+Te
         UPj4+yKIKJ9wfpqH1OHiTxkWCYxw0yaezLExOZIw3g2Yqz0a8dL6/B6VGM4lwEjrjTBW
         BYhEU1btgRLGHZwbJ5eLFT55UTXlChcrTC+cfBwrCtsfVtJM1t1RvCZHTs79bvQmA8ma
         xKY8W9k6TuXFuYJfgPqoonBZh7UfAEvd/5vATwVUm4F5I4ZCJKYpB8BAcC5JLZ/TvoeJ
         LSzzUMCnPPhS0CDy+iYQw93d2slN4Inwq31Ntnu0sNdEFUAEId0O6sXFMsXaL3Q4PiRP
         Tvjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=uBlepErzZtxhq7FrbkJwKUkn2EH46FszppfOEcbV6VU=;
        b=Cx6o1MOrcBtQEzdwKMV+HtMrm5Yl921n5UD5dC5x3f0dFZy6SfGjWvz3pGJGryLmkd
         oIJWGbaH+p9i4Y4imAlxS2PHvsCTpBWYnthfVfh+ND2rcRIjGWLTlZz7ed1dsWQvSd8w
         Ny42jrVgwKJmaBetadSkSYW8XpxJLZEZ7H9eL0Pel8mSo8zU7g4fO0Zpcy5rTuxeSQkH
         QwGmznhOptTZxZMRWdwxJ+NQmnDYCyl9Xx7crL6HBAlVvpa9DV3DYIB8u1uVHDGu4Cv7
         8yj6MNJvKyYpBe3fOX75mGueWPhfD8MTsepOtwTywDcQ+8Vv6qdC7c4+gUneOg9C/ezd
         ZeQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=gBFIptL8;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uBlepErzZtxhq7FrbkJwKUkn2EH46FszppfOEcbV6VU=;
        b=Y2s5fVkBEecdeRWwuUP6FpzDeUtfsMcx4j6cv9zDDk6a+2cCCKpnNmoikc/F54I6pU
         KwR7J/hsmKTfScqk9LPP2Xi1+MZnztUjFLewS5DypkwOaHyZed+8s29lg90PZzCBgaxF
         vdZaqBpVV4OBnIbCUEsAqAgxTFFUUpmw2kVvHmdXi8HSra2rhAkA4ty+g6MoErnQcczr
         Z+ohb4Z0/7h0nuvLHQwwjy2FlRa6Uvy6Gkm4mEXESvFhvhF22oVIl23MCshuVhgNFIe+
         lKhQxH4osbP8AbWLk04oMHcM/Kirffxf1f7dqGoRToOD9ee1h8EY9+2PQayPrNCZT4M6
         Bg1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uBlepErzZtxhq7FrbkJwKUkn2EH46FszppfOEcbV6VU=;
        b=f5bmIjSk+ge1toLVtb8gGjI74kELqNG8o/knyt7YEpm/GDL7pJFvTiVckZ8bO/R5Ej
         DKo2/jlBwsLJ/94VvYl6WJ5gc8QPp3rq0TOeTY7hEP1O3yCD+0B+lI2D6EOEi4n38QZf
         s/sh5KJyBBkyZkI0yfDuC0xlbgOdLOOOvzMLJsLBf8xzfLa+v0Hkw7ryQplD/4IJRT3V
         VJT+oQJa177qNeGs8u7/128k7+KHneFohVelsV7n8olHbQwCD52SWxD8e9hrzvVI3/mC
         9BsfYjl4GUkDolv+RlF2G8r08VciPKzqRDCOgFj49dJVIxQa4KmRu0rqfUPf3+8OYJHW
         X2MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zKY41MI4EyufBD11RFhAewpIhCbAkDKLUg3ARwuYpv52SMv0l
	1A9/7oux04HQL7A2qm5shts=
X-Google-Smtp-Source: ABdhPJzg/wriB+FDcGsKeVL+7d4ICr2W1y7aQrkG4ZBi2o/76N9DYd81jgxYPvFdjk4pNxSOWFz4rg==
X-Received: by 2002:a19:6048:0:b0:44a:219d:6c27 with SMTP id p8-20020a196048000000b0044a219d6c27mr23397266lfk.342.1649074355000;
        Mon, 04 Apr 2022 05:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90ce:0:b0:249:7e33:4f9b with SMTP id o14-20020a2e90ce000000b002497e334f9bls834689ljg.0.gmail;
 Mon, 04 Apr 2022 05:12:33 -0700 (PDT)
X-Received: by 2002:a2e:5318:0:b0:249:8375:81ab with SMTP id h24-20020a2e5318000000b00249837581abmr20481283ljb.243.1649074353845;
        Mon, 04 Apr 2022 05:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649074353; cv=none;
        d=google.com; s=arc-20160816;
        b=jn0Rkr8O613RbmnE1hLLahyzFOYpizQONCWSb+d+T3tBElDSipYjhi5XDjlV+rO5iY
         kv3rSMxIcSr1ooMWloAuvDfUPrg2Nqo65M5CxEpKVmDt/2/eDvlg5jxxm/Ffc+6jNnBO
         ZLXkf5QU6k+3gj58gcvzu2ZHJt/5ZG6/77m3gcWU7akUaAP0MNu0RhKqcno1QIjjraye
         wWFV3//LYyigi2ildcloWUuUAXXhKXyJ8+CSye4NpljPasg2yyCqP2oKqZ/h5pW+ORA0
         LHQJJBVb6N5EfZWc/uotk3Vj5xLZKWhjicMSVbnbg3bqwokkQIhm9JssrsA0DsRQkpmY
         ywEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=XvvJs/1Z3Mj6BB289pQ1sFCYWYOZwN9A4+jhoXHLPXE=;
        b=YN2lkUt5LMzASINUewbbL3A39wMO2ZSdjB/Q8FhTiDPzwjI8GzK21TFE3vk5ZHLj6A
         nP+xDhYWxH7BZXB3pmyxi9Adc011b7xBnyJpNDt+vZpuIkgAi2oZXgWuGaSpUC7rOxgh
         qMXlSyuxPctbdzedSzVGnuAKdzlTFkPSWO/Adk3qgWYYPegGtsFTg80GyCD/wz9wbVGO
         d/4QITx60fLBeNABO1K0jsymUsNNgbDmaK/rfO38Dl8G5CVlYLNKgG2S46c9688LNCeT
         OpOsSJEyavwuyy142h11tmhJHupXd9f12IW9m5Se5bSUB6mTzdiGrtoFUNZlY8az7ATU
         q8Vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=gBFIptL8;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id i15-20020a056512340f00b0044ada592078si369131lfr.6.2022.04.04.05.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Apr 2022 05:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([185.191.216.17]) by mail.gmx.net (mrgmx004
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1Ma20k-1nXxvs3ZbA-00Vy2K; Mon, 04
 Apr 2022 14:12:28 +0200
Message-ID: <dacc7a27f5545714f1f9ab51510e7856d5118b88.camel@gmx.de>
Subject: Re: [PATCH] kasan: Fix sleeping function called from invalid
 context in PREEMPT_RT
From: Mike Galbraith <efault@gmx.de>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Zqiang
	 <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-rt-users@vger.kernel.org
Date: Mon, 04 Apr 2022 14:12:27 +0200
In-Reply-To: <YkbFhgN1jZPTMfnS@linutronix.de>
References: <20220401091006.2100058-1-qiang1.zhang@intel.com>
	 <YkbFhgN1jZPTMfnS@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.4
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:yDD/V6srw+dnsfO45M/ZKWZVHJafFapRqtE2OaaAX2pCN96K+vV
 0vRIAimIchv/3E0kjJ6JluuH/JWs9THUEvij7tCWIeqHvMI2m/P/F1O3L6RyafgGDswHzgY
 Fpp9Y3JDqbBrdh24/cKg1vJ+ynmgcOq5qK2HVVuIGPi2ZHPQOz/+5de1Ws7dD3Sobv9az8Q
 lBYuDXQoDmBFlpaBj3gYQ==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:jqVeMoJBa8M=:6VrjVN+reFOb2M3+bsb2Vr
 zw3JsbCCPcpj5plrSTD1u08IFanf95ogTmH5BnDnfuDwtLQt/752WNoOO7t0n+5Hp6RTuIxvI
 rlQmXLvaUTW3skTKpG1FfzP/NKZ+1m/tN+261ePv26XOZ3AT8r8Gy4hCr3wWQZT+Fo+RF8EjT
 GJ5Fzk48VSdRMOWC7NbtJUQ3TAFPO39W2OsRAsZKRPsqN1o1faZmjlaPZS3pg7dyKuhGjZNZa
 YpMp/U9n+jiy+7VsZuRJT/xfGq9vvWxvCU6R/8XlPaEOgNwh91Qxy+MQWumJH0s6AUdVgQfz3
 CXgSE61bbHlnGFR0JgddC89HP5oC2vIy6z+lRo80IZDlNCeGb7ReKXWZMwqbhnaQ32nxticch
 x7wgr3QgU6YnOm8UT9+UYrkjYUsAP6lFaYLf5SAF9bsMRoIWWWZ0c/EO8iAInzpt1GIojF6tS
 oyH/kTbyKgNnIGM/ijh2TAbt4c1gv9OnsKRbYoyODEUcIn+MyQY94eTnvnLy9aERprEm3QZ4w
 mzKhesiNSm6J6H1/KMERpKM/vnONnk/bpXShZvRbnr+lqaqcsR2lCsmweBk2sEHFFCHihAwnG
 Zva+5Y1E1QOGiHPDe7aescz5xbmegw/u38lzu8bta9mqd/V3cOX8Sd6AQDT1LSQ+X4x36noMr
 KQYLosWHvghA62nOP86EpA9hXFvESRg/Q9NW0T8OHU5ZS/96mfw8+HN62wHR05MdK18R2gpMZ
 gCM0loXqFuu7MYA1Y5fS83p2k7EIkbIgqD9t+I1WyLYgrBv72LvKgzyOjOVZjbm03eTyd1M82
 miElQL7PAbvU6i+5OD2Wym9JjgtzAq5TUAx7262qDGQk/aDTIzQ9cb0Gzib6oPnL9qsYLeh/1
 l8sblzdraT+uxle5ePQL4/SlbBFc8eC6qqNMf6HlRBgY03qJ4jIZhynoDDphOkMTKA57sZrAt
 3f3aNdbCMDhBFRKzYEk8t3lzcFnrULuuj3WVjOPP2C7fALqMZ9xVhgmyEUFzejXhiibMetopJ
 GxAEw9DKqskLanw/uIq7u0SZIOo+sqpLEQvMpV/3D/FSg0xPHkNMkmHNu7jeV7oMAFhMOhKIE
 QNX3FQYEmiW6AI=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=gBFIptL8;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Fri, 2022-04-01 at 11:27 +0200, Sebastian Andrzej Siewior wrote:
> On 2022-04-01 17:10:06 [+0800], Zqiang wrote:
> > BUG: sleeping function called from invalid context at kernel/locking/sp=
inlock_rt.c:46
> > in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper=
/0
> > preempt_count: 1, expected: 0
> > ...........
> > CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.1-rt16-yocto-preempt-rt =
#22
> > Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> > BIOS rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014
> > Call Trace:
> > <TASK>
> > dump_stack_lvl+0x60/0x8c
> > dump_stack+0x10/0x12
> > =C2=A0__might_resched.cold+0x13b/0x173
> > rt_spin_lock+0x5b/0xf0
> > =C2=A0___cache_free+0xa5/0x180
> > qlist_free_all+0x7a/0x160
> > per_cpu_remove_cache+0x5f/0x70
> > smp_call_function_many_cond+0x4c4/0x4f0
> > on_each_cpu_cond_mask+0x49/0xc0
> > kasan_quarantine_remove_cache+0x54/0xf0
> > kasan_cache_shrink+0x9/0x10
> > kmem_cache_shrink+0x13/0x20
> > acpi_os_purge_cache+0xe/0x20
> > acpi_purge_cached_objects+0x21/0x6d
> > acpi_initialize_objects+0x15/0x3b
> > acpi_init+0x130/0x5ba
> > do_one_initcall+0xe5/0x5b0
> > kernel_init_freeable+0x34f/0x3ad
> > kernel_init+0x1e/0x140
> > ret_from_fork+0x22/0x30
> >
> > When the kmem_cache_shrink() be called, the IPI was triggered, the
> > ___cache_free() is called in IPI interrupt context, the local lock
> > or spin lock will be acquired. on PREEMPT_RT kernel, these lock is
> > replaced with sleepbale rt spin lock, so the above problem is triggered=
.
> > fix it by migrating the release action from the IPI interrupt context
> > to the task context on RT kernel.
>
> I haven't seen that while playing with kasan. Is this new?

Don't think so, the rock below was apparently first tossed at 5.12.

---
 lib/stackdepot.c      |    3 +++
 mm/kasan/quarantine.c |   49 +++++++++++++++++++++++++++++++++++++++++++++=
++++
 2 files changed, 52 insertions(+)

--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -375,6 +375,9 @@ depot_stack_handle_t __stack_depot_save(
 	if (found)
 		goto exit;

+	if (IS_ENABLED(CONFIG_PREEMPT_RT) && can_alloc && !preemptible())
+		can_alloc =3D false;
+
 	/*
 	 * Check if the current or the next stack slab need to be initialized.
 	 * If so, allocate the memory - we won't be able to do that under the
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -19,6 +19,9 @@
 #include <linux/srcu.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/cpu.h>
+#include <linux/mutex.h>
+#include <linux/workqueue.h>
 #include <linux/cpuhotplug.h>

 #include "../slab.h"
@@ -319,6 +322,48 @@ static void per_cpu_remove_cache(void *a
 	qlist_free_all(&to_free, cache);
 }

+#ifdef CONFIG_PREEMPT_RT
+struct remove_cache_work {
+	struct work_struct work;
+	struct kmem_cache *cache;
+};
+
+static DEFINE_MUTEX(remove_caches_lock);
+static DEFINE_PER_CPU(struct remove_cache_work, remove_cache_work);
+
+static void per_cpu_remove_cache_work(struct work_struct *w)
+{
+	struct remove_cache_work *rcw;
+
+	rcw =3D container_of(w, struct remove_cache_work, work);
+	per_cpu_remove_cache(rcw->cache);
+}
+
+static void per_cpu_remove_caches_sync(struct kmem_cache *cache)
+{
+	struct remove_cache_work *rcw;
+	unsigned int cpu;
+
+	cpus_read_lock();
+	mutex_lock(&remove_caches_lock);
+
+	for_each_online_cpu(cpu) {
+		rcw =3D &per_cpu(remove_cache_work, cpu);
+		INIT_WORK(&rcw->work, per_cpu_remove_cache_work);
+		rcw->cache =3D cache;
+		schedule_work_on(cpu, &rcw->work);
+	}
+
+	for_each_online_cpu(cpu) {
+		rcw =3D &per_cpu(remove_cache_work, cpu);
+		flush_work(&rcw->work);
+	}
+
+	mutex_unlock(&remove_caches_lock);
+	cpus_read_unlock();
+}
+#endif
+
 /* Free all quarantined objects belonging to cache. */
 void kasan_quarantine_remove_cache(struct kmem_cache *cache)
 {
@@ -332,7 +377,11 @@ void kasan_quarantine_remove_cache(struc
 	 * achieves the first goal, while synchronize_srcu() achieves the
 	 * second.
 	 */
+#ifndef CONFIG_PREEMPT_RT
 	on_each_cpu(per_cpu_remove_cache, cache, 1);
+#else
+	per_cpu_remove_caches_sync(cache);
+#endif

 	raw_spin_lock_irqsave(&quarantine_lock, flags);
 	for (i =3D 0; i < QUARANTINE_BATCHES; i++) {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dacc7a27f5545714f1f9ab51510e7856d5118b88.camel%40gmx.de.
