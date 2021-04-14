Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBDEJ3SBQMGQE6OH46PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C89BC35F6F6
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 17:04:44 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id g144-20020a1c20960000b029012983de0c8fsf2183459wmg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 08:04:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618412684; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjnhkSd7zyFGPAij+FRf4B9o/KyZCsONF2s1uEn/Y/iNUvzsdUAyDfop5EUenCm6PC
         CDWqAcK8gzfeLx41hQwb9IFKclooucDC5h37y2oOMxCJOcQw42uCVXf2y9Vo8d5R4qG4
         FW49f5Ke2O640tEoqvCED3bv/gE1nWbZgoC2PQxKvtX1NP2UEi266iHTv/cTya0ARDEy
         S4eYvSAGOlPzVkhnfWTOmN2wJTR5cGicUTpXKtclGtgp/AAJRVEQHJvLU1nByLap+VNF
         b/hno1s8IXaFbegU91J1J1n0wVWSVBFfNHd1G416VGWSjxchc7hKOS2O9HZiTXLNmEr+
         GXrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=psdO0sXrKpkS7VYfJArvNI5XBb+Yvuj0i8ydZzKJd0o=;
        b=PGx7AMdK0KV77pBda1kMtnUWnEdltJHCDCni4cL12WtQoyiFbzS+gOMHJ7O5NNFrlU
         rPlbiR4f7GZWURG+BVlz0kkRluBoTRhlSdaT7V53gOL52ZkGnxzebDKYFvoJ3+GLMLib
         CjUq5s2URi+grPTByiPzmW3IBilJMUOgqnJYZcnyNIdQORE6j9btMtQe0VSX847O/k9s
         WsrXWRxMzd3xEt+n37mBn3kEKb9jCBWewOvR1mJsuyaegVBNYZO/KnHUYwDI7g9Rk+WR
         UJWg2DHH+lqHb8LEUVA2t6n5eaox7KlE4dO8mz2xOnMPRhpoeVRb3av/M79cMCwrVdyj
         Bv3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=hmrwuZQk;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=psdO0sXrKpkS7VYfJArvNI5XBb+Yvuj0i8ydZzKJd0o=;
        b=Egw/RNL1hFDsfUCrL7S2CmHQLirZM0rZNUP9JaVDX94XTI7jAUYv/FTm0c3TuaFSsv
         4BzoL/zqCb88HQdnOPCrL1GALfxavD5XTamiIxbQlqkhz1rEHo80jeAv7iX7rljLpYUD
         hM4KYYmTuF6y7DBN/kC4aL3poO5x5akjxJ1VwoKmW2EATOeOiEaYjE3xLBlnMLOEqn8x
         /J2C9avZZUmqwfWsf9DLl8ADJ2GyN84CBj/2ITnkVmZJ25+/UWyG8mg6KPlohPv5oAar
         f2FnkjWgmJv7JXqKvt2Z9icF139c1a8ZUqtQQ6C59UOe+3Psoule8rXtR4Q7vST/tc4Y
         fv/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=psdO0sXrKpkS7VYfJArvNI5XBb+Yvuj0i8ydZzKJd0o=;
        b=UAoH/ttG3HZW7YUV+Csi3zZmZO2z/hF3g51oIk6dK5u9oANhIhlzzy5wSVB6+4Xb1r
         X3ygTLZFmvBVv3VpSAY9qzWsVrRYCSH3GTFFL6DhWZYwZkqm4YtGfRP94hzkLE5zfCnL
         esDvlt0Dwh7C9tXk60N7e7wQ1mc5c7FIc8R0WLO78XhpDfZMZpyYRkGYC8olWL+PhCoS
         gj5/M1/AdxKSQLtJDFnI48++kwBfJ2BImp3gbNoeDwiDPglxHANtPK2ZBXbOFmGlXmeB
         4Rmy7V9P++5GLJCJhVEyA5UjC8Zw9pFY652JxuxA6KGtlj2cmep86U9QEyiQfVtoQOmz
         mb/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bVs2vgRacjjgymMtMVXKlNFMM2NFOaBvFgT+UvABOoLPQpmas
	7Puz1jD+Er6oKlNtPNPREMQ=
X-Google-Smtp-Source: ABdhPJyG33vDAkXCfxeAZVfvF20TVvHvMiRScH/fycmQesOTimFQjwRf9et/xbbxyhlWanaJ73oFSA==
X-Received: by 2002:a05:600c:1913:: with SMTP id j19mr3450750wmq.155.1618412684618;
        Wed, 14 Apr 2021 08:04:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6c6a:: with SMTP id r10ls3325203wrz.0.gmail; Wed, 14 Apr
 2021 08:04:43 -0700 (PDT)
X-Received: by 2002:adf:bbd2:: with SMTP id z18mr18784357wrg.274.1618412683646;
        Wed, 14 Apr 2021 08:04:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618412683; cv=none;
        d=google.com; s=arc-20160816;
        b=BEm75sFSCdlS5LQ9hrTKCVZ1XCPevewLHaCY6UCaj7BQOqABBg9N6z+TEpbzXvC9Fj
         ZJ7h7DRGB0kOtQaCklKERZTbScWCZI2QJp4Ilzp6nRS1RyW3HuOEPzUg3I/yfYhbgidh
         /fNv2R6LJtL/v1wfCflEpeWol43QPp9FYcByPVObOmxbLJLcDjjfQkl6TVRAoZXiXQGG
         ExNm2uly4GmPca/Arje/X4P38NkEHpNU86/IccIjbYwTmn32vCQnxFwLRmss5bzNU8uS
         8Qm1SX04JIeIvdNAC84pBrNGWXemd46wf+8wQDfY+RWKfwE7S7/dedMpIWEAe4ljEA3m
         yYMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=CLzED8cPUxWBj4mgVohetuMPg5cTfFdErUO36DuW6sc=;
        b=yJvQvuEqra9Z2x+pqpoI+Hk5rlSItKdA6pAw/YBcwSv6nu4cqmZEz5xjOBDx6Op2vZ
         Pzj3KsJqn35zvbXh7t+vQW2/UBbk+VTPPN3Pe5kAPTw5310nTSjYSY3zpMj2lRJO0Di9
         gRCvYVqzm3k3KEu1oB6+RahGMMP+NHoD2Uc6S4rnggGcij9IMJft6gb0+6bAj7fKXbqh
         DH3XjZaHpTckk3omIgcbSQfDXSse1YMoB4TcF20X7vG+GynbK3Kf4KY8cwgKaksBqhQv
         /YbB3WW9mlSZJL3F94VupQxd24YEk6/1ifBVaHaXe4dXm54Zh59NEPaFRy/Kbx6K8k9u
         1DGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=hmrwuZQk;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id s8si1459991wrn.5.2021.04.14.08.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Apr 2021 08:04:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([185.191.216.50]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1Mwfai-1llmDK2ENW-00y5VZ; Wed, 14
 Apr 2021 17:04:40 +0200
Message-ID: <93866b6a806c268df14913e8d6c0ba185f4e11c7.camel@gmx.de>
Subject: [patch] kasan: make it RT aware
From: Mike Galbraith <efault@gmx.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Zhang, Qiang" <Qiang.Zhang@windriver.com>, Andrew Halaney
	 <ahalaney@redhat.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"ryabinin.a.a@gmail.com"
	 <ryabinin.a.a@gmail.com>, "akpm@linux-foundation.org"
	 <akpm@linux-foundation.org>, "linux-kernel@vger.kernel.org"
	 <linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	 <kasan-dev@googlegroups.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Sebastian Andrzej Siewior
	 <bigeasy@linutronix.de>
Date: Wed, 14 Apr 2021 17:04:39 +0200
In-Reply-To: <a262b57875cf894020df9b3aa84030e2080ad187.camel@gmx.de>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
	 <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
	 <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
	 <a262b57875cf894020df9b3aa84030e2080ad187.camel@gmx.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4
MIME-Version: 1.0
X-Provags-ID: V03:K1:v4AF15jsMquPNwP71BBtMvBL2S3DM0fJv36yORspF23isyW0veC
 zq23O93ELziAEOR4YXDVGBYhj4kr7uSJMeRcLxOHfWskuObzLQz+FxQUl3my2Zxxm31b5FT
 C0CAIgWJ4sxCKJGfCEeErix8YQDPgE6aWKzySblCXpARDmiKH9KHbm31PU5XlkV20UCC4zN
 bZnS0X9FHd6Jvo0VHsS6w==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:9qJGXrM1lRw=:zMdnu4jfn5Rpaw7gNViAeD
 uyQhgNTpfq2r2Z+qKGeh4+4mrp2nUiNn3DevGtDKmWbvzM3xa3dC5vbwu1GYw5WGyW4PCHVYZ
 bbjqFXY/sec+zOqih6KBaeY0mVrL3LR8gVO7iP5XFO63/yu1ZKf786qkXcQVUsylhwcFaMq3H
 aJyCRXSvo2G3QIvbaRvkViL8IearBu/sIzFs90bTXPBut9V4Im3KW6xaDEkOXdjUnuLbzgAM8
 TXaRduIzYLgacUEdmqsh4zN2K6i3es3it/GQrQ+KU/x3wiR7uhwQA8sXbP6Q3a7ec/To3Qj43
 AttdaZe6j1frNMU5ekpXxn9t9coh1SrjVGd6Xpr7O3VoV1uGwtOvlAqJQM8XvJ+o9RFqHWZTS
 gvr93Qhpgp5tRJZv7cMuKBtQzV7MW33Cuev+AINj/Iz/9gcp0OC8BcOkKesv/8c3ICwUERJZ3
 XJJWbnwn+dIAPhrPxi7p7BG7DslziK25WmfV9GmC/zVdJ45e7nQVTAOpWSzuHuW9H9xfQtkbh
 VJ18+uXYcr4J3nc4MddjH05tclxTl3AmCeRt12CXXpYhS3LHTr+a/jLP+UGKYDdhXYeZ1eFTu
 lNdCrwG6lFUTtZiuOa5q34pWN5GdRBedZdgs9N90DhPckb2jPJRyKjAETHCmRVeT2sJ8urWqL
 XsVRM80vDeabTsyVhCXlET95PfxNWVWAD6fTikvzy6Pz4+RWaz8xvT8lfopceoQ9D/+yQ7yIn
 H5GPTbDzx5TJ/ZbSQmsjrZj2g3MBERgrNlPic00BgBREfkMtFpKGmTti3tKo19j5YEvsZ4+PX
 Rpy+XxT8SAEao8ZlgoUtTRc8J9o1X1vR67Z3elsUUimp3cfRU+QBxtzzStXIP0K8lAMAOAgIW
 RzxFnHERcAkF1YDQV23e4g/NyXZ4rC3QTdG0qhyPQ0m/JExkXlIdsCEzZzX79qQFOzRLEBjgq
 fZkkfWuT8gzrUdHA39RHwiphP1eDx56HHZEQL+5wwiGtLWUDZ5CCTKSRiytHetx1ffhdwBKOG
 Rndg6vy6kW6FnCdVxA+ig7pZNFGjMDqUAjdeq5MS7dBtWw/wLCo0V8rGmRa+Jh8Duor0DTI8G
 RC2hmNLWv1OOJpA4rSsAlLwroeb2fpcoFNhE4iYkV1gwQrF0WWmRZadKE7O1pvxKKigx31wVi
 PTxkDymu77c1p63sckwIS+VZAxGRF6n5umHbij9BsaG+84QII6AUnS5bHsGbfCJw4V0hY=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=hmrwuZQk;       spf=pass
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

On Wed, 2021-04-14 at 08:15 +0200, Mike Galbraith wrote:
> On Wed, 2021-04-14 at 07:26 +0200, Dmitry Vyukov wrote:
> > On Wed, Apr 14, 2021 at 6:00 AM Mike Galbraith <efault@gmx.de> wrote:
> >
> > > [    0.692437] BUG: sleeping function called from invalid context at kernel/locking/rtmutex.c:943
> > > [    0.692439] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper/0
> > > [    0.692442] Preemption disabled at:
> > > [    0.692443] [<ffffffff811a1510>] on_each_cpu_cond_mask+0x30/0xb0
> > > [    0.692451] CPU: 5 PID: 1 Comm: swapper/0 Not tainted 5.12.0.g2afefec-tip-rt #5
> > > [    0.692454] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 09/23/2013
> > > [    0.692456] Call Trace:
> > > [    0.692458]  ? on_each_cpu_cond_mask+0x30/0xb0
> > > [    0.692462]  dump_stack+0x8a/0xb5
> > > [    0.692467]  ___might_sleep.cold+0xfe/0x112
> > > [    0.692471]  rt_spin_lock+0x1c/0x60
> >
> > HI Mike,
> >
> > If freeing pages from smp_call_function is not OK, then perhaps we
> > need just to collect the objects to be freed to the task/CPU that
> > executes kasan_quarantine_remove_cache and it will free them (we know
> > it can free objects).
>
> Yeah, RT will have to shove freeing into preemptible context.

There's a very similar problem addressed in the RT patch set, so I used
the free samples on top of your *very* convenient hint that pesky
preallocation is optional, to seemingly make KASAN a happy RT camper.
Dunno if RT maintainers would prefer something like this over simply
disabling KASAN for RT configs, but what the heck, I'll show it.

kasan: make it RT aware

Skip preallocation when not possible for RT, and move cache removal
from IPI to synchronous work.

Signed-off-by: Mike Galbraith <efault@gmx.de>
---
 lib/stackdepot.c      |   10 +++++-----
 mm/kasan/quarantine.c |   49 +++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 54 insertions(+), 5 deletions(-)

--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -71,7 +71,7 @@ static void *stack_slabs[STACK_ALLOC_MAX
 static int depot_index;
 static int next_slab_inited;
 static size_t depot_offset;
-static DEFINE_SPINLOCK(depot_lock);
+static DEFINE_RAW_SPINLOCK(depot_lock);

 static bool init_stack_slab(void **prealloc)
 {
@@ -265,7 +265,7 @@ depot_stack_handle_t stack_depot_save(un
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	unsigned long flags;
-	u32 hash;
+	u32 hash, may_prealloc = !IS_ENABLED(CONFIG_PREEMPT_RT) || preemptible();

 	if (unlikely(nr_entries == 0) || stack_depot_disable)
 		goto fast_exit;
@@ -291,7 +291,7 @@ depot_stack_handle_t stack_depot_save(un
 	 * The smp_load_acquire() here pairs with smp_store_release() to
 	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
 	 */
-	if (unlikely(!smp_load_acquire(&next_slab_inited))) {
+	if (unlikely(!smp_load_acquire(&next_slab_inited) && may_prealloc)) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -305,7 +305,7 @@ depot_stack_handle_t stack_depot_save(un
 			prealloc = page_address(page);
 	}

-	spin_lock_irqsave(&depot_lock, flags);
+	raw_spin_lock_irqsave(&depot_lock, flags);

 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -329,7 +329,7 @@ depot_stack_handle_t stack_depot_save(un
 		WARN_ON(!init_stack_slab(&prealloc));
 	}

-	spin_unlock_irqrestore(&depot_lock, flags);
+	raw_spin_unlock_irqrestore(&depot_lock, flags);
 exit:
 	if (prealloc) {
 		/* Nobody used this memory, ok to free it. */
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
@@ -308,6 +311,48 @@ static void per_cpu_remove_cache(void *a
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
+	rcw = container_of(w, struct remove_cache_work, work);
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
+		rcw = &per_cpu(remove_cache_work, cpu);
+		INIT_WORK(&rcw->work, per_cpu_remove_cache_work);
+		rcw->cache = cache;
+		schedule_work_on(cpu, &rcw->work);
+	}
+
+	for_each_online_cpu(cpu) {
+		rcw = &per_cpu(remove_cache_work, cpu);
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
@@ -321,7 +366,11 @@ void kasan_quarantine_remove_cache(struc
 	 * achieves the first goal, while synchronize_srcu() achieves the
 	 * second.
 	 */
+#ifndef CONFIG_PREEMPT_RT
 	on_each_cpu(per_cpu_remove_cache, cache, 1);
+#else
+	per_cpu_remove_caches_sync(cache);
+#endif

 	raw_spin_lock_irqsave(&quarantine_lock, flags);
 	for (i = 0; i < QUARANTINE_BATCHES; i++) {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93866b6a806c268df14913e8d6c0ba185f4e11c7.camel%40gmx.de.
