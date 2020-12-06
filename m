Return-Path: <kasan-dev+bncBDAMN6NI5EERBSEWWX7AKGQESE4GAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A9ED32D0747
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 22:21:12 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id r5sf4274051ljg.4
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 13:21:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607289672; cv=pass;
        d=google.com; s=arc-20160816;
        b=02j911O5vtap7CZht0mG9R+wBslstP8JSwIT34BJ+l8+PpYFw6WQdfDerHRQzfp7sv
         UyNppushU1bMzCpey4UFz7uEg5nXW/YTszmWrQSEHyty7VGfhHL9B6UtpHFkClR3n+bm
         5QvmgjuKXEhRS2rbOKAKIdVrA/FroF9FNv9GgK52gzAY9+Hfg1grYaEllr8JEm8x+//H
         Bs5Zdqt9oRC8R0vQmhxb7TSHtVawm3PkhPlp3WbhRVPrlBb3ZfGdYq1jGnVGqh8ZT2mZ
         UiVJQpkYhAEkKxVtTeckS/aBcLKW+pbNgr40CX4bNPwTQVEPKMYMo1j9JJrJWcndMnyQ
         9LbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:message-id:sender:dkim-signature;
        bh=L4bUjLI0jpiI9WJAqngbRljGwQs6w3AkxLC6vzYkRB0=;
        b=U8ZkB/yLjV0CDojYKucUh8Gyr8XywId/ttIp7hTqI7P80h9uIpXDziwBY6CWb3Iaty
         DdkosZnvnfM3Czzrhf9QKuddXbxulRU9wtvilBWaDS7f4EIW+K8glqnvya+3M5ZPUGn2
         aW+QV5lv7Un/mDX2cyP88tXhVdavotN/VjnB8MFPPLLj1KZsZgssqYHfq8TQ4O8Rz4fT
         s8302N88BpP1JVqghFpl2lHMBwMBS8J+YM3bR9A6AC1Ei7eOQqLB+PTSWOEa9zXidrk/
         H1cin2+WLTsmD6qGUQMSnKk/mT+FHiEF1J9+RWEpaKd8R8QDD3ZuKBjp7yF9/PrnaoMW
         yvSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=a0xqJ+XK;
       dkim=neutral (no key) header.i=@linutronix.de header.b=ofGJi84Z;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:date:from:to:cc:subject:references:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L4bUjLI0jpiI9WJAqngbRljGwQs6w3AkxLC6vzYkRB0=;
        b=CYbEGgFxOTLSIFceeseijcl4TJ194EZm/UguYHWj7c6vxxbn473wYHvw8n7eSnExy+
         /kwM3A02iratySS3forvkfvvhXQxCMKJF2ZP+4xhgfetM6WedAj73pK4jQJmvmlCZBSR
         1S48HPbJQ87RmTxvMxm5WgvOOWQwoPD/K4+/UPqjfXcWJMdlnSkJLFZxQgglfQRMVIHX
         8UC/dEwodMQ98JlmGN2PY2kS+4XGS6snlKmlPVkFIqrP1Pk9lXjVeQrE7V6BcBW1Ec2N
         wv4/46lrb65XvCKv7jCrPEoOhbmIbbdmQ3qx48uy3PMQrz5ze33EZoQhl9nL3I7v7CO3
         ep6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:date:from:to:cc:subject
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L4bUjLI0jpiI9WJAqngbRljGwQs6w3AkxLC6vzYkRB0=;
        b=V5p6JiTD5S5eOQBsD+UydZBy1K/tx0XSh+0nCCPfmXzjDKEmjQptmvJWjR40A1iIBb
         MaHbSlR77vEf3v0saAmQjGPOaIDaugQ0AekrA6Hx5xQEDjGPkVWpwO0azlRPdopyjScq
         cRr1f2pd4l5Hzqr5+RkMzK8vTpDN2Lf8AeUYq3Bn6cCkLe5cncncjeo0rJF0lZ6DkGRn
         s/ZIpteKyIGT3yKdXksOHeNmPS9sypUf08TpY2bzjaUuOFt+EBIoi0+N9p1mMy23xrET
         9LIhi6BXYEegk60fSTA6U1uynYxZSKxusuuylzqAje/2Iyv9rmiNwWSxMgdPHWzoYTBq
         aLPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XfUxAe6RXrSX+uGDRgATPnMRtZRvY9Oe1Zs045UKIhNszINNY
	7tPJOh49tECPCm5OTV3h6Hw=
X-Google-Smtp-Source: ABdhPJxDuxcN0bc8Pz5yQMx8wOkkiHvHoYSsp8OVOgQGBovB3Wdz89dk0vkGeN/RMVUh35TS//nccw==
X-Received: by 2002:a2e:884f:: with SMTP id z15mr7393622ljj.200.1607289672256;
        Sun, 06 Dec 2020 13:21:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc2a:: with SMTP id b42ls2437593ljf.2.gmail; Sun, 06 Dec
 2020 13:21:11 -0800 (PST)
X-Received: by 2002:a2e:2a46:: with SMTP id q67mr2226729ljq.331.1607289671256;
        Sun, 06 Dec 2020 13:21:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607289671; cv=none;
        d=google.com; s=arc-20160816;
        b=lsO5SA4HduhJQ2V5w+uHVggqHNyhHhNz02JuHbWKNuvZCDN7EtmHlGdA7gjfeBjJfQ
         1JZCt+jeY35oCmDJ0BBEVCpuuldpejUdyBMyNQpZ/N6r8KymLsLAhYH0C/Z4Ls+vSHBx
         q+uYNBbPXxZAGRDsM24gVSqJhQGHm/JvE2EM7Tpakcw9h0U6ti7YVlIJntGe3ANN1VTs
         YPNBAphSt/KTG7EdS2jTPFS9qWTHmfa3SLDsIDl4caus3SXbEqB4oF50sQcr7wJmYTBm
         24UdDlihMPb91ob9YZJB2TvYu0AP1ukYBg49Li6jWWnt7+/2fr+f7jNW+ZIKCy3p14qu
         IN8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:subject:cc:to
         :from:date:dkim-signature:dkim-signature:message-id;
        bh=7uPPJRC0zT+/X3ZhoKFyc0cPV876f8SJt5Y3T/6tcvU=;
        b=g5oZps4bioLSgYTVneqU9E79hcGuhhzV6BBPFPjAMWXCTU5NFJa/KdYXyn4F2HXCxl
         RKS+ZgrY2617X/Inb9ZcS9IM9nkpwYvXlYmdrK6OgrjlyK/DnwrVcLSZl3zB7UPKM9a4
         1Bats+2WCjtga41zmcd4TMrlmjBXiYs1kl6+/WJEXcpzejZ6cb4DMe9QYPFAT3Iksu8g
         PVOMJYZwaWVVPXF2cKbWddmmOFkuQnaB2adwOKhr0wljBUMSkkoaax9K5yyCzuVUABnp
         fOwAY5kKyLlPQyJu3IyLFLHlGnfj3FqtAn4kSBWi5B1ykqRAZfxSZS37+Vost08kjM9D
         92Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=a0xqJ+XK;
       dkim=neutral (no key) header.i=@linutronix.de header.b=ofGJi84Z;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id e18si180790lfn.6.2020.12.06.13.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 13:21:11 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Message-Id: <20201206212002.582579516@linutronix.de>
Date: Sun, 06 Dec 2020 22:12:54 +0100
From: Thomas Gleixner <tglx@linutronix.de>
To: LKML <linux-kernel@vger.kernel.org>
Cc: Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Peter Zijlstra <peterz@infradead.org>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Ingo Molnar <mingo@kernel.org>,
 Frederic Weisbecker <frederic@kernel.org>,
 Will Deacon <will@kernel.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [patch 1/3] tick: Remove pointless cpu valid check in hotplug code
References: <20201206211253.919834182@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=a0xqJ+XK;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=ofGJi84Z;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

tick_handover_do_timer() which is invoked when a CPU is unplugged has a
check for cpumask_first(cpu_online_mask) when it tries to hand over the
tick update duty.

Checking the result of cpumask_first() there is pointless because if the
online mask is empty at this point, then this would be the last CPU in the
system going offline, which is impossible. There is always at least one CPU
remaining. If online mask would be really empty then the timer duty would
be the least of the resulting problems.

Remove the well meant check simply because it is pointless and confusing.

Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
---
 kernel/time/tick-common.c |   10 +++-------
 1 file changed, 3 insertions(+), 7 deletions(-)

--- a/kernel/time/tick-common.c
+++ b/kernel/time/tick-common.c
@@ -407,17 +407,13 @@ EXPORT_SYMBOL_GPL(tick_broadcast_oneshot
 /*
  * Transfer the do_timer job away from a dying cpu.
  *
- * Called with interrupts disabled. Not locking required. If
+ * Called with interrupts disabled. No locking required. If
  * tick_do_timer_cpu is owned by this cpu, nothing can change it.
  */
 void tick_handover_do_timer(void)
 {
-	if (tick_do_timer_cpu == smp_processor_id()) {
-		int cpu = cpumask_first(cpu_online_mask);
-
-		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
-			TICK_DO_TIMER_NONE;
-	}
+	if (tick_do_timer_cpu == smp_processor_id())
+		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
 }
 
 /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201206212002.582579516%40linutronix.de.
