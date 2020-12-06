Return-Path: <kasan-dev+bncBDAMN6NI5EERBSEWWX7AKGQESE4GAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 140E32D0748
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 22:21:13 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id l5sf3402148wmi.4
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 13:21:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607289672; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmBtsm9NRbziGdw8gUdRGFTb/OyYui2lzmuSGXut8tz09WdcjaXHptoH7pb4Fdq2xq
         /PZRKz1jKyPwP61OsVu1WCAuLnbu8WrTDbhySrCRp0quvXIxc00BXhfoW9dpXFoIRfuz
         eTiEQbLZaihYyfqnW01wg12KNNK7nNKX5Tjw+YGtHsjoZyTmmQiTyljOkbxsDJe/BhQL
         7SYhQ7iQPNXSXdpcnJSgGMy8CZYsnUqaQQQrcj03/aBbETcIh+yn8toK4/BCkYQaFrVn
         agTozKI7+vW3dcG2VJN6WfgLh+t8PAYEu/ZxCSUSE4nkLV7TA23IH5zBBO9YyJJ3Etrk
         81AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:message-id:sender:dkim-signature;
        bh=fkBm1dtuRJLeEwW3FvZcpJ8Z4BaJUT/2bI2UL0bbKhw=;
        b=Fwub0xJM6acump22WsErSLqaRhmSATzcpohdlZ7VQVojDFDMI34DlACF4N4loEtSUZ
         K5jvzKtJyoF24N0xFi1UvcUSbJabewfomTCJg73pAFnviFyIG0WdlPjoSfxSAM/ZK0Gi
         62AcQC3mBksz7pdFinlEwbuuDmhJeWz+VGtWiJ1oXQhQuNgsGqJp/K9NlJr+o8cpskP6
         HXp3zjKP5vBCqvZLKyysE2iIpUIzRh5AnOsF1Aoa4QzgFpPW+1xjEGglsqPTmPsCV6kP
         KJjwQB9IIZl48w2m3holHRcOFml/J5maOpqyE5oWSKhJykAfHZNv30EQXcwRs2E2Xzon
         MIZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=XAlBQC0V;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:date:from:to:cc:subject:references:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fkBm1dtuRJLeEwW3FvZcpJ8Z4BaJUT/2bI2UL0bbKhw=;
        b=nbw7CQrUSqMODIYzooB0MZ73M701tmyjPJwjSuFLl6vlHSD25dv5q2/sqxXI1M9Do8
         FIb2fyMlDJjXmwcoQfbrODNXa8/bGbwPJUI+LXzl7U4sKc4wxltk0FweznkUtjV5/GMj
         5PGyz7G+mGVPeJuVphCw1mWnO/hbs/bUdm5++cvgxgWQyOvCoMisuuxb6mo3lI8rj1is
         Jo+bfjW3U003r3dk1mF6NUjm8AdJ/mcE+DVSUb+OdDS+BFrSaaeBH0bLoPZCKYo1NMP7
         kai/l9tqKa1BycHqexJamQim6yBio78gIFYdy2dHunaBdvHPo9xgwU1pPRn9mPzSiHzx
         rp1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:date:from:to:cc:subject
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fkBm1dtuRJLeEwW3FvZcpJ8Z4BaJUT/2bI2UL0bbKhw=;
        b=hLko9tEBlaL4oDpJ0MKAyd2h8LyrlCG8KbX2+mUnZO3gMYyKwtgGTAStZzaHLqkTxn
         tV3XHJbSCvb4JzSEtK9O8LywU1HdQvHFOmB74KbTu8c3S381zIMATwS2HsF3gWrQfbhR
         Alpbr17CLKmd+ZR0/OYDgKpk01UMLymCfyo9MqVuKU6IrlusJLnSJ7ozIm4Ij3uWU4Lx
         MAsQcBOq61qUHxPxt/ae54SapB/JEXnTOwRFUlj9MsGdo+jI0P308G1P8vAiuZnJkiUm
         vzLvc2KawgwZX7Hv75LUkeYY8NYvc1Fm0j2KZOJSFHPlGzSX6SnU1BPU0ZdlnBRFMlUT
         mAvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530H2cvZMLH9RqXKRCQznzstvTz1TmHZG/NWKxbd6F08QeFQ5tOB
	scsrhOuq37Zc3iHXGj3odv8=
X-Google-Smtp-Source: ABdhPJx0IEfDFS2lAOtfmORatRneoBoYKGZd1RtA078j1rNkFvdBagx2k2pUN+R6lv/EzHfHWy8fCg==
X-Received: by 2002:adf:f1d2:: with SMTP id z18mr17247477wro.244.1607289672804;
        Sun, 06 Dec 2020 13:21:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb0e:: with SMTP id s14ls3182571wrn.2.gmail; Sun, 06 Dec
 2020 13:21:12 -0800 (PST)
X-Received: by 2002:a5d:4b09:: with SMTP id v9mr16650317wrq.394.1607289671917;
        Sun, 06 Dec 2020 13:21:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607289671; cv=none;
        d=google.com; s=arc-20160816;
        b=ylKGGcOvH9HdIIGBLPTfIaC3hxDxFcPovs0EUmdfIAoeMx8C7dv4sH5XwSX4BRZda/
         OSIB+iOfuQOZunQsXnqLZAlVFerx0qjsatzd8hbQu4mKJMUZWpoam8ITRJOABx8kMT+R
         xYL0iMJGx/kKUamyGwQLLUx84VcxyA36RI9/wVY7tXvhuSb1Ze66jYfbBY9a1/FuEWti
         PBSNcr5RvXjSkNNOWribcWsPXdzRw7yce8qmSy3aet76H2EJGH+/Bwetn2jEHg5vEc/3
         T/VO3pnQzqTzDT3B3xLBKdRJpXqy+c91myuNdKKPmGUIKRgDKEGRvCOgblCtHFhwjf4N
         GQmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:subject:cc:to
         :from:date:dkim-signature:dkim-signature:message-id;
        bh=t7MBVP6KYWOxRUlHPQxrH6lEk6drMxmUxnHf4Vx3LVk=;
        b=w48kK7ZqiqGaIdjYu4Qa75IiQ54ZSZJMwE0uoxLbogOfNg4qvwwNjiofIWICkSQIMw
         L7ZaPcarM4Q150UBbn/VNzqmf4qzvEwc4bM9duo+LoVpQZUpfKvE1J/5sT949meJlCeN
         kBLCTA6Z+YifnKt7uZ4piP6PISjN95elU1h/yKarrokiISVV+gHeZcKouHWUfJmg1J2w
         7bvu9Et9feOwLkGCsGfSO+nuhAVszaS7cnD5dvMKJZ/h8ZjU1cLsQncQCSIFRtf99JHH
         zsA98ZmA1GgpYGuFDd2wtM1ZyBprS+LTHXUG0U3eSgJmS5aomn5HXwOxVRIsEC/Ghx5l
         q6Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=XAlBQC0V;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id y187si247082wmd.1.2020.12.06.13.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 13:21:11 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Message-Id: <20201206212002.725238293@linutronix.de>
Date: Sun, 06 Dec 2020 22:12:55 +0100
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
Subject: [patch 2/3] tick/sched: Remove bogus boot "safety" check
References: <20201206211253.919834182@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=XAlBQC0V;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

can_stop_idle_tick() checks whether the do_timer() duty has been taken over
by a CPU on boot. That's silly because the boot CPU always takes over with
the initial clockevent device.

But even if no CPU would have installed a clockevent and taken over the
duty then the question whether the tick on the current CPU can be stopped
or not is moot. In that case the current CPU would have no clockevent
either, so there would be nothing to keep ticking.

Remove it.

Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
---
 kernel/time/tick-sched.c |    7 -------
 1 file changed, 7 deletions(-)
--- a/kernel/time/tick-sched.c
+++ b/kernel/time/tick-sched.c
@@ -941,13 +941,6 @@ static bool can_stop_idle_tick(int cpu,
 		 */
 		if (tick_do_timer_cpu == cpu)
 			return false;
-		/*
-		 * Boot safety: make sure the timekeeping duty has been
-		 * assigned before entering dyntick-idle mode,
-		 * tick_do_timer_cpu is TICK_DO_TIMER_BOOT
-		 */
-		if (unlikely(tick_do_timer_cpu == TICK_DO_TIMER_BOOT))
-			return false;
 
 		/* Should not happen for nohz-full */
 		if (WARN_ON_ONCE(tick_do_timer_cpu == TICK_DO_TIMER_NONE))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201206212002.725238293%40linutronix.de.
