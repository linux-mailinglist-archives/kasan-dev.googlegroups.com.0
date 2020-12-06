Return-Path: <kasan-dev+bncBDAMN6NI5EERBOM7WX7AKGQE36YWPSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1862F2D076A
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 22:40:10 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id r5sf4512161wma.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 13:40:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607290809; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjbhH+SNrGPY+AMsHFrQXeiUoceUrUwPv57EArurZXF1ZQ14vCwJVGDzZYHLFvFK9T
         QHgqCr3/JzG4OdC9nGvwthHZZpRqIUjs2ZAvIjvUmuvZ47RqI5YaBqq3D0IQ8nSGs5kl
         ZiYgZ5gvmkNlsxPFkhEJPCiF5es2No1QlcSw0FNfRaknFBBkGNOJxU1HfP9JW+st0duA
         OYLJwOjDUDAlu8Yayqq8uMqyDvrNe7u+65tfOrnOQOrwAVD21Wj88Go7yNYsrkQL8Pt5
         7QFfN3htBn/PIymilMDHgxAK9WbWz9G8zNsx4pBY8/iDemWto7/ARdTZXnoPvUWz/OlZ
         Kgqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=stBvTd/zx6RZtTbXIG0SOSE3iVETCVx3i1F6a5fV4xw=;
        b=Pm8+l5HZm2qOOUgN9dUukfyiQmdUrKoj1bcEhm1UB63EbEEAVM+tEPBYn8WHfbp5K6
         j77ZqoBcaZTf1uQFvlfOa9uaVM1ocdSCGts2qhABO+ipEVRwyz80qMf2QdXB56XWoQo6
         N1CsqZ+dJ/AHIfemR8lQcNmH4z5dAF/tT4a1giTWX1EtFRj0+DZ4f4vNvFHs6TzPQrZC
         /XgA2iF225xySgWlb5ILuNKGaiSCuV4zkmZIgr78tccpbcbfs3aUbgKFd5tsPCK34vUx
         t+ItzYqr2HbBpcZJRIt3d7sEnRWkeEjtlQUjWEEyx2n5s3NQEGR1DWowWU4WyEhk3+5j
         COnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ddaiGB9h;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=stBvTd/zx6RZtTbXIG0SOSE3iVETCVx3i1F6a5fV4xw=;
        b=WUGWGwHP8AbSC5sqcOOwZ8vxm4g/1VzTq8TenpqGTdTfVguwbIuwQ4+hbPKhTfIE/j
         CJdfXFl1uYWNQ9T2h7ozE3HRlEPXMY2tUzom1cfh5LiTnjEU/9xKlvXzt8qlY1a5YS8G
         R8Iwge3qedD9lyDtZrT+/1YHelONwYfxl3yy4R7GHz46bTX8985VNRGQJJuWSElixxsH
         Lw+1OjDBoDTu9/u3xhR0CtVyM9ATRJFhfxRX36FAGhd1myri0JBwsJpsPvJFbGV9Q6mD
         tVE1fK/IiXsSXe/zRpvZ499VYo7jt4ZXs9C8WQkFYv01Oh0frWuik7oHkAXTlXKo0VLv
         tnPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=stBvTd/zx6RZtTbXIG0SOSE3iVETCVx3i1F6a5fV4xw=;
        b=e9557/Ypq5Bj2u2Itd1/EG2ptBeJEp8zuzznYlvk708ZbueTxRInIqWu/dfYp7ulhE
         5iOmLDKcgCtZzv9spbLYTGDlbk+oDcXNrcZvnzl20ezD/uGW3URPFQJ7Yuu6C1aBpkxl
         NOkwuvt4PIJX0ufEsZCcszoTd09N9tICG2cirPZPp0feWloXh0lM/rignlVyFEMQylTA
         BvGdblSQj7fnixwKOr1oWCWFlXPIj3qE1RmAt3rSP238Fj7AA8rv/nNaY6f3AvScI2Ha
         wsbVFqSqvVVQh09AhpqTiJWnY4FEY9EVd5bSkOMxANk/Xso5+6HeVXIvjFA6hIRGkgLL
         goug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XmzSxwIskB6T6QSIfGIKpPPHOZmcFKQtdzJmJ9D6v/oYL3bKI
	C/4BEOrMmH7l6EcXTdcwP78=
X-Google-Smtp-Source: ABdhPJzYdlF5PfTvatlPXq3TU2fU+PsipQyyo+Su/r80D8wg7C0AaK82jbG2Cs9HXJUBanENY84v5Q==
X-Received: by 2002:a7b:c841:: with SMTP id c1mr15626526wml.31.1607290809831;
        Sun, 06 Dec 2020 13:40:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbd5:: with SMTP id n21ls7214626wmi.3.gmail; Sun, 06 Dec
 2020 13:40:09 -0800 (PST)
X-Received: by 2002:a1c:a912:: with SMTP id s18mr14963553wme.26.1607290808948;
        Sun, 06 Dec 2020 13:40:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607290808; cv=none;
        d=google.com; s=arc-20160816;
        b=ksBE8cEWXFj1mjkXnHYtpX81Cbbq8Zq3zjNIxtSSsgibgat6EDvNOno7MBuKua2Psx
         DM9Pih3C6i4jEy+loej3GlORBGs17rpCovb/jIH1SaO3QEqKxi5w9Rh8ijTrWLcML+JD
         DgJJ1+jzB1Wanr33drxTUk6oyOc/fQE43/qwJ6Su8C77uJ73ayjrNyCHH1GZ+abPgfOB
         rHjZBX2AyrLCqV0/GQ9YJcTf18RfxOzyoo1QYuYl9lKRunLdqW7Ap5NNitmN4n7rYnVi
         VH9UoWCDRmGy9LhL3I/eK2zg8858BJSHJvV6ZN0jD2T9ORlWq/Rkw8TvFrAtZ9n7l+2W
         8JIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:dkim-signature
         :dkim-signature:from;
        bh=qdBhMtrI0eQa38m0gb5bqhyKq1hVq6WnHTslTr7nFjE=;
        b=tbJPLvSaVI3idTXNjWYQ35Nhh746q7KDXAHuvJroNMFZz4kmpCgfGFQ/mhtRVOc75g
         jnWS2bMHoIj/s/slwr2W1COAnZF9coXH46HMpk1D8Q3uad5QHquv5yiVG0h0jKz3OHGD
         qgSCYBfizam2q7bRJ/D5VuGMeCvDMCCbqYAa1R05ESGkdwji//UxKuVjwJix3pvUpnSw
         p69VHzkkn6iUTnzeK+wEsCXLFjmzdynsJvQB8jXmXwgitpCasPL0E4lZ5HCUHfEXv7NC
         GTr/EJhkIpU8FM8P3K0XATDYhapSF8LWlOB4jX/9a1FHHMOkixxa3OXW4z4PoE+j0SGe
         ag/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ddaiGB9h;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id l3si145020wmg.3.2020.12.06.13.40.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 13:40:08 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: LKML <linux-kernel@vger.kernel.org>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>,Anna-Maria Behnsen <anna-maria@linutronix.de>,Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: timers: Move clearing of base::timer_running under base::lock
Date: Sun, 06 Dec 2020 22:40:07 +0100
Message-ID: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=ddaiGB9h;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

syzbot reported KCSAN data races vs. timer_base::timer_running being set to
NULL without holding base::lock in expire_timers().

This looks innocent and most reads are clearly not problematic but for a
non-RT kernel it's completely irrelevant whether the store happens before
or after taking the lock. For an RT kernel moving the store under the lock
requires an extra unlock/lock pair in the case that there is a waiter for
the timer. But that's not the end of the world and definitely not worth the
trouble of adding boatloads of comments and annotations to the code. Famous
last words...

Reported-by: syzbot+aa7c2385d46c5eba0b89@syzkaller.appspotmail.com
Reported-by: syzbot+abea4558531bae1ba9fe@syzkaller.appspotmail.com
Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
---
 kernel/time/timer.c |    6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

--- a/kernel/time/timer.c
+++ b/kernel/time/timer.c
@@ -1263,8 +1263,10 @@ static inline void timer_base_unlock_exp
 static void timer_sync_wait_running(struct timer_base *base)
 {
 	if (atomic_read(&base->timer_waiters)) {
+		raw_spin_unlock_irq(&base->lock);
 		spin_unlock(&base->expiry_lock);
 		spin_lock(&base->expiry_lock);
+		raw_spin_lock_irq(&base->lock);
 	}
 }
 
@@ -1448,14 +1450,14 @@ static void expire_timers(struct timer_b
 		if (timer->flags & TIMER_IRQSAFE) {
 			raw_spin_unlock(&base->lock);
 			call_timer_fn(timer, fn, baseclk);
-			base->running_timer = NULL;
 			raw_spin_lock(&base->lock);
+			base->running_timer = NULL;
 		} else {
 			raw_spin_unlock_irq(&base->lock);
 			call_timer_fn(timer, fn, baseclk);
+			raw_spin_lock_irq(&base->lock);
 			base->running_timer = NULL;
 			timer_sync_wait_running(base);
-			raw_spin_lock_irq(&base->lock);
 		}
 	}
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lfea7gw8.fsf%40nanos.tec.linutronix.de.
