Return-Path: <kasan-dev+bncBCKLNNXAXYFBBB6T43CAMGQEK5IN4EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DD14B201D1
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:27:53 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-af911fc1751sf287303966b.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:27:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754900873; cv=pass;
        d=google.com; s=arc-20240605;
        b=JZUSm5c5CjjBwXRWAA8dBRA5HyaFs/pnZqsamlqJx6xDnAjgnOYcsWzTRkrWprJjm9
         dRdt/Pr9/Jo/zB7kWmVEfqGakor5U7ZCwfN5CoLumVBKf92e9yTPjc77mMuqbCLupoIF
         rxQUTr+1XIZEd+mTmoVCKivm9iw01Oi9rH+6j8tJA0jrtsR76q9pL8l7EDRINiWLCDBi
         XsYEB9/kmNsjyBGAQ2dt3zpiYwvbvudQdSIYIfkT/ZS0Kt38ews/qV+WHhp/VUthND/Q
         1qCSS3F5SjQjp9BxZ9FuFjWlQHe31vMW4mGG5tKxR6GCkUYptDcRTlXwbHoWDFOmnPiK
         xOWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QMh6Xlw/Zo51oK1uVwMNo/anMjtzOkP28xo6x2/fJZs=;
        fh=DgR+m64W6ORAIkXJ8IwXd+lEUHOhisVW9+5++LglJjE=;
        b=Hizx/Lmlb/8uWXcEIPSQZXjK2o3ns/c3JFF8SGqFDaKWkCgmWGomKh0aapW29VxOfH
         SAA+KeT9k+TWZD7zHmWwRuUmme3bA+00l9z4H1D+UVT26asj+7PKaKeAvKdicAQO3nZV
         ZhlEoyDxUWyKV4cLxWhxqsLudIcoJgws25/Y8vx1i6bSc7iAAg53is+hLDKc8DB6DxE3
         fzoFt2jOp4SmE1j0bi541mlgdYXrlGxFvBA/tFqTFo3OzwGO+qPRPoDh6iBlpvgohPek
         QsSq1YbK66an+9FAkUjcbXOEk/6aUFDV0yU5GHMRB3R5/wBa+feQ+UaeFxvwUrh6lwbo
         fqpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fx7k4uP6;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754900873; x=1755505673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QMh6Xlw/Zo51oK1uVwMNo/anMjtzOkP28xo6x2/fJZs=;
        b=BCZ8NxNxHtJLQsiihcfpRDqPWFyMW5kxAwdRkmFp6Ppx8FltQbU1oKFCyyaJJzCDvW
         12vz14Eggw77PCnkoLb3nsh3E3AM7/9STXuSytq5kdDaE1cQD3OSgFMPmkjeX4n7c2Yg
         F7gMgZc4dqBOKaS6TUSg91ObTLZ0DhUYytK567Bl6ZUZv+e5K5uDmNg8PXfz3KpTKHNR
         +6LQANLFFq8OuX5HYx8G07V0DgopKM4T/Idumr/dQbBS8FAV91fDRxrSJooJJ/bXDWCx
         3Ocu6KI3sf3k3g46uKg4dDGY2ZXtFeQg1CRNsplp21XJVOQi5hjAy80c5BxDr2ilnxtz
         DW2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754900873; x=1755505673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QMh6Xlw/Zo51oK1uVwMNo/anMjtzOkP28xo6x2/fJZs=;
        b=CqUB9COj3aLPoHC5RCeFxudRBfdXQ8PbrbVw6bx/YNlIQbTm21FMdLuURefHBUB/He
         DSdQ/5CwuSgOqUfI/KJYjpVp00sqiE4yLmMWE9t3emH3/4aWLPFuBt0jEHthVGYhfcIg
         MIaV68WM5FuTeQP/CQH4wM6grzNhi3SuEEc8EeveCwyg6Tim35J4obm/GXeKSJIoZB4D
         KIY+Rls3ov7leYGGQrJWMCkvqyHYx9rJDbGzjc95FHVq4172lCtzfIkiI+wqFHu2KND6
         lf0dLf/UT9cEl/xNXzWEHPUOFxxXj0ndwD5H4zKwLa61rOJ5vO8q/e3qsGMIvGgZc1nI
         mHQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnvauqBqjKl9G46YPnjIwyWo0UtKocR25uxGh8RhXO2o9eRzBQAr4/ttvQR0EJbOxLL0N8XQ==@lfdr.de
X-Gm-Message-State: AOJu0YwE507infDGchgnDMpWQJrwob5tRZxOLC0zSI/9Sktaf6u32V77
	kNjgrcJee+uiBkgsSe/tJl54XLlIsDdfwDxUrFLizPrdVPPttpQvQCld
X-Google-Smtp-Source: AGHT+IEMCMZjEIOLIwxN+KPylY3TxmdZvdSBVUbMF/igu3Wp/3DXca0xTA2/OT8B7d3RarWWfOXCig==
X-Received: by 2002:a05:6402:520a:b0:615:2769:88bb with SMTP id 4fb4d7f45d1cf-617e2ea184cmr9205512a12.34.1754900872497;
        Mon, 11 Aug 2025 01:27:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPjhM0RuNullouYUbzMe+m96UDonFD0FhsVNT5gv6ItA==
Received: by 2002:a05:6402:280d:b0:60c:5a6b:2698 with SMTP id
 4fb4d7f45d1cf-617b1c94ec3ls3448686a12.1.-pod-prod-07-eu; Mon, 11 Aug 2025
 01:27:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXM+8sEs0o5wPkhbug6fHIXacHpNu2yWQKIW9gO68tsgxFDKESGllvuUMIQTQVff6MO6DDALpgJnjM=@googlegroups.com
X-Received: by 2002:a05:6402:848:b0:615:b6b9:d859 with SMTP id 4fb4d7f45d1cf-617e2b70dc6mr10633662a12.3.1754900867261;
        Mon, 11 Aug 2025 01:27:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754900867; cv=none;
        d=google.com; s=arc-20240605;
        b=cpurMG1aAWW3o+I/mt+uN0ruwH3AOGmwy3rWAbYhkikcl/wpw+oppL20+nFUnYDvak
         j80IXVfwbHgi3ijY9aJYY4N53bpYOpaIFtERAg0nS3RQ5g7ZAM7Dmr+KLlT/184FJQnP
         Y7K7d1x7vSRP9DpySlxX7ew2elCr0BEJi9WVpcwAtGQk78+GgpJglmaVWuwSlhWy9Bjw
         2wcMt9tF6oREOv98bSxo5ZZFtdWbcI5r44QLckXxJ9+8bRJRusS/BM5T3iirBUR1ZLpM
         d5Yax7k4EfuC/QGqnPLMsIbhgGagROd5JQJCap33vFo7baVvBZiqoN7Z8N2RlRiJ+ZTj
         DSXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=XqR1vCaE0o2DPsF/1Op00CkgIcuAUqq6U2W5nEqoIsI=;
        fh=qTYAc40a9mFpy0LG8xoVl8gGOAZbZYpvmqsZ6iUnIjI=;
        b=juitxszYGPKgA8Fwv5awTLBXgNegk2qR3edD0nmV18MBVdVCep3WqoPBY6DeuICeZ/
         vYrJiNpqJpZfpAibOq10Cn9c6xJ8WtmDby9kda2XSX8D94LfqwqVu08tQ9szPTEzk+bj
         +xQGv6yLqfo5bnoIRiOSego/1TdMBfRecvwe3rTntMiGSYaVSsZrl37EFeJf15CQE0AS
         o5TcNDuzWgDQ0syZOxEcv5CghaG8rdoZaQ9x+neKi0T08sUsuhL7nsuJv8sbwLCAaOm3
         ALVSkVe8xcwp0UGyjdS4OyHXiVRzCLUwifTUZTlYipPnOLW74PQzISmq40vft4VJCHB6
         m8uQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fx7k4uP6;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f29032si777415a12.1.2025.08.11.01.27.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:27:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 11 Aug 2025 10:27:45 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Yunseong Kim <ysk@kzalloc.com>, linux-usb@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-rt-devel@lists.linux.dev
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Thomas Gleixner <tglx@linutronix.de>, syzkaller@googlegroups.com,
	Austin Kim <austindh.kim@gmail.com>
Subject: [PATCH] kcov, usb: Don't disable interrupts in
 kcov_remote_start_usb_softirq()
Message-ID: <20250811082745.ycJqBXMs@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=fx7k4uP6;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
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

kcov_remote_start_usb_softirq() the begin of urb's completion callback.
HCDs marked HCD_BH will invoke this function from the softirq and
in_serving_softirq() will detect this properly.
Root-HUB (RH) requests will not be delayed to softirq but complete
immediately in IRQ context.
This will confuse kcov because in_serving_softirq() will report true if
the softirq is served after the hardirq and if the softirq got
interrupted by the hardirq in which currently runs.

This was addressed by simply disabling interrupts in
kcov_remote_start_usb_softirq() which avoided the interruption by the RH
while a regular completion callback was invoked.
This not only changes the behaviour while kconv is enabled but also
breaks PREEMPT_RT because now sleeping locks can no longer be acquired.

Revert the previous fix. Address the issue by invoking
kcov_remote_start_usb() only if the context is just "serving softirqs"
which is identified by checking in_serving_softirq() and in_hardirq()
must be false.

Fixes: f85d39dd7ed89 ("kcov, usb: disable interrupts in kcov_remote_start_usb_softirq")
Reported-by: Yunseong Kim <ysk@kzalloc.com>
Closes: https://lore.kernel.org/all/20250725201400.1078395-2-ysk@kzalloc.com/
Tested-by: Yunseong Kim <ysk@kzalloc.com>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 drivers/usb/core/hcd.c | 12 +++++------
 include/linux/kcov.h   | 47 ++++++++----------------------------------
 2 files changed, 14 insertions(+), 45 deletions(-)

diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
index 03771bbc6c01a..d765fa5ec6718 100644
--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1636,7 +1636,6 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	struct usb_hcd *hcd = bus_to_hcd(urb->dev->bus);
 	struct usb_anchor *anchor = urb->anchor;
 	int status = urb->unlinked;
-	unsigned long flags;
 
 	urb->hcpriv = NULL;
 	if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
@@ -1654,14 +1653,13 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	/* pass ownership to the completion handler */
 	urb->status = status;
 	/*
-	 * Only collect coverage in the softirq context and disable interrupts
-	 * to avoid scenarios with nested remote coverage collection sections
-	 * that KCOV does not support.
-	 * See the comment next to kcov_remote_start_usb_softirq() for details.
+	 * This function can be called in task context inside another remote
+	 * coverage collection section, but kcov doesn't support that kind of
+	 * recursion yet. Only collect coverage in softirq context for now.
 	 */
-	flags = kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
+	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	kcov_remote_stop_softirq(flags);
+	kcov_remote_stop_softirq();
 
 	usb_anchor_resume_wakeups(anchor);
 	atomic_dec(&urb->use_count);
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c32..0143358874b07 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -57,47 +57,21 @@ static inline void kcov_remote_start_usb(u64 id)
 
 /*
  * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
- * workaround for KCOV's lack of nested remote coverage sections support.
- *
- * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi?id=210337.
- *
- * kcov_remote_start_usb_softirq():
- *
- * 1. Only collects coverage when called in the softirq context. This allows
- *    avoiding nested remote coverage collection sections in the task context.
- *    For example, USB/IP calls usb_hcd_giveback_urb() in the task context
- *    within an existing remote coverage collection section. Thus, KCOV should
- *    not attempt to start collecting coverage within the coverage collection
- *    section in __usb_hcd_giveback_urb() in this case.
- *
- * 2. Disables interrupts for the duration of the coverage collection section.
- *    This allows avoiding nested remote coverage collection sections in the
- *    softirq context (a softirq might occur during the execution of a work in
- *    the BH workqueue, which runs with in_serving_softirq() > 0).
- *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
- *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
- *    the middle of its remote coverage collection section, and the interrupt
- *    handler might invoke __usb_hcd_giveback_urb() again.
+ * work around for kcov's lack of nested remote coverage sections support in
+ * task context. Adding support for nested sections is tracked in:
+ * https://bugzilla.kernel.org/show_bug.cgi?id=210337
  */
 
-static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
+static inline void kcov_remote_start_usb_softirq(u64 id)
 {
-	unsigned long flags = 0;
-
-	if (in_serving_softirq()) {
-		local_irq_save(flags);
+	if (in_serving_softirq() && !in_hardirq())
 		kcov_remote_start_usb(id);
-	}
-
-	return flags;
 }
 
-static inline void kcov_remote_stop_softirq(unsigned long flags)
+static inline void kcov_remote_stop_softirq(void)
 {
-	if (in_serving_softirq()) {
+	if (in_serving_softirq() && !in_hardirq())
 		kcov_remote_stop();
-		local_irq_restore(flags);
-	}
 }
 
 #ifdef CONFIG_64BIT
@@ -131,11 +105,8 @@ static inline u64 kcov_common_handle(void)
 }
 static inline void kcov_remote_start_common(u64 id) {}
 static inline void kcov_remote_start_usb(u64 id) {}
-static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
-{
-	return 0;
-}
-static inline void kcov_remote_stop_softirq(unsigned long flags) {}
+static inline void kcov_remote_start_usb_softirq(u64 id) {}
+static inline void kcov_remote_stop_softirq(void) {}
 
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811082745.ycJqBXMs%40linutronix.de.
