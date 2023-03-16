Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMYZSQAMGQESSOOUMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 465E16BCF86
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 13:31:59 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id z20-20020a4ad594000000b00531ac1a175dsf291543oos.20
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 05:31:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678969917; cv=pass;
        d=google.com; s=arc-20160816;
        b=J4/mXpzUnrT/xCB8zKWR45kioVGlElcZyivMolhUB0YCd6Koun8GAOsZK2q5jtdPAv
         8y6V72nJ96hhz6U9Q9DkcWFC8AdaaxvnaRQQdmzVy3rOe/emIVutPqmNJPkvULYVLhEj
         1sietTWOqrrs2Po13fcxMaLiVjGW1knz9w6qGXWX2ImhXczNHY7kVdRn9pTBK7DCC6LK
         UIv43H5JSumqlUV2b3BCMQzhlzVMBjeoDhiYb+uB5u3EpFNkqNIzFtjYkbXqRMUo9l/c
         BPYQnkT/OxxxUIY8xDh4/OOv2waX2p/faZY6C7OZFMyM0NeV7SjqSgFTbdgKMLOgTNeB
         VPhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=sTlU52IB4H4kJnSHb4YCA9SCgTcdfK8R6Ee8atgKXMs=;
        b=yFMkt+n9vdQya3WITLKCPDlgGicbzoit7Zt7G2BqjXs3KDszmBaFKQwgR3Ow73OIfz
         TaaiVPhIJbVKr1px/FLlvHZUxPENjVgpBIHEu9iaMq61bYrdwypDFFSqZjEgovri15Cr
         m7qwccu8I2Ht5pf0JxP8ojlJHQ4T93Lj4HqlRtNdrUIJ0JmBNm61PgQe7TH9jMKe5jrX
         5D9RjMW3EyJKeB779XAOce7F9G520k85ogK/E/eSBMQOjMPa8lwHQU4/NPZuqNBd5hj0
         dS+bcZODAJVXh7Ej4lwyj7twbLKEfIyXWOmZB0Vs2KkGuQh1NZ7D4JWPmNFNMmzhN0PZ
         EQhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qCtLERy6;
       spf=pass (google.com: domain of 3pawtzaukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3PAwTZAUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678969917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sTlU52IB4H4kJnSHb4YCA9SCgTcdfK8R6Ee8atgKXMs=;
        b=IP/h5R7fjT6E53zymNBeir8BarLWbGPZvm7MEYUiSieICDT12IbsUdVEd2vwaX9WB3
         AkkXm+y31kfgq3A8DSvae/HpTqK4ErGlt+zYqfDVlbUxYzmMfWMm+A5/fIbNQ/bOvqB8
         npkS7XX5+TFqrDJDFGXYG7KfS2qXyQwDbOA8Lh5EvfIaqK1oz4Ej/YBpIRmMhctnWz/D
         dmLW9qsdkNX+tArqxly38bmgkmfD5PZzl3ONvDw5norrG4dm2xqeKRQSRiHUeOKKJGio
         0SEuRAtsBHWyGi5WNEPK4zotOPc08Aa4+uVbu0cySRxBwkihKoaX2dn2FW5aCV4zkHVX
         opZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678969917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sTlU52IB4H4kJnSHb4YCA9SCgTcdfK8R6Ee8atgKXMs=;
        b=rDwSoDnF6oHRjVk1Brh+ut7q+6HOnbM4lOSecnucixurdlI9lhCWJvf3ySKhfjbRE2
         3vY2/iCFEI9HXE4rE+gjpsnkL6Zs89/Z1QZLnWsxd/wBWIn2Z8pAZ89ODIWFAQcjY7fK
         eGpu5z+qJkjRmMfKWxBftjNTFgGPrQMU4+iS1AdJhOSnqiE7K5VS4Wqm1VSG1z5LmN3n
         0DFypcqgT+ref0XRLReocMP4wLDGzu177UMV+vdfcdgxDKWB0NuDDUvtszZ+cdu92K85
         KIPIizxmzrYIy6Y5SIAVl3nfLyyOTHSl9h+AamdmveVDRP28Uy/Vap/O0pqeI73GXCK4
         W8tw==
X-Gm-Message-State: AO0yUKWh5GskyPqV4gqeoQ4oUztNs4+SlnGpfbkpqLOY3pjNsPtEaDO1
	L7VRUiSIN2Wg0/PRfePURHQ=
X-Google-Smtp-Source: AK7set/yBS/8fXt2JjKjOjGcTXLcFV8IozBVkztdymnJ8Gk05qoLziTgxMvPujpC0jWeZucBbXqMYA==
X-Received: by 2002:a9d:7094:0:b0:69b:af37:6fa0 with SMTP id l20-20020a9d7094000000b0069baf376fa0mr1234507otj.5.1678969917653;
        Thu, 16 Mar 2023 05:31:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:24c:b0:384:d300:3fb8 with SMTP id
 m12-20020a056808024c00b00384d3003fb8ls385292oie.9.-pod-prod-gmail; Thu, 16
 Mar 2023 05:31:57 -0700 (PDT)
X-Received: by 2002:aca:1812:0:b0:384:202f:be32 with SMTP id h18-20020aca1812000000b00384202fbe32mr2638493oih.11.1678969917109;
        Thu, 16 Mar 2023 05:31:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678969917; cv=none;
        d=google.com; s=arc-20160816;
        b=m9zv6EaWzOzkRF5HQ8jRiyCM9EHbfuP21HUTMp5A2kbiE66j8bRaVNCvYVXz2A7KJy
         pRFAeyS/coO88aIha6SHLnaZDWVb4B7JAFgbZdrUJndUnusg9k7NUlUywz0tTKS7F7HI
         JMOQCLN+2eUWCj1YYK4VrvSjexXAmNB5KMQQJ8TX176E+Bvm8mGibM/av5Xf+NM/elLc
         aCbWgkk3/w2jTxF0GCoBue/r4gypX9wr6gsPuZjxWszSnWtkUqBRymx/eX4vuxMOjJQt
         N9coOibEvGMGZLTBySrRee1bsUJPo/7ao0oig5wWHCbjn0KbNcQfVpWJFqzGXSWskBR4
         4kYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=87DZZv3zvWxq1JNrpUvBlJXCIWW+Rra/IVtOi+lv2AY=;
        b=qbH16JKhYXcU/C1PyIK/p1upUdKBbL6u/uSUUqf1Nq5WOjTYQ2ErFI7TUUcMzY6dGv
         WOTFw8qX+ngy+LIU6JcvmsRu019LWKRjHaRZeJhVoYpYEvCpjPh8BZLwmNyTTcSffJpQ
         6YQ4lWbMYVb3jNwHQ+a06vp2RSMnUplVSaFWTPZ6dMQEdEty0mxzTkiIGC0pVDh2lHTo
         LTXKtabvdBEnWnBEvhNjq/+7UxfCUOG4boMXzo7kdsfolF+7lk2x9ggQuKdbzHf0iMcA
         l7YC4VgyzBR1BQceN6ctqzKuYfPcoi9eehk11ZQgRbDSyz9Jja+gtVu1m1QV+Jlj98Ew
         3KYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qCtLERy6;
       spf=pass (google.com: domain of 3pawtzaukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3PAwTZAUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id db23-20020a056808409700b0036bbb25d978si473113oib.3.2023.03.16.05.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 05:31:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pawtzaukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5411f21f849so13695867b3.16
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 05:31:57 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
 (user=elver job=sendgmr) by 2002:a81:b306:0:b0:541:61aa:9e60 with SMTP id
 r6-20020a81b306000000b0054161aa9e60mr2038578ywh.6.1678969916701; Thu, 16 Mar
 2023 05:31:56 -0700 (PDT)
Date: Thu, 16 Mar 2023 13:30:27 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230316123028.2890338-1-elver@google.com>
Subject: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>
Cc: Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qCtLERy6;       spf=pass
 (google.com: domain of 3pawtzaukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3PAwTZAUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Dmitry Vyukov <dvyukov@google.com>

POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
thread of a thread group for signal delivery.     However, this has a
significant downside: it requires waking up a potentially idle thread.

Instead, prefer to deliver signals to the current thread (in the same
thread group) if SIGEV_THREAD_ID is not set by the user. This does not
change guaranteed semantics, since POSIX process CPU time timers have
never guaranteed that signal delivery is to a specific thread (without
SIGEV_THREAD_ID set).

The effect is that we no longer wake up potentially idle threads, and
the kernel is no longer biased towards delivering the timer signal to
any particular thread (which better distributes the timer signals esp.
when multiple timers fire concurrently).

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Oleg Nesterov <oleg@redhat.com>
Reviewed-by: Oleg Nesterov <oleg@redhat.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v6:
- Split test from this patch.
- Update wording on what this patch aims to improve.

v5:
- Rebased onto v6.2.

v4:
- Restructured checks in send_sigqueue() as suggested.

v3:
- Switched to the completely different implementation (much simpler)
  based on the Oleg's idea.

RFC v2:
- Added additional Cc as Thomas asked.
---
 kernel/signal.c | 25 ++++++++++++++++++++++---
 1 file changed, 22 insertions(+), 3 deletions(-)

diff --git a/kernel/signal.c b/kernel/signal.c
index 8cb28f1df294..605445fa27d4 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1003,8 +1003,7 @@ static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
 	/*
 	 * Now find a thread we can wake up to take the signal off the queue.
 	 *
-	 * If the main thread wants the signal, it gets first crack.
-	 * Probably the least surprising to the average bear.
+	 * Try the suggested task first (may or may not be the main thread).
 	 */
 	if (wants_signal(sig, p))
 		t = p;
@@ -1970,8 +1969,23 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
 
 	ret = -1;
 	rcu_read_lock();
+	/*
+	 * This function is used by POSIX timers to deliver a timer signal.
+	 * Where type is PIDTYPE_PID (such as for timers with SIGEV_THREAD_ID
+	 * set), the signal must be delivered to the specific thread (queues
+	 * into t->pending).
+	 *
+	 * Where type is not PIDTYPE_PID, signals must just be delivered to the
+	 * current process. In this case, prefer to deliver to current if it is
+	 * in the same thread group as the target, as it avoids unnecessarily
+	 * waking up a potentially idle task.
+	 */
 	t = pid_task(pid, type);
-	if (!t || !likely(lock_task_sighand(t, &flags)))
+	if (!t)
+		goto ret;
+	if (type != PIDTYPE_PID && same_thread_group(t, current))
+		t = current;
+	if (!likely(lock_task_sighand(t, &flags)))
 		goto ret;
 
 	ret = 1; /* the signal is ignored */
@@ -1993,6 +2007,11 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
 	q->info.si_overrun = 0;
 
 	signalfd_notify(t, sig);
+	/*
+	 * If the type is not PIDTYPE_PID, we just use shared_pending, which
+	 * won't guarantee that the specified task will receive the signal, but
+	 * is sufficient if t==current in the common case.
+	 */
 	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
 	list_add_tail(&q->list, &pending->list);
 	sigaddset(&pending->signal, sig);
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316123028.2890338-1-elver%40google.com.
