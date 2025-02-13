Return-Path: <kasan-dev+bncBCPILY4NUAFBB2U7XG6QMGQEPDJ3CXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D29DA34EE9
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:02:52 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-220e04e67e2sf30248705ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:02:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739476970; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z4dFk55YMlJe9uaPyn2PYlSxCQrCJbnILd1T++ezJjd6mtb+IZDfer0T20cH3a4Osx
         LR4esrv1JCAYTFCh1rljlWMPk4eJg1Iupn6XpHD6/SMulqJTuFFSZima4NN3JH+co2yY
         pm7WE6L/mhvOHaFWWUnHjPRrqSmz2cuVDrxYzV6zizuU1Kp6Y9+Z9OdIKj0qQhKNAgum
         LMDtMsgOx025V0BtGr2wRPpO7hV5Fz/s/BkAkqSj2Xy07ZC3FNyHGl2Rxw5IWDT2Hbkf
         cjVlxrCZ+O/eNzLzT2dXoXHhlwzh+J7KrG979cL6ZvZJ7Fd3dLcnk+Uey5SmXaJKfrb6
         KJdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lUOVYAKbCGkPaSosBj3nw/HyB9MDypMFvLNFE0xj6D4=;
        fh=YYadj3kPKBX3P+bE5xDeBO4sqhJKiQKZksUF3yL1dlw=;
        b=irsI9rzL76qmUQ1lnOHFVVAG6+Yx02wWx9U96G2IriYD7kMKLw88zZ8j+i54TBaN4G
         DnnLLAVXfBTmNOjltU/wO21rqc77k5tBx6owMKlbvDHnsW9OvoT/4O2TxHNi7Jkfn0Bv
         lLSzJq3jW3gJunl/5k0kWdWdRZiEWyM4dGumakyGNQe4XPobTXG4XGtZ0mVCPvk7AWAs
         I91CtzYbKkc+NUk0pLp9oBXFdX2D1/KoMzVdhX/DtovwoQpMHUT7dLSZ/mdVCd2y2t88
         xCmh348OyozK/KgyhmOyXIFaNxQ5HVoJ/exYFmoRuDxGOebG8OTnvsavgGy+4RP5lht2
         4ERQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="M/jFSOpf";
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739476970; x=1740081770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lUOVYAKbCGkPaSosBj3nw/HyB9MDypMFvLNFE0xj6D4=;
        b=u24h+1IIuXzDx4R1gzCAa/X78rgGOI1bVpBJdiAj/DL59ONQ+RODp1k9rs14Iv50Lv
         kLbSi1X2V7EqdH8oj/1V6qJ+H7W3NfQda5LAuPp7/9Wfi1nYpt/OgXODfOJagS670Ae2
         oKkik5jYlEFLnD3ZgVnlS9Q9W0UvJxUVqPzaCbfVGZXlrmDWtpGXRLp9BBxvOnwdXX0M
         QnyskdV63UVY+U9rIIdM33Gx/s6GSKl+emyVfaRJZKAqK5EXYLoOD/i7iI4oV1AgDKTF
         7VKyb0FubZxpNXBqrsukbMnLGzPnMKLbl0FLVoHqgSg0ZUMv5Ft58dtNHFJqHrgDlr1A
         Vs6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739476970; x=1740081770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lUOVYAKbCGkPaSosBj3nw/HyB9MDypMFvLNFE0xj6D4=;
        b=sPJdo9llR/R+O94BAsKckKG+Hk6yyCT3RU//ePyeCcKEiH+UJsnPl9SEWVXmpofi0d
         k3EMY2gfVS/2KFU0boyve0u10BMx1rCf77sVe6p9g8ayl3zd/y2iItoZs6xh0xHNbdSt
         ZmTJwv2yNosrsZFFXrQ+zcGMo7uIHNLt4r4tRgmByN6Cjv0k4kj82368LEtLx+cWtPKM
         +ovcf8CpwMfS5afukT3NtQmAY7aaHhMI2jOF+HD6+AmQos7Y6r+cGoHkWv3pC7m1h4qL
         XvHri61lkVVYdFTtWESQwgq2p76ffIDhyBrmxiCgG+8w2LahS6jQqOr/DWsdCzCIqi0C
         YnmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeuY7OvgGGweU3Y6dyDlOaNAkaMNQp5AhWup2ZYzFDujTPFETSEvJxtwWNMA5S+uDlA44oow==@lfdr.de
X-Gm-Message-State: AOJu0Yx/Hee3XDGez8vEPf3N1t0G5lJZY/C9wDuCLiOfcvM6SLVu2rml
	0+lsqnlr4onpBFadbSZqLFg/uAdzQpKPK0sY8mROhYip1cB0M2dR
X-Google-Smtp-Source: AGHT+IG/iewjI+OATVWJUGU7qUq4ARddNAfWCoZGtNVZeBA5GHjqQ3+HUQb1AjaGqnssLMwpT25adw==
X-Received: by 2002:a05:6a20:2d06:b0:1e4:8fdd:8c77 with SMTP id adf61e73a8af0-1ee5c733c61mr15752211637.8.1739476970410;
        Thu, 13 Feb 2025 12:02:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHGskdw93twxId1kNCFawfDeeS3ZvznpP08w/f2H83euQ==
Received: by 2002:aa7:804e:0:b0:725:e2f6:f34c with SMTP id d2e1a72fcca58-7323bf27284ls1926134b3a.1.-pod-prod-08-us;
 Thu, 13 Feb 2025 12:02:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUGd8a06AMaHZyS5jx9+NmChG6PB1/DzfFNgl1S+lEhmoarNVb6mXyUOrH2E23Ju3a+5iwbCKMwMDA=@googlegroups.com
X-Received: by 2002:a05:6a20:ce4b:b0:1ee:6fec:3e5c with SMTP id adf61e73a8af0-1ee6fec404emr6771229637.7.1739476969181;
        Thu, 13 Feb 2025 12:02:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739476969; cv=none;
        d=google.com; s=arc-20240605;
        b=kLD1s5T//z6Z95hBFrhaHZlOSn5CEcRugeBF8ZjLsQnOk7vTepQC8LqcROqb11W/29
         Swj2SLyjLO2kSIu/EJ/2GdLlu55w/D4leU4vkYNwLRrD0CNKUBmh+bPeH1dCvNh7zwSj
         hgNXpzzYoQ3xwUE6/9R9Hu7Wir33YBPEOGIPfrTQqAWlkfuQW/eye1hqMIjWzHB9GChD
         HzG+gq5p595knD5aViRX1D6wYW1aCXEgklVTt8iDe46lwF/yKhKiKcO6/giL55YyzY34
         X90sZoto4XAR72Y7fdN5Z6Ca52vjezmD/atLERyCsxeORDlyEFPNZfv6iRapKRYdj/up
         beIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/2qiXC/cNFFNJmD/Jr1WU9cXX6QUwEFoWyQGXl5gh0Q=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=hfiddhjcCc9Xe0vEHcGlPs3aPIG5XVKQXLD0RwP0R3gGE+86jJ4b3sKzPB6aauTX7s
         Cj2TN8m0zVd0AirTx5IcLA0BQl6rcgHIhK6THM05zlRHWcqEBCC1JlOGJe6JTHLsKck9
         X83csMMWIrvC20gVa26gT/ZJ9BSO4UwPR3PSxIzQfuO8PYQuNo3ZB2M3aTGhS+bdIOsj
         FlH02fvA7JDxQgooPeXIyxjIoRu2g6sbGKdF7XIo1I17N4eNBAb3Dln9B0mNh3s7w7gn
         2JBYGbFusPgPs0UXFVvKrnBKlzGQxRGL7AZw8h4KAaWaXmTG6EDgU5yWd2WWwR4ggt63
         WO2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="M/jFSOpf";
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73242744949si85204b3a.4.2025.02.13.12.02.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:02:49 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-543-_VGgiUUcOfCNkxtkAmgh3Q-1; Thu,
 13 Feb 2025 15:02:43 -0500
X-MC-Unique: _VGgiUUcOfCNkxtkAmgh3Q-1
X-Mimecast-MFC-AGG-ID: _VGgiUUcOfCNkxtkAmgh3Q
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 02D4E19560B5;
	Thu, 13 Feb 2025 20:02:42 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.174])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 53E5A180035E;
	Thu, 13 Feb 2025 20:02:39 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 1/4] locking/lock_events: Add locking events for rtmutex slow paths
Date: Thu, 13 Feb 2025 15:02:25 -0500
Message-ID: <20250213200228.1993588-2-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="M/jFSOpf";
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Content-Type: text/plain; charset="UTF-8"
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

Add locking events for rtlock_slowlock() and rt_mutex_slowlock() for
profiling the slow path behavior of rt_spin_lock() and rt_mutex_lock().

Signed-off-by: Waiman Long <longman@redhat.com>
---
 kernel/locking/lock_events_list.h | 21 +++++++++++++++++++++
 kernel/locking/rtmutex.c          | 29 ++++++++++++++++++++++++-----
 2 files changed, 45 insertions(+), 5 deletions(-)

diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
index 97fb6f3f840a..80b11f194c9f 100644
--- a/kernel/locking/lock_events_list.h
+++ b/kernel/locking/lock_events_list.h
@@ -67,3 +67,24 @@ LOCK_EVENT(rwsem_rlock_handoff)	/* # of read lock handoffs		*/
 LOCK_EVENT(rwsem_wlock)		/* # of write locks acquired		*/
 LOCK_EVENT(rwsem_wlock_fail)	/* # of failed write lock acquisitions	*/
 LOCK_EVENT(rwsem_wlock_handoff)	/* # of write lock handoffs		*/
+
+/*
+ * Locking events for rtlock_slowlock()
+ */
+LOCK_EVENT(rtlock_slowlock)	/* # of rtlock_slowlock() calls		*/
+LOCK_EVENT(rtlock_slow_acq1)	/* # of locks acquired after wait_lock	*/
+LOCK_EVENT(rtlock_slow_acq2)	/* # of locks acquired in for loop	*/
+LOCK_EVENT(rtlock_slow_sleep)	/* # of sleeps				*/
+LOCK_EVENT(rtlock_slow_wake)	/* # of wakeup's			*/
+
+/*
+ * Locking events for rt_mutex_slowlock()
+ */
+LOCK_EVENT(rtmutex_slowlock)	/* # of rt_mutex_slowlock() calls	*/
+LOCK_EVENT(rtmutex_slow_block)	/* # of rt_mutex_slowlock_block() calls	*/
+LOCK_EVENT(rtmutex_slow_acq1)	/* # of locks acquired after wait_lock	*/
+LOCK_EVENT(rtmutex_slow_acq2)	/* # of locks acquired at the end	*/
+LOCK_EVENT(rtmutex_slow_acq3)	/* # of locks acquired in *block()	*/
+LOCK_EVENT(rtmutex_slow_sleep)	/* # of sleeps				*/
+LOCK_EVENT(rtmutex_slow_wake)	/* # of wakeup's			*/
+LOCK_EVENT(rtmutex_deadlock)	/* # of rt_mutex_handle_deadlock()'s	*/
diff --git a/kernel/locking/rtmutex.c b/kernel/locking/rtmutex.c
index 4a8df1800cbb..c80902eacd79 100644
--- a/kernel/locking/rtmutex.c
+++ b/kernel/locking/rtmutex.c
@@ -27,6 +27,7 @@
 #include <trace/events/lock.h>
 
 #include "rtmutex_common.h"
+#include "lock_events.h"
 
 #ifndef WW_RT
 # define build_ww_mutex()	(false)
@@ -1612,10 +1613,13 @@ static int __sched rt_mutex_slowlock_block(struct rt_mutex_base *lock,
 	struct task_struct *owner;
 	int ret = 0;
 
+	lockevent_inc(rtmutex_slow_block);
 	for (;;) {
 		/* Try to acquire the lock: */
-		if (try_to_take_rt_mutex(lock, current, waiter))
+		if (try_to_take_rt_mutex(lock, current, waiter)) {
+			lockevent_inc(rtmutex_slow_acq3);
 			break;
+		}
 
 		if (timeout && !timeout->task) {
 			ret = -ETIMEDOUT;
@@ -1638,8 +1642,10 @@ static int __sched rt_mutex_slowlock_block(struct rt_mutex_base *lock,
 			owner = NULL;
 		raw_spin_unlock_irq_wake(&lock->wait_lock, wake_q);
 
-		if (!owner || !rtmutex_spin_on_owner(lock, waiter, owner))
+		if (!owner || !rtmutex_spin_on_owner(lock, waiter, owner)) {
+			lockevent_inc(rtmutex_slow_sleep);
 			rt_mutex_schedule();
+		}
 
 		raw_spin_lock_irq(&lock->wait_lock);
 		set_current_state(state);
@@ -1694,6 +1700,7 @@ static int __sched __rt_mutex_slowlock(struct rt_mutex_base *lock,
 	int ret;
 
 	lockdep_assert_held(&lock->wait_lock);
+	lockevent_inc(rtmutex_slowlock);
 
 	/* Try to acquire the lock again: */
 	if (try_to_take_rt_mutex(lock, current, NULL)) {
@@ -1701,6 +1708,7 @@ static int __sched __rt_mutex_slowlock(struct rt_mutex_base *lock,
 			__ww_mutex_check_waiters(rtm, ww_ctx, wake_q);
 			ww_mutex_lock_acquired(ww, ww_ctx);
 		}
+		lockevent_inc(rtmutex_slow_acq1);
 		return 0;
 	}
 
@@ -1719,10 +1727,12 @@ static int __sched __rt_mutex_slowlock(struct rt_mutex_base *lock,
 				__ww_mutex_check_waiters(rtm, ww_ctx, wake_q);
 			ww_mutex_lock_acquired(ww, ww_ctx);
 		}
+		lockevent_inc(rtmutex_slow_acq2);
 	} else {
 		__set_current_state(TASK_RUNNING);
 		remove_waiter(lock, waiter);
 		rt_mutex_handle_deadlock(ret, chwalk, lock, waiter);
+		lockevent_inc(rtmutex_deadlock);
 	}
 
 	/*
@@ -1751,6 +1761,7 @@ static inline int __rt_mutex_slowlock_locked(struct rt_mutex_base *lock,
 				  &waiter, wake_q);
 
 	debug_rt_mutex_free_waiter(&waiter);
+	lockevent_cond_inc(rtmutex_slow_wake, !wake_q_empty(wake_q));
 	return ret;
 }
 
@@ -1823,9 +1834,12 @@ static void __sched rtlock_slowlock_locked(struct rt_mutex_base *lock,
 	struct task_struct *owner;
 
 	lockdep_assert_held(&lock->wait_lock);
+	lockevent_inc(rtlock_slowlock);
 
-	if (try_to_take_rt_mutex(lock, current, NULL))
+	if (try_to_take_rt_mutex(lock, current, NULL)) {
+		lockevent_inc(rtlock_slow_acq1);
 		return;
+	}
 
 	rt_mutex_init_rtlock_waiter(&waiter);
 
@@ -1838,8 +1852,10 @@ static void __sched rtlock_slowlock_locked(struct rt_mutex_base *lock,
 
 	for (;;) {
 		/* Try to acquire the lock again */
-		if (try_to_take_rt_mutex(lock, current, &waiter))
+		if (try_to_take_rt_mutex(lock, current, &waiter)) {
+			lockevent_inc(rtlock_slow_acq2);
 			break;
+		}
 
 		if (&waiter == rt_mutex_top_waiter(lock))
 			owner = rt_mutex_owner(lock);
@@ -1847,8 +1863,10 @@ static void __sched rtlock_slowlock_locked(struct rt_mutex_base *lock,
 			owner = NULL;
 		raw_spin_unlock_irq_wake(&lock->wait_lock, wake_q);
 
-		if (!owner || !rtmutex_spin_on_owner(lock, &waiter, owner))
+		if (!owner || !rtmutex_spin_on_owner(lock, &waiter, owner)) {
+			lockevent_inc(rtlock_slow_sleep);
 			schedule_rtlock();
+		}
 
 		raw_spin_lock_irq(&lock->wait_lock);
 		set_current_state(TASK_RTLOCK_WAIT);
@@ -1865,6 +1883,7 @@ static void __sched rtlock_slowlock_locked(struct rt_mutex_base *lock,
 	debug_rt_mutex_free_waiter(&waiter);
 
 	trace_contention_end(lock, 0);
+	lockevent_cond_inc(rtlock_slow_wake, !wake_q_empty(wake_q));
 }
 
 static __always_inline void __sched rtlock_slowlock(struct rt_mutex_base *lock)
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-2-longman%40redhat.com.
