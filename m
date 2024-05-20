Return-Path: <kasan-dev+bncBAABBFXTV2ZAMGQEIXH47CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 205288CA38C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 22:59:04 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-523936877dbsf4834600e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 13:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716238743; cv=pass;
        d=google.com; s=arc-20160816;
        b=ITwzyAANxhZUeGokyHaQUqblSYpjLDcNDB0GuZKRU9OjHD/CO62DZlPwxbh4bPs27M
         VPzwcUEkZJW1k8e4egQymspjXymoARg5NFUAX6BUFL4piL5kYt7RdA2u2hNXhwPvUqWP
         H070v4Qj14HcInMLnOo8X7kPaVx9klzjMsn2J2Bryy4pXxxibLMDwv7MHNBzGmrs0M6S
         HP/R9yQw++MR3qPZ3iC/Ons2el2LYoLHnbjLQ/WDVtpjNZBGpaJJAf+yAWEmJ3Es2hPj
         KzCXPdHxposrnepZCWkeenLMEYa3V8BCs0rF5scIZH6adTHl6W3EJFdEajZeSaM8ufB6
         1klw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fi2qpgS29BEDbcvb/1Sncfv4IBm59RknV0XqbArG9rs=;
        fh=ko21g65+L9bKVKapXRTznpwJ1EAxkDMxozN6HaNOhTM=;
        b=HbimwURr33d7u6597tS9rRrMzJfepAGd8JEgEXGeZTLhRjq26KKAVWTcIq2SLU4iyl
         joXnDrQw2JjFI0lFw6zkt/nfUZs18P5r5RuMWVWOrVuYKp5bM0JmBjQqi9MQgzGYDaR4
         y3tx5TZnk48MEZb/00Dh8P+dEhxHAZ5IxKZOQ6KRTWT/QTgzUaeEjWmNSIYaXsKMwR+W
         SkhCMQUXJjhkKiRFUyWFArg59whklD+CEdZPUvNum8qaqYa61uBjVlYKQ1O7yNSswIh6
         Pi1mOaZ9giWtgYeNJS5qZxj2tC7rRSTnaD2Vq/le0JM4Pk1mOGkaN7akcp4+eSVJA8gb
         GRzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C1JjhjK3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716238743; x=1716843543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fi2qpgS29BEDbcvb/1Sncfv4IBm59RknV0XqbArG9rs=;
        b=JPQkwBCOSln9/ebuIIl8a6zXODufnNFGY0yqqKwJ76cNT3w6Ha/s5py+lhhiJyAam0
         m2g9lAPZOhtuDflxrj3CxYIRWuPDNOY6WHkh4wK5j2U6BDDMxxF6UM/7iI5cJD2zSeKm
         nh3t1e2BwmnTsMhUuKBlLHFLT+HncF5jhl01r3/tKiC/UlsVO5cSpCEPaghfbr9Kp8tt
         KBS/1yG+X8bzgwVQE3bFpxrJYjnE1+MecsgdKOigHx/McD+sn+tZUHyLVhlpRA+Fzo/U
         RJub0o79LvXsbvznA5dM8O0Z3cZFhrf2o5tTKkI/poriSyoyAOs+7pY99ezo55oXGhsY
         tulg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716238743; x=1716843543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fi2qpgS29BEDbcvb/1Sncfv4IBm59RknV0XqbArG9rs=;
        b=b9HLn/Mj8Rpbqo0KTBGqkFnzk3A46+sb4rOIXLhii7lUa84UaH5a7aTdT+WAryqPOc
         qVaPVf9aGMVrzft0GVgNfTnugZxyaHjPqQ+CKnXqzm5EauJIKPsFIzoWb/Vn9RvOsrvg
         XBbE4F4v/S11Kp334zn0N7TBtLnvlYuYrOyTv72sZk2hHVhT2j8TQIWpZTmyJdO1GiPv
         s/anWEwCpIo86Axwl1nQQcpQ435eMZ9KJrl3BH5dE3JCnMyzzBqd62oBopiolmXHMC4a
         VkMkdJV7Ix0GKSf3jAaK3QXukRVElAcCz90QUtzRcOQsGhmr5NLtI8ejLeZuStgNudD0
         W80Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXrrlWIdbc15nD0bn1a3UGE/FskHWCGAJGAJZRP96UzkczeKQXM7k5Qm58BhUSg3GALqFTHPVLTE4xFF1dpQUznfEqoILZJQ==
X-Gm-Message-State: AOJu0YzmINFT9Dzseq0OPNJRpo5uNRwm1pcQiwdOT7BXqUwT+1XFoRlZ
	U5k2N/HKpzAdAyTC1Qjux7IRvagVtAClkGNJNO5DeXK7WJcmqjhJ
X-Google-Smtp-Source: AGHT+IEWQsX4nHHOPolDMH8RHAQYMuz05njurzqufT54d212pXBeFCsCF87lXV/YDTpfjKA6JEvWwA==
X-Received: by 2002:a05:6512:280b:b0:523:da2d:6b8a with SMTP id 2adb3069b0e04-523da2d6cccmr8273023e87.24.1716238743067;
        Mon, 20 May 2024 13:59:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2355:b0:519:6fe8:c02e with SMTP id
 2adb3069b0e04-521e3033afbls1507377e87.0.-pod-prod-03-eu; Mon, 20 May 2024
 13:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUc10v5NYp6hXtsMyuTx9RHh31rQg6i/Lhh2kyMzE8kPqQnTVoWZY92Q1Yx6AEcATj7Skb+G2XlzgviV6glKLHN2DfUKSRVB/3BOw==
X-Received: by 2002:a05:6512:1152:b0:523:b3f6:8fb4 with SMTP id 2adb3069b0e04-523b3f69039mr9941785e87.46.1716238741384;
        Mon, 20 May 2024 13:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716238741; cv=none;
        d=google.com; s=arc-20160816;
        b=LkxT1dxg22Zipr7IkheI7HK6296yrYduCcONRNkJVoF1v43y2hpa/kbpBPqvs1tDcV
         Eucp+8Nx+1xeg9BUkb8CtTs/HIiftd3pUhVDWqCxcETk2HSprOQ6gSgQ04h8Fa0FwZhS
         wYqdjK1Wj5F+qhLS6fj+u5AnX8ZqYEgJLdjOhp4craejzL0VRgnnIR3lPTYJhwWa9zOO
         cl/FHRABZhrDuvvC3pAZEhB//75EFnJMp20T+SXFcF3EPrCPaqVsYom5Uix3gigLTtdK
         iHcnMB1kwjlKG3PUTQNYFZbX1FTZYivaO3oKDn6WqcUxddPRm4FFPdUbOoV020iLURJ8
         1Zqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dVtkm6Cg+QhrfgIVN0pjJZdjkLBJfP8oJdEHuFJPJQU=;
        fh=vzUw7PUiCZFQ+9TOy7Fqic/NTmihsgiz7wHWl8OdU2Q=;
        b=FISt6uEwIydv3TtPLp1mENsJK5M9Q13oqC4RTJ2rwdJmx97sOHui0G6G+8QTRwLXZ6
         OMeLM/mn+rEkQ3juBZGf3xbbhp6XB0Awp4wTmBhMeydz70QM/T2gVPeGN2xSQwx67sDd
         eDJZdiKnqonwy/onl4Uu1hEg5w1tIhs8rdvY8EUFAtpwvxer/oK+cATSx3sEiuXAypVi
         sWXi4CIvXEfYGGexeksPKt3bTxiIowAc845WVV4Io3Y3PCMX+UnJSflJKrO6gu7DQhK9
         dPSNzINOWkGm4Zo9E764uqhVgI4S5PJp6TrVL1nV+R7C3CSzo6chOWzQQuwKkc0AH/Ro
         pDxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C1JjhjK3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52231471aeesi548018e87.3.2024.05.20.13.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 May 2024 13:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
X-Envelope-To: stern@rowland.harvard.edu
X-Envelope-To: gregkh@linuxfoundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: penguin-kernel@i-love.sakura.ne.jp
X-Envelope-To: tj@kernel.org
X-Envelope-To: linux-usb@vger.kernel.org
X-Envelope-To: linux-kernel@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Tejun Heo <tj@kernel.org>,
	linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
Date: Mon, 20 May 2024 22:58:56 +0200
Message-Id: <20240520205856.162910-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=C1JjhjK3;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH
workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
interrupts enabled.

Thus, the remote coverage collection section in usb_giveback_urb_bh()->
__usb_hcd_giveback_urb() might be interrupted, and the interrupt handler
might invoke __usb_hcd_giveback_urb() again.

This breaks KCOV, as it does not support nested remote coverage collection
sections within the same context (neither in task nor in softirq).

Update kcov_remote_start/stop_usb_softirq() to disable interrupts for the
duration of the coverage collection section to avoid nested sections in
the softirq context (in addition to such in the task context, which are
already handled).

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Closes: https://lore.kernel.org/linux-usb/0f4d1964-7397-485b-bc48-11c01e2fcbca@I-love.SAKURA.ne.jp/
Closes: https://syzkaller.appspot.com/bug?extid=0438378d6f157baae1a2
Suggested-by: Alan Stern <stern@rowland.harvard.edu>
Fixes: 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH workqueue")
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 drivers/usb/core/hcd.c | 12 +++++++-----
 include/linux/kcov.h   | 44 +++++++++++++++++++++++++++++++++---------
 2 files changed, 42 insertions(+), 14 deletions(-)

diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
index c0e005670d67..fb1aa0d4fc28 100644
--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1623,6 +1623,7 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	struct usb_hcd *hcd = bus_to_hcd(urb->dev->bus);
 	struct usb_anchor *anchor = urb->anchor;
 	int status = urb->unlinked;
+	unsigned long flags;
 
 	urb->hcpriv = NULL;
 	if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
@@ -1640,13 +1641,14 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	/* pass ownership to the completion handler */
 	urb->status = status;
 	/*
-	 * This function can be called in task context inside another remote
-	 * coverage collection section, but kcov doesn't support that kind of
-	 * recursion yet. Only collect coverage in softirq context for now.
+	 * Only collect coverage in the softirq context and disable interrupts
+	 * to avoid scenarios with nested remote coverage collection sections
+	 * that KCOV does not support.
+	 * See the comment next to kcov_remote_start_usb_softirq() for details.
 	 */
-	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
+	flags = kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	kcov_remote_stop_softirq();
+	kcov_remote_stop_softirq(flags);
 
 	usb_anchor_resume_wakeups(anchor);
 	atomic_dec(&urb->use_count);
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index b851ba415e03..ebcfc271aee3 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -55,21 +55,47 @@ static inline void kcov_remote_start_usb(u64 id)
 
 /*
  * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
- * work around for kcov's lack of nested remote coverage sections support in
- * task context. Adding support for nested sections is tracked in:
- * https://bugzilla.kernel.org/show_bug.cgi?id=210337
+ * workaround for KCOV's lack of nested remote coverage sections support.
+ *
+ * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi?id=210337.
+ *
+ * kcov_remote_start_usb_softirq():
+ *
+ * 1. Only collects coverage when called in the softirq context. This allows
+ *    avoiding nested remote coverage collection sections in the task context.
+ *    For example, USB/IP calls usb_hcd_giveback_urb() in the task context
+ *    within an existing remote coverage collection section. Thus, KCOV should
+ *    not attempt to start collecting coverage within the coverage collection
+ *    section in __usb_hcd_giveback_urb() in this case.
+ *
+ * 2. Disables interrupts for the duration of the coverage collection section.
+ *    This allows avoiding nested remote coverage collection sections in the
+ *    softirq context (a softirq might occur during the execution of a work in
+ *    the BH workqueue, which runs with in_serving_softirq() > 0).
+ *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
+ *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
+ *    the middle of its remote coverage collection section, and the interrupt
+ *    handler might invoke __usb_hcd_giveback_urb() again.
  */
 
-static inline void kcov_remote_start_usb_softirq(u64 id)
+static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
 {
-	if (in_serving_softirq())
+	unsigned long flags = 0;
+
+	if (in_serving_softirq()) {
+		local_irq_save(flags);
 		kcov_remote_start_usb(id);
+	}
+
+	return flags;
 }
 
-static inline void kcov_remote_stop_softirq(void)
+static inline void kcov_remote_stop_softirq(unsigned long flags)
 {
-	if (in_serving_softirq())
+	if (in_serving_softirq()) {
 		kcov_remote_stop();
+		local_irq_restore(flags);
+	}
 }
 
 #ifdef CONFIG_64BIT
@@ -103,8 +129,8 @@ static inline u64 kcov_common_handle(void)
 }
 static inline void kcov_remote_start_common(u64 id) {}
 static inline void kcov_remote_start_usb(u64 id) {}
-static inline void kcov_remote_start_usb_softirq(u64 id) {}
-static inline void kcov_remote_stop_softirq(void) {}
+static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
+static inline void kcov_remote_stop_softirq(unsigned long flags) {}
 
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240520205856.162910-1-andrey.konovalov%40linux.dev.
