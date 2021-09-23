Return-Path: <kasan-dev+bncBDGIV3UHVAGBBN67WKFAMGQEAFHHWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id AA32A41638C
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:51 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id r9-20020a5d4989000000b0015d0fbb8823sf5638489wrq.18
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415671; cv=pass;
        d=google.com; s=arc-20160816;
        b=lgDh8sI+XdufY0E7eLaLu68odtECjOH0Nbhc82CgqoEkcNkmc8g8T6yJejvEN43c0j
         +ju4xR+k+yXfv/VHMGqz1frSwSa9nhAdRFMqDQ8ZPJBVaoQTxlByaXo3rUypp1E7D+u4
         UddQe/bt/7cawuR4bU3cYeFwIaG8m2u1MlOeZWCwRCgtDRwa6XJjStcJUjUPpTco+BNv
         DoNQ2Aa6EZ6kRbfRwkfYxDEzyKfdRotlQGTFzreUPteznJ1UpZEgNWw4rXEFzjXh/TqV
         oATLfwn+DBvfHXiMarWcY913toF37xiq62lRYNfJFPu9TaK3YvV2gs70AcOZzwGkmVju
         8udA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SkjGMxFRilUSyYoWae/YHF8ZYW9KQbS3kwULhQ1N8AE=;
        b=A6Cqsm6avrjcXb1bdrxiHp6CcZk+Zvh6R8nsjZudHOfKL+421HmEec1QLUQtMCxT9q
         HEu11lV+y3fsyXAm+3lb1VAP7A9xp7+eOv0tqkId9Ej28rD0Imt7Ou4hE/vnzRIu0q+/
         c5U1uVllsIColYGYTR9Sb07PVQyA4S82EWYQa0CIlwUUMcSTVrLSya4sDcy4Zb6GkGHY
         vEpnKHPKO98c/ZyFQbmUEpwh1jGAiOzKJ90R2CeGbUFDJ9Hle5jwwBcHEUL68TCy+sjF
         GSA2XlfpcHLqYCmcKlWk5nxdV8RHLmB33iN7w60dzwkxJRLSXH1nrjQ314AEXtVMzMPK
         HrBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JWe3kMMq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=2B6kHqoK;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SkjGMxFRilUSyYoWae/YHF8ZYW9KQbS3kwULhQ1N8AE=;
        b=shvaXr7PLsWjA5h6XYYaYUPZk0l2jVm0AmoJlrndKN/tlxVJQXMuXEFypPOITT3xTC
         wfo00fIZFKWpHA3gTEN41jzoo4a1WcW3plArFrtU8z+FkN3dwEW9PknqCV+88Hd1X26w
         7CTexDxpfyi9Bc7Rq3kQqeSPh2OybHayVmEtFV9JOI+ukE6OS4ukgR+roAx1JGI0frAA
         +gh5FpYUhay1++BQ+ESr8JOMSqOXrn8mKc5ZwUFxiYPjimwjCXVjnkzoOcCR4htOg4ck
         qx01nCdyTByj/9xOVBFq1dhmMmW9vzCkxrhnPIO8PRM+NusyGcbONJArJsWbKt4SsrXB
         Qh3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SkjGMxFRilUSyYoWae/YHF8ZYW9KQbS3kwULhQ1N8AE=;
        b=t33xbxnrqNQ+JkGzIvNbBXpEnkPWzi6Mdo8oNZrqlIv5tk8nSZc+eKipY8LAQtE7Lf
         YAwCYvxt8tvNS1f4oSgOMfFvNvUFEMb7zQzuZNIxV7oz3twpEHKIobOPewRVvNop7C2Z
         iRlFm5OM7zMl3sQXkB2oZvjatCQLqpdvlGMwpLyeHsSiJ0cHUR1GI2j9dV2QpA6kV/Du
         wnRW0wL8HRBr9Ks2KSN1mW3gpjGh6+j0+nkysG6s7/4jg+oEgoiJIKSQs0guYhieIDft
         T+TwCjgmvCjqkjtoLfz/eCH9bclGyoKOCvPox8h6fEATXSiaW8l6dqNxC3ds0lwd0fxn
         yl3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GRDEN8inL0hhciWxJ+UsAbIBSyUnfnZ7YfuyedFF99Mw2Kx8C
	JPlNiz+9B78U/CE0kdsElwc=
X-Google-Smtp-Source: ABdhPJzoQDdWG70EZL6sjhnpa+cjdAgS4IoY986LJW7fWA0P5VrXGze+3DG4W7Ze47cw9gslagbB4g==
X-Received: by 2002:a05:6000:1090:: with SMTP id y16mr6356233wrw.208.1632415671482;
        Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bd7:: with SMTP id e23ls1369809wrc.2.gmail; Thu, 23 Sep
 2021 09:47:50 -0700 (PDT)
X-Received: by 2002:a5d:6ca2:: with SMTP id a2mr6151243wra.291.1632415670745;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415670; cv=none;
        d=google.com; s=arc-20160816;
        b=EGBjUI/DGMIB4YOdj5ZbdeP0veHhuIKREhoECFKPwHFyouFPbqErkzCihfpFa4/E2d
         5XLwYPsEFjLI3l0NZSsj2PqTOsn/6ltxqHWocDM7dl2zviyNrDZnAObrjxEQRsaMmQZy
         3MhfYXNy2inXevNveChzZNFK2ZCyN4PxE4GPvFDd7iM1w7ISgiab3Yn0zH0Bg9YujVIs
         FqwbdQrTMjWrHLU7Uj7C6P/xYU/uvISoyYpC2/CukDo47AaHa4Gb2HjQ/Yio7wbTTYI0
         PAMi4TWQb9jG9JrnMQxGcVZ9DjvlXQI+Nlc3Weg6SsLWqBdc49Lthe7+p/zpqSH4palw
         M4Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=kn4h8q8DpMJPSv6z4C9SyTJmRzBjAT7j77L7iOFXSak=;
        b=LKsmIPli8ACGnGCihABvT2o2xAMbCLaqD0WfZEyD9IQIVIBJ/RtQ47fAkQQodkF61j
         uOv+zOJdfrKpJfuv2CutK3xKLhFwk8AN+6OflBIXmOw0mEWWp0+GO1KFHXTfmTLHhuro
         3f8n1I/luPEj79SUJqNHxnPUtdli4oNFzBUBeBtWXh8/4qGEg1XZrElCDXYBtNQ/ZkF9
         lH8/m7tG15QtpHzOj73fLbbb5jJHVUmFPwySw8bxdO0PjjTYJIyBDXrQ2pjdMjz6EsK9
         bS0MXnyG1SJuuiYhP89usm5bnhya7LX3hNMQvvBUr7SeSiFfQ2ay/7hU+L2VOKOkFs1i
         LDQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JWe3kMMq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=2B6kHqoK;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id e2si417456wrj.4.2021.09.23.09.47.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 5/5] kcov: Replace local_irq_save() with a local_lock_t.
Date: Thu, 23 Sep 2021 18:47:41 +0200
Message-Id: <20210923164741.1859522-6-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=JWe3kMMq;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=2B6kHqoK;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

The kcov code mixes local_irq_save() and spin_lock() in
kcov_remote_{start|end}(). This creates a warning on PREEMPT_RT because
local_irq_save() disables interrupts and spin_lock_t is turned into a
sleeping lock which can not be acquired in a section with disabled
interrupts.

The kcov_remote_lock is used to synchronize the access to the hash-list
kcov_remote_map. The local_irq_save() block protects access to the
per-CPU data kcov_percpu_data.

There no compelling reason to change the lock type to raw_spin_lock_t to
make it work with local_irq_save(). Changing it would require to move
memory allocation (in kcov_remote_add()) and deallocation outside of the
locked section.
Adding an unlimited amount of entries to the hashlist will increase the
IRQ-off time during lookup. It could be argued that this is debug code
and the latency does not matter. There is however no need to do so and
it would allow to use this facility in an RT enabled build.

Using a local_lock_t instead of local_irq_save() has the befit of adding
a protection scope within the source which makes it obvious what is
protected. On a !PREEMPT_RT && !LOCKDEP build the local_lock_irqsave()
maps directly to local_irq_save() so there is overhead at runtime.

Replace the local_irq_save() section with a local_lock_t.

Reported-by: Clark Williams <williams@redhat.com>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/r/20210830172627.267989-6-bigeasy@linutronix.de
---
 kernel/kcov.c | 30 +++++++++++++++++-------------
 1 file changed, 17 insertions(+), 13 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 620dc4ffeb685..36ca640c4f8e7 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -88,6 +88,7 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
 
 struct kcov_percpu_data {
 	void			*irq_area;
+	local_lock_t		lock;
 
 	unsigned int		saved_mode;
 	unsigned int		saved_size;
@@ -96,7 +97,9 @@ struct kcov_percpu_data {
 	int			saved_sequence;
 };
 
-static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data);
+static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
+	.lock = INIT_LOCAL_LOCK(lock),
+};
 
 /* Must be called with kcov_remote_lock locked. */
 static struct kcov_remote *kcov_remote_find(u64 handle)
@@ -824,7 +827,7 @@ void kcov_remote_start(u64 handle)
 	if (!in_task() && !in_serving_softirq())
 		return;
 
-	local_irq_save(flags);
+	local_lock_irqsave(&kcov_percpu_data.lock, flags);
 
 	/*
 	 * Check that kcov_remote_start() is not called twice in background
@@ -832,7 +835,7 @@ void kcov_remote_start(u64 handle)
 	 */
 	mode = READ_ONCE(t->kcov_mode);
 	if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
-		local_irq_restore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 	/*
@@ -841,14 +844,15 @@ void kcov_remote_start(u64 handle)
 	 * happened while collecting coverage from a background thread.
 	 */
 	if (WARN_ON(in_serving_softirq() && t->kcov_softirq)) {
-		local_irq_restore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 
 	spin_lock(&kcov_remote_lock);
 	remote = kcov_remote_find(handle);
 	if (!remote) {
-		spin_unlock_irqrestore(&kcov_remote_lock, flags);
+		spin_unlock(&kcov_remote_lock);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 	kcov_debug("handle = %llx, context: %s\n", handle,
@@ -873,13 +877,13 @@ void kcov_remote_start(u64 handle)
 
 	/* Can only happen when in_task(). */
 	if (!area) {
-		local_irqrestore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		area = vmalloc(size * sizeof(unsigned long));
 		if (!area) {
 			kcov_put(kcov);
 			return;
 		}
-		local_irq_save(flags);
+		local_lock_irqsave(&kcov_percpu_data.lock, flags);
 	}
 
 	/* Reset coverage size. */
@@ -891,7 +895,7 @@ void kcov_remote_start(u64 handle)
 	}
 	kcov_start(t, kcov, size, area, mode, sequence);
 
-	local_irq_restore(flags);
+	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 
 }
 EXPORT_SYMBOL(kcov_remote_start);
@@ -965,12 +969,12 @@ void kcov_remote_stop(void)
 	if (!in_task() && !in_serving_softirq())
 		return;
 
-	local_irq_save(flags);
+	local_lock_irqsave(&kcov_percpu_data.lock, flags);
 
 	mode = READ_ONCE(t->kcov_mode);
 	barrier();
 	if (!kcov_mode_enabled(mode)) {
-		local_irq_restore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 	/*
@@ -978,12 +982,12 @@ void kcov_remote_stop(void)
 	 * actually found the remote handle and started collecting coverage.
 	 */
 	if (in_serving_softirq() && !t->kcov_softirq) {
-		local_irq_restore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 	/* Make sure that kcov_softirq is only set when in softirq. */
 	if (WARN_ON(!in_serving_softirq() && t->kcov_softirq)) {
-		local_irq_restore(flags);
+		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
 
@@ -1013,7 +1017,7 @@ void kcov_remote_stop(void)
 		spin_unlock(&kcov_remote_lock);
 	}
 
-	local_irq_restore(flags);
+	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 
 	/* Get in kcov_remote_start(). */
 	kcov_put(kcov);
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-6-bigeasy%40linutronix.de.
