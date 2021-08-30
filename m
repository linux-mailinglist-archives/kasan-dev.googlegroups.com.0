Return-Path: <kasan-dev+bncBDGIV3UHVAGBBT5JWSEQMGQEUZUWORY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 552D43FBAE6
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:40 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id q18-20020a05651232b200b003d9019c6ae4sf3254878lfe.22
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344399; cv=pass;
        d=google.com; s=arc-20160816;
        b=vbSprS+0ZG4JrwG/68BNRuFCXTCA50DV+CuOllEPbgnG0Qfj5pMtc8hD0ldBnkfJAn
         ut4XvQbZUfDb0qaVZCItekkKsxBKHPrfD9wyJqMh26F9AdUNeUo/gdp88Yd0mpF58g+U
         hjJeiXOD3WhX0qaNyVxsgl+N+hbeCXRz9yCNZpfXlo6/BMS3MQz5D9MOczjl8tef4rFN
         DU8bBh+xu41Tol+aiTbhS5ib1VzppjwsBB74DZWJeabGh6kuq1VMVzjEABA3VgSNeuhl
         nA55vdpH63sCAX3Eyi+OEhCdbkKdVVnheyCRXGA0DBk+BCzGQt9ltEQIBiT+ZTWoJHrx
         WpEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dZaaTzR044YJCBlelfhTQsHWBpgzEsg0rPUKentEFaw=;
        b=u10ZD2hmrIvYY1DI1gImcKbd+KbcxmL51q3cmuSALeqk6KGEhhHm9vREtevDGcajgR
         bKsym1S6HhJ0hjDsTYb97tQmEMH5at3efBhIUwfj4q8BI/d06Tf3LF7xsFm2mzRj+8k9
         u3fW9QkQ/9kaaBMfQykoIVWbMuK2yMeHEiUpXAH6NV/V/oLKmw0ev1YkA6yns7yssHId
         nMeikr5peNIxnlzuz3cPAOLknfyd/2dZauSbgO1MkXciTIkW5fhBMdWri8wUFoOTiSsU
         JklF3TzO9h+98VEgJDXk3fgFW73XVsPISuuJFMfjtswLaiDGvV0so089JDlW8FA23u44
         LKZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ehsCfouJ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dZaaTzR044YJCBlelfhTQsHWBpgzEsg0rPUKentEFaw=;
        b=IW9lvIiz1SbPLJv/hnoFBWDRHdX3O41UyRveED4KWKEZxXOT5d0IEePQaCkyVVB55e
         G7C60K3Rox1jy5pkLdNSjOnKOAHWZ6C19dMmWEOL/hLPE7KkWdeWueY9qRC+eCycqGc1
         hYdEPyTFhALuRYkSSI8UhaQTu2CYKsTiaqm65I0zz4PRILp7TzEYnpcN7ABZUSur0hJJ
         O9bVosmbmLhL3U7KowtgfTTH9KTR5g9mX/0/j8h/BFck9NIDWJjIbGQXzt8EmF2/io4j
         G26zxzdZY1SKkFCAABr2dU1AFs0xNyPI7V7MEzfS3a9AtOykNnF/mg6GSO0raCLUoqhm
         P7+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dZaaTzR044YJCBlelfhTQsHWBpgzEsg0rPUKentEFaw=;
        b=LBT3vt8ONTXePj37l8natqwcoHDFK+N40GeBTs2nCasYAWBXneJWFf7Egj58kMT5K1
         +Z+UefTSOPXUPlViJUK/q3VH6cqCkNg1b/qo2JJEWBOVkc0GS4DxIuYWlMWnGmLcpA6h
         dILZyCvNNtqijuBXcyOUrHk3d2A+/iKkySEHYVf2jgYgVVz3lkujG16nT37rdV8JoiGw
         gSBHVZ+W1642bPueDbC4HgnwpTGWq4bEJV060hXBOXqI1rshaEylUQIA2H+OoldfXnwe
         1GcQq8umXA0J/Th6eueZfe+jQrnMjnYb49GQfeHQau9DdCo4RKCA2q1IodQhXqQNggbc
         bovA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mXMVTJ1p1X2oWlB25ISTfIwBB9+PD0kLjTGMCqnpc4Dgb9sQw
	D4EUngDTrKs6PhX+erXFd98=
X-Google-Smtp-Source: ABdhPJw6+75VZZjpFNG4wcxFJjioT2/h5rgm6abrv/spFXvxyD/YBeD8FGUVIa2/bfJSNXkcs7vQZw==
X-Received: by 2002:a19:ae05:: with SMTP id f5mr18091697lfc.117.1630344399862;
        Mon, 30 Aug 2021 10:26:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls1709607lfi.2.gmail; Mon, 30 Aug
 2021 10:26:38 -0700 (PDT)
X-Received: by 2002:a05:6512:e83:: with SMTP id bi3mr18149886lfb.420.1630344398860;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344398; cv=none;
        d=google.com; s=arc-20160816;
        b=AnXo2/nw2+cm8sxi+R/vy9gST7kLPqpBje0nLJbmJX2cso/NyiGviqwI5PI8DYLzXa
         Y4NjAGQS79uUNLiPZJO6hnzebP9j8OHclHAuyPHlnLOfzZpsHW8hER+MTQQaBNF//YW/
         2A76tJ0ndpfRq2rmEA4pt9Mi6r7s5nXdkdzGkDYrCc7rbONTChnwHvgSSP/Bw2OTjXnK
         l/qDgrno1vZNi2ZrvlW8UCXmI2MRBOhVUca0wTQY/oOj88sxxjdrVk/r2in7xtGpg3YH
         DeDXTy6lsrb6fSiN5TUC/h4iiWsmow8qXcFDhtnSB8LESu+2KJsvk3hg6HcFGOY+sfcL
         54Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=MLg28R0I4l42Wp7Kr6HQPjKRPPqXBv2DvuNgpG1iY5M=;
        b=ez1XZi+nqam8gNyRLSH4WwoFA8vXfrwjVGjmqhLCD/vftOHSRGCj6ghpG3totKOVYt
         PugefLTOKabMBKTf6IE0HNOH2k6MxincoQJgM8LugTvB9mlofxaSZyKdhU0dOSAheD5j
         7BWHCiUykNbrRjpH6OD7u3aOG2V4Kbm7IHMYuh5WpoEprHlvarayC2UjtaNP8zZr0ZjI
         x5c7kSPTGGpocGy+zFLpat+Hh+xBJRRiqrJBKv1FG/so6sCuNdSXDkkXv/dXyzNOMqyD
         w73yYPzYwo3HNj/2sfMtR7BYqIEIj67IVpy1f0xajV8vp5URgS7JinRm++nTq7Nmmo6g
         dPjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ehsCfouJ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id n6si813732lft.8.2021.08.30.10.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
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
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 5/5] kcov: Replace local_irq_save() with a local_lock_t.
Date: Mon, 30 Aug 2021 19:26:27 +0200
Message-Id: <20210830172627.267989-6-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=ehsCfouJ;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-6-bigeasy%40linutronix.de.
