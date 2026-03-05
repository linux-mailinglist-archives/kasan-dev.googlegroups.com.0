Return-Path: <kasan-dev+bncBDTMJ55N44FBBUOYU3GQMGQEKBIUCUY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YKo/GlOsqWmtCAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBUOYU3GQMGQEKBIUCUY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 03FA2215457
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:18 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-389fc2e6433sf80340011fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727378; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bw1Vuo1eHCm9rW5VR8gP/VmkcTCDrsxnVARza+QCbk/EtjNmWLmvp66HHHk3HcVTY5
         ntoxnY8bmgYnHpSqsmj55BuFFIIdQupkovXdy4vEuDPZOBbsEMDHi5EFBiYCoCpYDj2P
         CPv4XnXZw1ZzxZhANqxYYHkX+VLcqq1lg2B/cCZRo6ROHZ+FjtffnXIZqFEev1eoNXjv
         RiQ6OHEDTQvugZv50VZCnGA+BRLSa2ewCWYwOOTFLB8Ix1mSZrVehpgOw2bBhGD16fqD
         DfnUH43EJcxfj1pN3Sw9sfxsk67+bmB+19TuuwV4RsA8MMN7dM9Hsz5XyX7st5cttap6
         zS0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:content-transfer-encoding:mime-version:subject:date:from
         :sender:dkim-signature;
        bh=tHm58NJQXWikC9udTXE7aPHm/8iBaBS7iP3dMSGGY2o=;
        fh=BmyCto+a9snT73FUiu+RJFjpq6tfHEeY70etb6pE+Pc=;
        b=j0R2nscVR/yzBN0U7ertl2qxEWV8yQ+5Ti2okNhsL7MD2v4kT+E4OtNJckB2JgPNWW
         llnVBdqChtSKQdRa/5Qi+Lz38vmFypajPy3Ob67c36tFfOCO2Mha9QsOcus7lxZ3QK74
         aE/ZR0DhNoRHlCodpMBzRuzUmk0s0iVLstwDDbWA8f5LKE7GuKW7OHtc7Rvks7iGeUiz
         nX79TZL2BYMiOfcTc8RsBf6JF+cRQZCFTxdcujWwKWckTl3o3uYzjmQfQazMPdTt04CH
         TVgpciIf/1nKl+r7Aw9qQxM8OcfBwNb3TsKu0bVb/aQB9mq/nm3qMD4gMO3fTI7Gj8a6
         5vLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=aapduRpW;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727378; x=1773332178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tHm58NJQXWikC9udTXE7aPHm/8iBaBS7iP3dMSGGY2o=;
        b=S+CM6e3h+2SbQDsjLlToBZxeslpwhCN3LPQQlji+Jn1t4Kj5UcrNXf7ivnD7yxuVPP
         bQlV3vs6TfLSBcg3cpr+PEfacm/vigA1jqIu4lleGrp1zGNozZpqU/mmb+qZoRJm7sai
         QxLeasKNaVyjGqSiMT+kbWhQkY1toTN0/xGZAh547HupSadQVX8j8kXqFxmgdBCqQAnQ
         iI8Tv4GSbR5NdC5n9RHzHOgg8d/+r5oNoLI1QX40EqXerL0tHK6aGGxvxY5mQXYm2nZm
         DSHjEDydiuBfDYBZ0Jxnp5fsXCMSVYB6CSdm1VZPHyEn2TqsVvRHLY4BG8ki4oeoWC4v
         EdvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727378; x=1773332178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tHm58NJQXWikC9udTXE7aPHm/8iBaBS7iP3dMSGGY2o=;
        b=qfSEPnXtm/zbpf1kz/zbgcChUoDgh3jSEB6zjqHWsTC6mSPL9bnvY/+QsC9BmSoLu9
         8MLPaqijc5RnNLsenBnUfm6IwcyrST8WvES2rOxa/ZFPrZLTAEuJ7hS/jdpxlvVFdroj
         5lUGaoPYHf9Uv0fwz4vlD3WI7TEx9cP0ASKF/Z6wyEG3o0LC3WVYDMoTQ6Ixq+qiIAMW
         uvrnGORwnThe9kd2LLBvF9kqLqHPr1bLjJou/qfFhaZuQDF/GXiGJmwtH0QJ4c7KhzkO
         Bhr5RdJ+bweqn8ffqFzDW9+x+kTZ6ARAe328ebuguyR/4t/r/2SahhigouO3DtKPYhlM
         ho0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxojnKDrLiM0UyCwfCIs0fPDE3p4n8YuLNtNC9sQp9uLC8/noS8oCHcbCsVufH9242eNj2GQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywai6aVkw8j6IWu437tuvoU8EjNbBbxnDMLg0osIslXVVQ60+cC
	WgYaH+I8DJn3YATVUdd1UTTBGBd7ghwQp0SvuCUWFZ5tKy46is7yon5O
X-Received: by 2002:a05:651c:1587:b0:37b:a955:d497 with SMTP id 38308e7fff4ca-38a3c819b26mr156491fa.17.1772727377715;
        Thu, 05 Mar 2026 08:16:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H4xCApf8OitZBLXJUBV6hAd+WPginbFWPbkrOrniUYpA=="
Received: by 2002:a2e:9e8e:0:b0:378:cfe9:cbdd with SMTP id 38308e7fff4ca-38a33931d4cls2073801fa.1.-pod-prod-07-eu;
 Thu, 05 Mar 2026 08:16:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8Y+OrTJVrdSCtL8IvX0p3PQIEG8OI/sQxZxKfO9hN2ke3/Wj7w2WGtUqqG9BxQiIqzN032RtfTGk=@googlegroups.com
X-Received: by 2002:a05:651c:2113:b0:38a:5fb:46ab with SMTP id 38308e7fff4ca-38a3c706a14mr167471fa.3.1772727375101;
        Thu, 05 Mar 2026 08:16:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727375; cv=none;
        d=google.com; s=arc-20240605;
        b=G86ANkTt4FVs3rWTMzgKGpABH+IASBoCT/yJ0i+QGW/CUiavw/AbPIwSXKa9ai6xKq
         7W41Hn8ucX24Y/3f1m6TjNdpqFLci2iOUTZqvJxWu4uyyWzCGhSm1dg+Gf8obMfzT15M
         JAaIRWa6ecmGWM3SIQT/vZ1RTXZvgRuS3Ruq5YFicuEWY1j8AX3F/bGsWV9WdtA9fZL9
         +fcBt1XIomsP1asIrL54dyASqFLYMmVQiR5tP1sR1E3pgAE/NI9XKPBhlvIRcf+JIaTH
         PgsuTqrbGz4j9vSw4AqUTODzNmzL1vRvrRbt1q0g1s1zpz8JdHPpwZXoqlHHzYeWvMtR
         vxrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=jrNtcuD0+LCQ0GXSBo8d49WJRSGDNH67GbmqlwT7i6o=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=R7AjTeTdI4PJcd98cPuYOeHuTBRuwpHv8FEapM0lnMlHJP7j7K3aveOSqmYGry+0eH
         CiQKzH+YK0kPjcmSgXIBuAYPaWypGgso5YPGWvDj0smNIXecuABqNTXgmguO1SU/ZBEN
         VzI1wMuak+/bbe8WnFGuU1Q7BvOo64Usl+AApFddnIlys4FwqEhZg6QEjPAk5893FK99
         1dPspid6fosEJAgDk4eAQVB5meVCR6y2N30ihFODd7FhHI+KkDrMTXIKe6oMM+XYPZ1t
         TadCaaJwVQgIwP13w6P7OJe5PCSthIQp400WDv2e8T98EwO8kKXg2ZpcvXG+h1Ol9nFN
         wLgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=aapduRpW;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-389f2f03f78si5423391fa.1.2026.03.05.08.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:15 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMv-00Gqr5-8S; Thu, 05 Mar 2026 16:16:09 +0000
From: Breno Leitao <leitao@debian.org>
Date: Thu, 05 Mar 2026 08:15:40 -0800
Subject: [PATCH v2 4/5] workqueue: Show all busy workers in stall
 diagnostics
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Message-Id: <20260305-wqstall_start-at-v2-4-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=2985; i=leitao@debian.org;
 h=from:subject:message-id; bh=LiVumjyG7bZ7XQH4sr3/408yTD7fFBw48LSnf9KFbjI=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqaw0+4KdZ1bZ/6RpgPjb98Fi8CGUtO1g7SggT
 on9De5+jP+JAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsNAAKCRA1o5Of/Hh3
 bSaHD/0WfWVWoTO9dH+aT+BJlfv+wRrNM9nWl1eUAw5aSDz69XE2hBRkzbgWKF7ycmt+P5sliJx
 G5fdRj6tOfTf8YDTTbNudxf/qmYdZ7gAPQ4R75j7wxKEPoBA6Y23XjvF+eGwG8H1W1+qtE5hCzz
 4MhqReGF5zXfvKkGWlW5rDnWlGvPJjG0U4aq0tnZQ2S7C9rz0MNL5Wt2Xf6iMMk12e1tfB6FSu9
 d6/yBGagM/9aHFUVH4Mvt5RtVZW6IgFNehEnuc08Wr+HPD+tQ1+5spzRyiG93sgEv49arg8rPlS
 lcCErKK5lzG+5zUcv5VNqIFePO6oDxu/xKTDGc7Jqo7m1EigED7/r4yoI2wJIsmOKIVun54KxUr
 BsDOC5KUXDdZsppfkmm5jUnPzwyWyG1wJW4Vp3ozZ6R0yBj7W+GqkydIW0YVjrhrLXDFVdUOTU6
 dfVM6w8m/FjsYJ6LNJ3/sjqJfbhSi7IK2VVHUbMwxzaeDYhPOp9fRqSVWXVyDzpHmrBugMxhbWv
 m3viWlEenK47t+E5fNh0OI4WK6fzquRtvcHmEIBTl/aV+5TTqGHuySOCJ+xTXEplYyWjrBeZNNb
 fXEUesWeDhbCI4OsIeZ+QP34npN7TlsEaaZPzz+Onf/HsJSCji9c2mjvdDGpcL5N0jcVIrTWqDU
 EyUOA2gEGX/pIrw==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=aapduRpW;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Rspamd-Queue-Id: 03FA2215457
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,linux-foundation.org];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBUOYU3GQMGQEKBIUCUY];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail-lj1-x237.google.com:rdns,mail-lj1-x237.google.com:helo]
X-Rspamd-Action: no action

show_cpu_pool_hog() only prints workers whose task is currently running
on the CPU (task_is_running()).  This misses workers that are busy
processing a work item but are sleeping or blocked =E2=80=94 for example, a
worker that clears PF_WQ_WORKER and enters wait_event_idle().  Such a
worker still occupies a pool slot and prevents progress, yet produces
an empty backtrace section in the watchdog output.

This is happening on real arm64 systems, where
toggle_allocation_gate() IPIs every single CPU in the machine (which
lacks NMI), causing workqueue stalls that show empty backtraces because
toggle_allocation_gate() is sleeping in wait_event_idle().

Remove the task_is_running() filter so every in-flight worker in the
pool's busy_hash is dumped.  The busy_hash is protected by pool->lock,
which is already held.

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 kernel/workqueue.c | 28 +++++++++++++---------------
 1 file changed, 13 insertions(+), 15 deletions(-)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 56d8af13843f8..09b9ad78d566c 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -7583,9 +7583,9 @@ MODULE_PARM_DESC(panic_on_stall_time, "Panic if stall=
 exceeds this many seconds
=20
 /*
  * Show workers that might prevent the processing of pending work items.
- * The only candidates are CPU-bound workers in the running state.
- * Pending work items should be handled by another idle worker
- * in all other situations.
+ * A busy worker that is not running on the CPU (e.g. sleeping in
+ * wait_event_idle() with PF_WQ_WORKER cleared) can stall the pool just as
+ * effectively as a CPU-bound one, so dump every in-flight worker.
  */
 static void show_cpu_pool_hog(struct worker_pool *pool)
 {
@@ -7596,19 +7596,17 @@ static void show_cpu_pool_hog(struct worker_pool *p=
ool)
 	raw_spin_lock_irqsave(&pool->lock, irq_flags);
=20
 	hash_for_each(pool->busy_hash, bkt, worker, hentry) {
-		if (task_is_running(worker->task)) {
-			/*
-			 * Defer printing to avoid deadlocks in console
-			 * drivers that queue work while holding locks
-			 * also taken in their write paths.
-			 */
-			printk_deferred_enter();
+		/*
+		 * Defer printing to avoid deadlocks in console
+		 * drivers that queue work while holding locks
+		 * also taken in their write paths.
+		 */
+		printk_deferred_enter();
=20
-			pr_info("pool %d:\n", pool->id);
-			sched_show_task(worker->task);
+		pr_info("pool %d:\n", pool->id);
+		sched_show_task(worker->task);
=20
-			printk_deferred_exit();
-		}
+		printk_deferred_exit();
 	}
=20
 	raw_spin_unlock_irqrestore(&pool->lock, irq_flags);
@@ -7619,7 +7617,7 @@ static void show_cpu_pools_hogs(void)
 	struct worker_pool *pool;
 	int pi;
=20
-	pr_info("Showing backtraces of running workers in stalled CPU-bound worke=
r pools:\n");
+	pr_info("Showing backtraces of busy workers in stalled CPU-bound worker p=
ools:\n");
=20
 	rcu_read_lock();
=20

--=20
2.47.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260305-wqstall_start-at-v2-4-b60863ee0899%40debian.org.
