Return-Path: <kasan-dev+bncBDTMJ55N44FBBSOYU3GQMGQECCXU25A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6EehBkysqWn0CAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBSOYU3GQMGQECCXU25A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1D0215449
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:11 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5a12f7bb92fsf678919e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727370; cv=pass;
        d=google.com; s=arc-20240605;
        b=FGzHcLkvSbBZ6UEx8qlFLWL3XVgp6cdW1jokX9TBVmX+/zH+JF4G1Io237j+wUmjaD
         4haH1gkfRgN5lQY9IYTPBprZjx1cfDV0CJKWM9wNSQr+3RCn0eZvklWonMLQxef1Qw7I
         pGhFtgzCGWSgZMODizUIE5F7jfTRidZ2bMZHzEqUAc1J9i9KStILNAmvxAPcYzjAQe6H
         0ouE1+sbNZJsUI0XxdPNpDw9mrewEpm084BrPCOdba75Omt9l7sYhoWroOmimsxI8VMr
         ZYLdEr++iu8e18UGd4ZSM0bWUFPx77F/qhyYQKTuysViFkUNbNcdiUFiC0M5OXJelEsl
         6qMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=s6MZlb4PVrEZ6PSx4FX4GqQRn93pj8pcQ0RwKVHa+t4=;
        fh=5Zm6kTw9O27/pu6ELO5l33KFcamDGDTnDsiVa40nEgM=;
        b=DMkNlmIVph3JrpUpqVclCpae9RzfX7+7H8cbj2W7XpLlY5nF4wRnN/yLDPEaapqu7S
         6IZjJl5JAr9XxOEgQVsZaDpUpkWVWEOvo83m4lkz2FEBPtC5oY0tHvlbRiHw/cqPqbeZ
         NJKFMRKsD4th4TIE/1R4W6Od4kSqMZnp+rmUYhkl+KKYSpWruJ1haJZo2ZCUuBCaUI21
         WqMEK5OBFewLVenLmXx0WLh3mYP3LZwnZ9bIecrZVou1TVqwJUXe5Utij9BtNitbIOTS
         8P0EqQEQ3ZkQwoX9nk+mo94rEV5SUyBh0Oir2XvF+nVUfn/ujkiJQpz4aktC9aq5Vkqf
         OrjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=ViA7B+iD;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727370; x=1773332170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s6MZlb4PVrEZ6PSx4FX4GqQRn93pj8pcQ0RwKVHa+t4=;
        b=wypL5d6r6g/w3JbnJdcy5Ax/yhdrgkgmrmo9nLPQz1EACo4pKlnRdUb5PXv9lCwF1r
         ZeWEx6/lbzpSOSe3MQkeHGP8siF0Vycssg54T2KFVqy7h/iwn0NNY2O6I2A4N44NuTYP
         05w1JC5wB/SN++Pc7WGtCGiQ4t3LSlCgLJwNFHxGzFxzA/Vv0+jtm0WlQFmFpbl3x72g
         RQsRGNkpz6Uu5glbk6QcuCNRyVcjsDNrLKZunW2N8fdgc+oUfbMSRNX0h1zXG5G5PkPL
         qk2yU6CAXEwmfYJKGQCDdmejpi09xULL08t0zBFrDNW6OVQvQ5u7D/8rQgqTffgJHfSa
         z7Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727370; x=1773332170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s6MZlb4PVrEZ6PSx4FX4GqQRn93pj8pcQ0RwKVHa+t4=;
        b=Sr+ecoLARAmO/tBE/M+S+Mo+0X8tS+xtbNAn24F37/EP8efOrTCNJFZMPTLt1q4oWS
         lfaFfDi/DfycvxjzAtx5TwT3Ul344JlFkmHqHeCGssFvsBC+E63v6ExHye79472YE3yM
         ziXh5KqLYXDG2TZwT9IlcSaYnV+1kO23sUDaXT604Lc6bO9MtnW0uOaCpAImjhGuSu4L
         lZT9JdGP/yEwQeztgoT565JUmE85bNaBBLeZCTgbHgs1Hpmpn+8KeZGhptBIXNBUsfiE
         NRhtskrcTB8sACFFnMNZKlCImAXG87wcUJwylPbeH3WGxZaCgIIJLY7aDxVYJnF0+rcx
         CEVw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJ3+G67l1PyDJq6AabSoX1cgZqlTgxKRtu7VXkRrlRpoilKfkDtbQSts+ypOljc2MTH/HFgg==@lfdr.de
X-Gm-Message-State: AOJu0YyB/SwBL5aNO9EAcLfNpNwFzNV7DnNbm+MTluzDVCQVT3DLVu3x
	6MofPkAPMktAzVxkSrzjTUHzHINGL+Hn7riH7p0oBr+3y9Vw+t+1Y4mU
X-Received: by 2002:a05:6512:12d0:b0:5a1:1914:2bac with SMTP id 2adb3069b0e04-5a12c2a09cemr1087172e87.25.1772727370466;
        Thu, 05 Mar 2026 08:16:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FyLPHmoVxlcepnP1/RDiNokxg+xrcHcrv+u3TidcHskw=="
Received: by 2002:a05:6512:a90:b0:5a1:2f9e:ec98 with SMTP id
 2adb3069b0e04-5a12fc4b3abls287624e87.2.-pod-prod-01-eu; Thu, 05 Mar 2026
 08:16:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUNhT/N1LK5LrSrCM4Z2H9WRaTcWTYVlssidZxpEHCfqWNbXvHSHVhUvd/4Z3kUHnMZAnvcMBvyaiI=@googlegroups.com
X-Received: by 2002:a05:651c:4418:10b0:389:fcc6:4923 with SMTP id 38308e7fff4ca-38a2c7b1ebamr28940861fa.36.1772727367327;
        Thu, 05 Mar 2026 08:16:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727367; cv=none;
        d=google.com; s=arc-20240605;
        b=B7KabQQ6VJSiWK5ufDPkWUGlePVClpTs1AEHsTf3HrZT7/aduAVvmA+nlu/XHfPMAk
         TmqZ6yigRenfhUOVJc44HSiteSVRBT2cNbf4lS6GwxJBrMNa4SHZP9x3Zt5iEQ53A1XK
         K32CWIFpLgI+fGuVfbFDboA9YJo6sRHx7mK4CF4cY2RtPqR5jnXFWrK7M7g+59QhGlJg
         R6TwL7+I5yt1HoMpc33p5B/IlXJwepSMZxEc6NIWbaT/neypBrG1RITfcvKHEow+gG0l
         vJyWkVSGch6WZXc3wmTkLxUV9AnK8Nd3CEy4H5OaOoOIIEVqYlFdbrWU9AYhaNWqMdPb
         FWGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=VZ95mweHQ1vmkIUmkfYL7umUDQqMZc9sVmEAZmR6MeU=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=IYlpwvk8xNMaDqEsju8L6IrPQGobfkV+RsuPs32EeQiUIjCfpF5SdTDTey5YHIRPGj
         jy8j0Poi9lpLt8E+zvtXlH3NEue8kQ75Q2hD2VTGfWCuwf+GB5i7NNxHZVGv45bLCkJv
         jjTo/L1/zgOUyWkzJf2ny/yPejavfUV52IgdGRXLqzhMtuRBoJ2vU9nGRRU5+UoiGz1S
         rlN0hfxthKLyf1PI84rtunhIY3vO22xFaHPD6/bLJPgW8CXlVJor1LUB8pvEGWgIm854
         fUhOP0lUIZXo75+PU6vCdsDyIcRMkATf0bsmN26bSTiWEWOwuOj/rwtv8aYo7yeSJnAk
         O2Aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=ViA7B+iD;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-389f2f03f78si5423301fa.1.2026.03.05.08.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:07 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMn-00GqqJ-CS; Thu, 05 Mar 2026 16:16:01 +0000
From: Breno Leitao <leitao@debian.org>
Date: Thu, 05 Mar 2026 08:15:38 -0800
Subject: [PATCH v2 2/5] workqueue: Rename pool->watchdog_ts to
 pool->last_progress_ts
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260305-wqstall_start-at-v2-2-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=3162; i=leitao@debian.org;
 h=from:subject:message-id; bh=6EydzvmFj8FtEPXreGAsQ9uPpRkJYUhi0mAr3wk1XNg=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqawz+HFuZiX3bVrygyQi68X7XuG2pybr6mKiT
 oX3kEA0dpmJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsMwAKCRA1o5Of/Hh3
 bfCDEACoGVew6HYwSbOZ+DkWskdcZiGfBoQr0laHxcHIq0agPX9g1LWjgEKN/3FQ7a1dBeI00EA
 UL91ZTGNg6YqYZAx//lXujrySlNEb0Ko7ZWnGlCeM9H0WsYVJgAlLIBrcPnDSPb0/V5HtbhY1cg
 Vja5yOXmlZSCP1ttjNX2lV6E7UXA79WTbmCfZ9gXJ1QpHq5cK9sM8D5Kjn08JdE4wofrOR9C9yO
 NCyTXPglYpPg+HuDurx0ztFC62CTLHiXtKqAxb28RKOtdM3rcxTVmPjJsFUX8xokE8Z3lAHfm/K
 u3LdZYHkSsJ2Si2ZN+L2+pCgA5QyUZLVXKgSRpskyDnmCJFzSYVLCyJUffBVUP6PYbGaI9fiBJ2
 1v1fcqrmw2d/gx9ODlugma2rZkjl/CfM99j0Q1PsE1+bxmeh0mcEU1qqDFO3Jpc8ZCHJYV7tin7
 4y1+l4KfHfSCYhM4kJjmOs9IgeopQprH8m6nWyg8fDd/w4KftudZ/uhBUuJZUMzqE9OryzNEGJE
 WaS3ulMLTLBDvRJI012R2NdCZuKdujposRxtglXHSX2lR5BOygws28gC+m2AEC/X9NdyAdjotTV
 RGgw22egYGcu+qU+emLklvtw4JW6ecVS1SugupFrPbnu5h8f6MCR5G+y+gtAtMKzWAAWB5Ojl1d
 uwkufkwMyEyxr6Q==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=ViA7B+iD;
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
X-Rspamd-Queue-Id: AD1D0215449
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
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBSOYU3GQMGQECCXU25A];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail-lf1-x13f.google.com:rdns,mail-lf1-x13f.google.com:helo]
X-Rspamd-Action: no action

The watchdog_ts name doesn't convey what the timestamp actually tracks.
This field tracks the last time a workqueue got progress.

Rename it to last_progress_ts to make it clear that it records when the
pool last made forward progress (started processing new work items).

No functional change.

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 kernel/workqueue.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 1e5b6cb0fbda6..687d5c55c6174 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -190,7 +190,7 @@ struct worker_pool {
 	int			id;		/* I: pool ID */
 	unsigned int		flags;		/* L: flags */
 
-	unsigned long		watchdog_ts;	/* L: watchdog timestamp */
+	unsigned long		last_progress_ts;	/* L: last forward progress timestamp */
 	bool			cpu_stall;	/* WD: stalled cpu bound pool */
 
 	/*
@@ -1697,7 +1697,7 @@ static void __pwq_activate_work(struct pool_workqueue *pwq,
 	WARN_ON_ONCE(!(*wdb & WORK_STRUCT_INACTIVE));
 	trace_workqueue_activate_work(work);
 	if (list_empty(&pwq->pool->worklist))
-		pwq->pool->watchdog_ts = jiffies;
+		pwq->pool->last_progress_ts = jiffies;
 	move_linked_works(work, &pwq->pool->worklist, NULL);
 	__clear_bit(WORK_STRUCT_INACTIVE_BIT, wdb);
 }
@@ -2348,7 +2348,7 @@ static void __queue_work(int cpu, struct workqueue_struct *wq,
 	 */
 	if (list_empty(&pwq->inactive_works) && pwq_tryinc_nr_active(pwq, false)) {
 		if (list_empty(&pool->worklist))
-			pool->watchdog_ts = jiffies;
+			pool->last_progress_ts = jiffies;
 
 		trace_workqueue_activate_work(work);
 		insert_work(pwq, work, &pool->worklist, work_flags);
@@ -3352,7 +3352,7 @@ static void process_scheduled_works(struct worker *worker)
 	while ((work = list_first_entry_or_null(&worker->scheduled,
 						struct work_struct, entry))) {
 		if (first) {
-			worker->pool->watchdog_ts = jiffies;
+			worker->pool->last_progress_ts = jiffies;
 			first = false;
 		}
 		process_one_work(worker, work);
@@ -4850,7 +4850,7 @@ static int init_worker_pool(struct worker_pool *pool)
 	pool->cpu = -1;
 	pool->node = NUMA_NO_NODE;
 	pool->flags |= POOL_DISASSOCIATED;
-	pool->watchdog_ts = jiffies;
+	pool->last_progress_ts = jiffies;
 	INIT_LIST_HEAD(&pool->worklist);
 	INIT_LIST_HEAD(&pool->idle_list);
 	hash_init(pool->busy_hash);
@@ -6462,7 +6462,7 @@ static void show_one_worker_pool(struct worker_pool *pool)
 
 	/* How long the first pending work is waiting for a worker. */
 	if (!list_empty(&pool->worklist))
-		hung = jiffies_to_msecs(jiffies - pool->watchdog_ts) / 1000;
+		hung = jiffies_to_msecs(jiffies - pool->last_progress_ts) / 1000;
 
 	/*
 	 * Defer printing to avoid deadlocks in console drivers that
@@ -7691,7 +7691,7 @@ static void wq_watchdog_timer_fn(struct timer_list *unused)
 			touched = READ_ONCE(per_cpu(wq_watchdog_touched_cpu, pool->cpu));
 		else
 			touched = READ_ONCE(wq_watchdog_touched);
-		pool_ts = READ_ONCE(pool->watchdog_ts);
+		pool_ts = READ_ONCE(pool->last_progress_ts);
 
 		if (time_after(pool_ts, touched))
 			ts = pool_ts;

-- 
2.47.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305-wqstall_start-at-v2-2-b60863ee0899%40debian.org.
