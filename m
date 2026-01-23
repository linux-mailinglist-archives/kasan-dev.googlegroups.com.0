Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SBZfC+Eac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:21 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD793712C3
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:20 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-435a11575ecsf1236078f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151200; cv=pass;
        d=google.com; s=arc-20240605;
        b=aBFqBiuQ1VHo3DdbAT2qncoHWD4pn8n3att/hrUyiT9vxj2XpBng4DfJp5K6ZLrK0B
         X/78CwNHNJbhHGXtzbfwoOA02hyjeEdVuIqKZBn/VPP33klROfX5x2jjcX/1oBSAdSH9
         Ympfh+Pvkjkf/2C0WKzNRfoQfEi8lxhg0oIOW2ZmoT+VIJD/XBE5i8E07gU5xGTBkwPn
         kN8PingGhMz0INFqGJ76WxwFw1hlGew8LIdleRpipA+cwR5DtOItlS+w+LHhbNEeBHNv
         ulekRFKEJv36cLvAtKxdysFgV5+8ctqWL2yrX9nZZ6ytbOsercAtFgMnuttBWYF5wN1I
         p00w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=x25+Vs4s/FcwYigDimnl4edGZqIOTh83KYuxYKeMKIQ=;
        fh=uAetE5oit6e505yQOw6Mk1zG2q2MGR/2HqSz9DPHGP4=;
        b=IUX7qgqdGB4m/HVoIJB88C3bQel64JKn04K5TaioSeVsjtH4Xm73NaLwGMztvLdz0F
         dmwxX0VrYDtglAKfe41dUjBS9qGdVeu1VlGhTFPDU1mQ13pVp8kYrdOuOA1/k3Y9egxE
         6pwUI3g6NQCiXmns5hu0G7o2tkCakPHRiqVV6AHIhoLgatmYwmtzcCvRKvuOzbXnN9As
         DUg1Lxz/tJrYPFKBOTIw3lF1qSYI6d25mxv9fTPgQv7bTieVOKPwWAwdGp9b0icnWSuf
         90xEyw6p+C9aVPP8mcPJ/ew0BO+5TSDU6RJKTuPJpvaGjaZh9DeCnLNjw3T1zN3mD/Vk
         YOyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151200; x=1769756000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x25+Vs4s/FcwYigDimnl4edGZqIOTh83KYuxYKeMKIQ=;
        b=Kfur2P7y4EjaPoa9MeZnYxLwF3hptm7kfSOgkQSHOCFqSJoVjvaRE6hMblFNTod1wv
         JonEDIZ3TNNePWP9bi9b+FsnkqMBjkSCEPhIoB01PkeD58RoDhUIg4n4not9CJm4UJta
         UakNHWM3PvyEmOV86ISW04hdOSuCubS6hhpkpQ1nglYo/Jt+m/KAys2db5J/Q5sPKfhB
         aFUeRD/8/iqRJMYOQUwJNSGyayvwvAj5GOqzlXdFMAJRIdw9NgEFRjs1eTdZNtlmrD3Z
         rDgHQfEWQe8A2QRGxMkriOdZnIyY8FEKfYodzH5nez4zdx+5OOp6DLjIAIvJ2/t+88Zv
         bp+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151200; x=1769756000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x25+Vs4s/FcwYigDimnl4edGZqIOTh83KYuxYKeMKIQ=;
        b=abv/0fju0vTvCxHaWskOisQ+ttYFor9+GblWIkUlXThzTY8/PxaH+QpMYPORN4kB52
         PlVuHfSv2dcovrKYEyTi4ZNv9sSoQNnhCkEjhV0TyacJt6gcmRn40tXKHoSSK5XmD3IN
         fcX8vuZXdIoEKgw990NiOvlX0KzFWpr01FvpzBC8K3Q6rixqw1sEcAtHizeXW8L+8NNq
         r9/y0bN7K3IT+ZtWRvTmQpVeC1jCdmCy5ChdNwCbnHdPyh0TdwXHv/hv1D43HQpmBnOO
         JpKOtk2qizyrylu7PYdiFvRnqmVninzJldrbH66Uv+uLMFqYRerQxYeHRBZizNj5kTVy
         qXSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTqnHWNzJKo+4eUe6sHFFggAy0HEOnq802BRRjQJVYoFbtsu4jcZen6/ejnfB/6qBFM8C7rw==@lfdr.de
X-Gm-Message-State: AOJu0Ywb8FbmvA09RNSLCiQjTdqRmyW4AaDggUOuap8XWOaQH6WjhHIk
	Q7v7zCFO4nXfoSLTkEIXBe/MSc+3DNx4olBurvFndhYtNJMQPrDFH89+
X-Received: by 2002:a05:6000:18a7:b0:435:a363:f2a4 with SMTP id ffacd0b85a97d-435b15f9233mr3041873f8f.34.1769151199947;
        Thu, 22 Jan 2026 22:53:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GdmpEWQl1cip+8axEN2+ZtlmPqt5rCNhOlkNEec2tSLw=="
Received: by 2002:a05:6000:4382:b0:435:a126:d539 with SMTP id
 ffacd0b85a97d-435a667ffd4ls1070142f8f.2.-pod-prod-09-eu; Thu, 22 Jan 2026
 22:53:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXS14CjGVT2U2oh/owwTawUGOY8Z0n6ox7uuXmlaAGbX7aqP7M1hodGX7rRvcP6FTl5I3aco6mTtYc=@googlegroups.com
X-Received: by 2002:a05:6000:4022:b0:434:24fe:b25f with SMTP id ffacd0b85a97d-435b15fa09emr3118127f8f.37.1769151197804;
        Thu, 22 Jan 2026 22:53:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151197; cv=none;
        d=google.com; s=arc-20240605;
        b=VuDm5BpiBgyL5iknAyu0XQvwqN9gRNIhLOjk6t20gu3/TcWs/8r1z/rfh7xEBTDfji
         EBwP1wcb98Dnn7dKdmiqTQQ+I8y7a1C1qmM70ZzRhireuelguso8weZfqeOAnlyxIWve
         likl2WlbSF8QMoOXh+dITI8+PZ0S6cs90BZ8Wm+9Ev7SDeOiNY/KyCM3kAeoihiF5QTZ
         +oq3meF+HJwN47t5hFSoK63iXZLZ0FfWY41Vxv8GhXsm32poiSQVxQOqH8Lhrb2pSgmM
         mY0VFEI0oWCi4ouQSJPYzY25I2U9JnTT9OXuteHoCuIUQQOTGSlf4io94JAQQZZBB58I
         BYdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=5LUNr88zjhX+hkWnDoeUdsyPIuhpIM8czLHZWHOSyuc=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=DnC6fBvmIU0MyX3RAAaCgOf8scOUV+LqsYzJlE5tLhi7tlXHF/5GQhAgqZF9BpT3Mv
         BtpOLTjt7w/CNBit/UPFe3/5qrTOIVNc4LiXFoPStce9BNhcuL0XAAH5rKFDO+afqH71
         1g3oNwRZl9pKbtO449OEVC2sIAlwCTQ3NCRVC9SLX+73rbCCUTrg+chRooBQJHlY20HN
         kd27fuu2TcePFdUpvW2mUT9Sv/zq+pJ4wCTz4uW7/+is8jx9Pg1/CA1O4JD81GNoae5D
         CO3ecq8mzVTyhUmwXBMt2wThjvS/TVmBn3xUzulmVQSv375gbyWbWU910f5I1K8RbmoP
         2vxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1bfa5f5si39116f8f.1.2026.01.22.22.53.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B6AB33376B;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CBC35139EE;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GAx4MdUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:45 +0100
Subject: [PATCH v4 07/22] slab: introduce percpu sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.980];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email,mail-wr1-x43a.google.com:helo,mail-wr1-x43a.google.com:rdns]
X-Rspamd-Queue-Id: BD793712C3
X-Rspamd-Action: no action

Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
sheaves enabled. Since we want to enable them for almost all caches,
it's suboptimal to test the pointer in the fast paths, so instead
allocate it for all caches in do_kmem_cache_create(). Instead of testing
the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
kmem_cache->sheaf_capacity for being 0, where needed, using a new
cache_has_sheaves() helper.

However, for the fast paths sake we also assume that the main sheaf
always exists (pcs->main is !NULL), and during bootstrap we cannot
allocate sheaves yet.

Solve this by introducing a single static bootstrap_sheaf that's
assigned as pcs->main during bootstrap. It has a size of 0, so during
allocations, the fast path will find it's empty. Since the size of 0
matches sheaf_capacity of 0, the freeing fast paths will find it's
"full". In the slow path handlers, we use cache_has_sheaves() to
recognize that the cache doesn't (yet) have real sheaves, and fall back.
Thus sharing the single bootstrap sheaf like this for multiple caches
and cpus is safe.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |  12 ++++++
 mm/slab_common.c |   2 +-
 mm/slub.c        | 123 ++++++++++++++++++++++++++++++++++++-------------------
 3 files changed, 95 insertions(+), 42 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index cb48ce5014ba..a20a6af6e0ef 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -277,6 +277,18 @@ struct kmem_cache {
 	struct kmem_cache_node *node[MAX_NUMNODES];
 };
 
+/*
+ * Every cache has !NULL s->cpu_sheaves but they may point to the
+ * bootstrap_sheaf temporarily during init, or permanently for the boot caches
+ * and caches with debugging enabled, or all caches with CONFIG_SLUB_TINY. This
+ * helper distinguishes whether cache has real non-bootstrap sheaves.
+ */
+static inline bool cache_has_sheaves(struct kmem_cache *s)
+{
+	/* Test CONFIG_SLUB_TINY for code elimination purposes */
+	return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
+}
+
 #if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
 #define SLAB_SUPPORTS_SYSFS 1
 void sysfs_slab_unlink(struct kmem_cache *s);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 5c15a4ce5743..8d0d6b0cb896 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -2163,7 +2163,7 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
  */
 void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
 {
-	if (s->cpu_sheaves) {
+	if (cache_has_sheaves(s)) {
 		flush_rcu_sheaves_on_cache(s);
 		rcu_barrier();
 	}
diff --git a/mm/slub.c b/mm/slub.c
index 594f5fac39b3..41e1bf35707c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2846,12 +2846,23 @@ static void pcs_destroy(struct kmem_cache *s)
 {
 	int cpu;
 
+	/*
+	 * We may be unwinding cache creation that failed before or during the
+	 * allocation of this.
+	 */
+	if (!s->cpu_sheaves)
+		return;
+
+	/* pcs->main can only point to the bootstrap sheaf, nothing to free */
+	if (!cache_has_sheaves(s))
+		goto free_pcs;
+
 	for_each_possible_cpu(cpu) {
 		struct slub_percpu_sheaves *pcs;
 
 		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
 
-		/* can happen when unwinding failed create */
+		/* This can happen when unwinding failed cache creation. */
 		if (!pcs->main)
 			continue;
 
@@ -2873,6 +2884,7 @@ static void pcs_destroy(struct kmem_cache *s)
 		}
 	}
 
+free_pcs:
 	free_percpu(s->cpu_sheaves);
 	s->cpu_sheaves = NULL;
 }
@@ -4030,7 +4042,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
 
-	if (!s->cpu_sheaves)
+	if (!cache_has_sheaves(s))
 		return false;
 
 	pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
@@ -4052,7 +4064,7 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	s = sfw->s;
 
-	if (s->cpu_sheaves)
+	if (cache_has_sheaves(s))
 		pcs_flush_all(s);
 
 	flush_this_cpu_slab(s);
@@ -4157,7 +4169,7 @@ void flush_all_rcu_sheaves(void)
 	mutex_lock(&slab_mutex);
 
 	list_for_each_entry(s, &slab_caches, list) {
-		if (!s->cpu_sheaves)
+		if (!cache_has_sheaves(s))
 			continue;
 		flush_rcu_sheaves_on_cache(s);
 	}
@@ -4179,7 +4191,7 @@ static int slub_cpu_dead(unsigned int cpu)
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
 		__flush_cpu_slab(s, cpu);
-		if (s->cpu_sheaves)
+		if (cache_has_sheaves(s))
 			__pcs_flush_all_cpu(s, cpu);
 	}
 	mutex_unlock(&slab_mutex);
@@ -4979,6 +4991,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!cache_has_sheaves(s))) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	if (pcs->spare && pcs->spare->size > 0) {
 		swap(pcs->main, pcs->spare);
 		return pcs;
@@ -5165,6 +5183,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		struct slab_sheaf *full;
 		struct node_barn *barn;
 
+		if (unlikely(!cache_has_sheaves(s))) {
+			local_unlock(&s->cpu_sheaves->lock);
+			return allocated;
+		}
+
 		if (pcs->spare && pcs->spare->size > 0) {
 			swap(pcs->main, pcs->spare);
 			goto do_alloc;
@@ -5244,8 +5267,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	if (unlikely(object))
 		goto out;
 
-	if (s->cpu_sheaves)
-		object = alloc_from_pcs(s, gfpflags, node);
+	object = alloc_from_pcs(s, gfpflags, node);
 
 	if (!object)
 		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
@@ -5353,18 +5375,10 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
 	struct slab_sheaf *sheaf = NULL;
 	struct node_barn *barn;
 
-	if (unlikely(size > s->sheaf_capacity)) {
+	if (unlikely(!size))
+		return NULL;
 
-		/*
-		 * slab_debug disables cpu sheaves intentionally so all
-		 * prefilled sheaves become "oversize" and we give up on
-		 * performance for the debugging. Same with SLUB_TINY.
-		 * Creating a cache without sheaves and then requesting a
-		 * prefilled sheaf is however not expected, so warn.
-		 */
-		WARN_ON_ONCE(s->sheaf_capacity == 0 &&
-			     !IS_ENABLED(CONFIG_SLUB_TINY) &&
-			     !(s->flags & SLAB_DEBUG_FLAGS));
+	if (unlikely(size > s->sheaf_capacity)) {
 
 		sheaf = kzalloc(struct_size(sheaf, objects, size), gfp);
 		if (!sheaf)
@@ -6082,6 +6096,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 restart:
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!cache_has_sheaves(s))) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	barn = get_barn(s);
 	if (!barn) {
 		local_unlock(&s->cpu_sheaves->lock);
@@ -6295,6 +6315,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 		struct slab_sheaf *empty;
 		struct node_barn *barn;
 
+		/* Bootstrap or debug cache, fall back */
+		if (unlikely(!cache_has_sheaves(s))) {
+			local_unlock(&s->cpu_sheaves->lock);
+			goto fail;
+		}
+
 		if (pcs->spare && pcs->spare->size == 0) {
 			pcs->rcu_free = pcs->spare;
 			pcs->spare = NULL;
@@ -6691,9 +6717,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		return;
 
-	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
-				     slab_nid(slab) == numa_mem_id())
-			   && likely(!slab_test_pfmemalloc(slab))) {
+	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
+	    && likely(!slab_test_pfmemalloc(slab))) {
 		if (likely(free_to_pcs(s, object)))
 			return;
 	}
@@ -7396,7 +7421,7 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 	 * freeing to sheaves is so incompatible with the detached freelist so
 	 * once we go that way, we have to do everything differently
 	 */
-	if (s && s->cpu_sheaves) {
+	if (s && cache_has_sheaves(s)) {
 		free_to_pcs_bulk(s, size, p);
 		return;
 	}
@@ -7507,8 +7532,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		size--;
 	}
 
-	if (s->cpu_sheaves)
-		i = alloc_from_pcs_bulk(s, size, p);
+	i = alloc_from_pcs_bulk(s, size, p);
 
 	if (i < size) {
 		/*
@@ -7719,6 +7743,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
+	static struct slab_sheaf bootstrap_sheaf = {};
 	int cpu;
 
 	for_each_possible_cpu(cpu) {
@@ -7728,7 +7753,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
 
 		local_trylock_init(&pcs->lock);
 
-		pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
+		/*
+		 * Bootstrap sheaf has zero size so fast-path allocation fails.
+		 * It has also size == s->sheaf_capacity, so fast-path free
+		 * fails. In the slow paths we recognize the situation by
+		 * checking s->sheaf_capacity. This allows fast paths to assume
+		 * s->cpu_sheaves and pcs->main always exists and are valid.
+		 * It's also safe to share the single static bootstrap_sheaf
+		 * with zero-sized objects array as it's never modified.
+		 *
+		 * Bootstrap_sheaf also has NULL pointer to kmem_cache so we
+		 * recognize it and not attempt to free it when destroying the
+		 * cache.
+		 *
+		 * We keep bootstrap_sheaf for kmem_cache and kmem_cache_node,
+		 * caches with debug enabled, and all caches with SLUB_TINY.
+		 * For kmalloc caches it's used temporarily during the initial
+		 * bootstrap.
+		 */
+		if (!s->sheaf_capacity)
+			pcs->main = &bootstrap_sheaf;
+		else
+			pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
 
 		if (!pcs->main)
 			return -ENOMEM;
@@ -7803,8 +7849,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *s)
 void __kmem_cache_release(struct kmem_cache *s)
 {
 	cache_random_seq_destroy(s);
-	if (s->cpu_sheaves)
-		pcs_destroy(s);
+	pcs_destroy(s);
 #ifdef CONFIG_PREEMPT_RT
 	if (s->cpu_slab)
 		lockdep_unregister_key(&s->lock_key);
@@ -7826,7 +7871,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
 			continue;
 		}
 
-		if (s->cpu_sheaves) {
+		if (cache_has_sheaves(s)) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
 
 			if (!barn)
@@ -8149,7 +8194,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
 	flush_all_cpus_locked(s);
 
 	/* we might have rcu sheaves in flight */
-	if (s->cpu_sheaves)
+	if (cache_has_sheaves(s))
 		rcu_barrier();
 
 	/* Attempt to free all objects */
@@ -8461,7 +8506,7 @@ static int slab_mem_going_online_callback(int nid)
 		if (get_node(s, nid))
 			continue;
 
-		if (s->cpu_sheaves) {
+		if (cache_has_sheaves(s)) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
 
 			if (!barn) {
@@ -8669,12 +8714,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
 	set_cpu_partial(s);
 
-	if (s->sheaf_capacity) {
-		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
-		if (!s->cpu_sheaves) {
-			err = -ENOMEM;
-			goto out;
-		}
+	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
+	if (!s->cpu_sheaves) {
+		err = -ENOMEM;
+		goto out;
 	}
 
 #ifdef CONFIG_NUMA
@@ -8693,11 +8736,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!alloc_kmem_cache_cpus(s))
 		goto out;
 
-	if (s->cpu_sheaves) {
-		err = init_percpu_sheaves(s);
-		if (err)
-			goto out;
-	}
+	err = init_percpu_sheaves(s);
+	if (err)
+		goto out;
 
 	err = 0;
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-7-041323d506f7%40suse.cz.
