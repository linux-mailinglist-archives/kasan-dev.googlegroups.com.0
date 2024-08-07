Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM2ZW2QMGQE3T4SKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 497B194A586
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:39 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5a2c84a3bbasf1813087a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026699; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlCyFVTVYNHpCExgDi0aIxFm9vJpUbTokpO9HSy+CTx6HjadxFKJZvVomD1Ff9OOVq
         DH7iXwx6O3Rpo4c2ly/myLWLawDmP+C3XIoJHwp/jP417eLCv003Ip6N6l/CGJv2OFhA
         CoiekWodjwd5zaQTjBuyDI2/uR9MV+Swh/mkfbXhdDXuv47C1jv0qebnb5OiHEFiCNn+
         0Q/rcV4RdGtuNTXkR6g9gJziad441ll0G2qOfILGH/CmtOKuEY1YLBAhEk3MPpjLgU01
         hSYfP1MkhcRecUTgB1by2fKkYFdARE07jf0wV3GQl0eOTAPPMIkyAE0lqWwGCdbaoRc7
         OSZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=Y+PFBTKB+9n7WsZffgirR0/QXJbKY6KqjK6eWIbIJcw=;
        fh=boUwH284TNetg43uIQA2tIUaE79tAqFe3SUFoDtr8xU=;
        b=sbRQK6y9j59wAgYCLveBp95isLLFGf4trv8bsWjMKjn4bsMLQRAlfEZtC0TcEuoT9K
         8dyWvsYubesm24jiwkhfp2smy13Mz1Tb8jlaGzVrAoKrgVXMny/QBMtgLcgEwJWQSJ1h
         E4OSLuOQRXiUZQAfyvnkZl6Y8brcGM8ztNoIa2ahzlQ75tcFHWNez2XdLBV8olvD6ZS3
         D4IL3QDgGHRyiHS6hlpPp3/Ny62+tRsvFJ4JzUcYOP0AP1ylD6oG3XbNhN3nZl0+Fmdo
         mCC+g41X7gV8P48s9NJN4u1/HTx2vu4JcKMcIIlwcp982c5UgRfnkoKf0i/Tg5y5/wKR
         CDCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=FR81OezO;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026699; x=1723631499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y+PFBTKB+9n7WsZffgirR0/QXJbKY6KqjK6eWIbIJcw=;
        b=ras+Bnx4uxqpn+ZTJxZz7XZEdY+mZ3wchCHmDB0YzNgkmUf3gF5UcV+yyRVPqsBIwI
         lJTPx5In46QnEMMRmvQvwZYEoU8/d9QbY1G5CRDx+Ew+ioiLXK80Ea/KH2c8gTCSb+zg
         LIauqhjevepQdM5o5qpHWr7BcuMO1ibRRL6DN1FlQf24Go5J7zZikFFve2glMKmR0njr
         GWEhrUGD04ZX6O/3F/GMsB8UPZPRA5z6w8GHT1YbIyoUW6rsidLl985o8AYFhrAHcM53
         14F+1+OgEbV2D1rOsfEBXGCCG7E0hSFpjkAcxWHnQWwsm9PfL+dtnJv26umfopC4ND6W
         WiEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026699; x=1723631499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y+PFBTKB+9n7WsZffgirR0/QXJbKY6KqjK6eWIbIJcw=;
        b=qzV6TMTeg0HsJr8yXrgG4CqmOat5jdwIjFurFykU01fgX1aTQyBNRKVGXNzAF9at22
         KU6fmdMJEcvrJ/VWI99qpCM3RYoNMtqLw2aU5Zda6AA+///pPqJrHXGnch4Ta5bEIRR9
         +h9ARi/3AIVyNkjFKnHglDNO3FuZdktJxUnurEl9L+wPQOwLLMXGSpNYOeFckzaBZh5H
         703nVu+dzTF6PTDBvTN4Thbt7OViV9nS6R1hR0uuaO8Z4emt7uAIgfBLsqYgHkULMeD+
         k48oYLkZ1p0LggqMizZjVgWD2L55Yb8FVsa6hguW1dWlMItuFMtJPvMOnBdeInT1Eksl
         sA/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUve2yalWJN6cWRmZvUY322xZCzz36ZP3SHtoVsqZDynWfd4orN24MJn9zv/OqYQ9EP921BlOklw0Bc71JQ9JBS8KckJkugKQ==
X-Gm-Message-State: AOJu0Yy+qryyyiv7yK3SuSaXWlAar7R6iJWO8OihG79Hk1ynMGujkRHv
	RNZvnabnSip6iJcnx+FH5l4r9g3CSg4+FtnPhkbjRvOAjFyrg831
X-Google-Smtp-Source: AGHT+IERtnGS8HeK941TJCTsIKnS9Zb2X3QVYrlzAYVaz51anJn8NQG+XmzMaWmNQWlpzBUVVlvIFQ==
X-Received: by 2002:a05:6402:515c:b0:5af:6f52:c139 with SMTP id 4fb4d7f45d1cf-5b7f3cc7458mr12969423a12.16.1723026698081;
        Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2805:b0:58b:ce37:ebce with SMTP id
 4fb4d7f45d1cf-5b98036d229ls15753a12.1.-pod-prod-03-eu; Wed, 07 Aug 2024
 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQszpMJH5vxvoSMRhXEVrl7UiqpqpoAaKxuL3zHSogsN0IdgHC/oxLTWHiR0kNzAj+NzKQ0z2DbdM+0qT+iyvPTKNjtvwVhVsmqw==
X-Received: by 2002:aa7:de0a:0:b0:5bb:9ae0:4a4b with SMTP id 4fb4d7f45d1cf-5bb9ae04b20mr3021733a12.7.1723026695945;
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=nTIIsYvBxlbcEQVuyaBzv1JD6UGabhnH4o9vM9+hSodj0D3cIIl5fwsOOSxcSk6V91
         fRJ3zon9KI5mxZoRuoRO3Vox/oInaK9QD8RnzBR/Ajk4MIjrWASM/FWM4n7ipixN2jz9
         2BhKpiJa7kVhItoitPv/udAcjw+AXvmx9KDiqoyWAxM+k4WH83HhzxPLG4SAadEMfTJP
         EknzKuEQZ8i8RpNnli1e1ff6078qvhb1W9edZclhdbfYTMRtXuDzmUzRJriqqJJF3dhR
         EgAuArg10HWzM/l24MPdhfwgLSnSdZ56Fgy3+39Y+kwox5OLdO8bCE6liz37OnkU/J4j
         7R4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=j2GOiA9T7Jb2ihHQdRICUWrhL/KNdHwLnom7wJXeQZ0=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=WQj6bUGsgwgRek9kVYKdpiNSpFrgHHkxrX0Smzi6/ci6B91rBrscBDqOEDS6qFCYrM
         IaFrFTunn4z3JXEnarCPf5/U1xsSzA/auoXPKWpECqqkpXFWYxhfn0QstZCgUrX7lO26
         9Wo2brtjfsMB5c6yuuv1mpSy9YKuFfq/Co6N9anJo6RLTKq63STn4NQTP8ijrhIB2qka
         1es4Vu4gMGOQIJQErBHcXqJy1XKeyaOlDcZWORY34lSfPLlGDD6tL7gt8E5Lm9qAI6ov
         rOoNsTOYAcwbZIjD2oE7sOg9SFKm+9s0DVzwnxld8l/uxMZ9LlIll+G3beIauIFfraD0
         1ATw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=FR81OezO;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5b83972193dsi254500a12.1.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6A06C21CF4;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3CBD413B08;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IOqMDgZNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:34 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:18 +0200
Subject: [PATCH v2 5/7] rcu/kvfree: Add kvfree_rcu_barrier() API
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
To: "Paul E. McKenney" <paulmck@kernel.org>, 
 Joel Fernandes <joel@joelfernandes.org>, 
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, 
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>, 
 "Jason A. Donenfeld" <Jason@zx2c4.com>, 
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.1
X-Spam-Level: 
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 6A06C21CF4
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLsm9p66qmnckghmjmpccdnq6s)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=FR81OezO;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jpwuLCpP;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

From: "Uladzislau Rezki (Sony)" <urezki@gmail.com>

Add a kvfree_rcu_barrier() function. It waits until all
in-flight pointers are freed over RCU machinery. It does
not wait any GP completion and it is within its right to
return immediately if there are no outstanding pointers.

This function is useful when there is a need to guarantee
that a memory is fully freed before destroying memory caches.
For example, during unloading a kernel module.

Signed-off-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/rcutiny.h |   5 +++
 include/linux/rcutree.h |   1 +
 kernel/rcu/tree.c       | 103 ++++++++++++++++++++++++++++++++++++++++++++----
 3 files changed, 101 insertions(+), 8 deletions(-)

diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
index d9ac7b136aea..522123050ff8 100644
--- a/include/linux/rcutiny.h
+++ b/include/linux/rcutiny.h
@@ -111,6 +111,11 @@ static inline void __kvfree_call_rcu(struct rcu_head *head, void *ptr)
 	kvfree(ptr);
 }
 
+static inline void kvfree_rcu_barrier(void)
+{
+	rcu_barrier();
+}
+
 #ifdef CONFIG_KASAN_GENERIC
 void kvfree_call_rcu(struct rcu_head *head, void *ptr);
 #else
diff --git a/include/linux/rcutree.h b/include/linux/rcutree.h
index 254244202ea9..58e7db80f3a8 100644
--- a/include/linux/rcutree.h
+++ b/include/linux/rcutree.h
@@ -35,6 +35,7 @@ static inline void rcu_virt_note_context_switch(void)
 
 void synchronize_rcu_expedited(void);
 void kvfree_call_rcu(struct rcu_head *head, void *ptr);
+void kvfree_rcu_barrier(void);
 
 void rcu_barrier(void);
 void rcu_momentary_dyntick_idle(void);
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index e641cc681901..ebcfed9b570e 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3584,18 +3584,15 @@ kvfree_rcu_drain_ready(struct kfree_rcu_cpu *krcp)
 }
 
 /*
- * This function is invoked after the KFREE_DRAIN_JIFFIES timeout.
+ * Return: %true if a work is queued, %false otherwise.
  */
-static void kfree_rcu_monitor(struct work_struct *work)
+static bool
+kvfree_rcu_queue_batch(struct kfree_rcu_cpu *krcp)
 {
-	struct kfree_rcu_cpu *krcp = container_of(work,
-		struct kfree_rcu_cpu, monitor_work.work);
 	unsigned long flags;
+	bool queued = false;
 	int i, j;
 
-	// Drain ready for reclaim.
-	kvfree_rcu_drain_ready(krcp);
-
 	raw_spin_lock_irqsave(&krcp->lock, flags);
 
 	// Attempt to start a new batch.
@@ -3634,11 +3631,27 @@ static void kfree_rcu_monitor(struct work_struct *work)
 			// be that the work is in the pending state when
 			// channels have been detached following by each
 			// other.
-			queue_rcu_work(system_wq, &krwp->rcu_work);
+			queued = queue_rcu_work(system_wq, &krwp->rcu_work);
 		}
 	}
 
 	raw_spin_unlock_irqrestore(&krcp->lock, flags);
+	return queued;
+}
+
+/*
+ * This function is invoked after the KFREE_DRAIN_JIFFIES timeout.
+ */
+static void kfree_rcu_monitor(struct work_struct *work)
+{
+	struct kfree_rcu_cpu *krcp = container_of(work,
+		struct kfree_rcu_cpu, monitor_work.work);
+
+	// Drain ready for reclaim.
+	kvfree_rcu_drain_ready(krcp);
+
+	// Queue a batch for a rest.
+	kvfree_rcu_queue_batch(krcp);
 
 	// If there is nothing to detach, it means that our job is
 	// successfully done here. In case of having at least one
@@ -3859,6 +3872,80 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr)
 }
 EXPORT_SYMBOL_GPL(kvfree_call_rcu);
 
+/**
+ * kvfree_rcu_barrier - Wait until all in-flight kvfree_rcu() complete.
+ *
+ * Note that a single argument of kvfree_rcu() call has a slow path that
+ * triggers synchronize_rcu() following by freeing a pointer. It is done
+ * before the return from the function. Therefore for any single-argument
+ * call that will result in a kfree() to a cache that is to be destroyed
+ * during module exit, it is developer's responsibility to ensure that all
+ * such calls have returned before the call to kmem_cache_destroy().
+ */
+void kvfree_rcu_barrier(void)
+{
+	struct kfree_rcu_cpu_work *krwp;
+	struct kfree_rcu_cpu *krcp;
+	bool queued;
+	int i, cpu;
+
+	/*
+	 * Firstly we detach objects and queue them over an RCU-batch
+	 * for all CPUs. Finally queued works are flushed for each CPU.
+	 *
+	 * Please note. If there are outstanding batches for a particular
+	 * CPU, those have to be finished first following by queuing a new.
+	 */
+	for_each_possible_cpu(cpu) {
+		krcp = per_cpu_ptr(&krc, cpu);
+
+		/*
+		 * Check if this CPU has any objects which have been queued for a
+		 * new GP completion. If not(means nothing to detach), we are done
+		 * with it. If any batch is pending/running for this "krcp", below
+		 * per-cpu flush_rcu_work() waits its completion(see last step).
+		 */
+		if (!need_offload_krc(krcp))
+			continue;
+
+		while (1) {
+			/*
+			 * If we are not able to queue a new RCU work it means:
+			 * - batches for this CPU are still in flight which should
+			 *   be flushed first and then repeat;
+			 * - no objects to detach, because of concurrency.
+			 */
+			queued = kvfree_rcu_queue_batch(krcp);
+
+			/*
+			 * Bail out, if there is no need to offload this "krcp"
+			 * anymore. As noted earlier it can run concurrently.
+			 */
+			if (queued || !need_offload_krc(krcp))
+				break;
+
+			/* There are ongoing batches. */
+			for (i = 0; i < KFREE_N_BATCHES; i++) {
+				krwp = &(krcp->krw_arr[i]);
+				flush_rcu_work(&krwp->rcu_work);
+			}
+		}
+	}
+
+	/*
+	 * Now we guarantee that all objects are flushed.
+	 */
+	for_each_possible_cpu(cpu) {
+		krcp = per_cpu_ptr(&krc, cpu);
+
+		for (i = 0; i < KFREE_N_BATCHES; i++) {
+			krwp = &(krcp->krw_arr[i]);
+			flush_rcu_work(&krwp->rcu_work);
+		}
+	}
+}
+EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
+
 static unsigned long
 kfree_rcu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
 {

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c%40suse.cz.
