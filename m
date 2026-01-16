Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6U3VHFQMGQEAQGLJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71621D32C75
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:00 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-383005da622sf12233131fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574460; cv=pass;
        d=google.com; s=arc-20240605;
        b=R+ANlgbBXssTMKU+6puMyiHjenDy3ZxJmcR+Yvv+D04rLOSc5YwKPLpoBPA2HgOqbv
         m+BWc1yJyfDpFvK3F0SCG6CpF9cCNM9GGPrel4oNzZ2udPFkoxp0JHDBhJzzerSzkLWq
         GRlmc4C2WDI8gRpG9muMOcJpgpboeDVv8rookAL/n/o4uyUk5UK/19fPwEwIElLTS2ZA
         PFAI2x3t/APgOTdt0YsktG3SD7ON36BCSJsIBglUkj457Z5sNVHBZOuP7ZnAuB6Hpw4/
         on2+TfO9prYEvv0qn5rLxrT8yqcZ8/gBVjxBBNO6EIcl12kNTXIXdOeRIM99NgU4Xtui
         DfDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=+Evbb0NUtG4SkFD+mhMypdILlSLnWSqJRL7b0j0X41A=;
        fh=J9KICNiHkJukg9+7gDczl+w+X4QmFZHNuazz0VG3LQE=;
        b=IcGcia93NrzeglyKkrspyIURNao4Y+2rO2Zqrrww+5zGPdIdKlOVTXslJR9f5C7GBy
         M0yKnuYbbFCdUNlbE1cfFtlQijvIkg9xWv4EyVnBY33ZlPjqUSPFv3cEntT+KG06PauU
         DUvHCeKSd5Ib39DEz675tqcPZq8DzIybo5f9eVTB9Z59aJr6QdtKDojeV2JTBT72tvQ6
         keLZi+Yl3PE3XXDHQxyzlq5XPVHN0JoGdaZePGU2FDvhvpgRJxyvB547zYysnCFDZyqd
         u/tCT+5B0jkQYMJa2qPEhOUX5bxI41EtK+tMfPm7vZapF/HnnJ8xHaJERHizZJQ+LGhW
         w77A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wlDHTb4I;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wlDHTb4I;
       dkim=neutral (no key) header.i=@suse.cz header.b="WuUiQAh/";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574459; x=1769179259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Evbb0NUtG4SkFD+mhMypdILlSLnWSqJRL7b0j0X41A=;
        b=RIDIeglT6m2vti6C8HN85owgdAR0AfkDaAxVwXjXwoq7JPFkv/nHQ5xg0hJ9X0gAYj
         M1DxFFkwmjGvSWu/To08xg13hOV5QSEf9D7+m4qAbzkKrAKjuhptInG744GklEhwT8wD
         jzZrhIyOGAylE1A2YtVTg0M/EFRZXjZJKBVmH2ExPjw0V4hkJrGemjCLmDstW1gqL0aK
         XLIM9iYNV+asBmdunzh9cDFfKKP2KQrzZz+X+auhSno9tnyFzHniwn7rQKwmfXSIsrC/
         Gg4V3VnDlo4KpAZ8R17qzdII4q840PMpc6IQiEspJvEPXx6RDfacXcKor1M/CNAfcmhh
         PvKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574459; x=1769179259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Evbb0NUtG4SkFD+mhMypdILlSLnWSqJRL7b0j0X41A=;
        b=VUbRs6kF++zpJcMRPRnC9MS3wGZ3xBeAxulQafEYXYvav+lbUQL/GaUSmBpzxfLPLl
         rl9dxxk97s90uUlz0Li5/J60YRUnH4q+tww4MdkDqZGJbzktdJyxieLCeZpktX8gvvyp
         vJH51Ki6jVn5zxwR4tAEy8QsEr9FI82SCNMVD+fDgH5HTwL7twBcSUG64ZBWvmtq93jF
         UR+wobkBzAqRTJBwjhZoX721zr7u93mxw0IFJ90cLAPwjixNaMLVtcEF2qTPOz5xAF3B
         RJLPqBUoZzXiegx3iMot5Zohem6UO+CsspoJ6ePTv+BYqWwzq5KMF/eJAqBOSPB3fiZ0
         SefA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3I1+Ixpm3Op+bxwAQhq6MZ34QiIm7oa/+Og5h1r30erklcw2PMot73zj2L6s4UMBvIvWYoQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy1lLgthdamsA8HeQgwY0vMCr/nhxvnb2Xi181woV+KozxLvhQc
	+/4vNxQGggvnJbIndkp/10/UetORYVywp9PQuCpV84BLklfGvdWeQwJf
X-Received: by 2002:a05:651c:2205:b0:37f:c5ca:b737 with SMTP id 38308e7fff4ca-383866b0f0bmr9312011fa.1.1768574459458;
        Fri, 16 Jan 2026 06:40:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gj2ofaX+3OUWEtux6N215qfyovAqbIIvzECppuAtRk2g=="
Received: by 2002:a2e:7a0a:0:b0:37f:d2b5:65f0 with SMTP id 38308e7fff4ca-3836ee5e360ls2577631fa.0.-pod-prod-04-eu;
 Fri, 16 Jan 2026 06:40:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVM/IhaK/28JGAupCwREqp3y0LH/LQsNRDWJLWB2fjao82/yf60U/MjOtz3JCJl6rmfhmD7xfJBV0Y=@googlegroups.com
X-Received: by 2002:a05:651c:1503:b0:37f:d1ac:47fc with SMTP id 38308e7fff4ca-38386c7cf14mr9260681fa.44.1768574456646;
        Fri, 16 Jan 2026 06:40:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574456; cv=none;
        d=google.com; s=arc-20240605;
        b=UThQTBs64UNMi1NYorb7TmC3GHh51OiVQPzNgU71n9/4PNcTKu8B5cMYnLqsdYmL57
         +qlybdLmSGGd4Zm13pZ5WVaUMCNc9E5s6oc1mTMLxm8af4BQhjC7g/z1nzYZ05LCEOLd
         bPKk0+9+hWY10TsGNfIKnJz9qsGDDOsrJ96t3fCA4JU5mGdi1ondL/7pszBW+gEfTrNT
         QE6v8/tynp1Q75AWgCFgsytle+WUhbWGzl9SHuvPJ4FCRp7u0zYVCsH9WOB9rcgJzdTk
         9znpiQxHMiSsuje707b71N0a81lo2j2fKVldLaGlLuEdZ1n5XmsFuRqDwLSmeK4NQq4H
         s4yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=SlmRMlA71C/tKf49jhF6FlOyuOpzrs+mYjdHh/yliVg=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=alVsTzQXOYFSiCWjbnceNodOGhxnpeoQJ7OEKkt5fIHqc8RJ4PeDm9dEWg+JepX+Pi
         PAomIGKFKuqtoNEiBWZoQGRz/6gOMJ3uQgzo82lb3IsBoCTfnloH0789FrjFUknIgnF7
         dpMccSQWLeaJdpShHNtMl86TPV21rjTL9W5O/+5R+cOOQUkkNeBLzkiQCdylm187un9p
         QoIKBXFGSsWu2AhqQ4Lqj1uvyqnEHgRtojqT7aub37y+pDoeriXSb+stdl0jukl1yS6H
         xngN7yHvBuAExO5Dzb6Zr7PVrzUk5apXHrG2SLb+TpY76fUTTnydC7Gs0xVbu4gKBJS3
         y2RA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wlDHTb4I;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wlDHTb4I;
       dkim=neutral (no key) header.i=@suse.cz header.b="WuUiQAh/";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e285a2si597311fa.5.2026.01.16.06.40.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:56 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 50B495BE94;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 31EFB3EA66;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 4AjoC+ZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:35 +0100
Subject: [PATCH v3 15/21] slab: remove struct kmem_cache_cpu
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
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
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to(RL941jgdop1fyjkq8h4),to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 50B495BE94
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wlDHTb4I;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=wlDHTb4I;       dkim=neutral (no key)
 header.i=@suse.cz header.b="WuUiQAh/";       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The cpu slab is not used anymore for allocation or freeing, the
remaining code is for flushing, but it's effectively dead.  Remove the
whole struct kmem_cache_cpu, the flushing code and other orphaned
functions.

The remaining used field of kmem_cache_cpu is the stat array with
CONFIG_SLUB_STATS. Put it instead in a new struct kmem_cache_stats.
In struct kmem_cache, the field is cpu_stats and placed near the
end of the struct.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   7 +-
 mm/slub.c | 298 +++++---------------------------------------------------------
 2 files changed, 24 insertions(+), 281 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index e9a0738133ed..87faeb6143f2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -21,14 +21,12 @@
 # define system_has_freelist_aba()	system_has_cmpxchg128()
 # define try_cmpxchg_freelist		try_cmpxchg128
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg128
 typedef u128 freelist_full_t;
 #else /* CONFIG_64BIT */
 # ifdef system_has_cmpxchg64
 # define system_has_freelist_aba()	system_has_cmpxchg64()
 # define try_cmpxchg_freelist		try_cmpxchg64
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg64
 typedef u64 freelist_full_t;
 #endif /* CONFIG_64BIT */
 
@@ -189,7 +187,6 @@ struct kmem_cache_order_objects {
  * Slab cache management.
  */
 struct kmem_cache {
-	struct kmem_cache_cpu __percpu *cpu_slab;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
@@ -238,6 +235,10 @@ struct kmem_cache {
 	unsigned int usersize;		/* Usercopy region size */
 #endif
 
+#ifdef CONFIG_SLUB_STATS
+	struct kmem_cache_stats __percpu *cpu_stats;
+#endif
+
 	struct kmem_cache_node *node[MAX_NUMNODES];
 };
 
diff --git a/mm/slub.c b/mm/slub.c
index 8746d9d3f3a3..bb72cfa2d7ec 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -400,28 +400,11 @@ enum stat_item {
 	NR_SLUB_STAT_ITEMS
 };
 
-struct freelist_tid {
-	union {
-		struct {
-			void *freelist;		/* Pointer to next available object */
-			unsigned long tid;	/* Globally unique transaction id */
-		};
-		freelist_full_t freelist_tid;
-	};
-};
-
-/*
- * When changing the layout, make sure freelist and tid are still compatible
- * with this_cpu_cmpxchg_double() alignment requirements.
- */
-struct kmem_cache_cpu {
-	struct freelist_tid;
-	struct slab *slab;	/* The slab from which we are allocating */
-	local_trylock_t lock;	/* Protects the fields above */
 #ifdef CONFIG_SLUB_STATS
+struct kmem_cache_stats {
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
-#endif
 };
+#endif
 
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
@@ -430,7 +413,7 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 	 * The rmw is racy on a preemptible kernel but this is acceptable, so
 	 * avoid this_cpu_add()'s irq-disable overhead.
 	 */
-	raw_cpu_inc(s->cpu_slab->stat[si]);
+	raw_cpu_inc(s->cpu_stats->stat[si]);
 #endif
 }
 
@@ -438,7 +421,7 @@ static inline
 void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
 {
 #ifdef CONFIG_SLUB_STATS
-	raw_cpu_add(s->cpu_slab->stat[si], v);
+	raw_cpu_add(s->cpu_stats->stat[si], v);
 #endif
 }
 
@@ -1160,20 +1143,6 @@ static void object_err(struct kmem_cache *s, struct slab *slab,
 	WARN_ON(1);
 }
 
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	if ((s->flags & SLAB_CONSISTENCY_CHECKS) &&
-	    !check_valid_pointer(s, slab, nextfree) && freelist) {
-		object_err(s, slab, *freelist, "Freechain corrupt");
-		*freelist = NULL;
-		slab_fix(s, "Isolate corrupted freechain");
-		return true;
-	}
-
-	return false;
-}
-
 static void __slab_err(struct slab *slab)
 {
 	if (slab_in_kunit_test())
@@ -1955,11 +1924,6 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
 static inline void dec_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	return false;
-}
 #endif /* CONFIG_SLUB_DEBUG */
 
 /*
@@ -3655,191 +3619,6 @@ static void *get_partial(struct kmem_cache *s, int node,
 	return get_any_partial(s, pc);
 }
 
-#ifdef CONFIG_PREEMPTION
-/*
- * Calculate the next globally unique transaction for disambiguation
- * during cmpxchg. The transactions start with the cpu number and are then
- * incremented by CONFIG_NR_CPUS.
- */
-#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
-#else
-/*
- * No preemption supported therefore also no need to check for
- * different cpus.
- */
-#define TID_STEP 1
-#endif /* CONFIG_PREEMPTION */
-
-static inline unsigned long next_tid(unsigned long tid)
-{
-	return tid + TID_STEP;
-}
-
-#ifdef SLUB_DEBUG_CMPXCHG
-static inline unsigned int tid_to_cpu(unsigned long tid)
-{
-	return tid % TID_STEP;
-}
-
-static inline unsigned long tid_to_event(unsigned long tid)
-{
-	return tid / TID_STEP;
-}
-#endif
-
-static inline unsigned int init_tid(int cpu)
-{
-	return cpu;
-}
-
-static void init_kmem_cache_cpus(struct kmem_cache *s)
-{
-	int cpu;
-	struct kmem_cache_cpu *c;
-
-	for_each_possible_cpu(cpu) {
-		c = per_cpu_ptr(s->cpu_slab, cpu);
-		local_trylock_init(&c->lock);
-		c->tid = init_tid(cpu);
-	}
-}
-
-/*
- * Finishes removing the cpu slab. Merges cpu's freelist with slab's freelist,
- * unfreezes the slabs and puts it on the proper list.
- * Assumes the slab has been already safely taken away from kmem_cache_cpu
- * by the caller.
- */
-static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
-			    void *freelist)
-{
-	struct kmem_cache_node *n = get_node(s, slab_nid(slab));
-	int free_delta = 0;
-	void *nextfree, *freelist_iter, *freelist_tail;
-	int tail = DEACTIVATE_TO_HEAD;
-	unsigned long flags = 0;
-	struct freelist_counters old, new;
-
-	if (READ_ONCE(slab->freelist)) {
-		stat(s, DEACTIVATE_REMOTE_FREES);
-		tail = DEACTIVATE_TO_TAIL;
-	}
-
-	/*
-	 * Stage one: Count the objects on cpu's freelist as free_delta and
-	 * remember the last object in freelist_tail for later splicing.
-	 */
-	freelist_tail = NULL;
-	freelist_iter = freelist;
-	while (freelist_iter) {
-		nextfree = get_freepointer(s, freelist_iter);
-
-		/*
-		 * If 'nextfree' is invalid, it is possible that the object at
-		 * 'freelist_iter' is already corrupted.  So isolate all objects
-		 * starting at 'freelist_iter' by skipping them.
-		 */
-		if (freelist_corrupted(s, slab, &freelist_iter, nextfree))
-			break;
-
-		freelist_tail = freelist_iter;
-		free_delta++;
-
-		freelist_iter = nextfree;
-	}
-
-	/*
-	 * Stage two: Unfreeze the slab while splicing the per-cpu
-	 * freelist to the head of slab's freelist.
-	 */
-	do {
-		old.freelist = READ_ONCE(slab->freelist);
-		old.counters = READ_ONCE(slab->counters);
-		VM_BUG_ON(!old.frozen);
-
-		/* Determine target state of the slab */
-		new.counters = old.counters;
-		new.frozen = 0;
-		if (freelist_tail) {
-			new.inuse -= free_delta;
-			set_freepointer(s, freelist_tail, old.freelist);
-			new.freelist = freelist;
-		} else {
-			new.freelist = old.freelist;
-		}
-	} while (!slab_update_freelist(s, slab, &old, &new, "unfreezing slab"));
-
-	/*
-	 * Stage three: Manipulate the slab list based on the updated state.
-	 */
-	if (!new.inuse && n->nr_partial >= s->min_partial) {
-		stat(s, DEACTIVATE_EMPTY);
-		discard_slab(s, slab);
-		stat(s, FREE_SLAB);
-	} else if (new.freelist) {
-		spin_lock_irqsave(&n->list_lock, flags);
-		add_partial(n, slab, tail);
-		spin_unlock_irqrestore(&n->list_lock, flags);
-		stat(s, tail);
-	} else {
-		stat(s, DEACTIVATE_FULL);
-	}
-}
-
-static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
-{
-	unsigned long flags;
-	struct slab *slab;
-	void *freelist;
-
-	local_lock_irqsave(&s->cpu_slab->lock, flags);
-
-	slab = c->slab;
-	freelist = c->freelist;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	local_unlock_irqrestore(&s->cpu_slab->lock, flags);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-	void *freelist = c->freelist;
-	struct slab *slab = c->slab;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void flush_this_cpu_slab(struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = this_cpu_ptr(s->cpu_slab);
-
-	if (c->slab)
-		flush_slab(s, c);
-}
-
-static bool has_cpu_slab(int cpu, struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-
-	return c->slab;
-}
-
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
@@ -3853,7 +3632,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
 }
 
 /*
- * Flush cpu slab.
+ * Flush percpu sheaves
  *
  * Called from CPU work handler with migration disabled.
  */
@@ -3868,8 +3647,6 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	if (cache_has_sheaves(s))
 		pcs_flush_all(s);
-
-	flush_this_cpu_slab(s);
 }
 
 static void flush_all_cpus_locked(struct kmem_cache *s)
@@ -3882,7 +3659,7 @@ static void flush_all_cpus_locked(struct kmem_cache *s)
 
 	for_each_online_cpu(cpu) {
 		sfw = &per_cpu(slub_flush, cpu);
-		if (!has_cpu_slab(cpu, s) && !has_pcs_used(cpu, s)) {
+		if (!has_pcs_used(cpu, s)) {
 			sfw->skip = true;
 			continue;
 		}
@@ -3992,7 +3769,6 @@ static int slub_cpu_dead(unsigned int cpu)
 
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
-		__flush_cpu_slab(s, cpu);
 		if (cache_has_sheaves(s))
 			__pcs_flush_all_cpu(s, cpu);
 	}
@@ -7121,26 +6897,21 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
 		barn_init(barn);
 }
 
-static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
+#ifdef CONFIG_SLUB_STATS
+static inline int alloc_kmem_cache_stats(struct kmem_cache *s)
 {
 	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
 			NR_KMALLOC_TYPES * KMALLOC_SHIFT_HIGH *
-			sizeof(struct kmem_cache_cpu));
+			sizeof(struct kmem_cache_stats));
 
-	/*
-	 * Must align to double word boundary for the double cmpxchg
-	 * instructions to work; see __pcpu_double_call_return_bool().
-	 */
-	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
-				     2 * sizeof(void *));
+	s->cpu_stats = alloc_percpu(struct kmem_cache_stats);
 
-	if (!s->cpu_slab)
+	if (!s->cpu_stats)
 		return 0;
 
-	init_kmem_cache_cpus(s);
-
 	return 1;
 }
+#endif
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
@@ -7252,7 +7023,9 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
 		pcs_destroy(s);
-	free_percpu(s->cpu_slab);
+#ifdef CONFIG_SLUB_STATS
+	free_percpu(s->cpu_stats);
+#endif
 	free_kmem_cache_nodes(s);
 }
 
@@ -7944,12 +7717,6 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
 
 	memcpy(s, static_cache, kmem_cache->object_size);
 
-	/*
-	 * This runs very early, and only the boot processor is supposed to be
-	 * up.  Even if it weren't true, IRQs are not up so we couldn't fire
-	 * IPIs around.
-	 */
-	__flush_cpu_slab(s, smp_processor_id());
 	for_each_kmem_cache_node(s, node, n) {
 		struct slab *p;
 
@@ -8164,8 +7931,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!init_kmem_cache_nodes(s))
 		goto out;
 
-	if (!alloc_kmem_cache_cpus(s))
+#ifdef CONFIG_SLUB_STATS
+	if (!alloc_kmem_cache_stats(s))
 		goto out;
+#endif
 
 	err = init_percpu_sheaves(s);
 	if (err)
@@ -8484,33 +8253,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
 	if (!nodes)
 		return -ENOMEM;
 
-	if (flags & SO_CPU) {
-		int cpu;
-
-		for_each_possible_cpu(cpu) {
-			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab,
-							       cpu);
-			int node;
-			struct slab *slab;
-
-			slab = READ_ONCE(c->slab);
-			if (!slab)
-				continue;
-
-			node = slab_nid(slab);
-			if (flags & SO_TOTAL)
-				x = slab->objects;
-			else if (flags & SO_OBJECTS)
-				x = slab->inuse;
-			else
-				x = 1;
-
-			total += x;
-			nodes[node] += x;
-
-		}
-	}
-
 	/*
 	 * It is impossible to take "mem_hotplug_lock" here with "kernfs_mutex"
 	 * already held which will conflict with an existing lock order:
@@ -8881,7 +8623,7 @@ static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
 		return -ENOMEM;
 
 	for_each_online_cpu(cpu) {
-		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];
+		unsigned int x = per_cpu_ptr(s->cpu_stats, cpu)->stat[si];
 
 		data[cpu] = x;
 		sum += x;
@@ -8907,7 +8649,7 @@ static void clear_stat(struct kmem_cache *s, enum stat_item si)
 	int cpu;
 
 	for_each_online_cpu(cpu)
-		per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
+		per_cpu_ptr(s->cpu_stats, cpu)->stat[si] = 0;
 }
 
 #define STAT_ATTR(si, text) 					\

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-15-5595cb000772%40suse.cz.
