Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM2ZW2QMGQE3T4SKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B9094A582
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:38 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4280e1852f3sf11798595e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026698; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAd+cHRCDCs1kNFEOdQPXF587UyY6vysMhACuYfXz04hHJCPajs3Ag+hxeCNeIxXkd
         KTXWtWYkZhYrBSUsqcKSV3TREk1NstYdn+NNdUmVQ9kFeyipkHDXl1NSm6Gm9AEOPIFt
         TmI44XKizWzqJJYDg4ckl3VsACNbPKoKpUSML8vW1wQyqB//39r80egPY0xnm/olBE4v
         gT0SvQF3733NWxD5F698z3GNGMOTjtO2ndr257TythK/sh/ixUC9t825QX6CgwKkVG6m
         cIrmXApfMQYQB6TUK3ohdxm7tlvA0k0KKjm80rcqvAPFVZJa4FW64myoWrb437q+Kc66
         GSTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=eaV1MfzOUPWIEEQsE5/oHch8LEA8aP1fOpz24LX9YrU=;
        fh=HF87Lv6WhFEoRHXdi2P6z/4G576ZqanDckJZZzYQRYU=;
        b=Vt+JmH7ogsXRyDLf3QkpSeebkIdmOrclbkeFgLT7UDAKWHjYJn69Rnuylj6YfyLF+7
         XVfSu1NFQymUlQxdS80C+G75+By9xq8mfCLBPELAotZvZlK2pUnPlbgtvTfbUglSXwm2
         9YEIz5zY6a7A/vME6NFlc+3zRghYBJAxxeNnWWGhRnbZxazLr21r4wcW1lYo+cAdUueQ
         iDQMOmq1wfc4I6ly7qr60YIbfcHR9FZO58kERAzoaYJkW5aJJYL64JwDVjaNKNa/CFLx
         r7kxBuOLaERW5bwdOI5Wo5WiKh0dZETgUDFzy/6sPl8M3nOln2sfXUwEP3UBsvb6DyYK
         a3Gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YwEVT8Zy;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UlFErIrL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026698; x=1723631498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eaV1MfzOUPWIEEQsE5/oHch8LEA8aP1fOpz24LX9YrU=;
        b=pvunX57A6VxQ6VpwCjreUqwnoRDij4c+BFi8dRCHVtu1rhLCYoNTmnr+CvPNhsGm9F
         MaNqmXc4w2zbOSxrCnXDdFRUEJxFi7iWXlbRvQp6vTmxyB9SabU7vaekUHCJ0J8d/5VN
         BxGCzVY3YkrJgH8D54/G0PrUVyCOJCIudGpquzC434quWy0wEskuZ+keGusjXVZHLkRC
         BEN3p8sKL/C+6hK8mPrTVUlA4Onf45f6E8PRr98cJosu5u16161Fc9/z1jKbiUuYjSno
         JoYpbEXnueU52jWVll3NcjnGm5kgraSCj9YkNV9M2jwB5HtDG9LRA/zDndg2rIRd3sSY
         YRjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026698; x=1723631498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eaV1MfzOUPWIEEQsE5/oHch8LEA8aP1fOpz24LX9YrU=;
        b=rxsbRfHxPHbhUdYLws0UIlLuoCmUkmS+XXfiB44FwEXzsi8b7ObdGexKohiReXTa3d
         BpC5uJi19ZJIggH53DTJI94SSmraNG+o+TSb62JFdToOEUmde8Ey+6SVs/aFfqw2k0XK
         YfmbKLOmV0C9J7gq9Auqoi2DSPlt0U4YZfGycAH+F2swlURKVjBH+kTg5KZVpyZwOVTc
         fC1IX2JtDlvEVd9DXiqZmPi3fl5C4rkrlWk26JEL6t+7rdUq99UWx40SszFPCMIbKBfR
         Ud+pG/74MRnSXksHFc8dd8OU/I0BWoxhSIo0yEMpeE7YmaYo+BN3ve4tngdaHa7d1Kyk
         bHOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUv3bSk9nbGedJlNftOtpvXzj5JgMG3ba57Mkl3sP/GF3f5rN1xF9PjZoDSNb9waO1vR3scsLcnA/OJXNyhmhnlO620JLGRyQ==
X-Gm-Message-State: AOJu0Yzt+0CEyEqhgdRBaAv/P79XcOcho5/v990MlxEQSvRZGTkys8fY
	HsFk054lBU+tgjrUdZ4C9Ozkwczeiv7KQjPx3KEtpTq0gmMZ2C95
X-Google-Smtp-Source: AGHT+IEHwAV7hOuh06H1IeBJ/NlsC5/ODM56E0RouaZqvDe2RJzKdLN69cdI0LwKzDt+kwpWHKvcbw==
X-Received: by 2002:a05:600c:35ca:b0:427:ac40:d4b1 with SMTP id 5b1f17b1804b1-428e6b7be88mr120068175e9.27.1723026697600;
        Wed, 07 Aug 2024 03:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c8a:b0:426:73d7:f1f5 with SMTP id
 5b1f17b1804b1-428ede2001fls20103715e9.1.-pod-prod-07-eu; Wed, 07 Aug 2024
 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQhmJiopC74c5hKgSMVnEmTmwByhmMCQv9bRvPlyd+FoebLXsDjfG4YSCJ1SoJBdUZdqsT6lieYlgZPpiTZslaq4mZVv3Wgyi8Kw==
X-Received: by 2002:a05:600c:4fc3:b0:426:627e:37af with SMTP id 5b1f17b1804b1-428ec6bf40bmr94186195e9.3.1723026695846;
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=Xdm+N6/Dzm2Xqv8Me7oOU6LNiylGO93nBbw+ryORz1UG1jFEgzI+nkYTFdCBHTBC8E
         WtCYNq9duQwatEEwbgux9C116522sPFrCfw8ptb0sOQIT+ucJsh4XvqKp+hRazm1s/kZ
         hg2Sutuct5kicUNtboB6A1VtHLr9+Wp97Bv3LFUVvfgkV971fYmMoSGzKDjkpHEGwlIm
         e/lCDuggAF851eKulVLoFRbrEPFvQm/pSYarD+Q6Odu9jyrvifs43rEQGZPdF0Nm6Sxz
         nChlPVUG9ek07Y3QO+qL4NE7FOwwBSGexJ5Rl4NwmYKL6gdWR2TqQxh3gBiYbQwa/62R
         NL2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=3R4VEs0s4uyTtqaeQIxLvgBnoD49RLjNoURIedFN5O4=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=rLm1PAf+0o42Phm+L0TnnM/AmBJF/tof3ys0XCVGd8Cjn6lzo57gDTIwio1vCQshIH
         CHlb8roOqZmUtJ55GkI3pUCy4MRCF1sa7YhBUgZX2+V126OSA3uL15phSCnFjXkFFfF4
         JmcgQSNgXC4wsurtTFnhHP++ZYT9h2H5JJN9Y/apkyVMKmR9mHv/xv10/fG4k6TU1Wgh
         hk34k/dtNxe0lJ2wv77Tetv4BLuJrYvWavwG25GuRjVq0fRtfw16NBqWViVIGnd0/bZB
         S3DjpLLUHUnEanKRPhRKRxq9aZgZClEeuHSOL1OHWvFTFQ5LB4TiofaaDh1QxJT5R/ng
         qNCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YwEVT8Zy;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UlFErIrL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057ea2f7si563015e9.1.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E65B621B51;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BC82F13B05;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ELi5LQVNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:33 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:15 +0200
Subject: [PATCH v2 2/7] mm, slab: unlink slabinfo, sysfs and debugfs
 immediately
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-2-ea79102f428c@suse.cz>
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
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLsm9p66qmnckghmjmpccdnq6s)];
	TO_DN_SOME(0.00)[]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -3.01
X-Rspamd-Queue-Id: E65B621B51
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YwEVT8Zy;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=UlFErIrL;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

kmem_cache_destroy() includes removing the associated sysfs and debugfs
directories, and the cache from the list of caches that appears in
/proc/slabinfo. Currently this might not happen immediately when:

- the cache is SLAB_TYPESAFE_BY_RCU and the cleanup is delayed,
  including the directores removal
- __kmem_cache_shutdown() fails due to outstanding objects - the
  directories remain indefinitely

When a cache is recreated with the same name, such as due to module
unload followed by a load, the directories will fail to be recreated for
the new instance of the cache due to the old directories being present.
The cache will also appear twice in /proc/slabinfo.

While we want to convert the SLAB_TYPESAFE_BY_RCU cleanup to be
synchronous again, the second point remains. So let's fix this first and
have the directories and slabinfo removed immediately in
kmem_cache_destroy() and regardless of __kmem_cache_shutdown() success.

This should not make debugging harder if __kmem_cache_shutdown() fails,
because a detailed report of outstanding objects is printed into dmesg
already due to the failure.

Also simplify kmem_cache_release() sysfs handling by using
__is_defined(SLAB_SUPPORTS_SYSFS).

Note the resulting code in kmem_cache_destroy() is a bit ugly but will
be further simplified - this is in order to make small bisectable steps.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 57 ++++++++++++++++++++++++++------------------------------
 1 file changed, 26 insertions(+), 31 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index b76d65d7fe33..db61df3b4282 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -484,31 +484,19 @@ kmem_buckets *kmem_buckets_create(const char *name, slab_flags_t flags,
 }
 EXPORT_SYMBOL(kmem_buckets_create);
 
-#ifdef SLAB_SUPPORTS_SYSFS
 /*
  * For a given kmem_cache, kmem_cache_destroy() should only be called
  * once or there will be a use-after-free problem. The actual deletion
  * and release of the kobject does not need slab_mutex or cpu_hotplug_lock
  * protection. So they are now done without holding those locks.
- *
- * Note that there will be a slight delay in the deletion of sysfs files
- * if kmem_cache_release() is called indrectly from a work function.
  */
 static void kmem_cache_release(struct kmem_cache *s)
 {
-	if (slab_state >= FULL) {
-		sysfs_slab_unlink(s);
+	if (__is_defined(SLAB_SUPPORTS_SYSFS) && slab_state >= FULL)
 		sysfs_slab_release(s);
-	} else {
+	else
 		slab_kmem_cache_release(s);
-	}
 }
-#else
-static void kmem_cache_release(struct kmem_cache *s)
-{
-	slab_kmem_cache_release(s);
-}
-#endif
 
 static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 {
@@ -534,7 +522,6 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 	rcu_barrier();
 
 	list_for_each_entry_safe(s, s2, &to_destroy, list) {
-		debugfs_slab_release(s);
 		kfence_shutdown_cache(s);
 		kmem_cache_release(s);
 	}
@@ -549,8 +536,8 @@ void slab_kmem_cache_release(struct kmem_cache *s)
 
 void kmem_cache_destroy(struct kmem_cache *s)
 {
-	int err = -EBUSY;
 	bool rcu_set;
+	int err;
 
 	if (unlikely(!s) || !kasan_check_byte(s))
 		return;
@@ -558,11 +545,14 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	cpus_read_lock();
 	mutex_lock(&slab_mutex);
 
-	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
-
 	s->refcount--;
-	if (s->refcount)
-		goto out_unlock;
+	if (s->refcount) {
+		mutex_unlock(&slab_mutex);
+		cpus_read_unlock();
+		return;
+	}
+
+	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
 
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
@@ -571,24 +561,29 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
 	     __func__, s->name, (void *)_RET_IP_);
 
-	if (err)
-		goto out_unlock;
-
 	list_del(&s->list);
 
-	if (rcu_set) {
-		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
-		schedule_work(&slab_caches_to_rcu_destroy_work);
-	} else {
+	if (!err && !rcu_set)
 		kfence_shutdown_cache(s);
-		debugfs_slab_release(s);
-	}
 
-out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
-	if (!err && !rcu_set)
+
+	if (slab_state >= FULL)
+		sysfs_slab_unlink(s);
+	debugfs_slab_release(s);
+
+	if (err)
+		return;
+
+	if (rcu_set) {
+		mutex_lock(&slab_mutex);
+		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
+		schedule_work(&slab_caches_to_rcu_destroy_work);
+		mutex_unlock(&slab_mutex);
+	} else {
 		kmem_cache_release(s);
+	}
 }
 EXPORT_SYMBOL(kmem_cache_destroy);
 

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-2-ea79102f428c%40suse.cz.
