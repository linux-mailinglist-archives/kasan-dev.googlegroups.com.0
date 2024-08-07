Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM2ZW2QMGQE3T4SKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D44AF94A583
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:38 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-428fb72245bsf4101265e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026698; cv=pass;
        d=google.com; s=arc-20160816;
        b=v1IzJanNvu4sArZjY0Nmhu9KAlktll+UfffVkuko3MsnvvukH6HPCkEdb8+nQXQk+c
         INDw/LuKtVGkdK3DxtOvje5E6zq05Wldo8cHPK7wnDGaKr9grZG7kbUDIUQwtcg6WB4T
         93kbJXzZQVlgc39RgTv2OS+hfm+WnE61+57fmrw3YdPR2DhsvM8SpNb22fOlMI9HW1aR
         hxc5epwFF6Sotj16rf1aIgnWabgfXWn+zWdZzJpgdZ7i+seIKUj3gAWzUEqgs9CnJk4l
         QA82yM2IX6wdugIKaCqaG5NeNSP1F6z39LKDDbiuXcLyR6y/BgNzZOOF4MSg9cSFLjt/
         hD3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=ZFV4fCavwMQr9UfuTwX+o/HmGnbvGMKYrE3UoWnzIzA=;
        fh=mSUIIkW8nx7n3hwG39VaGbGvXKRvtXrXYFK4pYhlXE8=;
        b=jgvHmYQWohBOdJ9z4rXO3l73fctjlNWBK/4btdmNMgArJpiw2veahAuzYGy6hZAL5Y
         JQb3UHSCZenl1G+09ZlUqv1NUkW5i5/jZHmTyh1dG7YSeyO/2RPeI+8Os4QwnXh5GD4P
         6VFrAELUtFY/66y7yjGSjppakdUpX48iabLcml66J2/w9JirdNkqGbY+Jv5fd5K6+yc8
         q+ki0IgcU+JYNjYS9knOC0hbCd263hu720UUiO4PlgGElRmtxg2OZ8ZoRDIrOlZT7JhH
         GdruUzzZzOChH1b6vynJr4k8ig9JBeuaF+Ffa7rOBebv1fEFtWQEfjT+H5wYI2DKYPRM
         +wjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026698; x=1723631498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZFV4fCavwMQr9UfuTwX+o/HmGnbvGMKYrE3UoWnzIzA=;
        b=WvOoSRxY8pqnro7EgNYK1II3IYCLgm0+Be/TRZ26/TD1/BHn1BEfef9YGtqchGmPf5
         ud0SVVPPrIpuYkuydP7f8C9fCd4B0CY8JgWiuNZaosx2u2Scgayz9CGvpQZxvmbM+B1j
         FOkiFM5JB7CSX2Ai7TNRqUySijwkLxsvi7u6/xL6GlBxpG2jnSe0QVP2nRsIw0SaXhcu
         C0WX+r45IrUraasOfmnzN9Qq0/COHQ77smhKY1QO1uCk8s9SG1welgxpRj3F7J3NVPCw
         6Dz+h1Oc27/r0AumX2uLVKlnlTCnapOuDuST/PoKqgVq/hgGhmLPBEPMlq5pN80q13Wf
         6xHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026698; x=1723631498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZFV4fCavwMQr9UfuTwX+o/HmGnbvGMKYrE3UoWnzIzA=;
        b=BVnJ6o/rFmF+nrTEfVrOzaq0RH5QRpGhGdarPV13MAfFiqWlSXPtlASynXjlXSqIsj
         TMeBc7jTxKlNdTpak/rVqm57oIOnIE1/NUhgdEQUIsGtSgDQkZR7/KPUS2TDGykuOHgQ
         g+p9grCA2rK/2iVBvwubtHzrgsvCHQk79g5jOzXXhGquOI6PGRZq8+7wZSueER6Ck1Jm
         Pl6k0yG4DVsa3HXmPaMmJ9ud+dFcU5ZZeENQFKMWHVflkhyrsCsFaGkwfow8NX/Z+W/c
         zQD3EPezQNfgkounIgrfzINKTP1k4TkR9FDaGpS6dI3RY1BHMPbXGYnkscb/wQGHeSi3
         cowg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzvceNhaPPRwcZLTgnzooJAHXPgLupEa7QyXv31gQRUzzOASX9/FTUAeyTfrqYgrsR6H53GyH8RRIJjw7XW+2Fwt4F5gUzBA==
X-Gm-Message-State: AOJu0YzHYXww6oRKdiQp+yj/xL0f6OLwJcw/7FAYuVVDA3pDbEc02QsG
	ErYtI88fw2bCGvAdrf6hrhP8Z2B9VBfR1rQGXeEKhDWXVnFrqhLx
X-Google-Smtp-Source: AGHT+IEgduwKTVYNfsHSartCNnimUjO6qEKm0hTyNNrtcbFa3kKCxo9iZKJH0PnFa+b9m4kvegBodA==
X-Received: by 2002:a05:600c:3581:b0:426:6eb6:1374 with SMTP id 5b1f17b1804b1-42904fa2077mr15210795e9.0.1723026697594;
        Wed, 07 Aug 2024 03:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c92:b0:428:9f15:7820 with SMTP id
 5b1f17b1804b1-429027ff053ls195035e9.0.-pod-prod-00-eu; Wed, 07 Aug 2024
 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLqIMI7AT1DplD/AMZWyeCBuASFcmyvO44yKfVOcKrFnlfodLQtAbSRdbwsX3RJTqpA7gsDxrFRlZSVnEMYzuHJzE7j261Bbwydg==
X-Received: by 2002:a05:600c:4f14:b0:426:698b:791f with SMTP id 5b1f17b1804b1-4290509fda7mr13169985e9.3.1723026695756;
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=JEnvNSw2gpYxwLEOiA1ffVHctm6ri6SiXPOrG4FDcb8jsSWRBWaHZXuQn/mOUNN/P2
         kx8gV0i3bMOd8zR2rKJ86by2zx14Qakwci51NmAxbF3RW9C9gIztF79+4cBKEOsjlJeR
         hZzBbeuX0XpC1vW0kzRQ9LDrApGfML8qZh1i71RGM4WTTkcO/zbtp5AVpBm8crfL8AHK
         KlQIE17ZISfs5n7/WqC0SrOUxFoUPj2UuACkquqvfIiejXghiFJblCZbvqn/CwKL9RB/
         iNkKdkL5i/hKZRNWQNywvgrljps0FblejqpKBm4HxnwOWQFgUnK6A7a3kALw/5E7ImpU
         AnHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=h1qL27IVdY8UFaeKEjvymEDe/A+3RtrkI79ewzI2zdg=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=f0KTA5thDs0E+Afp4luEeytq3mDm295X4M9z8oVakxNf9Ink+64Jn0iMmCFxpjmF0b
         JByw8txgNy0uWnNO7Xch+FbzePbe2mRBj8nz6DPaWDChQdP/sK9A6YChpqjtnWvZ4hvY
         wpljGV+l+/+CYPPaFYQppz7pQMR3vflYiV/anPpuRUR4eqF9PWp3mYoxaUfTANsSteD6
         XCNpyaC3u/avX76Mw7mHlNxWdcPhvC9DOdz5gR1Nd0mLFJ1hZ4ri2EEPCCtSeYfd57lc
         ilNjrJohVnj6B4eYt7gFfzByqOj/SQdJe9NcGcPdptUenJ5e7YTVZdnRxktTpaYU5Quv
         bOAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057e4206si800435e9.1.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4316B21CF3;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1631513B06;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id uH8iBQZNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:34 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:17 +0200
Subject: [PATCH v2 4/7] mm, slab: reintroduce rcu_barrier() into
 kmem_cache_destroy()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-4-ea79102f428c@suse.cz>
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
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=sXT1azEr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

There used to be a rcu_barrier() for SLAB_TYPESAFE_BY_RCU caches in
kmem_cache_destroy() until commit 657dc2f97220 ("slab: remove
synchronous rcu_barrier() call in memcg cache release path") moved it to
an asynchronous work that finishes the destroying of such caches.

The motivation for that commit was the MEMCG_KMEM integration that at
the time created and removed clones of the global slab caches together
with their cgroups, and blocking cgroups removal was unwelcome. The
implementation later changed to per-object memcg tracking using a single
cache, so there should be no more need for a fast non-blocking
kmem_cache_destroy(), which is typically only done when a module is
unloaded etc.

Going back to synchronous barrier has the following advantages:

- simpler implementation
- it's easier to test the result of kmem_cache_destroy() in a kunit test

Thus effectively revert commit 657dc2f97220. It is not a 1:1 revert as
the code has changed since. The main part is that kmem_cache_release(s)
is always called from kmem_cache_destroy(), but for SLAB_TYPESAFE_BY_RCU
caches there's a rcu_barrier() first.

Suggested-by: Mateusz Guzik <mjguzik@gmail.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 47 ++++-------------------------------------------
 1 file changed, 4 insertions(+), 43 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index a079b8540334..c40227d5fa07 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -40,11 +40,6 @@ LIST_HEAD(slab_caches);
 DEFINE_MUTEX(slab_mutex);
 struct kmem_cache *kmem_cache;
 
-static LIST_HEAD(slab_caches_to_rcu_destroy);
-static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work);
-static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
-		    slab_caches_to_rcu_destroy_workfn);
-
 /*
  * Set of flags that will prevent slab merging
  */
@@ -499,33 +494,6 @@ static void kmem_cache_release(struct kmem_cache *s)
 		slab_kmem_cache_release(s);
 }
 
-static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
-{
-	LIST_HEAD(to_destroy);
-	struct kmem_cache *s, *s2;
-
-	/*
-	 * On destruction, SLAB_TYPESAFE_BY_RCU kmem_caches are put on the
-	 * @slab_caches_to_rcu_destroy list.  The slab pages are freed
-	 * through RCU and the associated kmem_cache are dereferenced
-	 * while freeing the pages, so the kmem_caches should be freed only
-	 * after the pending RCU operations are finished.  As rcu_barrier()
-	 * is a pretty slow operation, we batch all pending destructions
-	 * asynchronously.
-	 */
-	mutex_lock(&slab_mutex);
-	list_splice_init(&slab_caches_to_rcu_destroy, &to_destroy);
-	mutex_unlock(&slab_mutex);
-
-	if (list_empty(&to_destroy))
-		return;
-
-	rcu_barrier();
-
-	list_for_each_entry_safe(s, s2, &to_destroy, list)
-		kmem_cache_release(s);
-}
-
 void slab_kmem_cache_release(struct kmem_cache *s)
 {
 	__kmem_cache_release(s);
@@ -535,7 +503,6 @@ void slab_kmem_cache_release(struct kmem_cache *s)
 
 void kmem_cache_destroy(struct kmem_cache *s)
 {
-	bool rcu_set;
 	int err;
 
 	if (unlikely(!s) || !kasan_check_byte(s))
@@ -551,8 +518,6 @@ void kmem_cache_destroy(struct kmem_cache *s)
 		return;
 	}
 
-	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
-
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
 
@@ -572,14 +537,10 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	if (err)
 		return;
 
-	if (rcu_set) {
-		mutex_lock(&slab_mutex);
-		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
-		schedule_work(&slab_caches_to_rcu_destroy_work);
-		mutex_unlock(&slab_mutex);
-	} else {
-		kmem_cache_release(s);
-	}
+	if (s->flags & SLAB_TYPESAFE_BY_RCU)
+		rcu_barrier();
+
+	kmem_cache_release(s);
 }
 EXPORT_SYMBOL(kmem_cache_destroy);
 

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-4-ea79102f428c%40suse.cz.
