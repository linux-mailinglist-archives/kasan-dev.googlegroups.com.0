Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCE4VHFQMGQEVBWDXYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id AA456D32C8A
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:13 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64b756e2fd1sf2300343a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574473; cv=pass;
        d=google.com; s=arc-20240605;
        b=YkpXZIXiYaldmCOE8IvUGwYU1J0rn+SXVRuxWRL6ldIz4pqyWVW0TT8tgZscAaRYVL
         lHzgmANPKCSh1h8B6T6ilMN0xjAbqW+RL4d29/jTkeEoug26Hhkl5xhwW+Um3+B4Euz4
         dgF5So0zXky2FUzNGPp3/W8ZYnrEAfgjbrwMIeBrqNw7CCNWQ02HeWH9Toi+d555VdUz
         QClBe0syLpzRE0O4Yo4FNx+sDbQFcZEiMHXZ4IUAQQCJiV33b5tZQDb9kh3iQs4/E1Kk
         uyaXrrigkBasIV+MdLmaFEGhM67X1FR7pPzt6HqUMqL0LC2uPzxAmj3Q2NRUdsr28ZxI
         kT7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rfAglxnu9PM5FZfCH+u7OUEetPZWXoxdzayQvzaCqOw=;
        fh=ediotFb6NahN2aRkNoti7+Ph7BNbPZmjlr2m9WpR79U=;
        b=FRgFTkMWzMH/zG14NeW6jY/43E1tqEEh5tAzBzVmxfD5QAhJ1EkKCHU7UAf4j4bvE9
         8kPve5ql7CY1Hp4KoOfaqm4kGV/aKbDG998KOIZKHQOpDfkTAnTMmIwPe55df2ijPSIt
         lDL1sWasFBPZX1Ya7fDfSD4v2dhewBrgsPELNAwbi4zkcBqhNBDPw1DqnTv/JwCbTV2T
         x2OkoN6QT4Lygv8UOIPinoqPnfU6Shxhko229YvmOEA1UkyHzUp9UtYMEnCU4gw2Yjbr
         iE/a1WfO1reLmGqg6niWbiQBfF3RUvVBqQXVfJPQ4Wi1On7/WwP+voGM8hBnQxoTqT10
         YVHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574473; x=1769179273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rfAglxnu9PM5FZfCH+u7OUEetPZWXoxdzayQvzaCqOw=;
        b=WJJdk9P882jsts+uIgqzjE8ElOwZrDfjscfL2IcxrcuhBgYg7C4crZ9rAxKfdN1AJ+
         mxEtGzefQCsgc5/+8Y21mFwq5lrs2A620GaZdUGlTyLS6m9LWNfXbE4ALrN36ZzKuROf
         ni58cHtgkiADr+in03JLQAylrxuUd6RHrjO2dCHI9Xl80qi1h2qnvZowkcuPKaQoPirL
         Qe9du5iPURjhMLFjIY+nBRgUmwMXS16HCWopxtsa1vYS7j/y0oLldTsNyX/3jVZopaVC
         VovJuO63eqwnCsYxDTNwCME6eGhpO7Od5jzvxEjv7OpVUydQ0lD584lk6yUtkarkvaVt
         tAMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574473; x=1769179273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rfAglxnu9PM5FZfCH+u7OUEetPZWXoxdzayQvzaCqOw=;
        b=ujKG37mWSa8wcaobFl/8ZT2qWIz1VPTyZUWbRFjjrwKZFEh8AS3MhMfc4ekUc2DM0Y
         dt1qbgZvkf0WaVpUMiOeQSnB3Jw6TI0hSPF+vkOa0norfgCsOhEZCL0yW/gEqqSsMsA+
         NsnapryhNBxATJlGNUY1zdqqAFebbun4q82Gdqv8npEReRwCAcDIdqj/tEbf7CZBTJnt
         K8l6HI5w03HU0e14fUnC3RWJaKuzBLWCEp1C7rDpCmUk6Tz5hAIWSf5b9NkPDIcS+4yy
         p6mWoUZtitez2tw4BaXmcR28wc2tIl8cfb6CoqQwpit0+D2ySxSHB5lNv1Lt3E+pdaW5
         nhJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUDbvjpjR8VJcGd/tRKLJi8NFtu8gxlNZc3Q4pHstYFA4JPjM9AH9YhYXd9RlaY7ncFUvvxQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy+0oT3qQqEyZGnYfmX2HcK3a0wbYNKob1arK+9579jOPIB40L+
	K1IvGVhsmgbQyJiUe5A54mCk+vR1Hdbpq7Xn1pHLUpHipAB+RuvCfeq/
X-Received: by 2002:a05:6402:34d1:b0:634:ab36:3c74 with SMTP id 4fb4d7f45d1cf-654526c910fmr2094078a12.9.1768574472996;
        Fri, 16 Jan 2026 06:41:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HtQugbq22sVmPg+xtgFYPXxls5i4jlIJUFTQfdCoPXDw=="
Received: by 2002:a05:6402:a254:20b0:64b:aa13:8b3e with SMTP id
 4fb4d7f45d1cf-6541c5da4f8ls1593405a12.1.-pod-prod-02-eu; Fri, 16 Jan 2026
 06:41:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWBGSpYvjTVZNhZJxRsDVsfFB3cGWLCB0l2XRN6y1ZxMzcKXqWYd424R557UHEucVoRFcSTOHBe7gc=@googlegroups.com
X-Received: by 2002:a17:907:da6:b0:b83:975:f8a6 with SMTP id a640c23a62f3a-b8793033340mr280204166b.43.1768574470679;
        Fri, 16 Jan 2026 06:41:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574470; cv=none;
        d=google.com; s=arc-20240605;
        b=P01PwULYt+oTuup9LzAJsMNFvSDY9J8sYuiTuXXETXo7AwGjDK3XBRflFDPa1/NjGf
         g9IKzSkUTX1l5KNllDDQ00xnIKRyvAexM8V6vN1VoTbNZhdQxArhHi12+XZ2AsHaqhYo
         5ijrLHsxOLIfa7T4YR4eJD8qMLxtbOKg/d/mcP9wYOr6XKPDZ04xsWpCYqslQP0w9Xi3
         vjUCgQP2Z0hQhdplnpeNw0MJNFGEQ7dow1rw1N4tUOotdOVs6UlLbl/aKzcUd6vIdptX
         aTzUZdgVw8ihrGVdmEzR5a6QgaDWOeWqpFBUW9GE2rX2lZFXu0ZRD81HldkUiZbf6mcj
         UP7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=xgZ9GBTAAzmeTyqJuDn20wm4Bud6VxP9e5RLLgZE5j8=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=kfLS65liNqQEcMB2ACYI64WBBfvcWdmBljpVTfzsog/IuLMS0ouHhJYrvk00fo08nV
         CSEB0jUQ/BSIz/Q/JSG+MUtV3/puFGg0dBar2zRFiL6miiKsLaJmWajvE6WaM4YYmCQV
         v8u925bjSk+Unxzf+5vyTX/b4N4q3FkovS7FPwRUpZgLN4E1kIX04gmWBka4uFngVMii
         7igK2drb9vThhUqo6enawqiqHBjlurZS4LKECP5vA7morQYg/oy4MJQi1ekgp/PftK1T
         OkPSIogfpa7dv/VWPf08H2Qv8Ek+piwthazKf6vhpCpR+dfXcQttz5hlfJcJrAyKBTHu
         5ZUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959619dasi4702066b.2.2026.01.16.06.41.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BAABA337E2;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 99C753EA63;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id eHNEJeZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:39 +0100
Subject: [PATCH v3 19/21] slab: remove frozen slab checks from
 __slab_free()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
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
X-Rspamd-Queue-Id: BAABA337E2
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Y+96g/mv";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Currently slabs are only frozen after consistency checks failed. This
can happen only in caches with debugging enabled, and those use
free_to_partial_list() for freeing. The non-debug operation of
__slab_free() can thus stop considering the frozen field, and we can
remove the FREE_FROZEN stat.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 22 ++++------------------
 1 file changed, 4 insertions(+), 18 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 476a279f1a94..7ec7049c0ca5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -333,7 +333,6 @@ enum stat_item {
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
 	FREE_FASTPATH,		/* Free to cpu slab */
 	FREE_SLOWPATH,		/* Freeing not to cpu slab */
-	FREE_FROZEN,		/* Freeing to frozen slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
 	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
@@ -5103,7 +5102,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			unsigned long addr)
 
 {
-	bool was_frozen, was_full;
+	bool was_full;
 	struct freelist_counters old, new;
 	struct kmem_cache_node *n = NULL;
 	unsigned long flags;
@@ -5126,7 +5125,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		old.counters = slab->counters;
 
 		was_full = (old.freelist == NULL);
-		was_frozen = old.frozen;
 
 		set_freepointer(s, tail, old.freelist);
 
@@ -5139,7 +5137,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		 * to (due to not being full anymore) the partial list.
 		 * Unless it's frozen.
 		 */
-		if ((!new.inuse || was_full) && !was_frozen) {
+		if (!new.inuse || was_full) {
 
 			n = get_node(s, slab_nid(slab));
 			/*
@@ -5158,20 +5156,10 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	} while (!slab_update_freelist(s, slab, &old, &new, "__slab_free"));
 
 	if (likely(!n)) {
-
-		if (likely(was_frozen)) {
-			/*
-			 * The list lock was not taken therefore no list
-			 * activity can be necessary.
-			 */
-			stat(s, FREE_FROZEN);
-		}
-
 		/*
-		 * In other cases we didn't take the list_lock because the slab
-		 * was already on the partial list and will remain there.
+		 * We didn't take the list_lock because the slab was already on
+		 * the partial list and will remain there.
 		 */
-
 		return;
 	}
 
@@ -8721,7 +8709,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
-STAT_ATTR(FREE_FROZEN, free_frozen);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
 STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
@@ -8826,7 +8813,6 @@ static struct attribute *slab_attrs[] = {
 	&free_rcu_sheaf_fail_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
-	&free_frozen_attr.attr,
 	&free_add_partial_attr.attr,
 	&free_remove_partial_attr.attr,
 	&alloc_from_partial_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-19-5595cb000772%40suse.cz.
