Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCNBSTFQMGQEP2ULE3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 96C92D1390A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:31 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b78ae5ab2sf2306529e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231050; cv=pass;
        d=google.com; s=arc-20240605;
        b=CYHFbaji3yPl/l7YsUPs+2Z0vEBJB0smmdGDSB1IDs0oSHid5w8uXfjl1Mkfezw8Cb
         Q2nB4Nu7FjLPh9uEPy4y64yJ6VbBbqfq3hTl0Cl7B0ecMhpbm/7LEt2+i1IbZkgWtHGT
         Uue/EnsNa+O9+7va7XCLqu0IHn6IbE4Ypbak1bwq3KegxaoDJqlxQwmAEohCveCWqeSm
         4l2UYmMpVVqZjmga/C/PlgYdvKQ22jS6EanTWovUmz/zL+YcPW8vB+Ixsy2RR6VA79FK
         8OSR8PCPGcGmDKl7iAjIitA+2tl7NeGy1RYdCkEC8ELM7YO5wfjQOWD/fKgKw53bSC9o
         I3vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=wHg5DvvOqtqhxqe4P/FNYNNrBfgLdLLBxltCjyJrshQ=;
        fh=6wm6PpEsSTobv7+OhXvRoHnUXi39sv1/xpdcVIqNfp4=;
        b=bgWd57ax50+PZk8yemwgfp/7W1KwzW4HfaS6bda69ctguheFyoCv/uorenQAWgEz/5
         IwYnG0bSFpT0f8p6dkL7sw6WdCbQ/zCFzwspAgeh9fb/4o8sPrw0LRQkebPErMZq1Pxl
         35tPwiuwb5ppaMTw0q1l0/pKKGEW/TExg0Zz9ojp5lk4l6PzWFRHHC4SHTSH0tlsSmOb
         bhVbEUci+xB5JWlA0wu90/HPxumUSavslvM6+qXlNnuIeOXi7IGtDbPuyma9HUcAKjWj
         IIAdHUT46Ov7iDYcmmiIxHnHctJphzvqpOZunjMi3h9anp1K5j3QfOsqllOwtkLOkTuZ
         KfJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231050; x=1768835850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wHg5DvvOqtqhxqe4P/FNYNNrBfgLdLLBxltCjyJrshQ=;
        b=J92g4m/HxeoLa6ZGdual7yprDi2j6VcEmZIa0WxaSReA3kBJ7s0T73CUK3OmviNHYH
         I3T3mROAhvaeLPbF+AQ9nHNp+apbMNPx0LvOOH9spsCi/0B5lJepqo1hpVAYSKHEbAU6
         vX2J5kradCQ7bl5SWVgNue9qQpp0fZW2QH2Ac7oESRhm/Q2LRFEu9N1QE0czQkSJPpVN
         iWOZPpOCT9O9ss+vCZK9Vj9P3m1y7RRBUeRd44FjZlzZKM5iWiGumuTZU0gwfl3ZrUqS
         oP4WzPWmYVhFvBVKAH00H44h+b5s7Il7yx9PPEpsP5r2yq8SZlsPdbd1+Zt/YRK5i8QH
         VaTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231050; x=1768835850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wHg5DvvOqtqhxqe4P/FNYNNrBfgLdLLBxltCjyJrshQ=;
        b=SB13iHGF3ogqBy3D/Jr68D5batyxAzqHPfvIC4+2CVZlJehq2aKzsEb5/zlMaaP9hR
         lImWKpZjN9/auZWVSvdbMqC0d8CHpycqO0/xKj9BfVmABo8ZH0Se1wuevWwf1ODiOkil
         MtrCYXQ0h+UkpDG+lcZdRs+2E+b7rEeOekds5TfT2N83L6p8aaOXdgN3M5YRljgtUgdm
         ezB+NHzZ8dRnryWN+fEjuQ7uFVgpCc/skHJFSWflXMdU8DIQzbwvf0oxPK2kY1J5AGtU
         hhSDLLdOXzEVMeqrDHjzyWtNzzN71hrP3AgsTkL9eu9VPXodAkFNct2ZjndnP5PjuPJw
         j6bw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxsh7dBWriBtkuolwuWv5SjQNrG0a3702vfK3VYZNE4274A/YhlhpAMuP2ov7YWkl8n7Y6oA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5/VyfTNkwIPktOxTw2THhnEedL1DWhNzos6i2CgD29PDsdi1M
	wWlCvB43xgsn88k//i2AgaHQa5x7HxV5htcS/vX4nVhncIOFJ7VpoBbc
X-Google-Smtp-Source: AGHT+IFwxu6fW6KP6K/vR/0L3+CJgE5j+ROfEtd4SGXVZWahhiHDAC6HJPVHRyBDCY4xaynzfhBIdg==
X-Received: by 2002:a05:6512:39cf:b0:59b:7c76:dede with SMTP id 2adb3069b0e04-59b7c76e0cemr4288324e87.20.1768231050025;
        Mon, 12 Jan 2026 07:17:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GqRbD5SH9zoROxJClovYfYBspHQcjjSbH2VqBg5l1sKQ=="
Received: by 2002:a05:6512:138b:b0:59b:6cb9:a215 with SMTP id
 2adb3069b0e04-59b6cb9a37dls2084631e87.0.-pod-prod-09-eu; Mon, 12 Jan 2026
 07:17:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDF0YSkV2kmQhto/24kzCaguZW7nWfjxv7tJamc/qnglduBoRGmb4O8CshE+tAOkAa/8j/+R9fYic=@googlegroups.com
X-Received: by 2002:ac2:54b7:0:b0:59b:7319:1177 with SMTP id 2adb3069b0e04-59b7319120amr3635026e87.38.1768231046795;
        Mon, 12 Jan 2026 07:17:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231046; cv=none;
        d=google.com; s=arc-20240605;
        b=E3K6d+wiy4E8WxHir+K4rhAUk+ODvorQrR/hmVy+kAEoVmgImuHGAputtd4vbxGsH1
         X9FBQbtOql4ia0vLjGJJFekcUKV6Ht7n1ztOpbszL0bUfCZBtqg5owahgZHxlEb++YdS
         Oi4AcDcsjDMnt9Kg+h+hpLLJRWhoVs5H29gUdtjGDonBORUSoNU4CrwLdhE4iBnVQeFh
         Pd/94/Gxuw+54T0lf52A/fOifbJ0LZTJjPoXDV10EmoVMoOOvx9ltX0XrmgvYpwnU6g1
         j5vZLtRjw19EtovXN+Oe5g4+PDYo/RUBaLNonC8tk/WjEdtVqz6ZFLrNWDETvIVjaqp9
         GN3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=rViawX+xj7FbNbHoLK3aJgUNTuEVqQrGyxgI1nDCQeQ=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=btqX3H9LloqTgaHJDfxwauu39mY0jZkjMSFemKuy8CUAani9NSjjWbhtCKVoHZ29/G
         +nW8GXuPN3rGOqYIBgoIK771PsWdVawyqwHM5IDFuWDhSLCn5yvV+rwvzG7LHvAiVGH1
         GR5k2Cnf//wivpmZjwNKYDyh4pL29169R53u466Z+ID1OZ/M4IuDmi4g7x6nnAGUWMgp
         HPpK62tn4zFiOZb9UkQpdF9zZc1s204inLiJ9JAUYC1tiMhQmFiz/0unJ2+3BI9SORLK
         yEI/tkCxbtzxUjdyfs2AvbJCeAQ3np5ZSItgmNwY7w8UppACXT7/e+cfkBkFkXqC/O8D
         d8Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b662c0faesi259220e87.1.2026.01.12.07.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:26 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6FDE03369C;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 54D263EA65;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SHhsFGsQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:12 +0100
Subject: [PATCH RFC v2 18/20] slab: remove frozen slab checks from
 __slab_free()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-18-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
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
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 6FDE03369C
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
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

Currently slabs are only frozen after consistency checks failed. This
can happen only in caches with debugging enabled, and those use
free_to_partial_list() for freeing. The non-debug operation of
__slab_free() can thus stop considering the frozen field, and we can
remove the FREE_FROZEN stat.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 22 ++++------------------
 1 file changed, 4 insertions(+), 18 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 7f675659d93b..5b2d7c387646 100644
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
@@ -5093,7 +5092,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			unsigned long addr)
 
 {
-	bool was_frozen, was_full;
+	bool was_full;
 	struct freelist_counters old, new;
 	struct kmem_cache_node *n = NULL;
 	unsigned long flags;
@@ -5116,7 +5115,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		old.counters = slab->counters;
 
 		was_full = (old.freelist == NULL);
-		was_frozen = old.frozen;
 
 		set_freepointer(s, tail, old.freelist);
 
@@ -5129,7 +5127,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		 * to (due to not being full anymore) the partial list.
 		 * Unless it's frozen.
 		 */
-		if ((!new.inuse || was_full) && !was_frozen) {
+		if (!new.inuse || was_full) {
 
 			n = get_node(s, slab_nid(slab));
 			/*
@@ -5148,20 +5146,10 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
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
 
@@ -8715,7 +8703,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
-STAT_ATTR(FREE_FROZEN, free_frozen);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
 STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
@@ -8820,7 +8807,6 @@ static struct attribute *slab_attrs[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-18-98225cfb50cf%40suse.cz.
