Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYNGVTEAMGQEWIMKS3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B2CA9C34AC7
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:38 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4775e00b16fsf2997535e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333538; cv=pass;
        d=google.com; s=arc-20240605;
        b=kI3Chqica0sL/Gt/fXX+HgjoIqJGVUfywpm5rptN3ahoDjKLbmyiDmnI7ZtiR3aH7x
         ll0f0v+5AQJV3p6RFLDX/ttIEb0/9rJ4aqpaXdYuP6W7LBGg82qjAj4EbJs68Stj1bug
         CcgKIvKQc82AKFxtouRfHmClVsgFD8rER/Jk20M1k180IwPwKCqu8p50jU2QPY4XcD26
         JH4BhZf4z4xWtgd4s/lioEbLi7VKFF5L2jSr2t6RRiLjjsAs3EpGXLLm6jq1d/FWeI8Q
         nuZr9yItUFDo2LbghggQ2iBBaeOBRQrAhC4PuJMooDFJnBS++sr4aq+D+y2wdT8f7g77
         VLew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=JjhHRp8rGirxR/oEU4tFJeOPAY+u9xSyFq7Yc246F6I=;
        fh=PoKhaif1a7LqjF1krIAUhr2eycNQivEba+i59uyxLPk=;
        b=j9lDqZrPd1hE+NfSXwrIGXhNFUEglzODcn46E0uOh0OPDUPchh8SZbqORmCSVggEGD
         qnyeWwjIgDGy/vciKs6HvR4CcselPEMkhlcopSh1n5Ivxz/D3gu+I7220rd7b7ayNYtA
         eVF/JhB3glWHRoTy87DamyZ/mactB+wWxFJyo5VXkNAMK2ePm5Dn+aJ4lnjs9quSI761
         lvrAeMCnlJqEXIlLLr2HnGV2O3N6aypoBLKPfMMVjF/fYK/wCjJYIkk1+4WI/X79Sf+u
         DXdx7Tv+QfycE9dwlFfPzcGxrhmYaZCqK45FtspmxfeNgO8e5hg+yzm7ffomGpAlYki5
         g1Mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;
       dkim=neutral (no key) header.i=@suse.cz header.b=GzVO54J1;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333538; x=1762938338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:in-reply-to:references:message-id:mime-version
         :subject:date:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JjhHRp8rGirxR/oEU4tFJeOPAY+u9xSyFq7Yc246F6I=;
        b=J7g9rWie80x7kSAQ6aPOmOfC67fJY7aE1aoVKnTUEuONOo6gSt5c24it7M1EeCVl5c
         vCyhDka5525VxPsE8blFh2kxkuqAg2UNmZVx5dM8fWemjMOWkksC6mADgQMjsQhQDiB/
         5bomkVBWCRBnQRonrQC7BjwjdPc/7YELZ6j0s3j0APJG6zyH1fP8g4npgtrpahNJSQvb
         2Uid7KJOYt8NdHieMoagVhH30FVObEHMg3bdlMTI9Lf3ZWOqR0pXERJz8FS4A2OjWH/o
         VKKCzCn+8FhpKebogXcfRkvW6HoeSZdgt9tcs6i2iPtuYjHYcyO66AahF92pfWdmKv5t
         hcIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333538; x=1762938338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JjhHRp8rGirxR/oEU4tFJeOPAY+u9xSyFq7Yc246F6I=;
        b=l7ioafPYveGVzLTfXbh5OjXmbem3gsJO4wNl7o35EAxpicMw2uS4oAhIHZ3Yp95978
         WqlrYfDxQLK1FreTAnpcCMSIpmE80beMbycyheNN5EcJzoRE5/CMwFBzW/ivKPg+Ee8R
         oDR79N1IAVsoFp5yakS5pn5MZoD7n+kvc1KN32CczRXfLhvruMoaAnEFS2ACXqntQMuC
         qoyvLgCuSh2nFCJ1VRYJufQrLS8ECXPm0b7KfvsMvcGpe9trScIXzUIk7Ls92YMwfsp3
         Z1qPr+3PwZiZ7KoEhmvnr43lXZcSM2vjwyXZMCB4VT9CMwmXhmSuZ9MlqAqchlQsMuxb
         ft3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9YP23mMgyXc08xRHTRaUNINkZHPykmakoe3iH3EThsIY9+qBIsT0vjHSDVKykXrzD8pIxhQ==@lfdr.de
X-Gm-Message-State: AOJu0YyuJy08OUKSX+pMdQgNeBbKaMJy3/tqPyurqMiJv95qEr7PkE2R
	D4gorFXys4JFL2uwE06weIEhy5t7qsP6eesMSs8jMGRH9v+ODpMASqBB
X-Google-Smtp-Source: AGHT+IEagezmOkSCli0m8bvcqwPcxyMNVbmEp0B0ttaObTK6jHUv8OsZtZVwQq/wlvRpt1r4A8PRoA==
X-Received: by 2002:a05:600c:530d:b0:475:dbb5:2397 with SMTP id 5b1f17b1804b1-4775cd399fdmr20706155e9.0.1762333537935;
        Wed, 05 Nov 2025 01:05:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Yn2yVrOtzcenOu8b3J4KkYRkn4NIgeikV4Y15WIaunkQ=="
Received: by 2002:a05:6000:25c4:b0:429:c4ad:e771 with SMTP id
 ffacd0b85a97d-429c4adf286ls3139545f8f.0.-pod-prod-08-eu; Wed, 05 Nov 2025
 01:05:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgrySzJ8fnFwUKa7JMhupurKepbzHU2Pww+L9Z2LSFYXNyRuLiAG/eEurwHV5IV8q2ALLC2gmpIvM=@googlegroups.com
X-Received: by 2002:a05:6000:1a8e:b0:425:7e45:a4df with SMTP id ffacd0b85a97d-429e32c839fmr2123303f8f.11.1762333534794;
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333534; cv=none;
        d=google.com; s=arc-20240605;
        b=WECrINC3wSiuJqQOeb4UwtNx+fOH3zo38tm1inrcmoacE29tnrCGA67ybRU7kdzBV+
         8XAYimyrVNnWuXTPjs0+GkvEUwoNGJbehnMVu4YzeqAyEMQQa3sA2yLWYurMbBG8uOwQ
         flKF13Fx5KuW/Oezn6RCXS+JLdkJZcev/8mZKfMq500BEUYjHXeUYPh9dN7sn7V29vpP
         O8vM78wYr7TdePldVrtkQGK2U2cz9dOyfZe7L8A+umCrlwAB2AVlkMGQ5Irx0xJ4WQjd
         FmAqiTxgxRFbiEjNQ4Hiw6k3Xv6RX5nvcbcPSCVvrXZpIip7P9PmmyeKY44Oqy0GOQjD
         7gxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=k3xWBfAUG4JHWgNOrNA/S+tg/3AdmFzQs0YfUSio0A4=;
        fh=dklpSMYSEC41gVZaXcntr2MBCAntdHiJG8gGN2y0lZI=;
        b=cZOxlr5yLzfQJHz4FuEEzQyXbxNxP9yRStYUGUMAIJ6ORq2WwRvIkJTgJxVvwlHAnQ
         gRSEBGs2jPAJejgqL873p1IslZdFgczb+NbyoESHcZoog+TlYhtIRwC+pek8d01ug+/C
         i8Iv0n11Wb6Ny2ytRqimvNjcPcCN7XoZ13yyIK71ALlEVZViNWKzAeB3/XWkHZ67sZ2U
         OdzBgHgO6wFGtiX29RD26HuLyxGfwDlcwQp8Ot5u3sLcYS+N+7ha7+aLoDlAVTFjz4Jw
         Tc6zyVsdqAmVGRh2H06n5nzajxlF/ZUBpESZx+mx+wcVn4gmd1c/AR5RqnPssE9/Pmev
         b4Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;
       dkim=neutral (no key) header.i=@suse.cz header.b=GzVO54J1;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429dc1d5d56si104016f8f.4.2025.11.05.01.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A05C21F452;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8699513A88;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CAyZIFoTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 05 Nov 2025 10:05:29 +0100
Subject: [PATCH 1/5] slab: make __slab_free() more clear
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251105-sheaves-cleanups-v1-1-b8218e1ac7ef@suse.cz>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Queue-Id: A05C21F452
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,suse.cz:dkim,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;       dkim=neutral
 (no key) header.i=@suse.cz header.b=GzVO54J1;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=g3fD4LL3;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The function is tricky and many of its tests are hard to understand. Try
to improve that by using more descriptively named variables and added
comments.

- rename 'prior' to 'old_head' to match the head and tail parameters
- introduce a 'bool was_full' to make it more obvious what we are
  testing instead of the !prior and prior tests
- add or improve comments in various places to explain what we're doing

Also replace kmem_cache_has_cpu_partial() tests with
IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) which are compile-time constants.
We can do that because the kmem_cache_debug(s) case is handled upfront
via free_to_partial_list().

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 62 +++++++++++++++++++++++++++++++++++++++++++++-----------------
 1 file changed, 45 insertions(+), 17 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index f1a5373eee7b..074abe8e79f8 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5859,8 +5859,8 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			unsigned long addr)
 
 {
-	void *prior;
-	int was_frozen;
+	void *old_head;
+	bool was_frozen, was_full;
 	struct slab new;
 	unsigned long counters;
 	struct kmem_cache_node *n = NULL;
@@ -5874,20 +5874,37 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		return;
 	}
 
+	/*
+	 * It is enough to test IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) below
+	 * instead of kmem_cache_has_cpu_partial(s), because kmem_cache_debug(s)
+	 * is the only other reason it can be false, and it is already handled
+	 * above.
+	 */
+
 	do {
 		if (unlikely(n)) {
 			spin_unlock_irqrestore(&n->list_lock, flags);
 			n = NULL;
 		}
-		prior = slab->freelist;
+		old_head = slab->freelist;
 		counters = slab->counters;
-		set_freepointer(s, tail, prior);
+		set_freepointer(s, tail, old_head);
 		new.counters = counters;
-		was_frozen = new.frozen;
+		was_frozen = !!new.frozen;
+		was_full = (old_head == NULL);
 		new.inuse -= cnt;
-		if ((!new.inuse || !prior) && !was_frozen) {
-			/* Needs to be taken off a list */
-			if (!kmem_cache_has_cpu_partial(s) || prior) {
+		/*
+		 * Might need to be taken off (due to becoming empty) or added
+		 * to (due to not being full anymore) the partial list.
+		 * Unless it's frozen.
+		 */
+		if ((!new.inuse || was_full) && !was_frozen) {
+			/*
+			 * If slab becomes non-full and we have cpu partial
+			 * lists, we put it there unconditionally to avoid
+			 * taking the list_lock. Otherwise we need it.
+			 */
+			if (!(IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_full)) {
 
 				n = get_node(s, slab_nid(slab));
 				/*
@@ -5905,7 +5922,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		}
 
 	} while (!slab_update_freelist(s, slab,
-		prior, counters,
+		old_head, counters,
 		head, new.counters,
 		"__slab_free"));
 
@@ -5917,7 +5934,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			 * activity can be necessary.
 			 */
 			stat(s, FREE_FROZEN);
-		} else if (kmem_cache_has_cpu_partial(s) && !prior) {
+		} else if (IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_full) {
 			/*
 			 * If we started with a full slab then put it onto the
 			 * per cpu partial list.
@@ -5926,6 +5943,11 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			stat(s, CPU_PARTIAL_FREE);
 		}
 
+		/*
+		 * In other cases we didn't take the list_lock because the slab
+		 * was already on the partial list and will remain there.
+		 */
+
 		return;
 	}
 
@@ -5933,19 +5955,24 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	 * This slab was partially empty but not on the per-node partial list,
 	 * in which case we shouldn't manipulate its list, just return.
 	 */
-	if (prior && !on_node_partial) {
+	if (!was_full && !on_node_partial) {
 		spin_unlock_irqrestore(&n->list_lock, flags);
 		return;
 	}
 
+	/*
+	 * If slab became empty, should we add/keep it on the partial list or we
+	 * have enough?
+	 */
 	if (unlikely(!new.inuse && n->nr_partial >= s->min_partial))
 		goto slab_empty;
 
 	/*
 	 * Objects left in the slab. If it was not on the partial list before
-	 * then add it.
+	 * then add it. This can only happen when cache has no per cpu partial
+	 * list otherwise we would have put it there.
 	 */
-	if (!kmem_cache_has_cpu_partial(s) && unlikely(!prior)) {
+	if (!IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && unlikely(was_full)) {
 		add_partial(n, slab, DEACTIVATE_TO_TAIL);
 		stat(s, FREE_ADD_PARTIAL);
 	}
@@ -5953,10 +5980,11 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	return;
 
 slab_empty:
-	if (prior) {
-		/*
-		 * Slab on the partial list.
-		 */
+	/*
+	 * The slab could have a single object and thus go from full to empty in
+	 * a single free, but more likely it was on the partial list. Remove it.
+	 */
+	if (likely(!was_full)) {
 		remove_partial(n, slab);
 		stat(s, FREE_REMOVE_PARTIAL);
 	}

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-1-b8218e1ac7ef%40suse.cz.
