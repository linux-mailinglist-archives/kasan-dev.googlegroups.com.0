Return-Path: <kasan-dev+bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6D3qCPkac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:45 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D1D0771357
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:44 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4804157a3c9sf16658015e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151224; cv=pass;
        d=google.com; s=arc-20240605;
        b=heQn3srXXrf/UMPc/97f206aZc0JcSIL1uSjvRlKju4y9IR237pXDDfCHbIoUBqU2z
         lakxsnihzmQVo+t1tS4Z8QzpzhzME8OFrD0viFHQcWhDVH2dC2BgmzQ02mEo5JWZYW8y
         8RC5FJG1oQ081aGOcAc5uop3r7gCuCNRbZg6Na3iMaQTT82zPueTaEzroPTt0kfG/93C
         mA6vsZghTUDHcBMSE3JP8BUgCaWFMNJr/ujx6tz6E8XiPp1wutS8acYQQukkIAcsmMZ5
         h5FBx2JXGgyfJU9JvPF39Y5jJxjdCU+zfCOEAn9ihRVCeP+AkeA9F9LYQC9Wlrhas9Rb
         bT/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=qElbJR2TCZuS/abSzUkKM9VrFu0HH24n97DR9SH+834=;
        fh=VW8BmOg9IXN7Eli+9O4JRIler8ndoRPdzbrOOaQG1iU=;
        b=BEdB/m1fj47cgn0lLtx+UwNgXY14ua5ikLxLfl2UHrpMXJWJS/GRU8FmN9eOa1rsge
         aG+v0bim+d6xrXLgPSyMS5SiVLG89khc/E9+iW5AsHiqWOvp+9GjJF83d1ycNTPnvQP3
         MpQY8hkqUcYgNlgE76shU7dccAMf9r+xaSxYGevlpBOWrL+BrutcIJ/cEFmaZw4hRfiR
         9AtpOji4WzU4w3Ov9m3+iaEc3vWEcxJeEqlbFCsJ8tpBjiL3TtIkuFdiuuoAiByr8t5W
         vO1cm1Gzjtllp91AJWFGOE/EpZFIfts5x3g6QmUKjoFv0G6zCIKqLZwDRGHlgerPgDVm
         MtMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=27Uk3vvZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=27Uk3vvZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151224; x=1769756024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qElbJR2TCZuS/abSzUkKM9VrFu0HH24n97DR9SH+834=;
        b=kRXItn53IftJtvPuqcZVR9ImEmTFSTjaU4/J+98HZGaFJlx4X1EFKAu2gcY1OVMT37
         y0EBq/dxNqUKdCCyCCIqZhUp0QHSfGPAg0DLoNUu87yEGpzL4rVclQImc28oS5B3wGfS
         O9B6hrlP3x8S9LgEerQJgDQRs+o968der5wOYFH8ZtjChnacitew34KcJpowcjVhVJdg
         yBK+FmoThcKrs4w9whb1vhIiI4eOw4nBKKFhI3fKq1y60HiTeq/SFkFZ6RuPBEwl9ov/
         ebyTuhbcwmqXp1AqFMOm+te6WazbrlK2Ix+OVKrZUKO5vqOfE2uVEJICpjuejWEACXon
         BX3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151224; x=1769756024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qElbJR2TCZuS/abSzUkKM9VrFu0HH24n97DR9SH+834=;
        b=C/fBIcXpeKyd5qLe1yvrRYAjQFLiT31+sx6rX9+ExwYs1/gKTTvPUNDSo2HxM16MzK
         8j5Amk8e1huh9PKcoNSCfox2AU0hrLmDcB5mxGwSgXvfY+6veUIaOxSEyVNoD9+vbgaa
         4SpgDl9R6RgTmkNvE+x0UDzz27h4Of/TYB5eSvLudfpZUhUnxQ2hFhFJJukAAr7+TNI5
         sdCiUrBoTGhcL25ixcffmbChLsjy/FGW6z02SrkGTVzbP9NZGi3vzatcLPbHtVbxPfDd
         Du8QitrQznu6Oqp6AOKXhPi08jWcjVIfcRjpzUDkjjuU7riMAECRK9OxKEsGrDPugduK
         /6aQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWApXlv2D5f6tznPNT/JJusEnLTItP1BgyECc9b2/9HDlqIyPD90DR9hmUnxU8kF5hXfOBuYg==@lfdr.de
X-Gm-Message-State: AOJu0Yy8XpVnF9AFUqnGY6OPwY0BDCH/Ds+mdcUdA2nPYJmyyynpeSWn
	4s4EDMYzP16gMpajg2X9T4Lax1EkNTPDA/wnyAj2k2EVNNa11aIsqVoL
X-Received: by 2002:a05:600c:4fcb:b0:47e:e807:a042 with SMTP id 5b1f17b1804b1-4804c964ad5mr30012335e9.15.1769151224071;
        Thu, 22 Jan 2026 22:53:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FMnI4kGTX7WFhbltD6EAe8B/2sg9xKcXHR1rfVLJEUUg=="
Received: by 2002:a05:600c:1c03:b0:477:a252:a832 with SMTP id
 5b1f17b1804b1-48046fc76b2ls11752445e9.1.-pod-prod-05-eu; Thu, 22 Jan 2026
 22:53:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIZL4ZSXtyrAuPUjL2i9rs4B987oD1OHpu/ycd4etpyOA2fVTiwmaFD2dWxKQRHLOhzva/4IOTHLY=@googlegroups.com
X-Received: by 2002:a05:600c:8b6e:b0:480:462e:d640 with SMTP id 5b1f17b1804b1-4804c9cfef1mr31935225e9.36.1769151221914;
        Thu, 22 Jan 2026 22:53:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151221; cv=none;
        d=google.com; s=arc-20240605;
        b=SPCHdbnbjxxMY6g3zn7RW/PiF8rokpN6QWI0czA9L1NAO0caGVelrVdkGSRfjGXzGr
         Yb+rHQawXNkmndrkKxsQ+k08zdbjWDjY+P2GO2n0qGyD4mMN5sfGmboGOCJF8eGcgiqN
         KsNX5HrTl3Ppl6VC4JGIqvZEkvGFTZQwsHVA0JoutCw0mqgkWaVNQkeqKbrhkvvQpiol
         v4n8woYD1SWRIkCBF+ZQFZqNLQf8XwEwJrcTv/8fS7OxgygY6/sguw8PwIv0AYRErZO7
         jWX+DejQVQuDnwfhbmZM1xb8qHaHGMVdmxhKj6oIBe4GJqpcxjWLcCvJw6Rt8uVBHrfG
         VVZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=xSBhOPdL5sebK+aDhtX6/iV+qHkNH9ah4WZSL6is/IE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=hWPpyPuPn0+jiAzGBZnxv6YVqMLBFkl3Uzx6qiiPIDIy6uzXJd+jgdQh8Y6zsg/aJs
         vw5kiO2Z4IKHdFp9AzDkarA4pFE2aChY5bHSE9RS06v2QqpYGyLMuyFyOFZtikyHKVJI
         tCd/zy6ywzlEwiGEvpFT9GF3AO/GkZthPdu8IIAObPIiCJsg43/0db2aLpiv6f8RpaO0
         XuA1bODFfAUyj23Rg3p8uToBez2rY1JuYwySC42Py/8Fps0l1meSaYe3ch47e7rXmleB
         rnodYAuf0iKnd31ZlUWPzAsY7A50RjPGRwDBeBXzsFDewdlLplxx/q8yY+O4eAwk46vt
         h1XA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=27Uk3vvZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=27Uk3vvZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4804db5d467si76875e9.3.2026.01.22.22.53.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 600B95BCD7;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 38A441395E;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wC+KDdcac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:58 +0100
Subject: [PATCH v4 20/22] slab: remove frozen slab checks from
 __slab_free()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-20-041323d506f7@suse.cz>
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
X-Spam-Score: -8.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=27Uk3vvZ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=27Uk3vvZ;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI];
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
	NEURAL_HAM(-0.00)[-0.975];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,mail-wm1-x33d.google.com:helo,mail-wm1-x33d.google.com:rdns]
X-Rspamd-Queue-Id: D1D0771357
X-Rspamd-Action: no action

Currently slabs are only frozen after consistency checks failed. This
can happen only in caches with debugging enabled, and those use
free_to_partial_list() for freeing. The non-debug operation of
__slab_free() can thus stop considering the frozen field, and we can
remove the FREE_FROZEN stat.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 22 ++++------------------
 1 file changed, 4 insertions(+), 18 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d9fc56122975..3009eb7bd8d2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -338,7 +338,6 @@ enum stat_item {
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
 	FREE_FASTPATH,		/* Free to cpu slab */
 	FREE_SLOWPATH,		/* Freeing not to cpu slab */
-	FREE_FROZEN,		/* Freeing to frozen slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
 	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
@@ -5109,7 +5108,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 			unsigned long addr)
 
 {
-	bool was_frozen, was_full;
+	bool was_full;
 	struct freelist_counters old, new;
 	struct kmem_cache_node *n = NULL;
 	unsigned long flags;
@@ -5132,7 +5131,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		old.counters = slab->counters;
 
 		was_full = (old.freelist == NULL);
-		was_frozen = old.frozen;
 
 		set_freepointer(s, tail, old.freelist);
 
@@ -5145,7 +5143,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		 * to (due to not being full anymore) the partial list.
 		 * Unless it's frozen.
 		 */
-		if ((!new.inuse || was_full) && !was_frozen) {
+		if (!new.inuse || was_full) {
 
 			n = get_node(s, slab_nid(slab));
 			/*
@@ -5164,20 +5162,10 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
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
 
@@ -8753,7 +8741,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
-STAT_ATTR(FREE_FROZEN, free_frozen);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
 STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
@@ -8858,7 +8845,6 @@ static struct attribute *slab_attrs[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-20-041323d506f7%40suse.cz.
