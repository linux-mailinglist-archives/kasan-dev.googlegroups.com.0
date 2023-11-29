Return-Path: <kasan-dev+bncBAABBZUVTSVQMGQEUFXMYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 923877FD360
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:56 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5b9344d72bbsf8817609a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251815; cv=pass;
        d=google.com; s=arc-20160816;
        b=fsXSxTnuAiqCaaB/8R3blkh/2UQOtAI7C7ODGbD48+FDcSLexFE4mVOzoGkwuXTeXk
         DDJbFJan7O+hxsX0R9D8dq2cl0tLK6QTZvGGpV1bzK5fs5/0Vx95LgwNHJ6IvShMWWKJ
         0Phwu/lZrYo90RPdY81RXCK4GCNLsfY8SwgzTEAdvI0AATSobXDNIej36zWhLtwwi//F
         a/++GUKj6P28j6eRL2wLCknjazLFR/HMMMStNxCeRmqibNd04l0cZi3SAIUxsCVQRKjE
         LmBq9S3Y8j8EDJ/fZz3f64Q04KayIFcx8OhMhBlkvTrIdl/wTQfN96XWgb7ZxTKoaHX2
         BhLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rAXNqabTcN5XcvnQep8J71aGxNN8mFwOweI8rNDgCYw=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=QrTL07iJD8Pwo2wJ2NfJu4aR1vEB7bZ0tR8e23hDeWoExYt3rA6A32eYLEUlhTaIZN
         cddgFHaraGi5ioh3k2YjaRHhoGei+YFfI29GbOy+Kj5vgSafui6YtpcaT8qQy6a+hjnC
         Z8Nns/fy3u6arkvqzudhW6dEKNsSFDTaEudjJpwkeU8TDGzbMxlw1P7NBuBc1Q/wb7vp
         aHiTwwM4YUVBQ27nTQ6f1hTaIb9nPGG4S8cN+yYOY+oQvNHUDxPLQC04FRJoaWqMPiME
         n11Jx5m9Y8ounUpoYa8zpDAfvUtuAR9LsbDOBI4s+drurFdDa0R79iFOwgsXatUPEHoc
         XP7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JSaWHQ5n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251815; x=1701856615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rAXNqabTcN5XcvnQep8J71aGxNN8mFwOweI8rNDgCYw=;
        b=DqIcT8+Ty2hNaOAByTvvrAcD4oPEZAds3Hu6KWZDisnHiWrkncd4nCCW8eut/bwloL
         xaCOGp+m52bBIX4GXxTEVJQdmf7bhf7t4j2a5WGZpeN6JTON9l2cyFRAOxFDEK6uTUIb
         SD3wBgbQ43JXS1hojxbkr6PakgiNH1hrG1hUuw774YbTxErwDr6PHK9PtejNO9yTLlvT
         KLZ+CQkIv/f+I4tvBUY9QXmpAGTvKRmmlHFLQqk26nWOwchpGkA3BvBoxUYk4r3s8S9h
         Ny/oE7GJINHwsMdQ6ZRCZMETOz0IvbOmY/OjqYzNS+3XoVxDTYBDCIkWl9+r0AkIUn6N
         59JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251815; x=1701856615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rAXNqabTcN5XcvnQep8J71aGxNN8mFwOweI8rNDgCYw=;
        b=Xei/6t2RKKd+4mFyMmLvnZrBmLW98FtRha1zQ7XExHUy7O3FoxgRJiEovWG7IyLF1L
         DbavHhmWpI46+HQL2iFlu1vDzlXktlOKU8fAZAqOUztCPFzWUk8duIq7l/6b+SZochts
         P2jFvbUKSRfIEb6fU+jTsIXrYbaLk+XCQEY2CG0dD94CQr9/owv+qSpbflM05nj1wdiU
         F4p6ph9tiLLLTsc5AR7vNYqMEucVNwCVQQ3qOD5D3rfP6/YfHW+KsVYkB1IgAKTYD3+5
         yKfNqtU3zfXBbCajIAg6aNzcCacP9Phvm+rvMe06mg+ngYPKbluuSN6jhtXo2Vb3jTnH
         k4eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx2gCqOTLzGYpzLw7eSfUh7gPEW0Zok4w3F5XNFF2oR0lwWc1Sy
	tBBWn4w0mqQVBj5LidnaXOU=
X-Google-Smtp-Source: AGHT+IE0b5kpC0httXE4OedliNTYvazXCO9zspOEyc0CsFfOwPZ+CYY0h6NLYiIgrCloA1YNo62CCA==
X-Received: by 2002:a05:6a20:9384:b0:186:1781:d660 with SMTP id x4-20020a056a20938400b001861781d660mr25049247pzh.6.1701251814902;
        Wed, 29 Nov 2023 01:56:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e381:b0:285:ed8:1a0c with SMTP id
 b1-20020a17090ae38100b002850ed81a0cls4299062pjz.0.-pod-prod-05-us; Wed, 29
 Nov 2023 01:56:54 -0800 (PST)
X-Received: by 2002:a17:90b:194d:b0:285:597d:46f2 with SMTP id nk13-20020a17090b194d00b00285597d46f2mr3730636pjb.0.1701251814361;
        Wed, 29 Nov 2023 01:56:54 -0800 (PST)
Received: by 2002:a05:620a:170d:b0:77d:a5e0:dc7c with SMTP id af79cd13be357-77da5e0dd27ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a2e:9c51:0:b0:2c9:af1b:de5f with SMTP id t17-20020a2e9c51000000b002c9af1bde5fmr3039036ljj.37.1701251618979;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=j+41rhGQMFcl6Al8wziUAkrF2vR2/+dw0qLhslDmkoRzdwg1do+NPfHIRe506RJq3B
         ijE4RQOjgv7N6p5DEX32UwJpTpRKcv8GQX/v6K3VlwKyh4qxk8gM5RJEs6kVWj/QNalU
         J1b0WbAxlo/6PiXYHRCiiNo+K4kWo/DPv4KUCyOl0UWS7+3PyL7G/WdihoA3WBXX/IEd
         W3ws95R9+TcHE/pIq1VOZbVwXZEpD9QArNi+MIbcovBAaind5JclUhno1OnIgSLjOqAf
         0OOGX41RVmil3JeTVTOKh3OA2Crpp4bs8GkkhTIhnpfCnUvdySR+ieHB4bXh3F2vqB+I
         zpvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=Z/MdY/rw/HJ2oq6eayRQ1jISyVijjFBbUkDkU5iKbc8=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=TSGYH9R5g86WkAb2navHeRPMUSJ6ddGaX2R2aXvCRzJ4buabcCa55hKTxX1uir8MaQ
         nM89Y8CigVlnJrmNimZzjN5VLhekf9q2nZJ3a8KaTdKnnGnHeva2tvdlBsBdBfYmnCrf
         1rJUqFXQde9k65RviYXmXw2ldriBrE7ajjx1ioEf2ya8NkG3av+S43xDl4W7wtCs4pWa
         TP6WCia7GrPH9QUzsQupnetz58FLVL+TvJ1wW+gxPE1iw2BJqJ3x2ClS35sX9xqyb5E1
         n4zPKKNe5sL5VJ7mPSzs2WoBSaSES8/fWclPTHtVYPE0+NiWfK4yaSpr0qc0yr+vxjZw
         AfDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JSaWHQ5n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id u20-20020a05600c139400b0040b47a6405bsi52541wmf.1.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 44CA81F8B9;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 240B213A9A;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +GmBCCEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:29 +0100
Subject: [PATCH RFC v3 4/9] mm/slub: free KFENCE objects in
 slab_free_hook()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-4-6bcf536772bc@suse.cz>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Flag: NO
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[17];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JSaWHQ5n;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

When freeing an object that was allocated from KFENCE, we do that in the
slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
the cpu slab, so the fastpath has to fallback to the slowpath.

This optimization doesn't help much though, because is_kfence_address()
is checked earlier anyway during the free hook processing or detached
freelist building. Thus we can simplify the code by making the
slab_free_hook() free the KFENCE object immediately, similarly to KASAN
quarantine.

In slab_free_hook() we can place kfence_free() above init processing, as
callers have been making sure to set init to false for KFENCE objects.
This simplifies slab_free(). This places it also above kasan_slab_free()
which is ok as that skips KFENCE objects anyway.

While at it also determine the init value in slab_free_freelist_hook()
outside of the loop.

This change will also make introducing per cpu array caches easier.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 21 ++++++++++-----------
 1 file changed, 10 insertions(+), 11 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 7d23f10d42e6..59912a376c6d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1772,7 +1772,7 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
  * production configuration these hooks all should produce no code at all.
  *
  * Returns true if freeing of the object can proceed, false if its reuse
- * was delayed by KASAN quarantine.
+ * was delayed by KASAN quarantine, or it was returned to KFENCE.
  */
 static __always_inline
 bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
@@ -1790,6 +1790,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
+	if (kfence_free(kasan_reset_tag(x)))
+		return false;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
@@ -1819,22 +1822,25 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail;
+	bool init;
 
 	if (is_kfence_address(next)) {
 		slab_free_hook(s, next, false);
-		return true;
+		return false;
 	}
 
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
 
+	init = slab_want_init_on_free(s);
+
 	do {
 		object = next;
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (slab_free_hook(s, object, slab_want_init_on_free(s))) {
+		if (slab_free_hook(s, object, init)) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -3619,9 +3625,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 
 	stat(s, FREE_SLOWPATH);
 
-	if (kfence_free(head))
-		return;
-
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		free_to_partial_list(s, slab, head, tail, cnt, addr);
 		return;
@@ -3806,13 +3809,9 @@ static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
-	bool init;
-
 	memcg_slab_free_hook(s, slab, &object, 1);
 
-	init = !is_kfence_address(object) && slab_want_init_on_free(s);
-
-	if (likely(slab_free_hook(s, object, init)))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-4-6bcf536772bc%40suse.cz.
