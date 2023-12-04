Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX6TXCVQMGQETKF745Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E59803E76
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 20:34:57 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c9eca8abe5sf23110101fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 11:34:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701718497; cv=pass;
        d=google.com; s=arc-20160816;
        b=dVPuxoXOUQK3U+ECPQr+mMcuTZHmDQkv3X1KNY1vPp2C4zmepRIos4M0QTD79/F1gQ
         YaYZLCugHjwSlaAEifZzSBy8JwXN82Sfz2YqrxyL0yKUPop8MtaSD8llBZGC7SoDQcor
         SmkxhZaBovFaSQotqbyGrRh6UsqOJluSzswuoqhPHy3kYKG8aubETDkdk2zDE3eEtR8C
         1C+58jQ8oVZa7PCXipfwFOfLbrABgUG45JRJBk0v3GHSz907fykbS58Nqv2mx6LjMmVL
         6vmCLxfO3Yg5QDV2UAg8G7eMVIkdopC+FJ5o6g8Ie/SxWNMHfhbvI9u07zHlrqRNwztu
         /wbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=aeSTvFOADdGOnFobIjIuMyBxc1tgJRkLk7RlRLLbo6g=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=iHNlSIcIy0gWAh7LcvAeAZ8nZhvwtGofho4eHIS6JGUcRCxKyQbL++1x6OwsBYDXcH
         HRwOiQKr0FuH1yIkw/3uYL9fPDuMVNayrHadNLwlBcp5zumtzJc5FhyCncshAzm8teDg
         8HdaUF5+AqQOutpXOkvZwSR2og+G+ijDgULPY2COkY8pGobl3RFUHt2+rHF+E7AxTwsK
         lFpha6TRu68OJSFrjJS3qB99DviqWReRlLz914vGgWQy2Du0hXhYAyua9gofjPQkeFUj
         o2yXpn+yfe6hf29m6juWT/sTpbymaq1LWfh+8wAZr1XJcHM+Z7z2URNDLA6mziHF96GL
         V7tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3aoiT3pa;
       dkim=neutral (no key) header.i=@suse.cz header.b=LJvwh73C;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701718497; x=1702323297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aeSTvFOADdGOnFobIjIuMyBxc1tgJRkLk7RlRLLbo6g=;
        b=bpPXWonXFeByn7wzgd/iwYFJOf4xo9Hw1e1/6KqpNhh/G8RUmSONpeqHqI+fEhJoWE
         e+sGA2y3DpeQboBF2XeJ1mddHZ2kt3GC1+PfZSowD+/T/88/Rbp+ZMVNLrbSl4SovvZQ
         ivWui0QooimpZ85KNGmSYF5daBd40rQk7jiyGI6G8VhzG81R/oCkL99P2xsywVa0fgJ6
         meCH2cPZJV+cJ+n33NrOcATkMcz6lenA/qwc1bivpA7L5S7IDqcYhAP4T4+MCDtOH3/V
         1PCOlhCZK1Pt3rF/mWkgXfkcVbcF3RMHOrZP+hHCmfO08KJdMb8oOQHX9XoV6FK+RFNO
         NOFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701718497; x=1702323297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aeSTvFOADdGOnFobIjIuMyBxc1tgJRkLk7RlRLLbo6g=;
        b=mTzQGNQfLqHNhEw6Fnqs/TZu/DcAFZaj4Tw28QfuMKwAa50S4+nLkH9JrdpfVOz3TA
         qMxYt5U0PKc9bG2g6K6aKPs3Va1IL4M/FZMf5PFJ/bRQ2On609VxynIfPzNNDud1t4KE
         P4LF6kPkm9Oe6KAmCR/qR0d7hTxNTR3QLZ7hMK9jFkzKXRZzWwFQ1WndPYF76pmvvWM4
         vzROKWq8/7M7Jyi1pFaQYDRzAfe4SeLXFncVuJLYFD04+YeBnu6fQcvbKHO2cuv63RUk
         mF5x57zsxEZ99yILASzsxL0F2K4xjwiooQ4mZxdeAmLLVisLCstVvNGN+je910vpnHa4
         qUgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzikAri1qwJ6sbwdc9hV5SQ7tnWYQvMejYyDrIYvJdYMbuaZpGL
	mHwX6uW2jQQDvJNdmAgzqOw=
X-Google-Smtp-Source: AGHT+IFXQ3KKHT+5bf6nzUg3+jpr9LOlFvt9KgRd73fPt43UHgtE/izjSpzwmj8gNFk9gubeIW5IsA==
X-Received: by 2002:a2e:8813:0:b0:2c9:f5ed:8034 with SMTP id x19-20020a2e8813000000b002c9f5ed8034mr1821333ljh.64.1701718495883;
        Mon, 04 Dec 2023 11:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7d3:0:b0:2b9:b171:d776 with SMTP id x19-20020a2ea7d3000000b002b9b171d776ls275435ljp.2.-pod-prod-04-eu;
 Mon, 04 Dec 2023 11:34:54 -0800 (PST)
X-Received: by 2002:a2e:3614:0:b0:2c9:f09a:4ee with SMTP id d20-20020a2e3614000000b002c9f09a04eemr1930393lja.57.1701718493865;
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701718493; cv=none;
        d=google.com; s=arc-20160816;
        b=DoIJnXGXXeUzqrvi4Ey0gsrdGAWZlfzoBHvl2xZvjKHF8YHfl3P2oUOgj2t47apk9g
         G4Oyi7rdpN1pwwiT4ndE2BkKe5rA09jkicS8lZsNAxyuT+b5MU/WKBqboomF9O43MDM1
         DuXSPNqfUaa/nBxT3gM5ufc5Qit0gzF6L1X+UqXmexjkXDYi/C7Ly55LlrH12hzvMCJg
         DAz2w5/iCuPPmB3C24Z3K6UBnobWqTwEopXD1gtXEY4U2ls7YfW5j7LVhsxPF+RtH9mD
         4eaNTvM97/r934X+1zLtuvLIsplPLptGPGt4n+xPo7CQ3qMidOo3n3IUCyUOHgU1ggzT
         Inlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=EqcJTAjZFB8lQHDKYDjIZchVKot1dBAP9whijzHZRBs=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=NcKhbYgS8zBHmseo0wAjqOOmNpsu0NKKmI+SHlXCX/ENtPFraJjfAx7YDz07m2ssvo
         D/qewriExN1nLXntsZf3gI25zhBalZ5BbU5IF6u/ympWJ2lCNRU2yzXsr0rsRhzGKlHD
         eFKJ84Egb9egRNgzJBIcO3sl0jv8CfIXPOA3nWrdjrhchJAWN6mQFXJN2Qe1Fps/K5JL
         l7fqmy5Gb5adDm2n6/vh6IMV6ncnqmuRzDW6BHLE8HnLev/Ixu/qRWHqyygdo/akmisF
         lcpPEgpYt7+BfAEhQUD9j/n5rij5PqcMKW2XkGC7+qNAmA61PwrQL4W1r+4PwrCP4ue6
         a02w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=3aoiT3pa;
       dkim=neutral (no key) header.i=@suse.cz header.b=LJvwh73C;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id v23-20020a2e9f57000000b002c9f6a36a65si268853ljk.1.2023.12.04.11.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 11:34:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8DF80220FD;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 70C1D13AC1;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KHI2G9wpbmUPMwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 04 Dec 2023 19:34:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 04 Dec 2023 20:34:40 +0100
Subject: [PATCH 1/4] mm/slub: fix bulk alloc and free stats
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231204-slub-cleanup-hooks-v1-1-88b65f7cd9d5@suse.cz>
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Flag: NO
X-Spam-Level: 
X-Spamd-Result: default: False [0.20 / 50.00];
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
	 BAYES_HAM(-0.00)[15.64%];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.20
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=3aoiT3pa;       dkim=neutral
 (no key) header.i=@suse.cz header.b=LJvwh73C;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The SLUB sysfs stats enabled CONFIG_SLUB_STATS have two deficiencies
identified wrt bulk alloc/free operations:

- Bulk allocations from cpu freelist are not counted. Add the
  ALLOC_FASTPATH counter there.

- Bulk fastpath freeing will count a list of multiple objects with a
  single FREE_FASTPATH inc. Add a stat_add() variant to count them all.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 3f8b95757106..d7b0ca6012e0 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -396,6 +396,14 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 #endif
 }
 
+static inline
+void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
+{
+#ifdef CONFIG_SLUB_STATS
+	raw_cpu_add(s->cpu_slab->stat[si], v);
+#endif
+}
+
 /*
  * The slab lists for all objects.
  */
@@ -4268,7 +4276,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 
 		local_unlock(&s->cpu_slab->lock);
 	}
-	stat(s, FREE_FASTPATH);
+	stat_add(s, FREE_FASTPATH, cnt);
 }
 #else /* CONFIG_SLUB_TINY */
 static void do_slab_free(struct kmem_cache *s,
@@ -4545,6 +4553,7 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 		c->freelist = get_freepointer(s, object);
 		p[i] = object;
 		maybe_wipe_obj_freeptr(s, p[i]);
+		stat(s, ALLOC_FASTPATH);
 	}
 	c->tid = next_tid(c->tid);
 	local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231204-slub-cleanup-hooks-v1-1-88b65f7cd9d5%40suse.cz.
