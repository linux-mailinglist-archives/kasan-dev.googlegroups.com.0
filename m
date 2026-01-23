Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5FVZTFQMGQE4TRTCKY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id iCgtLPUac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB5FVZTFQMGQE4TRTCKY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:41 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 739D17133F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:41 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-42fd46385c0sf1123957f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151221; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJFgjX5E6PFYN7LnuRjTYRhVdJE2A8nI30Hs+9dDcnxnh6wO7HM3ir4L27IX1wILhw
         UtlsX1I3dZH3uo4NItP/4TUVh3KcFD8RvCi5w/h/K5cGO+CDC7OipIcoIXo+Li1eEdNO
         CFCSc3dsEzwx5GgyTK6Gdkgb27p4NZvGRGZ3kvdRkrbdYT+w0aPwuA+zFb0iqAedksY5
         b8qGTUiKK/Dkf6YhPah2rwhN20dLNQ/ao4qWKgQWqiufL4e4U63xPAiPWiT+1AhM8QWV
         bjImpbmF4WBel68n6PyDO0eZk/XgbiZb95zBF+NCXId7NIMaZmSiX6FhRN9AyVjNvwoh
         hSqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=gN8QAtqQy5lmDjCMvZctR9RjFTA0aKzH59YQy+2m/U4=;
        fh=qTiUpP/1sqpTuxrw8ISahEIw/0feJCEjVnLOJSHStow=;
        b=QPiHOVUB9eTrDa2uyA5MKImOpt5zSO3/m+6uuSvM+WB+LHbsCzQbqPMfyRxSklXHsA
         Nd/UGUfQLDmrNjtpEh0PpMZYXafvywnFNjeQ1U53ZYZw35xLVE5DBjKRAtELPnBeLGLA
         ddsRy+LCktPHNFS0+xwLj1vsMcOEbwdZXtwUzuVziW1YYa4Vx0jzahdYb/2bC8wP89IK
         Xd5IJ9yRujLE4lKvChaybCXCYGFFvf4vMoUKjms7E2yJ0ZjfsaC+61oGBOML/V/qkGLI
         bZhPiNVcAuKvCbBzGK12udalZQKxEXKZKbbAFGGb3s4FFubSBF3TN4du0+Ph6fsSmUBT
         UZ/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151221; x=1769756021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gN8QAtqQy5lmDjCMvZctR9RjFTA0aKzH59YQy+2m/U4=;
        b=duIPI0UWSof5viSFt0ScR4HuvtazC6g/2PPlUWRd9zNfZ5rmU45u5PPRnOVKO+ZzHn
         cVd4U29bwqQ0xxwXOD1hDIyBexQRCnjP78MRDH3lQGLhnPCrhr6PKmL9/vJN9ipwnww6
         RJgZJAdfAa+i09ShVvodYTaxUSwjR/UeEKLG9FbkxAo1Q+RZBlRhS/w7Bkbe43LBBZWO
         O1cQ9+2RHzzG++1iy5rzzNPoL4bt8um1fxkM99CyavOgMls2NXgYSyRoymKpjtvFZVUF
         VuAF60S5U9ojewpNQ6v3rJWOE1BtscIj8qoUMSNxyOBXkdQvPftI3ALYOy5lBmxyyBxJ
         G3MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151221; x=1769756021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gN8QAtqQy5lmDjCMvZctR9RjFTA0aKzH59YQy+2m/U4=;
        b=mGnyuOZhMvA4HwnNttVPBLFHQUh20qtM3gnPW8ua+adCfEKxgcks0QQEJjIXhMj8R5
         3NfCUITT32wh1gS849ou6xOl0F18ZpNJU23Z9glyDpEDLvwTBOCV75tLdwwndMRJ2lPY
         bPmIwE8N4faST027dYpVcyZs4hdsntPRRzW/uQYfl+oCU4ntxFnXK2M9Pumv4nMfKlUt
         /vmohR2DZDS+FCyVc2rl9F0OlDHALGdbWRIteUiWw1xOE3AwclnfrwOV5rMs+tB+eeEj
         SLkeSmluM+R0kW4ZlOOYHVe9D8CmBRg7Wmz7hqiKVv2N8k+p/s9FYcQz+ZHQrmsmxwz/
         yDHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmDHozkaWZANFdx6bIrNUdAG7/bNSB+rECsnDLNMkNRafPITieWfjpNGVqkmpTSRL6ehKLeA==@lfdr.de
X-Gm-Message-State: AOJu0Ywzlu4f+Hcob5kxi+PFUk5Y+yOQlYM9EoTZl/CMhXYmxK9wnMG/
	Kn+Q5oyrD3W/3wOUliyQmZgQnt6Msvd4QagxRhvoltbMbI/PKAfxBCuY
X-Received: by 2002:a05:6000:612:b0:435:8fd6:5949 with SMTP id ffacd0b85a97d-435b966a5aemr495039f8f.46.1769151220672;
        Thu, 22 Jan 2026 22:53:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FmKvUyU787FeBvRynalQ+W1a3vR8y1vcvzcjVIl8pwwg=="
Received: by 2002:a5d:5d0b:0:b0:3fc:116b:d99b with SMTP id ffacd0b85a97d-435a668bb6bls1069789f8f.2.-pod-prod-01-eu;
 Thu, 22 Jan 2026 22:53:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9qB/Gmm/jQqMC3mpHF0Vi6jct+YFP3uch5K1SsYILXyUuWuFpIDD49a3+9/16E5dbHSjnzf4g6FA=@googlegroups.com
X-Received: by 2002:a05:6000:1ac6:b0:435:9241:37c2 with SMTP id ffacd0b85a97d-435b92f81acmr382623f8f.9.1769151218488;
        Thu, 22 Jan 2026 22:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151218; cv=none;
        d=google.com; s=arc-20240605;
        b=kYZxU2VT280sLPN5XCjIXxYBr5V8keQLgpHg7kwTkgTXgZ/pxV+F/kza8PqX01KbwX
         DOY+XL+cGypGBM13lE3MFT5cddzRQuZQssNC/C6OhZ5IAXHhQue8AmWMXvYKWoBPDNYB
         aZU4a3XBE0laZs7NTQ0TYlzmeHrJSyKV6qzkFoMyKI07YgOSLCWL1ymoQjkmcl1jsw3E
         sTLrbCWSleH+rc4bAAnGHqZCmEDLkyCGvbnOAJU01ON1HmLYP+UImTVspfB2V8ZRpEqT
         xnuUbYTN5sjwbKP6370RItD2D54JeqO4JnOBFWMslFpG9hks/j0upsqMRURpN1NhDcKn
         t/Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=Z7Imrx2RQafs2CP6MR8fcwa6W5Q5qaE5LnHmXENECaQ=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=K1I+Y2sqe6+nTGz9C1pVGp/gHFZhCc6rb4TGn8ROR6arYNB2o7r4/2sIzA3fzO64Mg
         /mKAq/OA9qhvBralZ7pwn4YXUCXWAc7yX8cZ1yS5WYUY1AGgHgZhlh4S65lfgOOb6CCk
         GLkjGKupYbL1wJVkqQZPAUCu16iiQZ97hfAFmbKEeoLFINKqBIoRyjFl7AbUp+Ksa1j6
         87eErQwALM8HoWZzvLx1YUekQuvwYzlrItrSRXWmO0NsB4HHDVbZk2WJ34Rja0EuehIb
         +5iydPGytl+3MxioDT6xA6ZrIxMGrzbX3Bbxb7xfA7zJqsDh9BiRZdjmkhzBOyCoLHPd
         UOHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1bfa5easi36183f8f.2.2026.01.22.22.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 44A415BCD6;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1F91B139E8;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id kNVqB9cac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:57 +0100
Subject: [PATCH v4 19/22] slab: update overview comments
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-19-041323d506f7@suse.cz>
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
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB5FVZTFQMGQE4TRTCKY];
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
	NEURAL_HAM(-0.00)[-0.983];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-wr1-x437.google.com:helo,mail-wr1-x437.google.com:rdns]
X-Rspamd-Queue-Id: 739D17133F
X-Rspamd-Action: no action

The changes related to sheaves made the description of locking and other
details outdated. Update it to reflect current state.

Also add a new copyright line due to major changes.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 141 +++++++++++++++++++++++++++++---------------------------------
 1 file changed, 67 insertions(+), 74 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 540e3c641d1e..d9fc56122975 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1,13 +1,15 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * SLUB: A slab allocator that limits cache line use instead of queuing
- * objects in per cpu and per node lists.
+ * SLUB: A slab allocator with low overhead percpu array caches and mostly
+ * lockless freeing of objects to slabs in the slowpath.
  *
- * The allocator synchronizes using per slab locks or atomic operations
- * and only uses a centralized lock to manage a pool of partial slabs.
+ * The allocator synchronizes using spin_trylock for percpu arrays in the
+ * fastpath, and cmpxchg_double (or bit spinlock) for slowpath freeing.
+ * Uses a centralized lock to manage a pool of partial slabs.
  *
  * (C) 2007 SGI, Christoph Lameter
  * (C) 2011 Linux Foundation, Christoph Lameter
+ * (C) 2025 SUSE, Vlastimil Babka
  */
 
 #include <linux/mm.h>
@@ -53,11 +55,13 @@
 
 /*
  * Lock order:
- *   1. slab_mutex (Global Mutex)
- *   2. node->list_lock (Spinlock)
- *   3. kmem_cache->cpu_slab->lock (Local lock)
- *   4. slab_lock(slab) (Only on some arches)
- *   5. object_map_lock (Only for debugging)
+ *   0.  cpu_hotplug_lock
+ *   1.  slab_mutex (Global Mutex)
+ *   2a. kmem_cache->cpu_sheaves->lock (Local trylock)
+ *   2b. node->barn->lock (Spinlock)
+ *   2c. node->list_lock (Spinlock)
+ *   3.  slab_lock(slab) (Only on some arches)
+ *   4.  object_map_lock (Only for debugging)
  *
  *   slab_mutex
  *
@@ -78,31 +82,38 @@
  *	C. slab->objects	-> Number of objects in slab
  *	D. slab->frozen		-> frozen state
  *
- *   Frozen slabs
+ *   SL_partial slabs
+ *
+ *   Slabs on node partial list have at least one free object. A limited number
+ *   of slabs on the list can be fully free (slab->inuse == 0), until we start
+ *   discarding them. These slabs are marked with SL_partial, and the flag is
+ *   cleared while removing them, usually to grab their freelist afterwards.
+ *   This clearing also exempts them from list management. Please see
+ *   __slab_free() for more details.
  *
- *   If a slab is frozen then it is exempt from list management. It is
- *   the cpu slab which is actively allocated from by the processor that
- *   froze it and it is not on any list. The processor that froze the
- *   slab is the one who can perform list operations on the slab. Other
- *   processors may put objects onto the freelist but the processor that
- *   froze the slab is the only one that can retrieve the objects from the
- *   slab's freelist.
+ *   Full slabs
  *
- *   CPU partial slabs
+ *   For caches without debugging enabled, full slabs (slab->inuse ==
+ *   slab->objects and slab->freelist == NULL) are not placed on any list.
+ *   The __slab_free() freeing the first object from such a slab will place
+ *   it on the partial list. Caches with debugging enabled place such slab
+ *   on the full list and use different allocation and freeing paths.
+ *
+ *   Frozen slabs
  *
- *   The partially empty slabs cached on the CPU partial list are used
- *   for performance reasons, which speeds up the allocation process.
- *   These slabs are not frozen, but are also exempt from list management,
- *   by clearing the SL_partial flag when moving out of the node
- *   partial list. Please see __slab_free() for more details.
+ *   If a slab is frozen then it is exempt from list management. It is used to
+ *   indicate a slab that has failed consistency checks and thus cannot be
+ *   allocated from anymore - it is also marked as full. Any previously
+ *   allocated objects will be simply leaked upon freeing instead of attempting
+ *   to modify the potentially corrupted freelist and metadata.
  *
  *   To sum up, the current scheme is:
- *   - node partial slab: SL_partial && !frozen
- *   - cpu partial slab: !SL_partial && !frozen
- *   - cpu slab: !SL_partial && frozen
- *   - full slab: !SL_partial && !frozen
+ *   - node partial slab:            SL_partial && !full && !frozen
+ *   - taken off partial list:      !SL_partial && !full && !frozen
+ *   - full slab, not on any list:  !SL_partial &&  full && !frozen
+ *   - frozen due to inconsistency: !SL_partial &&  full &&  frozen
  *
- *   list_lock
+ *   node->list_lock (spinlock)
  *
  *   The list_lock protects the partial and full list on each node and
  *   the partial slab counter. If taken then no new slabs may be added or
@@ -112,47 +123,46 @@
  *
  *   The list_lock is a centralized lock and thus we avoid taking it as
  *   much as possible. As long as SLUB does not have to handle partial
- *   slabs, operations can continue without any centralized lock. F.e.
- *   allocating a long series of objects that fill up slabs does not require
- *   the list lock.
+ *   slabs, operations can continue without any centralized lock.
  *
  *   For debug caches, all allocations are forced to go through a list_lock
  *   protected region to serialize against concurrent validation.
  *
- *   cpu_slab->lock local lock
+ *   cpu_sheaves->lock (local_trylock)
  *
- *   This locks protect slowpath manipulation of all kmem_cache_cpu fields
- *   except the stat counters. This is a percpu structure manipulated only by
- *   the local cpu, so the lock protects against being preempted or interrupted
- *   by an irq. Fast path operations rely on lockless operations instead.
+ *   This lock protects fastpath operations on the percpu sheaves. On !RT it
+ *   only disables preemption and does no atomic operations. As long as the main
+ *   or spare sheaf can handle the allocation or free, there is no other
+ *   overhead.
  *
- *   On PREEMPT_RT, the local lock neither disables interrupts nor preemption
- *   which means the lockless fastpath cannot be used as it might interfere with
- *   an in-progress slow path operations. In this case the local lock is always
- *   taken but it still utilizes the freelist for the common operations.
+ *   node->barn->lock (spinlock)
  *
- *   lockless fastpaths
+ *   This lock protects the operations on per-NUMA-node barn. It can quickly
+ *   serve an empty or full sheaf if available, and avoid more expensive refill
+ *   or flush operation.
  *
- *   The fast path allocation (slab_alloc_node()) and freeing (do_slab_free())
- *   are fully lockless when satisfied from the percpu slab (and when
- *   cmpxchg_double is possible to use, otherwise slab_lock is taken).
- *   They also don't disable preemption or migration or irqs. They rely on
- *   the transaction id (tid) field to detect being preempted or moved to
- *   another cpu.
+ *   Lockless freeing
+ *
+ *   Objects may have to be freed to their slabs when they are from a remote
+ *   node (where we want to avoid filling local sheaves with remote objects)
+ *   or when there are too many full sheaves. On architectures supporting
+ *   cmpxchg_double this is done by a lockless update of slab's freelist and
+ *   counters, otherwise slab_lock is taken. This only needs to take the
+ *   list_lock if it's a first free to a full slab, or when a slab becomes empty
+ *   after the free.
  *
  *   irq, preemption, migration considerations
  *
- *   Interrupts are disabled as part of list_lock or local_lock operations, or
+ *   Interrupts are disabled as part of list_lock or barn lock operations, or
  *   around the slab_lock operation, in order to make the slab allocator safe
  *   to use in the context of an irq.
+ *   Preemption is disabled as part of local_trylock operations.
+ *   kmalloc_nolock() and kfree_nolock() are safe in NMI context but see
+ *   their limitations.
  *
- *   In addition, preemption (or migration on PREEMPT_RT) is disabled in the
- *   allocation slowpath, bulk allocation, and put_cpu_partial(), so that the
- *   local cpu doesn't change in the process and e.g. the kmem_cache_cpu pointer
- *   doesn't have to be revalidated in each section protected by the local lock.
- *
- * SLUB assigns one slab for allocation to each processor.
- * Allocations only occur from these slabs called cpu slabs.
+ * SLUB assigns two object arrays called sheaves for caching allocations and
+ * frees on each cpu, with a NUMA node shared barn for balancing between cpus.
+ * Allocations and frees are primarily served from these sheaves.
  *
  * Slabs with free elements are kept on a partial list and during regular
  * operations no list for full slabs is used. If an object in a full slab is
@@ -160,25 +170,8 @@
  * We track full slabs for debugging purposes though because otherwise we
  * cannot scan all objects.
  *
- * Slabs are freed when they become empty. Teardown and setup is
- * minimal so we rely on the page allocators per cpu caches for
- * fast frees and allocs.
- *
- * slab->frozen		The slab is frozen and exempt from list processing.
- * 			This means that the slab is dedicated to a purpose
- * 			such as satisfying allocations for a specific
- * 			processor. Objects may be freed in the slab while
- * 			it is frozen but slab_free will then skip the usual
- * 			list operations. It is up to the processor holding
- * 			the slab to integrate the slab into the slab lists
- * 			when the slab is no longer needed.
- *
- * 			One use of this flag is to mark slabs that are
- * 			used for allocations. Then such a slab becomes a cpu
- * 			slab. The cpu slab may be equipped with an additional
- * 			freelist that allows lockless access to
- * 			free objects in addition to the regular freelist
- * 			that requires the slab lock.
+ * Slabs are freed when they become empty. Teardown and setup is minimal so we
+ * rely on the page allocators per cpu caches for fast frees and allocs.
  *
  * SLAB_DEBUG_FLAGS	Slab requires special handling due to debug
  * 			options set. This moves	slab handling out of

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-19-041323d506f7%40suse.cz.
