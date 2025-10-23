Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWHG5DDQMGQEXEJEV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E51BC018FD
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:29 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-471001b980esf9100485e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227609; cv=pass;
        d=google.com; s=arc-20240605;
        b=UU+klBj+wIAaUqNXSoJtRQSY4VeBaVp014Y+l2CzA7pBT8kn6j8dCagodlzh4xgF8o
         A8rPW+mq52wSP5FpjYmFf3nPfYCeI2d5/QLVrSInrtZcH9Swu2yT5Q0Q+GA940/Qm7zY
         Vg9ZwMRdUWYKYI8fktiyO5+4loiegiESmvfJSqTDcq3i09yCgsIJvi8rAgOuOR0nJ3LG
         LPZEAesuTL7Tnutdcl45/YQvT4AuheamooLTfErufj3QBL9YuHrWq365djRUwonFL55N
         u/8POolp1s/ruqMrsaoB+3cD/1TWoZVKFyiXW76ZixpWfChsMtOK3KobyXk6Ep3A45Jn
         VFmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=GnqwIlIEgpfAEcdYxgdyq3YX5ExZ8Pzo/HFvBW5WYlA=;
        fh=12pm+m0eu2HBM5aGO8J1dQN5Gy50w1zyk7BGAJn+T/c=;
        b=UoT0yuOd/6T0QWDwhBIPQGho972VptzquqZTwOCOAcym0dPNpAJRfcg3riYIBq0YTi
         2oyWwU52bc8b/T5Lx6ZehyK7BY7z9D3ebhwmZmwXWL1PTCQKFwZsX0Sj9MAgpBNa5FbT
         5Jnm8z2unZMCxXU/7Tc8ORnYApQbjqNuy3jt7GrooSyAKf+xOeUdl4haEzrtB64k4BN0
         JEvy3KOQYK74dmLLQFM54BMtqwcWeNgcFMdimZ7Ti84mI/p0ZcpDRQAV3VCBb7nmJdcd
         3o+FnGCQm+FKYa+7EnrC9ZKsyeBMNlFaCrv6XN3RgHIyPrQ7aj8mLdH2bBSRwHvSD8+2
         Wvrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227609; x=1761832409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GnqwIlIEgpfAEcdYxgdyq3YX5ExZ8Pzo/HFvBW5WYlA=;
        b=s8sGSscHghAlVIjQCea9741DkiTIDUgzKiTQU6DGM4RQXz+mdtB672Rm6/jEv6mffo
         grsTGKahBvvNyEQGUr62V2QIK5W5GuqontbVmVSrJZBPT/rfundnDegTMEiTBkgQaTSi
         68d2z0hS+WvO5PyFEAbXwCj9UZVG0/szvJigKZoTqb6etfjz5wUe+fzUeeFYIYj9C21O
         YyAXXfyhWFuGCqdcsetOWARNg3P5fqe/3AujyENeU8M4rKg2fxD3icQ/WARE6gZY1Ni+
         l4W2RITBareVustAwy2z343eLkScFoJvTq0sC3WrLwx8t3HsXPna8x1HlEY8YxYpAI2A
         KTsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227609; x=1761832409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GnqwIlIEgpfAEcdYxgdyq3YX5ExZ8Pzo/HFvBW5WYlA=;
        b=jIPEyaOYyI0wKIV3yjpd/4l4KCarY/7p9HOxdMuWdp0SACyUD0WARVYaexWrZJ5RsA
         lKdtyy1FTF0FN9owxcGzi7ZjZEJUOpEp7jx90BbZdjGPTm14hDVYfE9tNMnxFGN92A5z
         mJiDVoZEcEtd44FD/2ruZuxuKIqMwG59b/ybPprbseB+13q6lsGBu4k7ZxdUFf0crT3O
         OR1utmrYsSsfYLVHCN7OnPinrAnxEP/M4hnWZEf/5QAHA8D3V+S7Qwm8eNsGPH9oVlIW
         LEAdoUSBRc0qv/AcSySh7F+Bu15pDzMGixKk+ZE4kHhpiKbgqZyQBrcyN3kj6kjA9xDs
         fUEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDYSjQ5wuI992bIts1uACe+l8KTzp80icuM/haNGqXqUet9StBHnSdUNAcBhtlSVy68amIvA==@lfdr.de
X-Gm-Message-State: AOJu0YwYeQ8T1XMgatCIsm/y7roO31BB9z6B+dhS5I/BdHawggAm7xGG
	nbYnv5/KmiBW1pFpm0g8oFz9LJLbNiR22yX8W0Brxgmx/URPtqp+JPne
X-Google-Smtp-Source: AGHT+IEbfOeIT7tQj1rcj3W2rRIqi8IhLmW2DFLmULDKQvA9FXhf/h4n3puiEtvhwXqXa3istjEVbg==
X-Received: by 2002:a05:600c:548c:b0:471:16e6:8e60 with SMTP id 5b1f17b1804b1-471177c0948mr168755215e9.0.1761227608831;
        Thu, 23 Oct 2025 06:53:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5dIB3j9XSBKTbudcHFvoInUk43LM681uw6GI/g7NA1HQ=="
Received: by 2002:a05:600c:8a1b:20b0:46f:c75d:6695 with SMTP id
 5b1f17b1804b1-475caaa02acls3976855e9.2.-pod-prod-04-eu; Thu, 23 Oct 2025
 06:53:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuGTPUwojy0Qwah+u9gV3ernfKxnIrVzs8KUNd9DTl0M642aBVnzdvhKHFTQNmgwffjB/WsyHzqko=@googlegroups.com
X-Received: by 2002:a05:600c:3e17:b0:46f:c576:189a with SMTP id 5b1f17b1804b1-4711791c3c3mr194602595e9.29.1761227606113;
        Thu, 23 Oct 2025 06:53:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227606; cv=none;
        d=google.com; s=arc-20240605;
        b=UEeh//htP6E6L1GAaFkPrwp6BM8xl1vWGpXvFR7P2yXgeM6kvqsbumyrviJ5deLzEC
         WjZHxin15tLBIFpU/pH3MQ9nZP07RSZI6ru3dcuDHZ0GeaNoyhOMlp/fQoTYFV7W1qg1
         xpBsqz1JncrfQrHLuQhQIyJSkSwXzJkpQCUq8K9ZeRFAEUIQBnECuMdD3H9K7JX5lJ7M
         tNvYjG5h6eN1PbCWaPYwapBKC2ii6+8U6XBWZfbNJauj+aAV78j70mMSATSfLPl/W3cg
         u/IruMVmnHTcoCnFTUfB9DunZberq+ZqOsEHFa1TDV+Tt1AzSJ8o5Ktk5fR9ymJ8EwBH
         1u/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=jcT7k4ASuUNua7Fb7j44LhUIoyM1dwJwFvhsotHWEtY=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=J+rYTRIXo+NPQAdlFtUatS5zomOcMoU3E3YbT/fEw3ugEmA/DalrfJF4SBprPAE3uU
         5S/b5p6UiRyWbu6kXVBjBHsKFg8JFpLjpXpOZP3lVbELNc6a9NbKwamysuTPP+V2jAWU
         ZDnnnPIZRU/LYi5C0eeYorRLa3iOiOUHDCwWJTOtHOAznB8ztrRczotf589fFS5o4nQ/
         KHGKOxWrepsE/XsRkg7nYJnjZFvW1gyWdrW4Ccyb5I58g5A1oFQbJKmfDCYeK4sQuL09
         F+lFaGZRuJShTu0uWGgaUbpY/B5tUSetiH+/5+WT5aQssIY/MNG+sIC/s5l6CNVDNByX
         /R4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47496b28e1esi1771315e9.2.2025.10.23.06.53.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B398F1F7CF;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D6F6F13B10;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oDUPNDYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:40 +0200
Subject: [PATCH RFC 18/19] slab: update overview comments
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-18-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
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
X-Rspamd-Queue-Id: B398F1F7CF
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

The changes related to sheaves made the description of locking and other
details outdated. Update it to reflect current state.

Also add a new copyright line due to major changes.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 141 +++++++++++++++++++++++++++++---------------------------------
 1 file changed, 67 insertions(+), 74 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 4e003493ba60..515a2b59cb52 100644
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
+ *   list_lock if it's a first free to a full slab, or when there are too many
+ *   fully free slabs and some need to be discarded.
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
+ * SLUB assigns two object arrays called sheaves for caching allocation and
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
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-18-6ffa2c9941c0%40suse.cz.
