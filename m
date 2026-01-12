Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB5BSTFQMGQEBOA7N7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F615D13907
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:28 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id a640c23a62f3a-b8012456296sf617334366b.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231048; cv=pass;
        d=google.com; s=arc-20240605;
        b=iQubiqZPorDqb/9TPCG8C50subaX6xSVle5x7rTpLHqNacECKf1UndqCTXgwELn5nU
         gqz8ZL3asv2Wi4IR0fdp3p2FWVXXxiDy2eC+Z6QSFvorFU/ICMoYiXzFpfUW8SJ2VojP
         5KiakM+x7pkctI0pBH+vIf1glronA8J60EePcRIAjt/EUTNKioE39qpCAo3yFwfkndrV
         gonRf0ryGqQiaZV3MOHx2zdsJ/oYuxkGV0WEPkerae/ES1serKrEzdbE4RCMrtRdliDd
         xhA6VS+0dWdSB195ImcwyCCsW1aBUSlqdQjC5o6u/Ft3QrfGa6HpKmlVJyngQfCsr9yq
         cTSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=+j3ZT1ug5tWAzWfXhKtAQ6hZoYL0CO1t0SK3HGsTqLw=;
        fh=8FhDDMSizDZidtSCzs+sWA+mUUfUB70aTOt2mWKlbRk=;
        b=joOegLZotM/aMgYpX+QPqAjoXRU0yFEDEVML8SAel5Ms7DEjRvZ10AIUpcb28sDRsT
         ov3UQ8snr9W9VeyqWs/QdFrrObIwBdTEh21EkMkwEjzTOIINeInfmEB0PIaERWJBvn/P
         Nr0byXH1xXdDa86hQXpNQuIZwXAJyOao4vJ+SOjEQXJymJWkqYdPVJRXKap7kFaiAUwa
         clFNLa8CZwsYBe7wuuJYJ2mUM0Qd6ZIYn3DtzIcCqg4GLqsLrLK/HtR1om4MsZqp1n3E
         8K+EYJIZOFctPSu8A1LpqSTVz7AehnMlUWMt4JTT0toW+TRnJFNrvvxkKXVaMEib4Rcn
         d2Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231048; x=1768835848; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+j3ZT1ug5tWAzWfXhKtAQ6hZoYL0CO1t0SK3HGsTqLw=;
        b=jhXMgmI4LtllhaqoSxPcUvGpCDafn9OhtOYPC0Z/BGnOtR/cuNQ8BTfNfnbVpa6tc0
         RrSwv71xuO+FjfCsGVHWIiFhwm0+2respgzWHLh10WebFVJO8LCBi8cxWktgAK8yKkmR
         vSDHeRewqFYupBf+vPyxYj+1Qivr0ILf6UfmEqGCgXGyu5W7c/cEkFrYf8Pr6WUFRMmH
         bsGAZpPuZ65XA/u4AxErqPb8ZWxj9BLauoY/GM4px/laeAS+SexZN+TW1mgi6dBMlV/X
         ZqknXga+I+PL+8T78S7W+vwHVoIU+lgXtu97eziFnixhWAiQpPQjavUqsbOolKtPkgSb
         r/ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231048; x=1768835848;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+j3ZT1ug5tWAzWfXhKtAQ6hZoYL0CO1t0SK3HGsTqLw=;
        b=M09geIW6zBmDUas4Ght8EDscYAZFwtZ3tS8bI6jeLKuZoi6gDR6H8kNd5wHT6tyuI4
         HhE/scbkeZxP5krz9iPPw/GjRfKT++FeEs0I5q2kqeo8QWsyr8qKWpt8h9Y0fqBRQrVf
         a7Vd4aAo0mtaJM/02iqptjOq1sV73Rv3DE1hLIzMfz1r8n24aCXduXopbVUTtHPhnwS1
         KH7mDY83ZD05SRQ9UckdiAHb9/bPPdacygRYpmb1AnZfpOFUqcqIkJWztj1qwvMrExP/
         n1raln9z6zPsU/63j+0zxnNbAX0zLh6AWmKm5bCtaHM8PMF1+3iy1vYbqaWV38K5v8u0
         Z7Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVtyqFQSKMTe5WX6WW4dZ/3UxUKr8+fyJD6btMINkEWcOerJV7EvJM9K4kjdMIqQL+09nqpkQ==@lfdr.de
X-Gm-Message-State: AOJu0YyCRPkDsKjq/TCB+Ctja+0ML6V/r0TqCd6LJnT8rYyh2fq1hmqb
	BnBaMHL8jkUVCwLRnt7SNdUw69mBMp2pFqSCruFaIgiDJ0qtSGAqZjOc
X-Google-Smtp-Source: AGHT+IHQdzEF0j+X4fCxRfPFvor0Cac0PCUPgv1UynYlmXhrCR4HThe9i0zf9Rcf8cPk4K/lYCXZhQ==
X-Received: by 2002:a17:907:2d09:b0:b87:2b61:b036 with SMTP id a640c23a62f3a-b872b61bbcdmr170181766b.18.1768231047686;
        Mon, 12 Jan 2026 07:17:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GLP6XH7K73UcQZdXxVu+uoIqoY2MOCid5QwN400X8B7A=="
Received: by 2002:a50:fc13:0:b0:64b:643e:9559 with SMTP id 4fb4d7f45d1cf-650748c9c1els1868412a12.1.-pod-prod-07-eu;
 Mon, 12 Jan 2026 07:17:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUq9Deb+5MBOs5zeRT/dmYODf8lAfYI0TAVZjW5HSpYdcM3AwuifkGgCcTxRFMdMQE3IpMNtXWsmeY=@googlegroups.com
X-Received: by 2002:a17:907:3d46:b0:b83:84b0:9419 with SMTP id a640c23a62f3a-b84453eb2dcmr1887742866b.46.1768231045605;
        Mon, 12 Jan 2026 07:17:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231045; cv=none;
        d=google.com; s=arc-20240605;
        b=Q/6OVOqOhfnaEW1GHQ8uevzwyzrS3sGk8B8UB5pJ616syLk4Vo8kC4AxGtP86uz5HT
         rNLlgUer26/6rVWOS/b7B+98T8D9wTaR8X2VtT4xOJnAJA0YdeqJaZHGlW2b2zsaVlLH
         5ot0NQgEKiaQvPRxgYicPoo2RARQauVFdSSyNObkWKbx3BSovsoO8psMELCJcP09QopY
         9H0Mk5j//hYTIAcz3R5GSL//Ox9Ooq+IPZvf9dr7guA7huiZO+QX6bm00JUqPbh74Cs/
         7s0pohKjcA2LJbkcTUmuHS72+2/o/qtM/iAp6q5zuU3JArGwwHf0JuGKwa9+Im2zxEXU
         tCBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=YxlYUjYZa0WGHR7EN2ESB0/g4EFEaeY6xvWmXIwfiDI=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=US9zzxvTQw8uoR6y3Il0OkJhXkrhZT5r1UCN/QQ6hKcE0aZp7so3LkH+qRwMiW3LYX
         xKED1l9zqX2gPC6Q+2NGjC1ADl5dqH+jcTZj2NtYa0VEwnyy2T5b88QMawu185ngqJmq
         KL2c37MAvOX7etrdm+bM6bpQfdQ0gLe/TeAK6bra4/DRjYW9i0WfwdMkkvUiVnXDHPth
         Od0gtOs2o2IP/vsJP1aGhNJM/E09otSD0VJVe8zuLAZwJUfcWdotncgTnOx+dvY07JRb
         H9MYkQJv5yAqWrrjr9CL8rLLlFmypz47prRcmjcqTRujpiRhEJbRGcve1oXvUSKz1fMv
         fPhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d723064si382446a12.7.2026.01.12.07.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 565575BCD7;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3AD553EA63;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8EQXDmsQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:11 +0100
Subject: [PATCH RFC v2 17/20] slab: update overview comments
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-17-98225cfb50cf@suse.cz>
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
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Queue-Id: 565575BCD7
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
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

The changes related to sheaves made the description of locking and other
details outdated. Update it to reflect current state.

Also add a new copyright line due to major changes.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 141 +++++++++++++++++++++++++++++---------------------------------
 1 file changed, 67 insertions(+), 74 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 602674d56ae6..7f675659d93b 100644
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
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-17-98225cfb50cf%40suse.cz.
