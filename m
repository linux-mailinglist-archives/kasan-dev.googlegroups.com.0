Return-Path: <kasan-dev+bncBDXYDPH3S4OBBP7G5DDQMGQEMUWGVHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1809BC018C7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:05 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-46e47d14dcesf3961175e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227584; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kj0lPxnLKfH/1iUtgQ3B3WtBJaJ1hattMnEd23yInZJuo5/UEfc+dAetMWE00MyAPa
         sg6qmMBUFl79RLzn90oKtStXSsxcCrw9hbsL1cCwK5Jt2YWP3vBzUJBT5i+T2oi74UzG
         W6ljRDl1kiSi0FAeOjCJg9Kl7mkKUJKhbLSfPzVh3UVg9Oq52CpUrWdQFWbX31P2ROCn
         VI6LZjVIhh8bv1rzbqydlLA0lazwl7VYas/1iVhvfmQk3ViIp/qwQrR0nR8Mt4kBQb0n
         wtjD2LWSJaChQZtpltM0HxeFsE8G+wBR0CEBzrknRMBZn1aI2S2hOQ1v2gGDB4JjLxiY
         XPXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=3EeC/rzOLjWJ7E8hycdTqlnNZtG16fh3KTLEPZpVTds=;
        fh=Igw0MrOqbmL0zZGMcmovdbOn54G2EXQ31XJ/+DFer2g=;
        b=hobiLiV9eFmYnWrJOc/xQCEqTsQqSJNLZckZHXHl++/QbBAPYDjzvvx91RLBuZjUYF
         j4YtMBsSh3l3zkvZFghU9W+mYPSA01mAxJ61AnW978uJ6IdCAohy2oBEfVx8E0CyOwov
         RxFee7GCp59LBl5BDACETxp2+BSL7hIue/bm+NGhmIvL26pP8s3y5JKUVpHKwYf2LNry
         hul07Rzp7f39dlOhagKsPCi52j9kZCy+YBCyU5EU3K4ztkTlMlR6OThYCKVtsaWYzoYY
         QUBjO6ubyD/aJcyNxhLMHnxiq7wJD8ICQTBhpk/92o1vvuiJy1xlqrIJgZecOf4bZHhk
         oPfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ijZFYtF7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=O22eaDaE;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="zQ/9KIKM";
       dkim=neutral (no key) header.i=@suse.cz header.b=GVJOpUcu;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227584; x=1761832384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3EeC/rzOLjWJ7E8hycdTqlnNZtG16fh3KTLEPZpVTds=;
        b=cv7sKI1cYyLOknn1WQL5zrGB75CKn+8HUe/bFKscTEJfwSSwbzXFUERczjxeFWhPMv
         ZRwmBz7CkVreTbzltwFq9t7vh1H3IHbisAymJB4wSl2EqlQTuGuXIulBQC+hL2b3OcVu
         H6kdheBjuYJ+nR38qmrB3PUclCMgDAnkhYBuUlMPtnwi79CGte0+xCSX03O80Fkwswx+
         kfgsMSOeLPMI/PfdRecRBeTczqiMrKCsLDNeZF4KSAz8yVCK2N/SllBw/0EeiKp5Bx9j
         JktuPUBkiYukT9htpDBCQKzYf3b8qVoI4t9cIhd0NU8i4GN8oiYTEILxwNgdTl8rjeOm
         NWmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227584; x=1761832384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3EeC/rzOLjWJ7E8hycdTqlnNZtG16fh3KTLEPZpVTds=;
        b=SyUUFsk9QDUG7UPwbF3DIBtZekysyKJA99NLjHdhd9wpEvRj5fj5EHzzTCcsgEP40N
         gj77CC1XiG7XPnpETBf6VbsQwekWjP4mdb72i6+d9WthtYEfzwzGwo4V1f2G/BUMb7hY
         7U/r1K0CjmwQjM1+syCsL56q4DUphbSRZZYisD27ZyjEkK6bsRVXgIycMedfd+JJpbE1
         BEZulLlsiB+M9NkBFVA95/w8b1hHRRjgDA/87no0dr7618dXcQPVnyTN+EBnvf3TEPUk
         oDjli6++Ei9N7SnXoVFmeURSx1riNJeWECrKbHOC+EmKkXtkVuoKVeiSCxxgPSa2TyU8
         sjeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGc7YDg5KZ6QDi2nMpgljuuC5A/gJOx4GklP7+0zK0l4iG2OKF0Za5gdmixiWj87+kKrXF3w==@lfdr.de
X-Gm-Message-State: AOJu0YxYGuGh9ffkcR4QB/ShwCyX6eeDhMCRHyVTh+4KXdYyKRUuRO3o
	hE5TyBuhoYotcturTcoTw+3f1rznFaHjGwb4wt0Huup+VvQRk6YIaKDH
X-Google-Smtp-Source: AGHT+IG0kIB6SoK6KBU6hSbGSdxK3dhOZyfJmdsJjLVmxU2J32gcj207pfXosQn8Bc9O2qRWwTraZg==
X-Received: by 2002:a05:600c:6092:b0:45d:f88f:9304 with SMTP id 5b1f17b1804b1-475cb0450c2mr19143925e9.30.1761227584532;
        Thu, 23 Oct 2025 06:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7t57Ii6VdffLelOJ7sOYPYaNcLcPJoEqCLAQ0CPPNd+w=="
Received: by 2002:a05:600c:5951:b0:471:a42:614c with SMTP id
 5b1f17b1804b1-475caa6d90bls3695505e9.1.-pod-prod-01-eu; Thu, 23 Oct 2025
 06:53:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZyG6lhaLcPWkZRqhzqbeO8SHgbJuYWMLceAQm5f7zF1YIKPpbRgqJYZkbF7qHyv6Vdmnqtrp+D9o=@googlegroups.com
X-Received: by 2002:a05:600c:1908:b0:468:7a5a:1494 with SMTP id 5b1f17b1804b1-475caf930f8mr15990925e9.1.1761227581819;
        Thu, 23 Oct 2025 06:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227581; cv=none;
        d=google.com; s=arc-20240605;
        b=C6sXKDBZvjPgpJYIbHCj8MMLyM2ITQwgVDxJPtPGQFsaVI9xSDqzU8e8Vk3XPYjmNn
         nfU0LmrM1Dkl+eBO1QG1BsQ5IcrLbvCkBfBHcWw6pXQvzUoNIEluQy9SuEtf/aMxv65h
         EVtWCmu7IipwmiTftxdveGxuu03uG4gkz7uCP9Dd0+VdvHpcMNITfMsPHUtptPnvffCE
         7SQKtETXsBtclFOrWHTFEx48WILVNaRryzSqE7cQfKnnUhEFAlv8CF7ZqCXvpo+MjEol
         ImD3Ch1oBHCdNTqRegqSIoXy0gswUjpDnT/V4zvLQrLvqy0v3lKIytLWTPp9/5EvyxY+
         n37Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=lCq3wXn+tApmnVAfVNMGfQ1nbGBWrxbHUQ3MPoNIz/8=;
        fh=sn5LZh+L0Rfa+joht6VqgjJVwsYeldC59hPTZcGo6Vo=;
        b=Zom0IgpDdMy8P2pEzZm20Eek92ZyRGiPyQGrVz9ot4tdvwUrAgjbmEae8OFrBMcUkH
         MRGAUTIYX7BrMgarFEc6YvdLwPCqFN1wPdBJ2zOGByw4wwgFsYFe/yzL6fXtdWtHuvNU
         zjTCwO0vxRzNT4k2obqrGfbC2mXRySMNruGHg7H2XBoOq0ka99NW6ZDjHYcoNHDWvF88
         vDg6VjzBqOp9B5UOpBU9/F9hqL4xdzF4Ra8sY4hoYal+tDkwfgr11QuJKjjEe4GFka9t
         Gqvno50fcJ7PwAposxa6X8lBLXTNxypjZP1HLvKeJ4gGe5o61n2Im+LYIrOLBOZzMgvv
         5BuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ijZFYtF7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=O22eaDaE;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="zQ/9KIKM";
       dkim=neutral (no key) header.i=@suse.cz header.b=GVJOpUcu;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-474949df472si1288275e9.0.2025.10.23.06.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1401F211FA;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E7217136CF;
	Thu, 23 Oct 2025 13:52:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ANIIODQz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH RFC 00/19] slab: replace cpu (partial) slabs with sheaves
Date: Thu, 23 Oct 2025 15:52:22 +0200
Message-Id: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIABYz+mgC/6tWKk4tykwtVrJSqFYqSi3LLM7MzwNyDHUUlJIzE
 vPSU3UzU4B8JSMDI1NDAwMj3eKM1MSy1GLdtPwi3cScHF0Ls8RkQ+OUZBPzRFMloK6CotS0zAq
 widFKQW7OSrG1tQCIPxapZgAAAA==
X-Change-ID: 20251002-sheaves-for-all-86ac13dc47a5
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
 Vlastimil Babka <vbabka@suse.cz>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCPT_COUNT_TWELVE(0.00)[19];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ijZFYtF7;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=O22eaDaE;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="zQ/9KIKM";
       dkim=neutral (no key) header.i=@suse.cz header.b=GVJOpUcu;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Percpu sheaves caching was introduced as opt-in but the goal was to
eventually move all caches to them. This is the next step, enabling
sheaves for all caches (except the two bootstrap ones) and then removing
the per cpu (partial) slabs and lots of associated code.

Besides (hopefully) improved performance, this removes the rather
complicated code related to the lockless fastpaths (using
this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
kmalloc_nolock().

The lockless slab freelist+counters update operation using
try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
without repeating the "alien" array flushing of SLUB, and to allow
flushing objects from sheaves to slabs mostly without the node
list_lock.

This is the first RFC to get feedback. Biggest TODOs are:

- cleanup of stat counters to fit the new scheme
- integration of rcu sheaves handling with kfree_rcu batching
- performance evaluation

Git branch: https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=b4/sheaves-for-all

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
Vlastimil Babka (19):
      slab: move kfence_alloc() out of internal bulk alloc
      slab: handle pfmemalloc slabs properly with sheaves
      slub: remove CONFIG_SLUB_TINY specific code paths
      slab: prevent recursive kmalloc() in alloc_empty_sheaf()
      slab: add sheaves to most caches
      slab: introduce percpu sheaves bootstrap
      slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
      slab: handle kmalloc sheaves bootstrap
      slab: add optimized sheaf refill from partial list
      slab: remove cpu (partial) slabs usage from allocation paths
      slab: remove SLUB_CPU_PARTIAL
      slab: remove the do_slab_free() fastpath
      slab: remove defer_deactivate_slab()
      slab: simplify kmalloc_nolock()
      slab: remove struct kmem_cache_cpu
      slab: remove unused PREEMPT_RT specific macros
      slab: refill sheaves from all nodes
      slab: update overview comments
      slab: remove frozen slab checks from __slab_free()

 include/linux/gfp_types.h |    6 -
 include/linux/slab.h      |    6 -
 mm/Kconfig                |   11 -
 mm/internal.h             |    1 +
 mm/page_alloc.c           |    5 +
 mm/slab.h                 |   47 +-
 mm/slub.c                 | 2601 ++++++++++++++++-----------------------------
 7 files changed, 915 insertions(+), 1762 deletions(-)
---
base-commit: 7b34bb10d15c412cdce0a1ea3b5701888b885673
change-id: 20251002-sheaves-for-all-86ac13dc47a5

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-0-6ffa2c9941c0%40suse.cz.
