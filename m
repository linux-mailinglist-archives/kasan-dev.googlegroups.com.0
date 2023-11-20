Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRGN52VAMGQEUDVA3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 068B37F1C83
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:46 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2c87bb5a23bsf16741931fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505285; cv=pass;
        d=google.com; s=arc-20160816;
        b=J1NPQlzhEOwXw+ZdeHrSb5dz2A8enjsoakXNOimpXiAmbqCoLXRhBw5Yq7/mYO5xa/
         kcRuDGhyGI9Kw4XSm7qmJLHAfmocLtEH4X1vDJCO32Ca5CfhbHn9VY0EqBJ/mbuRNsqM
         6BNILqReLCdANMDQqj7fG6/EZ2DyrD9qCcWOpLHRkHKswlsLd+1bVEtl8VkrkzpAmTu8
         0NjH+66cCXe0+QY+usMbPudaiSWB58oas9BW1pQLGJPejjSnsTGixAdOfXKwdZIkMRaV
         5pIs0W1zFsw+anV6nmDuuepyhEBRKxhfKgmTeqok2xdwIxrEBuq3GpBSlGilEldOyabn
         1DWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=aXu4XL1aIU1+SWFpqSf6wDVdHYBazRyuu6u/GGLU3dg=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=aqAJD6t3xTeN+TZ40r3zn5d/2oM8gjZC0u6e6oasctqvJEL2lyNFAUP1//kZq/zw3R
         FeZytVjMzX30Hhp3AxVspsgyKrDc16VnksthEB9awNDCw7+fE/dy84naI4X2gOe/JYj6
         vGPqZtPZdcfPudVy9I6rDK5fh3Oumc1eXx3VcHeF/RrcDG8sxP8ksDhSBj2LA9WNm1BB
         yC7zjHgg66wMPrXGeUJLZO/9eiEMf35FZaWuEqN6AnZY+5WUopepzaTf3qfnZz4Eh0hZ
         Tzw6SnEJWivcj8wa8PP8mJB1+oGg+EoVwVa1ouMQs9AYWS6kFkJfmV/ooGfKLlqbqJOt
         VNPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=puBmaHYO;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=61j42JPK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505285; x=1701110085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aXu4XL1aIU1+SWFpqSf6wDVdHYBazRyuu6u/GGLU3dg=;
        b=slFppArwA3nJTpt9N5CUx9SkM1bjoGQmqLuwJTQHUGAB16uRTuaj9BFwsD1v43SDsm
         4LF4aosE8XEBinrTV51c04RqrgPQKPPsaD2pzKqgABR/mX07p+cBkEmNeg+1cq5eCBUC
         fVcq66FupVNClt7ErdbZNhXAXkNf9wuhp89YW0pUiKvsP2+5TJfYDSrUUejv5bT4trd3
         opHEzxIhOaEX7mV/2FCibQQUzNTVygPZQfrVeY7yNdRn8MMxuB8kGSKkrG5ny56AmwWF
         PrB24n390NhnTIr4QvWjZ69pw5uuVCh91w3cfcylBkKLdNYbulLLsUb3kXLDjBUrwSZx
         85ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505285; x=1701110085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aXu4XL1aIU1+SWFpqSf6wDVdHYBazRyuu6u/GGLU3dg=;
        b=ts4BGtPIYQiYpyxdL1c1fCKFbqxAHPv54/28+dNnTnwNdT/U8lxTr32i/N4FFdC2DO
         oTETUIJr4+SfWjlOpfUF4p3S9GAG9Ds68ectRVONXStHY2H172Q3YQslgiT8HLyJxpmb
         KjIBeTr5Jb6LBD8xwM/W0IZMmdzBZ4tGXsbEg7ec5ojG6HkrnvX3Q76ZVeYnnDy/J6dP
         hY+6+zFol3lR6h2q9VcxeilXpPHfjCimnIB2reT3UMLLoz9V/xo+A3I57GsieBLATSO/
         7ckFCQqX93uoRuK+do8wyK3UFA0us4PPnk/WxLLw854UShZvu4XBAYKdmWUPR97uzl1T
         x/RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzTJ8OKfVLU3tunLYDiouNxddq3FlVBw+6Fi81iN+T7ui6nbiAD
	zD38rBzm6JYy3Bq9W7R9iDo=
X-Google-Smtp-Source: AGHT+IFblsYDILDViC3N8yiB5qIOPI4+No0o/3YxSupg4Wn9NiLl2DUyS3cE7/X6giR07i6bOk/V9Q==
X-Received: by 2002:a2e:9782:0:b0:2c0:1fb4:446f with SMTP id y2-20020a2e9782000000b002c01fb4446fmr5061675lji.14.1700505285099;
        Mon, 20 Nov 2023 10:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1d:0:b0:2b9:631f:ac29 with SMTP id b29-20020a2ebc1d000000b002b9631fac29ls1462386ljf.1.-pod-prod-08-eu;
 Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-Received: by 2002:a2e:3006:0:b0:2c7:fa6:718c with SMTP id w6-20020a2e3006000000b002c70fa6718cmr6195540ljw.9.1700505283215;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505283; cv=none;
        d=google.com; s=arc-20160816;
        b=ClhBPiUBRf6TV23B33yg025zf/GfW7LK/vj85rt8DUzsJD+gT4p2wRAZmQmB5wATg1
         fHH8gpkUSWgnk5mP1/IfcVlFAPZeFlF5muUBbunrcflkCvMu3fWBYp6T2XKxd7nm2pfe
         nICTJdeNetqoqgF9dqr5MGR+++MjWh3rdSaDtQGWBIM1H3o6i/bWfFYSvMIn/+dJnKCB
         DfCqXKA67WbaIEHOrx6g5H0FiZOH1alO+FDsg4dDDKEBybnmojl/NlUZz6MAo0ct0obW
         D2rOjDqheFu4nURiR1l4TEA+ES0MxcyRWa2Adgsc2Tyq+gw8z9+0MomSypnchDqbr82S
         zsuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=HkihGKFc7KfRcWPJtAKuLkRXW3e6zJHroeb9H0FmoFU=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=HpR3cS0vb9aM+PxbVxk+O+9R/5pwr5Z/euhGs1bPKEDRRxSDyC4BdW8wfHEnboeG92
         t1BgkmmBdjPz1fcQVRrQ9I6YzLuoGDKq+bMizQ5d4v3jLfFnk4SuwjHzAwf8N6jqs2OF
         CO80Gn69YYKnASagvzBzN83J3IM3z+ozhGGQDyDuMwmYGPoTXK9zG5AbR5tKVtRqpNLH
         OSmEkLL0AaZdPhKEecmddh18qkY6Gi9D6gzeRj9eJpejvz5BhgvocipCioz2OCfV1W82
         gHlmJN+9VhrUG98SmWzmna7DHBAUC266aNm+whmJ33Ow2kmdHoHJRzSSo48Zwq3GXgjO
         CsIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=puBmaHYO;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=61j42JPK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id b7-20020a2e8947000000b002c50578f98fsi366323ljk.8.2023.11.20.10.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7BA801F8B0;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4A47713912;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ANuuEcKmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:42 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:24 +0100
Subject: [PATCH v2 13/21] mm/slab: move pre/post-alloc hooks from slab.h to
 slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-13-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[100.00%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=puBmaHYO;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=61j42JPK;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

We don't share the hooks between two slab implementations anymore so
they can be moved away from the header. As part of the move, also move
should_failslab() from slab_common.c as the pre_alloc hook uses it.
This means slab.h can stop including fault-inject.h and kmemleak.h.
Fix up some files that were depending on the includes transitively.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/kasan/report.c |  1 +
 mm/memcontrol.c   |  1 +
 mm/slab.h         | 72 -------------------------------------------------
 mm/slab_common.c  |  8 +-----
 mm/slub.c         | 81 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
 5 files changed, 84 insertions(+), 79 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e77facb62900..011f727bfaff 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -23,6 +23,7 @@
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/vmalloc.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
 #include <linux/sched/task_stack.h>
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 947fb50eba31..8a0603517065 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -64,6 +64,7 @@
 #include <linux/psi.h>
 #include <linux/seq_buf.h>
 #include <linux/sched/isolation.h>
+#include <linux/kmemleak.h>
 #include "internal.h"
 #include <net/sock.h>
 #include <net/ip.h>
diff --git a/mm/slab.h b/mm/slab.h
index 1ac3a2f8d4c0..65ebf86b3fe9 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -9,8 +9,6 @@
 #include <linux/kobject.h>
 #include <linux/sched/mm.h>
 #include <linux/memcontrol.h>
-#include <linux/fault-inject.h>
-#include <linux/kmemleak.h>
 #include <linux/kfence.h>
 #include <linux/kasan.h>
 
@@ -796,76 +794,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
 	return s->size;
 }
 
-static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
-						     struct list_lru *lru,
-						     struct obj_cgroup **objcgp,
-						     size_t size, gfp_t flags)
-{
-	flags &= gfp_allowed_mask;
-
-	might_alloc(flags);
-
-	if (should_failslab(s, flags))
-		return NULL;
-
-	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
-		return NULL;
-
-	return s;
-}
-
-static inline void slab_post_alloc_hook(struct kmem_cache *s,
-					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init,
-					unsigned int orig_size)
-{
-	unsigned int zero_size = s->object_size;
-	bool kasan_init = init;
-	size_t i;
-
-	flags &= gfp_allowed_mask;
-
-	/*
-	 * For kmalloc object, the allocated memory size(object_size) is likely
-	 * larger than the requested size(orig_size). If redzone check is
-	 * enabled for the extra space, don't zero it, as it will be redzoned
-	 * soon. The redzone operation for this extra space could be seen as a
-	 * replacement of current poisoning under certain debug option, and
-	 * won't break other sanity checks.
-	 */
-	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
-	    (s->flags & SLAB_KMALLOC))
-		zero_size = orig_size;
-
-	/*
-	 * When slub_debug is enabled, avoid memory initialization integrated
-	 * into KASAN and instead zero out the memory via the memset below with
-	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
-	 * cause false-positive reports. This does not lead to a performance
-	 * penalty on production builds, as slub_debug is not intended to be
-	 * enabled there.
-	 */
-	if (__slub_debug_enabled())
-		kasan_init = false;
-
-	/*
-	 * As memory initialization might be integrated into KASAN,
-	 * kasan_slab_alloc and initialization memset must be
-	 * kept together to avoid discrepancies in behavior.
-	 *
-	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
-	 */
-	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
-		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
-			memset(p[i], 0, zero_size);
-		kmemleak_alloc_recursive(p[i], s->object_size, 1,
-					 s->flags, flags);
-		kmsan_slab_alloc(s, p[i], flags);
-	}
-
-	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-}
 
 /*
  * The slab lists for all objects.
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 63b8411db7ce..bbc2e3f061f1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -21,6 +21,7 @@
 #include <linux/swiotlb.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kmemleak.h>
 #include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
@@ -1470,10 +1471,3 @@ EXPORT_TRACEPOINT_SYMBOL(kmem_cache_alloc);
 EXPORT_TRACEPOINT_SYMBOL(kfree);
 EXPORT_TRACEPOINT_SYMBOL(kmem_cache_free);
 
-int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
-{
-	if (__should_failslab(s, gfpflags))
-		return -ENOMEM;
-	return 0;
-}
-ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
diff --git a/mm/slub.c b/mm/slub.c
index 979932d046fd..9eb6508152c2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -34,6 +34,7 @@
 #include <linux/memory.h>
 #include <linux/math64.h>
 #include <linux/fault-inject.h>
+#include <linux/kmemleak.h>
 #include <linux/stacktrace.h>
 #include <linux/prefetch.h>
 #include <linux/memcontrol.h>
@@ -3494,6 +3495,86 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 			0, sizeof(void *));
 }
 
+noinline int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
+{
+	if (__should_failslab(s, gfpflags))
+		return -ENOMEM;
+	return 0;
+}
+ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
+
+static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
+						     struct list_lru *lru,
+						     struct obj_cgroup **objcgp,
+						     size_t size, gfp_t flags)
+{
+	flags &= gfp_allowed_mask;
+
+	might_alloc(flags);
+
+	if (should_failslab(s, flags))
+		return NULL;
+
+	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
+		return NULL;
+
+	return s;
+}
+
+static inline void slab_post_alloc_hook(struct kmem_cache *s,
+					struct obj_cgroup *objcg, gfp_t flags,
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
+{
+	unsigned int zero_size = s->object_size;
+	bool kasan_init = init;
+	size_t i;
+
+	flags &= gfp_allowed_mask;
+
+	/*
+	 * For kmalloc object, the allocated memory size(object_size) is likely
+	 * larger than the requested size(orig_size). If redzone check is
+	 * enabled for the extra space, don't zero it, as it will be redzoned
+	 * soon. The redzone operation for this extra space could be seen as a
+	 * replacement of current poisoning under certain debug option, and
+	 * won't break other sanity checks.
+	 */
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
+	    (s->flags & SLAB_KMALLOC))
+		zero_size = orig_size;
+
+	/*
+	 * When slub_debug is enabled, avoid memory initialization integrated
+	 * into KASAN and instead zero out the memory via the memset below with
+	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
+	 * cause false-positive reports. This does not lead to a performance
+	 * penalty on production builds, as slub_debug is not intended to be
+	 * enabled there.
+	 */
+	if (__slub_debug_enabled())
+		kasan_init = false;
+
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_alloc and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
+	 */
+	for (i = 0; i < size; i++) {
+		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		if (p[i] && init && (!kasan_init ||
+				     !kasan_has_integrated_init()))
+			memset(p[i], 0, zero_size);
+		kmemleak_alloc_recursive(p[i], s->object_size, 1,
+					 s->flags, flags);
+		kmsan_slab_alloc(s, p[i], flags);
+	}
+
+	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
+}
+
 /*
  * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
  * have the fastpath folded into their functions. So no function call

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-13-9c9c70177183%40suse.cz.
