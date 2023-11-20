Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRGN52VAMGQEUDVA3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DFB07F1C7D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:45 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4095fcbba0asf15219835e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505284; cv=pass;
        d=google.com; s=arc-20160816;
        b=h8DcSo7aUdGYGrVmPJvMB1cVg9fhsCUnQYMMfdBNTHiCHHQHmtL29OmQK9qIen1Ro8
         UKOY+UcDei/YrvngA4dq8vak/T2ItLHuhV6w9w2+Ho7MkD2z4MvkvLIvF0XNCJWhoMZo
         fujxc5bM8AU0FqwZTxXOxbnQJnpVyBJORwn1d6Gp7NIYPiAvSBrbon5fxZbMUAnoPFBX
         OvnQSaEfYH3E3eD5pCOfsuF5Oy/YdWr8wC6bYK7NjIYto1YwyYzwymMU1Ss4zN+Ju2+g
         2wA0U7x/L2UxCe0h3n2NFhWfmh9TPtuWb+f7bB2ESu0X6Eihu2YVNGivQKllzOdIL4Yc
         AsXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=WK1x1x1sVMvviaxTYkT7C9LP4uqnH2vvCIJU1nGd2Qc=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=xegE0TdJh1lLfWirGC54ha8U0BC/vcv1u7IU2cE7dR2bwCxCI9NmmOsXWmNTAr0iEW
         as1cPVBAZiKL7HCFSujL3100Dk9HCee+H8Ie9NBuRAiOm4fKRRWM26tJdd3XIX5ZAMj6
         SB+HwxDZCIJ1XjOVeGuredBHZYp2VKzuK0KgyO8SlwfRAQuxLqDCHEpAp8ar934RomOQ
         LIp6Lf++acE3bWx7x2fkaoQoGufSKF0fAdom9Ljtqi43M3SgynS00lzt3K/7nxatgG4i
         a2MKz4SyY6mKbTKr002+tATosPvP3CVcxoD1tFSRk7tF0z3TJXotaPwRSb0AGHAjuE6K
         7gHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dMBs6gEI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505284; x=1701110084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WK1x1x1sVMvviaxTYkT7C9LP4uqnH2vvCIJU1nGd2Qc=;
        b=wAspLJkPYOjb1oZJ5IORXuLaPjr/DFZ+U65TlzfSGplch4mVrWDGCbgmzJZS5Uwl1m
         Zp2E0KmLzSVeaN/ce5l0qAnwgFcvox3mUau903n9kNhLeMuqifygsVS+MTkfWEJDdBh+
         2280oM+O6RCJszj02/22op+qjTzCMpjl1Pa8tU8GuRis1OfcF5r/FoBUHQY3x75UnNUn
         MuC2rjQKJrELxfhOvKgJVceausB9oVwhTPylGYBBWcJnUNqdZWNoS3TJllu4CbwKOtjJ
         chi27+PN2lLM25YpDglCJv2lqpPaoTAhi6giR4oCDm1u0kce2VREy4d1r6NpImlieOD7
         yYhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505284; x=1701110084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WK1x1x1sVMvviaxTYkT7C9LP4uqnH2vvCIJU1nGd2Qc=;
        b=dbKJW1J3Bc7a82eDlG73g67wOP/zQapetG7kXliRTtP3smVjTsdNCLUOd+JcqoZZFN
         2/wBKqXh36j2xF0PbZgyTRsugnLVH5tQaJphtsfLWTmy1Q/t1GUE4V1FmKSJwJ1+EE1w
         osaPmTvBcjsK0kfzGDAio0S51tdqjWrDAnzlWq5ja/UyWNAbKni8S8lnaBMb7E8WDR3T
         yNaPcDamota9nhWgpnLq/NIzEqLgOyZSth/shDF0W357WFrUd+pWoE9NLyRkOElzlOkn
         ebIOOPNtFZ8LjVlzRcDWgOKwdx91Bm0b21oYFYuFIAD4laRACh41l5n14ROsZVFw0Sho
         ba9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz0Lhr+vZb36negDbL85IhyOyYzIy7pUXBMTTYHO3KHJ/veimdC
	+lKXZl728XOtYeh8dJIjNZA=
X-Google-Smtp-Source: AGHT+IF80QKYk2ZagjjygPwRCeXblFI6SM5f7dBFzJ59NnKH3+t7LPvUaPJ6wjJufiktPkovCh8nDg==
X-Received: by 2002:a05:600c:1f86:b0:408:4cf7:4f91 with SMTP id je6-20020a05600c1f8600b004084cf74f91mr7372345wmb.16.1700505284349;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c14:b0:3fe:cf02:f33b with SMTP id
 j20-20020a05600c1c1400b003fecf02f33bls1025712wms.2.-pod-prod-07-eu; Mon, 20
 Nov 2023 10:34:43 -0800 (PST)
X-Received: by 2002:a05:600c:1c14:b0:405:37bb:d942 with SMTP id j20-20020a05600c1c1400b0040537bbd942mr6348950wms.4.1700505282667;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505282; cv=none;
        d=google.com; s=arc-20160816;
        b=BZKIM7ujvJIw3sSk2+Ol5tepiK3Nr/9EH1s/iFSu3yGIbyKKbhE7dQgGqJ4c671EGY
         dyi/U7gtPx9Ml4Cf/xBJyhNOZ58GKvYiPIRDc2aRD+NA+e0e2fAF21o21sQtlgshX7XW
         tcPT+S/91dqSFsTMymcNLuIY6EwQl4FTVqPwNPg20yYmottjOlycOf/uH059Vgoa79ZH
         o51G29YBJx+zkoue/Px25Xi2bax//qg+Ci4dX7gz+XiB/W43JGRRLz+2vEj8R2+2S3+u
         tkS4qZUhWER96aqPF342slwZCLdcAQD3OMZfBjtlanwqMR4wyMg/aq4rNso4Ix5AiwTy
         8sdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=4OA8hmbuH8MxWfLH+c2HkYn0Z7Eu4RuF14fgas75tZs=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=gj1zVJIB9Z7VFDfPVVPNU851HJIJfhuexF1NXDX/eSbjGfjOF529T4/0/ftap6cLHI
         IWSCbZPWz7lcPHJdA/W20Wg9O0mIQqFIAshOpckZFp5B1oic4OiiMlIqPnoRB9R4wsgR
         rFKyIvgxzTO/wii73MU+oybG9fdK056czSBLvVoZU7vOhAPEtcCFi74s+vaQvCJbK1vN
         GJRMKhdBm7isRy5ye7IkHPAHndL1yQuVVj0vWRYiXEV+7d6s4eNn/5mw9NxaySr7scGi
         gajdePDD0GpvNAky3whN7so6Em0fUROhqn/e2lHRC/xXGrIcCaS0TYhskIXHWnM8kJ/X
         Wv/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dMBs6gEI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id j29-20020a05600c1c1d00b0040a25ec1cfesi539654wms.0.2023.11.20.10.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 453B31F8AF;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 166FF13499;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id iLgFBcKmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:42 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:23 +0100
Subject: [PATCH v2 12/21] mm/slab: consolidate includes in the internal
 mm/slab.h
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-12-9c9c70177183@suse.cz>
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
	 BAYES_SPAM(5.10)[99.99%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=dMBs6gEI;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The #include's are scattered at several places of the file, but it does
not seem this is needed to prevent any include loops (anymore?) so
consolidate them at the top. Also move the misplaced kmem_cache_init()
declaration away from the top.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 28 ++++++++++++++--------------
 1 file changed, 14 insertions(+), 14 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 3a8d13c099fa..1ac3a2f8d4c0 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -1,10 +1,22 @@
 /* SPDX-License-Identifier: GPL-2.0 */
 #ifndef MM_SLAB_H
 #define MM_SLAB_H
+
+#include <linux/reciprocal_div.h>
+#include <linux/list_lru.h>
+#include <linux/local_lock.h>
+#include <linux/random.h>
+#include <linux/kobject.h>
+#include <linux/sched/mm.h>
+#include <linux/memcontrol.h>
+#include <linux/fault-inject.h>
+#include <linux/kmemleak.h>
+#include <linux/kfence.h>
+#include <linux/kasan.h>
+
 /*
  * Internal slab definitions
  */
-void __init kmem_cache_init(void);
 
 #ifdef CONFIG_64BIT
 # ifdef system_has_cmpxchg128
@@ -209,11 +221,6 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#include <linux/kfence.h>
-#include <linux/kobject.h>
-#include <linux/reciprocal_div.h>
-#include <linux/local_lock.h>
-
 #ifdef CONFIG_SLUB_CPU_PARTIAL
 #define slub_percpu_partial(c)			((c)->partial)
 
@@ -347,14 +354,6 @@ static inline int objs_per_slab(const struct kmem_cache *cache,
 	return slab->objects;
 }
 
-#include <linux/memcontrol.h>
-#include <linux/fault-inject.h>
-#include <linux/kasan.h>
-#include <linux/kmemleak.h>
-#include <linux/random.h>
-#include <linux/sched/mm.h>
-#include <linux/list_lru.h>
-
 /*
  * State of the slab allocator.
  *
@@ -405,6 +404,7 @@ gfp_t kmalloc_fix_flags(gfp_t flags);
 /* Functions provided by the slab allocators */
 int __kmem_cache_create(struct kmem_cache *, slab_flags_t flags);
 
+void __init kmem_cache_init(void);
 void __init new_kmalloc_cache(int idx, enum kmalloc_cache_type type,
 			      slab_flags_t flags);
 extern void create_boot_cache(struct kmem_cache *, const char *name,

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-12-9c9c70177183%40suse.cz.
