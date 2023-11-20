Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DC427F1C7E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:45 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2c6ec02785esf45109491fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505284; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+hMzZMR04iO+pg0c1CLPe+0Vjx71+H6iFKyrAAexhfHHFQuZnUaIyyN2BrRmj9ojC
         GkfCzQ7WB/3WCAYqPdXVJ0HSGHZdctBGdJN8d/2hGJdpIqnWSerqn7pb3LUqNB5+Exen
         zcVs2zyatquIlqHM1qt6ixrhGfMaXR85QFnys98NZNpfNU0eK39B9odCWGdDqV06WNso
         nX5gGB45qcvrbdX3bde/asE2ZIm5/wVVz25A+0qEZ28rFphKPMWt5rkmrg6NhOG63vCK
         v4VnSbecb+JrjY+scW1hGltZkbkoGttQzj3Y8TVlfXuvWYcRE3SAYKZlfoZQYTJQzlqd
         +bMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=/qv8lb9qLQJ7+D3tuPrdE7TSqWpMAH0lCOHdH6EI+R4=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=PPG6yqHVR+oAUw7YDu2CkTaSNaAnyqFw+FjAoW/OGdTQbSiQhGqDoNu8H/IXRBr3qO
         sumI5FqAjZgsg1fajRO4Oej0AIvdW2aXy3HOTWAQWvC7b/WgJ2lj68LlelLLGBntsKd/
         VY5pZoTrFNgrSeLQ1i+sfZ8mB4Ci6HIRsjFWzf0iTzkQObOVVdt+HOrjTnb4PtCQA8hC
         uAr/+Cm+Rbhn1C4KVAbMQz6upEWaYpWHeoM/efcxkoxntbw6JEEKEVmuBe9nGgKVkKDw
         CMIuNhY0k/D1bCTDg2DY2ttRgkqLYF4X23Eb5T7dZSD78F3irU2LeRQIyGD7NhkarTJR
         AHog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FPhfQvkV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505284; x=1701110084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/qv8lb9qLQJ7+D3tuPrdE7TSqWpMAH0lCOHdH6EI+R4=;
        b=XsqAaHKSKsg8zvZ7yW9dV5tFLKD2B6xKOughOc/jDIDx5hdbR6FM1epZva0z9PyiFq
         BDxW9Y2J+I3aR0SRl4u8g9jpKknThhPfGes/iaCzpcUipzst3gzbDsPt/FA5oZ7JZ3qX
         7mDumbXLsMEUbbBdBGidmmvBscltYROpmYUK0IkQGfVuNDJC04kW5MFwzLi7qtgsvKLF
         /Gk2m0Xhmr7UA1uyKujS/4AYNS10fvzx/y2IF+7019SmFpJ12CGjLiF3tpUPPY5dfcof
         0Z9PjQ1XXHzoc6EfUqiXi5jewU8JHfDM6pr4GHAzej69ok8Y4g7JI/ZNR0yz0/LW+Cmc
         g5Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505284; x=1701110084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/qv8lb9qLQJ7+D3tuPrdE7TSqWpMAH0lCOHdH6EI+R4=;
        b=vSKDHJO0YqmwQlrH9spVItDkjp+Z6Oeb/TFnJiihrB6B0ZE9O+obYYLuqXxuLAsQXw
         MDdRDmz0FuspqZcwG24Of/XYJpNsK+X76CA5oXPYsJMGdEi/gMpExllLyE7+yNV4q4j4
         hTETX9+Aias0k4Zn5WysHgfvGPGIjqOiJqHuBMh3keY5qWxiViUWiyH/YH0fLR6wG44d
         ZRYBJ0AEYsLRZ1x97qzG12VYOt3v5qMdCxDAsURTU07T91QS6v7+u1CfwBaYVFp5cZIW
         BM8YRwNr+SsyMk5up3V6bXIpvJIaTn/aCxh/Ge5hFUs0GAwnB8xsP7E2DiebbxiuANFx
         w6Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyJE3RcnU3SpPWM/SiV0GaARRP4VHL6gH55RIS69Ca/C+/BJ6wd
	q4ARPjLGx9gSZJvqoz8O7Y8=
X-Google-Smtp-Source: AGHT+IEWCbrU7kVsZHb5Kvdp+9I+Rs8anoP0yVv4/P7C90fAPNrlxFjW8T9+NqCHvbX/GXeYbg+/VQ==
X-Received: by 2002:ac2:5297:0:b0:507:cfbc:bf8d with SMTP id q23-20020ac25297000000b00507cfbcbf8dmr5493253lfm.16.1700505284022;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2305:b0:507:cf9c:aa7e with SMTP id
 o5-20020a056512230500b00507cf9caa7els257257lfu.1.-pod-prod-07-eu; Mon, 20 Nov
 2023 10:34:42 -0800 (PST)
X-Received: by 2002:a05:6512:2244:b0:50a:aa65:2c3a with SMTP id i4-20020a056512224400b0050aaa652c3amr4979835lfu.69.1700505282061;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505282; cv=none;
        d=google.com; s=arc-20160816;
        b=hSB/g2g/RdpMIQ3FzxPDWg6MNF0lkbx9jAg+G/x1Fvelm0QK3N3pf1h8ANXRkgE6CD
         04sXPZoz2ly80d+tGb9DaFTo3wK9q/Wb8Uobf8E7lkrSpKp5gKMHzjef42Q1T74f6nkZ
         njT+bp+I2jvDDoSaeKOcOtuPAheWFJQhbCYLyzM4tcRh4wWSgFAThqmRcDhhFuMTcqwk
         ndc2y1Vgv6YI7HyS4kR/BxBcRyD3sBoxriKLBMxhoKU5m+7mtJnx46if0svUEzk4hSbU
         B3MSzSBVPxqPSGEYJ8kZWnLjj/eS8oIdt2BVsavnBi9y+mgnCbaGTJGSSE7KJPfBLVfk
         sIuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=5GrBCfvjCtpiJqa8ygwZPoxY8exS+14FRB1r254RD0U=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=CtaJF6QgaZsBMzApOHUt6AAAw6vppyy2pi4mSa2D847hlcSaACz2jRskXl/kekdb9l
         NRrDYLEPRKvOmfDJ0NpUiMtdIn1Dk0Wpg3cWzXzDNeHI7htldJu6P5h0cZcXQ3TCRIzM
         rAzOM8RU0GGb6XrFsZAzzpQvBT3EGBEmU5l2PHH+3l4J7dDBIFFFjj0RXEk4Ql1Qkhj1
         cmk7uV+sfwP3Qukk3Tby6bc/lAQNY6a8tj+7TPVT1mcxaAwT5uDW2aLp11/9rVwzvWHB
         JByB6oxDyZer8Q+6cWcEV1TXdP1ql6QSn5Y1s0rTDyD9jleu/toErgijJUEwRN0GqJx0
         qJRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FPhfQvkV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bi28-20020a0565120e9c00b0050446001e0bsi344636lfb.3.2023.11.20.10.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 60AD51F8AA;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 30A8113912;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id EAFrC8GmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:41 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:19 +0100
Subject: [PATCH v2 08/21] mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB
 ifdefs
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-8-9c9c70177183@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=FPhfQvkV;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
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

CONFIG_DEBUG_SLAB is going away with CONFIG_SLAB, so remove dead ifdefs
in mempool and dmapool code.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/dmapool.c | 2 +-
 mm/mempool.c | 6 +++---
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/dmapool.c b/mm/dmapool.c
index a151a21e571b..f0bfc6c490f4 100644
--- a/mm/dmapool.c
+++ b/mm/dmapool.c
@@ -36,7 +36,7 @@
 #include <linux/types.h>
 #include <linux/wait.h>
 
-#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
+#ifdef CONFIG_SLUB_DEBUG_ON
 #define DMAPOOL_DEBUG 1
 #endif
 
diff --git a/mm/mempool.c b/mm/mempool.c
index 734bcf5afbb7..4759be0ff9de 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -20,7 +20,7 @@
 #include <linux/writeback.h>
 #include "slab.h"
 
-#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
+#ifdef CONFIG_SLUB_DEBUG_ON
 static void poison_error(mempool_t *pool, void *element, size_t size,
 			 size_t byte)
 {
@@ -95,14 +95,14 @@ static void poison_element(mempool_t *pool, void *element)
 		kunmap_atomic(addr);
 	}
 }
-#else /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
+#else /* CONFIG_SLUB_DEBUG_ON */
 static inline void check_element(mempool_t *pool, void *element)
 {
 }
 static inline void poison_element(mempool_t *pool, void *element)
 {
 }
-#endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
+#endif /* CONFIG_SLUB_DEBUG_ON */
 
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-8-9c9c70177183%40suse.cz.
