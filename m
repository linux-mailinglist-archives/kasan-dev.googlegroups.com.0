Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSFU2OXAMGQEKSHF5MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DD6685C1E6
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 17:58:49 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d2399a08c0sf17493671fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:58:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708448329; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q/qR7M2tTFYPtHiB4uMWnuLmuCq63POP4+pqMc3TtvhR26aI/yLqDUjjxKkUCe9dWn
         CcwH0tR2Gisi31QVFzmoG3rJDTQYif1aKGDtrFcfQAg5YZx2wCswUjZybw7frYKxdsKx
         UPqjFueO2f+0r+i3/b8+fBJU2g5nrzDgFoJV4+zmAhuE7lhxABAVTCuZksaqDajGRyPZ
         bxdkQTc+RHkAnDkNVpOjMDTQjccuX6JW7M5rcKJuDV0uhNwKsxNTmeyswFFuJuRdKQKg
         TNoAtFpLM+xPVzAGV61PTH0NHiR/lbpxrFqtzEQ5Foq7G6/92oFygXRHEsQEYqalZkW6
         elXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=W89gDGxDLmb7kkCH82/DGq2RjPpfCMb7R0kCIJ8ibIs=;
        fh=k3aR4/OXPUBvsXT/OcXo+3RP0yPsba2fkzrKvUijCUM=;
        b=Hbmut6YAsNa6EXBXs45SJZ5dMZ5t12a3Tmq7mAKKzUgbB7bn18qj+o4fVbk7YAsllv
         yqWvHlX/Ton+88k0d2iKRY4Oaz4k3Ly+HUa+f9WBnNS+IgdUmuMxjlCcJsHsWSTQXtP2
         VPcjWJLS+tSx9WfcqslJbxdSC2EKLRRG7YK3ZMu+3Bmv8qMKn+DGargAzm3soDi+BQAJ
         ib/7ZUcMiZA5HOW1I39vgmKqk8yzGrMZ6nRElJUzCt/08CiYlBI1EblDGB4BAvtWAtpW
         fEP1WTkCG64M9sLyVt9h/M94Pcl8TBasYL6XKzBOhrC2kf0CkgGZMv6+BUdtBMgR+91Y
         cuEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708448329; x=1709053129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W89gDGxDLmb7kkCH82/DGq2RjPpfCMb7R0kCIJ8ibIs=;
        b=DEM492p/fdsEiFH9G56BvrKPYjfzthvFEPNfSjpuMMXgv48pMn+VrWrqCDkBk6qu77
         DJ11ihLy9P7u1ovEULMLzleB+/Sryq6DwS7sQA3mgHQ1UsdHz1o/7QxO7mGhCKgJ3uwR
         GPV2Q18mbXOyIX03g/fXd1cRY6SpXgiccvDxq2qmj8ygiqX/NSckMKr1er0SmmfwJxn9
         v2Xgy45FFpRvMgTj86NQr3Ud2kd6aoVP/QsboBn3P8WmVjjFeIzBLB4U1OkD6IHM3/iU
         FC45hodrUskNa7VXRjurhKkbEDX3ARaFsYVstpwtcmkDendVTdikimMBouRE6wtZfdiF
         1+fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708448329; x=1709053129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W89gDGxDLmb7kkCH82/DGq2RjPpfCMb7R0kCIJ8ibIs=;
        b=NYFrZ/O4rohW5SzhQQmlrkxdTRkF3eYlTzkuZLfSi02dDepsdRYg+uTJziohQ1ORL3
         dhN5YPNL5k2ZZzLKAtH8pjiu0+ZeAHE2P3Mh+pSCC4BDjzJD8iTdb1BlmniN3shZACtf
         dumqKeQJS0TjCTtTGl6qKZ44HbfM/wlP3pxoG8wDiygbvsvbrGqiLuNrJMB8Y3C9xGIY
         crEA/Ju3uGw+696QiEpPB7wNqTQDC2h5wY1UeY3nnlkURWK5WXCPtlFnXMaXADJ+JtHT
         PR7UdoPyEgfIl/2WnTgo0SI2EsUSEMPdaVUutbyvMrbjCwyJ8gSzCMdOvVO/8qYAvOn1
         f7mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7a/1l6zcaaAOMZvatZNU9x5oSiBs+I8r2q3x2eHYWyABI+8QXKjoXeS3aFLoUiHruxPvW4XHsl2th0s8Ec6q18eEjaLvFTg==
X-Gm-Message-State: AOJu0Ywni31dNiYMgl5TMnMpm5ixpZX4e6o8PIbkwS4FxPFyZmN4AVpA
	ZOoFoAQn/+Oh3v0ijVD3KUgHKdpOWt5V4Gmk8UoGh7YC3rRKD8Yu
X-Google-Smtp-Source: AGHT+IFCJN0fTIYHYIjLrM0o9NNktHYAGyCitF+UFbHsuP3actqmmWrHYcbid6cUfBUPZ+DOv3c54A==
X-Received: by 2002:a05:6512:1327:b0:512:99a3:62eb with SMTP id x39-20020a056512132700b0051299a362ebmr8820248lfu.54.1708448328528;
        Tue, 20 Feb 2024 08:58:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4010:b0:512:a450:e719 with SMTP id
 br16-20020a056512401000b00512a450e719ls919138lfb.2.-pod-prod-04-eu; Tue, 20
 Feb 2024 08:58:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEIKkbXj7UE0w6R7vkPZKDZGmaa1kjiobx7fTByXuSpsNiTeRpQzGglK3zGapl2/D4XRlAPjZ7KXYAX0q5yiA1GwSk21myBjzZjw==
X-Received: by 2002:a05:651c:220c:b0:2d2:3129:3d93 with SMTP id y12-20020a05651c220c00b002d231293d93mr7203789ljq.51.1708448326238;
        Tue, 20 Feb 2024 08:58:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708448326; cv=none;
        d=google.com; s=arc-20160816;
        b=OlhV3ItPK3F1G9yXbyYMoAJp3tj/EQtaN0F2NAPf8urDmXsebnMyKyIpuP3zYkg0G/
         nwc7HrQ/rhY+QUHSnWaPjiD43qYR9Mc32ekDuhWCXywUWZM6iKAFbQqgzAD385pL3II3
         nz+hz8F33LiCT0cZBvHPuw0JDegHs3xNpSkneXBU8reMO61SahBAKnXHuoWMHLrdqPRg
         CrVMR2dacb0T782ecL1xLT6+0Y1rBfLfZGZP0h6DCA6BvyU+pVwrHBLSolJMAVvCdM7y
         ewXPUhR9EAhkB1y4kWAKE0pNm1zX2Lhdh3JectyH6oS+SugFo244s/1cwnZ61BbhsTO3
         if1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=sZ+8lSmxyKMz7aX7YkStMli4RcGBfBcmvqFztfMzFZc=;
        fh=iiw6AxRn834Rp3X3mGFcQcmYTlAscmlxQxZZCAoI+ts=;
        b=JZopcjxXloNc3lyIFAT+Rtjy5xDwLXQc4Zm2IrJFtXzG9LXlWBHPI7sAwTCo5J7/Fn
         Xlw1bnEW6ldF+VID8iMaBi1yKnI8A6x/OwtsocI7zWLpcLhMFuFbCV3dt5OSJcqJMF8S
         2p7h0A4E4vsP1izDbDynKcbvfxA5POiKCST9Vti0NNUWQNwl3MYZxfP+m77t0wHggb0p
         C/h7itBEOqi/fvCQH1mr3tDCabao950YocdhAFRN2OBFQGLNSCI7TMUr2G7wiemgpFc2
         RCVL56W/tEyx6C7oO34ctNY83O7aP1IOAtXMi7fUXOC7wpEjjlUlmvdDKzj99HuSuFC8
         DnUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id e4-20020a05651c150400b002d24ee326easi62614ljf.3.2024.02.20.08.58.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 08:58:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5A1831F8AB;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3A49B13A94;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SA77DUXa1GVKXQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Feb 2024 16:58:45 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Tue, 20 Feb 2024 17:58:26 +0100
Subject: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>, 
 Xiongwei Song <xiongwei.song@windriver.com>, 
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6508; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=QNJRHlmDrZynn1U8943ItQzMzlmVSA/ls2WuKXFCGgI=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl1No/ygsO500Ssb9XAkmAz2HhpQIKGfJtG4YPQ
 qOlBzr+WcWJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdTaPwAKCRC74LB10kWI
 mr1zCACerO93/YH+0xXf3hmj9+Ly4RkBTkbOhSmsHedvITBcHdJXKdDsWBSKDvHBhaBrbYG/yw4
 ETY87JH94vda42AmV7XJhgJazaGSBZrOXYqc7+p6AXMPbIakyeejJaZC3auz5lG1smlQTfkCyzw
 UguX8Eka+Rs2SfLGYJnTUeWJPVbI1IV3yoymNc2ee2+E53VoW8WEHLnfawSrp9nF54jEEM9kL5r
 3RrsKEiI2lbguKI8+3HzLF+PPT5Ufm46y2zTqlcQkchaGnx/pL3wvZRKgiUrvKXLxjXnlsvx83f
 X+J/gmD8lECXksKyAhTcae7i21y5P2kZEg7iHI6844Z8mnqI
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spamd-Result: default: False [-5.60 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[19];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -5.60
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uUF45UK4;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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

The values of SLAB_ cache creation flagsare defined by hand, which is
tedious and error-prone. Use an enum to assign the bit number and a
__SF_BIT() macro to #define the final flags.

This renumbers the flag values, which is OK as they are only used
internally.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 81 ++++++++++++++++++++++++++++++++++++++--------------
 mm/slub.c            |  6 ++--
 2 files changed, 63 insertions(+), 24 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 6252f44115c2..f893a132dd5a 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -21,29 +21,68 @@
 #include <linux/cleanup.h>
 #include <linux/hash.h>
 
+enum _slab_flag_bits {
+	_SLAB_CONSISTENCY_CHECKS,
+	_SLAB_RED_ZONE,
+	_SLAB_POISON,
+	_SLAB_KMALLOC,
+	_SLAB_HWCACHE_ALIGN,
+	_SLAB_CACHE_DMA,
+	_SLAB_CACHE_DMA32,
+	_SLAB_STORE_USER,
+	_SLAB_PANIC,
+	_SLAB_TYPESAFE_BY_RCU,
+	_SLAB_TRACE,
+#ifdef CONFIG_DEBUG_OBJECTS
+	_SLAB_DEBUG_OBJECTS,
+#endif
+	_SLAB_NOLEAKTRACE,
+	_SLAB_NO_MERGE,
+#ifdef CONFIG_FAILSLAB
+	_SLAB_FAILSLAB,
+#endif
+#ifdef CONFIG_MEMCG_KMEM
+	_SLAB_ACCOUNT,
+#endif
+#ifdef CONFIG_KASAN_GENERIC
+	_SLAB_KASAN,
+#endif
+	_SLAB_NO_USER_FLAGS,
+#ifdef CONFIG_KFENCE
+	_SLAB_SKIP_KFENCE,
+#endif
+#ifndef CONFIG_SLUB_TINY
+	_SLAB_RECLAIM_ACCOUNT,
+#endif
+	_SLAB_OBJECT_POISON,
+	_SLAB_CMPXCHG_DOUBLE,
+	_SLAB_FLAGS_LAST_BIT
+};
+
+#define __SF_BIT(nr)	((slab_flags_t __force)(1U << (nr)))
 
 /*
  * Flags to pass to kmem_cache_create().
  * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
-#define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
+#define SLAB_CONSISTENCY_CHECKS	__SF_BIT(_SLAB_CONSISTENCY_CHECKS)
 /* DEBUG: Red zone objs in a cache */
-#define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
+#define SLAB_RED_ZONE		__SF_BIT(_SLAB_RED_ZONE)
 /* DEBUG: Poison objects */
-#define SLAB_POISON		((slab_flags_t __force)0x00000800U)
+#define SLAB_POISON		__SF_BIT(_SLAB_POISON)
 /* Indicate a kmalloc slab */
-#define SLAB_KMALLOC		((slab_flags_t __force)0x00001000U)
+#define SLAB_KMALLOC		__SF_BIT(_SLAB_KMALLOC)
 /* Align objs on cache lines */
-#define SLAB_HWCACHE_ALIGN	((slab_flags_t __force)0x00002000U)
+#define SLAB_HWCACHE_ALIGN	__SF_BIT(_SLAB_HWCACHE_ALIGN)
 /* Use GFP_DMA memory */
-#define SLAB_CACHE_DMA		((slab_flags_t __force)0x00004000U)
+#define SLAB_CACHE_DMA		__SF_BIT(_SLAB_CACHE_DMA)
 /* Use GFP_DMA32 memory */
-#define SLAB_CACHE_DMA32	((slab_flags_t __force)0x00008000U)
+#define SLAB_CACHE_DMA32	__SF_BIT(_SLAB_CACHE_DMA32)
 /* DEBUG: Store the last owner for bug hunting */
-#define SLAB_STORE_USER		((slab_flags_t __force)0x00010000U)
+#define SLAB_STORE_USER		__SF_BIT(_SLAB_STORE_USER)
 /* Panic if kmem_cache_create() fails */
-#define SLAB_PANIC		((slab_flags_t __force)0x00040000U)
+#define SLAB_PANIC		__SF_BIT(_SLAB_PANIC)
 /*
  * SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
  *
@@ -95,19 +134,19 @@
  * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
  */
 /* Defer freeing slabs to RCU */
-#define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
+#define SLAB_TYPESAFE_BY_RCU	__SF_BIT(_SLAB_TYPESAFE_BY_RCU)
 /* Trace allocations and frees */
-#define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
+#define SLAB_TRACE		__SF_BIT(_SLAB_TRACE)
 
 /* Flag to prevent checks on free */
 #ifdef CONFIG_DEBUG_OBJECTS
-# define SLAB_DEBUG_OBJECTS	((slab_flags_t __force)0x00400000U)
+# define SLAB_DEBUG_OBJECTS	__SF_BIT(_SLAB_DEBUG_OBJECTS)
 #else
 # define SLAB_DEBUG_OBJECTS	0
 #endif
 
 /* Avoid kmemleak tracing */
-#define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)
+#define SLAB_NOLEAKTRACE	__SF_BIT(_SLAB_NOLEAKTRACE)
 
 /*
  * Prevent merging with compatible kmem caches. This flag should be used
@@ -119,23 +158,23 @@
  * - performance critical caches, should be very rare and consulted with slab
  *   maintainers, and not used together with CONFIG_SLUB_TINY
  */
-#define SLAB_NO_MERGE		((slab_flags_t __force)0x01000000U)
+#define SLAB_NO_MERGE		__SF_BIT(_SLAB_NO_MERGE)
 
 /* Fault injection mark */
 #ifdef CONFIG_FAILSLAB
-# define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
+# define SLAB_FAILSLAB		__SF_BIT(_SLAB_FAILSLAB)
 #else
 # define SLAB_FAILSLAB		0
 #endif
 /* Account to memcg */
 #ifdef CONFIG_MEMCG_KMEM
-# define SLAB_ACCOUNT		((slab_flags_t __force)0x04000000U)
+# define SLAB_ACCOUNT		__SF_BIT(_SLAB_ACCOUNT)
 #else
 # define SLAB_ACCOUNT		0
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
-#define SLAB_KASAN		((slab_flags_t __force)0x08000000U)
+#define SLAB_KASAN		__SF_BIT(_SLAB_KASAN)
 #else
 #define SLAB_KASAN		0
 #endif
@@ -145,10 +184,10 @@
  * Intended for caches created for self-tests so they have only flags
  * specified in the code and other flags are ignored.
  */
-#define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
+#define SLAB_NO_USER_FLAGS	__SF_BIT(_SLAB_NO_USER_FLAGS)
 
 #ifdef CONFIG_KFENCE
-#define SLAB_SKIP_KFENCE	((slab_flags_t __force)0x20000000U)
+#define SLAB_SKIP_KFENCE	__SF_BIT(_SLAB_SKIP_KFENCE)
 #else
 #define SLAB_SKIP_KFENCE	0
 #endif
@@ -156,9 +195,9 @@
 /* The following flags affect the page allocator grouping pages by mobility */
 /* Objects are reclaimable */
 #ifndef CONFIG_SLUB_TINY
-#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
+#define SLAB_RECLAIM_ACCOUNT	__SF_BIT(_SLAB_RECLAIM_ACCOUNT)
 #else
-#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0)
+#define SLAB_RECLAIM_ACCOUNT	0
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
diff --git a/mm/slub.c b/mm/slub.c
index 2ef88bbf56a3..a93c5a17cbbb 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
 
 /* Internal SLUB flags */
 /* Poison object */
-#define __OBJECT_POISON		((slab_flags_t __force)0x80000000U)
+#define __OBJECT_POISON		__SF_BIT(_SLAB_OBJECT_POISON)
 /* Use cmpxchg_double */
 
 #ifdef system_has_freelist_aba
-#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0x40000000U)
+#define __CMPXCHG_DOUBLE	__SF_BIT(_SLAB_CMPXCHG_DOUBLE)
 #else
-#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0U)
+#define __CMPXCHG_DOUBLE	0
 #endif
 
 /*

-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220-slab-cleanup-flags-v1-2-e657e373944a%40suse.cz.
