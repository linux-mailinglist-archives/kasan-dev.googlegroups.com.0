Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHOH4OXAMGQEVKMTKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B567861B90
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 19:27:43 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-512e578918dsf585084e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 10:27:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708712862; cv=pass;
        d=google.com; s=arc-20160816;
        b=k/wqx/4aTcB+yBE//ennVEz9nTnzP7O3iVIS2Jv38+Fj1Gq4D8t5we9osnaR44redA
         R6c02C8mlML2PHmyantEL4OmjvXUB9wyKO5CDsV3y2L5JimZ4oHlc4VHFpfuGUAbTo6d
         kRQLs3SzKoQKZ70yCUktzIv+YC+cnVOSKcXzmKRzJFVSdUYGHq14U20PblRMYK/zQyOG
         /JwUy5kqc7oBH9z4IjDQMdqMfnan/blpCtFjtsT1FAd/9fv8hfcOUUcyKnC/HF9puexz
         WqYqGFpHiCenr/15uq8MlrFIAYwmTHlAHHvu6xcbF4gQ/0744Pl4wjCS0GyfYWGlZoH6
         tiDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=7KLI0CcLcjZS3AYcJzELOvPLPBprTrsSfvqvyfuMCTQ=;
        fh=y0fBmaN7lSIa+du9dzdYImqtsp7TOvlYIK721dlETgA=;
        b=pW8S+Ge3vPbIa6FgDDjV/PukFm3hW886OT8bcLmAWBcLw5sXKbhTSPsNEJG9mMTIxF
         c4QYdtdlWpufJYBQX+UQ35svkDT/9tC38Xc0xjaQiQ3zsvRBXGK3sUZbw3Bkx3rEttJF
         4rA1QgTR4XnRzIzvHIY7pv0nU4AQTCoqWbXv+JnvZRv/q+YLTgX8JJgnJ5JSsaUgsbEC
         5PL2a9eKDsAv7fb8J00QHC5o3WiktsxN7yMGOHu37RgJA9vsdIiyOsGNO5yexsvQsRLx
         9dqvkfN0itlrkyYCaPWd+JVQM4bVG9t5xRNScS6VbK6WV++XVB8o009IUAadQoawtOSD
         KMjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708712862; x=1709317662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7KLI0CcLcjZS3AYcJzELOvPLPBprTrsSfvqvyfuMCTQ=;
        b=Z7rLnVJNohZsDHVhoWbC2oXy3k1kF+g+khdOFyXZFKSJGQOjCwGhnqCNAc1ZrFb+kl
         8ZU94vF0I+HktqA5nZeMGpPlo99EBr0hfKN7IIihsv0VjBRNQZpz/v1na9f6Em61xyu3
         eQgHH76v6M81JgV7fD1/VLHEpzuNY9knllx8+yCeU52r+3Bj0pGWxduhh349k0ZbdBUf
         4Q7FW/mJnMLlrytuaGWKh8Li8p84Y3QTNX2q/IKMj9yS1yQQxPhzqzig36lpVSrGMnRu
         AUwCXVL/HvfV5b+LBii6l70t0hiZjaBFTDGe7/atf+yrAwVxO7+Wz9gPvnB6K4jLBMBC
         aWjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708712862; x=1709317662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7KLI0CcLcjZS3AYcJzELOvPLPBprTrsSfvqvyfuMCTQ=;
        b=EM9Hmkbmzh76Qpl66jSdKwwvsxaQLdN58EgqFJnBqtMoO0ncgdKFhgRG36iSg7vuTL
         i8UrPQSKnSfAClqHRHaUstCzOAIBZ6hz83WCM/tWUF0iGizV73e2633J8OIrqtzDPudm
         ldwkwGxfqMQbKks5vODuxJHmpILntT0j2Cajs+FmGJmoaCnCrUvuTU81fy0lui1yPU0O
         wF15HVKtOky0h8CmOs5l40R7A4G02g+vst7cZ/zF0jCVHlNdTc/pggz5czcSSc9RhKXB
         K9IxjIuW/fQFLzZojFM35k+gbbvzIYBB6qLlsnoDL1oMaoiCKVWs3CfheFYo5p786+rI
         7S0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvudmWvMrmIceNK10W3w8lET1dLzCbKpgsgrY6w/ar70gCLm84CyTA5A9NzDIFIty8j29VeeauU9+HwOp7BSirKQ62NU4+AA==
X-Gm-Message-State: AOJu0YxC99lF0nO0E1NLs0c2cc2L29w1WUpgXveP800ojQodJ5rKNQzQ
	MqZV+W4fWSTjnOMobviLuySbuMDr7X22sUaEHsns6W5qk9KbabJA
X-Google-Smtp-Source: AGHT+IFaW8ouHIhF7KIkyFgpvGRgPZtWnAdq2/HfvUl8w3RrmLTk+srH5wEpuRFC/F+/v237FvQa7g==
X-Received: by 2002:ac2:47ec:0:b0:512:c0ec:752a with SMTP id b12-20020ac247ec000000b00512c0ec752amr353784lfp.62.1708712862140;
        Fri, 23 Feb 2024 10:27:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a4:b0:512:ed32:18da with SMTP id
 bp36-20020a05651215a400b00512ed3218dals192208lfb.2.-pod-prod-07-eu; Fri, 23
 Feb 2024 10:27:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVOPR/fFSTVpWlQTCP5w4ArKFf3yAaNaDSeMXTZ+S6cJlk0i7qPzExktJgowUxCwq8if0Yz7hIO+zAOBcFZOySnh5zLOpeIZx0ylA==
X-Received: by 2002:ac2:4e04:0:b0:512:cebf:e8d5 with SMTP id e4-20020ac24e04000000b00512cebfe8d5mr437295lfr.23.1708712860215;
        Fri, 23 Feb 2024 10:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708712860; cv=none;
        d=google.com; s=arc-20160816;
        b=ipAbkqL0G/vRMV2yJg0gd3gwo4I3NI1lxAanvaJ7SkH64JmsN0yXsX7h8qJ2sgPGkg
         m9Wg3Zm0ZHnQE30s8AfWQBDe9W/DutFKLJtmvXC+NKnMZTL6omdoo9vHZtVBmK6jzRiN
         9cbenuejS0i4ETKgA8CI+FvrNqttuXC23Qbp7o53Ab6ytWXVEswOEqXEImJqeSrT2R9i
         4wCvP7/UHnwMgbAW6a2NE803k5B1PRPvYwpLa450ur4vfm3VGMiw+Ef+6d60b/uThwaK
         9bxxxw/H45jHZbrhcfvDCcfazc6cvV7yMHlbpi3zsWufSyOjB/WvFK9rMnGoG80owuUr
         4IgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=YO6OeAHEfcyOnMDaYbuFQtLgT98NdTKboW4QLF6GI08=;
        fh=iiw6AxRn834Rp3X3mGFcQcmYTlAscmlxQxZZCAoI+ts=;
        b=vHrZA2K5HIjv7DprPEEYqCx1enBGyHowHbtM7mtd45HHLzQbNuq3TCGRgO3nQDm4IK
         m/XGaIY1XGQwQd3Zg2I+o66h7QXawxUzqqw1N0BTJ9opiv7jPB8xLXzAO7xEGxmMNrAI
         1FXmj3e/omJP/b/I4gy8bHFTCqroDsRO7Xs00XrwjsE5Gp0Fo85xj6Y0v6yqIrMkviRp
         DruCx3SoBg7Y+Zrx9LqN6e9CJTB4w8zDxkMIu4jQT+EiXT2R9FSgC21DL90xg6/MCgqY
         xUshxCpMbI+P6CX/bENUPeIqU093uxQdGInl0MJ0QMklA+WS8ibCJ1OtXa+N1X5na7rv
         znDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id i10-20020a056512340a00b00512eeacf36bsi429lfr.9.2024.02.23.10.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 10:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 73D011FCDA;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 41879133DC;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id kPmxD5vj2GUaTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 18:27:39 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Feb 2024 19:27:19 +0100
Subject: [PATCH v2 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240223-slab-cleanup-flags-v2-3-02f1753e8303@suse.cz>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
In-Reply-To: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
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
X-Developer-Signature: v=1; a=openpgp-sha256; l=3708; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=oc217rqjv84A6cygyOWMLvkkVYYlf8fIgIHPUe4CqEI=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl2OOY129UnZyUFxvKzDcfwYdqEhJtST9zIVQhR
 OzNq64oBqmJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdjjmAAKCRC74LB10kWI
 mm6xB/4/euNwci9dIao8KK+SBBEedcYnZYBkvv/tfVj0jHJLbQRkDU7o18IDmCMksxzsn6GOBXY
 hWU77hCw7WZR01TCB62xaMRW0zCLIA0G06bqY9dvz33jRvBJCH9VBwzyNBAfZ/LcGTpL1GR/5sx
 zB/Zgky+tvMiAeSElsMcqFukRRZ++nF6UNa9NdGkSbr9Ox6qkWHuEPN96iNvR5yTCICx0egsZcj
 nd017gUj/VcmHvW3qxXHRIigA5JksKXUSLxXyaUT03QrYIfSlFxwFjslF2KknX6AGoDV7kJWqCo
 9nYV61PnjZAKDEeC69HZCBItCBliGzH3GGI89D6yycYnxU83
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spamd-Result: default: False [-3.31 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[19];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:104:10:150:64:97:from];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 73D011FCDA
X-Spam-Level: 
X-Spam-Score: -3.31
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TwrUziIB;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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

The SLAB_KASAN flag prevents merging of caches in some configurations,
which is handled in a rather complicated way via kasan_never_merge().
Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
for KASAN caches in addition to SLAB_KASAN in those configurations,
and simplify the SLAB_NEVER_MERGE handling.

Tested-by: Xiongwei Song <xiongwei.song@windriver.com>
Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/kasan.h |  6 ------
 mm/kasan/generic.c    | 22 ++++++----------------
 mm/slab_common.c      |  2 +-
 3 files changed, 7 insertions(+), 23 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dbb06d789e74..70d6a8f6e25d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -429,7 +429,6 @@ struct kasan_cache {
 };
 
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
-slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
 
@@ -446,11 +445,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache,
 {
 	return 0;
 }
-/* And thus nothing prevents cache merging. */
-static inline slab_flags_t kasan_never_merge(void)
-{
-	return 0;
-}
 /* And no cache-related metadata initialization is required. */
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..27297dc4a55b 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -334,14 +334,6 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
-/* Only allow cache merging when no per-object metadata is present. */
-slab_flags_t kasan_never_merge(void)
-{
-	if (!kasan_requires_meta())
-		return 0;
-	return SLAB_KASAN;
-}
-
 /*
  * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
  * For larger allocations larger redzones are used.
@@ -370,15 +362,13 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		return;
 
 	/*
-	 * SLAB_KASAN is used to mark caches that are sanitized by KASAN
-	 * and that thus have per-object metadata.
-	 * Currently this flag is used in two places:
-	 * 1. In slab_ksize() to account for per-object metadata when
-	 *    calculating the size of the accessible memory within the object.
-	 * 2. In slab_common.c via kasan_never_merge() to prevent merging of
-	 *    caches with per-object metadata.
+	 * SLAB_KASAN is used to mark caches that are sanitized by KASAN and
+	 * that thus have per-object metadata. Currently, this flag is used in
+	 * slab_ksize() to account for per-object metadata when calculating the
+	 * size of the accessible memory within the object. Additionally, we use
+	 * SLAB_NO_MERGE to prevent merging of caches with per-object metadata.
 	 */
-	*flags |= SLAB_KASAN;
+	*flags |= SLAB_KASAN | SLAB_NO_MERGE;
 
 	ok_size = *size;
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 238293b1dbe1..7cfa2f1ce655 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -50,7 +50,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
-		SLAB_FAILSLAB | SLAB_NO_MERGE | kasan_never_merge())
+		SLAB_FAILSLAB | SLAB_NO_MERGE)
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)

-- 
2.43.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240223-slab-cleanup-flags-v2-3-02f1753e8303%40suse.cz.
