Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHOH4OXAMGQEVKMTKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF632861B8F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 19:27:42 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-33d0d313b81sf511244f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 10:27:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708712862; cv=pass;
        d=google.com; s=arc-20160816;
        b=ejIggnfcmAEBluPWJp6uZ0tI4Bv9Ipi8c8dz4GYDRW+Op0AZlL/lA9tlHt1c024jOy
         NKYG7pvklQHIUzr+YQ1z3cIU3aGQ5pKxenlIIA5Jh2/KovkHfakvoWCppVBdk2WRHBop
         Dga0dl2bXecR+rzQomITep8++Yh9XrM84MldrAReslgg43R36k8hxa+W1k2PrBiIBUPJ
         Pg6DCucbkF5FylbtOKTTzpduQe2bqLPh0razHhA9Plcf3yKdjjFPt0iGqkMQeKMrRq+/
         V9NIiakgC5HBQfJDgvnkNIOO5h8Qgb5AtUAOxpr1H2Y/iujzVJYoauvn39d0koOA2oJm
         DY3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=v5BB0q8FURwB8PPxEzZrOay7jknrVoosgQBF4eYpK8A=;
        fh=KGVXqHHpskK7MVnaB7ZfEFHs0tAqLR8Lal9fiyJ1Hcs=;
        b=gvcalKK3w0ayLUN/xtx8sZQnwTSlFyOvqWTHvGsI53Rx4bFqjM9LUNAn1tbCdMthcY
         GO+5/T3D+b6GW5QB634a/V25vEZ4UkpqM4m5IDEwgiUw4CrwWE7GL3GCgBhekkrd/Plj
         Nyw1q2/+akZGseXs6tXw+O8EuBQRZKpvjBgpt2aH98sdHmlHIIcPR6HGrbiyHNx/sMOQ
         lUiQDp3FgPNyi2J6VYlBK2UF9lDltFMhXJQmfVN6HSzqEMN3S0aVqOtp4hPUwioCgaEN
         5UlyaQTG+vmCYxOBT38IBCb5LENinScOo+mwDqC01qUxwDj+08KILaEqSDrrabzz3CFf
         zEuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708712862; x=1709317662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v5BB0q8FURwB8PPxEzZrOay7jknrVoosgQBF4eYpK8A=;
        b=n+6DZWnBKrDcvCfmtDvdoGM+2IDMOMhNDDakp/Z48VmaSmqtqNROfYTsd+IxVsR/yS
         dRU+TB5VYYNb4lqMGAU9qU0HPIOHNsmLosLZ574Dp1zYMfRC/JOGLK3dODw94uH8n3RZ
         AFJMJZIo+31VQOw/D4j5DshEfhGj2rVpWYQ6cD4CJmDaLsy2kzu9Ct0nmrJz5ZE8k4jG
         4A2FRU1mJl22rgRsQ8L93O0DGtlRI2pnKU+8K0TBD3EUeaWTzjuKW9lDutRflmdlYAz8
         rsfSk2j9YoFJWGzQwSJpCAfSCFN4irDtEccEP+7JCExFmabFzF6xlziBZmAJoiDIeP2F
         jssQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708712862; x=1709317662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v5BB0q8FURwB8PPxEzZrOay7jknrVoosgQBF4eYpK8A=;
        b=SrjlCesfUVrUUr3CFpqsPbows/Dn/M56pa4bmivJm5OQ/KXaQXYLRV0Ke8YQgiwgIN
         /pG0bbRBzUBsJMBamuhUCwryP2J308qFL82gquFePIIoPUIv+BQeu3pB6sjcXX5LO5j2
         z8yyKUjcUJgJXTwxQySbp+3jvu4OFj5E2XgPQnF90l5hFwvYz2Gqg++5m6qcGs7Hi4mc
         l4HJsGZiMBI5oOiGgUm3fc26iI+QPgJ/aWXNGFoCjWd74mrM1vjps5DRuO/KSRaQkmli
         m50Hijzl0fUi0iVfMd4df6pfG1xSkjMQ5NcRA6KC+QfJV67JR/C8zlVPCQPlvQcJG8HT
         dVYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBoOtK6+JGB/yZAQ4M/1qSjjZz7pYsuh6OOjB0UdDuXLxurr/QiIf2Qqmm/k7m2qZvqJCh5NZHo+7DEsP2wZ1JGz0rO2pc+A==
X-Gm-Message-State: AOJu0Yyzci/dY1UVS2+HnEvyg4AI34LADBjbc7R1KUyTk641j9hRY1B2
	SO/lbFIAE3qm6IXbdLv8LM0xRZh/uabcHBU3QaVqeMbGykyuNFg3
X-Google-Smtp-Source: AGHT+IGwUSP2HldpMrYTUb37Fu0bQeBPyFTeP+Gb8g5I4vAjBBUGGIKXz5YSlQ6+ON3Ff18wM0qvMA==
X-Received: by 2002:a5d:4488:0:b0:33d:269d:a80c with SMTP id j8-20020a5d4488000000b0033d269da80cmr392590wrq.41.1708712861966;
        Fri, 23 Feb 2024 10:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:59a9:0:b0:33c:d742:7b30 with SMTP id p9-20020a5d59a9000000b0033cd7427b30ls478117wrr.1.-pod-prod-02-eu;
 Fri, 23 Feb 2024 10:27:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUIGI98STaQYtTDUf6k8Da7zuMbjO79R2BfOjaEPz666TPHF+CG6+C93n0Na1R17pHN4ioAgwzdWIjdz+vboGGtNzE9hnv2JYtphQ==
X-Received: by 2002:adf:f4ca:0:b0:33d:b530:58fd with SMTP id h10-20020adff4ca000000b0033db53058fdmr66811wrp.6.1708712860027;
        Fri, 23 Feb 2024 10:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708712860; cv=none;
        d=google.com; s=arc-20160816;
        b=FHt4l3A1SNEy7vCzvn/S22Ng9Mt4TgemqkQj++NRMuSdRYHctgj+jM6rD9AYOVqgbk
         USkpcjSTVd5rncXVuMKzKnS1Llj/0giwIJGtdu7XzA/Rth6tCajBvQkk3G1vST97PwR+
         CLKycJw4BoAEhDMlxL/JCZ76x2C5D0Z/AjgcR2bgsfdY1HU4rG1JyckAlVEo5q3rrv2Q
         b4xu4C9l+kSA8uqq2mtO28cRHIOwoLvDMf5xqCttRKYD8duDyt58YawMbKSbDMMMsviI
         xsSNeZUgpn8CknZ4Kw2YIX0qoYH3w26wFiLGWbdlY24EFggKlMhz8lIB4r7UlH2RIPvd
         pO6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=7brqYZxmuxrRKSYQEeacefCe+ctYuF6xWTXM5McbA8I=;
        fh=H+kigXjdCOVpCxcHPaVg6SgkIx4KR669HTfmciEICLo=;
        b=J4tUEHF1stj679P6URBcDyMfTQtDxnEtFU9zPT8lYqbqQvAbBGg1Of0l0ar9Ynko1m
         N5sdqkC0ZRXvVWXdGcAB7WUnJtBRg9dvXvC/eyqK58wlgEKiM2yt0aZ0qoxs3+0S2IH3
         +qLlTuVzUmaYn8B5CfQw8H2FVc76B496oyegvN3aJL+Ztrco0LFogjbF3TrLmwbrppm/
         zZi+XFEUqXcrBlfJueVtsvSl9zI0xMnR2q7GX/MF4X/KSBEWnHwiTSLVORa/ITQ92aSz
         s7iZulpBtF60oVgmz7uSukdyAIyhktZy9z6C0K080WPBskgEU5EWPizhrMCcGdfMA3OC
         WgZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id cf5-20020a5d5c85000000b0033da6ecf671si89320wrb.2.2024.02.23.10.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 10:27:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 28A201FC2A;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 008AE13AC1;
	Fri, 23 Feb 2024 18:27:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gJluO5rj2GUaTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 18:27:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Feb 2024 19:27:17 +0100
Subject: [PATCH v2 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240223-slab-cleanup-flags-v2-1-02f1753e8303@suse.cz>
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
 Vlastimil Babka <vbabka@suse.cz>, Steven Rostedt <rostedt@goodmis.org>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1937; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=xj2FbXNZUF1ZX1Yi4h91pRFSVKXZaW8ItJyLfGmRRuU=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl2OOSfAZ6NhpOQjvkRl542eUJ71NZdn+YC7Mu6
 stXO0E2hXKJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdjjkgAKCRC74LB10kWI
 mib0CACG+JmJHKxWWP/7G2u05sgQbj5Lct25lOvrv1QuCza7ZVTLPiTE2iE+BTE0PtH2dbdAYA5
 sl5xS/B71qhL1xjxpXhlT48vuelChx7oiMjOTPC1tbcKaU3HM68z420oR4LMO374DAlIaO5zlXu
 3UBG5MbidRfJxcqpQ8bWT8BUApwBuLjP1/psufGw7UGhM8uOii58OmE81DqIaPf9+9L0upk6xw9
 TNwRePi/w3rAJw42PoL6BkGJktvFbYpMLsDlfcPtjayFWVLix+Fwxkw09xUv4ZmAHSNjBDIMLjm
 HUnykdE/UgcYH0yBCAYi+6kvrVWPQw9wvQU/PWokxe3J3Ive
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spamd-Result: default: False [1.40 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.00)[42.50%];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[20];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Score: 1.40
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Qd8LsPfV;       dkim=neutral
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

The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
removed.  SLUB instead relies on the page allocator's NUMA policies.
Change the flag's value to 0 to free up the value it had, and mark it
for full removal once all users are gone.

Reported-by: Steven Rostedt <rostedt@goodmis.org>
Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
Reviewed-and-tested-by: Xiongwei Song <xiongwei.song@windriver.com>
Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 5 +++--
 mm/slab.h            | 1 -
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b5f5ee8308d0..b1675ff6b904 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -96,8 +96,6 @@
  */
 /* Defer freeing slabs to RCU */
 #define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
-/* Spread some memory over cpuset */
-#define SLAB_MEM_SPREAD		((slab_flags_t __force)0x00100000U)
 /* Trace allocations and frees */
 #define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
 
@@ -164,6 +162,9 @@
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
+/* Obsolete unused flag, to be removed */
+#define SLAB_MEM_SPREAD		((slab_flags_t __force)0U)
+
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
  *
diff --git a/mm/slab.h b/mm/slab.h
index 54deeb0428c6..f4534eefb35d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -469,7 +469,6 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
 			      SLAB_STORE_USER | \
 			      SLAB_TRACE | \
 			      SLAB_CONSISTENCY_CHECKS | \
-			      SLAB_MEM_SPREAD | \
 			      SLAB_NOLEAKTRACE | \
 			      SLAB_RECLAIM_ACCOUNT | \
 			      SLAB_TEMPORARY | \

-- 
2.43.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240223-slab-cleanup-flags-v2-1-02f1753e8303%40suse.cz.
