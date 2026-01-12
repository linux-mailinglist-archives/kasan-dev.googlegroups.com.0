Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3VASTFQMGQEGH4FHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 87357D138CB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:03 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-432db1a9589sf1263878f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231023; cv=pass;
        d=google.com; s=arc-20240605;
        b=iNCdx0n+jZ1ixNgExZYcEJjLKfp580cPjBbD2AD12zFcOouvJZzubJSC7IoB+nWy9W
         yxTcWW+n3eGtqDPbKbFRKismBaf6HBqZqmRQOkqUWt/s8JGO/54frdBCu3BWpjl53xlF
         uEhtBPHyJ3h6KgS+EuVFoJRPE30eGYW2nBYcGPi11MFIQVC2pgBfyg9Tmk05oPYbVVVu
         v8bHOFIbUWkoefplUp3Zwsv+Ov06q5c0zyAcd6HjTpJ4s4ueRllzZ4v5RBGikDvRMWrK
         8m85jCsK8WekFhpKbsurCPn6lY0te3Iych48F3oPtDOdD5vnC7seODvhklEMl5LnUNDf
         vFBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=EJ9f5WlHoIKPd/qJPrtpADDA2Vd7FhCnicqoGG6HuWc=;
        fh=AUI7A6TyX5evjFyWEkjuCZxpU9RuXL0DFmAsVjT3I8Q=;
        b=Y8indIgnydeCIxVK+X4cYpRZvgTEl/CLTMlgw5uYbz6xE1bWPQxzkqv/jWf92hqY2M
         Mb24sYitXcA7G5DMjrxpyQme86AEaXaay91NVYvEMGsHHn8gAUHOS8f7nN27Xw9xKf1g
         xFvl85SvY/dM2HYmC2IRvrlCfK67kEXBJGj5TLuYOX2VWMD2fiEWGTpd7tb3hA49/J3P
         jihEQIKZ9y6Vdg++eZHT54Is0KVwCNjXVoknsFsJZ5MioBryRpbXNyA1VVbjhvOipNs3
         t2haRORhw3ZI+gRQm9v2qg189tel0oTX/+YnPzcQpO2ZT+/v0BJpn2nYY77MU2SWuT3m
         cYZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231023; x=1768835823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EJ9f5WlHoIKPd/qJPrtpADDA2Vd7FhCnicqoGG6HuWc=;
        b=hCFqNghDB4wJ3ext9PsjcbXkFj8KEG0Nx7O9Qs1Uk+bv1wQtsirquRd94450O2B1to
         htQAHjyXlgul7Zgi4LIoIP8lm9zsnenNmW3np5lP9g5V5YVlaZi8cviw3I0ATbMO9tuf
         mayy2FdM4Wbou/bUKgwlUdqXSQRb0b9Mj63hSmnb7O72ilIUmYEhuR0+tOlM6Ed2dcBj
         6UBGtj3iM1OjSOthYdvQQezQ548PCG1hRPaohsqyYFZ7U2tyjDJP4SiSdM4DGkJlRO+Z
         O7mnFoZqo1h9EYVDkOxxXbm/mfuqLJ83JGd5NiPepQyyK7sMk88c6HbNpSSjAvDo+Pqk
         1Uag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231023; x=1768835823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EJ9f5WlHoIKPd/qJPrtpADDA2Vd7FhCnicqoGG6HuWc=;
        b=kOI7iMANtGdba6CaaBVaSKVtMKKxtbnR5mPDXcepqarKVxONsDllST63yTPfQUXT0U
         iIcQ34l7d4eel1App0XI7Jr9bZpL8YsPWGhmFkzZOQYv46W0rm0KGvlKa4HZvyPtBsDP
         p+sT3AaNWOUsonioFTJqOzGndmjd9DnW0oJxaMESo0XmPZ9NPRaU0H0sd1CHso2v0ChH
         LbxExoJO6nn/1Wol+qMC6rJJNvGuCuQhYihzvL+AkfiSCfnfEDdg+thrroAlT5X3/92r
         +Rw/kAr1jtmYVB9MJZ9AqI6YBpiNWEQZTa4OI6z6xyucdkjwAH6l5st3vGxAry2g6o46
         cgHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTIS67kXDYJIJIxMXUMB3hgRvjANUKjDXFqpf0lDkaSM7u8NPatOrb6Lfm/Ya4EO8OSc/OgQ==@lfdr.de
X-Gm-Message-State: AOJu0YwAxjP1+3M5OS+Pq9E3b3pCicyfaGY6Xw/Zoi4FsNF/9paQD6j/
	xauyviW1wYCQ2RTOJlYgtbBGqKED/LoRlftPOi6FOi1+/B7o9zhTB9DS
X-Google-Smtp-Source: AGHT+IFTlWoNo0yy90q6rYK0MobjqwmdJTSVpKPmbVBlMPQ5HqOaqq5DAKxP9kM6y8KWfHkEO5M49g==
X-Received: by 2002:a5d:64e3:0:b0:42b:4247:b077 with SMTP id ffacd0b85a97d-432c379de19mr24723346f8f.41.1768231022636;
        Mon, 12 Jan 2026 07:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FE7XhNGLIs0k37EFDzIKiMX0mmzohZH6hlU5y7+dk9WA=="
Received: by 2002:a5d:5f43:0:b0:42b:52c4:664f with SMTP id ffacd0b85a97d-432bc8ed13bls4111129f8f.0.-pod-prod-08-eu;
 Mon, 12 Jan 2026 07:17:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJYdHleArK6peCYOL7KwYHOtihwKzR/gb4QIo3i9WzNVdMmNJuP3QYYvDBpVACab0d3JGxyWzh2QQ=@googlegroups.com
X-Received: by 2002:a05:6000:1845:b0:432:a9db:f99d with SMTP id ffacd0b85a97d-432c379dbbemr19576266f8f.36.1768231020343;
        Mon, 12 Jan 2026 07:17:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231020; cv=none;
        d=google.com; s=arc-20240605;
        b=QtlcrLsitDZ036ZpjfZ0Yeo8ys4UWvxRe7gGqHZGjkPl1XQKT61V2ksmnr2IG2+bit
         1yf21JQS//S2AYQWqCbTNxeEXEnP94ho9qBkdZJ8Pu1A5P9yoHk0Fh2JXJYiGHwYqS49
         ec52w8MJogDnd44haZDBekQnSINj27gAq9O3lVo2YXJxbRR/n7LwpX4DVDiu8pSGLdXW
         5T9uGW/uPq/Kg7pmbZOwfqEM0CB6ZkUbDqjh2vFKGXCzmUAl7vr3uvx7bZbD/XybyYdp
         eYQydQrapz36VVuHaWMjAEMumuG2j8xd3YiOk68kWDnsfJnYDtCXSE0pqM4bkZcdRHs6
         EL1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=PCTJyWwPDFPcWrK4twCzQqUdDfuUWUHIy/bdXFPYDTE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=L1qK+w67S8waAIXcSL2uMIeMQa1uUHJ9/6xkDKO/2rkn8G5ompX8kQM6TkFnuWitNN
         dntVuEYnaF0tB85eZWQ0gqSeCx+S0VVgfTEwwJUkUtXG79/wQpSFmCo3YM4q9NBhLHmq
         xErHNUITdTBcQhC90BegRHj8JAgKTk+2H3NlYRWuSWC13T11nqq9lW7F9dZHebXYeUe0
         HfEF77ZuBFTZ6gGLXxrPdik/wAQc7iS8UmI1s7UUis1yuCaK01vJ7E7lZUGbZ1gL46e0
         NDk3Kl4ymreBdcNMPntrS0+mQMecwBCu8HOiLWKlhlsB5tQVyiJfekHlvAQd2S3ZAwWd
         habA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a50ad8si286743f8f.2.2026.01.12.07.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A16803368A;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 724203EA63;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id eDpLG2kQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:16:57 +0100
Subject: [PATCH RFC v2 03/20] mm/slab: make caches with sheaves mergeable
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: A16803368A
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

Before enabling sheaves for all caches (with automatically determined
capacity), their enablement should no longer prevent merging of caches.
Limit this merge prevention only to caches that were created with a
specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 52591d9c04f3..54c17dc6d5ec 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -163,9 +163,6 @@ int slab_unmergeable(struct kmem_cache *s)
 		return 1;
 #endif
 
-	if (s->cpu_sheaves)
-		return 1;
-
 	/*
 	 * We may have set a slab to be unmergeable during bootstrap.
 	 */
@@ -190,9 +187,6 @@ static struct kmem_cache *find_mergeable(unsigned int size, slab_flags_t flags,
 	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
 		return NULL;
 
-	if (args->sheaf_capacity)
-		return NULL;
-
 	flags = kmem_cache_flags(flags, name);
 
 	if (flags & SLAB_NEVER_MERGE)
@@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
 	flags &= ~SLAB_DEBUG_FLAGS;
 #endif
 
+	/*
+	 * Caches with specific capacity are special enough. It's simpler to
+	 * make them unmergeable.
+	 */
+	if (args->sheaf_capacity)
+		flags |= SLAB_NO_MERGE;
+
 	mutex_lock(&slab_mutex);
 
 	err = kmem_cache_sanity_check(name, object_size);

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-3-98225cfb50cf%40suse.cz.
