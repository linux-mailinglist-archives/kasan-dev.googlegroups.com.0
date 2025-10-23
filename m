Return-Path: <kasan-dev+bncBDXYDPH3S4OBBU7G5DDQMGQETO5EQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DDD2C018F1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:25 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-362de25dbc4sf4495281fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227604; cv=pass;
        d=google.com; s=arc-20240605;
        b=gQ2AU152h6Lhw/ugI+ZLdt3H1M3U+N5ssYiAkWgcDWOx5AfSYN88pncb2q9th+DXBV
         DLaG7Gz/6jAdcYGR+WfLcWGaDAGMeKGKL1z4Az7bmd3qchH9CTAmXrTfKSv1nCnz0vJ3
         Ra8LCUYFfPiTQbyaJ6l87Y0CeMQ03ygLNfS9zH4h7hGOScYlbbmGEAooWL9NEMM7RwS0
         g98jdh/3NXhg6ZdMsLGl42UkpoGAPGKKYQbVTjthY9b4zqs5wIZEdFX11U7ZGrnoK5uH
         itj5wMsbu8LlmzRGiiyl/8ja/KxP/LrLpkBH6Y/E/gbX/yR5lDJwTitZ8bLS04LfitQP
         ENCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=whXDvmpDzbnbN50zRtZ5tXMtehnqCaOAI+svASV/R0Y=;
        fh=29Cff2fTD1dCMpYDlCJ5rJm5Qg/9LuBOZBY2S8PK/Xc=;
        b=UckkP/QoCzbFoVApjQDanUAtdsgoc7OKMTvhdg9GBaZGHz72tm/TN4bJjzR2L38YP5
         AJ4sLY9ptnwq5GZlHC42mNTPytWXLMmZnoAsw/iOkMhLK2G8+G8ia96uwlZKjGV2SQpc
         lsjshMaC5LBubaMBznpaZwuJdEAjRM3gTHRkV3yErkFJYGtgM46AK7iee7jpE8Ydhj/5
         6wvbESyTMRvhwin76qa8+c/k2pywgM/wvMO4Em3W31b4eKOZgw/gY5+D3+FSWd8gjbQe
         dNF/tMk852CNsMcUsWxUtoK3cbatx84iCSqh6bNoa5Xa8C2guUT5046EApn38i516haw
         Luzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YQw5bU+Z;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="N03/pxcX";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227604; x=1761832404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=whXDvmpDzbnbN50zRtZ5tXMtehnqCaOAI+svASV/R0Y=;
        b=Ixgag1PCtiJn58+Tg91DRHlC/LdQR1uNLvr7la8KXFUJ92iCSOt0+ihJCmDD/gWAvX
         D60bloWWnmQQrcurwjN3X/4W5REPgEgDbayo0xPKFTXM29aLQLudk6nFInrvxg+JkWse
         bS/W1Y4adGxpUz08GedXjGoJHI9t9uwt1CMQLRzOyR1hOi46DlNemPZuFfapaaWmEHNC
         +iADva4kV1jpX2BsgDXd81rNirxnG42B+ckiAiMFKOy2VSnqenKox9Zl9013U2VLmISX
         yEQ1272yCZD04JAjwnXNL5YGlDWaJopxycFD4+IH20uCx7HLI5y179ctdD4LAuyXKcRs
         iN1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227604; x=1761832404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=whXDvmpDzbnbN50zRtZ5tXMtehnqCaOAI+svASV/R0Y=;
        b=BLE/iNij+3vJSgJGeXRS41BQzYb0Y/t0of54Gh+JkZAtt8PxQHMlMZ9jhh86Uet3nN
         y0heRNZ+QLJbT7PtuuWez3ngWOlYHOM53o8xonGVqzHbjybuvI0ooTIOz9+QWSePt4ek
         fpd6MUeBA0PEqnq6wmxqa8xJ19yUiHgjh88muwCnphIqsjhqnkx/36w//HIND0f1S3Tw
         5RwzXEmJstJHiiwaluMm2U1YypBI2Ej5bV7+kSt+rVkdKGIjisT6D7i3izSYq9GvioW3
         q+Ulb96iNHBXI2bjyqtJ/ckI4Vi4SROGk0eVOm8D0dEdc57anfzZeNcmMVSaKYdmvGtW
         eOGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURvfO1tVsdCS4r2wlmbKCFxobgrnlt5+IP7HB3WZy1k1mMGHipJu2VpDnN2xvosvqWk8UYZw==@lfdr.de
X-Gm-Message-State: AOJu0Yxl/V/uyvCGwz9KIky9HDUOGbod1ymXaxQcHEUTtWklX4rjH45S
	MMLEEkaJHPir/UXpe4zxQGIsRg6trgnocy/wZPdxd5KxL37Dm5lwLAYh
X-Google-Smtp-Source: AGHT+IHh3III4dYqGLzGIHTpvxFF6er60ce0NXTQZEuzq92w7zBq5Z9ivQeDYRKTrjn7XPXvgzzrJA==
X-Received: by 2002:a05:651c:1142:b0:36b:693d:1244 with SMTP id 38308e7fff4ca-37797a0904dmr63813241fa.30.1761227604386;
        Thu, 23 Oct 2025 06:53:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z7Qmduhpr6IMkJenn/0FNWWOkE5DAfvw96NSMYf+9pxA=="
Received: by 2002:a05:651c:40cd:b0:336:c2ac:cd28 with SMTP id
 38308e7fff4ca-378d634a59cls1074281fa.0.-pod-prod-05-eu; Thu, 23 Oct 2025
 06:53:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbL0RRNqsHgCl6YHI5NbKjH968hJZH2pyGh5lD42TgM0UJ49XwpMYjHakbCKzshY/QsNEyegjWLW4=@googlegroups.com
X-Received: by 2002:a05:651c:1593:b0:364:f830:230b with SMTP id 38308e7fff4ca-3779793f476mr73832651fa.22.1761227601590;
        Thu, 23 Oct 2025 06:53:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227601; cv=none;
        d=google.com; s=arc-20240605;
        b=cxohQXQDqQXafjVjzznuzrKgb/KHeYzIOj9Uy04bzJl2EmiXj8dVnvw4YPY5LnaWhQ
         4xEIyShO6fEB+Ti2PzesiiM+akoDnSNkuytu8OD5iNKVuuH2naKZBaGmcGspATsGyjjQ
         Oj4FYExyOl9EFBIWQAdJVXZ+XhPMwSEyMD0cz4d75OaEGP6eF0sHpepes97Bawtb7xCH
         ImNAjihv3FwY6LCuINCvp5OXI/8+aD1+inZgkLiN9hi8OsSQJ6z7lw1HuH1W0htCnT1W
         4U8wfD2xM6bsYlBd6Z5UCr6NaRkWarVWpjMm05+lOd2/K4ggYFL5C2Hbe7ncjMd3dNoO
         rUiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=nBqIeAt8PqOShiWRW8bX5+U1W1IZCUvUQH43Nd+h/zE=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=fXWdUE3Y/p4Go99CUn/6ucHhK5awoUD5/G+PtVRiKBIjcM6e9o5juIKxQ/7BqDSnNl
         4+NUN9QCdBlXPVsh97R+4kWCzdX/mAwdgDWExNYRst/x4kLBiFniCQ8J5VWXXa2b2x20
         tDW9o6Vejm0pqLdFhNvjwmoVwAas5CqqjdrKmEmpAERLvUlliiXzlFLh18g/W5fs9TlD
         iwsKuh7bKJ4/Taw4VBEPs8j6aOUkWuT2MHZWudNhrYijWtmz1mGYrj6LdEsjIyFJl82X
         TQDkw/aanzXnWu81sGSKrrqaNJT6P0As901Is6YCYuP1IPmjzx454SmkDHTlQIf/bGuc
         ELGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YQw5bU+Z;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="N03/pxcX";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d66942bbsi400181fa.1.2025.10.23.06.53.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A4D8F211F6;
	Thu, 23 Oct 2025 13:52:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 79A9413AEB;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AMNqHTUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:27 +0200
Subject: [PATCH RFC 05/19] slab: add sheaves to most caches
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-5-6ffa2c9941c0@suse.cz>
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
X-Spam-Level: 
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:email,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YQw5bU+Z;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b="N03/pxcX";       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

In the first step to replace cpu (partial) slabs with sheaves, enable
sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
and calculate sheaf capacity with a formula that roughly follows the
formula for number of objects in cpu partial slabs in set_cpu_partial().

This should achieve roughly similar contention on the barn spin lock as
there's currently for node list_lock without sheaves, to make
benchmarking results comparable. It can be further tuned later.

Don't enable sheaves for kmalloc caches yet, as that needs further
changes to bootstraping.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h |  6 ------
 mm/slub.c            | 51 +++++++++++++++++++++++++++++++++++++++++++++++----
 2 files changed, 47 insertions(+), 10 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index cf443f064a66..e42aa6a3d202 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -57,9 +57,7 @@ enum _slab_flag_bits {
 #endif
 	_SLAB_OBJECT_POISON,
 	_SLAB_CMPXCHG_DOUBLE,
-#ifdef CONFIG_SLAB_OBJ_EXT
 	_SLAB_NO_OBJ_EXT,
-#endif
 	_SLAB_FLAGS_LAST_BIT
 };
 
@@ -238,11 +236,7 @@ enum _slab_flag_bits {
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
 /* Slab created using create_boot_cache */
-#ifdef CONFIG_SLAB_OBJ_EXT
 #define SLAB_NO_OBJ_EXT		__SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
-#else
-#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_UNUSED
-#endif
 
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
diff --git a/mm/slub.c b/mm/slub.c
index f2b2a6180759..a6e58d3708f4 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7810,6 +7810,48 @@ static void set_cpu_partial(struct kmem_cache *s)
 #endif
 }
 
+static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
+					     struct kmem_cache_args *args)
+
+{
+	unsigned int capacity;
+	size_t size;
+
+
+	if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
+		return 0;
+
+	/* bootstrap caches can't have sheaves for now */
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return 0;
+
+	/*
+	 * For now we use roughly similar formula (divided by two as there are
+	 * two percpu sheaves) as what was used for percpu partial slabs, which
+	 * should result in similar lock contention (barn or list_lock)
+	 */
+	if (s->size >= PAGE_SIZE)
+		capacity = 4;
+	else if (s->size >= 1024)
+		capacity = 12;
+	else if (s->size >= 256)
+		capacity = 26;
+	else
+		capacity = 60;
+
+	/* Increment capacity to make sheaf exactly a kmalloc size bucket */
+	size = struct_size_t(struct slab_sheaf, objects, capacity);
+	size = kmalloc_size_roundup(size);
+	capacity = (size - struct_size_t(struct slab_sheaf, objects, 0)) / sizeof(void *);
+
+	/*
+	 * Respect an explicit request for capacity that's typically motivated by
+	 * expected maximum size of kmem_cache_prefill_sheaf() to not end up
+	 * using low-performance oversize sheaves
+	 */
+	return max(capacity, args->sheaf_capacity);
+}
+
 /*
  * calculate_sizes() determines the order and the distribution of data within
  * a slab object.
@@ -7944,6 +7986,10 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
+	/* kmalloc caches need extra care to support sheaves */
+	if (!is_kmalloc_cache(s))
+		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
+
 	/*
 	 * Determine the number of objects per slab
 	 */
@@ -8562,15 +8608,12 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
 	set_cpu_partial(s);
 
-	if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
-					&& !(s->flags & SLAB_DEBUG_FLAGS)) {
+	if (s->sheaf_capacity) {
 		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
 		if (!s->cpu_sheaves) {
 			err = -ENOMEM;
 			goto out;
 		}
-		// TODO: increase capacity to grow slab_sheaf up to next kmalloc size?
-		s->sheaf_capacity = args->sheaf_capacity;
 	}
 
 #ifdef CONFIG_NUMA

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-5-6ffa2c9941c0%40suse.cz.
