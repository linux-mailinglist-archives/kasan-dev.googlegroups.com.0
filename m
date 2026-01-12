Return-Path: <kasan-dev+bncBDXYDPH3S4OBB45ASTFQMGQEOH2JD2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 71D49D138DB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:08 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64b8a632dc7sf8690780a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231028; cv=pass;
        d=google.com; s=arc-20240605;
        b=kzNh+oIZehMk8J9WzipGQ9xIgWQUP8X70WVKTC5LUoeIp2wXO13A/9NlJ/GH2FpOKK
         oN2Qpabv6tpsG7xClirzF+0PmzVzYeF0nFHC99Ho681QlrmnFhE5njErfgfusN4+m16i
         b3nXZrQ/OQZ0gHbAm+0L9okDjV0ltTLWke3fscokiBeo4FSfo5CffnjjNAHajjQ7PWTR
         KYW6YW3ayKE7LIMQyYRK4cj+Jx4Wn92SA0Qf7m7Zy+2WoYZltKzSiw4kTBpM3CpSOjZl
         OptfgYueGkN7MEywgoePLZE8yAlSb0mmqPlKv4l6bHQcwOrL/qC9Ti7o6Al6HugEwW1B
         EOPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=MLEi6GUu0LgUjoEc4foOVhDOoXoKCxaI8QuJIpo2HBk=;
        fh=EnSDN2iPyTd1LLo3zRcvBOATsnPuqXVa4c1xaofaSDA=;
        b=k1aQ6eHBHYCX0DBtqUGPXfAvLL4giaG/vHaMjsas62zKUOy2UYEuoOgE65C+0gK8/4
         h/z8QcmOvAG+ZLxZlb3koR2f/Gtz2D7LTkhPZjIAyZ1voAib0yG9xn8E97uboueDiArn
         viyYycFOwot5XqjEF/rgFSsg3nSV+MrQXPHYugG8Un09vpHBd8fL7JpDJnzeGyTbEsLv
         IGpoO+MjwHHuBdeaZyP7n6Y7yYrcAJZ7OSLHHoIXK86ZRaJ11oc/QZuCRo1aPU5KND/v
         VB/4t0qZFPBK4ZleUXI4KNDyyP9+cI6vTA4KOa7K44r471kWLHKyWNK2xxPHbAA3fT9l
         4CCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231028; x=1768835828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MLEi6GUu0LgUjoEc4foOVhDOoXoKCxaI8QuJIpo2HBk=;
        b=EJkp5fc6R8pH3uLq6ighY7GOI6EKgonQt5k43oHJCPtsQmVeXrEnO9x3kNTo2I8rtj
         T/kl1ILxcduj4+Pa/SVkLgydr0F1+oib3eZ/xJjahv/7XiCW7Kr3/86og0iwP+9O1psK
         GnzvsBss/aTrM6TEnNmxOGv9EyoFRRZ/+qw1AzC4QUGIjKjd051S62Q4gZLMHIG2CyuE
         RimpDD8xB5AQkcgGkb18CBeb8L2lmNa4zo75966s04nIfr44XIsOptVrISrPt3nhl3qy
         siat2Dw+ND+NfQRgFTeAqeYmwQwQeCzGBT9mLThXbjknlyj/7A80vvoMTWaZHOpZAL7Q
         sKvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231028; x=1768835828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MLEi6GUu0LgUjoEc4foOVhDOoXoKCxaI8QuJIpo2HBk=;
        b=DLxzMGq4HwewLtt1wTivb0phYMAmRbHdtUS+n0EKQczDMuOXLS71S5p35JY2UV9hvC
         wW+2g/gTNzeOzARkon6UMcRHaI8TmcwRdFe0AzUzit3Pvqnmywf/M2/IrW1OrkzMG2Ke
         UEafmog6vn1lGLv3x46SlaO+uBITvzdZEHysyN2pY7Y2/zpS3TZGNznVk2jpY9KpM2Fw
         QXiHbCU30bBV3SwI2hR2Qqu9jrE/wWC+xPW01YYqIxFwZ5AinMaEfXMuRESRO1o0L9J1
         mu+tOI2Anu0geRN46XsEr2SR7KCkzs5TP21NABXZciV990Vx0F8QD+I+w4VC6Jzoc6Ho
         mQ0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnuZ6R/KbJ0qs2XXTEDqulkPCOE5qhrlU+0+1RRmdwjUHiT93CTHSjcjWXdqh/ao81tseBNA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5p9J2sgRoZAN2YOTb8h/H13aOJ65zZ6Oja+38DhKMRBiK7kY/
	ibe8hhfqdvDXvQOZLgiGQ0c5FBLE9/vrjhGa/nAdhSYdS8DqXGFOCjYW
X-Google-Smtp-Source: AGHT+IHRM09s10WWA3e3npnH81laPXHyBFGETPnolcjCL1xugCgLJKR8kT3/+Tu+qYv/1OdjTVDTvA==
X-Received: by 2002:a05:6402:26d0:b0:64d:1f6b:f59c with SMTP id 4fb4d7f45d1cf-65097e6e379mr17466739a12.32.1768231027532;
        Mon, 12 Jan 2026 07:17:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GBbsEjdvVeOm1FaLplKyul5j1bf/USK7HTYQNw79gF5A=="
Received: by 2002:aa7:c487:0:b0:64d:faf4:f73e with SMTP id 4fb4d7f45d1cf-650743340b5ls5792026a12.0.-pod-prod-05-eu;
 Mon, 12 Jan 2026 07:17:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWm8paP5lCCFF+hksvKgYVC6OIaPOluB7im4izeCKXPSmnihPRTOQx+usFnlF3sLmamLnnbNv2LMaQ=@googlegroups.com
X-Received: by 2002:a05:6402:51cb:b0:64b:9fa4:ade1 with SMTP id 4fb4d7f45d1cf-65097df569bmr16578368a12.14.1768231025431;
        Mon, 12 Jan 2026 07:17:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231025; cv=none;
        d=google.com; s=arc-20240605;
        b=R+l45K9gwY8VpcI5uT9yAbj1Mv3zznr92RbeeNwWYm5Xs8YkJmYp9pM2VH/0fTIvHQ
         p85Jm8lovSHBPTSEBOEvp7MUW6xe15VAszG7k9CBATw6kDao+S6OlEGTtPWTEaT6B3Ou
         FTmz2j/N/AMD2BOrt1DsJYyqLyJZKc/PXWOqiWIZBHmKw3grC98ElZYEd+kmxZATrfuJ
         Mk98cGcCSjVM55yCxkkXAghcHTyfj3h03r14BkjRfFjTw9FL7uyXKbfE3s4MrpYrGJ/l
         eK+zL4WC/gGthYqxA78qKQFHMd61UJmd+RdtbdYETzLQZbxl92WxdUcO8Zge64lhku0M
         vOXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=U2g8lMsPgMhUe+Zak9uNfJ1KurP7aWlEZWc/PUq01OM=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=kCusL5mG1TC/5piP0xpNCRis4S/3CdhvChKNtXA+0RL8QuIMyhRm4PQV0TOkxn53uC
         EMLmKbtdUHzPhDlwRf7F2sYrE8EFMStV/hOrlLW6g0kg66kEaBmYtsC4D96S9Azubx8a
         5iRCZfXgAkwT9khMnkYBNw5Z5Bv3rjgwkPvQjeDimrEGPUTWcXAipRTNlKtHs7skJI+M
         EQ7OPuJS0UOFOqGK88dMnOO6nqJEqyW5Z0/qxX1t/Y34z/TM9yUaMg3lB7H64zYkFT71
         t33Hx74PXYserNUVi6rk18rXnNA7+lo2epJeLoxs0BGw9b3Gydn740jt/kbCcSUcVUJ4
         g/7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508cf31221si275804a12.0.2026.01.12.07.17.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D5F8B5BCC3;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A0A423EA65;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GLLIJmkQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:16:58 +0100
Subject: [PATCH RFC v2 04/20] slab: add sheaves to most caches
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
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
X-Spam-Score: -8.30
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MIME_TRACE(0.00)[0:+];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HkJ5ezc7;       dkim=neutral
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

In the first step to replace cpu (partial) slabs with sheaves, enable
sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
and calculate sheaf capacity with a formula that roughly follows the
formula for number of objects in cpu partial slabs in set_cpu_partial().

This should achieve roughly similar contention on the barn spin lock as
there's currently for node list_lock without sheaves, to make
benchmarking results comparable. It can be further tuned later.

Don't enable sheaves for bootstrap caches as that wouldn't work. In
order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
even for !CONFIG_SLAB_OBJ_EXT.

This limitation will be lifted for kmalloc caches after the necessary
bootstrapping changes.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h |  6 ------
 mm/slub.c            | 51 +++++++++++++++++++++++++++++++++++++++++++++++----
 2 files changed, 47 insertions(+), 10 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 2482992248dc..2682ee57ec90 100644
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
index 8ffeb3ab3228..6e05e3cc5c49 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7857,6 +7857,48 @@ static void set_cpu_partial(struct kmem_cache *s)
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
@@ -7991,6 +8033,10 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
+	/* kmalloc caches need extra care to support sheaves */
+	if (!is_kmalloc_cache(s))
+		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
+
 	/*
 	 * Determine the number of objects per slab
 	 */
@@ -8595,15 +8641,12 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
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
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-4-98225cfb50cf%40suse.cz.
