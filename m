Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4E3VHFQMGQEMTUXGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 90B9BD32C5A
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:50 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b78ae5ab2sf1268690e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574450; cv=pass;
        d=google.com; s=arc-20240605;
        b=XA8ZKBLTQHxfuazoinPrMlpkClAAiSRe9GrOUIZP0OZGci3VKbgBtDTIwEX2KVQkql
         GWNtPZCmoLFo1redcRbRP9Bp7eLdD0e560N1GBGQ393oAcEjWUvsLCLx8iee93G4dFpA
         dp0+ucrY+2NTSFeBf3NDvfxMrz6fe3P701DyJiyeRF2t4VKqSdbTzrprWgrpZ+Tfveob
         kFLOLyYUp9F6hyYe6j6TQEYyc6NzBFW8K9s6ota89egv0cWKUgb1XPscdHPIvfNHCPpz
         vremH4r6C/gHp9CGvD1bvpA45UflTIAMcJwPUTAv7XhSJ3VhroTVLUzwFR72WFSmcvNJ
         wWyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=LVvi659CBSA94cjkq91+Xqidn55mOXob+l2ZMD+1g3c=;
        fh=UNUEjKppScgQKfsktitGLGStG5R+0evvqvcwLTiZPLs=;
        b=LvYvwHRgP/jTXnbG2On6DGZjZliq18QgrrEMT/irfNyG0h7YJcK2IPrdzsldCMwXxf
         O4CEWwwPVbBVEP5MHO7WlScTKqrM69HKHQkwCilMSbSPoLNuenfXa4A36jC8fwyTNzqN
         Co6bIQyoTTmPpgMn7uhSXJ1WZ9GvM9BUR32uwsE7lGvmR7ZV5+S/sLTQaDM2SulmrlWy
         bIcIgRBIJobmXLpdDsGLYoSg7BYY+1mr/+vvznKeXKBPhuE/r1As7nOaTARANS71Ibc4
         I0jbtiBjt0ACPRh8QLG+E/0Vox8SFi56uzhV4QfQTjNUXpH2d4qof2KtWQ5Qk1tf9Iua
         +l5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IjRAZpDJ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bHTXKLTC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9axPLR58;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574450; x=1769179250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LVvi659CBSA94cjkq91+Xqidn55mOXob+l2ZMD+1g3c=;
        b=JN8YzGHu8jinMj52NSMudp45plye+9rJnQ+FxlTKTlt3nPhz2ZdDB7SEMBHUtwjS7f
         liRIblTGTzmC2V22Pj4hbmG6YKsG7BzzK9tuXN7PQJHd+H26UIT/GxmvL9ny5IOn3sjT
         ZybpKi1aD0MTUAkiKQU03SmyT+9/tHGbXJ+l0HW36iFM2ANqFZDRdg905MwZA68lvlKO
         3yTjNpSNkbr5PX8gVdKO4TFW34BY6WCQkF9kYIxA2SwriGUBeiAYPhVDGXarT+All0Lp
         Qv3JufnvnrnWJpQdpAqvkQBxoqVoztx/xYd4yTXgVSdQYOsXbqI+wQyTgJ5s8OYiaQzr
         xYxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574450; x=1769179250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LVvi659CBSA94cjkq91+Xqidn55mOXob+l2ZMD+1g3c=;
        b=Dn6jQ1RCZ8092HIRXvuQCOL8r4AwbjLVikz0bT8swegwiwgABl3iNcWc+RsaI1UXgR
         fy81yRGm3XG7MHEIZ/JfEz//T3jD51RUFFXlL7knzzmxV0jA1fH51Ycgp6IlhMbirvKG
         uP9tu0enbbFVHxYyooS2NBxWYNe4GpFHeG6ybtv6KmIMKRb1cIgLx2gFwKMn1EFHtvA/
         IEUbqCOBORXaHQk4qGQ1sZCW6/Bepumh7QonaeJfYTjLwH1Fi3zfrW+RhQPQF/VsyWQa
         YcR8EKqBgvebXqyNaET5c22FmRW6fRsYPOBWW5eF07aIkWDjw9GTHgwkpvamnIBuSgfo
         RvBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIkV62eXnI4P7ck5S8iI7FQEWeHh80Dg+pTVVSaqabaC8emFE76k0fmuiIlw4vjJ4oeWiRuw==@lfdr.de
X-Gm-Message-State: AOJu0YzUV+0kTpC6TK8XR8SfM0wnecuNKe8coCISpUcjnAoHW/whtmWv
	e4uBR2lgzoxCedNQouOuqvmH3rATKfR4UybEt9KHKe120iXNN/3T1jjl
X-Received: by 2002:a05:6512:3d02:b0:59b:7319:1177 with SMTP id 2adb3069b0e04-59baeedfd78mr1097287e87.38.1768574449492;
        Fri, 16 Jan 2026 06:40:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FlY2Qegt77haT993iGeDLFmrVcZek5JLfZAhczaoFwow=="
Received: by 2002:a05:6512:3d19:b0:59b:7a7f:906 with SMTP id
 2adb3069b0e04-59ba6b44a49ls875542e87.1.-pod-prod-09-eu; Fri, 16 Jan 2026
 06:40:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAmD3m1zxmDNSIGAKYtVN1cZGSNSPIc7CH60atM+BIf71tKxofvZuUfN4AUQzhKXXjCpZ5ku3RqnU=@googlegroups.com
X-Received: by 2002:a05:6512:23a7:b0:598:f1a7:c70a with SMTP id 2adb3069b0e04-59baeed6320mr1154526e87.30.1768574446737;
        Fri, 16 Jan 2026 06:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574446; cv=none;
        d=google.com; s=arc-20240605;
        b=SpzQ06m+hxW1x4MAuiZulGBv1rWCNLCKCNecfAR2uNEV8qLFI8N0Wg6/HYseVt+l75
         1tJcQ2NuGJbfe6WhdE4mHDusigsHXtC3l1Rk/mroAN+U85E33uciUankTpcWuzVA3sxe
         Q8m+XRzg6fRfAipH7+rLJOzWuNCaf0WEgRrD3oGCWAYeyFw373iE0KkQBA1QPjc5sj6/
         jNlDNYDWWCi6w8F433wufHyDsI1WUNix7QfMofAUkL4jkUU9zLr0V+OG4EEWNGeR4lH6
         ooA2s3W39SD0P3dPjLse+b/zubJptaDLPa1a1PF6zX29+qMa+iUVG/tbAauyy56cWhgy
         8Q8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=8NQimX2qnHyu3iifkMxRzCZm5f98wg6UoDIBK4sRJ+Q=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=HqY5uthsoQsu2voCq2XJ1CP7TLw2imPGsG9xe1A6ERSy+dsvIBEtraeXwroxp7MYpK
         7IOfGYPH3J1Dk5RkTZLCXrfc2lbTLq8I0GYQJeuc4QuBIoqSu9lfumyb/Cb0VnrutYh1
         F3hcOW2QUdM6rMmX1W7SVX+MfAUW1hMOBO/jCsBHpICAUJg6QbCLpB8DzTj6d6A3pvj3
         cpjxJECwe0V4MlET40EsS8OrBXU9ifmqOU7KQSEh7gjJCqtAKKUTdG7irLy7HXGE5irO
         A5kreZcfEdO/+JbNbjL8qoit6dLIeECoYGIDCTycwK1w3QDgsIy6Oe134Hx3C9YE7e47
         nMkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IjRAZpDJ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bHTXKLTC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9axPLR58;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf38ed2fsi44344e87.4.2026.01.16.06.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E79D3337F7;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C5E313EA67;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ECUEMORNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:23 +0100
Subject: [PATCH v3 03/21] mm/slab: move and refactor __kmem_cache_alias()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-3-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
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
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: E79D3337F7
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=IjRAZpDJ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=bHTXKLTC;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=9axPLR58;       spf=pass
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

Move __kmem_cache_alias() to slab_common.c since it's called by
__kmem_cache_create_args() and calls find_mergeable() that both
are in this file. We can remove two slab.h declarations and make
them static. Instead declare sysfs_slab_alias() from slub.c so
that __kmem_cache_alias() can keep calling it.

Add args parameter to __kmem_cache_alias() and find_mergeable() instead
of align and ctor. With that we can also move the checks for usersize
and sheaf_capacity there from __kmem_cache_create_args() and make the
result more symmetric with slab_unmergeable().

No functional changes intended.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |  8 +++-----
 mm/slab_common.c | 44 +++++++++++++++++++++++++++++++++++++-------
 mm/slub.c        | 30 +-----------------------------
 3 files changed, 41 insertions(+), 41 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index e767aa7e91b0..cb48ce5014ba 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -281,9 +281,12 @@ struct kmem_cache {
 #define SLAB_SUPPORTS_SYSFS 1
 void sysfs_slab_unlink(struct kmem_cache *s);
 void sysfs_slab_release(struct kmem_cache *s);
+int sysfs_slab_alias(struct kmem_cache *, const char *);
 #else
 static inline void sysfs_slab_unlink(struct kmem_cache *s) { }
 static inline void sysfs_slab_release(struct kmem_cache *s) { }
+static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
+							{ return 0; }
 #endif
 
 void *fixup_red_left(struct kmem_cache *s, void *p);
@@ -400,11 +403,6 @@ extern void create_boot_cache(struct kmem_cache *, const char *name,
 			unsigned int useroffset, unsigned int usersize);
 
 int slab_unmergeable(struct kmem_cache *s);
-struct kmem_cache *find_mergeable(unsigned size, unsigned align,
-		slab_flags_t flags, const char *name, void (*ctor)(void *));
-struct kmem_cache *
-__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
-		   slab_flags_t flags, void (*ctor)(void *));
 
 slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index e691ede0e6a8..ee245a880603 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -174,15 +174,22 @@ int slab_unmergeable(struct kmem_cache *s)
 	return 0;
 }
 
-struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
-		slab_flags_t flags, const char *name, void (*ctor)(void *))
+static struct kmem_cache *find_mergeable(unsigned int size, slab_flags_t flags,
+		const char *name, struct kmem_cache_args *args)
 {
 	struct kmem_cache *s;
+	unsigned int align;
 
 	if (slab_nomerge)
 		return NULL;
 
-	if (ctor)
+	if (args->ctor)
+		return NULL;
+
+	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
+		return NULL;
+
+	if (args->sheaf_capacity)
 		return NULL;
 
 	flags = kmem_cache_flags(flags, name);
@@ -191,7 +198,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 		return NULL;
 
 	size = ALIGN(size, sizeof(void *));
-	align = calculate_alignment(flags, align, size);
+	align = calculate_alignment(flags, args->align, size);
 	size = ALIGN(size, align);
 
 	list_for_each_entry_reverse(s, &slab_caches, list) {
@@ -252,6 +259,31 @@ static struct kmem_cache *create_cache(const char *name,
 	return ERR_PTR(err);
 }
 
+static struct kmem_cache *
+__kmem_cache_alias(const char *name, unsigned int size, slab_flags_t flags,
+		   struct kmem_cache_args *args)
+{
+	struct kmem_cache *s;
+
+	s = find_mergeable(size, flags, name, args);
+	if (s) {
+		if (sysfs_slab_alias(s, name))
+			pr_err("SLUB: Unable to add cache alias %s to sysfs\n",
+			       name);
+
+		s->refcount++;
+
+		/*
+		 * Adjust the object sizes so that we clear
+		 * the complete object on kzalloc.
+		 */
+		s->object_size = max(s->object_size, size);
+		s->inuse = max(s->inuse, ALIGN(size, sizeof(void *)));
+	}
+
+	return s;
+}
+
 /**
  * __kmem_cache_create_args - Create a kmem cache.
  * @name: A string which is used in /proc/slabinfo to identify this cache.
@@ -323,9 +355,7 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
 		    object_size - args->usersize < args->useroffset))
 		args->usersize = args->useroffset = 0;
 
-	if (!args->usersize && !args->sheaf_capacity)
-		s = __kmem_cache_alias(name, object_size, args->align, flags,
-				       args->ctor);
+	s = __kmem_cache_alias(name, object_size, flags, args);
 	if (s)
 		goto out_unlock;
 
diff --git a/mm/slub.c b/mm/slub.c
index df71c156d13c..2dda2fc57ced 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -350,11 +350,8 @@ enum track_item { TRACK_ALLOC, TRACK_FREE };
 
 #ifdef SLAB_SUPPORTS_SYSFS
 static int sysfs_slab_add(struct kmem_cache *);
-static int sysfs_slab_alias(struct kmem_cache *, const char *);
 #else
 static inline int sysfs_slab_add(struct kmem_cache *s) { return 0; }
-static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
-							{ return 0; }
 #endif
 
 #if defined(CONFIG_DEBUG_FS) && defined(CONFIG_SLUB_DEBUG)
@@ -8553,31 +8550,6 @@ void __init kmem_cache_init_late(void)
 	WARN_ON(!flushwq);
 }
 
-struct kmem_cache *
-__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
-		   slab_flags_t flags, void (*ctor)(void *))
-{
-	struct kmem_cache *s;
-
-	s = find_mergeable(size, align, flags, name, ctor);
-	if (s) {
-		if (sysfs_slab_alias(s, name))
-			pr_err("SLUB: Unable to add cache alias %s to sysfs\n",
-			       name);
-
-		s->refcount++;
-
-		/*
-		 * Adjust the object sizes so that we clear
-		 * the complete object on kzalloc.
-		 */
-		s->object_size = max(s->object_size, size);
-		s->inuse = max(s->inuse, ALIGN(size, sizeof(void *)));
-	}
-
-	return s;
-}
-
 int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 			 unsigned int size, struct kmem_cache_args *args,
 			 slab_flags_t flags)
@@ -9810,7 +9782,7 @@ struct saved_alias {
 
 static struct saved_alias *alias_list;
 
-static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
+int sysfs_slab_alias(struct kmem_cache *s, const char *name)
 {
 	struct saved_alias *al;
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-3-5595cb000772%40suse.cz.
