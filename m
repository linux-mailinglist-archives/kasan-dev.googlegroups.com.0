Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4FASTFQMGQESTWKJNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B63E2D138D1
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:05 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-477bf8c1413sf43988655e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231025; cv=pass;
        d=google.com; s=arc-20240605;
        b=RMstZ/85oi56cOAC08TQJyPJehUzc4REMKDzZoNoRIQ+JA0IeuorCq7jH5CJ44AsKL
         LUdOxBlCyW7qgFwS7OYBDwvgBPOjgd2SEKuTv74OK/T7OmRLzPhwPYlozusv02q0TT2z
         8nG9YVrf6fU+ojLGdQqrI2JFHbI92X49Px4d+ChgsoZs9w+E25/yUwmihA42PmBnKGCA
         SKCcL6HOzJOyAnucVSD+LDnF2LZttsGGd/cTojI987/WUAlyK0ZqJIy5d4lVDWRbNFT/
         kEXhQ3/fqRq+q2a6bt3I/rGR/Vr3b68/JCRU+UMJZjHT9Mry7l0xH2xl1WdWN2eCixvA
         wHiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=nMPHuT/MIEMtexhx/Z7ZkJti5tvnr5mTF5mRRY2ee18=;
        fh=0Viqx+VhyJESVGOC0/OEY3wOi54AKOAx/Kx5U4ZIkaY=;
        b=J9k6iJFJwXUgXsIQ+S6ZbxVEaEbT2gcJBSDKOYQyGBJlK/5TKLqg0vNJoGqbSFrGSz
         ch9+YXRyfTQyLG6r/YKun8hU8V41QrWq50r0dxMqVriQA49vqUb7GAPbHpwvXDJUMaOQ
         rSuAP5Th3baZ//w7GZ5m3RYZbMp7S3EdPa4T/3RGQLtBMqIOlfc1HK75ArE2mZmtiFeE
         +DeecTLM9DX0OzFcgFXY+BZZq3haPeDx0MtQ97ush7hFmU6j8x5KkSsHMt6tr5qQHqhs
         E9Vx/4fuqM3DhUqox6N5ycguYIN0BdcFCBvsO7wwy/NmLtT7A6H/LhXZHD53K+DT7Nf0
         tRFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;
       dkim=neutral (no key) header.i=@suse.cz header.b=xJ2UPpG5;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231025; x=1768835825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nMPHuT/MIEMtexhx/Z7ZkJti5tvnr5mTF5mRRY2ee18=;
        b=WeKT1NDfms3hGiosjWHzfXr4HgEbasE7Ws3EMC6wL0guPP6LzgIU84NOdMrTOkVCD0
         Ey1RiaxLpiBfjv4xobcxWdVsbxOUqrOWuTSxZV/xA79ZkaLh7qFXoQlgjgM3iaT2ZTRj
         /a26ObFMmLaMO5efFEQM08QDSUTevge7WJr8o1xLd3tK8TYU/Z4A3ODqxPZJVvyVEh4F
         EZokJmTLI//kmjjQhF5R3HL4+QFGGcSgANdkI7BxwAKZ6nXJMkyWQa2F8rJ0+zET72W3
         2UdNJavC9lF3l+yZ08oylCV8pLosia48rRyUOFH9kKBd3IUbqGR9j3+p9p+gwbm0FoU6
         vKBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231025; x=1768835825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nMPHuT/MIEMtexhx/Z7ZkJti5tvnr5mTF5mRRY2ee18=;
        b=XmuW508powexWb5avbfwUATg3H8IuPXc3pK7Ka+ca8BbpOIjGd9j6wTAhtNSMPjMo6
         PbIHS5PqNuotFFkuGL732BcPe9Bimq2atduN74nv2VA1bhz/oG79kMZK//3CUV3Qnw/l
         GaTgIHjvkHMC9ehhOw5074++QD2uN4bOymNTDrLRRUvuBh+GcIQPqOKnkbEaJ+o+UrBO
         YPMrYfSJ0us/UT8b4c6JWhYa0Dj9G3qbSYlWXcKmpQJtfn++8cCRBkRWWhXGTBWDRq4k
         Bh3TQdWzX4I18US9Is0WtKbPtZWXlp2A7Nz64+nMW7/8fM2E6EG0LwtBBLwFZxRJNM4m
         ImSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRDohKX3BLqBAElPtA1Kz3Hz8UGeO5QTxMuY2HluEqiVd+mmjlI2gfhqsQKbAxTHBQlZTyiA==@lfdr.de
X-Gm-Message-State: AOJu0YyR8rH8z2M7aQKCzrd7rxOmRAiGoCcl5me+g+Atk/NdTj2q0UK/
	t9nmX+biGqG7/ZgPyxt7E9KXwa93fq8MfYrUPGUBcyC8V8FQWckDZBVg
X-Google-Smtp-Source: AGHT+IGvUN4/17gKeMd16DLhDlY9cQ3iwttkwSNd6TgE/xjQbZLY5EhYksaLymj+6iwfQ+8O6dfbpA==
X-Received: by 2002:a05:600c:1991:b0:477:55c9:c3ea with SMTP id 5b1f17b1804b1-47d84b40aa4mr235239945e9.35.1768231024811;
        Mon, 12 Jan 2026 07:17:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HrhvjOG3ffNga7Fm5sNeYDaDU3V5pgX3A9byubDqhwLw=="
Received: by 2002:a05:600c:1f16:b0:477:5582:def6 with SMTP id
 5b1f17b1804b1-47d7eb03e64ls39179045e9.1.-pod-prod-03-eu; Mon, 12 Jan 2026
 07:17:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW0WGko1NUzoK37RjTgB2gVCeFFOD+UGgcQMpL5PdInzVSCxjuPpcB68qV4IvsXWFZUj8B3YiCzKd4=@googlegroups.com
X-Received: by 2002:a05:600c:1c28:b0:477:632c:5b91 with SMTP id 5b1f17b1804b1-47d84b1a2e7mr229796185e9.16.1768231022347;
        Mon, 12 Jan 2026 07:17:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231022; cv=none;
        d=google.com; s=arc-20240605;
        b=kUbpIKcxj/7vdbeAad8g0Z5jTCPrWMdgUPRo0HAYOt2wuH0p3P2CF2BjjJtyLVg8gI
         lF+Twz0qhXey2ln18qjDr73gRFdDcVKSohExqzqTJ3FuudWbVBuittvcCBOO9aKzF8kC
         5QkSsSbgDi24x54uaC1NLft7On8NWsNUWbwLAxQJ8H5yQ0SJGCpA1HGQokfcXeO+1z1e
         trGQmNxcTDK87l7kjryQgjQWNCC26oWaJCkzwJd8avCowDypLkgVWiG0N5LGnQq1jI4z
         nOakYohp6psJLYPwin+/ND/CoFlTDSQO/CCnZviIUk2lrygdPVws6+DfG2uJ7Expjcrx
         a5YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=IQCs1RtsaTm73XRhw06koc6SL41acjRnO47ur3XmS+A=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=YtblAnJnvyAvtzC4m2T3QPQvcSiNMNl27JD1Jb9Ne+wPT1Utxl79g0KQqvGreBgFcl
         jN0I8rCZUyzeNWWllWITBq4d3LdOGAkb9gZDimu3MfEnO1jfz1ewZ/WJnPOtxNvVgLqH
         ZJpGwSBc8fUiFfKWn7TvAaRz4b8m29VnGpGvASgWI4zPqiilZzyFp/T01O+3R5TJjZv3
         YxsZVUtAOcQCYlB0lj3plWi90kv6ZOtpt4VDpYDAT6ZVaYDYtavZplQ9puYJULa0SV+C
         zVveraWnPhy0NZPDDHFKQUEKf9/02RTIOVKhjxEGcc8pBxdc4SCPfRJ1QjxJmq713zDO
         AuRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;
       dkim=neutral (no key) header.i=@suse.cz header.b=xJ2UPpG5;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a1bca1si267577f8f.5.2026.01.12.07.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 74E4E5BCC5;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5060C3EA66;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KPBRE2kQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:16:56 +0100
Subject: [PATCH RFC v2 02/20] mm/slab: move and refactor
 __kmem_cache_alias()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-2-98225cfb50cf@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;       dkim=neutral
 (no key) header.i=@suse.cz header.b=xJ2UPpG5;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Ta4URRSV;       dkim=neutral
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

Move __kmem_cache_alias() to slab_common.c since it's called by
__kmem_cache_create_args() and calls find_mergeable() that both
are in this file. We can remove two slab.h declarations and make
them static. Instead declare sysfs_slab_alias() from slub.c so
that __kmem_cache_alias() can keep caling it.

Add args parameter to __kmem_cache_alias() and find_mergeable() instead
of align and ctor. With that we can also move the checks for usersize
and sheaf_capacity there from __kmem_cache_create_args() and make the
result more symmetric with slab_unmergeable().

No functional changes intended.

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
index ee994ec7f251..52591d9c04f3 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -175,15 +175,22 @@ int slab_unmergeable(struct kmem_cache *s)
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
@@ -192,7 +199,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 		return NULL;
 
 	size = ALIGN(size, sizeof(void *));
-	align = calculate_alignment(flags, align, size);
+	align = calculate_alignment(flags, args->align, size);
 	size = ALIGN(size, align);
 
 	list_for_each_entry_reverse(s, &slab_caches, list) {
@@ -253,6 +260,31 @@ static struct kmem_cache *create_cache(const char *name,
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
@@ -324,9 +356,7 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
 		    object_size - args->usersize < args->useroffset))
 		args->usersize = args->useroffset = 0;
 
-	if (!args->usersize && !args->sheaf_capacity)
-		s = __kmem_cache_alias(name, object_size, args->align, flags,
-				       args->ctor);
+	s = __kmem_cache_alias(name, object_size, flags, args);
 	if (s)
 		goto out_unlock;
 
diff --git a/mm/slub.c b/mm/slub.c
index 3076a1694008..8ffeb3ab3228 100644
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
@@ -8547,31 +8544,6 @@ void __init kmem_cache_init_late(void)
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
@@ -9804,7 +9776,7 @@ struct saved_alias {
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-2-98225cfb50cf%40suse.cz.
