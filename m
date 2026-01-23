Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXFVZTFQMGQEX7AHQAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8FGNNd0ac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBXFVZTFQMGQEX7AHQAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:17 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C4B4712B4
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:17 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6582e841d15sf1708374a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151197; cv=pass;
        d=google.com; s=arc-20240605;
        b=kXxeVKXDp1yH/HIxkk9n8DeFTXrumyEEgn50jWA33xB+fdtIZJq49TPdkmdSyFMIHK
         wDMjiLCz6UbLhu/T/kXGDTgx6ekFo9jqABoHLW4W9EpYTOU9Pdo3gXc8FkGRxkiFfpmI
         rwkCFAHBYkcaa00Z9J4RcsK9T1vxEKSKvEnprvOUmxOedP4o/gkHR/IrteOL5UG7ovfY
         /sR4ec0SqNFDBkb2Xdt4osQsgTkvwG6eKSAwDMu5POrVleLg3KuaViwGvfM/83i/vGxV
         L3TdW5vkVBLLvlsK8LUaZUKDIHA08py6/Jx+9Is6CikitLHgJE9SMeYJ7SQdvM67H6//
         6tyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=mn83ma/eeVN1Q9jDg7WobAaAUIvhvJapslegPjor2D0=;
        fh=7x7z4XJXJ2k1nmMHags8mKWiijRf3QWmpCM8wPBHUcE=;
        b=Mjl56U0x/r0lOze4FgJ+GSupxUZ9sjBD8UHYM6GZOxwkyPHvVj5ZsP0FDxHV5D1T/H
         AvD7FRaNN1eQGcOwk6LgQuqFKavI1QZAlaWp6bQPIv6C/DlwblMZJo9sX1o40eNHYCHn
         Xz2Bq5ve4y9Zj4CzxGfDTEoGR7GsIZOAjFS8tXkTHFTdHPgkl3m9E7tODGTBryCNlgSB
         30Bi6/K1PEy0M3Ca1IvV+HrNWSCd6HEovVdzfbx0uEEdmte82ovaNHcTlybOi8/P4mMy
         0clsFRKr7dFU+tnOJsDIwNGaLvkNUpRl6C9tyO02v+E+ZkYc135mxv4dxZ7v71btuX+5
         nXvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnxYZGzr;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oW6Bsr69;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151197; x=1769755997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mn83ma/eeVN1Q9jDg7WobAaAUIvhvJapslegPjor2D0=;
        b=JmiJ7amzK1YaT+UdgO14m9OwRBpGc9fFQZbuX659uqAGVq29qLPcQgpJjSLwCJb/Ig
         Y5BDjL/hZ+/E37twQrIeEa7/2tIF01O8/u8eBOKNmquxrCXwciyhEF3lnlQQ+hegeDbo
         Nm4nbTVqyHndkg4aOMku1K88/657c/Gjkkui0jExRE2IYfv6YUp2IXMx4ujsPqrFdknL
         cbFgvT6wccXrrSzREaKOuJWZaK/+ohbBX7lE2BXgmnIIg4/OhEp4iEhuZgFcQQYUKJQe
         wfGgcuUhCMwRAh3vPD5pV9Z1NDN7QCLHDx2LIPic32o0X6Ks2mIzhZjcsspW3My/uxAm
         tqoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151197; x=1769755997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mn83ma/eeVN1Q9jDg7WobAaAUIvhvJapslegPjor2D0=;
        b=qydlwEnYeJzK7mvnDuQ3m/tCdQ9O2qYwtarytQLNwET4ZNkDSh2Tk27Qmp9Ajlj99j
         CO2YGrEPk6o3az2xIWuTbjtHLr3vUBQd9zr4Cq2+xtRWl852k4DOP//199ES6BYH1h4m
         sZS9uxII0W8zlsXRfihS3chj4qMAVnZd/WPLYAF8rQhyGzPyHw93YnU6ifkUJ5oZcvRO
         KSRZ3xiFuIAWNNOODcZQ7mcfTD3B1RqSmwTwln65/jEFwzj5Q+E1NBsdKkZivjZ1a4Gd
         DCIP56G7VocyPblARK7sud99fss/65KrENh1yPzX7wsrb1ZRrQhkhneAaadrvbOFeI84
         t+tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXG6fKh2w4NpbF1HD/ICVTTAiU0epEZB34lpREaJcG3v/95n6UrXQySxgJAALT+ROV70Wu/8w==@lfdr.de
X-Gm-Message-State: AOJu0YzNGgMxqZxq6ppeCpQYMFfrLcNFDPmLkEM5NlmBs+Zul+yk0Co4
	jBGa9eeJuH5bZ2KIPr6/otIElTiwQ2M27DWrteSTrKSOdtN65DnX3V8t
X-Received: by 2002:a05:6402:42c3:b0:655:c395:4553 with SMTP id 4fb4d7f45d1cf-658487b0caemr1280376a12.23.1769151196723;
        Thu, 22 Jan 2026 22:53:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GAZoZvl1Gsj8CT91awug6jWOqcT7RqZ9NUS2tAZpZhLA=="
Received: by 2002:a05:6402:4049:10b0:64b:aa45:7bf6 with SMTP id
 4fb4d7f45d1cf-658329fabcals1234307a12.0.-pod-prod-06-eu; Thu, 22 Jan 2026
 22:53:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLSNZJ67+0BFLJOtz4Wi6qH+kKwV+LsQunYOW3OvtB0h9ow18awdpmgQr5qZu3yXQc2LH5rGvrlcU=@googlegroups.com
X-Received: by 2002:a17:907:948d:b0:b87:117f:b6f1 with SMTP id a640c23a62f3a-b885aba505amr115462066b.2.1769151194301;
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151194; cv=none;
        d=google.com; s=arc-20240605;
        b=ACfmBjlQyuyPAdDRKI5zW7ql1NN1I0Snxl0ZiA8rYPCkFjxZ/UG8gN9mi7SNGdNZV9
         5YFCZ44nUs32EbdzSxyzscQ8f6DIsnCVKX+UzhBn1NOIgcrkIClDisvoSskasecxghk+
         LVivXCIRwFZm3Tl9UncWJWsbj+N6OjefA91+OdtJhVVH9q7pCwBUbDx2/N7gNpWcxxLD
         NGoxIA3gLQ5n8pFIbIE8T7HfL0T4YqaWpv4MHCOIptzclouWVw3gQRCBZVTT2LFNBtEh
         FPM+F+Og8PACYGXhLxHuNRrLS3j8PD5AWlc/ZQFoLXyqpdSsRnIsPg8AP5fVewW9H1sq
         9WAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=UkJZc9VVDwbCOE5N88ecWISWdsb2/cOXldbaYOteozg=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=a5ZbefOv0CNHeHhUu03YKxyt3fySurvjPhfx1qzxXLLJkiI90ipPNdPLr7LDn1Ngkr
         F+tDxAZ9+Uvp7P9Ni1+Kva0IjvWi0//Tv2ZbBMica3leC8a2KDsHPL0BaF6tCfAvgO03
         GkOagO7RUIBTYm+WdpUv9IBtobwrbrne4s0nUzmluwz2BbBrhY6k7r5eBvVjC8970w4H
         qKuqKuZOgZOUET++nNNtCEIFkZAxEq5sC2wf5QENFGQwjCsCrZfxwYhfnB9oK/O/sVz9
         Rcu9It3IqCZGVc8Drc9S2Qw7eYar8dZmar//kqhTTZEIkPEkQLOf4S6HEOnElrQdE4mV
         1ggQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnxYZGzr;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oW6Bsr69;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b885b67f781si3627466b.2.2026.01.22.22.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A2C565BCCE;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7CF5D139EB;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aBk4HtUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:42 +0100
Subject: [PATCH v4 04/22] mm/slab: move and refactor __kmem_cache_alias()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-4-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
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
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LnxYZGzr;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=oW6Bsr69;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBXFVZTFQMGQEX7AHQAI];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.982];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email,mail-ed1-x539.google.com:helo,mail-ed1-x539.google.com:rdns]
X-Rspamd-Queue-Id: 7C4B4712B4
X-Rspamd-Action: no action

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
index 4eb60e99abd7..9d86c0505dcd 100644
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
@@ -8570,31 +8567,6 @@ void __init kmem_cache_init_late(void)
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
@@ -9827,7 +9799,7 @@ struct saved_alias {
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-4-041323d506f7%40suse.cz.
