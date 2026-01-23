Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXFVZTFQMGQEX7AHQAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GESaDt4ac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBXFVZTFQMGQEX7AHQAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:18 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id D32F7712B5
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:17 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-658150fd8f0sf1740356a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151197; cv=pass;
        d=google.com; s=arc-20240605;
        b=aDRvg2nM1RunVl94sdzmiH14ig6i/iidZAQS2xJgZGCOkvVmVTsIrc52GAsE55zK36
         Eha0zk0PYeUi6XJmovGajKjtCetPIG/iAm1ojenI14zJo8mNhwzXG6n5mZgvvfquunYM
         J6Go/ziAMZPH7mSRAu2qrWWgMMuWewqEK98RZ16k9r+7fDNIiN/tFUDXIBPI4CEipGEJ
         pZf2RrQlewYsMWUPYp5aolpmrs+X6qkjUhE9oqC9S5+VMSNTVm70JjEm2pgHAvGQrRzJ
         PSbUQo4sTydz5hkZa4R29XexPdZ3G04SwJoYNwyWGHDaHJm4gDCXEB3u6DNLCDz8qOc8
         dpkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=sth2ZBhl3zlK8ycQoP7B4+NucRf95kmkZIwKeXWIBC0=;
        fh=FlqnVtGyvfeJkCZHXpwXjHXkGvPQEITKGQCcbT/fXPE=;
        b=esVKrd0qqo8DEJjMYv5pv9kA2yMjUWoDpr75ox1EjdFx8+X/VaHbXFphrWrQG2Qq5B
         OQD7KfG2OI0etsefJDIAJz+sFD0C2Fzk3scryqwq6dIIjiGjJtVvy6iAla/USRxZ3xUE
         LvD9sFt8woFUnL4eMwbbgk0rdcyCPNgWn5HwigTQB9nS8CBKRZpl7Id1S9hKeH9JYcFe
         5Xyl4bTUPTbkbhnQ4xht5QnuWdQYbTJ+Ff6gOi3Lp2rdspGoELT58CZpzqP/FJumxUdI
         2Yj0C5SbChbUM2uGyd4j8r5QJ3ZKIsipVW4LclxP9zociY4kAXj89ABioPmsnZRdhmlf
         k6JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gi3T+Xls;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gi3T+Xls;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151197; x=1769755997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sth2ZBhl3zlK8ycQoP7B4+NucRf95kmkZIwKeXWIBC0=;
        b=fs92YlUx/9UAyZoRBFHyA94ezmg+FE8mhQlXfRQY8hwi0xL0n4mO3iqXgqwP0tqHVI
         Yx2BvbePZnspuS1FF5HnOgxreIcEi/S1TDkFpT6bN3MZIgeWHUXU0iu+qlX0ZdzqWOGU
         kVWEAdsLIoxgWKfizbXSKa+BAX9TqN8oB+KTyeNd2Ewzelu5arqxvF6TKyc/NFdgV4bi
         3kx3BlhSo7diDz0Qq6VBhnQX4ZTmtlAqSdplsftwwl4fXE9AXLQyVl2J6jtpj+iiNZVm
         f89Xy0s/KqUj3crTkOFrIOpnOvOhMQmfTXO3YtsiIGiaEy65ciw1cTIJwTL8XBcD4wyu
         TNNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151197; x=1769755997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sth2ZBhl3zlK8ycQoP7B4+NucRf95kmkZIwKeXWIBC0=;
        b=O12m2hqTamWE11Yp9kVFYzGgOM4C27ZY1EYGFbosbgdSCx08x0ptWUndOGXIyBOH2G
         nsjwZOhLZ0cZLQGpb6glIalTfCBfWwyDI0doBbO20dNv79EU0ITt+7jhToWCzvADIEaS
         zyMFLw50RVhKYLuM+pqGNds014d5hGHBguve3sKyFLVVokjzR3MuxWHbxfxiygo1DdQr
         QsQCiTJp5EOVezaVZKGo7fAlDsHorjEUJaaikVevRBOpXRwvPY05nbXK14pKsjVeN5TD
         FL23QMYoUAE6pXb3i5DNXLN8UgshEzk0YeOSJqeMQ4c/41uGAXr9SNntpcXpFHlV9dLn
         Wghg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUYnuAjj08t1qnACg6zR+YeJ+cVM8va2nSjg7P8Y7mvPUXYnV3YcGDtlqSqQ3aTwhBUyLzCw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0m9a3JxaPMa3ebya5Z7GjuIrw/6fhnyUipEfCWhjE8hLJ1aVp
	BHHmB460K15Sg8tfHUUhpG8nec2pJ75Av6dNzgO1VQnhXFn54HCf3Elf
X-Received: by 2002:a05:6402:5252:b0:658:380a:e243 with SMTP id 4fb4d7f45d1cf-658487c675fmr1222096a12.25.1769151197090;
        Thu, 22 Jan 2026 22:53:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HTHR2TbrHn+jTCXt9DoS6UETIXF34XrVR+u6TWKXEjiw=="
Received: by 2002:a05:6402:a25b:10b0:64b:597a:6c07 with SMTP id
 4fb4d7f45d1cf-658329f3392ls1207293a12.0.-pod-prod-09-eu; Thu, 22 Jan 2026
 22:53:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZHf+3gj4aYtmh36ZaE4/ce3FGAv18AJuuqk6S3wPC9ZbzntPDvLPCzcOj0quSxS1hSvgpQGanYds=@googlegroups.com
X-Received: by 2002:a05:6402:1ed2:b0:64c:7903:afe3 with SMTP id 4fb4d7f45d1cf-65848779d58mr1410125a12.15.1769151194670;
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151194; cv=none;
        d=google.com; s=arc-20240605;
        b=Y7Bpyj+leoy9WR3cbrx1Zi46rhnGBrXezkE9/tJRZK+bkNtT1zptf7UZmLEDJJ98gf
         5NxKJkhoL1UGgfrZKsigGqLqHyxB9/qBKpVpNaIGfjbnVwP9WvqSf09CyLYl86+5mVMW
         V85wsJNJxCzdNLDzm9BKWIjZxE/s0C060aWtVCSw7KGuyn1ZbkFVRaFEdkg55ZSByYBn
         gl6AUxvUNqFyQ4udzV0EUOTbBxuSDQnlfUnL1IPdHq5NdCBsnaVvu/UxYjBc5gl646k2
         RijfFz6pvr7bOkBJswAM5sr/sopv9anxxO+gKND/AEt7ssVZHMxvVC63F24SsWoVXGlW
         j0ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=eEKVD7jaQE+LDv05PIHRGwJ26LSVOziITzWTXSPhpJk=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=Gvn+Mk/kHBt+zP5GOklyxvWyGaak5FgfCD7syRFQfbNKnoPsUJj4HQNYIhwjUYRR6c
         Dq/zrjR2r8WKP0wA2WLpvSszxnIj/SkrigExu7jKT/a79ZUbg3DDRnr0//rmdwaG0KhS
         zwBtR+CEzO1B0fQK7A+SJkp3oo3bOl+EeTlmLzE4i7FqYDz9Ry/3KYwivYUFmxRD3/j5
         uc3+iOyBy3rqMCq+X9fGnIWnfSnCOOwDst1oMibqilMJFRXJWWEiWFmEADM4poTwp23e
         N9fVeC69xtbxdjojMwFEpoJ0YmDPQsgNQm6LLRTr57c/VnS6Mu/too11qLH49c4hOUyV
         qBzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gi3T+Xls;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gi3T+Xls;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b526f12si25712a12.3.2026.01.22.22.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9EAF33376A;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B1514139ED;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0DYFK9Uac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:44 +0100
Subject: [PATCH v4 06/22] slab: add sheaves to most caches
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
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
X-Spam-Score: -8.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Gi3T+Xls;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Gi3T+Xls;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	NEURAL_HAM(-0.00)[-0.983];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email,mail-ed1-x53c.google.com:helo,mail-ed1-x53c.google.com:rdns]
X-Rspamd-Queue-Id: D32F7712B5
X-Rspamd-Action: no action

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

Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
recursion with kmemleak tracking (thanks to Breno Leitao).

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h |  6 ------
 mm/slub.c            | 56 ++++++++++++++++++++++++++++++++++++++++++++++++----
 2 files changed, 52 insertions(+), 10 deletions(-)

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
index 9d86c0505dcd..594f5fac39b3 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7880,6 +7880,53 @@ static void set_cpu_partial(struct kmem_cache *s)
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
+	/*
+	 * Bootstrap caches can't have sheaves for now (SLAB_NO_OBJ_EXT).
+	 * SLAB_NOLEAKTRACE caches (e.g., kmemleak's object_cache) must not
+	 * have sheaves to avoid recursion when sheaf allocation triggers
+	 * kmemleak tracking.
+	 */
+	if (s->flags & (SLAB_NO_OBJ_EXT | SLAB_NOLEAKTRACE))
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
@@ -8014,6 +8061,10 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
+	/* kmalloc caches need extra care to support sheaves */
+	if (!is_kmalloc_cache(s))
+		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
+
 	/*
 	 * Determine the number of objects per slab
 	 */
@@ -8618,15 +8669,12 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-6-041323d506f7%40suse.cz.
