Return-Path: <kasan-dev+bncBCKPFB7SXUERBAW77LGAMGQE4BWSQUI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YEf0CYWvnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBAW77LGAMGQE4BWSQUI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:01 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D168193FC4
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:00 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-824bf5fe8cbsf2837482b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007299; cv=pass;
        d=google.com; s=arc-20240605;
        b=RDpzGWl59NNGORDd6Igojq0PNbBS/XKUwBrKgyQ/D3zK8bv0vPEqTPTX2XbE3/qwKG
         YmflzRsZxHYyumBuUO7i60eoBbh3DTGMCcT0sXDu2woGPXFq89AeHhunlTswYbHVEDi6
         ndCpLKmvDv6tiYv7KVkkITI3BZUbwt2WNfZieUGDN5mElOSK5oWH4TCLTCffhIgui3go
         hJ1i4rqVX7o/dGU76K/Go1UT7Kumq0OkVxKnqXDTrfdhZFntvQ+8aSXGNEQUDNBV1rNt
         Sq9dnu2GjJh05ID35fTplrAYu0Ovdwuwek+CFiSuDvBx8IDnAANlrYVDt1QaQizeoDuf
         +D6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YUBoRZBKORxDH5Ciotid9AboUL/y5iWpoyWt25H21w4=;
        fh=2sz0yScZf95P6SvOWGhQdt+DMXX+vQ6GS2TT5wBTcgE=;
        b=JrwNnQPxkwq8zZY8CNNE0j47wap9RG26eJRFS50b1KQUmmNiPyua/6mXhh8asx88i9
         E4NLPWwhzkyi7G4HkXxgv1v5YHHRajQCoAftZDJzayh9YVyyPf+2D5iuh41DsQ1QR5rX
         Tnwon+0yeBDT9NFkL/xW/cQbOfvSMbclv5/oSAUcT4AzGzXwRHJ+/AQGTzQJAJxszcn7
         kClqZ1qBibVJslRV4O2+Atiy/3mxRmerceL+SzLdxJsl+eVcupXpfNsheyQHRMvl/mgQ
         Al85/TPQo4UI0FpXrD9VWV8AfCthh98YNspc2QZGl5gfzGTCZzquFEy+NcqgGeQdTleP
         SGvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MJLjPbSN;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007299; x=1772612099; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YUBoRZBKORxDH5Ciotid9AboUL/y5iWpoyWt25H21w4=;
        b=lnsQjr/XD+Z0RKrFuHHwdETMm3EjANt35wu08q+mRO++stJSoXGb+u4tzl3YwmpQiy
         2R46xOQOB/9uXpDFAUNo1oA2AaLHpPxrGejCjcxDyXmjMejng8vZR2fjJxX6Yqrc3CJd
         4JiQ4vGhqk5kGQR7YD/rd66FJFCes5PWIktYJj6V1QGRfNCSeFm8s0jJGJMzmsAk5O7E
         BBcZsrW19qFp8He1FnrslZ86vwSRVKM1g1oTiKbglLr+PrcnVvoU1sKV9Qrb3PFsdTuy
         HzEnG12Sf+nEok4a+UOazao6fJq44dBTXqQwc83A3TEZ5zzZTBlR496tB/tP7CoBS/am
         sN3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007299; x=1772612099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YUBoRZBKORxDH5Ciotid9AboUL/y5iWpoyWt25H21w4=;
        b=HrZTre+ILFj7ZwRp0sM0fGYahTHm3uvbK0JE2VUM1qqtH6tcJXFGA0pFLKdozPJqmo
         5LBnZ2tn4OW8+DX/1rG/ZxU9gnxMXbiZAej4KPlePWgwEgFn4zl5OOa3Azl7bImo296O
         CKH3K3HnCj281775N6a45kpTO83BFurdk3whQY2u8quFxpZzpL6uVWlDDEfckdv8yLXD
         J5ClJaLe6LJEdZz1j/r13qUXLujUAad8Cj2vFhjhZ/yVsTyBnEAeV8o+XnWIFneY04AK
         x51z2/J2B959RpRNpZY3p4aXRKkAt1TlhlgvyZek/bNmG6zBUKArxLMowb+hcaYQEir5
         SQtQ==
X-Forwarded-Encrypted: i=2; AJvYcCU0Fztu1Ndn1mnTaN3+e989tEeHn1rN3KUT2usIfDqBUsjazLC+DBL9tNJtYc8TyDDE8gDW6Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw8Sc4KR859M30sRnC2S84ReH87No/y5FeTZhg+gutFC86QxqZR
	M/mRE0PngGgN/kseX2C957ahI6RiAP5DFpJXz+cIylrJigbpHI7B4nbp
X-Received: by 2002:a05:6a00:ad5:b0:81f:3fbd:ccf with SMTP id d2e1a72fcca58-826da8f1917mr12321345b3a.23.1772007298620;
        Wed, 25 Feb 2026 00:14:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EIizUg1VegE49IDf++M/r3QDi7g6kTePxc7103yQGdOw=="
Received: by 2002:a05:6a00:90a6:b0:824:afd2:a5a9 with SMTP id
 d2e1a72fcca58-82726b92901ls412253b3a.0.-pod-prod-09-us; Wed, 25 Feb 2026
 00:14:57 -0800 (PST)
X-Received: by 2002:a05:6a00:c8c:b0:81c:96b7:7fb6 with SMTP id d2e1a72fcca58-826da9f1655mr14787141b3a.35.1772007296890;
        Wed, 25 Feb 2026 00:14:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007296; cv=none;
        d=google.com; s=arc-20240605;
        b=IdR1ibch9w3dJDildlSjZmZg5VaMsKFkermuUy9dWFPOfjrYyx4VSS1UK40raT3jiA
         ykQSD17XmdKujn7R1ZW5oYQ3ieCwllBwQ3H3qdWkOHL74qs/Jsn5cA3YzM+PB53pX4DE
         8ynisAZPRSTVrMmgeArsXrRnIi0KFDv9UStpdpn1iECN3ssidKTi70kePI2NXzgGMqVS
         tQtor2QtXM4hq4X8I9yvq8hHVUzWpBd1mYoJzR220x7uq5oNA2kki4VLXtWu0bEpDTmc
         10v4afdBqE/VWLiHPxQ7A2UBCrWuQpzHnV0+N0nG2eiIBFytWUTW0ElpSm402NQnD6ID
         KHdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1+o8INxubcV2x/Jl5UdObmj+gfJwsgp0C09vqymuwDM=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=J5bDWVAz+f9tBxk0uzg+E9t6JGtg1JJQJDWBhTBJWJahzvk3hBUFLEglO+n0fWtFjU
         joIxM+25l+Qx+zZ7TNMuCoHgS2H6t8bZHF1mWJ4qMUKUzLHFck3ZN5tjwd8gYc0ts/A1
         6hgd4IHwdqJqaORzOKgL3LhS0LIZPbdNgcsK+nnKfGoUiAxDkvGTpEOXfwZZJ55TXFTi
         GGfHapHwEl8MVPs3JoIKe6WUWKih5Mq69T5O2yBzCv6N9uwIpEnYcigHIf0INXTWeje2
         0svVHFZk296sgW+WVCgdMbjRjFjj7Hf8ekpyNqJ2XOJJRuNPD44/xRjisrbj4soBdafL
         3txA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MJLjPbSN;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-826dd894ec4si397881b3a.6.2026.02.25.00.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:14:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-556-nQ4DDfqXPK2cnN4hGIJDvA-1; Wed,
 25 Feb 2026 03:14:51 -0500
X-MC-Unique: nQ4DDfqXPK2cnN4hGIJDvA-1
X-Mimecast-MFC-AGG-ID: nQ4DDfqXPK2cnN4hGIJDvA_1772007289
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A0E82195609D;
	Wed, 25 Feb 2026 08:14:48 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id DE8351800351;
	Wed, 25 Feb 2026 08:14:38 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 01/15] mm/kasan: add conditional checks in functions to return directly if kasan is disabled
Date: Wed, 25 Feb 2026 16:13:58 +0800
Message-ID: <20260225081412.76502-2-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: HgTU9ru9V5cUbzFtp9CCdVtd5aKHcFOaxtoK4OeE6pU_1772007289
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MJLjPbSN;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBAW77LGAMGQE4BWSQUI];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.977];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TO_DN_SOME(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com]
X-Rspamd-Queue-Id: 9D168193FC4
X-Rspamd-Action: no action

The current codes only check if kasan is disabled for hw_tags
mode. Here add the conditional checks for functional functions of
generic mode and sw_tags mode.

And also add a helper __kasan_cache_shrink() in mm/kasan/generic.c
so that the conditional check is done in include/linux/kasan.h.

This is prepared for later adding kernel parameter kasan=on|off for
all three kasan modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan.h |  7 ++++++-
 mm/kasan/generic.c    | 16 ++++++++++++++--
 mm/kasan/init.c       |  6 ++++++
 mm/kasan/quarantine.c |  3 +++
 mm/kasan/report.c     |  4 +++-
 mm/kasan/shadow.c     | 11 ++++++++++-
 mm/kasan/sw_tags.c    |  3 +++
 7 files changed, 45 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 338a1921a50a..a9b8d58d8699 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -492,7 +492,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
 
-void kasan_cache_shrink(struct kmem_cache *cache);
+void __kasan_cache_shrink(struct kmem_cache *cache);
+static inline void kasan_cache_shrink(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		__kasan_cache_shrink(cache);
+}
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2b8e73f5f6a7..25850e7c2e00 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -212,14 +212,14 @@ bool kasan_byte_accessible(const void *addr)
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }
 
-void kasan_cache_shrink(struct kmem_cache *cache)
+void __kasan_cache_shrink(struct kmem_cache *cache)
 {
 	kasan_quarantine_remove_cache(cache);
 }
 
 void kasan_cache_shutdown(struct kmem_cache *cache)
 {
-	if (!__kmem_cache_empty(cache))
+	if (kasan_enabled() && !__kmem_cache_empty(cache))
 		kasan_quarantine_remove_cache(cache);
 }
 
@@ -239,6 +239,9 @@ void __asan_register_globals(void *ptr, ssize_t size)
 	int i;
 	struct kasan_global *globals = ptr;
 
+	if (!kasan_enabled())
+		return;
+
 	for (i = 0; i < size; i++)
 		register_global(&globals[i]);
 }
@@ -369,6 +372,9 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int rem_free_meta_size;
 	unsigned int orig_alloc_meta_offset;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_requires_meta())
 		return;
 
@@ -518,6 +524,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
 	struct kasan_cache *info = &cache->kasan_info;
 
+	if (!kasan_enabled())
+		return 0;
+
 	if (!kasan_requires_meta())
 		return 0;
 
@@ -543,6 +552,9 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
+	if (!kasan_enabled())
+		return;
+
 	if (is_kfence_address(addr) || !slab)
 		return;
 
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index f084e7a5df1e..c78d77ed47bc 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -447,6 +447,9 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	unsigned long addr, end, next;
 	pgd_t *pgd;
 
+	if (!kasan_enabled())
+		return;
+
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
@@ -482,6 +485,9 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	int ret;
 	void *shadow_start, *shadow_end;
 
+	if (!kasan_enabled())
+		return 0;
+
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 6958aa713c67..a6dc2c3d8a15 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -405,6 +405,9 @@ static int __init kasan_cpu_quarantine_init(void)
 {
 	int ret = 0;
 
+	if (!kasan_enabled())
+		return 0;
+
 	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
 				kasan_cpu_online, kasan_cpu_offline);
 	if (ret < 0)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 27efb78eb32d..1a39b3f62c57 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -576,7 +576,9 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
 	unsigned long irq_flags;
 	struct kasan_report_info info;
 
-	if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
+	if (unlikely(report_suppressed_sw()) ||
+	    unlikely(!report_enabled()) ||
+	    !kasan_enabled()) {
 		ret = false;
 		goto out;
 	}
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d286e0a04543..87f517b76d6e 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -164,6 +164,8 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
+	if (!kasan_enabled())
+		return;
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_unpoison_new_object) pass tagged
@@ -277,7 +279,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 
 static int __init kasan_memhotplug_init(void)
 {
-	hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
+	if (kasan_enabled())
+		hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
 
 	return 0;
 }
@@ -660,6 +663,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 	size_t shadow_size;
 	unsigned long shadow_start;
 
+	if (!kasan_enabled())
+		return 0;
+
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
 	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
 				KASAN_SHADOW_SCALE_SHIFT;
@@ -696,6 +702,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 
 void kasan_free_module_shadow(const struct vm_struct *vm)
 {
+	if (!kasan_enabled())
+		return;
+
 	if (IS_ENABLED(CONFIG_UML))
 		return;
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c75741a74602..6c1caec4261a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -79,6 +79,9 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	u8 *shadow_first, *shadow_last, *shadow;
 	void *untagged_addr;
 
+	if (!kasan_enabled())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-2-bhe%40redhat.com.
