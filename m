Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSPG5DDQMGQEVDC2E6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DB6B9C018DC
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:14 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-63c10d86ef2sf819370a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227594; cv=pass;
        d=google.com; s=arc-20240605;
        b=U/VHC/uM6agKtaEQ8vHOFO8bq0l5DquJWvohR/S9MOCQimX1S+fPoKU3Cuh6YI0iAc
         xdDrKDlpMq1NG66sY1Kmwpy56f3GdZ7pqnZcK6XAcB0NViINjRZ/Av0dTXc23i0Z7445
         YejEe4gapu6utZFdeuFSLPhIK03g2h4xql9yXpTm8Eyv+UwWg0iUB9uxgT5UDVI4L92k
         Ynj54gn1bB7ANon7yoFXtkr8eFeXuaOlO7BvBqzMVBoGLpf32uVCs+SufB7G0p1piq6c
         reCogJRkRey5vqlRc15SfuRLy8qilx5fdDP8EvpFEMfaCkDCLaBqboNYP2j6jO3d4hTA
         48ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=vwVDa8T85d9fXCx/fleLocXMeUQY1ODYnWk+Vq7eqFc=;
        fh=dJDyyJsgYgeC4oxoJfAFNZqPTysqZJQC+BU+DvCtK7I=;
        b=VNixHoHqb7fxS7YbJ7bNL31SsaV30y3gK+J06m5sMIia55VSPpwvm/F/jxs36t+m9F
         ztRA38vmyDaG7HG+rbQe9IwyKa7TG7C24v+aVyA4ImedgWa7VrhxFIekzx5BSDyPUA5o
         Uf+NAvMK0Yl/DgOq28lbylgWlskRDmVQR2WRs+GClwBitkkYB7bVApbbUk0z8rLqwGgG
         khqELD5842zgypRycYO73ZPQ+0e62Br149K4fwYlLYpZKMaQ2C4Cq/s25KZI2jP8sClL
         ucYowG75kuR4lVD4I1p6ebStMkK1K16sHE7KjOl6inkrza9cs1OqWsYRjplyRKyVAHHm
         tCGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227594; x=1761832394; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vwVDa8T85d9fXCx/fleLocXMeUQY1ODYnWk+Vq7eqFc=;
        b=Ew6X4dPDG/bpe4wIGbDis35OazEimizlNbZO9zWmSrd6El9WGZn5MMZJI3X1KkmjVT
         OFJOifXDJvh6QZ2/BLjZubJkqBnWZkiqVLNaep8va3F6sEiRKC2DRG7Q4dr3t7WOPcBh
         oep2oIxapuGRKj+GC9NCJxN8B+02BRCLTMIkH/idSNiSTg1AB7faqLrKo9EeNP8VmWEc
         uamgIkD7EwIbtYXnsWaoZVwgdxS0O3xSF+1PH5HxZDW9ya44l116IFpqzj6oShS0z4Ri
         woqdwFErrUN2hBH8R7aeMSQkEjp34LwYNHxeWt3VQvfHCFpO2g9xAE5mHixlXmAllIiT
         +G7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227594; x=1761832394;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vwVDa8T85d9fXCx/fleLocXMeUQY1ODYnWk+Vq7eqFc=;
        b=ivNzMXKhy0evk1vBYnjVmdTpgiNBatXL+9I5s/ZNOniX5/789OlH+B5QSJISB4rl+L
         kpD1bYlF0HcA13GBY3rxvWkiIhxyCvJTFEJPP9NTvZEp/gsRggvn0OSAwA6/Sm4FeQo1
         6RBfn47UYZnvf5SXl0KOT7+s1n16hrSUdIzYCrLBJXn95C9sU4uxJMUtQgcDTGph3wDh
         G3XhRjkh84crgqTryIDnm+ZNU1DyqMjDM4kkcDIk/hi4wpGc7uYwHpJMeKTke+ulM5UI
         cTeRKSfi9hRX/xx3VvXkH9neMxqwXAZTM3pU+RSg21oEBB1DzriWC6AwLNCGsQHo0IGv
         l5Wg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVz9C2Q1uzaKU/rNy6lSIHUZLK/wiX3ks8X4BlsCuOoU4QMJDU0H27D1syi6aS9Y+UUdFHEpA==@lfdr.de
X-Gm-Message-State: AOJu0YwrUN84lfu2scB+9dBcM6Q/wc3jML0Gcv8wHDPK37IEdG38BewQ
	VnmyMyE1yq4o7Jg4TBmZBAgGlZ6EDWfnoIJ6ElhfvL8P8//89+Hl4K3b
X-Google-Smtp-Source: AGHT+IHq/8FyMJqDx0vfxEEJRKMLY02nNzqZDU8IaWiROlGwIHP9cQQaBys3VfjF4z/JLwYL9OEV7g==
X-Received: by 2002:a05:6402:13d4:b0:639:e712:cd6c with SMTP id 4fb4d7f45d1cf-63c1f641d39mr23229256a12.13.1761227594047;
        Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YccD2V/ifL59k934avKCe0sV5HIVFBp3Zo2Za0LJUpDw=="
Received: by 2002:a50:9f05:0:b0:63e:4530:fd6e with SMTP id 4fb4d7f45d1cf-63e4531036als584186a12.1.-pod-prod-08-eu;
 Thu, 23 Oct 2025 06:53:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXRJj5zQyCEyF/nY/ZziDr95nZgEEcBYGVMTIV+UuZg5XI148iEYjZV38HgZ/IZkhckQTrxP2CIcA=@googlegroups.com
X-Received: by 2002:a17:907:1b10:b0:b2a:5fe5:87c7 with SMTP id a640c23a62f3a-b6471d4570emr3295665666b.12.1761227591216;
        Thu, 23 Oct 2025 06:53:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227591; cv=none;
        d=google.com; s=arc-20240605;
        b=QZmfKeWyUQkXA5+CCeoPs4zAclbb2csP+I7FnrI23uJXPT5ATSfaD1mzi1IumKzM++
         J4/jiowVi/Sv004aVUNGFwFWnL9buIXsqT3ATKsHYOIayvHpeGFeJzzepdx3qvQTlVEO
         kcN20IzFWnB2MtUYtzbgpRcHLrdyb8bsJtKea7ZWy5CbDIR5s9ZOIlEIsbfImh3Z+sLf
         q2u6rieeDRxUBzFi0quzA/Dm9DDoRRhrB7+YrFRLN3O/wzZkpIOy4JJE/OnF2iaJD9Kw
         vHQmQZwKy+vM+MouIJglZ+nT5xK6raLqDfHqt3zjuPsUlWFl/yPUviKAqQrbEsaXk/Xe
         WyTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=sTZx0sLtvJo4J0O41JGYb8/wviWvNFZ0we7krvm2Y4s=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=BHczuCWIqxXNzClnZ8I4yq6BfmrZr+120Ak6nIallwe1PcG9O3UUL239fOicAcZz5O
         7qtVe0izDJC0322o60mDy1DcM8PzYvX5aKCjSiBlCAjcsT+HgFwzR7VKmCxmXF8XnSkg
         dJSKlh2Bs+p9hy8QeAsM2gXpO8CVvqthhYOuUyxSngI953LWz+tiyvLWyf2JCTgHs4vr
         wVU4cmJZWxtIdV77Zm/V4trc3WPFd96rRfWaiFb+HMXfpxwZ3vU054KtTLSJQJR/he9n
         i8LC2oMmyQgjhllQubdjV9ZHvGZfbQDkl3hv+GFVxawV3hpIjd12MZlz2ytppkteVNpD
         jzVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b6d5f23f349si1701166b.1.2025.10.23.06.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AE58721250;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A73C713B0E;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WHqMKDYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:38 +0200
Subject: [PATCH RFC 16/19] slab: remove unused PREEMPT_RT specific macros
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-16-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Rspamd-Queue-Id: AE58721250
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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

The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
being removed. The only remaining usage is in fact testing whether we
can assert irqs disabled, because spin_lock_irqsave() only does that on
!RT. Test for CONFIG_PREEMPT_RT instead.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 24 +-----------------------
 1 file changed, 1 insertion(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index dcf28fc3a112..d55afa9b277f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -201,28 +201,6 @@ enum slab_flags {
 	SL_pfmemalloc = PG_active,	/* Historical reasons for this bit */
 };
 
-/*
- * We could simply use migrate_disable()/enable() but as long as it's a
- * function call even on !PREEMPT_RT, use inline preempt_disable() there.
- */
-#ifndef CONFIG_PREEMPT_RT
-#define slub_get_cpu_ptr(var)		get_cpu_ptr(var)
-#define slub_put_cpu_ptr(var)		put_cpu_ptr(var)
-#define USE_LOCKLESS_FAST_PATH()	(true)
-#else
-#define slub_get_cpu_ptr(var)		\
-({					\
-	migrate_disable();		\
-	this_cpu_ptr(var);		\
-})
-#define slub_put_cpu_ptr(var)		\
-do {					\
-	(void)(var);			\
-	migrate_enable();		\
-} while (0)
-#define USE_LOCKLESS_FAST_PATH()	(false)
-#endif
-
 #ifndef CONFIG_SLUB_TINY
 #define __fastpath_inline __always_inline
 #else
@@ -715,7 +693,7 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
 {
 	bool ret;
 
-	if (USE_LOCKLESS_FAST_PATH())
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
 		lockdep_assert_irqs_disabled();
 
 	if (s->flags & __CMPXCHG_DOUBLE) {

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-16-6ffa2c9941c0%40suse.cz.
