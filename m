Return-Path: <kasan-dev+bncBCLI747UVAFRBSNW42NAMGQEAGQGEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id F147260EA5B
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 22:40:42 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id b13-20020ab0140d000000b003e39e1390f9sf7320283uae.18
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 13:40:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666816842; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+DduoTuJnq1AZfZC6F1BhC8S57JFuarYGrwtVqyM+HUnkQlNWzEdLXt6W3vzQmxmb
         rz0l+UOeGYv4cXZjp1QaYQpyeAgvPvuQOeR9IvObg4WL9XipmyRgdg1qjkDQthk3pjE1
         tlYxt3VJpweTKH7QFYfAgG7Iqmb773qk2et1Qee4rAMaEJgcQp/RxTCP3f89gA4U6blS
         Ol+x0ZBqSXfENVIZmIAN9mH0PwS4MCk19XxFpgb2VGQiAjDRqGHnCYoTzWkhvh9ijXBZ
         MqjbE+4aExE4gEN5okdDPHSwATCuZtuK3IbCnVjqcs8SJOgKuWBey10rLmD9xCvEcjFW
         3ahw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=DnpjoAP98wzErSGWYEAR81jbWM2NdhjQAF8X/1pM6Lo=;
        b=kvO8XzIQgM3vspnZkcByvqXCyGDFMkAOYxphL/J+SeV0rN2J9yxPpjQN+4KY2ZTXLA
         JEqN8+MyM5FLZNTY8fDpG75ESqoCVZS4+GtvpX19lLBgnns89m2EMh9bjPFGmMrKhYaj
         olRx3eE8pM2vAtUFrD+vaWz0wfH3d/iCTq7bulhpAj5EOz9i4yjK4/SZx1TTdCYGv+ai
         yC7QvhmJX2ycB3wLXN21DMj6D8SJT/ZxLyAWu4M4ZnP6VkVtbWlG0HbPN2lxXsqesmy2
         VNCCF/FwOI7xLx3M6TmyVKINQ0LsDuBJ27dI6pq22jRVISGgRgtCJ6Agc54Pgm9Wtei6
         s6cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="d/VgUBbd";
       spf=pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DnpjoAP98wzErSGWYEAR81jbWM2NdhjQAF8X/1pM6Lo=;
        b=eqIp1a6Mja1E3fIX2zlT47nrdz0OT6pPGK72V5ZiveDqFhP0clotwSAH3cNDhy9aRa
         2Lh5vg9UtKlZyN/PNA7cxHa0u7K7VjECy+i3Un207/7gtethSXcRh1YtFaGucmelbsxU
         GGu5iVvgJ34PtwGdFs0iUYdD6wRropRa53g09rAuGc1/9qMxTatlAhGyF7zn6V2JEpiF
         XDXF7Lc1ByEJIGe73bAmyom2aW8L0l9qPiv+n84lGies+nXKtiHVaUc2VRgHqp3zgo65
         FFucfUUb5O1YCLBnBJEpZdIuqyRp9LNUGxaEaK8LzcrI7R2rLTh9GLhU15tX0U7WgHAf
         hlmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DnpjoAP98wzErSGWYEAR81jbWM2NdhjQAF8X/1pM6Lo=;
        b=whUrNHO3fEKqFW7bitgxLkccDmfZj35+2HO9gFEmlUDgCFlE5NvQFQ0ioLF1ftOCjN
         0cwCqvCbIBuG+2JXKTh/lwnEhT7cW4PNNN4dtF+jhf5oUlzXN+L4K21nOJGrtlly/FTx
         xwO9JefqqE7VV+M9DjVHEKMjncXm4qbGMVQSteTB0uLh1y7bWNIVyj69iJrzbWczU/gs
         WfkgZ558Qoz6QSjrq1+CYlG04+pCcaaU+z7b1F9jK6+KCnkpureyaeBI7S6KgUU+M9Gs
         Q+T3keJ672Xt1pACmSNHHzsNylz33TA63ivLbXb8k/b2+NIOzIyN5bnWiBkkakdWJu3x
         Sf3g==
X-Gm-Message-State: ACrzQf2Jvk84+pcR5PNtVghJkdthusv9fqmPmDs//F00SISg8zC/b3j0
	gj9EcoIgPQVGdw2/MBwqFB0=
X-Google-Smtp-Source: AMsMyM6mYot32xAsKrOBJUiHs0KW3gHrIfuNdHHQKWAOEnJIt4Me38BSoSh9Kh5i7v3k0LxHwiS5nw==
X-Received: by 2002:a1f:e706:0:b0:3b7:6c6b:7bbf with SMTP id e6-20020a1fe706000000b003b76c6b7bbfmr8075139vkh.31.1666816841963;
        Wed, 26 Oct 2022 13:40:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9bd1:0:b0:3aa:886a:3a0 with SMTP id d200-20020a1f9bd1000000b003aa886a03a0ls1698726vke.0.-pod-prod-gmail;
 Wed, 26 Oct 2022 13:40:41 -0700 (PDT)
X-Received: by 2002:a1f:9d82:0:b0:3ab:1049:dbfb with SMTP id g124-20020a1f9d82000000b003ab1049dbfbmr25132793vke.34.1666816841330;
        Wed, 26 Oct 2022 13:40:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666816841; cv=none;
        d=google.com; s=arc-20160816;
        b=XHEWEZfLFPSnA9O5ewbql0U9A+7lwSeh0lPSor77r5ifElSSU8IIDUfllOczuVkTDN
         Ol+3Sz7VWcskq98DdF0oRgCc3t8noq+uUXDvp2KOnJlqtsh6Jskor2vRETbeBWSmJYKv
         LbCTzqJJ2N0b0Czat/njq2PU3GhJyFH+CsVBkh1fJtGHVjk7D+Jrjl52XLULxoQkORo8
         SEhjcovb0F3z/3Zzv9dRf+4tWJDjS24mcqrSSBTsegvuV01+JVQDGs4ZDLUSDPhy2pdZ
         HAkYC5TZmYw9oJ2au50H5Giaxcy97x5Ox/AZBz4kAkfvK6Off0rif+DxagzlO+5Hq35d
         znHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AjdQcbTZ/4LQ9U5Pp719hqjaA/vLTDOip6pEN5i0CB4=;
        b=oQFOYF8x+dwyhDyPDwiv3nSWHzyWflTp40zprbVXBlNOZm/F+UQUsZgNzQmNW+I5UF
         ujAq2/3jsjeHJxO0G+h7Xe4mzNKfBbUMta2MvQNROS+EdxeIlUcwo+M+Dy3EjWIlaRKn
         GhGRR5/zrj2lk8qpIgxGtU28ckG3ivt+h3CyxW9PX/0rpqfBNZZzHM7whZrVZTmG8uRb
         1O4FvfVnV7k/I5aoVJFMvN/QydLDP4rpf/63VL7qCbE35ubOQco+zxm0xuxL1GbU3sW0
         v4L2OiJHJ9lQtnfKICVOhHOb1M09CUTD5Q1dsWwacRXPom+/LyuLFWwXuCCk2Pf6aogC
         A2BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="d/VgUBbd";
       spf=pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id p197-20020a1f29ce000000b003aa19e4feecsi332600vkp.0.2022.10.26.13.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Oct 2022 13:40:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C105B620C5;
	Wed, 26 Oct 2022 20:40:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8FA52C433D6;
	Wed, 26 Oct 2022 20:40:39 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 33fc5469 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 26 Oct 2022 20:40:37 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com,
	elver@google.com,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH] kfence: buffer random bools in bitmask
Date: Wed, 26 Oct 2022 22:40:31 +0200
Message-Id: <20221026204031.1699061-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b="d/VgUBbd";       spf=pass
 (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
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

Recently kfence got a 4x speed up in calls to the RNG, due to using
internally get_random_u8() instead of get_random_u32() for its random
boolean values. We can extend that speed up another 8x, to 32x total, by
buffering a long at a time, and reading bits from it.

I'd looked into introducing a get_random_bool(), along with the
complexities required for that kind of function to work for a general
case. But kfence is the only high-speed user of random booleans in a hot
path, so we're better off open coding this to take advantage of kfence
particularities.

In particular, we take advantage of the fact that kfence_guarded_alloc()
already disables interrupts for its raw spinlocks, so that we can keep
track of a per-cpu buffered boolean bitmask, without needing to add more
interrupt disabling.

This is slightly complicated by PREEMPT_RT, where we actually need to
take a local_lock instead. But the resulting code in both cases compiles
down to something very compact, and is basically zero cost.
Specifically, on !PREEMPT_RT, this amounts to:

    local_irq_save(flags);
    random boolean stuff;
    raw_spin_lock(&other_thing);
    do the existing stuff;
    raw_spin_unlock_irqrestore(&other_thing, flags);

By using a local_lock in the way this patch does, we now also get this
code on PREEMPT_RT:

    spin_lock(this_cpu_ptr(&local_lock));
    random boolean stuff;
    spin_unlock(this_cpu_ptr(&local_lock));
    raw_spin_lock_irqsave(&other_thing, flags);
    do the existing stuff;
    raw_spin_unlock_irqrestore(&other_thing, flags);

This is also optimal for RT systems. So all and all, this is pretty
good. But there are some compile-time conditionals in order to
accomplish this.

Cc: Marco Elver <elver@google.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 mm/kfence/core.c | 32 +++++++++++++++++++++++++++++---
 1 file changed, 29 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 6cbd93f2007b..c212ae0cecba 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -356,21 +356,47 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 				  unsigned long *stack_entries, size_t num_stack_entries,
 				  u32 alloc_stack_hash)
 {
+	struct random_bools {
+		unsigned long bits;
+		unsigned int len;
+		local_lock_t lock;
+	};
+	static DEFINE_PER_CPU(struct random_bools, pcpu_bools) = {
+		.lock = INIT_LOCAL_LOCK(pcpu_bools.lock)
+	};
+	struct random_bools *bools;
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
 	struct slab *slab;
 	void *addr;
-	const bool random_right_allocate = get_random_u32_below(2);
+	bool random_right_allocate;
 	const bool random_fault = CONFIG_KFENCE_STRESS_TEST_FAULTS &&
 				  !get_random_u32_below(CONFIG_KFENCE_STRESS_TEST_FAULTS);
 
+	local_lock_irqsave(&pcpu_bools.lock, flags);
+	bools = raw_cpu_ptr(&pcpu_bools);
+	if (unlikely(!bools->len)) {
+		bools->bits = get_random_long();
+		bools->len = BITS_PER_LONG;
+	}
+	random_right_allocate = bools->bits & 1;
+	bools->bits >>= 1;
+	bools->len--;
+
 	/* Try to obtain a free object. */
-	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
+	if (IS_ENABLED(CONFIG_PREEMPT_RT))
+		raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
+	else
+		raw_spin_lock(&kfence_freelist_lock);
 	if (!list_empty(&kfence_freelist)) {
 		meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
 		list_del_init(&meta->list);
 	}
-	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
+	if (IS_ENABLED(CONFIG_PREEMPT_RT))
+		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
+	else
+		raw_spin_unlock(&kfence_freelist_lock);
+	local_unlock_irqrestore(&pcpu_bools.lock, flags);
 	if (!meta) {
 		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
 		return NULL;
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221026204031.1699061-1-Jason%40zx2c4.com.
