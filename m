Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH4CRX6QKGQECAECMXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EB68C2A7369
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:39 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id f4sf1575ljn.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534559; cv=pass;
        d=google.com; s=arc-20160816;
        b=H/z321IJ40Vqf/qZ433z22GXyv0XYc1kgiv71+JItnAWBBmQbfRQ5Q5fOm0+soEARY
         4Ghy9Utrb99H9YHryWKqQmcLh9JvKuY6D5dmD4iZS0tsbWJaZYhmSo1cEmKnzrkRNuSA
         9LALI/Nii/y9ayFp0Es0fWGhB4BPFmUzcb9W8uiYEZyIvpHRJkCxsI1xqI3izVl0ouMS
         fWtwrbFHFewpwApj1BTIMYfvty0YUrCjLt3kQtV/kvXiVX32VsmBgTF3HirhIUF91PKb
         BNnrW5J43qmKs70wxmsNSNcFo/Lje383/fpUUM1FSkyjhCkCZiT9+GUnG5glrjUgS1sq
         HJvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YzUXLWwWQiQXP4d81jMPJ/SvvVK4JftBqJFV94Z8QUg=;
        b=uGhxorCZZJlA8/2X4bu1+AMJUTz6l8TJJiOk4aWQM6MLcOJn8IVP/oQl7i4lp+zCtJ
         0rm0ado83sKrtsnqUk5E7XftegNHlvKbL4vmBCjZJBI4EiXmsQ+xvf34C6nXTOlIK6uz
         UcEAGqtZfqHPGZcaKGwg3KOJ/buZ4SSuduDA5SCdMzmc8EYWHZSEOXA+YhE6Npiwqm3N
         29tgUaqWtyy21NEVX4UU/lz37ajRzra2GxY//vPpRXuceIXJ+YcrFMRcFd2rMd7GVXkZ
         Gh9P0G3+m1UcPV2sk/cHSt8h4K27wBS/wH4X4itysl/DmxwER2WQLxd8WT8Qds7ZOG0D
         4zQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TtFB7Uef;
       spf=pass (google.com: domain of 3hugjxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HUGjXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YzUXLWwWQiQXP4d81jMPJ/SvvVK4JftBqJFV94Z8QUg=;
        b=DD4KG/VJRnSJ9yVz2JTUHwd1SKv5fVT5R6/u6yQ0wdkwC8wSpBqfevWfq1xPu6t/nA
         pIMbJUmig0k0CtV72kfLMtB4lUEzvTMpAb+A8SrtloQ5Y6EEIhSsD1ZvVRG0BWEqBP+B
         BZngZVQutQaNclzCYQZ1zAAgDN0p74LX9EmINul7bLxgSiwa0irTGhG+o/l6zTm1rnnF
         XBVYldwx54p+Ai9dddewS6aZvilHfY62YsIsBXuvJKFGk6bFZ+4SBA/pI1tZa8YCndBU
         NPZf1VYoxqtVb3jgdfnV5QeCfzdTxgyj7pN5VDZxw4bE7nLQPXsK774CuRsDmlHk4BEY
         5dKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YzUXLWwWQiQXP4d81jMPJ/SvvVK4JftBqJFV94Z8QUg=;
        b=O7R0v2GBrE9rpeNjmkfborN8nSp6GaFD85kSBcfonhrJzVvkclP5RHSBoCuL1KQWpe
         Cz439oS//lwijQhS3T0XPZz0H4+uh6Td4vypSh+xwAsuz2tOnCjByGNvtDZhbBEaw1gE
         XvzXqM7CfNVu4u8Nk/5PDhNIo/8URPHL42YJ8V4jJehSlI/64ovLwU9Yr2fSCzXOcFv1
         p7IAhIsOY91F9uuNi5alRYE/CgvlFcKCHcbVlHkXHEoQiK5hNn/Ko24cJu+FYy1IKQ+N
         AEafufz2kaDJPNk1oa+lfcdX5O4uL4qYJlrEpWPydTmsV7We7NfdR/qov1jBJI7cvMRM
         N3fg==
X-Gm-Message-State: AOAM530nadkwon/RRg4h+JeqlqZy1Ef5smOyEB1xCzd8udLWe2F0Q0Yj
	k4RM7vMo7m4cWdVBnUJuevg=
X-Google-Smtp-Source: ABdhPJxpNBbCEXujBkjXQaQSkTs4QUQzPODZBWojYsyaVZUK4jUngGJ5J4G98/mLkFzSIRIBuBpm0g==
X-Received: by 2002:a19:8285:: with SMTP id e127mr74778lfd.270.1604534559532;
        Wed, 04 Nov 2020 16:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e89:: with SMTP id z9ls679476ljk.11.gmail; Wed, 04 Nov
 2020 16:02:38 -0800 (PST)
X-Received: by 2002:a2e:9f42:: with SMTP id v2mr163674ljk.316.1604534558416;
        Wed, 04 Nov 2020 16:02:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534558; cv=none;
        d=google.com; s=arc-20160816;
        b=v2GXlpc+1yfSUnIXhJ3vfpRMy7RTjuZ16f5axODFR/7oNjAOEErssgVjvkvILv5Jlz
         FIurj+a2qbgvrmgtHhf0p+/OJgL2Zxq+F6xMjnvXSTBWu20y6g9zrJlB8kJWabYv1rYa
         mlAEMcOrU01zQaUMU28aEn8fjndAy2XSRVRpFs+mzRdoUvaOmbFjefxgcWq/OM1kdEXu
         GYjIdUUlrISwA1TboAU8nzh7PVvbjUdEKSMXQ8V/EHUg5nHRk4uMqHGRA9Rim8VrKPPP
         lQyrZoYXZjGxBWQT6nvMrvEQWFEqfia77kIWgUORjNB26f0rDC++K7g4YIWBYAOKJaPg
         hXnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ocomz11lJ9KE0anC5CzM99SKlSLQ0mxGbD3mCLha9hU=;
        b=c1irSfq2FBBRurTsdylMUUW40Pgoy1IJo3YotCKqjgVIGE24sw+ady4SbhPymR9ADz
         QdxunX2M0gSMPcXYt8ZkUcssBFIVpg/9yEYcEv/iRJni7ACDtsJjPWPlGNqnVJd0tQEE
         gGGvZ79RwTqUumeGKRmXcWqxImDXyxfW2ATfF4PKc1mBNxbJzCa27DPFgxfms9gQlfkj
         AdrH8GsTonv+Bqeo1briQZHpJNbZy9ZCsyzqSjJ0M8h712gcyqLISuMqb+KUUcfL7v+Y
         v2/2n9NlzF5LLW3h+0RQSweUXH90/wzt7OmBaZ8XuaReixbjAjhcQdJLnsT1dwg2rOno
         OjnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TtFB7Uef;
       spf=pass (google.com: domain of 3hugjxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HUGjXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n5si113900lji.5.2020.11.04.16.02.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hugjxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w1so99438wrr.5
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:22d3:: with SMTP id
 19mr178957wmg.161.1604534557830; Wed, 04 Nov 2020 16:02:37 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:11 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <e6fab9ed577dc3861c3ea0bde82bfd04df2bcce1.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 01/20] kasan: simplify quarantine_put call site
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TtFB7Uef;       spf=pass
 (google.com: domain of 3hugjxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HUGjXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2bb0ef6da6bd..5712c66c11c1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b0a57d8f9803..994be9979ffd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e6fab9ed577dc3861c3ea0bde82bfd04df2bcce1.1604534322.git.andreyknvl%40google.com.
