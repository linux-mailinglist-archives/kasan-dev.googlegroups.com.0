Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNHH3WEQMGQE6LQ5XHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E08FD402A84
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:12 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id k20-20020a05651239d400b003d91160994dsf2719169lfu.1
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024052; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovzQ8PttiKi7KIwx8NVU6mosNWTiiXaioOI2rn5blDjYRu7PAxRHM36PSaj8RwGuV4
         PWypDa2DFQd2MIMx9V0DF+ACvlS3hhmt6vuNqAy81Rjz3qnU/paX8MlI5snPKfQteX6A
         d1ZjeLYFCJgQpnO2jfCT2foPyufcWGAoAqP1rJieIw6SSyITVUQ4ejXmEMTuaa0N6Zu2
         5tMx4iD6Bq9DD5nBCnlAnGyYn7iE8wI/ZedLaRF+3n3amc421W8ZENL/zasdOtUtfAk3
         ChPgh+HfzBk/QXmRdswvVvvK4jPUx4E1h+vkbZVKFJioyDFu/YsEw6lSUwNKnv3Lc/j7
         PojQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xJZTpbXjxMG74543u9uAoYXUPs1wDhktvfYV1ploImI=;
        b=iar8BlzmI/wiRkN4tL3dprfxEDbvLLcE89pXTOM1FfIKooJbW0QkVh87f1g3QkaLVa
         2LHJ2QqPsJEZjn2pa/a2FtvK0lVwuFmHRD5LwwW+7osJtzIPX6jJhVZP1PSI4gORl3pT
         /AviwMunFMEMtfA7rYs63wgAXdGq1qgxy9zMa7WlBRak08QFPVUWPfahX4ATm33vF+cq
         TV9LgSrB244PGWGFAzD2KMcZYTixdR7Qw6toEYf+fjaWa5qlBDlCV+5HOPyROAnhReh2
         V5q4nis3fVv9dUYYILGIJwwXBMkMqZpZAAe5Trcz5H3ykyySyixuMtrihUz3n17PDvYy
         e72w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C+fu87Go;
       spf=pass (google.com: domain of 3snm3yqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3snM3YQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xJZTpbXjxMG74543u9uAoYXUPs1wDhktvfYV1ploImI=;
        b=TkwKcp/NbEL4EZOgAZRAr5xcyDnljQ2P3LpdUbPxhdDKj1xlanBosv9MdyPwkWvCNE
         MkuiVubypUP9lWyTa4Py35XdAvKcza9YnilCVdOweSUzVBLaMwKtnYxrldPNQUdB1NSO
         CC2iZQgU/1mqsywecolcQQvmfnKgbY2R5l7bA8AW6MDIe1pJfDm2MMBKddpuFaauY44H
         zHJbDjfMr5NX+Dai6eW32inoSajYKogJItDY/mqGigwaK1jYYsfMaP7JnMACb6tsGHQA
         TcwPHX+69vSPeY94lUGZyF7JfRIBhjBMdmB8cjGMzI3S2shKiJKHD8R5GLlJBcz3PJAK
         22pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xJZTpbXjxMG74543u9uAoYXUPs1wDhktvfYV1ploImI=;
        b=lkDlxjYYC5ferFaHMmRWGDFd4/MU0r7iec0uTH+AioJgKiyaNDmr86llWgPreXES+U
         fjb4eVG83dMiBXyohXpyY/4a384+zNcAjN6ffrp/+oS178hQPqV+pTNBdGiPgtrOo14C
         zQiq5pBfY2ItKcLHtLIe34/XhFzYmGZL395STrbYExgxBOkoCzIGH8B8phcUJY7N+QcZ
         3FmQg/7cMfj0Vmtas2oupgSjQ2dD9DvhrmEPuWeerPZTjoE2M+mi2HB5X1fDbp9YKbn3
         iB7HcwgqnWX4Mh58IUtLuO3pEbsoOYlAe7Bu4KU0r9QSdZOplWOumkLHkeh7Gia8be3a
         TPsA==
X-Gm-Message-State: AOAM531ntirAewXt+HMSNHU2uDAzpXbfP/BfZoi8EQBfc05VKH/KDPaG
	A2bWy/HjWAgP8bCWJVFECRc=
X-Google-Smtp-Source: ABdhPJxFWzRKw3Jaa/66/SBedTI0L6MTthfjX1wZF2mQf9FBIon3oLmcbILX9fgCKFuZtTZi6p06RA==
X-Received: by 2002:a05:6512:220c:: with SMTP id h12mr12538835lfu.398.1631024052419;
        Tue, 07 Sep 2021 07:14:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cf:: with SMTP id u15ls1750337ljg.11.gmail; Tue, 07
 Sep 2021 07:14:11 -0700 (PDT)
X-Received: by 2002:a2e:9055:: with SMTP id n21mr14917583ljg.451.1631024051294;
        Tue, 07 Sep 2021 07:14:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024051; cv=none;
        d=google.com; s=arc-20160816;
        b=i+pEBTEHOA2c1IIk6EpZPcLYYNVaOaD6o90Ld/PLk+0uE9+XhNQmDQQASvyK75Etqi
         arOwmcTtuHspC3KWTHDwndu+0fK0kUosLC/eA5l1nLHhPS6p56ECzfi67S7Im692bOG6
         sVRX1QTOKgygY2tBgHvnNlnQDGhYaComdcgjQhjhUdToiiArexX2iykPIFZDe66aZ7Zw
         PWxM1YC530DHzp4DCfYaHg7NXb42aalFB1TS1wK3GOqhefT6dU9/bCRlaq0u8gMk1avk
         AbkYAcclhWqDPTrsPKerGj7weXg9O4JNqvUOMfoZEHHmyCBkh99pBKZAfnXtvr5GXpOZ
         xOgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+Rc+8EwMgZeFDUhTR7EsEOP4LhinEf5yz1jFhEz7Lys=;
        b=hnYeq6DfPyvpkNnTDZ6dwSA3tzL+CkZYAI3hWtmfNjnQ9YdQH+RlE9EVAXFfkoZZ5+
         Jn0WIKAi+WH5S9KxOvfw4MP+UEAdt3MCo3fXEcsd7fGuKe9JGfHtQJmKClFj9DduZqCd
         cCF9yZf+eeOi45bMv10ZNFQPGkw86KHcaTLL3ecxi1AUiIGFbijFepKNagzavZQqzP7P
         XjzixD54n003PhWFDz06+5EWTSLVmODb0/W3umpPZgRNHqf9TJQO5HLXDSC0KvPrsXV6
         p4DRY0f/bp/f1+B1VgN7V6NPvXkcneauUCAvoqvEF8yN+NSoz9YIre83Xsd+satI7EO1
         lYEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C+fu87Go;
       spf=pass (google.com: domain of 3snm3yqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3snM3YQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b25si654285ljk.6.2021.09.07.07.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3snm3yqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v6-20020adfe4c6000000b001574f9d8336so2149109wrm.15
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:11 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a05:600c:4106:: with SMTP id
 j6mr4288917wmi.102.1631024050593; Tue, 07 Sep 2021 07:14:10 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:05 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-5-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 4/6] kasan: common: provide can_alloc in kasan_save_stack()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C+fu87Go;       spf=pass
 (google.com: domain of 3snm3yqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3snM3YQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add another argument, can_alloc, to kasan_save_stack() which is passed
as-is to __stack_depot_save().

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kasan/common.c  | 6 +++---
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2baf121fb8c5..3e0999892c36 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,20 +30,20 @@
 #include "kasan.h"
 #include "../slab.h"
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags)
+depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
 	nr_entries = filter_irq_stacks(entries, nr_entries);
-	return stack_depot_save(entries, nr_entries, flags);
+	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
-	track->stack = kasan_save_stack(flags);
+	track->stack = kasan_save_stack(flags, true);
 }
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index c3f5ba7a294a..2a8e59e6326d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -345,7 +345,7 @@ void kasan_record_aux_stack(void *addr)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, true);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fa02c88b6948..e442d94a8f6e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -260,7 +260,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 
 struct page *kasan_addr_to_page(const void *addr);
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags);
+depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-5-elver%40google.com.
