Return-Path: <kasan-dev+bncBDGPTM5BQUDRB2XLYP4QKGQEFLX7ICQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id AF80E240262
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:23:23 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d2sf6926762qtn.8
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:23:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044202; cv=pass;
        d=google.com; s=arc-20160816;
        b=QlKfw/xbojjPDCKc6AUEjh3msE22ARSCgtO8OyXfIPKO2VSObn+v4de6u7m5c3zG1r
         sHTBoCvCVo1q+vFLEopyCNVR90m/r1EJqv1YpgWicAThK0okz+lKqL2P14C2m7Gm+RT8
         0bqrsVhICLOV5QAXS5wUSH/KfcJI4j5VU+qP0TG4N83ScG2XnbiHjwP1PBqfbxHbjt3c
         wRbG+cqtgKE70ffz9umLO8GdkG9NGw9DFUFPbvpmkyYh8JoATBWZLernMCJ3KOvuso1L
         nx3Nrga5j2rpJkGmRN9qQzWRMjjWztMfpGtUxv3FRIQBB9OavqkoR2HLbKnBJlfMqE8f
         fQsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dgDIw1c5ny2H25r8P0DLwh/hS8/MdHa4rDz1WF/OR/M=;
        b=MVfJg50HS4ih6gKrhtC716xH2kjulo2jECspuh+cdU6y6Aoxs7De36glSUklaQo33A
         tF47uZD839TPaxilWFDqJql2GOmi/MRnY/6iy0mMp+8cTxDfoUvicMIB0BgTMPS8JtIg
         QB6arFlW/MmtEv+hUiP9nbcb/chhs/v84sIsctJYAHT+jL0VpsaAFiM/FchksBc/32VG
         qs8RlVFJqWwqPjx6MANNZ/KmAgjjFkjL3qqdgEfjcmAtH8mV89ckuXHaJSZ8wBNm2k/I
         FkkJrGrVu3JxQBzCXrt+tnhK2mVCj4mXhO0GgdouI+iNavOclOOiuZgTUnVDp4vEVNgp
         eLOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=mUc+I3UY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dgDIw1c5ny2H25r8P0DLwh/hS8/MdHa4rDz1WF/OR/M=;
        b=tC4+mGKR5YaEVvxGAT2g2BA8iM4w5q23yH/lPunN9VzYMatzg/jBKr056MHYdbGu+i
         wy7hAAar9B6lLOlm08lbK3kt/I8XkN6JA+bGx4F6Pz0XWPFXykPJSK5tDOQixNT1zn+j
         oyauGLl76g8gtS20iQxwWqZe7qtV8iQkqBWj/i82a/upNNe8j6gd7M9wptzLiJpaUnPz
         rgdZ7+r85UWJn0cHJG4eYF5Bm86SpzpUQp/hf0mSckexgldPOO07KYtY0uOYJYve/7Ov
         vHDj7wIfzZelgcinqGZe2L8Hip4OjncbkbWgjJ5k2r/KPNzhTsG0LgAJpkrMC5FVqXj7
         6Uxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dgDIw1c5ny2H25r8P0DLwh/hS8/MdHa4rDz1WF/OR/M=;
        b=CkQPaYPnNca5+L3kneR3DbLMiBXhZrEQCAnZ3IkXV9dDDoMsDGRhHafLhljLPJjVU0
         9XkywjfAUj3XgMjh0F/5AGUTGdq6KtdkDnUrV9VjvRaeBeo6c2v+XoViSw2fQ8ZfgnGA
         Ww7sJO3zeUB/uSI8R44T6/Bf46Dgzb0nG+Cw2NPhHiIwbFlNviC1IRpvt93ZQ01yvZv4
         DSPviqu9YdgizlIHK/71Do7pqm6KNi9zD1A4gSIU48/KWCj2Sc9lH48F50w9aobYheOm
         vZ/A4EDmeER/S6cDaFtjrQkVVr5LE47tt5sl8akODijXUCyhkF9Wss5IIQ8k4VhojosQ
         5pAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r6HmLK9OHsFaIXsq8SvksV4SqHJ4nFR03nyK3zJavL6reokCR
	/AJvZZE2x/u15ka6MfSdSPA=
X-Google-Smtp-Source: ABdhPJxWebebD+xHZgtML5i51ioKsSWzVWAFLrLjXtY6Ymky5GuTVuEPK0G7dMSeFQ42g9PM8EghFQ==
X-Received: by 2002:a05:620a:759:: with SMTP id i25mr24959214qki.455.1597044202768;
        Mon, 10 Aug 2020 00:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7390:: with SMTP id t16ls6511022qtp.10.gmail; Mon, 10
 Aug 2020 00:23:22 -0700 (PDT)
X-Received: by 2002:ac8:152:: with SMTP id f18mr26578167qtg.163.1597044202459;
        Mon, 10 Aug 2020 00:23:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044202; cv=none;
        d=google.com; s=arc-20160816;
        b=KGjPdZ5yP2gHmsHtM8gTsbKg8QXhqx6Jv/ykmsPR3ovWLKUWZUSEp0AnChIOHv4jCV
         v/gnXa6rzrPfr0AvesUos+/Ca9eGkBdZTqF3vQmDthKzvbGq2uxF0e5W7dGMNkOhUezQ
         zU3ilIwaV3GX/n/rWEEmxOvBgNlu4mByBrdBH1MK3yj7soio8ziNrx9wrMwiMH6heppB
         wJMcjUDH/Z+eSnecj6WxImlzyNVGE6w6roLUP8rIgs5b6mqeH/1jPrKBMr8x4yEmcNRW
         CKL1NxERhPWXYWvJSp4Z9aS0D80b6y5pmCoHaaRpMSoKQohGB3mApvaOUFAP5TqPeNV8
         nChA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=PpSc/tEQuCx3Ee+gj4Ko/cEUAbvYmxsK1TcRUj0zqIE=;
        b=tSL3BQUeTtcNFNRTyDkCK4f3ttg85tEShQwig88dFQiCpApLGfgMKPgM4LzckNanQn
         u6WT4V9RWg1VucTVTF8SHUK5nshGLo4afeYPmM407d5p4nGCsymjWIki9eVPd4Mu1qO8
         3vqs3PL3Shar7dn7WVbL00g+OmSiIiBq6h8ANv+M8TZH4OdKiM3N6E7Pd31KCBK2DoEC
         kK0nmIUactB+s+l0qsW3nG6NE+6cTuhHcq65QBjPro/3FRMXVJSlZUnJj9WK+DNuvp4i
         T9O2gHVxZXsRqsz/zBo1xrAUHCtj68yF3ah/Th9WmOJdvoEuBrk4Ig51EkReO6OkZT9s
         P9bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=mUc+I3UY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y14si881610qka.6.2020.08.10.00.23.21
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:23:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: a2a2e3ec4d1e4852ae6c1321513c1dbc-20200810
X-UUID: a2a2e3ec4d1e4852ae6c1321513c1dbc-20200810
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1729549305; Mon, 10 Aug 2020 15:23:16 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:23:13 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:23:13 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: [PATCH 1/5] timer: kasan: record and print timer stack
Date: Mon, 10 Aug 2020 15:23:13 +0800
Message-ID: <20200810072313.529-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 98F01DCE42DA20CE4E3012D87E3ABB3D61BAAF8BDBEAA7561BC5D251A16DF3722000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=mUc+I3UY;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

This patch records the last two timer queueing stacks and prints
up to 2 timer stacks in KASAN report. It is useful for programmers
to solve use-after-free or double-free memory timer issues.

When timer_setup() or timer_setup_on_stack() is called, then it
prepares to use this timer and sets timer callback, we store
this call stack in order to print it in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: John Stultz <john.stultz@linaro.org>
Cc: Stephen Boyd <sboyd@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 include/linux/kasan.h |  2 ++
 kernel/time/timer.c   |  2 ++
 mm/kasan/generic.c    | 21 +++++++++++++++++++++
 mm/kasan/kasan.h      |  4 +++-
 mm/kasan/report.c     | 11 +++++++++++
 5 files changed, 39 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 23b7ee00572d..763664b36dc6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -175,12 +175,14 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
+void kasan_record_tmr_stack(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
+static inline void kasan_record_tmr_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/kernel/time/timer.c b/kernel/time/timer.c
index a5221abb4594..ef2da9ddfac7 100644
--- a/kernel/time/timer.c
+++ b/kernel/time/timer.c
@@ -783,6 +783,8 @@ static void do_init_timer(struct timer_list *timer,
 	timer->function = func;
 	timer->flags = flags | raw_smp_processor_id();
 	lockdep_init_map(&timer->lockdep_map, name, key, 0);
+
+	kasan_record_tmr_stack(timer);
 }
 
 /**
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4b3cbad7431b..f35dcec990ab 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -347,6 +347,27 @@ void kasan_record_aux_stack(void *addr)
 	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
 
+void kasan_record_tmr_stack(void *addr)
+{
+	struct page *page = kasan_addr_to_page(addr);
+	struct kmem_cache *cache;
+	struct kasan_alloc_meta *alloc_info;
+	void *object;
+
+	if (!(page && PageSlab(page)))
+		return;
+
+	cache = page->slab_cache;
+	object = nearest_obj(cache, page, addr);
+	alloc_info = get_alloc_info(cache, object);
+
+	/*
+	 * record the last two timer stacks.
+	 */
+	alloc_info->tmr_stack[1] = alloc_info->tmr_stack[0];
+	alloc_info->tmr_stack[0] = kasan_save_stack(GFP_NOWAIT);
+}
+
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ef655a1c6e15..c50827f388a3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -108,10 +108,12 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 #ifdef CONFIG_KASAN_GENERIC
 	/*
-	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
+	 * call_rcu() call stack and timer queueing stack are stored
+	 * into struct kasan_alloc_meta.
 	 * The free stack is stored into struct kasan_free_meta.
 	 */
 	depot_stack_handle_t aux_stack[2];
+	depot_stack_handle_t tmr_stack[2];
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
 #endif
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index fed3c8fdfd25..6fa3bfee381f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -191,6 +191,17 @@ static void describe_object(struct kmem_cache *cache, void *object,
 			print_stack(alloc_info->aux_stack[1]);
 			pr_err("\n");
 		}
+
+		if (alloc_info->tmr_stack[0]) {
+			pr_err("Last timer stack:\n");
+			print_stack(alloc_info->tmr_stack[0]);
+			pr_err("\n");
+		}
+		if (alloc_info->tmr_stack[1]) {
+			pr_err("Second to last timer stack:\n");
+			print_stack(alloc_info->tmr_stack[1]);
+			pr_err("\n");
+		}
 #endif
 	}
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072313.529-1-walter-zh.wu%40mediatek.com.
