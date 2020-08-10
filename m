Return-Path: <kasan-dev+bncBDGPTM5BQUDRBY7MYP4QKGQESIPEZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 18FBB24026B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:25:25 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id 19sf7177065pfu.20
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044323; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0nSr8xUAtNf2Vyrb01Uhzqw31mUeZfc7v6HS564I8f/LBrCI4mjbcz9zYOANiyELZ
         SIP0F27t3NEZQ65uz1VQ3ZcH35z0VlVLZoJCN1WZZq1b+u3ecsRbghAhfJqzBt4qwEo5
         lQFx51jmYitNLePVxrrZIekk0G6a1qRqn/g/vV7ccusqo2hq5wqC+6mnwFunx0kyS6/k
         mFqQmJnZYOD5fXez6W+rMPz2vyD9Sv4Spm3XJ0wFuAJguK96FuWGK4uzr5FDpTFauGf8
         rXZvcBHdSWchPDApDomdrpC2D4L4tfMkN7FXYa4CHRfg09DfsLe9VForgkEi4T3TB44W
         t1JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nU9sAo7iGyr/4/QJ2bpXW+KiJUEmWqcXdTwFpcePpWA=;
        b=zxRN6ZFk9GMZc4H3fZSB1fr5IEvyL1aXtlG6inRzpML4k8CrklziniCX8Q8waymtS+
         e41wp9O+b495YrvIaXwDC6elEkxKYoxqdArTECNx4nLTV4A0Su8MzjTaQEwnnmFPhPEG
         u+0OK2ql3e1wZCG9RrPJyWhFBrbAgBR4ipioWqaPamqKwtf/2KsX8c7zW9j4w2ISfM6S
         LfekmmcCV5pZ2GKa8qbU3Xy6xIEp2+1e+QHYcm/1jRsm7wA5GnWP9+1C+9WySvi+Imrm
         00UIw+AQ+P7YB/fnsqs6BXAiORlb1ZdwhabfjBiDg0Q7Nks7GOcCDXexJNEAOJKCRdj8
         ZsoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=s6qdsFqZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nU9sAo7iGyr/4/QJ2bpXW+KiJUEmWqcXdTwFpcePpWA=;
        b=haZX2bQAa1Qf9G8hKjBpxHBCB0nUiK6WXmrwClfig55ZnTFiXm27MEoBk6Xtu2NZ1f
         KsxgcYJxvNf5GuTYvesYNCEMXwOc9zaA4tjccrBeJW48ZYXzb9EZFjl2Y5p+I+90IqSx
         By5+WSKoZB1rN1yx8khzitQ82F9TKkVs5XpFbdjNDSAeOy4KTA5sKZ5kVPGD949arp6L
         Sa3fZVJJJv4xBMpj+Dqqd4+B+V84DP0rd9tpx+I3dzx/3FjATZw1I3Eowx5E1fPPAbIf
         tfes+Nt1/xxBdxn6gpSGIQUfE+hTG8vtYUEc0E42F1QyziBgCU+Zhhy5yq3d+ZFQnE/y
         txXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nU9sAo7iGyr/4/QJ2bpXW+KiJUEmWqcXdTwFpcePpWA=;
        b=gDZAO3Rai1qjUSh1GoNvC09T01sGmjsLppVOEIaUWb3W8gNDdNcBC1q1HSEnDXtftk
         6DcOmu5Qazc+hPAzieXPD90DD04p8Yy04Jvw0wCZ1BPqhxvoKSPNmM8EPDsNCogG7IYT
         vmw49D3pkc/UVYJWd9dX2g7kVVepuJVPYSE2ZnSVo4pcX2kigVFe5eFLPZlCzrv4GcQL
         Baa9cshvnerAJiKhYdj79CjE4aCxFVzjRFEhA2XHY1BHtDY5b934VBtvSjPu1yBTsRC8
         TyGB0MByqZxIds7tQ1xAf9kKtt9+uRaMR1O8icGfLlOsUHgkV8Gxxy+QYnpgkXaS9T9/
         shrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cIArRmdelWSMfpq2j2Aexl2ayw7s9DzbiltCiqDlG5IyGRgHW
	H4phb19HpiNIAbPjDrg1YkM=
X-Google-Smtp-Source: ABdhPJzn3RSD8uVbw7dJTfFMRcSCpO/lndbWwbsrXvnmMsmOJnPq3qIy0Rx3f+/czTQhmJu0llDlVQ==
X-Received: by 2002:a17:902:8a85:: with SMTP id p5mr12517609plo.193.1597044323277;
        Mon, 10 Aug 2020 00:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:88c4:: with SMTP id l187ls2070878pfd.6.gmail; Mon, 10
 Aug 2020 00:25:23 -0700 (PDT)
X-Received: by 2002:a63:2944:: with SMTP id p65mr21798737pgp.271.1597044322912;
        Mon, 10 Aug 2020 00:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044322; cv=none;
        d=google.com; s=arc-20160816;
        b=SI0vct8P7PY01fiYm6AXc+565uyF3B9GuegUwI4MKp0279PVe9mOtr9d0DjrQ6bC1P
         6cR04InGpO8P0/zo2n2SNFyrwnE/oTUdxPZUil1kKiEHmuqzsitphTt+ZbmdxjPjCIgh
         1zLUfOCieUgnkVfxPsifhjFayEqAVx1avNLRl1ImgcxfTOLbKcQ1Zl8nEHD268c8dw5K
         pGPfpH7sBJk3DEWjM95QIxtcp9vLDMxd7ViFvyVXrgCn2PakqWjR8Sgt2GcRqweiHAJv
         GqYFY7PWalQMnRup863jJuQ/b6auCRJFA3D3GL9Gj8vxAA9BWQRfqaI5WqT4EmMfiwk6
         DUmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=WMW/SN71MKFExQk+QjN4pv2EvhjdGtOmUqiO3skR3Gk=;
        b=o6u+x6XVlBXcayRiYlKWpfCjmy/QCXB69YzrHpzGZ0mzJhFC1/QAeXAdDgKMxgL56r
         oUKOwjjfsKGqyB4ZMPeau9vkbbA4CdAy0Rg8N2xieMhmXmDjYe69lqG5Ryb2qblqQzsN
         ybmwv3W9KY49yCiIYFOc+GAx06dfCtZzI/ztya0RHkFpyMSn8RghSwWPHMvotCLi86uR
         n2SR6O03iBRIy+2ZEXcWLkFflDPw5m49j1LhtEv2u0xBBRKgRvALKI9xA7LtGTvdE3fH
         x52kejU6+LOOEhW6tjTvXGxrWMfThDQK6bIU5+zqUW1vN2LR+LrdP7te2DjA4WQVRtz2
         HehQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=s6qdsFqZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id j4si1155848pjd.0.2020.08.10.00.25.22
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 941674fcae4649e68bed1d030d86ddc6-20200810
X-UUID: 941674fcae4649e68bed1d030d86ddc6-20200810
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2068200356; Mon, 10 Aug 2020 15:25:19 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:25:18 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:25:15 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Tejun
 Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 2/5] workqueue: kasan: record and print workqueue stack
Date: Mon, 10 Aug 2020 15:25:15 +0800
Message-ID: <20200810072515.632-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=s6qdsFqZ;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

This patch records the last two enqueueing work call stacks on workqueue
and prints up to 2 workqueue stacks in KASAN report. It is useful for
programmers to solve use-after-free or double-free memory wq issue.

When queue_work() is called, then queue the work into a workqueue, we
store this call stack in order to print it in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Tejun Heo <tj@kernel.org>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 include/linux/kasan.h |  2 ++
 kernel/workqueue.c    |  3 +++
 mm/kasan/generic.c    | 21 +++++++++++++++++++++
 mm/kasan/kasan.h      |  8 +++++---
 mm/kasan/report.c     | 11 +++++++++++
 5 files changed, 42 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 43ae040ae9b2..687cbf2faf83 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -174,6 +174,7 @@ void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
 void kasan_record_tmr_stack(void *ptr);
+void kasan_record_wq_stack(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
@@ -181,6 +182,7 @@ static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
 static inline void kasan_record_tmr_stack(void *ptr) {}
+static inline void kasan_record_wq_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index c41c3c17b86a..0e5963e06730 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -1324,6 +1324,9 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 {
 	struct worker_pool *pool = pwq->pool;
 
+	/* record the work in order to print it in KASAN reports */
+	kasan_record_wq_stack(work);
+
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
 	list_add_tail(&work->entry, head);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 627792d11569..592dc58fbe42 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -367,6 +367,27 @@ void kasan_record_tmr_stack(void *addr)
 	alloc_info->tmr_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
 
+void kasan_record_wq_stack(void *addr)
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
+	 * record the last two workqueue stacks.
+	 */
+	alloc_info->wq_stack[1] = alloc_info->wq_stack[0];
+	alloc_info->wq_stack[0] = kasan_save_stack(GFP_NOWAIT);
+}
+
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4059f327767c..a4f76b1bde0a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -108,12 +108,14 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 #ifdef CONFIG_KASAN_GENERIC
 	/*
-	 * call_rcu() call stack and timer queueing stack are stored
-	 * into struct kasan_alloc_meta.
-	 * The free stack is stored into struct kasan_free_meta.
+	 * call_rcu() call stack, timer queueing stack, and workqueue
+	 * queueing stack are stored into kasan_alloc_meta.
+	 *
+	 * With generic KASAN the free stack is stored into kasan_free_meta.
 	 */
 	depot_stack_handle_t aux_stack[2];
 	depot_stack_handle_t tmr_stack[2];
+	depot_stack_handle_t wq_stack[2];
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
 #endif
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f602f090d90b..e6bc470fcd0a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -203,6 +203,17 @@ static void describe_object(struct kmem_cache *cache, void *object,
 			print_stack(alloc_info->tmr_stack[1]);
 			pr_err("\n");
 		}
+
+		if (alloc_info->wq_stack[0]) {
+			pr_err("Last workqueue stack:\n");
+			print_stack(alloc_info->wq_stack[0]);
+			pr_err("\n");
+		}
+		if (alloc_info->wq_stack[1]) {
+			pr_err("Second to last workqueue stack:\n");
+			print_stack(alloc_info->wq_stack[1]);
+			pr_err("\n");
+		}
 #endif
 	}
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072515.632-1-walter-zh.wu%40mediatek.com.
