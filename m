Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3E4TOPAMGQEI3DZRFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE14E66E3B1
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 17:35:56 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id r1-20020adfa141000000b002be28fd4a7bsf312901wrr.12
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 08:35:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673973356; cv=pass;
        d=google.com; s=arc-20160816;
        b=V/5HSkxuA1gdXGSR7G57kO+u7r6T3lCj7xtCMBhZQ58EGYHw9jYeuMN2j2w122Ax7y
         KxjvDsJj8KR1F7tc1GXtzXbQ3OEmxB9Ga33oASASgbDnyGI1OPywsNY3TPQV4jBZczx8
         WoAxhgYNRcSI3+vuF8NRhCh/FXNA9w5JvrqMR1CufwbYPlap2UPC/E6mDsbvF2zR/7VH
         N3bixjZhlu405wEQGSu3rq2MoYZqctzi8Y/I43JkZquz0bgkHrl5Zvl8ttZvM6gQff3e
         DO7xkfu38+ZsTpd74H5CkbbaLUMa4VEX5OrP76bQdS3bjc4U+/mqRu49Kuz0CfKBnulU
         iUXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=OXdcO5FzwB3Yt3HnwKWdcnrPZJinXsLGUXSTVduLv0k=;
        b=kRQ+kTbuW/x7iHgFELXzam77V2DZbkQYCbzvk0xABMYP1P8U5GeFxNrZD8CG9Z817K
         ChCD3LwkdMjvTAKKwtxf/96dL+nyK/WV+9izZBN/I82jQ2u3n+TnLRmrRbxL61G0XNFS
         2UceXLOlG21vUgN36t8ywaMya42yH+zVc19ewzJz8HFmza1CpvILTnXwzE9CDl7rgODe
         4S4/6jC9dc/EfGmzd5qwVjMKjxBmU8EgdM27Q34IEqGHMPkcJ55loXKW+O2Sj7V4NaMz
         EgJRycWp+Ll54BnBmjH1KmFuw8Svb/mEoO3SeyzAIkSS8W5vPv2JwvtPZEQksYLBi7Fc
         AcfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QeCeDVWg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OXdcO5FzwB3Yt3HnwKWdcnrPZJinXsLGUXSTVduLv0k=;
        b=O+3LmZOyAiDTeLjrJGgA4hHuxag9vVZAwxxtDxlbo8eDu5nZ6IDPJdanjqJfdQhXpV
         UcYxc5woM2MwYotm8RAyX7TyCgG3SyWENBuVBBA7XkhEXM06BAatTll416VP0eitioo8
         B22ifNKn4P7uYeYhwcRJ4POst0vBKcuI08/Le57K1O4SNgSQ8DL/G1wmIhOAqPR6H45P
         pmuZrgMthC7vub3i/2bDToQktkYR06iplspCDzcnQMN4ct0op9JShGhVUFgwkxhHd5wk
         6HDqatT5Qncss4Szy/05S0cKvNdEv4tdkwrH+Pr9NVSKXDsR2+KAToiRxIA0Qdua2ojU
         uXjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OXdcO5FzwB3Yt3HnwKWdcnrPZJinXsLGUXSTVduLv0k=;
        b=KuB7NPJ/WraCUGdj/MJnmFW3ysiKeaedp2pCoy8rH7numvXxqKvP87iOZ20cb/8Waa
         /5OaqCZstZl77zfx8uf5gJIADKmhPMW9eomKB2j3mJPMm8x++I5a0rNr7j40PDw4BOoE
         eb+1Jskk+spljQaZQ9kYeazSAEubYI8NkWNtCSVWU9wdRAOT47+icukDfZsg6DWP9UdA
         IDs1RcnQmjtLcJhNreJyFHPwIxr/DJeZM+L7QHPUwUcK80pXzDDdTEwEIPjw/TxcTMJv
         TOXOkkfG8Re7pxjDsn7j1QytL8FVhfNGfGE1oe4qj4xSC0n27qb+uL5laX1+tgr1m6Ju
         aSkQ==
X-Gm-Message-State: AFqh2krChbnMRiQ2mXnJ3qqHKjqZW/v6UGdJekzD1vspjDIypl6JOpFS
	VsoyXXeMIGnkL17P0Cb6Bjc=
X-Google-Smtp-Source: AMrXdXt9jXzwF5TwivJtPzFOqvHuQetLvibjEwZDlDaMWnbR2SPUSrhyNB7TJTc5NjKJpnfOh8fdrg==
X-Received: by 2002:a05:600c:4d06:b0:3d0:59cd:5a65 with SMTP id u6-20020a05600c4d0600b003d059cd5a65mr180295wmp.69.1673973356393;
        Tue, 17 Jan 2023 08:35:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d93:b0:3cf:9be3:73dd with SMTP id
 p19-20020a05600c1d9300b003cf9be373ddls9549849wms.3.-pod-canary-gmail; Tue, 17
 Jan 2023 08:35:55 -0800 (PST)
X-Received: by 2002:a05:600c:3d16:b0:3cf:8b22:76b3 with SMTP id bh22-20020a05600c3d1600b003cf8b2276b3mr3660759wmb.0.1673973355439;
        Tue, 17 Jan 2023 08:35:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673973355; cv=none;
        d=google.com; s=arc-20160816;
        b=SLFcgKYt9aKImcLwGXuJmydLBysCx5/nkX99yZdcJ5b92EXwcwxKWJcYWaMIRICX8p
         cXxEsOqbl3T4JmLvnia+WY83JTiYW08m+yh/pmwNYY14z9Oq/53Pbj4r2kzYcCH+XMVW
         OIcwA/T3T40Mhud9A5MoZsHK91k6G3xMU5t8KvPckylr8VE2yX1faQg916LOcYo6PTEE
         DBxLuCoXMMHmkiELlkVpbg9cx0U6vCFgVBx6TsBcNOEEOfw8oR4LG0miTlpH7fxHfGHk
         Dom5Loz7sDp1QiGewMSJHLYmvXuxDIVXxZf7TDVjAJ94ZwKtc07ZCkpjaC+33GeSyK9o
         Eh9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZnZx85Sf0ezER0rilQtZPHDwVHsmiiEfW3AZAr5ZtFc=;
        b=M4HmeNA4Cnhm1Dl9l9QJqlHb7BaB5CHk6jVqi49vJwFXbmSg62SFKccyCFL1r7r6cO
         M3BSmEKsdAYwklpPltUZ/CzqTebKgcDBVDu6FUaHv5SCU+AKUZOGmoFYfVom2FhoInHJ
         Gqo9it41+cjJo0J5FZHpaHDALPk2eyyxe7VQh5EYVWwyOSTBtcEpSrvH6REMMFte+QGA
         B0f8GBvP5a1Tl6B6mpk2YkygaqZWVeGAmnXj6eKAgKlpA+lwVaDEP0ADsPIVLn1rUWjQ
         XBO5VX9eBkT2bMPMTQUdMv1oE3cD08o764YuOscE70dMF5+PrhQR/o3ycPVxXvKDMA0o
         vD5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QeCeDVWg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id n18-20020a05600c501200b003d9dfe01039si606533wmr.4.2023.01.17.08.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 08:35:55 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id q10-20020a1cf30a000000b003db0edfdb74so65463wmq.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 08:35:55 -0800 (PST)
X-Received: by 2002:a05:600c:1d92:b0:3d0:30c8:c47b with SMTP id p18-20020a05600c1d9200b003d030c8c47bmr2335336wms.2.1673973354962;
        Tue, 17 Jan 2023 08:35:54 -0800 (PST)
Received: from localhost ([2a00:79e0:9d:4:9df1:9663:75e8:617c])
        by smtp.gmail.com with ESMTPSA id l24-20020a05600c1d1800b003db09692364sm2302292wms.11.2023.01.17.08.35.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 08:35:53 -0800 (PST)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>,
	Andy Lutomirski <luto@kernel.org>,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
Date: Tue, 17 Jan 2023 17:35:43 +0100
Message-Id: <20230117163543.1049025-1-jannh@google.com>
X-Mailer: git-send-email 2.39.0.314.g84b9a713c41-goog
MIME-Version: 1.0
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QeCeDVWg;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

KASAN (except in HW_TAGS mode) tracks memory state based on virtual
addresses. The mappings of kernel stack pages in the linear mapping are
currently marked as fully accessible.
Since stack corruption issues can cause some very gnarly errors, let's be
extra careful and tell KASAN to forbid accesses to stack memory through the
linear mapping.

Signed-off-by: Jann Horn <jannh@google.com>
---
I wrote this after seeing
https://lore.kernel.org/all/Y8W5rjKdZ9erIF14@casper.infradead.org/
and wondering about possible ways that this kind of stack corruption
could be sneaking past KASAN.
That's proooobably not the explanation, but still...

 include/linux/vmalloc.h |  6 ++++++
 kernel/fork.c           | 10 ++++++++++
 mm/vmalloc.c            | 24 ++++++++++++++++++++++++
 3 files changed, 40 insertions(+)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 096d48aa3437..bfb50178e5e3 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -297,4 +297,10 @@ bool vmalloc_dump_obj(void *object);
 static inline bool vmalloc_dump_obj(void *object) { return false; }
 #endif
 
+#if defined(CONFIG_MMU) && (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
+void vmalloc_poison_backing_pages(const void *addr);
+#else
+static inline void vmalloc_poison_backing_pages(const void *addr) {}
+#endif
+
 #endif /* _LINUX_VMALLOC_H */
diff --git a/kernel/fork.c b/kernel/fork.c
index 9f7fe3541897..5c8c103a3597 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -321,6 +321,16 @@ static int alloc_thread_stack_node(struct task_struct *tsk, int node)
 		vfree(stack);
 		return -ENOMEM;
 	}
+
+	/*
+	 * A virtually-allocated stack's memory should only be accessed through
+	 * the vmalloc area, not through the linear mapping.
+	 * Inform KASAN that all accesses through the linear mapping should be
+	 * reported (instead of permitting all accesses through the linear
+	 * mapping).
+	 */
+	vmalloc_poison_backing_pages(stack);
+
 	/*
 	 * We can't call find_vm_area() in interrupt context, and
 	 * free_thread_stack() can be called in interrupt context,
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ca71de7c9d77..10c79c53cf5c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4042,6 +4042,30 @@ void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms)
 }
 #endif	/* CONFIG_SMP */
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+/*
+ * Poison the KASAN shadow for the linear mapping of the pages used as stack
+ * memory.
+ * NOTE: This makes no sense in HW_TAGS mode because HW_TAGS marks physical
+ * memory, not virtual memory.
+ */
+void vmalloc_poison_backing_pages(const void *addr)
+{
+	struct vm_struct *area;
+	int i;
+
+	if (WARN(!PAGE_ALIGNED(addr), "bad address (%p)\n", addr))
+		return;
+
+	area = find_vm_area(addr);
+	if (WARN(!area, "nonexistent vm area (%p)\n", addr))
+		return;
+
+	for (i = 0; i < area->nr_pages; i++)
+		kasan_poison_pages(area->pages[i], 0, false);
+}
+#endif
+
 #ifdef CONFIG_PRINTK
 bool vmalloc_dump_obj(void *object)
 {

base-commit: 5dc4c995db9eb45f6373a956eb1f69460e69e6d4
-- 
2.39.0.314.g84b9a713c41-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230117163543.1049025-1-jannh%40google.com.
