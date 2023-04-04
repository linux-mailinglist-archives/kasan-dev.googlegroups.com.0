Return-Path: <kasan-dev+bncBAABBQOGV6QQMGQELSXJ7XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 82AD26D5B22
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:43:47 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id i192-20020a6287c9000000b0062a43acb7fasf14240217pfe.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:43:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597826; cv=pass;
        d=google.com; s=arc-20160816;
        b=mdAFUI9AVUVOeWRdQQcntHAL7bfIrgSdJjRgEjn0ZUNVi0x5rLOpMd88Oq/D5+2y/z
         EEGCG8JzsutSiPbsPUBxbYuy1IVs9hai6DnQWT0+S/Ae3Kv36UXG6NhJBz1S6vG3tt96
         BKtqPiXC0Qo4sHuodHGTIqgREIQPYtcfbaJ4uyIb3mQNSS6lNEpmP7BRo3Ac48r9mfuG
         GIuXB4G5VcE/b4t9YrYEgmInpikdl4JZP66d0jdFLvR5Mp1xOD6vq25NuBDdAjfu7llC
         8FppqYpwi1qHYyrc6K8LdUg/X17u3yWddEs7pH2H4KaH8S6Ohco28UcqUCtidLS9Jo+E
         yrBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GKFb8wwNDZObiAYYJp4keBOZ1JQ8pBqoQ66sDyaHsw8=;
        b=VLeVRiy/NuNjjdyKIN6+wuhzNavJa+ZMd3BgaqcCyR9zlz4ZOHmU1+AYnRmowdvuXb
         uyCWVAe8UxvH/UVnA+2irzCEQfw3ZSt4OixGE7zFVWs3OhaTXFiMHxGnk9ylZwo1/SqV
         RSg1EWWb48P+FBqzorYcQaQiRPh+R1tOcNnOWgQcBzgL9e2O9sJebboxOIimhuwy0Xx2
         y0NdLNhBEdPv0JZaolwhF6qWtHla9k0U/91fqN+lTiIPb+KOnumajx4UzSijz4q4EtZ0
         XLG8GZqiwEQ0lorD3SX9OzRde4gL0OenzqJFH97uBvAWLvu9gDw8bGpaNIqZ4zI/X7zm
         LBCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GKFb8wwNDZObiAYYJp4keBOZ1JQ8pBqoQ66sDyaHsw8=;
        b=KfmmTWj3UPk3fNqlfjrPMOuZmAelboVxxl4aLBkZArOESMCKk9Rm1GoK21aPuFlRHG
         SSrYmt0wN4uiSkjRw3iP9DsvfzBQ93mTRSyUOKRL5VUFHz1dNCztDhfoSO04JlamonGL
         f/EA/h6MDDgvnoBzG2ybaIdLf6l7WMiCstSK4gPLf2ZF9fbUtBzcV9NWpvEnvA8XYnEy
         r/T+DSUwOmOYLV2r7Xrpc8ehMe6b46QZ010kd/ESuKnNs8mRSpdg400q7MjDr+R9e3sP
         LdlqZVPdxuLAcp3ZD8w0i0dfeyVYTOoQ5rLliXBGcIwqitSX2iEDP/9Ln7J8OLxOqgpO
         xKVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GKFb8wwNDZObiAYYJp4keBOZ1JQ8pBqoQ66sDyaHsw8=;
        b=z2jvQ7O8AV4Y+kV2mS0qYPaVvZg4StR2eDdQXGfsvO+SgGn0D/vl7Kvaz/N30WPj/L
         5/hVFThSYhnJ1puyfwbDN/T6em/6lE0wsagia1YbtEhJ5q/NZApsGeGMXCxI2f+2iydK
         1Li+zquRAYH/XX8Tocde9FOEyVb96X9/DDBzOFMEp9Deqra2teIz6Iwauj3w0YInZPML
         tBvhblNzSACQPxyQVfB/4tLawGANq5iAo96xR611IqXYu5I8QoZMVxWvGGtqlQzHuMdP
         s+XyhLotlz+WPpfsZz5muKIG9KckrCImpSWef+cSPrDnfQxfb/FC1XnUFMVealfbpFH5
         9AzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9emUpGEMYfuCkLCz+ynGyttrOfDHgbU5x09SbMILipNmYM4/q8S
	vnh+B1Vgd/KzgunuQJ/18X4=
X-Google-Smtp-Source: AKy350ZkE6nxaqh/UOq3Fj/ePeQ+9L+DWsbB8QS5M1RTnFMvHkVL/kmM2KUOvHPemWJe2WcOWWkP9w==
X-Received: by 2002:a63:e705:0:b0:513:9709:17ee with SMTP id b5-20020a63e705000000b00513970917eemr462693pgi.10.1680597825863;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac02:b0:210:6f33:e22d with SMTP id
 o2-20020a17090aac0200b002106f33e22dls14527859pjq.2.-pod-control-gmail; Tue,
 04 Apr 2023 01:43:45 -0700 (PDT)
X-Received: by 2002:a17:90b:685:b0:240:5397:bd91 with SMTP id m5-20020a17090b068500b002405397bd91mr2129363pjz.4.1680597825264;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597825; cv=none;
        d=google.com; s=arc-20160816;
        b=pxmCUyUP1kUN0GFmBpnk9mVDfn4gwApFIEj73Ppu8rC75Eq6HQ3zbLXC9kZa0hlQPV
         3sn3NpKbO6M4gFRPXjh5MixVSp5vwhAtjGokKOReJNld9ak7wtGrvUsESQrobQ5AT/Ho
         CBgNZc4QSVAzskx0sqmXqewoQRibqDrEV6bKlLtoIF+nX7skAMGHBmSYA+VS4YuUy21F
         zl0lCv99QcgyG5tH6RiFTmySHpZkLPT3czqmtA+adOixnCmQm9TFdMt2KYSE7Aal4wEY
         Hisetfj4gxBbkWH4r1a/kttnpPGxcptsZwnmH2nPbid+kRYm1Ca7C5QLCLgxw8j6l07a
         xsQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=UVoDPEwl9zzWrReMqk0AQq31NzX8iUtFEhFKCcfSYL0=;
        b=wesm5DhgQ31KP7+ImqlIFHsFP6eqmKJntkLKX5teQPNn98cCPEZJelQcO2aDa5pVS3
         cRsEsAws1b3LuVPkTT52e7GodLkSm7mvgesW31aad46mT807LPs5IQDZ2XgA+JVDd9JO
         GeF/HHrWmyTCUdIWx02XxjA1Y1Du2sDg713CUI5bh15l+00HEt7LZHMaOkVphPwWlWpO
         U1Wxspt0DmowRwWggQ/q38K1TllPUHTo28PH2Di5lMBgEjnN8uAItOILFi/i+a7KaYSM
         7sMESzE/DencYOZMLXiY0NzsRzXEAUjZGD4xMAQuaAEQz3iwN+vCFJMpPzp3Rrhbl5Qu
         iX3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id b20-20020a17090a551400b0023dbbc039bbsi86221pji.0.2023.04.04.01.43.44
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8DxE4Qf4ytkqV0WAA--.34687S3;
	Tue, 04 Apr 2023 16:43:11 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxT+Qc4ytkChcVAA--.55041S2;
	Tue, 04 Apr 2023 16:43:09 +0800 (CST)
From: Qing Zhang <zhangqing@loongson.cn>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Huacai Chen <chenhuacai@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Jiaxun Yang <jiaxun.yang@flygoat.com>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 4/6] kasan: Add __HAVE_ARCH_SHADOW_MAP to support arch specific mapping
Date: Tue,  4 Apr 2023 16:43:06 +0800
Message-Id: <20230404084308.813-1-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8AxT+Qc4ytkChcVAA--.55041S2
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7WryDtw1xWw18Xw1UAr17Awb_yoW8uw4UpF
	ZrGFyxtrs2qFy0ga43Cr4Uur15JrnaqF4ktrZIgw4rCFy5W3WvqF1q9F9Yyrn7Wr47tFyY
	vwn7ZFZxJr90q3DanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bc8YFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_JrI_Jryl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVW8Jr0_Cr1U
	M2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4
	xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26rWY6Fy7McIj6I8E87Iv67AKxVWxJVW8
	Jr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JMxAIw28IcxkI7VAKI48JMx
	C20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAF
	wI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20x
	vE14v26F1j6w1UMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr1lIxAIcVCF04k26cxK
	x2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26F4j6r4UJwCI42IY6I8E87Iv6xkF7I0E14
	v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuYvjxU4E_MDUUUU
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Like the LoongArch, which has many holes between different segments
and valid address space(256T available) is insufficient to map all
these segments to kasan shadow memory with the common formula provided
by kasan core, We need architecture specific mapping formula,different
segments are mapped individually, and only limited length of space of
that specific segment is mapped to shadow.

Therefore, when the incoming address is converted to a shadow, we need
to add a condition to determine whether it is valid.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 include/linux/kasan.h | 2 ++
 mm/kasan/kasan.h      | 6 ++++++
 2 files changed, 8 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f7ef70661ce2..3b91b941873d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -54,11 +54,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
+#ifndef __HAVE_ARCH_SHADOW_MAP
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
 	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
 		+ KASAN_SHADOW_OFFSET;
 }
+#endif
 
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a61eeee3095a..033335c13b25 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -291,16 +291,22 @@ struct kasan_stack_ring {
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+#ifndef __HAVE_ARCH_SHADOW_MAP
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
+#endif
 
 static __always_inline bool addr_has_metadata(const void *addr)
 {
+#ifdef __HAVE_ARCH_SHADOW_MAP
+	return (kasan_mem_to_shadow((void *)addr) != NULL);
+#else
 	return (kasan_reset_tag(addr) >=
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
+#endif
 }
 
 /**
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230404084308.813-1-zhangqing%40loongson.cn.
