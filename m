Return-Path: <kasan-dev+bncBAABBMN262RAMGQECVESBGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CBCF6FFE9E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:58:11 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-52855ba7539sf4991296a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 18:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683856690; cv=pass;
        d=google.com; s=arc-20160816;
        b=puCz0i8kms8JeXJrFMNgh50GPU3t0Co3LuZJX7avpopRxWWzx6Pr8ft+5Xy04aRJRU
         GtEC0JBdfrDOcpSrLQEw7tM8Dk9lNgZGFNVxmKOhMIynY2jgEUnGqmQosF+xMM00CtrC
         po4zARWERvDJLh54itLyjZF4U9G5fYgTvUp2sPUnEquTiRZoLXs/+OvB6ExZKKLo603T
         P/3EkD/KF8T3G2xlTNSg9ULgPbudji4ZQ9Q/+UZ8JgseyiYgrGApM946hbY0R+x1GEbM
         Lg/daHhvxIS9A5D4hRf1/QM/prH4pa5MfVNSLogH+ab2XOXOhtWI2v4N5OxhU/mW1W6O
         FvkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CzNXS0CI/Dan7SXpEhFRF/e+u01YbzlFOLPv27j2OwA=;
        b=fzMrZkzh13JpjiMplpmZhti+xHO1mPZNSom2njTaT7VSvaqkN53efh6pwMW113WWc1
         mKfyvVwjmlRwOU8j4uZkbfKxgo2HBPdSZbBnVnZikSrXSO7OznD2EC8uQWpO512H1mes
         q1y5Xn28hQXFQo2OzUNn8zPkPE9TqUuoJ2WOyFlTW1rkGZKsW3OQ87maMUwjn7Tx8XdN
         /W9+BJnvBy4Ncuwd6cV337RSwPfclIEDcbI+ZTMlORQ2HBm/w1CvENs2gh6BgBBeZl9d
         hJNv/a6qcpSz7a5ZXOFu9KbLGAaoIqKtLpm5NARot/KMQqG33vsgC5SB9+8mpwKgH2sE
         YuWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683856689; x=1686448689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CzNXS0CI/Dan7SXpEhFRF/e+u01YbzlFOLPv27j2OwA=;
        b=eu0N7WLjlCO86MV8LBrutaObhoRrYoL1PY3ALFFjVUAL3yj5lqoyhrQvKiDYQUe21v
         1BpdmYp9D/LeWYS+M5BCbFL5jJLXHK21Z+KEs50wqZYCT41JhPi+o9Js/R3/b4m7mduB
         AzX6HbDW7OSTqPHUYj9GaaGnvcFQ+UaqYHpXV5n4anWCV+mpJ2eQDdU11ZPOLcKf7gQp
         jBDtD//hlsA7uBQroLEVIFAcvZvynkj27h5TFnGnNpoiZtCJxbT7FYue1L9XkZ03C0a7
         xiSyz4z1Lel3Hw7kiIhBfxXRc0x465ASDBbT9MT5m6e+YoC8EGvbu+MYAY9T4TadYhMQ
         Kk3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683856689; x=1686448689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CzNXS0CI/Dan7SXpEhFRF/e+u01YbzlFOLPv27j2OwA=;
        b=aDNB6z6SQhXQ55WRJMZnr4Ckr80CF5cnOagR4CUm80Xwp6hW3vEHNTEE9DM10kEyDd
         CJ8dpVIn1I5rN5XdXdPP8wZCFMwtAstaGis/c2tzk6s12SIcVVsvsXezdTs7clpDN6Sz
         An7h0rhKruYrnTgNVE4OE5POIhwnLB2Z99YfBnKOwgB5LtmxHrbwPs16MXWGit0G3v5s
         3G/YwqpNUNJT9RHwj8t8rcGCAFvYMu1Ctjwh1zoEOj3dRK6tk6GgKqYkqzpLieTMRFKd
         X0R8qQ9+IJwMGnKDQFCOeJ6bXKgQUdUs/Pyat8MVE8Fy7KZoeHNFDZJnB8zzDPPlqAep
         pp8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx1z2Vsfb5B6OMmq4xzKFXlFb4h5MmoDLT7EmyKgce7DtPFiFAO
	eQJYGS5+uFb3abZ3s3MjgdQ=
X-Google-Smtp-Source: ACHHUZ40uJTFkAKccNaT70G+BwVnnXdka4dgvXk90R9hSDSmx0sEmq/8iQEvKIMu+vsiX1WgOxNSeA==
X-Received: by 2002:a63:6cc8:0:b0:52c:b46d:3609 with SMTP id h191-20020a636cc8000000b0052cb46d3609mr6094455pgc.12.1683856689624;
        Thu, 11 May 2023 18:58:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4293:b0:643:aab4:99be with SMTP id
 bx19-20020a056a00429300b00643aab499bels5347477pfb.3.-pod-prod-gmail; Thu, 11
 May 2023 18:58:09 -0700 (PDT)
X-Received: by 2002:a05:6a00:2344:b0:643:b68b:dd08 with SMTP id j4-20020a056a00234400b00643b68bdd08mr28288067pfj.30.1683856689023;
        Thu, 11 May 2023 18:58:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683856689; cv=none;
        d=google.com; s=arc-20160816;
        b=i2EEibnbl+ry9dwEoKuLF1HKQwGABqHB/qe3omawISjSYDVYHPrtxcoRHPoFOO83YH
         1Dox5pSk3fCZpVI/T8J4IKSEqRdHk2Mm1bGAfqBcNQ2BQo6kU1WfBYEnxLo/cuz11GF1
         1mPdAlXuk3i9PnAU0G2ST9ZyDLE6nHU4qylioBZ3O0SVKiNSud77Kgr2gWjX6//5TouW
         0UIi5DnHgd4UiEGakg91lHgPcQ7yPawdD6bN8pbFsUMCeL8aNwwftJlVE3QJbtQXSWL7
         A2ETTJYgctjpPBv9IWZeExKJsmlLCRWOQT0kxYe4CoSZZHcRkMx6Fcufm8UTvec1ew2b
         nGBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ufbFAfMCnpeCvaB/+yWOVkP2+lCWp1uAkGpe1WpI5Lo=;
        b=Hk8i01GgvP/0/byrG4UTtGA42YnsSMfop3/pJ6UQmVkTKz1D0Buv4rhLRdtVnPteKc
         GExyVZc2vfhFn4nJck12PTZxWz60DIFdkx8iOVyz5CGu5juqaBtKRi42LYJs9K6aMrf3
         5LE3vXa7ElNK0KqDEoIodV6wNVJdQwFoG5kr+q9zbgkMl1v0vZrNt4TWcgglbAi1THis
         wnZL9VLBF//O4aqHwwj7/msLM1XBlLo8aeiHZ+1VUqhIoShZyF+7QwI2zQHqwHI3tql4
         OTw8AKj9Oi9obRUXaDUTBWG1luiRyoMY9qJ76XO4eW/vZ1MuqmnZWrGjE9p2qRCvdPOC
         DZjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id z37-20020a056a001da500b0064364fb3b6esi786890pfw.0.2023.05.11.18.58.08
        for <kasan-dev@googlegroups.com>;
        Thu, 11 May 2023 18:58:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Cx_eoRnV1kSfkHAA--.13350S3;
	Fri, 12 May 2023 09:57:37 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxXrMMnV1kocdWAA--.23198S3;
	Fri, 12 May 2023 09:57:36 +0800 (CST)
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
Subject: [PATCH v3 1/4] kasan: Add __HAVE_ARCH_SHADOW_MAP to support arch specific mapping
Date: Fri, 12 May 2023 09:57:28 +0800
Message-Id: <20230512015731.23787-2-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230512015731.23787-1-zhangqing@loongson.cn>
References: <20230512015731.23787-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxXrMMnV1kocdWAA--.23198S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7tF1rKFWxtry3KFyUKr43Awb_yoW8tFW5pF
	ZrGFyxtrs7tFy0ga43Cr4UZr15JrnavF4UtrsIgw4fCFyUWa1vqF1q9F9Yvr1xWr47tFyY
	vwn2vFZ8Jr45t3DanT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b3kYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAa
	w2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44
	I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2
	jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20x
	vY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km07C267AKxVWUXVWUAwC20s02
	6c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GF
	v_WrylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVW8JVW5JwCI42IY6xIIjxv20xvE
	c7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14
	v26r4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x
	07jz2NtUUUUU=
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

MIPS, LoongArch and some other architectures have many holes between
different segments and the valid address space (256T available) is
insufficient to map all these segments to kasan shadow memory with the
common formula provided by kasan core. So we need architecture specific
mapping formulas to ensure different segments are mapped individually,
and only limited space lengths of those specific segments are mapped to
shadow.

Therefore, when the incoming address is converted to a shadow, we need
to add a condition to determine whether it is valid.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
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
2.36.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512015731.23787-2-zhangqing%40loongson.cn.
