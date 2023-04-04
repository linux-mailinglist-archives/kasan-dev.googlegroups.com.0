Return-Path: <kasan-dev+bncBAABBQGGV6QQMGQEERG2QPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F3C16D5B20
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:43:46 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id 9-20020a5ea509000000b0074ca36737d2sf19173148iog.7
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:43:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597825; cv=pass;
        d=google.com; s=arc-20160816;
        b=UZCJ3sfIlnibN1zcLrqlzhGGztOTuVeKmPF2MCsQL60fq1QiWABZ8/LgDUWvLgdJUf
         ramNdSUWS/R+0ZBnmI6VMT1pQxa2srNwUKB6bLnGSdLeqclvFrLBkA6FaTr7B3xnbDnt
         9/A4bx0dzyBUQ8t33reGV/JVeqNE6WueHFsnOoZZPKyGlH9AJ7rNfTT9MMH3ai59Wnp6
         0dp9oLTq1y7zH2jrvnXj9rBbMUREaNs0KuLWVpku3saPdei+Zzh87y9R2jZoA4PXrAvh
         1gqV8vZc5ngZa4NTz58VWxxZ6QuXq35C/H+ZgBOFZO6NklbjAE/fGy1axdF8w47HTeAB
         BUAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gjVlZGnursOVbGLGhtvi05V5nZoXRfKKHPj9r+u3t0c=;
        b=IJcVeIRb72BwORWZsaZ0FHShW+1rMPYc1ZYAauwM9DnVPJn/gYnQ4Rq2daTuhCSfcu
         WSb/aGTO6vBRU9KYnNpVSJaLH1LN5uFZ4cXM15NQWCO3ebsytfwlXR0ydUfjBUr1KFec
         wt9+53MCjhN/9vCgFA1ldTJhhUerP+hDUjNUlkRG9TdnaXaDTW8nOvSGUrLaoSd51Goq
         DcDur6wgLXRbP0pbkSyBKR93pnznTT+g+fa3tNN7dBznQI/Hjo/Pbp4K6foKdoa+1a0i
         swapxIRDBjUE9dN+Y8HQ6HXaAQyIpfVnblZJRh2/rvHMwgnuY49i1f8pITJrkPMeytw1
         dvvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gjVlZGnursOVbGLGhtvi05V5nZoXRfKKHPj9r+u3t0c=;
        b=G9jOVnhxXHDplvhlQLPEShVKoNCCgCIMiViiD0wbKOF9JWOGDVvpbuq230jhz6XScJ
         tnBrDkkXzNSEgzAZp7IABStNPL97CUmkQyKIluu6KqHUt9HVN90RoDZBIPJQPqUlRu4g
         muYOmzpwkONMrY9vuR7AmvJccyinqkoSiE/WgJAkSfd9/pRs2GEsTK99SjlmT1g2Wxz/
         smbiGKgf1m9BBwOlEOWo7w5GhklOtfvptcpeTJcSp4ZWrEeWBLLLBDU4T+w7Gsx6fOJ6
         5gZm0oo7ZcTcZaKFT4ejbG9bNNVaEnaNfCgqfVD3AxyXCDFakddzOVNAC2NuMaPiAqbR
         akew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gjVlZGnursOVbGLGhtvi05V5nZoXRfKKHPj9r+u3t0c=;
        b=qen0HBint/T2A3gPFeKO411P5/KqfFl8ZHeelAEbDDRlFWdPGq/ZGTJHJhi4mksMig
         hHIhNRPtThWmXicTWT0pKMljyH43IAfZo1B+VE8vbe2A2W0NDjpfs67Wsz4gLaHy+Mfm
         19CYCak8Ya8f9qj3ixZtQivnSCOiPd4NH0ohAXtDXlq+rcplDC/i3U1ajD3Om0ld1tV4
         xFTIwc079XzgmMOBVRuTMqb3adKqkcEeK09pKAyJ+It0ZrDLzzYITbhwZOJtz4hN7pZ/
         0tcOQd74cb6k4fsmpU9HFJzHczmO59fANDijh8/7g50qnRUojSN/dNPyQ6llZdzO6MKM
         AWKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fCf2wfa5gZz9cYfbn8BfKRFLv6kc0QGy7e5SpkihpGfAy9rHJG
	lsGCLJvwZGe5NdvDUNOFQuU=
X-Google-Smtp-Source: AKy350awb5XapMXmOB7Crm/KQ0CPVxylL76TuwaC9jJS9+rS/2mMr3oIuKX9Am3kwNf6fbVU4MZDjA==
X-Received: by 2002:a02:b181:0:b0:40b:43c2:4a7 with SMTP id t1-20020a02b181000000b0040b43c204a7mr1236246jah.4.1680597825067;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:15d1:b0:74c:8f72:2953 with SMTP id
 f17-20020a05660215d100b0074c8f722953ls2818519iow.8.-pod-prod-gmail; Tue, 04
 Apr 2023 01:43:44 -0700 (PDT)
X-Received: by 2002:a6b:7016:0:b0:758:d404:8241 with SMTP id l22-20020a6b7016000000b00758d4048241mr1744117ioc.7.1680597824719;
        Tue, 04 Apr 2023 01:43:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597824; cv=none;
        d=google.com; s=arc-20160816;
        b=WgDJMNZGIgj4Qw7GZ3ZtbQhffj8nKrAuXvlYEg9MSpiY4/hTYpuEARMTuK8DjgEze6
         61fg0eu8OSRViHqd1X7K2iYjRTXu1HBUivsb7On/aaOEQvPwy1HCMlXYA7xAPQytOS16
         YnYxqSPzySmJJsXh8Xewo5vo0jLTnxqgM7uTG363z6o12eimtheMmzg2dZFfUbrAhkFB
         x3sYG3QgVGpRVHfMG5oDOHtbhwCdMCYo7OgA1BqGM+IzQuFv3Jcul5t8WWblGfLNTcBV
         Yp0Wad8KByeQP5HJCDs9wRaa/2wioE/gH9Q2wuPWustkJozL83AEftOWV6h8rD7yQS1X
         efQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eraKDZXAVWRAoDpzslhZKrcjIAmbAugbyfi3AGnEHjo=;
        b=edeGsWWUeMDK34DC8Igrx+Hqj+uCz+PlF+/FFMbUpzrqucPejEo8iNn5cnXAGT3mIi
         KdLavdCtZ0A1b56Kywu/63DBJSYw86yV6dE1OIb5PSCcZlm6/mb3zCjUJcc+iKfs7d6+
         w6+WCzTS3gH1zqMHISoHFNNBrnfv8F6f5/JMQhpdPPwkD6gThDtaKYqQ3tkvPAxAZTBb
         lZDR5tHaZaCD3klhQPXXo0mhjxDuNuC31kTFEGaoBwKhTZylVHcZNYNkaV11GIK3V42W
         +V9ekWzC3Xf0bweeM9grzYgjkdC3evMtHOLI/+kSygwU/JDtf5Arau4ojtk7kM282J7f
         966Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id cp14-20020a056638480e00b0040619abb9aasi972291jab.4.2023.04.04.01.43.43
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:43:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Axu5cg4ytktV0WAA--.34601S3;
	Tue, 04 Apr 2023 16:43:12 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxT+Qc4ytkChcVAA--.55041S3;
	Tue, 04 Apr 2023 16:43:11 +0800 (CST)
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
Subject: [PATCH v2 5/6] kasan: Add (pmd|pud)_init for LoongArch zero_(pud|p4d)_populate process
Date: Tue,  4 Apr 2023 16:43:07 +0800
Message-Id: <20230404084308.813-2-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230404084308.813-1-zhangqing@loongson.cn>
References: <20230404084308.813-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8AxT+Qc4ytkChcVAA--.55041S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7Zw4DXF1rtr1DZry7tF4fZrb_yoW8Ar17pF
	WUW3W0qw43Xa9rXws3Jr1vgry7Jan7K3W7Kay2kr1rA345XrWUXFy8Jr1q9r45AFWkZFyS
	yan3Gry3C3WDJaDanT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	baAYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVW8Jr0_Cr1U
	M2kKe7AKxVWUXVWUAwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zV
	CFFI0UMc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWrXVW3AwAv7VC2
	z280aVAFwI0_Cr0_Gr1UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04
	k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km07C267AKxVWUXVWUAwC2
	0s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI
	0_GFv_WrylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVW7JVWDJwCI42IY6xIIjxv2
	0xvEc7CjxVAFwI0_Cr0_Gr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87
	Iv67AKxVWxJVW8Jr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI
	43ZEXa7IU02ZX5UUUUU==
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

Loongarch populate pmd/pud with invalid_pmd_table/invalid_pud_table in
pagetable_init, So pmd_init/pud_init(p) is required, define them as __weak
in mm/kasan/init.c, like mm/sparse-vmemmap.c.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 mm/kasan/init.c | 18 ++++++++++++++----
 1 file changed, 14 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index cc64ed6858c6..a7fa223b96e4 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -139,6 +139,10 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 	return 0;
 }
 
+void __weak __meminit pmd_init(void *addr)
+{
+}
+
 static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				unsigned long end)
 {
@@ -166,8 +170,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				if (!p)
 					return -ENOMEM;
 			} else {
-				pud_populate(&init_mm, pud,
-					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
+				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+				pmd_init(p);
+				pud_populate(&init_mm, pud, p);
 			}
 		}
 		zero_pmd_populate(pud, addr, next);
@@ -176,6 +181,10 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 	return 0;
 }
 
+void __weak __meminit pud_init(void *addr)
+{
+}
+
 static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 				unsigned long end)
 {
@@ -207,8 +216,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 				if (!p)
 					return -ENOMEM;
 			} else {
-				p4d_populate(&init_mm, p4d,
-					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
+				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+				pud_init(p);
+				p4d_populate(&init_mm, p4d, p);
 			}
 		}
 		zero_pud_populate(p4d, addr, next);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230404084308.813-2-zhangqing%40loongson.cn.
