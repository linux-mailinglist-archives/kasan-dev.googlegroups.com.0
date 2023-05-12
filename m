Return-Path: <kasan-dev+bncBAABBMV262RAMGQE3HB44OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id ED0106FFE9F
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:58:11 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-76c66399a93sf223082539f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 18:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683856691; cv=pass;
        d=google.com; s=arc-20160816;
        b=UAfhabqzPCXdaz1q0fenIeAeUrVjsxZ2SrwO0lThKPqx9v7y2c8NNBUlLdy0GmasQh
         alRgE/mSwErncxv+vO9ttUxtuuViqOWcbSqaWrXdyDIHEmG1Zf2hup/IKRt4b7Delbgk
         y5FMxEHNsUXuE3rCU8z97s8Tzuxp4Xy9D+bth2hl7TddI4DhiYM7FeaJUHIKYrQDjj8G
         wdgXR8EOD//C1UMvgZNe3N+6FTS4mdzYm2G2sn3Q+I+aCwtdWvSLgxmenU9W/dgQdfis
         eoPe6lgGnlE40lF03q4sXo+DuENgWXS7QuoMEq35gFVWOf7ttaW+VtZCkzK9Q+dga6u3
         8qwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D6WQbuFM4WFoLB7Q+rJX/wAW3u5AshrGSP8pzBGjgoA=;
        b=EWAZjUA8uYDDF/oRkZZyGCNt5PM4ve1PceFp0UWvjb3MyhPbRXAg5+deG7QueEADfT
         RZf9mzfRL+Vim29r7wsYd9mFKr/b3Z6pkmkn1Rper5O//j6e6cQ77frGaHR92BY2oMAb
         a9tQA4KWp/8QjzfKhQDAWzeoi8VNy9a4No50aCGdH93UhT31LvsS8NvfvINKn9TIJ62D
         OtHFENpb6n/WUXVB52xVlNcn1JA1JdUrPR/3MKkg2f7cH0AMkbhvNP4L9UBjIeHQgEdl
         CjXYV9KbZTFWdxbwRcw9jMbvt5sE54LU2q2GTJTCN5KT1Q+hukn5peo8v4wULlc/seeN
         5FGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683856691; x=1686448691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D6WQbuFM4WFoLB7Q+rJX/wAW3u5AshrGSP8pzBGjgoA=;
        b=UG5oe8QaUSurSbjItEyaSjU9Q9KtrYpSFCWE12SccudI/ho2BQ5uatX6s4MzE1V9dw
         lz6qrR0Sr6m7fA6kopmtUByiypW7acDvoA2t2jEuVhS0nno5vgcFdmSs7aKcs7NCK0Hm
         e+RPG/FrCkZz4xKrttREY+VjreGeUJdHJ1VmL6+HrYUskJw+wnis0fXh0i1B8xxO1rb8
         19ewM0udORPYX//fR1sNamKtP98U3KWIXmEe/Op5cISwQrvq6UBPTK1EIA0u2sg7f8me
         VsJQ9SxtDO1vEkmUVszWfP14PALvfC5CpXLjFd2vHMmhqowdhe0xLniRC/qozY2K1eol
         QyUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683856691; x=1686448691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D6WQbuFM4WFoLB7Q+rJX/wAW3u5AshrGSP8pzBGjgoA=;
        b=hoFxV26AF/8EJGii981cZjks8y7Mnf60GURakUngDc6DZCSIsu0q5QT0CS3T2GjjtB
         jBnTbmzubT12kXDyjq/B6bYmfKLrhiefwj2FXlaW5xKT6oMwyHXFn4FJ3MZoWmRy8lJQ
         2jdG+50RKhbHuw6paBiyf9cByCCfQbTgDp7brEGAm4gpPcqoT3qhElVrXwHA/3bvS8Qp
         JFVujoK0HLnqxsFLgQ6CTxWKSCSRMh4PvrsmCnO0wsQ+SrBxdz2XopViO8t2JmT/L1zl
         pgMvChBZ1ECiavIDNs8VdfJqwvPI4SBK/s5crpDp2mvdPoP1BjRyXEL/P/IeTxs0uDNR
         TOog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwwi43E4zFTdbZsX2xYZN34XdPlXGLOkv+WB0+wG8MwkB9UNzFs
	jf5BSOTnTS3gP1OTrRA8pgo=
X-Google-Smtp-Source: ACHHUZ5vv0dzOJ1mhjcXupY0q1pA1FZGD5LlYQiTw9q5XBmvuEr3LTqvpETGIXub337vmtAJu1ZE5A==
X-Received: by 2002:a5e:a90a:0:b0:76c:7d48:d798 with SMTP id c10-20020a5ea90a000000b0076c7d48d798mr1900126iod.0.1683856690786;
        Thu, 11 May 2023 18:58:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a807:0:b0:331:4fba:5178 with SMTP id o7-20020a92a807000000b003314fba5178ls806955ilh.1.-pod-prod-02-us;
 Thu, 11 May 2023 18:58:10 -0700 (PDT)
X-Received: by 2002:a6b:e819:0:b0:76c:320a:3670 with SMTP id f25-20020a6be819000000b0076c320a3670mr13779789ioh.2.1683856690321;
        Thu, 11 May 2023 18:58:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683856690; cv=none;
        d=google.com; s=arc-20160816;
        b=U5UP/V3BISPtqkm5IlC/kHxuXtvoWBN5WTHlLJIE8MLSvfq3MmqnByUmpvCav9Qind
         dNrFd86SYhVyNJCV2x/detoDUlM+Fz8d7PFy1XcbZP0TaP1PrKos9CdmWOF6wFFwcOBG
         KEtvvjjDl9tmJ72rC3B64D8SsMHNnphth9nvi91EU7EgyytRAKZ6qhhyyVHXGxI4dHip
         a6LUDlToIlxaAc7E1+j5L3M55nFlVWBB/XGHVbl1t7LogeVNyZ5c81rZYPe7VyOt9yPq
         grZgIQ1etDT33kYPHPb2/zoyA6lOvoXbXK6DVpCcIxK5/8cKQ9HxUFQzOoEgVzOYgI+H
         96rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Kdd3ymX7f6cRcG6sLtOVJ1i26W6EVvSv2TVMUXcCQUo=;
        b=r+m8+owgxmm7rfBf4djojCPW5MnPlwOHp6NFmzIqefkudc2t5Ukss/ELhCUoFlpzV/
         yAwTQTcqE5b2Y3jVufIXKhDW+gY78k6GqkXhr6xxdNXNm+mdAtcJOOSlNDkeHIPOOgJh
         7/XH4bzU4/h5JkvFpbp0eMDXlfRbQxv/FKBCxT02Ipmfr3ej1IJIzJ3hhd/FpwHk9j53
         YQTcAtSf1+mbAVHARlCYLY5da4VKvFOPW2w/fKZ4cB+k8CA18YWZTH388AWzSOdsO2rB
         kLQbB6BNwPDZ14HlnLrrCfv6aK/Gl6i7VueM+aEV2RMygKhfXAVQlmD06ECJdVVV1+E+
         MaKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id cs21-20020a056638471500b00409125e3b19si1425212jab.2.2023.05.11.18.58.09
        for <kasan-dev@googlegroups.com>;
        Thu, 11 May 2023 18:58:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8DxDesSnV1kVfkHAA--.13775S3;
	Fri, 12 May 2023 09:57:38 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxXrMMnV1kocdWAA--.23198S4;
	Fri, 12 May 2023 09:57:37 +0800 (CST)
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
Subject: [PATCH v3 2/4] kasan: Add (pmd|pud)_init for LoongArch zero_(pud|p4d)_populate process
Date: Fri, 12 May 2023 09:57:29 +0800
Message-Id: <20230512015731.23787-3-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230512015731.23787-1-zhangqing@loongson.cn>
References: <20230512015731.23787-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxXrMMnV1kocdWAA--.23198S4
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7ArW5Zry3GF4fXry5Ar1UJrb_yoW8AF47pF
	WUK3W0qw47XanrXws3Jr1vgry7Jan3K3W7Kay2kr1rJ345XrWUXFy8Jr1q9rs8AFWkZFyS
	yan3Kr9xC3WDJaDanT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b3AYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1l
	n4kS14v26r1Y6r17M2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6x
	ACxx1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1q6rW5McIj6I8E
	87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41l42xK82
	IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l4IxYO2xFxVAFwI0_Jrv_JF1lx2Iq
	xVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r
	4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Xr0_Ar1lIxAIcVC0I7IYx2IY
	6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67
	AKxVW8JVWxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuY
	vjxU4AhLUUUUU
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

LoongArch populates pmd/pud with invalid_pmd_table/invalid_pud_table in
pagetable_init, So pmd_init/pud_init(p) is required, define them as __weak
in mm/kasan/init.c, like mm/sparse-vmemmap.c.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
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
2.36.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512015731.23787-3-zhangqing%40loongson.cn.
