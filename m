Return-Path: <kasan-dev+bncBAABBQOGV6QQMGQELSXJ7XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A4DE6D5B21
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:43:47 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1805c875a3fsf5666444fac.17
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:43:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597826; cv=pass;
        d=google.com; s=arc-20160816;
        b=XE7PR5+XBV4wSIOsl4dKolzLfue0dKhY8ZeSA4834kEVbmnKS52fOBHscVYvPzP0jr
         XIubx8jKRPpfbI7kTdSKg8eQZ2LWoccg83hkbfL0/MfLYGM0uGAU04wfLOO2DPa5q2za
         v4ihoh8vkY8lo6KI0Xdkfl2LwibPufx6a1OaDTAGeYTNf3StwDCm9flFsnBmChPOOy2m
         ylf+6z1CMH+5TuKMx/KSmAGiUDhrspKH1Dpqxb/R9Kva042JHd8GxwNWE2FPNjHZSuFe
         XnB9B1Slpk0G3exfc1pMycXg+DCmVnsJJa6GTkqpu3SksqlUFy3vnchNAV1UnVJ90PKo
         5Twg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Se42NY44veYM1gEe+3FXH/6it48ZhvYHhFyJpp2E9s=;
        b=HyYZsFZYtR22cgV1QE9v6BlBpT45BB6rx9gQu6zFjgdRT3kSgWfMB7HfPFichVmOJF
         APaYPKis4sDpBVkIvQCNuBHPUe2+8bufef8nsVgdUKQzcTFoJoedCxR9GusdbP2ZcF2K
         L66ecjgkrOdmixPKtwwewXvuWbxFygYGfGDMzXi2yCPklbNF9l1EWPNmJkY9xuKDqzoF
         9v/sbXOnJpOEWgdH0j8P7jkB4C8DK6iBG8NsQNI/Y0gfTjeX+qLlxakTJfxbFf4Rw0qv
         l6U7Bmwf7V0tSC4VwfWeLSHVHsKHJQsGeFdxb4OAlegrgWG99tzaGWOJPpc31sE/iTzC
         z0cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Se42NY44veYM1gEe+3FXH/6it48ZhvYHhFyJpp2E9s=;
        b=InBh5l2Y8ec/zLz1vcwi00NaT5vqqQVJ8/W16F0frCJ69zCEfF207hA4yegpWApXQi
         z4agLwKxAZfuIPpIQHF1nEJtTMIPVk6vD3g5gmAtVAF9dkFZXOhkhp5Eegdq+vdCO2ac
         xQDs1yo1qabOQr0DAHmLU0BCmzbZpf5q5YuIWIJMQeX/4V1iABTIxe+hBVkk290vcFko
         ilosHPq3Jd3bCSTUsLjTIjO/lxLoFifEPrTkrUJV1ew9g1uqEQ34CsY4NFsDFayO8DIl
         q+TifiRTDQ+sTuPUFuiFB9GXikhecOLCUJr3+/kqSnmfb3Oo9zeIVUz1z84Hr70wmUrD
         nk5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Se42NY44veYM1gEe+3FXH/6it48ZhvYHhFyJpp2E9s=;
        b=gDIDgCfbfV49OnAzhmXig/GuFaybnaSOo1MCA6HpIIYHE7jpdrfcUW0LXW5JUZeZer
         XNeH/viYWayC1XlzLqUtMQpTQFk4iYWdagiT9QXTF72Ctuy8hcRp9nXbHBvBbb9tpR58
         pJcou2NKb48BmthpL6GTgy8MosUSBV8hFENnQlXVjWsth4aWQeHvQUhqOXX+7IleUqzh
         xrKi+NQ/LdnYtxE6Pq3BDB6Z+7cf5/PbvJzSARSaGITWJiGUoOmgUGLsm49n2bEEsxyq
         W2eBNkQbJWlXHfjQo3gStYEhZt/YQRhNQUp/L4E1rexHdIQTyQeqAHblLi1zEBmincM2
         TR3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cxMmVB26uaCCkwpzqu1F/XS09Qs9QH9VYADzjxnMy7XLS94eJ1
	ZVhl+LhL7SSTTGAFzUJpcPk=
X-Google-Smtp-Source: AKy350YSqp5r6iqKWdiG5oQod+GBzyuA1QIyYhXhOPno5pqdzldXOHMKi/0NBqdCdiVcpWKX74nlzQ==
X-Received: by 2002:a4a:bb99:0:b0:52e:17e2:7d4c with SMTP id h25-20020a4abb99000000b0052e17e27d4cmr729363oop.1.1680597826005;
        Tue, 04 Apr 2023 01:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:708e:b0:177:c590:4bf7 with SMTP id
 v14-20020a056870708e00b00177c5904bf7ls5069533oae.10.-pod-prod-gmail; Tue, 04
 Apr 2023 01:43:45 -0700 (PDT)
X-Received: by 2002:a05:6870:e749:b0:17a:adb6:9e4a with SMTP id t9-20020a056870e74900b0017aadb69e4amr1077961oak.49.1680597825684;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597825; cv=none;
        d=google.com; s=arc-20160816;
        b=t+/rrl98FZ8/nCi8Wp3Dfxgnyk9eERhEBxzKArW6FTjpZWfOVENn9uie3sqyHwELdT
         0xGcWm3ihYinwOa/o3nL4Ck8NFpMczetfTRvf9eh1fso6FQkCXgkHbXJ5+9/4FfFMHLY
         ky4nQ2Tmi7el9cIB57ereefLkhPiEpEt5D8ICv/u0b+Sy++if3Njz5ioHgxucj2wKyVP
         F7r2MA/B76DYNW2lCjk2qZoeZQOId4YoLoxxINDZ94dlhpC5nk94uea2aBaz8BHAxDbS
         PpBR/3LBbFgII+tDMKqun86r2t6+yFUWW81n/ZL8dPkb9cCUh5cwDifF9yFK7jH9gkTa
         YmvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ojSUF8/qqXE/bnfEFAt+zRgTWbIStxDciISKhrAb4TM=;
        b=h3jUxlaP8AAq3oEHeBshWY2Rdqr9sUnQOiIE9q4ODui4/+85f9jSYU3zt28D+k2TCh
         OGQFRJx+U8/S/6JPcYlma3OC7WUPP9l4TLbWs2/4cxlWlvzgLRrDjWPOCkE9i9bEmD3R
         5T7reRN/Muy2bxPNrCNagDoyaIvIUYFPr/hiRvetgn+9RRSOK3CWEhGxu5TPFN8JhTjV
         1cWfQZj+Bh86Vcojxgljm3ztw1w0xZA1d3Yt+/OA7/+zO4a9ZgCBhfp5bRCCfRnrOj+8
         3RiVKjj+MC1EPVIK5LtYCW6kv+OE3At36gib9LRTNL2Me9lhijbcoEA2hcuuUZqBebR3
         BhUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id pc4-20020a0568701ec400b0017b0d68e731si1190340oab.2.2023.04.04.01.43.44
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:43:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Axbdoh4ytkwV0WAA--.34372S3;
	Tue, 04 Apr 2023 16:43:13 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxT+Qc4ytkChcVAA--.55041S4;
	Tue, 04 Apr 2023 16:43:12 +0800 (CST)
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
Subject: [PATCH v2 6/6] LoongArch: Add ARCH_HAS_FORTIFY_SOURCE
Date: Tue,  4 Apr 2023 16:43:08 +0800
Message-Id: <20230404084308.813-3-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230404084308.813-1-zhangqing@loongson.cn>
References: <20230404084308.813-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8AxT+Qc4ytkChcVAA--.55041S4
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7uF1xtF18KFW5Gr1ktw4DXFb_yoW8WFyrpF
	nrA3s5Jr48CFn7AFWjy34UWryUWF97Kr42gFyYya48AFy3XryDXrs2q3Z0vFy5Za1rG3yx
	uFyfWa4aqF4DX37anT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b-AYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWDJVCq3wA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8Jr0_Cr1UM2
	8EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4U
	JwAaw2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4
	CE44I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_ZF0_GryDMcIj
	6I8E87Iv67AKxVWxJVW8Jr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JMx
	AIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMxCIbckI1I0E14v26r1Y6r17
	MI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67
	AKxVW8ZVWrXwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26F1j6w1UMIIF0xvE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I
	8E87Iv67AKxVWxJVW8Jr1lIxAIcVC2z280aVCY1x0267AKxVW8Jr0_Cr1UYxBIdaVFxhVj
	vjDU0xZFpf9x07j4GQhUUUUU=
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

FORTIFY_SOURCE could detect various overflows at compile and run time.
ARCH_HAS_FORTIFY_SOURCE means that the architecture can be built and
run with CONFIG_FORTIFY_SOURCE. Select it in LoongArch.

See more about this feature from commit 6974f0c4555e
("include/linux/string.h: add the option of fortified string.h functions").

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 arch/loongarch/Kconfig              | 1 +
 arch/loongarch/include/asm/string.h | 4 ++++
 2 files changed, 5 insertions(+)

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 61f883c51045..6c525e50bb7c 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -11,6 +11,7 @@ config LOONGARCH
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
 	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
+	select ARCH_HAS_FORTIFY_SOURCE
 	select ARCH_HAS_NMI_SAFE_THIS_CPU_OPS
 	select ARCH_HAS_PTE_SPECIAL
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
diff --git a/arch/loongarch/include/asm/string.h b/arch/loongarch/include/asm/string.h
index a6482abdc8b3..5bb5a90d2681 100644
--- a/arch/loongarch/include/asm/string.h
+++ b/arch/loongarch/include/asm/string.h
@@ -28,6 +28,10 @@ extern void *__memmove(void *__dest, __const__ void *__src, size_t __n);
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
+
 #endif
 
 #endif /* _ASM_STRING_H */
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230404084308.813-3-zhangqing%40loongson.cn.
