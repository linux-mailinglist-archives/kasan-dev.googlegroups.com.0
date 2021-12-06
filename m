Return-Path: <kasan-dev+bncBAABBMMJXKGQMGQE3LSY5TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F138B46AACC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:25 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id h13-20020adfa4cd000000b001883fd029e8sf2357153wrb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827185; cv=pass;
        d=google.com; s=arc-20160816;
        b=YiCUjPbp6GZd0QUQ35/nfK2UZ0OyQSV9uEu9ePQCmzytd6nZebmjDxaUjs3OsWceDz
         /vVfoI67a/QiprUQUcq/3TlnOoixKeCQtbJYx+JGqT6gc+0VtijK+BcongMqQ7UEn98h
         39lOZVInfQWrszxxaN5XiuH/gwGhAxp7fyPSylkDRO14qL8dyPo5rSOKWRKSh1W2n0cP
         /EQ8v7JYAZGf32owxvpM36lN2NDgd/RCAPmuRGxos3j/KJ6Swk18GaKwiZz1Draz5nfs
         /DEp8kjhYnxw3dT1WOc9mt4YW09ieLoc4dgmoV6AxQx8wyoVvWPzmIwAam+xsRJPNm2w
         ea8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o4Vg2zT5Me5nySFx9ya6nFwvzT23CW994wlbKLliiCI=;
        b=IbbuC9TFaGYaeNuU7K1bK+PxIh9BwCdB6zfxFDuoeAFTbS41oXA1WdUqGt1QRQakBV
         ihrapundIttkJWjH2kAT7ZURw4DfUxndJaaN6HDtyv/f9Irz7bULZx/ecQcjqC4ouu6w
         xmzrt8Z8ho9Eo/FidUlOEoY6moPvhDCwwyV+YFAmFLe95VEIuajbF0OkplrZ9zcs/a9F
         9mZBB8EHjkpifYxWM1wc2rEZwqcBFnwfw1kSYt2WqG6D8SMNjZq9TcvYdABg8CFHRcCS
         fWMqh+Ci8N+6QGibC23P4sklt1w620OI/xQxktfWfUFMqsfEV522qR0tk8tcCMOomZwJ
         HCZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AJN2EJAa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o4Vg2zT5Me5nySFx9ya6nFwvzT23CW994wlbKLliiCI=;
        b=EXcXlGrWIX/aPSTpFvpdHPAcv0FblUKOWvU5uwwo0FHsXXicwkgcDzqtzrgXlrUj1x
         kcfnUR52GN/kW8HYrBmxoXuU7g/BXjhg78UyteGXcjzPzEMZVeNv+9bsIh7oabc7yTrf
         /ifT9t8zeeRMaWEjwfYCBdrevGVzPRxb+v1g15tc37xy9sZOjTmaE/khwHp8NQWLsQo3
         wzOYSCgFXxn/3alCclbtSloKe7n62zIxJZlJoocDMvHNsNOtIs17G8wUZ8QuiumRH9Sv
         dheBqTOoVYYYfnwuTzQIcwWN78Ron0pg3j8g2bHqn05ZWH/rgsuiEUhF0oSdz3URP3LA
         jhWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o4Vg2zT5Me5nySFx9ya6nFwvzT23CW994wlbKLliiCI=;
        b=TOlwxhq9NmJ/a+4MwtL7CW/NKofGPydHkf8zOlw2ARaz/BIjS4liSa27uYZRb5DvYB
         3BghYaNGLaP9+1AmEdt8xke/lrVbOqCX5NWXgFnDqux4jhgYnokUu/W0aiBMx5MvDwwq
         2c/npxN6DngrkUru3AmjiL9MKwgJ6Y1BJGbWNcFFHPt4QU/9MewOUhv0U57mAeoGjbED
         +ln4ecvEAebABBFTqUPi1+XXshdT/FwRbO5waGwXf74WpFSilwNdeLJQdYHPKQ90Ank1
         gCnpHWUZVM9jn08dUqgkrxPNrDuKRB103dK0Bd8kePDsQhgy0O0LdZT15syuA8whepqp
         UHug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530j/YU1wBxeGjKH6GpILEUj4HwmPguLE7SSDAtbSQoraeVgq3I2
	5V72CGo7pMJ6Nwt/5cAsWoE=
X-Google-Smtp-Source: ABdhPJwW3BC/Z2SghAS2Uk9BGAE4bGA6IXxqg3xeUV7Bew1i63KXCrLrunX5Ww37wBw7l8VRfCNv3g==
X-Received: by 2002:a7b:c770:: with SMTP id x16mr1578002wmk.66.1638827185768;
        Mon, 06 Dec 2021 13:46:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls229733wme.0.canary-gmail; Mon, 06
 Dec 2021 13:46:25 -0800 (PST)
X-Received: by 2002:a1c:1906:: with SMTP id 6mr1573073wmz.19.1638827185069;
        Mon, 06 Dec 2021 13:46:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827185; cv=none;
        d=google.com; s=arc-20160816;
        b=JJLPU/bNENifWL8tFRZX7jkoICVBYi+qeTQEqttbvuq3RRHecMl5PkjpRbjKnPc88a
         2vrPW01HbJuUTstw9xWVc7OpobrS7wJkVK6ykLad6X7MAfjaCqDWVLZocLIZfOJXMfSl
         8MAU5qFWRwzqi6ueAQwNfv7aIuxsMEk9y43sUGNed52k2Jnp0oxzMo2YJOm9Ljp0j7Ng
         AHeC0caSoJ3pf9HgRO1kMnAqMvdmqmPZ/j1wQUeDDqPXawB76yp1ogTnOrRCuX+iA3l2
         q6ObzYIUmY9z5HY903QDtKhTOt5ydgUaFxnWY4Ke3MssPjOxfx2oOe59u+vacQ7xGxEI
         IpjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kpH+33k/GfROSS5YE3KBLshkOEFVObuKhNsDDFbF7nk=;
        b=ojg1TUslUDdSil1HY8Zx/bT9BEJhDmNWv+9W278X+eSSkEox+d7FWLUHLGjaZ1EpsL
         YiImoXCak3cl859ydAjLZxwhKsjMZXuUKDmW8C1cneMZcLF6JU5k67ZqFEZLRoV1dUbB
         d8k80cfUlBWjbtf2yb4sAJS6vaocI+whM7S0PZlEwA4m/OX4YcPT9o0zOSKSvETC5i7k
         TvUCFSFQOHrUQuePc00s/dW4oRlD4AcR1CQP82xAZDV8koegKlPSQ2Yv9ZiaeFhdY4JM
         YJk1xwXOsNxZAAAnotslcCRF50arvOGrKks2gC303O23xGb2Ac5TR9zbtIzzYCzzK6Gj
         oCgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AJN2EJAa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id c2si104926wmq.2.2021.12.06.13.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 24/34] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Mon,  6 Dec 2021 22:44:01 +0100
Message-Id: <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AJN2EJAa;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
memory tags via MTE-specific instructions.

This change adds proper protection bits to vmalloc() allocations.
These allocations are always backed by page_alloc pages, so the tags
will actually be getting set on the corresponding physical memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/vmalloc.h | 10 ++++++++++
 include/linux/vmalloc.h          |  7 +++++++
 mm/vmalloc.c                     |  2 ++
 3 files changed, 19 insertions(+)

diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
index b9185503feae..3d35adf365bf 100644
--- a/arch/arm64/include/asm/vmalloc.h
+++ b/arch/arm64/include/asm/vmalloc.h
@@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
 
 #endif
 
+#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
+static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
+{
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
+			(pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
+		prot = pgprot_tagged(prot);
+
+	return prot;
+}
+
 #endif /* _ASM_ARM64_VMALLOC_H */
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index b22369f540eb..965c4bf475f1 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -108,6 +108,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
 }
 #endif
 
+#ifndef arch_vmalloc_pgprot_modify
+static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
+{
+	return prot;
+}
+#endif
+
 /*
  *	Highlevel APIs for driver use
  */
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 7be18b292679..f37d0ed99bf9 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3033,6 +3033,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		return NULL;
 	}
 
+	prot = arch_vmalloc_pgprot_modify(prot);
+
 	if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
 		unsigned long size_per_node;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl%40google.com.
