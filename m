Return-Path: <kasan-dev+bncBAABBJMC36GQMGQEVTJ6OZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 845C14736EA
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:46 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id k17-20020a05651239d100b0041c32e98751sf8069465lfu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432486; cv=pass;
        d=google.com; s=arc-20160816;
        b=fv903YlIhVmBZaL13KAc0q02791eUGbdd3o7VwrzrskFFGcs79MXHBxvcXVMfr60SB
         T8PCaFKZgktnNkwTVHvjBfhVCORfPMRYtO6PmNN7LWQbeZoNAcPAmKwIKfl7iCsDqeVm
         iuycWuzZWKPJkN2GXxZ5NXp57Kn4/VPkJPOg6i5gGVKYhUsF3P/zUsklE/b4aNwoQbmN
         YZuqwHrNuJuXhbfal+ALeUUvaVFizF1rdD2Xlc56egLf1CqQa70xidC/s1s6tSaeSQf3
         YwmXfU4pHrYsHV2yyhgR8EngBM6Gtpfq2LWGXVvMxiJjtLwM/fEF/PvLvGqJI0qdBiok
         BU8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/CKyBcffrhKUhGVKQcTqiHydabhtcrDOC+BmK0dmTnM=;
        b=GlbWxm4+pFFK02MY13BvVQozZE0jfwHLIwzOcvEhjBzIyt0o8QXcvFXXK7KDV9RkhP
         OUCzlOz/uiXxXUWz9/kSi+YonLFFOGLr+M8FTxzertJ72++3u9+7Mg+Pau+ymJZZQu/B
         9EEFrFLN/XshgX83skdqoFd8T4pPMvjicSJk68G3KFfPsIIvzde0g3Tm29JCPdJiYesH
         48GFUquios5MlierjgILRjVqXvkB0URHhTPVciUE0xG0+txVpJGIZ+HXsAp3c626I71B
         04iD2iOwf52eEEhj6kEOC1jRQJM+SDuQnRkE7HJAqBfIV7q7mWxM2BRaM0Tk7AEYvfPu
         KLXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EP1GPSuP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/CKyBcffrhKUhGVKQcTqiHydabhtcrDOC+BmK0dmTnM=;
        b=SDQdq3rRmJaC3U4bjyhH/mP0fjbl2mXWcRF2wFoXLTGijRuams5FXD2Y0mE3TCRUQs
         eiIki+XWgEERFw2DaBy3B+ROGv4WIec7AruqnjVfw0thy+wvqiv44DAqFiqXIi4tzp8d
         2TS3qyaJpLVpXYT0Oo8eLrBCkGj0RM85SFgyIfPBG5IGERQr0TdURWshpN9ZgGrPqyqy
         z7Fjl4TYp/TpUJoe6zh6YKDa/geJg+CUlT+GdvxHTFbXIYkuGvO2AJH9JjKkVbuxr6tr
         O1iIZlAOM7N5uMp3b0ggjQTNFHD7J5oCEKkbNYk6k20BTjAGPol/bW2msj/XZvcufUr3
         UbpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/CKyBcffrhKUhGVKQcTqiHydabhtcrDOC+BmK0dmTnM=;
        b=AuBbTq38OjQTIUV3Y6otAUkawXdr+TDeJw4jjtihdYbtML1L5FpijAZi8sCzA76n14
         gxLF3EpwBLTG921UAnh7OD4V8AgDWwUpK+rshkk7EB0BWH6CYwdR2f4gGT0jpBw3D/Ba
         R2Z2DpqNR/9vJ2d7iIpbGCubZi6zK8w+trg6kn0Y4QaA48Ox4N93AzbLACHoOiGhET/v
         RqnRqrDaMflhk4TCyVxlvsb1CRAeLMPh1YZIUc/CyYXrMUrfdCoCV4nxCLlzX2N3EOYy
         Tqr+ojrQIHDNIeL+YV6nocekfKKg34X8u7qyAR5rzHuxT0LYXac/S80HCoYxEA7EYgjQ
         WTEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mMXsXgzQBi0MS9WwvucxKx0RkPYbKXuSwB2QnFget2ftCMSh7
	ABnTkJwaQv+gmfteaMTOa5g=
X-Google-Smtp-Source: ABdhPJwiXtJa6m701de6XCh/TUlYL4ogXJywdujJq66j5GyWvw7bexfnwQEyrdeoazrMB8V3tft0FQ==
X-Received: by 2002:a05:6512:3c9a:: with SMTP id h26mr883649lfv.155.1639432486118;
        Mon, 13 Dec 2021 13:54:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls2715609lji.1.gmail; Mon, 13 Dec
 2021 13:54:45 -0800 (PST)
X-Received: by 2002:a05:651c:503:: with SMTP id o3mr1084143ljp.249.1639432485431;
        Mon, 13 Dec 2021 13:54:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432485; cv=none;
        d=google.com; s=arc-20160816;
        b=diDV3dlsQ8r45Tbx/9D+cOrKEGuLvJWgO7Z7Sfc82Fqz9ig4s2VYDHMV1SNhYx/ltE
         WMJ7bw0tzHYlMESd44A9uEYhDaZncmoqkUnuUGgvwgn+48yPoBTenf345fkEaxMRAeoA
         mOSFMP4iceVUCxZp0Wp2X3m16yHcIUufRSNriHnKGNgx5A6Th9hhuoWBbqJ1Wu5K8DnG
         a6LUR/pXagh8Fp2DjysoLiAeHicwXXshciqx8bqdO2jbmPFo3uPpzOtkTYgjevwknrXg
         KkudL5po9au7AQOY5zIFuMk/Tj+ZrtI96JfoiX0rJ5N9MeFpU5sqquz7mXF6dbudIaw4
         2ZIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yORKjcCEUipyyeqk50NvnNF1FXzG3q2NQ93FJWpnTtQ=;
        b=sJyhnq0g6FFjyt7R+01nPqBJQyBh8+ASXsxVRl20oyciCJ9ortnwGgWwENnosv6DEG
         j/P2YUTKWRStarcUy4njzdh1F5zRejoIq7ge9/D3yk3gPz9Hi6ZRf7Ell4QI3p/KGBsJ
         LlpyPS25XkdW951yAiTpfqDgHNKo1/vpYMwVPMnjVSNSN1YtUZ94v1v18S8+jWrnG9NK
         IsUOWu6FiT1L7IbbVTpj6HnryqVbY9/O8I0YHfnIJpR2hy+N13VI309OwpuX1Pfv7WQU
         Jr5YE4bbHfAiWdHLorGVsPw9UeAT7qhIitfhMdpcPAwJdkagY3KJyk/UJ+C/Q/pWXBDc
         Kd1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EP1GPSuP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id g21si810755lfv.11.2021.12.13.13.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 25/38] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Mon, 13 Dec 2021 22:54:21 +0100
Message-Id: <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EP1GPSuP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Add proper protection bits to vmalloc() allocations. These allocations
are always backed by page_alloc pages, so the tags will actually be
getting set on the corresponding physical memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

---

Changes v2->v3:
- Update patch description.
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
index 28becb10d013..760caeedd749 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
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
index 837ed355bfc6..58bd2f7f86d7 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3060,6 +3060,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl%40google.com.
