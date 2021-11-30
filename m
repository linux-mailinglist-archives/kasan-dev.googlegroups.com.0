Return-Path: <kasan-dev+bncBAABBQGBTKGQMGQER25IH6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9395D464102
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:00 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164sf14528337wmc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310080; cv=pass;
        d=google.com; s=arc-20160816;
        b=sc6w+KPcfhdN+dV/ekxBn0TUioTFr/SWzzDpcAoNL9H7HhVzFIbEilBhzWecEBOJzB
         +ptu5VEZ/RV4jsxIug8kf/ykL778Jt2O6HPOixy74DWQnAFL4/9d/cf0ZBNNGN1rYg1k
         8f7An9wLNo5a+C2zffdw+iE3axYmP6Ph/8WEWqxdOHid6LdUmxVjQ/hM+sqIAjRAzFTn
         kG6qRfveZrttHKzDVjXFZ0uKiuV/OM93Ppl6IFRQ8QEGedNYDWU1FhYIUr0gYhHXGxFX
         ljGjbKdFGAkHFnyOi8LXN3dpsAfUORoEuJrMW2gJnUNqApUXmhxhDyC3dS33xX15C2mw
         6qHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2aU1YcSK84Stv4gPnfr+dncj2QmraoNE7/9mpCGSQ+o=;
        b=KDP5UXxaXGAvMY3Wa9FIpKgh8nBR0vFjwb2sSTQSda1Ad15Wo9S3VeAI5rBKa6fVsY
         /qLy2mVv/gHc17MKOgoR4UQ2mijiUJZzkHGRftgQianEp+UfFrb7p57/iJBnxW4bL3yW
         Cak1Dl/UiXvnrvAT/gQ9l4rWKxC6OhCTY28Kus07tC0PKjteCJZtf1EltKWJbdI570pV
         Lm86jjT7NY/FuHv2KwlEZBL34Ls/DPOsDm35ODgLjKbiJhVNU2wDZB71nAruw1NcSevc
         F1TVvrGPXFkYr1ShbvZsKAYedVOcT5GftLuVGupMpkQhcz8dJsipOcmAsEEhCd8JxYvF
         Z6AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EI9KMQ0F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2aU1YcSK84Stv4gPnfr+dncj2QmraoNE7/9mpCGSQ+o=;
        b=Ur7r9bRN6s23EWZQZQQl70pWwtbLC8Rr5hPZPf2oBG4pHgBgl52guNFIBQWIaRnV1m
         uBhWAeJWlR4xtNSSqri7Y6C7Dhz83nlsGzbB9MbIRjQEoSDPbgjHZoecMjNZ1RVeMETi
         3+GCWH4WkEUQv+65eqRbtwxLRlI6bn2z8qrJYK1FWgQA4MEjC7dLghGugY17s1eTt0Ea
         aiGL0nEfpox/ihKWGudo5eGDUAxk/3MzXFVL0UGkhyt9hvSo+a5Z/fHe/zRWO5gZGWOM
         ZMAXK+wKNW3dZR8uqESiKFDUPDhYat3c8QBmKBGcxWiS+WEg+Ir/E6o8dxTFpwTcNqH2
         4pLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2aU1YcSK84Stv4gPnfr+dncj2QmraoNE7/9mpCGSQ+o=;
        b=KMXHnqM+ascjIX7z9IKtp2WW7Gf+qYW4T/y8s9AaxFmlqJuHDhAZJFCtIsUQXxmBRp
         tMY1ehSjj/Ps9CGC3nJSRoUwtC4vCEYStQcUV9QBU0YbFuj6ehqacFlDVbH/SLp7NDtJ
         s90Lbw/YeWANjkyUhbQ6+9PK0blZkXXVO0EQ3eV9jYKXLi5rsUrT7jK7g5hRTI6zmtPX
         IIyfwJdKfVJVKSvMoswoELrLa5pWXlmICurXO0vtOEvVvfGqf99faOyZ+t32pfNiyCzr
         RVihRRR76qvTN6uqHX17RtOrRyNFZCZt0oa0jiXdX3GWOVheE2xJpMyIGE1wn3B1MyLz
         Y0Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qeMk16GIVR3tdsVpvq30O4Flf8SvkTk/o/r/XpR15kHcQyvlY
	Qn4Yjh+Ev5JHjgh1zyioulo=
X-Google-Smtp-Source: ABdhPJxAF2jIvBSTQLxFW6l0BUqfDB1IPvKEPL2UB/YwoUUaEbm/JZuOU9gAqOzo6XIxJuV585k1gw==
X-Received: by 2002:a05:600c:2dc1:: with SMTP id e1mr1788109wmh.170.1638310080356;
        Tue, 30 Nov 2021 14:08:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls181827wrp.3.gmail; Tue, 30 Nov
 2021 14:07:59 -0800 (PST)
X-Received: by 2002:a5d:4411:: with SMTP id z17mr1872749wrq.59.1638310079731;
        Tue, 30 Nov 2021 14:07:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310079; cv=none;
        d=google.com; s=arc-20160816;
        b=jvVYnojOU3cg+ZnD0f/VSXn7TX5oACQfaYqo5BnFEdhaGQIzQ4gc2rbUKjOinwesbQ
         yFiS6dyYaT+Iy66C+h949ZaTsfCvuAXdQKtSvfuwZ+s9bfe2AFPfA7R4nO8x7+H732Aa
         KPocxMaXwX46VYuF+qDICilhRcqFrQ9rT6amSQ9x435Pehj3v285v0ImNfSb7Rp0KxYW
         mVzmDNvpN6mtomTfIS7tm0ZebZ0D/eQJRzvOWYETO3CyXC2qEGOYPOfrowr22+ML3OCW
         al3set1lsJZEDlzEDG0pANhZn+3WzFMaEZMu4VGYzhanbJo+q97MLfBtHFwGJTMKNUYu
         CCnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kpH+33k/GfROSS5YE3KBLshkOEFVObuKhNsDDFbF7nk=;
        b=p6i8fvgmW+TX+ljS/6xJCwx+c5mdgCWQPY+a//sbECwYK7SL81gVDXhBNH2rmWjDSB
         GSUpV5HZxwqrWS8yI6CqlfKapvpyA2ZGE9vdcXohpw0SVc7v+0S8hpl3OvZvivU6F7kw
         sOUhXcs+OJZUAeWNAB7w4D8e1WCywEyOrGMy60pBhYf0zLYSCkh2XyhcJAxZxJ2+bfQ8
         z2I2Y+CToXFDLjo8FAdDWacpfKGw6GfHGQg/ZzFtg6oW1krnZRzGOSfX9ECFShhSPYFT
         hHWH7PN1hqrAYN/BHGs/fWKa2lo7VdL8xXYqQ71SCR9BIi4rhxmifrf2aWWijHPnLH5c
         C/CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EI9KMQ0F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id p5si1268219wru.1.2021.11.30.14.07.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 24/31] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Tue, 30 Nov 2021 23:07:56 +0100
Message-Id: <8557e32739e38d3cdf409789c2b3e1b405c743f4.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EI9KMQ0F;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8557e32739e38d3cdf409789c2b3e1b405c743f4.1638308023.git.andreyknvl%40google.com.
