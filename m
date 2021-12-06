Return-Path: <kasan-dev+bncBAABBX4JXKGQMGQE5RV7T2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE74E46AAE1
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:47:11 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id g80-20020a1c2053000000b003331a764709sf217818wmg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:47:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827231; cv=pass;
        d=google.com; s=arc-20160816;
        b=mZPOiE3eRn5v3Y6Ydcdj0oeok724V7J5kOgVtZ8igfD8hPjOvxyjh1jwpHfyHkDnt8
         tGPP+7Yl3bP1WoC9mT3Wzk1i7Ya/CQlLrFWdpcH1x8mMWpddsD990dF/7wHWDrqYiawD
         lZAerDftZrDUqgQYyXZJpXt1pj3ZcOF6I+hyCYzQi/gduKP1/Uv11AxKtHtOjDecEGi7
         VQZJF+gB9+v2dk8IgbiZ90T423McL5Vq1IXhThlr2NOVEq8ESskor/oI+lQZt7rrQ5Af
         DkaKILy9pj3Ji9+btmebrciM34x7SKbMPqEGH1m9fBlTvbeKQaf2QMN7OkzWvvKHW9Pk
         708w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NS0P/+qoCyw2RfzB5Fh7/VyMG1OGwBvpozzzxJ7wG2g=;
        b=vgdxtFzXTd6bubyykRK1YvAysWbCaqoFaoO231U4QMj3caZspFoDYorVbVm3NtEdTu
         1xisK0+X9WEmNzZL9A/m9TQp+tNUbWd5Sfw8fWo6vCtb600pEwj7C2/z48UoyzJqzZii
         fyUCymK9xJzUog/mK0WB6zgS0I1FPf0HvXmqviT448kCT+H47LLgfk50Cu23mZPt91++
         On1xdz6yjHAHm3gFF4V5vSVWXcmxDWsBEjPUnDvVmra77qAo9K7NyX+Ql1Rg8nZWe8mD
         DT/ZakxE+8n+PfVVkvQeX+PZCdhUYB5l47SdbjAhx7x4JE+QB/+5k4hKSvpRL4d73u8J
         KxdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jRv2K2Lt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NS0P/+qoCyw2RfzB5Fh7/VyMG1OGwBvpozzzxJ7wG2g=;
        b=obKWuyuGjJS3PR2cAyJkWiWMvNmGxwtLwCZDsfixLwHvv8XJAArAJ6ton2oUuTx/Ww
         gHNnQLZ2kB79EYI6hC7n+k2geoymJ75hnJN8FYAojymnTtt7QMrpnowdqognjmxgh9yh
         UyVoCiPUjfy2iCpCdBZbgzuF0XiuCCaPWgfHpqpjlsaEi7uoErxymuZOZ/HZUKn5Nj3C
         a4tN3K09AGolWatF2G5cQLErKlSXKr3+5GuVeiCJhWtnZWncgbArqa9EPMnKNJgrytdx
         QTGEa9aEPqwpgTYXJoVSy6KA8G4Ks4blT1eYD50/zJbfTn75f2/pE05lXYeTbmcXJ8He
         wVRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NS0P/+qoCyw2RfzB5Fh7/VyMG1OGwBvpozzzxJ7wG2g=;
        b=sw3hOJnwyGZFvh/DrO7mnyiC5sIyacPET9u1flwrGH/pbBRbMsSgpIJsrUHlhln2qi
         MLvG3dGSSviEH+me6arNyal2HCecOkiVHrNfQi8zpyr3sN4reiCO3as1J1i8r9gXrLEE
         ZKwowvgBwAOAggmFYtdCCua6iaw4SrJrl9PTmfceqQQRFS9+JU8rQv7krqkBp9432Bz2
         1PWJEJd+sikch/qnAlmMBx45Sr7uy3RrExnxDU6y8gyHg1tyho8iYVxeI7M5wUxT6YrC
         cLHmGb5fh4IOuUx4/89zYiciCxKNaJlX+n2jNjTa/U4Qv1yFwYxCjTub8DhuPBElmV+X
         l3+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LPq7zlnpZ8wEVjNLR0wiCNZ+objL2MuxSoaUZDxRqFfLrvN65
	eRF8vIh+WscA1YktK1YKiR8=
X-Google-Smtp-Source: ABdhPJzlnJC5OQVXE5isNFa4qFCbEwTWhWbmrwgv0YCPznS7Icyb1hGVEWBflSAyogRzrZQnNQYB2w==
X-Received: by 2002:a05:6000:252:: with SMTP id m18mr45942396wrz.117.1638827231693;
        Mon, 06 Dec 2021 13:47:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls1151471wro.2.gmail; Mon, 06 Dec
 2021 13:47:11 -0800 (PST)
X-Received: by 2002:adf:e8c1:: with SMTP id k1mr47423511wrn.257.1638827230961;
        Mon, 06 Dec 2021 13:47:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827230; cv=none;
        d=google.com; s=arc-20160816;
        b=ImaiLtbaWppAftMDcyYOpCZER0LPetqAg6rNERpZGCZxFMjiwNGnyrxwt70bophjLw
         m/76H1xIMejswqZ89cuXeVpa1u5zRfFg1u3ngu07A4k+Atu73Ho1jv4luaUnsqYyAw7a
         2OZBTJnCNphzbD+hSzb9FBF9r5MtnHEohqy5AIahEbvEtt4ga3ykrlM4akaAwRzOL3wh
         qkSQl3VDMp1MnCrA4nHVH3VgynqxoLD3Y4FA5RyA96ZSfm2asmnza/h5p7Ii+eId6Tfq
         NfH1I1UU9s7R9SOT9qcw57p+aPXvLwCevWqMRLgTNdkHUvwxIP1Dqk1RNIAo0Ey6OHXw
         kucQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vhe5kEMNFRSnWjEMXar5wkGHtuo9NDKTQhUT0l8T7fU=;
        b=qsqPoVZlxOGflHyagmUNdFDFEyerl1qDCo9Et0G5MpLiX9DFleuieMIaYyUlpSCTzL
         BJIXRkcRAXrUaqC1pMXg+H/6ts/lXrAIY2x2CD3njLwSckOM8GXpGiwT9xNOdq+2JrCo
         nHIhqVKlzCNCxIaEaANYoLsPjlTr7QNf7tizSjYUoy9+AP6J0Ar7gkVsls8x226BJRy3
         z0kkP7nF73m4ZyAsg7I395P3pOAanlZwstOAHDLzQqVmaJw4M6wsj2oXBza4FHZyXS0O
         PbYgGTm02qiJqnG2T4YkDBudfWo1NLD++BzP3bThs4Ocqw8wp9T6+DAe7n5G8k6R48aA
         OBPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jRv2K2Lt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id 138si71121wme.0.2021.12.06.13.47.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:47:10 -0800 (PST)
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
Subject: [PATCH v2 32/34] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Date: Mon,  6 Dec 2021 22:44:09 +0100
Message-Id: <4f56dd2bfaf945032a226f90141bb4f8e73959b7.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jRv2K2Lt;       spf=pass
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

Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
select KASAN_VMALLOC if KANSAN_GENERIC is enabled").

The same change is needed for SW_TAGS KASAN.

HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
they already work together as is. Still, selecting KASAN_VMALLOC still
makes sense to make vmalloc() always protected. In case any bugs in
KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
flag can be used to disable vmalloc() checking.

This patch selects KASAN_VMALLOC for all KASAN modes for arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Split out this patch.
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index c4207cf9bb17..f0aa434e3b7a 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -205,7 +205,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f56dd2bfaf945032a226f90141bb4f8e73959b7.1638825394.git.andreyknvl%40google.com.
