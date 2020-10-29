Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZVO5T6AKGQEWKAXWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A3C29F4E6
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:31 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id o14sf1662447ljj.8
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999591; cv=pass;
        d=google.com; s=arc-20160816;
        b=C09eaXBS5sH3O/Cuw5SL+b7sl3hPwCFRE9shbBtOKqGlFQEmVnMLowhW1wDKjfaYg8
         Yn8w4EIGLLbQBIAtFM13E3f+8VMvr2Y0e+O2rL8g4eEUK895+cBb+xudBQlSqrJvBiie
         T+CP5j3K/Ygs3AjSNclbV7tLhf5B2qjo2Z+d9rT5NK9IdSx0VPywB7reKIkm06OJ7SJx
         HA8vga9IySStrU66GgC4TTZJkd3jxxkZnLD84V8/uK0CHMncjCDSpl1UQuvl0qcaCMzh
         Rvlhu8CtDLSaEGofEJkbDmjZvsTpCEDNCZXJ7f1xizgjk6GdtbJscw5smc6SgJsNk8iw
         eGPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=J/GRgJmWNKsjiS2th4xkonmxm0epDq4ENMMXgSAN9XA=;
        b=KdEm5ywTnyeSwm0dwS3iKxjsn8rlMFGSf/pGsoVaY8Dj5UaHemIRrcPEymy+O6rHYs
         lLM73BOCKM8LBjj9fh72oW6lXFNH7UMUiWEIOWXFasduDoZFowlFPwp+NKsL42ayLJSd
         8mboiZVLdgeMfcxM4egWkEWrXWHUwcalH8muEOGzKJOGggJbzsOeS9Eu7HTkkmPizGgA
         MU5w4F47diyRONmod72S+L1N2RFn5fjUvkQLtoqQWvdTnrzAZDaOoiX4A5FMrE9keKMl
         aeTmoBIk97yT4Ebd/58REWoGt0AxTg6MmNgiS4J/091pCGf8D17CqlNRKE9XniYQb4UC
         o6oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=noqYF0LR;
       spf=pass (google.com: domain of 3zrebxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZRebXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J/GRgJmWNKsjiS2th4xkonmxm0epDq4ENMMXgSAN9XA=;
        b=ec7BTNVuYwj2AzEBXOWbjBXj9ddRyK8N5JTjgP8lvVrF5eRsFaYLgo+GrIHoxgN5+J
         MLxzjIRw49DSORHR3RLMlgeWl3pgnLrYZXhFrWJd9YbL86+VUzpK+ZcKr5r2t++7FUwQ
         Z47aJ3f5hwa1lsXdzM4/QjGUDjsMx52WOdN3+FHVb5O3JTtR+g1fLMmpKkFXovZHGV9Z
         G0qyVMvw2mjkD0sMYKGQ0G6h1UTF+/wgk9/6bJyXIrWGd62rtJDhzyXZRKbKy6sHA5wI
         8BhNjWudfyDn8yOuTDoJf0GPObSgwjAdxCjoe3KpL1voUURCoGj5Vou3eknXfrtfM4mS
         GTeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J/GRgJmWNKsjiS2th4xkonmxm0epDq4ENMMXgSAN9XA=;
        b=I8L6LQlVwYTcnmTVUdqU0C0Zi4oiLcXvswiTywutlcOut3K/B9aFQPmB0+WaQdociy
         yu3j0/BiMC/BVQZznRd9bzOQnRr35w47kW2iWsWGqjFDv3tdKzX1vnAr80JD0DRur7Sq
         tq8Psq0Xnipe/jAZlFivIWa6fSthitDnSilo+GM2dT03beAs8HVPfEx2BVOsPgW+hlAt
         QNMjj9fXWMMuXpOWPkNroytRaO58EsQtjS1vy7bRpd0JLeLNL8p70E6M247o+EF1kYUI
         I0CVn1dqyzuZUE/Vcv/FnsEYAv+JuGKMxOJRIw3COlq07bYREwNUHIPCq/Ry8q5ofFMK
         xYew==
X-Gm-Message-State: AOAM531fcekHRdQUfYjUZc6KtNsX5QHPvVRT3FqHEVSA5zes4lEOVw5z
	6n/soKAcepTPxzitYXwsuoI=
X-Google-Smtp-Source: ABdhPJzKyDBt377srpnfWRLz/epLFK3XkvKTeSBLxueZzUxSANBICD3SrUU5mZVZ1m8N2bXpOZmyXw==
X-Received: by 2002:a19:e015:: with SMTP id x21mr2388040lfg.586.1603999590935;
        Thu, 29 Oct 2020 12:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2395892lff.1.gmail; Thu, 29 Oct
 2020 12:26:30 -0700 (PDT)
X-Received: by 2002:a19:38e:: with SMTP id 136mr2378107lfd.438.1603999590044;
        Thu, 29 Oct 2020 12:26:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999590; cv=none;
        d=google.com; s=arc-20160816;
        b=RDfsCEm7+455P8hUPBVpNjliSwOERxyzY9eK3f22KUKgVnpuqhWkQeh6nlIdbqXWXT
         D14Th3ejQ9vH0Y/OtSDzeGe5hGZtFN7UGmZVyMl0vGYbgfZSpcK6qkzl7C2NlG6DzNP9
         VJLV5RJbHFm0shEg5WoDC1sCiId/F2ELVn7NCopha4GW4X7bBwFu7ZPvub4angxU6CXj
         cSyJdXlK2OLW8+FPHfsEQU3yDcGoPGK9vRTV7Ohv/MjPASVuTAual5GRLpEyHnK4Ktqj
         EDX1N64U8XHZ3PTUsbuBqTlcBugHTPU6N0uznPDGldRT6hceIPossWslibrKmz0Syp1T
         5FyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qrrYQwa9ShIhHuQejhOGo+FpOBNOJz6qtkpSS2d97D0=;
        b=NQNfDYdTX0BZEaaUb2vHLDAtC4h23EYg5+/63KTrVz1mxzJjn2AuwGc1TSa8WtoOdC
         SPNN54FVVmLS7lAam4yK0p1Wx7UlkvkLpgxKlksPlhIimrQQw1Hn+0+lymQX9EIIMwLc
         eVLZFAKQd1v4wFc4kigDzuwI5X42bXqIcFPdXprwRnYpISkk6qXT8Q6n4wANZyKkjOZP
         R0xRvWCDy111WSxLridyPPvYyWOuiqt8QloNIgjxI4ghtNZ66XK3hZ8jGPZXjT3Wzcac
         r9kT1EBON7Hg5FYfojEXcP113AVyqoig+ix1Q3B4piebqH4E8v9Ms45aIFjakMKGmOLF
         PKZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=noqYF0LR;
       spf=pass (google.com: domain of 3zrebxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZRebXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a16si93954lfr.5.2020.10.29.12.26.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zrebxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id e3so1679254wrn.19
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:30 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7e4e:: with SMTP id
 z75mr749584wmc.55.1603999589356; Thu, 29 Oct 2020 12:26:29 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:30 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <0cddd36c904f3e5d6c51a1aa10f218b3f81d2064.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 09/40] arm64: kasan: Align allocations for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=noqYF0LR;       spf=pass
 (google.com: domain of 3zrebxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZRebXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN uses the memory tagging approach, which requires
all allocations to be aligned to the memory granule size. Align the
allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
CONFIG_KASAN_HW_TAGS is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I51ebd3f9645e6330e5a92973bf7c86b62d632c2b
---
 arch/arm64/include/asm/cache.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index 0ac3e06a2118..84a8e25b0234 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -50,6 +51,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0cddd36c904f3e5d6c51a1aa10f218b3f81d2064.1603999489.git.andreyknvl%40google.com.
