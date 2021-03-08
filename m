Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5UYTGBAMGQEZQX33SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4AC331302
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:10:31 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id h20sf7626212qkj.18
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:10:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615219830; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypN7qVk0ETyihz574Rcb7kp6PdjNIS6TjZ+zgBO11V/3tH+00j0MzCkmKpgTl0H60U
         4PCanDb9AqzN6phDZCztqTX/48UM6EL91otl8W/wRJcvhbYXXGz9+m6edmrU4M0sRESN
         ll6lkZE3A9WjY7QxxlPX9yE1/kYqBi23o+/Flurb7xDsx+SrBRwl+D/Tsdoeewp40vBn
         0uoB0dU1M2FcqKieHpgeh0RNx6wM+S268MkFUX+6RMkE/2OqkOKBiTc6AhMft2KArIGg
         MAe2GLh+U3PMXNaDCC+I2MB9J/PlZ9q3vSJBvZROUAfO/Pda0qpOiWMBKc7BvgmKkMuw
         rLFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=J38TgXwIzdLS5C8umt4KruegiASxm4DK7KsScnDyElk=;
        b=AzOr7mSmK5u64kmt9Iw6ewx4wwdkR2J/OgKEs8BeK75gHQG7UgkohO3SO6ws0kCFOC
         1CKYiY8higOEfvUuGPqKIZRc7nfCWGj4TFB3/zMMHcR81CTIaB1NYk4gf9P1w+kpgWc+
         y5G/iPbPdaB9Xs6CMXpoSv6qjrx1+pus90jqwpcHaywiMOfSgz33GCiPtabK51ZYzFJi
         aSdgcWyE/GhHxtsvA4RwHZRfG/9oZ7uBDctiK/GAQv/t0F8iAtOgdyJodzN9mnPnnx3o
         j4tMaCUJse0EGYoxK3uu4qb78jGXjwIFVfmZMqNG61DUZDBOIENOto8MOoSYzQh1uEpE
         qgxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f9G5VYb6;
       spf=pass (google.com: domain of 3duxgyaokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dUxGYAoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J38TgXwIzdLS5C8umt4KruegiASxm4DK7KsScnDyElk=;
        b=Kqc+Tj5DY1MLGMKteStxRxMqb3hZZyJnhXfuxTVyStFR9YdEeDl/KVAmrS65nDIFq0
         yJAAJlUAyidsuX7HJZX0ygcHVbMJ3h9PNf3UPzNC348wygs6SOJhn3LMcEhD+8Rv51tF
         U28ydMvHyEOoWdHhqQzGmqDa5d1Nw9Ua7fzGTx+zvNtkBeS6lUgrxIoA23RQ4PuU7ln4
         HcZnujZFOGys3PniWrNun0RbFf8uQqMelRnx6RnmKllMG4Ao3VfX/kpi47iL0oOs2rea
         lP34m9O5f1gSInBb9M7YDHb3aQZ42QhA0Upg7GcGJmQRAG9VfScd9RWLAlmsfmHnsMT1
         LH9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J38TgXwIzdLS5C8umt4KruegiASxm4DK7KsScnDyElk=;
        b=OxVaI+ZxjKbFpwsVCkbnBVRPWGBeN15sgF0LhaoH5EevWhoaNFGZYP85osLgXNzT7e
         ssIbnJcTXB6/RMuAd1gO9ns2iyjBR3GylpkQa5NvQiUIgT8/WIh/sRSexcX7DYBoWNqZ
         aLmKV8OSsG/UzTB1+JoYUyo6N6QmZjXG1W5iiO3TChBMq0BzdGoR7bzxokIh41a4vUhe
         V9m78r2suNC0ivbnUqExfjDW71rDwHXMM7b2YmPuC2/obrwwkrym+5XGjK+ywYzYHKzl
         y5bTQ68iKD+p0jXrslpbzSpvzha2U0OA7AvhLNr/dHpqLfRu02Nfz81Sc0yfsehdQ6DO
         73dQ==
X-Gm-Message-State: AOAM532dGOnoLSNROFXjoT/r+goF9rzr/4PVugPG5riJ7FN7ms87arVL
	aPYbS6jjMfvK4T262FptenM=
X-Google-Smtp-Source: ABdhPJy2MG0BM+yauYte+0OxCBUNV5/3w62ae9K6cFLvdWYLm2Q9hy5q/sDptVww1qfdSQParXMHag==
X-Received: by 2002:a05:620a:88e:: with SMTP id b14mr20948617qka.166.1615219830385;
        Mon, 08 Mar 2021 08:10:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ef0f:: with SMTP id j15ls2683224qkk.5.gmail; Mon, 08 Mar
 2021 08:10:30 -0800 (PST)
X-Received: by 2002:a05:620a:681:: with SMTP id f1mr21220860qkh.280.1615219829957;
        Mon, 08 Mar 2021 08:10:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615219829; cv=none;
        d=google.com; s=arc-20160816;
        b=Jr2bYeSvFYpOYVD/I/4S1bf07SlSw2rYLPfQRYLnziDJ8JcnyY10AdP3D8FzqJqOTJ
         EKXxwz+/bfXp4/zczX/eZeD1vhmcB4Sf8irXmkmbBpeaBME9ZNpNW1RIviWTJQYV2b4u
         jPoVDh9RyS2geKASzOLzNm1c7/JM0I0RehlN0KJfSIsowgIV8oxNmk/xaatD2faW9kxS
         kxxUPpDIKTp78tsRrVd2k7u8zp0DNqkEYgKjygw7GCaxeQaUU0tK7FJT9YZ8BET81Qb6
         AIBjfEwcSrNb3nKW1lgfjB46puFW0JXugM/uLBLyxgxcVN1VPX/5ugIeQ5Fhyz19vUN6
         wpIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=oHoXOsuCgC7xf9AhbyLfG6oKwbjtqz3UKDIdpKdyom4=;
        b=ZODpxcNBkB+nT0cQ/6cRQHi5Q1PibywPeUpF4CYxxv1yVy//dxkaEhhlBtyhO4BPuj
         Dlnam8rtjobcJ8BQHQyScwRVSnX2Z8yzlb/GLedWetNRVNPOYpXF1hGFe1lfOTM24/z1
         paXFpWMHpc1bCeWXz6EqNDhBpTmw5yPerZNZE2P96BAq1FW75C+TfzCWb+uL3zYmHmGT
         F+YvNwqxqKRWFVRbq9LoIZodbFrNNO5DInmQvpykHvoO5w6TC5uVBTN4Y6IWyqrocT1h
         oLfNfLUdeP2RsBcANAp0RgSiPqPWi5eqbm5GC4t/2dA/j93wm12QbritaoCMJOcPaINb
         DWfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f9G5VYb6;
       spf=pass (google.com: domain of 3duxgyaokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dUxGYAoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id b4si766703qkh.2.2021.03.08.08.10.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 08:10:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3duxgyaokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id dz17so7995273qvb.14
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 08:10:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f890:: with SMTP id
 u16mr21837557qvn.21.1615219829599; Mon, 08 Mar 2021 08:10:29 -0800 (PST)
Date: Mon,  8 Mar 2021 17:10:23 +0100
Message-Id: <4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH] arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f9G5VYb6;       spf=pass
 (google.com: domain of 3duxgyaokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dUxGYAoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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

When CONFIG_DEBUG_VIRTUAL is enabled, the default page_to_virt() macro
implementation from include/linux/mm.h is used. That definition doesn't
account for KASAN tags, which leads to no tags on page_alloc allocations.

Provide an arm64-specific definition for page_to_virt() when
CONFIG_DEBUG_VIRTUAL is enabled that takes care of KASAN tags.

Fixes: 2813b9c02962 ("kasan, mm, arm64: tag non slab memory allocated via pagealloc")
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index c759faf7a1ff..0aabc3be9a75 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -328,6 +328,11 @@ static inline void *phys_to_virt(phys_addr_t x)
 #define ARCH_PFN_OFFSET		((unsigned long)PHYS_PFN_OFFSET)
 
 #if !defined(CONFIG_SPARSEMEM_VMEMMAP) || defined(CONFIG_DEBUG_VIRTUAL)
+#define page_to_virt(x)	({						\
+	__typeof__(x) __page = x;					\
+	void *__addr = __va(page_to_phys(__page));			\
+	(void *)__tag_set((const void *)__addr, page_kasan_tag(__page));\
+})
 #define virt_to_page(x)		pfn_to_page(virt_to_pfn(x))
 #else
 #define page_to_virt(x)	({						\
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl%40google.com.
