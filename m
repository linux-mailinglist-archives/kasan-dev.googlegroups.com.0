Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTFAVT6QKGQE3UWHGTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A3B622AE2D9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:29 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id x134sf2681006vkd.17
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046348; cv=pass;
        d=google.com; s=arc-20160816;
        b=qovx8E3M9cPvilKtWfHQpOE2q9YYCwNxFEDvzlsfe/Wwzfa2exghfgt47IEsf6Ig72
         eM74M/Mn2zda/fJz0o4F3EC9/c/fle6m9IYxs0teXIPrWtD4H5tD7PUDOrmk+LeSYCnP
         DtLN6EEbM1e2Qf/VfkTJAIhSneTDhlLxaILaLt7sw7aG9nPXIAszeMxEuA0J69S0h5Eg
         pq2c4gSdxnhBQW8cEGno1w/IEnCyYdPcbDQvh+tqe3HzCo4h+VxXaEmjvPzUOT1zz6rX
         z6g4kEdRsW+4cnELEOG5RrfEgQLjyNSv4dVQT1GVJuRUoBjlR6tiY0facAL50/BRFDma
         dqzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=L9jGtG9bWgn0SzXHr07Dkx1KypqLTVWnEuIjO7mAdcg=;
        b=X01UcHxmrqBE77AYRpahHK1QAZqMGkhngsyYbNk9sfGnKZMhoVLD//SsYMuTKYba6H
         jdDdB3Wbf9CS+J5sDX8IVkrEUqyYh2PVZzuwUYrEMv7TxkJRI77E6A5mJ9AD0YsGRZdM
         McrscReNAQt+V49eVj2gRa43fbOVhQwv+TOCCKSoZAt5gXVBeVw3qCT02zT+pvG809Gd
         8dQlLVuguYGNietNg0vEUX4G6X9cma+P61r8wUYgwE+RnjE99fT7KtceXJcUMRsFkeKi
         R4cefm1FOLHWo27wtUtYYrkkaSmGv2bnWVshmhpCW74M0scwE5DbfdeMCOBR2QU0rBkY
         yyXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e3OOW+tq;
       spf=pass (google.com: domain of 3sxcrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SxCrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L9jGtG9bWgn0SzXHr07Dkx1KypqLTVWnEuIjO7mAdcg=;
        b=lSnNzMKQmvucYc7c4sfz3UQMVooWu/b9F/Or82zmKXw7/zNh7V050oGRlLO9m9mfWD
         JJsrh4pXxo3dBpaTY3dU1VqCrtbL2b9OAJbJduA3xgHZePcrbLYap+oH1aVTNMQJ+L4e
         kshV3MTiyhdXOzfExEW60dg3JSdLOZvbPGyCsYS2wyM0Eq2AuF3rBCWe3sxvukc1XMMN
         Ja4H4DzulvC8YpK1iwrzcFV+x6FnIDGgrpwmgEkr6TytczLNS7CnOsUBTT46+WAoTkLe
         WtccQmBCevZutQeKK3bEAj+x4AGxudQDzMX7FvGSz2ObcBU++N99MYxwtyoXXl2UYeYY
         n+0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L9jGtG9bWgn0SzXHr07Dkx1KypqLTVWnEuIjO7mAdcg=;
        b=KND6YUOMW4RnWe0AzZeKPLokc6HC8JNoQPqjnFuX85lFTDNOFVKaDHjgPszeGBFXWF
         WbIL2uomoq9KB1T9BNc7fg+IKcJsHtFJupShm44uNhMXg57lGJ3hmMrYElvS3OzQ5sAC
         ic1mD9KnHkIQliX+MwQH82pUMvvh6DNkKbL+tu7h/wZ/utPP6oiSZxQtJtJvOtl6qFSX
         P/p52yog2WhraLHmRYijySmGe0FKNhn8Nfg4gXnBr5IiROshaMcLU5PJeBLyTfrI5tC9
         Gdv/xTINn7YUpGgmwTZNK8YUzc9fyV2sxnnsofzUe2v03dgRXHo++rgChK177Uzvabu9
         uE3w==
X-Gm-Message-State: AOAM530rrxADyNQXW881sTtakH5Ouf/XimdVuVc8wxuk4VjMfgq2/dnX
	F7dZVm80hhPbADG7pQgqdOo=
X-Google-Smtp-Source: ABdhPJyzf6gBsVz4PdB8sad+5jjtKbAk8j8b1I30DI0w9xmVnKDHVlWNcdEP4VTj4E99jGQtJurm/w==
X-Received: by 2002:a67:fa01:: with SMTP id i1mr2885275vsq.17.1605046348740;
        Tue, 10 Nov 2020 14:12:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fd11:: with SMTP id f17ls1004102vsr.6.gmail; Tue, 10 Nov
 2020 14:12:28 -0800 (PST)
X-Received: by 2002:a67:fc4f:: with SMTP id p15mr13987677vsq.3.1605046348266;
        Tue, 10 Nov 2020 14:12:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046348; cv=none;
        d=google.com; s=arc-20160816;
        b=LAsEON688nhV0wycRcAb1MuqYW/YQQpey+3vXLoNSsT0VoNI4/kS6dTy7rWklu39GT
         FkgwKd8PZVz/3sAd8F6CgYAmgRbzIIlym1CdKfn9iK90h6ofyeFjkVNUrhR13RKuYAey
         iMGGKY7Eu4BFzsNhZt+0ncQgtLvikhAOdwosMQIBgEwnAC3iB4MdFF/P7SFEFV6HKdDb
         okBvTvrjHbTqnAUAYIT3A20Z9l1roWyd+AGoqDWMuMj9FnVnCo4H9FlHJv42GKW3xdcI
         y80zbT37KAXUot8Ze9rOQRa2aUToNbyNdQ7HrZlq5nYWZXHhPrydXmL7GovUAmpvxIU+
         eG7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=AWBOrywbLQB+4u6q3KIizLA7Ns2sbu1oUV46sd6l1CY=;
        b=gZaenoK6aiUx75VLhpb3WekySEGAx2o7ow6JKU7PxfYDigbt73EV+CrRx0wyA4JfG9
         rFXUaanYxJwdr3FBTaw7kSbgmm9zFq98WVtlV+y+kEJ9m5F0vzmLYjbU7ZqlB3Bj45gT
         PBbwmoCp2hV1llA4q3xwLhbhkOfq88lTK2utty3yZwbAuM6IZX1pIkkSJ3vtJCU1kgI2
         7w7ujKg3q78137nd8/JyCZsahzPY13g5AyVaziVX3QVCnllb5ynSkXs+pNeQExzP1jY5
         gFb/nHvNSAZycwxufxZhxiWgTk36gHSkImyCuC8xiQzTHpZScZUG9BubwTiTnpBD9B+3
         UE1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e3OOW+tq;
       spf=pass (google.com: domain of 3sxcrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SxCrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id c124si15248vkb.4.2020.11.10.14.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxcrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id j10so139203ybl.19
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:100a:: with SMTP id
 10mr29800073ybq.410.1605046347868; Tue, 10 Nov 2020 14:12:27 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:31 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <76b91f88120fc8c3e5923d6432a1d537ee584fc8.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 34/44] arm64: kasan: Align allocations for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e3OOW+tq;       spf=pass
 (google.com: domain of 3sxcrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SxCrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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
index 63d43b5f82f6..77cbbe3625f2 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -51,6 +52,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76b91f88120fc8c3e5923d6432a1d537ee584fc8.1605046192.git.andreyknvl%40google.com.
