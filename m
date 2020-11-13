Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAMMXT6QKGQEQCW6ESQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 99FB82B282C
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:38 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id w4sf12416528ybq.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305857; cv=pass;
        d=google.com; s=arc-20160816;
        b=Isgc/Cj+OgJEjeMo03F2l5X1bhZq1yz3VYbogsyFrtoejaH1CmhIULb9Tmu2CuAL0E
         OE4F/comh9Fmh/kysl9VivkqZkra6tBX1risH1QHAV9DdnnXtjeD+KynWTj+616tpK4C
         ZbMX+hlx3G01HhSvEzOd665ADZBdDrRWteuHircPu2mOgKYUEm/rKczWOgu+oz3btWUK
         O2tP7GQvMJrNiYfuJ8cx5zR5x83UdzGVcT/WHu+aIwJ3vCAxXCCEfuQUIEGrXxtENzRM
         3wiKygjtZlISM0z0evaBVFIruLKLfCfLue9NfjiF2vI6hYXB5+2Jw4xhG4rSaerB5688
         /C1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=uK2qUMwc0LZcpKPQ/tMlZBR11/Kc1J2LHHD25tW4PNc=;
        b=sAP6K1yqgD2PkFptH1fWfhqXPmtsuto5LyIzy9caZaGoc3XY/Ee026g+NlFmbYlLAo
         6pBsMEyIpkS7siE/PPkK2Kn3/dARBp7cAnFB1tPu+uR8HC42P4V45SKch/1opVBC/6hl
         /wx1OCwcP3YPpkW9F2/1LidA946HFMEAb00S3aoTzBLGiTSVLU91dQYIrlI3vTZPtICR
         fm+khih6tfxU9pd0wRrND8Lin9LfxBXeEWXiH98GkI7MUYhocz0sMl3G3Q5EwYn6tnH0
         mxX5CVhUCAY0YHTUiTuH37PJwEByaJEeWVTj15vopTdYq6HTUh4qZOD34TNNldXlOyw/
         Ca6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OViFLnDT;
       spf=pass (google.com: domain of 3aaavxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3AAavXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uK2qUMwc0LZcpKPQ/tMlZBR11/Kc1J2LHHD25tW4PNc=;
        b=E2KtT7HDd5uTtVcG10p6+mtdGtAyUuTBtVuWDz1skOASaiZcw42xmgPb9ZMdl+UjL1
         K+kBOm+riJzrqwes5ArFWXZP/lXQUrSwH7iYQwV6ScRP6A0Riqy8E3ididKYr2c2v6bP
         +vrIzO325fgOIdRHf/cScXOdb6eBHFUMYcyF4U6sFZ0upb5vWXAGuSubPVw81r/fC3Ki
         NcNFQ6OvMl0WZNsnC8TXzqCtAt/ITn4oGnGpqARHd5+GHkOnAcxAhzA+atifar8EDKwC
         ss41g/Xg77nrtX0Knubv4mPB4XiDNaGhvysIe3ogIdt9rxD3aN2i4qWcEK4qI6C0yd4K
         G23Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uK2qUMwc0LZcpKPQ/tMlZBR11/Kc1J2LHHD25tW4PNc=;
        b=qZvVFvW8D31UN1r3zJNzI+9k7MZIHH7kvXkO+DyAPDb8kkVB1ovSh8dtnJw4qo1PRz
         pZkngaT6zz6hjIqDpWrVZDM0KWTSmj1brIyG+qry/oY99qMHyUoNNUs4uxJ43853Wuz/
         Ollq/wfmyDGfjcOJf/OUJYTaossyhki/ZG27O8i7mxYVTqZCFAZr1QcDCmcY+ynuNDTO
         Nm+uTWMWOfu1fvDDuur/qx0ZNU+HVTLjgmd5EGy42EAEVYRAsZ5N+UDX9bio2oWtJBIb
         VkZRjeCDcGEDLKfhkOHtzm+KpFrpOqFhU/g6JAI90o2kcoY41dkFNFL/6Zo1yK0L0zlk
         J6+w==
X-Gm-Message-State: AOAM5303m+Ykr1f/cd5egNL3IAfjRJXRhoTisqt/D0IOGyyl5JzQJ7/n
	6YrjyWUR+Izsij91D1ZKwyc=
X-Google-Smtp-Source: ABdhPJxqnyLOLNHUkSDH0PFb3GhvMdNbKh9MQlOzEO+CxCS6j8VSHrqVCvJ9wk10i3ZkfPljg8nOlg==
X-Received: by 2002:a25:4f0b:: with SMTP id d11mr4397546ybb.147.1605305857724;
        Fri, 13 Nov 2020 14:17:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a268:: with SMTP id b95ls3976863ybi.10.gmail; Fri, 13
 Nov 2020 14:17:37 -0800 (PST)
X-Received: by 2002:a25:bbd2:: with SMTP id c18mr5140227ybk.442.1605305857269;
        Fri, 13 Nov 2020 14:17:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305857; cv=none;
        d=google.com; s=arc-20160816;
        b=wVXjVIrPDbr/3LnBxbc17xc9Gc2yilXkuT3Gqx0iuAlFNeUPlsbRfsmZgmOtmSQry8
         J1XH6Xji6OLvM+IJjZmC0Y03SHprlPdRu8dZ3GGiM6xVhR1qqYa3epZ7E9VTPl3buoRV
         b+CX1kFKWojxttZNSTTMHmX3+wWElFwbNG10uwR5K9uSEIl17OQxIFoe7xmnqQ/l1nMW
         Zhd3ImlRHlahEJ7+TL6taOP+n4yP1zESuKxSa+4iFKP5pZer3CXI4mh4I+fm8XLrYfX2
         5IcnhRf3BEbOac8ZcNGubT3zBLuqLVQWvXWw+nYVSUbLUFydVHLveinBgiHwv2L3jNI/
         3Oig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TQ3h/P2zSifjnEPKLUt8MfrzzWgegpurLotLIMb03KU=;
        b=v2VxTUGlL9+ppsT9D48i+LPkhyc1fBSqlyizpqpWEi0hN8GBImBpbu/pEsD1CvsR01
         dVhllMFZujNaQbM+ZP859Sbbu9XcYrIKyiAebMDmBveTZxzA9RvLgfe4kV5+P7/NshJY
         3cQqmOcKK9C4JrNnjCZ0mD8zKrZSW0jcsOLMXF92HJ6D+tjVYzTCI2+As9KVb2ZnYFJv
         74jJeg+vM9NJLf2xlnmRMhH7sz1SwNY/8gUBllTLbdZh6CkN/PM4jjSm4Ay9wUj04qUW
         aih1CirFM2iymQkm8Dcfe1j595BM1iZfzb8e+wWyX3dSqVFzw/Xgor7OJ1ArFQhYPPM4
         tHOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OViFLnDT;
       spf=pass (google.com: domain of 3aaavxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3AAavXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id n185si657634yba.3.2020.11.13.14.17.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3aaavxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id b191so7558966qkc.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f254:: with SMTP id
 z20mr4721382qvl.36.1605305856867; Fri, 13 Nov 2020 14:17:36 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:02 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <67354d1e68484b547d222b8f0ef402887954be06.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 34/42] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OViFLnDT;       spf=pass
 (google.com: domain of 3aaavxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3AAavXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index bc4f28156157..92cb2c16e314 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67354d1e68484b547d222b8f0ef402887954be06.1605305705.git.andreyknvl%40google.com.
