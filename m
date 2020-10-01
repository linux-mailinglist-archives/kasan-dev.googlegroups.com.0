Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP6E3H5QKGQESASQI5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3067B280B19
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:00 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id c194sf56125lfg.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593919; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yt+cNSULFNn4p+3/FEZchbF5Z8DLL2qoSKV1pdEIfnM12ikeO4FNGhm/b16GOH8FOb
         gx7CT+69vGAoU+lWWERyiU8ABjvc3oEUdyLc7wWBq4CR6y+kDMPxO53TqdnGOpdL+NmD
         Eb4Q5u3GlYAWlgtiiSE9tFm/ofaFfY7SnFXs07/+A2V8EqlAar3++U1gVyqNe7m1UMvz
         INl/HbL8S2/9bJzzCBPldxvXPFxxwLMq7fVFe0JupUbtvbr9Q9AQ/w8eNMvbFY/m4SzN
         8nyNKQso0TsJ4Lj7GadRMkrrhF7l+JkXdZF/NETftaJWAwifRnVoam4Q38s7GTYcQD+/
         pCvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=wPRtfh6B2KKMaaBTUF26fZGze5dGr8io0QL5Z2XYhKA=;
        b=kWPMzjjZL00r4DaRayJ63CbeBw6jA0t17YYPM68d5QgGuPis58GnASaQ/sR3JijRuM
         5hOJuTV1zBsTBLprsLllAPoDkbDpexvL7OT98+MGLdhSNpDhs9HfoGcm4Rt8xbFqELNe
         IcWo4ZwBbFKkUVToOwl5s8g/uAJaTsmGmie0Mc/MtQc9zNJmwppSzu5UlgqeGF1Gvarc
         WCvGKLoAApcAU//WTcIramvldF9WyW1ePVwsCWPA7iGwQgnVSXS3Bgy5szpwQFk66DUS
         3qN/bkbTVnb3Nt4rTNqo8QiOLurqTw3xzbdT8fqgyCLBs9QvAChVD93gdQmSg42YuXif
         Rfjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aGW3Cnkb;
       spf=pass (google.com: domain of 3pmj2xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PmJ2XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wPRtfh6B2KKMaaBTUF26fZGze5dGr8io0QL5Z2XYhKA=;
        b=H7k9LcVEAbD1d8KRHcNXv2D076oY1enaS3rfUrILu+aVigSoqKF0KGMRIrtap92V9L
         Wg6eR7QYSVfRUktZiUHnFJEEQhJMAOKPunQVFn1vJUphmescWfVU484Z63GZkwCbpuNE
         r7grbPkImjHwDP+gpcixWW6lxmE55zeQnkpjrAswi7kF/mUf9mYGEgaEKKgx11W5PeVV
         b3+QXQRBQb6sevUebZsVFrOdRZCUgoULNreXj3EH6v3EtiTGeECgeSyM4IenELMaD4gc
         JKbLhexhxfDWZSVVqWbV2Ohu8BdCb8BV9Wox62ac4j3E0AlLDDC0VvAfirbQpvWIiXiu
         o+hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wPRtfh6B2KKMaaBTUF26fZGze5dGr8io0QL5Z2XYhKA=;
        b=N7H1gAp8pTtXOSZDpIIasl9sP55LGkBsUs/YX3ZwUvrvHNG8vtFJ7GOHC4PNJcm1Cu
         emY44xgldeRY95NejeN9oHjEHu5p7vvx944LPam1U8/KDCWiwjrcPeF2mU2Bx/E7fL39
         9XhqkOy0+JQJ+VSmH8UKMzU+WKY3dSoHT2ibJZXhHNTl3EZ2vafIjLbNQOgK/1Jw0miq
         RWu81U6Po0dqJh1LipZJSUmhkcU+ZIVBH8HKMUpOXnMxqQoh0GKzewhJrEuGH/z9TIOu
         GffOnjelT3HHKx4g3QVs+xOfCzVeI+/YLMVaaVlE/yPyETGV1PH0/v4NkPGzI4XY8Pql
         vxsw==
X-Gm-Message-State: AOAM532IvVfjcMawMRY5/IDWsPoFGaUd1JxmhLFum9h33ck8CLX+H0Oq
	Q4Ah/NbZYn1VsTO13mxR1io=
X-Google-Smtp-Source: ABdhPJzg87iAyOHiI81hgKWSBQUUCnV8ZrLMxROzFZ+8dWe3wnYHrchix0s51hIolO9ezgGeXw08yg==
X-Received: by 2002:a2e:a163:: with SMTP id u3mr3237260ljl.414.1601593919750;
        Thu, 01 Oct 2020 16:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls2141090lfn.2.gmail; Thu, 01 Oct
 2020 16:11:58 -0700 (PDT)
X-Received: by 2002:ac2:5e9b:: with SMTP id b27mr3202235lfq.312.1601593918923;
        Thu, 01 Oct 2020 16:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593918; cv=none;
        d=google.com; s=arc-20160816;
        b=Wt0MohEo+17DqF7VKgSNzenxR9X3BgYUKTI/HK07UIo12IzfClrXRnbkbm0jMM/9QZ
         QGYkvLS5rgj0ZlUsGWpopECruRcCFZvroKpZeRwzQY6s9J8k5jcmxdPEhJdm2SRmAh/l
         eguFqQpcD0mPdkQNzOx4xkMS8jZA5ZB8nG7ZaREVkPbVXAcwcoFkyDlGJceLI3/cO3Rw
         CTo09hkhaRjrnb898TxhQtKMMTwNQLYL7Mi6fqA2EVBbYtYqdjPxGdPO9J/ynGEvHH9P
         yST58gv4fIkou4q+ymt4BmGFbmulJh1bhz3H+4GYevGEOkdnDb5tsc8IVwFEtE/t7tDZ
         /9Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NeJpwcUoiisJbm1IU+MKWZ9xhPH4pDihjUaOi0iEgto=;
        b=Jvecb1NbDsWUlUP9YbfBhiBGqOUMGhca4B/MY3jV/ENuPkl4cbJ+quCT0chtTGc8kV
         kh5u/afTh0ny0x3qOrrrhciWA2O6bNPM7BwO5aysvqFXuimcY5HiUdkPY1vSQaarPSrA
         7WuEzzIb2C/KwYrCfeh6SX+HPkYci9Vbl6Jw0gopC/fwY2nDYH8sY9+FYLFbhhloc5Mq
         +KRfUlEtBdobuiMCxHENOgz+BtoVRNMGD9zyytEJmwvGbGQgTRXNCqUM2oauJM+5UjMC
         be+4OPYHPpgGgx1uE5dHE4SfgoxKp3r90w8l0iTYi6HFG8UjswxCWeNSRvCSC0vQPCMs
         +SKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aGW3Cnkb;
       spf=pass (google.com: domain of 3pmj2xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PmJ2XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z6si227019lfe.8.2020.10.01.16.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pmj2xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u5so27212wme.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:22d2:: with SMTP id
 18mr2181468wmg.145.1601593918669; Thu, 01 Oct 2020 16:11:58 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:32 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <def198b749be0c3b6065cc853a7013afac45316b.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 31/39] arm64: kasan: Align allocations for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aGW3Cnkb;       spf=pass
 (google.com: domain of 3pmj2xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PmJ2XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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
index a4d1b5f771f6..151808f1f443 100644
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/def198b749be0c3b6065cc853a7013afac45316b.1601593784.git.andreyknvl%40google.com.
