Return-Path: <kasan-dev+bncBDX4HWEMTEBRB74LXT6QKGQEQMAV7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D2EB2B2829
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:36 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id f9sf4737101ool.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305855; cv=pass;
        d=google.com; s=arc-20160816;
        b=TYH7/P3N7eaSdYALtrnnEL6b/TNTf/Oou2gcqRj5dvi6ppmWETWmTk5uo2fgbnsBG3
         l+pcp+Wuk9BRPGsakd0YfVBvaLdcByCVbE70cwQrLv0yX9kbjiu4UUKRaEeoF6KjOIRy
         56+LQSi+PgzP9wPIOC/VRhMRsMPazMMZ3TvUxQtouNdN7FNA+Acboir2Vw6qH2bLBT4g
         um6rVCg2fPgTmOlwoTi7hJRF6NZRVyfnBhp+4BUJ3TT87BHJB+M9IVZPcc7F2BZEmSpH
         Jqq3xBR1mC/AvA7ljECaEzwIA4vCDeiOoUYHNd0GWeo13Kmy5WnIarCSz18GLz+MYVWB
         pFdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=F4YhPWu5Tx7J1uUrGLeamiSrn0Dp7HMRUW+sw+0q79I=;
        b=pkF+nBE8X3LKM6YjRXkd+/XrNIOsPlMHzlBGpp9Zu0/SqGm5630vDsZdym1ybnm9Kn
         2o36RI2xOo7sYXhrKcLO4AUFxDdka4GS99H07P7GcUW7+NtZXpBGlPguEDtKx69JHhLn
         32ImdEr8VjVWewn5kRUT/wwq2SJ7Z3lU1SujvNHBQlRMcF5Ef+3HbaeZQwLiZcPArNRT
         EBBpZycbmV8hnN7Womnt+DB6QIMulGZ0DA1yLgenUHZKIKZCatDf+Cxwrc4WimDhHX95
         CuNvkvOclucfQpyxHfAr/A6ENGIeEi6S5vhRHGFMpd+m6FPRKuBHnrsc+GS/IpbS3vlg
         epTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Irv9DM0U;
       spf=pass (google.com: domain of 3_gwvxwokcckp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3_gWvXwoKCckp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F4YhPWu5Tx7J1uUrGLeamiSrn0Dp7HMRUW+sw+0q79I=;
        b=mQL3pG4nifb2+vUUam5iN/9/fYQjDFtd2dU/I4MQ4YuEG/mG38fL2fiwIeG3zSL0oS
         DxJv6+gYU+16Wm6bTHsF/BkDcFAJv7vnId46UVHDFjFzz8WRCRlAOTdavZ6bDd/aEA1l
         +jP8TNexHZKjEsDWvAg5tnaKR3sjRSNXFQzzBpPZHSna8mV/ls/Tn+DqGARGB0JHtk68
         pjsJ9wodZxZL/hRCugDaqZrzOnMVyiTGar/vl6Ng0uO9+5hx2veyaVuO5EGEaIxc+hRp
         GyWps52a+4hi7UVwv8aQwn6zRsyP/1Gygnhq9XuQVSTWRiBYkO6o89XRaiwAoq/9y0Rg
         upCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F4YhPWu5Tx7J1uUrGLeamiSrn0Dp7HMRUW+sw+0q79I=;
        b=e1OOq+j0IMy1i7REpYAt1p89C5pmoeNJ4f9GXJVK+n2LIs5BZvVzuG7ZYQNoyYSpSX
         Tzv3IiF2yjjwVmIXDXOfxackXtLEcBFqebFkwEpQRh5T7mgpMC53Q8N0J2xsahb/PvBO
         TDy6IvUaCEelE+eHjwQD3JdKXKgSefWI0tQOBdQ6ItInXS2mvKrkatXIxOyctJ10jpZN
         WNXb1JTpJUMJdduQv6d6dEk314i3TTGScs3zZRtUaEzlooIurcH/GMkv0v6nkLsU6mxu
         YUECdeO5gkxpyet3CexETD/WIyXWQ6oj1WUOT2tNzzZhS9tGBAJrqK5phXVkRJ0g77vi
         nGXg==
X-Gm-Message-State: AOAM530/IzcI4rOKU7niUKTeoGdUFKBodgmw6mC9aAvm2sqygltI7SLY
	EHAbJu8xoeohcfwXRSu0dss=
X-Google-Smtp-Source: ABdhPJyJLdsuAHfGwISvqCPNKU5xnuaQYxq6VepcKkPM74DohRgXcv8jxKqYlH5/IXpiz7zqthUz5Q==
X-Received: by 2002:a05:6830:1dd8:: with SMTP id a24mr3087807otj.163.1605305855394;
        Fri, 13 Nov 2020 14:17:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:51cd:: with SMTP id d13ls1898493oth.11.gmail; Fri, 13
 Nov 2020 14:17:35 -0800 (PST)
X-Received: by 2002:a05:6830:1015:: with SMTP id a21mr3257858otp.143.1605305855051;
        Fri, 13 Nov 2020 14:17:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305855; cv=none;
        d=google.com; s=arc-20160816;
        b=C2T9WdOBRMT122ICvWka73Vuc/M3w3K8XJblqKjEL0PwcCU2ZN9wkle5qFAnWCZwX/
         hiTYFbYGbcjDeHzufebK+CHn1slAg2qqVOL0pTJ2Ffk4gA6mdFWOswMZGJFLsNCAVBt4
         dk0TM+Bj12x4IvCQwdKxV1sVRgxEkPJyw6fXpG0n9ITtzn+Di6h/v5lqdQdOqSu92I81
         jPwGKI8N2eCP29oDbEaIetracngOY+qanu47XrDvb87qHA4lIwLkq9pGJhofFgrHWIGw
         n/HEpr4hDnGY+S5CSqbjLjAOL0bMyMo7biirsVfWjeN3q+hhogbHxOjddCmyeMCBprrN
         owkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=03ZVTANVMndAKxBTmMPKTeOd5fHJJQ7JXgAuJEAynpY=;
        b=bmeOhBL7/0Fnz5UWYk2/GRSWxQgUae25I45WipclqeQXg2hKz6JTLtDQPHCQpqAVPO
         GjK0rXnjkSJLDA7lh+qT1+RfbZDkdn1ReoeVTxGshIyyLg8asHalsnZoVnfitWfFr4s3
         zkrNNPphjRTJmoJoUB/ECqxqj4Rkg6jAnIjnNXOQv2FuZZJefTYAS4HxAdyw1Q/WVaSW
         y6hQvrDKN4rN5nQ9K2VNLKNFZCjgMw0TR7n0IwfdDfzjiP493e1d2T8cgOJdo4jLHHeb
         BEWYeQ1gtstUqH1562YEn8JaH69iiYxfKaNJmwROl/RjrpVl5VxBN7IbnVdBe7PcKBqj
         CG2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Irv9DM0U;
       spf=pass (google.com: domain of 3_gwvxwokcckp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3_gWvXwoKCckp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id f16si926640otc.0.2020.11.13.14.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_gwvxwokcckp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e22so6599649qte.22
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:56ee:: with SMTP id
 cr14mr4795372qvb.15.1605305854497; Fri, 13 Nov 2020 14:17:34 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:01 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <69ccb75b7fc7ec766e05ac62335e14e5bf0c50e2.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 33/42] arm64: kasan: Add arch layer for memory tagging helpers
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
 header.i=@google.com header.s=20161025 header.b=Irv9DM0U;       spf=pass
 (google.com: domain of 3_gwvxwokcckp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3_gWvXwoKCckp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  9 +++++++++
 mm/kasan/kasan.h                | 26 ++++++++++++++++++++++++++
 2 files changed, 35 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 556cb2d62b5b..3bc08e6cf82e 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -230,6 +230,15 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3b349a6e799d..bc4f28156157 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -243,6 +243,32 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+#ifndef arch_enable_tagging
+#define arch_enable_tagging()
+#endif
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_init_tags(max_tag)			arch_init_tags(max_tag)
+#define hw_get_random_tag()			arch_get_random_tag()
+#define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69ccb75b7fc7ec766e05ac62335e14e5bf0c50e2.1605305705.git.andreyknvl%40google.com.
