Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCFO6D6QKGQETWSDJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2398D2C155A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:45 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id o197sf1931420lfa.12
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162184; cv=pass;
        d=google.com; s=arc-20160816;
        b=XTQjD8Y6GB+sZ2fWkpboAStmyhRZNYv45Bnqkdn3dVlJU+4CyA6tQ7Z8FRIr3UBg0k
         gxGX0RsVR/nwOWIMQ6GetIHc5JmnYBWraNKSsSZh0whQNKdL9hKvD436SI+dcWOl2JSm
         RoWaK+X7vsyER+xQPYEBHJkbY9PhO/G8Uv068v+zyFucPqtVu9OHB6SjDzX8FYR49Nw2
         P95bJeFj+GEalyFrKpvASyPeIkeGvfAyj6jaSMSN+YJc7iiAOja2pOF0+MZuR800ctS8
         MjVSjXoCXldNwW2UWTE/HkJlBfUdsn9eloXJ++E4U3PkEoxDupMYtyhQsVGmyt5EGCRQ
         VyeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3/GgqnD9/wRuwQdOyt0RvdTjTrvWvFlkBcuQayvCKCU=;
        b=EdozuB8Ic9gN9mWbZGAxpR/RFhVC7ax5DlwUqJZKlbkWHN245Z0EG1cOMB8w4+ZUAz
         esrD9rf6NadrVKVJtJlwohpttv1aNtq9uS3bUg9cASUnMlZCmOMQkHQtcr+CoVjj/qqW
         GV4t9RU12D0BJA8+T+nOdfZwrl2thY6YCGAMtBmXiItLuupDTxz1m5IETwJX3c/pQ51X
         WZPZ51BsGHnab9RIBjyMcyzp5LLdgMMSmX43j5QrhgiuTS2Tr2AAuOFR/MOi0YlxXjb1
         rToq2l9fdBIIEoS4Cq8Ow39eh7471g59a6IMSCyKrEGNJzVVl/3fOBUO7j6hozz72aLn
         xT7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cDTXlXdO;
       spf=pass (google.com: domain of 3bxe8xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Bxe8XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3/GgqnD9/wRuwQdOyt0RvdTjTrvWvFlkBcuQayvCKCU=;
        b=sDQcx8JrswHavR7iLYpWguzZhn3yG6l17kzkQ8Zw9urBQ5L2AKOSWocIkKgJdgWCh+
         KBc5b/yHpzzl23gaGzu299xaJSnK1X2ZQdOx0za41RtB6/jt2rNdn/Bu5r+Fli61EC4z
         DfHLIwuUA6Hfr4Uya6uK0pDGEeinAgz7okQkA+lOMoCnGighYCEZMRXkVvykTFTUPwzK
         U+MlmkHLE4LX5GdNmxV227cS+6PwHHq1eRbokLj8uSAxdgh1O43ZoP88r4t3w4xXdn9v
         FvvLp3Bl2MeDCsL/kGgaNrx1qowzdLiX3O1O7Xgfg5Py3JzSergEMg4p+E8z+MVIuRrO
         3r4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3/GgqnD9/wRuwQdOyt0RvdTjTrvWvFlkBcuQayvCKCU=;
        b=PBTcD2qsEoB9WZ8S7fWvo6wTOcMn4dotxPm9pBlhBhfQbMuMTrm7fDpqzoBy6CLKzn
         9uM+7/kLkVdwUDw0/PIJZ2Zd31gmJLLsVq3Qez7FE5JD5a+akVvdVP4max9KgelStLRX
         eYmpnXToIKGB1RTHG8kf6AF+Y238+TfAomzq4b5SJGz1s1liveJezrSEKEHjyBEASsCb
         zTVOOX88JV4xK/5TB7izbJyCI98UoAq0H8hZ3Ji7MK8PFiwCs/SQgpXQx3pv4q8rDVAj
         xdZWRBZ674msedyRRd9e1VeIDoLATIk4R4FKa+Bwb+KyIwNKnPqh6IlI/PNOuHMOZHRN
         pmtg==
X-Gm-Message-State: AOAM530hkgwKhcZ1bKSDg9BLKYCP/two6+AWKTYXy1jeXQCVmfCPH/wM
	dJzw7HV7rFhxMlN7LLeXyYE=
X-Google-Smtp-Source: ABdhPJzEY8dSVR04QjFvepXKD+rXLBFP9tvSUiS1oqWqpeRPzXPkWY7NtFfgzX+N1zx4Snte3Sc5eA==
X-Received: by 2002:a2e:8783:: with SMTP id n3mr434815lji.25.1606162184653;
        Mon, 23 Nov 2020 12:09:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9908:: with SMTP id v8ls2347543lji.1.gmail; Mon, 23 Nov
 2020 12:09:43 -0800 (PST)
X-Received: by 2002:a2e:a17c:: with SMTP id u28mr440876ljl.453.1606162183602;
        Mon, 23 Nov 2020 12:09:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162183; cv=none;
        d=google.com; s=arc-20160816;
        b=OZq8w6XrSmAvidV/C43KU0OAj68zRLzgpciGFZbzVW6hHF5fr+AO8odDqMr7po2LhW
         2zTepFoj7TPln9b7uIwj7uXkKb8Y5HUWm1eIgpW6IOlkTioAfgG8+ccAeA9C8IAfnWQn
         S0XEN09yTXob9aoIFdnqossgDDTNnCwEi7VOJrYe6TWZr1U68U8Zp/jonnn48OHHTTVZ
         FHxZS/KGnhdSMhoOcKK57Vx5bgIscQ0Ek4h2nwtOBflXjsOhShVAHcx8Rjh/tDhON207
         2OHjGKHiLLhq6QoMgNA1usdbOnQZ6qYnOoIX6/vyh1nLZ2LGoxgXhxXUz3pPsD3Xx76v
         3ocw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=npUOT2sfAgaDvlkN46GsxTaKsomnY3H/Y0C/GfI83qM=;
        b=PoNdrm5iDSQ8xOKfaqlVsIruN1MCFgTCKbtDRZbKNRGgS+tmhbaPXwaFqpBecU+d4G
         Xk/tYlviWgVkahOroqsLDhZfsBOL2QDCcwXm3lV7v4wQJT0hrpMITiWv0fPvTt05sVIb
         47XPhd6DbnAp3mjSozDpqiNiF/IBgWdN9S9PsnmWBxvcel4qiEdJxR+2G+XZscCn3xsc
         5fsuVlsPNU9q+7tseLDKZofBsrMSzANk3brK6ON738yDZCR1sedp/bTsuw4ZnWynQ79w
         08xWtICVKM+3Ol8wRnCJEQXmniBcUDFNAcwRL3tRcZW/j/2BqMEBaxbfKAhDWHWpTrQN
         yeUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cDTXlXdO;
       spf=pass (google.com: domain of 3bxe8xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Bxe8XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f5si28971ljc.0.2020.11.23.12.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bxe8xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id n13so1515964wrs.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:90d0:: with SMTP id
 i74mr1449685wri.288.1606162183048; Mon, 23 Nov 2020 12:09:43 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:56 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <fe64131606b1c2aabfd34ae99554c0d9df18eb19.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 32/42] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=cDTXlXdO;       spf=pass
 (google.com: domain of 3bxe8xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Bxe8XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe64131606b1c2aabfd34ae99554c0d9df18eb19.1606161801.git.andreyknvl%40google.com.
