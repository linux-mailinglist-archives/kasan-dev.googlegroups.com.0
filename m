Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7MLXT6QKGQELJYCD4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CF032B2828
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:34 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id s1sf3208815vks.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305853; cv=pass;
        d=google.com; s=arc-20160816;
        b=hFNhZLXJ0xavGUUyc06/KUob4aND90r4QdLOvw+GF6xLgYMOxiqmYGB9WUb/Xo62bp
         VgP+hjchKA4SQnTWC2sz/CO0hWUDTs7coPlB1u4C0/Elr+wIxhDqhlPGKk1001Gdf1+e
         dxB+ir2o3wA+aYdXbUVQmYj6EcFxZVSF5QXtBDQSOun7jH8LUOIeEoehupNcZxckZyee
         dRc2OhRFMO99ALCbHU1DINNGTrUOX+lSIgYN/kyLNE0MSI7PUe4rgSpf9lyJs7PtYJGH
         J+zUFpmsaJchVNTutoVWhrAgH0PlYdFNp+9Nq/82IK729Acq4gvBENi9GJZw9As5zu+f
         3BVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=KAqbHctR+8/G3Ao87+eu2hwL775pFQesLyGmxv8bCb4=;
        b=HJ1MYRNBfNECxABvL6OfYJ4+qC42/E/6yquhy48/UQEiwpX7LxSX/lE3+thU0QBBxY
         C/N9ZG7kCJWtzyiP9gkNtBFT2kGUngEynfkJYK+IZuDbh+SUVh5sm1Euxp8hJMCP1Isc
         RshwR9CqNuYQreRQhoplyc6cgSUy02YIb12YL/nkdqaHLVqIabWRIVMEFykCiFAZxbV3
         6u24/mcYfeMfr08XiBg5sNB91L/OtXgVTGjC7XZHAzkfWRyBc3Jd4rxqyls/6PG8rkON
         zrl7ZtzRxgOJPNnpib+SuaKBPjYB6rNl/2H8AtVPGOHQrjuRXfWIwT3uOwVPzv7JC9Vr
         kjHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nmTDGdvS;
       spf=pass (google.com: domain of 3_awvxwokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_AWvXwoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KAqbHctR+8/G3Ao87+eu2hwL775pFQesLyGmxv8bCb4=;
        b=T2XTjpb3Y3HYdXj2qV1ig+KdZXS0xFTFOfE9s7xnM2NjzeQ6yGiHk3WIisWxZyPh+i
         WCUG8PyP9n/w78WXZ+yjaVCI6MUuIKnEJmjdUIDsT9s4WJ6PU9SnFAWj6bGi3pFUP8xP
         zxs54E5g/fx5vuttYGDx6QpQ3cIO4GqkkeRZlAP0R5zeNl/4mEPeumZv3VtNped1S/3b
         JCE5RMRZdIpqo6Q6seNdBVR9VMT1ad8O/HtCTLdXzSlZNdXVVbXNvQ4imOyl9zEGU09Z
         009xW9p/48J5Tf9cZyWq2h+GB/yUvqnBH1RV5meep2J92dQll/QaAa0WfEMbgKYh1MoI
         BAiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAqbHctR+8/G3Ao87+eu2hwL775pFQesLyGmxv8bCb4=;
        b=oo/ExigiRit40MLo5l+OmEBfbZ9AB/ZEUxiJjN0vSqMO8m3hwLXQR6nQqTus6WqYDQ
         L31xl3bY5d4yHUy6hM8hCMpUU2bG2uw8AGceKSLpE9ulmRHdq2GBF7EworhjBLhVei2q
         Bs8lwkdvkjq+WDe88ToPHxgjgxrf8lqAoZNc4VmMNdSqLukX/cobQwbYYEWxD06L1q0W
         odvW7vSO6R7xJxzn+FDzvHX9LLY2N2rGqQ12eB/P5j0efvWF7HCo7iQUx1e29fwsd/fv
         aNFgSnw6359V1cqoNmGZbZist0vrp39B7Y/UB0b8PUcY8sFP0cc0GM+cz6jX7VB5wbES
         NT2A==
X-Gm-Message-State: AOAM533awTjM1kZdEhKhsCnvFtwiCw8YdpmCnmeYEgZHihBEo2rcJnxe
	NfbvhL6wLwt9TxfQnoB8a5I=
X-Google-Smtp-Source: ABdhPJz4v7pHcmBzJRs+xYQAE87wHHmuPTTK7Z/Lg8KYpdk7CD0KH+l+WvgzK+Jjb9JmDQO3v3pZ2w==
X-Received: by 2002:ab0:2a4a:: with SMTP id p10mr3549113uar.95.1605305853221;
        Fri, 13 Nov 2020 14:17:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:d9c6:: with SMTP id q189ls431352vkg.10.gmail; Fri, 13
 Nov 2020 14:17:32 -0800 (PST)
X-Received: by 2002:a1f:e584:: with SMTP id c126mr3011568vkh.3.1605305852779;
        Fri, 13 Nov 2020 14:17:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305852; cv=none;
        d=google.com; s=arc-20160816;
        b=dJ18gE9XVrdNvNM2nxjHiIqYWgarmjlnI9cxe6ezUe+ArPU4C1n8VgKKcBQfj5TAnW
         T+6Ykmkx1MSLWvmht1RFDoOphY2adH9Rmt+dpTZZRUd8F9YRF2NQNMLVsjlRJpbG9JJT
         mxwqwO7Y07wjDxKck4l/aYU5vX0Zam2OPLaPh+XUOq4b4W4fawJbuWkWEnJISiRibur6
         8PHcp0Nmz12SVg3QzpmRnL1dhlQqZWGPfpTWMkptDT8j9M/NrEcKFBUGpFs5IiI0Q4/4
         YjcNEOcI26/hmszWmLn2kuDVlMe+aw9VMO13UIzsDejQtNC1VjjpgQVhGjMGgOWtIXE0
         illQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8wuQS8Ui6lRxf4z6N6Fb3Z17fSYd+0q/Aq0OIY0oU2o=;
        b=AxhkysD3wo+fsB4yPVKQ3WpiEXnTNgB9xXHFNnWyahV78NHfAzxijDXACSiC9g1ry7
         Bs/ul1l+wQbtIClVWt10uzpEKis2TVE0d8cg7iOkPHkYLE8N7Yel5XUXA3Wh/tH8E0+8
         bx+NkiUMZczqVxzVoAozF60xdIhMPT5/C/H2iSJKvPIRY5J/Bs9cIWw2yzb1yBkcIdFc
         +6CRD/QExXR25p2F9gutfjZlZHijg1xc5FrhtJJ9A9Ejwmtw8vWTnV0zHYVrPRPrnS9g
         BhPUa6z7ljELCNMXOZq5fRxOqAjaOvx9jBcE+IUseTKcY6MBpC/KxgQNYpnbZnf4N+XC
         svCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nmTDGdvS;
       spf=pass (google.com: domain of 3_awvxwokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_AWvXwoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id j77si640497vkj.1.2020.11.13.14.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_awvxwokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m76so7616210qke.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c709:: with SMTP id
 w9mr4788537qvi.50.1605305852387; Fri, 13 Nov 2020 14:17:32 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:00 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <3d2ffcbffff7cdfe60d10493081f82205c181ba7.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 32/42] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=nmTDGdvS;       spf=pass
 (google.com: domain of 3_awvxwokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_AWvXwoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d2ffcbffff7cdfe60d10493081f82205c181ba7.1605305705.git.andreyknvl%40google.com.
