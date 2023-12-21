Return-Path: <kasan-dev+bncBAABB3NUSKWAMGQESI6WN5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3569B81BF52
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:03 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2cc53dac71fsf11970191fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189102; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZluPpTKuh5ZnawPl/jloMj6AZ2MUxxj90MC+KrQorb0CmhUn/u5KCA4xU1OWbvrK8
         JucEIHYVM8t0x8UkHXKM9VaKYx3iRNIBULPgUuaJ4+69Qb43wnrU/gzIjYKUrtc09UkC
         u0sVLQclugWoaQKssCQwiOG35ZLJL8k6mYUSqjWIoxZ1t2UrmZnajj7hbZ+U4h1FPdz1
         RDPw6ME0OL/9m+KOae9OVAqInhlKoHNED1K+PgyDl32zXwXIg6VJL/vpV5VM6wxkxIFa
         +vbWBSBk6OUUn9NrT1AJ4fH8bNaBURCy1a0JJGcI/M0AxqwSoBT3pQOTt7IgtIKd/rnh
         /ATQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GvoC874iUKLLBEwKosN1KfQ2hFgz37kjncCGz1uE8Sw=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=S/01ZNYqQrXbOgH6eSfjRMjDAfYohvv7X+9P5DxqKmwnduuunIagVU8XoeYBoCrZxP
         j+q8yzEYerNqaD26BzTNCMRGb83BlHifj07FlnCavmIffzGvsQ5lnxY1PWcsZf/J0giX
         5lvLN+kvAMeTdsN8UI1AQ2euP5fa5zvAFyGByFAUitxBXg4Ymos0SQPuzNeCtenNiF+s
         Q3h4YURUPROhgB/56vf23kV0D/4fk+bM5gndiY0r93aQVcDq7QmJdm/sYGdMt6mFWY3/
         2UuQajyxnWDTkvg3LkGw5R97dVCYY9SC1IKkjkv0FxreOcKs+M/+8+QN8ujPMcKE+MBL
         aLJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ca6Xr6Os;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189102; x=1703793902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GvoC874iUKLLBEwKosN1KfQ2hFgz37kjncCGz1uE8Sw=;
        b=RhPHdVfamUXbrWLUMMqaxTtDWPxa/tkMcQAZ5HfnotMvWSjU5S+Se3ajEcA4D/+1Of
         CrIltoepIp35kUSV5DklQDJdkgNL5AaXXuugm0ncn3BNpN89emwk9HaRT5JddI6xirFY
         3h3Qvy5fmy0y84CK6/9Ik7je1MUhy5QLFTVXTnvlafpfXhcnWmsdSVIRjM0XjaxvJ4zt
         jm4EWt7zPGSFKkENhEKZtt+gvSsr3MxN84UFMWMxTdAOXwyv6geqSkWVojOResc66cze
         GOa7J3Kny9g5PM15jK3KlRShRusrlFef1irad5urbnVJ50Zbw+3x/Nxa/6aS5XHZwBw0
         +e3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189102; x=1703793902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GvoC874iUKLLBEwKosN1KfQ2hFgz37kjncCGz1uE8Sw=;
        b=UvqlgPZOSFOMHYv6HoUJ05kDUySenAXxvqT5RWac2PUWoVaLDd+vpyWEqob8QGCxSs
         3Oa/FafT2lRuj9hp9iT2pAbazYVfrRaeUz5FggcuNGuTidQrOnXzVzgoSe2YW6XOw/U2
         5hkTLh2n1UiD9iNnuz4TSyqayX/CN5MJznhg2Tx5GBnm/bKDdU4i3KEYj3A1p65YuSEQ
         3UOuEWbq0dbkdbfzMbIni69di8RDJti8v2qbskobsmHLdMz+Lp7ZiWPjUfxfx7bj0xHr
         dYPM7gxbufDh84xe9iNulMrfiVhCn6WzNtir0sk6Yqreowb4m01CFUQHKm7jZkTaPctS
         kbKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzIMSg0eMlzKIS/JTH3vMHiKBep/fb0hEfrQJBVGMVMLbY+d5ce
	3jMdZ89CVKtgMV4BYxHT/hA=
X-Google-Smtp-Source: AGHT+IHNDXZBy6LjcS2wQ+i6j6FG8DR/6GBNDSjlsPIzDDihZye3ZWgRimDsAaFlvbQwqE1zmaXM6Q==
X-Received: by 2002:a2e:3216:0:b0:2cc:6bbf:ea87 with SMTP id y22-20020a2e3216000000b002cc6bbfea87mr143550ljy.0.1703189101985;
        Thu, 21 Dec 2023 12:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2111:b0:2cc:7110:a363 with SMTP id
 a17-20020a05651c211100b002cc7110a363ls199313ljq.1.-pod-prod-00-eu; Thu, 21
 Dec 2023 12:05:00 -0800 (PST)
X-Received: by 2002:a05:6512:ad2:b0:50e:3e1c:5cad with SMTP id n18-20020a0565120ad200b0050e3e1c5cadmr1000871lfu.17.1703189100268;
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189100; cv=none;
        d=google.com; s=arc-20160816;
        b=VASeUnt8EZ7XAu12IbjAOUj+kVKBk1PopryvP+tDiVj9kD+yxsmb9Ylgqno4ZQKX8n
         a6GKFSeLOifj19tYk+RVLd75wAlOXwPQXTlJXq1OvDyX/dWuArZZmwInZBVL+fwDczzV
         0cWtbxLJSzXqRxq/4rJ8KqyfoMJrWfPmCc7wxOaZDREbm6/KMN37eNfMd66fyiUYi2F+
         8OGhcDF2/03dT5+6eABuRJ4ncX/zk+4XFy0Rcg0OVPNmtTTc9lwIo8uw19+s5P+YCxOh
         03pnnKP/AOmTtqeNw1Ma1AVnRZ6wbuuQ5yX5Y/zwl0GWOchG7z9ZSBLANIfnUvJuCPH0
         GnFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+hJyqXb/2fG9kaa/Bl39ZO/TtJVAZ8OgDJUIBMdnwuM=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=Qsy/UA1c1QtUaUkQuN4t0gFbubmalAvPaYh45a96DKFvz4vwFCxlGk4nNzM1HCfRrL
         3SxUZRpHs+ZkRFFquVFRsjfJrPovM4fELXcUq/fJBQTS2618sOEtO2kc/I6anvKiA49h
         NhCPOKH36OmnQ6IabTsw0Sc9qiiH5zZQxmeeHECEWKV9ySkKkdUXYdUyzeZbwSs29NMf
         HTs9rvrn2GCweh6d27UEK/x4Bj6nmVKeYdjaDXZEaqhqLG9EwpFNQHPLIfxyLF3L28Vv
         z/RUqmUwrNLPPiFK3UIGiE3EEPWcuhP+A819sms1wlQlDxaaXOq6PQ5KTciWgpYH/M+O
         Q+/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ca6Xr6Os;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id o20-20020a05651205d400b0050e1c5be1b4si112625lfo.6.2023.12.21.12.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 01/11] kasan/arm64: improve comments for KASAN_SHADOW_START/END
Date: Thu, 21 Dec 2023 21:04:43 +0100
Message-Id: <140108ca0b164648c395a41fbeecb0601b1ae9e1.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ca6Xr6Os;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as
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

Unify and improve the comments for KASAN_SHADOW_START/END definitions
from include/asm/kasan.h and include/asm/memory.h.

Also put both definitions together in include/asm/memory.h.

Also clarify the related BUILD_BUG_ON checks in mm/kasan_init.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/kasan.h  | 22 +------------------
 arch/arm64/include/asm/memory.h | 38 +++++++++++++++++++++++++++------
 arch/arm64/mm/kasan_init.c      |  5 +++++
 3 files changed, 38 insertions(+), 27 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index 12d5f47f7dbe..7eefc525a9df 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -15,29 +15,9 @@
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+asmlinkage void kasan_early_init(void);
 void kasan_init(void);
-
-/*
- * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
- * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
- * where N = (1 << KASAN_SHADOW_SCALE_SHIFT).
- *
- * KASAN_SHADOW_OFFSET:
- * This value is used to map an address to the corresponding shadow
- * address by the following formula:
- *     shadow_addr = (address >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
- *
- * (1 << (64 - KASAN_SHADOW_SCALE_SHIFT)) shadow addresses that lie in range
- * [KASAN_SHADOW_OFFSET, KASAN_SHADOW_END) cover all 64-bits of virtual
- * addresses. So KASAN_SHADOW_OFFSET should satisfy the following equation:
- *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END -
- *				(1ULL << (64 - KASAN_SHADOW_SCALE_SHIFT))
- */
-#define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (1UL << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
-#define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
-
 void kasan_copy_shadow(pgd_t *pgdir);
-asmlinkage void kasan_early_init(void);
 
 #else
 static inline void kasan_init(void) { }
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index fde4186cc387..0f139cb4467b 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -65,15 +65,41 @@
 #define KERNEL_END		_end
 
 /*
- * Generic and tag-based KASAN require 1/8th and 1/16th of the kernel virtual
- * address space for the shadow region respectively. They can bloat the stack
- * significantly, so double the (minimum) stack size when they are in use.
+ * Generic and Software Tag-Based KASAN modes require 1/8th and 1/16th of the
+ * kernel virtual address space for storing the shadow memory respectively.
+ *
+ * The mapping between a virtual memory address and its corresponding shadow
+ * memory address is defined based on the formula:
+ *
+ *     shadow_addr = (addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
+ *
+ * where KASAN_SHADOW_SCALE_SHIFT is the order of the number of bits that map
+ * to a single shadow byte and KASAN_SHADOW_OFFSET is a constant that offsets
+ * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the start of
+ * the shadow memory region.
+ *
+ * Based on this mapping, we define two constants:
+ *
+ *     KASAN_SHADOW_START: the start of the shadow memory region;
+ *     KASAN_SHADOW_END: the end of the shadow memory region.
+ *
+ * KASAN_SHADOW_END is defined first as the shadow address that corresponds to
+ * the upper bound of possible virtual kernel memory addresses UL(1) << 64
+ * according to the mapping formula.
+ *
+ * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The shadow
+ * memory start must map to the lowest possible kernel virtual memory address
+ * and thus it depends on the actual bitness of the address space.
+ *
+ * As KASAN inserts redzones between stack variables, this increases the stack
+ * memory usage significantly. Thus, we double the (minimum) stack size.
  */
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
-#define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) \
-					+ KASAN_SHADOW_OFFSET)
-#define PAGE_END		(KASAN_SHADOW_END - (1UL << (vabits_actual - KASAN_SHADOW_SCALE_SHIFT)))
+#define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) + KASAN_SHADOW_OFFSET)
+#define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (UL(1) << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
+#define KASAN_SHADOW_START	_KASAN_SHADOW_START(vabits_actual)
+#define PAGE_END		KASAN_SHADOW_START
 #define KASAN_THREAD_SHIFT	1
 #else
 #define KASAN_THREAD_SHIFT	0
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 555285ebd5af..4c7ad574b946 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -170,6 +170,11 @@ asmlinkage void __init kasan_early_init(void)
 {
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
 		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	/*
+	 * We cannot check the actual value of KASAN_SHADOW_START during build,
+	 * as it depends on vabits_actual. As a best-effort approach, check
+	 * potential values calculated based on VA_BITS and VA_BITS_MIN.
+	 */
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), PGDIR_SIZE));
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), PGDIR_SIZE));
 	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/140108ca0b164648c395a41fbeecb0601b1ae9e1.1703188911.git.andreyknvl%40google.com.
