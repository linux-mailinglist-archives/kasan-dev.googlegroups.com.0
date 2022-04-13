Return-Path: <kasan-dev+bncBAABBUGI3SJAMGQEKTGGUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B1CD44FFF43
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 21:28:17 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id eg29-20020a056402289d00b0041d6db0fbc9sf1584138edb.9
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 12:28:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649878097; cv=pass;
        d=google.com; s=arc-20160816;
        b=pMSdMVzV4UYOFz18/AO+j3JCSbKDXSB2KUyAo575on9As8YPVs1YA33DpFD4ozbS24
         Q4CmGtiNKfPv+xZT+3JTC2cWD5NsgQg8ld3P9qjZGN9grIHmj/4n6ZRgukXD0oitm65f
         vH521M8cdAXKDQtSRGb+zDGlAcNzdmo+jW6lrvX/bTzhxTMOY4MEPReYxUGSsa9L5EYJ
         c0HwcsZus359gM/HNXvwvvOikgwdbD8InuVQCC6ZQpSTcZHKjEhreZK/sSf6SmANvyKe
         v3Ld25bDE0AVZs7Q93hPhcwT/PBW+pibliZS0elvtPFs4QpPbB4vNdrIrOny3r+L7Rgn
         6dOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RRBLpFLmv+AYbXFpzpBdNxO+UdvD9LHITfVKK+0lGGM=;
        b=gMrV0Dd9DuCMNSIGHDMPC1RTwmVDEqJkcXmW8eFt6vCjZ7HtXko/OdXAPbCWRjl3B8
         yDpW4pQIL//nTUKgSwhkP0g6UZAfcHLixO6Y7SjE0ORO2VMN5kgZphBuJbhNHwELGDOl
         k7lu2CyrXgB6sS1jU85HW/zY1RaDUgNSZf3rWT9TZn+Y9VjA7e2z2SVFTgjsLvzk6Wlb
         q/AMYliM4Lt2E0RJUGqPH2aGnuU4+lmTRpPG6lY/q9n9onfwhtpxGM7bMi+jJGj9Bl91
         5HK2BbAAIO+1TkLbAooz9YCRb/qjMbviTOFHODHzOCK4830VQlJ9lbMJFM3+7nY61ogC
         yNsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nykjmmr0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RRBLpFLmv+AYbXFpzpBdNxO+UdvD9LHITfVKK+0lGGM=;
        b=nzJCKHIlSrQPgrKArq4vht6YHbz9P9Y/KfEBvmc1xeYwOrE6k9NJMWsmTBG88vfreQ
         CitpAF1U8MF02wy9+LMRSjiU+g3BvnLcGdJDJchwncJ1dajMqhtQs0qTHI0gkpmdqqqr
         7YIynUMfnKbLk8Er6NeNXo6YSdoazFW/NcjOB/NGHOyLTYCxFIFbrP9PZVMh0RoJKepG
         kq1kXjJZMBQbMhFp/5e/Nb0Ym5vgCxBXknZ8so7mUoEymUX6Wx3io9wGFddIJ8m8upRA
         4NXJhkGw5du23RQF8r0K3QLXWFpIRks1EC8SEK7N/b/xAHo3CW6+riuWcL+dlihu8LYo
         MdvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RRBLpFLmv+AYbXFpzpBdNxO+UdvD9LHITfVKK+0lGGM=;
        b=yxvbgbGzZthhCKc6N3WplY/w1cCszgltyXesdfuODw1BI15o7WoxKtgQ/Oz/+72NEC
         gesjSS6fQqafSE3eu5tULp+7ibrSVqnUpYwGLID+yN/DE+jB/oErLSXVpKj9Sl9GHvg0
         5Wt57ZGl7VtP/L2ZD9V7b44eXg009pDvzTHyAhGS+8LNcfpKx/ZAxKgp4+Wle/nOiNQg
         CPsa0/f0ynuNbvtZOdSZV7WIu7oMMxSU0fgVGpeOi7Hv+PDNhyKcFY2IV0xJOnkTy2P7
         MhvWY6tzzqGvFYPaOc87Fo0pRGAysyadMvJKBgZF2RKYiGy4seAxjssV6vzFiJk5WlmO
         V5AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hUmLAILSGuBI7u5d2Ao2CHzWNbYuo0tVEc7X/8v+rLquJkC7M
	xTqfWklNTZMWaQCDOP0N43Q=
X-Google-Smtp-Source: ABdhPJzwoTaFF3qBkJE6KE/C4uYFcpw8W62vaRvrZxCIjZ+jEgdhQieBstVluO0AYOCLxZmBm4oGpQ==
X-Received: by 2002:a17:906:9746:b0:6e0:5c9a:1a20 with SMTP id o6-20020a170906974600b006e05c9a1a20mr40881315ejy.714.1649878096889;
        Wed, 13 Apr 2022 12:28:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1b03:b0:6e8:5d66:6520 with SMTP id
 mp3-20020a1709071b0300b006e85d666520ls1507532ejc.4.gmail; Wed, 13 Apr 2022
 12:28:16 -0700 (PDT)
X-Received: by 2002:a17:907:971b:b0:6e8:67cf:6caf with SMTP id jg27-20020a170907971b00b006e867cf6cafmr22884498ejc.259.1649878096172;
        Wed, 13 Apr 2022 12:28:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649878096; cv=none;
        d=google.com; s=arc-20160816;
        b=YBPu6Sw80h2Jv0fGUIqsAzqRrukRcV0vepDwfNwcSavBiemJ63myDBxdEvV3wdz2Qk
         HQT3ued5WrrCyu2sbAqvgjXALi+r19r13perx8jKskil9bhTTJMazIxt6+psNrYepWjr
         emKFj8I1LT0IDLXjcAHFobq/Cf1aBWVOCWlnrTHGQ+1KAGTpwy2p5tR0GhT53DQfGU4i
         MTr5zXYgnBB+kNiVEZKekyoij+CSo52w8+u8ej8zR8nGTWM8IAyEqWVYk/cQQUabHzyT
         MmboujAbbHIyV6IKH0IxjZfnuNQDHaV7BsvnbFR7ROy61VN/t720Sh30VtkJ/iar2M65
         EHFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=k1Ti9WI7kQjXH/LtbtJpqTp8bomGV2aI21uzEA+/hgk=;
        b=dnPJgskCi82yE0n/rMbfAfXodxQKTfDERLZa8O2EUpSz/0Dyy/noFk3VL0S0lGMMVF
         dRKZUvx/XlwlKj/hmAVEMoIUUG0y5eMCYZnXcTBzC+IWs3wbpowL3Tn4I3eYhIZPzapu
         X1HV1zszVrwavloJ9UbET657Gu+AhutYWVNyyPDVnUMHTxX4vOT56DM1rg6tFm+p6DJ5
         5M8Z66UpZJDChHU5njSNkxIZfW+rBGsx0UL8LrPoAxb3oTIm7+3HiTrk0z3gkea/Q+JB
         /bFiIA6nWEnn+1rN+mOEBMBcAlDmYZ/IJUXe/jajjajx06IU6hftvyFb+J/JvdXJY8CQ
         sh8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nykjmmr0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id n21-20020a17090695d500b006e89250c574si35454ejy.2.2022.04.13.12.28.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 13 Apr 2022 12:28:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 1/3] arm64, scs: expose irq_shadow_call_stack_ptr
Date: Wed, 13 Apr 2022 21:26:44 +0200
Message-Id: <cef39a8fe1d7783d1b6dfce5eff83c08e75577eb.1649877511.git.andreyknvl@google.com>
In-Reply-To: <cover.1649877511.git.andreyknvl@google.com>
References: <cover.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nykjmmr0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

When a hardirq happens, the Shadow Call Stack (SCS) pointer is switched
to a per-hardirq one, which is stored in irq_shadow_call_stack_ptr per-CPU.

Collecting stack traces based on SCS in hardirqs requires access to
irq_shadow_call_stack_ptr.

Expose irq_shadow_call_stack_ptr in arch/arm64/include/asm/scs.h.

For symmetry, move sdei_shadow_call_stack_normal_ptr and
sdei_shadow_call_stack_critical_ptr declarations there too.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/scs.h | 10 +++++++++-
 arch/arm64/kernel/irq.c      |  4 +---
 arch/arm64/kernel/sdei.c     |  3 ---
 3 files changed, 10 insertions(+), 7 deletions(-)

diff --git a/arch/arm64/include/asm/scs.h b/arch/arm64/include/asm/scs.h
index 8297bccf0784..9d9ac04014f1 100644
--- a/arch/arm64/include/asm/scs.h
+++ b/arch/arm64/include/asm/scs.h
@@ -24,6 +24,14 @@
 	.endm
 #endif /* CONFIG_SHADOW_CALL_STACK */
 
-#endif /* __ASSEMBLY __ */
+#else /* __ASSEMBLY__ */
+
+#include <linux/percpu.h>
+
+DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
+
+#endif /* __ASSEMBLY__ */
 
 #endif /* _ASM_SCS_H */
diff --git a/arch/arm64/kernel/irq.c b/arch/arm64/kernel/irq.c
index bda49430c9ea..9d85c82f0b1c 100644
--- a/arch/arm64/kernel/irq.c
+++ b/arch/arm64/kernel/irq.c
@@ -21,6 +21,7 @@
 #include <linux/seq_file.h>
 #include <linux/vmalloc.h>
 #include <asm/daifflags.h>
+#include <asm/scs.h>
 #include <asm/vmap_stack.h>
 
 /* Only access this in an NMI enter/exit */
@@ -28,9 +29,6 @@ DEFINE_PER_CPU(struct nmi_ctx, nmi_contexts);
 
 DEFINE_PER_CPU(unsigned long *, irq_stack_ptr);
 
-
-DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
-
 #ifdef CONFIG_SHADOW_CALL_STACK
 DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
 #endif
diff --git a/arch/arm64/kernel/sdei.c b/arch/arm64/kernel/sdei.c
index d20620a1c51a..882f88ce8d4d 100644
--- a/arch/arm64/kernel/sdei.c
+++ b/arch/arm64/kernel/sdei.c
@@ -39,9 +39,6 @@ DEFINE_PER_CPU(unsigned long *, sdei_stack_normal_ptr);
 DEFINE_PER_CPU(unsigned long *, sdei_stack_critical_ptr);
 #endif
 
-DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
-DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
-
 #ifdef CONFIG_SHADOW_CALL_STACK
 DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
 DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cef39a8fe1d7783d1b6dfce5eff83c08e75577eb.1649877511.git.andreyknvl%40google.com.
