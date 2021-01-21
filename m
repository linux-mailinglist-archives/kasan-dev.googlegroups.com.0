Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBX64U2AAMGQEKM4E3AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DCE82FF094
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:40:00 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id l10sf2735610ybt.6
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:40:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247199; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ri02e5kQ/HkIZCUKWSZn+AgLfcbcxxMvPJqkgeub8ioiqrEUOj76qUQRz1P6OiMZ/u
         74XMvPEaHMjZlssyzlYb8YCeTmAT71AN3uxMxK4P0V7JOtx8ZiXcueOUduuTifqnM1+J
         dhp8FUp4z6BMh1XBGlXe8d2GsRqg4Xwp1UDwGhQskYf9YIb9Q3w5cNQnrqIBSxPMNsgS
         bVHYhS85JSQegqE6UKs+9rKAIyWTRp/W5j85bsbldtS17YBVfxTyzbXh2MQgFzAcZB4E
         9w1mETRjeYeMRKopza9RnltZQBo7d/6VR2Hkz/rTO2IkJRU8wRLHD1SB37/327JsHb3E
         97Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TTmuUfZLn4nNrmJLa7vBEOe8b9RHoCXe2ezkfQjT8YU=;
        b=lJXhVFww2SYVWTEerN//XE18r0zIxZgdJ2Va/oRnppLb188JFrtLIy2FN4EZxnOtJN
         IqQ7yOP0fMtynO90YYfNicDaB/hTkpuVyatK5g4oBoSjx7GKIgQV97ABxU854z9VTAgw
         PVeQqGw3Kz1fbGYzA+Iq+n/BenTK91Rcy/+r9tSE+RbCi1R6RYlWPvRGFSHpvfPJ3/yR
         kyP8VvS6XgLd6s+2af/qMjDHMO/nr8JIu+UAAyf0bdtMNx4tuTAcuf8OZQayhWoFFUlD
         850nn+aChdigSvynocnn6oky9mOcGqzdfOQWle4QAB39DHdtdRbz/CZ/1zySvmR+WwgR
         G7Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TTmuUfZLn4nNrmJLa7vBEOe8b9RHoCXe2ezkfQjT8YU=;
        b=oz67sr4IqB3djVyW5p8X3LX7eduaZsBrEgI0mr4b/RuXcsn0xYEOKDgFrltGPr7e/D
         2e8gz9WlT6r5ZqTXdvlMgPsA6jLBrdoTY4gW7EgVE4cJzXsTq/a591cLSA2rbA75NLr1
         rFFXASSNDdHm8HzDHOrNLYgmsKb86v1aDXM6JKaCESs5xLgVAFpmyRU+qJk20SI4lw1C
         nRxApbE2PfXApyo9UmvaBRJoKSpnr5KjPc/aIeAGMl7kieimgeeYxt4Ly4AbizoZrJAQ
         dWhU+dT10LCsYCSdf8q3i9wHcEHBwQDLdlG4uVlSojzhGqXC/ov+z4NGTQRRpVccTg/w
         CYaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TTmuUfZLn4nNrmJLa7vBEOe8b9RHoCXe2ezkfQjT8YU=;
        b=mKKijByGAnjrvh3oEMmbo8mwPZ5BVq0CIFIX9QN9gqVUK6aCPX51091SXFutkkuTdZ
         JHYd2dtoNjz4tqMrTFigeVELnjQdgZX3oGVhWpohERwNW1KMBJaSXJhx5HmiLKmIojer
         MtDImskgHrGH3STMI91UbYm7fd1LxWPEucJig9DIhbjMt8yzlQ4VTMGo7WuZvGd41eqK
         ldgOKsv/T3gO5aiIUBkv1fbtUoN8/UtFnbYHydJD0ijVafF5z3uYf1Q6mX2r6ZRU8i/d
         GRTsf1dipB/lY2lBB/BJ55icQcZn3923Zf1m167RlKE90LIV9EJUzZfM7ECS5oWAVTRX
         eHEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JofT0oJCU1eybjedI+Q4ZrkS8CcOM6tmIo6D83fUhKPqzIi1Y
	UbDsQZn8Iv3qJJPsq5mnkno=
X-Google-Smtp-Source: ABdhPJzA+9uadLZZ/4+gKdipMMK0JqUHmCKlegHTY7aAdYZyXKgHlph4R4g10GputGTjybUJYdIxDA==
X-Received: by 2002:a25:afce:: with SMTP id d14mr115663ybj.457.1611247199433;
        Thu, 21 Jan 2021 08:39:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:515:: with SMTP id 21ls1225727ybf.9.gmail; Thu, 21 Jan
 2021 08:39:58 -0800 (PST)
X-Received: by 2002:a25:4f8b:: with SMTP id d133mr176714ybb.402.1611247198882;
        Thu, 21 Jan 2021 08:39:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247198; cv=none;
        d=google.com; s=arc-20160816;
        b=PjE0VnyRTLRw1C7p/IXseYXLufMM4Vt0FMukNw1Awg1Z/9wmgKo073tU9J1eZhUzIT
         zqhPzFXZ+bDHEv/1Zo8K9ZqhuFcN7WvXqhTBwZxtoQnvzuodiWMp1N2J0UU4NrFY4c3s
         7B8/rjY1bnMkBhlWea7lWn18CMpeADsyJTl9zCeBTdFHZq2D79Q38XOrYaZV2pp+8tLJ
         2INtZzAc7ZULtlnQJZp7Iq6JO1J6jBK+GR+7b8FEudnopZ1bs4p0UbfSyyySRJY/oGEp
         WbHbjwK065L+uyF6j4Sd3D1sDAGaU7Rd8Ji9JmzU8+6BZtXWbYCE2F/BRLeSxYlp1kQ3
         DgKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=g6sK+9WykpztLrp6+wcTYcfsEkw9vO5C+Yjj3wiaDNA=;
        b=0ILgcQcNTJhnlCCa8Qx5iOF6bEV1VPZ8kocnphv8NQXcNU7Mu/NZAIXHCxEtz6vFVU
         IImct4orz3+sy7YMwQ82YVMxcuBF4Lm/VOXFBSTz2kq5P9fV+N8tHLuUfqjuR0yU7OTc
         SSe8BxLL1ewggkTWlHb/9yDyHphz1qPrn2OtgjxUnytzH8oozNxxzJBdU4lmxnWNheL/
         0z6KXVWg/ovSM1tm8fP3icWBn3HBk3C5tt1B6Np5PX7yPKdC6LXCrng7bi9kKWMrE1QI
         hoy00H/jLWVIaZ4tBpbmIhuvVUejaLeLhSqbTJwXhmgyVB8QLRs34HJGecq0+YMQRHxF
         Ng5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x13si737533ybk.3.2021.01.21.08.39.58
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:39:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6EA141509;
	Thu, 21 Jan 2021 08:39:58 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C2B203F68F;
	Thu, 21 Jan 2021 08:39:56 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v5 3/6] kasan: Add report for async mode
Date: Thu, 21 Jan 2021 16:39:40 +0000
Message-Id: <20210121163943.9889-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121163943.9889-1-vincenzo.frascino@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  2 ++
 mm/kasan/report.c     | 11 +++++++++++
 2 files changed, 13 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..b0a1d9dfa85c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+void kasan_report_async(void);
+
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 234f35a84f19..2fd6845a95e9 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -358,6 +358,17 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags);
 }
 
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	dump_stack();
+	end_report(&flags);
+}
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-4-vincenzo.frascino%40arm.com.
