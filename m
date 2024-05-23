Return-Path: <kasan-dev+bncBCDO7L6ERQDRBPPUX2ZAMGQEEHUZFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FB7A8CDC57
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2024 23:50:54 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-42024ca9500sf338945e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2024 14:50:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716501053; cv=pass;
        d=google.com; s=arc-20160816;
        b=ztES9k7iGAUQT0GL4Hbr5vkHl+eBI3M+WEegyP+UHW14unQzN0Nej8DEwkBu4oGUX3
         41MdlM2jZs8P/19tQB/6JD3oLZQb5jJnUFr2oEAbHTpYLrCWWBiDpa4xh8yZB2vXM9g0
         PhTAlrsb/Kl/m7rm6ELwDhbaTZcKpSaTlIyTJ/PjHKs0pNiWkOgoHtLLvf3zQbZvejur
         Hco9P1QtnnxbCABzj+AWjahVahabY4J65fLv8+TGvabqF7W4+z/ZFoifYV1lKXOzfgI9
         DyhQid/JLvilLHkdPbXEfbG6aMFE247WK8VNqbTHEZxC8UFcfFq7p09WT6ECuMRZvVap
         Lxtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=dQka9ltoAEG7Fo4oK13tkuQOLPUTeJDTxPxQiX5uGFc=;
        fh=6DEmV5dVCHfaTseWU+GM+WzvlembMFdvU1TPWJvqbiM=;
        b=iw/40vq99oTdndQbmBlzZs22M/XFDzTTMJfYU5V9lAUjrE23E9GxeEWW8JdLPYm1s8
         4JO6Rzyj/iJlWphWh1juReiX7wfKu2A7ajvU0VFFUpzE1NcFvM6ZseY9ThlSFGdlvgvG
         7fLz99MznNL3wi5Sv71zkqMArZVCX4FD/D03vWoSE6gGhMp6tvv2t5cXACu0qx4sgKMK
         t5rRnAUPxqEj4LWBtBYgESKW1LK7QEyw0vSaFyDmtBAmNd44dlmiHtCkoZx2AfarsLED
         QdbHWSDQ45eM2E3NCk5Iu9/qVjozSaBCyuTRwYrGQC7lfiv2pNUciK2B0jkEkXgDLIGI
         /i8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AGMKb87H;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716501053; x=1717105853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dQka9ltoAEG7Fo4oK13tkuQOLPUTeJDTxPxQiX5uGFc=;
        b=Dr45onRSaOB4FAREUySJ4m6ZHv4EKW+iVxlllZLRD3cn515Ct7wnqDD0U/2mtH4fJG
         UzbCQ8INrHs1jvbVK+lTMRPUAmCMmLZmPDv8aCQXvHazIpq5zkN4uKsMEaR6ZEez69Q0
         BIZqo4fDZAnJg7x4pv5dwJuvh+DBg0W72RMS7YzXCLTclCEupftD/rlvMeQ0OR+Y5iwZ
         0q4KYm4tktP8Eqyu4Hu/WlfA7654kBU8MPCyysu04RRoR2mGfSXXy0G92PYfEKt1KMoE
         Uc89qMhcrhGImP9H3+N2Uyjid9WXHcpO8Vp9yzj/paPqoBvs8IsLqLJyxm2+udf+3WO7
         lTDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716501053; x=1717105853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dQka9ltoAEG7Fo4oK13tkuQOLPUTeJDTxPxQiX5uGFc=;
        b=FjJKwUShzWT/V+vD2fBqZqpCK/EUn9xv+OTePBo708j4VNskp3E3cwHCT9gDWbWtNL
         GCpBLD2DiJ5aGJ/ttlfJ41wGnq5T/SCQgtWGZ8G5hOI7eZbAjJ8kud3K7OcEtV4jTYrV
         julvIU2Y2bgPnRHGh7KL1vEnd3233FiKlwowOOuNVp47M/eMRgIo89gD3sCkxKw4Zabu
         YHuyxp8LXeAIFUPi88jQwuzUytTEANKHAaX1FCIOeHiXHFW+gjN1vKxaiUXIOOU7Tdtz
         gZhFNbJktfeL7dozeu9cmCDVBzC+EOfeK95/wGXJsUk6mOlKTxPVIGCEr8VZQzi/W56T
         VCFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716501053; x=1717105853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dQka9ltoAEG7Fo4oK13tkuQOLPUTeJDTxPxQiX5uGFc=;
        b=JNS5R50+ldwTDzUD91PEdkb4NLZrkliDaV8W9stlyOS1QnGjJj9Hz7wu7YBWA8Ilk3
         sVE58I3Lr1KwxtIteiwCv4GPVhQ5YCzdG4Ogba8Iozk+me4Oc2osoFZlSpXus/gsMR5u
         G1opfuGZok5CZM46EKb0PDpByczz6bUXdQrY2i2kNJHNcSgdUNjuBWas691X9O72YWHc
         J2OBj2apScg2IEZ+l8+b3XRv8JCHYiNRdbWc09GLdiB26mxzSatSTrf92gKbpUJA1OKt
         EKz+uMiAUMMHZ24seKaYPXkwMHaS/YbEmwHvJRb2LKl4d8qnQgGopWGM0lsX7t3Mx+ar
         ZsUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6mlTYFdhQrSpXwlWCEsDg3KGj25EMs/sXwB5mDU2d/BHXTZr/l1MV0jLL1nYPfuV4gEiQB+6s1DPA/cHL9axejIwuLmbfjg==
X-Gm-Message-State: AOJu0Yz/F5kXQF6y+i4Q1ZFxlPdTTKjL7gToNhKeIcrIaeh49NqvDXrl
	IE5i7EM09jo/k3AQeX3Y1SYVF+o+jPNnBRRPpZMlzAsmClMSNYBY
X-Google-Smtp-Source: AGHT+IF1pQyAZd39+t5SfR3FYXkxfH6szfHmaybXoNwaJ5HVTV66a7SM60bgsSt3J9oV1+n436Fdbg==
X-Received: by 2002:a05:600c:b93:b0:41c:ab7:f9af with SMTP id 5b1f17b1804b1-42108da9965mr164915e9.3.1716501053366;
        Thu, 23 May 2024 14:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca9:b0:418:4830:9fc0 with SMTP id
 5b1f17b1804b1-42107bbc4f9ls1674985e9.0.-pod-prod-06-eu; Thu, 23 May 2024
 14:50:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIj7VZBDnOPn1GDn+BqDhNYPzHw7tKjqF0izsHtbuhYPzrl9SDciBkRi/T+MOrsqgLaetsz1I+NzCxgmu4RXOwaMwZS1KJahavaQ==
X-Received: by 2002:a05:600c:2c2:b0:41c:8123:f8a5 with SMTP id 5b1f17b1804b1-421089dd8dcmr3302265e9.23.1716501050816;
        Thu, 23 May 2024 14:50:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716501050; cv=none;
        d=google.com; s=arc-20160816;
        b=vBV9OTIatIgrL32Jd+yhrmx7X6DQzKPITGiW0gZm/1+HIGd3QMaWB4W6l/A3xxvea7
         02EMi/tnNXXjOXgMjar0+A9l/59zxZfR2Iu05mxSPsfLeOnkmes0znULNSx2o6q5Sf7Y
         MvnCQq4H/dcQDqw0VLoOcychiWP6XtPt0ZmMcqb8Ff3X9eg1WleB56vBoabz7ESGzTg2
         gAf7UZRSMI+g2ROeRg0LF0U8TRA+e1wEfFOfF6el0HtEtXYbjXTfure5T4Dv8U3LsKKm
         zBkat7iQ9kzSi/YznQjIWJPO9gDfFCyoa81GW6xIfBs9gfIrm3clko2Yir9KyeREIel2
         BNNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=cL3CjB9yMkr+C9cTAGf3ev6sBpUayp6G2aVmnb0yyJM=;
        fh=fnF/FZgr2L5DQbqeHjLZccn21KnO8SfTQ0El4t+PCqU=;
        b=dVmbEql+jVYfMqVzJQzsFkdDRosSKTUI2aJCGMaPI5st4vQsmUACzf7wP5GLlfRdE5
         ds+Kb+yrZMfTbSmvKP+FConx0E+39YdMYXU4yn0inkgO1azSadUpvr4s5woGlZhLK5Ck
         KO/dJzA+0I0ht/VlODvn7vlaWrLldbZhS6ged3N4m7JDtgkR7ZVhJFE3qLAf2SNJ7i0K
         I8Azndp7ADSITazWcwBm8IxL69BLZRLAQAF8kCW9F1/lmWvSF23Xt/kyCHykTzk98Xpv
         OXI9c7N2T2XTPran2vOHhZt9Yk/28Pr2ZU9Xhu6BPaL9uoRP9euWZWlWh3eCuLKGJdNg
         zqOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AGMKb87H;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-420fc82c541si1266805e9.0.2024.05.23.14.50.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 May 2024 14:50:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id a640c23a62f3a-a5a89787ea4so1080215166b.2
        for <kasan-dev@googlegroups.com>; Thu, 23 May 2024 14:50:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVE0HXvFEOZ/XfnRBYBaOcDWzq2ljCaH/2JzUf8SNx8+T5vjIiDRTOloFIp6BkLvactMz4TX2tBHeCxerqIb1f5wYfj6jqYC6vR8A==
X-Received: by 2002:a17:906:a252:b0:a58:eba0:6716 with SMTP id a640c23a62f3a-a6265128466mr23580566b.60.1716501049956;
        Thu, 23 May 2024 14:50:49 -0700 (PDT)
Received: from rex.hwlab.vusec.net (lab-4.lab.cs.vu.nl. [192.33.36.4])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a626cda9248sm14971066b.225.2024.05.23.14.50.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 May 2024 14:50:49 -0700 (PDT)
From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
To: Brian Johannesmeyer <bjohannesmeyer@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H . Peter Anvin" <hpa@zytor.com>
Subject: [PATCH] x86: kmsan: Fix hook for unaligned accesses
Date: Thu, 23 May 2024 23:50:29 +0200
Message-Id: <20240523215029.4160518-1-bjohannesmeyer@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: bjohannesmeyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AGMKb87H;       spf=pass
 (google.com: domain of bjohannesmeyer@gmail.com designates
 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

When called with a 'from' that is not 4-byte-aligned,
string_memcpy_fromio() calls the movs() macro to copy the first few bytes,
so that 'from' becomes 4-byte-aligned before calling rep_movs(). This
movs() macro modifies 'to', and the subsequent line modifies 'n'.

As a result, on unaligned accesses, kmsan_unpoison_memory() uses the
updated (aligned) values of 'to' and 'n'. Hence, it does not unpoison the
entire region.

This patch saves the original values of 'to' and 'n', and passes those to
kmsan_unpoison_memory(), so that the entire region is unpoisoned.

Signed-off-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
---
 arch/x86/lib/iomem.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/x86/lib/iomem.c b/arch/x86/lib/iomem.c
index e0411a3774d4..5eecb45d05d5 100644
--- a/arch/x86/lib/iomem.c
+++ b/arch/x86/lib/iomem.c
@@ -25,6 +25,9 @@ static __always_inline void rep_movs(void *to, const void *from, size_t n)
 
 static void string_memcpy_fromio(void *to, const volatile void __iomem *from, size_t n)
 {
+	const void *orig_to = to;
+	const size_t orig_n = n;
+
 	if (unlikely(!n))
 		return;
 
@@ -39,7 +42,7 @@ static void string_memcpy_fromio(void *to, const volatile void __iomem *from, si
 	}
 	rep_movs(to, (const void *)from, n);
 	/* KMSAN must treat values read from devices as initialized. */
-	kmsan_unpoison_memory(to, n);
+	kmsan_unpoison_memory(orig_to, orig_n);
 }
 
 static void string_memcpy_toio(volatile void __iomem *to, const void *from, size_t n)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240523215029.4160518-1-bjohannesmeyer%40gmail.com.
