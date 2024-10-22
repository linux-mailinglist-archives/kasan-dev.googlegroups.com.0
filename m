Return-Path: <kasan-dev+bncBCMIFTP47IJBB7UN3S4AMGQERCIXI7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id A307E9A95CD
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:27 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7b1492b01b0sf832404785a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562366; cv=pass;
        d=google.com; s=arc-20240605;
        b=kTaV3a/fK8jd3NHAnBbAjp1orukRTwsR8CIPSVh4l3FU+jUQ/XMWlywN1XhBjD+lMd
         gZAP7kDbsXm5wul8izZviBELl8uyP16bzbypfr5mLyqFToiIOrk9CMCNZn3xDzS8DQkU
         MZcCLpPLqCmY9bGXsQ9Y7nhu7AkwQB3xORAzTbXcW+MntF/k0XKTdWxLY64oeA/i/Xy6
         PXYDLKMwPQH0KLNUCM7BQMZe9nGupqNxrQvWewStVKv7xxeqNpjnaE3lMdTDRAfaZ+X4
         AmCdoveVvr5MYmK9Keo5fq7W/nQAI2Kpl0R3fAxDm/FhM3Vt01VcnAiofC5Aqhp+AybE
         51qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0hfWlHau8ibx898YWhhFI+EEYFHvtxJFpB7mq5gY/Lo=;
        fh=Ghdw1fffvtKhIXfNTPK/QrSaW8x5Q38eM9tfahHB/hY=;
        b=CCwKbSLOplai9JTOuYZT9JgnjqauIVWpGkZFQvrD4Hcof20d7f4mA1Hcj343JmF47N
         Ljz0iEqaVwUFgHx4RF1da2j+xmRTW1GrRgjO7e2KZ07jfne9hL9nhS7DNWQYWZVl8T+F
         qY8Xph/9WxEUK4q6XtOdEZP78k3zpf/iwk1JZ1uKAu6aYGWEg3AwjH8I0lmnDfatcgDN
         8dfClczvgUHWy5nMzL3O4m2R0Aly18GLIbuajOE4TQg5FvTttgGUYsAsTFglJzhMXGM5
         4tDMct3vxN8ARfnSG0Fxr3Z+b+QUvziG6Ko7ImGGpY130HKweLBPpBraqFtXxi4qIjRl
         NJ9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=fQaM6kCA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::34 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562366; x=1730167166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0hfWlHau8ibx898YWhhFI+EEYFHvtxJFpB7mq5gY/Lo=;
        b=osrRL0XkeHOHNyb83kiaSKBPPJBkMnNeVUW8HNZcq4k3ZlXKjc9sMEkDZkdpeVtGdV
         qPcSqMhev6GVXSkcBYPl1h+8Y9pE0tMHp7oESE01vYmvoRuoHwR1el7Vl1M9nHiW0rzb
         JShrANkvFfldxUI1o9vw5P7Gvt4WreemJQvsuTWRxXaF/TKA5SlZNdnqz0jnwyNOY/Z/
         SnGt1UYR89A8w6/P3LFC2lEvadVdcfYNRzVauwTzp9V9Ev52Wn0AbW/sndLX2SMGaJtJ
         1JN2dRtBxY0+96+c5495ZjwQj8jeA+6KL5gPYh6WKAO2w3WIbeBDCGh0NazGdLG9VSvD
         ix0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562366; x=1730167166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0hfWlHau8ibx898YWhhFI+EEYFHvtxJFpB7mq5gY/Lo=;
        b=YgJ2sMidQIJSMld54TyvAI5butX1syTHHuuaktpHh4U2450mpPJZsLBE0Fm0wJ+U9b
         ZbsZDmEnUlFNnuaRquZgREZO/IJx/qlMLowCnpI+TGSvOT0KKKYdhi3a0Gjhxo/V+AXm
         cldb3t4ckMKcUceQvglzZlztJ3kQoiG+NbPU+wkL08UYGJWLnJKUXGCMHAuLIgXaan+U
         v+4+SBvE0sCsuFzVzYSZIOYZSP/W+gyPb5DrDOw77CDBbV4Cf6Sya9UVUwu/5Fb/igQJ
         H0TW7LAh5Yw3bXYTI76+7OwA4i/Ko50a8ao4eOWdsss9XAIyKKU7WNWpBJdvGame1rHI
         ys+Q==
X-Forwarded-Encrypted: i=2; AJvYcCVPsyZaUckcEK0hYRAz3y3coQKX2pdoMmZMzEha3SgrRYzNX9P98xAmJ1Upl4A6Sv8xkmAUOA==@lfdr.de
X-Gm-Message-State: AOJu0YyrDz2yTv+Iap07I/mk7maIj6Y/wDNPApYQJ6RxXKJxZ0twvNq8
	XSPHkZYyfqC2jgEmhwzyiDWyx5tzRJ+xIYW3OXJnzsjgeuGpVd6n
X-Google-Smtp-Source: AGHT+IGben3MwykKoDrywdeyqM9AegAeRC0wfjX+j9i7HO0T4IdE9gY0LYTfsaSRYpJasiHAEoEk+Q==
X-Received: by 2002:a05:6214:449e:b0:6cb:f077:f2f4 with SMTP id 6a1803df08f44-6ce23da39c6mr11440266d6.17.1729562366412;
        Mon, 21 Oct 2024 18:59:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c6d:b0:6cb:fae8:5fdc with SMTP id
 6a1803df08f44-6cc3734d473ls52508586d6.1.-pod-prod-03-us; Mon, 21 Oct 2024
 18:59:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXs/LLsSRxc8WiMPBImrvB4t8C/cdrJNIS+w9/1mth4RG+TyYmB4E81I7TFUQDHeKO2M4Pn2H29N4M=@googlegroups.com
X-Received: by 2002:a05:6102:26d1:b0:4a3:ccaf:203 with SMTP id ada2fe7eead31-4a742d0e736mr1287049137.5.1729562365793;
        Mon, 21 Oct 2024 18:59:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562365; cv=none;
        d=google.com; s=arc-20240605;
        b=EYlfKnjgD2lSSpDLoZHXaO4rDFV3UkZmwNNLImwHbTCz7+A1iY77RJu4fh7ZC32AE6
         LNsZBw5/cMLEZk+Gn9SqVUZa2vCtNmonogutUD8W0zpZc+6tt5Fnj0P4XtwhURtafkO3
         fzLW0GeL9qDAP0JEIS2TU1XrudktOSjcilghCnLRtjveql0hec6PHtVfSNjC9M0xiOsp
         j5Yiy92jVqmycwYnVQ3hwXppZ60wx5/zc2BuzG1rZi9t5gLrtGIaRb6si0va96cb0pi1
         Zhgu9xyE04OaCwkb9Bm6fBEqU6FA5MJRpYlLa4bGe4BoePtUh/syquA8dm9iewPE5NUJ
         E5Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FpfVj+cCklKKT0meu9E3X+82meKkLqCR+uZsOKWdYis=;
        fh=rAkQxmDrkr2lMr6wbz/Z1CBKZtRd26rAl7DaCP8+X+0=;
        b=hH7jrF8IKo54ynvvmXVYegDd43vplOGhnKxNzIBtlkgPT7k6jnQDZxS4k8Bq1GHLy2
         czlcTQqDmkODVjjsPYkc9D5aXmOsJus8Y19VX1hAfLKz1yE6bPYjPlN6uxxzAkUYaq7M
         F7JJzHD1mFEg7QY8PY9wFw8CWHjCi8+eIYIcmuTT8U3m9y+0kB1LW4SsicAdM43d/5ky
         /w5sjUQy9SYbiC0F1BDVrVYX2sfWXk0IeZ2l/iBlzl6GR4P6UFVok/bMMCoJdusRuLxM
         jFqJVYSymp159EjTMEbcBCsyfQJpTsqgYo0ThgIEp052kEQfS48mvxKTPALSqXaY4uAx
         VXVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=fQaM6kCA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::34 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x34.google.com (mail-oa1-x34.google.com. [2001:4860:4864:20::34])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-852142fd1efsi216305241.0.2024.10.21.18.59.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::34 as permitted sender) client-ip=2001:4860:4864:20::34;
Received: by mail-oa1-x34.google.com with SMTP id 586e51a60fabf-287b8444ff3so2020161fac.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOvM6OvEa0vVj3zqTMUur+EZrjV2UiZU8hHEo+mcR28rR915EB0s+4VSRuoDNuvkgTgKRmBQJksu0=@googlegroups.com
X-Received: by 2002:a05:6870:148f:b0:27b:61df:2160 with SMTP id 586e51a60fabf-28cb010575fmr1017968fac.31.1729562365145;
        Mon, 21 Oct 2024 18:59:25 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 5/9] riscv: mm: Log potential KASAN shadow alias
Date: Mon, 21 Oct 2024 18:57:13 -0700
Message-ID: <20241022015913.3524425-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=fQaM6kCA;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2001:4860:4864:20::34 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

When KASAN is enabled, shadow memory is allocated and mapped for all
legitimate kernel addresses, but not for the entire address space. As a
result, the kernel can fault when accessing a shadow address computed
from a bogus pointer. This can be confusing, because the shadow address
computed for (e.g.) NULL looks nothing like a NULL pointer. To assist
debugging, if the faulting address might be the result of a KASAN shadow
memory address computation, report the range of original memory
addresses that would map to the faulting address.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - New patch for v2

 arch/riscv/mm/fault.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
index a9f2b4af8f3f..dae1131221b7 100644
--- a/arch/riscv/mm/fault.c
+++ b/arch/riscv/mm/fault.c
@@ -8,6 +8,7 @@
 
 
 #include <linux/mm.h>
+#include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/interrupt.h>
 #include <linux/perf_event.h>
@@ -30,6 +31,8 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n", msg,
 		addr);
 
+	kasan_non_canonical_hook(addr);
+
 	bust_spinlocks(0);
 	die(regs, "Oops");
 	make_task_dead(SIGKILL);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-6-samuel.holland%40sifive.com.
