Return-Path: <kasan-dev+bncBCMIFTP47IJBBOXC6G2QMGQECURVVTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 257EF95171F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:28 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5c65e857b43sf6393156eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625787; cv=pass;
        d=google.com; s=arc-20160816;
        b=w7zS22emkS1/vm3YNVnrg9IiaVY1S5ahHoY5yQELc3WNtocvuHCszpJ0uVvWL/DFb+
         wJyT1f6SAw/Ii9+yVdJ5RG/LWHzn/KcvzExQKWP98+Wqn7y82VeYkKqyFbW9HF0/Q8hJ
         2pNe9zgqVcoBIUrntouslk/VRxPbr968uyrvD9dpNhUGQkGax3dqVXIrgSnpgKwuaHAE
         mNEbwlqF/1LBX27pmzzADIx+tUhIbp30Vzxz9oqHJoHOTDuXU4tXNIQUatu5mlw4knbA
         GTQXASl+bQmZdzb+apBuNVrNnj4wPDij1zuxL0vXyg3wKM4aC4OZgZ5SLJfvjuotPkl2
         paZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UMa1DMGHbtu+RzrGzEsi915DoIKxgLJhy05sa6sSkQI=;
        fh=/vTFgUs7P1JEzTpI/OhYhKRnL0+RoHqGcDM89csAhBw=;
        b=TADYKwT3ELCT/DGVekyyn7HwmcdOGdjquO7JRx2MLRZo4YAPyhrJHx2vUo4b0WFU+5
         Plf+TJX9cJqHfzX5UxvpwUqWF7/3KTzlrfw+V68L2WvrusXpLGQs4AawAo4w8j1BKuPU
         Kphf1TYZmimjVr3lKT7THy6ZLiFGyUW+JDl+dQzeL+LphH+ExCdDKhjYQYo16dd03jq7
         LV+A8gtzFqDn/5RxGZnuu42Cd02r8jvZBbK6NKhNLQtagxdqJDld4DnQbPe0cvB8Q9RE
         NNukWf4IqXlENOl0VDkUp0oXNa//PYFQ+/0YZw8nBQtqsX1dlwZkT0weu9EbHI95G/cF
         h4dQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=eRimazG5;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625787; x=1724230587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UMa1DMGHbtu+RzrGzEsi915DoIKxgLJhy05sa6sSkQI=;
        b=K3F2Kj2SaidOo6dJKrvFDd+597QMKgnUleksanLKlwMIkV6jKJJBtRv9Y9/o/ujiQB
         hg0ix+MDY7fF6uXTqK/n+wFDNZwn9G5JyOVnN1g4nqnosIsfyQ6hH5PjpEnLkmY6YbJb
         x2w9dbXol6pZkcv7cbY3S/ZtfLiGQSDOaoYeM/kBtXzXGKL1dfNiMa9Iis9EcRg3AZ3I
         r6QkuKurDwl9VfsYF/AhIB2OPatwv9ycMfY+F3mvGwm0Ylc92/aCTSenLALQcfGJzbQ9
         QIxnF/SpuSO9rcRhn8AOz/v3EqIeO1P0p3lnM5mxjLjoaH8JwT0OhuFIF3BLxmSab2dc
         dn9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625787; x=1724230587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UMa1DMGHbtu+RzrGzEsi915DoIKxgLJhy05sa6sSkQI=;
        b=ZvfgHLt53h4LZrVQgZlLjOHDy14IHIP4lrHNQxl/R3LBSk1dqvmO4fOjPSY/Z7jIts
         loGdrZHAZwxSz5x0Y6pvt4gxDmAIV228tLmlXXgoa0skPV+U73wIcQNOx0uHuSje7QCu
         D+2b9BWCnZaD6t12J9HuoYgFa7G16hVTcTXsgMNnEjjcd8NH9MUccD2FOSrD6zsAjnjd
         zDTFcUJv/HOep2nJlcNTvAekRKPnOGiDJSyl9clCg1zyjhwnurSFTmJxPpLspLJnGu7t
         RItACtzm46LuASw/nYqSfTw8NJP7n5w/idJ+XkaapSaxQRXA74wVjt16LrTYArsm9yiX
         OhUA==
X-Forwarded-Encrypted: i=2; AJvYcCUXQJ3eAE1Oc2zdcmIhxEmbqip3d799C8aco1ugc7ks2evBJkSxe/I+fPvNvec94Z3K7ZgyawCHBGdsfhgEUK/mu2kkaSJf1w==
X-Gm-Message-State: AOJu0YySnL6jlW9Mc+sVl7kdCBPYvFyQpJA2k1DFiwXQ4vUVXTYHbLRJ
	aTTxyLW+ggUPlx4iazK4Oqu21n4KnIwGItTk7mneVq+cNQppfPXl
X-Google-Smtp-Source: AGHT+IHqAxMat+nf6b2FMUYg8K9KImqn13aepQtVqKTScW0YKVKccaYq6b9by6VD88GTHA3bD9vkwg==
X-Received: by 2002:a05:6820:168a:b0:5c4:27f0:ae with SMTP id 006d021491bc7-5da7c5cc4edmr2589394eaf.1.1723625786922;
        Wed, 14 Aug 2024 01:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:db97:0:b0:5c4:4ad9:156c with SMTP id 006d021491bc7-5d851052dd4ls2554721eaf.0.-pod-prod-05-us;
 Wed, 14 Aug 2024 01:56:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxQNpMU7Ei8ZYWCR5NILT67l9+A6H4oPAI//t7D7g1uk7YcKLe981dvN4Q9L4yI6Dy4GRwSA0ifOUOzB9fUd5tWgu3cPvb6wSdNg==
X-Received: by 2002:a05:6808:ecf:b0:3d9:2e2e:1ace with SMTP id 5614622812f47-3dd2997340amr2114677b6e.42.1723625786156;
        Wed, 14 Aug 2024 01:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625786; cv=none;
        d=google.com; s=arc-20160816;
        b=wPWPADR/TC7jH7ErTT3MGZTmBkSpyDse6ieFmHe/EZdFenr3YcKw+s3/r0qCBx2txs
         fDsQboh6z7RvDPx+okJBkL3jlB3xcKjSkdm47oUKdV5AEAMfXPhLjfYvK5f5ydWZt6mX
         ji39ByATt4M6YwVlkIA4LRq1DXXKyj002uKrOX+Rkr/320WPCzoXA55fZzTkhbv27mOs
         cUtlv19R80AB3Idx7Idq5/AB8e7GA4hTOE9/guRieO1g5Wfdzh3av+bFP5O3BgfJV62r
         KWWParkix4SljPnxMHftIbt99Yf1i0K/7KNf7Gx86EU0FWLO+X1SW8GDTvZLGjH8Ikwo
         /jbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Kr1OlloTvp35mKilBnuEZzypgigPXmCly4KSd56Q7OI=;
        fh=HXC+oInG5rCKIKLEGmKpWFwKvDUjTZQLCMo5Ngk9S0U=;
        b=OqwtYUVQa0XxJMvGNiW1sj1Rqy/pGC8N1TK5qp3ebUkEH5Ww5XSUYHzsSfcAoU/p1X
         cq1OgeI0zRGwvBzfvPG72gY47rkXX28oxCusoiq6k57j92LDJqDysTzEYVDuSTxLtRuv
         DEMjmVZ4KLfDUug9EMfJWZCJudgWEa2nzI7O+MbVV4cFq3+GpMjb+LQLxCGyUh9RZII1
         z3+vxh7PIXDabdMLT9jhkuMde6AxiZZt1iZygfXL5Az2hhXDNH+W+TJRL7Rqrs+3atcC
         FjNKg2EvndcEHgQ4ic9wGW3iosQM0oB6NohGS3T1ht/ku4xyHIEv2XRXL0jkwFJA64A2
         0Zuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=eRimazG5;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7c6979d4ab8si167542a12.1.2024.08.14.01.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1ff4fa918afso37469545ad.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvOu6kFsCAMDiP6RPOyRm68e4yDYL/XcnEJD7i9OSTO0OqbOSO4jvpbK1Q797rFR1NrvxqgawwlL9tL/7b/sCgKaUa6FrvnoPyuA==
X-Received: by 2002:a17:903:360d:b0:1ff:49a0:46b1 with SMTP id d9443c01a7336-201d6397db6mr25518915ad.6.1723625785721;
        Wed, 14 Aug 2024 01:56:25 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:25 -0700 (PDT)
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
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 3/7] kasan: sw_tags: Support tag widths less than 8 bits
Date: Wed, 14 Aug 2024 01:55:31 -0700
Message-ID: <20240814085618.968833-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=eRimazG5;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
pointer tags. For consistency, move the arm64 MTE definition of
KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
RISC-V's equivalent extension is expected to support 7-bit hardware
memory tags.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/arm64/include/asm/kasan.h   |  6 ++++--
 arch/arm64/include/asm/uaccess.h |  1 +
 include/linux/kasan-tags.h       | 13 ++++++++-----
 3 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index e1b57c13f8a4..4ab419df8b93 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,10 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
+#endif
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 28f665e0975a..56a09f412272 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index 4f85f562512c..e07c896f95d3 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,16 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#include <asm/kasan.h>
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-4-samuel.holland%40sifive.com.
