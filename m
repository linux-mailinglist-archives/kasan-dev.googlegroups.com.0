Return-Path: <kasan-dev+bncBCMIFTP47IJBBPPC6G2QMGQE3SN5T3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6D91951721
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:30 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id a1e0cc1a2514c-842f14321ebsf76648241.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625789; cv=pass;
        d=google.com; s=arc-20160816;
        b=HMqf3ijndbD6LeTXddU3XpnQpsc0p+CqrQks9Kb6gvx76/TL53i0zlP/0bvAIcDTGu
         ORGvX1vmLYhltOrHm3Qyk6UmmsQdVfGcre631aV38mickHcEqu5lT2qNTJO6TEwR8cuy
         T4yYPGEbEhzXkZTE7GhAm4QtaQlsP2TvhR2jUXia6LV+LrIwNoazfd5tt9dyVyk8gqLt
         659vU3RfFGIoyT0x4T3Qo7gujDPgMVyJMxuPAPeHSIejs/Uqpr0obRn/B5fLFqEsBKO3
         A/1lZSyoQpasz2Uwo5gkUzhQwjgIhl+4rCNfZDS2jCoVlpBzL8SwUbGcEf0ZV2kl4DHI
         v9qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=L6ltyb5a4OXS/qFOxxrtdG3P6Wm6qxkUlMBNVmW4134=;
        fh=tB1ZB7+azGaE2zkTPPkOSLwVkhHcu4TwThAxK7O4nHk=;
        b=IpITimG7hbFTpOxENHO5wNEBm4WeSt8MNf1ZZkBwssY47wPcYvDZk2Xf3G8yVdpOy5
         T/2QSfaTJzZJRaIf201DUZW0b4H5E9Wt57a97Ik5/aCcKzrZnXxVMdBkcXa3sxo+k1FZ
         UTedDWi2I90iay62MRgzeTWqZHZRfBusgxsMcMxsBqWbF2wpBI2KSonE1y/2o5JpFS2N
         TjVuQmv5hHo7t9po1m6e1Dg25vUq442GbgueD4+QcsC2FyUprqBFw+KQBPjD6hUJcqA3
         1Xihxv1VAHCB6/bt7NDwuWYVXj+nmLBioMvU6YC0/n5RHUoZUBnKjBh0w5BiOwoxKlSK
         0TCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=QAwSG5Qo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625789; x=1724230589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=L6ltyb5a4OXS/qFOxxrtdG3P6Wm6qxkUlMBNVmW4134=;
        b=XdtSa995uqsjMY7m4RYZGZzbvohKNokJlHxXMHdwYRup8q1CY9vJZELXKxhu+4wk0O
         a02DFZHywhC+zBu0ZuGKnW9c1j7pciO30uKYXzigd4dcK7Qo764Qxt0BmaI/9b4BJ4G8
         NGaUfDSyh6s2VFvoBa9k99GedXzwAZu1EFmdn4snU6Jg8r0xJAPpENLp7+0RP/gpn1l1
         63OGFSnx1QT0hKp7IoWLr2QnxRwKTKqn2X34JFYUTW3omNep/QJiWRyzFjCKNJMz1E7G
         VLIC+X6fEseYNqHuHVb6vo00kAsnR+yysk5r9lZNIjHspFNSXEU95ndXOEQUY0IiaLhg
         TIwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625789; x=1724230589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L6ltyb5a4OXS/qFOxxrtdG3P6Wm6qxkUlMBNVmW4134=;
        b=I4WLlQrn+rjMo5W/nXy18ezDxnu5OOVs0zSMXdA0gVRDGNpT7bjuUjknvMA28VDEhb
         A0tJ11Er+y1GX6GSiKJHc7jgdK7LUqlb7SyDViVc5AlN8doLkpmLeWOUzLcKyRX5EUUF
         oKkoRbfpR58xrl9UQVWjyfsM4zeRJe972Wuqi4bJutA4eneGmIvaWSZ9dS4Z2KV2J3W/
         JCGEnHlFXsX/PjKAuok/SLU6Vb5ZrDybem6t6LVne1DliHjq/QWCcDnS6cZJxqUeKMkG
         9XIVMGgwWTpPSaCT8RO4bi4mJvnD1ZH6DJNCoM6zEJNxiHbPKTf9GaK1IIKSKIcrPqnd
         l01w==
X-Forwarded-Encrypted: i=2; AJvYcCWxq3Cb84ZRZuRowaBCi534oY7vQUxFywA5RaCAToROhA1Smj7Ok6RvZNuyUb1NIUgCzLxdbK4Djs7nlAfm7nYAkkQyVGL09A==
X-Gm-Message-State: AOJu0YxDZQjf1Vr9JjyGJTke9fi7eNUNosfOjHUhIjuiyjdOspJ0LcCk
	heCwq0MfqnnB9LM+D8YYwGbfKnQrfkMF18nd05x40hzUwGnA4rGA
X-Google-Smtp-Source: AGHT+IFgH3y4TW3KZxGftoFBf3c+wv2KXHXAy9aoZoBcvlwflslHkde+Iue/aG1gUU+4tIBrP2IVLw==
X-Received: by 2002:a05:6102:3709:b0:493:afc8:17e2 with SMTP id ada2fe7eead31-49759922275mr3007118137.17.1723625789193;
        Wed, 14 Aug 2024 01:56:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ef8d:0:b0:6bf:60fd:c203 with SMTP id 6a1803df08f44-6bf60fdc4f0ls1840216d6.1.-pod-prod-05-us;
 Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/BTngPoAs4GMIspPEvw2Bv3/bRmM6DiUDFveD5Vt87KvzWj+i5qH3V1h4YG1BKtmQ8IxweoxBTd0JI6FzN3H+Y9ZPI+RXXQrYIQ==
X-Received: by 2002:a05:6214:4698:b0:6b4:fbf8:d652 with SMTP id 6a1803df08f44-6bf5d1642b7mr28071476d6.1.1723625788587;
        Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625788; cv=none;
        d=google.com; s=arc-20160816;
        b=SOsdHsDy1CXYh0INXE0mBqVUS07DP96akobpGnUoUJO1GXuZ/xPzS7r1QtFw0YY0WX
         N4LHd3Jsr6LvsFYX5H7zF+HvTS0rTUG+5aMF1VUP+NFmegfwoweDZsQWe8JXvJ4Ydcn5
         KM4Qur5bwb2y+p/ICau02FPNE5Qcoy7IULNVR+UEpARvGxzr/wZj9irJpHdYTa7WLvxS
         A+qH+pkDM+FstvavapwkWyrZ0SYZ/KAWaKFcR01ydLL6i3wi/vYwpubXRxSJqvzscQob
         NA1BvQe+nbbMb6Q6DKlixGRPuGFd03+kugvHV88DBTKqPy7m7h2GeHG/x12pqLH1q+rB
         nTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q+LcB4MC6Qgfr9kzwjEWl/9KLwOZpaXC6CA7cxVGJTI=;
        fh=I+W7OAQaLu2rxGDywjeEV0cb0NDObZUjRogvUQ9v2Po=;
        b=1EfDqmXojm2ylx24A9kAFkKsapUWGwka4SGdxr55ZXdyiMovdrMYwdAOBAjZbD0zWn
         RPm7I7SQyr11p73dEfgEZ9Wek8WSsaWGNW4DUHmGfRt0tJsIRN88RC12TtzI2ZAcAD6n
         lJftulIHjKA1bod7CSx/vffHyZ+xFzATDt0Vd/3Wgz91PeJxzSUJgSIWTSlvhCOUiull
         2jg9Dava61ihriQ+ohCpMZXwUhREj4xaFnjRTlLqL4dWD3avjMeLcI/YBJtkGiXeWfeL
         z6xrMN4TZIV2gsT7BFQW7j0Oz6HNalC1FjsGKkcw0rUW4fNVOYvuVFZJYCwFaxh4QRsL
         tjcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=QAwSG5Qo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bd82f83ee9si3682546d6.7.2024.08.14.01.56.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-76cb5b6b3e4so4216007a12.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXABB17u0gMuB4RlcdBNci8Q65tPeFUg9ddgpzmDCOEH0qlWxykjjc6d/Ji7LsK3Mjfw+qoY4vdPNK3OeIxoWfxxAxSpPrdmGiVQQ==
X-Received: by 2002:a05:6a20:c88b:b0:1c4:c879:b770 with SMTP id adf61e73a8af0-1c8eae8dd79mr2680167637.23.1723625787615;
        Wed, 14 Aug 2024 01:56:27 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:27 -0700 (PDT)
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
Subject: [RFC PATCH 4/7] riscv: Do not rely on KASAN to define the memory layout
Date: Wed, 14 Aug 2024 01:55:32 -0700
Message-ID: <20240814085618.968833-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=QAwSG5Qo;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Commit 66673099f734 ("riscv: mm: Pre-allocate vmemmap/direct map/kasan
PGD entries") used the start of the KASAN shadow memory region to
represent the end of the linear map, since the two memory regions were
immediately adjacent. This is no longer the case for Sv39; commit
5c8405d763dc ("riscv: Extend sv39 linear mapping max size to 128G")
introduced a 4 GiB hole between the regions. Introducing KASAN_SW_TAGS
will cut the size of the shadow memory region in half, creating an even
larger hole.

Avoid wasting PGD entries on this hole by using the size of the linear
map (KERN_VIRT_SIZE) to compute PAGE_END.

Since KASAN_SHADOW_START/KASAN_SHADOW_END are used inside an IS_ENABLED
block, it's not possible to completely hide the constants when KASAN is
disabled, so provide dummy definitions for that case.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/kasan.h | 11 +++++++++--
 arch/riscv/mm/init.c           |  2 +-
 2 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index e6a0071bdb56..a4e92ce9fa31 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -6,6 +6,8 @@
 
 #ifndef __ASSEMBLY__
 
+#ifdef CONFIG_KASAN
+
 /*
  * The following comment was copied from arm64:
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,13 +35,18 @@
 #define KASAN_SHADOW_START	((KASAN_SHADOW_END - KASAN_SHADOW_SIZE) & PGDIR_MASK)
 #define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
 
-#ifdef CONFIG_KASAN
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
 void kasan_swapper_init(void);
 
-#endif
+#else /* CONFIG_KASAN */
+
+#define KASAN_SHADOW_START	MODULES_LOWEST_VADDR
+#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
+
+#endif /* CONFIG_KASAN */
+
 #endif
 #endif /* __ASM_KASAN_H */
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 8b698d9609e7..1667f1b05f5a 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -1492,7 +1492,7 @@ static void __init preallocate_pgd_pages_range(unsigned long start, unsigned lon
 	panic("Failed to pre-allocate %s pages for %s area\n", lvl, area);
 }
 
-#define PAGE_END KASAN_SHADOW_START
+#define PAGE_END (PAGE_OFFSET + KERN_VIRT_SIZE)
 
 void __init pgtable_cache_init(void)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-5-samuel.holland%40sifive.com.
