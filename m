Return-Path: <kasan-dev+bncBDCPL7WX3MKBBGPYX7AQMGQEGZTGBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 12FDDAC1B19
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:56 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4767e6b4596sf148943701cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975195; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZlpIX/ZRMTu1AgkIhvS9cxi180gxll+Yx2jVVvJUCL08ac0OHaM4efZTisuxceKUwk
         yOEa/ohgd1jRjzsqtkxfTg9JlYJPJkBktLJL3Wrx9OelghWRkKFvJ58UvXrs0lKipSn+
         6Spt1MdRR5wTmc4qWHhZUEEH1ZhwkJ2tWbos8z6m0wZdcMaXxnTGuph3n2OUGbSHYAPE
         1s0/lO/rOIuBpRhUX2G1jGGxDI4gxVaBPUAnpN/0P6JxtLmdn5jJOimEoZu/+ay5dD1R
         I02VOvPMDk4BerKMh6AzQ8twkPvODgGV8xyfQXM9BuhTwcCIwVKqIRBvyll89BeyHxxi
         3q4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kSv5Ub0Qt397NL2Nsw9naZOpwx/Ur29rDObbp2iC0ic=;
        fh=q8k3v2qTg46DgwKjTSeuNPQGzerLFdjphS+vZu3B4LM=;
        b=U+NBZ0TyfDPE85yqVysd3UBPH+h0lopbZIvTfkq9JqDchXZpeIb4+9khJyueG3gjCc
         ov3S3HSxTaAElLTq3Uh+8wCxiSuBzKEtfxmIehwwQnQovRuJOynhLSk1jfRKKua2hBnF
         HMCUss1sd9Zs3AE5Qc5J/THp4Gnt5hMwdvxR1aoYZYgR287gLxks8V69tnr8XMBSKOuB
         3FMdeAU/cDy0J2xSIr/yaisbIMxmLTDjC2ijDw+BFum817wRjC3IpaeKTOiNfn8a+wD4
         p5+gFZyFg+SgbVrfWfYy/Fr89zrSYzEoj3aZWcJK0iSlZ3jH9A18Of+TXxHZbsb+mqXa
         m59w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HV5smsW4;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975195; x=1748579995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kSv5Ub0Qt397NL2Nsw9naZOpwx/Ur29rDObbp2iC0ic=;
        b=kun6WmvJ6IltvoY7mhPhf8defiiRjGqiAXlZE4ciwn8jYLKcLkoZSyR4pc7Tp5zLzZ
         ChQg7dYWydR0hSiKiDKhJo8MhiK+glzT3PyhA3dzYsZqihzXcPQwZWSwoBEQHI9iM6ij
         rTrFiOLn1Tr/lUPlVGLEZW8h6KfZL97XUs/h01SSW7nyK1Z2tMrxDgzpYyOHV3o99ujo
         tv7eYAYSdUrkx5uKD1/gqNuEO06LNagzZx2MtXCQHpJ9aUMJj1S1e+4uDNuCO3Ju7uIq
         FFySQtP5aBlex59fmpHoVOpwbOmVYU2D0oxSFjJPgWdTQ4cEAXr5tR3LDBKU/hzSg+ot
         rsYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975195; x=1748579995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kSv5Ub0Qt397NL2Nsw9naZOpwx/Ur29rDObbp2iC0ic=;
        b=A73zpTm1kpB3N21W+s8P4bdieRmHJkqVJd0bz+Z4GXOtedEantYmbCS/v9meM+V9VZ
         WzvtsI6+90I4DnyfNuc5lFShtGiqyJV8F+vYREfKa66qurjpoXYTkhwEqbOXMXyhifHq
         198N+SNBrz91HWFwXA27bop5clA+3sVHH+sJpWkCwnwxtevbQOwg8m2Q1YObsu39s5Im
         HexyRIiyG3u+LaRsZrj1H/pZffZaPGRNY9oUaAuuLFL1wO4EygmKlVycfklcAclcGW6g
         nCA+5Rmma2gDvCkZl6aknG6CJyW0SdmhgIBrCqAQ+4dZyjhyNiHQTp85yayBq/GXW4Rj
         KEyA==
X-Forwarded-Encrypted: i=2; AJvYcCXgta2i6uJfzE9uSP7b7BKCTLSOshbqW5S1kcoselYscei0zASj7NezE6/d2b74YDHh/vLBjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxbjFCrNXV7zvpKJHmIg+lGGxlup0PZB9knXnd4lL13em/dju85
	yVKC/6pF3MaxFSrPjjtpWLiNSXlNy7NRoHBdwfXW5rHtii3BpNvyoKpn
X-Google-Smtp-Source: AGHT+IEI/B8Rv42AL6Q3by3NRW2OJCR3Vdi/ouPV4rJQOFsxNbhlLH+0m5pDIXlKWdB0ss7j1ZbPhw==
X-Received: by 2002:a05:622a:1bac:b0:48f:5a65:b98f with SMTP id d75a77b69052e-49e1df23498mr30129161cf.19.1747975193641;
        Thu, 22 May 2025 21:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFYoN+0fSTbT6IEXg9Ns61OjdB8IY9XkNtmvAKOAGROvQ==
Received: by 2002:a05:622a:288c:b0:481:d765:2e0e with SMTP id
 d75a77b69052e-494a13a430als3989261cf.1.-pod-prod-07-us; Thu, 22 May 2025
 21:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuOEbEUitxr3BSz+mhZsYazUIACsuaeBc68yTqateSrCwAK4vrd2MeBSDK1J/Dx2+knaN+dv7s+P4=@googlegroups.com
X-Received: by 2002:a05:6871:2209:b0:2c1:461f:309a with SMTP id 586e51a60fabf-2e844baf7a4mr902310fac.8.1747975182410;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=YTIMpB/794TsRRzr4wMHXhUImHlIi/bmIzh2F4dict0WJraVLBGqqTg77yJqcf4Ihy
         m1Y3AMwGtg2UvwcRdunm+su+mXX2Mr5fIju4obkBFhoFVsE7bpBw40/ZB8K24wBykKk1
         LHT1JAAMmva+1FLEgee+5YpL9WZXYFD50uktpn04pQ2Ont8mWaJ0s6cXtcA+UDWVQyr4
         g0IEgvJ/5lcVhe5HkgIZ2v7LgxRxwhUZXmzmV7l5PqSrheHBYsdv3OTNqdqFo4a50nqN
         FNC7pp0epomMfxRMoVV9biMt+sKBEohgtB8xq55NjoPEruiioABObl+vNhf1qUEDtaAW
         ztIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TrwPW16gI1QhEkuIodQ7vBYATpIK0goPSTt0gdeuJsA=;
        fh=C90DpA8+Lhxr1XAczrbG3RZXTSbGvnftqD+yyDZwSf0=;
        b=bYvTWZ9N6km/FC5Fstvni5bmkoVKHbCC0VaCOz2aywDqON+fv9WtgdYeg8PBIW4zUD
         y98C6Y9zyHPAxF68nF5AHK4NuNkL6xmYVA/lWlcLHmc7fIKZBfnMfFYMBfgsdsLxlo3q
         rpwl0g2QIW4SvB2NXMPzytQjfJRsataqekId0DSRc31q1qdTFyCBXnJoF4kaVuCMfk1d
         ZeDKPy6DTepLmMY8vuTib1oWm+bET+2gyuPjU84UFsFSkxjD2+TNLP3qYvynA5nfCRJc
         B1tm8yjzgruQYbnpBtKKs2W4uigWdabITHv1uA0Wu+898HYC50KPeO2ybp0zIBQ5NNTt
         RCCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HV5smsW4;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2e3c0b02a35si37463fac.5.2025.05.22.21.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 72AFB4A96B;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 48AFFC4CEF7;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Thomas Gleixner <tglx@linutronix.de>,
	Tianyang Zhang <zhangtianyang@loongson.cn>,
	Bibo Mao <maobibo@loongson.cn>,
	Jiaxun Yang <jiaxun.yang@flygoat.com>,
	loongarch@lists.linux.dev,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 10/14] loongarch: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:20 -0700
Message-Id: <20250523043935.2009972-10-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2628; i=kees@kernel.org; h=from:subject; bh=iIpy4amE1B5BG/MZ7yXJlvvMYB45pyKPopqbUBpww1w=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3+VfPjOsGqOxm/1bvmH5mG/Ft0U++yRurxzx1V/U zZvk/rWjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAyAQ35zcDFKQATaW1g+Ml48vdNhQVZP3ef 1vDeKb/8WEj5y1q51xFz4zb0fft1+b4Pwz+7by/d73JzG/y39znK9F1H85Za25GAJ4ue8zB4rrl /awETAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HV5smsW4;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved. For
loongarch this exposed several places where __init annotations were
missing but ended up being "accidentally correct". Fix these cases and
force one function to be inline with __always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Huacai Chen <chenhuacai@kernel.org>
Cc: WANG Xuerui <kernel@xen0n.name>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Tianyang Zhang <zhangtianyang@loongson.cn>
Cc: Bibo Mao <maobibo@loongson.cn>
Cc: Jiaxun Yang <jiaxun.yang@flygoat.com>
Cc: <loongarch@lists.linux.dev>
---
 arch/loongarch/include/asm/smp.h | 2 +-
 arch/loongarch/kernel/time.c     | 2 +-
 arch/loongarch/mm/ioremap.c      | 4 ++--
 3 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/loongarch/include/asm/smp.h b/arch/loongarch/include/asm/smp.h
index ad0bd234a0f1..88e19d8a11f4 100644
--- a/arch/loongarch/include/asm/smp.h
+++ b/arch/loongarch/include/asm/smp.h
@@ -39,7 +39,7 @@ int loongson_cpu_disable(void);
 void loongson_cpu_die(unsigned int cpu);
 #endif
 
-static inline void plat_smp_setup(void)
+static __always_inline void plat_smp_setup(void)
 {
 	loongson_smp_setup();
 }
diff --git a/arch/loongarch/kernel/time.c b/arch/loongarch/kernel/time.c
index bc75a3a69fc8..367906b10f81 100644
--- a/arch/loongarch/kernel/time.c
+++ b/arch/loongarch/kernel/time.c
@@ -102,7 +102,7 @@ static int constant_timer_next_event(unsigned long delta, struct clock_event_dev
 	return 0;
 }
 
-static unsigned long __init get_loops_per_jiffy(void)
+static unsigned long get_loops_per_jiffy(void)
 {
 	unsigned long lpj = (unsigned long)const_clock_freq;
 
diff --git a/arch/loongarch/mm/ioremap.c b/arch/loongarch/mm/ioremap.c
index 70ca73019811..df949a3d0f34 100644
--- a/arch/loongarch/mm/ioremap.c
+++ b/arch/loongarch/mm/ioremap.c
@@ -16,12 +16,12 @@ void __init early_iounmap(void __iomem *addr, unsigned long size)
 
 }
 
-void *early_memremap_ro(resource_size_t phys_addr, unsigned long size)
+void * __init early_memremap_ro(resource_size_t phys_addr, unsigned long size)
 {
 	return early_memremap(phys_addr, size);
 }
 
-void *early_memremap_prot(resource_size_t phys_addr, unsigned long size,
+void * __init early_memremap_prot(resource_size_t phys_addr, unsigned long size,
 		    unsigned long prot_val)
 {
 	return early_memremap(phys_addr, size);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-10-kees%40kernel.org.
