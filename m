Return-Path: <kasan-dev+bncBDAOJ6534YNBBF6Q6XBAMGQEHCAELQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 50A4BAEA29C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:43 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-32b3162348fsf5294511fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951960; cv=pass;
        d=google.com; s=arc-20240605;
        b=ltV5sS+cWZP5vcGp8CYjpuq8OnQ7yEUd3pFBzHhDpk/Zvn9G6RAQOIXJ95mI/5ArMV
         zZ/bws+W1o7Rg6MTtYpluWYSlKMxQKEnTJAVGF11JemMXp+Bikts8qT2UHVdBt1a3E34
         w+KOFLwnBu8L2FkQO6gl/2YL1OWih0hOzmi2kfIFAFKvMIHrpQ92tu87M2exjz2W4dgt
         VnX8KRf2BGLtlY0N1NeSxrD0eObqvmvvI2NpAq1CTKBQnpm4SVot/JQJd1ktRJLaqUMH
         Ee6CFyjNH9+aXfwpIJBYMTZb9v9NuV46mmYzbxD+VKdT8A2MPPb8oM/PgLOAa5Y8eUvR
         1gmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=afDO0eFZ8qDRXmoaLXIaQXgxQ9+Witwobj9StwWgcQo=;
        fh=UvAXzGfUXmZRobSpJkYSa//AUtbOLWWkKh+HzLY1OcY=;
        b=fiRYDufaPrEYuogrVtOE+0gjOBHY+PdSTaRmrWclbJWT8CpyU0FZGW01LCuIGhpD9t
         4afwgYO/szUCeTzsHLlEysOrCF8+GzXvG1IwIZsgPxrtPdKvcxOj4QQ5QgbtEYMwrbLB
         IYNtssowAzmh7P8TS1Hgkxtt/uG5lT9WYR+6703bYRBiYoGs9wRCPr4i4+UmPHyqHuQe
         1+ITSYI7WYiLYl2d68ECj9vJ6C84WOISKc1XinRiy+VS+6rlLs6TIUwV4g1HdleyY5Lc
         U9j+xTAyAQQN/lmKYBADNYgxtU2t70pLt1d6p/3pM+gSGGBd7HuFwaFWIA0B/mKYRvr1
         g9mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m8vqobjj;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951960; x=1751556760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=afDO0eFZ8qDRXmoaLXIaQXgxQ9+Witwobj9StwWgcQo=;
        b=ejij5bbq5eB4Lm+KK19vyJaNQ7CTj8gT2zkW/F+y1NxAQ1jG18cWaCGWIBwEvEbeRB
         o/C3AaDWUUjT54/511jVOku9qde56s66v3MA2w8wv7mMQYzs6Eo60dVpUNd6s4uLHVDE
         SqYtRqiN9G7BnF4CdG6ZDEib2cGaeZVu4V0CzksoK2FotVW9XO7wkk7qvE158/PDUKKO
         MT6oK6DaiBPwjZ+qULgPLUHeIbpAgPyLcWxGb0lMN8OZHGN6jM55H98Ov0wNpO8IiEt8
         ds8h/9JIA4w+cdPH8vqqcoCrCQeKqhCKtdLXc+aS6lzKql4XC3+hdkWEXa2ASbdMbT1y
         IUzQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951960; x=1751556760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=afDO0eFZ8qDRXmoaLXIaQXgxQ9+Witwobj9StwWgcQo=;
        b=CU7N9HUU5OeKSCLq8KzdmqOz2eskRCfVHiC48rSQnrFIiUMivrcEa1OVPOINV8ym6X
         eykUaNPtOWnBLYuzNJGfG1SK1nlowz6JII+dXySZPv3Qh/t/yH/zf6m8i8XC1nDcHVvT
         YNN2noUiZ2Yy8pArkq6uOnb9lm4cw02YjKAdgwPUm4g6R8ECnidAfR43s0ez/ptnEYDb
         cqWK8ZhUhVoeKNNbyb08yXVfl94UX1FTqnFAhFyCMSlA+7O73JDIDy+78k7ETigThNYN
         7mUdKWqlOqtDbmq2Ar+M5HIOXQZaXB3FQO1zT5DObDj1kcUy6RJU4nqZQvCexs4hrVsO
         b1jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951960; x=1751556760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=afDO0eFZ8qDRXmoaLXIaQXgxQ9+Witwobj9StwWgcQo=;
        b=rEJVj3+pIuF+6IjTL8cKlQKUSyuO8+mnP7za4ae7XjPHPYl16jZ/9uICpqjy3UabnC
         GdV8yyVTsQz3l8b/yCjXEedMpyEPYOqAuLvkigrCkoq0M6IEVCwYgoOP2B94xy339+Ke
         Y9bwLaL+mjtlRNiPfvHDvXZy5qbTZMMP6sSZyMi1YKEjCd1aHUHvF8vOMN2En6Dam0Jm
         y2mcXRQT6zoAA3whwnmnjxFMb4Twu1PgXOIS0uMAP8uvap/J0mZi9MwOa/2KbLTcJVZW
         C7cW0c+iEnmHuBD9a8G84EFwXWVOjqDr77GejLezlP44qGj+DCri7DDxtROgr/ZxZtqU
         /aTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSRl+17049Ev4Yr7BdiRP4PFussWQ8PnkInH1m9jIZ7WIhxXs0g7DP1IAz7vx48qYndTFJlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzf+eilct6sLu4cpkqbDBxXg8wgnVanCQRYuaxHedj4TZUIlZrv
	z7Prv4rVEdwkpMea1F6LHIU30poEfgSQ26JufCIlCYd56I5BUt/D6Ua3
X-Google-Smtp-Source: AGHT+IEwMU+wvBUCpCypU+9ddr2zwScVOLIXnuT4llkG6fnmr2thnQ2lIyVp27a+cTn2osjukXcAuQ==
X-Received: by 2002:a05:6512:2314:b0:553:d444:d4c4 with SMTP id 2adb3069b0e04-554fdf8a0b3mr2763816e87.50.1750951960070;
        Thu, 26 Jun 2025 08:32:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeNv1dGPMPV9uxXy98bB1aFD8kUEOcYKAJBexIBh1wQ3w==
Received: by 2002:a05:6512:3299:b0:553:24ed:d64f with SMTP id
 2adb3069b0e04-55502e302eals319436e87.2.-pod-prod-04-eu; Thu, 26 Jun 2025
 08:32:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuoCSfWwU0juL+9dEufdz3+FIjDF8tobShl5KHlDLhiW5hxz4N83ahHI6+6FcFj5Cc2djI+doDUhE=@googlegroups.com
X-Received: by 2002:a05:6512:3d21:b0:553:a311:3c1a with SMTP id 2adb3069b0e04-554fdf56244mr2880104e87.37.1750951957631;
        Thu, 26 Jun 2025 08:32:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951957; cv=none;
        d=google.com; s=arc-20240605;
        b=auvQhAUCBxNkD1h4JsTDSjfvHyPgxuXWypRRVzeGu5G8Ugcl8Rn7etj4jsSPqO4JV+
         kBbRc6wvl4+sHB0IAWMUzN7+W9wT66o9nQm0NYdh3hGrMWtlAoF1CGJQlRoO7mZYeOBS
         aEQOHmjaGAyYqMAU7QLhb8ZbQorQfVsBCClQfzlVtKvy+XgI0b3Q6FFWSJCpZXhlF4cC
         91HfQOqQRT50ScskUjmJxT1/4NlizdYTr+M78SEnKk3o+OirE+1whWjYLp7lbLWeLI4v
         aAoUUanXDPSUgM8V5yVnLJ+JhzCSkgWoN0fvJ4npqr4gM+z3HlzDjw+V4ScQ8US2h/su
         CkUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dIODlzXqnC6bR1NnIlD5Ra9HGYOoS6BNr32H/5XQfhE=;
        fh=XTqVdPYPCY8BMH2EVpZoeKYDMR15FKPCBPT3iinGQho=;
        b=EJRW2l794SiSrKe+F24jn1Fz8XbTOO+P5LIsoUIdXR902FeBdk2N4m5lqIY8GOp3Ps
         bOovffaxcVb0QvwbFgpQ8Nj4jnEj11Iu72b5lhGaWhPAeFbGfisNFGIKk26trI03l/tg
         n56vaP8L0/KMauwYkpHPSdibAL5KZfHBzw/4wt8yvcWsfI+8l4jbhSWQTDKRHJ8KTSYa
         y9l72K4ZSuXwB9Pm8+tleZ+hHUptbQOCslGIz6dViFjG6ziqTEWEbdetKOnqpKq7D/LA
         S4hYY+ve0uX3rNXMmkK5QjkF9wixHkL5qUh4q9TJIrxGWNyWV4BgnwRthkJZWS09BU+M
         onnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m8vqobjj;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b23ad3bsi6670e87.1.2025.06.26.08.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-55350d0eedeso1262585e87.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV91cx3qQdJ1LEhoxn9x9AAEz378Qx64vVWCxwANBw5kxc0viGcHJ8wvbS4VtpPlo1RCdgeydZgiVU=@googlegroups.com
X-Gm-Gg: ASbGncvRKkV8g58al35BJMxCjZlm490MU2U90HSScWZX9r4ywOrbpLjhQuwRIUyPUry
	QVKzmU+8gG5mC30+sTJ0o0SFCgmKf3gtvyn7QZwbCuqKW/+ev8mx+GSczQs/abkifCkWuI2cCiE
	E2IwjJwF9fHMNtz92Vf7AK/twU7MiG1U/43Ljq+/uu7CTouVQ6ReKIp+1vhHeeVUBxSQPnHGy9Q
	/OO0B1pXLOVA0q1wlmYZIVD5NlLXrz6FPgCQpgYB3kIJ7J8/FVw7DVpIsFWIrFsdfZk+HKRFtby
	38PmqOXBceZexzxdmdjn6/qyeUoW6E7UuFv2mLTzQnEseXY4AfN+52KM/u3MPO/IaJ6fPUUlpWH
	G6DuxCTwwsdeir0nsnKT1W6SrC0jklw==
X-Received: by 2002:a05:6512:b8a:b0:553:a490:fee0 with SMTP id 2adb3069b0e04-554fdcf457bmr2652845e87.10.1750951956874;
        Thu, 26 Jun 2025 08:32:36 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:36 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 05/11] kasan/loongarch: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:41 +0500
Message-Id: <20250626153147.145312-6-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m8vqobjj;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which enables the static flag
to mark generic KASAN initialized, otherwise it's an inline stub.

Replace `kasan_arch_is_ready` with `kasan_enabled`.
Delete the flag `kasan_early_stage` in favor of the global static key
enabled via kasan_enabled().

printk banner is printed earlier right where `kasan_early_stage`
was flipped, just to keep the same flow.

Note that `init_task.kasan_depth = 0;` is called after
`kasan_init_generic()`, which is different than in other arch
`kasan_init()`. I've left this unchanged as I can't test it.
Defer to loongarch maintainers.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/loongarch/include/asm/kasan.h | 7 -------
 arch/loongarch/mm/kasan_init.c     | 7 ++-----
 2 files changed, 2 insertions(+), 12 deletions(-)

diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
index 7f52bd31b9d..b0b74871257 100644
--- a/arch/loongarch/include/asm/kasan.h
+++ b/arch/loongarch/include/asm/kasan.h
@@ -66,7 +66,6 @@
 #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
 #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
 
-extern bool kasan_early_stage;
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 
 #define kasan_mem_to_shadow kasan_mem_to_shadow
@@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
 #define kasan_shadow_to_mem kasan_shadow_to_mem
 const void *kasan_shadow_to_mem(const void *shadow_addr);
 
-#define kasan_arch_is_ready kasan_arch_is_ready
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	return !kasan_early_stage;
-}
-
 #define addr_has_metadata addr_has_metadata
 static __always_inline bool addr_has_metadata(const void *addr)
 {
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index d2681272d8f..cf8315f9119 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
 #define __pte_none(early, pte) (early ? pte_none(pte) : \
 ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
 
-bool kasan_early_stage = true;
-
 void *kasan_mem_to_shadow(const void *addr)
 {
-	if (!kasan_arch_is_ready()) {
+	if (!kasan_enabled()) {
 		return (void *)(kasan_early_shadow_page);
 	} else {
 		unsigned long maddr = (unsigned long)addr;
@@ -298,7 +296,7 @@ void __init kasan_init(void)
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
 					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
 
-	kasan_early_stage = false;
+	kasan_init_generic();
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &pa_start, &pa_end) {
@@ -329,5 +327,4 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized.\n");
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-6-snovitoll%40gmail.com.
