Return-Path: <kasan-dev+bncBDAOJ6534YNBBM6Q6XBAMGQEXVEXFSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD5FAEA2A6
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:33:08 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-451d3f03b74sf6229915e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:33:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951988; cv=pass;
        d=google.com; s=arc-20240605;
        b=UIBCv/o7nMSRnKiqB17lz03EVnADjM3geOOvicaB+odZHyO7v8GYOUI+hlTwjxdeM4
         mfPgLzBaw7z1F+IXsEzHdl3B8GiatqGFbdyLmdGgUGNwq2xpNL5YjsKSSIguqvslLuQ4
         pYBBwvtKXg/T1ioGA2vrEFRDX7HXHqpFhFfXG8+jLGIGT0LZAlzozmvU+gS0Y9qGZWtz
         mPdFF83mkzDtxoFt2yso1lXM7amvdXIMKGNUwfVyva+A87TZZRpOF0tnJ+eFB1itAEAV
         uSUvEq9s+45ykPwugnWPEskk0fFvv7AbkBO9fiMG1AKJWeL1O+nr8veybERNFC2atzuD
         5xjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=4ogyIDc9m4dWxN0IzPT0Ry2gmW41bzCvndGEbw1Wysw=;
        fh=GX9YfcGDVcdABmoAxcWmFedB5NCHmX3d5Po+HeFXwLY=;
        b=QgxuMuLAylOm/R2f2uGO0EtmfJ6AdT9ZNXyLo7mOQXvUJYkX71QgdIpLeoHHLIqCXj
         VD4o0pW+DKgpu0oWwN93+auuTW1POLC0oT+F1mDMm2RZ9DMO5GyYBpEJvwvWtk+Phegs
         XCfzkWoDVLrG5lQWyjB8s8sLJMZissvNnI4zT255EzbdLJbiwiGEpEFDkoWLUN6ZNcx4
         YCjDJZFXzhMGPMlxRqf8zwxrl9BTcW/Cj1xlmaH4E61i0WRShoMWqXn0wf355HeBZOLt
         SpzxtL4kvMLzReAssTqG0EwjtjjcppWs4NyK13Cx66czS8W9pxNSdTeEkHd1ZzoXUBEH
         PsoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=j86QmZ5K;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951988; x=1751556788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4ogyIDc9m4dWxN0IzPT0Ry2gmW41bzCvndGEbw1Wysw=;
        b=hCK+39jDkJu+7dpTcAT4S0HotbMdnfXUBVyBvYxD7uQGctem8AHN6k37DpJbXiWrac
         qhAILCq9I/r9zk9SWNeIWp+cMfMsE8pL3ccwrK99cFOOJ4fX6QdWlVtgwlmPs6IUd8BU
         w+6B5Rv7PuZDpsERYQkzKuIg91GOCneGjw5VvIjlA2IF0sCkowKqz5GCNqNdShUCzhlj
         AZte3EBLgr+5bStITEwXRwVaQLUWn3ldI3eKDa1bqRbYBJt1tfMj/f2pCIVMvMaVaJg8
         PWNwcGHF5QJwJzzlY+yf4TfJLtwxcpWlXJ05mgm8ii6dRixTUficr7NfQ1V7wTUE0OIS
         e9Zw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951988; x=1751556788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=4ogyIDc9m4dWxN0IzPT0Ry2gmW41bzCvndGEbw1Wysw=;
        b=d3lfnEnVgqs5pj4qhuxIjRK5tUguwH34+7JfFvVEjTu8f2B3LoztpPYxhosLsTO1iL
         +wCno7jfD0KG7ytANkKJUzk0zS1184WW+HEFksyjc7hDOWySHMWBifP4Tw86DLZuZm8p
         mNUiWP+T7XGJdcqYXAQ7qSbyhZwgE2bezZlfX9RtofuTBlSdVDVM0HOpAl8s5DLM/j9M
         BhubsSzWH5LYOBCVirArvn+obDKau4xGkKD1EJE+SKcawAEPiIo8CUH7viIiToEVniqZ
         2fiWVKv8kpp3CcbzmidA/u+LrsZ8QmDZVDBm4jm1zpvdFd4xksYi3SvKBgIuo9CqbRTm
         ojHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951988; x=1751556788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4ogyIDc9m4dWxN0IzPT0Ry2gmW41bzCvndGEbw1Wysw=;
        b=UkT8VJn6ztbCxZbWbEP6CPGltl70VLjAWrkE7JguG4G73ifdluP0FKFrCceDXB8GFO
         sPqJYDeidGC7DnXaZ8aVgqYKBXDJn1vpxw5Sm/DySAh+YSw8sNrXLmlfjDb6xuFK797l
         z2J96dz6o0zuHQDgfMsujcpkbxlJM/CfMhUHDrKXUiA8y6XRD/faz24qb3oa4qHxyyPT
         BLPt38Pdhjg0OLqUsOzWr/iE1IxO2lUwqDrAShzEWG3Q+Hck8qEApcbq6uL1UEDWY6R4
         /n4Z1vv4PIz47iUDe0Crc2Rv0WKVnVbODkC7fsNdGCKld/aG9DAgcUwudseC9M5k/yry
         B1Qg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUO49Tnar0JnjybazbsQW9qCnFSD1fTM26FbpS2CaaB8luYmu5tSe8sZZfy7RZ4ew5zfSpfMg==@lfdr.de
X-Gm-Message-State: AOJu0Yx++m0xz0YIsqezESZtPK3x9lIz4ME5ASX9GCNOSIDKAduO3e3L
	WIGtiFSkYW2TQVk1wLcq7T4s1dvPADLfL7vamOOpeSrtmCGQHA9Z6902
X-Google-Smtp-Source: AGHT+IF5W0SFbvPzAxYhhMgJvukpBDIEyrMqNg89rnso4a8foCDC2ZxJOqauFXxdm/Erk+G0ebG/tg==
X-Received: by 2002:a05:600c:3b01:b0:451:edc8:7806 with SMTP id 5b1f17b1804b1-4538ead043cmr1741425e9.32.1750951987776;
        Thu, 26 Jun 2025 08:33:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeB3NwrAbX3ZNHNpcKnuXvUluWIOSxPTAvCYiEFCCOzFA==
Received: by 2002:a05:600c:6285:b0:453:5a2:ef4b with SMTP id
 5b1f17b1804b1-4538b2dc659ls4677955e9.0.-pod-prod-03-eu; Thu, 26 Jun 2025
 08:33:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpVR639zz/7HQvf8C6cfzl9Cnk9sO+T4Q1Jtl6y0Bc7Tg8I5HU3IhF5GCUfjHOBICHCxmpJ0WXlqg=@googlegroups.com
X-Received: by 2002:a05:6000:258a:b0:3a5:67d5:a400 with SMTP id ffacd0b85a97d-3a6ed65e7camr6761761f8f.33.1750951983648;
        Thu, 26 Jun 2025 08:33:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951983; cv=none;
        d=google.com; s=arc-20240605;
        b=h2RZDQzRQRnKnH6bCQbC+tsmmki3dMRDOoXK1MdbIgl1Bz0C2uz69CT7y4NpYV6IpX
         /bjV626kPcFaRQev7IW9goXoyzM+FWXA0rWXs6DDl/PXlQ4j9RyWZC86Hx1oUllA9fgU
         n2ugrx5HaWGvzgfAD7wgKxfykcDid+xaBb0PmJQDjwW8k5DIjFdMtuu04DQn+B34H//R
         4QHLGzxt5GMrAOq5rhlK+glCTcNkShwvC1AZEetKungaF8WuPgB7gVu9mcbw1tWOLC4N
         s8LUuhTrp2wQ/ezFuvm+va06NI5CQM6y+lllxR2Z/01I3vDCmrB8hihkaU993aBCtvlZ
         jc/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gODL4ePLEui+bgBCtMqPW0nf/RnbL8ytBUu0XwvP9Tc=;
        fh=JRfqclwdBvDvT1c090xElFMwOn55KcGZ7dwVkiGyAZw=;
        b=Ib3EJ6zaVUcyD1o0KnsraGIsmWqndIXt0q86IKU06P+uaICdXgjBmJgS505ZnBAWiF
         bNEH5wGv6mA9mrpJs9M/dAKfC5BmSZydzOB+M7fQWXt+1fSLlDfY+xMK44cOzu1rCGhJ
         ADgWYdh9Rkh82e5jo1ugP0MWAxqNMfHzS+AJj3RF+MWMRveAk2kBBI2Ir3u+B0hphwTc
         rQE/Jp/KJPZIefyZmP6jy3UYBNGIu/oBTO+FiPh/tfAcst+4nzFUTZSohi5yxhxp2Jpg
         RJpK0ncQhZXiFIzHKDhQc1aHSSG8oafx2GOyfZNnU+woW3tEQswWD1XXPazK7rPuyS6f
         CHFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=j86QmZ5K;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a4debsi1170325e9.1.2025.06.26.08.33.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:33:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-553dceb342fso1028698e87.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:33:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVS1gZ5BPsVpqlNpoubA4oaOSbXwrwZSUVXOz0asuK3HMkhlRrW+rJJW1207RbeFo7teFf4CTC1GdQ=@googlegroups.com
X-Gm-Gg: ASbGncs2VcXi0GPx9iNY43UjPiowhhMjQyvw3nMssO6JiAQwaUqd6JgEJ66HW2Fy36i
	VOKRGNcUJgihYAz8sUHTRPVFqdyTSCjUaHkJXTOHH2OojUlPJFavXLiFyb2tjSqGlABPhwcvTY4
	NtWJxoTcHKBfSZ39OIGUkiRQrT+/H1D0TcMk4w3VipnLUUz69qdBtzykF0wyp80SjON3AtfqwzX
	0O8EpksUBl3X9B8v2MxwnvbTHC9Q9OB0SBjsuAIUSQBZbviqUxrJ+Y5tf+69X/rKfN8RVPkoXvw
	3vQB9KPfklH6oRTbgeP0v+h/gEI7kV+5Ga1cpA/0af4pK5eHFcqfrv4KxYGcnjqFYmX9bAI/Zpb
	OPHXNyCLVfrAn4Yj7Fv8eYthH9bxGtA==
X-Received: by 2002:a05:6512:318f:b0:553:ae47:6856 with SMTP id 2adb3069b0e04-5550b474cafmr117706e87.10.1750951982600;
        Thu, 26 Jun 2025 08:33:02 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:33:02 -0700 (PDT)
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
Subject: [PATCH v2 09/11] kasan/powerpc: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:45 +0500
Message-Id: <20250626153147.145312-10-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=j86QmZ5K;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b
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
Also prints the banner from the single place.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Fixes: 55d77bae7342 ("kasan: fix Oops due to missing calls to kasan_arch_is_ready()")
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v2:
- Add kasan_init_generic() in other kasan_init() calls:
	arch/powerpc/mm/kasan/init_32.c
	arch/powerpc/mm/kasan/init_book3e_64.c
- Add back `#ifdef CONFIG_KASAN` deleted in v1
---
 arch/powerpc/include/asm/kasan.h       | 13 -------------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 4 files changed, 3 insertions(+), 20 deletions(-)

diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index b5bbb94c51f..73466d3ff30 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -53,19 +53,6 @@
 #endif
 
 #ifdef CONFIG_KASAN
-#ifdef CONFIG_PPC_BOOK3S_64
-DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	if (static_branch_likely(&powerpc_kasan_enabled_key))
-		return true;
-	return false;
-}
-
-#define kasan_arch_is_ready kasan_arch_is_ready
-#endif
-
 void kasan_early_init(void);
 void kasan_mmu_init(void);
 void kasan_init(void);
diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 03666d790a5..1d083597464 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -165,7 +165,7 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void)
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 60c78aac0f6..0d3a73d6d4b 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -127,7 +127,7 @@ void __init kasan_init(void)
 
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void) { }
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 7d959544c07..dcafa641804 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -19,8 +19,6 @@
 #include <linux/memblock.h>
 #include <asm/pgalloc.h>
 
-DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
 static void __init kasan_init_phys_region(void *start, void *end)
 {
 	unsigned long k_start, k_end, k_cur;
@@ -92,11 +90,9 @@ void __init kasan_init(void)
 	 */
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
-	static_branch_inc(&powerpc_kasan_enabled_key);
-
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_early_init(void) { }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-10-snovitoll%40gmail.com.
