Return-Path: <kasan-dev+bncBDZIFAMNOMIPZ5EOZADBUBFZCVDOU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 254E1C21E7F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 20:20:30 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-428566218c6sf736473f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 12:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761852029; cv=pass;
        d=google.com; s=arc-20240605;
        b=BmKAbHRlxkgX5u9R8fpx7P+ucQk+gDcV2hBAQtpR1wBoQemUg6SGgc4iCR5eLMZyyj
         B75cQUfCerV74RR7TEi0qS2P16bizchLq5uFqYLVp4Yj0NVuoDW2GLM3Gqsj/Y6U0fBb
         o/6nj8yIUSA0A/JmsrvBix58OiIeIxh0FZ1i6r240OaB+jK/WNilGQDGdAMR9LbYngfg
         7+cdBuVSlzQD6WG85TLGs0q3Znc2sbefmxqGB9bPNerYE2lUCK4aho3+SaRvNaWkU3a2
         oadBckY80HJ5jFBJfRPiL/fALesrv/ZZYefGLRU+V0xrNKXvVDC973PjABbwckuAz1zw
         +PNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:ui-outboundreport:subject
         :from:cc:content-language:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rUYcRUTbbmVHHFUQum4gCIiXNa+30OkfHsdaASgcYQ8=;
        fh=qBuGS0esSPnpprCao6XvbCeadjQ7pMRrYIVDwgGmERE=;
        b=UQwJecPdFlV6h76dh5oPNKnSXtVTZR+SY60PwfqYMcrmDxthJCsKn23DLurT1o7ppz
         w9RYyRX+BHU0QPlklzhBR+IN8/n7b4X1eKCp1VBhnk0JPr17Qbqr2Q8aPoXNufrAnhqR
         nz0F1nP6kACiOgMNImi36Zyp15yjln9riukf8HirG0BLZa7E5E5ZceWIVP+d7umSq3LN
         uJs66UnBOe9/VcTpuQwSj6AxhRhIewnawzD6gLycU+biyFNC8jWsKbPHmV6LSUkTTmuR
         +i9pmactQLjn2QlTe3ioKtsozrmo2V3Vx5vKnYwTMp/cuvDIJIEkdhTyxmnbo9BNCcRq
         GhuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b=dw6mKfdj;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761852029; x=1762456829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:subject:from:cc:content-language:to:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rUYcRUTbbmVHHFUQum4gCIiXNa+30OkfHsdaASgcYQ8=;
        b=g+HkHcsglbuVmbRgEEAgs4PxILxt7JQlR3xmOZYXLvfGubcUooLlvsbydxpHTnnLIm
         CXlBlDBz6kC42Kd4nCLnCuowcoDJFrKlD68gfzNLNGBwFIhjPhQVakwabAwcFMYxODO8
         zEjKEdGLK9eIjkllfyLyJbDpUVmIrN7mYDNoK+uhe/OFao4G5nqisCglZZuYG1dToKWN
         YWSt9xs/YjE3BEoh8OKl22kUTLzOaCSL23iPuATXbADQZAvZwGDXHhU8q7JWpARQEcgK
         AsOsIEgbewdnwpvJqEdJbh1up54t6U1aTh2xkz6QYi11DAKM4O3HZBPw7e4EIYOPrw8a
         Wuhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761852029; x=1762456829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:subject:from:cc:content-language:to:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rUYcRUTbbmVHHFUQum4gCIiXNa+30OkfHsdaASgcYQ8=;
        b=Hd/LOOxHmSEOQD5ZEcpVnGtyZRIUYAJMyJiekZRKCncH/h4ysh4FhXgBoCKboZkLOR
         sWoE4vD945sRkS8T2ctorpS9uKgsVqyk/kniqCxXsOgAb9FNWuqwkkqE3qZ1Qh08rTEe
         2ryBPhkUaQ4Acj3dMnamox11IuG6ZOwebhcm1lMljAOgw7MtcgbvqXWVOSHjqn+omfE3
         zQZzVItFYF++5e8hH4W06C8Vx2nOGDyFNPkyNvOq8WvzCucxRCyf4BhhqIluLOc4PX8b
         U6ygt2lpM1LOhkDXO5kwzCXUcBQFYGYxdpqbeQgPaVbNoIwGhaXm8tXcRxMZLt/rhNro
         3axw==
X-Forwarded-Encrypted: i=2; AJvYcCUKbIOebpC4mkOHWKS4+Vh4at8Z9xZkmedXCxf2suaGCagRz2qlkt89SdKB90KQnOil3iTasw==@lfdr.de
X-Gm-Message-State: AOJu0Yyt/AyZsiE2ytYMaULHSkGmE7phKtgo0gO0ACsDv0DW+iYMrKVP
	TKfx2w1+eZL0lidgj5Ufs9EqY0zZSqLFnrFj3WLwx5kPaS8johH740rn
X-Google-Smtp-Source: AGHT+IHy81Se1llmMSDXmLdqjQcdH6JJypODvKB4RSA2XJSi6DURQ359i/Ypvxiomr81n931uTyGPA==
X-Received: by 2002:a05:6000:40ca:b0:429:b9bc:e81a with SMTP id ffacd0b85a97d-429bd5ef85bmr600678f8f.0.1761852029287;
        Thu, 30 Oct 2025 12:20:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aFrPVFPcFUsYYHBTIGFxa1BjjOLHeRwsdpqyml4j4eHw=="
Received: by 2002:a05:6000:290c:b0:3fc:116b:d99b with SMTP id
 ffacd0b85a97d-429b4e06be2ls906800f8f.2.-pod-prod-01-eu; Thu, 30 Oct 2025
 12:20:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuJ3ZRMTtbTB70bNjCNyCFh72KrbeYlOeDwZupag8OPeePztrtchRJU2J2ne/QTZLKce51/n+qjVE=@googlegroups.com
X-Received: by 2002:a05:6000:4713:b0:429:95de:163 with SMTP id ffacd0b85a97d-429bd67bd22mr783822f8f.20.1761852026135;
        Thu, 30 Oct 2025 12:20:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761852026; cv=none;
        d=google.com; s=arc-20240605;
        b=gDxDKPg9E5l/uHzuOy9AlzbpqSv7zHHiT+QhU/vYRHBf4A1A0Zne/7RDiJi2qbSd1Y
         ZxtXPBgFsbp2anXa2ZL6gxeYHHVno/MLrMsUdpm9DcPSswlYAuFjp6HBaPDWPQmLBdK3
         iWMMR2m4ySg+Fou0AknCGAU58Id4f+g35kJGS0sd7YRma0+WzvogtpU1TsJyYCK/d9cf
         TyOR0Qcr+mzAn2fhe1vSjYxqv2DKCAypC/R1eyj2iCTL/KQASdDOy9KFDyHWV7u3jY7s
         T0p3eFtnbTc2AK4vLwB9H1NCpEy0V4RkG3VdlXqrvDJpAlF3atR2m6kDLHd14uXr8k7l
         cqZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=ui-outboundreport:content-transfer-encoding:subject:from:cc
         :content-language:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Ez+rWdlJxXvTuZxuonAYjxuORLmLCaLwGK3tecXKsxw=;
        fh=iE44X9+vVqXdc0p9H606/GmarCBzm+td4kE0Wl/VZIs=;
        b=iXRptJkBcbEjO5cQKWXCeirxtKUw2uoQW5nDSe3BPEjCoOcjAwyU+X07mQmtzy5XpA
         HRTETp9DZ7vCyYhxux9AX0Kk+8cS7CRH3P82ECMxmv6j/TlNqsUEvpsqhdDJ3uElG136
         kXsxsUZTrD2Ko6YNb7WVgCFpNzRlx7WeTPT9Ip4BxUXJbhl26rR6CU5cJUi45gn+mkA5
         6sWcFglrdQgUh/sb1y4ZWUAzk7b1F0oGjv1FOfmExY0YiuvdzVZS5vWzQFxaVmXPjtvw
         N3KU/sS37DFkbV5uataNUkt786/n0RXP8Le03c//nE9JuzDIZNewcR3kD4GPwU/2+f1J
         T6dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b=dw6mKfdj;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
Received: from mout.web.de (mout.web.de. [217.72.192.78])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995f8f643si402129f8f.1.2025.10.30.12.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Oct 2025 12:20:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) client-ip=217.72.192.78;
X-UI-Sender-Class: 814a7b36-bfc1-4dae-8640-3722d8ec6cd6
Received: from [192.168.178.29] ([94.31.69.248]) by smtp.web.de (mrweb105
 [213.165.67.124]) with ESMTPSA (Nemesis) id 1Ma0Pm-1vkTB10Qjc-00MF2u; Thu, 30
 Oct 2025 20:20:11 +0100
Message-ID: <a87dd5ae-2143-4de6-a3e2-9c1f16a001b1@web.de>
Date: Thu, 30 Oct 2025 20:20:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
To: linux-arm-kernel@lists.infradead.org, Abbott Liu
 <liuwenliang@huawei.com>, Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Ard Biesheuvel <ardb@kernel.org>,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Florian Fainelli <f.fainelli@gmail.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Linus Walleij <linus.walleij@linaro.org>,
 Qi Zheng <zhengqi.arch@bytedance.com>, Russell King <linux@armlinux.org.uk>
Content-Language: en-GB, de-DE
Cc: LKML <linux-kernel@vger.kernel.org>, kernel-janitors@vger.kernel.org,
 kasan-dev@googlegroups.com, Ahmad Fatoum <a.fatoum@pengutronix.de>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Miaoqian Lin <linmq006@gmail.com>, Mike Rapoport <rppt@linux.ibm.com>
From: "'Markus Elfring' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH] ARM: mm: Use pointer from memcpy() call for assignment in
 pgd_alloc()
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:V5RoG/ey68k2qK2kiaYUN5TMTUEk17nuNumKA1tewu3PWEXMDdr
 jAkFMlPire2Kstbv+BzAxfw+ehgbWiQ4HOxUiaSAaRX2BoOcoJ8UrEBejqlusCsEQZvj0gg
 lUdK9YIvBQq/mNmI1sX0GU0iySPG3EXJn2MSDvwT2cci2ietk4GijBuW3zGWBQEdB77NawD
 pKLGCYU9UO2qcuyv8WQTg==
X-Spam-Flag: NO
UI-OutboundReport: notjunk:1;M01:P0:11VWYgs1VrI=;eCqQuk++6n11VUOPwjS3vVNuXb0
 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
X-Original-Sender: Markus.Elfring@web.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@web.de header.s=s29768273 header.b=dw6mKfdj;       spf=pass
 (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as
 permitted sender) smtp.mailfrom=Markus.Elfring@web.de;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
X-Original-From: Markus Elfring <Markus.Elfring@web.de>
Reply-To: Markus Elfring <Markus.Elfring@web.de>
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

From: Markus Elfring <elfring@users.sourceforge.net>
Date: Thu, 30 Oct 2025 20:08:04 +0100

A pointer was assigned to a variable. The same pointer was used for
the destination parameter of a memcpy() call.
This function is documented in the way that the same value is returned.
Thus convert two separate statements into a direct variable assignment for
the return value from a memory copy action.

The source code was transformed by using the Coccinelle software.

Signed-off-by: Markus Elfring <elfring@users.sourceforge.net>
---
 arch/arm/mm/pgd.c | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
index 4eb81b7ed03a..5e90faaa4934 100644
--- a/arch/arm/mm/pgd.c
+++ b/arch/arm/mm/pgd.c
@@ -72,10 +72,8 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
 	init_p4d = p4d_offset(init_pgd, TASK_SIZE);
 	init_pud = pud_offset(init_p4d, TASK_SIZE);
 	init_pmd = pmd_offset(init_pud, TASK_SIZE);
-	new_pmd = pmd_offset(new_pud, TASK_SIZE);
-	memcpy(new_pmd, init_pmd,
-	       (pmd_index(MODULES_VADDR) - pmd_index(TASK_SIZE))
-	       * sizeof(pmd_t));
+	new_pmd = memcpy(pmd_offset(new_pud, TASK_SIZE), init_pmd,
+			 (pmd_index(MODULES_VADDR) - pmd_index(TASK_SIZE)) * sizeof(pmd_t));
 	clean_dcache_area(new_pmd, PTRS_PER_PMD * sizeof(pmd_t));
 #endif /* CONFIG_KASAN */
 #endif /* CONFIG_LPAE */
-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a87dd5ae-2143-4de6-a3e2-9c1f16a001b1%40web.de.
