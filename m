Return-Path: <kasan-dev+bncBDAOJ6534YNBBA4R4TBQMGQE64P6ZTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 340CBB08F49
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:21 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3a4f7f1b932sf672687f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762500; cv=pass;
        d=google.com; s=arc-20240605;
        b=jG8iWuRKn1vvyg8y3BbqGmkuDPLsOJ2PCER4WP2Ak8QcFhriiuxssQpqKKEsW6EcpK
         FEIrTPpPPUyHJPCgETZpBrPfXa0Pmojl+bJ83hO04U7epPYsdLnIT8M8Zi5Kut46ZBAM
         2Cm8GtO1c4uW+AbCzGTx2Of7p23MlsHEL9SdwE9zRgxHpaM/YICD5h3Al0CGOdCSFugK
         rPReBUup939WRXxNiX3VriKOacvDpmHA1gIfBDkf9m0NiKO/5LvIWO6m62aUWZxSPV5+
         /EM/azgIglp9gbNYsTHLNPkXihFsBTVYrRwF+Ga6pCGkY/DIoSP9Z3zPQIfSdPNqFB3C
         vV9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=jm1pnYLVj619lI3pgYAGsBN9uFg0J8Lj63+AffezgB8=;
        fh=y3Zf5YLtWTH7ptj16vRPJB/g8xxQ5K81Lzj2D7J/M/c=;
        b=TX4HassROKoY5Urg7SAEGiZ0TYoN8EHTZ2H24ivn8qXyhTM7+NwsOKDGecuhDnwqKH
         QUgWU/IgAmfn9TsoeImfdon2+bdqZLx0iBX3duVAgMkVOzjuheQcfLNLq5ZTJ+qGj0AR
         /alu1g2BMoQeRr312qlwhaSG90kcydwuaOToaqIfeZo2rJCFq6Hp8L3z4B/wwrWGwZ5t
         QcORATnFs9f3tyBWgo8qXn/mDHjIqDYO+lRexD31pfT4hWmjtWk5MM8T+tU4E0xPXn56
         IQ1OD5a5hmrAYHpkXwvgBVW/IiG99MRZINuGDbA5X6TSM8GSoXSqFQKvPukhfqemEs53
         lG5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="aydZfM/y";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762500; x=1753367300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jm1pnYLVj619lI3pgYAGsBN9uFg0J8Lj63+AffezgB8=;
        b=Eu0rtPpf2SZG4pOwTmLUyaeUlWiXeMtgNWQsiuoUApBumP48C1a+sBjtj2SuQ3vrJW
         5lSimPRhQNisW+n/OisK9b13Jv/8fbVPqlAZ4M/OZ5itpIC8zkt5mD93LdmUSk/cFzmQ
         wuTULOTgUwA/v3nvDBw69gphmZmDpOusg3ZmGV72I1jXlWgcqhOfbRQtJaJpfHSp3jFj
         mUIhxvUgzyYCL28IVtMpW4v0afy/fEBMOr8h58ZvtOodhvUWqXJberMm62SFDu/ltXMK
         u4Zd2kmPZJQXG0RuOpXWqJs2nPL6678KaSS5Qxsr3GLx2b9TAlF2P3/zw0Fjyf+npFEb
         TaLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762500; x=1753367300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=jm1pnYLVj619lI3pgYAGsBN9uFg0J8Lj63+AffezgB8=;
        b=ahrU0HYwIx87pkQx+CtCAaMLKJRzXOq9/m8NkQzdyQHgJVsn1M5+FXt/IFv6sMLBUa
         Izt8fMWwz3hp0v4IpI4gVj8rzGQQgM0ajNgKKYUOoaBwuZaWWca5zsF9ISS806QCqMtU
         T/cYx2r6tgDKHaGiXjWn/8O2fXi6R+O8101ltF4MxzkCd5DbWp2ph/lfI4BjAbDVWagE
         lqiIcEHYJzKX4Km4jQ5BGN7RgNzeHrI+hzsRXD05Vljo2smLFw/d/mCUKGSrakZD8SqY
         su8nV5ssX8MgvCVyYCibZh64YggEZhCy+Wc7oN1IVcClrGjomlZO/P53VJclLSrQ8rvV
         xIPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762500; x=1753367300;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jm1pnYLVj619lI3pgYAGsBN9uFg0J8Lj63+AffezgB8=;
        b=rIwtKCOzTEA4/gbjZSjAMjDuT8ZPnmjHp1RLL3Y7Kyy9RJO4LQzcVIOtbGFN79zzRi
         OmMLbGMkabZYHOT/g5uwz8rbg01RWE1N7fO3tb4Pqc1PVN+AVHY6OzUF/RKc7YkcLZ2v
         0AXqLA6lcUiF/eJGJiNMFjCncNrDzB7cneOmvvz3q4GrQbYzjGAcO9kJmkPBD2HiHU6i
         AHlCl1+yyQHZYRmCQQrCjqgKFw3GLoDYVs9McZGyqQaYgE/sr2HBatRYo2b//LffQ915
         GA4ZAcZoBGZ8BYn2zOdXilj3eXJB6T/NYcs+7D2qReoIlDrxSQJLSLCrC8e+WloeBulE
         ZatA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUX9IMWZBjPY8PMZvk3NBcH3U+/xnZLCmhegysrvqMPMMEoWQ3N4jRqHscD4bGcmFHsxBVc9A==@lfdr.de
X-Gm-Message-State: AOJu0YyaD+l1AhhwFgfa4xkqVPHDBJLD+INXpSG6cf7kzewSptp+xyFB
	CNGw8YUL2DFFWIPD1fUvu/9NdapyDIRCMsC9Rcedac3/lDEmWtF+igmp
X-Google-Smtp-Source: AGHT+IGUkeI+ayVatwHGYoCYcbbC9LiRRNUnSSyb3y5q7jfhUGZzkBE29Hwj5JdEqfwDCpNBHSEc0A==
X-Received: by 2002:a05:6000:3107:b0:3a5:8c27:8644 with SMTP id ffacd0b85a97d-3b60e4ca2dcmr5777729f8f.24.1752762500272;
        Thu, 17 Jul 2025 07:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc0+h16WU4789bZKMxRQx4vM4y8quTz3gKOKpFzfRQrtw==
Received: by 2002:a05:600c:1c25:b0:456:241d:50d0 with SMTP id
 5b1f17b1804b1-456341b19eels6581435e9.2.-pod-prod-07-eu; Thu, 17 Jul 2025
 07:28:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeou0rlfyB/7OtqHodOadMOcp2nyaHsxvAP53G1J95MixigQkNWqFarJ0N0SOcM4TfDs89AFQk66g=@googlegroups.com
X-Received: by 2002:a05:600c:64ce:b0:455:f59e:fd79 with SMTP id 5b1f17b1804b1-4562e33d64emr70799715e9.11.1752762497419;
        Thu, 17 Jul 2025 07:28:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762497; cv=none;
        d=google.com; s=arc-20240605;
        b=V8+MZyRqIsYNroBruCgX7o4gKW+P01/ykbO9WP6z6UH3c4SX8yu0ctbKJfUGrf6ekK
         tSwQg53HE4sd4J2bZ4UXNb4hWcqLH4ozYR+HQ2dO0Fv9uIQXhoI5K2Rr+IoeiRbDPnAb
         y5Wa3FlsimzlUZTtbK9nywvZazq0wzgBXQgXjPOfSgRu4wvG+1zEA7V2dGEV5I05VnXi
         LYMv7z0JLv/NCXIloH7elCvA5J/4SN8adOXEjLrzgzCCzEsc1wsCKgIpHkp2kH3vHv+I
         6aQkokrNtfX8Jt0L4qi/d+fMrjXyoOBOlFc890clAghnCMapyPtCYcdj7Z0rxKUwQlId
         tVIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=axtwyv1QW9Jl3sEVwduJUxW6lENRlEEn6jAlKX1Xswk=;
        fh=ujs0iqHiSx7lrdLlshMgO9iSS+pEy3XxgLW1gYkK4I4=;
        b=T0zffxru8hPUfPS6eyskM3A8EF/lxvju1wLKND0SCBkuyp4UPmHEy0Jz35SyVZw0LV
         /gFxmylato16/wUQEk8o0KOwgps7ixXGclDRnxrAM7bd9kmjoT0OdRtK63m4mTo8Z25B
         mw6zt51le+DHH7LbFgZP/27lXrIs3AAuydd7jkBg7fOY0LVWHRr+V9t084UznF/n0arN
         7RMpboCDgDUv0Acs4AuKKDIvlbnjp0dJ91ReyZOpfCbM7tUzspz5gabPCBcW9c0ZIqq/
         9kFefRMU6zL9TquX1h2BVHren5aFj6k+oGPAcJ3MzNNqM8n5WuX1ztuVjBVo2z4ICFBJ
         owQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="aydZfM/y";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45626c7b1dbsi2115585e9.0.2025.07.17.07.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-55a2604ebc1so1000717e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYQFDvQhYEog8ZQ41T3VlRFztEQsA7X5Yx0YmtIsPnT8R8Rmq7DFVSu1OUIi9WINStsIzCDxl7zd0=@googlegroups.com
X-Gm-Gg: ASbGncvz/iW3ldlk3SgrEUycqLUkPtSr8+rjiAXn+QbVtR98mbK3fuoo1pTJgYlJ8ag
	EQMwRTckXgRw4biYrfL3aPO50EESI2DLld333lbhoBjn1zkIS6J+RVBn6T+I4uP+NlR0gFeNbsB
	+kCPAQPd7FJeVbKuwts0VnQ9IjM3aKIMnXCIHeteUh9zuALzLIHB0Jq9QVIU40vf8FDh1uNt828
	eY7Quoq7kXPzFpohf1Ywtn/HIT/AHK3z18Vi+I/AKv9+bAgZsFr+iw8vSJ0GDUv66+D/ujAKw/K
	K4ChFkcBdDpUV9sajIDJH8BjuhAojZw755kq4Tnjk/83KT1/9g2pKILAX5F021dFLLBehXl4m+g
	RAKdYliUVelwJ0EqxHv5MUb/oSNIPS1y66qAS85+SOt13Ga4JUiza43t0qjwCoO72DEN0
X-Received: by 2002:a05:6512:33ca:b0:553:37e7:867c with SMTP id 2adb3069b0e04-55a23fb26f9mr2259542e87.50.1752762496407;
        Thu, 17 Jul 2025 07:28:16 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:15 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 11/12] kasan/riscv: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:31 +0500
Message-Id: <20250717142732.292822-12-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="aydZfM/y";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since riscv doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/riscv/mm/kasan_init.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca..ba2709b1eec 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -530,6 +530,7 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-12-snovitoll%40gmail.com.
