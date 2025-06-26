Return-Path: <kasan-dev+bncBDAOJ6534YNBBHWQ6XBAMGQEMMRFU5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1567BAEA29E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:50 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4532514dee8sf8479615e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951967; cv=pass;
        d=google.com; s=arc-20240605;
        b=QKYU5PxM8+qpdrEGpEUxihauXQu5CLEwUUQ1/haCrTv4q7arGI3sR25iD4GcvDJoCv
         ufr8u7sXA4aH3xQCurUL9bHdsBgj06AyJ36ccK0MuhrxVzGvrUghZhT+UBoyaBMbwGYv
         9l9Q462WEd+m9uxUY/FY1BfeTDJ3pc4EIsDOEdlXkdvlEyNjH4Uk8oavn45pb2G4ulGO
         //qCUKRDttzbhLo7DeNILDq4EeYUZkhnLnYsxsp+SLFun00XtkcnOnz3rq4frrtauMCi
         kYx6KQW4CUzXpekmGM4aDQj5gzR7CC+lJeWy6wXN4g2n2uUK4Y1UCRpFnJlXW/3mdsXu
         Cm/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=JYRCdbUVmCpmUsue+u+iIwPpwWyokgJb3OnTZ5MaAjs=;
        fh=rrJ+sZpY4Ctm1sKANIzAATd2My/XMZfXrT4qRS5A7gY=;
        b=aaxumbctysApjTJMfYOR9RP8NVSBWHXKrxYiJgduoo7zQJCtLWRGiUyAnVJBcZh5Rr
         SSKcCSURmc+h3R1IWI/37WK7/XdTKei5Ymum55SQKNKHP9yurYvYuIwlOGOsq3cVUiqq
         qnrFOxX/xkTTHY0HZRgKw0h2qc9F3leXi6DyDf+paQxu85ISj1lFAXPpYtEv0OLitPm/
         +6IH/iEMV0vlgrK20J7Vb+pPjkARvF45g6ckUPyfjmrVNYepXQIrx8KQiLvKsB8k2M5S
         szNX3B5F4QJwX6CMDigep5zOireQNQn8MSlmrA9SMGcv2cMZa5XMNrTqUsz3CAkuL067
         g3Gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kC4tq88O;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951967; x=1751556767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JYRCdbUVmCpmUsue+u+iIwPpwWyokgJb3OnTZ5MaAjs=;
        b=nYZyKXCVlHCJ+X80vXk+j/ouem+LqS6vRddyd2H1YOU/U8cLHSN4AvyxqDaqc1Rk7t
         44gAeFQvhDX/VSSX8wtwTn0inxDEKjo+BCmsJNiEtYIAO2jL4337WnE/s/JM6yr9E9wP
         VtWviB41C0KURdJB59Xs86CGJ91gU5fmQU3pykK31SrSyfbC3KnMNbbZot2SXKfYo1Y2
         eoZwdAolhNVZ1FxAjpMjmZSsIToKpitvTsVSPDcbVCLG+/DThqMaaqBLwDFFXGuVIoy6
         /VV3xEYWEm5Gx3BlbOMF9JCpLBDN82nuDXUpEJb62rED9zjgK8UvRtWbQ2JrAflwlEnn
         ksNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951967; x=1751556767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JYRCdbUVmCpmUsue+u+iIwPpwWyokgJb3OnTZ5MaAjs=;
        b=J4FDpoyPfxr465LKmIbFzsJxccjpdAhenqXGrIgOPKe01tCqIu6Caffj3Hg0Fv5lZ0
         hi9lpDxBz7kxRAbYfgVnxzeGPZvFfzZSO0xs7AwlMPylDDBS0g4tVb8B8WBbgGd08mbu
         nSTzr8kVlWjIdx9Lmz/n3Db5s3hIz2naMx+2Tvq4z+BbqNp9cG/OcLTC1OBzNdGGnAzN
         pLiYT78xiliXQXRwrt96s81VK+25Po+9ucvDGMRDwucyhlOrcBNLZctP9UmqgrL2Abef
         OGfZwATZ4sL1r8hZX9oTKHiRr+iPAfzjdkV8SqjETpc4u5Cr+c/X3f3e6E4WKVbFXkBh
         yF8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951967; x=1751556767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JYRCdbUVmCpmUsue+u+iIwPpwWyokgJb3OnTZ5MaAjs=;
        b=d0OkaNPNJf2qEOHC10fJ1Q6NGhlAYHTEEoNRG3O4T04z/WHJwTljQuRthTKIIvcx2P
         /S8at8e37ZRoaeAY1xM+rBJv+BfXK/N3ZB1cn54LP0rd/CibhBhyW77wNdcf7/w58/NK
         6zh2GEj9MNctrNsHHuSbbApbCmi5LZ2uvFcUAtu0mf+rXC4nUmDa8Pby0FGLlSXsLQ5e
         OKA6kZYWs1jRJk9zsMrbEaqzwDiy+ESMwpGffHnYMBBXsNZnGmy+7uUbflDkFhM6KrBJ
         sB6DWqZwehifBmqt/i01SXVPC0cjRkXSb/dOJj3aqZhTxkrKJsJ6opC9eov/JV2M3dHo
         bXmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhDVFn1mv3x7bPS8hoFXAkxjhAXLMBp2iw2JTXl+AZg+JTldRnbAfNNyPytfpzmRvxgtUjfQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz8MflQkNUKQKteBjKbqDMob0B5ir20MCU10l9zFSfL54Y7DinT
	GmB+2VXIJeKUJJ3D0Sd1UomV7cM0Wc3Emm2owR9uqJX9J4MoPFoz8/kW
X-Google-Smtp-Source: AGHT+IGT1VIwUUruaD+r2KXz4S9HsI5CIYh5vWKbpbH3L9o39zZstJOJCifz1zb4d9TslV010BIRtg==
X-Received: by 2002:a5d:5f84:0:b0:3a5:8abe:a264 with SMTP id ffacd0b85a97d-3a6ed637b6emr5546108f8f.37.1750951966895;
        Thu, 26 Jun 2025 08:32:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfzddAQBcZ4SgwEnwPyiVlRysLt3YefjQR6Sh88uK2/dQ==
Received: by 2002:a05:600c:3586:b0:43c:e3ef:1646 with SMTP id
 5b1f17b1804b1-453889d55c4ls6366115e9.0.-pod-prod-02-eu; Thu, 26 Jun 2025
 08:32:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6Sv8PCbheoVxKVQ2WAWrAnVfok7ubmOVFQzrj0ExGX9THSfJg8wapG4ncfP2JzGtiqUvTZP9PkvA=@googlegroups.com
X-Received: by 2002:a05:600c:6215:b0:442:d9f2:c74e with SMTP id 5b1f17b1804b1-4538eaaf18dmr1695675e9.23.1750951964347;
        Thu, 26 Jun 2025 08:32:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951964; cv=none;
        d=google.com; s=arc-20240605;
        b=iJcy9uMJKp/zJCamjtwe5GkxjKq2/C4k8Br9ltdWNQiZasDPv3a/bDrRCRdzlMI51U
         Yfmi2qm0J66pYWo8v8pDj1e1ycPbB2ZzzdlDrVDcjHMNg2H7tQCgx8A197+kUSMuVxzI
         dFcl1cnTNe4yh2dp4IeJD0zbXk0hkNuSpFwoGMvpSZQxoMRcqrGirWw05r1J+K4JA8E8
         tQ1zsAWfPgDrzz8kHISC8UfBRJ4ZLoWC7punW5inByciLdBkIOWxMeQPmYRZBIJbJfbh
         7AKlLGaA/d90w7PT5hwH5UNoSjosUSefqfyjxV6t5mp1AFHFn/bKfzTHoRGSPLQ8UdNq
         wFMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UAzHyennbJbJNQdO/m8GiAxn8DKdiS3FDiXvLMA3BPc=;
        fh=5qsCN44DnGAUAx6vDZz7dPC5QIvSWiTQrb0OIi7LXlM=;
        b=k7RD8gGRL6odx3duDx0U0nzIvY5bH7PzXCYZ/ukkoEsd1pFhBb86v4u/YCh3EUA45H
         TJerJWhhemQPfjhOvSgOafJlh+1KqT1OKAPk7/pw3KjajXgf3CDFIC+dZAMW5+NTPNIH
         Wvruu7meDcaFaMQMIVRHN1HOzaz7IZ8WWAtor78duxD8EyRYSkdgR4+AKqRvnYCejg2S
         tIwQQQzGnmrATff3uqaYKtUEQNUcWdtrzUmHQlqpSQ7QcrS59+fcqMJlNb26tmEM2Kjd
         WR9ULH20cD0t5HEMWGrkk336OmsKQVzdK7oz382bcDu4CmxD0J88za8VLOJzsBM8U3OA
         IYEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kC4tq88O;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a5390si1102725e9.1.2025.06.26.08.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-553bcf41440so1196617e87.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSUgDBFKK6XZSltE+IXfJxs9DAsB/OrC2kdbki8aeS1aI4N9rC8+EH8TptF2o2gV0VF4KebFYHORQ=@googlegroups.com
X-Gm-Gg: ASbGncsELg2Xpcf8YHHwgRaZw6srzViJhDetudN6+XTphmpsvSCqD3bnvqcZxtdQB04
	11kQbouUOG3vXW4dc/9CoYPIpFfjykEj0CJUZer455cvEfqjDuJlpzgpc8ZMLWGcxc/xBsZFqRa
	HCyYKjWssTVRZKK8r/hBN8gauFWdcYIi7y1X7q57ViyHpEVlNDcdo6tLTv2+WIcbEU6c2FcMtQh
	Cw1TOwlC8JePr6LnO8oTQAb8Vsw67pT69lIWzWVSZ6CpzjtOI0ibxPk/idTJIzF9z1zqx8nntva
	eOMFnfheRPu5hbWHD75VImCycebtQ0WCJY3ewmwG3zKIg5ehkliUi+Tg7PZE5VXiOxBpwaZXvdv
	Al7q1z5vKqvCoV2B5PbAF1YgRvoyixw==
X-Received: by 2002:a05:6512:2392:b0:553:5d4a:1ce4 with SMTP id 2adb3069b0e04-5550b467d15mr132805e87.2.1750951963311;
        Thu, 26 Jun 2025 08:32:43 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:42 -0700 (PDT)
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
Subject: [PATCH v2 06/11] kasan/um: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:42 +0500
Message-Id: <20250626153147.145312-7-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kC4tq88O;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
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

Delete the key `kasan_um_is_ready` in favor of the global static flag in
linux/kasan-enabled.h which is enabled with kasan_init_generic().

Note that "kasan_init_generic" has __init macro, which is called by
kasan_init() which is not marked with __init in arch/um code.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v2:
- add the proper header `#include <linux/kasan.h>`
---
 arch/um/include/asm/kasan.h | 5 -----
 arch/um/kernel/mem.c        | 4 ++--
 2 files changed, 2 insertions(+), 7 deletions(-)

diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
index f97bb1f7b85..81bcdc0f962 100644
--- a/arch/um/include/asm/kasan.h
+++ b/arch/um/include/asm/kasan.h
@@ -24,11 +24,6 @@
 
 #ifdef CONFIG_KASAN
 void kasan_init(void);
-extern int kasan_um_is_ready;
-
-#ifdef CONFIG_STATIC_LINK
-#define kasan_arch_is_ready() (kasan_um_is_ready)
-#endif
 #else
 static inline void kasan_init(void) { }
 #endif /* CONFIG_KASAN */
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b..058cb70e330 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -21,9 +21,9 @@
 #include <os.h>
 #include <um_malloc.h>
 #include <linux/sched/task.h>
+#include <linux/kasan.h>
 
 #ifdef CONFIG_KASAN
-int kasan_um_is_ready;
 void kasan_init(void)
 {
 	/*
@@ -32,7 +32,7 @@ void kasan_init(void)
 	 */
 	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
 	init_task.kasan_depth = 0;
-	kasan_um_is_ready = true;
+	kasan_init_generic();
 }
 
 static void (*kasan_init_ptr)(void)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-7-snovitoll%40gmail.com.
