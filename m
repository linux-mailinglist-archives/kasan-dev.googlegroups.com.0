Return-Path: <kasan-dev+bncBDAOJ6534YNBBK6Q6XBAMGQEKJWFJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AFB0AEA2A3
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:33:03 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4530c186394sf5059325e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951980; cv=pass;
        d=google.com; s=arc-20240605;
        b=lJi1BAX8aSmTrfzZ5LDGxph/SdhfwPiHGYm7X3A1qWg6aqbCdFdV8w1umeP8ustmYZ
         69FttBQUzro6qGhR9DAFqrt/Y2XIZMQIGwQy+a5xFlPMirudJiISwL6AHQaOD9/L3AUR
         +w/u7aNbmZwY16aPSmD2eA81S0rDYvsSyp1vxQMjsD+bF1FLAvHFbQ11QxwWnYiD2kOq
         N56wOaYVpkqKwYSN7OQol7rDEUpn+IC/L9/bGHuLGyfugh0Cj5gF+tCjBUG/QGg1JsE8
         sxePcaL/IetV5IND9usEKCf4VkAdDTFt5A9wLZPlin5HetEy1prdypXpAJe0Nbm+ivP/
         aoeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=tzvMfyHDTtoIT1m74f72+74y5PIyZ4z9p+cjogS4hOc=;
        fh=ifMpAWAZTI8ALOewhW1JyJFC/PauNzU9cub5BxsLzUE=;
        b=Mz19rH1hog3W76UvxTRRAQbUmnzDiedF5xHomfxEVnMn/OVwz3Q/IWcNOnamJJHtul
         6XT6yzA/wJJYOv4CX26KCsfSd5LRg9rmgSlqpgykleegUL9hybUxk1fNg8sWfkKSLdhV
         GNRtZ/LJaLnm2ILsZ8Im98ykoErOUztzZ+n36t7dHRdkI+ATns2KxbgmcKgNzbdKaUkp
         nPI1QVjPc678evBBb7gXkGUF8KBv6W+oaBgpFaoZCRMnfiw496rZTZ90em0SMASC+3YT
         7GDqITPqsplFV0hdLqt/3A6vIJg9Q0/Uj2nzvHU4t0CfOfMulPmn4Ji0Q0Rshzf2PFlP
         MlAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="eUNp0L4/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951980; x=1751556780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tzvMfyHDTtoIT1m74f72+74y5PIyZ4z9p+cjogS4hOc=;
        b=arm8n4V+IGWh3QRf49t4sxsMbokTqplSlWv8xfwGo5QGtmSvkBIOwAocCRRdCYC30Z
         WKbQqmYX2GDaHwsWyxOLBiV6NW4NAkhUHcgYPrkQwHkdIH/BGdtsOuu1DqzoAy4sVZ51
         W/gPCG5VM74OTAWeB9X2Hfwk9hwa2BjqeF8PMH/bRpV9XjUeJ0m4yJo4wmcV4SpwLUzd
         IOc+fVgTZ/fPmTcCuzPItSBSj17xOQyuyLy0Ndjt6xKCS8uFUyZfd/CFjoktXnO9lVia
         3tM8wJ6My9opedrkpixau+LBEdOhIQ8mvdkJoLcsVdeh9Pa/MoAePwet8JbjoJdvzQnN
         5bjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951980; x=1751556780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=tzvMfyHDTtoIT1m74f72+74y5PIyZ4z9p+cjogS4hOc=;
        b=hn4p5o0QMENuyVCSkTcbcroM9rtj319fmvTKwWYGtKUAcYTRHXio8N5vB2rPUfHaZ6
         r+tafIp0KN1MFGZ4owQUNUt5DuGqQUUJQ18mkccR+zGxMaESRhIsXW5q1u35ycT04p6N
         L7gOpifjDnjBkHoyMtA8Joe4Pz9bn98ut95+7uExckJxPe2uowTd2JNcMxf3XGvX1x6C
         TBTmbBuCfcBWrs8o/P93Iv19TguoirPU57SoO2b5peCVvb15DgRnIZZvxOkG8CfBOPVg
         ZhTxCziDzFcsQoy7mdRQ72raS7cfd1b6KNBoL4sWPB8HvuucVrxYeRF18W+QQ3A1PBP8
         BlEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951980; x=1751556780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tzvMfyHDTtoIT1m74f72+74y5PIyZ4z9p+cjogS4hOc=;
        b=TqTsFuIsy05F7grN7W3QY5dBZJ5HKSP6pfIEdV4jpPiouIuBWLsxeqsvJ+1FMUI0IV
         0ctUtkYpsnw847+XFoOK00nGLFMvzxYF5Fj6oQOpAu7EDod2atcx5HUJnkTvMr3qusNJ
         IPN3fgAefju/Jz7lFRAucf+QlO5Mj4NK+SMsRANHEoFXrDgeVvNFcqqMM7W8lECbL4Ml
         /P3p2i7F92XUlqzFN5fawhgZf3qaiRysS2Je8omKNyCS8ySnwnFBtDrW+41osdfBfz55
         E3b17XPQVF86L/7WwbrieBodCRe8mftAI6Bz04L9BeO9hlZa+MPJ2PfQQtpZRm6Pe7nl
         r19g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtC1LxiyKXC6yoZk89Qk7fao3jZFuT79yWhJIhG1txhRWWVwazuoyB7+kh/xMKjbcb2h2PtA==@lfdr.de
X-Gm-Message-State: AOJu0YwE150nKE9QsAkOuCu48nYtyz07on2ceuRa60WDM0O5OFh9o8+e
	+/yVvf0VP1Wjo9NrD4tSRIfwZfkFQ8sgCTpz6/LG8i+fU0Q7AOgwHRtC
X-Google-Smtp-Source: AGHT+IGyqESlRb4Uai61WJ4CqM2jSzjrckCsKzQwfxGLvZ3AoxMMLEpmvA/nIoX3y709RZpQkuEoyA==
X-Received: by 2002:a05:600c:46d2:b0:43c:f513:9591 with SMTP id 5b1f17b1804b1-45381abd337mr80852305e9.14.1750951979872;
        Thu, 26 Jun 2025 08:32:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf21X5hrFgsNihk0eWtlPQnTSObslsI4RXIA61HvayhIA==
Received: by 2002:a05:600c:630f:b0:43b:cfb8:a5d7 with SMTP id
 5b1f17b1804b1-453889b4dcels7357495e9.0.-pod-prod-06-eu; Thu, 26 Jun 2025
 08:32:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU43IKzxw/bm0AgXzstAQd5HuBrhQL7fQVbzG4gGao+e6r6uIASv4ehC8nntDX5ZURaEKUYpWeI0Bk=@googlegroups.com
X-Received: by 2002:a05:600c:c0ce:b0:453:8a63:b484 with SMTP id 5b1f17b1804b1-4538a63b61dmr24150045e9.30.1750951977281;
        Thu, 26 Jun 2025 08:32:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951977; cv=none;
        d=google.com; s=arc-20240605;
        b=ZoaOWV+fSM4c/wyME352GRG70TWbItLYmritiwG/xzICl749bl1aioqIbaXIUBu3qw
         9v/0w9Fl8QvFZLhfHwxL1ZEsjeIOnaBTq4TOHlzOEKk2xkEGRD6iz50IwHUsyW5oNEIo
         lNkB5Fm39lN5hyeYNBruVARFBjiwcMFzmkIPzpDILUyYAXktUKmooZMMTEFzI+E53wgp
         gKMbV7XYzZeu/j4oVtQSEJLCk4of6YND5asu/oaN8sBgnWkgF6WN9PQsUp8shdoAg3Oc
         DxQDFAw/GqaqZDO6gCfB1bXgno5RouSE73nWnkzn/QPqKR/emZTuG24Xzoxy2dpzPlGV
         yzwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZBJYqNEFUsGcSKAGhcxt9dDlG97Ga+bpIV5ghyvlETw=;
        fh=N1g4gjyVcwNx0ttpbmTJLZZdFgsL5OTrkqz5caSMpQU=;
        b=VM6pD+BK5LP6I8vRd2bimVzcV6VJtqRRUGBWHu0w6iPq7/hPgA0xul/j3Cri5qnyrK
         8UXPgV6XyEDssxlJG54SCpUiwwsCsJiUYJeKAVOItN8Q9h02SSWf6e6hiJpH+2cTzDFh
         k9yuH+SaWZgIVy90iEnxyjCiNu3A1/URcmXyEbvnYjVNueTvFQOetqZRjIgOv/Du4R1Z
         nJzJ6ZeRK4spj0NnWV3GJGvvWG1MRATlGBl1leqRc84Wn+0AQce6nmyd308r88XEWrij
         wDoUF5qTkbX5eVOYzMe4Zc15I8Li1aTkyZfPUsxNz+koIUo4jPR4MS+jPf8QVJ2y/UN5
         KGgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="eUNp0L4/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a88c80df36si3105f8f.2.2025.06.26.08.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-553dceb345eso1130158e87.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqojDbQcF/2ShyxkoO9slHfrGlRxRzLaO6jBpWTOPtdnWqVLh0ljSU+8DDGKEckM3MPilMvC4j+44=@googlegroups.com
X-Gm-Gg: ASbGncvkEhM9/MKv/U7z8crykQWVHCNIz1n8OgkTbVtzzKo+xaMib8HEkXnfsDhIvUz
	4680aV1CNVZwidZAnXnfsZVHAxe3g/EfNGjXDVQPIowaa9cKEeGpIBrtUuA3tXgOuWEjMrZX3S8
	fEi/s8tmAoWCcRbSVvdN/5hZ2X1crNiHbG19gy97BfLj4kZHdTkCu/65HARM8ZlpUs0lb7/Qiks
	E5sE6Vl1dvLixF8DvxpGW7IimjNsCDuR75dUBNsZdBDiLFkBKv0/7oIMQht7L8mi3Ub0Uh1aXiv
	Tg4ViS2UN9m4IrAEgPcp+6hG25LS6q+A/Wt51doOnNxrFCmA+FYa+5YEAeefCjPq8dJWN4YUer7
	7efuDX1VXCZ89nDu+asIQ6eAI0UYWYpd4jgtW7Jpl
X-Received: by 2002:a05:6512:3dab:b0:553:26f6:bbfd with SMTP id 2adb3069b0e04-554fdce00cdmr2633203e87.8.1750951976245;
        Thu, 26 Jun 2025 08:32:56 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:55 -0700 (PDT)
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
Subject: [PATCH v2 08/11] kasan/s390: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:44 +0500
Message-Id: <20250626153147.145312-9-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="eUNp0L4/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/s390/kernel/early.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 54cf0923050..7ada1324f6a 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -21,6 +21,7 @@
 #include <linux/kernel.h>
 #include <asm/asm-extable.h>
 #include <linux/memblock.h>
+#include <linux/kasan.h>
 #include <asm/access-regs.h>
 #include <asm/asm-offsets.h>
 #include <asm/machine.h>
@@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-9-snovitoll%40gmail.com.
