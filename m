Return-Path: <kasan-dev+bncBDAOJ6534YNBBFMO57BAMGQEBCICDOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id CCCA4AE7E17
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:29 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b3ce96f8dsf28974181fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845206; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVANhlSDrz3HtY1rHqVCTn4NRwGeFhPeh9aC0K4VOmChaikN+eC50bDFiKyL7vDfjR
         8ExU53f3ITKjXYk+Ewt/8epliOk7jf7menTx7P/1eSz1ktUVofazwY0M7RKcTWNYeIg7
         CbMvLbNxHekqd1n+Nip6B4Ofu+i1Dd0lFrARoCCZGdEk+NgbsOjXaNHJZ6uR6U39PqUj
         bCvWVpo6ntV///13hF5Mtut6ZAQvI2u37ydOYoWv4FrrChtw1kXXZKwASFvwD3hbR9HD
         R+DaX6eYDyZ52rgcJmy7GD75q5YDQaltgXshfnh0tlq6eB9U6Kt0att7gz/WXdyH5oBY
         AXiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zwCXZTa+AX5f2zyfeKs4L9HT7CFN2gequZ+2VYyL7z4=;
        fh=mfaMpHys/QEfPUon1E6/yuK8Z5WRWGibRkwg29AcHKM=;
        b=cOjihEH9tMGR3SRKgonJGApNQmBQoJtFlhhY/Tcm90+PDa8uFxuCgvAukaRMZ1fUg4
         JnpqgKt5IvTRadaeR8AoJEunN1ga4QYKQ5K5XlbbvMljCpwP0gW7b3BxBIeLgxBCWN4v
         MTp0IfYY3Vmr/NmrnNJcq7MlHusTTPKyzHdmWL8u6C/qyhn5Mobs7MrTctNYDwWCi9yR
         uKs5iLAUcUNnvUX7U4wE1HpSCnwzTlY10IhjLGw9nGswqI+EZ1ZTJlb0Kr/iIJBaHx5Z
         9bWeYEbBeuOAn22++WHofKoR2Nkk/pDP/Fs8cQddrEF8zxUr16yg+Elle4q67j/bwWw/
         5J4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e8Ao2GFP;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845206; x=1751450006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zwCXZTa+AX5f2zyfeKs4L9HT7CFN2gequZ+2VYyL7z4=;
        b=QsHirjAmKvqjgW5vTbwpSmrlZGry3l9o1c2kwvoxmXbWWh6FgUbSTxgscsUwjZFHAZ
         KtQK8AukztKH/OVQa3SpC9PORbwfY/BLx240qaUSWPw3Ot/QsicaNVHW6TlexidvIAMS
         ny1E2NrMqbnzUMpBOZwN19eWVbO/9D9r4+G+g7v0Qi/k9k1qyIr+aB0HFPN4We+gxBL0
         E18fPVjwp4sS/ZVuCSwReVyMk5qUtWJK4nmB7riW+hCST6rM/R6I2/aaMXl2OAB8rNWK
         lRBYusbhHDAIEr2SXFGY32ejaIBlT0OLQbFR1fW6oLaGwiEjbEuFW0lnArMUB4sxTGXz
         N/3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845206; x=1751450006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zwCXZTa+AX5f2zyfeKs4L9HT7CFN2gequZ+2VYyL7z4=;
        b=auwgX6W7AEjQ682g6jgB/jhhaglC8AUrXBIqDJWZVlY5EC+I8/ZKTT87+FlTv7gHTo
         c6IY25xC/lJvscXw6oAfDkLSJgdYewDEb8ij8+PzfodhZlK+/jjcoyFkEBIeWxfXAieH
         UPNQVrf49AGtV01GyQOxAEoVZSBiTBLVOXzzbCi8AtmW0NLkdkPW917kMq0KgAJnaoMp
         TIcPKbAc/HHPHvwNTg9G6tUCzKQlq1J/2cgsBrRU0e4KQK3Gp426ngePN7ZMKDWfxRM1
         3y8pumh0AfqpC4FCh596eHhRFyowT7LEi/ftDlRh51YS7LZs8+TgZ6jYfBYWTdgJ3B9E
         Uzmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845206; x=1751450006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zwCXZTa+AX5f2zyfeKs4L9HT7CFN2gequZ+2VYyL7z4=;
        b=pwETbtGXz1FlxHZZY95teqx+6A+LSl+/KgRu5630w32SF2k2xczv87bqTdLg9BYl4j
         4zP5ZC0gUwI3y+hMQmmRRMpn+9aUC53LDqaFoWUfw3N9jqJsh01JKwsgupXcgDP9e1eG
         W1TXZlNEAr8nRQkTkFyYaxtalz7rj2S4rN/XCew6hWM5IxEi670HXSdD840B4gZtqaL+
         6t4JB6hTsbPjrX3quGZBXc1tqefLPnbu3RKhEWXIArn3nGQZNPiB8jIhxOxCoOj6c56z
         ocRUXNawqFiIIkcRLgahq/DWKzQ6FDBrKzW68BYpedcyQ97TMv8NFZzTGh+tRg4uE1Sh
         02Hw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWXUUYsCqEyGTLktlD+BtZzh4kfBu6a1DQmfSSpu7vJWyETRAptiuNEOnVJ3rVycPNIMaKtQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAzDhrkVgzqDEmp4PpJPUzhxRTBW+uDj4cNUgwScwvWu8rWvr7
	2gbBLCLYfWb3eJ8ZENeBfX/pHgZ6KSWQtq5HaMH8O1dLKf09CwS5SaiG
X-Google-Smtp-Source: AGHT+IE23LByKNdSrOWw3Sd0WHybaMNBKWf5b9U3/8lQugiAoJLBJahv8m/+bNsf4WMCIrsUJIsM9g==
X-Received: by 2002:a05:651c:31a:b0:32a:7666:80d0 with SMTP id 38308e7fff4ca-32cc6547681mr5455521fa.23.1750845205903;
        Wed, 25 Jun 2025 02:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe+zVvOPleSVhil4GRfrYvwWgYK+pvGepIb0bRN/k2UWQ==
Received: by 2002:a05:651c:1688:b0:32a:6413:a9e with SMTP id
 38308e7fff4ca-32b896fa66cls12371791fa.1.-pod-prod-08-eu; Wed, 25 Jun 2025
 02:53:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4U96XHspZ0WHe0Zn8jvCAjqSXu044H0nrSlvLpYVpjGmBnkVDZQoZTPjCpyNcc5OhmesSf8XehSw=@googlegroups.com
X-Received: by 2002:a05:651c:4118:b0:32c:a097:4198 with SMTP id 38308e7fff4ca-32cc645ec94mr5237261fa.1.1750845203426;
        Wed, 25 Jun 2025 02:53:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845203; cv=none;
        d=google.com; s=arc-20240605;
        b=TDjl8utGrur3fwJY5EVjlOzdFxeaiEWdXsA2QrU/rwG6KNB+mL8kEg/XlHwWUK5mDS
         tr5dPvi+VVPT4YaA5fs2n1DDr8TzrEvNw2aNMx7CQYWIyhC/3kTAf8b+Rf475Lz60CFM
         X08JiBnOItQWnSjsfDpQPlJs0dz1l2h9NygovK2eTQsnpsPSfoZ2XoOWcXKJWftDmWhG
         pXs6hYkOcbXOY1NJoCr1WHg+vn7O+VmRQHFn5Vt4VjRHabnw6aVxzi9dmwtp2B7vYtf4
         wTDRHYDVsmsm0uVbNf55NRM5IPwhx+v9O9eq52FNHjh9NXaZVYUOBw8zJix1fXlvTIrL
         CzYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8HfJTJJcJZY7/fCA0Tiz5Rc62kUV3pDrNC7eedpHA74=;
        fh=2c3HtM4l2YnUX+/8PSl3gEcD4gfeQ2TBx3OuhSi7+8A=;
        b=EkZtRU6w//5S+QsW2YRzGg6SCVFPv0mKXj811qiZdckGyFitu/qKwQnztZgOPO96Qd
         zLU1kTd1EEpssJhROxq6RjKO3AK/uDZK5XWV0JPiQamNAhsT1ZpU9+nfrMBk1uF0x1rT
         F6wLWRTTMxNYjk2GJ0/Wz0kj0sj5xMrmx9IxxKWjrFZQR9gsDaROdIJLGcS8I6lL12g+
         UsVKknW2pNiov8G0BYuX7uIFu3NwqMgFscw9af7WizIbTlaMNGs5WcXIogONV+sQTkv6
         JIVEgaHl8vrb/XnVsyl2b6qHDRBfhmbXZKdTXgjufP9o6VjCeKahXEh6R6v8sp2qZNBX
         QpdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e8Ao2GFP;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980a016bsi2697911fa.3.2025.06.25.02.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-32b78b5aa39so65437291fa.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrGuX9ukklEoFAmBG98CyR1Gnem2kFhsALbR2JJFeZ2rMcmXQdx9ZrxftTmfmF/WQx5nCsjC74+B8=@googlegroups.com
X-Gm-Gg: ASbGncsBBlPDEi6fFyxEIVtkH4qCvkpQ62I0tuuZ5ox9EDZlhUJRf1JrnAxNg9dDA+O
	hgzW5t7mOF5Wg0AArNs9rwniM5UeUkfbSiyuVKY7jWknQ8bHKgekz1ZO+2Fb7dzkJmvj/pl9twm
	teMAEa1IprpdAZgQWrT7uYDxLbnpPiG0L2CyvN3JuO7NwWzTp+4ZOR9f6pSZkFhQx5Y1FfOuTK/
	kbof9Pii6PdIvffa6KYyumJ0UYnnRQW+SkMbZhhbtNE959nQhrJ7X+J/mnNO8aBGWaMcYb8b5Sf
	Y9NMgRHcF6a/h6p3GJcrHvGL4V11Zq50zQonbqwAmQqRMLEDA3Gj8/lrqPJtLRW8Tj9++UFuPQR
	h8qee07CA4tuBbUIT7wIgFkmJCj0nbA==
X-Received: by 2002:a05:651c:31c:b0:32c:a771:9899 with SMTP id 38308e7fff4ca-32cc648af6cmr6208261fa.9.1750845202774;
        Wed, 25 Jun 2025 02:53:22 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:22 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
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
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 6/9] kasan/um: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:21 +0500
Message-Id: <20250625095224.118679-7-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=e8Ao2GFP;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229
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

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
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
index 76bec7de81b..2632269d530 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -21,9 +21,9 @@
 #include <os.h>
 #include <um_malloc.h>
 #include <linux/sched/task.h>
+#include <linux/kasan-enabled.h>
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-7-snovitoll%40gmail.com.
