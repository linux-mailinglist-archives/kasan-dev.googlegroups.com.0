Return-Path: <kasan-dev+bncBDAOJ6534YNBBJMO57BAMGQEEDJDA6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 35E4FAE7E1B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:45 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-32b460a1aa1sf32267721fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845222; cv=pass;
        d=google.com; s=arc-20240605;
        b=OC093cJgE7w0Tvbc/In4bsRuYT4Wpbpepnncio0PqQEVQ0T5pZKhjq39/GFwOxpmMS
         aCCBe54D/H9VkJn7yYU6BwCc/0Tys0c1bD+vYZWA35FLtMuHGjbEDlnPsld4vatwkLAM
         kejOPDCuNJdMoLugYD50QAGjsJAPnwkvKUEqvcg9UuJVjDG6aWIimoeTS/jaqbrEPuLt
         E+L8Htyw0lqFPhmYV+c129cOMPkqWuup/M3+DOvtTCRsaS1S9phh1yYt+fPmMwuqaxE7
         j7/JGSUHJz3nESXeOZAUMLWHj09dzH50mw5E/BJhhWY4Ch+RzbZe4LwuFV0ys95K62iF
         Upjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=xezMrRQ0K2wjciAYIXk1opJo47n6gGObkcglN66fDnw=;
        fh=j9EhpL1fTFESF1lWb5piWKHGUG+bE+B+ZFSQ2jnv4Yg=;
        b=JQVqly2iS/bVksv/83hi7yQI1KJRT/769PyUtQ710cZr0OF2gDEsnRes8S6anRisGh
         UUWuJCfqjrJnIx2lMm4KjaeyGQc0Ew2QATYDCIRZBtfpTOCiahT6YyIp7NyEft94W84j
         kp7ygyRDG6rnXwUIPKqxnjst6IM/ioop85AwDXAi69kbwOleY7kHmX4TqZEfeM89oJo8
         YyYHPBTWcnxuOEp3r5CRONG0FXzCuhbs1pUKNnk4mFNJwaCa0h2Wvevo+yPRQ3rrEHvO
         tPqP8MQgaPoVkta7g7OTwzHN2gMWNRoK+tRD3SGPAyayrFAOhZkJiBniy7AAHk7nnons
         zDVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UvD5SwoY;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845222; x=1751450022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xezMrRQ0K2wjciAYIXk1opJo47n6gGObkcglN66fDnw=;
        b=Ci0LvxIf+3n1L0DZs3TKdc7pwy2NOlfaniPK72Y/sCbMIecqUWdct+kmun7om21S4o
         QGNcnEwVvkU+49bZU5/W4FfLpSrzeCGPfkeXt9tZ5VHLIusxltaKFIVr50DXfpfv2e7B
         CQVikmhpAAZNP8wILQNx06iLw2LVuT0GsTv5+AnljODDidhBxfl36a89BWQOD8ocuO6R
         Cb8KAYaKLUK+0QlYSWPwMHj2DSzc723VnB2PyO8mLxIt7wGSZ/ay8IkqEBHcNrxU1vlf
         pNzu97rX07RjOD/Zs6ruK0eqMpIU5AF9YDgmj1HqPty3nZrJjdqIZgxtRgz3LLJbvNa6
         rkmw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845222; x=1751450022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xezMrRQ0K2wjciAYIXk1opJo47n6gGObkcglN66fDnw=;
        b=R3MSzrJjBRd+4dZ9u1n+c40dJU+gKenu9tn6LI3j+PYU610r01cwvXfTXs05h9XhbK
         4+XoRCpHPrBjpAqGFICSlCJuviBWgNv0NnnIZVAvepCTBaV1F9u83fsvNh1MSTDBsb0t
         r+4qu7T1dy7q0sSu2NKBi7noeIELPUstpiUJQIDigERfXdaOzsbjxCnkd/nyJznuTlut
         FsgmOSuvmYQVSMZpQh7L/KtG/2R3YpRynCPqF6Dgkm1GOJmz64HmDZb+Y7tg088x5zlX
         n6uRXYqsbGd6rTHayL2mX3a1ZOLBkCqW+tkElbh400G9m7NOzBJRBqT10m6Xykr2tu2b
         RKJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845222; x=1751450022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xezMrRQ0K2wjciAYIXk1opJo47n6gGObkcglN66fDnw=;
        b=EupXCMzj4Kd0CRCo/HnphR0GEmhtYB97JlNii9JhYn/y08AN1XIYLCPMtQ3jfnkfVZ
         a86dOT4bKmPwzLC8CyU+7nMB5tAcUgMTXVucGnJnDBZdTJnhwfUxALh+xQH1Na7JXT6J
         mfjMHzzWCQlJt4VNnp15S3/nGfBnPkxxqkN73Ndoj3G4j2fuX25RyKnK3pPfgJu6XLsO
         h809xvAM/3VYRDNwgie4cVa072+KmWwgg0twnNjhalz1Yjgsv4VGS+nUUdD4e7OHj/Eg
         u8OZdureJpeKcXr9+hKSwmha8U7whLvAn8hpJ+zZeJpwKsgZaazrGqXPREteG9JKH0Xy
         cnEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW59qjI/XpsyHOMDNRQp82vz94k5BeNLc21AvJq3fGsA2+umZos/QrtS4sgL2GHtooGht2ysQ==@lfdr.de
X-Gm-Message-State: AOJu0YxQEvEzrodfJddytFu/mLUG8AZmywUbDf5OB6CoUq191POE/CXx
	uR9DKdbjZa28MbJRY6cbmecVZ6fim2ELEKJGLz1b4IwIxjiSwRRHRpwK
X-Google-Smtp-Source: AGHT+IGHSVzSi4s+njYXxAfdcHebLxCH6N58/RSSbDfs+IrQ1tLYeRE8l53tyVg2ytlgfsl0zMpdvg==
X-Received: by 2002:a2e:9246:0:b0:32b:2f4a:35e4 with SMTP id 38308e7fff4ca-32cc657cacemr5183531fa.34.1750845221864;
        Wed, 25 Jun 2025 02:53:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdC33909gBQ+1xTL57LBmQVmek+V80cjcnoYZpiaMl18A==
Received: by 2002:a2e:8a96:0:b0:32b:800e:a2e3 with SMTP id 38308e7fff4ca-32b897423f2ls3458081fa.1.-pod-prod-06-eu;
 Wed, 25 Jun 2025 02:53:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+pT1Bid9rF9pt+6xsUWRue0WPwxaws8pChiPnKzFZHOFoNyKMWyiG6/cjL7b+4xnHTATeqpD60Es=@googlegroups.com
X-Received: by 2002:a2e:9b0c:0:b0:32b:76fe:134e with SMTP id 38308e7fff4ca-32cc652328amr4778221fa.23.1750845219364;
        Wed, 25 Jun 2025 02:53:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845219; cv=none;
        d=google.com; s=arc-20240605;
        b=e4oxFTbXrgFQ/o7bQHmie3h2npaAOSkjqu5YRf3l56ea8dI5SFnOTMmqWVUPrC0Nk4
         02K3DEAIASgNabTkBtpNBWuZsI2zLuUiSnQpWgxo+ht3JF0vB7ZulErWlNaYmqFXz2Dg
         tfa3368EB9RUjxyJRkPQDv+3zzHoX8VzgdO3i1Cwm+iUBKpBAMnvKSKCQQW/pIxGvc5q
         app7qjJTX63/B/Th8mnAH4hpHdnvankOZhNnnywn5wTkpIydF/mSywUPCgfvlZry6Jxy
         EW1aWjv+2gPTxX+fB1tJPoz2aWfe7Hjp5sScoGu5K4cIInp6PlxMDiC6yhLBCUo292lJ
         pHVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ovwzGubQ7EZCWb++7xcfiusg6EJnFDR8lh6aTJ/PpoI=;
        fh=cH8MFpyfI/I6kp20/xSsGsoQ38/SKcpuTwvEoIBetao=;
        b=P5q2mvh173TTdzKbxGfqmDPOjIlwAciBTiZPnAGWm7ZZgFmUjFO3S1jiSCNXvZ2ykw
         Dw+iMQ+0kHByhiZWulG4kDTUSX7vmLr1GtEBwDpmb91gNGH0xVARMa7ULwQkzn5WtlhN
         voG8SJm87REV0qwCa4LhocDFlC1GXDb+6QFDBRAL1/oT4S2v4FEkT1XkTE4oHxE6b/vo
         0F9zQM76DcZXe/m/sW+2V+B2gwn4JHy47gfn9/w3Xr+rB+RyBaS93ffs0oDk8AcjZScz
         PK7rtGAESDQ2AdbTaOWONnGqneVk0/fTicwePLzF+hRGnYG9iQzHT1zlafM55txw7NUd
         PqHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UvD5SwoY;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980d3316si2452991fa.6.2025.06.25.02.53.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-5533a86a134so4735994e87.3
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXrnTRMQh9sfGt3Yoe9vjwUsU185+GlezhX/E6HMAjxXH0f7bXKCO16gLnt1mfSXmAoExrGEtBHLJI=@googlegroups.com
X-Gm-Gg: ASbGnct8P8+Jcd53THzdrmzue6SdBYUpC7A1dF14yOGsCLr/KNh10rXS1bcHd+OiNPF
	QeVib049Tzo0F1eDbe0rM/VGvllvuTSiJ3X+Qc8gxbICqrT2MWRrO6e0/3fbYlm2o1Wr/l4vqFt
	/j/Kjnj5PX5PDrwebRfcQUXHsXVfthab74yRS2EnzFwBe5bjDitY9gFVamgSg15tzN+QnBPlT4K
	40LCY9okSYQ4gEnQo8OM9Ji97kR+6Qk9amU0tFrFoSBUopM03oDghLlulh3g+L4/mnsbjQ/+xpn
	el3xy3Ra5zxIFNp770EwiKWGVv/XXoJZUrDd/zP+d4ZbTyc0dh8kT63oGOgZz38b8mlD/ScFpuZ
	86FVKe4OJwXuGyCwZ8cNMcjT35TUWgw==
X-Received: by 2002:a05:6512:3dab:b0:553:26f6:bbfd with SMTP id 2adb3069b0e04-554fdce00cdmr639671e87.8.1750845218713;
        Wed, 25 Jun 2025 02:53:38 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:38 -0700 (PDT)
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
Subject: [PATCH 9/9] kasan/powerpc: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:24 +0500
Message-Id: <20250625095224.118679-10-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UvD5SwoY;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f
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
 arch/powerpc/include/asm/kasan.h       | 14 --------------
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 2 files changed, 1 insertion(+), 19 deletions(-)

diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index b5bbb94c51f..23a06fbec72 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -52,20 +52,6 @@
 
 #endif
 
-#ifdef CONFIG_KASAN
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-10-snovitoll%40gmail.com.
