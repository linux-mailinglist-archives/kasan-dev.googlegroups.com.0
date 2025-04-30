Return-Path: <kasan-dev+bncBCVLV266TMPBB4E6ZHAAMGQER6QPWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86F20AA519F
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:27:30 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3108149df63sf38304811fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746030450; cv=pass;
        d=google.com; s=arc-20240605;
        b=FnezzBzDBCwEqAW/PWPb8oHW9iKso4ivUdqLc3F0x5sNKSJguv2lo1qro5Y2yqh7jT
         0CSBZs+1qlhLxRweWbu904I/cwqkXXGZBGpiYN6jvN34DS82LJl+EnJz738wMXqsD67i
         RahyOZtW4wrrKKBtm1DunkonZ6WQg1fP5vpsWKrazt/v+tZ9hkiFhioSdXS5ZlY4IL5s
         kavOJM8VC7UnG2CGWHnxCzH9GDTkMKVLde/U8PQWsVRuJcqcGcVfgWdZgAHtYvURsD2O
         Xq0/Ykc28gT402+FRmoUl9Gp2k2bd1oqcFFIolR75SQ5LTCj1eQDTeTmAr8fPZQbaUNZ
         dJTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=sIjAzDn+M27PiE1d87fnnp/sfFGNtTJhD7djfseBkUw=;
        fh=1uQfpCvoiTSCA7GXiOcMoLBxenuHQ6SfQlauvJFlcLw=;
        b=f8Gpw9l+W5FEaJ1QQZKdIj01H0TFexsNIbPal2q3wWIxKuU1OeRzysKrzgROMIS+9p
         K2eoE1tdJAYyaZF4p5pcBC5Ttbe4Q9WkAYY0UfCk4OmVK2PlhuELo88V1rVn5hwh4zcH
         FI9ZFW/xopERIHeETqy8XqDuobKx5yVYMwUuYNkeyw1RVCpOXq1rO32R8yv/34n49XqS
         arUOYPTeWxZ9uUocxZg9IJ908REpew1zofNvQqzxXMmNIxyvB6JnOQEiJFqhz6nO6DNr
         oscvAHY/TusJ3Ljr86MEfriE3tHpM9YWSxXZQZxvEKGG4iACblHW+UgKHBteAUhhQn7N
         m0yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pB6YKBal;
       spf=pass (google.com: domain of 3bu8saagkczwoikop6b6ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bU8SaAgKCZwOIKOP6B6CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746030450; x=1746635250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sIjAzDn+M27PiE1d87fnnp/sfFGNtTJhD7djfseBkUw=;
        b=uHNJ8G9Et1f5OFw6+KImbxPOHc7IH2pUja2/CsyzpKuVZff8+BymORkJ9S8aNqlvk0
         h2cyPu6kqXO60sN8GglHqi0FQCZwrMc7dYs70LFuDKn2qEGIq3eBY7B1sPEJYY+1KW26
         5yjkG544Fi0tLqsosJzvTtOWBrfO0D+jz1P/zIUoCmbq6E3KwTnChaFH6d6RtEVmrWi5
         6O56SSXqZglOxhk8agdWQtfY76ZGlyA9qiGq95/EAjUzGnsdCf6N4jTtbdyftaX9lYfS
         WzZMLqC/1BD1UOLAexP/ZtGdPTGaads4rSgoe9R2AYWqbAHmsWmIhmOjdF0LfYjxcw8E
         7JDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746030450; x=1746635250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sIjAzDn+M27PiE1d87fnnp/sfFGNtTJhD7djfseBkUw=;
        b=rVxgmP1HflHxZlbuXRLyui/rICuoFj7cUFzq+YCjtr84uEANgQ4+rQKsd65H71gugP
         epa2UvJ5NzM4cFZzp2X+Ec6hjG6lzEJ7ErmRdLa+LJGYlFuSKscvo42yGetT0r9c20hk
         mRLx3KYa+z54kEX3woGV5haVYaBZ2u3OLgCzBm05hApAgblxCB38w7pC06A+pYCDC4sf
         08JkxFuOuh2Xzm+5vI3HOrtAqHUw3vdoZAVUzOAfDB8onTF2C4yzTCng3DhN8ktWgDXj
         /YGh/jMhKRZLZpsAR1HqJjJ0Q0kEggX+qcq6FndUngxD6RVepqYfvs7cn0CtOp/fU8RX
         oeGg==
X-Forwarded-Encrypted: i=2; AJvYcCX/uxuiMeyFHoQeFnRdm60e4EoH4f0Yu7eiwIgf6VY96fU89lkiTGmoIBr9uDWddQALiJ80Pg==@lfdr.de
X-Gm-Message-State: AOJu0YzWyTvd3mbRXYuizDaeTXg4PSaNmQiAN2+O2Sgvd+u5D+CiSzUG
	Pj3Rlfr+5+cejFZjMd4mFwyO2UNdWRPuaQnJlOaQalYlMDVsMtfB
X-Google-Smtp-Source: AGHT+IF2fN4II0f3ns6oRhBxN/hj1oC9Tns5KlrUNXijCxOJTn7bT0dMJXIP6bdD+evGDTZnA8Ph7Q==
X-Received: by 2002:a05:651c:a0a:b0:308:df1e:24c4 with SMTP id 38308e7fff4ca-31e6b2c62a1mr14958991fa.29.1746030449359;
        Wed, 30 Apr 2025 09:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFUV6yGS6bh81jo91UHNW0Sh9/+14H/eGOsHsPAEyx4CA==
Received: by 2002:a2e:a801:0:b0:30c:453f:c433 with SMTP id 38308e7fff4ca-31f79bdd341ls139391fa.1.-pod-prod-03-eu;
 Wed, 30 Apr 2025 09:27:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7dym0O+VKzpTw4FWqrK1vF3+MgVhO5pVwmbZNPSf6ugRKH/7mFpVOVCQGHbs4y7xIUj6yMfyin/Y=@googlegroups.com
X-Received: by 2002:a05:6512:159f:b0:549:6759:3982 with SMTP id 2adb3069b0e04-54ea33ab685mr1199753e87.37.1746030446408;
        Wed, 30 Apr 2025 09:27:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746030446; cv=none;
        d=google.com; s=arc-20240605;
        b=kiuNJMuksKjqWjq6MQFbRuADrvOUu8P/AREnS0qf89mkhyp/Inb2WXGfMyjFALjzcl
         yBNeh+SigDQPcROiDegmWHrKV/jEvOCANS7Oiq9TO543fn66WAIVyFehFrEjI5rIxIWv
         niSHLlrAyEoZpltKZEFZYJPYbKRIM/hV7FrUO4ZHpYGEBZ+eST/gxs4U+RwNwUfszA8p
         rHy82yWFdDtSrVPYg9hIO3y6Z0bGVQT6mVeVADbgSTT0N6MYUpecAQW3hEv3CKKWX8nm
         tko4/R+aezMANydRf0Ip/Xgw9fvNm2QV3bGtV15V7GzhkUARgkW35mK9fy62U/v3ZNox
         Ihwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/Cc1UFbHiSntYShVPXAcoplaHQWwRkP8Qvo8LnShWWI=;
        fh=bgmise1hq+xcokHptRRU6TSSidGMfzrPgZjR092hrJk=;
        b=fHH5vAK6ehPdgn/48EAD71tqTVzpY+T/RnOxIYJWoUlyVV3s0ra0iANQafKY8xsril
         BzxRM+n7Dm+9jx3C9FvbLEQb0vMmIQxtWzvJi1hN/V99tvo1U+ROYWanxHpw9RYo2vN+
         NLMvF+8aZEojunkXnPH5y+K7/FNJ2pmRntLwMV0IU4m/oN4L1nEplpXhZKbAICNDgzaS
         peW95Yhd5YNbai1UqL4hI6StCwH3hCwh8BZwNaz2nYJgfM6V6sutPGlG4qAWSOfk1iX1
         7Mr07XYgyqkO/txBYuiNF5CFoRFg21DZjsF3WDD5pf1n/HX7fHbkBuIfZs04jAcnfyNB
         sysA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pB6YKBal;
       spf=pass (google.com: domain of 3bu8saagkczwoikop6b6ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bU8SaAgKCZwOIKOP6B6CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54e85d2da2bsi418722e87.8.2025.04.30.09.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:27:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bu8saagkczwoikop6b6ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-39141ffa913so3602200f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:27:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzQHwv2OD/WLyrE8JCvwHVVONdDDUF2yYmCBMgIsqOoqusZxiGCikNUOz/TMcRELHD0tmX0l5Ej8U=@googlegroups.com
X-Received: from wrbfu6.prod.google.com ([2002:a05:6000:25e6:b0:39a:bcee:e7a1])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:420e:b0:3a0:847d:8326 with SMTP id ffacd0b85a97d-3a08f777d82mr3895576f8f.25.1746030445844;
 Wed, 30 Apr 2025 09:27:25 -0700 (PDT)
Date: Wed, 30 Apr 2025 16:27:08 +0000
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250430162713.1997569-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250430162713.1997569-2-smostafa@google.com>
Subject: [PATCH v2 1/4] arm64: Introduce esr_is_ubsan_brk()
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pB6YKBal;       spf=pass
 (google.com: domain of 3bu8saagkczwoikop6b6ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bU8SaAgKCZwOIKOP6B6CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Soon, KVM is going to use this logic for hypervisor panics,
so add it in a wrapper that can be used by the hypervisor exit
handler to decode hyp panics.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
---
 arch/arm64/include/asm/esr.h | 5 +++++
 arch/arm64/kernel/traps.c    | 2 +-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
index e4f77757937e..350f02bf437d 100644
--- a/arch/arm64/include/asm/esr.h
+++ b/arch/arm64/include/asm/esr.h
@@ -440,6 +440,11 @@ static inline bool esr_is_cfi_brk(unsigned long esr)
 	       (esr_brk_comment(esr) & ~CFI_BRK_IMM_MASK) == CFI_BRK_IMM_BASE;
 }
 
+static inline bool esr_is_ubsan_brk(unsigned long esr)
+{
+	return (esr_brk_comment(esr) & ~UBSAN_BRK_MASK) == UBSAN_BRK_IMM;
+}
+
 static inline bool esr_fsc_is_translation_fault(unsigned long esr)
 {
 	esr = esr & ESR_ELx_FSC;
diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index 529cff825531..224f927ac8af 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1145,7 +1145,7 @@ int __init early_brk64(unsigned long addr, unsigned long esr,
 		return kasan_handler(regs, esr) != DBG_HOOK_HANDLED;
 #endif
 #ifdef CONFIG_UBSAN_TRAP
-	if ((esr_brk_comment(esr) & ~UBSAN_BRK_MASK) == UBSAN_BRK_IMM)
+	if (esr_is_ubsan_brk(esr))
 		return ubsan_handler(regs, esr) != DBG_HOOK_HANDLED;
 #endif
 	return bug_handler(regs, esr) != DBG_HOOK_HANDLED;
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250430162713.1997569-2-smostafa%40google.com.
