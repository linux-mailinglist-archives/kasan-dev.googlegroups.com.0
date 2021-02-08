Return-Path: <kasan-dev+bncBC447XVYUEMRBENDQ2AQMGQEZVIXFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7608B313F02
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:31:29 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id w11sf6977437wrp.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:31:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612812689; cv=pass;
        d=google.com; s=arc-20160816;
        b=EpWKb/emlqde2HCdtpcuNH0bzWtHPlx+fiPca9dpakh9N/zuNI6S2gygB2NUAy51L3
         BYpyWWNBVzyUkrzFlp/EiqMs6U6pj4wJG4+OVzh5eiIDp00sgCl3Ofw0gUb85etaYYUs
         G5Dn7/wocG0HBL5dUewPpMpL+snBVcbT6NjCAdXc8He9gEE7jrpESGo6IHH8RrPFv3j5
         OQ8FEVFseEJfwacdjUMJSI2aSiKrYYI1MA6BW//IkeWV1aVVmfmlExnfsvf057+c0she
         e6d/kk29KMJRz2GLAtUNHAQWG+ue/bBRmdxBfchYnH51q9Ni6u3RSXMsj9+26zXpAXNt
         +b0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qMAvc9DwpVpZhNQDW00RDWqhKAm1upPBtO7rV1tgZRE=;
        b=VHlY0C2nh7GLSdbP/Fsjk8y0s4pi+GP82Ix0mEkZ4jwyWEN9j17LonNfjmAis96MJf
         kK/VfgENYbHqBrAh/xuyaOcq0Hg1hGPyMMRqKjeBnfnnLsJs2Es0iGQi4DzKXxLufkU1
         z5y51JJMyzUY8GW+WzqcqoHp3x6YikjPt4GClsoyDK632kFZKImLh4v5MoTCTWun1yne
         IpS5SFqiF11qn6/OR6/cX3+5OSZV+R4ekm2D4Hqf552IDDjiO4KyoRMGbb4XUaiTmN/3
         cFjxZS9YLMSe5SEADtu01RbbVKeUkMSmYPGgQU7SFq27CHJ6h/0FQlocpn5tuGhnnn6O
         EpjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qMAvc9DwpVpZhNQDW00RDWqhKAm1upPBtO7rV1tgZRE=;
        b=PvFE5CY95UHK/bz7kpDEAzRj0ABDAh6VYqaVZT3WvAyv2eHG7DpOsliIM/tAsy5prD
         vm0TIOK/3z7ZX6ldap/heHRgPhUyQMF6xTqqqyZvmccJQd4lIhZlzPSi9geW/8PlXEo4
         /INa6XfLTTI370riUxBJuaciVQJOXzW4zf7k5P8b0RaVywfAs4IrciPtxUbJ175/aQdU
         dxwa1y+ABCxV7Rf1bb7mFuS8oQOwdLf5Sdb5EglxhUNRKOVfVCgqJw1pFa4LZhNVieow
         v6CbvI2gBnONXGinHAA6WQH3n2bG3SubdOWHi0XSJS4VoszSSO1bUKV+lkHkXZmsz6v3
         Dz7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qMAvc9DwpVpZhNQDW00RDWqhKAm1upPBtO7rV1tgZRE=;
        b=quNbCtu0c05tlX299se7P+f0InJeemWss6n6BDrIrXcHf2PFIV4IHexFeYdPxcntgK
         36dA8FSZPSnbNdrmuRv/u4TaJ55gsqUZKTvd8vus+vT2YOpdM70gxImRjZBeFuDe72uN
         KJR9Wcuq2m+2xZw3Om5I31eHqFLywqAtSqr9kLUigOiamxF7f/O36qVf6eeHKAwXEe82
         bQlg89TdwNhwbabKkCX7/K5iwFFCFMnY+AJBagG0xtfLZtqKyhGAMOsfcaL1ptBHVTNs
         H4zsVNe41C0LwKALUxg8XDd8fl+8JVY2YxM7I1yOtsaK1wrV/EvPdPwvR4fjjP8Rqus9
         cJLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530haoE4OOjinlrEDCJa56BcujTygNA9IHfQp+lG6GXj/j/kbxKO
	mgunJIwNt82c9Deh3dBimGw=
X-Google-Smtp-Source: ABdhPJwrpVwHais7NtOR6rIcTnuFmp5/GBtOrJfE4tPwTTwG+dFi1Q0CyLXANZaO52LYBMzEQ7vzCg==
X-Received: by 2002:adf:b1cd:: with SMTP id r13mr12158612wra.157.1612812689218;
        Mon, 08 Feb 2021 11:31:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f88:: with SMTP id n8ls104767wmq.3.gmail; Mon, 08
 Feb 2021 11:31:28 -0800 (PST)
X-Received: by 2002:a1c:98d4:: with SMTP id a203mr333350wme.10.1612812688402;
        Mon, 08 Feb 2021 11:31:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612812688; cv=none;
        d=google.com; s=arc-20160816;
        b=NDHEMwcFaGjFxL4udSwbM2MSdhsoBRo+7CAhbZjvBXCtzMJ1zfPbrQ6lxlSeausZ7S
         qOabDRLIxLzqfcnVQOmhSorCMrKOpMQTpSPH5/5xArlHkkz8Jw21j1kRNGvO87Uh3HK8
         xGvjS1KZGVaPC3Fa99A1aTezgCjRhNLjcP8xUqq4gFV8/r3zug3WfVTfCuhNtbenpkLb
         oXU1FwwJIi6a4NslHi9OPk0EhcHro1FlPgkxEmEBlklTPr/D/iDdg9dHQFue1Rd1Px0N
         rhzD9JvZ1LR7W/VIXAxNz7YJtKIer+4RlSVpl/mfjjDWTzSXoeRH+KEFr8HBrvqburU1
         PYUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Nt08x/e1M06EURUD1LXp/c05E+0vYqfCV+k39JTMPjY=;
        b=xbyEh+k69puc0B9xRbmLNHGP47Av4wMnWKMUXmNVPCewiydRCsHP6PeJI0X4WvCofw
         rGnbkZ/5/2IA0cj+bUD3Vyq5LR4hQh0w5Ov1+LWCHk5harZXeLcZkCeSW4IFusVjzeBf
         TKJD0s5bTt32pIX8QHu6pH96ciu9B96xFOe0uGVW8Crh66dlMpLe6EUls4Szx0NP9Q/V
         aC2X14RJcX5ludjLJfNSLX1c2YmDnDDZjLuBOZ7lzm8JCikuP072fUCuk4R4CPvtFjQz
         nUTBNuN5RpnhAlWWx2HRF9nOMnz5tVzhDDpv6IdFfHVex5QDPLq5cRXP7JnnWq4MdqFn
         5HYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id 201si38560wmb.2.2021.02.08.11.31.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:31:28 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 916D420002;
	Mon,  8 Feb 2021 19:31:24 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH 1/4] riscv: Improve kasan definitions
Date: Mon,  8 Feb 2021 14:30:14 -0500
Message-Id: <20210208193017.30904-2-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210208193017.30904-1-alex@ghiti.fr>
References: <20210208193017.30904-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

There is no functional change here, only improvement in code readability
by adding comments to explain where the kasan constants come from and by
replacing hardcoded numerical constant by the corresponding define.

Note that the comments come from arm64.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/include/asm/kasan.h | 22 +++++++++++++++++++---
 1 file changed, 19 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index b04028c6218c..a2b3d9cdbc86 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -8,12 +8,28 @@
 
 #ifdef CONFIG_KASAN
 
+/*
+ * The following comment was copied from arm64:
+ * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
+ * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
+ * where N = (1 << KASAN_SHADOW_SCALE_SHIFT).
+ *
+ * KASAN_SHADOW_OFFSET:
+ * This value is used to map an address to the corresponding shadow
+ * address by the following formula:
+ *     shadow_addr = (address >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
+ *
+ * (1 << (64 - KASAN_SHADOW_SCALE_SHIFT)) shadow addresses that lie in range
+ * [KASAN_SHADOW_OFFSET, KASAN_SHADOW_END) cover all 64-bits of virtual
+ * addresses. So KASAN_SHADOW_OFFSET should satisfy the following equation:
+ *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END -
+ *                              (1ULL << (64 - KASAN_SHADOW_SCALE_SHIFT))
+ */
 #define KASAN_SHADOW_SCALE_SHIFT	3
 
-#define KASAN_SHADOW_SIZE	(UL(1) << (38 - KASAN_SHADOW_SCALE_SHIFT))
-#define KASAN_SHADOW_START	KERN_VIRT_START /* 2^64 - 2^38 */
+#define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
+#define KASAN_SHADOW_START	KERN_VIRT_START
 #define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
-
 #define KASAN_SHADOW_OFFSET	(KASAN_SHADOW_END - (1ULL << \
 					(64 - KASAN_SHADOW_SCALE_SHIFT)))
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208193017.30904-2-alex%40ghiti.fr.
