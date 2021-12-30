Return-Path: <kasan-dev+bncBAABBPULXCHAMGQEPUDRXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 752FB481FC4
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:17:18 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf6566840wrc.17
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:17:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891838; cv=pass;
        d=google.com; s=arc-20160816;
        b=EgbeUlB7jpL3jDU0jeB8IjQlqjkiPvauWUsymfkdBoTDslX+GpcT8bIm9iSrgTrMOS
         seDmh9TbGKS7c5yq8oAQ7cKsaA6CnQTYSMRLolDaddhhsnjN4mrV2umJO+8BxwTs8uuK
         ixTP8SM2sitbCpLY9GKSpdKcMiHRyaHT82Zn32oWdjCLbiG9YfLs1tUJ0ofJhE/uEDux
         Fr+KvB5XJ1J10OdG4+AdXIRqz6lDRqoLSTMH03nCr7BruTsBm3RvS6PqGgA9EjPRLG0y
         Jt7JX25GPIlmhbrUls/qtziZ42jMjAK/d/qZo3CG9a7FDoqrpWpbIKYtRFsD+hthOgUw
         uBWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+Zp/vRvsDg4JK7W8omuDnJnSnsYTHkYqz6JqooEXUgA=;
        b=EM8SMHr0mTzh0T/94Ab43KCn5jU1A693ctqxBqcnD2dWR8oGPKLsDtMpIw+UrlSgbC
         lP8WiWuvZrwPiz+Lq454aEud0y/om03vH1WzeuvLib+1F0mfyvXaR2J1b3lgCYZaE8A0
         USXms8cZUafriddI7/bQwAb55uEb6H/llVF56q9DnHCaDJTr3PibE9zGRogQmziWoEWZ
         tUYA1FJ+xYnfVrMDmRc7a5QaW5iISCqTm27/A2YR2AklNap4M1Cws8Z8aDPm6UJFaIMq
         mIMijT86gGFUzxGGvyeZmyK/uH9anzOGojRCtWy/qeX8FrKdgd1iQnVExjjPwUIQKojo
         eNKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HptYvJTc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Zp/vRvsDg4JK7W8omuDnJnSnsYTHkYqz6JqooEXUgA=;
        b=PdK5MtL1YCdMBuavHxT6bIsxC6fHEdzpgxRX56CkbolgG/f1Lx/IuEiHlnuhDD7Rkn
         BO1PYSlm3FF7Xz+RhObKJohS/PJnTa7pyljhg0CYG+urhgCyaBINryL0ciNq8Ox2m5/m
         2FAb2ds9q+GoJLS3hdta14In/zEgqU4Q4EEzEVffg2AP2RRIIMTiR33tfmzfZj4zZ/CV
         SEoTyxxFKwQl8H+S/Mrd8pVPhF8LJk2Ado1CknOxpaGRKIOC/xAq8Xvr//fQd1xWirY1
         a3KVmOfaNzTAJ7ouNX8YvM1YZk047sKu81BcD7UQo2Mh+0rEiatluxGtJ369JJeHkFdG
         h7qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Zp/vRvsDg4JK7W8omuDnJnSnsYTHkYqz6JqooEXUgA=;
        b=YGL5XsLQLLoM4hgx29Aa9UBzv3eRMutEj4KSKmosFjx3WvkxYMWAZAj1ZrCwPTwPN2
         ViqnVqJPZlJEmiNdWTJVUf2716KYaSBuJR+RsqCQlMPAh6yL1YeeDi7V1Zml7bWnL1NU
         UYKKF+75Id3xoG4K/AZ22qikXgsz9DtuwO29eigDv6Ww/m4hsbNFRB4CpgqNO2q6nCrB
         YJei3Qx+X+60leMK7wofnc195Af2tLpxoxVxDWVxDzHOWg7Iui6OQJIADllcDI+Ru1fJ
         LyKyKUHyRCtHzqZKFXfmE4DfwhER/CyYGTnMG7h27RzosoTq8kOUfwYRNjjcMNkWU9Vv
         uBOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306lYoRgRjypir+cotKz9a8nbyev335PKo7avtU4e5ak2PiaXrN
	5kg3nfMZ6lJSoV5gibOpGu8=
X-Google-Smtp-Source: ABdhPJyY21qX0hhk7NZhjQY54fmRVqUAr4F2uj8L2shYSoAQTXkBMOdzKzxIm6CP2+Xehqy7FIrvig==
X-Received: by 2002:a1c:8002:: with SMTP id b2mr27245568wmd.2.1640891838237;
        Thu, 30 Dec 2021 11:17:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c2:: with SMTP id b185ls324675wmd.3.canary-gmail; Thu,
 30 Dec 2021 11:17:17 -0800 (PST)
X-Received: by 2002:a05:600c:286:: with SMTP id 6mr27720543wmk.194.1640891837479;
        Thu, 30 Dec 2021 11:17:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891837; cv=none;
        d=google.com; s=arc-20160816;
        b=z0qQSKwkTNsovSk2JTG7LN+nbZk00Gwh6t2w1oXXHvsbWz93dmDTzXCRVONFIdDbOu
         L7PWB782f6an4e7IuwL9pFCxRcATbRWR/zRIjmBml1dz0hRLzX3P+26wHDNbR4yBYJKp
         V+clOOSGx8jjL6mEYPH25cg2YanXYSfFBNYkc9Ml+skLn8mNZy/Uv5psi6vQeEKcRlTO
         xnQkK70rBNIrgfSpNg+m8YqUv7p4e5VFr6BbLRLZVyp+NDjdfThnWF9UNXuKTmGQBak6
         URTTs8UdQa4rk3MF0vU5eJjiDXotAvxOK2CKa/Tu7ynzdkAJ5oyy+WxUoq15Al2Xs1nI
         ZZpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3futlslnRS1bChcRGJd1vN713hfm9wuyQmsIKS3rviE=;
        b=SWWCEGtlNwv/jrslJi8XwWyvl3w9kGRiezo1xgRKKC08Waoy5UU7ICOAX66LZsx6Xn
         T6jeLG4v1cuqPd/9fXMOGTRefDmuFgcVNxoiHc6bDWB+48P9mvWvxn0tw5TKH5ZeLEzO
         1KoldUdk3GFIxMIo70o72mvOypbf0+3RKYPahCLUtFTzLS6lpzqdvflEB4TQ8/8MccbZ
         Bejmm8zM20fBcjx8u6IRQA4s6M/qApyfscXgpXLABmQb1B9IjjeC3ju06WsN2vAPHHhR
         uwVBjKRAl6d995CTm94E322qW13zWQnmj+9S4XP/xsr6FSQf/rMQ9MlOfw7aR/+HYqeq
         Tbxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HptYvJTc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id d15si1182707wrw.2.2021.12.30.11.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:17:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 37/39] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Date: Thu, 30 Dec 2021 20:17:12 +0100
Message-Id: <e9258f9554bdfa12bb1babb91a3c3936bd10c54f.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HptYvJTc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
select KASAN_VMALLOC if KANSAN_GENERIC is enabled").

The same change is needed for SW_TAGS KASAN.

HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
they already work together as is. Still, selecting KASAN_VMALLOC still
makes sense to make vmalloc() always protected. In case any bugs in
KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
flag can be used to disable vmalloc() checking.

Select KASAN_VMALLOC for all KASAN modes for arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Split out this patch.
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 3bb0b67292b5..8798c918f425 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -205,7 +205,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9258f9554bdfa12bb1babb91a3c3936bd10c54f.1640891329.git.andreyknvl%40google.com.
