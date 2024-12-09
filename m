Return-Path: <kasan-dev+bncBAABB3FS3G5AMGQEOFUSZWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8617A9E894A
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 03:43:58 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-3eb600a39b2sf21392b6e.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 18:43:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733712237; cv=pass;
        d=google.com; s=arc-20240605;
        b=IGLwpbbgmVQS91a/aHAPITdzl6tUraEGWxpFUD1pG0CjIhGNylDh2FSW6IEzRQ92sE
         UakTBsbmlWJ+5wlyCMlVpSLWBvM7YiNXDAU0O0hRGeAuDfobvZhCl49aXl7oS2r+p8gq
         LHGou8smLCatR4Cur+Tec8IuXTi5MJ3SDceG20wGmZZAjUOU4v3FANeoLYnxROOlPJ0N
         7AzkKSZ9Sy2o9Cp6kaFfDWlxxHA0Pa5AfyTpJ7R3GHi4flIWYuehp6Za5jDtos3oXq84
         OUdhzcz3VcY8C5xWxYMrzM6a2Wky97YlNHwo6OLnC01uLoNaaANoo3L0Tg6F4UWXUwsg
         91eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=n4N8QhjswgBtjmha9TaURDjigiNRsif9MbIaDbWKNLE=;
        fh=eneYqrhtvpjNFCd7uUI3e4APuogzOoNDXBrktlAHlA4=;
        b=jN545vrVxWF4ryAVhd7ZwjQwYjAuxzyScyeRmd6VzwE4qY444z440slCrc3WT/E7Zw
         xZlCF8RYiLn/HEr0GvystNe6QAJ2SN48/q8vZDbZmGLwBEqpeuoYOzBCYQEzy5chucYg
         FACOODWZbrqmGw8N7BpzjlDRk9MkamtczLSlF4qXo975cUtVJGIgdCaBVu16RVmKKcX1
         mwz1L3KXTzh9DXylsgQzetmIdW7UciL5mes29cIm/d/zbgGNhcLR8pMQd2Z54IwSwEkd
         3QoT0vQv0p9ndgaXaZYcMYz0T2/ckMtlTiS2wSqQMEX5K2YKRItHb621j7Ihx8IEmF3L
         0QZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733712237; x=1734317037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=n4N8QhjswgBtjmha9TaURDjigiNRsif9MbIaDbWKNLE=;
        b=nazsHKyrEkJu2Y4Ra83GJNZuH9nF3U9lVW9lJDkxBakrHZpA1ZDLCAfqycvnkLq4Uy
         9tPPBEro3G5b5JX5ymuRhPCvtjHPo4rRBv2G8eYmLk4geR24NgAcQE69GxMMIhYojz3j
         cxRY1hGdON5Y5ZgZth1bwv7/qWQhXUxW+L2iOApbU5zQIc6T14S3zZNdiL0zFsXBrQV4
         +mYbVPJnfXj0zXEjDmj8LwgnDZtOhrgf3tp1mZUgljq6Ljrkhiw133bvP6p2OgEiwO1c
         mtzvym6DbRUo1p7LuFjAv21Z4DOXHgzWHmh9z4jDbC0ZOSPcX2CAswwiHYnfZYjzGKcA
         jSbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733712237; x=1734317037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n4N8QhjswgBtjmha9TaURDjigiNRsif9MbIaDbWKNLE=;
        b=YpAxZzgYqcKpsygUSBw5P/c8enxU0C384M8Cl2uAekPiyOr7pdvU9Mg0htzjLbFVc6
         FydW4vj88PEeRk1lOKpgG8JwgpvSyz5koRf63vvjJDQ1Zqhj7BQdVtEeYD/Ex1wtYKOM
         /9oVJVouOVX6O/25S9CcGhntJwzJqMjnnvfkJqvmNfRlTBq61uoz1pzkfI+5KerHfOmu
         vSqKjRSFj6tFsG+lCHNVsNvt7kO2q6mk7Y+4yRa/669xmNUmKzQMgROWpjWR811VWb6b
         +ooDMkHPajzzbCf/Z/Ab++SUv8KvCBeuMIB1WCQYOSpCWrwK7QxHhmy//r+619G0hiCl
         FTOw==
X-Forwarded-Encrypted: i=2; AJvYcCXkzNfNK8Nq+OmfTiD1bEPs5OlhtlijVaVr7Eg5/ulznG2MAwWRoaC+DKRwNqFxwbEaVnu9Xg==@lfdr.de
X-Gm-Message-State: AOJu0Yx2nyx77wC04+ls13RTeHNB+Ot578mw+1Xk/w0g4e5IKW934D5Q
	Yy90PMrgE4P6Wg2z9uu+NrciISFGsefbhuayU7+j64+kSzYf7Trr
X-Google-Smtp-Source: AGHT+IGOsrYn1xZ1EPHLhPvRB7MSDG3VPC6URgU6X6jmNFq5a0UhH2v6bypkCZcs6SDbmaJzaoaCFA==
X-Received: by 2002:a05:6808:2109:b0:3eb:4189:4432 with SMTP id 5614622812f47-3eb41894cd1mr3144330b6e.36.1733712237002;
        Sun, 08 Dec 2024 18:43:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:a89:b0:5f2:bbe7:601c with SMTP id
 006d021491bc7-5f2bbe7670els81815eaf.1.-pod-prod-07-us; Sun, 08 Dec 2024
 18:43:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6cRjivbqcj9jlbh5uBbnUwP27HGhpU5iuXAdyXW2RvZGv2+DPvNa3sxL6JEtgZ7d9IOIL6KLty3Y=@googlegroups.com
X-Received: by 2002:a05:6808:d46:b0:3ea:63e2:1aa9 with SMTP id 5614622812f47-3eb19c16946mr9887259b6e.7.1733712235987;
        Sun, 08 Dec 2024 18:43:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733712235; cv=none;
        d=google.com; s=arc-20240605;
        b=Lwirdhglib3tUgQmLweBYV15t1FSbhBApKRn/YIiBUwcxY3qN4hQKPyTriN0TDV/jM
         uSIMakqhINCTesIktbbjzZyFXM65Moz5bIJbXGOTBCSVQyRtq4uKJB+HaWyLLw2mONaM
         jdJpZ+ZKVowG9iwn97Kdu2FnUjM0Oi5XQM5fPmc5TI4NsMkmrDTcmlHL8DIygYgTobBe
         1lc4kZ+N+tbSolcEe75HoW0o5f+ofbsr1qVMcg4u2H26mfsUynk5uxhHurNuX07e1r51
         YWg74O9WVsxH+4oxHXHw741kLrIJLTEdtGedF2zJXRN/hWlZ3+QIYE9SF64AB58q8HMn
         4uVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Dl98tFGY+rPyC8FqJPKFVEBdvlsf0WDTKEQ63I8mg4k=;
        fh=zBWha3m7j9g4fOlI2Dk54gN6qyAThRjo4Lp4VAY4w1U=;
        b=LgAwV267gCx6OZqsmP3EgqKX19+GBjpfKZLctxF4mVSZN5CDSoIQ1j7APj0CunXwzU
         QO083r6e7UMzwAUk3U2BHp/Ma0PXr5uYX1VYvP412XM3T9E7x5SG3dKipZszxhWFR1uX
         YZcg2eq3CkwHQW+bOKQHZuyO0tv0zDZakz+VeLt44HPujJw89VXB6NMu2kdCCQcQn63L
         u6OOrWVCCTu8iL0vgxClH5bmDewc0GOuRsXGK41fzPMTMzjuCzUE+ao7zhzFSrtnel5F
         3SaAgp5p4epsqNET69gd68Gg89zL0rgKNfl9gXajcALoaYC+C+2IVGgZfxAjgBxpQkzE
         pfug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga07-in.huawei.com (szxga07-in.huawei.com. [45.249.212.35])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3eb4d1618desi69407b6e.5.2024.12.08.18.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Dec 2024 18:43:55 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) client-ip=45.249.212.35;
Received: from mail.maildlp.com (unknown [172.19.88.234])
	by szxga07-in.huawei.com (SkyGuard) with ESMTP id 4Y65hT6ZTFz1T6l2;
	Mon,  9 Dec 2024 10:40:57 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 483AF14010C;
	Mon,  9 Dec 2024 10:43:21 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 9 Dec 2024 10:43:19 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@Huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, James
 Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Christophe
 Leroy <christophe.leroy@csgroup.eu>, Aneesh Kumar K.V
	<aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan
	<maddy@linux.ibm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v13 1/5] uaccess: add generic fallback version of copy_mc_to_user()
Date: Mon, 9 Dec 2024 10:42:53 +0800
Message-ID: <20241209024257.3618492-2-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20241209024257.3618492-1-tongtiangen@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

x86/powerpc has it's implementation of copy_mc_to_user(), we add generic
fallback in include/linux/uaccess.h prepare for other architechures to
enable CONFIG_ARCH_HAS_COPY_MC.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
Acked-by: Michael Ellerman <mpe@ellerman.id.au>
Reviewed-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Reviewed-by: Jonathan Cameron <Jonathan.Cameron@huawei.com>
---
 arch/powerpc/include/asm/uaccess.h | 1 +
 arch/x86/include/asm/uaccess.h     | 1 +
 include/linux/uaccess.h            | 8 ++++++++
 3 files changed, 10 insertions(+)

diff --git a/arch/powerpc/include/asm/uaccess.h b/arch/powerpc/include/asm/uaccess.h
index 4f5a46a77fa2..44476d66ed13 100644
--- a/arch/powerpc/include/asm/uaccess.h
+++ b/arch/powerpc/include/asm/uaccess.h
@@ -403,6 +403,7 @@ copy_mc_to_user(void __user *to, const void *from, unsigned long n)
 
 	return n;
 }
+#define copy_mc_to_user copy_mc_to_user
 #endif
 
 extern long __copy_from_user_flushcache(void *dst, const void __user *src,
diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 3a7755c1a441..3db67f44063b 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -497,6 +497,7 @@ copy_mc_to_kernel(void *to, const void *from, unsigned len);
 
 unsigned long __must_check
 copy_mc_to_user(void __user *to, const void *from, unsigned len);
+#define copy_mc_to_user copy_mc_to_user
 #endif
 
 /*
diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index e9c702c1908d..9d8c9f8082ff 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -239,6 +239,14 @@ copy_mc_to_kernel(void *dst, const void *src, size_t cnt)
 }
 #endif
 
+#ifndef copy_mc_to_user
+static inline unsigned long __must_check
+copy_mc_to_user(void *dst, const void *src, size_t cnt)
+{
+	return copy_to_user(dst, src, cnt);
+}
+#endif
+
 static __always_inline void pagefault_disabled_inc(void)
 {
 	current->pagefault_disabled++;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241209024257.3618492-2-tongtiangen%40huawei.com.
