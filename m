Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTO4VODAMGQEBCVCF6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2047D3AAC90
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:40:15 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id o12-20020a170902778cb02900ff01bc1ddbsf1340812pll.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:40:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912014; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8/5yZFAlSQfE/fdr+/2WJ8ohCi2rZ6ZjUF456tMH0fjW/VW9OVa5OF3VKk0BBD6AO
         ZcApU/0neH6J2HF5B/DXZKoNbZqJLUoLA/exU1GcwbaTr3wbSzSYIwlPf9e602Eygftn
         Dvd9vJOhPG2uYP35dCltiepQ/5yEobpmJIsVDuaPQ16lERR8bYiM2uTFEZmMYxQQ3YXp
         Yue+NcefTlLBfXciOf81rqSteG4VbKto5BoIg9GoT/MA2Fh5XoNAKKX9FuUeOlRah160
         yHGRhmMfpbrk7thjhybAGkTNonQaAJOgTtgJ62ikM15qx1EDmKMIZZM+avK5jfO1QYyu
         kN0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HY79mIkNXgwvzUwr4BemI5KVMibPYby5XH66VAgOMe4=;
        b=snnQfvzWYjNtyXUcSB+MNYkX86uYSuPqhSiFdUUbAFsv1t84WuuTFW7EAPrhk/wFGx
         WkGHtdjZwC9CjHqBbOUMP8KqM8tPrkGxjCXbASC3E2DP1487HJd5LpMYfIExqbOueooO
         B4LwsGH8cqVawPVmVifyx5BOiixih90znOFlcIqtB+eYVKMFnfCjdxmjhecelj8fL7Uz
         8ceWTgait0pawkpRffw+StsHFQp6ABMDe1z7YS4KTf9H/EZpWPD7sx8KgE5fZeg27vze
         H4sh15NmdTLUUqcTiwx1ZPt+dHSj8+i9asHfT7AuHE671d5cK+0wM+7yxDcTkOWo/9JP
         9ZAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aX8fvAkw;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HY79mIkNXgwvzUwr4BemI5KVMibPYby5XH66VAgOMe4=;
        b=QWjHfOYeJE0qkAX9KNS0ROoMoSx+ubZvgyAnBT3ujLiAxiIa6KgNVgIFfVMQUd7pCD
         ADmKW7YZc5zemUkmGmwTeXZOAN5SL1s52w9peNFGvNt3ASrRQ0vQGjivFhAd6Ld7V53b
         8fE4aydBIhRDp4zm51G0JkSj5ThYJzoERvz8C9yn6HIPfr88nSzg9KwyaHDYBgoNAaUW
         WfymO9tTEbZ7VD3aAvKXbB7fB5525Q8JtNaJd+9var+RgDwBoVLRkN/gacmLmnF2f0l2
         KcWO3a8ktPQpCgcElwK5QGLMccf+Lz2YPIQfy4jydvjMQErRa7jXMnliTVKLTjFjU2jj
         bjAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HY79mIkNXgwvzUwr4BemI5KVMibPYby5XH66VAgOMe4=;
        b=KlnmVoeSpH0GMY4n0O03ocd4P+HtICTjAgpipawfWsl78Qz23SIAZ1aHxFSolTx2ul
         PyK8jLriiV9I0/Gt+I5Yj5eYHsO08SSXklbZzALm/YtZgEfHrGeIWth8oxQ2iL9oAEgV
         BwJapRfJiDXruVok0CCCFFQTaJM60oZ9wkx6tf1bMQO/vRugpZkFl7M6dEJBJcLVOapF
         MPMlQ0mz8rHWZfjCS2BKOjNpMrGhc6ypPg7keWK5hLEzih0iDtu53P5bFina+CWWKfrf
         5l6aXmUa5iPPxWuogTdb340q1eTsDe7S6iBcfOFLUBKYnxyD4pT8ljep3WWxPe2xM1bn
         +hog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311jQsWHSgeWw2iLxpDKJA03tL7sn6HsRHGxeRqwhWrAlXjUGsP
	pMXZnYZ5vOYrRHmRMaIayX8=
X-Google-Smtp-Source: ABdhPJwL3Hq4QT87gHJrFXOZqKPelGcS2DMZ2KhMxEcEG3PRlqdRoYq/JqwzDbRIdY58TRVkFqjToQ==
X-Received: by 2002:a17:902:aa86:b029:116:3e3a:2051 with SMTP id d6-20020a170902aa86b02901163e3a2051mr3176437plr.38.1623912013738;
        Wed, 16 Jun 2021 23:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8206:: with SMTP id x6ls2493197pln.1.gmail; Wed, 16
 Jun 2021 23:40:13 -0700 (PDT)
X-Received: by 2002:a17:90b:4c52:: with SMTP id np18mr14984291pjb.186.1623912013239;
        Wed, 16 Jun 2021 23:40:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912013; cv=none;
        d=google.com; s=arc-20160816;
        b=yTlv2nO9gIYhwYfjeL5zak0M01ABD5Cb46Dvo52gL19yFe7THa4+aDruxBAiER02Ck
         UzTQFf/ZGtXStiZDnKf5iuIwT95yrPaR2TkBkTL1FFKSkU0dOjZkH2VngWsUC1j8Jndl
         Zf9TXpT7byQamoEyRYY3j4/vwTMBlz6hB7B2kxbIUYZYX1ANmuX7PRY3vAwTlRyWT7q6
         v7ZNBaKZwFaINyXTiFIBJByDBxHfVVhm6DFhDxteMWc2cgPX6YDHFPagD2EJQa/GO3GL
         BIyEAp0J/WqYxw8psdveoPKT7CiVugxl7qNs+Yo12fXqnGRZ8nI6+51dB1wY1711V0OX
         r+ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ly/BuIfXTXWQRb2ER2SUgvo52sNSO+fWpTpraSlxuJA=;
        b=gfG4PFtHGThbB+EQywipBjmF/zjf/L6ns+CFRVZgBaRi6QM8LXFkwaGNpRzriAo73X
         6MXTi8xqc/9wbA+RQytZwij5O3Xh1l8yx9CIBmkphjhrq/r1lM0KLuU9lyz6hjzY2dTd
         iNiQ4v99FQywYEtdgB04um2cYgcKR0Kd2ivzlrFmy0mxSbuZdy7A+ru/QjY3/i0VF2uR
         ChUIHEj+ud3HdOMHz5UfesZrmvxC2WMD/uGvcBso2gHGilcFtKnDgkoHh7fDUhDgG9Pb
         gQgcK/rstGUJaLwFWXP12XqnSYAqLEZpJZUDGiEH2zhGU5OOi1N7hrI0iFXw3XuALSxC
         sZJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aX8fvAkw;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id y205si561292pfc.6.2021.06.16.23.40.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 23:40:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id k6so4162990pfk.12
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 23:40:13 -0700 (PDT)
X-Received: by 2002:a65:434c:: with SMTP id k12mr3551339pgq.17.1623912012898;
        Wed, 16 Jun 2021 23:40:12 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id 65sm3950520pfu.159.2021.06.16.23.40.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:40:12 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v14 2/4] kasan: allow architectures to provide an outline readiness check
Date: Thu, 17 Jun 2021 16:39:54 +1000
Message-Id: <20210617063956.94061-3-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617063956.94061-1-dja@axtens.net>
References: <20210617063956.94061-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=aX8fvAkw;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Allow architectures to define a kasan_arch_is_ready() hook that bails
out of any function that's about to touch the shadow unless the arch
says that it is ready for the memory to be accessed. This is fairly
uninvasive and should have a negligible performance penalty.

This will only work in outline mode, so an arch must specify
ARCH_DISABLE_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

Both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series

I haven't been able to exercise the arch hook error for !GENERIC as I
don't have a particularly modern aarch64 toolchain or a lot of experience
cross-compiling with clang. But it does fire for GENERIC + INLINE on x86.
---
 mm/kasan/common.c  | 4 ++++
 mm/kasan/generic.c | 3 +++
 mm/kasan/kasan.h   | 8 ++++++++
 mm/kasan/shadow.c  | 8 ++++++++
 4 files changed, 23 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 10177cc26d06..0ad615f3801d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	u8 tag;
 	void *tagged_object;
 
+	/* Bail if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	tag = get_tag(object);
 	tagged_object = object;
 	object = kasan_reset_tag(object);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 53cbf28859b5..c3f5ba7a294a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..b18abaf8c78e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -449,6 +449,14 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#else
+#if !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
+#error kasan_arch_is_ready only works in KASAN generic outline mode!
+#endif
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 082ee5b6d9a1..3c7f7efe6f68 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
@@ -99,6 +103,10 @@ EXPORT_SYMBOL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-3-dja%40axtens.net.
