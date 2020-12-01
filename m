Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3WYTH7AKGQEIP56DKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2842A2CA7EE
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:48 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id o128sf1305971pga.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839407; cv=pass;
        d=google.com; s=arc-20160816;
        b=xo8FrIuG0FjokRK3XHcCaNbWJPw49+Uy+f2OG/KBP4YgEgAACyJKRYkYm4BKy39KdA
         iju1Kk6pQMcbKVfo//f77XdAEFLRTAQ6vJU7k2iDVfTn0anteg/eOnRxmsO++5IsPdHF
         5VxhXTyK26PIjQp5vtoAH1CgAOfOBJln+9nJLwkrUrP43vPIDHWiQ1YvR8nNrIn6o2zO
         LQ6D9onGNeRgu1s+WkcJDVa2n6Elae7nByDU1faGlTRTH7P4cRVxD/QFCgWhSsyz6oFu
         LDGDOy27DXK8KPnuFCgJqTJBxDCTHNWwc5N+18dysTmZNik6bISdBL0fpTyixwJMlzHf
         UafQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Tl0I0YGKoQBpPmnTurA6B3OCN+Ro6Xl26pSub3jwWis=;
        b=NFVmGtX7eOjwdwIQGthl4ga8fGWH4ikG0jVkYxMvgZdKLUVZBWW/tiuWTJcNlFIlVS
         FeMCyQtzKnp8pRELVEjswHm7bD3jsTsweJGi8G+ckXg5pt9rNMwTYosIQOciWnHp00sf
         qhTebCNfXtq3tpR7OjBo/2c1LIfd/udhP7+zD1PJj1EG9JopvLSu/htt43fSLM+zvthn
         HqwAlt+MeQVbUszMMd0VuxdWkucm2I0sTaU4GN9mbSxh/+bzkfFCEjCxtS3UNEXPix1H
         ytd+yqNOOUnPF4u8uEUZ0nimDrm4qgupreY3trJ8ez+8sytdEqIgDH36bLo1QnB5iFZe
         mVlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=nMVol2Mb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tl0I0YGKoQBpPmnTurA6B3OCN+Ro6Xl26pSub3jwWis=;
        b=JXc842DuPB0COX+LR6mkFvqqFrCrFSW3GB5emw8JNt6f3yRK4u+OKQ/HGem8tbnrso
         OrJGgyT2EgETuC3AGrJv8AeV1CuPH8DRk55gtxZXBp8fkzu+yMHqUUHMLBRlirIAsFg2
         kwm3puM6G4YaVVEHK/FvuCOIZWVz+hps+/1ht5Da9x1fIBr3VBUZp2qG6j/jUnK17gWB
         jcMf4MfO6FSOIbxdt/dQXlFtyfRhwXr9gVJZfFGQdyvQpUml7g1udfYjqG511/mj+pAX
         YXdov2wcysNkzBFYabV7STXqxd+VA/GElarCYRzpxNR1QAyJukCaCFUtz6FjYDl3o1T/
         LdJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tl0I0YGKoQBpPmnTurA6B3OCN+Ro6Xl26pSub3jwWis=;
        b=KhtFC1ATMvvYZoKFeiOkKKWNDA3zjq/Nh+DIGNmmdXP7jwxtXKW/GchV015IBv6enZ
         i5AMDgjBhc2fTw3T37JA0DKKt5KrPOvSDKMCZrukT6Yw+v4LozfOslXFN7TLSnVXkVtX
         /SOc05Ckgd+kuVf0XGBFUMG5U5KWtkOFsqjWPYXP0H4BtppnZkhAFQMvybikbDXdsdxl
         Ir6HQQSLqTaoT5MbcE297k8h1NgtJFxb52HbfbWPWDVGPkWKqw6DMcD/kfoAc4tTZJ+g
         cJBBszTFVrSjYRZc9NDg6BKrTeezDLuEKb9UF5ACUw1XaVGUyWbqg1P1sijeiU7NJXr/
         /rqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iSkiiU5NglNwAmNNfSDkar5elowuF4hOeIkq4lcEMW9varWSs
	bN/UgjIX+WEbte2qRnW99kU=
X-Google-Smtp-Source: ABdhPJzGAhAlabTqq+i5Av2glKgfIiK+cAjKEs6G1tR5SXSqQ5ezFLrbLl3uySG61kMt+3UCnxYjnA==
X-Received: by 2002:a63:7d0c:: with SMTP id y12mr2944000pgc.34.1606839406915;
        Tue, 01 Dec 2020 08:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8508:: with SMTP id bj8ls1212654plb.2.gmail; Tue, 01
 Dec 2020 08:16:46 -0800 (PST)
X-Received: by 2002:a17:902:bb8c:b029:d9:261:5809 with SMTP id m12-20020a170902bb8cb02900d902615809mr3375047pls.29.1606839406398;
        Tue, 01 Dec 2020 08:16:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839406; cv=none;
        d=google.com; s=arc-20160816;
        b=Oz10ylYDsCoAmA2SCw9qkeVkHi3WGx+1M4wI6s2AkzpGCjerx4Jz/G9VfvjQkgCUhF
         KspYTgmpYMvDTotcOhsCuGmKkCkGWOsaOyC1ExGSK9tskbB2O0i/rHOj14jAiqC+ilas
         lu0xzzvzedNB1FkJZWS/XPA9UQli+jR1NCmcnlIpQKjpbl1fl0/H2dqYaGfkRtoiveK1
         LC0GjA5AfBYtIKIhu2Scc3hnQ91GIjW1gl/TZ+itItTXFnGHtTTrCoJKk3Hr/2Q6tX0G
         QwDS4S8ph7UN8Pf1Ih8xzshnmYR/KVMnJR2EF/Q6u+THMiOL5418Ir5N7geHpGv1VYK9
         wong==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ktiBTqbjFAD6ffRKByOoWmP2o55vmJOJ49Xz+HTLOBA=;
        b=HKjes2Ee83tQEncPBVX1qkWX5gR4BR6Fe0eOUxx45o+uIbTqLjBTaymb4W5Dm4vS6z
         KuJHTwnEKJdhOc78RWsvQM7GHqGJtjTAoqQToFIger67FsOJhhAzITjVS84FNoME1FbN
         QQjwZyeoLpBWNqleLfnB220RO3hq4sDfMf6EFYs+UBsOecaniBo7v1S6cNnfCshBV2xm
         J5rlH+Xgx6XSoWtkzbKWmu+hndXMbMb8LdQ9tE/5X8dmQyV5JsRuFLEnXZRCF+pMsE3i
         LUdZDusAse7YJwI8THvB++0N4oqYqSa8Gkxm346UdRmLVT6ErCJG35IWxVtRzEeC/oEf
         HwnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=nMVol2Mb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id u133si18812pfc.0.2020.12.01.08.16.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:46 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id w16so1447894pga.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:46 -0800 (PST)
X-Received: by 2002:a62:7f56:0:b029:18b:a70:4f76 with SMTP id a83-20020a627f560000b029018b0a704f76mr3167081pfd.8.1606839406112;
        Tue, 01 Dec 2020 08:16:46 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id jz7sm160129pjb.14.2020.12.01.08.16.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:45 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v9 2/6] kasan: allow architectures to provide an outline readiness check
Date: Wed,  2 Dec 2020 03:16:28 +1100
Message-Id: <20201201161632.1234753-3-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=nMVol2Mb;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
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
HAVE_ARCH_NO_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

I discuss the justfication for this later in the series. Also,
both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
---
 include/linux/kasan.h |  4 ++++
 mm/kasan/common.c     | 10 ++++++++++
 mm/kasan/generic.c    |  3 +++
 3 files changed, 17 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 30d343b4a40a..3df66fdf6662 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -20,6 +20,10 @@ struct kunit_kasan_expectation {
 	bool report_found;
 };
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..ba7744d3e319 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -117,6 +117,9 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
@@ -134,6 +137,9 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
 
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
@@ -406,6 +412,10 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
+	/* We can't read the shadow byte if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
 	if (shadow_invalid(tag, shadow_byte)) {
 		kasan_report_invalid_free(tagged_object, ip);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..e87404026b2b 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -169,6 +169,9 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-3-dja%40axtens.net.
