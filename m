Return-Path: <kasan-dev+bncBDQ27FVWWUFRBR5MVSDAMGQEHG7BUIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 98EB43AAFB9
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:30:48 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id f16-20020acacf100000b02901eed1481b82sf2651867oig.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:30:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922247; cv=pass;
        d=google.com; s=arc-20160816;
        b=If5+xSVryGJOKxl3n8rEbEFL0qxg/xu936L4PNCMnk7Cnzx5kwo7oQAc4ew1XzjIjI
         Nfk2kRRGCslphPcEk9nb4hvYgeZPRCbN1mCawq3dH7AAfLkHfN+E4m2Yc59vQ1k1+N38
         +4wzwxQbxf/W09cK8capADtmm9FDn+iS9CwXQaUxccB2zcP1os0U+NfjWLfCLMIXy3Kz
         8VNEyMJcmm5MCYnosIwjiYQuZBWhVkK58RuD6AU4P0sFztPHAP9jVlerf+HnAW2TjH/S
         0/ZP8u96yyw7u3MQuVSAUIFdK/HTtcsw2g9Ry3es/Wvhap/ui7auBVZXKxuqtCvTjjOY
         Am0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G4v6s/kIUCvwJzNWGd/U3OYWn0dqJiTKucG3uZX7ESE=;
        b=0ZpToxoAElYxeNcMRYQdE2OkXr5cd/6C9+q0LA3Dz7eY5n2b/WanGcxE0LR+92TWqv
         loRQv6yWVvCrZazOs33UnQ0FpFCOTDk1ZLzCjPHV3d6R+gXH8B7hU8DFyXYUQONsT28t
         HEgr9GtErD8M8OWeo7Gx9UaJOWJ8w+mu9ksCr6AI10Rpg0LrjVyBgKRdyM7E8D/e8WpS
         +1bJgyzMxhLN8ijLVXtgxseaWPAaY9YiU6AI8Av/ZinVBlYLLoeTBdWNYfM+g2Bzxo+U
         GICwvOIUCFFmWz14jbekScUpKUZPOhOFOW5iij6ICqfiMdyEkHHojcLcZqKv0CQq9mNP
         21kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=J9G3pN4F;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G4v6s/kIUCvwJzNWGd/U3OYWn0dqJiTKucG3uZX7ESE=;
        b=c/yhthjnKcmHXLU/9ojEjkC+93byOsz7ifD5dAgZm7bcLzmtG1knjjR1v4C9+1W8Yg
         U5BcGVQs91E46XxQE+s3/wQIHc1fABHNaehWYMJ2/eWRz09A4fd4M0TQWqHyoAF2G1Qw
         U9aeu4qibFPOf59hwmc2rUznmcKGONlKhE4QgLJsuhYpOhzdaS9JB/FZKUwXST+ArXUE
         F66x1bkW6jQpL+oK0CK/QPJJ/fLd2pqRjiqNlpo19AZ8dslkUnysjXK/eZzwr/uuWtB/
         c40c/i14MAJtzsren8U4OFZoQNsYyjsFakmwvp40YtMJfDbHvzb8ctgbGmNUM9li1j2i
         9aSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G4v6s/kIUCvwJzNWGd/U3OYWn0dqJiTKucG3uZX7ESE=;
        b=CYNzg7fQEcpbF0WxiUrO1qyPhQADpIwm3OoUNuAstIfJ1A+ZuSfG312t3hHYYEx+w7
         x9TQMaoUpw0pJqKF9uABSzMN3Whb3r/XE/LpUgPq+L1hwAHh+2KDYzzNyAZrq9+tNU8k
         WaVu+HbIos1xY9QpbptE6ZU3184yjXi/N/pgFwaM+gR+85jdrbxW0166w+GUFlSi4wVD
         dXH+JWkrt5V5RGECIbv2//BZSz9s4aOUjVvdByvYBWoyP4/KyTJ2RPMU8zevQcRpgDiF
         FzBtKemXycdQvvuKLvJZB4Q+XPi6MYRF7BCJoTTzvr0E+XCVlOX2YgOZnxkGEi7dB9M+
         Kg1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xY0WfKDlNN4aT5f2HFX81xjixloHnxUPkgmBO8i4U85KYWIna
	dkVpLHVVrnPaDTVRm/0z2sQ=
X-Google-Smtp-Source: ABdhPJzRoFUTZV6yOUAQN+4zsOyaRP9aW7R77tr55AQZKs3GL4LruCwzk0DnwXWiANmawEYCJ8WiqQ==
X-Received: by 2002:a4a:d456:: with SMTP id p22mr158348oos.13.1623922247463;
        Thu, 17 Jun 2021 02:30:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4610:: with SMTP id p16ls1710078oip.2.gmail; Thu, 17 Jun
 2021 02:30:47 -0700 (PDT)
X-Received: by 2002:aca:eb8c:: with SMTP id j134mr2666981oih.179.1623922246910;
        Thu, 17 Jun 2021 02:30:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922246; cv=none;
        d=google.com; s=arc-20160816;
        b=iCB4WfYPQQZP9CKyq3dJlCXwcy8Ggv6mVfWEMbexucWNe9vYQzz7oEh58oPQxEIFUz
         HXdxehC96MsYWU+beosjmaH8zHw/uxDBKdOT5o7cfZwPDTxspJXqyoOR7YEoUOhFnbdT
         gaWM1116Phjxc8wuYwez7ZmIiqoqlKym/5fU8lFmpwRAhGnJO0vMOpwOkOhyOIxfp+l8
         w2ZBh6N60C8ryiKqYS+gnpO+ykhnHzfpT++/7viMZ+TwY5VlLN8uD0ITkZK/X2egFVCn
         Lq7pI4RIAwlC0+iX7ruBuE634HgU7HhqN5T2NByADf0gl2Mgrnl6rYQIJzHVi3z57NSm
         6GEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jAXfPAXKGHI5d5AfauBRh2rw8y0WXn7UCziFxxBa2G8=;
        b=ifIejTw16OB5D2DuotOfaghR0crXDJIX74IzcSLGBau/Ks295W3Z2u7nr272kVYo3/
         N6sOPuRwgkZisaVJ/lJIUZvIg53tlWf5ZLIZENf0Anoj2mB77T9FMSR5vmRFHPpdAt9X
         it2ts96syBDPLMrHpV+P6pMEUvcPW80jNtT4Q+rIf0+3FqFTo2im1DPQQNlwdOaIyJjs
         ndctfng5BhQAmBQjtessNDjWaxmUQp/Ufwtil82tWFZaDvGkgH9qV2UCskfglVEq+H1X
         E+LOFap8SQBuIlywfm7eL6lV+fMtU522nH5i3hF+Hbwh52lrTg4fBLQhl55kEosGrwOM
         1jSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=J9G3pN4F;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id l10si570986otn.5.2021.06.17.02.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:30:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id k5so3453256pjj.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:30:46 -0700 (PDT)
X-Received: by 2002:a17:90a:f094:: with SMTP id cn20mr4668681pjb.157.1623922246569;
        Thu, 17 Jun 2021 02:30:46 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id t14sm5692272pgm.9.2021.06.17.02.30.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:30:46 -0700 (PDT)
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
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v15 2/4] kasan: allow architectures to provide an outline readiness check
Date: Thu, 17 Jun 2021 19:30:30 +1000
Message-Id: <20210617093032.103097-3-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617093032.103097-1-dja@axtens.net>
References: <20210617093032.103097-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=J9G3pN4F;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as
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
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

Both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series

Build tested on arm64 with SW_TAGS and x86 with INLINE: the error fires
if I add a kasan_arch_is_ready define.
---
 mm/kasan/common.c  | 4 ++++
 mm/kasan/generic.c | 3 +++
 mm/kasan/kasan.h   | 6 ++++++
 mm/kasan/shadow.c  | 8 ++++++++
 4 files changed, 21 insertions(+)

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
index 8f450bc28045..4dbc8def64f4 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -449,6 +449,12 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
+#error kasan_arch_is_ready only works in KASAN generic outline mode!
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617093032.103097-3-dja%40axtens.net.
