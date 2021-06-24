Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUP5Z6DAMGQEEUULP5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 060343B258E
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 05:41:07 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id w2-20020a5d96020000b02904d5a6cb5d72sf3488774iol.14
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624506065; cv=pass;
        d=google.com; s=arc-20160816;
        b=OqFMwxTKJ6+IT6mEwbhmYGZM16Y+YiYEMJfkGrdgPDHpXHjBc+OJexvLyZw0R/8gg6
         MOywy90rBz6XDTh5dl19J6Xp/2eWgdvyiMxne0XKPr1P8ibtOH94UqYtRvrZn4ISMW3o
         oAz0YdAwqxRAaUM6YAJ9pXiOrPEa5pZ5jvHplDeJim0z1KB4czLItGOqHZkmNjuhTsgf
         9/osIhIGlNf1MJZnt2JVYtVNNdKIoNnLfpx74HPBsPYFj8IbR53A3rQ88BT65F4x3oUK
         2lPSiD7jEGj+JyHB5umCXz0rrJJOJbvYeoFI6NDpoET5uE4zJDLer5Vk2QNyOFplHn31
         Dr0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T0Ubab3fR3QQT0u9166CeLzkzTpaX1ftgWiFZS4NoIs=;
        b=ZKuFJEXA88olqu8R7/jEHpZGHM4A6TV0xkiIvSTMPbuwlTYttdn3Qne/bY2wkRKJ2N
         TwPTKy91WznbMaZNkZbk0JZiBxlab9VBlOYb3T4d8NQl0ou6Lhgf7t4jWvZZmm9ROwbx
         Kkp1JxwHX33/egvkxocBJnHM/A1rnXT9Al9kqLq1svhvmkfh77Hjt2wflotzmi7KTKhl
         q24Q/USKJ+27S02h66UhVnb/4r0bx0IipFQLWveejQaJuQtOAH5IoCEkFOkf9jf6AkIF
         v39whUrb0X5MlRhAHN8VlxOrHi5Frznyo3cMkVQwTHbGtgQQ5YXqa08VlaiWb8Au4RDB
         qTZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gUFBIaMM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0Ubab3fR3QQT0u9166CeLzkzTpaX1ftgWiFZS4NoIs=;
        b=d9qXD+/GdF7zKwMdirIMZvHAvduSLFvmfQmAEHnJsGFl1YQ6SHGdmWJsZlnSxdF+Dn
         q4EQGkFz8STGiZefwiFmj6ddYooRiPFDmcHPPiEpR1J6giC2N9U43AjMZMEm5PBhyMbc
         mufTs9sIfAdmgUHM87LkpBPVJdFE/kL7R0q2trG/Bb2/aO6oEgbUEgdkrB0q9pYczqFG
         d2e2dHBbZDt9dwwS5wenOwNVWHEoQBIunxNjs+PfBbF9bSwDpAekAOmkVHVgt8LLPQrt
         ePzoNSW4jQFPMpqH9n5yKSajSiPSvGKdNwQqT3kQxb7yB/hMxR/BURZ68KTybo8FXdBL
         XvDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0Ubab3fR3QQT0u9166CeLzkzTpaX1ftgWiFZS4NoIs=;
        b=T39DUU6LX6lDA55JfmCYQnvkr5Ll4ZLN6E2clkXyac8ygU+DlueLiv7yYAtM8yUuQw
         QdGvT0SarXQ5tfiePeV75VyC463FtM1Bn00+QWl1/yH+dkGMR4mv/DnBAdESqHEun/0K
         k8iszCUXfN8QclCPelBvnIyTEq8Q5y8mVtNc6FTdWJVGmTGXDWPcFPwTSdJqhTkhGsZS
         T4B/PpdB9s9A7IEVAPDZVeVzrhqrTuLrLPEW3DqTj24Y1vhGcIipU92T243TH21X4jNT
         cFOD30nf395KX4kcRaaXnUaiv6ZSgVKnGEQmUGPfNUjKSg0vnSJjndgGdas+qQHN7San
         Z9aA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KmJgtcAMR3qfrvoWv51p9sjGPEeQzuQipdhUl98id5rHyk2No
	0CZRt1GOpHrVzejtkmq/BM0=
X-Google-Smtp-Source: ABdhPJzL5oLMAjhQLbSLobnNgdfPrPigNcDoxE0hLpfZofidfUyD1EpMtAwPv2n0J/ZU4poAF1bbEw==
X-Received: by 2002:a92:d781:: with SMTP id d1mr1976093iln.162.1624506065713;
        Wed, 23 Jun 2021 20:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c089:: with SMTP id h9ls167265ile.0.gmail; Wed, 23 Jun
 2021 20:41:05 -0700 (PDT)
X-Received: by 2002:a92:ce41:: with SMTP id a1mr1921685ilr.283.1624506065410;
        Wed, 23 Jun 2021 20:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624506065; cv=none;
        d=google.com; s=arc-20160816;
        b=Y0ejxgmg5m6GxVGBQKMon18fmvzl11cZIAMM8qddGJQk4Vubf5v6fZvWhzWT50iOV4
         VJ74ghVPBfjo20A2ean4gwtOfpdtemqNjdNhroF4VJgKWA8si+UZogC/Gib7velcTRPC
         /D5EsUODg1uVSPHAQyGUt7Nhl27TU/+NUgPUJMxKfdX+oGvcY2oFVvT+ZMeDGcstvY9S
         ETyXiBF7xUsrtJtUuDhUs9Vp0qHqrc6Ibq0Ly2T1MCghjABDZjs8j8b4nlnBfn5Ixzmp
         C8mQbKC0NOI1e2s90yJaw44CigckWZQ+tsBl6c5YYsfgP8iiAo1bEbNlnTiQrSurQ+cq
         RKSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EvVNbLnwqJAIYi/oiSLioHcxV6FtIVBfZ8nguMWCTFE=;
        b=hS1AMYBFe6SCybXgaUai/3obhI4gqyUWFy4N0JJ7PcF6T52NXKv3pwgs3CsbEe4HX4
         NI+k5yxw07vhJFtoUw/8iBet4q3AYKHf/+vctcoHhz1m8BTLHGfoCLJT6rwcVKKp8oAY
         d1KyyYLkkxgJCtXbLXoWOuXUPZR0xM2OKMX/L8yr/93E730dP2DeC/wvLWtsuORbybDk
         VTrMH3+UwxjegvxPGEDc3cXmwAmGXRvBddPB9gNQ3YujcOivfmx1gRcpblyKA+CipeyY
         DASjnarRQueHvwipVp5xHIlQ5km61c6QFVXcTrIN+m4qLn+Ua60rZArOtAF0YSwXoNnG
         MSAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gUFBIaMM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id y16si82898iod.1.2021.06.23.20.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 20:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id e33so3584956pgm.3
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 20:41:05 -0700 (PDT)
X-Received: by 2002:a63:501f:: with SMTP id e31mr2748949pgb.231.1624506064897;
        Wed, 23 Jun 2021 20:41:04 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id y7sm1137228pfy.153.2021.06.23.20.41.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 20:41:04 -0700 (PDT)
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
Subject: [PATCH v16 2/4] kasan: allow architectures to provide an outline readiness check
Date: Thu, 24 Jun 2021 13:40:48 +1000
Message-Id: <20210624034050.511391-3-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210624034050.511391-1-dja@axtens.net>
References: <20210624034050.511391-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gUFBIaMM;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::533 as
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
 mm/kasan/common.c  | 3 +++
 mm/kasan/generic.c | 3 +++
 mm/kasan/kasan.h   | 6 ++++++
 mm/kasan/shadow.c  | 6 ++++++
 4 files changed, 18 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 10177cc26d06..2baf121fb8c5 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -331,6 +331,9 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	u8 tag;
 	void *tagged_object;
 
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
index 082ee5b6d9a1..8d95ee52d019 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -73,6 +73,9 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
@@ -99,6 +102,9 @@ EXPORT_SYMBOL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624034050.511391-3-dja%40axtens.net.
