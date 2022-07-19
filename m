Return-Path: <kasan-dev+bncBAABBMXO26LAMGQEJA3F5NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E764D578EF3
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:38 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v18-20020a05600c215200b003a2fea66b7csf4845689wml.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189618; cv=pass;
        d=google.com; s=arc-20160816;
        b=ykrbhi70Rvv9kIg+xYoqYE8Lz+pDyB65ipy3TL9JbMViPYT2ravYt2DVl6t6ziDymD
         sTMKBNXLZSmdwmmRemCCO/bIA9fuN+fuNV+w4f572WzQ2ySKru6wCkA+7ePKf+9xHoIc
         La+PnDhpwZLajVBmfqRdvn218rVYvlp4XM3CAFFxoMnLG7EkygNu395Jb1cI9+dwmDwy
         xbA0jqkhKmNjDhdfF+s0cgUTfJcawo64y8PJ9+e05CAx6EhYiYhmd3yuiRa3Y9g0Pxpq
         +3dV6IKQfvFRz7IBodqv+zF+8NovKkXjEAB6JnKXMzw6moRzM0hzV1sT2s9OIPlY08hJ
         H+YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tb234gMRUraTOqloQzv924qqUX3bE9bfuHTvtksBXQs=;
        b=yy0sk58WMS1aE3S7doRC1GjSDkprHVhLGtBR+nU6zX/7N0mMvVQB+WIobl/A1QSuf7
         zuuHTvJJ1qEQml7vPxvLKyPCOckFKVjaOVTOWAZCWFJEf3cdpvVnPv0A5kLR6sO63DXV
         XxaskK6gPlR7GdlvMGzqJvJwJFJVHxIJsqL6u6ZHRkJePTf+G/feNNpK0azn2l6JrR/E
         jtdwzho+gT5w2zockKPXA5HbO4YLnZyl8V7PWKdpjddD4cFLL0LGPuBoF06kGMpqkx3v
         Z5jX0xmZ34qTUYFn127ZbdXqczRBjIQeVpvC3u6oK7fartexV6kk1bmqWvkMV/mC37EL
         A6Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LVpP162e;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tb234gMRUraTOqloQzv924qqUX3bE9bfuHTvtksBXQs=;
        b=Bkv4X1xXUIVkMoh4DFK5+cPBOvBSx67Lf52J93CgMIFVlUeyO1c2aqFaE+mrZil+4s
         tVwVHjYbt8XqNh5Hv3nrjz1MbAGoF6AILUTdqcFk6l+N5x/0Y/VkOJUnvecwhFfWSVEv
         yrF370jM3ILw51sd/jCh6RgSob+S1jFwykZX9x/hP68FMBM4USv0hlLpJtT0M70oUtvi
         yTA9RlQgE/PsTyYNJOG4sYpKO70AEekiI0Wxl53Dbc5TcPdwyrwu5UaZuwdEpbVhVRry
         JZj4Nilvr02P7aULsSKOo/ZYB9gjVCC94/IvHqYdFdipYAHNM3HmcXHxWgKOIkUCMeZT
         S9/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tb234gMRUraTOqloQzv924qqUX3bE9bfuHTvtksBXQs=;
        b=6Q9qxvDfzZQjuTek1OcBQMDYfBdg3VA1FK3ZfkZxGqYA9N+B/1uriitT2HEWvs8iaD
         DGfzO8KsRo3ZMuYxWtjpxrQBG6ph8d1I+DywPTi4iaQsxmNFNpWghliz3U5A4AVU7RDi
         bFpVPd4Fy7hcfjEVmErjflsihnNlH6EBzcFRQ/5RsUnbr0fWlpeNNv51SUReQ9AitNnn
         45oFNtgf38Yf2TaJ8p8Ao0A3N4sPa5gp6nRqd1zbQjx9Ddui2Yb19BiJZs6SzWBQ0DMW
         cmyKkZ6Zg8cd2z/V6vHGwKE+njp7BdEXxwvDgYXm1HQwERYYyMBCuISKiKvP7muML/SF
         /osg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+JkrELNVTIb/yb4PxuYI8uhpxXEF3BG9iznH+Yf1xpRNQLhfqv
	SN+nIXtqn3Rie1l1rQjQXaE=
X-Google-Smtp-Source: AGRyM1tAFzRety5hqbcARmEvSwbXy1vj5i1U8V+iIVtezosZwMZBcxK7SZboVBA27U1a7YRNTvLiaw==
X-Received: by 2002:a5d:50c4:0:b0:21d:a9ad:3aeb with SMTP id f4-20020a5d50c4000000b0021da9ad3aebmr25542606wrt.591.1658189618706;
        Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2195:b0:3a3:1b8f:2e1 with SMTP id
 e21-20020a05600c219500b003a31b8f02e1ls41827wme.1.-pod-prod-gmail; Mon, 18 Jul
 2022 17:13:38 -0700 (PDT)
X-Received: by 2002:a05:600c:3845:b0:3a3:19e8:829e with SMTP id s5-20020a05600c384500b003a319e8829emr7368881wmr.11.1658189618008;
        Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189618; cv=none;
        d=google.com; s=arc-20160816;
        b=Eu3XFH7xuYy559WtUpbnzdC5M+d339ODLa8GLUgVmF4kBG2TyFwaue+/NaWbwKJ1hH
         DS3IW66o07YtgUo2lngGdQM9MgbjxZyv0MmjFnRHRt1D1zInElp0AMU6SFv2O8/4knt5
         G6pbj2I+TQgVPrI6tq1nYZNRnZdewKtFq5KHgV9VEW0VABCwxqoypMN4dXIVg8U/5/Yr
         iM+QvUVBeKrTvDnHxucpCbIBmsZ7KsEWoJPuaeANE/xtgrMVX5H7jNxq6vxWoR1gcc12
         /fis3YAhyOh9MLGN4yzraYYg9tjVtOA8uSp+gjNOnncfF1m8auqK2fGYIvWBPuCB6S4Z
         dJXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=O4rrLBlHP9NeNLXeiOhUcDB35KsXuF54OmWKXqnLQEA=;
        b=OF3FTBwHXhwp3L23842KjVQMHQwZxxuhYglGdoEE4xjwEo14/tL5qYHwsN2ih50eDi
         1W0f1kA4noJ9ersMSpR7HPIbOTx2KNngkHa7NEHQzV5FSnufZYmclhN8AS3NoW/LC1jx
         nPwv5lkfIKeWiD1Zod7QfWjJT+OCo2iatUAwMo19fVVhachCc5DRbFIU2L/kjAivb/UZ
         U3v3pnRoVQiy5xTnkbjUZShq0lUUE09nVgD39Evxu5YSo7sBpX+WNBIjJQncANVuxV8n
         LbBmdID2ec7kadzDErgO++mNM3yGkAELypt+IMO1115Dcvioi+1/8LEpV3lz7dZo5eEZ
         X1wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LVpP162e;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id f12-20020a7bc8cc000000b003a31f71c5c0si55062wml.2.2022.07.18.17.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 23/33] kasan: use kasan_addr_to_slab in print_address_description
Date: Tue, 19 Jul 2022 02:10:03 +0200
Message-Id: <b564ec299087548c5391ccea6f589a9370116d51.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LVpP162e;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Use the kasan_addr_to_slab() helper in print_address_description()
instead of separately invoking PageSlab() and page_slab().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c |  7 +++++++
 mm/kasan/report.c | 11 ++---------
 2 files changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 3dc57a199893..cfb85b65fa44 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,6 +30,13 @@
 #include "kasan.h"
 #include "../slab.h"
 
+struct slab *kasan_addr_to_slab(const void *addr)
+{
+	if (virt_addr_valid(addr))
+		return virt_to_slab(addr);
+	return NULL;
+}
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 570f9419b90c..cd31b3b89ca1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -213,13 +213,6 @@ struct page *kasan_addr_to_page(const void *addr)
 	return NULL;
 }
 
-struct slab *kasan_addr_to_slab(const void *addr)
-{
-	if (virt_addr_valid(addr))
-		return virt_to_slab(addr);
-	return NULL;
-}
-
 static void describe_object_addr(struct kmem_cache *cache, void *object,
 				const void *addr)
 {
@@ -297,12 +290,12 @@ static inline bool init_task_stack_addr(const void *addr)
 static void print_address_description(void *addr, u8 tag)
 {
 	struct page *page = kasan_addr_to_page(addr);
+	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
-	if (page && PageSlab(page)) {
-		struct slab *slab = page_slab(page);
+	if (slab) {
 		struct kmem_cache *cache = slab->slab_cache;
 		void *object = nearest_obj(cache, slab,	addr);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b564ec299087548c5391ccea6f589a9370116d51.1658189199.git.andreyknvl%40google.com.
