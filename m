Return-Path: <kasan-dev+bncBAABBZN33KUQMGQELW4PC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A21B7D3C3F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:02 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-32dc64b0305sf1448917f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078181; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYgtGPgFLiqHS5GVPi4iWVqHC7alkBlw4Y/Gc/KAiKtfpaBiTn4rCF/uYNMOgBbRN2
         C/HGElttxSnGlJsn8w2k/k9xSsD7RAHWiIPhKNTyKIeSaq9eN+C3/iPIGoOE3r61jG1B
         9izZZqcC6+Yj2ecTNWG4hiQR3VOqu3Tko8957bZOyp5blO7XgYxizImlAHTt8+qoiYBg
         oIzQeRMGSUqv/gom9UkQTf3Q0x2MPPySFLFwKUuG0SA3J6y7NUf4mQS6G0bnAKiK4vJM
         Bk0A9KnVxfZU81yUzwVMvpa9YelZudynSvTRw4R+JiZGd+3W5Vu/3Rf0QCkLjTcXYrxe
         RFUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G3XcNsbRNeKafUC+sDxmFhrKiAMHF4Bop6XOsJiVLoE=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=GHbV0lBQaVmVPBHU0Fe07yooXXrUgKUS4cASoLemUe+tDa4fHNzFPLu0sP6KpBVPUb
         LJuUvwUWQwVmA/HwtNG9ZTuZy3jEVk/LOPMG8K+9zZ8DQZZNJNT+Dj6WwO99klpTtruw
         xpC/Axng73Yh+Es3ild/eww0G457lnl0uqThD7AoM+4h63rQe5emp1Du66B1jmFzP4o9
         iEXtUM+9SMN3OJW1Hr0Gbhtji0kCN2N2Z4nR01Xw05SNZYmYmb9esaU6ULTlZgfM6hSN
         upUv2aSKf3gqjHtZ+STZnL38d2dBGlTJQaX/FRbBshpia2uqLVwaEqxajyl1Npa0A9TF
         JPzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="S/cthfh4";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::cb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078181; x=1698682981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G3XcNsbRNeKafUC+sDxmFhrKiAMHF4Bop6XOsJiVLoE=;
        b=rDX+YkwiPvwE3uAgyzg1pWdbrR/nvjVskd36C5vMHNVehSigKHMHLJheTY4gF0bqpN
         J7ZZ4oGiUHP63nUaxus8TWdYaKw6XBhboi3JRgD3498JsXvOsoq/S907KeItuwZFkbde
         k3EsiAC56MhDkuP/1ZBncGI4hqiRnWN10D3+Zq1Lb0W+HxmjRluZFEsPDQWuSircu2ge
         Tc7I/4tfg/soGikL/TRnbvHkNS2rNuQNL8f57sN4MX+PEK9JTIdCU3PYyjmj6ynbbcKV
         8UThYrE0i3ZKW1d+AAs+V7wNr8oK7ZmKpZmX9qW4TWEpW9S+eAopv9LsDvGHyibVi0Ou
         1iow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078181; x=1698682981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G3XcNsbRNeKafUC+sDxmFhrKiAMHF4Bop6XOsJiVLoE=;
        b=wkjkzpH/xUTvdJ9wqkAWs1KHRS9HySmXuJdAwOfgxPJ4kCm7fwZ+0tGWLtxGWv/R2T
         jsQud7Vy15eP4Bm6DJFQ0QidEScRQPHqu+wXL8vURnkohADyP+QhUkt3/o1K7+as41OX
         eJ6fbGNhLuUUY9sGwACbZT8ST2H6Gc6mm5DEe/AI/sQ4LOuO7tNB9B5JisqblDn1X2fq
         8CvvH59UveNjwSSZNQpPNuHgs8Ulb7e12p+dgAAobbuEvwGx2x6EKOrLkh/p9F0ZkuBs
         K2xu1DJDW2L8sl1V58LDJTdG//vZcLbHjbVjVOFEnZlrQTBkNn1DyvykAPrSlOW++vvU
         Tnyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxf9x1vHLZlxi6UT5SRnkdghVSqHtU/ICtz1B0LMHTC2rxD8Mhy
	H26CZ4indWYWo1fWwL3QUWs=
X-Google-Smtp-Source: AGHT+IGqlpzL/AKxVtE0MjSBBAouvCqrsIZM5xz5+LQmcjqv+qS59IEEJaXsCacqbDhZ2RvoYgfdXw==
X-Received: by 2002:a5d:6851:0:b0:323:37af:c7c7 with SMTP id o17-20020a5d6851000000b0032337afc7c7mr7513621wrw.69.1698078181463;
        Mon, 23 Oct 2023 09:23:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:4006:b0:31f:a870:d4b8 with SMTP id
 cp6-20020a056000400600b0031fa870d4b8ls1174700wrb.2.-pod-prod-04-eu; Mon, 23
 Oct 2023 09:23:00 -0700 (PDT)
X-Received: by 2002:adf:f74c:0:b0:317:4ef8:1659 with SMTP id z12-20020adff74c000000b003174ef81659mr6426820wrp.28.1698078179780;
        Mon, 23 Oct 2023 09:22:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078179; cv=none;
        d=google.com; s=arc-20160816;
        b=h5Fl4gjS+s2OSl3+Im0CJjiQylNeJborXObGG4315AGv4dwHPBLs3CgPaioQslRQTq
         W8PcBYC11zPPX2u9DODUnLsdY0Vaw03QbjvfeOL1yS2PVYnnVglsTZooGrMh6Cs0nOeK
         NwOcUQ0gcXPQxg837d2moRgxk7NcdN/DUehbXuZ6jgflfWxP/Qfm3UPE6YzrnYf7KXh/
         G+RE42Qbn1iR7mhmFGGqojFCdV9aOCAEguD3x9Sr69Qn2gceuDeutfxbpo5tn7RetPRw
         JFy9p20l5ZTHF9BixskSfSUkFky3fpH1DwKFoagbNFHo9Xvvb0jKDpBGLB0jLHbmi2mV
         edIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eQriSK20/8KwwHOVdQKhz9C/zLOim8sff0QLVit0F7g=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=jEzo091eRWjFidNrzq7OnIKfS8SBaHVFX0v6L2UrKqfqMms/RY7wC5STvywLjMMUAC
         vcuwDnU5cOrYvpI3jBa2JkezvQBtnlQ3/l52mNXh8PdAfJ1mK5KqAj4kfr7QVokCNsU5
         RqJGNZScVbDfif96Da0cSnu+C9lBOesyj5Mud7z1ub3aNb63XEKFmxa58MTHKkrUCG1G
         5ezMZI4lpBFdeAY4PKPbSmKtsedUdpuaArGtD76NHKyEQfFkjaIeBiZ28FSIqNCfMHKa
         Chwb3lMXsxqtxO4t8Owvt2KMua6HmFroL7cJuNVo/KK6XfkBF44wFTBkjlFUaiK9v3QX
         cu7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="S/cthfh4";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::cb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-203.mta0.migadu.com (out-203.mta0.migadu.com. [2001:41d0:1004:224b::cb])
        by gmr-mx.google.com with ESMTPS id m9-20020adff389000000b0032d8f0b5663si283989wro.7.2023.10.23.09.22.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:22:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::cb as permitted sender) client-ip=2001:41d0:1004:224b::cb;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 03/19] lib/stackdepot: drop valid bit from handles
Date: Mon, 23 Oct 2023 18:22:34 +0200
Message-Id: <5e251a589cb3142607ec5af8fcb904d424702a14.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="S/cthfh4";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::cb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Stack depot doesn't use the valid bit in handles in any way, so drop it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0772125efe8a..482eac40791e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -32,13 +32,12 @@
 
 #define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
 
-#define DEPOT_VALID_BITS 1
 #define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
 #define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
 #define DEPOT_STACK_ALIGN 4
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
-#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
-			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
+			       STACK_DEPOT_EXTRA_BITS)
 #define DEPOT_POOLS_CAP 8192
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
@@ -50,7 +49,6 @@ union handle_parts {
 	struct {
 		u32 pool_index	: DEPOT_POOL_INDEX_BITS;
 		u32 offset	: DEPOT_OFFSET_BITS;
-		u32 valid	: DEPOT_VALID_BITS;
 		u32 extra	: STACK_DEPOT_EXTRA_BITS;
 	};
 };
@@ -303,7 +301,6 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->size = size;
 	stack->handle.pool_index = pool_index;
 	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
-	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e251a589cb3142607ec5af8fcb904d424702a14.1698077459.git.andreyknvl%40google.com.
