Return-Path: <kasan-dev+bncBDN7L7O25EIBBZNBZCNAMGQERQ4VTUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B579D606E48
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 05:24:21 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id x7-20020a056512130700b00492c545b3cfsf484678lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 20:24:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666322661; cv=pass;
        d=google.com; s=arc-20160816;
        b=irnTbzG8GCh23Y8Gaqv8sj5DOmX+0skmAJVb//w8q8pX1+zuG+NcjiiYCdaIbS4K8T
         kHZAgy4VQhdz7VHBqu7Y16w1JcaLPkXvn9tTMzIltHOusS+TWTCck8VHvBhA53qb5C7J
         P0xLlRK/+MbNl8wg7O22buHB+sv1S2r0P1kBxbk3LzLzSUWcDIbCfOFyMxHVBSvxW3r6
         /iucI3JzcFE2btRjqbuLUb7Xwnl2i4hXeqeP/Unmt6AWpfRS76z/bz7MQnsocMtx6yRm
         +agIzc3y/7wPpDVNFOflJwSD16MqZ8CMtBIm+1w+LHpHBhQH1XdfYcUPHtXffcdpPYRJ
         92dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gh0kxXITNZEGR6COZL1dLrk7zVGWQltBM2sjT8kgcSw=;
        b=A/anNLIxFYAvSWphavOJ5/KQlEfns3L9PJxqq6Zxc8URCE88aCMhfJ9FjU11JRqFp+
         /fkNrDumT+fhLy6eGHPeEkOfrGYPke7HNkfJOSZpMfL75yZG9QiyZZMmV6MtWYk9i2cs
         1P44gjjKDiwwTU6XDu/tRXI1fm9HF5B0+4iTkqQUtpm1x9T9LqYlxmyyz2gyVwanFm1v
         /YsDqJXH/9b4A5k44C3tI2rrOjlx9qMft3mizgUjpj9hF3nIu2DENPAnIJtA77+jLm3J
         gewhH6wSNX90vpjXEBQqrRKwmisZ7eIL3kxBzAsAIVlUqmytU/tIgF2fuk71t/ER0fC7
         SRnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UvBTWdXZ;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gh0kxXITNZEGR6COZL1dLrk7zVGWQltBM2sjT8kgcSw=;
        b=QTix5QnFpn+81mFJgVUCAAQKoZe2lgPooSRHwfvyqo3iiPZNrCKZxapyZbZ7VYkt2B
         ANtG66jlYSj1/twbsrK32GRxZ2xzOPtUmTm9V/MOKkfF3kW2wvA7viZ0ouotFY2iLZPo
         zgHfIodIxT6sWlYlXhyDZs9XodV150wqFVqBHUiwMw5/qyKgr8iRbCPcfSeha647mvcr
         lLvj4unTmq60IauZQnxEp3G9TDLrQ64CrEKGGb8qrI8/I7Ptige3Rp+2I+19kpIXe5MA
         FH6R794m/rafXvataGiz11xnUlowNE+TonUpNyY2RGRClzskqjaMKIDbjoCVDV0yFN4A
         PyGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gh0kxXITNZEGR6COZL1dLrk7zVGWQltBM2sjT8kgcSw=;
        b=1PNkZX0aQEpouWro6oL8+ZB3ogDBqC/iF9KHpREZY6L7PPVnZu8fHzmRg0F5Nur8wf
         8WPVZ8QZTqVnf0nfakw5Vv91vUIO9mU/t/JgyHbIfzgxCMmkR0S2caJnQyW002K9YIe/
         4Occ+ka+SADjdqJYUFALe8NivHAAd/6AhsWcHYsxxHxYqZgJmCNtUX0nhJLVRXbmrhZE
         4bS9uKV0f4Mj3YEc53bC/KqmfJFciPi3cK4pahUwuI6XO/5fMURLcsjnILIZhKJsflMv
         2/FcEo1XqSdZPtbS+R2aqEEdQ/Ibs3PRo7E0pio8DXUy6ZYWBpGCPnm0g26XEWDAcBLF
         jrAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3ddV6U3EdOjeFLRdxwV89ZKMlxjQjBy1WPG2IYAQP6roebJVAp
	Us4lQYDFMvIiyGcGkQJF3lA=
X-Google-Smtp-Source: AMsMyM7VxFJjYwtn7FiWmmP/Y2Q/e9OMjvoA35Pu9CZLy/JP2pjiYKy7D5S0xXdI0bt3BDTY+hsZIQ==
X-Received: by 2002:a2e:7401:0:b0:26e:506:380a with SMTP id p1-20020a2e7401000000b0026e0506380amr5878615ljc.222.1666322661248;
        Thu, 20 Oct 2022 20:24:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4897:0:b0:49a:b814:856d with SMTP id x23-20020ac24897000000b0049ab814856dls12127lfc.1.-pod-prod-gmail;
 Thu, 20 Oct 2022 20:24:20 -0700 (PDT)
X-Received: by 2002:a05:6512:798:b0:497:aa2b:8b10 with SMTP id x24-20020a056512079800b00497aa2b8b10mr6500202lfr.636.1666322660063;
        Thu, 20 Oct 2022 20:24:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666322660; cv=none;
        d=google.com; s=arc-20160816;
        b=YBxClOzE8NQDEH6ogxmnj8zwyaxw6Ke+vEDbR6eh50Q0zWewn+YBx+iybXKObsBRrO
         /9a3fVyEPRzb56rZ3bP/NKQjSAEJrghXarGTAePjk6md5K6nGv+5DICYPl3ct15MFttJ
         CJR5TcMhuS4Rf25Ndo5UzumxiBodORLDWR0ro3JdjQCXO5QSwFBFq/cspfnzoHeqKhwe
         rIf/HnznhAtZx6AypEq4N/eYVN6k6dP0txaTBZtfosKTbgl6fAQMA0OrfyciWucw7Yw8
         RNPoNN3gijxCPRC5yU7zB3t3U90rv766pgbmM8m782Xh7VNmubQ1C6abeAsmrPGZzIEu
         EcbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qT9aTG4MhKp/JZdJeVtvRHIFl7COGLInTpwNhLfWtPo=;
        b=oozwLd7D7DkHxaUP1lzhMUKzspq02dC/laXhIDSL08TF06XeXOEyU7McaYR+t4+u/c
         YKYyqfjXwSk0mE+xNHEQc+scysNtCB63hk1plfYoyfiH4tvLX28ilZzo1TXQeT/5LN8z
         txWThfhX4hecO6rkVdgCpuRQUKB/6mqepYC5V59+SJvoTSyyw0IDdG6qmA0J3NPnfXnM
         kom2YbfEfiE6kB9fZZjbfMrBqr4Ve4y+nrf63ewfS9roP/J7eV5N5SxPnUlwaRe3RhsB
         RHM6TJwITIg8mRaTIPKg8gnNH7o+nrImNxB19VxllEelYtXIy75OgdawANiSbPtYGWF2
         VEDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UvBTWdXZ;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id k20-20020a2eb754000000b0026fb09d81bbsi595748ljo.1.2022.10.20.20.24.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Oct 2022 20:24:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="371114066"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="371114066"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Oct 2022 20:24:18 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="719459592"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="719459592"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by FMSMGA003.fm.intel.com with ESMTP; 20 Oct 2022 20:24:14 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>,
	kernel test robot <oliver.sang@intel.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: [PATCH v7 2/3] mm: kasan: Extend kasan_metadata_size() to also cover in-object size
Date: Fri, 21 Oct 2022 11:24:04 +0800
Message-Id: <20221021032405.1825078-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221021032405.1825078-1-feng.tang@intel.com>
References: <20221021032405.1825078-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UvBTWdXZ;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

When kasan is enabled for slab/slub, it may save kasan' free_meta
data in the former part of slab object data area in slab object's
free path, which works fine.

There is ongoing effort to extend slub's debug function which will
redzone the latter part of kmalloc object area, and when both of
the debug are enabled, there is possible conflict, especially when
the kmalloc object has small size, as caught by 0Day bot [1].

To solve it, slub code needs to know the in-object kasan's meta
data size. Currently, there is existing kasan_metadata_size()
which returns the kasan's metadata size inside slub's metadata
area, so extend it to also cover the in-object meta size by
adding a boolean flag 'in_object'.

There is no functional change to existing code logic.

[1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
Reported-by: kernel test robot <oliver.sang@intel.com>
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Feng Tang <feng.tang@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  5 +++--
 mm/kasan/generic.c    | 19 +++++++++++++------
 mm/slub.c             |  4 ++--
 3 files changed, 18 insertions(+), 10 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d811b3d7d2a1..96c9d56e5510 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -302,7 +302,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
 slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
@@ -315,7 +315,8 @@ void kasan_record_aux_stack_noalloc(void *ptr);
 #else /* CONFIG_KASAN_GENERIC */
 
 /* Tag-based KASAN modes do not use per-object metadata. */
-static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+static inline size_t kasan_metadata_size(struct kmem_cache *cache,
+						bool in_object)
 {
 	return 0;
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d8b5590f9484..b076f597a378 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -450,15 +450,22 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
+	struct kasan_cache *info = &cache->kasan_info;
+
 	if (!kasan_requires_meta())
 		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		((cache->kasan_info.free_meta_offset &&
-		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
-		 sizeof(struct kasan_free_meta) : 0);
+
+	if (in_object)
+		return (info->free_meta_offset ?
+			0 : sizeof(struct kasan_free_meta));
+	else
+		return (info->alloc_meta_offset ?
+			sizeof(struct kasan_alloc_meta) : 0) +
+			((info->free_meta_offset &&
+			info->free_meta_offset != KASAN_NO_FREE_META) ?
+			sizeof(struct kasan_free_meta) : 0);
 }
 
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
diff --git a/mm/slub.c b/mm/slub.c
index 17292c2d3eee..adff7553b54e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -910,7 +910,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
 	if (slub_debug_orig_size(s))
 		off += sizeof(unsigned int);
 
-	off += kasan_metadata_size(s);
+	off += kasan_metadata_size(s, false);
 
 	if (off != size_from_object(s))
 		/* Beginning of the filler is the free pointer */
@@ -1070,7 +1070,7 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 			off += sizeof(unsigned int);
 	}
 
-	off += kasan_metadata_size(s);
+	off += kasan_metadata_size(s, false);
 
 	if (size_from_object(s) == off)
 		return 1;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221021032405.1825078-3-feng.tang%40intel.com.
