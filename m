Return-Path: <kasan-dev+bncBAABBXWUXOHQMGQERB7BTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 13F044987B4
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:19 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id o4-20020a170906768400b006a981625756sf2423729ejm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047518; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uo3QhuIWzBII1qzGCIbw6j3a1of3TDPrP0PVIz16KgiSeAUXAoyRGw6R3a9eSS3xW0
         PzV7+DAlhVLDLHjqqtkMOmT7IpWb6/+oGvT6rwZmvTPUdwxI9T+d6dDJQg9u+fB7ktrZ
         3ngUQE/X6ZakKgJGRLBR06A+NAYa0IsB9Xp8kjwxOhhiFpuU42wkBjxEhz8Qkic6CtjD
         dX3DDZjg9bHkLriS9VeWkzkS2UT1/ignCriybiclRW4gmFjbvBPhcP1IF2GkxDAFT9Je
         4OXbnlsybf2nYpQEO3PWDPfiqzcbNFMiZJqL1ld6m/reZKHJLfqvi7Y1BBCKYMBrcwOy
         +abw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bIFDQSJ8MFGAT3M5+hZINsmnVJAQ1UWenB55SRAr16I=;
        b=cYR+kchj5DhvhhGW1QsXRkDlf5rjEY8GcK1RMiO27XbDyj/gzOfytOGA7xDS9GrQfw
         pcJmasy1Q2ioUy2ZYZuslH54ow3sX9aHHqHTeC372o8s0RKLY7aOt2ZjN6yvdqXxLow2
         kMsWbUc7TPoIdiXOJGqtXOxW6LwNS6Lr5ADGAM3xn23cCDx7eVNiEvDfsAShm+57HMGr
         hyhp1I0r3DTymP7pxXHQl8WnIlwYwYwat3wrGBu3jlO+kSvBG8AkmYHWUzC+4dTLJVbi
         cdnxSBrg8tE80eQS66aZnZR2DlU720UNqn20tNfzDZVtyDS6e8nDvo78moIGeJ5rdmsY
         Ebmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W6Ni6gXq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIFDQSJ8MFGAT3M5+hZINsmnVJAQ1UWenB55SRAr16I=;
        b=Ti/3SNBbS6iHa4l9If+28ACzGOTkvCHmMcY3BnkHvIBfggIlvEd4JW0Kcb711D+KrK
         DcGFhgaLqwvdOvawTLPBn9WascyyJs2V/FpWsUXBOctCmenMNG/1Jr3trw6AUn4rWqxH
         7xG01ywrGgHhclt9SqdNGPAPpQWIGpl+SplXBMceQGgd0sstCrwVGBQSo248KQTtsNAl
         qnbIYn+EPp0Cvh+ZYEGUosgxlKeeB5hiMn3+101ADYt0HbZFG60hxjIfNwcnISY+PNUj
         ld0g8/JtYvBxUTryxidd+RJxftSuoEZ4d0y7TVGVOx7/ZVLWL7Ho7gbqUNXl0uAWrH3z
         tGAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIFDQSJ8MFGAT3M5+hZINsmnVJAQ1UWenB55SRAr16I=;
        b=J+qvoH/THwdZidVqHxrcZMXImbNFTZvEBM9w6MnB5guZ9rt3IPJgzZzV32HcIP4vZ8
         jEdD6x4q/MSoGpfAOLYQGbh03ZjctjrISk6QxJR2W/NIg19aF6HKMZoHQczDs2DLyobH
         YPI7PA6HR5SN4ZHlCrhfZ6D8Swc4pH58qvVUxWnIy6BA1m7dl0YEXKycPNN0HP3oEsMh
         x0/wxQJQDaA64e3oqeVnNXe8lm2MDjhe64p0kE4NZz70J2suzNOLJ5kfn2R38Sr3C4ZT
         cLWHrpwHjUwFo/NTBfreI8KopafX1o66MY995zE15GqauvDHM09wWAmXODPeukS8NTi4
         mTpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Mb00HW0LkVsahivSkZICSiBbaGyWCEzDKny5ty/BY7LN7AEV9
	inYzcCQCDMlULizFqFKFmvY=
X-Google-Smtp-Source: ABdhPJzFIViHLqzXhSDhcv4ISjS6LAjGl07A96WZ7VBfzOg9Ff3cEZ+iJxpjSnRsRl3lYNm3dPxvoA==
X-Received: by 2002:a17:906:c047:: with SMTP id bm7mr13415276ejb.334.1643047518826;
        Mon, 24 Jan 2022 10:05:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4ac7:: with SMTP id u7ls2255236ejt.0.gmail; Mon, 24
 Jan 2022 10:05:18 -0800 (PST)
X-Received: by 2002:a17:906:ca11:: with SMTP id jt17mr13486776ejb.149.1643047517981;
        Mon, 24 Jan 2022 10:05:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047517; cv=none;
        d=google.com; s=arc-20160816;
        b=JuK+2jSJ846KVJSI1KQ46GoL/w9KprQIctJyTTeNTIwPJraQfRtz4DQJ2uUpctRjXK
         yepLKfKPeBsg1Uis6mu97ZeAZ2oAmjnYouzucCEF8k6/ZDCFv3acIAMt8dtG0fNhhoVK
         v3b84Hjobmop9g3TO0NXJWR2s9+9JzC/36JP8mDfZRSzmaibDB57iBAoBtAY83BWhU6S
         veqUPrvbt2eQPYqknT9sERp0m7L4TJEPTLnEfPHppp38OFMAj9r8YZxg2sOhwy73xUH4
         YBzAGWGKMRAogt2tjBbI58iZdblm5+IfbjDpzxCbibHCFAtIh2JiiQjXfPmNiBcDc0aM
         FshQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lnm9A41ImFCEtqp3Gi0grxBV1YcMXYG5Az9GP4mftA4=;
        b=xcbU0d8MAVNNgFlfj+yr/W4cIsIMjCun2Cvoox6y6UEiKGlktqEbEOP0j7fisisQja
         A2DaYrU7eD2aINxndGpAj3YmHSF9Sx6j1reEbL8lBvegGvr1TOik3fv/eY+KG+cFf2z7
         buGbr6q5wGEXTtiv9RaZ2oWMlgsy0Qi5JTVtk8f96lPIOLG2vCCoPaVT4SxZ2qwlNWx+
         C5mtM3lwdd4tf9R+T71Gb2sJ8xbvNeszhHAYHlnAz0Jf52or8z7lMFTOjGcRgL0zYZHM
         S4sKi1fItF06WPbs7I5yPX+Dn0ZIoKYoiKPBUNOyKZqm8xQUghXfBr7uB169DMRVCBHK
         DoGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W6Ni6gXq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id g11si666421edb.2.2022.01.24.10.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:17 -0800 (PST)
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
Subject: [PATCH v6 19/39] kasan: reorder vmalloc hooks
Date: Mon, 24 Jan 2022 19:04:53 +0100
Message-Id: <aeef49eb249c206c4c9acce2437728068da74c28.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W6Ni6gXq;       spf=pass
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

Group functions that [de]populate shadow memory for vmalloc.
Group functions that [un]poison memory for vmalloc.

This patch does no functional changes but prepares KASAN code for
adding vmalloc support to HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/kasan/shadow.c     | 43 ++++++++++++++++++++++---------------------
 2 files changed, 31 insertions(+), 32 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 55f1d4edf6b5..46a63374c86f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -418,34 +418,32 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
 
 #else /* CONFIG_KASAN_VMALLOC */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size) { }
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
 	return 0;
 }
-
-static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
-{ }
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) {}
+					 unsigned long free_region_end) { }
 
-static inline void kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
 #endif /* CONFIG_KASAN_VMALLOC */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e5c4393eb861..bf7ab62fbfb9 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -345,27 +345,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	return 0;
 }
 
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison(start, size, false);
-}
-
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
@@ -496,6 +475,28 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison(start, size, false);
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aeef49eb249c206c4c9acce2437728068da74c28.1643047180.git.andreyknvl%40google.com.
