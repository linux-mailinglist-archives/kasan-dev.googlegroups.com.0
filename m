Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFMT3P4QKGQEBKRAYDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F473244DBF
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:50 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id t9sf3941756otk.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426069; cv=pass;
        d=google.com; s=arc-20160816;
        b=h0nmJcCnkRTd+deBFry3irRlXoGIp6wDszPiuOT6MZUcoFYhQ2frL29Ze0SSelhNT0
         DFqixyKoTEsFab1gLOan+lH3ZQWJs5keXA2ZyNpRh5mPZHcEQSv/nD46dNMXjQNyzgMe
         fmsDm/b4zuWZDNCYm8gRim9W+jMzscuglKieBofISVAitnecsRWCeG11aWdvMS6HUzOf
         VU0PFlHpWwxJd2ETe1RiSv2uuyPCVUxboXn7hlVXlUw+j1Kuv66L7dp2j/ctZ1zqSA/7
         jFezmOILOwdo65vgb6kAr27k8Guhe0tZ9vOCKWZ40YiYQL0Qes7fxxRp3E0o5j5Hrbjk
         /w/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bOgCKst0WdQma9TOo2GY4z3SMgaXiPDB3yKGruYc9hI=;
        b=E0E+/Izlt/avKHfVnvGaoO6xsoImfUW2njxt+cAiQf3t/lu6XOFuVB9mTMM5SbvU91
         aajLm55eCAmx781F8GnLId1+Y+SpqrXN5B7zBTFE9+rSqDQ8O7G6k/Jc9yus5Y7UaN4+
         Fwr3s5M2qXz8cak6h2YUIBV3FDnyDC2j4LIA6H3PbTFc5IIMggfUA3OWhcUOKX6Ra/DZ
         i97e97iJfIQP3B1XM6mscsFPPEKpH/OqvLrmfuQd35wWYQITQeOmrZxWHurZfR0AKPPP
         4XGzu3acAK6Oq5yMi/0pbM4CL5z7XIS41NmyKZmmwbBIXK4rAhvr/rv4jyhtS0wO5M4o
         JhIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aNwZunoi;
       spf=pass (google.com: domain of 3lmk2xwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3lMk2XwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOgCKst0WdQma9TOo2GY4z3SMgaXiPDB3yKGruYc9hI=;
        b=XTXTUb+MVRwp9vmDudQFlkMkpuj7hyLwTQLFr2wFl0nQdtZPXMRwailtCBkTAexzO+
         30eapvRpcpT49xajZxvhO26W5JySVDa7H8CE7IYA2T4yI1mL3zJ+EDasjak9bcVupsM4
         7WJr3GFx3DwEHfMURVVVYP9FzK7xY42pVXxZXYo01bh3cFRzDOA/8dbQvTePSksqurPQ
         X42oCU0URbJfymaTZ/KZkzP9U/vqstzPdPnhKkX9pNZe+oH/nxZSc1i8p1eOkOIAbOJg
         +Ffoz4oOLJ/ebmUTkauT5JuYpGC3YdZF54pBPnDHamLq0JLVgywpUciNdysf/X2txbGl
         sEGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOgCKst0WdQma9TOo2GY4z3SMgaXiPDB3yKGruYc9hI=;
        b=L9eETHqkVoPE0c2FN8WjZi1+LjwOHz+nVK71evtFo6PakDSCiI2lJE3ssZgBIPsqkp
         PBduOTTbFHtzvuuheX2kYHqFsk9qG7rKLcyHBQGM9UkeCL9MaMDyQ4wjrORP0pLUBzi1
         9rsX2hbUoyquyyoMrdjZ9I00Bn22hp4sQHzDFVQeGpknWlFtY+sLSxVHHXPw9FKiiloR
         vE+Vh9QembLb2e+5X8qGb9oTySeByFQZXgtiJ4+3qWhMyr6LvH0ccSLSvUKIm0AlPcsC
         MGta6YxYn0/URRNFWw+R1ks9yjrAk/je2UE2poMpJtF/rQp6/HA6thN12C7cyKOnw9Vg
         5Z0g==
X-Gm-Message-State: AOAM530bp1+bL596N8+1mL+tAWLjd8gxl7Vv2+9olOVyUSXhoD2HFe5u
	iOORZS412r+n5vfzYzQ3Nck=
X-Google-Smtp-Source: ABdhPJxKAxkBllc5iJCDc/DuXP0cwBL1Q4Dazu41WqkrkhGtux1GNGqx+JwFecuSjntqzaThH06/gQ==
X-Received: by 2002:a9d:5e0c:: with SMTP id d12mr2657272oti.239.1597426069289;
        Fri, 14 Aug 2020 10:27:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d9d4:: with SMTP id q203ls2041087oig.4.gmail; Fri, 14
 Aug 2020 10:27:49 -0700 (PDT)
X-Received: by 2002:a54:4588:: with SMTP id z8mr2287824oib.86.1597426069008;
        Fri, 14 Aug 2020 10:27:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426069; cv=none;
        d=google.com; s=arc-20160816;
        b=ftyWAZwNg1GUMIHba0JE8y7dzaTxoWMoP5n3GIuXWQWV0xC/21HJjp3jCKPdbgRUR+
         YjLofACTu7fKUMIiifoFn60VYQjeukhP1tBUt3xYX3BhR0bnEFEO48YPUSsMpWqGOAi1
         30gt+6c9btuz3Nell8ZHQc2Y2WrchBU28MAguPgaSbqnp+gnCT/cdzqRT1QU0zu+R6VV
         9dHGHbyThsNXlUo0vy+BEOtcChCMonJEM0JLv17hJg0EU8YQ89CGSdSvpD9p34IPgLZ+
         jBB7mRn48aZ6bb/gPdCIiBMPbhiANOjZBQo0D3XFzpbXK4wkUf2xnXzTS5tB9jIVBOqN
         AXbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1rxlsTFeHZWa6ONOeuQ+mv6OBF5H+hBIiaZ8LmsUVlw=;
        b=uJ3kZjShU6RyRuRUIp8pet7nmLXlJ9DCCBNGDjPPb9OO+l1FEOJWBkbe0ApZ0257Zv
         9HTH+t9mlplUnBRrrT4wNFcdc1cvyiRrfEAX/cnFW4D12/glBtWbdZk6NdmZb31JdCvS
         PAwW+MmyaILNtWemsNOSD62x7XRfzbQrtS18d4gX2ieAiowJP8FIIfLYqDzg9DQnDgmt
         K7qc/WAd3AH27o2tQMY03OQPtQyjf+ouwau5uJzVoKiQJBC/gAno5T5g2WPA49xNXpye
         z8sEEUbKUdVeXzQafmgbG0negOBi3Qh0/47uoGXojifzvDCbw7g++5xwpXEJt5+0HRsM
         byUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aNwZunoi;
       spf=pass (google.com: domain of 3lmk2xwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3lMk2XwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id z12si465030oia.0.2020.08.14.10.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lmk2xwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d30so6508283qve.5
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:48 -0700 (PDT)
X-Received: by 2002:ad4:40cb:: with SMTP id x11mr3720078qvp.176.1597426068373;
 Fri, 14 Aug 2020 10:27:48 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:52 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <5a3f6b39567f2b7270e8d45bf1b909796259d3d1.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 10/35] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aNwZunoi;       spf=pass
 (google.com: domain of 3lmk2xwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3lMk2XwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

For software KASAN modes the check is based on the value in the shadow
memory. Hardware tag-based KASAN won't be using shadow, so hide the
implementation of the check in check_invalid_free().

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/tags.c    | 12 ++++++++++++
 4 files changed, 22 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 43a927e70067..a2321d35390e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -277,25 +277,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
-{
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_GRANULE_SIZE;
-
-	/* else CONFIG_KASAN_SW_TAGS: */
-	if ((u8)shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
-		return true;
-
-	return false;
-}
-
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -314,8 +298,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f6d68aa9872f..73f4d786ad5d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -192,6 +192,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
+bool check_invalid_free(void *addr)
+{
+	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+
+	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+}
+
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
 	quarantine_remove_cache(cache);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c31e2c739301..cf6a135860f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -163,6 +163,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 4d5a1fe8251f..feb42c1763b8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -126,6 +126,18 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	if (shadow_byte == KASAN_TAG_INVALID)
+		return true;
+	if (tag != KASAN_TAG_KERNEL && tag != shadow_byte)
+		return true;
+	return false;
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a3f6b39567f2b7270e8d45bf1b909796259d3d1.1597425745.git.andreyknvl%40google.com.
