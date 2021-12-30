Return-Path: <kasan-dev+bncBAABBP4KXCHAMGQEOU2YOYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F06A481F9F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:11 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id y8-20020a2e9788000000b0022df5cf52d1sf2805286lji.18
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891711; cv=pass;
        d=google.com; s=arc-20160816;
        b=zSMTdIDGiaJgkRbJpkwSZA2iUIuyAtPx1eYzpj5bXgAIO8wg9WtbWBO5vAdPM1joke
         e0uvH8WdGJ/hNjOSnL3A+T0IjwNZNru/JY7GKrt9HHxcHjcdg6D2SHzz9bh9xOFRZsbb
         BirccOuNk99crV8HBjc87hxG8lhlf5Me+HTKi5ueWGrALQ4et2bHCgpkycMRHjTyV0Ev
         +fihbiGuaQ27rpuFQi0oHWP51aStIpHcrmOfK1+ntSl0EvyBFTS+hliqhTNh7Ff3tul1
         dhCu9qVMQidUeH1WWPPc7oHR0wTUSjwt5594TvlMgxdkpywf2jgvcSCPkToW7kRHWz8q
         r51g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qkRwpPkXsY3iV4tndk35W1vKVH178bhrUVgFLX0RXSY=;
        b=D/nuTvEmW7hvtOdL5qZrIE8jr1ZHvXVgSRzHZvC4hnvWpm/ABrU0sT+xHqf5b3QMBn
         khJyL1M9eFgNWI46bG0lLSHx8KWUolRxJNuMWAAAnVToqWiuYKm0lnPxsO4H+HUVAV5a
         b8+gdo1kXjxAda3MY/XozHinvdNICcsEraev93+Ne+0vZr+Z+WKAKvOaxY+Gj5ydvLFq
         5d5upY262j17pWnKJkeevCajj0Korbq65PPmmu0QdR6ziOtmE1p+lbYQiSVlq8FNLkv3
         Yzqq1FVs6ngyAy+RuyhjJcgZunQ3hzrH9N3bI9s2JCUMP9kRkZjRW4W5n0wD1rRY8ft9
         C4jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="A4V/+lRW";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qkRwpPkXsY3iV4tndk35W1vKVH178bhrUVgFLX0RXSY=;
        b=cORQuJNFJEIR43Wl3rTmB9xdD2+VxVo9auhuWNx/Sdx3h/PQNJ6KRUSZgmbHaYY9/i
         5FI/mHHfkkMYGTugF/FkUyMCB6qfbcC18XJOoWFiDKhrjfCBqEVq0DycqvABBX+S0hqu
         esm8MuwjfBXwPYg/RgnGYX14k4sye1IsvTQ4Xn0zwbUZy716GMsU/UmGyEtsvoPLDeyu
         zWuwB9w09KTg0l07XZuvKQAaGwe6fUlaNaZDVkNxL68jHyPzzrhP/Zm5u0b5dit67Chy
         wBXjhZ3B0iDqC6BNAdKNlC3U0sc0Ht+8nmjIhVkGSJlFQUREw1PkJGFyfw+wzEZcqIIy
         0pTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qkRwpPkXsY3iV4tndk35W1vKVH178bhrUVgFLX0RXSY=;
        b=dBdzYYk02TfWzESNKE7UkfvquHKzjaFKX+K72mmCj697JprnJNSKv//0pRfUk9+nyi
         DgclfIMnB1bvpXZ5DQqIyho6vewt+AMPdIaRKrNrdThCvntwUkpZAl/PY7TgOOCAnq8t
         dWwMWpIXufdwUQj8KXa2Qg/lu0uw25oA+/Aeye3+KqSBcpzZogvX6PzfGMCGru/GiUGS
         3FBjl7XXd+pLZRqxQIUeLUwtQg4CIiOO6YAncHGO9O6FlruBICnfD1qCU4pymX8Hunwi
         939ytl+F5Q57+bj2of/YODPwyvNGUjIQyN72CiAAa+od3e1yISnYRj4aMe/ZyJk2i1u2
         ojng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328OpvxxGNook1SEJMRB6IkutUh7567OATkcUyJ9lTvgxuPovzz
	Z+TMRpRDfA/2UvGXdLqnLLk=
X-Google-Smtp-Source: ABdhPJwNj3R8zUCnV4WouzSXhgGKtb62YOvWPRuZuAfeZ4MgXgihHvIK1vmyGFjrviBxy6epDZ2u7w==
X-Received: by 2002:a2e:a28e:: with SMTP id k14mr27707869lja.488.1640891711237;
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158e:: with SMTP id bp14ls2237297lfb.2.gmail; Thu,
 30 Dec 2021 11:15:10 -0800 (PST)
X-Received: by 2002:ac2:4e0b:: with SMTP id e11mr30169332lfr.604.1640891710552;
        Thu, 30 Dec 2021 11:15:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891710; cv=none;
        d=google.com; s=arc-20160816;
        b=aMzchn9vMjLbgUJJQt9kDlqXRbLmtnYPI3U4ZaqNkLHXtH6bJjJYfpe5FfZzM6vsTn
         I1JmayVmICrY/kAw/R8zps74vWZ3800jjpkT0ACrZDmJpvxuXG1Z80/L1MXt/gXHzn3r
         6e0gMI2egqUZVn79xgiR5eNTOTlPBhoVq/jwFqBn7wq03p4UqqnnxSnnLEsnr98Rl7Ol
         Tt0XpdeAd627UZtQ94jO//EwiK2vH0ac/7GJtrJy70+S5c7zbzi6uIprUkc5pzV6xOrN
         B5f2Hs6rjyGdRgLf0T2uTRTK5YeOtb/Q8L8kUA3pDcFUKoNY4oVBOugQWACaH0Nz5THr
         /zpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lRncW5DK5eaCSNy60b+4mgX3vZ6DGA+/MNVQYyqgQzQ=;
        b=ISbtQ93FupATW2aj8QeM83t2ZE4kDW4WPg4qmNk8KxQEg9iotJcnmtwwWZWgZIQNHX
         DwOepgh5pbfFdyK5sH63xN8fzvn7WAicdCLig6UY9npCd/+/rqibmY9iWp0M1zL+EiK2
         9tNVFk6iS2+USoLiFadydAojPyPiEX1Nc1ww260TLAOHFnMu5UxMf/cZG9QAAWRoNMlm
         kdVjuKpWO6ykTYA8JnMcV059e28+dz7hYCow3VjhbPkEkO9jckmGx8Llh8bJhJmhXh36
         mv2Nxz0VrYbb7C9heOMWSHeQe1y8TK9fhETDF7ZqWCyz7g7DKkV9g+bJ1VWnD7fJqeBu
         fH8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="A4V/+lRW";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id i21si1362279lfv.10.2021.12.30.11.15.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:10 -0800 (PST)
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
Subject: [PATCH mm v5 21/39] kasan, vmalloc: reset tags in vmalloc functions
Date: Thu, 30 Dec 2021 20:14:46 +0100
Message-Id: <344dc280b602b93927ad353d728c55eb21f0c6bf.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="A4V/+lRW";       spf=pass
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

In preparation for adding vmalloc support to SW/HW_TAGS KASAN,
reset pointer tags in functions that use pointer values in
range checks.

vread() is a special case here. Despite the untagging of the addr
pointer in its prologue, the accesses performed by vread() are checked.

Instead of accessing the virtual mappings though addr directly, vread()
recovers the physical address via page_address(vmalloc_to_page()) and
acceses that. And as page_address() recovers the pointer tag, the
accesses get checked.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Clarified the description of untagging in vread().
---
 mm/vmalloc.c | 12 +++++++++---
 1 file changed, 9 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index f3c729d4e130..52336b034fbb 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -74,7 +74,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -632,7 +632,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -806,6 +806,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -827,6 +829,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2145,7 +2149,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3411,6 +3415,8 @@ long vread(char *buf, char *addr, unsigned long count)
 	unsigned long buflen = count;
 	unsigned long n;
 
+	addr = kasan_reset_tag(addr);
+
 	/* Don't allow overflow */
 	if ((unsigned long) addr + count < count)
 		count = -(unsigned long) addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/344dc280b602b93927ad353d728c55eb21f0c6bf.1640891329.git.andreyknvl%40google.com.
