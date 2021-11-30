Return-Path: <kasan-dev+bncBAABBHWBTKGQMGQECXH2AMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 540EF4640FD
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:27 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf8557127lfv.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310047; cv=pass;
        d=google.com; s=arc-20160816;
        b=nATQAxCDe+rsZ1ggzRcjhBsM+zTzHJtBUJ4BmVj/a8WXHhtb9oKVShGlOc91kfpFrh
         c3kMIt1f1GLcj1rLEjBfk0/NGhU7LTYyOd1uJcS3hACjqj2lMsob81gNces2Ky5/TX6Q
         5jYKxiBq7rGGIcpeTP3lvZlOfBglaAtSogd6b4Nz8eSNK/X2gmQFHmyIC016MKnSqsSt
         IkpaG6SKMb9InWDSE++Yn8zYpueEPv4RWlK1Rg/aICIBm5inc693bn65DqOu++WjrPm0
         wUVLp0NuTwgDY+uYU+NViF34CfqkL9yGlQAiJ/7vqf+RYD+Jxu5vaWqjIOOGYWIptHWw
         gq0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=owtONZBQCEOu/R/IOy2PYXv/r1vt2Tqk+5TETh/YIOo=;
        b=bzymRuqx3sF7E0Dou+vVZG8FlA/kL95QzqWIiE0wbPhxxvBDqUASsnzG3cqLfR6rCJ
         HcBvvcYKdW9x4ji5HmA3WhkWcDeY/4WdHbgU0fuiO4BDCsaBfTX09RBYehObiaD30Hmm
         XOjKbda+o3JCd3GHorqtzc7TJJpp5pDwseAiteRqldt0lvd6+n/glLxqGPTCXxhd1/hf
         zQtzWCBfgmSw1wIHgEVi3D+LCSuldo1mGQWOnMRWU/HVu8rKqUwWCFGej0rStJX0L8p+
         M+R2hz58TKCGRcuc/FVnmNySnyWler19NluOwAOmzt3FFNBCg0/dplW30i/lEb8BcLg5
         snzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VdAAuU8y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owtONZBQCEOu/R/IOy2PYXv/r1vt2Tqk+5TETh/YIOo=;
        b=M8cobJMpeMIjZznoHmOpS0P3HAPwnCZpfKzB7C1wruMaAuPH9bpThwKpFPNntvSG4+
         gV+pw3sJO7M/FQLZzRQBl9aRppr1gmaYPf3eT8NDI3isv+Y5BxcuNHnx4/73Rgj+c2AW
         gXssaovgurX0R8lXJJ1AbAuCLQ0RdRXXjm2vfAFtvDwC2z2HHEjFWzj0rY5eehatunTS
         Kx+li2F1NBkTirDZvnNeOJvjM8KmI9lJpz+UzN7aBNInJ2JfZS7vXdvuFIcDiyrlNEBJ
         fTDb0ZBk0vLd3nlqKyi8FtdUvOgsFLrWLFhSC2mdDUiWK9kslHZ73WcBmxgEiiHVRRLj
         k36g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owtONZBQCEOu/R/IOy2PYXv/r1vt2Tqk+5TETh/YIOo=;
        b=coQwnWpVSlmdoac4956LLbpTkag8rfY4vf1dEu5WQGXGAhjTlOEy1LCQ/2VzX44Gbm
         sjCuxGn0gjGcn740SyzqilCFkHOSAdM51OwuxGkypsxmmxb9vc3m/4oqMrUSAwE4Xblg
         vEXPqXBwAcY1iKlp6lC/aRwGpP2wAp9d9n/Hcku+iwF+THd+F8VhobiIShp95gQ2tDNQ
         Wth082RBNJ+jnpvcDUiG/cLtBsSlPSQ/8TfQw0RH+iz0R9b+TCtOeM0b/idpCZnOjRqE
         bWwGgjyQ4st1W7TpdfNVk7FDZIlWtiK+zPHuHjvpzf3K71ibjXQbKiuQ/ec4B9p64F3h
         e8ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CpYoWxMg97oKg/wUqGDgwp56zG/2zfibQdmOeelEE1mF4rbk6
	XewAi32r83fUn+53kXQ771I=
X-Google-Smtp-Source: ABdhPJweVmy7dZcgYiaOmtHcE36y16dKH4Y0gyGenliyqdN+T5+8y3XH0SKTwqfY0ETcjOi8L08hTg==
X-Received: by 2002:a2e:bf24:: with SMTP id c36mr1699032ljr.150.1638310046948;
        Tue, 30 Nov 2021 14:07:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls89626lfv.3.gmail; Tue, 30
 Nov 2021 14:07:26 -0800 (PST)
X-Received: by 2002:a05:6512:1395:: with SMTP id p21mr1931956lfa.98.1638310046129;
        Tue, 30 Nov 2021 14:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310046; cv=none;
        d=google.com; s=arc-20160816;
        b=bWp/tYsZR+qmUOdImzuCYqw9sq6Z0BZvK58oU/Baql5G2+qpHz3Za6CpGQ/AecLmHF
         U2E0NddsuvwQ1OkPRtG+5ffj7NNlLG3vO7ByXhdXDePbPopvyAybh8Vk3h2lfg8xI7q/
         /YpNtDicz2EjZx7IkB0p1Gri6PwuUR7Fkq9vrpQTriUvm4XsZCIbsUTzIzqqG3U9hlFr
         q0soS+bjZ0m8VcG/xzV2Vvaizyad+5NCVktXKVWjsOkNrIRWA5spIElKpa77fYGCDrVd
         ZJLyMGUn6MKyO3/iEFnK3nQfLqK5ygzXIX5QxTtP4mFfV9SCttoXR6vvcOgB2VodMJoD
         qgrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OFKLwR0n61M6N9uSIaGXlIm7A+MUpLcvomUMG6SjeVA=;
        b=yTg4FSN4HTN23HHUQMo9ZDzaXcfXj2uy2Vid6mZmp9qrwwgaDUMjj4fIbXLDpK3Ry6
         eTiP+ijVZeSC6oP8ZlG0N4m67A2rNh7Dvb5iMwpi+e2NgFH16/aOkiJ1WDDKxLHmjhm6
         4+RBMuiAQ0lVdJ0t0AHzcLlpRU8ZgYCQeAKl9klYQfHXWqS/8BJxav2Of+Jp1d8Mv7/n
         xFVZjpPp2IMdIEuqAY4tujTVv7s5LdcOErx+UjU/zeqmVpC0Gatai8ftABt3IM1gUDk6
         +L+ZeBKK3cvrHgYK32mKGDBxjw89oApb+2DEqjc8il2rJpHm4jo09nAgc482rzK/m1z7
         E1aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VdAAuU8y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id y7si1582752ljp.7.2021.11.30.14.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 20/31] kasan, vmalloc: reset tags in vmalloc functions
Date: Tue, 30 Nov 2021 23:07:05 +0100
Message-Id: <f405e36b20bd5d79dffef3f70b523885dcc6b163.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VdAAuU8y;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

vread() is a special case here. Resetting the pointer tag in its
prologue could technically lead to missing bad accesses to virtual
mappings in its implementation. However, vread() doesn't access the
virtual mappings cirectly. Instead, it recovers the physical address
via page_address(vmalloc_to_page()) and acceses that. And as
page_address() recovers the pointer tag, the accesses are checked.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/vmalloc.c | 12 +++++++++---
 1 file changed, 9 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index c5235e3e5857..a059b3100c0a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -72,7 +72,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -630,7 +630,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -804,6 +804,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -825,6 +827,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2143,7 +2147,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3361,6 +3365,8 @@ long vread(char *buf, char *addr, unsigned long count)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f405e36b20bd5d79dffef3f70b523885dcc6b163.1638308023.git.andreyknvl%40google.com.
