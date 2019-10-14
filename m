Return-Path: <kasan-dev+bncBAABBNU7SHWQKGQEESYAE6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 888EED604D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:36:40 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id v2sf9830415plp.14
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:36:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049399; cv=pass;
        d=google.com; s=arc-20160816;
        b=kw3q4W9Ob9AACLAxuaOOq2bMa6Tyk1vDhnHbXmMjGLHt3CLwB2KjmiW7E0fn93i7DN
         O5F0o+anaw/T43QpUuY25Fruxb/Lulxt6qOFwEsb/i8bYwImmLTLt/onIn3wmKkqJSHs
         FsDXNBtqmFGwHeXvSR90xODv4pD0UOAB3/9hKPdTYh5Uj00GuwWnGzv3GJlVGVew7/Hk
         lNfvYNBhUZNxOFIC2q60K7nryLk0iUBDYerlgnnp5l5S/yBld60Fufzxsl4oWNax8tr1
         VjHQbr7MqoZ/CBN5rebgu037tFtGWRN28txEQNtAfsQrhmGqL5y6eTsp83/67MK1EGdR
         TY1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TEu1+b6X+7UzQN9UGl91HzWrnlRU6kF7l8Oxm3esUIo=;
        b=rHbu0lzVNmRXMMFy3iVazzDUhBu7xQxQK1dtBB3E1OVrJh7fBG2YfgLcekKDDJJyTF
         l1uwb/5NpiWd4f1fZo6I3+6h3GySANaFRS3t+mtR10b8l40Vozo/SW8SSjo/jk3VygUS
         4HSD7Dn3dFmJiRGqRDmv9EWyeB+qUeb1I0TRKXoWGnO12V0epjDfTLdIJCUmd2UiwQvw
         t9dfdhOgBysDJFySTcyCPuCoPk6q8XEN0JWCpi0K/Dsgvbv2bliFNaDBKuv5f1gM37c+
         3xdIE/kUvt0v4nl13CJxK0ehE3JWpjeBgyXfKLM69B9mXyQXDSC1qWtBNga9A6Mt+GLc
         NtUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TEu1+b6X+7UzQN9UGl91HzWrnlRU6kF7l8Oxm3esUIo=;
        b=AafSKnmF2h/KOyemExqNpj9YRUzaeseviVDSL1STvC6rZZWpA9EUFPS8GO/VnWJi1m
         ICynRxcKiznqijgJlSWLDOHEADqLBgqkBafBnNgH7e8673+klrQB3UMQviGCJbK70ZLK
         1qiPZm1RCoOmEfcFasBPh/Jss4Jb75iQpxul0Vr/KlnNA239EaRNeWmIHmYinOcTJs9a
         1S9UBi5pj7ne9BSUMHaTy62V6wX2+pPtHoalc9Xmwk/4uNF0ZyOAB1qtZJ8hvVnUtX9C
         oF/MFXsAIhtccqL/kx9qvT7JBEjJf6lXJnoSdeqr97Sc/L4BOETbk1V+WWlkiwz5BV+r
         KpaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TEu1+b6X+7UzQN9UGl91HzWrnlRU6kF7l8Oxm3esUIo=;
        b=HDqCfkwPS/Zi1myz3GAYwzFs03iF24puvyRwMYA94lLRNHQ8nWEYnKUjBy1rtumJkY
         deVzb1iUjM0FBzym3xNPD7WhFf8rkVdYkntebcN4wGK4FYbEJ3oO+SMzaUdB29ZdvgzT
         1WaCNkkcfAuZlkD+yUhNDusgmHgzMP48jWNlId7MScm7VeNyjd6t86qgrHYdsM24NHzV
         MefcvqO1ss2IZXourbUd25qRLZuzqIJ2aMPDSTMgf43c7bXXWLQe3TIGk+yuaFhjjJvB
         vOEqJqyqmLCNh1v8EzAi+LUDe212Qy/Tn912si8j/rdQ+oFVFidElbapwMRf58/QJFwi
         shTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVoZc2rUvflwy50nqg5ozKeRcWK5Mvw5+ZmpQh4khDXPMGXQH5/
	RZj0OsvuSWnu8xtd78AHf6M=
X-Google-Smtp-Source: APXvYqzWEGnH66EehPM4t8mTJTi9MzNedTzfr8azry5snmSTeqCIYb03xRfHQzRp3P01S2Gs2ONusg==
X-Received: by 2002:a63:5064:: with SMTP id q36mr26654113pgl.393.1571049398725;
        Mon, 14 Oct 2019 03:36:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:5996:: with SMTP id p22ls3922558pli.3.gmail; Mon, 14
 Oct 2019 03:36:38 -0700 (PDT)
X-Received: by 2002:a17:90a:ab0e:: with SMTP id m14mr34238184pjq.78.1571049398455;
        Mon, 14 Oct 2019 03:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049398; cv=none;
        d=google.com; s=arc-20160816;
        b=btss9F3trdHHV/Nt+dNq/+/52o0vpdLSQrih1Hzx2DJD/dyV3a77GAQ/Lu+/JGvVYR
         Kl2bjIPtnH+Ia5lzpDmEoR5+rqKrRbdUEneSMmYNBZ7HpLXI1O85+jb7ltZ1S5x9jcG1
         P10fld54ljwUUnqcmecOA6/roedvud2JPiTsUODfy25k8Pt4HYHJd8q5DhPUfVBnH4oR
         RCTTEiib25Naf2wkwNerKXfyXbWuZLZU7RoVCGGibmJvF+IH/w6H9m9AenrpUOIel1Qh
         x7x+tWOiWloPzcOuS1DYhfxzfVFr2vVyH5yLEIEg3dibuFdrYv4tQfsdEtklpcJ3u9no
         etTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=FVwd12vEcbE8GAmEcyd1hVzRSsZ/9O5JJDMJ0e6luZc=;
        b=bgMm4vPeXRmrFm7CprvRv2uwsrCf90KVfmApasOlum8NFnPIpiZ3NX2dkFt5jzC/QT
         MH3z8o2+r/abGAEwvoLCvdjDs4jXjSHo3W2SI44pRbwpb3f7ZgqtqmmdtJJMHukTuzFm
         ZxAKm3CVeELEm+gNGvnG3eD3AruYL/w6WDDRmRAZGyEsOGPo2NYdTiLXNj0XTtkwTcIg
         dFJ2oRFuihewdp4phe36PjHj/ZfITVPVwWpLOQtPXrbELFWdgISHuM9+vFrwrgGCAgyE
         iDMI/aKJInN/HsBL9/uNVecsFVbwdBF2qzKzEe/FtsE7anX3np2DaiptQsRMmhVZVyCx
         0Tfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g12si1632602pfi.5.2019.10.14.03.36.38
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 03:36:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1b6304880c8042f7a27372ca13839b5b-20191014
X-UUID: 1b6304880c8042f7a27372ca13839b5b-20191014
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2088515174; Mon, 14 Oct 2019 18:36:35 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 18:36:31 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 18:36:31 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH 1/2] kasan: detect negative size in memory operation function
Date: Mon, 14 Oct 2019 18:36:32 +0800
Message-ID: <20191014103632.17930-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

KASAN missed detecting size is negative numbers in memset(), memcpy(),
and memmove(), it will cause out-of-bounds bug, so needs to be detected
by KASAN.

If size is negative numbers, then it has three reasons to be
defined as heap-out-of-bounds bug type.
1) Casting negative numbers to size_t would indeed turn up as
   a large size_t and its value will be larger than ULONG_MAX/2,
   so that this can qualify as out-of-bounds.
2) If KASAN has new bug type and user-space passes negative size,
   then there are duplicate reports. So don't produce new bug type
   in order to prevent duplicate reports by some systems (e.g. syzbot)
   to report the same bug twice.
3) When size is negative numbers, it may be passed from user-space.
   So we always print heap-out-of-bounds in order to prevent that
   kernel-space and user-space have the same bug but have duplicate
   reports.

KASAN report:

 BUG: KASAN: heap-out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
 Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72

 CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
 Hardware name: linux,dummy-virt (DT)
 Call trace:
  dump_backtrace+0x0/0x288
  show_stack+0x14/0x20
  dump_stack+0x10c/0x164
  print_address_description.isra.9+0x68/0x378
  __kasan_report+0x164/0x1a0
  kasan_report+0xc/0x18
  check_memory_region+0x174/0x1d0
  memmove+0x34/0x88
  kmalloc_memmove_invalid_size+0x70/0xa0

[1] https://bugzilla.kernel.org/show_bug.cgi?id=199341

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported -by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
---
 mm/kasan/common.c         | 13 ++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 18 ++++++++++++++++++
 5 files changed, 54 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..6ef0abd27f06 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
-	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
 
 	return __memset(addr, c, len);
 }
@@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	!check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memmove(dest, src, len);
 }
@@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	!check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memcpy(dest, src, len);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..02148a317d27 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	if (unlikely((void *)addr <
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		kasan_report(addr, size, write, ret_ip);
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index 36c645939bc9..52a92c7db697 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has three reasons
+	 * to be defined as heap-out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 *    a large size_t and its value will be larger than ULONG_MAX/2,
+	 *    so that this can qualify as out-of-bounds.
+	 * 2) If KASAN has new bug type and user-space passes negative size,
+	 *    then there are duplicate reports. So don't produce new bug type
+	 *    in order to prevent duplicate reports by some systems
+	 *    (e.g. syzbot) to report the same bug twice.
+	 * 3) When size is negative numbers, it may be passed from user-space.
+	 *    So we always print heap-out-of-bounds in order to prevent that
+	 *    kernel-space and user-space have the same bug but have duplicate
+	 *    reports.
+	 */
+	if ((long)info->access_size < 0)
+		return "heap-out-of-bounds";
+
 	if (addr_has_shadow(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0e987c9ca052..b829535a3ad7 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	tag = get_tag((const void *)addr);
 
 	/*
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 969ae08f59d7..f7ae474aef3a 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,24 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has three reasons
+	 * to be defined as heap-out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 *    a large size_t and its value will be larger than ULONG_MAX/2,
+	 *    so that this can qualify as out-of-bounds.
+	 * 2) If KASAN has new bug type and user-space passes negative size,
+	 *    then there are duplicate reports. So don't produce new bug type
+	 *    in order to prevent duplicate reports by some systems
+	 *    (e.g. syzbot) to report the same bug twice.
+	 * 3) When size is negative numbers, it may be passed from user-space.
+	 *    So we always print heap-out-of-bounds in order to prevent that
+	 *    kernel-space and user-space have the same bug but have duplicate
+	 *    reports.
+	 */
+	if ((long)info->access_size < 0)
+		return "heap-out-of-bounds";
+
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103632.17930-1-walter-zh.wu%40mediatek.com.
