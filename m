Return-Path: <kasan-dev+bncBAABB2OOYXWQKGQEQLRZNCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 82979E2CB8
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 10:57:14 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id p2sf18478918pff.4
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 01:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571907433; cv=pass;
        d=google.com; s=arc-20160816;
        b=gnFyj+36xeVJWGIXQEjHML7B2kw7uOU36Zeq6+ggXWocgZYxGe+qH3WckYf2yq6Brg
         Sj+crnfEh0jEWG42ouQHq28ga9yW4OpzChA4EwOGZwRH3by/A372aMBRavapd+zipvpO
         XExkc0B7Svo7PSJKCGp+YIEnWslEjJwYn9PdsKfBOR2FzwV05NbRQvuha752YDefUUEf
         cs8K/qC3HslP3OoBeSEdYuYrmNcbPPHf46bJ47zWR7tG4IAHlXAqVr+BWMPH0cqr+mQx
         Qz3D77rU7p1SdE+X1p7+Wfp5+JL2NdTsD5Bjd7ZBy/kxWvbVgJE3mKV4F9t0wpAZ8PAK
         /1fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Vnye0hJgb6bc/o/7t57z4K/Fx9PXwEb/2Xa8jTfx/6g=;
        b=iWO7Maiw3/1XYHd39HoWq83WmrahLtkcKU9pciXRmd1VafRpsT9Krh8TL973qEdtlb
         ARRUJNDpN3SXjukLkfzINO4EYOdTo90GKW8WxAejJjZaHk1u7tL3OANof7xR0P/nNsfa
         k7Mm/lu1mkZHTEL3tMfFMIMfbbEVy0xpHpcNcyzByQkYM2g+WDFbM9+KlAAMzKC4hGFq
         EBTL3W7+KIstjvEjzqoqcE9FmMibaNZhSVfsXPFIn7SHuZbPF05tG+/T95S/htQXYQnw
         QyiLYM64LNjxf7I2g4F9FNr90AAgsVXScngtasCCCJt/SLxPpezkksVK0TAo/GOfvu9W
         xGSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vnye0hJgb6bc/o/7t57z4K/Fx9PXwEb/2Xa8jTfx/6g=;
        b=RPrZa/0m6hdhLAdcj4EIVLnliiZuBDcgwuWdI6t4++hg9frlrWp9jTX7CKtn8ATNZB
         Gh2v9XQ7Mf+jhv5e79JElvArPyAPceK0gBOqd6ZfnTGRYKVN/1XQQB4JyZUtmPt8YvVI
         Mdla0sMnUVQet50q2PYUAYMFkKDoNbc69QHl2hO6J5VkwTKaJeGNzxSYmhXtp7W8hU8h
         9PMzAqCxjWTVkUVHcZKeHp2AkqKRM/S2/jT14aE9z6S+p38CYYDFLN4610qDhOX5TWzU
         z5Mc0Wpo8xOBbIAghyQJD6J6XrhIQyIcz4m1knmR+n10v3NXSoGeiOKy1BfDfc6BFITC
         OJWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vnye0hJgb6bc/o/7t57z4K/Fx9PXwEb/2Xa8jTfx/6g=;
        b=dWWheHUNt/FjFEK1MBZ4gYlf8XMjYQgb9oM/Mh2qCEGg8e5kKZ8opipUb0o0KEZoBz
         luVZ3nNK0vQX7G7Nb48hyEQXBbETWvBOcjBckEg9IyG9EpQJUrdEy+8B9EtA8mAnJFLK
         CLoEp5VWpiKWVikdyA0KN8p6KViYHI2JYdsepyzqPGAyct/v23hLlU8Mf6Z8hcJI8gd9
         ihsluTln/OahlrDWvCxYcyd83gtBBhgWk+35CvGBYOV8re4ulCL6nBIEv9ZNz2ByVLlL
         a2e3o5X3Ultog41aRcUbotg6FVrArEXxCv19rI+Qqu3HoAPvu0xh1Q6VXbpfyeyocI4d
         0G5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXPeDv7rx0GDdCgaWwSJ2lcrJQCPnWmoOazKP/nZA8Wwqwk8Rfz
	ZGb0v9rXT80jxafsFbVDxco=
X-Google-Smtp-Source: APXvYqyQgv3yhmf04ou985NSN1jzfs9u1rJZdOytqwOJkGXuNIymmSjHZ3zTHcjB/jtwLWa7taF2vQ==
X-Received: by 2002:a17:902:768a:: with SMTP id m10mr14560231pll.343.1571907433200;
        Thu, 24 Oct 2019 01:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b86:: with SMTP id ay6ls1591837plb.7.gmail; Thu, 24
 Oct 2019 01:57:12 -0700 (PDT)
X-Received: by 2002:a17:90b:153:: with SMTP id em19mr5699073pjb.22.1571907432914;
        Thu, 24 Oct 2019 01:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571907432; cv=none;
        d=google.com; s=arc-20160816;
        b=Sv+ucmlv8H9Mul9C45E3wgMIhBO1/l28ZfaMoWE7QXFmJMhF58OcnKdKDU3T3RkTrs
         KaP4YoNuJ2UFY9YMTkjTTHN5P03UzRRllzphfW5n1hOntUzaAD+7D4cEjKkVX72lpi/o
         uDjWgulwtlkL2gieC/8yf8YglU4JFAkO3ze7uMRHAdu4wc32QEiWVyWDeTbTfxhkUBZP
         U2RPCwNORrV8WNhLmoBG74e1qtKeJULLf6pOUdLAHgsB87fxn+zcQL/qcmbmGzKUGIJR
         rjCUoEwq+NCvdT7RqWC36+UI+f98ARyaWeeYm2AOArC4aoCJhtPHfE5TfwK3a9Y40XpW
         Bscw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=TXZ2NNtKauSA1yP3EjFosYeo7HxtmfpPtFRnEB5MPH8=;
        b=VHacLWghe0WCnBWjOBkPO6e5d0Vctt85LCtpUdIwdfqL3pdoJwCa6EH82t2wLmWPrj
         e3JXTOO8X9vz70VFONkCr4hFmHCx0KvYiGCbvI8r+tu5xXzy7yMf8btqYUE60uH11hFD
         kPZ5TfDzSoXzlMjnAfAur+RKKSy2QcnAHvhW5XCSYfatiwW5HsaNMV1E4hp3wh44VyMl
         ytBwme18gPl0ik3k1ky+19PdTV6c934o3ykisa/svybt0DzZO/mOJjsMPVh8h3LXFxNX
         4uAKfkBa1rz274yos0/EUgUjkrry0VpygWB3GE0k3Lh26GwpiTc7AX+90JDx5pwTgJQl
         YmPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d5si1234448pls.5.2019.10.24.01.57.12
        for <kasan-dev@googlegroups.com>;
        Thu, 24 Oct 2019 01:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: fcd8404f8dd847e583cfd21705ce994d-20191024
X-UUID: fcd8404f8dd847e583cfd21705ce994d-20191024
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1577409883; Thu, 24 Oct 2019 16:57:09 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 24 Oct 2019 16:57:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 24 Oct 2019 16:57:05 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v3 1/2] kasan: detect negative size in memory operation function
Date: Thu, 24 Oct 2019 16:57:06 +0800
Message-ID: <20191024085706.12844-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

Changes in v2:
Fix the indentation bug, thanks for the reminder Matthew.

Changes in v3:
Add a confition for memory operation function, need to
avoid the false alarm when KASAN un-initialized.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Reported-by: kernel test robot <lkp@intel.com>
---
 mm/kasan/common.c         | 18 +++++++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/report.c         |  2 +-
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 18 ++++++++++++++++++
 6 files changed, 60 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..4ff67e2fd2db 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
+extern bool report_enabled(void);
+
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
-	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
+	if (report_enabled() &&
+	    !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
 
 	return __memset(addr, c, len);
 }
@@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (report_enabled() &&
+	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
+		return NULL;
 
 	return __memmove(dest, src, len);
 }
@@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (report_enabled() &&
+	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
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
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..c79e28814e8f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -446,7 +446,7 @@ static void print_shadow_for_address(const void *addr)
 	}
 }
 
-static bool report_enabled(void)
+bool report_enabled(void)
 {
 	if (current->kasan_depth)
 		return false;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191024085706.12844-1-walter-zh.wu%40mediatek.com.
