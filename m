Return-Path: <kasan-dev+bncBAABB2EO73WQKGQEUMAOBWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C9A0ED765
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 03:05:30 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id w22sf11790062pgj.18
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Nov 2019 18:05:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572833128; cv=pass;
        d=google.com; s=arc-20160816;
        b=iuSSC0nwxKo2W/Jk1JQxSltO39jDn1pwQdhlW8LVv29L2pWvKf4+216vXE5TsVSDaj
         WCqXFWw9HAwGpV1b4tJTMYU6eOyDPZ3YVMTAxwsIoH48ULDsCi/xgblcfErbqe43rnG+
         fHhPCDFSyY2MpiQWhgTTetlh7WPWEN36Ml1AMhIMDMOOuuiaIGMvZ8Afv0VzwGzxSAOV
         ZwDdv8ay7KTfY2gN4LbxKlosgPRaikcqPg4oFWieIwWfsNM1feP9n3XnGolAyemWKPAr
         uSmrmUk3qvL9HA7nNhrYlc/bzPchtDFrYd9ttXvq2Pu3Zw2eHXWfsHRAZia9pqyoL8YI
         912Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YRiaLrPfNpR7D934ficLE7cccqwmUc6jggS09E46vx0=;
        b=aDq6vsldZfiDwxll+uAytEF7WoT8E0xlXN0wSK2XhL4EHDgbj+/GmwEhXpeNH/YnKW
         bUdYW6427sTaH3s6mbURVxPNrVzIIabYrQEccB0u4Gg5Zacy78nlxOjrklaCdpfQj8Oi
         OObOBL/oANFkFi8GEvr8n+k+UuXaVk3cyEzZomn2LF6XJImJl93HVfZvCF2jxFrYijRj
         j10oBVS/vjtmVLvcQ++5H+0iAuykrw09S8Cat+KGxBhPiydJz4uxqoa3zwdg3+/mZOh5
         RMA2YIpWR0RxKLq9MSdHsWrZJWgq8XeBRSs3qmIorygcAKNwNdHyICUzFtOuO+Z9y8Gd
         zKJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YRiaLrPfNpR7D934ficLE7cccqwmUc6jggS09E46vx0=;
        b=ClHFkFu9RgoomwBPKkQHcouswkBBGzDTPIEmIYAYtPIF9SP7bWYrwo5R03BIAiwvoS
         mKfeY+jUyOsRh6alkyaT0KEE0FwH6mDJWGL5yYPM1isauoLiu1WK2SY3QDO8xSVSuTA3
         dFNl0RWZF2FYNh/3tl56GrQBNiecrzZdxOrMpk667itVgBcoI6NKnrRBRPWb477vGJB1
         1K8/CkxFzICypnpOZCvjgoxvqnGxG3vNqJD5GKXZPLBaHN0ZHQCM1S0teLBqnIml6n6I
         UPwRFUiZCTeTUamuJTKbJu0aqrOjGh8AYcmkjOSPEQ5KLiBLXzIxDIsOiDqX/q5LlZNO
         KnyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YRiaLrPfNpR7D934ficLE7cccqwmUc6jggS09E46vx0=;
        b=fGU9B64xJMJZumggqzX0iysY+/PcgrT/AJ40lEAErANTK98bLiNPOycxjQq0Wqa9wK
         7WUzOacJhHFyjGQwJN7z8kc1Gg3kReM0VrhEqBcTasWLnd/E14t9XtMKMZfcwQ2a7H75
         S/Wo5AkGYu5mG43t0nX9IofE1pNVpqE/QxhDxKMHJoa43NotIT0pDKSd/t9rxQYAw+YC
         AiDEAtX9RNAV47v/i42C1nxniiksxar+f3OGJ1p4KmzkAGPRMRZsZh4hgZNwbcJwHVhb
         8LPMNNgVZeoGvMMA9g5Z/At9pnehHI+FIwk+6CO7Q91Hgwo3wSSa2I4i0cYAmznK/01M
         o4/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWyEUuPFDMt46ewFyo4c9YcfybJ7IyFemtNlfajXoYaATBXBKw7
	GOuvvs8Q3ux5PL8PQM6h4zA=
X-Google-Smtp-Source: APXvYqxQ8hqxeZ6LZZjxye1AwbFYrsA30t5K65V/uYxTEYi3q0yp0IcIJJE/tasgU0IzQ5H2TJAtqg==
X-Received: by 2002:a63:f94f:: with SMTP id q15mr6963072pgk.412.1572833128519;
        Sun, 03 Nov 2019 18:05:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls3112891pfb.2.gmail; Sun, 03 Nov
 2019 18:05:28 -0800 (PST)
X-Received: by 2002:a63:eb47:: with SMTP id b7mr26695382pgk.179.1572833127916;
        Sun, 03 Nov 2019 18:05:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572833127; cv=none;
        d=google.com; s=arc-20160816;
        b=VJEScrFSpEs8HvedanyE51QApSW2etmbq3hw5cZyQgBiZP9ZkNSJfHFyCpjcIYz3eU
         sEkVauN4+0J474MWjRogKZ39g/7zj7hu1Pbyf4ljinGbtCrjikB14DQ6fbIEyxlbqqRu
         ITNZ5Vlx18EZ+1nmbYBNlbslaqfbdGn+/Eih8gN51x6NlfRu3vDCTgiveB6ZiDVW1G0R
         kjwy+2WWtUZv4LnsTjiVekah9QLB0ACW2i91GtqKIBOBI+12k1UaW/OCgQffO75/jbv0
         m5dJjl1iEI+53rTEwpl4BZXbSRQXVlN3ekVzXkXzIaYQQG4HqAjT2+EQ9LFy0mDUAbfa
         /WhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=r0mMRPMhbjJLPm/S3b+Jeo0txFeZF/3R5gTEshdBWSA=;
        b=fCUz5UNGsitv65HeJ1UZjbnPmZMbddp/FbTRDpcC7/j6YMg4KPqTvu3ufb0ZT6Mj0b
         PIclyrH4m1DL882e6CuRVx4Pfx4DpqBkh+qQ7zh5lbZDGQTB6nblKiDz0k4qU8iGLuJ5
         XyUrNWZxQbwqWkDDVhGw0kDmCvUDyRHWmmdqgEe6BbAXOZiHuQ9f7RzsovCULwXEOtxs
         IidYvNQkzTu7IZECkQVxlGNJdiDz6e4sFXspMFZD4ibbX6pAyMvJQqWTZIA3iyfsmH8K
         h7AFCTRj1CMcKgyPhi/rzJXZ1K1qX1157RfPfCalYTr/5Ip2V1jKxxeK9N4mjVNo4Jl+
         WfBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id h13si529723plr.2.2019.11.03.18.05.27
        for <kasan-dev@googlegroups.com>;
        Sun, 03 Nov 2019 18:05:27 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 235d6a98566b40138f5536bb1366f053-20191104
X-UUID: 235d6a98566b40138f5536bb1366f053-20191104
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 357250501; Mon, 04 Nov 2019 10:05:24 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 4 Nov 2019 10:05:20 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 4 Nov 2019 10:05:20 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v3 1/2] kasan: detect negative size in memory operation function
Date: Mon, 4 Nov 2019 10:05:19 +0800
Message-ID: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 1D3F81C588A033BF399029246331A216836E7AD6682CE88A56765C49DA8899102000:8
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
and memmove(), it will cause out-of-bounds bug and need to be detected by KASAN.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104020519.27988-1-walter-zh.wu%40mediatek.com.
