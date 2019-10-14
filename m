Return-Path: <kasan-dev+bncBAABB7OBSLWQKGQEGR5HEOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74DF0D672F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 18:23:26 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id a6sf7862297otp.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 09:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571070205; cv=pass;
        d=google.com; s=arc-20160816;
        b=YD85ukgwEfi20UY4KCmnATdUa3kHY7+yhHZ7iKiMKKu+DkuZr/kZKTjviJ75Dm8FlD
         ZnKx2s/OSwjg8l5WeZmrhS7+GyHEJXBxZdcPoeRY91W7nOGUvFRtGDzRpdDIL36zzfLB
         V+3sARj5awkzGFYsxttMeobXIHh3RmgyxvctaFzi5isS8jixTOAb0LJrHvvmmq7L9t+3
         psnUupdOsALrU4xDEVS9xWVKM1QiZGR6qZdkQMDALeHAFb28pRQlrfBnVT2PkJJXt8+d
         Pch3dHmxvimXJLmLdwoow+kllb9Sg7xSCb0V3/6lMtUiGTgz4Qek/vgxlB/wICfcbl4Z
         AbSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VeBh9ScR3Dkng07o+n0vmNcwMck90xUlcGLVjOShBV8=;
        b=zX5Jo7fhMv4IKSJ1Wgm/ue7gULIj5SsQqIsb0kO1i4n9J/yx4dyZqFWKCMRkrfU8Fe
         rogeK3/xmSVdx8yxFB0XiXyGRBvZxZpjNlDrHurMuuazQJgjA+6Sek8zu/b2yojPdUgh
         JbM05cbZh33l3enkM6pdvPrZ/x62Jm/e+n0w4Wnx7SzAkeyaraK60HP9aPYt1hCvKZT0
         OmjXsI5EcTA8Q4BmFy8DX4e/3PYij4gVZPGcy/JosJbARit1yDXD+LOMscENkjzO9wjZ
         35cl1SUv2LvHumXZgjvryuvJaMaXrkp/sEtUChIoiKDq49jyNIDeYiJPQsHRDdJg4N5d
         8nhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VeBh9ScR3Dkng07o+n0vmNcwMck90xUlcGLVjOShBV8=;
        b=W4QawTTVwM2Pe8tDgM+OUen/50vv9eeCnhKKcgiXJ/0q2DI3INkLgN/kzShIiGQfLG
         kXWqO7JYSNl1UiekHV193nuSLVdJY7Ma0GchjOom4s8Q5TEHNGCIsfyDV4jJWJZ0W6V/
         zKu6HFFh78jQA0BZsOapobXvVSxi0odA/neQd0ERAXogFKajgDl3Xezl5bRp2h8+k0U0
         dxskAWkkZ7KH1J/xQZMlFnLk+PtDZCU7DAt1r944GwyV1/HzHR2nZLAm6fFjyngwH4uN
         kkn44nPP4RQEliaxezS0WR1RcqzTWx3tQVGML4/VY5v1dfSQMZ8BsQEpZujkq2OT65cu
         Jf5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VeBh9ScR3Dkng07o+n0vmNcwMck90xUlcGLVjOShBV8=;
        b=AcKsFjmOGzgIggGGrPIJLvrvTy9G2jKU8QFCS7CMAFcMi93oyE3hvfI9dAsX8TUVL6
         bnzxbRiUt3yAQfM6vCLoU8a1mIUBB8N/rVp5yt7ntUnJchD26GDsnKqpJrG3srA0Kp8a
         tOic7E556Ahn4ShsW//NcL0cQeM22feDZYAGKmYF7AICNfYYfUvbqT+oQApMPSo21cio
         Ub0Wydp4ubLVEHabX4WyIZ7SeKKhvilS1Ur0R42L9EL+FzX/UTWo8goEV0TTb8iGcU8L
         nEkMk5b3/7duC8IFM9tvfBS/XGwgZeX6a+8BTgzt3MRDS4e1LhcaX2HlyUGR5UtFH75U
         SlqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWwnim/TJfOY/X2a0+QCmqwE7Z0liI7TyxusHhdAJXpdWuL2Nw4
	VQh0cI/ZghvMfHmbvvrXo2s=
X-Google-Smtp-Source: APXvYqx2G4tPTQZySV82/uaKqd5i1syFQjHuBaxlHPziR6BsFhEXYzMC28FXB0niZRfmeA5O0KiAig==
X-Received: by 2002:aca:b445:: with SMTP id d66mr24024606oif.111.1571070205069;
        Mon, 14 Oct 2019 09:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6f83:: with SMTP id h3ls2763021otq.10.gmail; Mon, 14 Oct
 2019 09:23:24 -0700 (PDT)
X-Received: by 2002:a05:6830:1e1a:: with SMTP id s26mr22863256otr.5.1571070204792;
        Mon, 14 Oct 2019 09:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571070204; cv=none;
        d=google.com; s=arc-20160816;
        b=cLl1EVIJ4B31XasmveS9ITvCAss27BrJC4WlQc5y7BRYvbubvQlFOtEPZe0CgQ00Fo
         T+Vd+SwJ1iuDNRRN0ZVhZ9goUs6k0P4SzwIH+NKfxnvt5z0m1Gz3BGt0DO7xtmIqPQkz
         dp+/gEGtBRNJ7v9rEgFjZgf7W0fTiH7jSvREwBwA/XPJstypCsWJsH0CteUgMJxi6yFU
         nvvrE9+rLpEwJm8qy9Py6RbutqHfQQ3wK4ArZbI2F01WRI7uw1hEFtSG5YZagcX8ezVG
         +u3ZziWOYfofBPajha8Wk9JQdVgYFNMAQO+K8nHSeJy5r3U+sJgYcxb1ojcfxoOFBqxD
         jBJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=OOpbcZvQnZLYTMW3rjyYOqnV3KahCNUGT0GoavBwSkM=;
        b=gTKq8YmY4wd+ouCttiRRUfEsw+AYlqGzV53SvS07JM4UZsESlNWvDVXL0VxB3GcxMr
         gRM/wIxcgd6VgjEt8DbKSNFHi+owbTZdDo4Xhh799PoATu4KS5/vIEyeGgFfQ44Z0n3u
         CoT0er/TS/2CtsDdXL99DPSkHYpMHYqFou0KGt/nnNTa52Z3YVJeAa8wxPNbGwPg5g2+
         CUu3o90M3FS3AHtsRoec0qh42WR8WgG8qHUJcNIRwF+oA2/Q6f72Q4hCQUORKzhBX9Ma
         NspoiX5eWaklAAL41MJl4fAb7NKUASmsatEeDCKegIejMw0mNu8DHCn/A5rCOsJX9b/s
         3O2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v3si977924oth.4.2019.10.14.09.23.23
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 09:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 00e5f5011c1b421da9e2c7e6370c8c49-20191015
X-UUID: 00e5f5011c1b421da9e2c7e6370c8c49-20191015
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1840082822; Tue, 15 Oct 2019 00:23:19 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 15 Oct 2019 00:23:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 15 Oct 2019 00:23:15 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v2 1/2] kasan: detect negative size in memory operation function
Date: Tue, 15 Oct 2019 00:23:16 +0800
Message-ID: <20191014162316.28314-1-walter-zh.wu@mediatek.com>
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

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported -by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 mm/kasan/common.c         | 13 ++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 18 ++++++++++++++++++
 5 files changed, 54 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..16a370023425 100644
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
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
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
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014162316.28314-1-walter-zh.wu%40mediatek.com.
