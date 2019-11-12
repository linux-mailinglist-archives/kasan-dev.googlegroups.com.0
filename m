Return-Path: <kasan-dev+bncBAABBVFNVHXAKGQEKO53V6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 39B16F88E9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 07:53:10 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id b184sf13458704ywa.15
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 22:53:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573541589; cv=pass;
        d=google.com; s=arc-20160816;
        b=tauaJ7aIFA/jxUDjqwtv4h2IKM1TOP1lRmEWd73aaMiBJAuMmgDcGc1m3W4VFPXtkY
         YQcGUgWqIOPn3lRU8Q51mgOjeHSle83OFVTv8FO97u0DG1LFBmv9Jy+CYCr0LonQj+pj
         bC1iUJjGcl1BfDdeYskN962rdM1PdALsp4itp788/IoO8rc8qoEVmUM8wUC4ozKJLxz4
         DSL3n6m1fb5HGHGQ2vbCZ4EFz9fPD2swUIbgoo4j9EP9YbFOdsQEHKFDz41eHRa5euk9
         qSBPGbiT3sak4tVEQFeSHGC0eJj7KdYddbHeorDA3jt0gZx6S1dCYsoETt4C75So15XT
         /xxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hePm3SI6YkKlDo9cPcGQLnFSpV4RWfK6cK11dABUuDQ=;
        b=wXBdbrn1khUWx/szbDktrKIy7Otp0XwUP2VHY7svWnS1+ZjaR1ZnfPEOHNYoqtq70m
         IVd3Hskr1faJyI1k2rzuQ485Df2CfaBz8ltA8Kg3Oj8uWylpUJFxNcJ3//3mhOzifxll
         oGtJNmGixKe/qYhzH7EK94W1zXpc+8Nzu01GlfRDAPofKHi6kYTHi9MpTwmn16OxxcI5
         gafgz5Ntvtjt09aMw6qAcU0rbNPtJ3P1EBL1DCl8lk1KUc9P2al80n+ocZjdMHSHvAuR
         1IxKy4qbRUMQ21Mzv867YA0Qz0zLGa8Zpa6HdLfc+c94dn/abMyGFKvD0fob8rkRYCj5
         Rs6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="OAk/h7tY";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hePm3SI6YkKlDo9cPcGQLnFSpV4RWfK6cK11dABUuDQ=;
        b=eUKVE9pJzbr8rOqacrVs9m8wlU+Vd0LeNJ2LhyEeJfZX/g2tC8v8ru5FoKmoA/M7lK
         17Ih5ZP1aMxX4UGm+/CaVWF2t9xjea/hEXvm5wb2fr3yCELCv/9BoRSOyJC4l+8mU8I2
         Dop1oIphHJ80NNOiNB7JNlr3mlHk8G5LGJngm4YUi9MwVaqVrpQAsqIE8eMSr1mj9ZoL
         Sp/q+2mpNex/7tGPdPjQvKL/xo/YqhScRyZot3RK2Hq4WCjvCJ7QeWzwiokGOzREnP+Q
         b6ymt7xDcxnDJBdb2Mw/mOySmfscm6Xuk9gu5I9yvrsk4oyukJAz67ASzR72tvLNFmTV
         Fgdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hePm3SI6YkKlDo9cPcGQLnFSpV4RWfK6cK11dABUuDQ=;
        b=uSSKOg/vBjNYrNilIXbpp+q6x9TXR9evLqPHiV0tZjl6TqTui/PMTqNEJKf9G9Sp03
         utvXnaR1QnLHwFEAD747jM8zVMZ8rXqh0nwWPHP2c4jtP31R3nPrp4xzamPN7fu2EqVr
         IIe+GxSblWaeLR2lPBbE4qIA49U5HxIr9ro8VfcCsakM2lLajSXw2gZWthTcD4J3vOB3
         HANmblC7lEdrOlRylzMVUc7MBt2dKHLh0ll/J3behm/PFutSCJ6kkWI/bjBXL2ebeEGm
         YEq4+5ToqXqRAhAQ0PzynjuI/Q14nGR0W9cO1C18NNWL+EXF2H3EBs3HVwosxoHabBI4
         xFdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXdzMGGwFK7AGyhCATFFLfXLeKI1mQtM2gXM5gM0TK3iKmBPUeU
	zdEUVrVCynhwggRgLM8Bx1E=
X-Google-Smtp-Source: APXvYqz05/SaSBFXBQ65nCCBVQlu+2DvWUUWUgLDypWI3sMv1D7AnEJSWl4Hxou8jMOeAWeSvS7Ylg==
X-Received: by 2002:a81:6d97:: with SMTP id i145mr18423475ywc.389.1573541589097;
        Mon, 11 Nov 2019 22:53:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6c89:: with SMTP id h131ls351450ybc.16.gmail; Mon, 11
 Nov 2019 22:53:08 -0800 (PST)
X-Received: by 2002:a25:258a:: with SMTP id l132mr23193000ybl.227.1573541588601;
        Mon, 11 Nov 2019 22:53:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573541588; cv=none;
        d=google.com; s=arc-20160816;
        b=LO4WXmigm75zU3J/LLl771OBMpGT5eOaw0S4FRDo89kPX5PdcX1oK74msAxFtgd1lu
         8y3JwuMHyW/Odl4lpVGvtwjEp2bQfGBOfkviyw1ehHM3QJ96lV00skfZ2/KsmJfVqUhs
         gLOfqNgX5wfNujlWDXh+Rlzp0WismnCXW/lIiRTfypmwSJBfY/vgaUwalKA9voyDEVjW
         l6PeEgKYE1cNuC3w729lupw6TldfeaAME8wzZ7iHI4eoMd36fXVtYwf4X9bRDefxKNO9
         zHp0P+TrXs7P1LoXKploKuWBFJAfE3i8mCFQQIi79Ro8L08evKwhcd9axL8b2vENoohB
         ut3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ajKp09d7IkN8w+Fz8lu3IvhtATq24/kTWameVprGZZI=;
        b=tSVcaD4olTl39R5UFX5WwpYpdLora0bR15uoBZ1l4dBEi5KtYHya3s0R1uu/RxXRaA
         wa/uglEJNyWx0hNktfnIO3iaJrMLeSlKtuug9AVMLCS7JafwMCt73R0z5jx7ih3J+qGx
         5TqKqk4ApxK7+WWE4kJ8p0jU802ekAP4u6PsqizvFXLDg3CkCotRhEelCk8yXMdO10W0
         /9yulgOExEYGN7N4JSf8k5m0UsUlrv+PKP7x+s+KfAevHsgsVwewjYAcmh5DjIAhgBJv
         VCPY1wIAOEmnnudUt9e/sILQfPvqFK+6dfhLgFcRZ70tbUv5TPMtQ7MiFlUBX1I/SzrA
         r3AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="OAk/h7tY";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d192si1160394ywb.1.2019.11.11.22.53.07
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Nov 2019 22:53:07 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6ed53018ad224b42b8a8ab472c12c54c-20191112
X-UUID: 6ed53018ad224b42b8a8ab472c12c54c-20191112
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1234647263; Tue, 12 Nov 2019 14:53:04 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 12 Nov 2019 14:53:02 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 12 Nov 2019 14:53:02 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 1/2] kasan: detect negative size in memory operation function
Date: Tue, 12 Nov 2019 14:53:02 +0800
Message-ID: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="OAk/h7tY";       spf=pass
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

KASAN missed detecting size is a negative number in memset(), memcpy(),
and memmove(), it will cause out-of-bounds bug. So needs to be detected
by KASAN.

If size is a negative number, then it has a reason to be defined as
out-of-bounds bug type.
Casting negative numbers to size_t would indeed turn up as
a large size_t and its value will be larger than ULONG_MAX/2,
so that this can qualify as out-of-bounds.

KASAN report is shown below:

 BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
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
 include/linux/kasan.h     |  2 +-
 mm/kasan/common.c         | 25 ++++++++++++++++++-------
 mm/kasan/generic.c        |  9 +++++----
 mm/kasan/generic_report.c | 11 +++++++++++
 mm/kasan/kasan.h          |  2 +-
 mm/kasan/report.c         |  5 +----
 mm/kasan/tags.c           |  9 +++++----
 mm/kasan/tags_report.c    | 11 +++++++++++
 8 files changed, 53 insertions(+), 21 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index cc8a03cc9674..2ef6b8fc63ef 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -180,7 +180,7 @@ void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
-void kasan_report(unsigned long addr, size_t size,
+bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
 #else /* CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..4bfce0af881f 100644
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
@@ -627,12 +630,20 @@ void kasan_free_shadow(const struct vm_struct *vm)
 }
 
 extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
+extern bool report_enabled(void);
 
-void kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
+bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
 {
-	unsigned long flags = user_access_save();
+	unsigned long flags;
+
+	if (likely(!report_enabled()))
+		return false;
+
+	flags = user_access_save();
 	__kasan_report(addr, size, is_write, ip);
 	user_access_restore(flags);
+
+	return true;
 }
 
 #ifdef CONFIG_MEMORY_HOTPLUG
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..56ff8885fe2e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,17 +173,18 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely(addr + size < addr))
+		return !kasan_report(addr, size, write, ret_ip);
+
 	if (unlikely((void *)addr <
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
-		kasan_report(addr, size, write, ret_ip);
-		return false;
+		return !kasan_report(addr, size, write, ret_ip);
 	}
 
 	if (likely(!memory_is_poisoned(addr, size)))
 		return true;
 
-	kasan_report(addr, size, write, ret_ip);
-	return false;
+	return !kasan_report(addr, size, write, ret_ip);
 }
 
 bool check_memory_region(unsigned long addr, size_t size, bool write,
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index 36c645939bc9..c82bc3f52c9a 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,6 +107,17 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is a negative number, then it has reason to be
+	 * defined as out-of-bounds bug type.
+	 *
+	 * Casting negative numbers to size_t would indeed turn up as
+	 * a large size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 */
+	if (info->access_addr + info->access_size < info->access_addr)
+		return "out-of-bounds";
+
 	if (addr_has_shadow(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 35cff6bbb716..afada2ce14bf 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -152,7 +152,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
-void kasan_report(unsigned long addr, size_t size,
+bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..c94f8e9c78d4 100644
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
@@ -478,9 +478,6 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	void *untagged_addr;
 	unsigned long flags;
 
-	if (likely(!report_enabled()))
-		return;
-
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0e987c9ca052..25b7734e7013 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -86,6 +86,9 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely(addr + size < addr))
+		return !kasan_report(addr, size, write, ret_ip);
+
 	tag = get_tag((const void *)addr);
 
 	/*
@@ -111,15 +114,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	untagged_addr = reset_tag((const void *)addr);
 	if (unlikely(untagged_addr <
 			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
-		kasan_report(addr, size, write, ret_ip);
-		return false;
+		return !kasan_report(addr, size, write, ret_ip);
 	}
 	shadow_first = kasan_mem_to_shadow(untagged_addr);
 	shadow_last = kasan_mem_to_shadow(untagged_addr + size - 1);
 	for (shadow = shadow_first; shadow <= shadow_last; shadow++) {
 		if (*shadow != tag) {
-			kasan_report(addr, size, write, ret_ip);
-			return false;
+			return !kasan_report(addr, size, write, ret_ip);
 		}
 	}
 
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 969ae08f59d7..1d412760551a 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,17 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is a negative number, then it has reason to be
+	 * defined as out-of-bounds bug type.
+	 *
+	 * Casting negative numbers to size_t would indeed turn up as
+	 * a large size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 */
+	if (info->access_addr + info->access_size < info->access_addr)
+		return "out-of-bounds";
+
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112065302.7015-1-walter-zh.wu%40mediatek.com.
