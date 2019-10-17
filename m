Return-Path: <kasan-dev+bncBAABB64RT7WQKGQETHSJQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B310DA36A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:50:53 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id x125sf528461oig.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:50:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571277052; cv=pass;
        d=google.com; s=arc-20160816;
        b=oIbUpaBSVFEFwkZIMcDzpZPflGWwyya94ZplqKcuJTGRhF6XRgcgizjBC7xPBd1XF1
         sPSvDEHZxsuc3k/H89BKsXeuxwvN/w8ax7Iw/+5h9AqhSkJBnrOuC6UVBVCN9thJESil
         t0WRJgcXXZG9AwEtmjBZVbThZOl9iAgC42Jn0yOFNKjrRo1hQx8Nj3TOkJ27CED9jhGw
         d0Gcau1lJl+Hr26EOogcFBQ6e53W/kPUBMYNKW+uM5Jqv3Ql7Ohtb2OxdWI1EkBtdG2F
         rQfdZpMIv2WiqCUP7wdE4PmO9ARw1RiOY6IDYINJEMuqdPK0jFna7zoUOLhc/4Yyr7/o
         Hy4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=jzKB8XpmJ5JizIH5TM98Jo1NYyK31qcmj0UEjCWaL3c=;
        b=Hk+ZrIspE7MkgemZuzOZ3/V4peKltYyQxeq9qREyDr1FMOu7/oc61qor9TQLPYsTvp
         lARTLDSEFvE67Nvpqq7ARtbNdSiEcevT2oly09HCZW/zp7p9rKH5SWKBau1KaYvItsdM
         HYbyx9u2s9g+EMDgBwKiZBxhbA/xYueNxKLFjxYNrYW5ZpW9ue5l7vWvWD4tWR5mWqJ1
         mZvLwEphQnOzqlS6lpGsDyawYMEoxgfUluFOIs7C31Gae+4C+QvwbMMG/zSLPU0UTn53
         Mtcno+enwssTO8wJ/inWcNTIyI5uh4ttlqeHZD3B9SFiW8fv2eMiQjjLJ8/T565KJPDi
         OP3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jzKB8XpmJ5JizIH5TM98Jo1NYyK31qcmj0UEjCWaL3c=;
        b=LWsh7xzQ/7JLUDx0wm2UufhPMWUg26JmC8Ap5QyRlFjUdoqAykH4Y+a3y8f1dPHu0M
         5Yx66D1XiNsjgnAjCk0ckfXNRcOHHCQc11qyJL/bOhdzF5XoqFdixq0AEZ8Asg6KFIci
         5MjrseFJKXZY60m/Yt9ZmvGds6GNkJaVfdUK/fZHDgoprYva65lg+xr65W2WXndkf5kn
         hUWwUpZWsoM9u8y2CVN07vwuclD6GGjS9G09wWsF/uaGXsFK0Dc62j5OcTZHthDs4tpy
         66sxYcxbVz5SMvmN5J2CHTgWwmXM7/lwhoJCP58wT5mGxgiST54Zz40auH/UIC2WieZv
         NuhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jzKB8XpmJ5JizIH5TM98Jo1NYyK31qcmj0UEjCWaL3c=;
        b=lSiEFWg2R6jQXwKxHj4APIOj4/kLSSNPWjLt+6iJQHxJl65mBlN0oJDecjf4zJVtFD
         pXHrGHqTPWmVmEjWK5nFWIXiV//Q6Ug9AxRfOdtpPKtdueORrerRsMoirPuCYfUjg0Vj
         DjQPJV8EfvO7RK226njv8C35q569HrzWafAmlJeyj9GZw7pGznHSgAnUktin6R4YLlod
         RhFYYXVTvW0+M1QYyfQx7s8NsZyWxwZjcSNVW9IiogGFvhL8K+QjlMU+1EOnm1JEOehI
         NJL76YIezVAFe39ux94p50chpsRNNrWcvEjk1CjcZsoBQOTYckrbjO0PR0nU4ifLnXdF
         atcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVMdd4Iq6hm8dEQOKszb/icxfEepIz60Zo0UKzWjh3u/6dAQThv
	ysFQSo6WrKu3E8F7NHY/PaA=
X-Google-Smtp-Source: APXvYqzf13UK6LviMhGn2E+468P4A/ua86Kgcxczrk0RdEWM1oYXgHmkJNmIi1f/fXO9VW1O9qEwcA==
X-Received: by 2002:a9d:724c:: with SMTP id a12mr1061145otk.230.1571277051948;
        Wed, 16 Oct 2019 18:50:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5f09:: with SMTP id f9ls128676oti.13.gmail; Wed, 16 Oct
 2019 18:50:51 -0700 (PDT)
X-Received: by 2002:a9d:7356:: with SMTP id l22mr1012117otk.16.1571277051573;
        Wed, 16 Oct 2019 18:50:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571277051; cv=none;
        d=google.com; s=arc-20160816;
        b=M7witnTUc+qtyHapgTgh8tQjjasFe+IBkZN+Nk+BgHjkWSx3eFLfGhLEUtthWXvLOs
         7Ah/d3MArrw/+7rSESl+VyTCsN97h4t6PptG35CEYTmUHo8Isjz84MgW/Ju63eR3zrp6
         /lpDk7VGFR9iN0xvF4SI8pXALcqpxZHJ0220MYHxwgGBfl43jVIeDUVGajS0eH5WUeeE
         LeV0qZXRbQLj17aMHunQg4IYYoBVy5okP/tF0Utp6Ww3V9eI94eHag+fjxoKGxOUfMGh
         XBHvCMbEu9oRlDI3jn9GHG07uK/NRVyWqe6fU1uq0vx0bHPZfACw/4L10OyWG8Q8Ift3
         HgcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=wxGjjBtXR8ba6Nv96o26Mbhh0l52DEOMDSSBMjfAXRY=;
        b=HrjS5M9ySSDJCh0ToOGF9xuinYMGpr/1UilaMdmVYdvMTshgQCYRqqKrKgcPQdFG/1
         yjG4NL+/sG74wYTZxoVwHj+Zzc7KQE0h/xFtJLAwCyb7e2VewPUbiOYIm9wlCH5SphrP
         0y+UpCbT5Ml6sPzLL1tFJVRXmYSzCoqmEwcmJHSV3D6CXd5Y1dvpzNEH+HhN5BmGGh5W
         leXUWr/ptOZgAUpZG7eVNrwCK4fDv1sWEoso3bTaOPFfN7Oy2jA6vLWShfoD4OD2f6TW
         JOSIVEfBBjm4vKMtxpXM1Dt2eH5BBXQ9DujxrckUHLxMjSsY25wiU+nxztZk+GQW0BEH
         WFVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id i19si40862otk.0.2019.10.16.18.50.50
        for <kasan-dev@googlegroups.com>;
        Wed, 16 Oct 2019 18:50:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5abb0a063f3348d5a0de588d3f47792e-20191017
X-UUID: 5abb0a063f3348d5a0de588d3f47792e-20191017
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 497781176; Thu, 17 Oct 2019 09:50:47 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 17 Oct 2019 09:50:44 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 17 Oct 2019 09:50:44 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v2 1/2] kasan: detect negative size in memory operation function
Date: Thu, 17 Oct 2019 09:50:44 +0800
Message-ID: <20191017015044.8586-1-walter-zh.wu@mediatek.com>
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

Changes in v2:
Fix the indentation bug, thanks for the reminder Matthew.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017015044.8586-1-walter-zh.wu%40mediatek.com.
