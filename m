Return-Path: <kasan-dev+bncBAABB6XZQOHAMGQEU4BZS2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BBD9147B58C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:26 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id a203-20020a1c7fd4000000b0034574187420sf227613wmd.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037626; cv=pass;
        d=google.com; s=arc-20160816;
        b=KOvlWQ++sCSOP5FUswmD4FqnoLwyh/l4WzXL8PxBAbsDGhSCNFZN6N/R8XlvoVn7T+
         dEUDsr7moQx4sXCSLf2UEP1KA+SQluqsBcP5F5E7l/jq39fUrUDYyNxF/j9MNi6FUvc1
         WYLgighcJlcbprVjfjZ8Hn3yw/tLqq9SdfTGlgmAiqBbI9z0inbYDgc+q3gMd7uRCpD1
         MCuDNP4GAtwIC4IYWnRDuj0LXtFl78DK4fXs0PzY4C7YSJLaBfsB+cZ52OvsT4n4veLg
         2QVj9U/nvrgDrN5Fgkg8QbcF794PfcNS6RCOgU/gTTobzA9gWBMA4ze1MeZdjQqjCmcO
         LxAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E7ptYcQmQaF3Js5EXcPzU5b8+OtIxIa8y/L53WysTSo=;
        b=No3wOVwzAh4B6x1IEilJcFrnHoOk76/t7bq9+V3hVFcKGwiaE20KlbQTJW7TI5MSD/
         Jw2y2D7Vr7Ilbqbba7LvLhBx0ZVzZilHISAqcZ6rXi48ePl19WvMtvlVqKhXbPFBHTKU
         /KL6XKwucOotvaR9uKQru6lH+h5rAJCI2kJ4Kt4J96zi/ZKNKjwlQkfc6P3tvRrkk+Nh
         Bp5LonYg9uX6OJ9veLNyfbbN13a/vq8nRJ2DqB/Y/NF8QyvkPw9n+18l7paomOaA21Bl
         9LwJ9S/M+9gSM4ExKazUj9FOyjpCazPO173IbrgM7SNJysfMnEDrza8/eaO8swtycdS3
         HeIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TA4mQFnr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7ptYcQmQaF3Js5EXcPzU5b8+OtIxIa8y/L53WysTSo=;
        b=rEZlJOzWZlM7uWPWUNrzr3qCpdNI6Z9UFEehWEXQxXx5Ca6ABkoliY+sKSSiGeldOL
         xZdV5A/euMtWVz7ZQRlaIL+9BTfEzfj/OwB+Xn9LeLj5mpg8lPhjGGqeDr0nS54kUxVs
         dPJGdKdeUJeeecxYykhCOdhKkausGIDYq2NeUU5H2nH6aPMgSHelPefHg/EWQIhzDkfi
         Txf0MpGbf85fnrS/D7XPS8JCEL9ysYsFWp62rUJcGz4sPAkOqUF/qflJwNZqAB3Zy8Bn
         F8BOhi3cYxpp+MxVED+fsrLIlUHOtpEvtbd65aF2AuK/4xg+OZt1j9SC4etSfIozlrW/
         e47Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7ptYcQmQaF3Js5EXcPzU5b8+OtIxIa8y/L53WysTSo=;
        b=13Yl44NipLT/wIolqWv30sAYRGa1yWYRUAQIMEOxHKw0VQfBR0RDbicuXZdfB6jxkZ
         8JdFFnKR/lGJwBhUIhYwJib1gH8aN0S5MxBQEkRsCwqwLeKTPmQpfH5aYO/GWawYcrRe
         55RTsPOvRYFBDM6mekJXoVmQDGX2oRJNED8dPr+08rugDe2NatJVbfZdvqre1yilCxTi
         D5l+mIsYE89dTiwBg4KMWGIacBItXLUT1ZuJGxVwyeiflu2Y10htIK2V+Tq+SDlV08T7
         roWJFjYU4x2t//qmOP6VToRxzw5DxlbbWLoZrY0KOMqrKyIau2tmyA4oxd4ohkm3HKJs
         alUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nw1q2RHy8+yrP39gaaMBpnv1rFFBR6CT25bQhPw8FKgV0WqLU
	Pl/cH3sJHbzzGV9tImxr2ys=
X-Google-Smtp-Source: ABdhPJxdsS0u6xULGKfjAJ3el2J2702bSKKN+lhsdcx7eYB89FOWtyZYbaRS6Cv8uh+3rgBRzwkhPw==
X-Received: by 2002:a1c:e913:: with SMTP id q19mr34181wmc.87.1640037626572;
        Mon, 20 Dec 2021 14:00:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls6380189wra.0.gmail; Mon, 20 Dec
 2021 14:00:26 -0800 (PST)
X-Received: by 2002:a05:6000:2c9:: with SMTP id o9mr89342wry.377.1640037625950;
        Mon, 20 Dec 2021 14:00:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037625; cv=none;
        d=google.com; s=arc-20160816;
        b=f0m62ilpYOFJHrKmHiiDN8gLqyXUGB1yXc259PlpB9Byy8i15PaJcenDMUGYWVmnw1
         8dUOVe+GbkLmi8VMAhIy7HsU7ct/fem2AVVGeB3++lMlt0p5heYSyqMJm1yV8h1Nxepz
         P5d4OeXK4bzKNBZDWiPFiIuQM2OeBHX1zVuB5ws5JzqaJHZpMT/sdA7YCNjTDtBjYKh7
         Boj6Vm3RdIQWEqmHat8JaOi2PVgq8qLL5rbm+bZx5WMroLUSjnVoSJ1uPCb1vc12T5GJ
         MUcIY+/q09nxntgEnCIKGfXSi6/BmlGInvK4NPcrDU4+UPrVPIOAOqO+CxsvVZIedGgL
         Lynw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZYMkDyTA14TCHWK1+gvITVpmr4ZV7O4DHhp5KoEByVw=;
        b=ejXWomnPowb9BFzTmf3ZTvMq/ePgHcxyKdCNnk+xh753d8OKysjIORYZMRtu2NDaAQ
         E/yziNZgzaIGydSAYrzessX9wP+3if7ZfU96pTTu6J3sATSbn6FFjFte2gvxK/11wjUr
         KojFIngE3d8WsuRxvR8lpRYF0S62Jxbf3YmIoRcJymlwY0t7WTi1rPjNw8kwe3cataZ4
         axPo/hZxP9PjQC6ubcKUIccNI1mDopIdyjBY3GVlX3RMjh7qRw0XsmnB0/2bwXYTcw0V
         1QTSzMJyx49fOgDcG9KUR0BE6ejAG3I30w52ScKYrJwYsQnrLcHxAdCCto3M6wBt1Y4R
         pREA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TA4mQFnr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id l19si84561wms.3.2021.12.20.14.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 21/39] kasan, vmalloc: reset tags in vmalloc functions
Date: Mon, 20 Dec 2021 22:59:36 +0100
Message-Id: <e31d392c5eca9db6f45ca6b320a929ecd53f787c.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TA4mQFnr;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index 10011a07231d..eaacdf3abfa7 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -73,7 +73,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -631,7 +631,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -805,6 +805,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -826,6 +828,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2144,7 +2148,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3406,6 +3410,8 @@ long vread(char *buf, char *addr, unsigned long count)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e31d392c5eca9db6f45ca6b320a929ecd53f787c.1640036051.git.andreyknvl%40google.com.
