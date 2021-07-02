Return-Path: <kasan-dev+bncBD4L7DEGYINBBSFI7ODAMGQEFZDJH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E3623B9DC8
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Jul 2021 10:54:34 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id l16-20020a25cc100000b0290558245b7eabsf12154849ybf.10
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Jul 2021 01:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625216073; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRQnI5jdufePe36nTE5QEIPlvMUoDn3myHzvjLVF0gsqIr1PP36J+Dm8dRwuyzTkkA
         Lt8U8xrxCg7oQeIus1dQZBvJhPjh2uBJuNSVI9vduxqkgd9n2vBudHyhtdyPGlQLhi67
         HF8XpEA78pzS5CNl0Uv0zzHqMewA1d7poWEteCsNPmJBlbH43iBYJKYJZhWdyWlMXhzA
         +2k7AUlk5hDS1IHK+e4jzO4zKTV8niRNDkwnOZGrn2XpL0wwxytnQMQXoKMacsggjLtQ
         AcYkPF4+XVlBjvihEedujWAChULTsEHxugkdfWQz632RqDxh2nEb8ObqTM34a4FeI7ru
         urjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=isPvxA69XqOM3l/a1ABk3NZ2IzaJlxG3QeL+JcQ3dpk=;
        b=wqef+zsnMcxgZjvmqZI4/eY6UzWtU4E7UermD/BP+5dcE6ZqeyDxTz83MtMx1e9aLo
         JEWPXYVDzcMvYTTa04cdBBG4PrJmUFxBNG3qggUpZm9TDi1e38MjGP+yhkga7dmxWBW3
         FFgOkLKNoj3FpbCffr1lbIhuh/aR62UfNzaFCSQWYrCOtG5F6PNNB9eNZmSa/hTGmmxl
         yP9TCwH6DsZe2w3hAtcTPaLqIUJ4A7Rv+nO30XNtuhquXyOKVCqVgRAIJsN5QivvOra7
         cFL4yvk3FGvLfQsoaXwzgqLj/3QuDfqQKic9CjGd1IZBIWl+J76iDPJmDGPFeq+2EDdn
         Zy9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=isPvxA69XqOM3l/a1ABk3NZ2IzaJlxG3QeL+JcQ3dpk=;
        b=euPxPc8S67tffzwtscaB8IAgrzr/c5fR8YneT1HXELnQRegy004UVilFi65B2/zMFL
         z3g3MK4qbVP3WeOToXxxe1wtnaeKt3fIUlRSdI4nCUatP/UEZU57VYZjCIi+8NLxq+8Q
         7THfk05nXyMnkGtklXg5WPqvtniHueRVnlMVL+Y2kT45/yT/gt63GntHKxFxukZVcmTO
         NGlgwC/3bD2cVYJTQfqUcpeD5uPvtoMrZPMFM4wlN7FKFEBwFPeUFtXF0QV71Dt0DzF3
         JtnJlPdEW41Osz1DBGzv8IGcjDPd1qTMSe+X+YGJsajPpNXYuTsHugiGXWET8rKbCrh7
         KoRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=isPvxA69XqOM3l/a1ABk3NZ2IzaJlxG3QeL+JcQ3dpk=;
        b=lTpnb9RUNT7/UQcNr8+UUHBX1zujV/lMXtokOGMrKe64iAJXxBSeehvHAzZVEWmkb3
         BiAh18YaiT4s+dDioElV6YRrOyI3Qjm89SGl3FNRhfsmGIQYjdNc31cWBzZdB+AQxfaW
         ivWrkMPkEijmqs6adVh/mnPmXbIQXykGHtQhd23oBFJIi5Oj2XTQj8wc3UnYsZNWX3lz
         D6LJ56nEO/Didu8H1uMAJ/qUxbe1gOf3RiHXB2ZT7DGYjNV5Qo9GDVUfReOtHunZsxrf
         Fmwlhv6+FmZqYN3R4yrEsUH7ZoxEYHvculycIjyLPzGYlYr2dZ60S6wuiptQ9DEs88uc
         o09A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dPOXctGPWzwH02dPODOkkh0ZpR0f0oLDm4A9Yq7bFaWI+yApA
	xZLDBHfpb0nz3g5ss90bv98=
X-Google-Smtp-Source: ABdhPJze+TA1yHvUlh/Hq1GMbyPwcLoQ2syXkJYaLgpdWCf+7vqc3ArUPiF4jaLLsMYcH4nWC4WVVA==
X-Received: by 2002:a25:4044:: with SMTP id n65mr4930211yba.500.1625216073125;
        Fri, 02 Jul 2021 01:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa24:: with SMTP id s33ls165625ybi.0.gmail; Fri, 02 Jul
 2021 01:54:32 -0700 (PDT)
X-Received: by 2002:a25:abf3:: with SMTP id v106mr5440380ybi.299.1625216072587;
        Fri, 02 Jul 2021 01:54:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625216072; cv=none;
        d=google.com; s=arc-20160816;
        b=NNMnuXHgX80zBXJyPW51rybMyXMy6WXI8xb/2Fepqm7gPFu3SchQVh5ZNPPRBXMpT+
         eovqIbHU/xAa+igWOPPVSlqfLiar+3+XrqTnZquMyIlQsvAa5XlltzX1kjhArhsFMLTb
         Xs1OdZWyGLw2IrdW3yjVEK68oK5yVaBWi0l/wzTxFlqqmvxo7HSTHJF27NYuCFcumWT0
         7EXJLyy7igN801GW9WBsKHqh5OQl0DhqBgbAMYXxJuNg2aYOGh5ow4MVwnVc5/PqH9Mx
         5xvR7/TUE8qSeKSMGsxEvta35m9Xit8ehOdK0zWal4djljVMbcxLieMuNVRHqMpbm9ON
         u+sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=kZq6XoWazE9KAKG7goF1w9zg/lqsLIS+4jFvdzSbzD4=;
        b=UtYsHxw4jM+AVM0o+VojLjs4yQ7YRNlmAjaCXpXBe8m+v/mOCkaTRv+mNxUuXBSqLv
         N0InS91BC1vf/phxIzwCqvQ2J5fuA3QogzU/A6ZHcr2t8dTTzJyrjjW76qh7gWH1vpTR
         YyezFXDlZy0W7d4eAlGTksS4pjalszSREzLaOB+0pkJvXeojahMC+2JdpqYz/2l4S56e
         u/a6SOCYzDAPhpG3l27kWrHOOUUCI/lCyiTs7IwcFI9sTA76pTZNsHhNq4PgAOMKj6n2
         OxmZGyDpt/LsEEO84XQwHqzUGGP1bsenhRp9u3Ep1JltZ/CNdTvwLztue+67Se4ofONu
         6njw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id r9si269318ybb.1.2021.07.02.01.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Jul 2021 01:54:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: f26b78631b9647f9a077c496c8ea81b0-20210702
X-UUID: f26b78631b9647f9a077c496c8ea81b0-20210702
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 740660104; Fri, 02 Jul 2021 16:54:27 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 2 Jul 2021 16:54:26 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 2 Jul 2021 16:54:26 +0800
From: <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, <nicholas.Tang@mediatek.com>,
	<Kuan-Ying.lee@mediatek.com>, <chinwen.chang@mediatek.com>, Yee Lee
	<yee.lee@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list
	<linux-kernel@vger.kernel.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Subject: [PATCH v4 2/2] kasan: Add memzero int for unaligned size at DEBUG
Date: Fri, 2 Jul 2021 16:54:22 +0800
Message-ID: <20210702085422.10092-1-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
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

From: Yee Lee <yee.lee@mediatek.com>

Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
the redzone of object with unaligned size.

An additional memzero_explicit() path is added to replacing init by
hwtag instruction for those unaligned size at SLUB debug mode.

The penalty is acceptable since they are only enabled in debug mode,
not production builds. A block of comment is added for explanation.

---
 v4:
 - Add "slab.h" header
 - Use slub_debug_enabled_unlikely() to replace IS_ENABLED
 - Refine the comment block

---
Signed-off-by: Yee Lee <yee.lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>

---
 mm/kasan/kasan.h | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 98e3059bfea4..a9d837197302 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -9,6 +9,7 @@
 #ifdef CONFIG_KASAN_HW_TAGS
 
 #include <linux/static_key.h>
+#include "../slab.h"
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 extern bool kasan_flag_async __ro_after_init;
@@ -387,6 +388,17 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+	/*
+	 * Explicitly initialize the memory with the precise object size to
+	 * avoid overwriting the SLAB redzone. This disables initialization in
+	 * the arch code and may thus lead to performance penalty. The penalty
+	 * is accepted since SLAB redzones aren't enabled in production builds.
+	 */
+	if (slub_debug_enabled_unlikely() &&
+	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+		init = false;
+		memzero_explicit((void *)addr, size);
+	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210702085422.10092-1-yee.lee%40mediatek.com.
