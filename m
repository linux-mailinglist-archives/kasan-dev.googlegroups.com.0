Return-Path: <kasan-dev+bncBDGPTM5BQUDRBT4HRX3AKGQEXVIHCUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B96301D8D9C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 04:26:24 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id b9sf7638530oom.21
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:26:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589855183; cv=pass;
        d=google.com; s=arc-20160816;
        b=F6aEpcdNuxUwKej9+CXO3KxrM5tTDpyl5V2cNK6lb8PkH88SqDdDCcPSfR4fWN5uFl
         8rG12Sot+/yr1CcfDUWqoHjIZm/EE2bg9ZGvkeSzfDQPL8G2N/ovQzwehdTwdTtLgYjH
         NYBmXaJ/q99A2l2fesCz42gjQ/7mbrxhJ1h3Hgci490MX+K7pjCggkbr74utXCHsQCcC
         mNPFYkWUi446nFlBoSG2SKVD2eX0jDs2z1QUw5UJxN7P+fIf48PaVZcZxC2mehF5R90z
         QuhithgcRBSEKYaueccB2+hWs03WfB/voLirvoipFnhzWkRE69x8jHb5ntVsmBqa3OYz
         KCOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qr1BL5a1kWvU8hAYfK5oGy/fQXWPEflMA5LMi9hoegs=;
        b=UPNCY+M88SkUrSZRO1iVSuW849M5AA4GZbiCs8ldKUzzTc+qq/Qlb2NPR6lkrbEIBm
         fn8zC9wPi+/UOQtsLXL5vwyW0IK3iHdQo5rhZ2EnzrB30p7YaLsDiJLUGWoBZjzb3+xr
         sGZ8NQzOPnrzbujy9OIQj8Z31A6F7Maef+G4IdqxWddi89kv6vCVZHhBHmk1ttoqLGRE
         xqzCQcnzGhj9m1VWt6YNDwrKaK8/wU7ka/57/Vmw28e3EWNJYUl8qknu0iT0uEGunWRq
         6D7ea1SAeuxNfDDVuRTFyrB+oCnDulFvORdddWR7fjYSFJuf4JA1dXTjjpvK1NA/VYRa
         xApQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=QWOlKfMl;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qr1BL5a1kWvU8hAYfK5oGy/fQXWPEflMA5LMi9hoegs=;
        b=E4mCWeQQ7TK0fx0YmJchSR+1Swf0PWT3UFjKlcNlJASoFVH8RRQX3B5UF8AT2PZL3G
         ZvfclBet44HFXsrdZNGeKKV1HckjACUNqTJJtoiFZVJ58OkOXZZMi5GnEqhYX7nqLvGA
         wcirLHuvDJs63Xb6QG2h4DqYqXn1TeuNAwMHhD1nV+6bIg8iBepUmEGcJnDy805JANGt
         F3uycfLkIFsoSYVwGVNBen7R2RCOYKsALXt16xbRzoMJlZUXZjADy8uLygLOHqJ4cD/1
         0oV08EoM7tamMa72cduIN5EuUTJaIUdWUg6r9r6ugO4O313c8mtNcKMxnuc+FKG2aEPm
         4gOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qr1BL5a1kWvU8hAYfK5oGy/fQXWPEflMA5LMi9hoegs=;
        b=ckJeD/qgo1cYmlJfIrmCuUSo2YW05d5DtM5b2D8R7BO2f18AjAksig9yKsB3Zzy2i5
         oajIVLTSnoU23DyOZrjKEZAryylJpBf9eMr9DCOynmOxcn/CfmjqLHTvgw2hK3zCSdY7
         zdptMwoCgWgYrIfegqh57+qFMXjFnLf75tEeaFHWAmqLk1G8+7SrKBe/KjozL0GBbx2R
         53ztFUSroz97R/RCXDGQZuW/FrgPkE9u45H/NjTUVCSaniFJp3L+b8f1+maHVQsD1l2w
         oUbKtZzL5ztM+P3JX8dJxY/OhOkJCuQoA7SQ8LMzyeNanZp/HeGDmPvEM+cQLK5Njm3W
         5ubw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jp6w+CvHEzyZcg9tVI9Q/H/QKQWpDhBntr42XgKGIx2o7r2q4
	NDICO305aNNPkMqCABUqNOE=
X-Google-Smtp-Source: ABdhPJzAgEfAPWJ6i7XpPAhLDv+kzhYDxtiBMF7HriyaH7k5eGGv3ymMClGN+eSgpXhSruxpxPmxoQ==
X-Received: by 2002:a4a:a3ca:: with SMTP id t10mr15326967ool.82.1589855183495;
        Mon, 18 May 2020 19:26:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:8a5:: with SMTP id 34ls2412879otf.4.gmail; Mon, 18 May
 2020 19:26:23 -0700 (PDT)
X-Received: by 2002:a9d:20e2:: with SMTP id x89mr15059628ota.110.1589855183123;
        Mon, 18 May 2020 19:26:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589855183; cv=none;
        d=google.com; s=arc-20160816;
        b=TtNHZXhLPRCURigO1eFDHETxYjsEWPWXHipewX5bSMuf87gpUiRnuje4tU1UWcHvX6
         /k70LSS7G0R5q73435iOC1M8yZl//7uF4BmEC28Sfz8p+/VMBbfuZi1J7J6MuVw6GNQA
         AX0LHTimcxIy9DP8lTIUfmNL9BG6tyF/24pw/QBziY/VAcVrD/2US7XnshEcN6LxQ6tx
         VX0uAjcE98ywp0DbF2i1k3T1z46N5WWPg+QlBRpm1XnwHujlvt8WPFROsENys3uOmjW9
         WYbLgHpar7VKgEO1SbS8OLUrgcQiNmeoBx/Tye0COPU3KS4ChbSpy5R5eB2IJ26xQwzS
         SstA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DbdlJu8vuZUyyQAeAhd6YD50kjTkWp9bEKvDh4VAu5A=;
        b=n2TIHm62oD0e2GFRQBY5cFkeg/GOlCHi7qgqL02nLkIC2M9Ig91qvLZSFjfhJ9Ly16
         JNPPNJMVXHfAOC/sr7uKbL1sgDCGjINYMtksmg70OIGTwV/gr3WP/NzqiC1kH+4AGHbs
         EZwNsgKvrhllFRvr96mtlXs2zLtVDlg1RBhhTb3YKiFYHjhkG9llQcYQyRfxVeJHyJDx
         DI4ZrdMIVLR3IyKcN8Ii6zZBIGLO+5M7ace5+iNCiGucdeNUPaO8uK/agE8uxCuhFNfr
         LDD4sPUl5eelfAPxhmonpDuOapjuYK7HIn3vDCs4TipavDkK+cZlqM8ZPzoXG95iL5Wx
         Vcww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=QWOlKfMl;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k65si900392oih.1.2020.05.18.19.26.22
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 19:26:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4fddd827095c4bd7b29fcbc0fcd66d20-20200519
X-UUID: 4fddd827095c4bd7b29fcbc0fcd66d20-20200519
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 446216767; Tue, 19 May 2020 10:26:17 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 19 May 2020 10:26:03 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 May 2020 10:26:03 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 3/4] kasan: add tests for call_rcu stack recording
Date: Tue, 19 May 2020 10:26:03 +0800
Message-ID: <20200519022603.24251-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=QWOlKfMl;       spf=pass
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

Test call_rcu() call stack recording and verify whether it correctly
is printed in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..6e5fb05d42d8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -792,6 +792,35 @@ static noinline void __init vmalloc_oob(void)
 static void __init vmalloc_oob(void) {}
 #endif
 
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_ptr;
+
+static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp = container_of(rp,
+						struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	fp->i = 1;
+}
+
+static noinline void __init kasan_rcu_uaf(void)
+{
+	struct kasan_rcu_info *ptr;
+
+	pr_info("use-after-free in kasan_rcu_reclaim\n");
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	global_ptr = rcu_dereference_protected(ptr, NULL);
+	call_rcu(&global_ptr->rcu, kasan_rcu_reclaim);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -839,6 +868,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_bitops();
 	kmalloc_double_kzfree();
 	vmalloc_oob();
+	kasan_rcu_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022603.24251-1-walter-zh.wu%40mediatek.com.
