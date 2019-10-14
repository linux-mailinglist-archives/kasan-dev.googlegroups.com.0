Return-Path: <kasan-dev+bncBAABBTU7SHWQKGQE62U5ASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id ED037D6054
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:37:03 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id w1sf6794285vkd.10
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:37:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049423; cv=pass;
        d=google.com; s=arc-20160816;
        b=YX1evqFw8ZgXxDo8bjm9QhOcwSZyUHBL5/9cbihP2C3Noql54rqM06qEElJjMYay2x
         9MKKi8+431x8AD0+v5R9jDDdz7F7nh0wBFH2rsLJvUNRbo1OjLtcu8QFr7U7Nl46B5js
         uyqjZgDSUcUNzmwydeSRqeMMrZ6HgXLxwnK8lpbSYSb/MYy9KhAaK5f5oSPfdCbdgphe
         AlOUCZU4NMkmQAuzJ8ig7fc7bbh9b+ft7GUrfmw+ZnTY7IE6/nhqmq5xiYZlDFoZygI8
         a4Z5qnDRZKUvj1zjdFJ/NRWi336y93NrCK3JNsNRsr3FDEEi71Gx8RP6ovWFuLT4oMgk
         rcrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nlb7xMN7MQ8N+OU8VDZs/lIZhzEokU0XTr60xPkBhLc=;
        b=P/r8UP1duwrqqDQ9IXhF72MYOzQ7nMxgv253+yYQ6fvn8iE/+gF4F9Yt5BoRVn/r04
         9s6l9kS6cFBPrMxBhqtiKDtDJ6cVO3v527obzLs676xIovYHVs3ll6iybBUf8Q6hf9TJ
         tpkHaRIcG5/WeOugkjJUUjNgAOGMUzg4CjQZBw3/IBohV/zniZaKN3s+6gsZvXAvb3+I
         xnb4diF/p3YW8wKWmv4oySnvYKzfLTtziudr5PC8YPEHDNbJbrpDpHQ2cxfI/EfNY+ej
         ZjWlh9iFYnCfS1PlkeljQHgqs7N6XLp2p8wWLJO2QwChQ+EN+JRud0QKqfW/96Xiaofx
         rxLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nlb7xMN7MQ8N+OU8VDZs/lIZhzEokU0XTr60xPkBhLc=;
        b=KdNAZhiynFLIQ9PP083DPb7YnKxStwc4DPaEa8F3SlQjilLZGaJ0jaUcbeJc6KPM7B
         dbgRdSboDPaqYV4RjaZ1CtFlv/g9+brTjSuv2SOxNPjCnhEBwrTHyrx4YeVnjBR3EqPd
         rED8vtaI8W8pNiDG2pyhIortdnA7f8LYhTVdd2ZiN1WloSfCrk5EPwazsE5whdMA7YtK
         d5NGdjonCm6I1DtXnlUcWi60xqRg86pkspxVakLQIC1QG9P+7S2QzL7xuqFERYt1rg7G
         ECkURcScTe2lZI6KrZlanvKojJBai9t7iTzD6OYn9Ey6cu4tDXXNhYWI9aBFWb8hwc2L
         qtIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nlb7xMN7MQ8N+OU8VDZs/lIZhzEokU0XTr60xPkBhLc=;
        b=f/53JVDz1XHdI109jhz/yOSW1sYu33FXFiweNTV4k6yr9cFP8KCQFkZsyZTHnhvsGR
         SJ5HbDZZEqk2MzDaq6LI3dwJJwZVrpXEd1MxF3Qunb6g8obbZhcjCFD9SbE58RBIu8rR
         tz6VDLmpicqWFQMYbKOi3VZSAVLeq3AaLjEP6S2baq+7lsssuj7eQnnQ5gBxpGU/Jvke
         oGOMhEu6/6GQDhnuQ+d/Ai6RV4OtwfrKBKIB8OV3zttiBKXwz56U8eJP6SRQonYmjNYT
         6fGnGuvLO/0QMeybrrQbDwzvlmYbdI5A/jR7caRJBFBocZ0U8RkSitdM70S28/I6TVPd
         CJYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV24sTFtBaVSmjkuyKmWwYugDyf3w8Ht4zcqLLnYHUjCpUOc5UU
	2FhT+XTsXnRA2AS+GpcD6Bk=
X-Google-Smtp-Source: APXvYqxUGZLHJq124vo8zyBq23DrrjHpmyXiEmSe/a2S7Xaimq6iSNejg6Cr1HuQ27NwJZZ+Wx5iEw==
X-Received: by 2002:a67:fe8f:: with SMTP id b15mr16114974vsr.90.1571049423024;
        Mon, 14 Oct 2019 03:37:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e891:: with SMTP id x17ls1348587vsn.13.gmail; Mon, 14
 Oct 2019 03:37:02 -0700 (PDT)
X-Received: by 2002:a67:e289:: with SMTP id g9mr5064826vsf.30.1571049422752;
        Mon, 14 Oct 2019 03:37:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049422; cv=none;
        d=google.com; s=arc-20160816;
        b=KgX1qxJOn74S8jCxtHbhMZf9O9gv8AsP4CQSE14uU2fUN8BaVrTYGq18dTMjs5TL3d
         31JkDro0msYgon1kJIvW34gjG1m4fOGi9EfnkCi2jB/VgUG2+qy4hd0iamiE8tpOMmcr
         tZZKhJYRjKcMz8SJS61AN6MeNaM257VP8jHmGkabSBl+bT8+M2+b/rv6izsEe81+jj+A
         BeCYMfwVAOApHvox+6y9GpvHgsvZN2FQmfLIACzxYHgQJ+KatQj1hMJFwAQTL4m3lhS7
         VA4gsSOPxBEd8e0DXL2qQ742BsJ4R2J7hh5sptI0Z1AgdVoIX6p4Wii2f67quLSL8py0
         KApA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=8FPgTQop/5D6P+RLHbKHGh0ZbBOGliZrgDB/gUABhBM=;
        b=In9J0pIRxwQNFGUXUAxHBb5ymofZ8qgp/2AZV1pkO4kJxCVfRGEAo52ApaJcfu3Hki
         7SzZjzzeD5CMpqdBrFSS8Hpw4SYn2pV7IWhO+INfZ3j8PgKoiOLZT/y24TzUR8qtJRtZ
         rYrcNNhdGcCkJzL2AkcMKQdMRJE2ryPYrVFbOzrSxTxK0ryfXBNQwTtokUSewSThKxTS
         7v53yLyGXOumkVgKUDQtqKtNxvK5XvqLeElwgL2NCWlQ6FWAexbdJcXBfgG1T9Vn+mym
         Kzw8Y3d9s43eZj/kh3L8ngaOoyW4FgJHqrms65ILR5MIVE8gco64NppCbKbIwAx0sis/
         weLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id 136si1398935vkx.4.2019.10.14.03.37.01
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 03:37:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 7dcb933b18764e979c3cfe88a285e36a-20191014
X-UUID: 7dcb933b18764e979c3cfe88a285e36a-20191014
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 752259523; Mon, 14 Oct 2019 18:36:57 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 18:36:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 18:36:52 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH 2/2] kasan: add test for invalid size in memmove
Date: Mon, 14 Oct 2019 18:36:54 +0800
Message-ID: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 0CF6CECFA4DBB0B2BBA0BF7B47F0B4713B9EC9875EB27669122A6B9E49B63E752000:8
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

Test size is negative numbers in memmove in order to verify
whether it correctly get KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 lib/test_kasan.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..06942cf585cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -283,6 +283,23 @@ static noinline void __init kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103654.17982-1-walter-zh.wu%40mediatek.com.
