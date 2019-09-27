Return-Path: <kasan-dev+bncBAABB44KW3WAKGQEEKFITCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 242A8BFDB0
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 05:43:49 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id v15sf3430269ybs.10
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 20:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569555828; cv=pass;
        d=google.com; s=arc-20160816;
        b=jloGOgpNtVIjlBt0pWa7C0fn2kErqYU5UQb3cBRb3aJCFz7MHp/COtlJRC5DSjF9mV
         X+khY42fyPKtS9T4w/rZCABZ8Y+z+t+i08BUbMl+qyOudkML38gMPziJ4UIRpFOnsrst
         Z/4+Kt3+SHAx9D6QnF5MvYRDQrZ6L7PCy1Yo1MokRgcJS+KNx39eS2/Lltk+ORxvOzwp
         Wt4jSZMlIxwr64e8tl4ul1+FxEbTjsrtt3r4SowXzlNY5u6hQOBuUaFb78hektgus6eQ
         FGL15fp0A5QzqVc84WxYXkWYCRumuvmO0VE+4rjCwyxgGWALwk0LeEC6NCMXpm8usy8f
         PPyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ySQAxHS7emOp9w0reNlEq6sEkv2hDmtgUhefyrA8c80=;
        b=SbhD564253EhvuAVh6WNNQD2mf+WaH7xI00YfelgqHLAi79/eRSFD0QYxDJ9n+REyH
         TEilAq5mr7KMQWS8JqU8M4yb8BTrNyXZIK+izaFOnbnPO86Unz1qakHRA2ON/D9w+tdb
         eegPLS6PSiucGdV3nv5wdKwLFt1K+ZfrLfGgOhLxAsa+bsR+QNLDURgpzxAxogArBJ0X
         P4G1nyEWIriKd+SBHtsHOBqUwMlWSkuLEOPCigesi/8Fd85DgxYMpvfpGw/A6Ch6uQZJ
         43UwvWPlp0cjTmMQb+N4TwaBU+i1LQfvkH+ZcLSCvwzzujFZKznPhAMOcJdDr+yz6u6e
         Cu8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ySQAxHS7emOp9w0reNlEq6sEkv2hDmtgUhefyrA8c80=;
        b=FKMNSDFB//mxX3bXx6x8rMDkSPajf1HgNlqWG5LUT8opLBAcjuQCj+iUwLCtNI1D6J
         dEzdKtWR9ZHcjIwZ47GHDVIR2waS+wiYhPNAYVkEKWsM13t88jk0AxgEH4nXWWP0S8DJ
         Zm9wd9+iVJeT+xQ/g4iWwQtYMgxulvYfQjq5xWtiFAw+f9MSEVYtCNdhcGmfqXmED9eA
         Cv+C/1bY01qG5Fq+mhJHvoJg2aklNEoYYNYh/7Ibex+dgEgtZ4JL+CqvLdSvKUWFxhip
         qWCT9om47YnkUMTmxafnFtW2/nppUaiPE4tnp2pps5KUxb2aSaYnTTQuMMaWDUqMvqkn
         Ey3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ySQAxHS7emOp9w0reNlEq6sEkv2hDmtgUhefyrA8c80=;
        b=e7YaMntQ00ivFGF0HgGdvuOcL3M8DoDMZsNDxjNDHPi/EgMIgTKyR8pHeGFP3hsHlP
         ZjJcHtYBpYY1Ahv6WnYpKD03huBA+BMJk4/J9fgS/4Ax0gfX/HPR6ImVZqNH/UUPYDP+
         1aQNWk9ngdECPRLrjGPE8rYFaEKd4hlBniTb7mVlUZdro8s6eWs/WdpLLMcPhmw8P75z
         St6Eg+5Ib7KsumO0bFKQ6/bm2lnfE8ogUwSs5aldTwBt358Ey/rBo5DY5dn8AchMyND1
         VZR2hRq9+/ph0hwf/IT3mg55+g3luYLVjKwYFHHpGLLoBRoc76wsczGX83Ueq8ECT6Jw
         RAaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWpkSauCmqCASTNiAvRld+sY078/A1AjFE4f/dKONH/oTGk5V6G
	WQBvEAGjqOcFpk6XKSZskXw=
X-Google-Smtp-Source: APXvYqzmvKC1LHjOCklTqvFtAnB1iuve5vZAEcOm13/GeCl6J2yK0ISLMeQalslPwVyrrFQAlAbHPg==
X-Received: by 2002:a25:e741:: with SMTP id e62mr215285ybh.455.1569555828161;
        Thu, 26 Sep 2019 20:43:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8008:: with SMTP id m8ls744754ybk.5.gmail; Thu, 26 Sep
 2019 20:43:47 -0700 (PDT)
X-Received: by 2002:a25:6fc1:: with SMTP id k184mr4694830ybc.8.1569555827778;
        Thu, 26 Sep 2019 20:43:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569555827; cv=none;
        d=google.com; s=arc-20160816;
        b=b1fd7y6IIUQNfYrrUhoYb6iaDC9Vy1/LV6K7SMZGC/P6WgQRZ8kHHz324CNmbNlXWw
         2gVeMyv0X3UgnBcwOnLWaT8HmvDDbwYb+ydzodpjywuEY6LxIal9LlrZl8sg6ROS8s/7
         gIowCfnby0Uxk4pLplC4On5ZC3kL2PGz3EE5oXdRZAtGBowNTxAfRlQWtk7rek937l2Y
         /HrIbALoDur8QNyWFRtKSSpkqBLGfFeFgPTW1kiDmss1tSlpl4xWJZIzvPoi9awWIvOe
         gmgEBW6WurIp0osREZvSgBn0CAzHNfBsB4Bz2uvVBFiMY04eJEYgBySwAXRP96JUTnXU
         5zXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=kTvqOGNkX1dajKcz0lk7XHXa8sAJ1Oe5fe/wKGsY1fI=;
        b=r2LJzJy+6nQRX19eSKZzJSkGW8BskvHKnVoMxX0C5Mgq2SkuHmV8FK1vZLvzjyyBzQ
         VsHcR4DPVl3WBIitRi9bGkqODVflOBnOEEhFKBspRyfYA1BncvT0BO/MDwCqUN2OPd15
         +boAJ/kY9w7SEBLvsAk0Ln5OlyP4F9vcfYT3yfzrTDLZ/jDzskVIsFN64NX86YlF3Y1g
         8D+IJuLyfTkO9JC9ivREx9Iudp3BxQx53l8Qvfw/vsmE+R91pecGLMehaseUpgAQdhvd
         q/U7M87fSSHQrzGmTPAecQ6E0AbhBhFDqoCROEeEXLTYCg3kcGt9crF2jTkqsY5k/TxD
         o2Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id x188si42207ywg.0.2019.09.26.20.43.46
        for <kasan-dev@googlegroups.com>;
        Thu, 26 Sep 2019 20:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d4b5f999be8148baadc251c1b858fb6c-20190927
X-UUID: d4b5f999be8148baadc251c1b858fb6c-20190927
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1048956367; Fri, 27 Sep 2019 11:43:41 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 27 Sep 2019 11:43:39 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 27 Sep 2019 11:43:39 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH] kasan: fix the missing underflow in memmove and memcpy with CONFIG_KASAN_GENERIC=y
Date: Fri, 27 Sep 2019 11:43:38 +0800
Message-ID: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
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

memmove() and memcpy() have missing underflow issues.
When -7 <= size < 0, then KASAN will miss to catch the underflow issue.
It looks like shadow start address and shadow end address is the same,
so it does not actually check anything.

The following test is indeed not caught by KASAN:

	char *p = kmalloc(64, GFP_KERNEL);
	memset((char *)p, 0, 64);
	memmove((char *)p, (char *)p + 4, -2);
	kfree((char*)p);

It should be checked here:

void *memmove(void *dest, const void *src, size_t len)
{
	check_memory_region((unsigned long)src, len, false, _RET_IP_);
	check_memory_region((unsigned long)dest, len, true, _RET_IP_);

	return __memmove(dest, src, len);
}

We fix the shadow end address which is calculated, then generic KASAN
get the right shadow end address and detect this underflow issue.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=199341

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
 mm/kasan/generic.c |  8 ++++++--
 2 files changed, 42 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b63b367a94e8..8bd014852556 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_oob_in_memmove_underflow(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("underflow out-of-bounds in memmove\n");
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
+static noinline void __init kmalloc_oob_in_memmove_overflow(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("overflow out-of-bounds in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr + size, (char *)ptr, 2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_oob_in_memmove_underflow();
+	kmalloc_oob_in_memmove_overflow();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..34ca23d59e67 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -131,9 +131,13 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
 						size_t size)
 {
 	unsigned long ret;
+	void *shadow_start = kasan_mem_to_shadow((void *)addr);
+	void *shadow_end = kasan_mem_to_shadow((void *)addr + size - 1) + 1;
 
-	ret = memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
-			kasan_mem_to_shadow((void *)addr + size - 1) + 1);
+	if ((long)size < 0)
+		shadow_end = kasan_mem_to_shadow((void *)addr + size);
+
+	ret = memory_is_nonzero(shadow_start, shadow_end);
 
 	if (unlikely(ret)) {
 		unsigned long last_byte = addr + size - 1;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190927034338.15813-1-walter-zh.wu%40mediatek.com.
