Return-Path: <kasan-dev+bncBDGPTM5BQUDRBFXBSH5AKGQEOPYEHIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE91250E76
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 03:59:51 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id gj13sf583367pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 18:59:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320790; cv=pass;
        d=google.com; s=arc-20160816;
        b=rhonQ/I5Og0Fu4AcfdQT+UVajtFb7JylCd33Gsi2U4yWGxA/hX5MRlqBh8dl9wx9pe
         KetW5kIaOzoLG+i5rDrwb6CJUkz+KVQJRGGzFzzbls2t2mGeINKNbGX0J2j2g5WtLJ4t
         U3ujr28Tj4JXZTDNTO4sFw+FkQ/oh0krN5JgCNvtAzF9lGRaCTQfUMx8aRXkvy3645K0
         /iBf+CIMSO0kAmFcUf4EMkzyETJIFVUOEIMUBIJkYlOLFJa0GbDRfvlHrZsj66OorwD+
         49SaHPh949GirTCUhp64/dlAeLjaKo2tN2WX7brJq/ts8EswQQszi/0MmHNXPRUwwvQs
         cgyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=z5PlVjErfLLVvpFwDDaHCWxXjtTbzWFD5r4S1iAlibE=;
        b=W1t30eBSz8WeDRy7kBhlLH6h+efQqUf7JSEbxufA3Lg+WyjjdU5szgqUDDr64/OnzJ
         EIDFcjyqZLlGb6RnwJg4l+yQFIWLz31/OtOo4DIHRgbvZe0TweE7fw7EdG9TSaFDKXke
         qCel5372jN8sdqvs53jVSK5Ry1X9g8t3feijuw8ZuXgWZulNyg73jXTn0CbS83q7rq/f
         sgqUUi7AjHOxzdu2CFLxxdTjDKVQ41TgISanMRgkoqduLe+SRSbs5Chi/mzzuaWIxbvc
         EYGqcALA2ispm2giBOu7UVuaaJ1GsfWe1MDea5ULPxFRwEmW3r3cAglzixrxA81F5fAi
         uhXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=AEwEMb9K;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z5PlVjErfLLVvpFwDDaHCWxXjtTbzWFD5r4S1iAlibE=;
        b=nqXOJzfvBYR7WDWJcCkmKW1ZGHHgeNr5KibaA2NxK8bfZRzrklZajRZzHxejDVkFVY
         l0eUtZAYa8BWZW1FuRcUyvEevru3LFb/Sj2nebciLSe1iJCglT38yjwPJhhcOwaCGKUx
         SpSDS4zByzVjzwCHfJNnEe3ide0cqzh1gvs0CIc7MQRqEKcr8ARcw7hhtytFqFwlj/Ms
         2JQ0CJ8NxsJ8i0ByVx2Xsf6bADP1HvuHmq61xPCREjLZ0F8Asv23+i3ARgp3HUqXhta4
         avxx/sNfp9ky3S529+96tw/nPz2fLeyq4hqnIry7DK1eOviCW0Cdwaqlmcvr9x+oXWU6
         lOMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z5PlVjErfLLVvpFwDDaHCWxXjtTbzWFD5r4S1iAlibE=;
        b=fuTFpIrRG7S/nQpowmR5zo6c5yxYIFBwhmBO9zkArBhPrvylJSWOyYgL4RbMNeF8q4
         HU2tVC3Fo+y5nx2znq4YfzesVvqBdoJT3GZZBWivi6gVmrpMtBJzfS7MYpxnSVQX0Ooa
         A1vJcaA2JeytJ+5Os2QW4hp3cDcc2Fcdgj+OaEKcQRTbeWl8oJoA5qHvFw+AcPrt76CY
         KcVrPOwRzJwW3NWv9WItPfMOiHSirT/Zw7TTxLMlv7NY7zAV7dPZkrzOpzB60ckbtvJE
         N3faxj05bIYND2yuxR3zDN7CrHXc13xeW/d9xsQK32XT/egGbt0GH/BqScN8BfXm8AmJ
         d4sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531E9eGUAZNAVHH8Nq+9zgVTo5/1hwQ4qQwHf43Sk07/jcUlsc01
	IM8ctq7Dpgow1H2rWskjD1M=
X-Google-Smtp-Source: ABdhPJwwq5JTItdTpDZlC4mhMzU1SaQox8ynjdk6p6QcuulzyBKHN6MXGhIGZH40xdX6d1CVsjQwnQ==
X-Received: by 2002:a17:902:b087:: with SMTP id p7mr5791565plr.28.1598320790312;
        Mon, 24 Aug 2020 18:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b12:: with SMTP id b18ls1814770pfb.8.gmail; Mon, 24 Aug
 2020 18:59:49 -0700 (PDT)
X-Received: by 2002:a05:6a00:798:: with SMTP id g24mr2322558pfu.196.1598320789867;
        Mon, 24 Aug 2020 18:59:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320789; cv=none;
        d=google.com; s=arc-20160816;
        b=MEzh4tpdSDQJjo5lrEgiiqr+FZgpASGmVj8U63Sq//j8psVdimV+9E+7UBZhldfUeK
         pRziHshrxRAoE+buSoPtmgxEwt5L6LL43y+HW767MOk6dlSBMQiHRxajm8HeLKGgam4y
         UpT65JUofNta7Or8tLdahD1dQk+/j9d6Q9cbFFyyG/1weWrxtzzPwg/j+z8GXdV1t2M9
         CWCEcZOvwaPMCrOBB2Gydp/EEm6NvOTPUP6QUsGuY3wclH+DpabGWKXW9W3BPJ3es9Uj
         mw7sFZVfvMu4CjSFAYb7QHc6oqV3Y4BkTe0mt1MvMpecMSWUWL59bbH/0eQ+qqbnQzW2
         E68A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=epF31PMWeocflqrG14ZTfXrn/tbNID2roIzjg+E6Ras=;
        b=Wno6qdg920gQwe77cO4scdZuviAsUSayeQIkZudQ9nWkxfzEV0WvbgiAFyd16MpfE3
         5+D8Pq1tka6J8JOo6RQG0nQgpQJOvYyr0c+FbGjdO0VI3sh75jUtux6XjhGEeJyzQVAW
         AsadwdI3Naw7A3jo6lCPT29herV7UiXJMPP5qIex3v31/SlE15GwVuzRApaRKCHon0Ts
         Nb93UM0efaFbBmDnwMV9eWpvEB5B3lTNi8bqoiHoRtRtFEVJMUxljsSrVi3vPwc+ljBs
         Xj2LnKFTT7hOr5q2FBrH827vPbp+Gk43UkEEXTQwmyOnKDmB1lEdksI3aizDuOdw/xsM
         HJKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=AEwEMb9K;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id b21si583099plz.2.2020.08.24.18.59.49
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 18:59:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 98a7e483496941cebb1de58f45bc043b-20200825
X-UUID: 98a7e483496941cebb1de58f45bc043b-20200825
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 389396664; Tue, 25 Aug 2020 09:59:45 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 09:59:43 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 09:59:44 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 4/6] kasan: add tests for timer stack recording
Date: Tue, 25 Aug 2020 09:59:42 +0800
Message-ID: <20200825015942.28005-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=AEwEMb9K;       spf=pass
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

Adds a test to verify timer stack recording and print it
in KASAN report.

The KASAN report was as follows(cleaned up slightly):

 BUG: KASAN: use-after-free in kasan_timer_uaf
 
 Freed by task 0:
  kasan_save_stack+0x24/0x50
  kasan_set_track+0x24/0x38
  kasan_set_free_info+0x20/0x40
  __kasan_slab_free+0x10c/0x170
  kasan_slab_free+0x10/0x18
  kfree+0x98/0x270
  kasan_timer_function+0x1c/0x28
 
 Last potentially related work creation:
  kasan_save_stack+0x24/0x50
  kasan_record_tmr_stack+0xa8/0xb8
  init_timer_key+0xf0/0x248
  kasan_timer_uaf+0x5c/0xd8

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 6e5fb05d42d8..2bd61674c7a3 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -821,6 +821,30 @@ static noinline void __init kasan_rcu_uaf(void)
 	call_rcu(&global_ptr->rcu, kasan_rcu_reclaim);
 }
 
+static noinline void __init kasan_timer_function(struct timer_list *timer)
+{
+	del_timer(timer);
+	kfree(timer);
+}
+
+static noinline void __init kasan_timer_uaf(void)
+{
+	struct timer_list *timer;
+
+	timer = kmalloc(sizeof(struct timer_list), GFP_KERNEL);
+	if (!timer) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	timer_setup(timer, kasan_timer_function, 0);
+	add_timer(timer);
+	msleep(100);
+
+	pr_info("use-after-free on timer\n");
+	((volatile struct timer_list *)timer)->expires;
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -869,6 +893,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_double_kzfree();
 	vmalloc_oob();
 	kasan_rcu_uaf();
+	kasan_timer_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015942.28005-1-walter-zh.wu%40mediatek.com.
