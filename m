Return-Path: <kasan-dev+bncBDGPTM5BQUDRBF7FTT3AKGQEO2MI76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FEEE1DDCF4
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 04:02:00 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id b8sf7303239ilr.11
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 19:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590112919; cv=pass;
        d=google.com; s=arc-20160816;
        b=KinWrFIEJUgooBhObxCUAXFDdvODMOCuOxiN0DOO4TPIuLPkAd55aKvg3D3+O8VLdw
         KSF2Kq9nkAvyVfX0RwKVFmeLK+VQHCzruzM7NmjJz/DuxDSnwumGLk5F7dXUw7VrK+TM
         wwGtSWSGtl6BTCJ7FGatlAkM7e/diQNYHZwh/HhJwbkA0WC7wMVYabVQtXW5HlUjsTnZ
         HN9xwPh1/aaPgGckFM4e1VxCRCghknm7rmcGnDZcqlWtXatUWjKwn+GVOvTo/IYLJrEC
         jLFFmBK13nZMYoPC0KuRL98Y3OhzDO8m4O0U22Hce2WHvJQFQgdX7s+bfpc/Uqvk9eQi
         v1uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SsNq4HOW2FQ2De/6FVnNWMqD0/C9VTPpTuySUL6KW20=;
        b=YJkWzmbCAbVpVnsmNQ0WkO4n6JiusFOgtzDyxFRX+GtEDP1kZmvDoNVGFIBv/5Z2vh
         7fp2+Cj6GQdwPWKCwi0H/SdNnFJPYyq5143qOnPRl3ZGTgzyNr+f8ouSmE7DnRbinVlb
         HZ6zGVnnvgkg8lIGgJuyiz75+rcyRXB+pK0Y8g5UIKFzIhV3mlTLzN1XObt+7FE81Xdp
         pqihwx1Nb6aFRm8tTBHNAsK7ECuq788QC2CUBKoQIAK1dL1p53uTmJushfRDXlBs7PZl
         u0HJZEHd4i+mlAc8wpX+UIlHuombNb+Gva4BEf+GyYr9xFs3sqRewra7ZG6M1jHsIJ0R
         bqQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=H2iF5wuN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SsNq4HOW2FQ2De/6FVnNWMqD0/C9VTPpTuySUL6KW20=;
        b=BFyEY1hX9lBxlZ6yjtikWRvBgFdafViA0OFb5cROQiOkb18IUAGDvYXWeM2n3pxlyU
         DU/fpJmygsFWIyMcIGdfdwcMph2FVlzJ2Wuhnm0X/u8Cc8aBcsmvqX/8XnhtGJlGo8eU
         ecV6ikGrFQCr5/FiRjlGMYduL4hhKZdH51MtDns0m+moeKxJhdzLz6V5ggbLjrJMPgo2
         l8tNi877OUWedYSgcruTjYBuwdVSGNoeQ4N4zzKH8tNq99YACknWYW4GRFsszWrQksnW
         WSJIvrDkF7vSnWYhQj3YGxZ2Lo4pjJS5b2DvDGXny8NFRc7v8EbQZkHrTXKd2bXnpdPi
         yhKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SsNq4HOW2FQ2De/6FVnNWMqD0/C9VTPpTuySUL6KW20=;
        b=WyvjsYUNY8d92tOuzDNvA1u+HL+HlEH5I6PTh0tqxsC6jS/WORf6A+JEiOBx2alSp+
         y+UvLnHqvdQ+TV3q5nLPnAI+0CieJ4woPM/93iOQ9hvaE/k/OQfFQ2TXqGJ94yZmIkyx
         tHqyzoMmmooWvxvaCplstaBnCjDGvOMDFihX11HYUhaLkxJ5SjIsS4H/6oYGyp4u99e9
         rOIbZaYO4qCxQ/QLtqgkHSysEuwvvIpTNs5rY1Lu8VOGC4VXBkfzi9QsJP1NLVp+yZkN
         AiwycDDmKSTplxWBE8nVU34LcJFOprG8hgp1gj0h62ZMdLTV0F+MaOriPuM7jJspMQoH
         51zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532red7Xsfzxo9/bMGp8qAHf/iEotKbQY8if1I8KZ+OcbVU8auBE
	7oYevmMAYC0Fa4yU3CB1dbA=
X-Google-Smtp-Source: ABdhPJySnKy/wi0vI2GKuUuwvWU8PMiWGxX0dZOjsM+j3yg+lsleGMBkQeVCNspi/TrM+4vgCrSi7w==
X-Received: by 2002:a92:ce05:: with SMTP id b5mr10550364ilo.124.1590112919145;
        Thu, 21 May 2020 19:01:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:99:: with SMTP id v25ls65927jao.7.gmail; Thu, 21
 May 2020 19:01:58 -0700 (PDT)
X-Received: by 2002:a02:2581:: with SMTP id g123mr345683jag.35.1590112918795;
        Thu, 21 May 2020 19:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590112918; cv=none;
        d=google.com; s=arc-20160816;
        b=a8y5eV3LK29TVM+JRZfiP29VDL7M2BulxNeAU/ls2JUNWvmrBI9athfqMFrjexW1DQ
         LE0b9ndJNHUIvphko99FMeMOfq1LoqqUsotV8tZElm8OVcyRAeHnqAX5iwZlkcd1JGQs
         +jhcYM9vF0NxATZQcG+ahwo/MbbT9V3wu82B7vXhyBXeZ5A/1eTjoDcX3dpR94C4Hokx
         hhoWfr293fS65QHGhiAXojopxiXNuqqVvVbRazh+uYVkuu1+UZ+yK29GorTCS2kgkdae
         mRjm21H3wHym6v7+DemmmmceMk0PQLXm8YuzQBZAyeZagA2qtlGnBxuwwdA6A+j7AKMA
         QbMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DbdlJu8vuZUyyQAeAhd6YD50kjTkWp9bEKvDh4VAu5A=;
        b=dinnjX+fzHhA2TFW5f2+nVpn2tQVMtUVwCVeIV3LVnJ+m7IMEFH5s+yJp5pJaz+bYF
         tgfJs09q37Qa1Kw2bWQli03W7/tmOypG162ahqXZxk/+xxmMGAlUNWanyV3oHbCLdvlO
         hjjxLRTa2+7AYh9F5oJ7HfFzWMUceCz+tUL8f21C+A3laJ0fmEm9eA+af59NaVZolHF+
         VBJc3pvW5xDK3tBaGogNPh07TIVG6DmVoQLc+O4PiZoCiThg9eWKnS6HGjtfLtTfSLDn
         TKGkU01Kqgg6dT1Nv5/QfJg5xdmUSOVZHxIYD2y4xW5+6FdqO8FDoXDwjzLYWSFiw+cu
         PqCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=H2iF5wuN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d3si518274ilg.0.2020.05.21.19.01.58
        for <kasan-dev@googlegroups.com>;
        Thu, 21 May 2020 19:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 12f6c77d0e474357b2a3248c96270604-20200522
X-UUID: 12f6c77d0e474357b2a3248c96270604-20200522
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1189950889; Fri, 22 May 2020 10:01:54 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 22 May 2020 10:01:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 22 May 2020 10:01:51 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v6 3/4] kasan: add tests for call_rcu stack recording
Date: Fri, 22 May 2020 10:01:51 +0800
Message-ID: <20200522020151.23405-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 1DF83D308094557B8096DD8171A9C524EA3231510A950D2F5EB96F4701E47C662000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=H2iF5wuN;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020151.23405-1-walter-zh.wu%40mediatek.com.
