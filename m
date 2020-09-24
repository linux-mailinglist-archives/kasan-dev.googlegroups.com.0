Return-Path: <kasan-dev+bncBDGPTM5BQUDRBI5WWD5QKGQEQD5N2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BE5C827677F
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:05:56 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id r128sf1197452qkc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920356; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZPIlIZdswj7GEWBgfEeNgOp2gKnQvUaXVme26SU7oTxPZb2UKH/+ZkoFDfkKs/Xm/Z
         kZcOqhyHsNi90hlLISCr5avAo+KwfaugveCSrbaG8tInu6lapRDh9XFW/RbguJ8RXNh1
         +iGuO/faRK7GmdqFVINaP20Rh6pzQtx5U2Sg0YHOdl+8KgaLXQmMb1urCif44zG7+Y74
         vLfxRgSN2xeDY5hqR3FWh7siuO3PwGHiDVHB4TkIn+xDZb5s7P1qbkWmLH0uhT14T+Ku
         c3giUkkxFSFlfQPe6swNzVBKV/9ZZoI3Kw4zM4K4PEG+voehnJaTy7RgebQqWzhidnaI
         Zo+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9nQme5sos2D84H16YRgToEGEH9u3NbFLU73LKyNwW5I=;
        b=RKnEwvMm0qwp+zU1p62owEnP75fBgd3gHVyEZ6X/AlI1q4xeArEXcdtPmhY4W4NtH7
         yPdyNGGsLjFG/djj45CFNsr6WKnRo4TbvgAaqg2+G6izlrtK+QGH/W3rQ4IXOyswTccH
         /8w5GAfAA9GDBJsm5Gm+QkKG9DgdDaOeaRl3bo88X0Qwr1/OgIhxKkzXvLMpvbZIVOo+
         pDi6zkJGYsah75bclzg06sSbV8L6P4E5KuCI79MzfRdZ1BTiQJMYSRvi2pRGATstBl3c
         zitq2KN8ISX5jLjyE2S5cNfqAn4QMM0ZxVQ1AatT23dkHs49t3fFvmTqvJOM0PVxbYid
         kIZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=rzaNtTpR;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9nQme5sos2D84H16YRgToEGEH9u3NbFLU73LKyNwW5I=;
        b=fblkIWDryuSuz8/Yx+N13id0ptQlDRHFsusrDY/P6btExOOXCo14Kp9oHki41ccZg3
         p9xnDC4sPptgQFFvkd5mFRdTtogOynLI6hkj+Hc1UPXYri6e0BPrfhxVsvEFx+jk9pVq
         5SvliTQAv7ICPcrrcZLQam+BzqmPErB1zF2Ig8Ajog9lTij0FqSQB3SOJ0lUwmhvZA8c
         GCi4WRtDSSe62OlpY936T/XI7h+KvfguY1AXCpc3AO5JJdxT2ribNnNAx/sIKWHvp8Tb
         MOP4SsKuTX9mUGDs4gL717O5c7qYrSAP+p7zZyPYBtDDVcj6PBFBmnW+ABwDD71UILny
         HyCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9nQme5sos2D84H16YRgToEGEH9u3NbFLU73LKyNwW5I=;
        b=KaecH9B9LSjVKQ71hpTUaOhCVHIp7tuwSrTyoykCtdUUUPTuAyIxPVILcBYGchg3sp
         6mRvGZ/g6smsjZuKwA9hGaJgyzHIi5everPhgZ7NENyYT3HPDO+O1sSs5cgIR92c6dhg
         kpvh1molaTo5FPPA3mKna7nmWb2EMAHI7hyYotsDMy5LrUIGMKOKqCJbPddGjExsGcrD
         BGLdkOGP13GRqvUaXUcTlClv1tpaf0/f+OHWbRW6JOQN1kn3FNKDMYAE28ExaSoBSTs2
         K2EhglfFUlqgczNxChmn6UwDrcrZg4hgwfEuv2c+lrarKobqiItzPM5xA6Wfgybo3ucF
         wb/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xMfk4gIyc+7afwwO/cXbVTw5LLoB/UB98gXv+px03HMHcnpLN
	2s7ajgXONdRxFIJDsEvnoMk=
X-Google-Smtp-Source: ABdhPJxFHDTwU6DZHH88vnB7EeVx8/OxiX/HxALXlfBpCbSVevZTOgKIX2ivXQ6EHWMA+aYsT/+s9w==
X-Received: by 2002:aed:3e2e:: with SMTP id l43mr3655669qtf.392.1600920355797;
        Wed, 23 Sep 2020 21:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:16c4:: with SMTP id d4ls497612qvz.5.gmail; Wed, 23
 Sep 2020 21:05:55 -0700 (PDT)
X-Received: by 2002:ad4:47cc:: with SMTP id p12mr3345127qvw.25.1600920355258;
        Wed, 23 Sep 2020 21:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920355; cv=none;
        d=google.com; s=arc-20160816;
        b=vSC15XBRdyFBcezHropedjrS7TRdbDj5b/J3HnagOxBPYODcBTeHJ/0kAAM3VbfJWz
         dDayw5qtAjTNq6djayqCefXEwqFfykvvqWCL4LFthqO19Yaski6Y0sVe8r1g3crJvsDA
         ZQBVfOgXPO4bDULHfnjbMwA96+u6K1OslQEZKVYJOuG383cRSURLBFNnPOpz2wspqBkT
         w34Evr5ZC7SOkl2AmpNZKy3x+E/RFlT74tBR+p83/jH2gD/fCNXLlujqA4liRnGjsoix
         aIK2f4mVEb7rwhRbdNObdsCZtYlBnszVZGdHSG19B7AMo9K/2ToM9b5OmGkSYSupBVbm
         9nzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=PimmuaElZUMsgbQjwJ8de8rcFyaYrVbSXAmqAq7D2xA=;
        b=cVnpP/VsxCfdtePRXTJp05xQ9KHj7XwrtqiCGCpHsg3p9he534/H98gytQ5M2R8L0d
         GpLjZbzlipYu5ooXM8Wsw51vEQHtLZ6400ZwTJem6V8haZ9HE9uIzQ9Uo1VgUK7RsleH
         WGjMOT05hDzTyfA2U9jolENzwZ/l1jdnf/wGgE/0/DBeP/Ko+lXe0mROgo0u3aYurCJF
         3Bf/teJKpaE4NH55ZZg+Xv+yx+5Z3ZQnDiwBdVrZQn6JORpuWetStNPrBVJQblg4Bxmj
         7ol4YWcZfvp/1Ud/U9TL+qOy23tUU7DUYRUI+RUHZtVngv2rrdTXJeOdVJMqV7FYtN2J
         j44w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=rzaNtTpR;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id h18si135430qkg.3.2020.09.23.21.05.54
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4f037dcdbe284f00a0fd594db2bdaf24-20200924
X-UUID: 4f037dcdbe284f00a0fd594db2bdaf24-20200924
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1895011425; Thu, 24 Sep 2020 12:05:50 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:05:49 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:05:47 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 4/6] kasan: add tests for timer stack recording
Date: Thu, 24 Sep 2020 12:05:48 +0800
Message-ID: <20200924040548.31112-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=rzaNtTpR;       spf=pass
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
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---

v4:
- testcase has merge conflict, so that rebase onto the KASAN-KUNIT

---
 lib/test_kasan_module.c | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 2d68db6ae67b..d8234a1db8c9 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -12,6 +12,7 @@
 #include <linux/printk.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
+#include <linux/delay.h>
 
 #include "../mm/kasan/kasan.h"
 
@@ -91,6 +92,29 @@ static noinline void __init kasan_rcu_uaf(void)
 	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
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
 
 static int __init test_kasan_module_init(void)
 {
@@ -102,6 +126,7 @@ static int __init test_kasan_module_init(void)
 
 	copy_user_test();
 	kasan_rcu_uaf();
+	kasan_timer_uaf();
 
 	kasan_restore_multi_shot(multishot);
 	return -EAGAIN;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040548.31112-1-walter-zh.wu%40mediatek.com.
