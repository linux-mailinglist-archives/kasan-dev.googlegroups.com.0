Return-Path: <kasan-dev+bncBAABBGGL76JAMGQEWQY5YIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id A7D0B50865B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 12:51:05 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id u7-20020ac5ca87000000b003495b55ea6bsf205095vkk.10
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 03:51:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650451864; cv=pass;
        d=google.com; s=arc-20160816;
        b=E10Ze8lOY4QyJ6cE6si3d6ZCJ+CBTHqzx60mbtcsno+MLh+kCKi2CqckoEECmLzZm+
         6EEX17rStKgoq+qCDpiaWQxqMTmwgz0zUUlbCnUAYYvvAHbj+8FrRUF8TgbYbZbVGFEX
         hYnl+uU4e0e66iWjrwQBKSHuTPbSS+PbmnrZqnZzWEbqcVSgn9IOYrnNCKGx9c/hEYuv
         T/6G/HzQwhm/LPxgfKLIl5FSPxX/zH6ysqF8kRm3G/qKn4AV0ZIzqPjOa1yIpySvNOjJ
         nCBpdHhMFWU5/tLNZHY/vMSyYKxGiIB2cYkAk9XijI5Jge6Kc5mDd8n2rjwzmCV6kCiN
         nnLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=ejOSIHOE1JR7Q0CvexaIMUazs/kimQXZHx7WVMbKFRQ=;
        b=m79xI318NQ+bWS7bEC3GfxhqGdDpFlfus6+0DUgs4iKZ66Jfuak81M2FAzYTM1/7sq
         H/X/uGK0+Qdc4K9qkEfhYg3E8sYZ01YyBKluqH9qlDTusRbhf1A/HuqCnUy5X2EWb9Xg
         /qbJbSmkO8pJYB1DOJkXJvs33ujG1yQqO2vHJUUU19UDDij7Ku5NKIbELraA81BzylJ5
         RzhcFnAWY7L7yn+q4EsLYZLvrdaQE8oIpN80hX9EZAmFRJNw/V2FwKBjMWMTYZqoTCGZ
         vhn6ORUman+jMXtL4uucs2lo5Qz9/EDMK8NK+he8utSzIop9s6Oj5hPCwXEd7IvlXmQN
         IqZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ejOSIHOE1JR7Q0CvexaIMUazs/kimQXZHx7WVMbKFRQ=;
        b=Qd5q/DgqhjRne7oDjC3Sip7SNZ53PRfavY/hIZc0BeZrSZtyaqlEEaqDEEHwjI850x
         b2EfZaXk0yrfAGtTW+KVFNuR7KJaL5p/wcIGMmSicHLiKQUzeQ4YuCloRcEK57+xxN9l
         4D4JqeKFj+9LczlL8pKbNGWXAd3Mq22LMPzbozgwRS+fvsVw/+g6Ix+HHQPsH/E6WeIc
         Ltd0eBB7hObaLIIzX9hGj+INdxo5hyOc9iUGNMdeKQvc8rWOb09ITJGXKU1TmwDXz314
         QZ1rFPY+SFVRwdT/HLUzZeztUL4Pj8sKO7/zu+75NVByiURsldsEDmxfIABBJW+1dJEj
         yV7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ejOSIHOE1JR7Q0CvexaIMUazs/kimQXZHx7WVMbKFRQ=;
        b=biZYpj/wqiQweuPWQH2ZWRnWsMa2mLovGVaJ+eNTSAIWhvoQU0lHGdMBpAnRo3/1DF
         xP8xL36VpqyVppcpcs7uNuMMdMkaayhbhJyZSoJ5wA3lnJcZkJ8Xq68d3yzb7dlDZuU8
         /gmea8y383y1mGB9CYOCPWkpFDvjqPOgEiIf4ep5idxajuwj7YF4SJkq6eGesSvWexx3
         aTCqRXgUCGAyhyhrt+BK8an25QsFNdiOsq5aEyoPBDoUOJ5brO1d+0SkeOxDw8r9XJDD
         AaEvos0RG51I5P+EDgWVWmduY4yzsXFRaDDGIY8jjXbfY0bXDXTPUrcRWMrtGLOehUGG
         s2KQ==
X-Gm-Message-State: AOAM530yGvyS4y7mk+ihf5mqaTAnWH8boZBUxBCmUyaiI9Oh2FA4XGPE
	PSndFsl9X5zl8OBXo3G4l9Y=
X-Google-Smtp-Source: ABdhPJyon4RIITSxizQ9G16cHa5RNuNEAuJtMyQ+X4IqMj7T5pcgcXRO9rNFGsqX90OMDXed6R7Avw==
X-Received: by 2002:a67:f9c6:0:b0:32a:32d6:3a1d with SMTP id c6-20020a67f9c6000000b0032a32d63a1dmr5855992vsq.24.1650451864399;
        Wed, 20 Apr 2022 03:51:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9047:0:b0:343:3bbb:5863 with SMTP id s68-20020a1f9047000000b003433bbb5863ls243878vkd.7.gmail;
 Wed, 20 Apr 2022 03:51:03 -0700 (PDT)
X-Received: by 2002:a1f:d904:0:b0:345:a109:830 with SMTP id q4-20020a1fd904000000b00345a1090830mr5975277vkg.9.1650451863906;
        Wed, 20 Apr 2022 03:51:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650451863; cv=none;
        d=google.com; s=arc-20160816;
        b=xaK7fi2Zo/DOv1gPi21bGiIyTUYgp5g4DoxGd2GbyEQDb3tr4HJF5t5sSzDQYl0XMG
         L2bHGqY9SmrB+I6A0chkI8Ln7rNBHVbu7Ti0trO0QKb7gO8XkXnGk3s+5tfvno17p7F7
         wawdToGe/fEWiENTBPBV/yIsClELn1A5ZlkTjYdqr9dGn6qK/Tqzc6BXZmcmXhCDFW6M
         oAvVZC5LMQmO8soGjoD+xaj5uHCo/GWMIbo8zhg5Dovp2Dl7eDsn4rgdPI7JjsB8TVTR
         y6MfsmJ8evtarr9ydBFDG9hpiqoQFGiRftHK+YLDCMWXX9WZZTLhkrSw4puG78Js+g83
         eDDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=7zUWPWWo8GJ5khQhpR8YhqRSb3sgz3Aij45XsEKxXpI=;
        b=hwLC9G+f/4777eUU5lad7f0SZfh5KVexmYGxLD2KsO8KDLCnAunDPYCy0vztw8BlNz
         F04nXQJblI7tajaAv8jWEzTbzbN4yz8zzw3R+588qXM+MdlLSGhH7r9j0MUwu/p+2YPn
         cvenTrKgR6bqRgwo8tXPTMDlUtlS0A0Pe6XxLWJ1W3SaKXM/OT7itDX3gzUWou7OWl47
         homuTdgSAc5kBkvron1SI1EWEH8tZ/m4t0rD52ufKtIMYRZyZxh71bCmrGzodS9F3rBP
         HmT/D0X1C5TLtOlNVodTRk0MBYFw1kBis/2fk+Io3orhinEYDORjHLp2XFt8Z76WqMeP
         ynsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id o2-20020a056122142200b003493a70c4bdsi142807vkp.1.2022.04.20.03.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Apr 2022 03:51:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100011.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Kjy7N1D3NzFq0Q;
	Wed, 20 Apr 2022 18:48:00 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100011.china.huawei.com (7.221.188.134) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Wed, 20 Apr 2022 18:50:30 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Wed, 20 Apr 2022 18:50:30 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <young.liuyang@huawei.com>, <zengweilin@huawei.com>,
	<chenzefeng2@huawei.com>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<huangshaobo6@huawei.com>, <wangfangpeng1@huawei.com>,
	<zhongjubin@huawei.com>
Subject: [PATCH] kfence: check kfence canary in panic and reboot
Date: Wed, 20 Apr 2022 18:49:27 +0800
Message-ID: <20220420104927.59056-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Shaobo Huang <huangshaobo6@huawei.com>
Reply-To: Shaobo Huang <huangshaobo6@huawei.com>
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

From: huangshaobo <huangshaobo6@huawei.com>

when writing out of bounds to the red zone, it can only be detected at
kfree. However, there were many scenarios before kfree that caused this
out-of-bounds write to not be detected. Therefore, it is necessary to
provide a method for actively detecting out-of-bounds writing to the red
zone, so that users can actively detect, and can be detected in the
system reboot or panic.

for example, if the application memory is out of bounds and written to
the red zone in the kfence object, the system suddenly panics, and the
following log can be seen during system reset:
BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70

Corrupted memory at 0x(____ptrval____) [ ! ] (in kfence-#59):
 atomic_notifier_call_chain+0x49/0x70
 panic+0x134/0x278
 sysrq_handle_crash+0x11/0x20
 __handle_sysrq+0x99/0x160
 write_sysrq_trigger+0x26/0x30
 proc_reg_write+0x51/0x70
 vfs_write+0xb6/0x290
 ksys_write+0x9c/0xd0
 __do_fast_syscall_32+0x67/0xe0
 do_fast_syscall_32+0x2f/0x70
 entry_SYSCALL_compat_after_hwframe+0x45/0x4d

kfence-#59: 0x(____ptrval____)-0x(____ptrval____),size=100,cache=kmalloc-128
 allocated by task 77 on cpu 0 at 28.018073s:
 0xffffffffc007703d
 do_one_initcall+0x3c/0x1e0
 do_init_module+0x46/0x1d8
 load_module+0x2397/0x2860
 __do_sys_init_module+0x160/0x190
 __do_fast_syscall_32+0x67/0xe0
 do_fast_syscall_32+0x2f/0x70
 entry_SYSCALL_compat_after_hwframe+0x45/0x4d

Suggested-by: chenzefeng <chenzefeng2@huawei.com>
Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
---
 mm/kfence/core.c | 28 ++++++++++++++++++++++++++++
 1 file changed, 28 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9b2b5f56f4ae..85cc3ca4b71c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -29,6 +29,9 @@
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/string.h>
+#include <linux/notifier.h>
+#include <linux/reboot.h>
+#include <linux/panic_notifier.h>
 
 #include <asm/kfence.h>
 
@@ -716,6 +719,29 @@ static const struct file_operations objects_fops = {
 	.release = seq_release,
 };
 
+static void kfence_check_all_canary(void)
+{
+	int i;
+
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		struct kfence_metadata *meta = &kfence_metadata[i];
+
+		if (meta->state == KFENCE_OBJECT_ALLOCATED)
+			for_each_canary(meta, check_canary_byte);
+	}
+}
+
+static int kfence_check_canary_callback(struct notifier_block *nb,
+					unsigned long reason, void *arg)
+{
+	kfence_check_all_canary();
+	return NOTIFY_OK;
+}
+
+static struct notifier_block kfence_check_canary_notifier = {
+	.notifier_call = kfence_check_canary_callback,
+};
+
 static int __init kfence_debugfs_init(void)
 {
 	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
@@ -806,6 +832,8 @@ static void kfence_init_enable(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	register_reboot_notifier(&kfence_check_canary_notifier);
+	atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
 
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
-- 
2.12.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220420104927.59056-1-huangshaobo6%40huawei.com.
