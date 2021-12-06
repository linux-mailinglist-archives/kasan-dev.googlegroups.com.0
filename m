Return-Path: <kasan-dev+bncBC47LDOHVIGRBEU6XCGQMGQEYJG6Y2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF544696EE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 14:24:35 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id m9-20020a056e021c2900b002a1d679b412sf7765042ilh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 05:24:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638797075; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWmUdePQ0DUQgSaj2nAxTto1dsDQpR5vLGwOeGLnwqaFcLjrMQYx6Y87zaVVoTlh+M
         n3QmjthURpHyLw31mCrpmQ8fDpo06KKg009swhHTzZfoA/hH35+k2281obAhkOAi+sY+
         aaDP8E8pyRUpiviNTKoExx5Jsof+PYt4gfbBQwa1y63rH0sjU1v+RLsyURGJ+EKsz0nU
         Qpgg1gUaG4eQ6akupzCzqS2iPV2UVOw1QhJuJetlaiEHG7CwfpzPCe+99x5PXdIOZh60
         Ob0TAlOCoriv7DDowkmsPoZv7YOArF3Xfgfzz17F/ntd5BPQRcfUtjWR1BvXw1iMZ9Z8
         6AkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=f2a0XkLRneqZpySqb9/FwXl47V3tGCvu/t/iyiDgzMo=;
        b=TVqV6ycjVgOGHQCYtcFtMcfS61d15zk9PQ/QU+FGyR8oRCUeNvNpnpaNGFBYPvsXdn
         8NHsO5l7Ch3C5CJ5bOAFUUH06j/XlF7SfQuHKsLqzwFnaeUevPVMz40WdScW/mW2QvlB
         d8ABt5HJIm3THwScZU4qGEi8cQUrqZYS+Ji2B9x2Ucd/P3OZ2L9B8JPP/AdLb5HKinqO
         +khvPXGQrs2cqkddILn2IHwqSoxzCiz53eea6gZ22kWJ58HwBtBWDVyUleQKoMoxxQwo
         IvHCxQiHCy51PVCQ7OoswGM89evLOaTQ7DjI76jg3C9vZw5fWR4so6mWf2JoIvAurTlC
         CfBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of libaokun1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=libaokun1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=f2a0XkLRneqZpySqb9/FwXl47V3tGCvu/t/iyiDgzMo=;
        b=oMunde++asjJrrdZZJDw6MAaPPVyl9BOVrTYXLzAaodDnHc5jj/7GjVRwA+g4BVuw/
         /F7nXB6b2XLfovy7kLUPwD9ZDiYvGJdGOWafjh2l3ifLiSU3vFVYluT3qeUch5zqZ12W
         fuzzb6YiMESbvbn2OgzCtVsl3f89N6clF8X1QGDlzt1Wv+Dbz2FdOrHBgTk5lPa5+LPa
         i0XtYLM5cbLKu8tsuQm3mM9Hx2UMtw39BVJtBNJCohvzTkX8pqgWcWLFra8YkE0gN7L8
         8abtUXEpNliP10voMHIkjvchBDnNxI0FD47xxjMF6IHGGnqRuUtb7MpEsmgrc3dk8zC9
         ItDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f2a0XkLRneqZpySqb9/FwXl47V3tGCvu/t/iyiDgzMo=;
        b=nwuIU2gsHpNRfN3ehz8j6xFfcsU4bqd0zxva+WBhcH+kPJgcu7pe2XhBmpmjNVZGEi
         VaxS4yd/hnrb3GkPYL1KYBoU+AoZTO9Fbfbt/fQ5xJOy932Ha178kN+Gel45uwrbpIYj
         0GJBjrJ682rLXzOFmKly3DDQ3VqPUG7b6KLnunJ1GyJ0lyxu0MP+0lt5pSFsaGtymZmX
         tQtBIfPHk8ELHf9ZupWB6kLr50BxvvoJkZQZQ6JCeONzD2PENP5fQdEJQBeCGJTtudsA
         m/MeWNDtv6yKBJFeJc5+jTq1AcktODKwBJBfeEp44vLs+GUQhna3X0L7tDgEhcLozGGC
         OWAg==
X-Gm-Message-State: AOAM533fAWf+k2OtrMDfLCNFuA9wx4S3H2+jLNR+WfBJnP7yS0jynU6f
	rn51JezCLQJb12zacuBsRTk=
X-Google-Smtp-Source: ABdhPJwR0nzQ7WKnBTbxGewNYSdJPMR+g+cWhRJwjT4kPOPCeUBnqZWzUInPtcdn1wmbxkznXeZVVw==
X-Received: by 2002:a05:6e02:1686:: with SMTP id f6mr34158321ila.298.1638797074963;
        Mon, 06 Dec 2021 05:24:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170b:: with SMTP id u11ls2885583ill.3.gmail; Mon,
 06 Dec 2021 05:24:34 -0800 (PST)
X-Received: by 2002:a92:3013:: with SMTP id x19mr10412412ile.113.1638797074171;
        Mon, 06 Dec 2021 05:24:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638797074; cv=none;
        d=google.com; s=arc-20160816;
        b=R4ff/cQdAAJXkbnk2MrWHNNxnvPZUjiZxyxMmRrABtWvr9jWbs8CMnd7y6J+/i5e1g
         09ogcjzGWwv+a26czXZbgz+nMaxMSP4SJhfRYieToUzAt83WaE51YbCaxzehXYnfP0VF
         K1+gS3lO/gUjtTZ/TfroYUxSEHEbQBuHyClvWXhJWp2zLD9xouRi0C6G5d2dAp+aicq8
         CzaODN+vC/pawQZb4Upiv48vuSyU3jXVD3eEuCRiJ2cX807kWlJRpDU0tQfRnNAdudJF
         v/TrbtabxiVo2pscPNn8jpKnMn00ENNuW5iideplWlgWXteCeCdnQR6Tf7jAegWX00Od
         rAJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=q8IySeGuVBrWIutvMaCnInRGtozFC3A/ov9vg2WPOWY=;
        b=dt/CMZHjU7qCYh7yNuNlhV876kV/CpDVSaZkQr1j59x6BPAjKhmhV6RZubnjKKt07i
         wyq3wbIew2EDCkEG0zz7iEvGwyFAiBxSi47amgxcZC/XKp9vSWDM+PW0V4bNb8wheJ+C
         CcSyd/XWwel2nwwv6Ze3lp1Oa9nJn06E1sBtlq9KJ1XKEbCOUOO9U3b904eOKPyPY3bd
         sEuHLO3A8GLFrzuUVTOq4pmPf11kWt5d/BTy5mqA4lJAGYr1FEECSJFy0FyOmGM+Do/3
         AHaHiW1eyntdxrsT2jy0CoTgsGWVWrzrHMNFWmPkkZL5DsXfzPPr06cMpeUfoY5vEzof
         tkmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of libaokun1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=libaokun1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id d4si589206iob.2.2021.12.06.05.24.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 05:24:33 -0800 (PST)
Received-SPF: pass (google.com: domain of libaokun1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpeml500020.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4J74045l9hzcbmZ;
	Mon,  6 Dec 2021 21:24:20 +0800 (CST)
Received: from huawei.com (10.175.127.227) by dggpeml500020.china.huawei.com
 (7.185.36.88) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2308.20; Mon, 6 Dec
 2021 21:24:31 +0800
From: "'Baokun Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <viro@zeniv.linux.org.uk>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <libaokun1@huawei.com>, <yukuai3@huawei.com>,
	Hulk Robot <hulkci@huawei.com>
Subject: [PATCH -next] kfence: fix memory leak when cat kfence objects
Date: Mon, 6 Dec 2021 21:36:28 +0800
Message-ID: <20211206133628.2822545-1-libaokun1@huawei.com>
X-Mailer: git-send-email 2.31.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.127.227]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpeml500020.china.huawei.com (7.185.36.88)
X-CFilter-Loop: Reflected
X-Original-Sender: libaokun1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of libaokun1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=libaokun1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Baokun Li <libaokun1@huawei.com>
Reply-To: Baokun Li <libaokun1@huawei.com>
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

Hulk robot reported a kmemleak problem:
-----------------------------------------------------------------------
unreferenced object 0xffff93d1d8cc02e8 (size 248):
  comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
  hex dump (first 32 bytes):
    00 40 85 19 d4 93 ff ff 00 10 00 00 00 00 00 00  .@..............
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  backtrace:
    [<00000000db5610b3>] seq_open+0x2a/0x80
    [<00000000d66ac99d>] full_proxy_open+0x167/0x1e0
    [<00000000d58ef917>] do_dentry_open+0x1e1/0x3a0
    [<0000000016c91867>] path_openat+0x961/0xa20
    [<00000000909c9564>] do_filp_open+0xae/0x120
    [<0000000059c761e6>] do_sys_openat2+0x216/0x2f0
    [<00000000b7a7b239>] do_sys_open+0x57/0x80
    [<00000000e559d671>] do_syscall_64+0x33/0x40
    [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
unreferenced object 0xffff93d419854000 (size 4096):
  comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
  hex dump (first 32 bytes):
    6b 66 65 6e 63 65 2d 23 32 35 30 3a 20 30 78 30  kfence-#250: 0x0
    30 30 30 30 30 30 30 37 35 34 62 64 61 31 32 2d  0000000754bda12-
  backtrace:
    [<000000008162c6f2>] seq_read_iter+0x313/0x440
    [<0000000020b1b3e3>] seq_read+0x14b/0x1a0
    [<00000000af248fbc>] full_proxy_read+0x56/0x80
    [<00000000f97679d1>] vfs_read+0xa5/0x1b0
    [<000000000ed8a36f>] ksys_read+0xa0/0xf0
    [<00000000e559d671>] do_syscall_64+0x33/0x40
    [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
-----------------------------------------------------------------------

I find that we can easily reproduce this problem with the following
commands:
	`cat /sys/kernel/debug/kfence/objects`
	`echo scan > /sys/kernel/debug/kmemleak`
	`cat /sys/kernel/debug/kmemleak`

The leaked memory is allocated in the stack below:
----------------------------------
do_syscall_64
  do_sys_open
    do_dentry_open
      full_proxy_open
        seq_open            ---> alloc seq_file
  vfs_read
    full_proxy_read
      seq_read
        seq_read_iter
          traverse          ---> alloc seq_buf
----------------------------------

And it should have been released in the following process:
----------------------------------
do_syscall_64
  syscall_exit_to_user_mode
    exit_to_user_mode_prepare
      task_work_run
        ____fput
          __fput
            full_proxy_release  ---> free here
----------------------------------

However, the release function corresponding to file_operations is not
implemented in kfence. As a result, a memory leak occurs. Therefore,
the solution to this problem is to implement the corresponding
release function.

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Reported-by: Hulk Robot <hulkci@huawei.com>
Signed-off-by: Baokun Li <libaokun1@huawei.com>
---
 mm/kfence/core.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 46103a7628a6..186838f062b2 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -684,6 +684,7 @@ static const struct file_operations objects_fops = {
 	.open = open_objects,
 	.read = seq_read,
 	.llseek = seq_lseek,
+	.release = seq_release,
 };
 
 static int __init kfence_debugfs_init(void)
-- 
2.31.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206133628.2822545-1-libaokun1%40huawei.com.
