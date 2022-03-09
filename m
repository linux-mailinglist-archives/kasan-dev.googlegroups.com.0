Return-Path: <kasan-dev+bncBAABBDEGUCIQMGQEBUS43WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63A274D260C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 02:29:50 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id z194-20020a627ecb000000b004f6db380a59sf579051pfc.19
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 17:29:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646789389; cv=pass;
        d=google.com; s=arc-20160816;
        b=jN4CZJ6XT8e5al5Wdjme5jO1u77rt67vEVlhZbMCQodxXOxDS5559PPTfpjKDBXGmq
         0OkzVlxh2tGhdkW2Yd1ndRnP2vDJqq2cUTssbUoL18+pTfToLO7xYfQM3fTKUB0X9XR9
         AGPyq7EhNZgfde2gQV89HwRxZ27wSLi9V5/YCJpP+UnqIzCYpUevwtKiFliByPMWPf17
         5avb4AAE11k2NsHsiYm/TkcfCpeWmjECeEB8V1g7V+e2cvY41E7PgTdWWdKhRXyjmA6r
         2PA7gKYA5VU6tSfxs9YiDZqHhbAgkHXybyVyjYRX6RA1zO7on/w3x7XcgcnvHR6DdwGT
         8x9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ypmVCOyIjSLee3qyci0LYfsmjV+ziZpiBA4nNv9bPxI=;
        b=bhusGUkMXMCfo/Nx8onf0zpe66S+qbgCcwntr0VT1RmIUtdy/Y3Ilv7fUzSmwdzGCG
         LMKSgN07HKYqOhnF/jTutt9qG1xK9h/uzEkUs4vVxc7T7WWAHil3zMvYSaf9gWfRgY6H
         w0s2sn0R91owpcO8j5RJz40caL30tPKpraFehRKm7YEKj0jQrv7EOns9Ay0kPSEm2Ghh
         tyez6ipF8d99c4bRwToHr1ADAkXrt1ysMTFqFd8D35L4Ba037pGHRFMi4ogrn6E7yL0/
         h363jOifZqJA1mDxSiUvs/3IiBHRbYeB3zVrkD6vNB0ZE6RDOsLbAWtz4vdlCKt4jsRr
         L6oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ypmVCOyIjSLee3qyci0LYfsmjV+ziZpiBA4nNv9bPxI=;
        b=qk1fHNN98hMdKCyxrlGuyyT/GHtAVCrVQWtK6DGJ0yUpePreASAedD37uRAfe1IQEl
         yCHjpYIVRDapQv++bgELxO8OuUT9gvvNrg+HDqHs5WaWJAQgip/c3wgbcosNynxs0E9Y
         btN0ywq+wyGa7N17mmgtHtDJQIMy8FR0CVYztSAqy6B1TgWASKJ2DGCvB33jYslen09O
         GlvKjlIIcLXzUun8qdPzeWe5IFLyerEktRCqjcGa43fk32eWv+xKcHrhQWMBs/oOgmA+
         YWZm7fC3uelYh8QqJeWrnkrCft1ibH2p56vAC7yfj3FpKt1PMYrwPKc94X++CconCKi6
         lP9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ypmVCOyIjSLee3qyci0LYfsmjV+ziZpiBA4nNv9bPxI=;
        b=olhHiXGzjypNhhodfiE6odRuqvZPP7Y7hnibz7GvDrzlS0h1fO/Z9aidz/+vIaY3rq
         9sZ6hcDTzYwvF/9b3zmE30drwd1azvjr6aOLntvUrDiAji2CeJx7joogdlmWTaNXKn7o
         +Vh+GZWlf3n3/oaX9Phk2Wjq5tov4YcMAXpQhBoYvj6alTqr51BspZO5f1aJ/jLPr2yW
         S2e1oeiuCmIT/umArNeyHPcjn+cgXjiWY5jFRlP5cBhR5jNQ2XGo1WYUIbVvjnq7Uaf8
         35OB4MwE/l3noAd3UW98a4h7mkn7GJ2plfAJ8iHztoBaKyh4W/YIvhgYqvQ7nKBNoCJk
         f7KQ==
X-Gm-Message-State: AOAM530vYzTTYVnAGPWgXbEuaMtrMmaDBN5N2NjikP3VVX5AzJtE/h/n
	uvc3bCrjwMZZSAC+l0VT2Oc=
X-Google-Smtp-Source: ABdhPJw5CM3xU556tZy18JyVO5aGIlJn51KhKP8NdZ7PXPBisOhfWsEumRTzb5iPX/1c5TCcPjzakw==
X-Received: by 2002:a17:902:b94c:b0:151:cd93:ec85 with SMTP id h12-20020a170902b94c00b00151cd93ec85mr20390620pls.76.1646789388808;
        Tue, 08 Mar 2022 17:29:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed4d:b0:151:cea9:660a with SMTP id
 y13-20020a170902ed4d00b00151cea9660als397292plb.4.gmail; Tue, 08 Mar 2022
 17:29:48 -0800 (PST)
X-Received: by 2002:a17:90a:d206:b0:1bb:e73f:9592 with SMTP id o6-20020a17090ad20600b001bbe73f9592mr7670107pju.17.1646789388315;
        Tue, 08 Mar 2022 17:29:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646789388; cv=none;
        d=google.com; s=arc-20160816;
        b=o1xaZrjrpYQ1pNqSlljVKwTQdNmXRPMjMZi5qQNIX2q0wRv6PYJbtZau6htYAKQI6M
         iy3qw/P8z6LnBsGP6TZF6JpjxWUmuaJcHA7of+wSJC0eGXgFRTAojZ9TjugMp4rjrdgE
         LxAlwYqiRWFemKxB4r9R1Uz8L0gZrvrUP5ua8+GzeuJsxF+yneTrVFPa6L0u6Q9cy1yz
         A8S15X1Rd3dsg3Zum/DQVQ/QFk8uq4Q/2FmjmbdYCbBEOtPz8zxIJhoDjHNBFmWUZBr6
         u1Z5CEHSKu0W+9QG/TkAuf2omOsvM/I+/6bSZD1W6EOusAblFRQr/gg6USMPxayvh4y/
         phNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=YFaKWon5NB0f7nRiYcpb2uT3VTnpgKbLKW/8TXRcTgY=;
        b=Im9Q+7DtdRKA7eVDpjh7nNLMkclMl28fWUDUDmz+YdLpm9i5uzvcFYEqCOhH4/01gz
         lRWHjpNl1yQSRK/3s0j5G1hFi2qxc9fWLBBj0fzLMdV7sQM5O7zLWJMDpkPUQqUY+pxe
         Lnk/GSznfbDHM0UStxNNlbARn8/vFFfZKzFesBe2xFSI6yCtQx+hS9DSN19c8jtNhIwi
         S2MbOxt9ZF7FENvdqzUb6Ls3NLAcha8/Jnee103WqzDXLWE7L5IupZdFhj1xCy75vPmx
         ddKt4RRH1YC7JuDj4G9AARwBBroyvSPrymg5TRxHxdWqMnlRfuqOWuvctkZeYns7oVNJ
         hGdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id b12-20020a17090a990c00b001bc2f04b85esi208480pjp.1.2022.03.08.17.29.48
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 17:29:48 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100015.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KCvhR3LnKzBrfj;
	Wed,  9 Mar 2022 09:27:51 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100015.china.huawei.com (7.221.188.125) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:46 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:45 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH 1/3] kunit: fix UAF when run kfence test case test_gfpzero
Date: Wed, 9 Mar 2022 01:47:03 +0000
Message-ID: <20220309014705.1265861-2-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220309014705.1265861-1-liupeng256@huawei.com>
References: <20220309014705.1265861-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
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

Kunit will create a new thread to run an actual test case, and the
main process will wait for the completion of the actual test thread
until overtime. The variable "struct kunit test" has local property
in function kunit_try_catch_run, and will be used in the test case
thread. Task kunit_try_catch_run will free "struct kunit test" when
kunit runs overtime, but the actual test case is still run and an
UAF bug will be triggered.

The above problem has been both observed in a physical machine and
qemu platform when running kfence kunit tests. The problem can be
triggered when setting CONFIG_KFENCE_DYNAMIC_OBJECTS = 65535. Under
this setting, the test case test_gfpzero will cost hours and kunit
will run to overtime. The follows show the panic log.

  BUG: unable to handle page fault for address: ffffffff82d882e9

  Call Trace:
   kunit_log_append+0x58/0xd0
   ...
   test_alloc.constprop.0.cold+0x6b/0x8a [kfence_test]
   test_gfpzero.cold+0x61/0x8ab [kfence_test]
   kunit_try_run_case+0x4c/0x70
   kunit_generic_run_threadfn_adapter+0x11/0x20
   kthread+0x166/0x190
   ret_from_fork+0x22/0x30
  Kernel panic - not syncing: Fatal exception
  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
  Ubuntu-1.8.2-1ubuntu1 04/01/2014

To solve this problem, the test case thread should be stopped when
the kunit frame runs overtime. The stop signal will send in function
kunit_try_catch_run, and test_gfpzero will handle it.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 lib/kunit/try-catch.c   | 1 +
 mm/kfence/kfence_test.c | 2 +-
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
index be38a2c5ecc2..6b3d4db94077 100644
--- a/lib/kunit/try-catch.c
+++ b/lib/kunit/try-catch.c
@@ -78,6 +78,7 @@ void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
 	if (time_remaining == 0) {
 		kunit_err(test, "try timed out\n");
 		try_catch->try_result = -ETIMEDOUT;
+		kthread_stop(task_struct);
 	}
 
 	exit_code = try_catch->try_result;
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 50dbb815a2a8..caed6b4eba94 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -623,7 +623,7 @@ static void test_gfpzero(struct kunit *test)
 			break;
 		test_free(buf2);
 
-		if (i == CONFIG_KFENCE_NUM_OBJECTS) {
+		if (kthread_should_stop() || (i == CONFIG_KFENCE_NUM_OBJECTS)) {
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-2-liupeng256%40huawei.com.
