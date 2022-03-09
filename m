Return-Path: <kasan-dev+bncBAABBLMGUCIQMGQE3W7LVMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 593CC4D260E
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 02:30:22 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id kj16-20020a056214529000b00435218e0f0dsf1005936qvb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 17:30:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646789421; cv=pass;
        d=google.com; s=arc-20160816;
        b=I6d5Efsi0VBtWs24IqTB/2igHyhBQlIhqHCtTk3hUUy3XdNzdRI220McGubH7ujoEW
         RJCtrPwlN8qv/4RK7aRzl7YaY4VmvTYVzL1WcuY3uKsro5/OWJExWdjYPRrc7T8w2h1V
         u40RdmOojL2xjM0UDVMC0SKT8F6SY01v9vYU+G1iataSBXgfrqO8IgYTwuGRCbSsuMRA
         S5zPXSpYRMrIDizsRf5CvwsBEasgKL+6TD1c/DNju+T4o/kGbYxSKxS5FUACBfgsxcGm
         fe0nAdeby9gC5VgsoBSrprytYP3J7ByU1UGjYuLl/VptnWjjrkcvQtlCb/qBOwFhhLB+
         eEDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=/xpO6vXtQO6NxSqOsyIJTR6h+4KNLWR87LAPEXMbKQw=;
        b=f47hijm6E0+bsJDSAYCvPWH+YktqHScvlzMBa/V2Sycppi13C5CmljzALuq+4QvJcz
         k4uEfx9BS9ijsxJ1oSrTlbrXSM+cIVqqNSwnZB4WfE7V4/Yv+yBN8lk8MIiR+GYje1Uu
         fjHm8pYFSIUOq5i8nvPhYyeLJG9Fm0J9g76Wp87b6YVKNnseyNaol/YQ05ClIbZTItp7
         UKv/rgttIZW2Y0/ESxA7LdvJSptGR2MpPlRxIpV1EuC96bRLzxNGeLSRqyZtC33to4v9
         5kJ4vkocu0G+EhOb+q3n5xO8gLFuLGUNORFjPySfTddTS2BpE6zRkXihIGwkrtBE/R2S
         9eSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/xpO6vXtQO6NxSqOsyIJTR6h+4KNLWR87LAPEXMbKQw=;
        b=IybiktNO7PM1vSWNn6CH4BUuIJzUjieabELYBFUrexuvDt1rM7+Dc+i9veKXLlgRYL
         5D2n86WAA12v0MZvb47Tiua1g7JTCXO5Ssss5ZMi52vSFyztaBWijpNKfvnR0Dh/3lFM
         cL29pfr70W91PvQrpBY5boj3wxnYc6NT61BjNGIm67+m/txsp5Itm3ToXdPOYt+OdwbE
         QI04MOtRvj430diu5hifq4QjJhkycrtRHs/Nk0Y6s2I67in8PrZ3DcrZISKLO/GqiTej
         RrpRBfpevQQbsZciPUu8bGnZ+n7DIcYLA12i3wxAIajKF7AhIO8H1LCayDcVj9/29Y8C
         OB0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/xpO6vXtQO6NxSqOsyIJTR6h+4KNLWR87LAPEXMbKQw=;
        b=f/b9svIjewTihH6TlmvfLpRzPm/L/p3+SdVY5YzkigvUk5YHR92jSbspC20bwteP0G
         H24GePbTkHhxDvMYd34zgRbqpjZVLIZmbapPOliYdjODhEtAP7G5Uj6C9TTi9bQf3oTd
         HX7CviyYo2/B2LWMwaQP9e3mStPjoSzJ8THcLd/8Ws5jhlYdtjX15uIbDLWbZfCKb8AU
         TMaK5SasLGfYyM5f/WXU695p7qUxizi8559fd99rmZAxoe9Vy2RV8wohFW12OrkdLqxZ
         SLKHbYG46iuGp+r0BkEQ9Cv7EdUXXY0tk8ivcU3CU35FSYr4C1TdFJlsUU3GCwsLobU+
         fSzw==
X-Gm-Message-State: AOAM531FrJs9+jboeo/eojENeMmg2GRy2TBIUBBh27Im03uqutY0M6GH
	14GWZVOFry+C6puBi0MvhTM=
X-Google-Smtp-Source: ABdhPJxDz2YkCOT4fWwEzYbrKCO3OfJX4+A6aspOF1oLJXe5sfWzMxV2IQKO5eomQeYeRVjLKisLpA==
X-Received: by 2002:a05:6214:9c1:b0:42d:b2b8:f760 with SMTP id dp1-20020a05621409c100b0042db2b8f760mr14597607qvb.123.1646789421248;
        Tue, 08 Mar 2022 17:30:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:14c8:b0:2e1:9fcd:b2ae with SMTP id
 u8-20020a05622a14c800b002e19fcdb2aels334464qtx.5.gmail; Tue, 08 Mar 2022
 17:30:20 -0800 (PST)
X-Received: by 2002:ac8:5c87:0:b0:2e0:6d4a:47ef with SMTP id r7-20020ac85c87000000b002e06d4a47efmr7824032qta.57.1646789420801;
        Tue, 08 Mar 2022 17:30:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646789420; cv=none;
        d=google.com; s=arc-20160816;
        b=hwwLPOjujOJc/VVJ8HDTa51BsreEpD+4+HxfDiZLsc5rkaGhe1I8+TzlKVkWeLTbk9
         FKafmMwsMDqnodmOj3M9RvjaeeSKV8TnCiKzCr0SoZnJfuYUWWGylOEc+zi3llPNjJMh
         6+iD+yJcpcKQy0EeUgSv0GGUl09+Nl4SL5af032QykM0d3C3Mm1L670w9nayNMQ+LPIV
         MvIXWLOkK3KcZV0dgaH8e6sJemkmKQnbpzkuwHYDpaIH0bVAPv/lanOJT+adU4xZ6r6x
         7r42dvmCthrXFBYBIb3sgQS2SHW+BTlkN3Hvfk16bVjkYLiAowQ5NV8hO0+VkV714iyB
         NYKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=5EjU4IdtLZJamkjHgcPd0z4Qqec8Idstt5juoxChStQ=;
        b=NnAHtyPjxAfWp4GHM8b80KUAfFn6zEhUdOXKkQ8jVhWqFrEhA1qA+rWH4OvvScjWFY
         NsjFdARN/pl6IZiWr1obqjTRyGZRiTo8jO3K1l77XqxEg+ke/J2wgLHRWYuKhMuRCAgE
         2qGHRY6UrSmHzTPWSpQYYIIJGh1fLgC/O55S6kzaTfLXTzVcJgoSTYWiPnRYA0xdc4IX
         rMWLyfIBUmYZFZsL90svos52r2BlzLDlHUOTeYsMpNarfBaehVcuOVbmzVHOQ9wwmNsd
         J+MVofSUrORVf+IAdczMjlmU4MQ+c2yB+GIKe0g1+CcQr4hXBAtwfnWWdFfuYqxJ7fKr
         dVCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id t7-20020ac87387000000b002e06b63a5dbsi30284qtp.2.2022.03.08.17.30.20
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 17:30:20 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi100011.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4KCvd74zF7zbcCQ;
	Wed,  9 Mar 2022 09:24:59 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100011.china.huawei.com (7.221.188.134) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:48 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:47 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH 3/3] kfence: test: try to avoid test_gfpzero trigger rcu_stall
Date: Wed, 9 Mar 2022 01:47:05 +0000
Message-ID: <20220309014705.1265861-4-liupeng256@huawei.com>
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
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as
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

When CONFIG_KFENCE_DYNAMIC_OBJECTS is set to a big number, kfence
kunit-test-case test_gfpzero will eat up nearly all the CPU's
resources and rcu_stall is reported as the following log which is
cut from a physical server.

  rcu: INFO: rcu_sched self-detected stall on CPU
  rcu: 	68-....: (14422 ticks this GP) idle=6ce/1/0x4000000000000002
  softirq=592/592 fqs=7500 (t=15004 jiffies g=10677 q=20019)
  Task dump for CPU 68:
  task:kunit_try_catch state:R  running task
  stack:    0 pid: 9728 ppid:     2 flags:0x0000020a
  Call trace:
   dump_backtrace+0x0/0x1e4
   show_stack+0x20/0x2c
   sched_show_task+0x148/0x170
   ...
   rcu_sched_clock_irq+0x70/0x180
   update_process_times+0x68/0xb0
   tick_sched_handle+0x38/0x74
   ...
   gic_handle_irq+0x78/0x2c0
   el1_irq+0xb8/0x140
   kfree+0xd8/0x53c
   test_alloc+0x264/0x310 [kfence_test]
   test_gfpzero+0xf4/0x840 [kfence_test]
   kunit_try_run_case+0x48/0x20c
   kunit_generic_run_threadfn_adapter+0x28/0x34
   kthread+0x108/0x13c
   ret_from_fork+0x10/0x18

To avoid rcu_stall and unacceptable latency, a schedule point is
added to test_gfpzero.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 mm/kfence/kfence_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index caed6b4eba94..1b50f70a4c0f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -627,6 +627,7 @@ static void test_gfpzero(struct kunit *test)
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
+		cond_resched();
 	}
 
 	for (i = 0; i < size; i++)
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-4-liupeng256%40huawei.com.
