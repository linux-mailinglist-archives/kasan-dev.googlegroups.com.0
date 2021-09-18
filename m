Return-Path: <kasan-dev+bncBAABBRF4S2FAMGQECZRF55Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 319F74104F8
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 10:07:34 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id b25-20020a9d60d9000000b00519be3bdc04sf40407482otk.7
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 01:07:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631952453; cv=pass;
        d=google.com; s=arc-20160816;
        b=SuKIeaVaI8WuMDTQCETHrWOC9SNoT/4COlM0sP8r+AaEIBs8w2gQesryEwHJ5uct+8
         ZzcFtbINCBdN6L+ET3SXAWYD0O4lDi+d3nfD8jKfs9+1c9r423EXOjhW0d9fUNLehbYl
         9F1lwZcs6K5widfsBBhhNVg22HTqk0qHai1gg2c6+bSrpsFijWSrIefv/18zp+wX0zWX
         aKAA0Qn6z9VfGJmVZNc1MSmoOJJeNeNXLPNFJyOeFUnMbhF4VgCZg4ftvw+nAQ16oeP6
         S7/Phnh619pv7yjWQUsBtynBJXuV8CkYyi5I3dNCwh0BWxzOmLGk+dsgTXg1HYMgez1u
         XDww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=TlA/XjsZLioCVib3TdtNNsxnEfMGU3ZXdIIPw+RJ7RY=;
        b=QfxoP3rsIJuBvzE31TYJF2vQyPaepL+e8WuhyXs5lSF1TifW6ueNetm+40eDekr1Ja
         CykdHG3m30nE2BL2Z7Az/SW4nV/KCgC57d6yuJZtxUoGsJfBD6O1HBCwvMVA9BW5XPF/
         Iqg8cz5BDyVRrVaY0RkFaRlUVYnYQ/8v5OBTw1oSPgl04z346G/iG5QkVtZ/X9yRup8H
         rbwaOkqAutncqJyXdjX4K5QJUn45TUH9BBwkbcjYXHEvWpcv4GMjjJbC73J1cww5OtMc
         u0cMTKANDg93jHEZ1LRbtmzv5fFfGpZr3GSZuAdtsn7n/OwIcrad66W+QR5WsjmVyCZa
         1YHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TlA/XjsZLioCVib3TdtNNsxnEfMGU3ZXdIIPw+RJ7RY=;
        b=dsrYxMqxttg6ehn5aZwQWgwhlap9Gy7m8zZ1gWYYXcI2tD0vPdeHn/tErgOT7hwW/a
         rIFWU6NJVlB3mrB6BEsh4IUNHGyaezgLJn/QxQIDlK0TtwJYJoaPRN3MGTQsUpkHP9c4
         kEk5TvlgnKndLhBMv9EBIdGwtx4sUXahj0OoRjJNZr1cJ4ZiqmPXFCcnZyRgza6J8H90
         Vo+/nSF8fjd52Ki69pL8xQisHPt1emtxWUSasxXBvLbiBeL0VI6WegHt5pFq5WZdm/n/
         AYyTmwVvC2DaI3HG3bbh8Orr5We7s5/ExD11B5bh1CE9XH2a9jxKrSnRfigi67TsgRap
         b+vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TlA/XjsZLioCVib3TdtNNsxnEfMGU3ZXdIIPw+RJ7RY=;
        b=A6ppfxSACDMF985DTmFmYY9flE3A4A+wUXFQxMvmm6q1MwzDyt1zuteT7I+ob+7HK6
         UWgISbxKrp/IiliF51xO4riXdoAUKL+pBzeF6KGi0wT/gP3+SwG94NcNWEQeuCbr/6jb
         DujAXeGiDrfqS+KiAf1+onbizv5EPSyAAK6K/iB11J2g7dMRgCriuFMKKjFwbZQzzxxB
         Ou4ZVb7VKOKhX5bq862eTaNuiu3SkXxB2bO2wXnq67UZJd3ao4ddnNi1AU7f3iLBniUP
         C6j57faGgordjgvAGmvvX01bD7J504XC0jp5k//ydXU5oKcdTXDVu2AwIjxTO99WxG1b
         9p+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pHRzqvc9bIjA81VKmHBPa4DCwKtoDop/BpRTIqv/ygUw8nNE8
	0A+A6VFVZREGwDFF0zd+zR0=
X-Google-Smtp-Source: ABdhPJxY3CtSI4yMVhNB+fQaCqNa6LxOxXIbEc6mqwZ8IrBT86m1C4brPsWAJKqmZntUEW+cFE89ZQ==
X-Received: by 2002:a9d:71c6:: with SMTP id z6mr12920939otj.382.1631952452941;
        Sat, 18 Sep 2021 01:07:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:6155:: with SMTP id u21ls915829ooe.10.gmail; Sat, 18 Sep
 2021 01:07:32 -0700 (PDT)
X-Received: by 2002:a4a:e9b5:: with SMTP id t21mr3904566ood.3.1631952452619;
        Sat, 18 Sep 2021 01:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631952452; cv=none;
        d=google.com; s=arc-20160816;
        b=C65XzMMOmyz0xlkEfV+NdxjYmEbgtbqyXykbAM3icDUjIOvhU/hKfe0tSatG/pxmeW
         pqSpX81oMtZrNh1M0xyFvVRb0jis24mqIBVq0MzAVZNqVa44VrMn1zJv1rBidFyNdMb4
         2erIDwde1xW7uqInPaSlJlRYZMxS7DE874GlM0gmlI1S++MGWqxMphb3TFdnDQ3vQkye
         teeXgyh5IE5Cyneh2PuVdnQQKy6oAULNSAfnvG6Xa6DCL/MEur1DNkX+OP9psaGbGKNy
         FB87vL7dqb8hb7nGTnsRGhDJsUHZU2+ecrmxKL3dcvyfxlzk+VICkQ9T4aZXrCdp+52z
         vdZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=MI6eQ2eFs8rCLegl7gksQc14lOufDHNodUbKk2Qg4zY=;
        b=PHLlGtcqDoTtfe/bZr7u8G0ECVqmqevhGNLXaguSQW6NwoIySAc38r1gnHotebxKfF
         X5deec7Qe4SCaxygOFEfOC/aZ3KFeky5/xtBxOcS0y5ylFKsGaqRagShsraKyJhTU+xF
         obJL4Xpbz6eSUM7Ky8rXurFXIzWTyQGeiNHEEWXFQcXbdM5RM0Q1zlCzLpZTGs52Srx/
         wOKK3vpY7NMiUN7rufL3pYCBJOMS6DAof+KktfMcLwtqUQ1hnYiUk9hA5dz51fqxmbRM
         U5MYZLrFRaYTl0vf9n2kp3bjbf+Ue/LzNNiDc3c206yQ5lMMyUF594pJoREkXVZXKEl/
         mh+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id v21si881429oto.0.2021.09.18.01.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 18 Sep 2021 01:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4HBNh96Zq8z57Cl;
	Sat, 18 Sep 2021 16:06:49 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Sat, 18 Sep 2021 16:07:30 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Sat, 18 Sep 2021 16:07:29 +0800
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: Marco Elver <elver@google.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
References: <20210421105132.3965998-1-elver@google.com>
 <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com>
 <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
 <CANpmjNNXiuQbjMBP=5+uZRNAiduV7v067pPmAgsYzSPpR8Y2yg@mail.gmail.com>
CC: <akpm@linux-foundation.org>, <glider@google.com>, <dvyukov@google.com>,
	<jannh@google.com>, <mark.rutland@arm.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <kasan-dev@googlegroups.com>, <hdanton@sina.com>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <da6629d3-2530-46b0-651b-904159a7a189@huawei.com>
Date: Sat, 18 Sep 2021 16:07:29 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNNXiuQbjMBP=5+uZRNAiduV7v067pPmAgsYzSPpR8Y2yg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/9/16 16:49, Marco Elver wrote:
> On Thu, 16 Sept 2021 at 03:20, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>> Hi Marco,
>>
>> We found kfence_test will fails  on ARM64 with this patch with/without
>> CONFIG_DETECT_HUNG_TASK,
>>
>> Any thought ?
> Please share log and instructions to reproduce if possible. Also, if
> possible, please share bisection log that led you to this patch.
>
> I currently do not see how this patch would cause that, it only
> increases the timeout duration.
>
> I know that under QEMU TCG mode, there are occasionally timeouts in
> the test simply due to QEMU being extremely slow or other weirdness.
>
> .
>
Hi Marco,

There are some of the results of the current test:
1. Using qemu-kvm on arm64 machine, all testcase can pass.
2. Using qemu-system-aarch64 on x86_64 machine, randomly some testcases fail.
3. Using qemu-system-aarch64 on x86_64, but removing the judgment of kfence_allocation_key in kfence_alloc(), all testcase can pass.

I add some printing to the kernel and get very strange results.
I add a new variable kfence_allocation_key_gate to track the
state of kfence_allocation_key. As shown in the following code, theoretically,
if kfence_allocation_key_gate is zero, then kfence_allocation_key must be
enabled, so the value of variable error in kfence_alloc() should always be
zero. In fact, all the passed testcases fit this point. But as shown in the
following failed log, although kfence_allocation_key has been enabled, it's
still check failed here.

So I think static_key might be problematic in my qemu environment.
The change of timeout is not a problem but caused us to observe this problem.
I tried changing the wait_event to a loop. I set timeout to HZ and re-enable/disabled
in each loop, then the failed testcase disappears.

[    3.463519]     # Subtest: kfence
[    3.463629]     1..25
[    3.465548]     # test_out_of_bounds_read: test_alloc: size=128, gfp=cc0, policy=left, cache=0
[    3.561001] kfence: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~enabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[    3.561934] kfence: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~disabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[    3.665449] kfence: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~enabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[   13.464796] --------------kfence_allocation_key check failed 13839286 times----------------
[   13.467482] kfence: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~disabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[   13.469166]     # test_out_of_bounds_read: ASSERTION FAILED at mm/kfence/kfence_test.c:308
[   13.469166]     Expected false to be true, but is false
[   13.469166]
[   13.469166] failed to allocate from KFENCE
[   13.473592]     not ok 1 - test_out_of_bounds_read


diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 3fe6dd8a18c1..e72889606e82 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -25,6 +25,7 @@ extern char *__kfence_pool;
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 #include <linux/static_key.h>
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
+extern atomic_t kfence_allocation_key_gate;
 #else
 #include <linux/atomic.h>
 extern atomic_t kfence_allocation_gate;
@@ -116,12 +117,20 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
+       static int error;
 #ifdef CONFIG_KFENCE_STATIC_KEYS
-       if (static_branch_unlikely(&kfence_allocation_key))
+       if (static_branch_unlikely(&kfence_allocation_key)) {
 #else
-       if (unlikely(!atomic_read(&kfence_allocation_gate)))
+       if (unlikely(!atomic_read(&kfence_allocation_gate))) {
 #endif
+               if (error) {
+                       pr_info("--------------kfence_allocation_key check failed %d times----------------\n", error);
+                       error = 0;
+               }
                return __kfence_alloc(s, size, flags);
+       }
+       if (!atomic_read(&kfence_allocation_key_gate))
+               error++;
        return NULL;
 }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7a97db8bc8e7..637c2efa6133 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -100,6 +100,7 @@ static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. *
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 /* The static key to set up a KFENCE allocation. */
 DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
+atomic_t kfence_allocation_key_gate = ATOMIC_INIT(1);
 #endif
 
 /* Gates the allocation, ensuring only one succeeds in a given period. */
@@ -624,7 +625,9 @@ static void toggle_allocation_gate(struct work_struct *work)
 #ifdef CONFIG_KFENCE_STATIC_KEYS
        /* Enable static key, and await allocation to happen. */
        static_branch_enable(&kfence_allocation_key);
-
+       if (static_branch_unlikely(&kfence_allocation_key))
+               pr_info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~enabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
+       atomic_set(&kfence_allocation_key_gate, 0);
        if (sysctl_hung_task_timeout_secs) {
                /*
                 * During low activity with no allocations we might wait a
@@ -637,7 +640,10 @@ static void toggle_allocation_gate(struct work_struct *work)
        }
 
        /* Disable static key and reset timer. */
+       atomic_set(&kfence_allocation_key_gate, 1);
        static_branch_disable(&kfence_allocation_key);
+       if (!static_branch_unlikely(&kfence_allocation_key))
+                       pr_info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~disabled~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
 #endif
        queue_delayed_work(system_unbound_wq, &kfence_timer,
                           msecs_to_jiffies(kfence_sample_interval));

thanks,
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da6629d3-2530-46b0-651b-904159a7a189%40huawei.com.
