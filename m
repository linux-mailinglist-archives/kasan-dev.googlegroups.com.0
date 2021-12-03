Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBUYU6GQMGQE44A43HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 348864672EB
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 08:49:28 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id x6-20020a056e021ca600b002a15324045fsf1522879ill.12
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 23:49:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638517767; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqcWEZ1/eSPMOdeNU7yPPvk4AXgrzND+KhklOCKsAZYI3VrA4Qwcv+khAAiHV4ckb4
         DCyFaLmdHIcjwDB4x1DHZ/cRKEnxSAAF+witJqB62IX9Faajl1A6iwp/128ioqgVOYhJ
         AERxO/QC2038SM6dav8iQP1XPfPhdoW6Z1+NrMSM2UHo13XpHv274zNmICxHlvHUO6cH
         m2Q2oWXpGDAqOz0PTkeDY7YKPzVjBSx75veyUvPnTxjwOohFMdD/QDyoGZTNa3Sq9ITM
         lHdgf0gotvTr8BGvDxz+WXLX6O5X2clfAb2NYx+zepzE7NkeODkboxSkOkbb85VcKm/k
         eV1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=FNmteF1IILj+35UjrQ5BnBijfpZjUXgk9elliOJwlWs=;
        b=xcHSmnQPsEZpAr7T/8CssSot+XzppHvFLuuGr7UrnxWvRZScO5WkEAFC9XUZ4xIOBd
         RV2X9CVPmlQf75Zr05fq4tB0MejLgKmz42bmY/d8cknCTGpyZ3Q3QI5tiRdcsWa/P2r2
         KLDUOoj1ZD2vLlxVuajWpUygctg8hUJKyNouUmV8SCvWgE3bAd8N6wlh/HZmcEMgDHCP
         zx8rNGzYdGT9KgEZyjDfOa0Ge7EpiOqK2+0VAz7d7K+wXxM4vqpM+hAdf03vXsYbI5tO
         95n6EP3hW1zfuX+2Ajqv3HR+MWZGBLfNAxGTsVb/jfkyzLFEqVIBHdSBAN6vZfhWLTO7
         2ZbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FNmteF1IILj+35UjrQ5BnBijfpZjUXgk9elliOJwlWs=;
        b=N9mJ1fSS98S48I30uoB1G1SekpfCehJXoUxA4SrC0gWg/bifRpuZHEk8apnU8SU52n
         tnjSxqriB4jr/GB/XvM9cdYK90NtaoxeXiP3ndZB+W4bQZUx1Vqp4YxOCOojR1JbHya4
         m7Ds41Tk4QynNBbqu5jRQGSsceYsLC5MyXWoa64Ux4G409XN3IyHql0kmRs+kcxeYxHF
         bskLLC82st+fD96Su07P8MiTXonQQXfe72TjD1uTIu9OdVQz6AyIIg/7/G8A+wjklHnt
         syrZHqU/FJaLL4p3xJkmBonjTCxLo2D5omnE2fjp6UJteeIGoOqtO/by6hodaxbVSKS8
         Xoxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FNmteF1IILj+35UjrQ5BnBijfpZjUXgk9elliOJwlWs=;
        b=QlOMtdwzPMFAVOvKzbfrmprcRQjypkkQ+pY25WJez9PiyMNg5MR6fF+fkuVErXGvmG
         3/aA9R6dWy90+y/5sIHpAWgd2BcOJC6bFS5/i7OVMHaPqiwcXXBnyaGdFeu2IPMpNHHI
         61SonJhqWFxhXR6x+yP5kp6JwsFBN/rBNrQ7ccYt+BO8k9P7kxC63mOzLlGIT9GnDWkC
         qH6W1C1TXVKngbMEdl9kZF1H0nnoS+sm/eh9MS3k2jATy9DdCbH43UunG+ov12eohhkX
         XsggjGGBZHzCUl0Rtc1s01HhNWtVAByVl+vtXP5jPqtfGzb0Ytd0OJeHvUgWeCy1QKiq
         7h3A==
X-Gm-Message-State: AOAM533Of8831BysDrPhAjFOz9sspNA5x+Jy0MkX37X6gifE7HY20HbR
	kBC7wueANVXuEYxJH0595x0=
X-Google-Smtp-Source: ABdhPJxe+vPAT8wKrT8UU68Lo1Y33LsZV0jRilCRhxrj+1w68q3fu3ioLbC6kWX4eLp5a93DKoPP1g==
X-Received: by 2002:a05:6638:11cb:: with SMTP id g11mr22290550jas.139.1638517767038;
        Thu, 02 Dec 2021 23:49:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d9b:: with SMTP id h27ls1539234ila.5.gmail; Thu,
 02 Dec 2021 23:49:26 -0800 (PST)
X-Received: by 2002:a92:c26c:: with SMTP id h12mr18940859ild.179.1638517766677;
        Thu, 02 Dec 2021 23:49:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638517766; cv=none;
        d=google.com; s=arc-20160816;
        b=wqN/V3hAzd7e+zLBrUjLHnu8BEptb+wdpvKxxR+Cqwe70C2Og3EBnCJ/NT452YQgLN
         Ps53SjbnEtGTbssVO/ZQE3zkRkPoAB7OLzM1gfOfQ5+Iw7xFY2t2v7546UX0nlU+y7H3
         1UIpwvRjhwarA/D40hF4by299C+Ejls9YfapyX2OD6MPCppvTerYih/4NAYR7zRkYIHD
         aGtnGL3LiabFapJ+zxbKzV9B4C2t5u0LHEnMUvlvY67xwF31KUmOXxndXGBAedIC/uW0
         D4o2w/R88kGhkYesoYfXQyWy7gdhpJCVjLa5q6Uy6LgJ48hlJzF73TcRfRGArGgjStU+
         5nzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=p5W0oyygcbwX00urxFHbKcqkTP4ZzLRMtbR9RNVCZu0=;
        b=k/dYY4frGxmIl3E0dT+Ov/nPY24dJOXY1gKTvh5axgR5Gsm06oJGG1uQ9g2XvrcsVZ
         dCZs2cuMcmBkExMnzxl9S69r6xrosWz2DjmfKIzBvwN/tY9rnVcrImQaQDw01Ba0Gdqw
         rS7j3pPySeS9DaSWgEUzaWyNE6Or4AESjyy0+j3yleuml6J5uHal03hMiqrCVBcRdCB0
         W16hYt1HwyolxgxTqocuEDlMGLEdC2F3NJCPv/TXhcN0E4oB00PdjgjYL4wZMoHDHnHb
         5qfcCCoxsvJQvVRPf+XUrmM0XOp/2ViyMt8U8stajTZjueqUya8ys+s54EXArowSEB9i
         3Kwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id g14si414114ilf.1.2021.12.02.23.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Dec 2021 23:49:26 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500020.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4J54hD59c9zbjJb;
	Fri,  3 Dec 2021 15:48:44 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500020.china.huawei.com (7.185.36.49) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:53 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:52 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long
	<longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>, Thomas Gleixner
	<tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney"
	<paulmck@kernel.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH v2 2/2] locking: Mark racy reads of owner->on_cpu
Date: Fri, 3 Dec 2021 15:59:35 +0800
Message-ID: <20211203075935.136808-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
References: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

From: Marco Elver <elver@google.com>

One of the more frequent data races reported by KCSAN is the racy read
in mutex_spin_on_owner(), which is usually reported as "race of unknown
origin" without showing the writer. This is due to the racing write
occurring in kernel/sched. Locally enabling KCSAN in kernel/sched shows:

 | write (marked) to 0xffff97f205079934 of 4 bytes by task 316 on cpu 6:
 |  finish_task                kernel/sched/core.c:4632 [inline]
 |  finish_task_switch         kernel/sched/core.c:4848
 |  context_switch             kernel/sched/core.c:4975 [inline]
 |  __schedule                 kernel/sched/core.c:6253
 |  schedule                   kernel/sched/core.c:6326
 |  schedule_preempt_disabled  kernel/sched/core.c:6385
 |  __mutex_lock_common        kernel/locking/mutex.c:680
 |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
 |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
 |  mutex_lock                 kernel/locking/mutex.c:283
 |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
 |  ...
 |
 | read to 0xffff97f205079934 of 4 bytes by task 322 on cpu 3:
 |  mutex_spin_on_owner        kernel/locking/mutex.c:370
 |  mutex_optimistic_spin      kernel/locking/mutex.c:480
 |  __mutex_lock_common        kernel/locking/mutex.c:610
 |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
 |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
 |  mutex_lock                 kernel/locking/mutex.c:283
 |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
 |  ...
 |
 | value changed: 0x00000001 -> 0x00000000

This race is clearly intentional, and the potential for miscompilation
is slim due to surrounding barrier() and cpu_relax(), and the value
being used as a boolean.

Nevertheless, marking this reader would more clearly denote intent and
make it obvious that concurrency is expected. Use READ_ONCE() to avoid
having to reason about compiler optimizations now and in future.

With previous refactor, mark the read to owner->on_cpu in owner_on_cpu(),
which immediately precedes the loop executing mutex_spin_on_owner().

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 include/linux/sched.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index ff609d9c2f21..0b9b0e3f4791 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2177,7 +2177,7 @@ static inline bool owner_on_cpu(struct task_struct *owner)
 	 * As lock holder preemption issue, we both skip spinning if
 	 * task is not on cpu or its cpu is preempted
 	 */
-	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
+	return READ_ONCE(owner->on_cpu) && !vcpu_is_preempted(task_cpu(owner));
 }
 
 /* Returns effective CPU energy utilization, as seen by the scheduler */
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203075935.136808-3-wangkefeng.wang%40huawei.com.
