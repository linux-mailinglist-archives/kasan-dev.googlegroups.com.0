Return-Path: <kasan-dev+bncBC5JXFXXVEGRBXXXQWAQMGQEQYG7LRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3227F313BD8
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 18:58:55 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id p15sf8762592oth.20
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 09:58:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612807134; cv=pass;
        d=google.com; s=arc-20160816;
        b=wMhGkyW9nw75+3N0SC12O+N0qhSKhYhRr8f2/sxMS4KW+IUDqwsNEfB1WkpM+9pVWe
         +xX6Hopei9oO+blmUanFh6nj341ZWcgxHMXHpGumPFzhC+eQjWE/4y4lmCx+mWpbUf7b
         pl6gYW+4Jqm/Bo/2J0LKRKq89j995mC7kBgR7OM9Ot8xT9vABjKXLjbERhsOAtAW/jfG
         OV0AUMiHLTkO5iXTmf1Ops1WfhYxPJpUQIPwqf6sWxRfkyxZo0ZCnX8DyAZaLoaSfTQM
         2SRVooIg6Mg/kc0SipM3eB9IqQ0pZXJveJwZ8peK9CtmviYpfFfK4qqhmJMJ5wQnhyBy
         HxMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bkCaWB42dYQRIli0srxSTvFl17rYTa30wo3dgL4iu3c=;
        b=DxIfppUcW4LTzb3oKMIzq1ZNb2A7i+zXFjewWHbUzZFcJJUPzsBKv5qx65PbszmnV8
         kiFYkxz4NcXejtmVGch7hm5rQfosIjXa7CPu7HNX66YdSoA8Mc1p53LiT5Fx5CCxblnV
         B+0kMmAr7zmJiyaCiZIVQKFslsymVHERPo9LnUE7P1j9ePzUz2AlSBj9EbF/xVWBg5Xu
         gx8VtSh7nyOiD32HqLk8agjA4XIxhzHnnMW9Yt8cwtlEwnihQiVN/EEbYefeVbvbOp83
         jaGfQmiZpR4CGmMfJ3LGsEYDVWZwYtt/qvJDkYPRkGJFdJiu9wUnppGS3HnhsKcpoSxI
         SQ9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BK8mZc5u;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bkCaWB42dYQRIli0srxSTvFl17rYTa30wo3dgL4iu3c=;
        b=KTGx6HPDTaT1+nQP95ROXU2NK+cEMIi75MQQ1emP3fHVX1Fy63DKb/O5J8zO8WTJBE
         lfRZmIyXWi72fQ/Js/iy2nMM04UOwjIFwqVgw0iLRVMa+EySibS0LXQ5ofXnG5ARVDfM
         Eje9BS7wja/uWiqc2cugkuV5vO9N0PIwNjbrht404ccBCBiASnM7u+xDkCYXPxVPG+db
         CYxi9L5I2InVDJ4cbNuHwDSso1j55KHy7vJO2xKjBS0huzblD1EMEgQLbsrLYeHWhc67
         K1nrsQ4OE6xFUrRXal0HWocqmj2gl908XRZ6DLIP/lmsd+f1i0GianZbS8U+a/77ifWW
         50QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bkCaWB42dYQRIli0srxSTvFl17rYTa30wo3dgL4iu3c=;
        b=fJTzvVCmuS2amCWdqk41We3Wql7n1xqr+EnouaaGF+2Xg+urbO/Us+qy+bXRnjZbKN
         FLu0ETWl7onQCqk9EBu38dyNUfSd/XUyme2Mf94ZMc7Z632a/w6lqQoXD/GXQa3jhJhY
         ZT/2cJX/XriziJmoWKqR3cF5jl1CiUnf4KmLhOGE5dkoTi7Wqfcb1+nU50+h9zPRoX1F
         /aAUtw5im25wLLAfYjvF5vgs20+aixNhRlRF6venYQVCpQAFfwm84KbgRzGtU7jp26Pg
         tqd1Ow5Vl8oWUyjkAeXRnx8Rqq0B4qr7ftyj3n7qMcHBRgAqVSFllFh9CHmOjtlJJGvl
         Ca7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iwVZFr2rPjLuYEPZYhw1phq0CLbLD7o9q0EJiaD3nV/zFsDxG
	p3xbDDgN4N0LmDmsUIEBrOI=
X-Google-Smtp-Source: ABdhPJwskC8pVUFaKICPqAXi7qPZCUIeDdeI97T3A+Un3kp6v9WHlRATYzV8GZJHb4OcCpz43j257A==
X-Received: by 2002:aca:d14:: with SMTP id 20mr12490631oin.157.1612807134197;
        Mon, 08 Feb 2021 09:58:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls4351031ott.0.gmail; Mon, 08
 Feb 2021 09:58:53 -0800 (PST)
X-Received: by 2002:a9d:53c5:: with SMTP id i5mr13080185oth.159.1612807133751;
        Mon, 08 Feb 2021 09:58:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612807133; cv=none;
        d=google.com; s=arc-20160816;
        b=xELNeP+57UoRXF/r03wLkwFYF1xEetTKWFN6zDzfvhmTKmaD4RkyRLTcxMfDfOmipN
         4J1Vwo8yURCa1Tkw6ZxJsaSUaufIdooorSSwq2jIFfw27n7af5bA8KDpA+8l6ks9OZso
         oF79P7qhkY6W5MLkfydriutxHpTO5kz+jj6VzHreIvMRnss3qq+yce0WQ9fMLLeDNbtT
         Ipzx4JhLWFoAHdHIZkVgyd/TqSQwfZWZkpKRIThD0pFVmIzATMabWwxXuPknY3J4B/Ud
         4Dp/cy49Kl3B3PuLcs8iQ41dI0AKnnQwqc4hnSa6ER1zQf/T3t/8Gri2R1Ru93zGzGRt
         kfbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BUjmzl3tKHafuLwtfUcF/Doj6jtotBcHl98hu/AYado=;
        b=p3cG5mPwO2L7aj2pkMtErb3kvj7Vgdjwu+RPIeREEcy12U+QH0KuQV55Qqs6NMpR6C
         bHJLQBWYyeIv6sxafuhho0st3Qv8fJ7mvz6yIqkHwEMnkVRP75DrVT9IFoIano6y5xJp
         Lsi8f/XoMoEMf/mkt9DMoy2/MY7LMKnV1yoMrN7shfuDKlzZq8J1zJ/ZueWQjhumMOoQ
         FrQgpGEYTUkEaExIgyNjpHm79aQX/0gLZqe97Qpu3qy6G8rc4S4mAe0p6R+kqrNRopzO
         EqiMhlQZI5yz2YC18lmJZwH16UFGZ9C8ZbVOnKcfCRvZZis6kzaVeGBCZ1OySI3taRoy
         39Ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BK8mZc5u;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g62si967249oif.2.2021.02.08.09.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Feb 2021 09:58:53 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 27D6464ECE;
	Mon,  8 Feb 2021 17:58:51 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.10 33/36] kasan: add explicit preconditions to kasan_report()
Date: Mon,  8 Feb 2021 12:58:03 -0500
Message-Id: <20210208175806.2091668-33-sashal@kernel.org>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210208175806.2091668-1-sashal@kernel.org>
References: <20210208175806.2091668-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BK8mZc5u;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

[ Upstream commit 49c6631d3b4f61a7b5bb0453a885a12bfa06ffd8 ]

Patch series "kasan: Fix metadata detection for KASAN_HW_TAGS", v5.

With the introduction of KASAN_HW_TAGS, kasan_report() currently assumes
that every location in memory has valid metadata associated.  This is
due to the fact that addr_has_metadata() returns always true.

As a consequence of this, an invalid address (e.g.  NULL pointer
address) passed to kasan_report() when KASAN_HW_TAGS is enabled, leads
to a kernel panic.

Example below, based on arm64:

   BUG: KASAN: invalid-access in 0x0
   Read at addr 0000000000000000 by task swapper/0/1
   Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
   Mem abort info:
     ESR = 0x96000004
     EC = 0x25: DABT (current EL), IL = 32 bits
     SET = 0, FnV = 0
     EA = 0, S1PTW = 0
   Data abort info:
     ISV = 0, ISS = 0x00000004
     CM = 0, WnR = 0

  ...

   Call trace:
    mte_get_mem_tag+0x24/0x40
    kasan_report+0x1a4/0x410
    alsa_sound_last_init+0x8c/0xa4
    do_one_initcall+0x50/0x1b0
    kernel_init_freeable+0x1d4/0x23c
    kernel_init+0x14/0x118
    ret_from_fork+0x10/0x34
   Code: d65f03c0 9000f021 f9428021 b6cfff61 (d9600000)
   ---[ end trace 377c8bb45bdd3a1a ]---
   hrtimer: interrupt took 48694256 ns
   note: swapper/0[1] exited with preempt_count 1
   Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
   SMP: stopping secondary CPUs
   Kernel Offset: 0x35abaf140000 from 0xffff800010000000
   PHYS_OFFSET: 0x40000000
   CPU features: 0x0a7e0152,61c0a030
   Memory Limit: none
   ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---

This series fixes the behavior of addr_has_metadata() that now returns
true only when the address is valid.

This patch (of 2):

With the introduction of KASAN_HW_TAGS, kasan_report() accesses the
metadata only when addr_has_metadata() succeeds.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Link: https://lkml.kernel.org/r/20210126134409.47894-1-vincenzo.frascino@arm.com
Link: https://lkml.kernel.org/r/20210126134409.47894-2-vincenzo.frascino@arm.com
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 include/linux/kasan.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 30d343b4a40a5..646fa165d2cce 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -196,6 +196,13 @@ void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
+/**
+ * kasan_report - print a report about a bad memory access detected by KASAN
+ * @addr: address of the bad access
+ * @size: size of the bad access
+ * @is_write: whether the bad access is a write or a read
+ * @ip: instruction pointer for the accessibility check or the bad access itself
+ */
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208175806.2091668-33-sashal%40kernel.org.
