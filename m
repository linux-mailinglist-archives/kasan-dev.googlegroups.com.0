Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCXR3D5AKGQED3OKVJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE2EA25FB93
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:30 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id l15sf5717244wro.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486090; cv=pass;
        d=google.com; s=arc-20160816;
        b=w3o530smg5UyNaDGU8VaPROJPD3IMeLI7MVIwQfPwiEeDURKC1MgNCnB24PqDWSP+X
         uhnAy19wHcu0CGbRSonJ880D6LVntzQ4Svpb3X+FRz3AhkdvS41HKDKz95VteBzqNSQI
         eBTOSi9eVnC8sb8tpUHaDOx3qod8t62A4MUo+GKJ31u8T/vKU+FBdJW87hzl+AnTwYw2
         AdxcDdJU2+Ha39av0bYaOIYrRQJPXb8JRMZ95tSPSOsmeJ6Pl02xbjqZlxlpy5kbp50+
         RDjmZiWBRkgu2doT+skwJpZMjoTgc3XLaixXECPanx2mZ/4EgYZhieUhLYIaZXn78DW7
         E8og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d7E9fcln9b5j5mavE3Sw4AYZniC4VEVRztIvp5b0xFQ=;
        b=DR6RGEGZvW3YzbUbzznOMZ4HR2M6j+9SosEHSidW8KZAH8WU1lvvNd1MiC9GYSPfXV
         rBCp/slkoZcUEGM2iki+IBsyOFpO22jOvRpL647scT1NdQ+PWVXoE2GUya120dFalRQa
         uZehxJFOHanJlw7nNsj7gAw7BghZms0AwGhpTEn/LKEhNpnTo6vM09gleWh0snH/rXfQ
         dHYOuEe7I1MwSyU28wwis+/Kd5MQiUifgk6p4ssDw0Ca3fCXJLREZ4gT+y2rjfiEdHZj
         ZvqHq0tAbd9zHjBfhG7XekYGD7zqWEef1B3eKmKNdab/N0eCZ7GUh9IAbOQEbOFbhP56
         CdjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s4MbRGJa;
       spf=pass (google.com: domain of 3ithwxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3iThWXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d7E9fcln9b5j5mavE3Sw4AYZniC4VEVRztIvp5b0xFQ=;
        b=VNdjDwrqDtGSvcDYgZL+AiCy/QwaC+SFVh0K69xa7+WT2W2u2bM0+Du23VJrmKxuNQ
         nGRNzNmZCTZT6YVfsebcfQNZqr+wPeP4iU/xraEVn6MaAXWPyEIaSZakYKiiItHU9soJ
         d+dM5trg9m5zkaVXZ4hAlXDY+j4DIdsOchGBIJbadj+LlTHesexR7z6T1Q9DWDe1vPAi
         jJsbu6r3OSl7x3Kly/Lxsc+GSw1MvTV8Rnv0zxVV2xUR3Cs4ZK5aoe2ChkeLgwMgsFY2
         ZTqX2CFen3B2NbQMLlcnzDF7MvHAj0PDTQoJYZdI1zYFnU1PlOPEHo9YuFDhGX58Gskj
         sjMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d7E9fcln9b5j5mavE3Sw4AYZniC4VEVRztIvp5b0xFQ=;
        b=MIWRAfw75SXnbEKRabdDY7kGrSmsVwUr2SbpNNrg6o3gwrUc/9r/irXSgLy+CUs8Sp
         oE5Tw5di8a2sSXypUB5SOPB3s55KdHVhatRI+p0cbPBn1ozMC+S6mgpmu8+paqD9waor
         HsbkRYYEesMyLI/nROPxb2Tt159LspWNUvk42zoE229tkK6+2TesXqcEW3gxq1N2Xnni
         5wQmw2ySkbUlT/pqDlz3fdWXA8CTTEd0N+7jnRRqugmYQ5a+j4Bvh/etNgh6MyzCT8v7
         A4Umldahgdb9stl4/MIlOzPJK0+bmvCNZXFZlwY3JHe/2muWajY/ygh6x6NDJxJjK/hS
         OKcw==
X-Gm-Message-State: AOAM533n29N4sxb9raJkw21FeT4oadBWyFYAYeD0iKMHtLoXcJq41W9d
	ECi19NRYbw4Ehtd4agjbpcU=
X-Google-Smtp-Source: ABdhPJzTQVCxs2OIiEYGR2USLkAeG4am1///iZliVsYlKFW2MgPbLl0ZF5sUls7YcMHmewl5tK0kGw==
X-Received: by 2002:a05:600c:228e:: with SMTP id 14mr21885491wmf.17.1599486090684;
        Mon, 07 Sep 2020 06:41:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b86:: with SMTP id b128ls8182559wmb.3.canary-gmail;
 Mon, 07 Sep 2020 06:41:30 -0700 (PDT)
X-Received: by 2002:a7b:cf36:: with SMTP id m22mr21907057wmg.51.1599486089955;
        Mon, 07 Sep 2020 06:41:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486089; cv=none;
        d=google.com; s=arc-20160816;
        b=pEjzUgC2JhhghSF+teqxwf8bxnMTvWMU2WMLYUh6TSb0dLUWVuFFv0KAncrK6/feen
         KKQZ4y8fNNMqRGYfVA7YbtfgBT9vSMWJ+GUq8S8JnWLYfAlXnQ5aAUpK58U8txSMbL1n
         F8oa3HCqLi0SSHtTUuYD7QwRp6iKYQ6T7smJ65V4Bh8bHtAdJSIBYAxBE4VPkYL58RmE
         XPNvv6KVhJ/EYRMTD9jKGu7zQ2rExMGWRoQwwYYl38Sp6uywGtceOQKhS35DiaaGKQfg
         k1KC/dZNy/L6OGwkoUF+VmkE3UPvPpGEzBSb+j6XOiXvzCEfFxCywdJ7bzhBjhIIeNZk
         EF+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=QC9NTo7nxtZYJpQO/i/DXWRBIzGZiJeRrgmmIrmcLsY=;
        b=PAzLdgIEqEALC/7j9J0oWWdlQzaKvgKi2afBYmp2D0RjF3zno7HUcyIx3muj6jZGKE
         LnOfot/Gz0jppyG6cGeYoWj1/Z/39WR58f2Oc41JMPD9cObRZ6n66BXHMB/e+fEBX0cU
         YIFFwXNlBV+aa5UylbyulQ6VUSG900+os52uQgPRdyEkzXs8A7F5gtnbvhHxxlfVsA6z
         jfjQGF5Nspz49X8wpcgVVIMi6/Qo+Sjj6shr82M98s2HmG/Ex2idItAlHQ8nNDUFBoGT
         PYzpzcJr9ZAznV55KGtGqKu/98yHntAkMaqQA0FoLXvwLw94j1z9CMzKs2oJ/620ZjS6
         86jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s4MbRGJa;
       spf=pass (google.com: domain of 3ithwxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3iThWXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id g5si955800wmi.3.2020.09.07.06.41.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ithwxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l17so5672574wrw.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:29 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:6551:: with SMTP id z17mr20816665wrv.200.1599486089420;
 Mon, 07 Sep 2020 06:41:29 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:53 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-9-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 08/10] kfence, lockdep: make KFENCE compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s4MbRGJa;       spf=pass
 (google.com: domain of 3ithwxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3iThWXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Lockdep checks that dynamic key registration is only performed on keys
that are not static objects. With KFENCE, it is possible that such a
dynamically allocated key is a KFENCE object which may, however, be
allocated from a static memory pool (if HAVE_ARCH_KFENCE_STATIC_POOL).

Therefore, ignore KFENCE-allocated objects in static_obj().

Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/locking/lockdep.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 54b74fabf40c..0cf5d5ecbd31 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -38,6 +38,7 @@
 #include <linux/seq_file.h>
 #include <linux/spinlock.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/interrupt.h>
 #include <linux/stacktrace.h>
 #include <linux/debug_locks.h>
@@ -755,6 +756,13 @@ static int static_obj(const void *obj)
 	if (arch_is_kernel_initmem_freed(addr))
 		return 0;
 
+	/*
+	 * KFENCE objects may be allocated from a static memory pool, but are
+	 * not actually static objects.
+	 */
+	if (is_kfence_address(obj))
+		return 0;
+
 	/*
 	 * static variable?
 	 */
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-9-elver%40google.com.
