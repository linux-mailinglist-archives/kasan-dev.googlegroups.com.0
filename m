Return-Path: <kasan-dev+bncBCS4VDMYRUNBBMHX7WZAMGQEHGHIZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7A48FBD73
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jun 2024 22:40:17 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6b0025a123bsf6509846d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2024 13:40:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717533616; cv=pass;
        d=google.com; s=arc-20160816;
        b=zRn5wQA0RI7XXue26XM7ukbiHLiT6+FRKA1M+8/uYUIzszqrAgkkyVBKj4GM3N2fyM
         JaCDh+v4PQXglf1lKppN1S4oCpgf6b9wefm7kd93Q7eS0sfDl4VT24C7lZlp/DniAON/
         4ewZoWlXKrIFZdz4s5LV6oTjlBdLvCxv1Q8nP4iFtbicUc115yOsQpy8dCwGQcUNeS1C
         qH8fLRYW9xAowoxYm9aEkyCXtbASN8l5viVT8MevzoBEdqrInI3HIFFsWQ/OupDrzyQR
         y2U8o9Xk5qYrcp6s1lWYbzIaVl9CjVKX7j1ZOvWup7a+6NWoH6S+EWsVMXJvuPm6UOBW
         dPkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NXZnOM1Fz78NTOmNYaCfF7VOyDVk71OzL28nHTNxP5k=;
        fh=4GLA98IC4dSqDmMxYlHPTti0I+I6+Nm5Q6kyCwTOYDY=;
        b=aX/iBptfqtG2rbvhc71Fq3OysIFNxPCehS7HTGXneE6sXmfqaAT66lAnN9BjxRfNYd
         Tx85huSi5QI5ZcHMNTbebJ//cCXKbfEY2AKtJbv1Vmchc9aqcHulfl6YyAZ3l2g6kao+
         YLEnFQbW+46jT+Vm0CSMXIZI9CpCmKvBJAAG3Au+qKU4aqReDcC62I9wOUlUgf/e3KI6
         dtyBDCSDQg6X8JaLU3X2G4/Be3Ddqij3+XqRmsXMwBMQZKVhjyJc98tUfnwxgwaJKJeB
         ayQX4LgmaNyxQFknQFkIPJ/wJOqL6UU6CAMVjws+/wSKloW+McwH6wuQy/cHviUQVrjw
         nyCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iQuK7mO8;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717533616; x=1718138416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NXZnOM1Fz78NTOmNYaCfF7VOyDVk71OzL28nHTNxP5k=;
        b=qmMbIgOYkDZqUUWWVQ4DaKLaUpD+Px00/W0dFv5gohna/XmiAudn7mr0LY2BoqKTsP
         UfRquKhhVZWrWtbVv9cvBjmKfXNZxPTDtRGqu2UodGEYOtaFWwvgHCnq/lmW/DIvLFcb
         n+Br/oqS1cjD8yKfCW2BeFVklEmgBCR28R6QXcoCioQHXqM+nzwXf3GSZOZzFsLo7Vli
         DGn0pMmJEIv9m99xQTotunQ+uYa9yJNQ5sbaiO1/FKYh6YEYE8yQ4tUkQBvE+rXVpJjk
         depRXiM3LHMCxV0MAOzGN0bgTBXNupVvzb4Jb1P43ZQ3zYgAJdjdKkdXkA72my8BIhBr
         qwUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717533616; x=1718138416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NXZnOM1Fz78NTOmNYaCfF7VOyDVk71OzL28nHTNxP5k=;
        b=S1S1pWcv9Qyw8C7kqyJR0Lo4AI2SguWgrq8R3TWMf1Z1Iz2jI3krGSMdEogglRvcti
         2hJxgorIZetURX/ioxhjvhlQJ6Nnsq3tQ6w8vTupMWOKQfxZTRo6D7olM5c1zgzFYu4n
         ulxZSn1+cG+hhvXvp9sp8wBUx4101vKH+C2X75MbReH0Iz20D4uWBt/lVys0ASs2Ky85
         ZvTA52ixMFHu2jo1a6KNSnnW5rfQoJTGacMJYTYYiEY5Ml0drtHT6C2bm7/aZBBZQnLg
         5LN476GCS+Sglm0dZJvcHIyJ9YKIAOyw678BInNs7/gzbPHpMGUEPGwxKMZpkvR4qn8k
         U5EA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVWDIa9pgPHIdJzjt8E17ObGZvt/SUOZOuO0KY2EjO8GI32xqAiCEqQ8gdHVTFg6jpo/4H72yRTtjU4FWmCMBjHzrdVdjuA0g==
X-Gm-Message-State: AOJu0YzV9R8S8FVn2KNUX0B0pSyGhKtdtultCqILbn92qK79K/m3WpOa
	mZRoyUFE0avghhReJyt5ZIlagPbpO/4xLk4LTOPJCmrL+kETpMgp
X-Google-Smtp-Source: AGHT+IHikPsxBrJLWaTGCcdFsx9XJq0CPRHb+nQmkXnYT+yIGzMvJJtDCxZRDIQhAbZFg2Q6Wc/+Yg==
X-Received: by 2002:a05:6214:2b84:b0:6a0:c503:17c2 with SMTP id 6a1803df08f44-6b030ac2b3amr5269136d6.63.1717533616257;
        Tue, 04 Jun 2024 13:40:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5744:0:b0:6ab:8f81:8496 with SMTP id 6a1803df08f44-6ae3f65e256ls1101686d6.2.-pod-prod-01-us;
 Tue, 04 Jun 2024 13:40:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4UbL7x+ij9dPZ5IVZeSTKaHIXv71ri/lAnm+zD1LJPlzDcPgvkN/YbMHbhaeTxas9uHUljpCTk7TqMfjRgvsxdgd8WrjaYCQ4PA==
X-Received: by 2002:a05:6122:c91:b0:4dc:d7ab:7f16 with SMTP id 71dfb90a1353d-4eb3a41ead5mr968321e0c.8.1717533614205;
        Tue, 04 Jun 2024 13:40:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717533614; cv=none;
        d=google.com; s=arc-20160816;
        b=0WoBLxeuUjntuhCGN/RwWBlNP7WfDb/XEoiT+nCGUYrIaE4cmPmgVjskpCJN0CHuSW
         s8xAVvX936R8ifX9MMj0T/kgpR5lrCLgDLgk/wGz2TJZpyqOBD4sqt0WHfuxhbMrSwen
         brRytFBlGpujv4F9PMhPUtwZa6FzCnwpwpOSa43SnmWl49cqMP0IgdBqTHNUsb5C0MlI
         3MRAINQqoT1mOVcbXbZI/a8vswFkBPVlUYOpcdO1Wzzabpld4aMM+64hhBFE13AR4VjS
         MQRk5L9y5XJAQ7UKyUSulEMJ1ni9mP8nd3Z1oKrHTeExTkyszEWv/DBSy8j9zYXASnIa
         b+sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0jT0aEf9tM+bN3Sg+Ch3w9OOLh2WMqcyNipCyZcD19Q=;
        fh=lZtp+aPlO3n/dA81ufB6aTjpVYBC28jYtVjXiwIxB00=;
        b=w9oKxnctm4ih5utn4ne3vMLOFcjDp7RYtrP2u/ORqg9Jg5twYsqr8Mz9IwD+zSqOO4
         25qjux0wOecjJ5s+22LFwUVPyJZlTxFqyuU5MuO4yBhOBTzJxIKo6xAAfC/UQ/3i1eLd
         bVooZtiRe2RUQxNNmjZuQaRAEMbWgcJPCmiJZLFJ8NTtqi22yPAGS6JnHTr0tXgXr7+6
         Np4tUSlTDDynjr2Aiq3xwTPae6kMozuumqO9+0jmVqsBfvWSLjvp696mRSiYeeUUzZGx
         mC1OWwR1YAJBUgkbfcYVi3RplQm04OVilLvF5qUacT37NZEA7mhmwShiRStEPprWMZNa
         KtOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iQuK7mO8;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4eb02af704dsi797780e0c.5.2024.06.04.13.40.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jun 2024 13:40:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 8A13DCE131B;
	Tue,  4 Jun 2024 20:40:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5893C2BBFC;
	Tue,  4 Jun 2024 20:40:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 77B2CCE3ED6; Tue,  4 Jun 2024 13:40:08 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@meta.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bart Van Assche <bvanassche@acm.org>,
	Breno Leitao <leitao@debian.org>,
	Jens Axboe <axboe@kernel.dk>
Subject: [PATCH kcsan 1/2] kcsan: Add example to data_race() kerneldoc header
Date: Tue,  4 Jun 2024 13:40:05 -0700
Message-Id: <20240604204006.2367440-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <ecf1cf53-3334-4bf4-afee-849cc00c3672@paulmck-laptop>
References: <ecf1cf53-3334-4bf4-afee-849cc00c3672@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iQuK7mO8;       spf=pass
 (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Although the data_race() kerneldoc header accurately states what it does,
some of the implications and usage patterns are non-obvious.  Therefore,
add a brief locking example and also state how to have KCSAN ignore
accesses while also preventing the compiler from folding, spindling,
or otherwise mutilating the access.

[ paulmck: Apply Bart Van Assche feedback. ]
[ paulmck: Apply feedback from Marco Elver. ]

Reported-by: Bart Van Assche <bvanassche@acm.org>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Breno Leitao <leitao@debian.org>
Cc: Jens Axboe <axboe@kernel.dk>
---
 include/linux/compiler.h                      | 10 +++++++-
 .../Documentation/access-marking.txt          | 24 ++++++++++++++++++-
 2 files changed, 32 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 8c252e073bd81..68a24a3a69799 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -194,9 +194,17 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
  * This data_race() macro is useful for situations in which data races
  * should be forgiven.  One example is diagnostic code that accesses
  * shared variables but is not a part of the core synchronization design.
+ * For example, if accesses to a given variable are protected by a lock,
+ * except for diagnostic code, then the accesses under the lock should
+ * be plain C-language accesses and those in the diagnostic code should
+ * use data_race().  This way, KCSAN will complain if buggy lockless
+ * accesses to that variable are introduced, even if the buggy accesses
+ * are protected by READ_ONCE() or WRITE_ONCE().
  *
  * This macro *does not* affect normal code generation, but is a hint
- * to tooling that data races here are to be ignored.
+ * to tooling that data races here are to be ignored.  If the access must
+ * be atomic *and* KCSAN should ignore the access, use both data_race()
+ * and READ_ONCE(), for example, data_race(READ_ONCE(x)).
  */
 #define data_race(expr)							\
 ({									\
diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
index 65778222183e3..3377d01bb512c 100644
--- a/tools/memory-model/Documentation/access-marking.txt
+++ b/tools/memory-model/Documentation/access-marking.txt
@@ -24,6 +24,11 @@ The Linux kernel provides the following access-marking options:
 4.	WRITE_ONCE(), for example, "WRITE_ONCE(a, b);"
 	The various forms of atomic_set() also fit in here.
 
+5.	__data_racy, for example "int __data_racy a;"
+
+6.	KCSAN's negative-marking assertions, ASSERT_EXCLUSIVE_ACCESS()
+	and ASSERT_EXCLUSIVE_WRITER(), are described in the
+	"ACCESS-DOCUMENTATION OPTIONS" section below.
 
 These may be used in combination, as shown in this admittedly improbable
 example:
@@ -205,6 +210,23 @@ because doing otherwise prevents KCSAN from detecting violations of your
 code's synchronization rules.
 
 
+Use of __data_racy
+------------------
+
+Adding the __data_racy type qualifier to the declaration of a variable
+causes KCSAN to treat all accesses to that variable as if they were
+enclosed by data_race().  However, __data_racy does not affect the
+compiler, though one could imagine hardened kernel builds treating the
+__data_racy type qualifier as if it was the volatile keyword.
+
+Note well that __data_racy is subject to the same pointer-declaration
+rules as are other type qualifiers such as const and volatile.
+For example:
+
+	int __data_racy *p; // Pointer to data-racy data.
+	int *__data_racy p; // Data-racy pointer to non-data-racy data.
+
+
 ACCESS-DOCUMENTATION OPTIONS
 ============================
 
@@ -342,7 +364,7 @@ as follows:
 
 Because foo is read locklessly, all accesses are marked.  The purpose
 of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN to check for a buggy
-concurrent lockless write.
+concurrent write, whether marked or not.
 
 
 Lock-Protected Writes With Heuristic Lockless Reads
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240604204006.2367440-1-paulmck%40kernel.org.
