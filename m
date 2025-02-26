Return-Path: <kasan-dev+bncBDHMN6PCVUIRBA5Q7S6QMGQEPOBOSOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 50548A460FD
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 14:32:53 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-54621417c2bsf3958992e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 05:32:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740576773; cv=pass;
        d=google.com; s=arc-20240605;
        b=YEtmUM666lsZGoGpRKd3O2TCEFT7eXOMiB/qKrqaBJmAzZ0xTy2QU3T1MW4ZtY3a+u
         2TPNXq6sTg6BoRsr0RHp6fdDtlM0sRkvVopUXWr56ojzphzEVRft0IlsXI11QnY4clW9
         qcnx5zk7vbfZ4YBbLCnSF3P5R41vJSeNPUWKiPCGj177LEmL8/hSyFgdZ3tK5qSDWWtq
         0R0POyVjw1pmu5N7Aw70BOvxyzcIDeqWTAb5d96KWi+52zOFpXAGmnhPPD/pdlgHoYVV
         0x5pgp3TzOC/oNRKEg5aplGDIQNRNBJDgNOfS7HGeoUxK8DtzpEFzww0hd57V71KcMR6
         8USQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8no5oXxnRvmRAQWF6e0EWHD9/Kffx9Lqj8Vubh/uhxk=;
        fh=MGXociygQYxZt9oIQpy+EF8NP9EuPRZPAoizdT7QG6Y=;
        b=XhUKfYoa1Lvn9zZygMKsBe0+wH4ogqYFlINaeIR2alw8oOGqjbKQIZGLtcaUHFhmRT
         4dRvrlQml1rg8Phu0kbP6MgGG6Mj0B9nSy0uCWz+Kkod/5UrOD/IQ05sS+yL2SK6PeC7
         cGVdZ0Jl13YIRVkgmEuFlLlImZw6N0b/pJ/cj+KzlOZ/HNYMYmvZuRsbdfucXpPuZsD+
         kwgKzREEkn1yDxopxGResfExb5ph8hAAD3pQ+xn6tdsc4m7zOSqs7IFJg08w2k2uhIEF
         L7V+ojEu8VaRfr68tdzH0oj9wweFvLOlDEWE9T10Lt0cSyDK18rQge7AAWodvypaXN/p
         XbZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=Sduo9Fim;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740576773; x=1741181573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8no5oXxnRvmRAQWF6e0EWHD9/Kffx9Lqj8Vubh/uhxk=;
        b=u9VwBpIRdga4nqpC7DEWjzPqwoBV4mGu5oCPPV0h1Fjeqqv0eMzATWIo7CYQzrX8Pd
         lIuXVWf1MyKXOIRxhpZXCplnU11S/zxycT5ngYDQFSJrsROHo5a0VOiq98LH5gOSfoDu
         vbHoIDzQE6BDL7IDqg2OGjXUGBZCx/k1nXbLV3X6f5PuhwsN2DFOR3AlyBQbjmDaZH3F
         9oQU5SPcM1KSmf22npb6JtYSjvBLfpaPwGUz0PEZpLrcMe+4+lAH3kwWabsxPI8LTZQW
         L/9FFy8WY+TuRTLEOctq5bSQr6Bu4EoxmhJhVZdY98VoIvGZzP0RtzS3Se8fHBia79QV
         R5EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740576773; x=1741181573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8no5oXxnRvmRAQWF6e0EWHD9/Kffx9Lqj8Vubh/uhxk=;
        b=mNJVwA9MJ0f8XvAEdXAgt4sWLmAX9LdXeDXsyhwYML3iQs8iq+1Hb6OY9vn2KsTm/K
         2oUGMqMgY1ry/6oN6ZKTnxq4UQzZqxusvbmxkZ88MySZ85zkzD7SLCRrH0oWfTfjObN9
         XCta8TL17zJQaeYHgkii/QSVdYhCcVIFuf5t4Omu4r6MLe/l/qfgs+4UG9kOsd5vm9K3
         78Q0R+KND5I0cyNYhPVFgcX5R6yZhJcEpDZa7WUZv0OH9I1tB+mBZW6VIZd78rgfEA3i
         AvOCj0v5ronjZ8QvEAV9raUVnZfRQi09nUWtCRWXb1c9Z1aFdEui13lTunphrwkGiqbg
         +HNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmIJyoGC7kJHZ0SGOOsZqI3SNIC+nmu0Ua3qQlX0Rg5wkQFn+lnJlgYBuBVfXNYIr/3hJXNQ==@lfdr.de
X-Gm-Message-State: AOJu0YyovheQrjdTL2vCpOgoByLUeI+Oa6rJ09gs/eps1uAbQphpKF3p
	8cqvVkgV7+JXVtP5J4p/lYUwCzhQo8KubBdNtNAzJNVu3mIc0qrh
X-Google-Smtp-Source: AGHT+IFx81rwYoCSLqIg0QLi7Fcsz2eB4/h0G5hsfxkuF9GaQmF32dtkKtyrjBvc2X5o6ZpRR2/HTQ==
X-Received: by 2002:a05:6512:ba5:b0:545:e7f:cf33 with SMTP id 2adb3069b0e04-548510ddc55mr4847101e87.28.1740576772148;
        Wed, 26 Feb 2025 05:32:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHshyDABMdVKN25/UNfRBkJc4hNYIkTAZljkMnnd0xF4A==
Received: by 2002:ac2:5181:0:b0:546:2104:35d with SMTP id 2adb3069b0e04-548511271cels341651e87.1.-pod-prod-04-eu;
 Wed, 26 Feb 2025 05:32:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV8NLlJjA0CYhgBZJ5p3ifUmcH8erYy86PgtHjIEJtkKNVRLqy5qLwBORjjzHchxgyHjBEBQ57nNXs=@googlegroups.com
X-Received: by 2002:a19:ca43:0:b0:548:91f6:4328 with SMTP id 2adb3069b0e04-54891f6443fmr3661141e87.15.1740576769702;
        Wed, 26 Feb 2025 05:32:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740576769; cv=none;
        d=google.com; s=arc-20240605;
        b=UJd9TuLAQ1YPO8xEQY+U9WRlzv0UqLsVogtQ47z02Tahv9nxN4CeJzl/o9uLtWSFFx
         Mfs2w+eBa3zQG/Y1NuWw9++Rw6bthq71M2aWDq1X1iQj2liX9g5vifvEit3Ytei+iUPE
         a4hzGkr429pCEkDOBqk4vtdJRS90Ne6PH9RQujNJqDFc0BDacEiughpldq2dqNaE9j8X
         UqEZg3zGhQH5BgXhdTKvD4NQ4SMBvnJ2qYFAoB48pPJmSQyGgG6D4qomlNIioKvBdj69
         w1fWB3r6FZW1FqYVgHcRMxjGcC22t1NPnPChuGA4R15tFeq37VgzmQu0FgfkEgqHV2W6
         ir9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=owRcVAIfAdo/eBUmry6xKaLhXuxlLmRZar2zptWsOeY=;
        fh=8LsfdWgEWODHiHbe4JqcY4lOzG/wLiX9sTHQ7r/dFAY=;
        b=EzhYzkhsL+66+59muPuWb75u11KTciA57I9jti2M3IbQqiozfe4uaNdXr6Dwl/uUhE
         x9ZUaNyoTLvcIA8Y1Q2ONUJqSAxYRaRxFVwu8hCCM5vPPeUcjVlQAIAv/rD5FHw0TS27
         dwXt754X3LZXUkS1lJTolrmK01NH1GoFMCq5Dp5d+mHerYjyWD+mC8SX1U1hBwJ4PYhl
         YokSDei81x5j8R8KY2rAjqmtRunk93DMT7NTXOSWMmYd4fgXxuA6V9fD+XwES5kDWg9z
         J3qatChnu51zcywasHHi7ATIZmPA5jlJYqE5X24ZYq8akf+JqdRcOra0HmuwGVClN4Pu
         Ua7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=Sduo9Fim;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5485147a662si186404e87.0.2025.02.26.05.32.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 05:32:49 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tnHWp-0000000BVAQ-1rwO;
	Wed, 26 Feb 2025 14:32:48 +0100
From: Benjamin Berg <benjamin@sipsolutions.net>
To: x86@kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	mingo@kernel.org
Cc: Benjamin Berg <benjamin.berg@intel.com>
Subject: [PATCH v2] x86: avoid copying dynamic FP state from init_task
Date: Wed, 26 Feb 2025 14:31:36 +0100
Message-ID: <20250226133136.816901-1-benjamin@sipsolutions.net>
X-Mailer: git-send-email 2.48.1
MIME-Version: 1.0
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=Sduo9Fim;       spf=pass
 (google.com: domain of benjamin@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

From: Benjamin Berg <benjamin.berg@intel.com>

The init_task instance of struct task_struct is statically allocated and
may not contain the full FP state for userspace. As such, limit the copy
to the valid area of both init_task and dst and ensure all memory is
initialized.

Note that the FP state is only needed for userspace, and as such it is
entirely reasonable for init_task to not contain parts of it.

Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
Fixes: 5aaeb5c01c5b ("x86/fpu, sched: Introduce CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT and use it on x86")

----

v2:
- Fix code if arch_task_struct_size < sizeof(init_task) by using
  memcpy_and_pad.
---
 arch/x86/kernel/process.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/arch/x86/kernel/process.c b/arch/x86/kernel/process.c
index 6da6769d7254..a8f65c17df10 100644
--- a/arch/x86/kernel/process.c
+++ b/arch/x86/kernel/process.c
@@ -93,7 +93,13 @@ EXPORT_PER_CPU_SYMBOL_GPL(__tss_limit_invalid);
  */
 int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
 {
-	memcpy(dst, src, arch_task_struct_size);
+	/* init_task is not dynamically sized (incomplete FPU state) */
+	if (unlikely(src == &init_task))
+		memcpy_and_pad(dst, arch_task_struct_size,
+			       src, sizeof(init_task), 0);
+	else
+		memcpy(dst, src, arch_task_struct_size);
+
 #ifdef CONFIG_VM86
 	dst->thread.vm86 = NULL;
 #endif
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250226133136.816901-1-benjamin%40sipsolutions.net.
