Return-Path: <kasan-dev+bncBDHMN6PCVUIRBUN6Q65QMGQEOHQCUKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B58499F57C1
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 21:30:10 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-436328fcfeesf34081385e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 12:30:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734467410; cv=pass;
        d=google.com; s=arc-20240605;
        b=CCgvVmhMsBB6hIPXaZaSvQxiiv04tEwoa1M1827OXnjyI/F49Qc6ML/RujXsgFrJx6
         rbn+y7FuvN87j2OBFCQ1tgdfqLUY5GOTVe6aYJVPDr3IxxOtNUuQvc6SLzRZ5kZqadjW
         1+/UdQpGwoGFddaJ8FLnzfVe88deuaaEhRkUdFPQFfV0NsFVSw/tqdGSi80rLhTKmEPX
         EgWUolOFlacn+QHR/fumexyIdg5e+R8tdfOjLXf8NLFrf9kKkMLK09kNOyOxHketPePZ
         bYOrBTKB+nYPMWE6yNs/olBWTmC7nEsNDxGv+FHdKxQ8GGwvbKTmfah9Z2/02m3e9Hcy
         3cdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=U34FCnh3s7yFA7WjAdVwYnKCj9Q3pEzT2elUr1nbSQ0=;
        fh=Qdly6EWxdLAeqEKy2PqnxooAUmen0qJCGVF6kzzpcbQ=;
        b=ahGUS4dtVctax5StJO34uWLi84fJMyq1ID0QeN/EzEmZ9oT3G0c5TKLv2BTTag0Off
         lfZN//+XZEoFKvXomF0v3j/yrBVTQvjSpjKLx99mxxso/V8wfW4hwimDaiRJ45e1/P7b
         AoXj5pKQb7cLEfqiUQQM40UVzGSgPaszxqF7ANM09+wSojeDxQOKs2bVoSgfvB/hWeu2
         SDNXVe6nf39/3JpqNDwwbtRffJ9qFkJViYcoCLWtnXkKSrrLaTnhYuXnFSn8Vr7u2Rbd
         LdGY7FTu6XrrhYftrJVVTIWFp5iLJoxodRFqyrWb5DOlwjI1v33QwUeGpnK9gkbaOQEZ
         CICg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=flm+413r;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734467410; x=1735072210; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U34FCnh3s7yFA7WjAdVwYnKCj9Q3pEzT2elUr1nbSQ0=;
        b=Qyuc7YAKUTFiugZ6avOLAs6MWgrIDbSyxtejdEkk33iPizLWh+sRwWh4rAmMHG+8Mo
         bg1ZOiGMCdEddqdQTQODfGgCWCbGIWcGQMV7T2OPdJTeebTEro1RwqyhjGrvJa5xTBJ0
         uXCYfft5PYkiK4y7UYI1D8TNOecp2gSd461LAiUznbp3qg3qjYL6HaBgZxgO/PHlI9bV
         TE8288hFykjbtaVoeBu3nAtpAJ4UroZvDeg7xBPjPoKXn77aJfUb2n5jduAMV4r9ggh6
         dU8x02ukormqsv7X6cTd1rU4qDRMl0Lxssf0nI1afCpDyyG2BrpuI6GZNcM13yVE5jku
         5stg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734467410; x=1735072210;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U34FCnh3s7yFA7WjAdVwYnKCj9Q3pEzT2elUr1nbSQ0=;
        b=Y+BruurtuuTzA6oczYaUdbhBvoDXh1uNoCmmUcA1DHg7JmY9bRVjd0c3sZEFPZ3ui5
         ZXuPX6ao6WeOnl/XhZw24Zucw9qUFqtHzGAW4g8NyDgiFBVEd2U/vd8H7rnd6cUJWmZY
         lYCIhjZJUn/xcdp9eIlYcU2ctl+zuyMyGWLuLO1+7MB3FoigTt0nIanuHukym4MOqvGk
         Xog6e3MBFZc1tj3gHKXzj8msSj4twWn4GRHouewAl+74z55eVTIm5mrIozZe4pNP10q3
         ++zeb28Z0QNdgw6ylf7Ij6m15BYgxaqj4mb4lNQJT/unSKCBhmRyeXtl6tN7DDqbgfPn
         frzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUd/FLdmNs3otQt+nwXTvXbpXB9Rtlh9Q9FCyiktrc7h/NdOLdPDDPs+FgQ+oMN08PKP4pdhw==@lfdr.de
X-Gm-Message-State: AOJu0YySyMfa5hEdd6qQ6T0XLlJh6mSNkgBA9ZK6XcgiO0GWnpKy8QE7
	ZyqLE4cGF1hyQJtC23d8xauJClCUL5Aj+BtlOS0UvRIGORpdBiKs
X-Google-Smtp-Source: AGHT+IFy60xFUApFQVRdLM0MTFPobobvIwC29ySX4x26nHoPmbxK9kc9Y88ywZF2eFfqAjMIh2g+7w==
X-Received: by 2002:a05:600c:1c87:b0:432:7c08:d0ff with SMTP id 5b1f17b1804b1-436553f5573mr1071055e9.23.1734467409506;
        Tue, 17 Dec 2024 12:30:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:12c5:b0:436:192d:419a with SMTP id
 5b1f17b1804b1-4362b19ddb7ls25338625e9.0.-pod-prod-02-eu; Tue, 17 Dec 2024
 12:30:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHhVyZpecpWeQncPgXYxHj2DKWRN7Gv1dljvStJP4ODD3zCWq/2WFW6El0EW4R8wDOr9ua+DzCtAg=@googlegroups.com
X-Received: by 2002:a05:600c:1382:b0:434:f7e3:bfa0 with SMTP id 5b1f17b1804b1-436553f55e9mr1050295e9.21.1734467407440;
        Tue, 17 Dec 2024 12:30:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734467407; cv=none;
        d=google.com; s=arc-20240605;
        b=jWhD1wfn7YS3HTYTFO7gRgPqIRoXYeZRplLLMqQEDHN2uuusWpf7lXxlr+IyT0TF4Y
         jvyjhqC8lPqIEx3iUcERQ6287YFQIMNCnRnKW+UilSHSVO4vMVfIVoLpSh/U3OQJk5QO
         6AA6MiaNRejEcvkBWFtzoc5KPNvYMm7z/4j+Io9qMbt5K+YHJGeXmug1U4VDc6BB4MLA
         RulHdgtAamYl7WFRSCPbcMFuYOTV3s+GDi1WbxQCsgHyehUYNpV1z/Pol65J8IIl/UL9
         JADK7+hEUDNc903VyFlfW9Rw4KepV4GVNCpaUq/JFKEjXD0UXmKeFQZr4hAGJgcq3Z9K
         J9NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=111IE7H4zmyUsr2adVE7p7sD/t82ixlQP2Vi9ldpbO4=;
        fh=k2Z8B0SyaWkPc5Fxzj03jgfC6ikcy0wx+bFc5bYaPPs=;
        b=IC4vpwLPGNHN8rFvlUQuP3mCx7ylbKiaOY0DLhVEJY/emYtaYmAtJQupy3oQMqmll1
         fGlkkKSaJC5ZLODFiKnHYWNG+1jLsYc4D8TR/w0hzdDMwOPyIwdsYRKZ1B1yzmGJqfru
         wwTIt/8+tKmR6yRnzpobWk/e2Aoxp+6J0BEl2HplUJuVT8Pi/E4uppey/Lc1wRFLF10v
         IXWYgXphB9tumo9G/kg5oqpoSjkk6YG7HaRBBPkC4/91jFHgRP30HcYFb4kn9ZKfhSfl
         Wafd2V5pcPPuNO15dFFUnyS9bE7UMmxkjOa/RRRNjBmajOQdB+Ly/9/jWxD4RpXOzB3G
         poEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=flm+413r;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4364b058038si1570915e9.1.2024.12.17.12.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2024 12:30:07 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tNeCh-00000002NwX-3323;
	Tue, 17 Dec 2024 21:30:04 +0100
From: Benjamin Berg <benjamin@sipsolutions.net>
To: linux-arch@vger.kernel.org,
	linux-um@lists.infradead.org,
	x86@kernel.org,
	briannorris@chromium.org
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Benjamin Berg <benjamin.berg@intel.com>
Subject: [PATCH 2/3] um: avoid copying FP state from init_task
Date: Tue, 17 Dec 2024 21:27:44 +0100
Message-ID: <20241217202745.1402932-3-benjamin@sipsolutions.net>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <20241217202745.1402932-1-benjamin@sipsolutions.net>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
MIME-Version: 1.0
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=flm+413r;       spf=pass
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
does not contain the dynamic area for the userspace FP registers. As
such, limit the copy to the valid area of init_task and fill the rest
with zero.

Note that the FP state is only needed for userspace, and as such it is
entirely reasonable for init_task to not contain it.

Reported-by: Brian Norris <briannorris@chromium.org>
Closes: https://lore.kernel.org/Z1ySXmjZm-xOqk90@google.com
Fixes: 3f17fed21491 ("um: switch to regset API and depend on XSTATE")
Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
---
 arch/um/kernel/process.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/arch/um/kernel/process.c b/arch/um/kernel/process.c
index 30bdc0a87dc8..3a67ba8aa62d 100644
--- a/arch/um/kernel/process.c
+++ b/arch/um/kernel/process.c
@@ -191,7 +191,15 @@ void initial_thread_cb(void (*proc)(void *), void *arg)
 int arch_dup_task_struct(struct task_struct *dst,
 			 struct task_struct *src)
 {
-	memcpy(dst, src, arch_task_struct_size);
+	/* init_task is not dynamically sized (missing FPU state) */
+	if (unlikely(src == &init_task)) {
+		memcpy(dst, src, sizeof(init_task));
+		memset((void *)dst + sizeof(init_task), 0,
+		       arch_task_struct_size - sizeof(init_task));
+	} else {
+		memcpy(dst, src, arch_task_struct_size);
+	}
+
 	return 0;
 }
 
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241217202745.1402932-3-benjamin%40sipsolutions.net.
