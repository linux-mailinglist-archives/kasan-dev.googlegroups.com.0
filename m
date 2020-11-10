Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV5WVL6QKGQE2GVL3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id DF5F32AD80E
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:53:28 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id bb2sf6633801plb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 05:53:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605016407; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSfPpDfWg+V1OMfj3UBrdN4Gw23fCLCr94KFAFUV/feodfs1fW+u57x1GbZhrRsgzB
         y8FXF+V+wNCL80Gk6GSqoBwM0rtFvZiJ3atKxRt3wj3wEcRpVbJIPuKh/0pS2SADblAM
         eomgkantu4ZzHRKpt2Cam+LbkMiLsxNREHXXOTrYQCRmcIPYIfZPM9wJmTY54bsRYL1T
         f/VdHgbNi+GpK0PO9IWL4zaECOu1ZjKhpd9+WfqA+ox7q+Znc/xbGyYDDQ9/rB1Jqp3n
         Q2gVMI+GgFTYKhrrzP6UyQIrPnI2tMRGbYlOv1fqkDej8wyK0ZRv2NPEbrcj0eTti42K
         xeZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=aUjSsXN74CzJ6JxWilbUbMPPe9KUBdBLThWqIMQ2DBw=;
        b=VZTr8qZz4w/2S4iQXwHuNtnbRjvQh5YeM6Sj9VUiqpiq568lz3tdZDggQs4nOHRYT6
         nckJGPgu6FXVVh4KhdQLFFqmiA+WWjmnDrvuNdtyWxWWRZxwdnz3yi4GDAeirji0o5oU
         VVmExj4wSMciAXt57yBgJFrorTjvLVdScTlnMvkY+Ig7oyzQK0L8wUkUPH6RQKf+vywz
         Ibcc9gYkXtqWX1asxJWmOmq0z3c5IXyv+8GcoOoQibf9E0bNtkE4g9Jh6oElMSjU3dTF
         mRhkbfV9VZJfylIZGE74Ut4TC4vrvt05VdZV/zcJz9roa8WW8NaxNmL5y6TJvAMnC89a
         +UDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DUJbPjRA;
       spf=pass (google.com: domain of 3vzuqxwukctoahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VZuqXwUKCToahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUjSsXN74CzJ6JxWilbUbMPPe9KUBdBLThWqIMQ2DBw=;
        b=Dv6XGytGKrMvDFogoCWCKIKGEXBdXVgzbBUyHdHjeJe1gMHrh4HkoPVIgpdYhSSoy8
         uxXou11mnV+RRWu8IgiaMIIcFHSAHDVT2eRr66xHpQap0LoLIL5pKLMcT2TQxOHva8Al
         81yemwQf4iOMLsE5ZC9myRK8nUWw60zJVejpU5TUZ/CleMY0US3ffxBFU1qSswiZuG9Q
         7fmC1Umh7vsaQUvFiEUKg0M4W4k8ehVBN/8A4BuDJf/4MX60s0/xO9Wbvmg+zD0N0flB
         XpveJEo0lCaZS9r6tbKQmxwsqnqr5wo0oCwxnu+qkA72Z1wYYvTxwFeVUV3v6uBKU+om
         6MpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aUjSsXN74CzJ6JxWilbUbMPPe9KUBdBLThWqIMQ2DBw=;
        b=M4uTuNELAgbq0bPNNb/eHF2tz+CI6SxKIi1QI8i9dddbjxLe7Ol2Rhzdwxuin358mU
         fDsZCq9HSMyI6TVaO88rSy37lcpZtnnZ4OmFD6IH0VqBjyDCNBKl3SYj+8ijD+ZD2TqU
         MToFjYxkDVDUyar4GjFwlL3A56akn+tMMl/r67EmLe8Co8jMrtXDxsqybCw4Tg8Wm5PY
         2Iz2S4qqrPY3TZteaH/KKti9GbfAJiV90gUPKN0420IRKnXc0nrkR5yOYNt2NddMfqur
         W1XBRWMMln8K8BkTKfiA1xCN9aJC9pEvr1PKCn/F+NlYyP1zbv678FhyP5Hjc5Ki6xnU
         QzNg==
X-Gm-Message-State: AOAM532I0YiPljX0eeRjsiMgxBbE05+K6EGMxtbd5njIY9490LGk16Kc
	BFsj/Ot3bcbxUxoFZ5KnWnA=
X-Google-Smtp-Source: ABdhPJz7a89eIT4BWwuRg6oGC76O3rhHEb7lgcGdNPyXZ6yyNM01w7RVylhoXBYOYkzapjPc9u3ZJw==
X-Received: by 2002:a65:624c:: with SMTP id q12mr17499174pgv.310.1605016407468;
        Tue, 10 Nov 2020 05:53:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3712:: with SMTP id mg18ls2011610pjb.2.gmail; Tue,
 10 Nov 2020 05:53:26 -0800 (PST)
X-Received: by 2002:a17:90a:9dc6:: with SMTP id x6mr5441129pjv.100.1605016406813;
        Tue, 10 Nov 2020 05:53:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605016406; cv=none;
        d=google.com; s=arc-20160816;
        b=TSUOOsFe1LnpeOFwQRbvXGHaDmUhh66IU0AzYVcGzaUQ7f8sqYCuiZMk4R8XdQl9BA
         MEiufCbMnaeaUn3PBMZ82um3CRv5A1A4EWNmnv7SwwNIR0H2EDTOJms07zWLcDFsho2o
         VnkmR17QP/CLIOwDxBnItm/IlYPhsJ/1of1lBFAwrGSOIgMLhrHjGgF113v9LMdM9vfs
         RSvYSSs3pXYwiufoJhbpc8k1JDGjnwIcbOKyIop3GkP5JK9GG6p3Cfk1HgxeHvIOXlyU
         +jj1kTjdKcLA2K/I4XxhuJG1e1IIGintKTdWfvl1xGxMCDxqx7DHA1NiShJvWjCbnYmC
         50IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=HVbq6NPlJzIOUbEGDX3ZF6qnq7VBRGwp+e76lTdscsU=;
        b=QNu0/3Tg+WMi6N47qeMYCGCnMU1J3fSBCRfCuQgR87XoZbF318ZMJtKstEeMweaz8j
         ziKPAeLLt57ar24JV939Vup2tGswMjn+KqB6th0T+f5RzCksLz554ZzcXqqgtoTUZaFw
         PdVlnklVWNG3jI2pbCMjR3ElhXs388tSP3AqbxQcxYuRYLSphzyB5M2VNvk5vIt1lpMr
         dxgDqYFxjjA2idagtYeIWntNlIj4N2j2QOr3BhyuaL/KtELV7x7H440EYdWu+hS11d4+
         Zs4GJ0yAcqVOyQuKsqNexKVb8qLVeqmPu9HTVAcRzvFwdIcGsGP0IyGMqMg13/IhXbrv
         eDAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DUJbPjRA;
       spf=pass (google.com: domain of 3vzuqxwukctoahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VZuqXwUKCToahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id 80si198886pga.5.2020.11.10.05.53.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 05:53:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vzuqxwukctoahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id h26so4495467qtm.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 05:53:26 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:174f:: with SMTP id
 dc15mr18927895qvb.26.1605016405908; Tue, 10 Nov 2020 05:53:25 -0800 (PST)
Date: Tue, 10 Nov 2020 14:53:20 +0100
Message-Id: <20201110135320.3309507-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH] kfence: Avoid stalling work queue task without allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DUJbPjRA;       spf=pass
 (google.com: domain of 3vzuqxwukctoahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VZuqXwUKCToahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

To toggle the allocation gates, we set up a delayed work that calls
toggle_allocation_gate(). Here we use wait_event() to await an
allocation and subsequently disable the static branch again. However, if
the kernel has stopped doing allocations entirely, we'd wait
indefinitely, and stall the worker task. This may also result in the
appropriate warnings if CONFIG_DETECT_HUNG_TASK=y.

Therefore, introduce a 1 second timeout and use wait_event_timeout(). If
the timeout is reached, the static branch is disabled and a new delayed
work is scheduled to try setting up an allocation at a later time.

Note that, this scenario is very unlikely during normal workloads once
the kernel has booted and user space tasks are running. It can, however,
happen during early boot after KFENCE has been enabled, when e.g.
running tests that do not result in any allocations.

Link: https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com
Reported-by: Anders Roxell <anders.roxell@linaro.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9358f42a9a9e..933b197b8634 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -592,7 +592,11 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Enable static key, and await allocation to happen. */
 	atomic_set(&allocation_gate, 0);
 	static_branch_enable(&kfence_allocation_key);
-	wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
+	/*
+	 * Await an allocation. Timeout after 1 second, in case the kernel stops
+	 * doing allocations, to avoid stalling this worker task for too long.
+	 */
+	wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) != 0, HZ);
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201110135320.3309507-1-elver%40google.com.
