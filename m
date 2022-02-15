Return-Path: <kasan-dev+bncBAABBRVUV6IAMGQE7GFS5HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 026914B73E3
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 17:52:23 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id h6-20020ac25966000000b00442b0158d70sf6324051lfp.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 08:52:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644943942; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJhiLFnGD0zKzvzADmtsZfYKxvvfe0MmgMY8fKyF8fworgg4rqp/nLpZp6C5Dou+bt
         /Dw3lHPDtKZSmpTV58N8oVOdb3KUxIGcOOUEp2Tsih4dBnilwdbaBlBWLEQ+dLXX0VPw
         qlf3MAAA4egD7MlIQ2epaAbTthEf23qnYePpa+ek06y3qB16SfoPeAylWCFsfjq/xSJV
         rpJjEBS4Z6Wktfw65GFTRkO5FatQvrrJVci6cAjWbSlYcOo4/P1zhXYOdHbTQlq4PKZk
         mcGo1PC8QJm77uwjx2EYTIngW6qc56/Wy4pg15ZoGAFUTbXaaFYnWjc3/JfXVakjFfUC
         hKhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JOD2mFWLB7F2bqiWG9Xh5lTqDZ2QJ56gf+YFhqJXxLE=;
        b=Lfiqylvc+CtymfJzYLcSUKCcxyJnKy9B4+HGt0lhT9wY/dHRWgPNqtPFqcRl0P3IwJ
         9BgwEiHScItRZZedtsZ6Z9XQkpk459jSqSWHVpaVsjw5Nf5k62q6gKi5IEXxp6WX04am
         QxjJUX/u7+kwxe/SmloPUPsEc0rpIh/VVgeBL+gb9mMdilLJTYJYdF/ErLOCc/mA+UpB
         964UK+01o7Bb2rVg+jdZkJY2jtrHTP6XMo5+3CBqddTVk/dPvNbVlo069bod+0rRdXO4
         U4ITYbM4zUy8k2jnfU69b86LLIp4zwxIgaUgJvuL6vUAonIpY3KM0SOD0gkhylskgzFw
         kM6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hpIlGRiz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JOD2mFWLB7F2bqiWG9Xh5lTqDZ2QJ56gf+YFhqJXxLE=;
        b=k0rdey1vIy5PpxpU7m/EpOR9Xv3lFatNNZ5ijlXp7uM6kcy627YppwmBUdkimxr+97
         mR/FvGrYPNrhCBDfUNlYCvhfqP8hPwZI+qkxfbvlNe00pfoRBTMKB7isnUNRHVqr5RC/
         tPNOwEqrkreWmnCZPjhexmJke9rAhY3EYf+tjuXnAxlejf4DFuL/cy6DY1lGVUmUakn9
         vLS5EmFasvfUTfO+pJ/KongTXHuWhOy7jmRY0kBxvqG3+p6boMR5YC9C4D4iByXyyNDr
         jEgIB5C6eY+ugibXae3g3KY14nQWR3uPUYxPC1Tp+PcwSWqtytGIKuKwIMOdTvWnu2MN
         qGSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JOD2mFWLB7F2bqiWG9Xh5lTqDZ2QJ56gf+YFhqJXxLE=;
        b=NBS+mhkwOu1lH7OgFP6RV4SIW3KFa0BL23CwlFUslKHYZTZNJw22BrJZ2HUFqMhCbP
         pRMmgGG8QNzc6P85HDh7KgkmlhzzkWfp6RfSs/gZj2SyAYxWK9yXB2PReFizT80jcIRX
         vBWaj/BqfUa/gEHVu+1dm0SkzSBaD2gpVT1DMv1r3n4e3B+kKow9Ujjpgoh/iZOj7jos
         I8ufQ6MJUI6JyWdtjSkJixcnsa9/jNAVSzK0EagcJiwr6YEC4myQlAsGIaQCWiLeSHCi
         0QdilD+CP5NdA9DyJGguoa8ITb73RWVydHHKLQND6D6vAVQFgWpBYcmMmHT0Br886fOq
         NbQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533pcjGOi9qRcSD39opzJXaiKHUZDom/lN+o1Omb3lmbBfX1Yn4f
	7FdUfvGzvP5Jo+WMUgznTSE=
X-Google-Smtp-Source: ABdhPJwsrFSQJHr9Phz8a0hSEaPLDlY8nHaLoEGskcKSqwJOKkyQOjyUtISmAsBu0Dk8Qqdq4+RLkQ==
X-Received: by 2002:a05:6512:2205:: with SMTP id h5mr3858864lfu.614.1644943942405;
        Tue, 15 Feb 2022 08:52:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ba6:: with SMTP id g38ls2957031lfv.3.gmail; Tue,
 15 Feb 2022 08:52:21 -0800 (PST)
X-Received: by 2002:ac2:4c4b:: with SMTP id o11mr3730424lfk.253.1644943941624;
        Tue, 15 Feb 2022 08:52:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644943941; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0xIiob1z7a6UwvcjeL2CsYUnXxE3aH9tpTurGJkoZ0RUENErg/wUG6jztKuMGaHzp
         LBXngVQv2kmefGPX9ARSZBJSYr+G5xCzBasr36098Hwbem7tl1sq2xxKBg+VcsOLJCGr
         ptP+x6eire+NMpx5pOWaQyEeQjYKYYLyxv11If0odhF9+IP7kN1BDSkUe8/0Be0Nw7My
         mx5aqrV3pA5m+cxpcd3SiczR7rdCl9a0bAYlyPDoiBrIoqdPSqioj2d4c2dvO6Z4cKS1
         GXT4SAVJGI1pRhSZMzItIL9YXUEcwBDzkpQ1J4HQoi76aX7xhhgDlkPrUaIRvM1Wig4A
         ykGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=x0WqM712H6kGeqw3TwDc06pcqFg5ecYp2OoNXB9nDtc=;
        b=DA/Ea411dm2r1rfriFKtnYRLKYCol8xDIn8WRsIN/RmT5enC1m+DP8+7NmGfpb7TMi
         l0xSv1VjVCFuGMlWJB7MX75QaTVyk8P7ZWOnikWhFKbTQzT9CvCqb7xkVYssc6V+kO7Y
         WgfRCIC7pPh9X6JS9rNJFngEB8Sr7ASILVQslyUQlId3Z7pgDocDXKuEl/fzp4Vm+xnS
         OikRZBrnKM7kNaC0pON9b1R3J6JewX+9c7RmHOuIt9sn6WNo+ZImSvk3Rsuw8C0vo5X7
         6wCmEIdGgxXVzgr1rweUopn/iqlQeHuOUvJ9NcYXD5fFzWh4BhLdDbUvIsfIKqeIpVIb
         rYAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hpIlGRiz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i2si1741693lfb.3.2022.02.15.08.52.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 15 Feb 2022 08:52:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] fix for "kasan, fork: reset pointer tags of vmapped stacks"
Date: Tue, 15 Feb 2022 17:52:17 +0100
Message-Id: <f50c5f96ef896d7936192c888b0c0a7674e33184.1644943792.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hpIlGRiz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

That patch didn't update the case when a stack is retrived from
cached_stacks in alloc_thread_stack_node(). As cached_stacks stores
vm_structs and not stack pointers themselves, the pointer tag needs
to be reset there as well.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/fork.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/kernel/fork.c b/kernel/fork.c
index 57d624f05182..5e3ad2e7a756 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -226,15 +226,17 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
-		/* Mark stack accessible for KASAN. */
+		/* Reset stack metadata. */
 		kasan_unpoison_range(s->addr, THREAD_SIZE);
 
+		stack = kasan_reset_tag(s->addr);
+
 		/* Clear stale pointers from reused stack. */
-		memset(s->addr, 0, THREAD_SIZE);
+		memset(stack, 0, THREAD_SIZE);
 
 		tsk->stack_vm_area = s;
-		tsk->stack = s->addr;
-		return s->addr;
+		tsk->stack = stack;
+		return stack;
 	}
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f50c5f96ef896d7936192c888b0c0a7674e33184.1644943792.git.andreyknvl%40google.com.
