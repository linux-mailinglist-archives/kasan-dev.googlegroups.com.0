Return-Path: <kasan-dev+bncBC6OLHHDVUOBBLNL5T3AKGQEKHBGLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 610931F048B
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jun 2020 06:03:58 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id n123sf7031031iod.17
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 21:03:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591416237; cv=pass;
        d=google.com; s=arc-20160816;
        b=pec0g9DnzYPWXT+SeyXRnwiZrcyolA+p0vaW3FfXT2UMPf4EGB0DJRsYmBG7JNTlEi
         RF3Cp8RDL3Ogn+Zwx6eQWbTHIAN69l6cdpkEP5zn8ix1mv4F5bTJnBB/Ff3+E04pCNli
         Z0lZb5d/ngoa9FQbFztHYJnvxHsr1hUqAlgGHg7ZTVpAvOdIYKaClPO85ZhGRUe0ykEu
         iJN+VTgadp41kE6NcWgwvh8RLFzzECJf/LvKbBUbRfopyKP/CC6nvHmRM78CyzGHr5PR
         6N+nj8RDbVu7w0CHlj5kiAVJEcbPemwW4EjucapYRGT1Rh6i7BnvWUq3ydcRiH0J24wm
         iymA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TfmjkpJUz5qCk6Pov8OBFswtMf18iFSP2ucwyKfSlt8=;
        b=AU/+cpjs+amu/UjuCpDtWTcw34MOVgoaqe7hEEEXnc2olpzX8bjaIVv4L8KaMq4ii5
         rqMXmYC4R3ex5JJXlwLskvFaaCo3xQfRMzkXsjSOHcxoaG/4NQ2biK9R+Fy9/NZwozhT
         vtxuL9NQD+jTKmlzKVEoJdJdxqaA1nZDUMBsuDXMw5t0QnsYNlW4sId7fPRYj57EyfXc
         zDXp4TgvRKWN4BcgkSD28oVU7/WXrl9q4oLwqxvEXLU7HYDIi1wWm/dukLBJdPZkGtsb
         e3EKSb9p3mE9vKdcbqbG1Y+0iaaIKQH7giXbepQm7pYJF9qwnuBCDu6H8H6pQU0ED6a0
         Z/mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yw2TjbZf;
       spf=pass (google.com: domain of 3rbxbxggkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rBXbXggKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TfmjkpJUz5qCk6Pov8OBFswtMf18iFSP2ucwyKfSlt8=;
        b=DKq0Cd80bBe+uWSsJvmKZDLr3Oh/Su3OQXSdjb5YnZ409/RkN7rMenDmEX8ctlllc0
         HGguFo8eX27pUblTGvxnM4g09TOxNEozKfAIR7L3Um2Sb/xq93b9QjAIHarEBTbmw/uv
         MgHZk4hGjJKK6IzRjfoi+u4B2uGadUajrcbcPgDq/MAr72hzQGv8Ewlg35+27NLmsXG3
         BjjcUNtGwklJt/6v3mxKj/NGdG1+MZ+mWb5H0r6p/1VKFtfOeewuTesBJcrOmcVS+Y/V
         BfviV1TzIo+nqy+nMI0/h/1/l2wd2PGpJbacIv2gAFuKZdRHCe8PYNE+7SPqSNjbhxiw
         KsAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TfmjkpJUz5qCk6Pov8OBFswtMf18iFSP2ucwyKfSlt8=;
        b=JHeumQCieSADdLAkzCHx6cBpxzKns7SioGJJQWu6gBeDzSYH+lDm8BDhR7v5pw/WUM
         3M4P0SfMJB9WjMrcwa/6P9qQFje0WHLEqo57txC012IcHzgYtnHQEn2YN0H9l8uiibeg
         HEQ98OYKFBYA50lRow0BEKHyegY/dCuXttb49bUoHb1M5Vc3xb1i//rVV4L3Mr/z2V4G
         jO/yanIF/6bwzKsc+r5/8dRwpBOXINIvYcu0ktizHl7dA+FtNvpUt0upvve4PDs17JYh
         bSPK+KhzsSD+vIyZaWIQzpK59w1qTXDaJF1hM+96hcIA2ZVTh6z5wrOCcwFPURf1fNA/
         uIDA==
X-Gm-Message-State: AOAM531fVXVhLya8kHS06276YGS7boaXo3Nc+r4ysLIMaf7xnibHbwfq
	IGVlpK6Mc3iFymGHmLPPTgQ=
X-Google-Smtp-Source: ABdhPJxVc6lIyyVbHWPlocw/lRchyS3n1OW/IzrDK0SQnYUs/zWxWTu14705ZDn7tYBVmOPknrAA5Q==
X-Received: by 2002:a92:9a5c:: with SMTP id t89mr11052868ili.280.1591416237406;
        Fri, 05 Jun 2020 21:03:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3001:: with SMTP id x1ls3005439ile.6.gmail; Fri, 05 Jun
 2020 21:03:57 -0700 (PDT)
X-Received: by 2002:a92:b603:: with SMTP id s3mr11804522ili.175.1591416236900;
        Fri, 05 Jun 2020 21:03:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591416236; cv=none;
        d=google.com; s=arc-20160816;
        b=soZZ+wnJSCcEYa23mmoyzVqNt+dIacHGrm7RzU5jmTANx0+mHxqSt4GjlivpQC6J9K
         U+cCKMtv5Ss/GVpRff1jUwLQK901NNuvvS0hxgHxBx64g2V5CZR6DalvEcL8XLczXOlb
         n46vIKurDnCpG2mlJLji+2qCUs3OkTm/EJmeNXH6VU+jNYwOnJEC555Q3op4pCTfAv46
         fhK+EAkzLh/w8oHDxYfJzAERoNc2bkzfEYmMqfnVeaG4Jv9YbJeJI3ZdwHtY7FLUaNvX
         JMN2wnJq4rnUslXWitVaz6M+EpSvIfICJX6+4HqpUJJmYtNcANe0nmn6bHiB3TlHqtUW
         L+zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=og6aLJN4ELJf8ujcyhVHLwiOkETXN2fux8N+5uOmros=;
        b=nDgfT9zkQNqFHLT7dEfxrXOqoP9RXdY3qmIMRzWBx7WAWSFf/x9UtPBChHMOSWAnem
         nIe4N9dCLKumYxVX3bZmiYeDODMghU2VAtOKHS5q0duaMtWMXf6Tt95PakXG/hHBXAHV
         DPaESY7y7QxqOQ+QSNIwgHF4yyJmdpff3GO8OAFrFx6e2nQXAxYrFeCFgMZm6m6Xsx2F
         FUpSu8UCoLo9uHFoAPloUITk6np5qRT1hd2/6lmsTG0/zEIORD62SpB4IXdaIqLovKD4
         35ouvhcdspiKJLMO87qqh6L4Y/fThSTjcUwCjZSgvuYAszKlbuBxrv4Pq0ZdqnOSqReY
         sbKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yw2TjbZf;
       spf=pass (google.com: domain of 3rbxbxggkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rBXbXggKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n16si233628iog.4.2020.06.05.21.03.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 21:03:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbxbxggkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id f1so14156442ybg.22
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 21:03:56 -0700 (PDT)
X-Received: by 2002:a25:7ac2:: with SMTP id v185mr21268882ybc.278.1591416236401;
 Fri, 05 Jun 2020 21:03:56 -0700 (PDT)
Date: Fri,  5 Jun 2020 21:03:45 -0700
In-Reply-To: <20200606040349.246780-1-davidgow@google.com>
Message-Id: <20200606040349.246780-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com>
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v8 1/5] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Yw2TjbZf;       spf=pass
 (google.com: domain of 3rbxbxggkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rBXbXggKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 4418f5cb8324..e50c568a8dc7 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1188,6 +1188,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200606040349.246780-2-davidgow%40google.com.
