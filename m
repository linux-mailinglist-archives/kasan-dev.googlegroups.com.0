Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXK7SEQMGQENQ57BHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 319CF408A12
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:31 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id a27-20020a5d457b000000b0015b11fccc5esf2555213wrc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532391; cv=pass;
        d=google.com; s=arc-20160816;
        b=Djnfi3ymw1SLmm9YsdYc8TbCStuFBKbLMte5Ehy3F39HGJUGC1BQjF+4PxL/amhMqa
         sf2vYjUgGMvMfaR+o5uGxbfBpT1CG36Kw2rq5YochKZ0yq/mgh8NBde1JSGanTaMQ4lS
         im6c8Nf0hzkQOUKyoTEWN9OtegnSZTZRldNKB0BCbgOlu/td8pCRPpWqnu3SvFuycEjG
         9O+9FEX3h+4mfzcKGyJIySc0/t+DE9zlHn2uk7c6EdDzdQj2N8N9QIHNlYEw354JRYWV
         z0YX/wJMQL2AgQeDK317sGOfpwhtMszjY3PPfLWVdwaPgPE6MEK4++9M9rGxg5no2clG
         vJ5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1tcl53EOVdEOUEQK39n1GRNwQJ968KILjWacViNCo5U=;
        b=1FR1VeOzP4rIMkud4rZPTZwRz7/mzuMRIFh8hwIYg5VNbJ5DmWu+SfownzsOZ6zyHP
         BxbSi6fgzdJUNJUnR3EdJURMVeMBKorE3PJMo8SLS3jgjIftpa/jB87MxE9wpAWmd4MT
         ghT0YtNzm/W2tCu1k1n9vcz932XG/Q+R8qk9ATPXZXWzg7jFbMs9Lh+G1zwU7K72yi5H
         GnWSa85PkYTMiGkVktS9xr3bUeixTrEHIFQkht+crHbEaCIo6KHCbYMGDoR0lG62Pu4R
         3q8B7G1YPuhu2azudtZNwGX1f6HHvnSw5UZenzB9G+lDF5bI7/wWztJsVbwRgu3+tR8L
         t++w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eEroU4oV;
       spf=pass (google.com: domain of 3ztu_yqukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTU_YQUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1tcl53EOVdEOUEQK39n1GRNwQJ968KILjWacViNCo5U=;
        b=ZkKzBw/z9ZNKB7I0JahDTLCCiPvztaNhM50b4E4jCIB2di8r2uYengwDkZmw+j4qDe
         LzhUtWcROnVeIRxboYqH9h34GgjDRpp8glOwiQsBape4+JEdQFmPTFvgkqwUKHwJ7Skn
         ytEb5L5ha1cjZpo3nfVf0JPktPArAtN52bnsgQU7+d1Lr7VpLGIh+3vkrnB6/jvYJcA2
         bLID5yjFcl4+WjVbBxitwvLsqPgMY2ORBFM6Aji7UXM/GDkPNAh6DoUZCsoyKUXbt/5w
         XQUgn/BheANS0OZCzrGOXywnD1LABMSrGzMZwDlVX4GMcYwfVEe19XYx57xybHfwWFQ6
         S4Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1tcl53EOVdEOUEQK39n1GRNwQJ968KILjWacViNCo5U=;
        b=OoADqI61e5/Tf1Gy4PPyIxRswjVdXC7ZpYBTwVhR3sOf4QjKGYkTPQtp0GryEO//Sl
         91iTpUfiFF+OQBjUE8KetVvrl2KgqYsmitDJ112UujHYEG6k/4E3CBGPc9FCo4ZT8IRa
         M8KhZzepUGyAPJcFNJVWEztyvso/VYrinfh5CnxjDk98MoVR7YAFYesLAQOV0nqkf61K
         YBRAKmSyirN3zSYQ9GiH9XMREfXgWAbqSyueIrQ9QVbJ9Zge+b4nXxla7H/TedF1lWKb
         OSCl6/kpqJeR3wXji1o8xvok8CVl6M6Ereb/57NZ29zC7hPa95kGWuFFCRyx5MLziS/t
         7/nA==
X-Gm-Message-State: AOAM5321bYI/+t6uXoD6zswyB6+1NuxO/y62Dwgn5zA1K3UyMTopr74R
	h+88FbdoyHut+ha/Ppi2sBk=
X-Google-Smtp-Source: ABdhPJzDOnq7K8LmiiBlrLQdT6uQRMamMdnfdSOh3JpPhBAkPz8NNy9OAVxnwn4cKxiKhcyoLKt2OQ==
X-Received: by 2002:a1c:f206:: with SMTP id s6mr10507820wmc.15.1631532390938;
        Mon, 13 Sep 2021 04:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c2b2:: with SMTP id c18ls2811360wmk.2.gmail; Mon, 13 Sep
 2021 04:26:30 -0700 (PDT)
X-Received: by 2002:a1c:acc8:: with SMTP id v191mr10694017wme.146.1631532389966;
        Mon, 13 Sep 2021 04:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532389; cv=none;
        d=google.com; s=arc-20160816;
        b=ZgjrCC9b/Tc1xiiz3ijqoIAmdfktJvtfz8Qc0nQqU5z4xX+713LFOhepNZqcLrQ5aU
         OfxY4Zo6znfPbYxuxpPCa0gvTHQSPl3MMVu+b2z97tcUQi3Qwf/yQ5PEF5OO5Nb/W803
         r2lEPU1nk3t1zsqos8mCZf4Flk6zsC37gBcXo1QW7al2sdppCosWr//xkonHgIlykiWa
         mSRzhY9uGda6zeF8fpmmKPGblez3ZGd08iEqWTDuduBmZ8qD+k3C/xj14Og4F+MXz2rC
         dm3dH3KvlaW72VzgEohp9HUWKWpum/D/hspNiUYuB2dM9voEUSvwqAgiGpYJagu9BZ1F
         9zkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=jCMn+6PWYm/AH96CM8EJiUE6dV7GrC639I1pxBug/fo=;
        b=h5LoFh/1Dnj/GTQVHwcT8TaQ9NYc+MFf5NmWDUay/7yWr6740RWSF0Pj05hA15smby
         oWTlp2udp7Ny5CDz+nObXYEPBr6peM4H9vKgooJmTUf91EEZhpSWtnibot6boQEtqNEo
         VtxD14SfT9PipdredO4p7Jq9aE1+ISqyo2gBbT3Q13JacUXeJExSYOypKfof6j9lRmAA
         TAscMTkS9nKWQw92P85uTABd48oHRYW8LGbQeOSEc8wdrhVpM+Lx6yz5pc4VNvs6o7Mx
         2plPii/t4522IWIipTE6az4jXJ6X7RtOaiDvUjKtYWAfjz8XEKvRaz6r3JgiBLWEd9Ou
         7EGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eEroU4oV;
       spf=pass (google.com: domain of 3ztu_yqukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTU_YQUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b126si759829wmd.2.2021.09.13.04.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ztu_yqukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v15-20020adff68f000000b0015df51efa18so1218967wrp.16
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:29 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:adf:e745:: with SMTP id c5mr11878126wrn.321.1631532389487;
 Mon, 13 Sep 2021 04:26:29 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:04 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-2-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 1/6] lib/stackdepot: include gfp.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eEroU4oV;       spf=pass
 (google.com: domain of 3ztu_yqukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTU_YQUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

<linux/stackdepot.h> refers to gfp_t, but doesn't include gfp.h.

Fix it by including <linux/gfp.h>.

Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 include/linux/stackdepot.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 6bb4bc1a5f54..97b36dc53301 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -11,6 +11,8 @@
 #ifndef _LINUX_STACKDEPOT_H
 #define _LINUX_STACKDEPOT_H
 
+#include <linux/gfp.h>
+
 typedef u32 depot_stack_handle_t;
 
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-2-elver%40google.com.
