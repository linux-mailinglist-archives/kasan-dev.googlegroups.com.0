Return-Path: <kasan-dev+bncBCMIZB7QWENRBNELXSIQMGQELPC4BRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 675564D7E1D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 10:07:01 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id y23-20020a0565123f1700b00448221b91e5sf4490282lfa.13
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 02:07:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647248820; cv=pass;
        d=google.com; s=arc-20160816;
        b=lvAyyZ+vakwuIWmXisBozD8hmH5U7Lq0MrmaGYkUETOd5ybGdOKNWR4Wa5p6G6vKx2
         F5TrglUdU+qoaRvcoywd/AMfYYhSwKUctnaUaI7uxAnJTg2IJUFuP5Hxoxtt5dLuj2Qq
         9noGB9ZcyAWtTwPI83bz0K5JVTU7u3NMkxPWn4Zo08RMXq8DgnTxXWv71bFAD7LoQjdm
         I41NwLQ1BCkLkLPZ0pZsTu4fQG/GCMXLynFrWFMUUcElrrd411LdEiOAHH7tdL0eTlTb
         npDNVriTIuWY39xlc5+/wor6eLLLvHJLKr8gOWBNmi1qWbNPmwW01rEXqS846GZGFiQz
         z29Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=vsNfFyXkqTQlvqRQ4p/cZIQ4xKePocC+M3sCr3oHVvg=;
        b=gBHD5eesWlngnnLOaUf7Ae8nU5EQwQs58n7+I81f1k7T0MQn5aDHReL+35pe9cIuD/
         0Nk4ivF3A+53Fps1heicQI+5ZZ/EdcndWlxbXpv2sSnICGZVi7T0FylNcKGLVBupcF/4
         vyDkbjd/FJvRW5bjTIKNf2eT0TXstP6Fzp0Miqwsze2CFSN8W3wmtA6cWAVuDfhMzONX
         NfKJDgs0Ko08T5vX1SWsqccS6LV4/4FY7+liAkqdy1mIZ5s1r5xlpMM+HQ8Dc3+sdUlE
         0q5DhJlXrZoiVcNP9ul7tAJYQLRSgHTizeYL1hD4KFNtraOP8xPt0VTrq19foMsvdWfc
         g3Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WYLlAG25;
       spf=pass (google.com: domain of 3swuvygckczizhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3swUvYgcKCZIzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vsNfFyXkqTQlvqRQ4p/cZIQ4xKePocC+M3sCr3oHVvg=;
        b=t1BIJ6uO05lfkWLVnFG7ACPZe6UWpkb0ganMs5baVJzHPQ+nSIF3WrcvAhpgDbpSuj
         JvYKDe5JKncNPzuXXoPmb0xo+vOYULJJ67J8SP52HTwfa28/1oHPQEyZPg8XzT3R4WI1
         9sCuwT0riDPU2NsfdVIgFUa9DJ5N4zPa1Q8AUQuW1YfQ8Qbfee29aTtGm2bEPQcJyNYV
         tMnumlCBjsGW6J6ySu+YKQlgtdfo6VaQjs0lXGRTTG6JcLTDQWoIGVmNWSewgbJErFoQ
         QCysQzzyeRPnL2FswWMDC7J/GYdWAmxtrV4QEJzgnWshJLoDel9wEKtmAWbj8NWYjYaM
         pOwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vsNfFyXkqTQlvqRQ4p/cZIQ4xKePocC+M3sCr3oHVvg=;
        b=rrtIN/95SYzPXE+pKeOPmdNWyEBB+c836YsSi4l4MwxgR1ReEhkCE2P8DjFfd3FKA+
         ULmBvW1yBzdhyXMq4Qq8bvi4iEEoa11UEjn/M874hm1cfcLNu5zhd9gzCRBPin77uxr3
         zJHSeQbGwkGdmscpezcCjy/+5xWRJEoy1fBMoYxdk5IXwaDowv89UxhanX9200MQge3F
         V9xm8vzEIm4q/DN9vv3lNget+s/qf5/igOp/Nam9jGyAH99UfSEpqLM1OA6/DOiwxdiu
         eCuXb+jJiIiS//6y8N24+z9iAAMdZ78cPvUE7KcB5M6Yk72iAhnSb1CWEXAR/pdhh32y
         Z2+A==
X-Gm-Message-State: AOAM531JUkTZNELVHDab4SKzO+y984BQ0IrPT5DBDWGNymb25mIU7iAU
	KoqmRFkHpXoVcP5rqynoRK4=
X-Google-Smtp-Source: ABdhPJwDZtJd+eYFmQHqgDW843Ty42GTfEjNjL79xPwGsqjajfu0VTqV0da3+rxVxZkziQvR/kZQZQ==
X-Received: by 2002:a05:6512:688:b0:448:83ae:ea4e with SMTP id t8-20020a056512068800b0044883aeea4emr5744986lfe.113.1647248820637;
        Mon, 14 Mar 2022 02:07:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b05:b0:448:696a:ea62 with SMTP id
 w5-20020a0565120b0500b00448696aea62ls1427692lfu.0.gmail; Mon, 14 Mar 2022
 02:06:59 -0700 (PDT)
X-Received: by 2002:a05:6512:e96:b0:448:82d9:53b6 with SMTP id bi22-20020a0565120e9600b0044882d953b6mr6175621lfb.33.1647248819630;
        Mon, 14 Mar 2022 02:06:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647248819; cv=none;
        d=google.com; s=arc-20160816;
        b=TiDNG9/7GC0/BpHAOrcXgmtx9BrUbvMVoyc4jHdZ/DZKhGx1rpen45KzM8Myqd4QQf
         kmyGpodKyvPBZ72xlEfsQUNsnWhySVaolIt41wWHQz1m8qk1ARKAVR1caireUpKrddFM
         SKHwUlE1CFCgb9m1mRElU/I877/qpck600pfm71AQzedUo9YLO3fh3hr6e3ZWD/qhbvz
         wru+O4zdhtNNnMYY2/1SR4LQIRbRiK4VoigfTjPDcqSRTyu9we5Vm6trviJwoCWJFR+5
         J40/f8I3w2P0BVAjiPIgEBK0JIc6y2Y1QgGKcAd5iKpnEREX8dv3tX0Dhbl7cN7qWo9w
         oLxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=a4IR97CqDqOCyGomwvsbWVLvZxZNOCZYNgnnVH7AcmE=;
        b=aMUyDtosC81LedfiQfCv2zIHaidYvilXe201IVPwnRiFwfruvTH3xGCdr7iEKmqqFW
         ZYeOYXu5885dduslvoDTK/ItpqLScwVmpzEZI45YZU/7j31h1uqMLQ/19SOoviB8pEX6
         WoG1BXAFTeeYitEOC/3nJoO+KdDFzPd1H8lrPdMOVJbXudoadma4ZzL9itEZsGhydE4a
         vnBc36t6ClCnn0PYpEd9iDhA8BwJZVMSiufAOlXUF0XHfQCphWv9kpAk78q03vKTxNsw
         50b6e+zOYc8OA7E+tFWFpBJCLTxDPn3wysP7zIaEwfOVANytV74VCQ89GSvPQzogzbim
         QeKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WYLlAG25;
       spf=pass (google.com: domain of 3swuvygckczizhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3swUvYgcKCZIzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m15-20020a2e910f000000b00246477237ccsi1082564ljg.8.2022.03.14.02.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Mar 2022 02:06:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3swuvygckczizhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id b9-20020aa7d489000000b0041669cd2cbfso8309600edr.16
        for <kasan-dev@googlegroups.com>; Mon, 14 Mar 2022 02:06:59 -0700 (PDT)
X-Received: from dvyukov-desk.muc.corp.google.com ([2a00:79e0:15:13:44f9:d689:30de:bc71])
 (user=dvyukov job=sendgmr) by 2002:aa7:d491:0:b0:416:189b:e43c with SMTP id
 b17-20020aa7d491000000b00416189be43cmr19392136edr.41.1647248819017; Mon, 14
 Mar 2022 02:06:59 -0700 (PDT)
Date: Mon, 14 Mar 2022 10:06:52 +0100
Message-Id: <20220314090652.1607915-1-dvyukov@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.723.g4982287a31-goog
Subject: [PATCH] riscv: Increase stack size under KASAN
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
To: paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, 
	alexandre.ghiti@canonical.com
Cc: Dmitry Vyukov <dvyukov@google.com>, 
	syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WYLlAG25;       spf=pass
 (google.com: domain of 3swuvygckczizhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3swUvYgcKCZIzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

KASAN requires more stack space because of compiler instrumentation.
Increase stack size as other arches do.

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Reported-by: syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com
Cc: linux-riscv@lists.infradead.org
Cc: kasan-dev@googlegroups.com
---
 arch/riscv/include/asm/thread_info.h | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/include/asm/thread_info.h b/arch/riscv/include/asm/thread_info.h
index 60da0dcacf145..74d888c8d631a 100644
--- a/arch/riscv/include/asm/thread_info.h
+++ b/arch/riscv/include/asm/thread_info.h
@@ -11,11 +11,17 @@
 #include <asm/page.h>
 #include <linux/const.h>
 
+#ifdef CONFIG_KASAN
+#define KASAN_STACK_ORDER 1
+#else
+#define KASAN_STACK_ORDER 0
+#endif
+
 /* thread information allocation */
 #ifdef CONFIG_64BIT
-#define THREAD_SIZE_ORDER	(2)
+#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
 #else
-#define THREAD_SIZE_ORDER	(1)
+#define THREAD_SIZE_ORDER	(1 + KASAN_STACK_ORDER)
 #endif
 #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
 

base-commit: 0966d385830de3470b7131db8e86c0c5bc9c52dc
-- 
2.35.1.723.g4982287a31-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220314090652.1607915-1-dvyukov%40google.com.
