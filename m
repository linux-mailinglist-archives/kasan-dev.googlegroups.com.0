Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKFP7CCQMGQEKGD2ACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 6130A39DD18
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:14 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id z3-20020a17090a4683b029015f6c19f126sf12582141pjf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070633; cv=pass;
        d=google.com; s=arc-20160816;
        b=HC8Jib2/PD8kNTYfZ3MF3aBwdc5PdDJQzTaqmkZHSv5d5roUYunm7q2gBLtbwHOiDm
         U+5+20le0stxCE+RUJHRvPUZPydgJUN1TosVVHLLGJl/jVzFk6TXzsSElrivak/cktyP
         KMav9ZlhlekLqpvyIcDmatOgdCMVahHyzuRAqYqpGq34WXzV+aaql7kqW71mMnXAkZKM
         FvnrDcAq3GCMPxl0OmZxBT9NfKyT1fB+HFTkCUPWxzjcxv3DGPxjWIlvKzQUNc7IV7+l
         bTr6AjL9zU+TuYPRG4K6s86AwQsYhy8L0HUUsS1jI7Msz2IhCjoRYGZrQHmjAjnrgwW4
         gItg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ziwZX+X/w4LzUbuP/YO+iA8FQL8YGYoWWvNqj1rX92o=;
        b=JSPbHkbwB4W2ZA0uNk0Vn1MfDnHl8M8x2zL+dMorInHBrj4EmcQkmfsWFu/Emw8HpY
         gJn6BH3hOhbxCJXxmYFYCZQYbNIKKm/EHvmuoR4+0gTY/BpD4MLc/mrUIjcTLX1yxjAu
         sgx+G3Z9NEvoIlBtwfeV5GtD8LxB/2sbmW25YFAsUM5q6rdYSJp2ziLg7PQdVNTMP1CM
         4Ld+sihbv9zPFcf0vW7D+9UI8//pBAz1kgiDetfgPg4d13bTOau9TwGZ7K9NqFiAS3jU
         F6D9ATTFeNQTUcFoO5afK0nL0ioHfkI1lDyF9DAKAqSEyWudU550kLkTW8rQQvIt6U9w
         fuiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HWg0wtm6;
       spf=pass (google.com: domain of 3pxe-yaukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3pxe-YAUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ziwZX+X/w4LzUbuP/YO+iA8FQL8YGYoWWvNqj1rX92o=;
        b=ngyptksJugS+MnA12iRTQ9lGKqcbJxQmWzIwV2aMjozpce5/EJY5ytIJ6xLRZv6GR8
         5tB6zj87zmvecjud5E607tDk4gJWJ6i/BnBrWLSDbz/Ama1BiZtDiH5l1a4CWdKoARcs
         w+ZLOjb0kWFjNDcCu6Jfc40gaV8Ls1I/r6xfH47AHzVvHFmlQFYN5bc1G+dpcY9/liCC
         CUPputVN5/3hNxYAeRk5UtdSkTzBTtdUTe4BJn7K7sOV90xvuvASfxgJ6SVS8p4Jk5DB
         FrSXXHuSP79bam/K8dIfrLnFgp9iwvUmfkJw3WCoiZDV+9G74tnKPKrdbZqHqiBVV2Tn
         tm1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ziwZX+X/w4LzUbuP/YO+iA8FQL8YGYoWWvNqj1rX92o=;
        b=Hzc7VTEJItXre6FNrMGsCZSCHn8i/XUkSV68SN+ipXWUC1dmxY4vyk+E1CkacuEZAN
         3+glpAR93VGmR2S7ru3MuGczwFDuQmgYuCuUl4zs4R4V8M6espGs5McakxiYN3Ft6iZs
         0pZ7vABK9z+bVotoPGLuhQ5xo2JrQO5wf+Cfgm1ExeoHwGNtSEwFG7gcikwLF1Yyz/9y
         NG1rB/mzp5+SE17f1Psj0q2iqdjj8vCzWgh/D4SZyL5PDJsUYSg+qBxNssbJNSUeE7n7
         YrMPI7RABbMzErfCuoPPoocO90uWpuNGZSeKfA3d3kTVAveIQeLNQczxCuV1LuIeuGJs
         Xvnw==
X-Gm-Message-State: AOAM531RpszvAqV+HNxTQaHpz6TDrTwb7UkWkZ8owD6lk0BdxF/Wzsw4
	g+QyS9m+HGpw/3HIawJrN2w=
X-Google-Smtp-Source: ABdhPJwWPq9qy8eSuMyn3sUeOFwM6exWIENt+/8I75T2gezrTWvyLjNxrM38Q/3adv96X2+TwPzHXA==
X-Received: by 2002:a17:902:aa96:b029:10d:be4f:83ac with SMTP id d22-20020a170902aa96b029010dbe4f83acmr17936831plr.38.1623070633037;
        Mon, 07 Jun 2021 05:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:414e:: with SMTP id m14ls4897351pjg.3.gmail; Mon, 07
 Jun 2021 05:57:12 -0700 (PDT)
X-Received: by 2002:a17:90a:448c:: with SMTP id t12mr20721519pjg.142.1623070632382;
        Mon, 07 Jun 2021 05:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070632; cv=none;
        d=google.com; s=arc-20160816;
        b=XKGXJThEcN9mlNTvY0a3u5/vxtgG5G2zhSFO+K+pygulrVxVU7c6EKRrSrzkWoJHXD
         jx+QLyLksdg5RfG7RV2Cm1c48tZPWtFwLsfaCwFfMnVkMAwRAY4c7XM/Ao5AjnghYB7A
         b3GhRKIKsOHtOxRD7VhnJiqPsy3qj4+jORra8QLL0msO++mdz96DEWNOnWAOuQL8PyDv
         2oDdHmy8aCb/oRJ/LQswzGs2LZrbZKMQLlwo83esT5XtfgZPJLzX3Ke012+uLUT61t/8
         k4xkhjPzjM0zfubR0uS9u34tbNsH9n8LBkfpEfmCPkkfjApqaYFcLseggKldKqo2fPFC
         rpaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=52fGvbimaCnuRXDzSCXEKwhsxycQvh+gPJni4oHCnrE=;
        b=sJ/wm1j/QZXYDoASdLEMrfGlF/ZORsJw1kXWTrR9RGpilIDkVx9JpAG2VPp+gFn2nW
         78bDf2doohJzCnWaiCgEBKNUVESolQo8Kh/SrHzyY2rll0eIpdZbgDmn86XP5V9TQGqm
         jBeWbL88f7teD03UEK8GKYo3dJi24UaojEiYOcXs28oOTT5mogdqdJEmUT0PEMQKW5fH
         eBOlV++EV5wmEJRenFN796voiOi7kg4c//AcMb1xU3v7gTcxEe5YrIzDWVhcnF9xXlj8
         bjd5+jTsrsiYgklfeXGfAbPgWY2EoPmRzZ/PupqAxX9DshtD8N1rvk0BZH7wEuD00jV1
         Ja/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HWg0wtm6;
       spf=pass (google.com: domain of 3pxe-yaukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3pxe-YAUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id o15si995099pgu.4.2021.06.07.05.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pxe-yaukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id k15-20020a05620a138fb02903aadd467ff1so409107qki.7
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:12 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a0c:c587:: with SMTP id a7mr17495867qvj.59.1623070631856;
 Mon, 07 Jun 2021 05:57:11 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:49 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-4-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 3/7] kcsan: Introduce CONFIG_KCSAN_STRICT
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HWg0wtm6;       spf=pass
 (google.com: domain of 3pxe-yaukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3pxe-YAUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Add a simpler Kconfig variable to configure KCSAN's "strict" mode. This
makes it simpler in documentation or messages to suggest just a single
configuration option to select the strictest checking mode (vs.
currently having to list several options).

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst |  4 ++++
 lib/Kconfig.kcsan                 | 10 ++++++++++
 2 files changed, 14 insertions(+)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index ba059df10b7d..17f974213b88 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -124,6 +124,10 @@ Kconfig options:
   causes KCSAN to not report data races due to conflicts where the only plain
   accesses are aligned writes up to word size.
 
+To use the strictest possible rules, select ``CONFIG_KCSAN_STRICT=y``, which
+configures KCSAN to follow the Linux-kernel memory consistency model (LKMM) as
+closely as possible.
+
 DebugFS interface
 ~~~~~~~~~~~~~~~~~
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 5304f211f81f..c76fbb3ee09e 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -183,9 +183,17 @@ config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	  reported if it was only possible to infer a race due to a data value
 	  change while an access is being delayed on a watchpoint.
 
+config KCSAN_STRICT
+	bool "Strict data-race checking"
+	help
+	  KCSAN will report data races with the strictest possible rules, which
+	  closely aligns with the rules defined by the Linux-kernel memory
+	  consistency model (LKMM).
+
 config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	bool "Only report races where watcher observed a data value change"
 	default y
+	depends on !KCSAN_STRICT
 	help
 	  If enabled and a conflicting write is observed via a watchpoint, but
 	  the data value of the memory location was observed to remain
@@ -194,6 +202,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
 config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 	bool "Assume that plain aligned writes up to word size are atomic"
 	default y
+	depends on !KCSAN_STRICT
 	help
 	  Assume that plain aligned writes up to word size are atomic by
 	  default, and also not subject to other unsafe compiler optimizations
@@ -206,6 +215,7 @@ config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
+	depends on !KCSAN_STRICT
 	help
 	  Never instrument marked atomic accesses. This option can be used for
 	  additional filtering. Conflicting marked atomic reads and plain
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-4-elver%40google.com.
