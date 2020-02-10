Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOIQ3ZAKGQELXHID4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A809E1582DF
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 19:43:37 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id n23sf5465217wra.20
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 10:43:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581360217; cv=pass;
        d=google.com; s=arc-20160816;
        b=iKzQx0tv8s6UL/t+ST2ICdzw1yxxpqvNRP/ZBQW3UOembtiXqv5D6jAEtzGwjLk4fp
         ibse8p0OQputF2OIAghsuzFT8It9PZVf4JC2+hRYVxr9T7d0v+rRwSP0HPC9xTAhvpUI
         tkMkw2ngM3BpiRqKxafRJ7Eu1bnAUh3l5Ea9+1HUwV2MsQhRuhSxiUU/1ryt3AbXSAWa
         sfgYQNqRC98VVLtgrCE/PbtRY1v0N3q4kbYUOpNtwQ7G0IlHRcEX0L8P1f3K6Wtr2ohP
         6ZE9mCI1mhx57pEw8cyyTQDOgbBNbaALbOrGBNCuegQ7RfI4cwc1um5ZiQK5hpIIZVaY
         lxew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=dw0o7NlWw9rBb9d/1qOmoBio+Crmujgz/JPMK/NkD2s=;
        b=iFunCM+386UwQ4QpyFxUs8UlQ2/9ytzOlkikZE3zSKr1mPeVNHecN1uzaXehlKc8q6
         TMpYy4kf/bRFfsKyncZtNxl9CacC/AnEoA+ZnYrdtw5Xk+bMG2DG1OjKa1vRvfssF/h8
         wpjCBz634d8XniPi1mojmFSxcrMjav7xQMN12Lr2rGHIuRRBqDr6lmbVxm6fCgdmDqqj
         XfDlia4+bmIkPdWU4/b01PQf+BxATCgSM3XNeUZJP3xmhzQCLCOBCdPukQrH1bKMg5kV
         DSuW7G2lrp2r8pWwpUnbbclgGNR+kyfqgjFYpkkrSRyLt21dAu7auYIpRi9ZpZM5sdVk
         meSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vX1tRBro;
       spf=pass (google.com: domain of 3varbxgukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VaRBXgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dw0o7NlWw9rBb9d/1qOmoBio+Crmujgz/JPMK/NkD2s=;
        b=fvoH5rd2UCGIN5otAjC4FBw/hIpGhqVe3A3SUMUQo2bIFgGQAxU+Awc/BwIlBa8S/T
         Cx7pCtS9wJ3BRdDrm3oPlUNTo6rTJl3lCZiZYx+eqteFJLdPo8TO9NBciw4iilpy4a81
         PbDwKI+PsYtzQ2e8PNdyLOOfi64yEAPeiVvypFZvvwuba4ynADDu4fyqav2aS5dhrsMB
         B2/VBz2YBe7GVhfmunihLbFYtPWMl5el+ug5XEArLlfkTnKvKb8nuye4zkKn6xfMocD1
         zrKPNDPbdXKoa05nkfQNT8EQw7vivOKtscRRD0gmCnP1IiQAzd5TuTudm8jJMPEB3eS+
         sOPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dw0o7NlWw9rBb9d/1qOmoBio+Crmujgz/JPMK/NkD2s=;
        b=RIBYJNf50C9CJLdpUuikVkaDqJbSxc8Ea7W30lYOfpVsoANMls/ZDP5xSpzdw9g7IB
         BPEWP8HLbS2KGK7JjzUZEqa/HEt5qXvpz8NPga76e8MiP1OgB3W4kK9JMCPD9MiF1BPY
         6hKHKtwOUiMM9qAPMzQQM0C63de+NzD+q4PY8gaVuKgVVkLqUXAMiMEi+FhgwvSAPMf7
         gE20skz07gByDofbE51pLLxTNDXA+93Twx0L6kT1unW0HwWfmcOA7Af627m+9GnJ6eq5
         2HNofdQR5qCeBwJVVpgpULgcJ7dWl7RESOiJ2jaA10XqtV+mItqDZrJvyJ8BA5UKQKDS
         N+kg==
X-Gm-Message-State: APjAAAV1TcIeAOOCkaOoV6wFI+msZovfLaTl1OwUzc5slADKC0vep5nK
	BurPdDocEUCXlsOQbcBYl50=
X-Google-Smtp-Source: APXvYqxnoWaSd8dIprIImz9c/R/2wefRkakxnsnU5Ucfq7ZHei7HoGgWXMQPoUG0bj2g0cclPQqjRQ==
X-Received: by 2002:a1c:545d:: with SMTP id p29mr350095wmi.91.1581360217429;
        Mon, 10 Feb 2020 10:43:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d847:: with SMTP id k7ls6011419wrl.0.gmail; Mon, 10 Feb
 2020 10:43:33 -0800 (PST)
X-Received: by 2002:adf:cd11:: with SMTP id w17mr3563581wrm.66.1581360213477;
        Mon, 10 Feb 2020 10:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581360213; cv=none;
        d=google.com; s=arc-20160816;
        b=SKyJYl1SLxN3vu7VudUCpYW68G3R56uEkHEiRamN5emufyGOhkvmM7pF8tdjJyBu8R
         RFc7jeN+kbbhxNLojFmuuj3E1GrRNneXmu1SmZqmypgaOEYYidlmuha/UjPI6Srfr+me
         0+zVP1OlC8vvgr6kHNBUbHLGrdlrCfrv/CTXh8Rfs2+BrXwpa76p2jaPUj4NI1M3Gunt
         QUnqKvFZ96I203PJhmn+eiJasqk4rp+jmU2Dt5qvpcu8coHpxMSShXwbyPGWb3CqzdV8
         WRN0KIfIa/z5Q8vwi9CJobBIxjIHabg3u4dh8qgO2iQFhYKBf4lyMtqpSeHdeOHr/HGA
         dIHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=20vSWayu1UQKfLLBTKC/qiTBVSsqf6DaO3yhuXkLFDM=;
        b=tDah7JmBGBrAUZ9PtVfVK4EC5l1zOQVI9ig2UQDbwq9PeATQpLnP3xbrueR+XDIZoF
         Ca4bZv+Yoq+0r8JGKbOkS1T2pefGQqKHmKOLKwPrcCeyfEcoved06BaKlsuNnGgabQ2T
         SWhTyw4rxONhGrbgzq2yOUOmMXOt7bnZkWLc1ayx3jdntu9vkadAFjqihIvhW7hzux89
         yI7wMYvXDxLuw1mlSc3wsnjCsDLzdDYrYpTZ7HBWzYlwUkz6ycPcBT9W0a6CCgl8XEe7
         D2NbHudedAN2qaZ5DPCvaCs17+88QPa+kn1BhDoFL9+0Rnyl5veTw4nD3o4igw6XuPS6
         GkxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vX1tRBro;
       spf=pass (google.com: domain of 3varbxgukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VaRBXgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p23si11670wma.1.2020.02.10.10.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 10:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3varbxgukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so5464276wrn.19
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 10:43:33 -0800 (PST)
X-Received: by 2002:adf:f787:: with SMTP id q7mr3295671wrp.297.1581360213051;
 Mon, 10 Feb 2020 10:43:33 -0800 (PST)
Date: Mon, 10 Feb 2020 19:43:14 +0100
In-Reply-To: <20200210184317.233039-1-elver@google.com>
Message-Id: <20200210184317.233039-2-elver@google.com>
Mime-Version: 1.0
References: <20200210184317.233039-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 2/5] compiler.h, seqlock.h: Remove unnecessary kcsan.h includes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vX1tRBro;       spf=pass
 (google.com: domain of 3varbxgukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3VaRBXgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

No we longer have to include kcsan.h, since the required KCSAN interface
for both compiler.h and seqlock.h are now provided by kcsan-checks.h.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h | 2 --
 include/linux/seqlock.h  | 2 +-
 2 files changed, 1 insertion(+), 3 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index c1bdf37571cb8..f504edebd5d71 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -313,8 +313,6 @@ unsigned long read_word_at_a_time(const void *addr)
 	__u.__val;					\
 })
 
-#include <linux/kcsan.h>
-
 /**
  * data_race - mark an expression as containing intentional data races
  *
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 239701cae3764..8b97204f35a77 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -37,7 +37,7 @@
 #include <linux/preempt.h>
 #include <linux/lockdep.h>
 #include <linux/compiler.h>
-#include <linux/kcsan.h>
+#include <linux/kcsan-checks.h>
 #include <asm/processor.h>
 
 /*
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210184317.233039-2-elver%40google.com.
