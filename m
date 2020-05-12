Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUED5P2QKGQEXOW35JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B5F01CF93E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 17:33:38 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id j5sf2244741vsc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589297617; cv=pass;
        d=google.com; s=arc-20160816;
        b=t4S8N7rikTKWRyC8yb4bg2R4gB+nAlah4j8gvgqU8LMAP1+Bn0XHC1g/qHtmBzAHpx
         7WxYMZEMlGpAXEGwCbKNkP8ItqPrAUpUiVNKVIsIApr3+C/vflr6YYY6XkU3o8fvWMTm
         Rmu6vuzDOR2TG+po6Wy/QDH6+Y7XK7gzfYQKHMcAkQE6KcG768RNIoxx4zvhizkVfMrr
         3nVNndKkYe6FkidllNNbRdWtJJcYOYm27S8xrdg+h/I2O0m8KH4F06Q4bTrtQYxXt7xQ
         bH9h5krL/USY8Hp+gC7QSoRGUT3YJ8+RoBnFoatzAHRx5oPXrXvabOOHTRDASNlWEFn4
         PrxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=5AGUXBdhv3e2vDvkTTc6eaT87f4bFuVHBH/8E4atHas=;
        b=H2WYYs5SMdv5/OY2uTez17jSrqveO+bT6qtPwxECmmfP4z6R3kMlB5iLqfEkOVyL+U
         remS47K74lIV16X6ecODbnnR9hfMIi9q+OjLZ7CHMnh5fkZXU0xfSbk9UsLrgYHwxS8H
         9m2Ix+xhfGzi+hs3HfrV7h1YzqOSsqs67UadC8sstHM3/MNWBkHZu+LSTqV1PYBymBCT
         KRgjjOR+3oaGNeJFE6yRAKJ2Z1aQT4Cf/W7duW7OCmcSxpxWQb7+Eu0GsovjVkOjyiA2
         4IcpzosFoXu50gmmD0OpJZ4uEY8xu+K8tRg9LVMDo9k3Rrx+oSYFEWjyk+6cYwqb77bT
         5vOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GzrS3eiC;
       spf=pass (google.com: domain of 3xcg6xgokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xcG6XgoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5AGUXBdhv3e2vDvkTTc6eaT87f4bFuVHBH/8E4atHas=;
        b=G+IZ2CfMkSVh2SmIh8NWpLudeKctMOAIgCrcZ4vZAB0uu0BEq7UX+zcpLxiqISuxI3
         hs/Dky5o113gnigb3lE/8yrg1f0u/5U9JFsBADogfP2pRsLLMMrWZMedlWAux94A1nJW
         my9a04qQbRFDiGa+vPpbPu55dxSGUJCLygEm+YkwAJ+i1TXiaJO2buszPxPaFz945Kt/
         VzaSYXeJ5l+gsZRch1b0l9qCbomTEhRQbkaLCdJVB+25xWx8oZUnfFX9UqGRYCc5Z8A/
         uEHEotjJh1WHZa/zu7owUzhTsofNXmcHY+uLmx8fet/tUFwx9543r1ffHCqUJ3s2TiU/
         YURA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5AGUXBdhv3e2vDvkTTc6eaT87f4bFuVHBH/8E4atHas=;
        b=deftUyHZla5uDnu/EGih8kamCYxk5Vgr6loVE2UiSBT5lgBxwYEDtEMgBbyYNbsYvO
         eLD8kWr0wpU0uys+g2xCZzKoyTnNaNXVnkHhaJ1Wk5FCZrCfwx7/iWJHzgw0ajhA4U6K
         1W1LnFwS0vX1L49GgiLOq8SqWv3vErFcJxhKgAoqUJlsgZKJbWT2scYHpv5rY0o9pHhX
         2xk/qK8X+vgc/1yi7yXMuUBtZyOoRt0xw9AOhNp0XHrpYbN9MsdseC+BNO6ib9R7jIXa
         zDXq2adDVvWnuIOEwwimhrVUNGYtzla4Ntg+Y1I7V5th8dGTgYu85722CYq4ugc//678
         XA3w==
X-Gm-Message-State: AGi0PuYWFWW687SvBgrzeISVCRCEYoBURv89EaEpSUSssMGjP1n1G6JD
	0Rwxhnv0kRlMNaiA6k6YfkM=
X-Google-Smtp-Source: APiQypLuKAbwmSVMT0NffSXmXdyFWPmfWMOh6ZcVqq0vqzYAp4rzA3+uBVbUtElu4iF1aYJwq2/3RA==
X-Received: by 2002:a05:6102:3117:: with SMTP id e23mr15234092vsh.97.1589297617095;
        Tue, 12 May 2020 08:33:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c319:: with SMTP id r25ls1593082vsj.4.gmail; Tue, 12 May
 2020 08:33:36 -0700 (PDT)
X-Received: by 2002:a67:d984:: with SMTP id u4mr4431544vsj.33.1589297616697;
        Tue, 12 May 2020 08:33:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589297616; cv=none;
        d=google.com; s=arc-20160816;
        b=oQQSZVejUmOMqdPxfgskbBXDlnfeJsbA6wP1OlJMKPiesmG4vx3tdJvpJndG7z1dJJ
         VUEoawzmQGpfpV9HbbNXdTF5WK/z/grcSs86HAPgnxWMFZjhrYLeq4gvOwr1C8RytVeY
         jufGXoJCnzz7UhtpgqyT3MmXuXjFiIL85+gqzwIM/xyii7byE7TJecYpSO4IJRvhWHHZ
         vfz1TVouiDouIhpVcstulgkP8iZvx7WqV+3H0WE4JA3mMgrCzRgT/4OMczuAVBjsEcrI
         Hhms/H+UoEt8khLt33Fbh8pMKK0D2jBX1kWgHUCwARjeQCdVD/pVm4K0LTxIH+ds2iMw
         mhtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=O4K/En/qONOrXfLbIOD+SAfMhnyVUMpgoQRYv855ayg=;
        b=eplNLw/HcA/OTT123u99u5/HWk4P1uwtVhwjipv+1Fv9eM/TNPA918rqE259beCcbg
         dozV+ZqUEwJvzRi8UgnkYF/QIqX6JWtC1xNoRZcCPj/YFmstNJH52LwI2roE7IwudK/W
         LiRzE9BNb8hoDVxVQ1bmB5vjg8FX1RSMiWD7OuORDYvBFT1mqyfBd9BIcHr1yFNPjh98
         i9SvpwE7HhcsGnqf/sNu2Bupu6oZq0T5emiizhJhj4wT3hIUdxMR1gYiW6Lo9z6fzvE7
         phnSaOFKHbJLNh1QIAiFKpq9QzuimshB9n+b2Yxi/gkYMCwb2nXf6de9rSEuGMaM073e
         ztxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GzrS3eiC;
       spf=pass (google.com: domain of 3xcg6xgokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xcG6XgoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e22si898202vkn.4.2020.05.12.08.33.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 08:33:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xcg6xgokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id m9so4612419qtf.2
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 08:33:36 -0700 (PDT)
X-Received: by 2002:a0c:9ad5:: with SMTP id k21mr14928022qvf.2.1589297605130;
 Tue, 12 May 2020 08:33:25 -0700 (PDT)
Date: Tue, 12 May 2020 17:33:19 +0200
Message-Id: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.645.ge9eca65c58-goog
Subject: [PATCH 1/3] kasan: consistently disable debugging features
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Leon Romanovsky <leonro@mellanox.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GzrS3eiC;       spf=pass
 (google.com: domain of 3xcg6xgokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xcG6XgoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

KASAN is incompatible with some kernel debugging/tracing features.
There's been multiple patches that disable those feature for some of
KASAN files one by one. Instead of prolonging that, disable these
features for all KASAN files at once.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/Makefile | 15 ++++++++++-----
 1 file changed, 10 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 08b43de2383b..434d503a6525 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -1,23 +1,28 @@
 # SPDX-License-Identifier: GPL-2.0
 KASAN_SANITIZE := n
-UBSAN_SANITIZE_common.o := n
-UBSAN_SANITIZE_generic.o := n
-UBSAN_SANITIZE_generic_report.o := n
-UBSAN_SANITIZE_tags.o := n
+UBSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
 
+# Disable ftrace to avoid recursion.
 CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
-
 CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-- 
2.26.2.645.ge9eca65c58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl%40google.com.
