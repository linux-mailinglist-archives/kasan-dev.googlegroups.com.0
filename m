Return-Path: <kasan-dev+bncBDV2D5O34IDRBIGBYCPAMGQEX63XKMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC35267A106
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 19:17:05 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id u9-20020a544389000000b00363be5d9f42sf4799383oiv.15
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 10:17:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674584224; cv=pass;
        d=google.com; s=arc-20160816;
        b=CNf+WCroTfsizfaA07S8BBTmy1tQUtdfOUO3/fOabhgwDapiEynb8eMrAVfHj55lXi
         93Cd5AZaLtV/WbmBP+1SvCABWUniNNnNbCirMf+Dxk/ZwEF7+L1wjBJW1Aa+T2kIyQEk
         Ha4X0L0zImn9ji40g7q3n2lJ449U+339McRsf86TcZtwTm6+Mm3BNj/6ZQKb8p3MlH57
         sme0lxu8H0vrkn1n7t5Am9coRwldbM4EjYQC/0km/emUmhvRAQG8uMKoaHavFwr0DHHW
         XQK+PekAzOuhhD+ty2W5IvQ0GRIA8exGOfVaJC8T2Sd9UQNhGGnNM66j71Qv7u2ElQE3
         m9Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ArMqGh/ZrfkA1W9u0BXqaMBu+a++OWWvQVBbDGIwSTA=;
        b=WvT1024ZIEAWJc/1hiLQAPngFnE8EAHeALLyR4SGFoAXgl7rurXwNnML1IDSvzHjUh
         R72Mu/+e+iMiti6sinao7odYN8MZFLV+Y/DVmfYyxiRQPW3lVHHuEzmLPRuY5Etugd2B
         zVf0ipz+0KcRfa1COmNR7jpzgUEIWM0GilCJZhAPAPWhSNPSJAaDDCNU8MKN9fuLqYqA
         lyNvxUqR+Uc1NlVHVQ2Zk/x0ONk3GrsbF8/z+GbNA0gqs/BXpGNUShf00SVDYGhkFy0L
         RVISOSqx/OSITnRB8t0AJrgaDC2GV8Shi4fUjHFoi8E/bKofhAhE1Zdw3W6C9SNiCzBK
         2pjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=uqSc5bi6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ArMqGh/ZrfkA1W9u0BXqaMBu+a++OWWvQVBbDGIwSTA=;
        b=NPD2bVCAulS1PbfryzcgTgaPQyOIO7gBCONWMwDuBgkLq/0m8dFTfmL5Xhymh0baN3
         40KdBjGFB6cMotPIYgKG0NThtEZt1TlqKp0QjZOEJJNUVA+Q7zaePEpxSv7kr126myi3
         MQyzTSN+CVobWvkuQs2E3PRui/tK0eQAh0BhvrKJPWJ60clZLIw1EyB6EDaPl9ljjv+2
         5mWykn3vyTDX2HYlER6MgFyFabOAB84Om8RmN33BMyTRillNsJT6g0SQgl+gwtLZh28X
         IUa4bhzCTgiaLF7yfmNMalqvaA9NofLietULi6qVvN2JvyFnhfqn9NnXsME1H0NtgAvy
         jJCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ArMqGh/ZrfkA1W9u0BXqaMBu+a++OWWvQVBbDGIwSTA=;
        b=KU3aWDe4pIX69vuCb5kpLEkcTifgCDF5G1xuNU92vC/RSOo0blkytAilC8sC3pyDGa
         tp9MdRh7B7NkgkyxDtH+jHCHvtBGujVEDW9KGWybh3JyyzR3Ia9Yt+FCqLHRtEzIcrw2
         b+piAzTF19i0pjsbY43S8x8dnYe8mriYLPnGjJkY/7RlUqvYiYPReM0J5GwVMXB6DWft
         /SbuHVzVMQgBvbJQzgboI67bpPett1cK7WJElSTKCUsecQdaeWTK8hDIjt5TdZnSZ+AO
         9LhTuklX2tIspPtou7XKmiKc8ZOHVWAwKyhq66F8HA5lT2XET4XxGbvOoUYRlZkNVyvq
         Zl/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqDNbKBuVe+rMdMfdcuYDcB5MmBxh5MmC6k+6WTnF5iIo0XtOQk
	KLOK3eQ/IJWa2P7n2g8v9nQ=
X-Google-Smtp-Source: AMrXdXvwX1xo6brI61nKU9vQEy220lwRlmE5cstHSgSKHXiGtQJ4twcExGRBsuFWu5nCU2a1CZnN0g==
X-Received: by 2002:a05:6870:4151:b0:15e:efa9:9754 with SMTP id r17-20020a056870415100b0015eefa99754mr2321438oad.148.1674584224328;
        Tue, 24 Jan 2023 10:17:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:601:0:b0:36e:b79c:1343 with SMTP id 1-20020aca0601000000b0036eb79c1343ls3838038oig.7.-pod-prod-gmail;
 Tue, 24 Jan 2023 10:17:04 -0800 (PST)
X-Received: by 2002:a05:6808:291a:b0:368:69d3:ac82 with SMTP id ev26-20020a056808291a00b0036869d3ac82mr13608506oib.17.1674584223931;
        Tue, 24 Jan 2023 10:17:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674584223; cv=none;
        d=google.com; s=arc-20160816;
        b=z6WbcRGHqrsp4sUiwAsji+3CpQJgG8/vv86ETH2H1GAkPdy149/vafMuiupqFl0vzO
         UKTGWOvS10bwScsGpiUXuhQZWhy7l1uHcppXaP6eD3X6cueJ8DcXlcnf9+zWtVcx/CVe
         9G1k8EZIst+hzV2SHIvRqbA5ry8CWtSVczoyve1f3d54Ahy4QUR7/bdGJszOOxwoYw5r
         hCwdMSUMxAVHFjfKCDCYgodt3F09uI6LZJB5UO49a35PDT5Hrdif7JBZrAM6Q70flNM+
         CN+hTxFvg1OMhXzeOe6ioRMXFSD61CWHkYtmIVjhoJGKQmQ7nqj/EHUHDUXWJNb1BR01
         aEXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=m/pasOdyMBc4nWtkzhzrsJ06EVonqIIgK3nxwNuLfaY=;
        b=c1ujzS+Bo6pNQhCu0d8sUOE4A3N54U0PA50/qNPQUctD6PBIgcOxBDCJQ1/+ubRQX8
         PxGZ1coIndRuYBo6RvvyMU2SG/ZSFPXQ/X16bY0kUMxZJY7WO8iKhtBkJ5iVq+2ZRkyO
         s0wrugjwQdC8L5BWnXeWfLh7C00OWycK8CsM6oTU5K75oEtNBpwbNVFMQpqUzSThGrcn
         26itndK8yyzUeoD5LkVugJx8hcegeHK+GyNHO+qDcPtkHxvGR0CVRvGC9j5xgvOaFxvb
         fKt6+Hgztt1B5rzJ4VZBAqy2CrAdZ6G5IyAgH/gc2XTZq1ZSi8PZ0c0VJZ7w6OO594uC
         /QSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=uqSc5bi6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id ca6-20020a056830610600b0066e950b0580si492737otb.4.2023.01.24.10.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jan 2023 10:17:03 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c2:d80:3110::9307] (helo=bombadil.infradead.org)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pKNqq-004vdD-CS; Tue, 24 Jan 2023 18:16:56 +0000
From: Randy Dunlap <rdunlap@infradead.org>
To: linux-kernel@vger.kernel.org
Cc: Randy Dunlap <rdunlap@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH] lib: Kconfig: fix spellos
Date: Tue, 24 Jan 2023 10:16:55 -0800
Message-Id: <20230124181655.16269-1-rdunlap@infradead.org>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=uqSc5bi6;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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

Fix spelling in lib/ Kconfig files.
(reported by codespell)

Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: kasan-dev@googlegroups.com
---
 lib/Kconfig.debug |    2 +-
 lib/Kconfig.kcsan |    2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff -- a/lib/Kconfig.debug b/lib/Kconfig.debug
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1876,7 +1876,7 @@ config FUNCTION_ERROR_INJECTION
 	help
 	  Add fault injections into various functions that are annotated with
 	  ALLOW_ERROR_INJECTION() in the kernel. BPF may also modify the return
-	  value of theses functions. This is useful to test error paths of code.
+	  value of these functions. This is useful to test error paths of code.
 
 	  If unsure, say N
 
diff -- a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -194,7 +194,7 @@ config KCSAN_WEAK_MEMORY
 	  Enable support for modeling a subset of weak memory, which allows
 	  detecting a subset of data races due to missing memory barriers.
 
-	  Depends on KCSAN_STRICT, because the options strenghtening certain
+	  Depends on KCSAN_STRICT, because the options strengthening certain
 	  plain accesses by default (depending on !KCSAN_STRICT) reduce the
 	  ability to detect any data races invoving reordered accesses, in
 	  particular reordered writes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230124181655.16269-1-rdunlap%40infradead.org.
