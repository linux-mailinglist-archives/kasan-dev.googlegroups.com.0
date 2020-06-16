Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XZUL3QKGQER62SR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93C921FB0DC
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:36:59 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id x63sf14275097ilk.8
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:36:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311018; cv=pass;
        d=google.com; s=arc-20160816;
        b=C23/p3VM8zBhjvOMWrc/MBzTdEkKD9nA08wv+pATjYpq18QrJZPuUBrkh4Mc4bbQlO
         N6MySH9ghAx8PPAjRn7TBT9PdNJQ36r5caESbEQjKm+iZ94ewqFNd9AxZNjCZho5nWNT
         PWiYEtPM9TyGDxz4iQh5AX+l1LbW8QFXteRToh9Topw2F8RniFcv/UF0hthI1cK4h2De
         Y13SoDi/D7aNRo9gJiawG/p5gAOWEIrlP28Z8PZ1Y2shsuk+Adp2iHEv+YsR05hToQQz
         VjHJ1EijwrKWeTvOaudBUg/PL/rUu8EgoLrcaMbBnnitf42u3h8Mnz41ePgJqk8aM1Ur
         l6IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yP/H9BHtUYFMwQqef3snHpo8AorYNVBj8n8lDnQRazc=;
        b=N/BNgx7VH0pgfNTO3t2Ps3vfQCJE3uwNYspZt1+ynCAGXY+lUQmI17hyyCIxwxjvG4
         rLX8P6qh6SfZsJeWRfFj0qFBDf4F4iL3yN16FnbHsusS5XzT1fN/jygfLO68V+mlSTCy
         NIYeTYGUnRTBsJSUV5o/wHn25g+U5cdz9wgGQ13jv2eLFiy/UvkOmidh5WZ+6RTyEiFs
         TKmM2OPUs8dGU7SaNXCNm1bb3kcGbCeTLOTX7PkkvTo3K5Ol3SRzhJl47pK9QbE4kxPn
         +kXXD3sOeXTvUxFo/1eVwSvMXhSP4glHK7UaZWt/+mFbO7kLUxMo2gtqN6qaKRUk3rzB
         7uYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rX0QyNeY;
       spf=pass (google.com: domain of 36bzoxgukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=36bzoXgUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yP/H9BHtUYFMwQqef3snHpo8AorYNVBj8n8lDnQRazc=;
        b=ATI7hwv3AXywsQJc4b8xfz7xPb+06U0yx1f1YrDWBNLhwJeB6SF4UCOBBHnDn4/NPH
         b4SIdP8sQCq59wAYlw8hkYd4q3cl07md9TfODBluKUif0zCzYB7ebjsg5YdfgTbFKoJO
         gTz2jvIIMRwc8VkkVG1ldY9O8BUm7nOkOrl/2pSu5uGXyqPxEaXOiN0Jke8Uadoklrvg
         IFTPXt/cO4nSs/tJR8+8uX5nwedlBtularcfXgUjRoUgAsG3z+Q+9iLN5F0Off5bAXEV
         lSOw/lfI0McSrnb7ueib0UshrmLsZ1elzgandRj9x1y1ir9vWLIfdtRShXo0myvWYX1c
         A9Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yP/H9BHtUYFMwQqef3snHpo8AorYNVBj8n8lDnQRazc=;
        b=Au26XBtQ1OBs7PIEUNiB49DBhnEJgdgSNv8Rd2SgcZlmchMC8z7DSQmyMH7qG+EJ1p
         2hrI6ZLsATeBx2jbNWVc/XKhuepSzcPx4rPL282+tr+SpiUXm9E1cH7VGGHG83ElVL1Q
         4C0R7f++low8HFkWeMkOLLd3g2pMVEYKZsgzSPJn0GLZo5TXzFZiXb1x5nQFliY9swI3
         UUGDdTIbJZ3p5yAm3nvCbFFBfGUeo6G5MYtDqTt2GwiV6gC+7YObsEI1pwAfM9XhMaRG
         GCjlRs58dFo7HwcxehJEcgsnUFbIHxWcyt+3Byj/SR3T4/HtgRSaz7jaoj3RMl/OsXTI
         EeiQ==
X-Gm-Message-State: AOAM5301Eyqg/NSOpU3hdK9mmPYllC89dNMn7JP9hqZrvpW1TJwFyKGa
	/G0XjEUmgtVvCPD2Faz+eno=
X-Google-Smtp-Source: ABdhPJzNEn1Gja6NhqsP4yof9/2Wajf+zmQQWLJJDRXVKG5zKcSJzWbsyrc3ieQhvsF4pHEgW/tOCw==
X-Received: by 2002:a05:6e02:eee:: with SMTP id j14mr2935443ilk.261.1592311018608;
        Tue, 16 Jun 2020 05:36:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ac8f:: with SMTP id x15ls1141002jan.4.gmail; Tue, 16 Jun
 2020 05:36:58 -0700 (PDT)
X-Received: by 2002:a02:37d4:: with SMTP id r203mr26376407jar.121.1592311018265;
        Tue, 16 Jun 2020 05:36:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311018; cv=none;
        d=google.com; s=arc-20160816;
        b=J/LMpRTzlRRBcXqurx+p/MX6QmvsBO1JJ5bi1+2serevMHKhSWathWLQkXKUiAl6TH
         O8qfvVBt6d9HztUtL7UjEDrtr0qZhEuYTIWQg/HpXxOXPvye4jh5jPqc5nBlZsajgUch
         QamYLefvJjOkkmL1lMIWn7TcgFxQC7DRp+lpkXHc7EeWqMXPTIDUP6zGh2OZgO6+T+a7
         3E3DHjlggapMb1oCEcWXf4oAhsea16iXHBzqUQKCejabFFe5DIgz7Keb84pz5wP5/VLr
         c1aqObkTBVZ28bP6z7bVphDu/D37YEo2xlcinU0VH4y6BJuiHkKMg9pnaiWWwTC1a7nl
         TaSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LwsvhgSu3llt3znh/vlryiffTNTLDnq/294g1wxgxfQ=;
        b=RoeROwA/urZ4tZRdRBnR1o0bFogeaW2Azmy2EWcAeucWjCbDWy3fr6SDMo4RWKkzi5
         61/Kqfzy3UxRFETpRj/Q/1TXttA+pJ7BZrLtoAyZbgGVgvhtDBYTJDvGtvcmqXFj1Sus
         7Fg5BITEWA5q7cVPuZxPV6PQ9B686+pVadwligtFjhBsH7tNkAJm4LhLP0MOTLQhSVM0
         weOdTvd9QJz6ReofcBR561l1raLYBzgg+qPIurGMoXWCFYSktlla2KPQxKaoKDIzosW3
         vN7B4Hy5UqJWwxEQkAzuZWyWL21sTo/bMkbnKHGE2NrLUqRtoZK8SiPK7hWoAjwUC9LT
         xUmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rX0QyNeY;
       spf=pass (google.com: domain of 36bzoxgukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=36bzoXgUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id d3si180534iow.4.2020.06.16.05.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:36:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36bzoxgukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id ba13so15410419qvb.15
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:36:58 -0700 (PDT)
X-Received: by 2002:ad4:4429:: with SMTP id e9mr2000606qvt.143.1592311017654;
 Tue, 16 Jun 2020 05:36:57 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:36:23 +0200
In-Reply-To: <20200616123625.188905-1-elver@google.com>
Message-Id: <20200616123625.188905-3-elver@google.com>
Mime-Version: 1.0
References: <20200616123625.188905-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 2/4] kcsan: Rename test.c to selftest.c
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rX0QyNeY;       spf=pass
 (google.com: domain of 36bzoxgukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=36bzoXgUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Rename 'test.c' to 'selftest.c' to better reflect its purpose (Kconfig
variable and code inside already match this). This is to avoid confusion
with the test suite module in 'kcsan-test.c'.

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile               | 2 +-
 kernel/kcsan/{test.c => selftest.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename kernel/kcsan/{test.c => selftest.c} (100%)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 14533cf24bc3..092ce58d2e56 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -11,7 +11,7 @@ CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
 	$(call cc-option,-fno-stack-protector,)
 
 obj-y := core.o debugfs.o report.o
-obj-$(CONFIG_KCSAN_SELFTEST) += test.o
+obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
 CFLAGS_kcsan-test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
 obj-$(CONFIG_KCSAN_TEST) += kcsan-test.o
diff --git a/kernel/kcsan/test.c b/kernel/kcsan/selftest.c
similarity index 100%
rename from kernel/kcsan/test.c
rename to kernel/kcsan/selftest.c
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616123625.188905-3-elver%40google.com.
