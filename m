Return-Path: <kasan-dev+bncBC7OBJGL2MHBB36EYL2AKGQET7JY4FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F341A48A1
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 18:44:31 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id s2sf505811ljj.15
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 09:44:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586537071; cv=pass;
        d=google.com; s=arc-20160816;
        b=IW0bM4hRgruldAfQoiOPNn2VBwT/LUOG8NLbgT2k1LHLRKE8Y6dcOUjan0pYKU1lsy
         1nCzrdXNEza5LGQx1MfN0BFcb4/1Her/05NiVrGDi48fZhiFi/4HqpBO/zs8glaQ6Yqs
         cgss9pk939Rgm8OTIHyEtO96KKUNoPEda6JYTDpfZ2WwrhkqeXrG3dbkRb2ekyNPHyK2
         phwKp/rYNi0eY3XXEN2Qkx6dY+OcWWwVzTqlqcFJdgWsWItJRxou61FFJ8ia2U58v+qf
         N0KXmQcgvy0E4aB2PPCi/p1w50vGiWioqqFZMbb846qA9WWE/YZKNOHpXlu8FDMk2MU3
         0clQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pGZUfuoP7Jauc6wU0iaaPd5yCk2rOkQTwbeXYcpqxwI=;
        b=m+Cv6awqWN1p6jlIpCVDH1p/vUWDs2h6H9XOdIAdftxdhbtSiLULB/YTDPts2sbS2Y
         9t23C/+9r6sb71ANBt11bgQOaLDPieJAp7mcw0vkCoZrUhrIyAOk1GgNfnQjp0gamDSM
         x7ritOEWQhfZSBzQ0XUT4A2p8llfsaX+9NGBOpDBRbKN9TrvA4m4GdgtiguNlWluMR3M
         rO5PEcaFQQNHPA0A2rAMz3j6aMRDetBIf2k/s/Sb4arMg+b9AHEChOhkRfppMLrf+EIo
         151WGsP/D8Y0DlolhX2zoVNxB4OArMztyvVOHlAls1NRz+lop8WQ9b9UeES4+OL+mAq5
         E5Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V3JjhjmZ;
       spf=pass (google.com: domain of 3bakqxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3baKQXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pGZUfuoP7Jauc6wU0iaaPd5yCk2rOkQTwbeXYcpqxwI=;
        b=f7kOfXspt3okKFMlwxu2hHsbfRXHZg8OaTh4K1syMI/pXrHO1jNKqwQsLSwJ32srx7
         XnWH7YHhnExPwT9k7QlAhZ053swWeeW7wxikDLpvWf3MgTNPug7HOPXZ+vC5f64UAlb2
         0EeOBRuQLFneT58QtD0eBEqy9lVbWhxv8ad6oE94HAxQs1V8yytzcVCDFq4EQB3YsyQ8
         x+kr92Ekx2XS/BFMXgYUel3Sw/zjGt0yjn6QEBDuw/yKQZnXh8+wfu+MMO5pNAEXxelC
         S8NKuICDvhWvsqEOaoJrDGNCGCuxDQ+gBlM4wqr1ejCqj+Vjor0xeF1vTeVT5uHMtjKA
         V/JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pGZUfuoP7Jauc6wU0iaaPd5yCk2rOkQTwbeXYcpqxwI=;
        b=mwzsGwhESUTUH/izsFpcJsk6Q2D6mACfUBgf9hN5u9rv92xfMHUFINFxuKXAg6kELG
         ybMBa6q0JiCMRkP2b+dNdAl5+06x1UZ283Bdfy9tsmxBY73GfGF4uFN7+1yxePU/F23Z
         Zay1QKZO9E+Cm2dOGANIAVOVS/bw/Jgd/3kXNMYGkDI5I6vBGMJOmXU4RR+aijHdZ5SR
         JD0X/T83RX2hYihefLqYBzsY5tWETU6pIDp8yuTevfLLT1xKsaG1nGNGkYUX0vuHbDnZ
         F0fAQdptmj3QySZWoRNn4PGe/Z5wnatSwfMgY+NWrcZv/xh/IU6q03hOd2z6XNrpOok6
         OkKg==
X-Gm-Message-State: AGi0PuZfmDfmXGZ/CYDatEboefRGSPH9I9Rsy7XyqONq48Nc6rzE3pqd
	QyucOpqLU3qDI2Uimxfo3L0=
X-Google-Smtp-Source: APiQypLmhW8FlhgvLBP5g1jo93soX/Rm6HZ74+Lhsk7UunMizcSieelK93O9m7d9ZE2ywMh9qRiFKQ==
X-Received: by 2002:a19:d3:: with SMTP id 202mr3034135lfa.24.1586537071179;
        Fri, 10 Apr 2020 09:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:984b:: with SMTP id e11ls1605942ljj.3.gmail; Fri, 10 Apr
 2020 09:44:30 -0700 (PDT)
X-Received: by 2002:a2e:988c:: with SMTP id b12mr3599973ljj.138.1586537070455;
        Fri, 10 Apr 2020 09:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586537070; cv=none;
        d=google.com; s=arc-20160816;
        b=GUWwKhiiqNP/bv6WLDjqRmEn0ZHRxhRP9mGrPo9h27qDnyCtLKFcyOFMr4ZzOrTQjC
         h5ev3V6kyU00511HhD9+k6RYgcXWNXAa/hooNFie7W/VytF43zHjMTTYcRjvdamM3zIi
         TDFIiq75ud0GXLZOr3mXLuh3zFPYFjfrx8DvOAnAO5PgEnXx4UOJhSvacOvw2Ai9u1Ew
         dOjyDoVU9VfWeNfiOiPwy0VJNOfL6XE4vRPCUYdgTxb6dSPxnEVKzOYmzp52CgVlsGH+
         /D3P7N2OWh5gDBCsUlipGX2HCulKFpFwt+p3wX8VoxO1gUz7HQ5V99g/40lS/UwtTYx3
         KjCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ueafPH9nFZnbYCe8pBTsy3DXxC5q7uCEv34zh8QVYcE=;
        b=UkaFnvDb2y7Ic94GslGoXBr9LQuoMbBhOGSidGLhpUoZ4SQojXoauhLcTVWFcwfD2x
         YiPlNFKrw6aoDiSzHiq0Jjbimx1h+TnpVXJ4JezKgeIyaeBabzaashslG8iA4E3BJF+m
         zLo2BzNSKQZzKP/bQUYhNaKUQIlKukpJbgnvCCzWTkupTcwMwGalNJID7+6OdEj0QP/p
         DOW4/nHR0bi5/SypeZw4TdpNGw4jpdzdKFk8oP537jV+XzCe0YJJANgvD01rQXVaZQyb
         urfsvDNbjwkDXY8pdo2ZX1jcStjnYhWtUr6DY7K4IwvsJW3Gnv0oj57NFNIN8QSIpErz
         N0Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V3JjhjmZ;
       spf=pass (google.com: domain of 3bakqxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3baKQXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p5si158451ljj.3.2020.04.10.09.44.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 09:44:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bakqxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e10so1487739wru.6
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 09:44:30 -0700 (PDT)
X-Received: by 2002:a5d:4248:: with SMTP id s8mr5315245wrr.216.1586537069409;
 Fri, 10 Apr 2020 09:44:29 -0700 (PDT)
Date: Fri, 10 Apr 2020 18:44:17 +0200
Message-Id: <20200410164418.65808-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH 1/2] kcsan: Fix function matching in report
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V3JjhjmZ;       spf=pass
 (google.com: domain of 3bakqxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3baKQXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Pass string length as returned by scnprintf() to strnstr(), since
strnstr() searches exactly len bytes in haystack, even if it contains a
NUL-terminator before haystack+len.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index ddc18f1224a4..cf41d63dd0cd 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -192,11 +192,11 @@ skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
 		 * maintainers.
 		 */
 		char buf[64];
+		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
 
-		snprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
-		if (!strnstr(buf, "rcu_", sizeof(buf)) &&
-		    !strnstr(buf, "_rcu", sizeof(buf)) &&
-		    !strnstr(buf, "_srcu", sizeof(buf)))
+		if (!strnstr(buf, "rcu_", len) &&
+		    !strnstr(buf, "_rcu", len) &&
+		    !strnstr(buf, "_srcu", len))
 			return true;
 	}
 
@@ -262,15 +262,15 @@ static const char *get_thread_desc(int task_id)
 static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
 {
 	char buf[64];
+	int len;
 	int skip = 0;
 
 	for (; skip < num_entries; ++skip) {
-		snprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
-		if (!strnstr(buf, "csan_", sizeof(buf)) &&
-		    !strnstr(buf, "tsan_", sizeof(buf)) &&
-		    !strnstr(buf, "_once_size", sizeof(buf))) {
+		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
+		if (!strnstr(buf, "csan_", len) &&
+		    !strnstr(buf, "tsan_", len) &&
+		    !strnstr(buf, "_once_size", len))
 			break;
-		}
 	}
 	return skip;
 }
-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200410164418.65808-1-elver%40google.com.
