Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSMV3CGAMGQEGE7IQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 09872455691
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:54 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id u20-20020a056512129400b0040373ffc60bsf3419816lfs.15
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223113; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZmY/nA+BKRu5JppJPrvZKPyKwc2FkLMIC0tAEpimdQISldNmP4/3ZOX6OJP7VyRkS/
         4BrCypGWwYopTYj7qly5zp54gekgr8hmeAq11tpYDoIudSmQm5wOLJ/dGhK5NARwzzLY
         2GwaL2qK31S3q3xamHPFtxpS72vWjWbVFwqcgonRmhRx55kqC9aEeUSLpubUe1VKw1a+
         W8CNISIEPrEamtKmiFAWKB3cEaJEpunn1Oa2em3FKsCYuUJ7FKpFarE0ug0bod5z6G7H
         q3yKGh1MyTFZmzUKlpxq7dwh4pFWk0EAkpLybf6FwP/UkiovXzHGwPu/wzX/B63W/qd9
         p5RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oM5N1+q6r54P9zGx5DmZSdFH/7gD7gxwup7RAA7D/wk=;
        b=CxtWew2cBs/vzDyHgQNZDDbU7KrlqscgudDg/hYAxhM/Co1Sev6WxlRG5zJlZ5PPpg
         zqpIN1qzZleSZ29UvwM8QN0sQh8tdViH/x76TVAiy3uv79ccLm9zXHWocronhhYOVXze
         6TldakDRbF5vUyX0WPfvEzI8VMb3C7JKmY2NmnCRFLkM7lQrPDe+jObkhv3yBCsyT+MI
         ci3XZsfxCTbGhtWytdp0IRBIfhxm6FES1jHsZtIU7bJCFrGnSakpl0jJBqL+cBX+WTHk
         n7f4qcyXC185lJ44PVGfHz9ywIfod3YOpzPg9qZu8uPMH52JFLj2CN4qnjJ+Z2qlvE9v
         f3mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J2dq7Bb9;
       spf=pass (google.com: domain of 3xwqwyqukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xwqWYQUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oM5N1+q6r54P9zGx5DmZSdFH/7gD7gxwup7RAA7D/wk=;
        b=nFr5nEY/HaMDlDzEoNdh6as/kpqrzWLfwN48EY7cSmCU7KZBZkRVjHtRzECnxxL+sl
         sSmjKSWfZevzykmsguNhiYL35BwuGqGTr6De+5oLHrwXF85XhwdhZn+099sgePkthzmd
         ca5AJSqx9uCtwwkNX9hYd2RUCmokw43pPV+cOfr3DDKE1u2iQqWEYCM5b1N08srnOqJh
         EG+05VI9PCZIFznanjWXzgkVGz7jCOIi1FQAw4ycV02I6l2n3Aoy+OEDGFMIC7bQVbFg
         OVJNnQAUaNg7oaPwILwSZw+s3b4LHcKkaz2RhRwWPHWI+pVgZ1AbttMSMgK9YGICjTKo
         QsHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oM5N1+q6r54P9zGx5DmZSdFH/7gD7gxwup7RAA7D/wk=;
        b=USfJz1KE5lqobU1/tgR6H1+w7sNeHtdm2oER2ALyKj7VeOIz+V/5tfPuwArI5ObsdU
         ov6Y86jHWBY+IKBRQb5FdIOTzEvDbuAZTE9ymTLCFt4KPUJ5IM6yMEV9pQ0A9DOeQo2w
         npwKXNfGL5UzcXKsDExF3febbRUXBdFMbDVqVgRxvHFcvgS+HciHZt0vMWNi0d6WMky9
         7JgGtzDdBGGm2RT7Uj96NO237i5cLtShZ0bYA7O1j+fGxi9ZIWF5f3wUga1dBTpnQ2q2
         siew/bfx2gzPp7/Q7pow5MhfYHuMPJDXvJwKrrUum0k9EYgRHPNkqEMQpaFAeIlHoRhd
         8iAw==
X-Gm-Message-State: AOAM532bV9LUC8Mgq9FSl1cw86QABiB4/92KzB/1xEGTd3jaUNeCdSlu
	bWbqJewI6NdTDIswEgSOtuc=
X-Google-Smtp-Source: ABdhPJwHf7GWC/PXH/Is3SfwC6FlWXqdujviF6D7NglboFYR6iprRyk73qG+bO7Dt+JdEoFguSDkMQ==
X-Received: by 2002:a2e:b169:: with SMTP id a9mr15575771ljm.369.1637223113627;
        Thu, 18 Nov 2021 00:11:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1687:: with SMTP id bd7ls393418ljb.10.gmail; Thu,
 18 Nov 2021 00:11:52 -0800 (PST)
X-Received: by 2002:a2e:b5b7:: with SMTP id f23mr14127914ljn.244.1637223112564;
        Thu, 18 Nov 2021 00:11:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223112; cv=none;
        d=google.com; s=arc-20160816;
        b=cnhNpUJRjx3J8b3TJz3HDBQhgk0++4f5n0ubH6kl7YdQ+jTk+WTU0H1OIoASYTE00H
         NDWVY7NhTCtb8MKjwxR/3sLdJmo24awUBZpSYJxCyQs6iaV81oRn/cl+9yUaOnCU8G2m
         TOrgrvEZBeVzJwQ8lLjODiaZ5LeoTnQYni2nytp63UEl3bUE7t4i0GY4pL/2p6fTq5JK
         V/XFJQ74KF54sy0kyhx4fKYYInWhnuJnkl5TJ5v1jbraq0q+nwgpon4WslaBjTY3yoQx
         B5RkWnHqFSiu4HQFZOG78alysPw7TFC1LICqYvm9l/VUmrFyLCr7x8nX+pkzWZ2tccbj
         i6tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JzBhpw0Qm81Z9lbF5IGyZhQAb+5o04LDLkCFlxupKLc=;
        b=sSBRqdi4fs/fIACoAe0a3TmWrM9/y6+vzGfsvxs1e4ydM9Cbxof3DE7Nq+HXNQ2LjR
         UG7BbQvShq84EICUaHgZrGIqgTz/4Btipgl2WDjRtpzmQ+hpuYP5v185RFEE/j1xbyAE
         pBGpNLRwHKpbUr12T4ZGnM247xmZk/hZ96pOMuZFZZ2VCVvbadHl1Ta2kt0dfRAoBgfv
         oj/52QCCDynplcEXQF7bsn8p2OJ+lSVRHog+cVtWMTE348Qfr3wQEI9Zyvl+w68NkrAc
         5NzlLdk4YRs+NZyAcTbx/rdW90Ht3a455u1LJ7x0ZNN57gPz8zRnEUGzeTPTB6eWkVUj
         6pAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J2dq7Bb9;
       spf=pass (google.com: domain of 3xwqwyqukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xwqWYQUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id g21si147844lfv.11.2021.11.18.00.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xwqwyqukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76daso3986222wml.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:52 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:2c4a:: with SMTP id
 r10mr7851761wmg.125.1637223111807; Thu, 18 Nov 2021 00:11:51 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:26 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-23-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 22/23] objtool, kcsan: Add memory barrier instrumentation
 to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=J2dq7Bb9;       spf=pass
 (google.com: domain of 3xwqwyqukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xwqWYQUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Adds KCSAN's memory barrier instrumentation to objtool's uaccess
whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 21735829b860..61dfb66b30b6 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -849,6 +849,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store16_noabort",
 	/* KCSAN */
 	"__kcsan_check_access",
+	"__kcsan_mb",
+	"__kcsan_wmb",
+	"__kcsan_rmb",
+	"__kcsan_release",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
 	"kcsan_check_scoped_accesses",
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-23-elver%40google.com.
