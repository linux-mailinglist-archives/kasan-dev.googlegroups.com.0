Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VD3OBQMGQEIT5DNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D105135F26B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:51 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id f7sf6387211ybp.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399731; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmkokOAKw7ZInAdgUKaO3yQJsfMrZKpe37AWtBRSRWj/RQ+giHEADiv3BTwWSBbPJT
         q9cHUex/kmNejs6iohSetF6C139LOnYefCrS7YuKSce6POopCF0hAw41ZGMgPR77tl7m
         yUNyqV+ChWrOr2ugWhbE+JikfnTAqSzJYeiS7l+dk4yLTKc+aPZTkHccnbDGvN5oOsuB
         3AOmDvtARA6IOlSgqL0F7qZa3ByATwSU7HMeMRaLvWTiBYTLphqEniDyGk4pQu1y3nRX
         hk3ffQOIArK9Yqz1fVI6ItcUCZEyNlG7jCzXFZvBKirnhqApWIlT1WMm0uGH7bFwSJhx
         fw7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kolFkIz7O54bHk8u+M0Qz9UNrntRsupGAnkh+SH1vIE=;
        b=UJ61ae5+dGQ1j7MK4AQGKIRWqkoNnWhBM7YnknslJ9qdY+3MFW0il0A8NwQWJUGv8l
         pVEFZQe4uXOFzh2m1XxJVdhZ2G0xeSncepwsM3j1Gt11i/hxsrsd9Qad99Jlc9jaetoF
         0KFGeZ+Cc6Q5rdo82ef5Y2aYOBGpmpCOEHxXxJN0xRP0Auk9YUP+Ud0BmUrCWgGp5ptq
         JfXgVs4pimgKv3b6dB/ckg+xv0DWnmGiiPOw9M1qzoPiSbe4xijLHJSftzL336nG4adk
         AK6J/5zvmfcu6IiTLsM4Ufg3ziq0ydsvHKXq0Vi9BIT6naSlOCYtlBS6idStS7HYS1rd
         eepQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvqPmC3F;
       spf=pass (google.com: domain of 38tf2yaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38tF2YAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kolFkIz7O54bHk8u+M0Qz9UNrntRsupGAnkh+SH1vIE=;
        b=YPY916XUS1kGtecaACohTeTFjnC+3r8QZgxX7IXRgOB0yHOxhi0WMO5ShAF6w7bJDs
         0qmKLKID0ukR0D9SnEU1Na8DvjFm9xqtBwjLeMjCTo4bG9L50U+GRb9ElHR8JPaGdw6J
         GAKd4Izkm9J/AHNpVBpBnfl+8k3wMDUNaUBhBh3de7rC9fl2IdCxebaitxciUv6xgjQJ
         peuxKcLXlJwsFY7idt59/GNV8MlJsSsVv1blX3cfUijOTWGKK2J3Fk20Jz79XRXueEFR
         rE71qso2jPOcLIen3qJ37j28PM0zMAhDa0sFQIv1+Viqgd0J/Ttcv74B9TYX3vI59VMN
         KVsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kolFkIz7O54bHk8u+M0Qz9UNrntRsupGAnkh+SH1vIE=;
        b=lfJfYQB4l1eK90w4Kq9CGWQI1WbYywl+4hPZzBjI47uFJURAhZRZACZ5n0C+HGTNRX
         RA2aMH5UucNsPOHC/mzzbMh7SfuRPofGVH+DELE0lUl+xF3Xo923pxueyb1y1UETWlBr
         mgH937zXqkXhuSP7k2KsxlQ28WBdFaWaKd2gDPl5YjdVRgOIXD5m7FX3+gQDUD8c7vYR
         fZzduay56b5UvO6wvdZaD+3C5oeX8YegJ8I3y74M8Nlsg20EgZ9KtDBD9Co1lKfV2nH5
         m7gh7BfUWrYKXnAbrUr9hXtK8uts76nElBfiM2kRw4gcNFcSiVBfq7raKNvgjEqvx6nS
         Yi6g==
X-Gm-Message-State: AOAM530RcyFCQvrnqdODVhwOUeqDAgAQtKfdnKDqW0jnkpizlDzX2rse
	QiJrd42KO+Nap8BrfNgMvyA=
X-Google-Smtp-Source: ABdhPJzP9NzB1bCUErSgiKJDFfslaqqxmnGXLLVzqhWH0Qprvc4cmbyDOejy8Vsd/uqF8WQ3Yg+/vQ==
X-Received: by 2002:a5b:44e:: with SMTP id s14mr54284702ybp.11.1618399730958;
        Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:702:: with SMTP id k2ls865195ybt.2.gmail; Wed, 14
 Apr 2021 04:28:50 -0700 (PDT)
X-Received: by 2002:a25:e70b:: with SMTP id e11mr12247160ybh.240.1618399730440;
        Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399730; cv=none;
        d=google.com; s=arc-20160816;
        b=NYmEUGsXQcQAlbbf/BMaxKmOiUP+qxznaiNlrFSSi2fd3jsqPYz+pWXZAwTUH4UCWW
         j58PP8Ls8YejhfvMFLOozDfiCyMRBPCswBsn89a1sSEWG3QV+eOrUXXZ/rFJAz5fz9wM
         jCG+fPw8MHRV9h6lvtvhPAsikqfZZj6gT23kYXltzmleT0wquSnOVYed/ZevHbg4CbiH
         AZ9e26Z/mpe4/w6oacWRbYq6+Fu3h5ffC1VhldY32FBf3Z4VKyXRC1EzIS92hKu7Mqkb
         kLZELyd132nbTTto4oIB2jJjD9g9HBttGo4yFrgTZHoAp22kMC/0wYeqqb0de5PzuZy4
         TQYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mUd7E8x0BAm4t1vvxUhc96USRUC2VnPVzcusbEWbh3k=;
        b=JLY5uhRRnTyUNoLqGsNqWuXTQ4Hl25NGPBfActNjkk9hoiKt+GudrCvemg+S4sHNvR
         p9L+WHDxBNfm4WcF4yBnRl8EinNEDDkPdj+ve46JYueoYnq3NefzEaBq1+lxQRKDRZfe
         x66CnLADmB0ab8PUA2oaOvrNmKnIo/QLXcvp38Y8/D5l6iw044ZZEJmSQn1zq2/6nKJR
         O1hiDkzRfcPlPQNLu98Jor0Z8lhV3d/Svck5xKIbZyTwoIiusqWSeGKi3HBb05roXUKp
         rejJ2zm+IWSU1Lq3DC2o2/LMzUlQ8Nv1W+nPAROkjv7N4Rq21VVgUKOKm2eHJOz/7izw
         XZYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvqPmC3F;
       spf=pass (google.com: domain of 38tf2yaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38tF2YAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id t17si655572ybi.3.2021.04.14.04.28.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38tf2yaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c17-20020ac85a910000b02901988c614329so1663973qtc.18
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a0c:c581:: with SMTP id a1mr37671645qvj.34.1618399730080;
 Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:19 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-4-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 3/9] kcsan: Refactor passing watchpoint/other_info
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bvqPmC3F;       spf=pass
 (google.com: domain of 38tf2yaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38tF2YAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

The `watchpoint_idx` argument to kcsan_report() isn't meaningful for
races which were not detected by a watchpoint, and it would be clearer
if callers passed the other_info directly so that a NULL value can be
passed in this case.

Given that callers manipulate their watchpoints before passing the index
into kcsan_report_*(), and given we index the `other_infos` array using
this before we sanity-check it, the subsequent sanity check isn't all
that useful.

Let's remove the `watchpoint_idx` sanity check, and move the job of
finding the `other_info` out of kcsan_report().

Other than the removal of the check, there should be no functional
change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 13 ++++---------
 1 file changed, 4 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 5232bf218ea7..88225f6d471e 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -600,7 +600,7 @@ static noinline bool prepare_report(unsigned long *flags,
 
 static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 			 enum kcsan_value_change value_change,
-			 enum kcsan_report_type type, int watchpoint_idx)
+			 enum kcsan_report_type type, struct other_info *other_info)
 {
 	unsigned long flags = 0;
 	const struct access_info ai = {
@@ -610,12 +610,8 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		.task_pid	= in_task() ? task_pid_nr(current) : -1,
 		.cpu_id		= raw_smp_processor_id()
 	};
-	struct other_info *other_info = type == KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
-					? NULL : &other_infos[watchpoint_idx];
 
 	kcsan_disable_current();
-	if (WARN_ON(watchpoint_idx < 0 || watchpoint_idx >= ARRAY_SIZE(other_infos)))
-		goto out;
 
 	/*
 	 * Because we may generate reports when we're in scheduler code, the use
@@ -642,7 +638,6 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	}
 
 	lockdep_on();
-out:
 	kcsan_enable_current();
 }
 
@@ -650,18 +645,18 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 			   int watchpoint_idx)
 {
 	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_MAYBE,
-		     KCSAN_REPORT_CONSUMED_WATCHPOINT, watchpoint_idx);
+		     KCSAN_REPORT_CONSUMED_WATCHPOINT, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx)
 {
 	kcsan_report(ptr, size, access_type, value_change,
-		     KCSAN_REPORT_RACE_SIGNAL, watchpoint_idx);
+		     KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
 {
 	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_TRUE,
-		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, 0);
+		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
 }
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-4-elver%40google.com.
