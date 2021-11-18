Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI4V3CGAMGQE3ZFYB7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7E24455660
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:15 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id k5-20020a05651210c500b0040934a07fbdsf3433387lfg.22
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223075; cv=pass;
        d=google.com; s=arc-20160816;
        b=nuCfIy+RCKkYlgWGys5WlNmrUDuVifgV7jVy1dG26Wm87uMJ0lGnAFUiTiXUl+Djz7
         ZMEB+vvrekAmgR1q9/wuiKRuVCUEQtAwDDxwYV797ppr2nwbzqmXXA08U/u7nuwEAmtu
         NSq6hqKRgB9pdpxLesIUtRCbp9oQTwjBFqCFKPHc2gbGl22hgv3uHJBe8iwEL8iw8tsd
         1JGZABc/vh+N4Ih949Xo7/1+uUiE7XtPkrFR7HYh67waR4hbAitvLuO0x7UCIUYT84PD
         Kl5248qeVYCtGFkWIlFWaP2sWNKxYGwIYfhIryAfIo6DXvhY7I3Z5dte4CEi9eKycMzP
         etqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=R3T8ZyAyoMHHlQ7mzCO9SD5qQZw67sR4566poIyrZjk=;
        b=qDto/BT4iOa9d2ybelP1v37ipwuwJLh5wjnov1pEwGNE/3tG+Mlvednu/wv3CbFECl
         McwsHeqfbNxQxcuBKcet1A3Go4mVv/TJGlpxmXJ3TMZaRw62QxzZOxq64ohJUGTSr2to
         JhZY+eA6kgO6SI9J6C5autK8HvmMpcYgv6c5oy8H3P+V+condBFxfsnuc1gKL8+WX7Ar
         +xrdu2DKJS7sknP77ipsw1X+lOUka25hu11RtIv4YCG37s9GXJXkiNazrkRJgQSUUsBB
         9gAeT3O/tyudO6PxgieFCk3p7kZAX4wwgZyXCXbnpG7nnV8hF2FF7sb0EH97jMi0ZRir
         1VWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AFKYBDtN;
       spf=pass (google.com: domain of 3oqqwyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQqWYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R3T8ZyAyoMHHlQ7mzCO9SD5qQZw67sR4566poIyrZjk=;
        b=GaYgSijpTcAq9Bq69V+v20ABc1zUiNXFi+arHryguYF5zKz5j2foG8cezTCD1v3CzY
         RY5TPkFknqKNP2+8ejVNIv/qfm5b2OuxIscmLdYqkhfbDG9suRfFX3zs3PwY4S+TlhDf
         W+wczpp65vjrHfukcYnvDnvf4sglnEFAdMUMg81sSBnteKgar4rqdKrdAGMyCrmCCeiO
         3Ad7sg4xRx6jqFjhle63K05n5YslNtTW8qMTLFSN9hd1kXH5sEFJFdCZ++E61lSWUQlK
         T1/ZZdivd+VJhJMSReH3EqyZLgbjqlhrGcGjVKmOnd2f7Dqyf4xZkFlBiOVgO+TVny4B
         vN6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R3T8ZyAyoMHHlQ7mzCO9SD5qQZw67sR4566poIyrZjk=;
        b=rNxyade2w5HXspPEoD8TWyHyMXY4M0xq1vJM/0AsEtpyNSTc/lq3yWbMIfoiC1SxIX
         Gfh2nOYiAxNHoV6wCcfbNKCl3cqjfmqtDl/lkrKGTxgeIGOIwmWmqp2sufla1IicvAJs
         zPtBDb3u+ryCFNpHRCKEsslaBLLL2gwpLMAVrtaDe6VhhUrOeLMNhMoDsH9gUP/6N72/
         ULZJLukuuWKIpxBOpWu9JQep1ynmGK1E+AztgAtlsp3Qj+5YXXEQ09d1FnAH4r2Ph4e4
         lEpLPcA22EnMI9arxViBtv4aFHsji+WSwWs+F7DyVfxWPBnFw2o32VgcvXJoP/rAAJIm
         8OLg==
X-Gm-Message-State: AOAM531pE/RMEX7kdoX5K7m1q7/3SyozfS1g3QMa0XzSdkw/UT0VZ9Dl
	l17ROLg7qaLi0/CB5UJWcYU=
X-Google-Smtp-Source: ABdhPJzXMKAtMOanCpv+Jz1iyyJQ1RmHF45w87gI+0yTCfDhP95gYjB6gcZ/z78gHkOy74lnr8IA7w==
X-Received: by 2002:a05:6512:3e04:: with SMTP id i4mr22529222lfv.167.1637223075420;
        Thu, 18 Nov 2021 00:11:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls1607154lfb.2.gmail; Thu,
 18 Nov 2021 00:11:14 -0800 (PST)
X-Received: by 2002:ac2:5d4a:: with SMTP id w10mr22516621lfd.584.1637223074379;
        Thu, 18 Nov 2021 00:11:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223074; cv=none;
        d=google.com; s=arc-20160816;
        b=aB+ezk3pcpd5MrKDYYquBqpcW57JslhZqadTpEL9W4wrGde+LbAldkHaqAtGF8Va1d
         Wo5ny4p8XsXJZx/pRczCbsHdNKbjNxUFk6HTd2Vt7uJUZcnrPEyzlgYR6+PmEgrZJDIU
         vRVJZ52ZBrH30LaOiVPHjEcVifro1nPsilpXUsZng3GV6XZX+Iv4e5iEwsK8yj94x7bi
         sS6cIqSiqFko6NEPw8AQROzfDla2rlGKT720aTtaF3wH0fBkcwBhRC0RBpY88/DcbLYY
         MIFn4i6oyDpZ0DhxobwQZBQpAMkzvBWVfHOkc3FliXJLrGWQL7dtT4ykRxV3/VRWgzKR
         aIBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j+xGmYJ7a6naxsOgId4/Y5ehX22eJTAnRqZAmnKJeqk=;
        b=h+IneOsvJrtHzYpNuH/78Oz9aWU+f6r+HS7hnLj4rKhrkpG5ZLyo2IuHcxdZRn0jrl
         pu/KSxJM2E/pu5/PquDban0MQ32+Oqf1p6Af6o/SwpCBJFl3fe+sWX8d0kgfsEc/7lzv
         70WJnYuBK43mqYGexNgpj7yS5LPRWC/iNPGUk1SFwKocWXOb10Akj6dQhomJzD0kCD89
         gBt/iPJv7+hCM2S3jGvGMLOVkOHDnsSqBoLIENjENUw8dzTIl59YNCKBCMDjn7+ITmwE
         d45Hhb8DTNJ5RQDA32nXds54vN5asWEaMv1SfCAJu6brytKGtmMcWESNZT82dKgRUNKR
         CG/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AFKYBDtN;
       spf=pass (google.com: domain of 3oqqwyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQqWYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c11si137552ljr.8.2021.11.18.00.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oqqwyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l4-20020a05600c1d0400b00332f47a0fa3so2708810wms.8
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:14 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a7b:c409:: with SMTP id k9mr7703441wmi.173.1637223073968;
 Thu, 18 Nov 2021 00:11:13 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:11 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-8-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 07/23] kcsan: Call scoped accesses reordered in reports
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
 header.i=@google.com header.s=20210112 header.b=AFKYBDtN;       spf=pass
 (google.com: domain of 3oqqwyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQqWYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

The scoping of an access simply denotes the scope in which it may be
reordered. However, in reports, it'll be less confusing to say the
access is "reordered". This is more accurate when the race occurred.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c |  4 ++--
 kernel/kcsan/report.c     | 16 ++++++++--------
 2 files changed, 10 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 660729238588..6e3c2b8bc608 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -213,9 +213,9 @@ static bool report_matches(const struct expect_report *r)
 		const bool is_atomic = (ty & KCSAN_ACCESS_ATOMIC);
 		const bool is_scoped = (ty & KCSAN_ACCESS_SCOPED);
 		const char *const access_type_aux =
-				(is_atomic && is_scoped)	? " (marked, scoped)"
+				(is_atomic && is_scoped)	? " (marked, reordered)"
 				: (is_atomic			? " (marked)"
-				   : (is_scoped			? " (scoped)" : ""));
+				   : (is_scoped			? " (reordered)" : ""));
 
 		if (i == 1) {
 			/* Access 2 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index fc15077991c4..1b0e050bdf6a 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -215,9 +215,9 @@ static const char *get_access_type(int type)
 	if (type & KCSAN_ACCESS_ASSERT) {
 		if (type & KCSAN_ACCESS_SCOPED) {
 			if (type & KCSAN_ACCESS_WRITE)
-				return "assert no accesses (scoped)";
+				return "assert no accesses (reordered)";
 			else
-				return "assert no writes (scoped)";
+				return "assert no writes (reordered)";
 		} else {
 			if (type & KCSAN_ACCESS_WRITE)
 				return "assert no accesses";
@@ -240,17 +240,17 @@ static const char *get_access_type(int type)
 	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "read-write (marked)";
 	case KCSAN_ACCESS_SCOPED:
-		return "read (scoped)";
+		return "read (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
-		return "read (marked, scoped)";
+		return "read (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE:
-		return "write (scoped)";
+		return "write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "write (marked, scoped)";
+		return "write (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
-		return "read-write (scoped)";
+		return "read-write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "read-write (marked, scoped)";
+		return "read-write (marked, reordered)";
 	default:
 		BUG();
 	}
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-8-elver%40google.com.
