Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMHA6CFAMGQEH6SWKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C30442241A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:01 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id f10-20020a9f2bca000000b002c9abdb45f7sf10382797uaj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431600; cv=pass;
        d=google.com; s=arc-20160816;
        b=RkTUnnxOrOxDbtG0RarhhHRXJpQ/X9fD2L82KWCHO1S5gtvzsMUKk9IA+3QvIlFfN/
         TgyTblSBDQU3+7M1QGeCI+vWbKTanGU+xceobhrPY2PS6kHscIkMvS3wEyidwryw+yw+
         8IjU02S87n+9W8U9KXc5N5EZjpANV7jReli2uspb3z3Jg54mFIfqTaEVp4ZzOaG7+RrH
         +GqThTXWBbWfunjM15FZSDvC7GB35umdgL2f+OF+1s1WFd+JDOtTOzdWXdjkH1YpN62O
         Voh5XbYSlhL0LB/c1hb5NiFWEJZIhcAULDtsUlZ9LoO53ibwO2cfXERu1UqSIBsrVUSv
         pRiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fxuwBii8/YknW/dwMvKiFWCq/Ir8SgnJ2ZfFZJMVpsY=;
        b=IHahEn6Ye+R8G9UBHl+MwZk2j2LK4XvpgDUzACL8L8cUzX5fdq+2d6MTmBi1MGcGmG
         fZdzWUZBk9O+DbnHfH835tSiEh5mBGg8NjUdNQLa/WwhtHVW/sGXIIoCmqlu8Pp4QFSH
         BZq/zS+2fQYCljODSEj7aSEVRaGoudXz/OEhvSw4pUWDOoojU/niJPtf693QepDC/Epv
         PipPjz9l9ah8IdJxRTCJ2GBoNRRXZdTbhjbZ0ZtL8C+WIZ8tTFsVOPfwVCs5EY2TM+RB
         6zgRCr5nUgjJRCTRmdXfvT5meCI2WJWiyHme3Zio98xfIxCiGDLOGai/Jpp9C+dssiIK
         4QEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qNNeZUdV;
       spf=pass (google.com: domain of 3lzbcyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3LzBcYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fxuwBii8/YknW/dwMvKiFWCq/Ir8SgnJ2ZfFZJMVpsY=;
        b=NzS2qFoS9bzxQFFQLgjr6mTNTxH7ySmPJWMAG0nwZjmyaFJtRv0BijI1bx8SYLDhzd
         rdszY1iCT3o+30lZJ/8aJiKc0dAQvNxczerhxFHOlymu7edfNjaNRdK7Sf1eyqHqWR/p
         U9qawEb1lzqD/BnB9FrwWZ+E4SK1Hmvd6/q6hVQmqZjif08aGI3fAGXZdVuOpQr4T7x1
         eNbq6O3GtlgxUe/FqzbhauRPK9fZdCzQ9mQiiPoQ1ffvkdJWikdQjKflxiEl8pkxOGMV
         aB/rp29h0/o2/gmw+jgqr8YraacQj405ewpjQCiW7rkBkmzAwZeVhotVsBdJ2tRG8OXA
         Npcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fxuwBii8/YknW/dwMvKiFWCq/Ir8SgnJ2ZfFZJMVpsY=;
        b=fJxwVQh1hpV5bDajqODsXaq+Qef/VTKzLKje5bAZoTFMZW9qBQV+BU3FbtUmovTE7y
         WH0o+3I80q3CaeaGQbLM6mi/xYjcCE3QpgAxntsqiIv9YevB0Iyyi4DLOhlSHAWCdd9M
         qDO7DslfyRpBar1RHjeuwNlYCfKhzrZzP+w0jA5YIpelvA7cT4GvNA+lMTUBXvphpD5p
         Y4P9ltx6NaSqwCKhnuU3OO+uzDaEK1WOmk99pcSu1Fk5vmQKjcTBZ64E20CEjgFu906m
         meru3UDUe4vBtmK+yB6RhJL96w7BQ5NSm1iDdAXilYTZpQwaNn04shqg9I9XmSWjMV+i
         jt5Q==
X-Gm-Message-State: AOAM530qVMlK2+4NQ7aFRxj1R0nBqPwqopnokW2LR9CKcFNonrv2RN2t
	/uPbowrLCREYxKE3hDVgXeY=
X-Google-Smtp-Source: ABdhPJyrGN1mgzFTYiDbA8n86sd76Yke8XlNrkBYT4xeH3CSRzd1zIr6Mq99o02lri/WzYQyecMr7A==
X-Received: by 2002:a67:e98a:: with SMTP id b10mr17615115vso.48.1633431600165;
        Tue, 05 Oct 2021 04:00:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:628d:: with SMTP id z13ls2997947uao.1.gmail; Tue, 05 Oct
 2021 03:59:59 -0700 (PDT)
X-Received: by 2002:ab0:2404:: with SMTP id f4mr5341080uan.102.1633431599695;
        Tue, 05 Oct 2021 03:59:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431599; cv=none;
        d=google.com; s=arc-20160816;
        b=Ax5MJgUeV8O5LnxKSmnbU3peC1l8uZpWQxzLT34vN3LF6bxaKTobNCS4PdU1pes+C4
         593Kmm0IfjvxRctUgllUCzH2z0n0cg3HDfquhjmeXUVjhlZBDoCRJFLIuOO0hryYD1+8
         TeXyOwlZL7RakCfXcphW0S2W3jGfI0WluqX1w7tmnnFy92Bd7RYRlq+QLpYaNnGUsPzH
         W43fcp2V7o2/5iHkbL4z4rp4S+1gsJYkHHaP2JDnwt0iG3ogCqEGzv2U/7726hJzwnQ1
         piUEz7V7IOFwSowIlSB5KTvjjgIDyvoJN5wRmED7DeBWflrkldNzcz2UNYy3Q5MEoTGR
         VHGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=L+fd37WmAy2s0UaVk4scjeutYzqXSn/VtNkU4zfPMW8=;
        b=Ukyxa/6lrZ3hoRolE4QbM1xQuTjfGXueinqvSM4vo+HaTAkhjg8N6xTovoDoNpWA98
         83V1mVqVasyohp7wyYhlbjW1m02VU2LrmhBazKlog61zZonb2zZvhtrvUKlj4B+6/hIO
         XMs5+iZcPuZwfUdm0VR2C6WAszt6r/rXsn+eifb/AS6o8MVPswZDtN9XdhnVFX9tP6CM
         DDg7tsbArfKd0Dzlxa+0IsUcHSxoqhF2VAwwPHDx7IWuuoQ5ARLwMKwrmbBIvWry3eTn
         ZxRg42dxuL7KmjU0rovZjo28QOENko79nKNTqfoBocmEFz0Cx0NnVfV0PCtPOmJ5+Avi
         XzUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qNNeZUdV;
       spf=pass (google.com: domain of 3lzbcyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3LzBcYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id a189si1206322vkb.3.2021.10.05.03.59.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lzbcyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l22-20020ac87b36000000b002a6c575f419so22778089qtu.23
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:1083:: with SMTP id
 o3mr435430qvr.57.1633431599435; Tue, 05 Oct 2021 03:59:59 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:49 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-8-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 07/23] kcsan: Call scoped accesses reordered in reports
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=qNNeZUdV;       spf=pass
 (google.com: domain of 3lzbcyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3LzBcYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-8-elver%40google.com.
