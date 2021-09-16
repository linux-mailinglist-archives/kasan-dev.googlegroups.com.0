Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 26D4C40D0E6
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:51 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id v1-20020a0cc1c1000000b0037c671dbf1csf23004144qvh.12
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752310; cv=pass;
        d=google.com; s=arc-20160816;
        b=0REOeVgFKtEkwf9FPNJjMv7Pi/sGSzaEwox91HN4zBhergxY89BntZot2kQuXC89Xf
         UKBME+OCrBhlwbJ/No9weX7tm472JOHmGnkcZNB/rFXWpkal3lDNy6+AYDGprHX8LCj1
         C5S7xVg6IT8jJySOEq89G+pw4HtiOW+ybK/cNgYJPOuUmKd6Om4cCqXlZPBIZnfbmJiv
         pmgCMtA76Jcitv+ZrKcFJ1C8U5ODnc+nYRYETuweEjwJMPqGhUHmDZStV6baUNMq/AoV
         xf9H38Lb5vqKdLtgz2fS1gJLmXeUVR9kwdy9DQrPgVYRnFG/gVNuhIdbePaKZFQJlvrJ
         T84g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4+dSz+7cyVYRD0nRejxqrY9Mjqt5qpcMDYhgFqvRSas=;
        b=fcSeh6qS/sNfBgl3yUdmWpJs4rxNS0wqtJ2eDXEec3ezyGKe3To256qHp5syaS9GOd
         YzIgXdb7QPohpty1R2SORsaW396iVFbYW6HE9hkp3ySQwULeZ2tU9drhuzD8Gs3G0ZKC
         HZ5BB1+IWTDmQoh+wu15atokhWGcQXevqoxH5+k9RA3TVETBTG1WqmMx+Q4mSU5h417B
         ygfoUroUwAZSvBDPIYnDVRXY4fclhTNrytrgWx/4ZxGhDwZ42+XogvHr8KYpY+lka6K2
         MXyagzSewObJc8sKLV/Kzv/FvDwz0/rv7RiK7YkToGU8B3KA0aJarSRXJbgEv3oMc1/z
         EOig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=azZ4R+Qu;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4+dSz+7cyVYRD0nRejxqrY9Mjqt5qpcMDYhgFqvRSas=;
        b=ZejgaJ5gzZUoVhJYlpJxJEY6bXIaK/rCSybnQScLANkQz0SFx/Qptk8lE6sfTGrlWq
         yYK7CgR89N6jr/4Jrl3mXsJDa2YNtThys0dyXqgDgBi8fwrQMlIVAevnIID7OeKF+7UZ
         WvK0c+VP52333Jop+KaKdm3QqWwzPqKqadwFJvWcnMo0rpvRvCWjEIvDQUZGF5audwr+
         BBHrKrM4yV4ePxHO/BGA69z6B09BfolrykbB+lBuDXJH+C8IlKb2PWFhYTnAzy2pP7VZ
         R14+bF4jhHUlAfNZ1u1a1DZOoHMMn74eP0abp0r8rb8N/zUw+ESPOQP1p3K5o5v/1UJg
         Z2cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4+dSz+7cyVYRD0nRejxqrY9Mjqt5qpcMDYhgFqvRSas=;
        b=Sb8fQKqqSmtPFpzIbLwjNAAZzpRV8tR/VnuUKo+q91/Oo5stV8gkp76x7WY1+qKHu1
         T00DPZxRAiCDPb4WRFiVwmdwvgVZG6SJNmnt3ZFo1f2jMSHjlaq3ubpj3QmbC45gpNaF
         5e5yUNiryyT4AcAgxZ9IXg1ePMYl17g3/XA3Ip8KbDodwfrgQ8Pv9jI2qBqDRp0TQULM
         M+oiqSWfxAKbQNN5JRm7004snvn7/wH2sdPkXqYRag4KTSJkPA3T+dFRb8aNNXA9esui
         AD8iS88QEdL7Xm0afrJSHSyD+OcwATjgyCTi8iOnNsV9gkylLeQ/kLkmJb07xk/h7yhC
         NyGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HAEd1hSEjuxEKQAdfqHhXJWAEWGiyakJs1fLnKs2F7SbgAL8y
	qqkGJTEgcoUaQ+izrUbwAxY=
X-Google-Smtp-Source: ABdhPJxp8938OkYDWm3mzNwf1lNPDuupRbOKyw/BpFQ55OCvl0yY2xGFyoybgcKlfXA92kQQ4DQDuA==
X-Received: by 2002:ac8:6054:: with SMTP id k20mr2650498qtm.237.1631752310022;
        Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4e3:: with SMTP id cl3ls808727qvb.3.gmail; Wed, 15
 Sep 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:a05:6214:132a:: with SMTP id c10mr2675287qvv.35.1631752309562;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752309; cv=none;
        d=google.com; s=arc-20160816;
        b=va/D57mmOm3AO56pjelL8bkiFri5TlFdBRz317Ga6kn/mAiuczg62og0LJRdUVW15V
         0fpdHpziLGXH3qZxOrU4TbXwJzeCjLcIoUJ+6WVgn0gSq5ySluAqgDX/BWulAilRUg+p
         AtgT9ZKYxr8sdir5QsSVoTate1RajhC30abL/ZpnLfVxzftzQCNj6doJF3hqw1rDI2Qm
         NpeDsRUGDl6/teDLSkCk3ABEKCmqUSrwJsH5mW30gKwdZ8TKZeSr+tz2PrLgTKiGuFS9
         IFsDsDA/Ck6sLDX4MCl1slhziKrpdCYly7YAsfkIVVfGsoW0ZxNwyyANdKHL75H9RYPP
         iw7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CGG8HOnF0k1JcbL/1ds3yv2zTuSf/Y5Lj7wNCwfYXnU=;
        b=kN4q40C7/AEVa+9vbfxLN6+9NKyVPNzphe7kR2QRvHBbrWkTFYMT8KWRGGmVqUnDr4
         uAYT8P7LD/zJnNn5AJ7ZlILmFco9XjhJCEdu6uho6rI3n/KndP/p4avxN54DA30eaW9f
         evqKLWK/VHU1iOuytcmjQkvW/P0rnf6sGCmB88toKswBsanWuUatVQeDpokm2uT/PR4V
         EzF9SopSwSxqbiTe2dYHYCOk19kiU+ATB5uXulx60mc6QqPSan4reDe86y1SZQqozVQE
         Vl14WP6Ckvzpu3U77BNzeldm3Gb5ibBsDO4BTiNwA1Joxj8/a/w6ZZC+02sRAwdHm+ZW
         pUCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=azZ4R+Qu;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d201si365835qkg.4.2021.09.15.17.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 110626120C;
	Thu, 16 Sep 2021 00:31:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B7FEE5C09F9; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 7/9] kcsan: Support reporting scoped read-write access type
Date: Wed, 15 Sep 2021 17:31:44 -0700
Message-Id: <20210916003146.3910358-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=azZ4R+Qu;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Support generating the string representation of scoped read-write
accesses for completeness. They will become required in planned changes.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 8 +++++---
 kernel/kcsan/report.c     | 4 ++++
 2 files changed, 9 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index a3b12429e1d3..660729238588 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -210,10 +210,12 @@ static bool report_matches(const struct expect_report *r)
 							"read-write" :
 							"write") :
 					       "read");
+		const bool is_atomic = (ty & KCSAN_ACCESS_ATOMIC);
+		const bool is_scoped = (ty & KCSAN_ACCESS_SCOPED);
 		const char *const access_type_aux =
-			(ty & KCSAN_ACCESS_ATOMIC) ?
-				      " (marked)" :
-				      ((ty & KCSAN_ACCESS_SCOPED) ? " (scoped)" : "");
+				(is_atomic && is_scoped)	? " (marked, scoped)"
+				: (is_atomic			? " (marked)"
+				   : (is_scoped			? " (scoped)" : ""));
 
 		if (i == 1) {
 			/* Access 2 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 4849cde9db9b..fc15077991c4 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -247,6 +247,10 @@ static const char *get_access_type(int type)
 		return "write (scoped)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "write (marked, scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
+		return "read-write (scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "read-write (marked, scoped)";
 	default:
 		BUG();
 	}
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-7-paulmck%40kernel.org.
