Return-Path: <kasan-dev+bncBAABBKNH3X2AKGQE5OU4ZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7742E1AB0CE
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:18 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id br11sf842526qvb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975657; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vidn9VfkSVZnnJ6OW7XYx4LX8fOZB1IDcBAypZgplbGKTOGtscq1/Pj1GkRe8aiz2L
         ODXDcCJfWTpNzkGiWbAkzqDfQijwfFc/Z2L59ysmemD4shwormLVz4kKDTmS27+VkvwO
         e/tcs4kLOOLxQplHJ5MRLx90VytNBp7fQRImgHkO68fVct8CEhfj8+M9WgD9RJJ7l9s6
         jb+MbUFoabQl4yC3QwKEhlL4nMNsLzE62FiyvPb3HW/SqOyK0LOOoTMol4+Yl42nJLsC
         OjWhplKiwKDfVamSC0TqcUrvw7V+g/Nxs+7jI7vToTdnlbnj+w/EfMpi4gzFiuYeAswM
         nqDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=a+ZdETs0QpWPvrt1fM9OkDWhjvv+dufIMqLa5AYc09k=;
        b=rCTBBf6QtAxsi16hblEvN4iLA1nRKaNwAIubGDtH+6QWMW9FhAEuvBYUG1Egmz1Rf8
         krG++b8WrKdwlMiIStJJf4743n7PoQjiXE4ycQm5CCwrK58vcxkX/N6j6Kw30AKF8qqC
         Eh//32dQv29s1Sh/sob8IQMaWia5TJRdm85Acy90Dq7ufjupjflgUvGMiCsbw09OsADr
         2uFXL8uXJjbOKkFx++yxRSmHo4+H/1W87HUduVVTBdpX54OZqK3fCjPwWXXgDIUsvwsU
         7D5BFZ9ivwro3vkEEfITm8KgOYD66sVf20OjDUPk6B/dnyEpzy53zN25+lNLHBAhNjom
         FISw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DXPlfztC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a+ZdETs0QpWPvrt1fM9OkDWhjvv+dufIMqLa5AYc09k=;
        b=Hp7fRwTQLwKt4JHTj9UirT+8zZS9Cx541Kwqi0wzYmhbPmVHxzqlDBtBzwy+ulRySx
         HPsihSYnCuH1FPQK0RroVqqxoJduvOs5+ZpGt0wvGvSMFqlY16zvVHVBBclvD1JOjJ6F
         Q5uxHZmT1Y1+8WqOMjJAltmF0R/gotf2L8lsqK0UW2ew1zc4FbRdSrHOTJJqWdneAIy4
         OSwa06xKEX99F/Jlyoi+KJpK8u4h2MfBmrsULYT4PrLh2SmgA3Kvt6nlPl60mYxLR7Na
         I4UzYyGmDgWjVERUf/uolTSBPF5DaEeDiRwMFAiCT7W99RYc1NyfnaeOrNEAfooPIaYY
         dVfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a+ZdETs0QpWPvrt1fM9OkDWhjvv+dufIMqLa5AYc09k=;
        b=tCmco3nJTCK5J7FcqyvEWUseBPmuBDRe9PkepRiVxxaucNaxQtzagpbKNPUoRc2vWw
         NfSHKvhL/9FsBSwYMIpdWpYJzPql7/CNekhG39mCHvnvnAIfDVQLy6/C1bL/g05PNC2W
         qGtqxdyCeuQsxzEN/RbE/mX3ZC/ilgQ1cJRHEYX1JfPaU8vL+kvGMtZbcPnHtFzYnOeq
         K9j+eVfIgqHTFmOlByEweXUBDgSXlJnzDf3v7cfPH5Nwx00aJ3YKvuY1p9UBRLDZpkGx
         UmxyT8c6t8efR3zgKZ7uYmxf4eFRnLQsrYndD1AUg56iR3uV56jy6RHawSuHv5DivQ8i
         uQ8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubtDXduUdK2Y6QgN3jjBISLO1XeVz2yz+D2QfYr+bUqx32rIg2T
	2AVhOXC3ssbiPBVagZYnW9k=
X-Google-Smtp-Source: APiQypIvXdKFdefk4aM1Bek99zlBL4/+DYwmdY4H5sLeRgHK4Gx2ne9m7EKPN/demNJLDYN+3S401g==
X-Received: by 2002:ac8:554b:: with SMTP id o11mr22606089qtr.168.1586975657087;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5217:: with SMTP id r23ls3966235qtn.6.gmail; Wed, 15 Apr
 2020 11:34:16 -0700 (PDT)
X-Received: by 2002:ac8:1b70:: with SMTP id p45mr22738862qtk.258.1586975656814;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975656; cv=none;
        d=google.com; s=arc-20160816;
        b=SF2KF9Ke526QvMmUxrPpF5UGmiZ8vMcdCh6W2Yu+c3cWflJjgzz8Q+1mSBJ6GvFdfJ
         Y95O4TUAW9hdMRx3TFrZO6SdXjVMWSUgnd6oAoed69JEVmUT/WFKNYhuxTG7eWag5PZT
         zEw3emm/Q+CUzmOIgslk5qaCiozAUnbQtIsXhAjZde9UmzUbQapsUFIF21kWIazYJPOK
         NHtUccnb2BQhL0oXP+KmFczEU8NLpXa0JU+pfLVPUoYFvlZYXuWvK8s9D69rDzlDLH10
         ghTfmArY6QfXWOOUKjndhhcP3qbxkXUK8MglogItmtGbCxn/zxxBBUFQeQKRDL3dkKvY
         +Xfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=yumnNzVNUe9o3O/rYbCDG2XcFq/hAkFquqUnMLG5IJo=;
        b=0Vf7OSHigVCShNKxkGNp4Z5O5PqUYxQcdlfTNIxCYKFLZ+76xs7YoPPhggca5jEOpA
         0vKY28PNSv9EFVyXA2oLI1Ap04P3ns0VcdzQ1J2wGm+nIOHkA/4zm6PTOOqi51oqOJ3g
         pAXzp4ybJ6NhzBrYJq8ISvLkWG/0g0HH4GGS1THBKp6wvt3TOSsprKOZCmU4EitXSK57
         wqi9qGbZzZwZnSI4Lzax2YDA7BHgb+ZRWrxw+60e4LzN4SUoIT4bqE7TQASXr1scN/Iu
         T6YXd08vJyoJM0vvof2IfXrytw6oLO0LboLZV72XP4NukzoJ80IPquQDtxhl3lBr2q95
         dPgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DXPlfztC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o3si985707qtm.0.2020.04.15.11.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9132F217D8;
	Wed, 15 Apr 2020 18:34:15 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH v4 tip/core/rcu 10/15] objtool, kcsan: Add explicit check functions to uaccess whitelist
Date: Wed, 15 Apr 2020 11:34:06 -0700
Message-Id: <20200415183411.12368-10-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DXPlfztC;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Add explicitly invoked KCSAN check functions to objtool's uaccess
whitelist. This is needed in order to permit calling into
kcsan_check_scoped_accesses() from the fast-path, which in turn calls
__kcsan_check_access().  __kcsan_check_access() is the generic variant
of the already whitelisted specializations __tsan_{read,write}N.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index b6da413..b6a573d 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -468,8 +468,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
 	/* KCSAN */
+	"__kcsan_check_access",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
+	"kcsan_check_scoped_accesses",
 	/* KCSAN/TSAN */
 	"__tsan_func_entry",
 	"__tsan_func_exit",
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-10-paulmck%40kernel.org.
