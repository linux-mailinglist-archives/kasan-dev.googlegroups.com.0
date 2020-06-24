Return-Path: <kasan-dev+bncBAABB3WGZ33QKGQE46HQCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B120A207BED
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 21:03:11 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id f14sf2072318pfd.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 12:03:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593025390; cv=pass;
        d=google.com; s=arc-20160816;
        b=KvudLi+CpKWOjUyLGnpSPSN554QVk7fpTdJvVJWEoKVEiH48/MGd1qxji4FkC3QhAa
         Ow8N9b7tuVjqVRYqoI5AUl7MsEqwGIKgl5GGgx4Qh8g5JoBpTzjzqgn8i8+CSYUflPZR
         +VbeSvZMXImqFALk6dGsVTX6JINT2rqWQLvWf6hFl0pQi3liStJSoALZB6orb4rlFiwO
         XsKgJMmTkAPBGysPSmSYKQcmS+JH56ACpwpfF8sKL5JkcePRqpjgUF5E7Bdwg5srlCxg
         eKwALW5l5iGp/Q1MGX6rKizDbTxlv9xq2FRvnOBwM08gp9Q+QVlU+GrRCXGr7WPoAOcA
         myUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=LKWxbSKzbKzWkg3qIXaXwYbhdnS5Lf1SAZBi/PBtGT0=;
        b=NoDV0ZejDBZ9yIQeOtKUCFMFK070ayNRjB7TzUQu2n7J7BAfRpJFzi/rGgaLxMs4c1
         g/+MfAkTYF5zI6coN1djE98UxdhaGN0tBfPh5sErwRMTzVAaoghwVcMiqlEzr5PSoHL8
         7C8sXATxlqs7BHlL0NdHbpDIZouifJ1Ad3uWkLgvdNeHdiMHULc/xvpTMCEfoWyPCHWg
         iY8fVgE50hDUKXNjCmZoBrlHDNOpYar1TumeUxTKhnfuBacLax4YNGcRKeJlaTTinGQn
         816pp9NTqDb6s74SR6f3dniKVKjZNQJqVtW1zPf3yxUXRrbL7xQmj1lSPoIDq54oAbJK
         pMPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fpCeZNxC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKWxbSKzbKzWkg3qIXaXwYbhdnS5Lf1SAZBi/PBtGT0=;
        b=kxFLVze4w+OSQ0JLP9ApdS+53QxQh20ImW1qscBVNcMhhry3w9wIZXxaaRTJIgN9PT
         Cx01TzjXivFDyPpLMTBtlTBOz8c/lFXgnh4h3hXc9tWRo6VTC0K73nV6JWHeru7TUAul
         iA/QxPX9ldqAHg4JbBFmkAgyvtdAQ9tikjD3JZLMtCcjjiptZKxUHIb9IjrAnuRj6WHo
         ou5h3RvV8TP19QZp7XUtk96fxzSIGc3BwcyuWZpcYJcGyILwBxTk9h0LLuL7nnoGgVa0
         fQZhQPR91qI39yWcU4fN/U6Xja1sqBRhXl6KbqUfdAnwzpi6L9idqJW3mQFusvwtXKQV
         EpPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKWxbSKzbKzWkg3qIXaXwYbhdnS5Lf1SAZBi/PBtGT0=;
        b=gKsPVXIFRF0o5yvvtcert6FoVXHC7vi0KjnFkXsAKb0+DjKpsCerF06mChSOUYkdoc
         e/2ReEKAcgS+uDSdMTddlLF6lO8mZfMsbHDboRSue1ORcohEYqk28eKufCOYJIymHnMS
         qZ9oc+K92EP9eALwrERNn1xai6/dpcKRLT8ktg7wcCJB8pongGpZMaQz+40Kx+0MWtC6
         yS26cAEfuL26DnBUV3vB2SXWe8k6MnVmMO1pXe+ugn5FpCcs0xc82qjGgg+pPCn3veJy
         uST8l9x9JrvUh3HtygBboiNFl/rg/0xHh0GbkdAOmW5v6RUHI3eWJ7xdS+b9WQNuULOp
         LOjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iz8WFtVdjbxssuqE5IAigiQiGQDwuxeRaE/6IOsPVLa1lIDeo
	o3fbF3UA+/8drJIuXGxsPbE=
X-Google-Smtp-Source: ABdhPJxIbixk+1XbzIydZBMeEPgwCS/Z7OiPsToHzu+zLzguspkZrlHuB7z5euyhZPOd1oTHljCMeA==
X-Received: by 2002:a62:f201:: with SMTP id m1mr32950700pfh.198.1593025390372;
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7143:: with SMTP id g3ls1334499pjs.1.gmail; Wed, 24
 Jun 2020 12:03:10 -0700 (PDT)
X-Received: by 2002:a17:90a:a383:: with SMTP id x3mr31167072pjp.199.1593025390118;
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593025390; cv=none;
        d=google.com; s=arc-20160816;
        b=crA8BFFyvV220YZy+8kkyxCHa0ALzttyo4vCy8wtzYdxe97TqqOg6W1/IWzd2nFWq/
         1p2umSMWxAZ3CSY/ogABmuNg3exHA5jdRrcGO2ubQ6BE9jn40VS5K+H71Mo1HmtwhEJL
         oBI+6NJZLKoz29A/wrKrhTwUUpNlm7T10hqR6+SrWAvD7KmKCCy9hvG270B6t9ZgZCE8
         ozalOkSE2G5ZR+VcBeraH9PfAr8YR5zXmJ2ckqoDNtsB5i9SLJ2dNT+uWt9AIt2ShLye
         eCMvOknh9mE/QpkgjeZLHULeeHsOJ5iYIT6KL8tgXa2RS97DvmDLCgPqH3cZDAtqSEGb
         ejZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=dTMJAP/iQ8/xgSBl7vlac9q94fIEEWPLMN/+Jk2eRME=;
        b=qscVTpgreOqHn9qjerqgKtWjBbpAjO9s4Vs1A2qsJ/m1egGeoc2iSJiaDn7S/6MC18
         IFxxkm1jYoLBG7C8wEyx2q72zMYyIBklovXoC3blqjtA9dVxbZuorauyhDvM/IMyfGRp
         VLJks+3vt8HtuaWBJPYB4oPMxitctHk2IYzj9d5wW14DhMzge/8OJh+XIwxjGqlcJvKp
         4OBVZ0VYDoQ4lyDQM+cYAOlepaQyo5KGEMqyhmtdrKJ2LB2aXsQFNuF5GJQ6T6PbabjC
         kxzCK2DsPXfPJ61HHSThc7AVjdiO/WqO3uDZ1Pb39JELRxw0SpzjB6FmonePa3BPzDo3
         1kxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fpCeZNxC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f3si1252273pgg.3.2020.06.24.12.03.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CACD920885;
	Wed, 24 Jun 2020 19:03:09 +0000 (UTC)
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
Subject: [PATCH kcsan 2/3] kcsan: Simplify compiler flags
Date: Wed, 24 Jun 2020 12:03:06 -0700
Message-Id: <20200624190307.15191-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200624190236.GA6603@paulmck-ThinkPad-P72>
References: <20200624190236.GA6603@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fpCeZNxC;       spf=pass
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

Simplify the set of compiler flags for the runtime by removing cc-option
from -fno-stack-protector, because all supported compilers support it.
This saves us one compiler invocation during build.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 092ce58..fea064a 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -7,8 +7,8 @@ CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
-CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
-	$(call cc-option,-fno-stack-protector,)
+CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
+	-fno-stack-protector
 
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624190307.15191-2-paulmck%40kernel.org.
