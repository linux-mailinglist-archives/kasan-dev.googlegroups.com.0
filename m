Return-Path: <kasan-dev+bncBDK3TPOVRULBBT5RSP2AKGQEHKVXSQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D883719B521
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 20:09:20 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id v13sf419282iox.6
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 11:09:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585764559; cv=pass;
        d=google.com; s=arc-20160816;
        b=MJjgTHE88kPiKdlYziOWaJZJKHlGIjPRO7s2RHpBohFpwKNc/yoGw9Noaq33rw3BKn
         E0tKXuio8nEZYOdeg0P7WC22H8PkvclS0S8p2Ic715qHWM7NvkFnhKBCRvTsC5rvu0eT
         d+6n63QfE4EOOX3pgKZxMpIw4AkcYuZUGc746BH0T7+iThIEq3y0h8TuaM8mqlpmYs9E
         CNpxmk9QgNJEObRUCD+J7de6emu+UgB/i/HA+zl18wQHL1a7pcKueY5Mn8XeI5BfM2su
         DyWzjd+ZsKt37FnWwvzZreXsOhfqL8OS0D5M/yqFWoDRMt7+dqVIvth0VNfBpx5NYbHR
         GIzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1Bm4hLLTsQ/N72YUvxufWr2KlcrcyOf4yPThhRJUKJA=;
        b=sXuXrnjE6PeUZRwo+O07Vc2HkgwU3AvSHfDGROxUrUePrhYIauLQY0l2lzcRRaRtyR
         w+hME0CVEq6t7IjeG6c7OZ1skOg8LnbFeenzL5ky0at7ysjbe0VRInvvpM0/DVL5b3v1
         yGKyDwF6G+Hv3RZOqCgClo0FUvQLvufmG4y58crqQw72J7vAaBAc5E/0cH4C0F8iujTP
         AYD0RDDEA0RqfH0yzyILbMsnQ/qZ/VCcAEGTHvCV1Ibqu19E/soGKxXi29lPByBMLG2a
         Kja6ZuJNSkcjg8eoEyMvoLXgizg5aFDuHJ+AHm/sAdiNVXGCRv3ASKk41uCkANSOwUYM
         seEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qnw5UGnL;
       spf=pass (google.com: domain of 3ztiexgwkcy0a8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3ztiEXgwKCY0A8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Bm4hLLTsQ/N72YUvxufWr2KlcrcyOf4yPThhRJUKJA=;
        b=YJepC+Qo1J4CzfQyWZlONtYrL7EhxPsotc99NkThXVMrmhdzyJXIkhX7tNmmTPOYFm
         XyHKOXWEOA3bBoLrxHQyb1zkrVXfktat9LZ5QG7PQCi6F4Yp/rpdoA4FtYlqmQp8D36e
         z01E7PvFZODrG3h0yj433UvlNPY8rfXB0Cov9b4KaIUtPdBZ9QytpRJmXISYOsHZm7RC
         BfiKXRB08ObZ2kmGts2u5LufBRY3byyH1nmuD/LMPAm6j58+XQ5ZAYInXMuuiO1qlFoy
         P+eSxNJyE7vpr+11xsh/p3GDjbyTAYOSRJeBjL8z7kRtIeVpokdWrCBUPRCiVpT6ydRP
         ntLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Bm4hLLTsQ/N72YUvxufWr2KlcrcyOf4yPThhRJUKJA=;
        b=ivacRurdkHL9JCcqBljSqVWpvE5cRtOW0CsUtYl/XwQsQDbHaZ2TdDaIlQT8J9FPdo
         v3X+9jnkAiL0avUoGVJve8iBYVRezzQYPTYUna4dTGX0sL8NpMi28/MqIPKMXphxnKXm
         v6zYIEJ0ewQ9m7aB+/VOwy4/i5GOQ05hf8LBHjpIpnG8lplx7FQ5T0GIoDANgy/pf550
         iSZtwKMzduanGULzCI3awCA7ZFlpx3wMf6hYfYU6lfypwwju9Qgj7cWoiF4ZHNuzATDP
         W/PkkZwTIZfBIM9Xnf76nrrQAzSqEOFXVOYvV5XF2nxEcDlMPXx+jvo8xetvXci2sf4f
         5Isg==
X-Gm-Message-State: ANhLgQ0tLFnCTILn5tY8TYFZRlt8WUObGMDPfpLA84MYtJ6WGhMc8Z7K
	dVSTVutGdnfFMYQrgR6bZKw=
X-Google-Smtp-Source: ADFU+vuCq4NUVUIEZnM1Q3W7JdLf8pJjbYGIA96kqFahqsmoabc1pvoRWcSsuK5En23fRWsdY6Zl0Q==
X-Received: by 2002:a02:ccf1:: with SMTP id l17mr17158886jaq.87.1585764559496;
        Wed, 01 Apr 2020 11:09:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:890b:: with SMTP id b11ls110844ion.7.gmail; Wed, 01 Apr
 2020 11:09:19 -0700 (PDT)
X-Received: by 2002:a6b:8b07:: with SMTP id n7mr21721625iod.55.1585764558978;
        Wed, 01 Apr 2020 11:09:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585764558; cv=none;
        d=google.com; s=arc-20160816;
        b=PzdFazQYqM1uTVSg3kD7L30M6nDGOG6Lt5aXszjEdLC1wx+ko3lt4zltKFaJt5688G
         lmrLWpguii+fLmiHa+7AxdzeVV94Jx9HHOPemsrxhNIULif4wa1VDIyhvquJbO/gBeXr
         Hjy02cgMQ2svMsHDjb37vXZhWJytbjXC2Fm5utNx15mgtl1pJjNF6zy4d1l/AR0g9AtC
         FZYkLVyXqmty3OxpvNcCvg4rOVofxBGrqs77fxUfZvUmV0aq1Pb+6J61GJtsdcZt0KCu
         A5dls3iG/ZVvngqfyQp2EutnEwDmtdh8OA5O+OWQtEmUgtRsOHAdbjcn1bWA6oWswD19
         Lukw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7tqR6IbLJuZB8xQehAvx+fGtdnXfyS7jowzmd4c+P/U=;
        b=xiTCPxi4hPmeWr7PDaxm7YiT3bXTIwNenvpu9dPvvxnxu8uj9f2LchDE6h/0D2IBm9
         CGhnDhtcPOQnwJhk8KabvVVarBtWo89wcdwGSqWln8sGXMwl9bRwfvNVNaoHmPxpKqJx
         HDBzfeuTxFPZl+lIUb7JVSSbdnldad1EuLmoEmGCXMGDx4sXaOFhBex8tVx/KyazwRNd
         B929YjES0MmSzqj3IeLnZNX0aoFq+IGd2nujsgHJKgoDJi4DHyBYeRm0RNjpugxUEsh8
         eZHR25Prr0/HYygvGEHpNXdot7UJWkaXd5QwXPmj5yuy6gOqLy893pr+ralHU48pPQYx
         EU3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qnw5UGnL;
       spf=pass (google.com: domain of 3ztiexgwkcy0a8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3ztiEXgwKCY0A8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id g17si247232ioe.0.2020.04.01.11.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 11:09:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ztiexgwkcy0a8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id n28so648981pgb.5
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 11:09:18 -0700 (PDT)
X-Received: by 2002:a17:90a:272d:: with SMTP id o42mr6327393pje.194.1585764558291;
 Wed, 01 Apr 2020 11:09:18 -0700 (PDT)
Date: Wed,  1 Apr 2020 11:09:06 -0700
In-Reply-To: <20200401180907.202604-1-trishalfonso@google.com>
Message-Id: <20200401180907.202604-4-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH v3 1/4] Add KUnit Struct to Current Task
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qnw5UGnL;       spf=pass
 (google.com: domain of 3ztiexgwkcy0a8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3ztiEXgwKCY0A8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 04278493bf15..7ca3e5068316 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1180,6 +1180,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401180907.202604-4-trishalfonso%40google.com.
