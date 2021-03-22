Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFV4KBAMGQEAAU6TTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D10653445A1
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 14:24:48 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id z17sf26004475wrv.23
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 06:24:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616419488; cv=pass;
        d=google.com; s=arc-20160816;
        b=exc6ks+jT+E090bxLwN5b/kAxjAOVxq+tvWy4CiQwLg9cFZmUI4wSC2i2Jj4TVUrJF
         6GG1OOzX6Ero0WALCn2QLhcGsbyZfusxGd1wzJiHnxwqAiC94Pq/WOE6J2XSv5fPyEtg
         Ob1QEOdyEIG1oukLfXbhFjLy5A4aqBwsvWe7BnL4Rrh5ypZOKlJBztIy9kVr8SSusZ1O
         8Ra8nAQfnukgonnDP+yhEytt+ZDAbT/GGiQW1dE+0hR6wCaB69N1RQXz+oQWh402bbtj
         HcjRvfmGEZ0k7GZui/h53FK/uHm1wPdLjHAb1JRxC2cPAoVpkp3qEoENWyY8rpaH9HUh
         PJMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RbCb6olouheD0n1hrYPzUXnf0Snt+h0OUTQ+MRmE3go=;
        b=PhyA7Y6i1SV8RQ4WvTAyEb295Z1TJdRai1r8DPESzSG98jSDXk527llHYTEu3gFB5o
         mNJR48cizaEaIe2iBb/CkKgXtPwfIgPW0AZF2Jx87qTGlZCownlOQTiUIGpZJB//MkzZ
         eVwn0UaTvd6SyTtzxicrqQwl0fjmUYwTcpWuKsIfcRFPnQXAmDgoeqbmqHWqel1mrfGp
         5VGpqdG91ozqzIXyL4pCdEKgEHG7nMvbnj9M9u93Z+5WhYPb/B+9vcXCEOZHnjo/nA5e
         QLrwRQ/hKFZD9LYPTWS5ICpWjOYtRT1IPUpDqNRN3Bq8dkAdJYBQlrikwnmIJb4Z4133
         CVew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GOqOWv3P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RbCb6olouheD0n1hrYPzUXnf0Snt+h0OUTQ+MRmE3go=;
        b=GOncieR6OB1YKZ2h09axs08eESVrFDpuLQKbUohsB71dzLbgAbRbqhmlVYDcJMz9ql
         QZO5e+R2e2csZcpKwVkPvVz9McRo8qZFdvwVRwPh0Xj2RIAR2ZSjoSUwEkOIAMNKJwgS
         P317/fFxoNvoUgws58x28scie+vNm4/BP69vdKgPzz7WyhWi+19aJk9LlVH1C54lvdrN
         41eXOSgQFyt6zXG8uuZ1tU/Vw6Z61VhXolDF+DnzShxl9mDzAj2l/tiL1PA7D8P1SyBF
         jZzkmC1ylzBCdGJY8Q6mwqjqbS3BrGwAf/0rbbKnCdMlvhEKMtTMiMF7OvWdn/45qEfz
         1v2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RbCb6olouheD0n1hrYPzUXnf0Snt+h0OUTQ+MRmE3go=;
        b=KH7YMRzfH6jbTaeY+JLW5pbxS9mfO42NdgQFZ/Iw59OAU5Ud8H3/c14LX8F7RkfgNu
         wLb/ampNnwZNL65VTNA46rVzwfih0FthREPuy9SPjS2Js7hqRhGogJUFMgD4zTCtB/hh
         +sx1m31bV6uVRvAn64xNM40aOVNauhyJWBvowyJCJLffLBxZ/P4+Y7T2dDrzLoav6tXY
         Ui5VLCyvdF7OfWFilEHihpE/Z6h2SOnCm/djQPZ3z6hCTqeUIZTVFkHsMMTTKO89TwpV
         x3CKCQeqCDo91p2b/Yw0O3Eyji1ne5/6Qj0J/iHFBnjHL/QbqtuUPWAX5Tm2eBK8WqiV
         87Ww==
X-Gm-Message-State: AOAM531N9zsFwLUxr1NB+NPu6jOlr7ggknNCA5oDxrAveWslCMKFJiMs
	kYT4z5lZPowevHl9dEYKgFU=
X-Google-Smtp-Source: ABdhPJwC4x9gCl/Fh76OrOtSuYJTQQ1ZNEAk9wpaylQav8C/SUnzKHrqdj3NgQgoEKGZL7AVfkVHbw==
X-Received: by 2002:adf:dc4e:: with SMTP id m14mr18993526wrj.248.1616419488666;
        Mon, 22 Mar 2021 06:24:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f8f:: with SMTP id n15ls6131756wmq.2.gmail; Mon,
 22 Mar 2021 06:24:47 -0700 (PDT)
X-Received: by 2002:a7b:c34a:: with SMTP id l10mr16186793wmj.46.1616419487714;
        Mon, 22 Mar 2021 06:24:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616419487; cv=none;
        d=google.com; s=arc-20160816;
        b=WlYOgi1sR1LMjcc7u0M5w6uK6K2yNXP+pmrz2KwZTkCaPS4wr2I33XSdoRZRazp2ZO
         e3R3lnmkJufTYv/Oyj90DhX4Z3n38zMja6SNmlVWs7S3eVJI51epE+I8d5C8E/8lwOez
         F48bY9raQyvxudj/yisJ9BKgV8jCBQjk0LLjUrnF/JXtvEKug/pYPQhgm0QO9q7/yZop
         RaRzfSowuPg0wi8LWa2pPNZu2r/TZeuPzOL1vPhWzvCc8BdRL9EaObFSX7KSzm4q6uBE
         pcO8pq7dlibn01pUZiuQLLfEvEwAXNy/nFzT/3NX1Xi/MfUfxjm0dsRHWwpEa28p+xYm
         5aSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=TMhYVugyzUF8SPxHtKMVFHW2d9U56xBeasWjyoJCSqQ=;
        b=txYwO6Km3p4Xca4VpZT6ISBbuhwnw3DiSXJ7s5e4Xp4OBzqxgkE3yTnefBapBEpOHz
         AVlC3SO0tf12VYdo5s78fmkhQqnDhFp+Sq0VvOrcFZ0zmEmCwFN8govYlQ0Y0ZGWB3v9
         YhZT9Js++MciCQ/xeutzP9/TmNm4hKQDBdz32f8xV0diXIn4OceaK5MnkxagBnyqEUIf
         oC7xwqvqpmk48Wvjak6zZDcGzQVvsMBZUKaGG6h2Z/mSBlFCWr/UcTI5h7gETYmeC41M
         B4MskfVKrCmnQdXhsLKSFD95qAQc8XpXE7UnFD51xCmHRVcfdqkO8jCYQ4v4ptu+W6XM
         eKrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GOqOWv3P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id z202si468382wmc.0.2021.03.22.06.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 06:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id z2so16754679wrl.5
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 06:24:47 -0700 (PDT)
X-Received: by 2002:a1c:2857:: with SMTP id o84mr16021674wmo.181.1616419487136;
        Mon, 22 Mar 2021 06:24:47 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:58e2:985b:a5ad:807c])
        by smtp.gmail.com with ESMTPSA id i8sm19692969wrx.43.2021.03.22.06.24.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 06:24:46 -0700 (PDT)
Date: Mon, 22 Mar 2021 14:24:40 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, alexander.shishkin@linux.intel.com,
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com,
	mark.rutland@arm.com, namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de,
	christian@brauner.io, dvyukov@google.com, jannh@google.com,
	axboe@kernel.dk, mascasa@google.com, pcc@google.com,
	irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for
 remove_on_exec
Message-ID: <YFiamKX+xYH2HJ4E@elver.google.com>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210310104139.679618-9-elver@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GOqOWv3P;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Mar 10, 2021 at 11:41AM +0100, Marco Elver wrote:
> Add kselftest to test that remove_on_exec removes inherited events from
> child tasks.
> 
> Signed-off-by: Marco Elver <elver@google.com>

To make compatible with more recent libc, we'll need to fixup the tests
with the below.

Also, I've seen that tools/perf/tests exists, however it seems to be
primarily about perf-tool related tests. Is this correct?

I'd propose to keep these purely kernel ABI related tests separate, and
that way we can also make use of the kselftests framework which will
also integrate into various CI systems such as kernelci.org.

Thanks,
-- Marco

------ >8 ------

diff --git a/tools/testing/selftests/perf_events/remove_on_exec.c b/tools/testing/selftests/perf_events/remove_on_exec.c
index e176b3a74d55..f89d0cfdb81e 100644
--- a/tools/testing/selftests/perf_events/remove_on_exec.c
+++ b/tools/testing/selftests/perf_events/remove_on_exec.c
@@ -13,6 +13,11 @@
 #define __have_siginfo_t 1
 #define __have_sigval_t 1
 #define __have_sigevent_t 1
+#define __siginfo_t_defined
+#define __sigval_t_defined
+#define __sigevent_t_defined
+#define _BITS_SIGINFO_CONSTS_H 1
+#define _BITS_SIGEVENT_CONSTS_H 1
 
 #include <linux/perf_event.h>
 #include <pthread.h>
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 7ebb9bb34c2e..b9a7d4b64b3c 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -13,6 +13,11 @@
 #define __have_siginfo_t 1
 #define __have_sigval_t 1
 #define __have_sigevent_t 1
+#define __siginfo_t_defined
+#define __sigval_t_defined
+#define __sigevent_t_defined
+#define _BITS_SIGINFO_CONSTS_H 1
+#define _BITS_SIGEVENT_CONSTS_H 1
 
 #include <linux/hw_breakpoint.h>
 #include <linux/perf_event.h>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFiamKX%2BxYH2HJ4E%40elver.google.com.
