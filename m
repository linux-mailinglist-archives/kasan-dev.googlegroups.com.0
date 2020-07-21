Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7XZ3P4AKGQETFCCPVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 9679A22824D
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:34:40 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 4sf2300760pjf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:34:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595342079; cv=pass;
        d=google.com; s=arc-20160816;
        b=gOJ0KOrHWmtmlvDMzgLHPjn62j0FbM09iZKtKCfb2HRAXMmFTnu7bw4JRjxUcrv/Wt
         aLc5AZhoUJZg0hsxQDPStHP9hCMomInms05bHC9EE/SPjWQfQtY2P1cl5CW9q6Epa+Ib
         ybG/wm/8vEpjjcIXzuLpgWrMHtmSuyzjE9w2W5S0znbgXa+ErA0A6ZxURE6tVmFLp+GP
         5QOg2VvBSvkPC7fPfECCjHYkV8bbjw51y9DQuAkwtSLbQCbNo6KfJsCq17ERQNZuB677
         G4PRgpDMRl+4Wc4xHz8uRlTd+0NNyh1Ekyn8y7x3ZoSevcx/rSdYru6Gy9cQo0G8YvaX
         KlpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g7Xdwvyyv9MQWDxRhDni8qGHCvErt1KiCv5S1eKg5ZQ=;
        b=VC8175464VUxpulXCiwJFVe/AX1moCAam0LR7u5Q2ellIrNxFa6XFBKy//czcOw74R
         PhMuaW1VOeHDSdLLAfQweOFQcNBp5Ij6n+PgLJEYMkqyEHarKqZfoFmhZb8E+MPl+7Ko
         YP7Os9bYbtvflmp0it7DR8JlJ44HWM7wa19op2ZEKxUPXkrwmOoTm1VO7vaC+oj7lOYT
         RlmNjJgJQA076gHnMKfq80ylJO+MwRwbzkyBMY1jLqZreYmyq9AAhfq56Zqm8ZV+FsVT
         QNUTnlcKVjf9DLF7dWkjYAMgHzrsrBybEg8NIZBNxTlc35DrqGHYYp0gp6QTnepXQP93
         w4lA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="QdO/VkrL";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g7Xdwvyyv9MQWDxRhDni8qGHCvErt1KiCv5S1eKg5ZQ=;
        b=BhlH2H4FZ+urDsGrgzsO4KDp5k+kZkIRZKrsnM3zY9qNS/Or8OQ8wZNQbNPUzKQrV2
         ew2Oh7V0pOqwgJXdEb9EXIZ9mhXJt9Gem1th87RbhkH618fUKSDKehQxaD8hYsZWNo9v
         uZ3i32TI1im1hiH0B8J+0oZFHSXe0HMVySFS0JFB3GZZcwFANK7hv4gC0PpO8PP2zArT
         g9Vn1v9eNy7/BFz6w+Eiy+Y0+o8fPodlS7k9NeS+UM7kwFl3xyWA+LA7acYJkiGE2I8H
         2ccwrXC7haRfIBf1M6Q/ZjmaE2FW4vxKaQBZsRZ7sufRe2SPTnQKxW39m4UOpS7KBAYk
         MWPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g7Xdwvyyv9MQWDxRhDni8qGHCvErt1KiCv5S1eKg5ZQ=;
        b=rFcDJgvngDTf8osb+hnyryi5fD/6Sqb5B8TqaexLedejhYGxeHDeohUgz9ymadHqis
         p6MC2adeWWXQ2yjnOIwFDfaAbrOFuZLoa+sGLzlOx1OyfskMooh8VhO3aw88dSpdCD6l
         bqAAq8YjSy2S+y4mct+4MpxlWVmp/6ujT7IKCXlJrdG/dRBFbdxzfeScGz5r7EniX8N/
         X5JntGOM1oXSBmPaO34FDAuBM1PMIcTx03YCaVdGkqgQqYjCDVM7W19NuDSjs275FCg/
         qfboUt/bZGOu9+b3Z1ul5JafT6s76A3NtLF+02NYDxe8oj1plgG6/KHemLPKv3/nH+kz
         mbWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ERGG/XSHfxLO5qO1/ml+uMCHjP8X+HH8UoDv40bOV1xKf/Oqr
	E8and3eFP7cv4oE+6O3tqsQ=
X-Google-Smtp-Source: ABdhPJxzmEbwNk6cJSxkHcqEXS2jGL2EUQPA2PErMJOFD93U2nLDH77P//MsGRsI5emP49zbqWpWQA==
X-Received: by 2002:a6b:ce11:: with SMTP id p17mr6515910iob.125.1595342078916;
        Tue, 21 Jul 2020 07:34:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2a9:: with SMTP id d9ls422589jaq.6.gmail; Tue, 21
 Jul 2020 07:34:38 -0700 (PDT)
X-Received: by 2002:a02:1107:: with SMTP id 7mr33807580jaf.84.1595342078637;
        Tue, 21 Jul 2020 07:34:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595342078; cv=none;
        d=google.com; s=arc-20160816;
        b=mdCsvNkSQfY4Q7qNv4q4/qinLs12/F6VsaRLZtqPbot31rppE1QBL5CCU9HKhsT2P3
         qY29gOXzHacjN36XFGNjo/6kbsow8oQ+OUPq8bSGlUlpE7mM/Y+na9K2cjs0qPO/k/Eb
         IqUowY8d0U+jYkyL6YHhNaQGJCzmfd2wyAvS2yPNpLkKabar0ydH+APBuUwLOr+SMf2C
         bQeet0KazwqKVuDYjll5EBCyi9Cgex3mg46FNccHA5COVB6JJUhSieUjEREl+MC/lM1i
         aqhWlnhuqiQrQnncmX3U3qB2jYQkQ4Mfq2Csk00itRgHxqoOVRMQ8JogO6WHJoYshBJl
         t3xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=awvO/AxzZMb5RICr1smsNlHEgfMyuxuSrzQI8mKeLw0=;
        b=fM/eoRCnkGoWjgRLwv5SqpyDm4AYNPVmKWxW3BRJ5I7ubuLv6rsNk0QbwJJetR8gCl
         OdYimuAyw4en68zm8iTLXrirFXUsWrehF91ZPzFIQ3t6BeUxfO8ZzNA7Th4breD01O/z
         UXbGO10gHrPRBt+FoRst0ux5tkMxGfUOgshR9BCitabAjZN3dlkzB3GIUiPsiYVYEZ4L
         svK6dYm6R1KGmUsXMgqqFBBKdjwIbgWym+mweqByCRS4mDgDO2SeFdzlEpZH86GCvdVh
         LRV8xkbw+/BihXxgP+4FRNRDt/N7C6A/RsvCG3xk0egdE4p2cii598666+T9mRZZvcSt
         iQWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="QdO/VkrL";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id e20si108947iow.4.2020.07.21.07.34.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:34:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jxtLl-0002ZX-ID; Tue, 21 Jul 2020 14:34:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5FE973011C6;
	Tue, 21 Jul 2020 16:34:32 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 24B9C25E22790; Tue, 21 Jul 2020 16:34:32 +0200 (CEST)
Date: Tue, 21 Jul 2020 16:34:32 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/8] kcsan: Skew delay to be longer for certain access
 types
Message-ID: <20200721143432.GM119549@hirez.programming.kicks-ass.net>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-4-elver@google.com>
 <20200721140523.GA10769@hirez.programming.kicks-ass.net>
 <20200721142654.GA3396394@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721142654.GA3396394@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="QdO/VkrL";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jul 21, 2020 at 04:26:54PM +0200, Marco Elver wrote:

> I'll rewrite the commit message:
> 
> 	For compound instrumentation and assert accesses, skew the
> 	watchpoint delay to be longer if randomized. This is useful to
> 	improve race detection for such accesses.
> 
> 	For compound accesses we should increase the delay as we've
> 	aggregated both read and write instrumentation. By giving up 1
> 	call into the runtime, we're less likely to set up a watchpoint
> 	and thus less likely to detect a race. We can balance this by
> 	increasing the watchpoint delay.

Aah, makes sense now. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721143432.GM119549%40hirez.programming.kicks-ass.net.
