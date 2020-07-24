Return-Path: <kasan-dev+bncBCV5TUXXRUIBBRF45L4AKGQEAGWJ57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F54822C0F9
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 10:39:34 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id h2sf5904890pgc.19
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 01:39:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595579972; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fbpa0y+czPMntFhoR9LBD10OK80/xKW3/qaNFQHGgrND2Xv1zqYELOsLkwIBak8wp+
         7Ghqah2n49QgnNua7/IePBzIEsCS6QwGyye9zEXAmDyp73A3695jzbduG6GMyP+XkGUW
         2vyfAbldLjdQqpDPY28ddA0t3xD207MicJiu6zqDDrMuEyTpXVXKL4bqKSF304qSBWLi
         hpl9xcfqVvkHt+69G3lYgh7BZyGM2KKFNtrhelOT+AJSb4shYUu+Z8FvpIJ9VikPRun1
         EmORE1CmQWXsXn9hXM5Rhvakhiy+SmEhYd02evAnNcjS3gb71e+VroxQIVhOdLqDXseP
         XbuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Eryknx8Hq79MeKd2oYyTJ9W07/lLBlRp8nIhhROQAVU=;
        b=keZyJiaXSWhMPrK55eP9wAEsxjX4Eq8K1f6nKHqKynPtwQrcAnVuWKiibNFTVOTjlF
         /ZkmwM5X/KC7QbSfAZ/JeM+u6AhO3EGWa6F2ibZLLLl7G5D0Z/Awn+A6TOTQSLd95yjw
         4udUyFyKMmP6r8uvw+Sz9au4cScPS+uDX1HQP2CmNMjn6Lb8ugb8O4lcP6Gu9wtODZ3T
         0OuwQyhv3VpTaZHoqu4AXltorYSA/S4v+UOR1+pvN0Qz9ErB53dKONkJGOrXI/ul7vay
         pxB/lwC7CBsA5kkNq4gZI8puHumgcPTeX8JAq/zfUGr/4Tvw/SzKweFQ3nJfLA5e9sP5
         s9mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=NOYfAHJA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Eryknx8Hq79MeKd2oYyTJ9W07/lLBlRp8nIhhROQAVU=;
        b=aEUWa02XSgoR60RLkyjz8Q5x+0axcp3TmL/9a0eRn6rHOiEUNdejMzKGEeyg1TB5hV
         jwuy9ZptVzkt4ckOOJk0bf5M4VeBdbnQkVYuX0qWhL2sOE2mbjvb8We8HzMfvtJgWr91
         P+qomeqypHgSPCmNUuUymScGEf9a0UeaJCndeFnbIZR0Kw7rVmj34It+NxF9C9wfY2AN
         JZ7f0jgz9OFwidPEh53wFEasGFpOm9DuZJk8AKGgMAJ1AJERVBZL4/Ku2I/ZyVmWzf0M
         7+kqQz5+7F0ZcngXY949lQImt4lVPo/TzihgK3STa61cYMAiKslljESGCcJk+4PrSc5c
         fJvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Eryknx8Hq79MeKd2oYyTJ9W07/lLBlRp8nIhhROQAVU=;
        b=VJM48nMBXMl6ojpRqb9/J1yExpZmLNDRwrE+mRsj5p0dAeSelIGZUc38eWSKZ7aJ9r
         bcsJJUiKqD2eeYudCCTmnFSskwPzS1BJBXhauLrKCiI0Gghy5TZMIn8o2zmMKFYwKVNb
         bRyVFwTK53yKsDxx4juR5auijMRzc4pnqGQ6CfDNOidH9XrPe4lBAoO9xS3qSL4CUGIg
         ySxUh4974eogGWySZocMCCJJFV9dV3sTqdecLwa8d+mWisdefxw+V+A14smBu5zD8AFe
         1Dt3IZGTbYOEGWBFVrBZc2fWlnJXzjCb+hxy3ftiCQOb4MTnSmkL5jdKh3JQSymRVz7C
         pHMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533pBktxYfNdXNfBgPz200KrtJM2lWgRhqay8jhVRQASgqcrPE5m
	roYMfx8fWHOGjPe64PS9r3k=
X-Google-Smtp-Source: ABdhPJw5Fcdl9uKG+DntKjuu2eTTn8KAOkcSi5HFXIe0sRqlvA7sFxqD4UzvvowuwbdJoWvH0prjIw==
X-Received: by 2002:a17:902:302:: with SMTP id 2mr7555455pld.169.1595579972456;
        Fri, 24 Jul 2020 01:39:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf0b:: with SMTP id h11ls3101350pju.2.canary-gmail;
 Fri, 24 Jul 2020 01:39:32 -0700 (PDT)
X-Received: by 2002:a17:902:c206:: with SMTP id 6mr7548742pll.30.1595579971953;
        Fri, 24 Jul 2020 01:39:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595579971; cv=none;
        d=google.com; s=arc-20160816;
        b=cNdfR+F8XVyx64QvakHTyOPiNKrKZ85NN3263VEeNqumyOZW5xuLYuZ9g90uK2gUqc
         MiDOtWGksGiCV1FLHgxCmHWipqRgNwV0aJ7W1A5yBswIJUxDiR8CbHOv80k83th+5yDp
         vz+spugITTNneNX8Aw9y7EUnRXBbsdHe7C2zdZTLIICfEgKYSEj3cTBFeQgGxcH9+72+
         OeO9yvGcnebU0ZtrvkRMY7gXlA85rBeiWgdWIAiRow2tSYRJtNc1NGCHw9Lf7H4ZrOkt
         HwwVBeHXUTfvtwpbpwJ65GZ0i9SyHU9IYu4stD7Q6DOhuFBiBfuRROpvBucjGPRfjdIp
         ISKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kXKoci4B8YFJHJ87vnIjv2pljX59x+0imMdXpdyFpys=;
        b=iJ8RElWm1f7q31ie6VYn5D+c5KTI/WnyydxpoedvjuftNTv9rtDUDrl5jqAoNexfyY
         H1+Ct61lHU/9IKv0piYxde41z9MukuvDXjyLFij5Ba/DuabU0sN+YExoclhRCP0gbVo5
         MRZgNp2in+OCO19EdTeMvj4vHgrbAC44ueekAqecHoWjxtE/y2fGG9EpnVxaD/w++OvD
         knSBRseoODA8+iCJ5Uh1kh2ZiRTEutYKzC7+XpeXhHwmlbqUHyFw68RpLb9mUGUlHFIQ
         jkTFF5yv5VE0jP0Vze1UWsEUsx6oiNoyCCZYg1pJd/6Nrk9oysUoi1at8Npbo3Q3VTV7
         Oqow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=NOYfAHJA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id l6si649696pjn.1.2020.07.24.01.39.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jul 2020 01:39:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jytEi-0000RG-O8; Fri, 24 Jul 2020 08:39:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8C4C430768E;
	Fri, 24 Jul 2020 10:39:20 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5B86925942EE1; Fri, 24 Jul 2020 10:39:20 +0200 (CEST)
Date: Fri, 24 Jul 2020 10:39:20 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH v2 0/8] kcsan: Compound read-write instrumentation
Message-ID: <20200724083920.GV10769@hirez.programming.kicks-ass.net>
References: <20200724070008.1389205-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=NOYfAHJA;
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

On Fri, Jul 24, 2020 at 09:00:00AM +0200, Marco Elver wrote:

> Marco Elver (8):
>   kcsan: Support compounded read-write instrumentation
>   objtool, kcsan: Add __tsan_read_write to uaccess whitelist
>   kcsan: Skew delay to be longer for certain access types
>   kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
>   kcsan: Test support for compound instrumentation
>   instrumented.h: Introduce read-write instrumentation hooks
>   asm-generic/bitops: Use instrument_read_write() where appropriate
>   locking/atomics: Use read-write instrumentation for atomic RMWs

Looks good to me,

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724083920.GV10769%40hirez.programming.kicks-ass.net.
