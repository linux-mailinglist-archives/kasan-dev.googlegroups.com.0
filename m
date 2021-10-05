Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJP66CFAMGQEYBAVZXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DAF904225DB
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 14:03:49 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id z29-20020a195e5d000000b003fd437f0e07sf1318038lfi.20
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 05:03:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633435429; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDdDcVGhN6H6Vaq/cKFj/nwM+L71YGh/6CWo+xoGfb+S8jF9PFrWBERVxBkaSIDJQI
         LMoad3cCYfLEbYnQ8WmdfhoElQGB/Dza46NLAVTkbCE8az2bHzJ6eUPFfue4IlD8dM0+
         4MNHxZXktsc0MPFMea9g7+udGaivNXTErZtScjCPL1eHyt0yKbxMRuOlhe/6BU6hpVJ+
         mA46rQ6EvO2t+itGLEe1gu+VzevO8wMEfHCW0aM3CK7/W53YyxVqBLJ2vnzLfvQCSzEV
         1woSAzVt3/zJpV2A4TEq6eBjkDwIdgL6XNn0g+tpM/o0bjSH8axlI6kyPxID7ppLa9G9
         +Ehg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rr+Ci5vzIpDPnM/onfexPHyPoEGdiA9+5JUjy1CbZsM=;
        b=PNBIxiNKtnzMDnK7Mayc7EynvtoRh9RwalZZnbYzWE1wV1MtjlCQJpw9q2fQUV/sD7
         74Mh460jQ2A8yqTcXCofHG18AgBmohwtc3eoNG/O2l5rWxJDWtkqZLGm/i7rSOXPdSqr
         38030y6a4Yyndyun/Joyy+s1F8jiXHamFOsajj8WCf8OwOQug3XKe++L/rksOwoxtYjd
         tqVQO2u5EYIdNvRGumFIQX6hdPJrgsvbUlA4I/oQdryxA+pKaO+A9F7PfK8BFtbhw1Sg
         NlR/YMalY7YJOmWGV2UVp7vXigzMQASEOjSMpifQLUfI+PyWtefZru2H7YA8dDwK+/TC
         06mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ugZGH/+j";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rr+Ci5vzIpDPnM/onfexPHyPoEGdiA9+5JUjy1CbZsM=;
        b=IdiDgM7FmrQ3D/iaOKfjW/cFf6lMEx9TH4ugqoaB0RU8/MUylDfkMDVQJrDX6zrQ0n
         ieRyT/Uhv+uIQP63smyx+Z1VV7JC9K736e6XoI0PcOi1mnHiLhUCRhJYwIpbTVr282Pd
         tmC/cO5WXTE6fTdwJT0hgjhjReWCsFJmPIdwOuReJgbpQfE3GNTGQL1UNLPEeq2IpfAb
         B6OVy+KOxWImaw7k0WqhhYXEs9dRbP5bS87lt2A1y/oyCXiUr4tyy2tdGB0QZ0QLpFdA
         XpC60LJVeT/1kPPdOAkiidFiHIeHglevejCUKDd2uEfvWiPK2WtOdtwfvCsSY0ikqtiz
         3dpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rr+Ci5vzIpDPnM/onfexPHyPoEGdiA9+5JUjy1CbZsM=;
        b=b+cYX4zsc0RpztUt8SOFsoCtZgpC2kaTkVU2kgHv2q5RoF75nuEwDEqr1N1SCpD0X2
         bzGm6Nem8Nil7BWa+onmaON742t9DOfUCngNcjCW3UfhitT/jReZ9TvDpjpG8cdzlGEp
         cAgC/JEJ8ng6ttlCrZRKliYoLgNqKFidOWGGkRG8KKggGoCZjkwFhILAT7yRsSnWlMz5
         P7wr/dYGm3wil/16oXnqESXYHBFBSgAy0tsQcDnOoP+3qXm9wo9nxyYqmNblud9/W5CR
         SdMMg+yJp3AfHk5yDReYg8LcBp+aBPg0UTaKmoQv/0tznE/2W4kgTwQ4El/E2mArq6JX
         p+Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331DZkqYHnVVbI5WIJi7/JP0UWeA3UrKRx3poudY3FttCY9vW69
	BoJY7XZ8hWcXBzoKvJaTW2k=
X-Google-Smtp-Source: ABdhPJy0hPCmyZ/5QMFcDBgfJcapjLa5bHZlEGXZEnJQXhiYphCbQdc4WkTLD36hzQYGuULO+l6bIw==
X-Received: by 2002:a19:674c:: with SMTP id e12mr3223756lfj.679.1633435429386;
        Tue, 05 Oct 2021 05:03:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:168c:: with SMTP id bd12ls3753665ljb.5.gmail; Tue,
 05 Oct 2021 05:03:48 -0700 (PDT)
X-Received: by 2002:a2e:a4ca:: with SMTP id p10mr21455706ljm.379.1633435428013;
        Tue, 05 Oct 2021 05:03:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633435428; cv=none;
        d=google.com; s=arc-20160816;
        b=K8A0j/q85HJ6iVWkEAfMqiDhiHN2C6o2Ruaj0pbVNrT+7is4qMS4ZzfJyurgEcJcR2
         J9COUCbAemCLbRsKanEDXxARUWZwjokHVKX6wlfZtO0HdMQsFvqYPqP8g/c/ZaXWzZwn
         hfL56J4b6ooXQPRE/tv0eyE5J7Iax2VtSP3OWBgHR4hjzd8PjqCigANFLdeYp4Zu9Gsj
         xonSChYoPbN6Vii4JpVHUtnFvE5qZ4PUF2C5HJj2SFQ/wfr/gIkHXmlKrwso+sdDCd6l
         F6hOXWQFKawG1d5dU3EyOa94GVcZYqYdTtx6NqYCRQYVgMEEBmnjN5K80AzAq3sO8Qr5
         l7Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ssIz8dxHAZ6IED8P8Bx3CPoq2/dqQqF2DGl8wwvM3UU=;
        b=zh7HDdt5fUReQicnrXxCFaLvpV+dC8dCRxHjSR6wLhSYP7h2a9ZXH8x7DOjGrtDz8P
         ou5bJYFZpbeitFLhW75oEYPsAnKUacEe4F1pHfIauu1WXze5d+0guuDdQrzSSVFkDavi
         3Ko/j0hK+Wis6oXbJUkbWm9/JJ9tgqcm9kw+YPpbtdlV1COrA+ficgHZOVbrSSbrjyd7
         QyfBzG3o8gyuSA5rSN+6GSJP0mgsYWNTuXBnsKhJkc51Wt1vlQM1S8sSDGSphTRtnUJ3
         lS2KOLGLf3fp1Cx5t4zaBScYOi6i/JJ5ViUAYfFRQPkSPOcEwdjaKmHlwhH4belCeunT
         evww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ugZGH/+j";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id z12si1069735lfd.13.2021.10.05.05.03.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 05:03:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXj9c-000PjY-SI; Tue, 05 Oct 2021 12:02:51 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4732430026F;
	Tue,  5 Oct 2021 14:02:40 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 27D732026A8AF; Tue,  5 Oct 2021 14:02:40 +0200 (CEST)
Date: Tue, 5 Oct 2021 14:02:40 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 16/23] locking/atomics, kcsan: Add
 instrumentation for barriers
Message-ID: <YVw+4McyFdvU7ZED@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-17-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211005105905.1994700-17-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="ugZGH/+j";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 05, 2021 at 12:58:58PM +0200, Marco Elver wrote:
> @@ -59,6 +60,7 @@ atomic_add(int i, atomic_t *v)
>  static __always_inline int
>  atomic_add_return(int i, atomic_t *v)
>  {
> +	kcsan_mb();
>  	instrument_atomic_read_write(v, sizeof(*v));
>  	return arch_atomic_add_return(i, v);
>  }

This and others,.. is this actually correct? Should that not be
something like:

	kscan_mb();
	instrument_atomic_read_write(...);
	ret = arch_atomic_add_return(i, v);
	kcsan_mb();
	return ret;

?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVw%2B4McyFdvU7ZED%40hirez.programming.kicks-ass.net.
