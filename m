Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDWK2CFAMGQESNWFO7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F9441C0B3
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 10:34:23 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id f21-20020ac25095000000b003fd0f3d19f4sf550735lfm.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 01:34:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632904463; cv=pass;
        d=google.com; s=arc-20160816;
        b=HzBp/6bo3Rax7Rjgj182X9Pe58vbB1/MReWn6eIkNUyofceLmiloDk5DKR36Vja90q
         k6O2esq0xv7D/4X9p5ChEc02sHVkN5Kz8QXzms4vEJTt0z65itYZ7gS3qsx4TE6w3NHU
         /ZlKMYtjb3LuY9wqzGw0DoxWBrQEvJ7OfvNqqxMUUxbsrW8Qwtf4h2RfUTssIezoiuHq
         aMj7EZIV5QVTma8YjrGtmpJiMo4DDYLtyRDM7pWJv534EZyvpGvrNVm6H7hqSW3wexDA
         KAdrC9MJxbJs/DKRWfYIjjWlg7T2cyvJei1FcsTxf1C0GPbmUouxmLUOv0k5hDRnCzxL
         jJTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jIBeg9tSvLI6XpQIO7eiRdlTtHk4o8v1Lsn4TYUNgVY=;
        b=AFHRP33YuwLRUY/AHXHgDvDEKy2vw8cJ1J9s6nUfTc6wtYLgsTpQzDxj2LagxQXEji
         OlIg8Qlx3BcsnizrKphoQmmtJxGxlrXVPFRkOIfRWXIdsQU06dJA2H13E4aHjSlI8l6B
         pzbgsgrJJKYfushbQIDJ1a26L2cCFNEj8DlMdCPvbLVxRT0bdq29kPC70LXLoM2PgLub
         I5+aOJ6WhiKaJQDYAgHTGeo/Hv6VLX/flgFjKXDae9baJlGUKZMC/iOvCdGwPqKCNrLk
         VHfDFgtbILLQNNOC9vjCVgOMrowI4cdOAcXvQCZfu2If/0MmQ9mOq8OsLuGUwXCe2o4b
         ap2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=rSe8TuC8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jIBeg9tSvLI6XpQIO7eiRdlTtHk4o8v1Lsn4TYUNgVY=;
        b=evP0C1tsKReNRTxqyHzg7hHl+fopIcWCEqWHWI+1vGsS/TWJ1RhcRkja/77LC9ui0S
         HxjUPut095bcvafuyAQyP7e80jBAvdNkxH7ldUKy5zlt3F/wox9gJ/qKdws6TTuUGlV1
         AlBl9nwmFfbnwL2Xoui7aODm8zWexECEGXIN/wlVNeDge15mHsOLacoMGkIwD5G2/9Gt
         qyirz67U3Hh0L7udHt5Gz6y+wId5hdEbceKZPpcjvur0N3bUndNOrhS+/u6l827CtqIw
         RKA6hHdeffImAjPQuBQLWbPyHsSXLybLqJMUNFlSq4XjN4npz4bfBsc2MpJMPKvCvXvw
         z5jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jIBeg9tSvLI6XpQIO7eiRdlTtHk4o8v1Lsn4TYUNgVY=;
        b=GydrLNiTIkP8aUTfrtzKow10KFjo/47lP4cWeAkbnPX9/45v5nHM0xLAoT/1Y5TPHa
         NELMbBWWZ7wmI4F1da6Fe7X5P6UavNipjIekkBuCQcpIEYTcC9wZCJ2ye2nvdq8fYawc
         0b8c9TmOuBTd9QREeUL1zzB4UKkHMXr3XFePxljJowxXBZ1KB46SP1LJZ7UGEmhlEoIG
         T/px2Z7cvGu6s5nFBTxsWOxy6CEf/Z759640NmUOnLAJ198q71+OYJP5GpWNRmK2P/GE
         VCavGo1VYkB/oYWORW+ceCTR3P/5b/g9oU0fVpxDGRbAiWXYBgfZvttg5KMVThAVebSE
         j9kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eO/EQdFGhVRT0BaPQk3cifFUZCO+nzh6+0sIKC6tLfAeESf/k
	8Wk1pb/VMWIOBW+zMAXvAOo=
X-Google-Smtp-Source: ABdhPJwgL6bzt4RGY3/daHrNQI3fLkrqSsGFiLaYUxX5/8yyipibdwWvC7CT5qx4ZV8GEZ0MAN8bHQ==
X-Received: by 2002:a05:651c:1504:: with SMTP id e4mr4794446ljf.75.1632904463184;
        Wed, 29 Sep 2021 01:34:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1242:: with SMTP id h2ls433371ljh.2.gmail; Wed, 29
 Sep 2021 01:34:22 -0700 (PDT)
X-Received: by 2002:a2e:1557:: with SMTP id 23mr5056089ljv.84.1632904462234;
        Wed, 29 Sep 2021 01:34:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632904462; cv=none;
        d=google.com; s=arc-20160816;
        b=1IQDh0LNl7eFL/s1VNYlqoKLaJgRw10KGW5hTcGUrddBf4drhPabm6rx58ozvSUmbu
         Z7WIFbdPEdcOC8sFoTPzBFbJnlW4dnoOx9uZmYjRYVmkOe5i4OHPJctj+TELKCHOoiFe
         sjT2A79/D0rwyUMv+U8l8zCb8VYRaW8XMnw9FITCXbR/Zv0/KgwVFihk9CqwdRreP+da
         mlnVAqHQ3mPhs1VotWVibQBHuraNOfE3UHAnEgj8W5ma1veGw2LuBHudwxus/MGcwrQZ
         bh13TyOsdivqARp68HP+P9RaxGJSP2AIFI4f0qyYL222LTns9mfnyy8BmrXnjSgaI1pN
         Un7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SV4z02fQHJKU53d8jxad0OxnLv9XTsMO9xV7N7zdQ6Y=;
        b=OS7H9eoduxbMVD5OUSsH8XyrOWzt6UB+fAspqQs9leEYA2REQAh7lg1GX3L0Psx3xA
         DdFikROQGip2O+Arr5A2pfilF517px3/7kAhhHkq9vbbrz46pZq1EtasQ7gqMWC9PuvC
         f2eLoaCBORaH9kNKh0JPlreMhyXndmi3U/+SAFBfN9pgmiUsIcAxyu9k3lNoGUO+QIkV
         JqcOllloBkPBllFPiqK5IYq9dDGDPRDK395QVWApAqtLDsYFU3rSURbbkiMAVYoWHU/Y
         co7mSOboPWkrLiCRSOM5B94/lLkq62YVZ+DpQLAnSUfVnG9M2YFz2g9pl08AvppANndS
         W3gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=rSe8TuC8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id t20si128611lfg.12.2021.09.29.01.34.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 01:34:21 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mVV1h-00BeBj-Of; Wed, 29 Sep 2021 08:33:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9B38B30029A;
	Wed, 29 Sep 2021 10:33:16 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 82F9729AD1D57; Wed, 29 Sep 2021 10:33:16 +0200 (CEST)
Date: Wed, 29 Sep 2021 10:33:16 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Klychkov <andrew.a.klychkov@gmail.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Johannes Berg <johannes@sipsolutions.net>,
	Ingo Molnar <mingo@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Jakub Kicinski <kuba@kernel.org>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCHv2] Introduced new tracing mode KCOV_MODE_UNIQUE.
Message-ID: <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net>
References: <20210927173348.265501-1-info@alexander-lochmann.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210927173348.265501-1-info@alexander-lochmann.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=rSe8TuC8;
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

On Mon, Sep 27, 2021 at 07:33:40PM +0200, Alexander Lochmann wrote:
> The existing trace mode stores PCs in execution order. This could lead
> to a buffer overflow if sufficient amonut of kernel code is executed.
> Thus, a user might not see all executed PCs. KCOV_MODE_UNIQUE favors
> completeness over execution order. While ignoring the execution order,
> it marks a PC as exectued by setting a bit representing that PC. Each
> bit in the shared buffer represents every fourth byte of the text
> segment.  Since a call instruction on every supported architecture is
> at least four bytes, it is safe to just store every fourth byte of the
> text segment.

I'm still trying to wake up, but why are call instruction more important
than other instructions? Specifically, I'd think any branch instruction
matters for coverage.

More specifically, x86 can do a tail call with just 2 bytes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVQkzCryS9dkvRGB%40hirez.programming.kicks-ass.net.
