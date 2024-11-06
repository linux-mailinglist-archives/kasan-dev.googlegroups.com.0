Return-Path: <kasan-dev+bncBCU73AEHRQBBBOMWV24QMGQEVIHI7IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8D129BF1A2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 16:29:04 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3e5f4437768sf5117441b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 07:29:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730906938; cv=pass;
        d=google.com; s=arc-20240605;
        b=ejzxvWS7o312vC21SPmZdgm19wa619E0win3ZfT7x5imwmRi3PNjF0klPrSDOFiZNH
         IPLTeAoXK59d/rh2DtbactElSRb5ZktAHkrBlH3TaCQlcRrDG0Sy0v9JksPKzntlQTfs
         NpQj4xN2ZYDIwqxYfqbkoTre3Yy7LgRpm7aYUPf6++os+94EA3lPM1yZr9nQ2/aWp41L
         gcuJWQoYXJJs/QkSB4hkp+2LSTog19Z0OXO8SPsg0jU/PMa2LxRIjgYodA/5kQpoW+Iu
         kHF5NhSFcsgF98TZFY2Nx5YvUyMHBoJS/APAfYOJVC0P6heSRFWVTcidyJmT7BYFe3KY
         dSyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ZM/R6wCalRBNWz1KP9GgDfZQuOeYYzanCaxNpvqNe7k=;
        fh=j44+506FK2OCfzq2cBjWjnxlmuyYi0+C7wjl4O3kFb0=;
        b=aJfYu2j3cBXvKEwN+u8o4TmdWTXN+4kaDCxYRPp4j0pQzJ4n0fYQ07Uu98F3V9y9Be
         cY/1fZMTxeVlZ+j4dSceP/Hhm9VCz615MU7Yxgl9aHDKPXPw2zw4qW9aGJSpsuNLwXSu
         yIufNVrxnbVrydrtqCER+Z6+hehwXYDrOMoZcbne7o7lipe5HQjpzY03U2b0EVnme05a
         FgoUIXXf5a+ywn681oq+IybExfOLdQUPd29zoSrWVzfiC3mlHVKJVlaZSIEpGdhbh8+f
         AReExs4NHNl3C1YK9XrAw4i3M5CTgFEUN5Y5pjdTmsqAJIHPEkGkW/XzEaJdW0i8Rt3O
         5w2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730906938; x=1731511738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZM/R6wCalRBNWz1KP9GgDfZQuOeYYzanCaxNpvqNe7k=;
        b=TUa55ARdZ/q0VLwDCKvywO+JMN8WMOJLtgv2irzziTRMtvR68RShv1aNV5BX8UuxPm
         Q5GCvjBHmxcZ07w1obRWCLG2kDbo7dU/W3rV0wSIsVzHbsYQsVLh7VpGitYKzV8+y1IG
         cp4g+lqtW2r4vQ2phQxSu6HDKerQI+gOy42InBfWhWf4bMwj4CLEzpMQDdRVBCqp8/Cc
         xRm2IjosspdOvU4WZwlgpP384SpGY5CkbjLH6IFAEdHgOiZ1C5QuqmfXmkDUsmHCzflT
         ddLbLS6aTpVTMCElPfj8fURdX/t+wUqCC9S1n2gwe7VNIZugasjZjzLBdMGuPosdPfyp
         FLMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730906938; x=1731511738;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZM/R6wCalRBNWz1KP9GgDfZQuOeYYzanCaxNpvqNe7k=;
        b=o5Hb9Ek44Zk3pBbhPevdCUiEpC1FZdAL/0FMHbKmgRgzWg88Nmhjs7VkhmdVL2LL59
         qGxPKxUh4IC2prEFUztac5Mbyda7c2DZHlUOesKgHs/GxNM9wQ2ZXRzfvAJ57tEpicBW
         yNhEwda6l7E8KdbolRCvAGXb1E5SMMTYVB7plQacKLcYI+VT2OVrX6EW6lubbx1Vb3sd
         mnOCK8gBOa+jOE5t/dAuav+SzHsIfd3Fb2vrzjCwHU0RYWLSUFWtpbiAM/x+0k7KNaYx
         U8yQk6zYuUrrreLtCgyu12elqUGh5jLYnZ5q50OmtP52z8Z1yAYpnr+6k5BH+JWYImk6
         ursg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcqVpCVjSCQtjvWAAjHeO4JUt8PY7ZEMysMQQSnSHvS+f+gJI708Xn4o19MWNXMI0kTzmeiA==@lfdr.de
X-Gm-Message-State: AOJu0YwB3ndzU2fwvdskAnY1IeAQqwJXqKx+bI1rxDAYrAD9QuMu0K2V
	BRTEQnDcpOXAcseRJhzPVcQgcJ9+W1M+CwVYdT/IAYyr8uDi7q8B
X-Google-Smtp-Source: AGHT+IEmJpXP+a1IQAwpIkowqLzvr/xs6MFTRbr9hWeVbEW+/b23IqS9DTFzmbZCU12ffdYhWtO3LA==
X-Received: by 2002:a05:6870:9712:b0:27c:df1d:85c6 with SMTP id 586e51a60fabf-2946467a9b8mr25198033fac.8.1730906937807;
        Wed, 06 Nov 2024 07:28:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3909:b0:24f:f4eb:3558 with SMTP id
 586e51a60fabf-294827fb539ls5603042fac.2.-pod-prod-01-us; Wed, 06 Nov 2024
 07:28:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXrNr3bIdgJU/RPoqXTGn7zEbN+0CmjI9Xso1ZqTz+dfYT1VZW9j49ZHczQHI2vt9NSXxL1e0m82sE=@googlegroups.com
X-Received: by 2002:a54:4398:0:b0:3e6:22cd:3bf1 with SMTP id 5614622812f47-3e658368144mr19154488b6e.18.1730906935413;
        Wed, 06 Nov 2024 07:28:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730906935; cv=none;
        d=google.com; s=arc-20240605;
        b=EiGxVrALKxsdSHZsUigtgnR98XgXK6t9tVIqkCvdvXW5oTwUAJ5cK0pJbsyoKAEjok
         q3hjO79stnaD5HQMZQniS+RHM+aaZn+DIkYR07pETxveTZm6bkuTUCY7L3V0DUFnATyJ
         qvMRZc/PHFspV5fdPXg8/LgD+9zDs0rzGJwHLFLuwYgbU8ttAaLW8OySGsFy6MTw51Ds
         EX9Y+rnzNoNlCrQhtsYAeinaEUH8PqJkygjS0HUbCWHrKLzOkuRGmFyAqHij8PW5d3v7
         yTC8Rhg0Qmrva6V6HZxGBalGUw9cn3oq5bW9OW25p6wKG+Qo8AunnY5oZoEBabaMunDb
         4keg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=tLkyvtBJJ/Z58gV2KRBvhJTK2+6aHj/GwF8Z0ea15fY=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=DeaDFAoprZx5851vu06os3VW1DP1U+iJNV407n3kIhzzWJFV2HOSBpRCH12Dqfo7CH
         IwULzgd6vCleSft1nNr2DIIVBtSCOTU+snC5TZfkQOmIhB6QphKtar1sb49T2RStFESP
         qElKy693ROelRRUP/BhwnF4mkb6pabl5HQsn1IFAGDe2LykzdT10NVaqg+MIXs+rwRs/
         x+eUC0/HLLM6fUYuZr4YOW10hoogzEABHrO/OcA+x1KRvgdXtvCF1T2dmmtAk0AJWM3p
         8nSNN1CpANf7mliqaID+KQ/8qTnHn+/Z6iaG4zo2iw71ubiwNPxQCUWKVndSxAt881ix
         SHtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ee45297844si729859a12.1.2024.11.06.07.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2024 07:28:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E9BAA5C58A9;
	Wed,  6 Nov 2024 15:28:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1DFFDC4CECC;
	Wed,  6 Nov 2024 15:28:53 +0000 (UTC)
Date: Wed, 6 Nov 2024 10:28:56 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241106102856.00ad694e@gandalf.local.home>
In-Reply-To: <20241106101823.4a5d556d@gandalf.local.home>
References: <20241105133610.1937089-1-elver@google.com>
	<20241105113111.76c46806@gandalf.local.home>
	<CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
	<20241105120247.596a0dc9@gandalf.local.home>
	<CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
	<CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
	<20241106101823.4a5d556d@gandalf.local.home>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
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

On Wed, 6 Nov 2024 10:18:23 -0500
Steven Rostedt <rostedt@goodmis.org> wrote:

> > Some trial and error led me to conclude it's a race between the logic
> > looking up the comm and the process exiting: If the test program exits
> > soon after the traced event, it doesn't print the comm. Adding a
> > generous usleep() before it exits reliably prints the comm.  
> 
> Thanks for letting me know. Let me see if I can fix that!

Hmm, that still doesn't make sense. Is this just a single line or do you
have other events being recorded?

The way the caching works is during the sched_switch tracepoint which still
gets called when the task exits. If a trace event is triggered, it sets a
per cpu flags to have the next sched_switch record the comm for both the
previous and next tasks.

Now the reason it can miss is that there's contention on the lock that
saves the comms (it does a trylock and if it fails, it just skips it). Or
if another task hits the same "comm cache line".

This is why I wonder if you have other events being traced.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241106102856.00ad694e%40gandalf.local.home.
