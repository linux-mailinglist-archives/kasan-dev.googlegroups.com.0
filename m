Return-Path: <kasan-dev+bncBCU73AEHRQBBBNMY3W4QMGQEYJVNSKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D01F19CDFE4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 14:27:18 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3a74bd1589csf3909115ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 05:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731677237; cv=pass;
        d=google.com; s=arc-20240605;
        b=WWon9XpvV5Rj00WKvS2007l6koDA3YNQhOJG1FmgasLQSqYLXfuum9mTH8++MNAZHP
         59pJHCGZtIY8euIw4RZzGDGPWnx4ic83BI+K+V7Phjy3+Ef1Knj3J7gwMi3VZ8b+H2Vu
         DFqVgvDo3vSQda64bAAeO/CLUlGy+1e5xgS9xJv8/INhUMNqVNCWsjFunU9VfltqqmN0
         6XO9/sLfn2Qt/AJv77MPhKElQAmm9N6pDb1+pJlGtZ7HYR3RgI/XuJNjUQrVWBKAFRz0
         gCqYd7iiiZjgMQTQ0HQEr7rnwQS7MlyHeCDjmJYbEfyXr9VjF3ccCMkpUjvWgWKPrcPs
         B3sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=f+AZucFDglRpM+YnPe8y7yin2JFgAF9GFW6WkHZpzDk=;
        fh=xK+k8HQcu3rfLtlCkpAbHiZQ5PDSJSLMTbTXoqjamL4=;
        b=Lqy+KxVaQbx1/bpTTqBAgbJPcjbNQyflb2qLdlQOj0qa/JiFFJgJ2zhxnXws/0Q+Ga
         WD8MkioexHy100GWVwlpnt9dNN0unHkCji3EsYa1Kw9QW7E9Vt1HE6vJUJoox1lmLTbH
         svXeaBHcusgjJcjIxmER5sve24EMjBTmOd3OUW85I0Y7SRNMLVVXSBxRZz4tPmGFOd9f
         HFpRqt4/sAVyd39hOnnVFnyKbH+cfy/LlEvGDQdChpAByiRzF8glorcYKw7xaCykRETd
         zuHyfNB7cm3FrKyzqLilIGNxEdFxSXP+Pyl4NT2I8fVdCUL2IMIbwNBFbo15nFMhT9Xq
         6jFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ihco=sk=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=IHcO=SK=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731677237; x=1732282037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f+AZucFDglRpM+YnPe8y7yin2JFgAF9GFW6WkHZpzDk=;
        b=jEme9O8HSQMKNy8X83nErdo8FMh+4VnjkQE5lotig/nRiTqNWQiOIDC6RW4Rtpzo7P
         LL4OVXAlid66JTrWndyfxKlI6VALKHhV+PPXbwWeiqAFkUUtURtpHjPoEITRdGxfaka8
         4rZGYzqECfrFMh3TydTs/ozo2mQ7bELt/keV8zTqZJysRoe9i4Ud+wxv+Pob0x5/tAOP
         Xotuikvm+HcyCfZobUQF+1Uy1gK65IRaIMviHV+8wNmMsqhr3dOOKCFRpZ1XTZ1IHh5I
         8ktZXvwelnMsU2NIbVtWpEs6dcdRmsNDuqUdothsr4aeTIt56eAGVxeNQwKF42dMgmAE
         d7ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731677237; x=1732282037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f+AZucFDglRpM+YnPe8y7yin2JFgAF9GFW6WkHZpzDk=;
        b=bO1nL2hfUBSY8pLmq8aLw2b5HibyEAiTWfNUNYacbDSV6c6Vv+DYkMK1scsabZirtF
         uwkc38GehOiiXfmDQdlXRvJumhFn6RjbHQnA2I7RYrsofuqwLeWXuc8mN3HruaFfVyBu
         AoLLf+680D/OGjYfXRhOqGA00sGWyH0IF7b9zq1Xf+HiZ5MK5Z/o1KG/pXhjoYkyv39j
         KDPMh879mIfJfLi1IuHBaJBSQEiBXOqQgXiG0zNcqLMXeldl6RZSa2layK8RjpNflAlA
         M9MGFDr5FcTALGMv1thnKRuFLkZmilX7K11W0SEFAMkN7yISDps9boUHy2DCXcf08a8G
         4ifQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAxLwi3nPwOh6O46Kd0ZtY0R1KTSaYnRGXKqzhrWieD2/VOw1O2q9vLtUqHZ/eR38tP68dFw==@lfdr.de
X-Gm-Message-State: AOJu0Yx79SeyMETFTuewtoMoxM/ll7slpc9Xyd4UUaIYuy2NwYq1C0UA
	Ei0ByN9pAUIJS+z4Hk7VonK9HBQcZgHt6G6pRcnJqaci8QaOB1Fo
X-Google-Smtp-Source: AGHT+IFja1QCXGzt0e3R4XAT6lrOKHdP3Bgl7hKWILezf32Flzu7HQTR5i+8XaA5Y/WWPBi+bS3tqg==
X-Received: by 2002:a05:6e02:388e:b0:3a6:ca22:7b3c with SMTP id e9e14a558f8ab-3a7480237bdmr27584485ab.12.1731677237309;
        Fri, 15 Nov 2024 05:27:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ceca:0:b0:3a7:1f66:5841 with SMTP id e9e14a558f8ab-3a71f66598als8580665ab.1.-pod-prod-07-us;
 Fri, 15 Nov 2024 05:27:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUos/OOhdMQX5gBOX/T2wB1AL8XgOhzdN9QYzk1+juVfd4KIZnspj8QNnzuRLLutSrJP/LQC/B4rkg=@googlegroups.com
X-Received: by 2002:a05:6602:160f:b0:83a:bd82:78e with SMTP id ca18e2360f4ac-83e6c32d9f5mr250014239f.13.1731677236257;
        Fri, 15 Nov 2024 05:27:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731677236; cv=none;
        d=google.com; s=arc-20240605;
        b=lc4EYQeuEy/4RlIy+TKcg7PP4NuYbyDFVkX8ER+V1nlRGGX8JNnRNRIvCbBa+q8qi8
         XImm34H/ywxVDu59DWc2ea0G39nKuxv6Fdkg/BN06/M4tv9FEBLyk5LHsBvTk2XY96He
         kSiL5ZsEck17eL51vDghCHANks25bGwzNlL6j/0RjG6nOpjNz5LTVYUkcV9ZtsGh1eC0
         gGwaDOhUsuGugjXamXPffJvFYVesl4zJU+uABTlb2XKTCvAGFyfErIjMn1LgfhGYUrKQ
         qU2U6VqfFX+bd23uC5xcF006Z3Ol9i3n1Al80xkSeG4PxvLQs0uFYHAlBhUHqVd7fpiV
         KWnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=l/ookk9bpEJYDRp+FMnTr4HqMtOntJ6hOvij0zqQijw=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=VfgvjESIh7u63oPKvw0of04ppqenx+UUxsLveZ/BcHvIo1ZAKTa1r6AkczqnW9GMrY
         Mqp81pLaWxy+FFWznTjlXypIv91pQ0teTIbkTpM4mAVKJuRPgN1aOHOM3SLZh9gVPo90
         SQADSo3cvytYYA2zmKDrVIfAv2cBEPtuCP66MPc+RyTiPXoEA8k2w3vJ63gDgx8aM9u4
         6wd1p2aa2uQrg/mMhzSQmePqYWThEk6A93RV8UBPoIUhW7GA8YtFlBgSN4iJWry9GSXt
         mqCZycilGEpaTW722YTxO28LKrC5jV6IIZLG/h2Sw6IzrcZtfbwC1pW4f1ry1WP0SDTQ
         JRJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ihco=sk=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=IHcO=SK=goodmis.org=rostedt@kernel.org"
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4e06d6db428si64176173.2.2024.11.15.05.27.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Nov 2024 05:27:15 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ihco=sk=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 4F7D0A42827;
	Fri, 15 Nov 2024 13:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AF660C4CECF;
	Fri, 15 Nov 2024 13:27:13 +0000 (UTC)
Date: Fri, 15 Nov 2024 08:27:37 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241115082737.5f23e491@gandalf.local.home>
In-Reply-To: <CANpmjNPuXxa3=SDZ_0uQ+ez2Tis96C2B-nE4NJSvCs4LBjjQgA@mail.gmail.com>
References: <20241108113455.2924361-1-elver@google.com>
	<CANpmjNPuXxa3=SDZ_0uQ+ez2Tis96C2B-nE4NJSvCs4LBjjQgA@mail.gmail.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ihco=sk=goodmis.org=rostedt@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=IHcO=SK=goodmis.org=rostedt@kernel.org"
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

On Fri, 15 Nov 2024 13:00:00 +0100
Marco Elver <elver@google.com> wrote:

> Steven, unless there are any further objections, would you be able to
> take this through the tracing tree?
> 
> Many thanks!

This isn't my file. Trace events usually belong to the subsystems that
use them. As this adds an event to kernel/sys.c which doesn't really have
an owner, then I would ask Andrew Morton to take it.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241115082737.5f23e491%40gandalf.local.home.
