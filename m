Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWESWQQMGQEZHIUNRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D6BB6D00FE
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 12:20:20 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id g5-20020a25a485000000b009419f64f6afsf18233413ybi.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 03:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680171619; cv=pass;
        d=google.com; s=arc-20160816;
        b=0WzODih3SRa04eykEx4Bj/Lw0lBGwZ9Bo1OKML99UPQbfwuPHo09lktxIs1xYHOAiV
         O0JoPjRyFOiWf2nmaalxYM8Q9j8CBvh2CSEIq4sY7doVeqi6T3ZuDxpPBmK4q15ShMIX
         fcLDocbSxC008+MsevfKF3pIWYjA7drVE+58rwIph/S5ho+1fniuqqxyAiSEsxw4Jmxg
         kS7rHauhghHfdlHxh+49q+O+BxJS/a81Ad2mjMMzNjdi+fMryowDjAttaGyY5nu84e7b
         tD3KPqyKmk39C3Fg7MPNpU1TRXxmqt1q0JLEjDxvTKmnBPx/ao5bNbqXHslbeZJGQyWc
         aYWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sGUwn6hhVm0iihm4a07mhK2/XgQOrdm5vl+3kM0YikY=;
        b=QXiZeHYhKTgcriE61tks3oPsgh7EM6N2SvqirD2r3GYC33hXSFvzRoEi+OdkwJE0av
         Ri0aNQzoSQ1xS/6gPxwO4LrfAIuw9k0vuD7sXrPkIhGCWJsVSQYD55l8DbWVTO7XEfOX
         gZu6obb+wzAopZQa4/EvVhgx+URLw9x5hy2b+dGArzUrqztk8WgmCKYYSYLPptTjY4u5
         1/8bz6Nq/5taj6CP+wkVCLGHSzM9PcD4DT805EkF2RVUzvm9oLhWQ0CcSE1YXKsf4Ubx
         dGzk1m/6UBUBGdDzShDgBno6f2vmBcb9H0FVPuOi/MqxWajFJ0aeNp0RrBSclFlQt/R4
         St0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzxQCOnQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680171619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sGUwn6hhVm0iihm4a07mhK2/XgQOrdm5vl+3kM0YikY=;
        b=ICd8cKQM+x5zvJDq7tyGgmTWt5flp83iZfnZww1+nzDjL4BCLbIOfAMjNJr/VfPZs5
         pTIpW3uy1c5d0DmSmX4TRxlFRtoV43JpV49yREuQaGFzSy1h/6LWQbl4LD+WXRvoZx2j
         Ie23p+A64ceJoeIEmok2ZezLjm+SAchMmllEUQKMv0NJmQX+Ggh1RJOyMMIfyT3xN4M3
         EEESiPgfWJvv0w+bF2Kke/wPRsEUlCDFWQ6+NTc8O0Gz3H4cfX1J+H9ReDaMCOJ6Yc6Q
         UG607OQDMgLwjR/M84o65mYvEdH9T2wRRjpOlOtzBLgxy5+CjZE0LoVdOcX236nS2UQ+
         4lTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680171619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=sGUwn6hhVm0iihm4a07mhK2/XgQOrdm5vl+3kM0YikY=;
        b=L6jE/vdgF1YJmS4+DYo+6pWDyaNcTNgoi592SUgr4KJBFE3ZTAdcyWM9XnJaIXNV37
         CrCa/tI5SUasTz+LDytCtJcLOW8UbaxNY2cv3/mySCGevylQnI+v80r6gPBdOdbdOw3R
         a9dZkBDDqV4oQT+tULZq0reaiLvLQXBg2nwFyJVfbpuJDMPR4wS9s17sxOJzJQcAkqEo
         p6OgksPxrR0YRzltvL8yHl3hA0vly7jVSPmQcYljxK/FVuQC06nnO/kUzWq/8aCWbfer
         vLINVkQwVNEpHJHRbt85uJUgFshWZTA4farazmDGnvSxWw99ghOBwcRALZL0MH+rzziK
         GQMQ==
X-Gm-Message-State: AAQBX9ddJ4dIGRNPi9cqAV9vbrh4qdQ3Coe7c5K+djJYNIWMWcN6YitI
	dJRtgspUrNse6uiAlyPvQu4=
X-Google-Smtp-Source: AKy350ZdlC9oZFnIGhkOsR1V61eTD3qGUbp8sF4SuFEI4XDfWldV8oGRFfkfNhCrDPIkiiuGiWiKbA==
X-Received: by 2002:a81:ad21:0:b0:545:62cb:3bcf with SMTP id l33-20020a81ad21000000b0054562cb3bcfmr11289857ywh.2.1680171619100;
        Thu, 30 Mar 2023 03:20:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2208:0:b0:b61:1f9e:bff5 with SMTP id i8-20020a252208000000b00b611f9ebff5ls892334ybi.11.-pod-prod-gmail;
 Thu, 30 Mar 2023 03:20:18 -0700 (PDT)
X-Received: by 2002:a25:ad60:0:b0:b67:c5af:525d with SMTP id l32-20020a25ad60000000b00b67c5af525dmr21805423ybe.55.1680171618361;
        Thu, 30 Mar 2023 03:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680171618; cv=none;
        d=google.com; s=arc-20160816;
        b=q2Ym1L4MiQqHJ4PstqKp94rhgVHpZQhDeIKkuqsonP5mySgmqj7R3csTdmC/YcSMEO
         P7cDjneSTt1G6ZnomM7qyaeOYBF2bV9ayTfsxaTneawmfTgR4qzjNsKXcVHunxbjHj4K
         /EtLK0vTNq34K4JBLQoZXEeGf9uVPTEvrx/bjKydkV5yBNoXIXEab0aHzyuo5oMcXICV
         l1UN/ZNUXQlCdST05DmvEc2qD7HgEkLu97wcL3+/Txmwu99v+6Y+X58Pg7tqLYLqD2Am
         P2OYtfja2ez6PhwRTteULgpATAQAXB3MYNo9MUm2iY+xAKxTuongQNhPAOQAyq2nDdXZ
         sObg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M4Y2U0FWvmSoCA4G791gIQlcGTXzfS+ytaj/vB6IHj8=;
        b=i9ZuqwmRXJhkkcAsHJBE6CHFdTr3/E9B/pmzyGDCS3pv7aOx/GsFv52zFJkHFrvH5R
         jtK94NujhTYCOmCEyhUshrPJUOcg2ndSLXfi5aa6R0h0Ho17FGJjCTUQfmNBQmBRmz+y
         BcE1nkrXcnYjnnzFK4I3shK91CZ3I2ONqVmYMcT6vMh9rdhUcIiPBizld/Yol0mhNRLK
         VapzHCG+IbERx6uGVPQ0S2qxe0v6qHa2B+AGxr67305VQ7NsrZFMWlpGB3qNjyRSaKZ5
         HDlNoDoqjHolz1WDPKm6TgpWRH7RmxjvOo+Y0Ls+ycXn58epl69Ov1HTgiY2A/5d/K14
         P9Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzxQCOnQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id s17-20020a25b951000000b00b76a55e9e93si1141314ybm.0.2023.03.30.03.20.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Mar 2023 03:20:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id e65so22746228ybh.10
        for <kasan-dev@googlegroups.com>; Thu, 30 Mar 2023 03:20:18 -0700 (PDT)
X-Received: by 2002:a25:16d6:0:b0:acc:1061:44a with SMTP id
 205-20020a2516d6000000b00acc1061044amr16607531ybw.50.1680171617974; Thu, 30
 Mar 2023 03:20:17 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com>
In-Reply-To: <20230316123028.2890338-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Mar 2023 12:19:40 +0200
Message-ID: <CANpmjNNZMHHjbN_5a3Krk1xPvT_WLKGUxueaKjUYJZkeDZ=AKw@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>
Cc: Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YzxQCOnQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Thu, 16 Mar 2023 at 13:31, Marco Elver <elver@google.com> wrote:
>
> From: Dmitry Vyukov <dvyukov@google.com>
>
> POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
> thread of a thread group for signal delivery.     However, this has a
> significant downside: it requires waking up a potentially idle thread.
>
> Instead, prefer to deliver signals to the current thread (in the same
> thread group) if SIGEV_THREAD_ID is not set by the user. This does not
> change guaranteed semantics, since POSIX process CPU time timers have
> never guaranteed that signal delivery is to a specific thread (without
> SIGEV_THREAD_ID set).
>
> The effect is that we no longer wake up potentially idle threads, and
> the kernel is no longer biased towards delivering the timer signal to
> any particular thread (which better distributes the timer signals esp.
> when multiple timers fire concurrently).
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Oleg Nesterov <oleg@redhat.com>
> Reviewed-by: Oleg Nesterov <oleg@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>

Gentle ping...

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZMHHjbN_5a3Krk1xPvT_WLKGUxueaKjUYJZkeDZ%3DAKw%40mail.gmail.com.
