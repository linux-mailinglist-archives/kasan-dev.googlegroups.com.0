Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVWCR34QKGQEP6WHW7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id A4CE5233E61
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:03 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id h88sf8406555uah.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170582; cv=pass;
        d=google.com; s=arc-20160816;
        b=jx7cKn1YjX4Uz93j4RMNmEwnJUkx44jncWChkwR+Pf78AKFhKHX2aUw+wGKcuso4nm
         sDCm9xLM/QLfroneLN9Xlby7MLg3bzsjtQXKuVyRrIOsTyWtw0q1xnh60yr13mMMM7PD
         2AieTeZsiMinS2qcTjNlzRriPEpCW5aKUaJifnrmtYSghOIJ/4aG1/wX8IuA4/lQyxMs
         /kz18pPLEZHtn0T3zV/e61S1JipaRXTv4/p5mif5atD5VzwBdOinbuVVKPFOYNdhTJMr
         aZqKrt14F+hWi18n5EATW8iNCP/7hJUNol2XzMTKCZJFfe5mU4caqpRqfvxQinIw9Sxy
         9XLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VHktAoKj6F9HkYMANpJRBlHMfldDWdai6XEUiMpQlRw=;
        b=qp+ZwHJZnobxKObujuUSPhH0Vc5RBkLU/j5cYTDent8yI/amn/27BCbgtfdQODo+qv
         yHXQVO9h84b1M9KgNh6eT6EUTBGWyeC1Mb1BzJZUrRy8ib2nZuckDxTlE5cQX5djhbgM
         7lpn5XCKEr4uxEJa+avunIM8kYrvJgXWwvxr2+jBw4CbyVQbngNHQ9omBZZ1lrShnbGo
         GVi95mI3uj8EjU8k8tJHHQkt5+WYQKbHI8A2qEEzC/Uc7aplg286wlky+aTbIQwr2VdN
         ukq56dnx7GOB8gIPN6qVtKZWp0yUXjokMigqhHudPtU6s9KYVML0oR3FLmHzEQZh1+UD
         YzcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wK2O50yS;
       spf=pass (google.com: domain of 3vaejxwgkcsyfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VaEjXwgKCSYFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VHktAoKj6F9HkYMANpJRBlHMfldDWdai6XEUiMpQlRw=;
        b=X9J8NhWAJNzPz5bAyjTTEtWpxODw8mSMUXEF3RSxVHlycvcqTrgC1FGQHtvuJhR8XE
         7Dv7btrwua1uv72nmEuvGGE2FXgZ7etFQ+E8KosXAw65RVLVXn+Ym0ESAV347zc+FEEq
         kOvlK98N48QO3koplCiLzPAW4oToATfS9/i1P226hrUgPO8FaSSrjKIRUWxXXRPSNy85
         QjWnPJTCgx6iPE8DJybjoc081k/7rGYskP7080MhtJ6RhNFr/EJnhXxMy5x+YvZGjcTD
         8quJuX9aj1xOsbBHF6mifRJ7VqpMjU5CPWyu3slzVKuSyw3L8VJCqGy4TaMx+G31NhQ3
         T90g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VHktAoKj6F9HkYMANpJRBlHMfldDWdai6XEUiMpQlRw=;
        b=dDFUAoBV3o7jFV8xtOl7ooIooF3rGVaMO/dmz6vD+GyDBhfJxN0aAdjAuBOO8F8mis
         jl9nZBFUVfQridEvBk+UJa2sOnGKbu9nqyHqL22j9+hix7hjIetjb37Pn10Xl+RuD6kI
         kyL7jdMGEe3mGuFomSR+NfPa0dLPk0gUuVNSadhobsf8AJMp7R7IpGRui89aspmfTaZh
         UPF+RX2tRRgKgdRo16UOgS3DXnceSBwYlNbcw9yNYKz2s+xxneDc/+pSzRT3tJEAwZC8
         pELvLT9gSEA9Lkqb16nMUPghrS0/Tkn2+BM23HHcpQfKbyGXJLx37VoSjQL01EO+ytWO
         QyGg==
X-Gm-Message-State: AOAM5333sklmWc0Tiy3IPTyuwikvMiViUQOOeTr8PRxpmjhJRxTMvk2m
	45FcA1OfCTxOQunmqIscFys=
X-Google-Smtp-Source: ABdhPJxjpzc09CagJyKNWqQyJUaAyX4vsjSX7RdAwbNiHSOCiLE3U9kjRS8qGnNECaMH9UHiJc0DVQ==
X-Received: by 2002:ab0:6905:: with SMTP id b5mr1525059uas.110.1596170582647;
        Thu, 30 Jul 2020 21:43:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2b0c:: with SMTP id e12ls561043uar.9.gmail; Thu, 30 Jul
 2020 21:43:02 -0700 (PDT)
X-Received: by 2002:ab0:1d18:: with SMTP id j24mr1414263uak.30.1596170582272;
        Thu, 30 Jul 2020 21:43:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170582; cv=none;
        d=google.com; s=arc-20160816;
        b=Zbo9OkYHBtTOwz8ULZRy1iayN/0ou+xXaErentPf5KGOSjUZu34Pfx99/hPBdnrEI7
         Jzi7JTAIPLCZuSxxIPyjFaNnoFSQHOBV4P6qkvX0B32mzM8byUvos+JLqo8G7xtPki6H
         +UmTGmDMe/fM551/7PCM80vdqJOef3knOKl320KKavJdruFMPQn190SqCfmcHw0TJUDs
         Imeatsw9R20DSC7PRTSSjZaQrZYPP6AFn/IxO2ImRraN6805yo1LPMOR/Z4byc3hyDRw
         OIv6zWuPZH3ozbU5CVqPxSpJxRhbpvxOOS40sG6qIOSuzWzl3Gtw7UD4iMbhUpILe6Wf
         9BWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=beEVykI/w3KZVAvPQjbc06TAF1ssDBP5sJ8EW7g7IJE=;
        b=Sv69L1tJjwFO9xZvJt5fbN6QfSTO2/ha3wSBWihHsay8uTWNcqSf3NDpxqGhOWHc6R
         s6U609/gIlFHzxe7y+QJDyqrk1bHDkKSO76ykAjoEXeHRddqGugU0+XzfgTDr8f9XdDA
         oGwsx5/7YVytPp975il39dzW5UpBtuW2jxCVl/nEIB4CqNkVgqmafvPG1QUnKi82oDgI
         LoS569Gqy78FUBpOXH0poe/JWSO/71XXDgRykYt2GjTGz0zdIyh5vPObAHpiJY3MtmuA
         jztzvzmY1QI7po7ciMfnJrBvpBxSNCiq5PCrdJ4l9QNMvM94zmqmzY8jvauqoaRRGCkh
         1jeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wK2O50yS;
       spf=pass (google.com: domain of 3vaejxwgkcsyfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VaEjXwgKCSYFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id l129si516484vkg.2.2020.07.30.21.43.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:43:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vaejxwgkcsyfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id a14so27550301ybm.13
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:43:02 -0700 (PDT)
X-Received: by 2002:a5b:30d:: with SMTP id j13mr3228618ybp.51.1596170581813;
 Thu, 30 Jul 2020 21:43:01 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:38 -0700
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
Message-Id: <20200731044242.1323143-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 1/5] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wK2O50yS;       spf=pass
 (google.com: domain of 3vaejxwgkcsyfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VaEjXwgKCSYFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 683372943093..3a27399c98b1 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1197,6 +1197,10 @@ struct task_struct {
 	struct kcsan_ctx		kcsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-2-davidgow%40google.com.
