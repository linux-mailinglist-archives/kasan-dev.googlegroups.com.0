Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBH7NTPZAKGQE5UGZCRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B6BD15F6EC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 20:36:00 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id z26sf7432089iog.6
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 11:36:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581708959; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pn5mUb95xNAGNDZccnmT4LiO1WIfMD2cqKsBcXUFR6eP/dK2qeUB5WO+6CKeOnVWey
         L1wGIe2ei+Xfq/k0RT55mb8VVlRzvb4pUZSNqaD5U6e8vhAwDdvr4ItujMBiESZe0k0i
         YWRbf50vEJB1M63+l0E75kxUrRIOFy5AU2nVaWKDHmS75DEn6RuXbU1A/edAonA8ubf/
         r0hsCBNeJdkpUKCpMNvZZ6JHQxuA7fhAJO/4cEYT5VvQDkI0JmNtYptoSxhVQxwG4f/W
         2mUfmkKNfVwpwweiMUx5WwDAD0wVeRvxyapq3EBVDBbbvPTY38fXGS6ORfWHatwDUNph
         SQFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Ku/DuR20aJIJBOJQR7+xeBl3+NtxViSMQgQ4w+urnfg=;
        b=Qu3MLtWPY7Jvy3nq0XM40MRxq9fGnlN/Ew5M3hMnO2tKzeb8JTPmSV0UqRPvdMqI7X
         Ed7nRcg+GHrOD4TsPurrNzPHu85+YM322wmVlpmERyl1VxiTAlVyUyKwqTRsYFKQIujs
         FFlUUKxJ0zFm1IELIBSGnBcEOzSz79c+vfcd87xyZtGZMwoeM40ZjGwV1C57K/vPidmY
         zXaXUktxqfcKDwtocl2gGu55x6wIP/utJ6WKN0u+hoZ7512FRUKfRe/WdfqXS56b66z0
         UcYDUXDsXRdC4PV4zjIxSIOnFipuFwI21PHBLHzTehPb9x6TFqP2/YnnlgR5C7FcbtaW
         P/DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hPHSSPqt;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ku/DuR20aJIJBOJQR7+xeBl3+NtxViSMQgQ4w+urnfg=;
        b=cwd5DchrM6heQxkM2q/kcmw20GqRcj9w5hhtHTbNDXT0LExdEAp4KNmGbRRXJT/bUg
         CpKWJ4r7FafU/LLMTg0kDGcGuPPJlB19rbAmQDLSa/4Ygcys3BXkew7qQ0KJb6jODGIO
         Huxj4vroc5LBNByWNNZ93CcNFsT2NAqZG6yvC0oKI6RqBjsX50AQAn8qAsMrYT2u/4aJ
         rVbQqxMrwjAR8PkJYvj0xEa97LerQbpPfVHQk0OUCPAwY/K+/Nsi+0KEBpPP/66r8mU9
         tKlTt/2wTnr29hEHa6TREs5w6gLbMplIJErzkhU5MmIwCar6qWMSkA6qpbKbNLnEZceM
         STOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ku/DuR20aJIJBOJQR7+xeBl3+NtxViSMQgQ4w+urnfg=;
        b=Nz4UEkBPb2ngCQgKJb5ZULfY5166Y4T45axynTncXmoXatexYhxZPVnR34fVPEY0po
         Zlq3L1/DsKybDQ3YxHDUkuPxnns2FYKbzEvUguL6lvVws8TC1+NJ0DOzt3Be4wkB+QVI
         4LQbVNZdPoQLMCKgBKFEp9tdF45l8bK6pb29LxVsWzsNho2ONzLnKL+wB+orfCtlPJ6n
         bscfJDiAaneMZSb88OVzIvuW5Lcm9KWT0ZQRPjL4Ei+SxCgBpJ7MhXVl7QmyDbypVsx+
         pUqWnWlPqDNqsY4Dbrhs8+i0SLG+xE97/OBVigN+xBT8OCBaiFdiLTIaLA7kVWLUU3j/
         3chQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXS7YieqGfyuYehDfHwHVgPmUpqRbJmODrmkafdFUWk2Xpl9j2Q
	cf7sSbo5pHMnbFun5KtmTgs=
X-Google-Smtp-Source: APXvYqzvhWBMMxtwaa0Jbneqdu9cPybcwI0eiDN/HA/1OLlYnUJ5+FJzimGqkGMtG+xmuXLP7iSG/A==
X-Received: by 2002:a92:81cf:: with SMTP id q76mr4383716ilk.303.1581708959536;
        Fri, 14 Feb 2020 11:35:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls735649iln.5.gmail; Fri, 14 Feb
 2020 11:35:59 -0800 (PST)
X-Received: by 2002:a92:9cc6:: with SMTP id x67mr4494483ill.31.1581708959180;
        Fri, 14 Feb 2020 11:35:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581708959; cv=none;
        d=google.com; s=arc-20160816;
        b=yVPMf6C8WlsEHk45uwuMD4F97bGh937lMUiWGeIVW7IXa6KEUXzx/D89RZtGyVAE/u
         UuBVGX9TVvr17A1aR3N8n9RZ8ChARBcsJJSRJjWfnSlCqzNxPE3BiEYMVNgxhITV8Yty
         +eajdFFJpSna0jCy7pWILSMRZo94ykopayRn1pmxh5pnK9kWhqH+o4mNiLMc/Ym4olG5
         TP3uynv5tNeJxPicbG5gxIlIGJajHynprF/8rlVcXTLn0loGZnj0ZUMLn24AFzgqpY6m
         GSj8CGaDQy14IQBhBQ1wEcm2+icXURoBRWmEiDAAjhRayumze67alxo6rqx45BsxJYFZ
         Q8Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=yb1Saty64VwiYtQw012LpM7Ap4tjw5lo68MqBy5+/VM=;
        b=V2OTPUDof+DZbfyRek8xv9JuWpcdfcmjsCqmnc8PMjveQ9nf0khtjRcSWo2vQEu2Rh
         7kXq+MVMxeWZ5wuR3awvkMn5OiNQNpTNp5CogiCjDh1TYT0xRxBTnpTu6xXbQ6i50fCP
         I8sDvRjqEFlSFPz0i8eii1kUSgraj5MAsj87vEHP5NmTB1f6jYtQGtx/4sw5u/uY3Pnn
         HLFSd2/kXNUfvz6fd9JUoiGwuOD6K5LExRkMlhJg/Eo5aw9ICWXYEqKxOG3VCT3KrL1/
         veBtTGdhP7z1Kzn0zFPgLscX57kptoeBaC/2cLkCkLcPmq8o4l65gAozXtM476phMcoW
         FQrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hPHSSPqt;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id b16si332374ion.0.2020.02.14.11.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 11:35:59 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id v25so7727707qto.7
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 11:35:59 -0800 (PST)
X-Received: by 2002:aed:2ce4:: with SMTP id g91mr3869190qtd.352.1581708958590;
        Fri, 14 Feb 2020 11:35:58 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id l25sm3762879qkk.115.2020.02.14.11.35.57
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Feb 2020 11:35:58 -0800 (PST)
Message-ID: <1581708956.7365.75.camel@lca.pw>
Subject: Re: [PATCH] kcsan, trace: Make KCSAN compatible with tracing
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
 dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,  rostedt@goodmis.org, mingo@redhat.com
Date: Fri, 14 Feb 2020 14:35:56 -0500
In-Reply-To: <20200214190500.126066-1-elver@google.com>
References: <20200214190500.126066-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=hPHSSPqt;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Fri, 2020-02-14 at 20:05 +0100, Marco Elver wrote:
> Previously the system would lock up if ftrace was enabled together with
> KCSAN. This is due to recursion on reporting if the tracer code is
> instrumented with KCSAN.
> 
> To avoid this for all types of tracing, disable KCSAN instrumentation
> for all of kernel/trace.

I remembered that KCSAN + ftrace was working last week, but I probably had a bad
memory. Anyway, this patch works fine. Feel free to add,

Tested-by: Qian Cai <cai@lca.pw>

> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reported-by: Qian Cai <cai@lca.pw>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Steven Rostedt <rostedt@goodmis.org>
> ---
>  kernel/kcsan/Makefile | 2 ++
>  kernel/trace/Makefile | 3 +++
>  2 files changed, 5 insertions(+)
> 
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index df6b7799e4927..d4999b38d1be5 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
>  UBSAN_SANITIZE := n
>  
>  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
>  
>  CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
>  	$(call cc-option,-fno-stack-protector,)
> diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> index f9dcd19165fa2..6b601d88bf71e 100644
> --- a/kernel/trace/Makefile
> +++ b/kernel/trace/Makefile
> @@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
>  ORIG_CFLAGS := $(KBUILD_CFLAGS)
>  KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
>  
> +# Avoid recursion due to instrumentation.
> +KCSAN_SANITIZE := n
> +
>  ifdef CONFIG_FTRACE_SELFTEST
>  # selftest needs instrumentation
>  CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1581708956.7365.75.camel%40lca.pw.
