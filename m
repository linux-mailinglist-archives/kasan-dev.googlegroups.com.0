Return-Path: <kasan-dev+bncBCU73AEHRQBBBJN7TLZQKGQEG3TSXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB6CE17E973
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:57:26 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id s13sf7494211pfe.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:57:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583783845; cv=pass;
        d=google.com; s=arc-20160816;
        b=krfewSsH5L84TLIlzMyUXm00Djalw6d8N0JeGYLD+nqN+Qc9vmRvD2mC3p6RlmvwZH
         zoYN438vJ/+Wkf1OZlWJKBiE+KE+2KdpOEyY2MfLcibO4151sAbRqRDYxFFxu5qi30/j
         7BNcZQ35GkstDP5/GpGhB6fK6he3lNKdNFrm62g9X8azR5bVuNvthB/iLkD+cEBMEYnq
         LjNoOJCec697n10li1BTWNQNAIfkRhCC2BlRyCvYF+T49CMw2NsNE+/PqQGukCXtSAEt
         QSg95hs/q8UL3IiB1rYdjS9jGXfrHN/Nd2ra1nf+v3LQd4EXLOcYu4HZiZBnu4pPc03g
         DGMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LfRQ1P2oxPvKQvFHRP7rZ3c0nAmm94zbljHbT+6JL8o=;
        b=f3kccrBUPeOHVddx0fZ1apHEpeOOuabNWu6OrrWzCJZTEZq0Dcax8YTPPn5vUso/xt
         dXgVfmkOa7btA6C1yVParJzrRij6eoeD1FrLp9269wDXYNfW/xg0lW6tpFbsMI3qL/sT
         AlubwHEoU/symSY+3ChFfl5QVyLU7YAxC4DRvNo5qCCw/ecR5HG+HBOEO5fqplwB3yms
         yvlMiTS2vOKZAci0HKlVLO08qVG/RpeeXp7S5im1qW/UIiNwpkIc4NinYmoL71hpKa5w
         lY/7+ZZYt+Ba1v24w4rcT0R93ay7oEE++ARGzEXX0JLEhjrzQLWtEeaMxoA95msu7bx5
         wrrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=nhwo=42=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NhWo=42=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LfRQ1P2oxPvKQvFHRP7rZ3c0nAmm94zbljHbT+6JL8o=;
        b=jjFtiyXmghoRH0t+bwKnO6ZFUAYg8n+GONfV7o8W+MSeBbc0W3W1AueLCsvut9tp9p
         btrfE0iaR3vo3On0TONQPT9gGBddBDzzhLcEhtTae178V4xpTaN6R0SKXTJ5nMB88w15
         c/owdw1gfB3B8Am+HIJsRd89KOyRU+z8OG6WSG5WZT/37f+saUTEf1Fe6vz/ZA1P3PbK
         /tEXrydb2cN6OXqNbM2I/W7kIWcGunQxqqYQlID2TGCaODW8egKSO39npdeCrIejmXpk
         hrZQMLXRGDnRHiqJfxbxojd0rA4EXFdp+6+EDku4AWH2zotwkKwmSZBswHXi04Ytpx6c
         yJTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LfRQ1P2oxPvKQvFHRP7rZ3c0nAmm94zbljHbT+6JL8o=;
        b=qp07P0PjOe1B+GTNLIVItpQQtQsWgexCDHI+CIh0c6eS8d3b6F5FUkmmbL21exYr91
         md13x0uF37UqgJSpqmDVIAPTbiDiyOSbhAx7v9F8BwMV0I6svLKnJuBZjE4ZM55KzlBu
         oHrd0/I0Zufr3kwF/1m9yKxEOI6n5sanVj2BpYOMP4+AA1aFoCNGf4R47bBYTPV8dTsR
         B4EOv8CGZjtJzoVuT/uyfkv0jclpLzoSpD8yqoqDJnl+ZHnxmniM+z1EPU8atDaGyOMR
         cPnDDRKXw68wz2bCdcA3KSIih1licPJXEdIiNQLt7QHgbYTTrk2vfEjZtnpRMyTvn3gg
         n3qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ06wMkG2KG1qJV1epDr8Yw9uEHwB0I9XXim03YPGs5vQIioMYhE
	u8R0GA0tRmz6G91q/p6oAqs=
X-Google-Smtp-Source: ADFU+vvCXiNAhZSq5aj7OWSgXVfNSx2aA6obYPTS0mETsAVj5jMP5VZZpkLpoqIj2/cthz8zEtqsBQ==
X-Received: by 2002:a63:b34d:: with SMTP id x13mr17932534pgt.317.1583783845604;
        Mon, 09 Mar 2020 12:57:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9e2:: with SMTP id 89ls487593pjo.2.canary-gmail;
 Mon, 09 Mar 2020 12:57:25 -0700 (PDT)
X-Received: by 2002:a17:90a:be0c:: with SMTP id a12mr1050168pjs.26.1583783845189;
        Mon, 09 Mar 2020 12:57:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583783845; cv=none;
        d=google.com; s=arc-20160816;
        b=CCTd2jfnQUd7hCPcdf2CfDOsIFOML1qsZkKCVU5+Z7ADSNgiVuX6WZS/LIgIpwP/8E
         3OZTfs6O8U9zi3tGlokx7Lj/JQ8dR+j+3Ztq07HhlhWdJXMiDEkBgZcuNv0tnR9XYYgY
         2DrVmbTmsMWEtEFVwYTD9c1t4vu+Qsvn7HXC0KtzqKB3simja6XbvzXN4eAS/jlIZeM/
         Fvb3QA6hj2Hia2TZvwGnUsumqlVFKZEfFrBfERtxdhaxOYbgT3Cph4RpAbRZMyNOsD+S
         /Jc1w4HlcllsUXqWcy31VIFsXlosfS6vEFc93R3dzL4B4pYFtubMXHPfqDHzu8j+1vXh
         G/ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=b3MRlKJHvJmpHlvmoCWFHY51W4ezO+581UR+7sUp/TU=;
        b=H+/23Y/B04lo8OJ2MjjyFmwCHbW0PxVPa4ihehNunJZfH45r1LMmD+UMu7jv0z8FQd
         +umL86OqVnuiKC8DhItoEIrfvcaJ/Kl3wPS5T79RAfCteiTMZTRpAqsJmGs069ILSAke
         O91KYADgwA9kWYpGhuluw+egP7sOp1/5OjlTfZFmtpITaYCJWfMavF+QaDtU3nNWcCyD
         rFF0LAByZRR+xfuWmfr7vBs62aYSArzMtbfTUFXJiIqNbJjSlAw2KChGCl/1HumBKyGs
         KjVKF5QsVGB4mnTPWUqboPWL0TsWaNhkaNQgyy04PTRBQFnWUB26cBgR/I09DTZ/SaU8
         LhfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=nhwo=42=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NhWo=42=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id hg11si34980pjb.2.2020.03.09.12.57.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:57:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=nhwo=42=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C8C1A24654;
	Mon,  9 Mar 2020 19:57:23 +0000 (UTC)
Date: Mon, 9 Mar 2020 15:57:22 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: paulmck@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel-team@fb.com, mingo@kernel.org, elver@google.com,
 andreyknvl@google.com, glider@google.com, dvyukov@google.com, cai@lca.pw,
 boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 26/32] kcsan, trace: Make KCSAN compatible with
 tracing
Message-ID: <20200309155722.49d6bb93@gandalf.local.home>
In-Reply-To: <20200309190420.6100-26-paulmck@kernel.org>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
	<20200309190420.6100-26-paulmck@kernel.org>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=nhwo=42=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NhWo=42=goodmis.org=rostedt@kernel.org"
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

On Mon,  9 Mar 2020 12:04:14 -0700
paulmck@kernel.org wrote:

> From: Marco Elver <elver@google.com>
> 
> Previously the system would lock up if ftrace was enabled together with
> KCSAN. This is due to recursion on reporting if the tracer code is
> instrumented with KCSAN.
> 
> To avoid this for all types of tracing, disable KCSAN instrumentation
> for all of kernel/trace.
> 
> Furthermore, since KCSAN relies on udelay() to introduce delay, we have
> to disable ftrace for udelay() (currently done for x86) in case KCSAN is
> used together with lockdep and ftrace. The reason is that it may corrupt
> lockdep IRQ flags tracing state due to a peculiar case of recursion
> (details in Makefile comment).
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reported-by: Qian Cai <cai@lca.pw>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Steven Rostedt <rostedt@goodmis.org>

Acked-by: Steven Rostedt (VMware) <rostedt@goodmis.org>

-- Steve

> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> Tested-by: Qian Cai <cai@lca.pw>
> ---
>  arch/x86/lib/Makefile | 5 +++++
>  kernel/kcsan/Makefile | 2 ++
>  kernel/trace/Makefile | 3 +++
>  3 files changed, 10 insertions(+)
> 
> diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
> index 432a077..6110bce7 100644
> --- a/arch/x86/lib/Makefile
> +++ b/arch/x86/lib/Makefile
> @@ -8,6 +8,11 @@ KCOV_INSTRUMENT_delay.o	:= n
>  
>  # KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
>  KCSAN_SANITIZE_delay.o := n
> +ifdef CONFIG_KCSAN
> +# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
> +# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
> +CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
> +endif
>  
>  # Early boot use of cmdline; don't instrument it
>  ifdef CONFIG_AMD_MEM_ENCRYPT
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index df6b779..d4999b3 100644
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
> index 0e63db6..9072486 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309155722.49d6bb93%40gandalf.local.home.
