Return-Path: <kasan-dev+bncBCU73AEHRQBBBGOA376QKGQEUFUO5SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 9524E2BAED1
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 16:26:19 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id a27sf7042855pga.6
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 07:26:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605885978; cv=pass;
        d=google.com; s=arc-20160816;
        b=BQOFyihlJpEPXwLOgBaGzZXsrmoglXZLWHsD+Kdkf8mIYcqRdGO3L2V14QFqKuUMmC
         7VBJDadlyx7hSIaVa/VLEX9yDXUqrbyol3dlZvqzAT3GUhx0ExEVNFHSDnlyMf4Fvi2W
         0Iyq4cTqMRrKVgLAxWMgYLl3/44DzCVFhnKwLPAYf26H9kNfC1yxFCP9f/EGaYa7Ph2R
         5I4cvS2S4XX3X3yu64UN0+RJO4XLs4MTa9UHtuM0HdkEsCisWUgBdRuKHl985oczOQ52
         IA0TNV1feMN9XD37HHssHP+2lh+UDs+mgB2czj/fu5Cf5I+7RqLMSQUwz5BDmgjSXyZ6
         9AiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=U7PS6MOdCBK5g3cAIeViJrm/Rn9xYCxcP5NrHmSaj/4=;
        b=t+f1W7K23xyCFOi9pP2DLQwWodYDZ1ju1pfBAXwucCng3ZipZ7pL9NO2Bg2y0lPEuO
         VnVAEiwBot20NriIhHwGBcgD9LynrUWPyKkxHAdmktU8h9QYaDGf9T8yv3HbWDsdBcU3
         eftyidDC+zSUUtVO+0v1/sSknNaY163e110dLRoxaxVb0/vv3SVKm0pqeOV6DW+GDjGe
         pEVbitDVJzfEX7B1GOmk3COpV0K9KnF8OkCYCDBwf87DuahZFZ6nYlcMExNU2CKFWC6j
         NGYbGYaNZp+WUXB33Cg/2440dCWT9bq5RrmfYCyrLLKrjH2KNeVlL8WRtRMeh+pTVYYM
         U6Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7PS6MOdCBK5g3cAIeViJrm/Rn9xYCxcP5NrHmSaj/4=;
        b=cUupQFmnRvNMpP+OIkzAA/vvsiABd4qnI9e27qzqFWnhbKYOq8VzZWUHpjSOXkCUwJ
         Uf1SOxHJgTd71fw13ikxoOi1pSRofzKOca9ZIUCdCsxlMGc7KhHXcTL+c0pjIvHiTL41
         l5kfKmduF4YZUIY1prCMKtnbqaC2PJh1EqxjcQO8Opb0GSzaovgkq+fFHptYNY3ENUzK
         Dt7Qp8tjzpSrojb65S/bkwYnpVSTIZwv8niCbkR2T/Ro6IUIx3kqxGA2pnxKaT2Ag/86
         p5HVOvMERO8BlyrTlulmjIz4oHiislF8oVqXhl70Y35My5EI4sJ3v3haDl4EtkkeDLzJ
         iO6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7PS6MOdCBK5g3cAIeViJrm/Rn9xYCxcP5NrHmSaj/4=;
        b=KM14zfXHA+xk49ijvjs+eEHQTQuUjEU4tzb38nELmIP4irDeIBcZZSitLB2aGdRSoL
         BLw6yTOfrPtO029LSqxevk3b147/ElCLixRrinRdPxRHhr1MYfGTodFNAXV7cRsv0Il9
         VT9it08Jm1bgCxiI4WKLN1u9Fgjj0k9zdNFeZL50+uMTUfulEw/Xr8V505xeosEMfCMx
         +w+7rLn7U/ojb0NZyA+t9QDiJuCtGMCi1CPrBcSwlf47b8T4JeIMxtkTyWdxpxiAUdZh
         IjxoOt1ThrHRMQWlu4D+8M2Jw2aBjDhZUXI0wIiimjY0tmxsjHVpH/2rQ2M4pD/g7X8R
         Q/nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+aEf8XPS4lNh11TNAg/PG+d3tJxzIy3r1Txf/YsCe5/rYDysy
	5ko5SKI+xvBe/XGKr2M5re4=
X-Google-Smtp-Source: ABdhPJyk0SK+SPdWtNm7uAbe291HBAxC0jmFed6uIiAPbPhdDVfiGNn8ZtuTDhilvjIjc4RMify9mA==
X-Received: by 2002:a17:902:8d97:b029:d8:94dd:43ea with SMTP id v23-20020a1709028d97b02900d894dd43eamr14672623plo.43.1605885978342;
        Fri, 20 Nov 2020 07:26:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4d:: with SMTP id l13ls2331307pgk.0.gmail; Fri, 20 Nov
 2020 07:26:17 -0800 (PST)
X-Received: by 2002:a63:230e:: with SMTP id j14mr9048994pgj.412.1605885977520;
        Fri, 20 Nov 2020 07:26:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605885977; cv=none;
        d=google.com; s=arc-20160816;
        b=qktaK2h9iI9Dup7CMs6dn0Jsm45tZ9UYWl6HN+YghAOlu2b2GOceUBhIIDz/dHGZnt
         Y/RBtW20Qg9chUC+dqO0Rmg1zcWfkUh5HINaQeEtWU4hyqJExCr2okYP2JIeCe6WS0+x
         sKaCZM6CcfdzurdR9Kt/5VoQmpa/aIpeKWA2rYU2gN0VDmGZQDvPALowIS2jNmIlCjK0
         jvfH47/RatIL8iKyYCOw1ETQdlUNsxmGl3mOYo3zcs3xaSgxiJaqUppJMzZagI/7+P3h
         X+TePGegYXGGHUFSItUlEbsXrzGBtLEeHC/qnP1BA+nUHKlYphxFa524FeXPTpkxHwp6
         v/dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=jUaqPamdyq03oB2jdnPKrIcFnN9DQ88uv9rRhBPBGuI=;
        b=oy+iYRWBGM0mogeKANo89uyfxAszF3SG6xermoQNZ0TIzPnFxcp2oJI4n4Sy1sqglZ
         RITq0AvfJ5BSNcWkAOEtR6mBoTx34r0zepX/4P88hrUxQtbxfPti8g9n7m2cqmgJ6stA
         QtlycW306bHebk5mgGirD1eFiv10HklQQfiaCZ/G14+B7wEDlGPSKLxa0GBLqOdURysH
         0QCyNF4rb/kj9RN1XC9KWPWY8//EbAPYndDlzU5gQH5zW1t9aoroPaEmgZyZ3DPD210g
         hKAi6+exZEjPTc6H6R9G9ccr6yE9Id6VK60zk9ZPCPvW/uaWokGBIvfCmF3vZyUgxoeY
         FVvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bg19si326825pjb.2.2020.11.20.07.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 07:26:17 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 80E0322252;
	Fri, 20 Nov 2020 15:26:15 +0000 (UTC)
Date: Fri, 20 Nov 2020 10:26:13 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>, linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120102613.3d18b90e@gandalf.local.home>
In-Reply-To: <20201120141928.GB3120165@elver.google.com>
References: <20201117105236.GA1964407@elver.google.com>
	<20201117182915.GM1437@paulmck-ThinkPad-P72>
	<20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201119151409.GU1437@paulmck-ThinkPad-P72>
	<20201119170259.GA2134472@elver.google.com>
	<20201119184854.GY1437@paulmck-ThinkPad-P72>
	<20201119193819.GA2601289@elver.google.com>
	<20201119213512.GB1437@paulmck-ThinkPad-P72>
	<20201120141928.GB3120165@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
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

On Fri, 20 Nov 2020 15:19:28 +0100
Marco Elver <elver@google.com> wrote:

> None of those triggered either.
> 
> I found that disabling ftrace for some of kernel/rcu (see below) solved
> the stalls (and any mention of deadlocks as a side-effect I assume),
> resulting in successful boot.
> 
> Does that provide any additional clues? I tried to narrow it down to 1-2
> files, but that doesn't seem to work.
> 
> Thanks,
> -- Marco
> 
> ------ >8 ------  
> 
> diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
> index 0cfb009a99b9..678b4b094f94 100644
> --- a/kernel/rcu/Makefile
> +++ b/kernel/rcu/Makefile
> @@ -3,6 +3,13 @@
>  # and is generally not a function of system call inputs.
>  KCOV_INSTRUMENT := n
>  
> +ifdef CONFIG_FUNCTION_TRACER
> +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> +endif
> +

Can you narrow it down further? That is, do you really need all of the
above to stop the stalls?

Also, since you are using linux-next, you have ftrace recursion debugging.
Please enable:

CONFIG_FTRACE_RECORD_RECURSION=y
CONFIG_RING_BUFFER_RECORD_RECURSION=y

when enabling any of the above. If you can get to a successful boot, you
can then:

 # cat /sys/kernel/tracing/recursed_functions

Which would let me know if there's an recursion issue in RCU somewhere.

-- Steve


-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120102613.3d18b90e%40gandalf.local.home.
