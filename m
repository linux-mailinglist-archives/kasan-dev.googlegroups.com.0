Return-Path: <kasan-dev+bncBCU73AEHRQBBBPFKYWJQMGQEDNNXJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B0E51897D
	for <lists+kasan-dev@lfdr.de>; Tue,  3 May 2022 18:15:57 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-ec4e7a087esf2783691fac.15
        for <lists+kasan-dev@lfdr.de>; Tue, 03 May 2022 09:15:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651594556; cv=pass;
        d=google.com; s=arc-20160816;
        b=sje6ApeVcbr42klR4MtBto/LHMez9FeisYH/JwaL+5pRK6nwTUjTbc7qPfkPW8tN4n
         5WrrqG9DMo5Azy1qEEuWawmXTzd4OsPxmPAFe8vH2pOyiIWVRmaH9OZRVAJ4WFYvso+4
         D18OVlpAoouCh6+Icr5+RKXXmnT+2/xWItBqmT0sQ3KYhy4U9gk9WCt16EXTp2GU0u4s
         Sh6J4RXzEV6mHY6uLkyB7oY9Bbbmvcyn15Km65xyZEcYCk0hm5GNKA8qcNBiuBcZKO6M
         SkFW6vetz05reMnZFPJPgWBXz3AUngoCS71G/i8qitWHJzlga1HiE7MPyp+UY8/XSocY
         k3lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=vWujMvI0QzMWkQ/qsInmT/V9IYHRo/DtTqxdFyz4UN8=;
        b=pY7tCzdksjlbL0D9bWhJLAmiEtQ/24YLEOAwuQ7ExFPrR55eZ+1rN2Lmo8um47Pbl0
         TcQwmbIpqVUXoUIvYXx0oxaZaZz9J7Bx1O3SMgQgeSVB1JjAtgPcP5yknHXXjQHOHJaN
         e1HTWeCbfvD4E/1Eg7snKlfoT9wJoQWCxC4t1Jl91E/bOo05V+5FtlXB7HvusXpqDStx
         kslGPkZWIlg3/iAKexvaeTCy88tivjZdGzI4Eqb/L39+5fsjplH8K8M+ewgUixGjOopm
         qY/6w8GGuITbvemrHtABpAZyBMcRkTg1TP4UKUI+0dTOq5iepos+9QV2nwZlplE1nEED
         FNNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7baa=vl=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=7baa=VL=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vWujMvI0QzMWkQ/qsInmT/V9IYHRo/DtTqxdFyz4UN8=;
        b=HkIQ5JvIdrAFrz7mxCVXUFyRZk/ZrkThaj8AThOM9uKO5LRMmdEBS/rjkNAPSxFUdC
         FiON2lo8LKhNXpU3uBD4lWBPcus15T269Yu/tBsqu2BMUb2QJeXDL++IJGtmaHQhfVpk
         N3PTKeuEjywWaw2cl1Xv5glhrp2kR95i1S0XELJezkc0PJfPbdZIXwGm/lHYphmXkRMv
         yJ6bMm2dWbBb84ZCPw9T5NN5Or4FiYfa6FhXxRTPfCIR3s8LUHyaLUUReL0B2ONbXScV
         H/Y0q5SDvggEEVDe3CDtmwFukRF3FvSZcht1JscJ99o4jksqJyOgjr7kwV5OzLs0wFgi
         3n1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vWujMvI0QzMWkQ/qsInmT/V9IYHRo/DtTqxdFyz4UN8=;
        b=ORbY3ku27P5eLrpSo7cz4TbY15ch/i4IxcBQSRceSa0UvKIpzwapPiUL55rXPYYE+y
         Wh+6Bz81zQT8fdlVyZ2d4OfwpmC0Y0eBWO3N5fSokqaZhsaHJ8kYrbI4R2HElsD+NqkV
         /xshSfZMVGFzDemzhKGbEi1MAN0nQ9S2dv2oX/WpshuDGjMNDiE0AVCKXhAolo5Ediba
         eVfqo8gQigbRPuWcMbbxYI652Z5DwJdFo1sz551u9UvjtdJyFqE7T76vDNn1GQXxMr7s
         6xiFQiIlTjhuMhufMmXnKaV4UZgo8dyr7okguZmqVkGnpnbtF8pFOd5KbyKbE28Pd8+h
         Y6nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TZ75wbrMwq++FdblyyJWZD4OwHIVnT3bmnUNgqTptC76zSP2Q
	rh4ReevAnro4vcApXTRLXXg=
X-Google-Smtp-Source: ABdhPJyDBaPvAQd9S5T9dZyqaMUob738NeUhc5Is+zVzU2nKwyJ/4aGPUtdS76nn3aVcMPfM7CdeHQ==
X-Received: by 2002:a05:6820:1007:b0:35e:a77a:e712 with SMTP id v7-20020a056820100700b0035ea77ae712mr5920304oor.64.1651594556563;
        Tue, 03 May 2022 09:15:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:23ca:b0:322:ac8e:f9e9 with SMTP id
 bq10-20020a05680823ca00b00322ac8ef9e9ls6273607oib.4.gmail; Tue, 03 May 2022
 09:15:56 -0700 (PDT)
X-Received: by 2002:a05:6808:e83:b0:322:3344:13c with SMTP id k3-20020a0568080e8300b003223344013cmr2047676oil.233.1651594556162;
        Tue, 03 May 2022 09:15:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651594556; cv=none;
        d=google.com; s=arc-20160816;
        b=ECZkIa7ul0G/76jGqvVYJ4H/m54q1TbhB7G1AGonZf7X49qT5hv4I5BtDa+f5KwKdm
         nBvWFr7OKpulPwzHiMUild+jUzFebjzGX3KrjguygGK6+rBB/fvoUb6QW7TFzwHpIbSk
         cZiCOEbnDG3svseV5lW8LyYC7BM5OphgAAx7LD31emXmQ3IDcojL5/5eZkrzVnRS2STJ
         9a5v/1zfs1cLe4mlfpj6xpfNu9F3OlrTNqpDqxg59BoOpUKPNltKiaoO7EOX3pkx58U9
         dnSUZWGVuUGnPmsYZQAA86noXtYDHwBw44Hp0UGadlWXMfe/VinkzRCTjLICxrKMxsRA
         /aNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=PtR1/KtWsE2Cra2c/Yxwm5nYtDs/1oAH766pn49Vpys=;
        b=LepVf0duVFCozexoI4opnfwUKdW2cm2ahTa9prvL5cihRg8UwRx2YKSa0qrU464dHo
         0wjVezbgvRwLiBBP6HvKh9Ikqil64o+LxCQRlf8nd0MZUxr+RfopnjqVLHbQD4QBrPPI
         rtw5tvPdgS5QxbFTsOOSNF7GFC3Uz90Q4KDlBmzFbCN4o9Qrh7DQHPXnKBu8CvbJUXhB
         rNo9qgtj2i5Bxz2AcAWII9Snr9kJqr/AndXBpmZV7NEgwzkeeagTq/DMcCGkkVgHYQZA
         E8baxjXMHgUbyUGjQ2uORT9ddCkEJWWu4KmebuZGbKj/aaNbTM3Qlcc+k52GGMuGrsZi
         s9jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7baa=vl=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=7baa=VL=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id eg4-20020a056870988400b000ddac42441esi1960324oab.0.2022.05.03.09.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 May 2022 09:15:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=7baa=vl=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CB563616C8;
	Tue,  3 May 2022 16:15:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7AB23C385A4;
	Tue,  3 May 2022 16:15:54 +0000 (UTC)
Date: Tue, 3 May 2022 12:15:46 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: John Ogness <john.ogness@linutronix.de>, Petr Mladek <pmladek@suse.com>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, Thomas Gleixner
 <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Naresh
 Kamboju <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220503121546.614ad6a8@rorschach.local.home>
In-Reply-To: <20220503073844.4148944-1-elver@google.com>
References: <20220503073844.4148944-1-elver@google.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=7baa=vl=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=7baa=VL=goodmis.org=rostedt@kernel.org"
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

On Tue,  3 May 2022 09:38:44 +0200
Marco Elver <elver@google.com> wrote:

> The original intent of the 'console' tracepoint per 95100358491a
> ("printk/tracing: Add console output tracing") had been to "[...] record
> any printk messages into the trace, regardless of the current console
> loglevel. This can help correlate (existing) printk debugging with other
> tracing."
> 
> Petr points out [1] that calling trace_console_rcuidle() in
> call_console_driver() had been the wrong thing for a while, because
> "printk() always used console_trylock() and the message was flushed to
> the console only when the trylock succeeded. And it was always deferred
> in NMI or when printed via printk_deferred()."
> 
> With 09c5ba0aa2fc ("printk: add kthread console printers"), things only
> got worse, and calls to call_console_driver() no longer happen with
> typical printk() calls but always appear deferred [2].
> 
> As such, the tracepoint can no longer serve its purpose to clearly
> correlate printk() calls and other tracing, as well as breaks usecases
> that expect every printk() call to result in a callback of the console
> tracepoint. Notably, the KFENCE and KCSAN test suites, which want to
> capture console output and assume a printk() immediately gives us a
> callback to the console tracepoint.
> 
> Fix the console tracepoint by moving it into printk_sprint() [3].
> 
> One notable difference is that by moving tracing into printk_sprint(),
> the 'text' will no longer include the "header" (loglevel and timestamp),
> but only the raw message. Arguably this is less of a problem now that
> the console tracepoint happens on the printk() call and isn't delayed.
> 

I'm OK with this change, but I don't know everyone that uses the trace
printk feature. I am worried that this could cause regressions in
people's workloads.

I'd like to hear more feedback from others, but for me:

Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>

-- Steve


> Link: https://lore.kernel.org/all/Ym+WqKStCg%2FEHfh3@alley/ [1]
> Link: https://lore.kernel.org/all/CA+G9fYu2kS0wR4WqMRsj2rePKV9XLgOU1PiXnMvpT+Z=c2ucHA@mail.gmail.com/ [2]
> Link: https://lore.kernel.org/all/87fslup9dx.fsf@jogness.linutronix.de/ [3]
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: John Ogness <john.ogness@linutronix.de>
> Cc: Petr Mladek <pmladek@suse.com>
> ---
>  kernel/printk/printk.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
> index f66d6e72a642..a3e1035929b0 100644
> --- a/kernel/printk/printk.c
> +++ b/kernel/printk/printk.c
> @@ -2064,8 +2064,6 @@ static void call_console_driver(struct console *con, const char *text, size_t le
>  {
>  	size_t dropped_len;
>  
> -	trace_console_rcuidle(text, len);
> -
>  	if (con->dropped && dropped_text) {
>  		dropped_len = snprintf(dropped_text, DROPPED_TEXT_MAX,
>  				       "** %lu printk messages dropped **\n",
> @@ -2240,6 +2238,8 @@ static u16 printk_sprint(char *text, u16 size, int facility,
>  		}
>  	}
>  
> +	trace_console_rcuidle(text, text_len);
> +
>  	return text_len;
>  }
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220503121546.614ad6a8%40rorschach.local.home.
