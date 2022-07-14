Return-Path: <kasan-dev+bncBCU73AEHRQBBBIXHYCLAMGQEMTMGXUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D6AC857518F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 17:17:55 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id i13-20020adfaacd000000b0021d96b4da5esf628328wrc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 08:17:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657811875; cv=pass;
        d=google.com; s=arc-20160816;
        b=mw9NmRQBMt7vYdHEIYZSMVdEpn1puU9wwHB/9vPn5ejepiGL56IYptnlXmY+JcWkAy
         weM24NthMETL6zg4IN0SaWMls7mLic9lb/EkiH6vDFCktKHL/lVEaoBeiG4Q17a8n7uH
         G0atxfgJk3jn2v335XtU50s49BnPLsPpqXzr/Tnbemq+BCwMtP0xd4owNosq2K/ykIVE
         hVpN4Ipcv2i6jVcEw/qrI2PFy7uozCFtSjy/NpV0k5lAx8g5WbyNNomtQeCp/y8md+Q3
         HaYpEKWH4W+kJK97gcy8Pa2VSePwj8ub5QYovfXbz5+j9tkdslXqudvw4Lzp0nt1DyHE
         nN6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TRMqVJIbopnE5yLHDzqXutdCi5FxeZYJBmaP2SQtdDQ=;
        b=mxySSsd55f4lu6JICEOP5Dj6A8y05CSq8S1QuFOu6Klu7eVmubdOuQ/9sE0y+LUxGE
         ICp/bjrScafNEr9yHhS5m5X4UJuGb51spRmcQpslQB8YJKR8WkN3UXIpiZatczOx4s/D
         RNFoYjYEPuxplj7YXrcXbQ+LYCKCWcBlst81BPgbEDhBonVDfwOFE2JsAtcqvd1ofXl+
         VWxws3hIopWyU5leIyYJ6/FdSxHnNfwm3Y9ps79ccLCpP5I/7YTP4It9SvqA2pWcBE/L
         buTrI3qc/phtEI6zLwO0a2dPHF0C99J+akgHYLdjyBmthvIUv9T7FYK+dU0JpQ8JGFQD
         AK7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=9/gf=xt=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=9/gF=XT=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRMqVJIbopnE5yLHDzqXutdCi5FxeZYJBmaP2SQtdDQ=;
        b=BFFfMH6AX9qdiSiDJaPWGEa8gJQ9No5yosD0mWUVOpEPAa7TbH9Ut3QHoPzN9PSM9l
         Rwa1rurdYT0sttITBz2u/RkULT5GIaad+/cDM1mScOvMqGRMmvlOKgJP6Skb2YyrK7xb
         MdJLiqVKrxMBOTGB9NXFJ7BXnd6vFL5/oeM83ZFn1H3xvsazxmd1l2uUdfzaU2WNqNyS
         GYeFw2JuZAjcp66LulrBWOYGvvuRJNggE+0hkb4QQLge1RyzrNIPQG3RhXWPg51XBU8Q
         EgzsoWuIeOxhLDzcAXEDrTJIdMHz0/dw2hpF/D64xknqk0iWzFBeI0IsEYZxNR6Fvebf
         1eGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRMqVJIbopnE5yLHDzqXutdCi5FxeZYJBmaP2SQtdDQ=;
        b=CWkFxXQGRZ/UzxWraiYG8b2Dv1uHSWMydRXjn1hewVsQySReWOXqeQ2s3cM2G6uSZQ
         paWMfXRMRFJx7OyUj8R2cZHsHpBKN+Thx9aokzb0tGxTI9V37RsXWRMQBSCqRpiPNKul
         IobQ53A1nTiRi2pW238KYUKYWM2f95EglgT+VtNb2yprcgFiPERJiYSFR+9M6gP0T5QD
         U9RC0y0SwlHxqnKFmUg+nMx2wBmD8CyI/mw7y2SivBR2uMmBWYlx1s5Yilj3R2Pz2yA6
         ty4PlS4QCVqJimpaLSMzFvBmd0DCx7BKWb+H/r51JJ+llVuS+lgh743GItTXePZvbNFY
         1Prw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora94FEfEVVzDJuCOHHBNmnFEL3hMRKKvi3DpxJevGRpdEZl/jfya
	DUuS6Gnv4UjvbT2GrIKmqe4=
X-Google-Smtp-Source: AGRyM1umgsESFiK4lb7JVpKhnDD3bMDCakTdr1mT9U5B+LhdQtlZY1ustt3in+1PtXTzwey406aJPA==
X-Received: by 2002:a5d:5263:0:b0:21d:7de7:956a with SMTP id l3-20020a5d5263000000b0021d7de7956amr9017180wrc.350.1657811875188;
        Thu, 14 Jul 2022 08:17:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:500f:b0:3a3:159:4356 with SMTP id
 n15-20020a05600c500f00b003a301594356ls1071445wmr.3.canary-gmail; Thu, 14 Jul
 2022 08:17:54 -0700 (PDT)
X-Received: by 2002:a05:600c:348d:b0:3a2:d019:2366 with SMTP id a13-20020a05600c348d00b003a2d0192366mr15818333wmq.187.1657811874169;
        Thu, 14 Jul 2022 08:17:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657811874; cv=none;
        d=google.com; s=arc-20160816;
        b=vydIKgHrTXXO7eFUTfQYm7FtWPBZI0RqX9DJwbABQep9aZ79QddH/LGrrr2qkItl0G
         sOm5OUHDibWz0dSjYbDdBp1NI45DGB3yWogRsIkerPyn8i0qCdmQKCJ+O5AZS9/D+TaT
         VzJkZVtOLDr6KCSNBFlTaOwTs7/1124/4h6AyZTe+KXaoDp8Y3aNLhLMhjsen5oidNT3
         oTlJtBkHD3QRJzXbCKAqP2Uyl6WQKynobbqXhLvAFEBCFK7m7vKPxQE8m86U9FwwZkvF
         3sm/Ke70lm1ti/9ZeEyzCRf560e+N0F4Q67WTgYw1P3SA4+feaxzBD+j19TkTRhGn4kL
         6Pmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=omgayQExAWyqmoG9Ksvc4hYpTaQCuRuJflsgnkJLwfE=;
        b=cQQCU47Plu2b3QeXqzGK5x5N8ibURj8Gle2wwRiatNki1lBDDo7ngtVmG6w8atmpkI
         PhEjySXhQMzdiF5REzrc1+YMMBHMQF0Bsh9+VDbyDkfgnTx/GodPBZgTPeIKpBKeM1Go
         tXsQ97iqqfzrkGCY9OwBI4fNbf/hseWBCTDv44ghCbRNWzkNmamyEBgLxJp/GiNEVylZ
         07Y77m8zmefBh2JabUHbmfohjz4vptHS84XL+4jCbTkjuhp+ROwyi0ACm57XkQhbcdPC
         fcdeo8tiYrxLet5mzNLa92AmHf6eVOnz9U9CVdAuyfLQ8n/vPZADotaIyd2l6JOP8EKT
         94/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=9/gf=xt=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=9/gF=XT=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id p184-20020a1c29c1000000b0039c4d96e9efsi334402wmp.1.2022.07.14.08.17.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Jul 2022 08:17:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=9/gf=xt=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B92A1B82158;
	Thu, 14 Jul 2022 15:17:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DE566C34114;
	Thu, 14 Jul 2022 15:17:50 +0000 (UTC)
Date: Thu, 14 Jul 2022 11:17:49 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Petr Mladek <pmladek@suse.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
 John Ogness <john.ogness@linutronix.de>, Sergey Senozhatsky
 <senozhatsky@chromium.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, Johannes
 Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220714111749.0a802e7f@gandalf.local.home>
In-Reply-To: <20220714145324.GA24338@pathway.suse.cz>
References: <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220711205319.1aa0d875@gandalf.local.home>
	<20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
	<20220712093940.45012e47@gandalf.local.home>
	<20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220712105353.08358450@gandalf.local.home>
	<20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220713112541.GB2737@pathway.suse.cz>
	<20220713140550.GK1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220714145324.GA24338@pathway.suse.cz>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=9/gf=xt=goodmis.org=rostedt@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=9/gF=XT=goodmis.org=rostedt@kernel.org"
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

On Thu, 14 Jul 2022 16:53:24 +0200
Petr Mladek <pmladek@suse.com> wrote:

> --- a/kernel/printk/printk.c
> +++ b/kernel/printk/printk.c
> @@ -2108,7 +2108,15 @@ static u16 printk_sprint(char *text, u16 size, int facility,
>  		}
>  	}
>  
> -	trace_console_rcuidle(text, text_len);
> +	/*
> +	 * trace_console_idle() is not working in NMI. printk()
> +	 * is used more often in NMI than in rcuidle context.
> +	 * Choose the less evil solution here.
> +	 *
> +	 * smp_processor_id() is reliable in rcuidle context.
> +	 */
> +	if (!rcu_is_idle_cpu(smp_processor_id()))
> +		trace_console(text, text_len);
>  
>  	return text_len;
>  }
> -- 

Although printk is not really a fast path, you could do this and avoid the
check when the trace event is not active:

(Not even compiled tested)

Tweaked the comment, and used raw_smp_processor_id() as I'm not sure we are
in a preempt disabled context, and we don't care if we are not.

-- Steve

diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
index 13d405b2fd8b..d0a5f63920bb 100644
--- a/include/trace/events/printk.h
+++ b/include/trace/events/printk.h
@@ -7,11 +7,20 @@
 
 #include <linux/tracepoint.h>
 
-TRACE_EVENT(console,
+TRACE_EVENT_CONDITION(console,
 	TP_PROTO(const char *text, size_t len),
 
 	TP_ARGS(text, len),
 
+	/*
+	 * trace_console_rcuidle() is not working in NMI. printk()
+	 * is used more often in NMI than in rcuidle context.
+	 * Choose the less evil solution here.
+	 *
+	 * raw_smp_processor_id() is reliable in rcuidle context.
+	 */
+	TP_CONDITION(!rcu_is_idle_cpu(raw_smp_processor_id())),
+
 	TP_STRUCT__entry(
 		__dynamic_array(char, msg, len + 1)
 	),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220714111749.0a802e7f%40gandalf.local.home.
