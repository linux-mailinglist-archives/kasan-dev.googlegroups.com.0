Return-Path: <kasan-dev+bncBCU73AEHRQBBBHMDY2LAMGQEKTN3LNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C0E576402
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 17:02:55 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id f13-20020a056a001acd00b0052ab9ae76fbsf2749906pfv.20
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:02:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657897373; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8XAOdI0URF+Y6sq/HXUaJUqaLDjO3U0W60f8Je3KBxnBb1xXO1Aat57gW4P3fQpOq
         uUTMPHi6M2BStqHLVOyzc4ZTpCfJV+qI15Xqcr/WMACGIcBklgss4VeUHps1fhYBs4Q0
         0n5hvplEj9esw65T2wkdi3ZEkOaVscaQln0QyQLIyTpx/O+H1m/OU6BrBIZNlF/Y7808
         6tKq7+Dakec+1Ami6atGJ6alexs0+gG1x6Zj3A4IERUFssZk6+qfI0PP0bZznqMeorlI
         zlsaX0k1PspCe+LeWNazDVc/n9zJyylWxRk2Yz7oFmroZRUaq+p0Mhbm/UOTUGrn4cRE
         n7Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wJpdvzX3R9QdMYjQXWG9zDwP5oto9P0MeSMrHbvgrFk=;
        b=1GHaJvqaWHveRUsxLkA+9xatk4He8cjdoHT+lW9YKGgIfmy5+deKK2x8z9IBNy7ziU
         DKl6klIaoIqOX6HHx9GAlVtm7IwiFIaw8uM0O2oXNX+GE9YisKXPJ66B/aNNKchtUa2r
         dItQCZ1jsou+2VpO8r8lZ/HdqeOme1jLn5TRoz2+7oJNNfxOnkKJ/kKPBXIWSVjKWDos
         dN3zuzNwpK12aAgpW5z17+V5lwSlIoWKK/jXWHM3Jx4ITNmacKN6q6hg2ViF60UV5m2B
         naCuw7WY2XHcAfN015LkJpO5cUtMHQb4zaDN/9b6RzkEPRtH9CRYGGZg2n9coK6CmfA9
         eNzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJpdvzX3R9QdMYjQXWG9zDwP5oto9P0MeSMrHbvgrFk=;
        b=Xar7oypgddwqFTSib5td684AMQkBfKwnrTPuzoWYfC1UxWxoN46wKzCXZBJxsgPBtb
         fnivH9NKVnPXCyVPkoGC0u4pRaoIFcsDRPiU9+215tAp6S59Aoctj0AEtNXmtnwEXogW
         0hNTWFkQFbkx0yxF0Q0fqi99RvzaNdyCYswRCmQ3uv6AHTOjkzZ4J0WnWHJ9uBlcPp5s
         YDLaYq9BFzrkSt/QUgK6o+GeEBA82SrWTB14avtpZQNqtsmOrBfhz4NbBcqY54hKV6P/
         tpqtjQjO+NtSs8HPI3Jf5NIaQjYcDGujQpuUCmVKAThvn4SrgwaTfZOmSVFD2B7SVZsZ
         0wAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJpdvzX3R9QdMYjQXWG9zDwP5oto9P0MeSMrHbvgrFk=;
        b=ylgl2r9dpv3Xtyn9iLTbBjhH/7TYWkSxG5Yd9/7p0l+bItmofV4FuSllEr5jaKV+pQ
         /8MNVQwRyXfgdy0qEZV0ZJ6ZTKMC0Udm0mpNtJKHwdwnRcXpfcu2EwLu/hrS++tK8AsW
         7Ktic3FapUJ3K0SMrhLtEFZ4yVkdBG/6FHsYgZNRPvCwBZuwH11cFt3mIDNMgSybAjqF
         DrN3/0qt4wNtdFC2YDLIA+FbSLWMFL5GgctdBH5UCZq6DkrvvU0gWaqkYMFlCPHG9kRt
         MlrAO4UInMsSenXbcPY0S8FywHvrToC/0ae7Uq5n/NZxReMDIm2QbttUR8jeJ5+YtLj5
         XeIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+feYauNXS1TIh0wrqpGYGYDZuz7CkjhUmqsAUU4r2qijOS4AmE
	qEQqeVcMX/+RvsJtbx6tGn8=
X-Google-Smtp-Source: AGRyM1snE+oe06uQ9cgJY8DyLCEgLMCxfV7Ynhxm9LI359t1LjBbJrf7rwrEzTN0LwE/weSda+qvzg==
X-Received: by 2002:a63:1c15:0:b0:419:ef13:f1ad with SMTP id c21-20020a631c15000000b00419ef13f1admr1411028pgc.243.1657897373709;
        Fri, 15 Jul 2022 08:02:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b010:b0:1ef:7a6c:c19d with SMTP id
 x16-20020a17090ab01000b001ef7a6cc19dls390297pjq.2.-pod-control-gmail; Fri, 15
 Jul 2022 08:02:53 -0700 (PDT)
X-Received: by 2002:a17:90b:2243:b0:1f0:b0a:e40c with SMTP id hk3-20020a17090b224300b001f00b0ae40cmr23082443pjb.76.1657897372989;
        Fri, 15 Jul 2022 08:02:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657897372; cv=none;
        d=google.com; s=arc-20160816;
        b=yFheOs37+McQansOA7XbzeWoXIsnX0QUFQcWHJXJYW/e1Og0ZGSR2kwsHLfHtkKzI+
         DRV7XNe9Pa5zIlQwuOCHHI5w3b+Sa5QmEISKkYg3E0q3YQOU0lvCkEsCnpNkn8aKZNNT
         pP0SleF/ytvvaA2TbZzh+tc9HR2o+tBdpkhEty8d0Nw7uNBvaqxN28su44ndYiaVSfrT
         DN72ehzrnT3ck5Dc9SVnvOMSlIR7pfOddKJfSmfjNOWZYubbvV8GEgSiMWkbjBfH3GAK
         jCbST/SenUOtvrSoplScTHCCMH78ka0V4HAsgK8+75xzSurWQeOTECYb1nut+UsZVWMf
         W5Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=/t5pGVbZUr3IFvqBc72I2/tMZAo2BjVlpArbSE2296s=;
        b=rFa4ps3BNT3gvue3A5Nus4xG0/EZrghLQO4L38STTfRZmbKP3AN/qG+chkGzRvMde9
         0BHV4sK7veLFWJuwCU3ls8XbID0kg9qLH8IcwGerD1XKWH90pnmp0oNskFLVeSRF/DDS
         9uEKVFHyrsKLGhVSiW4jOYsgCccvZZGruZ8JU14kGfnzBB/RiW6C4ws6uwaCPmjwVCWc
         5KUh9o+F4xwqnd2PDdysdpUbaBa4YftyDR9A7UietzIZRNiCh1cAS4YtVCPduFFbNdXY
         vGQhI0FgBdVeE3HR7adYwksCZkmV6lAn5WErsxSru6PnhzQ61fNx40ws3I2YJUeXswyO
         96Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k204-20020a6284d5000000b0052ab8d76afdsi149926pfd.1.2022.07.15.08.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 08:02:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4980761F95;
	Fri, 15 Jul 2022 15:02:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 35024C34115;
	Fri, 15 Jul 2022 15:02:50 +0000 (UTC)
Date: Fri, 15 Jul 2022 11:02:48 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Petr Mladek <pmladek@suse.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>, John Ogness
 <john.ogness@linutronix.de>, Sergey Senozhatsky <senozhatsky@chromium.org>,
 Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, Thomas Gleixner
 <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Naresh
 Kamboju <naresh.kamboju@linaro.org>, Peter Zijlstra <peterz@infradead.org>,
 Linux Kernel Functional Testing <lkft@linaro.org>,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220715110248.02b294b7@gandalf.local.home>
In-Reply-To: <20220715120152.17760-1-pmladek@suse.com>
References: <20220715120152.17760-1-pmladek@suse.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
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

On Fri, 15 Jul 2022 14:01:52 +0200
Petr Mladek <pmladek@suse.com> wrote:

> +	/*
> +	 * trace_console_rcuidle() is not working in NMI. printk()
> +	 * is used more often in NMI than in rcuidle context.
> +	 * Choose the less evil solution here.
> +	 *
> +	 * raw_smp_processor_id() is reliable in rcuidle context.
> +	 */
> +	TP_CONDITION(!rcu_is_idle_cpu(raw_smp_processor_id())),
> +

As Marco mentioned in the other thread, would a check for
'rcu_is_watching()' be better?

-- Steve


>  	TP_STRUCT__entry(
>  		__dynamic_array(char, msg, len + 1)
>  	),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715110248.02b294b7%40gandalf.local.home.
