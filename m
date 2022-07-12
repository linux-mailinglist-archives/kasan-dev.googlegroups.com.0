Return-Path: <kasan-dev+bncBCU73AEHRQBBBA4MWOLAMGQEC5CPBOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id EC00C570F1B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 02:53:25 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id u3-20020a17090341c300b0016c3c083636sf3790276ple.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 17:53:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657587204; cv=pass;
        d=google.com; s=arc-20160816;
        b=PLxFbkClv+CDXjD0N6Ley3GGxieiAg8JJkckU0rvRhvrZpY3g7Oh3FTPH0nvN3Q5HW
         9Q4tAUF+i+5W4EXiMjemYLvUAApfMtuMdornzOaBlwTQIzNcjvnJk3/KHKpw4IVaAjpI
         fZGh7e+W7w0+sMpJSIuE68gmA1MP/cQlNwsdE2xsQW3ow3/Jp4hF0yv5GWDGxh1ztyfu
         nb9iqK0BjJ4G+f6wPrJQhpdwhefbT6lcCSvLLZ9dB1+7cV2Hbhbn6ihcFZfyZvy73niJ
         1TtILWbsns7utEeRHO3vJkvW8enLeYneoZXFct127dQEdR/Ea+rPbQL+qmZ1nedPYwS1
         4aXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=traJu7zlJZfi2JgCY8b/osHbMdUtH8IqtY3KVmUPkS8=;
        b=SpLyJFhecZ0iYSUa5ZBVnx9uysQGeF7pG1huXQ2c4BWNIgPWJi8acWZVDslv6eVyf7
         t4xWAdcMS7GEOZoz7FW6dGVZlJz4MrHOWc/XounHoaA4RYMrApbRsWIJ+XABEp9e2dUU
         zxkyo4ppUOmHFQMwBo9h9TwwdPJENLQILtJDs/jn56aD9Ju1AlQGEmGvyzQbVJ8YUsd+
         iBiP6QmmIvz0EJHpjIukwbJfSAUiJHzBpdI54RUnIlanJl9jHIMSPWy9P53yckOMwwbu
         33BMuGKcKtq8zqVBRZ6JQisOM5FjCUcp7x/zCqAskVdmOoL4VNApfzzsogMXxalGzCcM
         iS4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=traJu7zlJZfi2JgCY8b/osHbMdUtH8IqtY3KVmUPkS8=;
        b=cIG/2U3GtrKWQpP3UHsh2NGC/iQGKlz/yzwJLx3RuIG6yIHJgVC76L84tLvs0TWnJ2
         09oQtl1CSGjf8zDYmEKohV2R6wIQXpM2Kcj0BWDhwKpBgIMVvk+kLbg/FKmLP3XVsUQF
         W81nxoZYMQf6InhYinfJv3BVdMTHagSJQsfot0EBLXwBJXGRzFsgFpBWr9qmfPrw/SAi
         7MsbOtYC+A5OJk7vRTtDrJ3h6A1ofYvBeNpDJoBUOSDo4jeihbKwSOIwBIV+qnSSdM/j
         H1L0Hfgsv7CHdlyAfhrWTXiknhbhfz89f1foKRg/NdlFlwbkKMsP/QbkzTdKpxUxEZpI
         BaVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=traJu7zlJZfi2JgCY8b/osHbMdUtH8IqtY3KVmUPkS8=;
        b=upppJd3tAT936fBlNOPccfX+wUiGJq0Zys3Wkw2WspKAsIvBdgQGgoCrNRKto6/NIu
         zfQkqouv0cTPi9gPdm/sQwMMVks70wiGnOHQDny7egKbrEfkS4B0ANMNct9wO5I/G3F2
         JEbCT452h5f9LorZhMK2uBSuXleZP3N1e5j19cqZt/HQFuu8ONIntsY0YoB+vkF0PQrB
         DZsPxblBas7A0d2J4i7X509EH7Ngk7EzUdXZfi+KpBtSZE3Ag7zs3lBXRfem9wC+B0FK
         rEyz2SwViROy4BojbAbaStid5kWTFKx4osn7WwVfRt/mjaGmMCdvd42VXeWryJn2KCJa
         A2qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/QTkTkV2BcPUe13Llks1CsDXFyxL5vkh/+bymMLWGTP6sAV9HR
	q0j31TIFkm57/iBbtmvMiRM=
X-Google-Smtp-Source: AGRyM1uY2Tbvqm4IaKLSFQCSe+lmnVwjdCQNbLx9TfcAeNiG1p+m0jXKpv4eJyjZOEvxusC3Q0ElfA==
X-Received: by 2002:a17:902:e885:b0:16c:49c9:792a with SMTP id w5-20020a170902e88500b0016c49c9792amr8102096plg.11.1657587203995;
        Mon, 11 Jul 2022 17:53:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:187:b0:16c:4f75:727c with SMTP id
 z7-20020a170903018700b0016c4f75727cls580528plg.10.gmail; Mon, 11 Jul 2022
 17:53:23 -0700 (PDT)
X-Received: by 2002:a17:90b:4d86:b0:1ef:8701:1b4c with SMTP id oj6-20020a17090b4d8600b001ef87011b4cmr1254299pjb.10.1657587203248;
        Mon, 11 Jul 2022 17:53:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657587203; cv=none;
        d=google.com; s=arc-20160816;
        b=PFndcLKC67S3F3aynd+0yoqPViBoQ5/Ow3O91ehPhHui10Kre0tN1byvCnMupCm3zZ
         myYNtyip0Ary4cnuZSlL0sBpbBqi0NfsSW+CIe659a7BMLsaFOzfB8Vj/1j3oi4x9zrx
         HbGEOj44b/3yHF+uSRobPF6Q15MnzyQVRC7czfbGDHJe3AaaQc+6gXCiz7DM/L+7zPGA
         43wUMV3RRS2EdDSJYo8V3nf/UV3WzTvLN97+yp7dYmTijkLeN1D7WtJWnKP+nllofLae
         atY6fiiEpekgrFllNrb5NYs9dP7ysMN/oqsPUJB7C/1V02qbUlWMSRrEDv8Z1caqaMgV
         HaGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=kV9iqX2gSHyWXOf1i9VGk3giFrxMPn2tysQ8Tp8BHZU=;
        b=0Z2kTceZGQBJ3sZ/x9Bfqml6Emja7BNIj0DO+kAvDsv/ouyeWpVuvsntXc+PHkCwLE
         UiM07iZTGJ/f7IQQ4Jbq1j5+Hp/wupvBNVkX1lQkY1WnpbK7P5j99PHEE+ky662ExIfw
         /WY7/FoA9CVXcD7IoJ/DjSpPe8D1ZSxvith8xyY8Xs5rCrbjSZgPD5FOch+KB9LLAmGK
         vEkRioM/5khIDSOVroKXlIhsKd3jsdwFQYJUxd2dDGgnzGliOOCLpE57XZZCscaUzKnR
         mxG9wz33wrkfRzmjN+i4ZyZRU4NSAD7AG9gDxAtYqSczvTJhvlrPMGSJL3loWJd6mmoi
         iQvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id kb6-20020a17090ae7c600b001efde4c6699si197129pjb.3.2022.07.11.17.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Jul 2022 17:53:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AC398615F8;
	Tue, 12 Jul 2022 00:53:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AFE8DC34115;
	Tue, 12 Jul 2022 00:53:20 +0000 (UTC)
Date: Mon, 11 Jul 2022 20:53:19 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, John Ogness <john.ogness@linutronix.de>,
 Petr Mladek <pmladek@suse.com>, Sergey Senozhatsky
 <senozhatsky@chromium.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, Johannes
 Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220711205319.1aa0d875@gandalf.local.home>
In-Reply-To: <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
References: <20220503073844.4148944-1-elver@google.com>
	<20220711182918.338f000f@gandalf.local.home>
	<20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
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

On Mon, 11 Jul 2022 17:21:28 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> On x86, both srcu_read_lock() and srcu_read_unlock() should be OK from
> NMI context, give or take their use of lockdep.  Which is why we have
> srcu_read_lock_notrace() and srcu_read_unlock_notrace(), which do not
> use lockdep.  Which __DO_TRACE() does in fact invoke.  Ah, but you have
> this: "WARN_ON_ONCE(rcuidle && in_nmi())".
> 
> Because all the world is not an x86.

But since NMIs are architecture specific, we could change that to:

	WARN_ON_ONCE(!srcu_nmi_safe && rcuidle && in_nmi());

and add a srcu_nmi_safe constant or macro that is 1 on architectures that
srcu is safe in NMI and 0 otherwise.

Or do we care if a tracepoint happens in those architectures where it is
not safe. We could then just do:

	if (!srcu_nmi_safe && rcuidle && in_nmi())
		return;

and just skip tracepoints that are marked rcu_idle and happen within NMI.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220711205319.1aa0d875%40gandalf.local.home.
