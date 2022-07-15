Return-Path: <kasan-dev+bncBCU73AEHRQBBBAPCYWLAMGQEE33RMCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8018B576319
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 15:52:03 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id x16-20020a17090ab01000b001f06332d7cfsf5313659pjq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 06:52:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657893122; cv=pass;
        d=google.com; s=arc-20160816;
        b=qe92rsGeN8KSjEudjWFm6QJzEvFtoGKOoueCLSeY5eSevY6lx39xXOg2GBxoHP3QPd
         TxNOO3o+/yibmrnoTJY6c7AWyysfTCK4YC+i6jpTlH7blu9JNLCsL/RJHIpGsHXlw3M4
         2noLry3WmOLdYDHJ3xM2Eh2Ry5hlnc3HxNhIAzCw0mdRWz5wZFb6vJ4Q6Zs6IRZ+8lME
         dgDJxCSj+SXRFaAsr+rT/lTSFmNTm6zKuq0DA1ciQMeEQexFnj8QTXs+cDNzyuYsqlsI
         rzgS3YAy9i7Jd79E14Ob4tLNBDTHWDCX4nbi9POBmpRAuQ+/nVIfeCBag3X1WHoBpBu/
         PxKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1ogn2kAS0Z32j3NAjzExTgj/+FdcuVnGcRBnuldmqKg=;
        b=R+sStRsKyL3woyJMWJhjkmfkvz+yYCmgiB5mhPmNBYXS7sbdzhbfmIykdAyS5jKbiI
         3zr2COsyJ8P1+VH6/tmJNWHxlnmXt+Pj348cSn2ya4KkNHwmXLt5uqvu6MF64Xk4ptR/
         vge7vFpe2maFWOr0KsgVS+xYLYA85kWvIpBhNxcuUPpUQVwhawit23q+uRUF6rQytNlB
         iH15OsFBTc65uC/kC042yYCxlZCTH0RAaWrnEbfmZZiIOWUj/TnGXYXiYTrGSt4jFzfG
         X3uUlE151Rp55fFhN/9c+mdB4JFFMMMtaoC9i5HSFs0f69Gv1Jc8wPQVg24TaIezcdN3
         wnrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ogn2kAS0Z32j3NAjzExTgj/+FdcuVnGcRBnuldmqKg=;
        b=oSRuGtDvKk4qcnQ10seB6pTwUyrf7kjF7598T+bbByMIazR2k/CIAknhpoVfNipOit
         47rFSRb6G7drMawnf5ionviCkhFOvzA23B2Kzx8stk+38QfZMGXs1jtPIVkPQav/KchM
         j6GUOmA+7rmHycRsilP+XcJcl7GJpcAWK806r49vO1sidVUd92A4iwVllSk98kMjQfPq
         tN8+n1OEBtcVUjNGwpUSbBMkZN4J9+HgMWjRvXcaGtPwXgh0UrmfWVTW8Ote2TpR0ol/
         nRfZY7t35TQR6rFpa9C3IA2XY65jEbo7INLCqjfVXhxQUQ5qnyukt45f6+1CmzKHcH3u
         EQ4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ogn2kAS0Z32j3NAjzExTgj/+FdcuVnGcRBnuldmqKg=;
        b=HPPYN1Xulz6S1apW7vLN5mweFaY7cjp5MJYEqdxFnyR+nxmmK/L+ZjwrM8hVTsslzu
         tDFTN2H1XnBEEAw+nFn+pjXAueURR0zy493Ssyi18BdPeUmU6tvUPibYO7rVzHq3B8YU
         XhMVTLSdA/+eRpNjpRMzmJS+ssasDI7B51pJFUY0GUEtxB5K4KhOubNEXC28A449msBA
         xgDlFxfypMBPx5Xj/c6Dg5XFEnlPlmEInO96LoPSw4RPL7dNmhluwn9At7tXGTDYfjFk
         t0GK+mzQwXuEPBPsthinriMUdGZ5XBHj9+jo08miYQ4z6UOMihdTZ/PywY8k68V9sy5g
         6opA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8wEAdeO327DLNpkfn6iV0D3V86HQbVSViQqSnUmYGNrzGUdEdD
	HiM9uR71mlyNp9LmtxApuxk=
X-Google-Smtp-Source: AGRyM1smHSunhn8R/L+5x7d5aNpcDcc3khrM3HrXvPdapFEDSRiShoAhZ+giFKDQtJWGuRSIRlSZ6g==
X-Received: by 2002:a65:41ca:0:b0:408:aa25:5026 with SMTP id b10-20020a6541ca000000b00408aa255026mr12962708pgq.96.1657893121919;
        Fri, 15 Jul 2022 06:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1a45:b0:528:9c55:f866 with SMTP id
 h5-20020a056a001a4500b005289c55f866ls6062638pfv.4.gmail; Fri, 15 Jul 2022
 06:52:01 -0700 (PDT)
X-Received: by 2002:a05:6a00:150e:b0:52a:ee55:4806 with SMTP id q14-20020a056a00150e00b0052aee554806mr13935149pfu.37.1657893121296;
        Fri, 15 Jul 2022 06:52:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657893121; cv=none;
        d=google.com; s=arc-20160816;
        b=B7TGgb5Bl9+/unCcTiMqgRwZyyw4P/LvjLRAoWTTFRgWZ6rn9WDUQI5SBhh81C3dY2
         RTntYskZBUOQcNyMWhJsgmmEcr4XFV59PGvktpvjCoZ9MDtTYrE0VIraFzwI2hKF8Rhi
         vW3ZDtff49ji0Enp6aJQ71PCMNLhE5lyLA2IaxSFghK8KTCL+iwjHw5738WKAANH8YvO
         tzeaqEnSqqffLdG+0QIvCpxCyuIOLHw5t+BUhMkJ07sSuZ7QuG7r/OWeMa+ntP47mz0p
         +q7Hi+60BZALCW9pC7Dkcz3CBwnlahlxKOmU95C3Wj7aUwNyHQM2lZhWN7GEbnDAmzL/
         h3yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=DwBoro6ohEaudedDerNKNJIZfhYlTPgtZTy7JVOygyo=;
        b=idSz352hbxTiUdiCqQ6dDfD77OJqf+ip2rvMWtuIVUDdAF9/CwohK3oA9MiPoSII3o
         Sw8LMFy2DWIvczcw8iCZvTRE5uNIpbbiL9ROiaMYwytcrZPwBWitOK3r6wpYsspyRh7m
         lcjWe5sCc4rZwhPRTrrBuDqU9dw85wVPwBRwwPaBrWTdlgW40OlyJPFnZEL9CSNf50Ck
         yn3oLECfNMhNc7VfUtFtm6i8McT0Hxnvc5hXQnukmZfpWEI3+/SN7YBmkGaJ978RqR3T
         zOOSSFHlRUR/vOBuHpXc7922kBwamE3MtZV8MLF7kdgW4UQoiZa/zVY+fDqmYspcG/cz
         X9bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h17-20020a633851000000b0040dbc21c6a9si184760pgn.3.2022.07.15.06.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 06:52:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 963C1623F6;
	Fri, 15 Jul 2022 13:52:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7F7C6C34115;
	Fri, 15 Jul 2022 13:51:58 +0000 (UTC)
Date: Fri, 15 Jul 2022 09:51:56 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Petr Mladek <pmladek@suse.com>, "Paul E . McKenney"
 <paulmck@kernel.org>, John Ogness <john.ogness@linutronix.de>, Sergey
 Senozhatsky <senozhatsky@chromium.org>, kasan-dev@googlegroups.com, Thomas
 Gleixner <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Naresh Kamboju <naresh.kamboju@linaro.org>, Peter
 Zijlstra <peterz@infradead.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220715095156.12a3a0e3@gandalf.local.home>
In-Reply-To: <CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
References: <20220715120152.17760-1-pmladek@suse.com>
	<CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
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

On Fri, 15 Jul 2022 14:39:52 +0200
Marco Elver <elver@google.com> wrote:

> Couldn't this just use rcu_is_watching()?
> 
>   | * rcu_is_watching - see if RCU thinks that the current CPU is not idle

Maybe, but I was thinking that Petr had a way to hit the issue that we
worry about. But since the non _rcuide() call requires rcu watching,
prehaps that is better to use.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715095156.12a3a0e3%40gandalf.local.home.
