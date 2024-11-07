Return-Path: <kasan-dev+bncBCU73AEHRQBBBKOEWO4QMGQECI47JUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B0C29C0A6C
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:52:12 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2e2ed2230fcsf1154851a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:52:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730994731; cv=pass;
        d=google.com; s=arc-20240605;
        b=J9Pnb3ktm6U02GHd1UkYlJX4gJa5mUmsn6AbIqbpwkpsBO0cK6/wbvwjTivCQHuTdV
         nRvkND3S18aMT8gb1q6mfqKzO4YMFG+iusBmf78QG/bJCH9c1S9YoIVuyPsxj+afpR8p
         2A1IsGoDUf3e2DXxU5rC7xAggiDcQ3XVMsEsg6M7bpFqGrAkPu8Sg8ufv1/yvqHNegu5
         Ch9YHV/MargyloW2KnivLDoB71A527vahH66ovKCQj5d/MnFMZMVMVrr6Fz/vbw1+lJc
         Glt9n+qjC6cTU9uqqUW1tWzCxYt2fwptt/Qn5dZUk8tIROABG2Eg/VCzrSTgptXDL2VK
         CjWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TlQ1NF5IIupfwug40pGNrRWqMsHNXkortZ7Gl/+DOOI=;
        fh=Zy3/fcJMFWLwX4YJng72029qGEd29Jnq3ma9pKNkVAA=;
        b=dl+i7E5lq9qwe67MbPWcIDT70cygmpDx4Mr/367Q9RlsGzOUqKRF9P5ercndypO2is
         TqyfiXdaQd8+kfQfn+9E2Yf+lXYz/4XLkhVctGMJccaTbI7hzQxfW61SlY+TuzSVV7jt
         4fKNZJRcfDjeAFX4scLP5ff9HXpKQFmuvi4CTqW8PWqtuoFq5o2kGuM1vYDC5EdJMDh9
         n2cjaUUzw3vKkjzmCphyDIBhNpMX50KMW67ylF03InKpMzZuIzIb4YE4MdNxRTi5FEkY
         /x2e5wPZjae6HIbX1sc9y28Cfr2sdpzoYPO6pZaTk9YAOQAbj+SVwKdg0rGOnlWy5h63
         zEww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730994731; x=1731599531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TlQ1NF5IIupfwug40pGNrRWqMsHNXkortZ7Gl/+DOOI=;
        b=IxHVN4N7OpYFg8Q9wfkkKiMkhR7Lmi0kZ4RbSZxR/tYDc7uMtDenyHFRWRvCeuRZ5C
         RkuXypEHmWjre2267PrxA3Uyw/vy5B276EYcLCCxdik0A3FLDLKR0gGNwiLlryOhyYLc
         /OcJUKyXQPY6rRnend2zXOybzq7dG+Qylcf6WTx1i4/2jP/tLMov9Pv4/uMiEFHu1VaM
         ZAqWj3jQBuYqda0armz6gcMEEfLTKUrl5K0xVCoYk54wuORDPsEx5dRvPhYerR0RV27b
         myjohIn1s+QAKhNL1WYK+OxU2zbTbLyHZXHzakDV1skAY02qf2UOEq3Nc9RYBGgoFkSN
         bdpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730994731; x=1731599531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TlQ1NF5IIupfwug40pGNrRWqMsHNXkortZ7Gl/+DOOI=;
        b=QXtdLEtnqd9uXgNDM9820kqgbwPkLptUiEvLyTchHylawlqPKBi/R0EiCVXQ215P9k
         2ZOaWTpNFwLIqouR/cwbhDWl/0ChvRRjj141IlLIa0hdXCn4WOsColShEjAxw3FGozii
         ZVbDNS3U1S4PyxVR1++SM6erYO9S7z33uufXgnC2w2VdDCN/OxKRaHeKd0WBtdth0dXC
         GOJoYxLIC3hsJb8GJWl2et3o4Tq+7/GwrlUp9xqBerAunDA7mlFvbYAsJta1uTLOCq+h
         XiEdTYC4pWyXdsfxrEMJMg7fSc948H88qEZ0jOsDOjgEX44YjNxQOrmKL7HKvL3KuGVf
         s7oQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUcB92t0vOgSsXvKjCpNgTc+qn7MxjShX0hLOz78Wt3ITcuMgMlrBsWXRnzjYU7AOJW970Kw==@lfdr.de
X-Gm-Message-State: AOJu0YwLcf16rP0YUj5plAZ/iXydQg77ejtC6LTxvMss7pxycNHMe9Aj
	eKnq+zL/dJdHXyaFJlVUu7MA0ubUdpyv7TSpzZFYl1rxSalqdKMw
X-Google-Smtp-Source: AGHT+IGBhmKgZZJtfXMQlon++CsCg0jO2ihEck6Qm/cTH1x0IgwACCw4M42+U97VUvpZJMqrhQM1+A==
X-Received: by 2002:a17:90b:380f:b0:2e2:cf5c:8ee8 with SMTP id 98e67ed59e1d1-2e9afbed104mr507792a91.12.1730994729326;
        Thu, 07 Nov 2024 07:52:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5e46:b0:2e7:8a36:a99f with SMTP id
 98e67ed59e1d1-2e9a4074974ls822027a91.2.-pod-prod-02-us; Thu, 07 Nov 2024
 07:52:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUiL63Mc+wlfiV8XWuN8g/hEx+CaLErbVfpwh6lXLxyG1gW2WbM2MzHRGWx47eO0JN8H5qFx7/520Y=@googlegroups.com
X-Received: by 2002:a17:90b:2e46:b0:2d3:c638:ec67 with SMTP id 98e67ed59e1d1-2e9afaf7f7amr597298a91.0.1730994727901;
        Thu, 07 Nov 2024 07:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730994727; cv=none;
        d=google.com; s=arc-20240605;
        b=Dsq7+Cd6BCQTAOYCbIqeR2W+qjYPnwNweeT+EHJJGDx59sSFwB91HsztYoEzmULSx6
         sKkJyGYHRQNO31s5ynZAcZI2dgxdbzzLAxwyCT5Gn1avnBQxbZDcjH6kmvzrtiDEh1Im
         c+KI+aS6IDgqNphPJx/CIHwI5TCS6nXJ8sWZjhwllT7YLA3UMlc46QbifF6EUgjWKzrQ
         aH2lfmdZtzFoWk5xewqFRqyRCvpQsRlyLxhh2gvmD0UENnPcnvc/5Tt2gK58fdC5u+gi
         WGHjxE7vNjQ6JjZCw4fDO8l0rcD7mEPK5h/Ou+VZncbChIQZMvIcsrvt0txNbZDLKoyS
         vMkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=0hwdWcbrWft1DjB/sYRyvW0V22f0lvulHb7B62YOWas=;
        fh=dSJMJtD5qUkaJL/wuD+ubXntj4y+QHLuwplSkt5M1vQ=;
        b=dMjQsZgJyMqMuaSWRa+FMzYKSEfInwsNweCFwOoZvbBiq8/Tpuoz6hYhuSVKDsjEcu
         QdkXZX2JoEEQSHhYGJvAooGo4bLAfHWK9JN2ZBve62rXNjyxMVDxs29EuPIrJzaISM4h
         WFQMLtwXk93YZCyBmr6nUWJyjWwWN7+PznaD2cMSBj34SzN8pyqq9V9bj3gm8Ce+uUwm
         KXsa8BdAgfFtdAW3Q1XjZW/UcdVVYSt+Gn2hOVmgymYeML5FUI7Jr0zpKeNi6vVJwKuN
         NuKW6KUKgI+fknEIakD82YpEbWoijAbXWyIS6yLhsQVe8JFVZuSyXr5Bri44G5F0j1jf
         LTmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e99a64e53csi157814a91.3.2024.11.07.07.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 07:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 85AED5C2D61;
	Thu,  7 Nov 2024 15:51:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B3387C4CECC;
	Thu,  7 Nov 2024 15:52:05 +0000 (UTC)
Date: Thu, 7 Nov 2024 10:52:11 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Kees Cook
 <keescook@chromium.org>, Masami Hiramatsu <mhiramat@kernel.org>, Andrew
 Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241107105211.3275831b@gandalf.local.home>
In-Reply-To: <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
References: <20241107122648.2504368-1-elver@google.com>
	<5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
	<CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
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

On Thu, 7 Nov 2024 16:46:47 +0100
Marco Elver <elver@google.com> wrote:

> > My concern is that we start adding tons of special-case
> > tracepoints to the implementation of system calls which
> > are redundant with the sys_enter/exit tracepoints.
> >
> > Why favor this approach rather than hooking on sys_enter/exit ?  
> 
> It's __extremely__ expensive when deployed at scale. See note in
> commit description above.

Agreed. The sys_enter/exit trace events make all syscalls go the slow path,
which can be quite expensive.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107105211.3275831b%40gandalf.local.home.
