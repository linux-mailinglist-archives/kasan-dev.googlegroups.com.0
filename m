Return-Path: <kasan-dev+bncBCU73AEHRQBBBQERV24QMGQECET3PSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D82D49BF16E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 16:18:26 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-20ce0913e67sf76118575ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 07:18:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730906305; cv=pass;
        d=google.com; s=arc-20240605;
        b=KYQTqnjvxEzryVDhl8LLBSgCmVxukOvpigR1W9rl4Paf1HybLX443Lh/uBIr3jnhnN
         xVtRmQW93h4+XBIpz66iZzoZ+CIEQSeNIQOeO+E95pjwLzo7QRB0QnocmK717ipqN8s+
         W270ToGAvzOGvRdPD+2U9QkV55A8hfXMyDVbnTPswJ+YA3RMgdrIa/ZkW+qwqDnLXORT
         ouAls/vemjZDFcB3+Rl8oh4dZtAteW0d+tIvy7N+fSLQCW51BH2bn0ALxqcuqimUBX7E
         49QRtRDd0lG9YxxPbe2DCfe9b4gSNDlgglSAbdqkfjbSbm4YN63N5m0kMEarRLaCjwEO
         RNxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=yxNyJGx2kjDOko0fu8gLl/LcLwGMf7FgA5GTbC/kB0Y=;
        fh=IFxNlvbn7jRTF1U9AiMSXgqh+CVq6uwteBfjhlbVPZk=;
        b=Ll0quveVvtqu/wkKWdc3OA/jyoJAXhKzWoSecNxJ/AnRqKt7GavVsk0oj8JXh0kLfx
         UrQYK47XYgklOf20itqjBiKexZrX8HI5/MZ+OOT+6S4hAIv72d4uvfZYncJiQjUnia5t
         fucU58O+NJtPG4SZj+oMDL0fEC8VxtDfwyA9axF83US1vIy36ERXPdhOeb/qQN5ucI+Y
         hp/OGybFlCiyId0tggPjTs3iWU3AuD3eHPP07kSk7lMrKSOUxAoCgH2yCBkgzOZKzMu1
         1pqCSukXXbTSifT69cya6dZNL+AocAettX5Za/FrBbzlETIz8/K6EcW9aLRL1LMTcGHm
         jN2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730906305; x=1731511105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yxNyJGx2kjDOko0fu8gLl/LcLwGMf7FgA5GTbC/kB0Y=;
        b=GlbB1cWmcVXoaxHl6t5c0Ka+2U5TwRomkgrMgLtb2v5zSDwt323G6Ws4ZARDsVfrXv
         Wzp6SaJnABKo3jDVqGjE+SgYtEZydXr0fDPeQZU5mbqiWn0KixqmtcIK2r+nQcwvlsUD
         YP7VwPO5/Myxlimj4b4g0c4mwztgxhKrxx/6qqNiR+P3iCk0JkMuopfb943LbYE6wiRg
         GSrXJqrEJpnD5bOwsoXWtASvvSXMdsvD5NyLBxFCFIzw/6xSICdRjxOl+qJmRkBt7GzH
         d2whITC19Zrk2aOtJ8gDrs7beNU4mnJ43t4C6yOafzeHvGKFJU0wzWG+mKQB7q2WSFDH
         PbFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730906305; x=1731511105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yxNyJGx2kjDOko0fu8gLl/LcLwGMf7FgA5GTbC/kB0Y=;
        b=NOU2tniM57J6v2RuSTZHGIYxegab/aTxkxD5zIpDq+oY8rYpkEvZSky2pvGFTypRmu
         iNzpracqhjrhFwXWV+/ksnA4/oz3VMSjFhnYhYGnrA/YjwAhNGrYLBrtKVe0zclZ7QHq
         7DORDZeQikQJiidZLGMNVMZO1LP0pIrEbrFoUceD7dlprb6a82wsRsupQO+6kUYPXA5e
         GjON4svd9jvVOslimmaI3atJyhboTBpI6bQ6uYx8VylnsCPNLb3/9MSzrbP+417jdFv3
         L8m4upecN4MSylGW/A303h6QEe82UA8drCYL/Avw4oUWEIWfkpoqwWOW1VJHp4m/szZ5
         0X2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVU0ARNWzC++C+jn3Wcx8r1SH5JhHmpjA5hbXwXLHf0348Sq1Fk2IOXzXGFIFFLPIek3z9tXA==@lfdr.de
X-Gm-Message-State: AOJu0Yz4+fs153fR/q13F99Z+17Lp/pdsKi9Rb+FD0Hp62CgZtybUJqT
	CR4pEJncvBvhjnixaQKgk2wmWeL2SzpkpNY9CKzgg141Z1X5D2ZC
X-Google-Smtp-Source: AGHT+IHOiBitNQnmlMjnIfnGkUJQt11ch4CE2+STXDbh5JNvHbWDNX6VTEz7vpahRMB6MbA8f9z70g==
X-Received: by 2002:a17:902:e886:b0:20c:d578:d72d with SMTP id d9443c01a7336-210c687963bmr533077755ad.7.1730906304667;
        Wed, 06 Nov 2024 07:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa08:b0:209:dcc6:1fc2 with SMTP id
 d9443c01a7336-2110387fd3cls44893255ad.2.-pod-prod-09-us; Wed, 06 Nov 2024
 07:18:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX79r1+9iKYY2rB1N0+9JaUw+Wdt9FgNGayVBJshlIPypQiHe1rIncXZwfyib6d2RKrB3P3SeuhCEQ=@googlegroups.com
X-Received: by 2002:a17:902:f60c:b0:20c:f648:e3a7 with SMTP id d9443c01a7336-210c6c7048cmr548822255ad.50.1730906302500;
        Wed, 06 Nov 2024 07:18:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730906302; cv=none;
        d=google.com; s=arc-20240605;
        b=Wb+SBOm+SHv+M86yHIpXDQlpy31WLaFV/AFNgJqfkt0/mAJcf/nz74vg/Huv8QplUo
         AahHFHRXaxI4TXtsW7G724mI8BY7A/0qH/PYYAUZEerw216BaO6rvOtAOZF57YvW+xA4
         NNTnbrYSc/ufwu6SCKiIUsmYaqoBSxewaL353a7avycxIBaNqEUN8115NxlMIYRSU0gn
         U7evj7OzwOW9JKxLnFkig4dkJYGWWyelBKRKSCW25xNMNDQHtcIelEc2LD6lIgDLKlnb
         ZbjRprkO+x+Y0cqUl6mNj0Nx8/v8R5v8nozHg7TeaR7wFTWrIE463A49IFOJAFCqUbT8
         6OvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=CdCRyr16lTcyOA7ghGSxUISc1EmPfEuBSOlBYKnSGtg=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=REp7x8u/E1m5UBFT8ODo2OF0whVKPN+04tYC3Tn3i6AZ8IWv4FWQj0WKOhjyFVaSqE
         bfaR8201L9MH1hOoB/wk9Umnj6HwlsFxSndnzXZWCfpjvh80fP+ICJIiiSSXhvCQlCbc
         ZKeFdGzaotbp95opejUtB/aqwbtded6IKZn0/09sAWT9IqNlZDPCDgKmdO76jxKz0N9l
         M3VRjG/AT6EMEbhFIJzCdeIQgNi4ST1q2xEaSyFOkewD1aXTFu9HEH56uFH4nsgbvTap
         Is6jvfFieeZhYIXfOGBKoa1XYMRXYP8LPieJOJnA86JHMdwI6sFTD1UsAFCXe8ajWQtq
         xvDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-211057a7fbcsi5195095ad.9.2024.11.06.07.18.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2024 07:18:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1C7775C57EA;
	Wed,  6 Nov 2024 15:17:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4CAE1C4CEC6;
	Wed,  6 Nov 2024 15:18:20 +0000 (UTC)
Date: Wed, 6 Nov 2024 10:18:23 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241106101823.4a5d556d@gandalf.local.home>
In-Reply-To: <CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
References: <20241105133610.1937089-1-elver@google.com>
	<20241105113111.76c46806@gandalf.local.home>
	<CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
	<20241105120247.596a0dc9@gandalf.local.home>
	<CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
	<CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
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

On Wed, 6 Nov 2024 10:22:15 +0100
Marco Elver <elver@google.com> wrote:

> On Tue, 5 Nov 2024 at 18:22, Marco Elver <elver@google.com> wrote:
> ...
> > > > > I'm also surprised that the comm didn't show in the trace_pipe.  
> > > >
> > > > Any config options or tweaks needed to get it to show more reliably?
> > > >  
> > > > > I've
> > > > > updated the code so that it should usually find it. But saving it here may
> > > > > not be a big deal.  
> > >
> > > How did you start it? Because it appears reliable for me.  
> >
> > Very normally from bash. Maybe my env is broken in other ways, I'll
> > dig a little.  
> 
> Some trial and error led me to conclude it's a race between the logic
> looking up the comm and the process exiting: If the test program exits
> soon after the traced event, it doesn't print the comm. Adding a
> generous usleep() before it exits reliably prints the comm.

Thanks for letting me know. Let me see if I can fix that!

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241106101823.4a5d556d%40gandalf.local.home.
