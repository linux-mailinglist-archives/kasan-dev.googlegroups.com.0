Return-Path: <kasan-dev+bncBCU73AEHRQBBB7WJWO4QMGQE3OE5A7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 65C3C9C0AB8
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 17:04:16 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-461011bd338sf17020861cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 08:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730995455; cv=pass;
        d=google.com; s=arc-20240605;
        b=C69a0BW70uETljq73QovR2pUF4CFqPIFN8QPQCMEO73DRpuZcnjJYal9qnh2yvnqIx
         4EtL6+K4PFXEGkCeJjg9tCVDGez6KIAlFkwZ0TSq++NF5PXZjXLgzdIQuL/uDFbBFTDf
         +r1rIpHLQjuPQ2slHAo/L0/8U+FyJvNrviU1R+DkWXtbq8M+/HlbczznCVdjkSWA/tyl
         WwynIDlJHZmopwlXEENtLwhnpnk03zUtVUccHaPQHz45GdrG1qI6kk9FAseKIqYNc8Qb
         hA6Bfh7BgxKYHL0y3u2gIqd3hNyON1lraxGJzwputaCJJWYmxpRg9JGizXWhmYl5Ewm5
         8TRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FRB9O4dLwyPWLzcdyTI+ctdbNTrSkGQo1sNoE85b5S4=;
        fh=yKomB3zGLaN+f8c7jAMm+xgxP3erJpdiD5Qj3nyRhPA=;
        b=crlCTlkkJsUlX/Z+FA7sqUHZsDU2eLFdC+SBtITIMw5pLqIXa3iGY4opbiNFN5nO7n
         mo4JmDpcOEr+xwWoW9EcunKRhw/GTAMybGfcrZuaYuN5+rSOS6vyloiNUyc8SoKsUyVa
         dWNoHv1odrohjmrxFdD/awvrwmsN2H12BN2eYPYUEhzcUaI/vR5OkEzUJ8Z8RRAT10KM
         hwCFwfutSPEYIIvVcWa6i7OKMafmdo97mnI8AthodCGUZaltzFgDf5lrVptzjVVD634y
         exQAZCuD/OP/l4HBdpqD2Vd2YvNnSP0Mu+aHrt1knR8sBiWdtVTh2wURsvDh3Ee2qGqn
         ejtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730995455; x=1731600255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FRB9O4dLwyPWLzcdyTI+ctdbNTrSkGQo1sNoE85b5S4=;
        b=Yk8Y366TbLLlRd0AewEzMyXBQ6LCRUGq3jRFRS2uLsLJRYmR4FC+1aeQLQZ6yzBMGo
         yqiI6dOnmD1Hk1mRdIoO7Mwx1l4SMjb1EDPX0lgTXRJsGuQHugscRAlCZk7cwli8pkXp
         czDYSg6c7Rr0YiHPN+BEL18cJX2FKzfw4I7/0SJVB669tjuB5+tSfXCpMrCC+aVbrP/9
         kuWeQ/I4PzW4P47SgwfiITAfPCM40aI+LKKjNZWsOqoqcKeVOGcV8BFyQrWz7KO6JaoB
         Ke4HpQ9UR7Gaupggh5nOUUKdUeyl70qfbPndNzjl83Sg//yIKj8JEUcFwfHSi+xcWF/7
         D7uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730995455; x=1731600255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FRB9O4dLwyPWLzcdyTI+ctdbNTrSkGQo1sNoE85b5S4=;
        b=ozpeiMmLZVyvaF1udLPac5NCWnOwlVf6aQZRKMhBDD8/0yE47L2dC46wyS9/OnjB3M
         ZY2UczJF6FewN0rjxiEHdY7Mqr0fBimoc2kTn9EiDsE/pfbkXrlUaGJ5WibDmg9IOCTE
         Ev0dJwD3ghVhtzFIvEDU4ZFSE9eHVTgDp05hnhzufDIAHYyFopVaT1jjk8X0p79Cp/wM
         h5cqdfiL8OzEqc4RSatA+AEoUis8Css8BAVVVPw/kE1JoXronm+Fhj7NI/w1djOAVqFD
         9ZU1LHevUQpGqUcK06P3uHbT7YZZTPD/IL6SkCk5WGkrWPXus0tTmZcPJ8nSeI80pkHb
         mvaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvjotAgwDMi0siDKxcMiz6pn8RbFJ4O7xkbMZOyi4lzlf2mAXQ5m64hQFz3VjP1O/av2JkVA==@lfdr.de
X-Gm-Message-State: AOJu0Yy7dPX5tpwT2g4VT1g1dWAHwZMI2DswSeBDlQUdhs9DiyGdFE5S
	e0rvwlYZXrDufBbKBvv315D9CA5wZG1fmsq45SE9XRJPzwzypHDC
X-Google-Smtp-Source: AGHT+IGp9K5qtcUMIau2Kl3znxUdMXZV3N7GLUTKwsiLQtj2Uo82wwIAJFXYGDNoOw4tlYpm+BSJPw==
X-Received: by 2002:a05:622a:2b49:b0:460:ac33:431c with SMTP id d75a77b69052e-46307f6087amr5694171cf.53.1730995455120;
        Thu, 07 Nov 2024 08:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:401b:b0:461:2c82:a2ae with SMTP id
 d75a77b69052e-462fb125498ls14528281cf.0.-pod-prod-01-us; Thu, 07 Nov 2024
 08:04:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUjQD288Pz7D0SvO/uJlgIBKeppo3OQMqLhFpdjrutLQ/NNMdXyLgGitHLjb5QRBBW2qCBVu//Dx+U=@googlegroups.com
X-Received: by 2002:a05:620a:4586:b0:7b1:4df0:5580 with SMTP id af79cd13be357-7b330d90984mr57617785a.39.1730995454284;
        Thu, 07 Nov 2024 08:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730995454; cv=none;
        d=google.com; s=arc-20240605;
        b=LsSl9aHgz29BvQabxL5B6RODF2J/RqxwreJ2bgw7e6RDliglp78tBPUp4G8YS04pcx
         jOUCnObqhzoAzTgG0rWxGoXBDK7kVJpYi+oMWNNDT+k/v5SgXa4zE1gh9VJ/tKsNlEQD
         0W1EOXWXGKSv/qFKBSmC207zeQ2zNE0LBus1SVAvCieZF7bu9e/z9uMnbx/TlrIHqaKj
         OpNKFU+UzHL9hVIkwLP1T+9rAV4ayv5hgEvbq3L1trOE1RPPJ6PWufpVP8idfKVxuua0
         eTXSrSA64Epp+YmxPfPnvLfPVfg9X06N4KJ/hgaS8QRQx+JD2ForgDhkTX/XkzqUZMqD
         jeJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=WzWArTfb7sqCJfcGG9ibNZsowtjNFJ9b8VfxVNdUuaA=;
        fh=UAX75mHJBFuIwB+dH6PSbABT8NSOKC2o7Qfz0qZzaoU=;
        b=XytC9SLn83ipJv/K8OWhalk9VrtiU0etTcxn+1dZm0rQZgFubyJ7+DhDuXyuwu9XKt
         xJ9LqVW4u52iTNclN+FsVeMxgtE/l1NkXv6nKyPvsiIjmVBFIYgHruUnDSXo4edI9Ak2
         AAtR/au+wZ+MELHgNP2HDys0wWCqG15hBkKUSkce2ypbiioT3npAq5vk5ELz1tjaJVXy
         g8r8GbRbXvXT+3peeRinqdwbrdk63GsEV1iZLPbPWDQ7Sz7OVDEUgRF1r5djZiBT3lFM
         8dBrQIE3eQMAu72UotfCg/RF+1QycJ5fPCpFsRR4a1qhr19Ejh4HHjmFGwPiDZUMBLE9
         Jeiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b32ace0dbcsi6795485a.5.2024.11.07.08.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 08:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1DEE75C57B4;
	Thu,  7 Nov 2024 16:03:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CFBBEC4CECD;
	Thu,  7 Nov 2024 16:04:11 +0000 (UTC)
Date: Thu, 7 Nov 2024 11:04:17 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Andrew Morton
 <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241107110417.7850d68f@gandalf.local.home>
In-Reply-To: <3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
References: <20241107122648.2504368-1-elver@google.com>
	<5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
	<CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
	<3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
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

On Thu, 7 Nov 2024 10:52:37 -0500
Mathieu Desnoyers <mathieu.desnoyers@efficios.com> wrote:

> I suspect you base the overhead analysis on the x86-64 implementation
> of sys_enter/exit tracepoint and especially the overhead caused by
> the SYSCALL_WORK_SYSCALL_TRACEPOINT thread flag, am I correct ?
> 
> If that is causing a too large overhead, we should investigate if
> those can be improved instead of adding tracepoints in the
> implementation of system calls.

That would be great to get better, but the reason I'm not against this
patch is because prctl() is not a normal system call. It's basically an
ioctl() for Linux, and very vague. It's basically the garbage system call
when you don't know what to do. It's even being proposed for the sframe
work.

I understand your sentiment and agree. I don't want any random system call
to get a tracepoint attached to it. But here I'd make an exception.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107110417.7850d68f%40gandalf.local.home.
