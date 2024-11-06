Return-Path: <kasan-dev+bncBCU73AEHRQBBB763V64QMGQEHWZEOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DA859BF94E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 23:30:30 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2e3b9fc918fsf310773a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 14:30:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730932224; cv=pass;
        d=google.com; s=arc-20240605;
        b=PaFJxx24evqNeZm63XdBuT3Q5A+Gpg/UFjD+YX3QgU8kI762BVqJAeVsYQ88TDIV+h
         rDS95IXQuzQXsoDGWSJIp5YzJYBdCXNVhpINfTeqdfnfxXynqnL6Z+nd1OefH+Krd737
         rDIcOW/4HfQwPLLJTM9O8QqY+x9mWL+FNoZYop3uxr0b9XbxIwTlwSel3Q7HmW6ZfwTw
         Bm3PuI3nnu19QdtxhWrSjQBYf9yAdcLTvJ2b1iUe6/8tZ6NRaBqCun+YzCgjokLwuX2i
         zz8EtU2UXpbJxynnWEGIuOlaDEO13aK4yuYsFnJPeh8WEAgoHlOWDvcP0VA+35jaOv0F
         /taA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EcxzIA3J55qvO5iQTEG2oM/zRzmW90nUMSmfgDjk1L4=;
        fh=jVqHuvoD4n8QifireYTc6kyxcpQSADGPfwDH5etLM/s=;
        b=g16ww2bhvhfPtX2mETztoT03DEQKGOzackYDJaQ0TlQzbe13ISEWH5RzrOuKpUAh3V
         PoKFV08hrGTCp02Vfj/8lWsLfXPXOrVLTF7mMv0dKMaP/9iP9CbNfQZQF8cMPdAWaB+X
         2PsmAL4WTJjXPAkRv14QItnZkacTJXrYcrZnQJRbPplnq/nIhcF0yKybAFAaGnXzfVub
         xORAi62/FV28E4EhDjWy2s6CmAsx6GYw4uTAGcxpWPaUIpcJBCuv3oef21HJ3MPrYZhi
         PS4ygTcIDpqUo6nuJC9u1tDBa7a3EiLU+2ifDTVWa366C4OPEUepRgEvVbUDo6jt34vO
         jilw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730932224; x=1731537024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EcxzIA3J55qvO5iQTEG2oM/zRzmW90nUMSmfgDjk1L4=;
        b=UBjCcUlU0sUUcXXDlDZ+tYgvkH+rwa+L0RJCJMUzhf8SqVa/2JEkL8teWaW71w5WET
         5oCKDCEXpqRnFsqGVDAIbGkJKeRvTHepiplbdadyFDPwQbSabrX78y2/9kLpIKQNhfuh
         DQM33oiI8aVh2zkHVAqaPgwYU63LV9xxZPkIIcIcKoHC1Rj5Fa38Jm1XL4ehf4hjqwCt
         Bf1YMurW2hJgl730bs9tPDGjytMsPi3JZ0B/2rkvBj5MSoQ6zljXn16s/AkFIkuUjKAj
         FLELdoCBBoqT4xjH8xEOGgw3Y123rQeNnSAbkyl0vFjN88ghELWXlOvwcCZdiE1Or5Kl
         T9FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730932224; x=1731537024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EcxzIA3J55qvO5iQTEG2oM/zRzmW90nUMSmfgDjk1L4=;
        b=kQNydzXV13CURtjFnoUFRD3ORKOgtjw61CtTJmC6wTHFEMlxWN7/60ZnU+VF+N9JmU
         8j1vVsjgHkL+edX3RZHkCGMfPt2S20yz83gLaDj3XL0AD8iYSnPKuGwD2OTto7MW3q+8
         i2Nl3uNwHqnJjfqChbiDh273HF14t5hvWE4/Un657O3m/TA5dSywW+lew9tl4q0Ej4Hx
         BfZz/gH25AwPNvxfLkbQ+PjFZjCNbKE8AWZmg+1YdvfhpI/u9uD9pIiL4GNpPeSHIKUR
         UwYuZHGVMXgo1qVgh21QZi29o7aFp7xDe59HMWoV7XlbiJh+c1MLyHipKyeogmCxgtOM
         Uu4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdJKWIBsEYL2yc4+1FUESew0SkqaxVLvu+aXh7x3IMlRH9Y14iv6ghOSylN07AQ7OteI2CSQ==@lfdr.de
X-Gm-Message-State: AOJu0YyiQmKT7CwXIknG0o0tVMD5kPM2eVAQAG52/T/Rhs95W8FYQ6s7
	22JRcTsnxWKZadxDOts+bmdojhDxNLKD0XgS/T7OMTyF+yMNxVw/
X-Google-Smtp-Source: AGHT+IGXYwdR7/3GF4rphd7d1WbbAOAoboQeX9a77kFVWjCeCErI0KUO9lux1nLS4KrH063avnBCuQ==
X-Received: by 2002:a17:90a:c90b:b0:2e2:b17a:b118 with SMTP id 98e67ed59e1d1-2e8f10a72bemr44234471a91.32.1730932224083;
        Wed, 06 Nov 2024 14:30:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fa8f:b0:2e2:840e:d4b3 with SMTP id
 98e67ed59e1d1-2e9a40771a0ls245131a91.2.-pod-prod-08-us; Wed, 06 Nov 2024
 14:30:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX1Tq0fN0oTxhusxKEMp7jmmCSG7rG9K/q+YRjYawY57SXpZEIHj0XZgTMFNdESuVcwTway6124nIY=@googlegroups.com
X-Received: by 2002:a17:90a:4802:b0:2cf:fe5d:ea12 with SMTP id 98e67ed59e1d1-2e8f1073b73mr45006005a91.24.1730932222452;
        Wed, 06 Nov 2024 14:30:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730932222; cv=none;
        d=google.com; s=arc-20240605;
        b=PF5XMnCYYviX0w//xyPg6CQ9XWOvtgFBPZtpnZwWk0iEuwDbeb5AmR6Z5vtPCP2Zp4
         wnLKMb77cbIy4iNWsnM3l/FEesdSC1Mam1+4bQ2fGOVaiBX/Dfe5emz3dZdtpGw/WURj
         5UynYYux/VZk+49e04T7F/l/vUE6RQc5fF2jQtANFXSb8m80MSq7BxNHfFVxoQm31Fre
         7TxbQWsFZWvVA4aOpT2qqPpGLb7ndKE3mulGKmCzvFbLfHBQ1KicacHAD8QSvDArzLY9
         5p/0sfin2ZhPkFKRGxVFswUUYhkGF/Y1qQaUNOqxTwVgEMpgWNZgXtyAoJLuih8reIkD
         raPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=eEL4VR3loHAo9NZypGwji+ehnlrAZtv68Tf4sbs/4Fs=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=gwEpo+slR0KHA+vqfEPT5DVWSFSSHOMc22RW0ZOZELhS17bHNlsUYGFGrgTvQ28Sbm
         lYpONdTG6/X40RTuEtAHKmYWTi5/8nkrVvZ99AFtmjy0lAf2db8XLgpLK6YvfNoQDrXr
         Hfyfv9P3hT1QvFDyH633nPfgEyno8hI8hOlbG9NEBLMlWyJBaBg5d0xTj9wVOdJd2Mvx
         GmV8RJ6mEiwpmAxxAWeBB7TRr1TxHzGUcWA6N+DhF1KKWf4AXcYkPsvj/ptpwwtxyL4w
         +W70FpMuC3+eOQLaK6bfIdaScOtEqEyPhrj3AoA0FQ+A81iV/hguuWc+j5U5LgKgxwjA
         1+fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98af3347fsi365815a91.0.2024.11.06.14.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2024 14:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 6BAD6A445CB;
	Wed,  6 Nov 2024 22:28:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C4F8DC4CEC6;
	Wed,  6 Nov 2024 22:30:19 +0000 (UTC)
Date: Wed, 6 Nov 2024 17:30:23 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241106173023.09322117@gandalf.local.home>
In-Reply-To: <CANpmjNMMvZPWJG0rOe=azUqbLbo8aGNVZBre=01zUyST40pYxw@mail.gmail.com>
References: <20241105133610.1937089-1-elver@google.com>
	<20241105113111.76c46806@gandalf.local.home>
	<CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
	<20241105120247.596a0dc9@gandalf.local.home>
	<CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
	<CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
	<20241106101823.4a5d556d@gandalf.local.home>
	<20241106102856.00ad694e@gandalf.local.home>
	<ZyuxmsK0jfKa7NKK@elver.google.com>
	<20241106162342.3c44a8e9@gandalf.local.home>
	<CANpmjNMMvZPWJG0rOe=azUqbLbo8aGNVZBre=01zUyST40pYxw@mail.gmail.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
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

On Wed, 6 Nov 2024 22:59:25 +0100
Marco Elver <elver@google.com> wrote:

> On Wed, 6 Nov 2024 at 22:23, Steven Rostedt <rostedt@goodmis.org> wrote:
> ...
> > > That's pretty much it. I've attached my kernel config just in case I
> > > missed something.  
> >
> > OK, it's because you are using trace_pipe (which by the way should not be
> > used for anything serious). The read of trace_pipe flushes the buffer
> > before the task is scheduled out and the comm saved, so it prints the
> > "<...>". If you instead do the cat of trace_pipe *after* running the
> > command, you'll see the comm.
> >
> > So this is just because you are using the obsolete trace_pipe.  
> 
> I see, thanks for clarifying.  I always felt for quick testing it
> serves its purpose - anything equally simple you recommend for testing
> but doesn't suffer from this problem?

You can run trace-cmd, or cat trace after the run.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241106173023.09322117%40gandalf.local.home.
