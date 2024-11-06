Return-Path: <kasan-dev+bncBCU73AEHRQBBBX54V64QMGQEPTPF65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DB9D49BF86F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 22:23:45 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-7e9fb5352dfsf272960a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 13:23:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730928224; cv=pass;
        d=google.com; s=arc-20240605;
        b=MONNNW44zceVyNy/x/hHSjcdSB9MOS34+ItXQ3oQ7rTjttRCOJQRWmLe/P09UEMPOz
         4nBXOIHOBMDtP5hQGgQwa6nr34xeEMRbrR4ARzSG1scciWSF2cITdypmlx0j06cf0Wqp
         4T3aU/hV9tDTlx/iDTEYiCjF9Cqkbi8Hy0TjrurNm6Yi4a2SI7vPrH77Egt4B0+qpFQw
         jxxT9XgWpAgnfCU0dO4meLvE7VcmHKMeAUNFxDCTklCC6pedcWkZdCVtLbSR+inVmQf5
         +zqxPwnj7KU0eLVSIo9J50a5AwDLoWEA+Uyjv10u3ZoKJ744yIK/84j+w6PZNICBWZ8t
         C0iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sxNjvQ7Y2CBterW7NrWOKZgIFbDEp3SCAJGcbg1h+JA=;
        fh=Zi+wJlIM7Cpq1zE8Be9n+AHA10OBAqEWIK98VRNtUvU=;
        b=GvbsTOs8gMNdCcvfuHVyx6ccQaIF2fX0gj3DfQ3BXwyE1x7gwVkP7Zgx9IcGFWpiLm
         HEl3C/OMt1b20hRgRlDh33phj4Ix508fcz3kQtBJ4u2bQaoNLClTx3FD1+gj8kB9HPh7
         FQv1Wu6IBnDHWwEQQ3Aaj0IFrF8wuPV7I/nY/r6vP4fWc0hOHH9mlG80u0WdA0P50N4U
         GKo46uDb+VzG50SMFeBXM968E7efvdBz/HvmqOVedhRMfQdOuIH/eL8WfoPVsmnGD+SO
         JSc4K4N289x1Et/oR+u6NinwVMJTZe2rxm2cqfyZ7PY007Is1AR+Oj9ac8XSJ5vNHYh2
         SDzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730928224; x=1731533024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sxNjvQ7Y2CBterW7NrWOKZgIFbDEp3SCAJGcbg1h+JA=;
        b=Dqav4I9NiOauYNsQD+V5i6tjmSJ+5+JCJM6Zh9Ikwit0o5hbMZ6SShMvuF8qhAp2/+
         HFBB9Yi7leiRaXzQsVf6rlcRCn1GSiEm6IRsY2zazKj344wv7uzJP48/6GuFC5UdJtll
         iA4M2V+Jc67psimWLqBQsay2uRM+hI3ClYqwGTiFFIdF5MWnNorCyn+F/iO1kurOv//k
         7b3qH4gceIbY6+4QkyPX7HN09eCDkjRXhfUSzYxAd1b+Q1/hTuXw1lys+7rv1FXwb2XT
         46EnRjVbOin4PLknXOr8uoZSKDzYIIX6cQ/XsxqMjGWyluAe6sk2TDnvYKIlGF9KoTre
         T4Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730928224; x=1731533024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sxNjvQ7Y2CBterW7NrWOKZgIFbDEp3SCAJGcbg1h+JA=;
        b=EH8HRc6PbRO6aozUGlnPEFgMGLwOmMByh3jslqzHpIu7/hz+pbRZ1u0msdIuN63wYN
         MaFUDMP7EHfPRDd9/p5dFJqtZA/hC9o/4T59AZC2ZqKadNHoF8/gaY7VLOscQaCmSFoh
         Aj4YminGMgeU8DGzvgQIvWxqYciNOpWYzNMTtAbKP88awjQpFIhYPKeyQWTwPfGrzP0G
         fB8+iDgzrofYbtqChewgrAYRMywveBMDU+/mfMZdSHI+nLQswcUl7sa5LLfaRFQUOYy2
         gQxTuR5gBXy0TfWPON6InkE+x8RT5q1ZqZFKy44FqRCVNgJJCUtSSIMh+ehwvhBlp2ui
         +gHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2c4sNP+wGX/7mw0c68hm/NGQgvde1ReP2TAwHtUo5R9LUoxQZ3g017NudDOg9+495Yb0COQ==@lfdr.de
X-Gm-Message-State: AOJu0YwP6wb5siijU2cfVsxQb6LXgfQCdtBE9zxqjjwNOMCBH6jEsFTo
	udUKaaiOBdjbVVYBwl46lzjQr53W0FY5VXIOkhLocvLCXAQWr04H
X-Google-Smtp-Source: AGHT+IGO8RLcBIBFy6ydaDM5mzQgFjxVFgBdaQTRgmWOa+9ZT/XVKYBLUgJ6EOsxCw8jB6oSL4V72w==
X-Received: by 2002:a17:903:2442:b0:20c:5cdd:a9e with SMTP id d9443c01a7336-210c6c02482mr548497225ad.28.1730928223699;
        Wed, 06 Nov 2024 13:23:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:790:b0:20c:5fda:7b55 with SMTP id
 d9443c01a7336-21175374758ls1402985ad.2.-pod-prod-08-us; Wed, 06 Nov 2024
 13:23:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWw3kBVf21yTjDqB1AO6/LxK6cRRcAWa+wrOLrcNf61E5PTR0c4CThZU8DHuTahdDfaxD7QnFLHAzA=@googlegroups.com
X-Received: by 2002:a17:902:da8b:b0:206:aac4:b844 with SMTP id d9443c01a7336-210c68aa047mr561411535ad.6.1730928221512;
        Wed, 06 Nov 2024 13:23:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730928221; cv=none;
        d=google.com; s=arc-20240605;
        b=lGAo3DdgOKF2wlWgNO7aEEM31Ho3t9vPjImMAcy9vJUuCVrYIXJ3N8+wzyeM/S9acB
         Is3RdNJwEim57nrZmq3sVyYLoJVJ+RSWe83vESmU3R/Dnxw2cEujU5QtZvNEa5wzGWEM
         53XKeMK0ahqukb3KyU1gqw+bGIw2Tpt48H3NvrqNrL09vh7MU6W8Et/LYsna7Fyp8Qmh
         mY+GmalKPVwdbxif6JvOyWk4xU7Oi3Tqq0FhiKAri0yfIwpVeaQTPCt5TsCkfIRqyPcc
         BrzEpX5zn9IdppueEV0cGtspn5+E+Bi+K3odCoB7ytYkYJIG/P8DaoeD47VaBG6SL4tU
         UHtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=re2pYga5D6pLqhUroEKAaOtWWgYKivSopfY+g4HEveo=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=Sj+OJ7002xS7+3N4C2R2FPchqPcEBTNHqO+Vt4VcvawxH0dg5rNIqufX8A33CMcMnt
         C8IBQ8LWKkmH6/mqGwGO/8Fq2TD5yFletYRpht6Mt+mp1FqTfHEsrtSVTyAv+NsyVLoS
         DPVmGXsLAfzdeuu34DAdLwmAhheSCxYrnyiq36VFA5vU37pYzCpLgaw3l/mulISqYre6
         sCa/noUqgInyBXer7CoM23EKZUh2MU3hKhEZuWP1tcti/Jko3jCx0SdsVAoZkU/FAqfp
         6hDYjxOvpS6ul6KCnGnzOatzLt0jfmvksvvC5sOzXl+7bb+LI53zJIX7ZyvHsM4cxNeS
         qChQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98ca46a88si210610a91.1.2024.11.06.13.23.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2024 13:23:41 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 572E5A444BE;
	Wed,  6 Nov 2024 21:21:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B5192C4CEC6;
	Wed,  6 Nov 2024 21:23:38 +0000 (UTC)
Date: Wed, 6 Nov 2024 16:23:42 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241106162342.3c44a8e9@gandalf.local.home>
In-Reply-To: <ZyuxmsK0jfKa7NKK@elver.google.com>
References: <20241105133610.1937089-1-elver@google.com>
	<20241105113111.76c46806@gandalf.local.home>
	<CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
	<20241105120247.596a0dc9@gandalf.local.home>
	<CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
	<CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
	<20241106101823.4a5d556d@gandalf.local.home>
	<20241106102856.00ad694e@gandalf.local.home>
	<ZyuxmsK0jfKa7NKK@elver.google.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=m17k=sb=goodmis.org=rostedt@kernel.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=m17K=SB=goodmis.org=rostedt@kernel.org"
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

On Wed, 6 Nov 2024 19:12:42 +0100
Marco Elver <elver@google.com> wrote:

> No other events should be traced. This is the test program I've used:
> 
> 	#include <sys/prctl.h>
> 	#include <unistd.h>
> 
> 	int main(int argc, char *argv[])
> 	{
> 	  prctl(1234, 101, 102, 103, 104);
> 	  if (argc > 1)
> 	    usleep(1000);
> 	  return 0;
> 	}
> 
> Kernel config is x86_64 default + CONFIG_FUNCTION_TRACER=y +
> CONFIG_FTRACE_SYSCALLS=y. For the test, once booted all I do is:
> 
> 	% echo 1 > /sys/kernel/debug/tracing/events/task/task_prctl_unknown/enable
> 	% cat /sys/kernel/debug/tracing/trace_pipe
> 	... wait for output ...
> 
> That's pretty much it. I've attached my kernel config just in case I
> missed something.

OK, it's because you are using trace_pipe (which by the way should not be
used for anything serious). The read of trace_pipe flushes the buffer
before the task is scheduled out and the comm saved, so it prints the
"<...>". If you instead do the cat of trace_pipe *after* running the
command, you'll see the comm.

So this is just because you are using the obsolete trace_pipe.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241106162342.3c44a8e9%40gandalf.local.home.
