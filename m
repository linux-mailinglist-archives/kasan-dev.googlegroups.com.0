Return-Path: <kasan-dev+bncBCU73AEHRQBBB4F3WO4QMGQEIK6CCDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D27D9C0A28
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:34:10 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-462e5b8a36csf16624451cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:34:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730993649; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/8bML498UPoaGZScuAZZ7PjMr0Hu5+OnCgcbQR3Yly9HhQgLXlBrod7zyvbiOdY4O
         +s0RkGOVnAxxauum0AKbKA1+0d8Wnqqwq5rZgTpZ1Jy2Roxpcx0T3GHGjrCQJlqGmyZN
         D1lUc4oqpxoeeon8P50XZ2oB1piMEcbM1q1GAKn8jSTemHN5dZm/B0BdE45DkNvUSDf+
         Cgj/y7d+DNn+lYdQq32jDVZ2qXaBu4GI7oHi4cuIVvIe3fK/ubIzpvIJlnSspwdlGH+3
         h9V2gIOvCi+i2i9d0hHm6b69EVIhedfG/Hwift32VPRrI9yn/asrlhC99PIlP0mEWMqY
         Dm0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pB1Dbvbe2dBAUc4DfxdbqjlnZtK/O8jgoK2sLfvSa2M=;
        fh=afbx4nUwBPIf4qCAZ1F1rbzP9/cn04WNy8xIbtZw5+c=;
        b=QW8T3e8Q5gA/4ojhWfz9F78qtsFMEFSdyiShebumiKT0culFGcbfV1gcdJf4MuxxBy
         HgOVQior0pb0wnacJMUQq2bdB6kANaFu8p+9cnAzAVoTmdnTtX1hYwip6EDxl73klbWv
         e31zcGeI+VLJwgVqx23UEINO5Lf6d9tqLwf8LLeUYacCsUOQ22++CGMe3kgdFRLFw/mT
         pFIcTH7h4KA8b/6ggyyDbUKZj+wXOO9PSFPvPdxOiAdLWawlPYGuNAh/YA13DMCmHs6d
         3M4KSjjEDUJa8iwr37CqJ1WB6tjee0lbCa7xvc+yhrh4yV5alIEzVvCnnyCBNeKlJsDO
         BD7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730993649; x=1731598449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pB1Dbvbe2dBAUc4DfxdbqjlnZtK/O8jgoK2sLfvSa2M=;
        b=gfx2rrAcjqhrwctTPUqwz/zc+iiAMUaygsvYAiZxRu35HWs1gQcEqOAJ4+TASUQakF
         nfGTOFJZ8WH93LzFTQQBfgkLB7rfqd3tULYgZSwD8RTjSfm0clDMeduumWR88Au/ONCI
         37xlNErtrD1eduemW5Pd1f9zf+T5usuyqteVkDkwSC1aJVPXYAWAEDeySF6k8v0F0fvh
         y4ES/9wC9cbktW//DkOSDaGpxYdLaVS5p2yaspx9mANyW8JlGAuHzuOMRDBkQPItvuXv
         qPf+/XQMMg6zIpQUM5fyAx1XCUr+OMCiG84V8ClDfQ0TJa0PE6VJDNmgFKhIhZxxgM1C
         XIAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730993649; x=1731598449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pB1Dbvbe2dBAUc4DfxdbqjlnZtK/O8jgoK2sLfvSa2M=;
        b=SfKOtuDLcHuqDSGxCpd/1m//JS59huMvJo9/BSuEEnhvEkOjb68oIqAr3AnZ7aevj8
         3K0HpkAyXkVGJV6hu6tuywN/D08KC1KNe5tUpgB0TzBqmtuUVC1W7reGrg2Q8b4De/yh
         LiFU8VZOpXbXYnmxwVsrUhfn5XFZZVxkvanIsuAHhSZy6Tm9TaiB0qwYKuZTSiq+UgRI
         96uP1YDA4SJ01OKxPQKGyJm5IqX2bK4fdn0CsLBL73VXIGwuS8gcinrh2k7+8iu1rbrw
         HNaXNfGzBdL+5ebG0fR6jrWh5kzB/tEqxpeKvB67Qm4yDe5j0UcQx+ZO/dsrh33yyDJe
         L52A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCOZLNFMfJh8d3rZ2RKcYb8aSqtLsyrVciz3tmEWhzzumjoBZ66QB81GP8+2j0nVlMHXotZw==@lfdr.de
X-Gm-Message-State: AOJu0Yzyio3GVmwWFCSdRcEzpTxkwHgbrgI3murxPpwEv0pehzn5SsnM
	ZdJMunZJ0f3sJCeMOTX+5GpUTyGRPHmgZ6G53fbcDnnihST3QvFO
X-Google-Smtp-Source: AGHT+IHVRYtjWHo9Qg3otpWlNAHbJTR/5l02tm8ErEtPhZFB5B8ZuaM8jqXh0ObLD9UABgfktrraGA==
X-Received: by 2002:a05:622a:84:b0:461:285:9d7c with SMTP id d75a77b69052e-4613bfc4d1dmr572475731cf.12.1730993648980;
        Thu, 07 Nov 2024 07:34:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4814:b0:458:4c68:593b with SMTP id
 d75a77b69052e-462fb32d9a6ls15921061cf.1.-pod-prod-07-us; Thu, 07 Nov 2024
 07:34:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWocpuBsKJZuAc5uC/AQZBnq420rZnDxoptX0YHHfAzZbGZp47upUa0JvkTS1X/lOluUWWI7FDEjBc=@googlegroups.com
X-Received: by 2002:a05:620a:170d:b0:7a9:b605:f823 with SMTP id af79cd13be357-7b193f03f56mr6150122685a.37.1730993648071;
        Thu, 07 Nov 2024 07:34:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730993648; cv=none;
        d=google.com; s=arc-20240605;
        b=YskcXbrRZqgmId1WGNy+i9BMJT6Z4ZexK1FpiYqvSJ0bdh0o8RsK+MHcW70TgbRPGu
         Dm77imv+fAT0ODZXYNwHBmSz0WB+gGftieUnQH6Ri+IT1NRj3fTZD9aMUiNhgw/Q4uja
         rEZHabT3Flo+rmzNVt1m/PfYE+j3MBa48Hir71hILRg26Sp7ddaOcq1vlOcAHaK6jAYz
         y99sd221G0Rknz4rD2BFb3X4bX5n3F5Pyu1sWnNguqvWbESkKhaK8tvCr3IrzSYjDdCg
         0rZFPEQW2ZNauRqt4yVrazCATYAWCjW/yeXO0qRTfSlI327TTMqfhstp5tCrLzYNqJZE
         SGyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=jz+J984uFC6feMMX+aYQoZ070mvIWvvic2jT+GJTdyU=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=Zn8KC6jZ5Iutmhp8psTtvsxzcPSBW4rhINg4XY0N2L6ECvZU/eVAESGCm9ckr9qDDK
         cKtwd3ZdvSUQy1GCXDoo9K0vkDUYOZceV85PrUhp01ntXLnZSIYxygVGLBdmb2u0Mktt
         iaBF3L4eUVwXg+bSin5Ww5FdOPQzNWBWweE49R1lSFM0CikMGN0i8DQJ/1GpS0aRYWlJ
         GaEiCu1d7xW+sRYj94piEhtynX9CeurFDRLEVjjPkpC/Fr7Nsj8xnvaHHmvAtjdOm63k
         eSc4IbmD0M4NFVa3vBk8pWvFkg2FVv4uUIo5Y9HZBfl124KPBYti3wAfxurzkhaqb3p7
         kbEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b32ac39e70si5848685a.1.2024.11.07.07.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 07:34:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CCFC05C4DB4;
	Thu,  7 Nov 2024 15:33:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CEFB0C4CECC;
	Thu,  7 Nov 2024 15:34:04 +0000 (UTC)
Date: Thu, 7 Nov 2024 10:34:10 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241107103410.44721a3d@gandalf.local.home>
In-Reply-To: <20241107122648.2504368-1-elver@google.com>
References: <20241107122648.2504368-1-elver@google.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=q2pa=sc=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Q2PA=SC=goodmis.org=rostedt@kernel.org"
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

On Thu,  7 Nov 2024 13:25:47 +0100
Marco Elver <elver@google.com> wrote:

> +/**
> + * task_prctl_unknown - called on unknown prctl() option
> + * @task:	pointer to the current task
> + * @option:	option passed
> + * @arg2:	arg2 passed
> + * @arg3:	arg3 passed
> + * @arg4:	arg4 passed
> + * @arg5:	arg5 passed
> + *
> + * Called on an unknown prctl() option.
> + */
> +TRACE_EVENT(task_prctl_unknown,
> +
> +	TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> +		 unsigned long arg4, unsigned long arg5),
> +
> +	TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> +
> +	TP_STRUCT__entry(
> +		__string(	comm,		task->comm	)

The question is, do we really need comm? From your example, it's redundant:

  test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
  ^^^^                                                            ^^^^

-- Steve


> +		__field(	int,		option)
> +		__field(	unsigned long,	arg2)
> +		__field(	unsigned long,	arg3)
> +		__field(	unsigned long,	arg4)
> +		__field(	unsigned long,	arg5)
> +	),
> +
> +	TP_fast_assign(
> +		__assign_str(comm);
> +		__entry->option = option;
> +		__entry->arg2 = arg2;
> +		__entry->arg3 = arg3;
> +		__entry->arg4 = arg4;
> +		__entry->arg5 = arg5;
> +	),
> +
> +	TP_printk("comm=%s option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
> +		  __get_str(comm), __entry->option,
> +		  __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
> +);
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107103410.44721a3d%40gandalf.local.home.
