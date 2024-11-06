Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZONV64QMGQE77WJS6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A9B69BF8C9
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 23:00:21 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-20c7ba2722fsf2558075ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 14:00:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730930406; cv=pass;
        d=google.com; s=arc-20240605;
        b=LnumOLSuu7ZI1C34cFts0fXmoVMCLCPoXHgFx4r76nubOf9VNJZDhH/c9UyQDxMhyD
         Ww3yd3vVqn9GBpdwhDI0y8b4xJyLfz5PB5s8VPh8ASt+2bh0WCu6Vp4CJpjr0ZkvNFF0
         3rH6+H21dlge+N8u9jsT24D0uMLOtGSrFtIFW0Cney2zmyReBlMZj1W4GVb4nShZ9j8S
         BZXL4AFil+Ku3fAHYKRnCgxWzLPMCedT5JK30waUoCQ3p/phR99ZRty5l7P1BUCf2nIo
         oJr/O1WtzbCMvGZk5pFrPy0AsErIax4ah05EU75x6MA2QGGnvC5OE18JAFLTWfxmQBwx
         5tDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4D4rESTugg2FUa8Aw18CWE9i1uis4rFNxTNuwertn34=;
        fh=82nZQzbupSkBhoJ6F7O5c/Hs7oIEIZtT71lMdyq3KcY=;
        b=j8S81JT2voOcpjMe/Fda9hUEZ+wQ8mgd/VkJYdgrIBqBqQZ8KXUNgT083D6hemSNe/
         DJeKwnkpXg/nymXiwEY4G1WFM7h7SMP68uea1avYmFXAH6XJdHR1AqqZUkbbbhzJkcpx
         T2838DyWot7msls6d9zMURekU6aKQA5M2ssnWauwGn2KVKSYk7+XEmuIT62olVCEpVSy
         VSUaCoUHfEmg9zyuhgCrPKIAQxcIMYuMGk7AeJ9uSQvik0zzpjkZzezBPcrs3Io78f8S
         Uih54J8iXZHplptRm3jSdHRy8ZFNZFWV304aG9fg5oW4kLCncKGlvHowRPmZi5qxi679
         TE0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pl3xoAZn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730930406; x=1731535206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4D4rESTugg2FUa8Aw18CWE9i1uis4rFNxTNuwertn34=;
        b=phDYtwhqd6qJqomLEvwo8ivAGdFsMpKedfMwdO2QcACUp4dq8FjmNnk5m9W/y7yb/S
         TzfsUljPmO0esn87y+47Cl8wfqDO3RoOLiIwVpCvEacRSa4iWaYYSW0VDyx2TQHu8nj0
         RuR33bMOH9AjgzjD1XrlTDgLxRYvHBcvtDR2d6AIDJbU/OGjirMGGiy13M1ahgXifjRK
         a55m67Co6Nt9XkMAmnKKQs2b7k1FWIJcIicx3mS7ee+l224H5Ij2J+aS/wb82ISOkBuE
         BToMU+f+N/4cTUZbcDU3XkvDiDImbx+sqmSWOZUCzo1o3WzHfKxacl4sfBScMFuX9bpf
         d19A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730930406; x=1731535206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4D4rESTugg2FUa8Aw18CWE9i1uis4rFNxTNuwertn34=;
        b=Ea2mhQqgrDwUMYi1RuE2AnAyRKh92Jy6xUFqP86xEQes6b01w50U5uyrCGt4UdeUnQ
         +tU2tPSxHA3iAl4o2MoOI3+L3hk7tbQJeCxoKcLqANgkawljS7qlTJSSZKtWxVN0xeH9
         GCX5Pl2nAjqNtvloBD2PoelfC9cFd3XS0CfBmmZy9PF5pviM2Hf26Xw5+/90/HkJ7o/I
         gmQvQn2ed72ASmPCPLg4JzhdO2t2s6HfM9aqS4i6HD37MZeIyF/vaLghlFlg1gTq1sOr
         bjk2VOAc0YiryG2SSsLSKEGOG4J4Ib3QZkvm9RjCfn3JaHoavEk1d2dyhmVThfzjCpd4
         vuRg==
X-Forwarded-Encrypted: i=2; AJvYcCW2K04x/j6UA/rLMTnasG76J3MsoN6Q0aClsfD1gKIEFYTa94Vr3t3xIb7FTIL/na/h/UVA6Q==@lfdr.de
X-Gm-Message-State: AOJu0YyFLODTc5UO8Z4e6zTW84pZP3uWpKaP9o2XVuIHPh/TIEmLj8MW
	Nm9ZCbLOQd3UKYvMG4kwPSvzijWH4/TDUdkMKf6x+saspxI1HO1p
X-Google-Smtp-Source: AGHT+IEEBgxO3/MbNQmp1x2sDFsm03WyJqcJ1VoZ9mpFHXKHekWCIlCNwnr92r8zHZH8LZaRvt7eNA==
X-Received: by 2002:a17:903:984:b0:20c:ee32:7597 with SMTP id d9443c01a7336-210f74f28a5mr398496415ad.8.1730930405983;
        Wed, 06 Nov 2024 14:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2d82:b0:2e5:5f77:3e41 with SMTP id
 98e67ed59e1d1-2e9a40554edls237494a91.1.-pod-prod-01-us; Wed, 06 Nov 2024
 14:00:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2Wfp3q959ws1ZGBvlqrQVCp+tQnMSq6hfTCgXhatF2q2OjyEfDnUbpLDVX4StMNU1VU6vGUX5+oQ=@googlegroups.com
X-Received: by 2002:a17:90a:a384:b0:2e2:c406:ec89 with SMTP id 98e67ed59e1d1-2e92ce75107mr33214054a91.20.1730930402078;
        Wed, 06 Nov 2024 14:00:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730930402; cv=none;
        d=google.com; s=arc-20240605;
        b=ECuaFFTx/a/064AbCUMGrtsvUSPxJGXaOdhfkKWRmxd570e8TaFVsaqU1Af51Y580/
         TOQuIlbtg0Qtvb78NvQw9E1IrW7qHihi3oIL+Bb7Ez1+E9zHsor9eQdS0mZTEgN8ufvf
         Hh6Qk+xe9xWKtI+VsUykTOg7DUyIXXhWifeUVC8Lhd/eWQwKEICc8AwMDhPfoE46RYcd
         m2G7pWletWlK7eEDyyZUIgrrNqyO4I71S02ZM1NCNJ6uzaRW0TH+BO6j9B1Hp+/Ru5Hc
         SE0MlezMt9j2rUbO677PJhoWOgdXexsgDurz4RN7kn08wkl5MhN1vxBrQwN5Xc9wima+
         imlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2Es3p6p94eraJRLtbFRw7m7Hdwqby+HzOFvb3PHSaFg=;
        fh=8l0vo5vbTxtEawt0OkRCBquDi/Cyy/NxZI2JNQXlf+A=;
        b=NEXH0eGDfwswi/jBot8rWYtCRu4Ru72Tg15gRaFVZbvzkkFqJqgaLveQTqMCBmw2oY
         ocYpIyWVID3IJmnopm2vRLTXvOJf8y2I5etYe6r8AofIPxOw+vAPlkWNNRxh8rvCIA7z
         M3aluwjq7N4MXjBq9AvzNglzv40Wby0vPk+GIpszOrp7GsQ7AdA8g0K5dXmF3Vd7qUuh
         1hk52OFG1tzW1sO5/2uds2yorBqIAXDP7rpIwVMnqkOWfYEpZ8Skjk/nfD4yPNIxscaP
         BKEVa/NKIooyDy9bUy04M6BMebuRwPpAZFcvA6shmX56dNOPPoId2E0kFv0uAC9Lp7W9
         tFpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pl3xoAZn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98ca4015bsi279220a91.1.2024.11.06.14.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Nov 2024 14:00:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-2e30fb8cb07so228382a91.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Nov 2024 14:00:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUdH7LZ8bsjU032/tXvh4mb/bEnc+W6mard4CIAr5Lgt/Zrcx48ZPQV66pE3k5It/GGaZZmisK8NaQ=@googlegroups.com
X-Received: by 2002:a17:90a:b305:b0:2e2:b937:eeae with SMTP id
 98e67ed59e1d1-2e92ce2ca0emr32021282a91.5.1730930401453; Wed, 06 Nov 2024
 14:00:01 -0800 (PST)
MIME-Version: 1.0
References: <20241105133610.1937089-1-elver@google.com> <20241105113111.76c46806@gandalf.local.home>
 <CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
 <20241105120247.596a0dc9@gandalf.local.home> <CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
 <CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
 <20241106101823.4a5d556d@gandalf.local.home> <20241106102856.00ad694e@gandalf.local.home>
 <ZyuxmsK0jfKa7NKK@elver.google.com> <20241106162342.3c44a8e9@gandalf.local.home>
In-Reply-To: <20241106162342.3c44a8e9@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Nov 2024 22:59:25 +0100
Message-ID: <CANpmjNMMvZPWJG0rOe=azUqbLbo8aGNVZBre=01zUyST40pYxw@mail.gmail.com>
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pl3xoAZn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 6 Nov 2024 at 22:23, Steven Rostedt <rostedt@goodmis.org> wrote:
...
> > That's pretty much it. I've attached my kernel config just in case I
> > missed something.
>
> OK, it's because you are using trace_pipe (which by the way should not be
> used for anything serious). The read of trace_pipe flushes the buffer
> before the task is scheduled out and the comm saved, so it prints the
> "<...>". If you instead do the cat of trace_pipe *after* running the
> command, you'll see the comm.
>
> So this is just because you are using the obsolete trace_pipe.

I see, thanks for clarifying.  I always felt for quick testing it
serves its purpose - anything equally simple you recommend for testing
but doesn't suffer from this problem?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMMvZPWJG0rOe%3DazUqbLbo8aGNVZBre%3D01zUyST40pYxw%40mail.gmail.com.
