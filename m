Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGGCWO4QMGQEEIWZA4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76C1D9C0A56
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:47:37 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e293150c2c6sf2206890276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:47:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730994456; cv=pass;
        d=google.com; s=arc-20240605;
        b=jC8aZDqU4nyorPmjJXI0RFmNU+IVfSqsVB1RC2/ilq7kUisD09QqyWOLVDognugeOP
         pGryUeYRYarZuTP2n1hI2JJsT3HI/2sc0Kkw4sWCgH/eYN3S875kLZ+gr6JTiC68l7RD
         pe69zUzKS/kVrINCvf+e6I7+DBnKNiFrrYkiyxE7LXV9+Q6bAeYUF+Npew/QRXmtIt1y
         W1jz69U/hCV/jvQX23PBqEqkYfKlBwIoEAHonjUmNGMzwXGRmPnS4fnZfRV7WAKgFHyW
         21iHJbHkINRUE0GklGB0GwwpF2hwJaWzAe5e7ZUNb+5qDq9BRH0ckCT9MM0td07YcId7
         5iLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A5qciK2XKuSIynganoTam0yXavkG+do0UencOklTzeM=;
        fh=+yL8oMsRakimYuUqAzUG95owfjsZCM26j0i4RE34NvA=;
        b=KMCE8Sxg5zujjAm8e5zgswOve9frxS+5Vfog/bPsbW5+p1+ZiYeXN4/jzFtlVXBws9
         i5fHIg6l5K051zrJcstNEYqzicVd9yNbAOlbKZBmlzSYdDlRJ9WgRh0r/N1Zd7Ssyhn/
         lxtBoOlorTIN9ULeHbAndeH46vQiPo1oUnsDENwlot+oVPWKe2xv2xafQNg9s6cPf9qU
         wgwxm/eLk3qtwlqdT3TUxKU3AqonhrQXNd3UVfXmPgonNhpoElzhd8+9TTgXhteJNxtA
         dckkVpGcFh2fgHsR/KgLQBbud5dKgZBzsqUzAyIyYfzZ9+KZujA4HPSt94Fiy8OAsVF7
         prjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RYD16Z6W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730994456; x=1731599256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A5qciK2XKuSIynganoTam0yXavkG+do0UencOklTzeM=;
        b=Ua73MTwFy4LBDoCFTQwYambHtrAA77CFR9SNfdSydd0uchJ+col+9MI0RzU48vAipb
         cFcnWNpO4UP6jpcSga6erprwDUXtXfiNUuWM34PaPfVotBd/wkmGmIcla1dOGVXLHCxl
         Ad9W1Ey7sfoSLPyfJFfUNJj5bt8luY0taCka9jUm3ubblKYzTeB81NB4xjiAo8uPKrmT
         QEyjUPSj9J0trdRQ7+MSRKWrCAiNUjYHI/6OwEtUbGGrTSiiBYylil1j8IiyUUoh7O8i
         da9zy1BY+ZLdhClotRnd2mbvH2eCTMP7T9lFH/a4vuDC6DWJop45L/d2p1qxhU1+Wo+t
         wa6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730994456; x=1731599256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A5qciK2XKuSIynganoTam0yXavkG+do0UencOklTzeM=;
        b=c20X8EVHP8QG9ptT3AZ8qwbOm+wehFcipMdB0r5n3f1UZhPnvo76mZHo69XRiJ0ItY
         OUdNeG6gwYrGXRIpnkoBxGXouEm7U404OqtiPXG1ivNleDepTo9f/TxjtTbtefeFZVju
         s7/+o2Tb5CtiLARs5zwEjkgOMP+aQbA5mk9T249WPaF082TyluVSCnVZF4LUXmpmcfSX
         SX8TrWMmVQmaRIudw14PJg62Nt62dinsIXVE4/UBxLCbC0lfPHlBHStU2l6mu1vxYxIy
         vnz+/CbiIfBWeaFrz9slPacfhb6caFqu8G/NgEeawsmfINAC5nItbxKGH2Qj2z35IO7H
         CGsw==
X-Forwarded-Encrypted: i=2; AJvYcCWzH1+Nd47stYwBa6fQ+9QnlOaHI6atf5fTqGBdVAlcDW7cr7qtByke9tGnX59GiELH2798bQ==@lfdr.de
X-Gm-Message-State: AOJu0YxBGeTA0O72zIPEyorWHfDfWH3VD1Av5YLgonJTSPdQUJqi0rBY
	hwXtuZHDiFYFLL+7fr22zUoTvHNSpMNpRltuFoIw4b4PWtLJejcC
X-Google-Smtp-Source: AGHT+IGHru9omxSzsDBqpAys92g7VYXYtfrBzqp8iZNdMtHlDP52t/wONVvh8sOvoXIxvADAncfDPg==
X-Received: by 2002:a05:6902:1683:b0:e29:1a7f:2f9f with SMTP id 3f1490d57ef6-e337d15e633mr511916276.41.1730994456211;
        Thu, 07 Nov 2024 07:47:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:3298:b0:e30:dc1e:d826 with SMTP id
 3f1490d57ef6-e33684f17abls1317673276.1.-pod-prod-02-us; Thu, 07 Nov 2024
 07:47:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXK3C0THlIqjhjJTbF2gwfGWw/EH9D14blp6vu+mccZDVAZg2lL203KiYYh8JlcYHHViQrBtf2uviw=@googlegroups.com
X-Received: by 2002:a05:690c:6e90:b0:6e7:e340:cd36 with SMTP id 00721157ae682-6eadafb9a34mr4529777b3.40.1730994453827;
        Thu, 07 Nov 2024 07:47:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730994453; cv=none;
        d=google.com; s=arc-20240605;
        b=dYfKukkkdc3QwBhNKMpX9xSKbU6XTBkGhdnDYe9QPQRhzeC9slX6YOSpu7JFq/B5gl
         4d6ggVwXTHljm+Hh4vRmmsu4MNJatt/taRNHzSBRigX+gduOHgvdXbSX1GyHAGxh0B6s
         JtPSz07samGje7UyQ328WfkCNPcYowP7PNXcGz++1wRBW7AC7FEAfmQ/enGeIh/JGrPk
         0UyN1EdE4oz4cwudP3gus66oLC1z4omEMhnGrYfMKnFfs5KP284SxpMFtZoUQ0PiAhJD
         DPmDbYJfNPRRPI6KkIKtMebLlYSn78djrreEHw65Hkqm2BT/bbW7xbw/NByqpTKniCkG
         c6TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bj3vIwGn1S4kVdNYQ6mNujveZuFRmeI++CpgKvIkmVg=;
        fh=OvQke3BB7yjiqhWdjzOxejjxtFe7MFUMKQ+4uuz2txY=;
        b=lW++strXVj3lQZQBijEMq2R+TnlTrvcJat+0qAlE3ZLduIPIC13/P1/qM5FxvUsByK
         ZPCRSnsL9LTTCRILqIGT0DPmm5sdkj8nK4Kia7jJj/kKLOWux/OVVU1AOr/zGkf6AlVK
         zbqiKxfB1vyFDUrC30+ARkMVSE8DAVDjp27K5gV0zU39uqW/YDk63OqKWNBM2zU/XvFT
         zxCFLuELjJy4L4bU/k7w/jZtwvy8TeH9VRmAodmtHjf7TJWmod0KnUZ2PwDiE5BMHU/n
         Gj3y/F8XmThEmCnQYE2/ntk0UzGgHLz2vEJ3sP2KNjS65K4chEotto9Azrd+emu09N/K
         MvoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RYD16Z6W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6eace7a5e39si1001927b3.0.2024.11.07.07.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 07:47:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2e2a999b287so919981a91.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 07:47:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+S+I8FreejRBybo3TwEB08puau4HW26Un01TIdWZtMi7FHEyxXlePcpCeYuEWzjuwFIwFe1ne+YU=@googlegroups.com
X-Received: by 2002:a17:90b:2249:b0:2e2:e743:7501 with SMTP id
 98e67ed59e1d1-2e9afbd3778mr526668a91.8.1730994453173; Thu, 07 Nov 2024
 07:47:33 -0800 (PST)
MIME-Version: 1.0
References: <20241107122648.2504368-1-elver@google.com> <20241107103410.44721a3d@gandalf.local.home>
In-Reply-To: <20241107103410.44721a3d@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2024 16:46:57 +0100
Message-ID: <CANpmjNPiFxkZ6HPXYR0Xz0i=0p-ksEH4tC19fsj1fAwP1XkAjw@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RYD16Z6W;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
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

On Thu, 7 Nov 2024 at 16:34, Steven Rostedt <rostedt@goodmis.org> wrote:
...
> > +     TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> > +              unsigned long arg4, unsigned long arg5),
> > +
> > +     TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> > +
> > +     TP_STRUCT__entry(
> > +             __string(       comm,           task->comm      )
>
> The question is, do we really need comm? From your example, it's redundant:
>
>   test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
>   ^^^^                                                            ^^^^

Ack, let's remove it. I will also remove the "task" argument.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPiFxkZ6HPXYR0Xz0i%3D0p-ksEH4tC19fsj1fAwP1XkAjw%40mail.gmail.com.
