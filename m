Return-Path: <kasan-dev+bncBDCPL7WX3MKBBTNNTSXAMGQE2TYDTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4958502BC
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Feb 2024 07:25:19 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2196a478acbsf1327174fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Feb 2024 22:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707546318; cv=pass;
        d=google.com; s=arc-20160816;
        b=RiuQhaJthRYWLS0sDkg/CAb66YsvVA9Oc81ZJKDlCASQi7+NjXQA5i8T0/PRDmJhnB
         48v7dTbTUgW5dr0PrEQ1Ve3s87Gi9X+Y2Jy9AsLXeF9G7iyfae+6PDWgUrIyvpRlbGMU
         G/KSdhRo0v54crfy3pSKtkAgU0nlKNyFXYAfn5IaTo2sfQ3PVYg7prxATTRD+5EU2xvu
         3yB3xPOozLVU8I8ztWDteHeQ1ARhO+2IqqUX9CK7d3xwJg4VI7ognZTNJj+KfaOH0gOj
         OB/1fkGcFZsNSWjrDw31eisM6tVNQQUCHxZl8dx/gZYQDhtbNvSlXtJgMs97ZjjxE+A1
         go0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xVcOGOMR0dQBdDinOh8DlohFhlLF/yNqc34Llk6uTng=;
        fh=mEj4BvY0ExS8qAHloJDfWEJ92TC0gC665Pm7+1d9gMM=;
        b=aK5OXqaHbrdEdtSts6GdKJpFvoWLr4QmSSBHhhxkcfsFhqOdSiKznM/kew0+SBZ2Qd
         cBjh34xnjqGKt9QY7Oynlk2QQzGMGvKoz2fH1d1LGmtaOKeSrYdndWkGm5+0mDFWdoa+
         /F4A9oM9jZHktjgf39f97rfwqFLQ/eHnb/xPZoBlXaliVnptCoq9QXuQMLtDwl8bSFf9
         X4+J50wk4QC0tSgOFxxqjgoRCIuf696e/r/Bq9sn1c0j5kctDNn4S1nNaEx57yGZdIf8
         gYnJqaZeYLvjcYNtnI85jBNOkenikmHB2J6Sak3wXDOBeQZvGEyygtcsUUX2l20qQ+nE
         Tp2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ER/SL6vi";
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707546318; x=1708151118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:references:in-reply-to
         :user-agent:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xVcOGOMR0dQBdDinOh8DlohFhlLF/yNqc34Llk6uTng=;
        b=tYGYoVv8Qv2IcRgFsiKqVG8tWRAzRboUsV1uR+YiiKQktfpMogCQCu5JTm0yInO0Ag
         /tr74ilGBcDRVOFcKJT2KHU50oxU5vqW4GfenUFl6n+c6CD4er9098Xv2Rmopr+AIhNY
         F/GRD3TeyEL7FN9pZwT2es1b5QLKGWeGsftTXLWHuQ+o0356+6jj4fn+WNJadZCWhMQf
         dAo7Cr/SugFj2tZ1xMa/1Z/W6OMYr7kmq4SWCkkggi8tnaa+qP5dCBGn7IWl8NIhJn4D
         IyxYn2xkKYxwe8sWbyjQtQKHXLcC4736Cq3EQxY47O+D3a3JV9DurbgQP7E995Lh99hT
         7/fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707546318; x=1708151118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xVcOGOMR0dQBdDinOh8DlohFhlLF/yNqc34Llk6uTng=;
        b=Ccd6z8WJTRu/bfuixJ6tLDRKRnxQvbSq2l2V8rqudlzpwUb7JFOrtOEw3DJo2E13mb
         pnx3j/c5ucygadZ0cfJFrEdMluPeIBLcTKLCGI7y/10gqxe+9YBfNmeJYroyaKq3ACu+
         kQ+wkJOyh7oaeDsp4IsS4C5Ra7c3UZEnA1v3YDx8f/AbElZhbsTmxcRmdxX3X8LSY+uN
         CtIcbJkcGOaqy9NpuP2v6JeHyqRrOR2DuD4r59dvmtn/9vsSGeIcr/T81esQYA9TnWkB
         5cPq47vXzYuXoIR6CUj+Ype+T/q4bqajc04VI1nG1lphekWOX47ZZ3kIYWfbPU9uF1up
         HsGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx8sXbHhkV3LeeIuyitH47M6mzgKlmS2mUO1mYIP0NJXp3jCUlj
	QI+hOmxqYpDDH6YRQXSg9Pt1IIkUi6bzClMZCVHrlm60xT2u9XME
X-Google-Smtp-Source: AGHT+IFKea4gGWkTHL94Mar2sBTHjpEzYMC0ji5g9n+n0pu1T+8z8UTwJ6a0Ekttf1jVazhQueJN5w==
X-Received: by 2002:a05:6870:1f16:b0:218:51de:95e8 with SMTP id pd22-20020a0568701f1600b0021851de95e8mr1654092oab.14.1707546317945;
        Fri, 09 Feb 2024 22:25:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:718d:b0:218:44b5:2d8 with SMTP id
 d13-20020a056870718d00b0021844b502d8ls1952992oah.0.-pod-prod-01-us; Fri, 09
 Feb 2024 22:25:17 -0800 (PST)
X-Received: by 2002:aca:f07:0:b0:3be:984e:c7fd with SMTP id 7-20020aca0f07000000b003be984ec7fdmr1156902oip.51.1707546316932;
        Fri, 09 Feb 2024 22:25:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707546316; cv=none;
        d=google.com; s=arc-20160816;
        b=WApGf8xLzRAuvZ3/mPiuVPfetuodfMfqQGkYH+Xz417rG7kCi0hUYw68l93soHuwg9
         k10gTn0J/bgeSaBdeJYIP5CUoqSsE7z6eATqJpuICc0jIXGL195WtH4aU2jVpZlD/ZXO
         pdKLKQJEpt4yZpYPa1KPXuyOOCc8QTXCmU6NHKInNxKpPqeZmBurONgOAJfc0uHjd3Xu
         SssSkjscsvshtZl05aXlxDZAp9fVkYDIWtO9WC1ZZrOKsp01nadmhie2Pyi+SBtAhQOv
         ue9pVSk+3ZjDINWYG5Zp38JYH3UvcoM3O6ZUGvuWBT6Or0knWT5++W5K0PPpelrlS7Xx
         QTdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=Nzu/ZgyMawcFEr8BAtgEG1bRxe5yibFVGSLa+kOFCB8=;
        fh=mEj4BvY0ExS8qAHloJDfWEJ92TC0gC665Pm7+1d9gMM=;
        b=PiiXUvFU3AGbUpzg2ph2QQ+CvYYZhAjNPiIB9N2ORUZkSnfHdN+kb2sgYot9PuHlEV
         pVI7MKRkpUDK+6NUrCnH1lAQJ5JE+AgNoB88DRStATlIGj3poUYVMila774yePPZQKmg
         4IBIl4TXTx77Tiri4NDkMsgj3GTMRgFqykvwkhnLtsXarCmeyZUKrh3Q/I53LQXcbhtb
         ff9AcXPqDF1s0U4rq/y0lsb555fdmVjeeneom+LNc+Mow/3FRcG90lYJWtORteqjRUNI
         ML+jpIGI3ORlVFHgIPdEeqwmZ4GXhmD5mw2H67jumuyO0GPori363642knuaNKB6Y3k2
         o0nA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ER/SL6vi";
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCUYHnIeP7eLhiKjjXmKFg1Fg1w8p28Wi10OWCHTfsjAeiQOAPVDmSqCHnRmIxS3rZqtQvgqZXeoEiCkenm1yyITUlH7FuhMg79DpQ==
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id eh8-20020a056808274800b003bff43c21dbsi309085oib.2.2024.02.09.22.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Feb 2024 22:25:16 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 45498CE1A91;
	Sat, 10 Feb 2024 06:25:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8D4FEC433F1;
	Sat, 10 Feb 2024 06:25:12 +0000 (UTC)
Date: Fri, 09 Feb 2024 22:25:11 -0800
From: Kees Cook <kees@kernel.org>
To: Marco Elver <elver@google.com>, Matthieu Baerts <matttbe@kernel.org>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Netdev <netdev@vger.kernel.org>,
 Jakub Kicinski <kuba@kernel.org>, linux-hardening@vger.kernel.org,
 Kees Cook <keescook@chromium.org>, the arch/x86 maintainers <x86@kernel.org>
Subject: Re: KFENCE: included in x86 defconfig?
User-Agent: K-9 Mail for Android
In-Reply-To: <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org> <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
Message-ID: <79B9A832-B3DE-4229-9D87-748B2CFB7D12@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ER/SL6vi";       spf=pass
 (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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



On February 7, 2024 10:05:31 AM PST, Marco Elver <elver@google.com> wrote:
>On Wed, 7 Feb 2024 at 17:16, Matthieu Baerts <matttbe@kernel.org> wrote:
>[...]
>> When talking to Jakub about the kernel config used by the new CI for the
>> net tree [1], Jakub suggested [2] to check if KFENCE could not be
>> enabled by default for x86 architecture.
>
>I think this would belong into some "hardening" config - while KFENCE
>is not a mitigation (due to sampling) it has the performance
>characteristics of unintrusive hardening techniques, so I think it
>would be a good fit. I think that'd be
>"kernel/configs/hardening.config".

I would be happy to see it added to the hardening fragment! Send me a patch and I'll put it in my tree. :)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79B9A832-B3DE-4229-9D87-748B2CFB7D12%40kernel.org.
