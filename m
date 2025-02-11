Return-Path: <kasan-dev+bncBCU73AEHRQBBBJVYV66QMGQE37UQB7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 513ADA31979
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 00:24:24 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3d060cfe752sf41442105ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 15:24:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739316263; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfWfLOW9qQEMq0omIxJL1geXmFRZhQb+AwMOGCacflT7CUdW4Z+pv3z3bpxMbJX2or
         SFjnWAeOLpXq+5yEvxx6pC7haBrlfHNn5Td8+7X67EOE0mW7TlMggerfeaZOsKHZkPYc
         /4l9mtrJmVzGNX9AhsuJ5zyiCKxTjJRamH7nk5+CWEqG+ShgYb63zFcE49kIJ2rzaoGj
         v930ATroTm4E1yakoADMPwLJeHkQ4sbChO/yvVANxhPycnvK7+mW55Ge7wNkbBZQ/KMn
         PiHGOfgutej7Zvp/KCXR4o8QqfXEaACk0YEpAF4VN7TgWZPZpi3/6+LlYVrm4zaHncXr
         64wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4/yZRlRHJmnnAOWGEF4chPZDU35JvEvUXhFOLeJdx54=;
        fh=TaR5/bYZZ83vxnuPl9tkg9TK8yj6xcaomMR2xz1ehxc=;
        b=Qcg1zrCBmY8MhpwYrgsnNMBLXbjqOXx5J+vP3SWhpnVoxtcv77BsgxXtSIqz+9ZzUB
         CK6yClKZDQvXulBQziZde2EjN2GDHLgmzbf38EiTqvYdrI8iB0akwwt9qu5GyNKsdpe7
         WGonv2SWpjWfFWYWo2YrGgQeHN5p741jDCpXs8R1n0e6azqCMeJGOYn976nK1aVXwksz
         OHHHfiJ2mCxNUT36DqkuphBoz3Ya3QNCd2dOdd+BdI0RZghiuTcigzuFu/xoXsa9VSwi
         bRBVGiwYmfP1qkxQ6Qli1QkKT0/TrSu0/2SIh+a36pzbuBGawdwrfx1l+SV1RHk8Lg3J
         qyiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6phq=vc=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=6phq=VC=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739316263; x=1739921063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4/yZRlRHJmnnAOWGEF4chPZDU35JvEvUXhFOLeJdx54=;
        b=GRxzm3COrxIZj/si/1VGVO4+bELQ6YbI6ondxbg8wNhxWPENNkEIeAuTVoTlUejmKw
         Rgs71lcif0oiVF2bQIeEhCfyVtlf8gsa9vsKqFEomGo1FJMydYvg5OlXt9Uu+8UkNuRx
         b+VOQCnFe7CS2ccmy4nNQAuCrCZ3a3PadIzd8LkYQWFglr9GCng07xYJVj5Bsl6Kn8Ga
         sk4vaUmGhcy2zu9SZNrAhFOiOq/+Dp4K+kybOXTcBwdJ0ZTCZUcDuim51/8Xgu3HGu0o
         M/TMKeJEG98NjUy8gDUqlnB9RbTvzhWIlAu4Pk3ALzJqmH660KNI7XTMQy8ERkNsa267
         pACg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739316263; x=1739921063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4/yZRlRHJmnnAOWGEF4chPZDU35JvEvUXhFOLeJdx54=;
        b=Tf7Qwy6iiAq0ADwnCTZQ8r6FEINGYxbfr8CCFIasJv62BsFRM6j48Oo2wtiNDjx4rH
         1XGLn5N4co67NWCl5NLBM/k2MhO/W/aDp+5uEjmZ+GIiprCmoIgRrxIZ5DZG8GxZLtBI
         BD6ZOirQpp2FMgYUsAv4L9h/sz6oPVcjPGqWRJ6s1/6tVfxu68Jz25W1YMtTJFmnLGZK
         /Y9GB+950KPuon8X0IK/Q1QCeglW0LLrwcglbrYQ2dcOzFl89YJT8cg2udfqHuk2QUBM
         vVQEceFtDwK4f+CROzNRjo33HrNU5pNETWYWWWxK05JsZaq5dRyMxK4B2l/vKIyaE2fw
         JggQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWc0FM2vtpWorz46/C3oisNz8kkci3Hh+rCilB9yFQLzPBfGUjAcRCLt5C2DdARx8ic+te/QA==@lfdr.de
X-Gm-Message-State: AOJu0YymYIQCaPbG0W9E8Q2z1VDd0FjteXN8at4tW3Is+Ca1FcTEXFbB
	+nCXGWOWFQryI+u7Oc921ycLBW/yRhfBqnqH/PAtjy/9rOp1YHAV
X-Google-Smtp-Source: AGHT+IHA608thA9ntYzr1okdOi7izeYkoWhj4hNXgbaNTlBlLtSwm2tk46R8DXmzuLURUiT5QCi7PQ==
X-Received: by 2002:a05:6e02:1548:b0:3d0:10a6:99be with SMTP id e9e14a558f8ab-3d17bf4afbamr10818435ab.12.1739316262938;
        Tue, 11 Feb 2025 15:24:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f90:b0:3a8:12af:5924 with SMTP id
 e9e14a558f8ab-3d13d6c8093ls15112855ab.0.-pod-prod-03-us; Tue, 11 Feb 2025
 15:24:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQKQAeTvZa0zqbDApNyCAFcW9EbfRouKieMIaYAxoVdu2/Xg5BYjgqzNoFoD5KbH36qfST8Y3mBa0=@googlegroups.com
X-Received: by 2002:a05:6e02:178c:b0:3d1:4b97:4f2d with SMTP id e9e14a558f8ab-3d17bdfa33fmr12109845ab.5.1739316262189;
        Tue, 11 Feb 2025 15:24:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739316262; cv=none;
        d=google.com; s=arc-20240605;
        b=WO421wrEC6ihv7+NqmhnqbwpqXHS/yAcfXgDO7gMwDbcDo6gDKr5lUINgoYFvqEz+S
         0zN9MNak4fqD9nyiZ/ta7+/kybFJ52nsK4zOR+VAxIS+O1khVq/MAed8gTlMN1bvZH1i
         gmtexmq4kI8GDU/xSdB36XCrPSn5zv6ES/3ew/E/bS0CI2XM4jEbU+mjNy9glEmXa3SD
         tDtBrwT2Za2VNPMLdkw1tSzILO7xsVrjsN3iKm+kc09arb+bHa4IOp+wXmtNEOuabthc
         amZGMp9OsVjaufNUuahfmvGZNLFL90JAIz1IeDqrzBtUzHh3aXV6g1wZWeAaCCKEzjjf
         SeIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=ewGDeMv/pYfdWn7SDkKzPPTuDjxzTx0RyOZv2BOYBtg=;
        fh=j0BE8IDK35vejh4/tA5J3DMq8Ihq+KdW/S/sf90Cd5g=;
        b=ev+NZTNUwr4fgnGbcCX6w3+ite5Jjk/fKzdbFcaj8ERQ2mMyeri4m38yX9sjCqrENF
         cjST/zdY2ZqIlQNRvl2cFp6EbyHG4HAqxUrAHkXMfuzOY9AIn1TTY/lLD9a2ArH37E2t
         dn0b24bhQmYFvi3MQmfm8yi5bLMTHgxe6aPEMjRQrmTr9M4/sXO1GENrlOTWLinWfiVb
         wf7KuKwkylDSUJA4oJpN7PvWzld1w88qQVo1/MinYcCLC30tcNuVOVMIK6AkrnbswIeD
         FMuZVBlGtwHhm70bNztkLF6iynqCC17HGsMShV1dfIAIllkNTfaUJhw6OvBo6SU3lGDF
         zH7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6phq=vc=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=6phq=VC=goodmis.org=rostedt@kernel.org"
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d05e975257si6272555ab.3.2025.02.11.15.24.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 15:24:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=6phq=vc=goodmis.org=rostedt@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 1F53DA40C7C;
	Tue, 11 Feb 2025 23:22:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BCEC7C4CEDD;
	Tue, 11 Feb 2025 23:24:19 +0000 (UTC)
Date: Tue, 11 Feb 2025 18:24:25 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Waiman Long <longman@redhat.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Sebastian Andrzej Siewior
 <bigeasy@linutronix.de>, Clark Williams <clrkwllms@kernel.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, Nico Pache
 <npache@redhat.com>
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
Message-ID: <20250211182425.01cf9a01@gandalf.local.home>
In-Reply-To: <20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
References: <20250211160750.1301353-1-longman@redhat.com>
	<20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=6phq=vc=goodmis.org=rostedt@kernel.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=6phq=VC=goodmis.org=rostedt@kernel.org"
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

On Tue, 11 Feb 2025 14:57:30 -0800
Andrew Morton <akpm@linux-foundation.org> wrote:

> I'm thinking we add
> 
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Cc: <stable@vger.kernel.org>
> 
> but c056a364e954 is 3 years old and I don't think we care about -rt in
> such old kernels.  Thoughts?

We still support -rt in older kernels back to 5.4, and we merge in stable
releases. If this fixes an -rt issue, please do mark it for stable.

Thanks,

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250211182425.01cf9a01%40gandalf.local.home.
