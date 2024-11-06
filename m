Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XKVS4QMGQER3IBYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 64DC89BE24D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2024 10:22:56 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-7ec0d56d624sf6881502a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2024 01:22:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730884974; cv=pass;
        d=google.com; s=arc-20240605;
        b=fB/r/Gn6cT4JY7oDZl3AaRqRGTr/Qba+LnichF0FyxcKDwImgTha++mOXjCgfaOsMd
         JDiUkjtksG0FNX/5t4iB4vTTu102J6MpSFFDyLjnphX3M+ZcpGR1IAAr9ERx6eXqcZc2
         J+A3PDolUfrYK+5MupVomx4U4zBPDcJMo+hvQ4WO/zZ2MZtTgqzflunfDkzMKuoGgj6z
         kMKXqLweulOcFGqgdU7nufr0LAKR36B5obUH8I/u0YBSN4vlWHeLRp23V1orurMTRYdN
         SOcZYJUNuaw5aXRcBeyxoUEebI1Y79Rdi7fYXoFFjZUE/Yn876rvGyAT25GPoGGzYxyt
         YucA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ppJprUhrfVbDe+eRgJ0TLwD1n62JKJcCON2moPSCWJU=;
        fh=LvjOgq4x40xNpJc1Fih6IhLKGyY/Z1cTLag6798eyZI=;
        b=J/XCX1GRN515BFgELOgtz4PKt/Vynb8jaOmwGUErVsslybY6iSOPkE/C1ENj8F00xI
         ivRUo1GJVVigY7StygqA1n34f6UoquQwv1dHlGzA8eHbPhXOSYtXa+aIm0RmtG852ixv
         oi7odW7WjVlt/OgGr/NlvtXkWY2yJtsyVKtN9az2fkZLlTUFZ3E8gQAq4OVL3FGa4Mm5
         17l2RCCBDVU8UAUVuNJxU8C7SpbTpPJhpriM24DeSTzVXWjoxhmSnb7j843/gK+XMeO1
         xOH714BzfbsfKWiLmg9ndfHmQlSeWO6Q2lZk78S1FieYxJxwwkzNBka/CPwmqaMI1cfP
         z6JA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A90pzUzw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730884974; x=1731489774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ppJprUhrfVbDe+eRgJ0TLwD1n62JKJcCON2moPSCWJU=;
        b=s6Al0jm30EXCp/OP971XznlhhQf3KV4sCsSJHKSGwrlFCWiX1aJLZ+eDRWlgnMuYMz
         57rd91nnBQrNam+86H41hkGLBsm3v6/7o3PDwATLe6bcKLIPb5312c/nchbSlhImrCcV
         1Qz0GdQF7uUONM3pWyILeImmRbwOw9k7qSAbcKRli486SjdNOrAPhrjQHgZCKK2CFO8+
         AuZiXEz4bPnEzYWatV372Oku27foW6UkCIhe9UmoQs7p1BMxRq9mB7me4GQix44qKDfU
         TgyP971ogx6PxYa90jICXQTjVfGTVoT5cGpKaZcUgOiQKbT8K1eVbGEQxKJkEfhms9RR
         f6NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730884974; x=1731489774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ppJprUhrfVbDe+eRgJ0TLwD1n62JKJcCON2moPSCWJU=;
        b=swUaS9zlsfUKlkhKbv27Oct7pzF9c1QFnvzvzQpAxsAuZpZ4rGvq1vReV3MEStK3jp
         hDNO2V8x7/9CztDChHLwv/ZX9iyyZvZA8CFCZayYjfZGLB3IlNxyNK/PQE8PA4w9onWE
         YFLOZ/3s+wbJroNXJIXyMZtyU/UihfLiRGsPT8s1ibV9dHmFBWFL8ELWSWulzJQGgTMC
         /f4K6F4rT1BLAcpsopxpXTq1qkszRranFbQ4PRP1aZffL8w5oCXInajloMyWAsiFEpw7
         x+HTNrrnmnUyqF2+0IqsekDYxW3kp3PMDg9a5fjx133kb3l895y24Ex+ofsSHwrH4G+L
         e/oQ==
X-Forwarded-Encrypted: i=2; AJvYcCUvzur+80PWadBGy6i0oyaWpBKrckxrgETFvWB1DZy8CJSzdT9i1K35vXIu1s5wov74pmZ4SA==@lfdr.de
X-Gm-Message-State: AOJu0YyOhjgV3oZuPSp32l7aYnamtcCjyrW/cutdlNoxVqifZFfFZTrH
	cKAeiRPjeUF3r6/2h7SUHkFgA1fNHOY/QuLo54AnOUJviFwM3tcX
X-Google-Smtp-Source: AGHT+IHBGyz6kw58/vYlG0NcWC4MPhlYySh7GSqThtGrLrWXg9Q/WsXuGouI9jxXspgL7wtOsfu0UA==
X-Received: by 2002:a05:6a20:840f:b0:1db:eb9f:81c1 with SMTP id adf61e73a8af0-1dbeb9f81f8mr10414866637.6.1730884974382;
        Wed, 06 Nov 2024 01:22:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8984:b0:2e2:840e:d4a7 with SMTP id
 98e67ed59e1d1-2e93b134845ls4328369a91.1.-pod-prod-06-us; Wed, 06 Nov 2024
 01:22:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXrJmrkaPb4L0QMdOd+WqJO3tNKKjdqtyAyijo3s8Amb6zx8HNKN3mQo1jo2UEvCeeNoy/Zxth6x0I=@googlegroups.com
X-Received: by 2002:a17:903:11c5:b0:20b:b40b:3454 with SMTP id d9443c01a7336-2111ae2bebemr221611195ad.0.1730884972658;
        Wed, 06 Nov 2024 01:22:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730884972; cv=none;
        d=google.com; s=arc-20240605;
        b=CwH6LLg+/9PJq2ZVRfU1WlBscNaAmYRs+CMLd/2wJvn2lBo4i6p58YG0J8/j1/v3Vf
         8f0H6W1G4O4+DoYE6x7mDMmB5mZLVGMSEJ9WUzdH7UVAmjNOx3dgMI5Y2PIA2z2xhhvh
         WR8Xd0IVOuC5ifauJH/kqpp3edA94cXV4rI+qIzbnUIoCf5Dg4rozu8C7AwX/MvIkHWV
         1kH26tfHqQ7t7kVQeJdek1+ExMJ5sRZocSvowRrOaZ80EqBxsKBwxiCLZat0mexn7yZR
         PZoEFPsLPfk5mm9CfcficZKX8gQFNrM4bDVwXN1Mx3rU9WewkPrttysRAB+t7PAnXsKX
         fujg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j1zaLifxSHG9dqHGVi3lzDCXh1QBtGfWizelzPv1KKI=;
        fh=J9D6ry35r9+EHtu6lzPoBmypAHyAbwYfZki9eYp0Ht8=;
        b=YZe+cehjpVhkHPckLvZLFe48sgOIDTX09cYnjYMPxTE2Ge8K2v9o5IzVIDs+bTULOV
         21OQ2n3HfdIQTVFZK1Ev32JGBwzGy9OcHXkBerMkBB+HYd7lXFGPYzEw6yeaguugllpp
         IGmgFtBsTcXaDYzfIniDsaHXyPGYdwM68lx0gcsVpqApPFNjSLC2wce4cqpkg7L+uREP
         LnDJ51+UQS2HycgmzCgjzlVib7dZUs18E8CF7FtpdmyNyC4BsODXwEKuAUB6lM1QTu7q
         i4zvK9PjVoNI9dBlaMrXdZlDMbEucGqeIQxjolyfEI78AIftUgkCxqePCC2vOd4nlvx4
         7YjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A90pzUzw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-211056f05b2si6009415ad.1.2024.11.06.01.22.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Nov 2024 01:22:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-7ee11ff7210so4570144a12.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Nov 2024 01:22:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVmylTEQJrK75G7f5OHgb4bcWzD510wRGfFOUv8PgzLAOlHkYTKsfFS7O7kMfD5gx4Fv50QlNz5mIk=@googlegroups.com
X-Received: by 2002:a05:6a20:d48e:b0:1d9:26b7:6ca with SMTP id
 adf61e73a8af0-1dba556fbfemr27874210637.45.1730884971969; Wed, 06 Nov 2024
 01:22:51 -0800 (PST)
MIME-Version: 1.0
References: <20241105133610.1937089-1-elver@google.com> <20241105113111.76c46806@gandalf.local.home>
 <CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
 <20241105120247.596a0dc9@gandalf.local.home> <CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
In-Reply-To: <CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Nov 2024 10:22:15 +0100
Message-ID: <CANpmjNP+CFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE=fqN=nhL8FEA@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=A90pzUzw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as
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

On Tue, 5 Nov 2024 at 18:22, Marco Elver <elver@google.com> wrote:
...
> > > > I'm also surprised that the comm didn't show in the trace_pipe.
> > >
> > > Any config options or tweaks needed to get it to show more reliably?
> > >
> > > > I've
> > > > updated the code so that it should usually find it. But saving it here may
> > > > not be a big deal.
> >
> > How did you start it? Because it appears reliable for me.
>
> Very normally from bash. Maybe my env is broken in other ways, I'll
> dig a little.

Some trial and error led me to conclude it's a race between the logic
looking up the comm and the process exiting: If the test program exits
soon after the traced event, it doesn't print the comm. Adding a
generous usleep() before it exits reliably prints the comm.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BCFijZ-nhwSR_sdxNDTjfRfyQ5c5wLE%3DfqN%3DnhL8FEA%40mail.gmail.com.
