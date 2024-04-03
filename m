Return-Path: <kasan-dev+bncBDQ6ZAEPEQIPXONWWADBUBAUZ67K6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE9FE8977F3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 20:16:28 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-513e3ed9bc4sf101281e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 11:16:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712168188; cv=pass;
        d=google.com; s=arc-20160816;
        b=lR41ONtMdDimyTxSPiFPSaKy8J6yXRzVjshvFgMRCbvA1y0fyjuuhSl3AcxQUEHJsv
         H+FkAW0xynbtsp8QQQgKvmnO2hXypUvfAKT1Bv5+qr9iHb7t3DI+9oE5b2hUY20xLUFw
         /HA5e3YGAFQV+qXGWlVDpw6ZshmEQF+vDGq9KNMamFXo3l016PycrkZ+SBv7ywhwTxuf
         0cG9oGu5CS1Q5NX4v9iqNA4aLtIm3g/1OxbXWUhT2QT+eiJ/B77xd+ylqHO3RzapdFSE
         LMz9lxaQBIfwsDsTs1fzEa48A3cQapwpDhEYf2SfXwZ4e2eFH9XJRO5+vI7slubyX5dn
         FHcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M1GGtoYQ3seBjvHsJk9Zdl+NoZ/1fOkXCJcoHenTcQQ=;
        fh=ZFKzsWXCKJPK7923FE+Qa/rD+ctJyn8Jw29nEM3YN94=;
        b=oSsEkN5F8cQ2qJ9lH42jtLIwhz3SQc6LbHL6PO2gP/E0IUtNEososnM8cqLPlBKgKC
         OOK8mAbmEc+1fUrxNzSMS/6ctC9i8l6ywZr/ztW0u673uDJFZI+/2dXr6ilhiV4lIZFJ
         bmM5j84dc8OyL6759R05yqkwHfH/nRGIzZ48ua92mxLzxfL6+Vz9v3ZCrIzkxpr5oRZv
         8DJv1OQbF5ew8Gctln533FvvAv1yxebyYv7dHSfLI+1+6OF6KhuXnKa21x/u5AuMpYPe
         rhZT/XiHtpBRjncRCKh1BZ1b0mQN97HYsWv596ovqxGLAYLf2qXly5U050Isok7SsZCL
         Xi7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sleu5t8L;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712168188; x=1712772988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M1GGtoYQ3seBjvHsJk9Zdl+NoZ/1fOkXCJcoHenTcQQ=;
        b=OyZ5oDJX+Ec12fQ1qOEyQE96JIw2sQAJfh0ZDWysjpBbQ+YCSnr2iqA8Z03DTlS5AP
         yBpKf8ITeZQ+1FVzT2JwMresyqq49QhIo8cJgt9Q43NG/HyCeepkpGBH5OP3KMeejJy/
         GvvlVOAU9B+nkztxNKwjgyFYjLdgLWMFEWg7AHS9q8idJen+SY0rWpWmpoF7Jn/d1Jln
         JwYRSOYYdJYhGPaMKLqdaMM3snPj/r1F7fH16wazl8223/ghNhoW7wXLeirS8DjJUFKu
         sZQlBE9RMJdQxu3n8e7l0XE9Yt+i8Voj2shlPQ9qZEHh/gxjbB4Hrw6vFGHrPQoSD/3H
         rU5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712168188; x=1712772988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M1GGtoYQ3seBjvHsJk9Zdl+NoZ/1fOkXCJcoHenTcQQ=;
        b=oJStsXve6tJ3/QOaCt3jNHzjY6+Ez4eNhqcHF2w7cKtT5iKrPY0iFQT/ZuFjYEe/K5
         75mYAWHwhNXjEubCVEJ/46UmuxTqt0hdQ+NzJlX6SQ1VEh49GeS80qlTciO5lbn61iI6
         BkhW1Qk9fjx+RCdc+ttknRfyQ7Gxw2xi0w54kFq6VAILyQp0vmFFZx0KsfvKIUBsuekP
         qNOQPxMXcuxpCQ7t28Z26B9Rqv4DSBSDKr878eoV3zdJvZEDB2VncYjHxHxYGGPitQuj
         lMrleGD9NPtG/ZJZNdn2v41KCLwOYUbJowUaj2kLMpqb1HYz96wVUjCjsVcMkrYbM0NC
         9N7w==
X-Forwarded-Encrypted: i=2; AJvYcCVSVI4qs80xcbez4K9cwiUhYKmz64bFs6B5Z8lnximnC/v3wl3eLip5IdrzjCdIBd/LRGPHBrua0tL/JeFiiWCQSXJabbTS2w==
X-Gm-Message-State: AOJu0Yz4eJ9QXSzYCAPzGk+KCrDYlJzThlKiWWSMfPt70Cb0YpyRIPt4
	lqzQsJUx55ffqPAifRvsJQ0FdYWmbUFmcevp7L46zf7JvJJHjSlJ
X-Google-Smtp-Source: AGHT+IG2N0AYji5c0OzYCo/pCkL6qAKRDcBnzbRBLFfLfh89QF2mag60c0pYI1AorEwUDBjuGY50mw==
X-Received: by 2002:a05:6512:32a7:b0:515:af97:6776 with SMTP id q7-20020a05651232a700b00515af976776mr211611lfe.65.1712168187701;
        Wed, 03 Apr 2024 11:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f8c2:0:b0:33e:745c:47bf with SMTP id f2-20020adff8c2000000b0033e745c47bfls91342wrq.1.-pod-prod-06-eu;
 Wed, 03 Apr 2024 11:16:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWa/3Pb3LI6BH/zk8R/oNtIzZTIGTzIivfz/dnMPaBLnV68lO/cxWtorCrY/7RNBY7N41/JMNd3vbMQkmg8HsMk6Zz2GMK6IgESMQ==
X-Received: by 2002:a05:6000:147:b0:343:471f:fe54 with SMTP id r7-20020a056000014700b00343471ffe54mr188430wrx.28.1712168185434;
        Wed, 03 Apr 2024 11:16:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712168185; cv=none;
        d=google.com; s=arc-20160816;
        b=Inbi6W4Iqyd1RdleDVYQdM8amTn8/NW6a8iAyy09a/F7dImMK5vrHurVH2cFxxl70J
         xDC4x1NrbRniPWqA3Vg3uw5t4R6HmDnOoexiLsfIJc4uUgqBm6uV1z3USecf3NG23Cta
         4X+XYJtlCRU9WUzrHmfHlz6MVOQSO4XISN5tzxfnRbMJ83qBTxSiZB47QV3b+Yy3vULp
         09OKzZvOsowaxAbTD/my/t7r6KA48xQRi0fy9A66Izxhdow6c772iEsXylUm1gBnL0zm
         xvJ1kLdO6YEAv9IHUOUigDr0Jq+FdMR09z/v4AtS/zJPG+dhfwSUeVviBkGCP0J/E3Un
         Tq5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wNELuWdWa80XXRXdRCDWUU8putHnEOf7PvgbPFwUh3I=;
        fh=LqnZCLT7tWRIF61/Whki6Y+c8uwcVGJ4bAwR7x02WtA=;
        b=jbv+x48t8OTWVkGVgzwMWgX8QsMmh0k6S4nFR7hJLfAZoTnPYj2wVRvUE7IQTYm59Q
         GJ6bwu0qfNiBzu8sdBL9N7gOhTGEbNianHHF1EsdmZQc7DTGhVhiZuAFSHUeQgzDZ5B8
         0HtfzscFmAttKvb0bGcFi+bLN/ZmnpMgl/xFGGXzCM89KbsqZO/Q5S4v5ibsPlVbf4Gw
         qEPLmVxJFbuUnFWSFkn7ZGoydpGkN5QpFBTBBkK2ujlZNPfytTB4dDqBOekb33LAnlir
         ikuW2EdWIhw/1VFwkwZOMEFn1g4d2ZqP4v5GXVh/dwwqJsDd9xdQ5id5DjK9s+4T3Osv
         GbPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sleu5t8L;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id e5-20020a056000178500b003418013729esi398936wrg.5.2024.04.03.11.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Apr 2024 11:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-56e0c7f7ba3so2916a12.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Apr 2024 11:16:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+zYi+rLgg86qg3tzRTCZCF6EWFCOAvj65hNFcvpY/xlRZbS1Zd/eyCySFdzpOYABIZrHHOSyj7SsclOC/cyLL0uEVDceK0Mu4UQ==
X-Received: by 2002:aa7:d645:0:b0:56c:5a43:5a66 with SMTP id
 v5-20020aa7d645000000b0056c5a435a66mr236161edr.7.1712168184752; Wed, 03 Apr
 2024 11:16:24 -0700 (PDT)
MIME-Version: 1.0
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
In-Reply-To: <87r0fmbe65.ffs@tglx>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Apr 2024 11:16:12 -0700
Message-ID: <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Oleg Nesterov <oleg@redhat.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, 
	Carlos Llamas <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sleu5t8L;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::531
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Wed, Apr 3, 2024 at 9:32=E2=80=AFAM Thomas Gleixner <tglx@linutronix.de>=
 wrote:
> Subject: selftests/timers/posix_timers: Make signal distribution test les=
s fragile
> From: Thomas Gleixner <tglx@linutronix.de>
>
> The signal distribution test has a tendency to hang for a long time as th=
e
> signal delivery is not really evenly distributed. In fact it might never =
be
> distributed across all threads ever in the way it is written.
>
> Address this by:
>
>    1) Adding a timeout which aborts the test
>
>    2) Letting the test threads exit once they got a signal instead of
>       running continuously. That ensures that the other threads will
>       have a chance to expire the timer and get the signal.
>
>    3) Adding a detection whether all signals arrvied at the main thread,
>       which allows to run the test on older kernels and emit 'SKIP'.
>
> While at it get rid of the pointless atomic operation on a the thread loc=
al
> variable in the signal handler.
>
> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>

Thanks for this, Thomas!

Just FYI: testing with 6.1, the test no longer hangs, but I don't see
the SKIP behavior. It just fails:
not ok 6 check signal distribution
# Totals: pass:5 fail:1 xfail:0 xpass:0 skip:0 error:0

I've not had time yet to dig into what's going on, but let me know if
you need any further details.

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA%40mail.gmail.=
com.
