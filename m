Return-Path: <kasan-dev+bncBC7OBJGL2MHBBONJW6PQMGQEWQD7HDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC77F698D85
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 08:01:14 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id n2-20020a9d7402000000b0068d96008314sf573653otk.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 23:01:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676530873; cv=pass;
        d=google.com; s=arc-20160816;
        b=El1OR3kIXpAlpDPUlBWFDbj+NZznl1L7dUV/gkg0TRV8h8IRcD8cV8/pHUUSeJjbpD
         i3UTEGchoqkSQ1Eib7W/zYO7zJp9WJyy/KJu1rOThU8V+U9EPgYvGPSyN4Nj7/CW4Sa8
         7WBu/nbhy58e5P3B/GQLWSyQBHFqe58nYt3D89rQZRUIjVgHq9flx6tNTm1g/Y+lk1tb
         Rj/P+vVI79vyABQpq+KK88Hvz/1sEwpaLdyYfWQWct6YyNJ4dlwcbRmmi8a/cxZvBjo+
         OAc2t/jT0q+USX40kTrlecPRFo7IoBoZ57L4u7BxGG6V+cUl5XXspIevuheHFXbCdRbj
         n+LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HDz/eTefKS5AYS+9r0kXG8mNl/Ys+hzOhUWD7ZKb/OA=;
        b=OUkaGWUj+qIN7S4Soe40+TAv11HbTuIPMsv9vUxznVJPeTkXBvCRZcpQfMUBRrc7+A
         sKSXe30zPpEhY8iCK/C4ot/vEU9wd74ZzAQ/JNzvpre1Q0U0XB1Mg+IEExyHtSlprgVH
         cQdHc40LlGT7ESoX0ymuEvjgCGDx9QJgDaUCkMy+dCeZpe4RFROOY6unvwnIZxS7649z
         yvagS3kt94YX6yGKDSS20wxY88cnUZtktKnHKgM1Rb2MzE/LARpUau33ZDfC+YMC+C9i
         1IyBjoKXTn8ZmlHOUK0SGERIpxPZ4kioJsuUGjqAxNZhOBCRb4VIV6tIsIaOY5ZKtvth
         a8KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LXLuI0lu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HDz/eTefKS5AYS+9r0kXG8mNl/Ys+hzOhUWD7ZKb/OA=;
        b=qsLFLFKYiCKGGPZ5JH6JoWCplSMeJiWTlY0hRH7aWSyqN+Itns41/abeSwusOWnIYu
         8JUs9KUN2nRn8tDaLGN+KgR5FjfaJAg9T4iDhSKaL7DU3nQIVWX1YfA3fXwvYycMKQgo
         6GHSuRh5Emj3OIVkrmSyia63DKCk7zpfq65EKP7iKPkevjDmIUGMHqZ7HL8xj7H+l7UR
         TAu7gFIz45IQHA40CurOqjaXY3fz06cop4Gtt/PvedMqIJQ7tSXFS5rtOVhQe7HoygiG
         orc3nYyPl651NCmbGdXx0VXPKmNxhaf2qR3V7O3cCICnAr3uMFuB3U5rnssPH8pgxMQC
         Urig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HDz/eTefKS5AYS+9r0kXG8mNl/Ys+hzOhUWD7ZKb/OA=;
        b=WlBfLRwjD+6LjXt+L1nsOruZgni+jfHmodmm9UXhlAf30pXbxAtw0WTohkRqd3ravW
         y/5tP6WIvoxJBx6gEz1lzqfd5JE23cdJ/GpwWMYxntcMZmtHtDq4hsPkxeNuGOLYBzTP
         6RET8sALJ8lNZ+DfPDLiRFZkFOa38RHb+bZ7ZYsZVgvC48KgC/r7uXFAi63quz7slqw4
         7K6G9gJbGNC2MydGavd9uodt6mPUxAroKJK7GRNRuu+fy/oFBQKCGXCMcqhQcjCjiHhH
         ZFw2ZPpgETzRKUrZgXWZ0LxT8CIz536hrVwb8hJ2CIDsAl8lb29nvriVPJ2ytDLfXlgZ
         s+Yw==
X-Gm-Message-State: AO0yUKWc9WLON5aTzBBBULxuqgzGVjvGnwbzLnIxFxYweENItAW2c1TP
	bi++R9/XYOXcmP/wUWf/7pY=
X-Google-Smtp-Source: AK7set8kmPffpGHjILqVA2NNeoN6mpz0MMSA5bGjeZvh/XJxCejtrvWxQS9StXqtpfBi/w0rcGuqsA==
X-Received: by 2002:a05:6870:1683:b0:16d:c60e:4cf7 with SMTP id j3-20020a056870168300b0016dc60e4cf7mr108354oae.127.1676530873295;
        Wed, 15 Feb 2023 23:01:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2aa1:b0:688:4e67:4290 with SMTP id
 s33-20020a0568302aa100b006884e674290ls119493otu.0.-pod-prod-gmail; Wed, 15
 Feb 2023 23:01:12 -0800 (PST)
X-Received: by 2002:a05:6830:124d:b0:68b:e5da:4201 with SMTP id s13-20020a056830124d00b0068be5da4201mr2473260otp.21.1676530872787;
        Wed, 15 Feb 2023 23:01:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676530872; cv=none;
        d=google.com; s=arc-20160816;
        b=EDdA6VyrAwJWBOw2YeTO/GSLezvNXsGkd3y00qHXJgHimrT88s/5+tpYYda2dlooSL
         exwdZWvmefFFbYbTQlNGPIRj3CTP5VmDrJHT9VxsLC9tTmYhku2v/Lprm4C+4eIVJ30r
         y4GXPC2r6hhL5ogt9EIik39QmKeVOQp78NuKqbCWs6r3fcXC5VPAjGZ9qGPsWa/gZuzj
         ldCYrooiA+rvB8kenjUDa1e+tfafTspb7++Wl89QcvTQr+ngid8MMCcPljIgw5nZt28p
         qjOPmbIvmaUimEUdzKdrYYKNcb7SqnSmRcAn4W/pPGVaDGHWnh6IX3jThX0Fwr7y0knn
         s3+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JiWCeaDHu0d2DzRL5Q2rZ6Kr6gE5UVc7HS7E+8OLbNo=;
        b=kz5f8HzKxev9ZUnk/uesf5IMPOf6hY+mqiwaamo4SEzps73gUKq42pMiw3NmLRL3pQ
         FWWFlnMxOD0FPheRU9hqGG/EsOWQNt01J8cW76h/wEi1ol1EEIqi18rePsebT4zU0Tox
         J3CpIYH0I7bAkFzBK41T7eUZs4mYiBJrnxOSVnDcAYOY26fyt/9NBLw6/0FJOLxqchWr
         RtoTydgXfinjDKbl9l3UOxDM90Kn3VNI2YmHCGFabd6p2LH8nrL4mQ8wqm8Ixe/TBtrC
         ivcr+JR/rC4VANpTdWquTpJXDPf+7b6Pmnm3E2yhBRlz2kClEmxvq9L/zRhO1CePvFZg
         YhTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LXLuI0lu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id cc6-20020a05683061c600b00686566f6f48si120875otb.0.2023.02.15.23.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Feb 2023 23:01:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id d66so964331vsd.9
        for <kasan-dev@googlegroups.com>; Wed, 15 Feb 2023 23:01:12 -0800 (PST)
X-Received: by 2002:a67:70c6:0:b0:412:2e92:21a6 with SMTP id
 l189-20020a6770c6000000b004122e9221a6mr913571vsc.13.1676530872160; Wed, 15
 Feb 2023 23:01:12 -0800 (PST)
MIME-Version: 1.0
References: <20230215091503.1490152-1-arnd@kernel.org> <CANpmjNNz+zuV5LpWj5sqeR1quK4GcumgQjjDbNx2m+jzeg_C7w@mail.gmail.com>
 <78b2ed7d-2585-479f-98b1-ed2574a64cb8@app.fastmail.com> <20230215224218.GN2948950@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20230215224218.GN2948950@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Feb 2023 08:00:00 +0100
Message-ID: <CANpmjNNz30RQMfX0Bv+hobdUp+k_jHwH2WniQj4g+b48tsoR9Q@mail.gmail.com>
Subject: Re: [PATCH] kcsan: select CONFIG_CONSTRUCTORS
To: paulmck@kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>, Arnd Bergmann <arnd@kernel.org>, Kees Cook <keescook@chromium.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Miroslav Benes <mbenes@suse.cz>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LXLuI0lu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 15 Feb 2023 at 23:42, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Feb 15, 2023 at 10:48:11AM +0100, Arnd Bergmann wrote:
> > On Wed, Feb 15, 2023, at 10:25, Marco Elver wrote:
> > > On Wed, 15 Feb 2023 at 10:15, Arnd Bergmann <arnd@kernel.org> wrote:
> >
> > > Looks like KASAN does select CONSTRUCTORS already, so KCSAN should as well.
> > >
> > > Do you have a tree to take this through, or should it go through -rcu
> > > as usual for KCSAN patches?
> >
> > I don't have a tree for taking these build fixes, so it would be good if you could forward it as appropriate.
>
> Queued and pushed, thank you both!
>
> Is this ready for the upcoming merge window, or would you rather that
> I hold off until the v6.4 merge window?  (I am tempted to treat this
> as a bug fix, thus sending it earlier rather than later, but figured I
> should ask.)

I'd consider it a bug fix. If it survives the usual -next exposure, no
harm in sending it as a fix.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNz30RQMfX0Bv%2BhobdUp%2Bk_jHwH2WniQj4g%2Bb48tsoR9Q%40mail.gmail.com.
