Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZP47KDAMGQEF5XF6DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D48B3B9CDB
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Jul 2021 09:21:10 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id h5-20020a05620a0525b02903b3faa7e1c5sf6153417qkh.7
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Jul 2021 00:21:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625210469; cv=pass;
        d=google.com; s=arc-20160816;
        b=czHAavk8AMcU5eHrBkfQNb3gio64ZyjrkaHxjqLIofcjRlqttdPYai4+NFKQ4mIAU3
         VtvhLAtiA4ll6PUqwfG+f+R4Cqvdb7idrddP+T4pTSQjsYLZOzx14gXqVRUuYWm7jfOB
         dsf/hdZacSfy/xvij0XE94o7sMakm81KXBBJ9XzEGighBjpIpT91GxdzzhXxnCTXBqw0
         5oCjHiwu0cYhz9iUU4fSCshWsILlIu2CjquN19wR5QKFF7VJ+IQzmBovBEXQfaeYlr4L
         8scweBxRHZK2jcvz5c09nyPMZKRbIrvtpfvupWlrfPwK4CC5SLdX87biRQKMU7mQietf
         kR6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jIBj9VeVoVrU4C28l3kMMSm17DpIQm02IF7qBn9R0+w=;
        b=dHtGTUGZhkUxaR5c7dAdkepqoiYMeMOPLvoMddABlLJcJ9ZOAdm/Qwn4+BV/wRvUE7
         ZH44Zlzt1F4jzKBkW533WyVE+9RQMKeWY5s+KxDjSYavWuj1+11pTbyZCxgJTyb6DViA
         pySOkTcXIjoN73vnB8SmD9XDRsHsdkAaMEeLAy0K6NT9cCB8tfAMpr4tOvm9H/88cZD6
         XNUMvVbJakhAo+BLCUPdz4vXh5iWgEmE/yB/zmO/GnqvYUR4Wrrd1FC4BuioGZiFWHmJ
         h6Cw8eRX/PABPwLD3BLzvGydExN6IYSNJxkjDwN6Wrt4WzjCBB11xWhWSCfn27J0Fm2Y
         km0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JC7b7TxA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIBj9VeVoVrU4C28l3kMMSm17DpIQm02IF7qBn9R0+w=;
        b=Q58mnDxd5ffGfAXOK/ozaAZc4/HVtBU94ZG2pZ5uoATGcQToFs2XSbZZuO/WcLj3Lt
         0JcP5VAKzZ8BVBqTSe5KFkmrIlxWgPN1x+3e/mdxfTiqbvKsSMbz+G5sQl/M8Uiwr0lV
         IZVI/rWfg8jlHNbhQzKkEXOVXqcPWH54nWOfQhDcz44hWLoBAGSjzYXEXbA2jAitUdPV
         /f22p4liXs85XHOA2o8MMl31YRy41Hoqqx4z0Gwt+2Z6A6qO+PNc9RXcG+j/cb76e25k
         PV4hcbpZET3R7U8jSaeIH1L3q+EIQJRN4xBpH0FWLx+hr6I3T8AMQCW+Go5aho/DYdxe
         8c+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIBj9VeVoVrU4C28l3kMMSm17DpIQm02IF7qBn9R0+w=;
        b=LVO795mlys9YoEk7QSCYPVl1uIfWgGUg1EcW3yp177bUuW5mQqyfj2FsbHNqU2s0gU
         Gy6OQgGz6zYs66o/SYtITBtBOUq7ESdw0tNEyyStR8LUYHIdT9eIr00h8OC8DhuNXgta
         fDg0yukCNLzN1lFutUtsHFsdDmev0HhE5J9y1a6Ye1RQp3UQvnCPCIKO2VPZ5pwQx2lX
         to6STHZhjh3IvaLLuFxMsWgtrfrrpB83QuNmcoV1WWWNxDJZWRCzBclx/wp7lQ2/PNBZ
         CuzN5qaw7Mo1wp8Wxha6FpQKuSiVTpeLCFW7Lmemk0FGIgWo+Drwz5uUChEkA2swRBD6
         hsFA==
X-Gm-Message-State: AOAM533xzcFc+rgtGq4ZkUTiH1x4TnaFCrPHbcc1rMx2JW7NiKsTENYv
	IPDhCtTmDvsfo4u/93489ZM=
X-Google-Smtp-Source: ABdhPJzAHd48guy0vPk+TyWD6B0D6uPlA5r8obsBKZnvBoXzHSuZVZNwazJb/NgT+4Yo8v03oqRVnQ==
X-Received: by 2002:ac8:4d59:: with SMTP id x25mr3698216qtv.175.1625210469231;
        Fri, 02 Jul 2021 00:21:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:695:: with SMTP id f21ls5367057qkh.9.gmail; Fri, 02
 Jul 2021 00:21:08 -0700 (PDT)
X-Received: by 2002:a37:7844:: with SMTP id t65mr4057680qkc.429.1625210468797;
        Fri, 02 Jul 2021 00:21:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625210468; cv=none;
        d=google.com; s=arc-20160816;
        b=qlaFUPk92oTGAKrCL7JFSafU25yJMjNo/C+tPDRI53+qkOqVl/gAeCCT5q7V2RIW5s
         3DjUwOVv061AY4T5RbQQBTRaha1IGNUC0MA1r1WV7l6gu1orIktTZKrrnmXWu/zkLILN
         ZV8HYWA2tiD5teguMbxlFifqDjYhZTxK4/f9i7Ytsks6/iyohIDiStmUzpZXmEwaS3lk
         wo3/YefOTYIxIE6DqiFBn64VCSuwM98iYwwm6TNsh/EvDBLesgtjurpvQgbOV5eS2BdZ
         LA1fGuLk/x8dBQKgQXs41KC5wMOF9eq8xafJiM2DFAZ3mC4Ukh1IxDtikgiLDX6eOGrY
         YPzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=irzywLWlswN5yWOuh85DPqMNyXrjycgbBXoyqQ4WPFg=;
        b=MlLP6UX8EX4WTce6O2Vn9W15+L9/zIipD54FhiSs4wXMTrU0V78nEihTZWrJUXyPH1
         YLC16pIo0rYvJdlffFmPXKV16zS+EmkRB0cU2Pm1h7REwFR97okCEWJkpG7+Z6PersDD
         p+oDirdC5m9uqabpFAW2+4V03fQlBuejTh4HlOC01A8eptNdqsT5bXHjQ2S2WJoui7jp
         hAR+cUKzl+Vsf24g5lOjN8qNbxxurhN/NxwCw7w7+0sDOMw+axEQV1hfZQq37dw95j8n
         FBC1Ru0HYCDkc0YMo+MLb+eTSsQ2PZtcEPwGWblCEBcm1bLyUUYgi4mkb3MLLXofv3yK
         N5xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JC7b7TxA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id g9si216949qto.1.2021.07.02.00.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Jul 2021 00:21:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id a133so10259746oib.13
        for <kasan-dev@googlegroups.com>; Fri, 02 Jul 2021 00:21:08 -0700 (PDT)
X-Received: by 2002:a05:6808:210e:: with SMTP id r14mr2100654oiw.172.1625210468059;
 Fri, 02 Jul 2021 00:21:08 -0700 (PDT)
MIME-Version: 1.0
References: <20210701083842.580466-1-elver@google.com> <87h7hdn24k.fsf@disp2133>
In-Reply-To: <87h7hdn24k.fsf@disp2133>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Jul 2021 09:20:56 +0200
Message-ID: <CANpmjNMtK53SiZwm0N9VuwGJthY0unZ_1_mZ=gXdMH0_LAFr5A@mail.gmail.com>
Subject: Re: [PATCH v2] perf: Require CAP_KILL if sigtrap is requested
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: peterz@infradead.org, tglx@linutronix.de, mingo@kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, mingo@redhat.com, 
	acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com, 
	jolsa@redhat.com, namhyung@kernel.org, linux-perf-users@vger.kernel.org, 
	omosnace@redhat.com, serge@hallyn.com, linux-security-module@vger.kernel.org, 
	stable@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JC7b7TxA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Thu, 1 Jul 2021 at 23:41, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> > If perf_event_open() is called with another task as target and
> > perf_event_attr::sigtrap is set, and the target task's user does not
> > match the calling user, also require the CAP_KILL capability.
> >
> > Otherwise, with the CAP_PERFMON capability alone it would be possible
> > for a user to send SIGTRAP signals via perf events to another user's
> > tasks. This could potentially result in those tasks being terminated if
> > they cannot handle SIGTRAP signals.
> >
> > Note: The check complements the existing capability check, but is not
> > supposed to supersede the ptrace_may_access() check. At a high level we
> > now have:
> >
> >       capable of CAP_PERFMON and (CAP_KILL if sigtrap)
> >               OR
> >       ptrace_may_access() // also checks for same thread-group and uid
>
> Is there anyway we could have a comment that makes the required
> capability checks clear?
>
> Basically I see an inlined version of kill_ok_by_cred being implemented
> without the comments on why the various pieces make sense.

I'll add more comments. It probably also makes sense to factor the
code here into its own helper.

> Certainly ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS) should not
> be a check to allow writing/changing a task.  It needs to be
> PTRACE_MODE_ATTACH_REALCREDS, like /proc/self/mem uses.

So if attr.sigtrap the checked ptrace mode needs to switch to
PTRACE_MODE_ATTACH_REALCREDS. Otherwise, it is possible to send a
signal if only read-ptrace permissions are granted.

Is my assumption here correct?

> Now in practice I think your patch probably has the proper checks in
> place for sending a signal but it is far from clear.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMtK53SiZwm0N9VuwGJthY0unZ_1_mZ%3DgXdMH0_LAFr5A%40mail.gmail.com.
