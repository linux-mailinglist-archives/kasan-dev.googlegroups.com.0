Return-Path: <kasan-dev+bncBCALX3WVYQORBMUFYOCAMGQEFPCIPAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 394243724BF
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 05:42:44 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id n46-20020a056a000d6eb029028e9efbc4a7sf2598985pfv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 20:42:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620099763; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/9OFaj0BG20/WrAhGLZAvOACCMeR3maBkReYWB+/5Ae17Vd08LedWDPMuBfgb2Q6S
         XMFKpNq7X/AtXEHEX/XRKV/B7zOo4Qxo+lA+rPLInCQdsxLOOfdYgBGCJxngeBHqyzhE
         ctM+4Z2BJ7Ls/P2B1TVgXvGozRVk//wO2VfK5GEeTYNguTEvbDYDb4rq5cZQtD1qmg3l
         i5Y+gv03ya6kGSn0j3/kDaGNwmcY+AUPP2A0SYsB8QinaZz5gK3kNODiJ7wQZjJoXxSX
         kKv9TKQTQnwpjwN/81JBePkpKtYaf7kC0iWl/H6Ht+VAVa/FPQfBrjsJMHVuBn4awEev
         usTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=dGy79FZO87h3s5oi7L9Z9VeCEWHPLFbLZQIxkIcLnyg=;
        b=NeT+LYQ9lvBQ9KCHsLKPTVGVKiqk9oA6FPDrMbZjPwhdDpOdPoA8WRg+ojuipKsqZb
         w9L7j8NGoIgXa+oxIFD8hwlve/0juKqdFdnIcDh19hFP6ku4U8OF2u/1ZnS/XVSc84U+
         d3Ab9Y/RZcHrO7Tqo24nuP4qFpnT5ZS3MLDfCGu62U+weFpXjEsz2TEf380sELgs4Td6
         EX1Eh4nWrX8CorjUIE2QovpJd+kkP6E+PwY+fCVqNzUUEleNlhbM83bnLgv3pfvdXNAp
         gEBwZlt+HPB7V9jXnKycuXnvDsVgTMUs5DoFuC2vBBE+cGdOZ2M6Hwm+mz6n6TitofEK
         RBDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dGy79FZO87h3s5oi7L9Z9VeCEWHPLFbLZQIxkIcLnyg=;
        b=kS37o0/BlY1RrO4echmxFyfwpLlW5rU7Ie5AB2q4OQ1kpY8WsB9YLvBjjqpskaLEf7
         lSvvGeHTsYbGHYcOkvYHRSSv522E3aZDTPx13B967GtSu7fVyJ2//dSGekmu3dZVG9Vc
         MTtowMaEHJ46VjNHBjFetxNH455nuoiLGbz7h5qAa7pBZEIFodpdFvXifoLYZtG4r+73
         q99kIdm/8iWtYIj1brspg3/QktklcpDid8dA72zYCN38CTEH8Smq9w7GbzV3WtNWSTwq
         F+BUuRe5VdQ58omvekCnsErc114+LuWQoeN7xFIV23Xgyyj38w15tPjXLw82J+bW+nKD
         Z2fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGy79FZO87h3s5oi7L9Z9VeCEWHPLFbLZQIxkIcLnyg=;
        b=d2iEs/xHCfEPS6Nzk2ZSa4qHYZ10YH8c6i5/04Mkrl8PZf4fiVrxN4NdlsgADxvbBG
         S7tWfPwbpW35u/Ssm0if724rlXRJrz4H3U11KXpcjm4aCE/AmpOpgPFZcUTKJz4NNvk4
         maH+sTMTv2sbK0h+EcPe2drT7wCTaNVMDM6uZskLSz+bLNsG3Nx2heqm7QM0JCkf5DaB
         3Q6qFZrzMADKr1AZg26RpF6jiDu3si2XJrAUBqUTqOjKPnlrg10AS6MLhETtBlKWlaUZ
         GsbEwGsBaOzTAZOpR99EZuhbEQThFWPm1uvyUpLB4S/3EjzMXAZKv35yFEOAHZGAhIA+
         pu3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uypbx1BLWpajGXUpF3u9iK5reRTris2KLikg/uKUhJkMIokhu
	/PTNN7Ack3Io0ZtCLNq639w=
X-Google-Smtp-Source: ABdhPJxxjNGoUV8LxNBW0W0m8BQKVOu0CnCC+opQMQlwbDrq0uB2/Y81fsdmuWog8eemmhEOscNBrg==
X-Received: by 2002:a63:e044:: with SMTP id n4mr21569064pgj.47.1620099762759;
        Mon, 03 May 2021 20:42:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ce88:: with SMTP id g8ls65319pju.2.experimental-gmail;
 Mon, 03 May 2021 20:42:42 -0700 (PDT)
X-Received: by 2002:a17:90a:c28f:: with SMTP id f15mr24467227pjt.30.1620099762022;
        Mon, 03 May 2021 20:42:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620099762; cv=none;
        d=google.com; s=arc-20160816;
        b=EItTaX49wgqjZ+MwrDOTB1kVehMakGFuvu4cqObIaNNGHeABlkZUkDTaMGfF1d9bHD
         WB25cFuF6oLaMVB7qEZ4JMAoHtSDb7OD89i0qCLfgLCn9j3YqRIg+mC4ow/4yfFKTKgc
         ChOc5sKcMzusd+cc9SIW/MD9AjjqcXxzAkKVqHWgKXH+fSEgOdw/ICbb6GhNufAPAMFE
         nV9Wz/uYd5264849/KxlzSUl7SZOCkSm/6zdcgUDiZz3zZHJc+d2KMgSqUIhLSEnUe13
         R3S+h4RBEW/heXiawdZT1lCtU8MnvU0ytv7IaPcqeiSLdOUBJ4htu3pdiNEanmyXFPmZ
         i9ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=f0ErGM57yT6fxWp/MYl8PxxH8cb0vpNroZN+Tk3UKco=;
        b=BD/rMp5I/6asf14dM6OO1QUP64XJcO5LT+i6meRCiMGgNdTyj4WXeuiGlhL3wtKkDE
         ygZA5rO5fQ2LPFUCMT1h7k6I3ql/aTRbzU7ancUa1HxDEsELyf7/XyP8shIPGmj37w4i
         cOlh82vaEB//XWmIWw+ahcPXemeMhnlJz+EO3HeBulfQp+WmNJUDEepEh5eT1OgG+bfg
         s9EbFWZuOoe7OVHkcRyCQbk63NZuJV+AQOqDLVU3+s8gaqROYgPdqLIRnCJYEtElCtAy
         1Avgbt9xyzZhU7hHz+X1HiUp7hNVE6ycbUuTtduDt/oyzEvHAOWcOVqMqOOtgiGeKl2A
         iczg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id x3si308062pjo.3.2021.05.03.20.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 20:42:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldlxF-000BpH-Gx; Mon, 03 May 2021 21:42:37 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldlxE-00ExZS-4q; Mon, 03 May 2021 21:42:37 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<20210503203814.25487-1-ebiederm@xmission.com>
	<20210503203814.25487-10-ebiederm@xmission.com>
	<m1o8drfs1m.fsf@fess.ebiederm.org>
	<CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com>
Date: Mon, 03 May 2021 22:42:31 -0500
In-Reply-To: <CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com>
	(Marco Elver's message of "Tue, 4 May 2021 00:47:35 +0200")
Message-ID: <m1lf8vb1w8.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldlxE-00ExZS-4q;;;mid=<m1lf8vb1w8.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18mY3qQVyc/DARziRPBgl/ZpXBERBLtEjU=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMNoVowels,XMSubLong,
	XM_B_SpammyWords autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4710]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.2 XM_B_SpammyWords One or more commonly used spammy words
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 657 ms - load_scoreonly_sql: 0.14 (0.0%),
	signal_user_changed: 12 (1.9%), b_tie_ro: 10 (1.6%), parse: 1.61
	(0.2%), extract_message_metadata: 18 (2.7%), get_uri_detail_list: 3.9
	(0.6%), tests_pri_-1000: 14 (2.2%), tests_pri_-950: 1.30 (0.2%),
	tests_pri_-900: 1.12 (0.2%), tests_pri_-90: 86 (13.1%), check_bayes:
	84 (12.8%), b_tokenize: 17 (2.5%), b_tok_get_all: 16 (2.4%),
	b_comp_prob: 4.7 (0.7%), b_tok_touch_all: 43 (6.5%), b_finish: 1.10
	(0.2%), tests_pri_0: 498 (75.8%), check_dkim_signature: 0.67 (0.1%),
	check_dkim_adsp: 2.3 (0.4%), poll_dns_idle: 0.59 (0.1%), tests_pri_10:
	2.6 (0.4%), tests_pri_500: 18 (2.7%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are possible
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

Marco Elver <elver@google.com> writes:

> On Mon, 3 May 2021 at 23:04, Eric W. Biederman <ebiederm@xmission.com> wrote:
>> "Eric W. Beiderman" <ebiederm@xmission.com> writes:
>> > From: "Eric W. Biederman" <ebiederm@xmission.com>
>> >
>> > The si_perf code really wants to add a u64 field.  This change enables
>> > that by reorganizing the definition of siginfo_t, so that a 64bit
>> > field can be added without increasing the alignment of other fields.
>
> If you can, it'd be good to have an explanation for this, because it's
> not at all obvious -- some future archeologist will wonder how we ever
> came up with this definition of siginfo...
>
> (I see the trick here is that before the union would have changed
> alignment, introducing padding after the 3 ints -- but now because the
> 3 ints are inside the union the union's padding no longer adds padding
> for these ints.  Perhaps you can explain it better than I can. Also
> see below.)

Yes.  The big idea is adding a 64bit field into the second union
in the _sigfault case will increase the alignment of that second
union to 64bit.

In the 64bit case the alignment is already 64bit so it is not an
issue.

In the 32bit case there are 3 ints followed by a pointer.  When the
64bit member is added the alignment of _segfault becomes 64bit.  That
64bit alignment after 3 ints changes the location of the 32bit pointer.

By moving the 3 preceding ints into _segfault that does not happen.



There remains one very subtle issue that I think isn't a problem
but I would appreciate someone else double checking me.


The old definition of siginfo_t on 32bit almost certainly had 32bit
alignment.  With the addition of a 64bit member siginfo_t gains 64bit
alignment.  This difference only matters if the 64bit field is accessed.
Accessing a 64bit field with 32bit alignment will cause unaligned access
exceptions on some (most?) architectures.

For the 64bit field to be accessed the code needs to be recompiled with
the new headers.  Which implies that when everything is recompiled
siginfo_t will become 64bit aligned.


So the change should be safe unless someone is casting something with
32bit alignment into siginfo_t.


>
>> I decided to include this change because it is not that complicated,
>> and it allows si_perf_data to have the definition that was originally
>> desired.
>
> Neat, and long-term I think this seems to be worth having. Sooner or
> later something else might want __u64, too.
>
> But right now, due to the slight increase in complexity, we need to
> take extra care ensuring nothing broke -- at a high-level I see why
> this seems to be safe.

Absolutely.

>> If this looks difficult to make in the userspace definitions,
>> or is otherwise a problem I don't mind dropping this change.  I just
>> figured since it was not too difficult and we are changing things
>> anyway I should try for everything.
>
> Languages that support inheritance might end up with the simpler
> definition here (and depending on which fields they want to access,
> they'd have to cast the base siginfo into the one they want). What
> will become annoying is trying to describe siginfo_t.
>
> I will run some tests in the morning.
>
> Thanks,
> -- Marco
>
> [...]
>> > diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
>> > index e663bf117b46..1fcede623a73 100644
>> > --- a/include/uapi/asm-generic/siginfo.h
>> > +++ b/include/uapi/asm-generic/siginfo.h
>> > @@ -29,15 +29,33 @@ typedef union sigval {
>> >  #define __ARCH_SI_ATTRIBUTES
>> >  #endif
>> >
>> > +#ifndef __ARCH_HAS_SWAPPED_SIGINFO
>> > +#define ___SIGINFO_COMMON    \
>> > +     int     si_signo;       \
>> > +     int     si_errno;       \
>> > +     int     si_code
>> > +#else
>> > +#define ___SIGINFO_COMMON    \
>> > +     int     si_signo;       \
>> > +     int     si_code;        \
>> > +     int     si_errno
>> > +#endif /* __ARCH_HAS_SWAPPED_SIGINFO */
>> > +
>> > +#define __SIGINFO_COMMON     \
>> > +     ___SIGINFO_COMMON;      \
>> > +     int     _common_pad[__alignof__(void *) != __alignof(int)]
>
> Just to verify my understanding of _common_pad: this is again a legacy
> problem, right? I.e. if siginfo was designed from the start like this,
> we wouldn't need the _common_pad.

Correct.

If we are designing things carefully from the start the code could have
had a 64bit or a 128bit header that was common to all siginfo instances.
Then the trick of moving the header into each union member would not
have been necessary.

Unfortunately no one noticed until it was much too late to do anything
about it.

> While this looks quite daunting, this is effectively turning siginfo
> from a struct with a giant union, into lots of smaller structs, each
> of which share a common header a'la inheritance -- until now the
> distinction didn't matter, but it starts to matter as soon as
> alignment of one child-struct would affect the offsets of another
> child-struct (i.e. the old version). Right?

Correct.

> I was wondering if it would make things look cleaner if the above was
> encapsulated in a struct, say __sicommon? Then the outermost union
> would use 'struct __sicommon _sicommon' and we need #defines for
> si_signo, si_code, and si_errno.
>
> Or would it break alignment somewhere?
>
> I leave it to your judgement -- just an idea.

I tried it and kernel/signal.c would not compile because a few functions
have a parameter named si_code.  The kernel I could fix but there
is a chance some user space application has similar issues.

So to be safe si_signo, si_code, si_errno have to be available without
having a define.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1lf8vb1w8.fsf%40fess.ebiederm.org.
