Return-Path: <kasan-dev+bncBCALX3WVYQORBFOP3CDAMGQEZYSOMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C6EF3B490C
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 20:59:35 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id c5-20020a17090a1d05b029016f9eccfcd6sf6123618pjd.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 11:59:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624647574; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rm1RCV87rBMfSyqg58z08bMER5LyLT418tEiGS3x5Fup639r3P9OvgaqE45Ute0Vu7
         WQe5kxYBJ4cWniPgffEGZOJVzOgbxnMwAVcUQRcXZup7r9gv/iBunVNrkwq6FB1awQ5H
         ECvmA3x9SqU0RO2xmj4eJXgb7w5U63OVeTXj4nBoQzCdVSlKywww86DbSUOHrNJsKpjg
         xoQKUIpmFQFzmPUrOFLImDBvdHfiIToFOT1gBLjdEMOeHcGrCjwwooJE7jCesXjfQ57O
         vzPyWZGvWM1UjbJLK1wSbBWD2FXtAQV/qCcjWto+kHMGL+5D/BVl5GqJVa9NQAch6Ve9
         6Yww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=cysLW96AC0cjLaxw9PU4hRVjeTxlzw5c8hEsFYzQAWU=;
        b=OegYVh0CbiLRRQDGRnHlQc1VaIWyepub7cBh+mEWyuwnAyZuzXIz4l9I0Gk/dfXIDF
         f4bNGU53OW/VaxtSiD3yPDLMOEiu0KqE4rKyfvkjYJNIOXp6UoSQ4I0kKnqP29DbuFmq
         LNwbdD49BezBWTdtBnOFsgToJ7tSVqjnZ+9lNtE/7aOdl6WNjSzir6SLrVSiRqJGabBB
         XIMSdtQdVlvydlyRSmdmsFHb4oxRDn7sN4ZHzGxRbS6U4Q6cYmLm0go3GrU96Pgp3DJe
         LCP8vSiIa823nhEu8DM9Y49dvv5YW07ktCM7UddffAGwySrI/Yr1WgKoHf1i4R1JnoSz
         2S+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cysLW96AC0cjLaxw9PU4hRVjeTxlzw5c8hEsFYzQAWU=;
        b=ak/Sn6Kk6RQT5mnzE4tihV8JPNH7jrT8bAY4jPo4zYpzxGH19vfNdvZRNvtiO1qmUU
         V6JGl0yYkAILobCvHAGADAm95Am328O1a/tLLhJ0f4oJt9rAJO9PZsGSrrUFYsAZr7c7
         a1562Fqe+bnfrUVSies39eWdkwECCURDfsaLrXGU1NWrzr7MbbMEjKc+EjibxZBVVE7Q
         JUU3X2AxwSvx520JEk2fwGHoncnDOJzTvf8+sk6Q0jf8bMYAaZL6otDacXMsMG0pJGjo
         UFqb7jHLn4kJHtUZ1nq4LHBBpEx/slQjuFRBkaLnZzSejpYpVY8f52NHtXY/5cmttW7F
         AwaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cysLW96AC0cjLaxw9PU4hRVjeTxlzw5c8hEsFYzQAWU=;
        b=gjm7Ax6DrVrQ5JxU3XJxm3o7PS3sosneOyfiIzdv1i1TD2Ss169lP/FiZWegMeAEEo
         1quv7HSdgwbw6dtYMgJg5NzNqF3JjINTbgjyZdowhbN9LyUzt0uPBCtkt2D08fW74wov
         fs71mFvwmA8z2gmxaev3cLYbOj26g+oaYz+mxHV78UfIXMrj703qO5Ap++2rfa50o8QF
         /ORkKno5Yp+f1MothcDdWR3ekxVJAXZ494xLwiGB8py5ZrlmCd7KRKn+H+HPgjdI6LP/
         afjSFuTa8rOP/RtD/ro0mW3LgjLhozOHcK21X31u3V4p8ziX08AFQswvc6+MAfSSOZEX
         SusQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Sa95GrOWYLnppTmNiwLAtQgIBGGXXqqSFcGVBUhujccRmMdQK
	Ckj0PYPuv12nT2eOPuzzLIc=
X-Google-Smtp-Source: ABdhPJxGvj08GWxx0dsAaYT5bT1eWj1+riLAozy3lh7+5QGYqkhUn52LHupe8VlktoBDGZ3sEpk79g==
X-Received: by 2002:a17:902:74c8:b029:11b:4da8:d180 with SMTP id f8-20020a17090274c8b029011b4da8d180mr10136918plt.49.1624647573783;
        Fri, 25 Jun 2021 11:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:16cb:: with SMTP id l11ls4663131pfc.9.gmail; Fri,
 25 Jun 2021 11:59:33 -0700 (PDT)
X-Received: by 2002:aa7:82cb:0:b029:2e6:f397:d248 with SMTP id f11-20020aa782cb0000b02902e6f397d248mr12090188pfn.52.1624647573272;
        Fri, 25 Jun 2021 11:59:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624647573; cv=none;
        d=google.com; s=arc-20160816;
        b=bY40uOsobVCVgjbcUPJrBnsdOECS7ILyIAm1sW0E9VLN3Dm89AQdMfQb9VFiVQnjp1
         Kd2NbQTcpQGL31MLFZ6063BZzLEYrZYQ3n/V1TBaPLyJGWnteBzL2m5I15FxQITOLEFZ
         ZuJ+FjF+GxuHGMxHjcPTCWD/aTBLFJMAMsmVGu3waMGNMSVdI8UnEXeH5Xf6FRxWRQwl
         M9OPUpOXmRw+aOz5YDdG6rtrhGrnXzao+6aE4RtA2d5tWv/ZJezhGPgGUgApE8odzowu
         08Avoo4mLfSROOsFLuJosksGDEPc4lHfxhNsuGlQv5Yr0sSV1hUAIu6GmDg0bKLMnple
         oE8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=4pM9Aita7k4M7CQKG7hY08rTnz5oVoUYdqCwwvnr8nQ=;
        b=kvh8Ucps1A/jO4YCbTc1EjUst8UZ6EQBybChTuKIbuMp/hN+urlXo75NYP3eG1Ge8w
         7OugoMk3QOiYZv8eLaPRAiGQEeRgKi/JI7IXsWMFAKJESV8IevK+gAAuWXW/oyBjXQEe
         nvcJX+/Fqpcs4voOsXcUDBMGIF7aoO6TIQfBbrt/ZEOAG9caGjDBn3drZ1B5YJ68saVZ
         pIG+P6PP58Z99O8gYijZe2NZvIxJ8Pc7GYSdqafdKFYwLNX4gsxYi2gpEvEVPXIMp0j8
         AlD+U5wU1gnq4pbSzPVospEQHMMgeF99ib3qdi1XNJGw8wKPQXTt2qHuE7hMmZXhYU8i
         L/7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id mv18si1053870pjb.2.2021.06.25.11.59.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Jun 2021 11:59:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lwr35-000f6c-RJ; Fri, 25 Jun 2021 12:59:31 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:53632 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lwr33-00718c-IM; Fri, 25 Jun 2021 12:59:31 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com>,  akpm@linux-foundation.org,  ast@kernel.org,  christian@brauner.io,  jnewsome@torproject.org,  linux-kernel@vger.kernel.org,  minchan@kernel.org,  oleg@redhat.com,  syzkaller-bugs@googlegroups.com,  Ingo Molnar <mingo@kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <000000000000ef5d1b05c57c2262@google.com>
	<87fsx7akyf.fsf@disp2133>
	<CACT4Y+YM8wONCrOq75-TFwA86Sg5gRHDK81LQH_O_+yWsdTr=g@mail.gmail.com>
Date: Fri, 25 Jun 2021 13:59:22 -0500
In-Reply-To: <CACT4Y+YM8wONCrOq75-TFwA86Sg5gRHDK81LQH_O_+yWsdTr=g@mail.gmail.com>
	(Dmitry Vyukov's message of "Fri, 25 Jun 2021 16:39:46 +0200")
Message-ID: <87lf6x4vp1.fsf@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lwr33-00718c-IM;;;mid=<87lf6x4vp1.fsf@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/6K7QSNjyoSlC4Vghb9ddd0B5Hb2/12rg=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa01.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4985]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa01 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa01 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Dmitry Vyukov <dvyukov@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1452 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 4.5 (0.3%), b_tie_ro: 3.1 (0.2%), parse: 1.07
	(0.1%), extract_message_metadata: 14 (0.9%), get_uri_detail_list: 2.0
	(0.1%), tests_pri_-1000: 17 (1.2%), tests_pri_-950: 1.05 (0.1%),
	tests_pri_-900: 0.84 (0.1%), tests_pri_-90: 144 (9.9%), check_bayes:
	142 (9.8%), b_tokenize: 5 (0.4%), b_tok_get_all: 7 (0.5%),
	b_comp_prob: 1.60 (0.1%), b_tok_touch_all: 126 (8.6%), b_finish: 0.76
	(0.1%), tests_pri_0: 1257 (86.5%), check_dkim_signature: 0.38 (0.0%),
	check_dkim_adsp: 2.6 (0.2%), poll_dns_idle: 1.25 (0.1%), tests_pri_10:
	2.9 (0.2%), tests_pri_500: 7 (0.5%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [syzbot] KASAN: out-of-bounds Read in do_exit
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
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

Dmitry Vyukov <dvyukov@google.com> writes:

> On Thu, Jun 24, 2021 at 7:31 AM Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com> writes:
>>
>> > Hello,
>> >
>> > syzbot found the following issue on:
>>
>> This looks like dueling debug mechanism.  At a quick glance
>> stack_no_used is deliberately looking for an uninitialized part of the
>> stack.
>>
>> Perhaps the fix is to make KASAN and DEBUG_STACK_USAGE impossible to
>> select at the same time in Kconfig?
>
> +kasan-dev
>
> Hi Eric,
>
> Thanks for looking into this.
>
> I see several strange things about this KASAN report:
> 1. KASAN is not supposed to leave unused stack memory as "poisoned".
> Function entry poisons its own frame and function exit unpoisions it.
> Longjmp-like things can leave unused stack poisoned. We have
> kasan_unpoison_task_stack_below() for these, so maybe we are missing
> this annotation somewhere.
>
> 2. This stand-alone shadow pattern "07 07 07 07 07 07 07 07" looks fishy.
> It means there are 7 good bytes, then 1 poisoned byte, then 7 good
> bytes and so on. I am not sure what can leave such a pattern. Both
> heap and stack objects have larger redzones in between. I am not sure
> about globals, but stack should not overlap with globals (and there
> are no modules on syzbot).
>
> So far this happened only once and no reproducer. If nobody sees
> anything obvious, I would say we just wait for more info.


I may be mixing things up but on second glance this entire setup
feels very familiar.  I think this is the second time I have made
this request that the two pieces of debugging code play nice.

Perhaps it is a different piece of debugging code and KASAN that
I am remembering but I think this is the second time this issue has come
up.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lf6x4vp1.fsf%40disp2133.
