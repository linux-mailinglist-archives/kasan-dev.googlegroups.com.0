Return-Path: <kasan-dev+bncBDAMN6NI5EERBF5QSH3AKGQEDTEG3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 41A501DA43D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 00:05:12 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id a17sf326228lfr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 15:05:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589925911; cv=pass;
        d=google.com; s=arc-20160816;
        b=HTITH0XNL0HWfilruiPVGZzUF3Jqd72Z211RRTb23nDdeme5dBySHl0qiTdyXvrA0u
         Iy+vzJqPDz2U+pty02PxRkEHVoTapg+5SFsDB+AaU13Q/Mz0hIfbc96Y0eX/VVLjPsk1
         9eNW1jtWQ6LiuErZJ98xbpDUTulyxxAwC1odKZLHzYST+1OHFW06jsFZSMfdXtOzL6FU
         rKxLNZDINcja5xtsHfL820+VMa/Mwf2B62Fduyq3ZBthzy+6DiqxVe1B+GO4fHqQGEmZ
         oaSRlIQbP251svh1NGriwkAKI+H0D5BuZOIFF/YS4HgQ44tRd/emdByai0pAkEFuNYa1
         IPWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=3JzDnJqgAe3+pYGPiNdB/5RrnT2DoCqs29ws5oQx+F8=;
        b=njJE7Ak1R9d33Jh29ZuV3YdEFDN4ZI7lyfaTAj845+4GDQbmPGKH6uyBCGPs4su2bQ
         ukVqS81K5s1w8qsAyR3kqMZjRVmThW6rrh3SWf9MOBeyQRE9M9pQtRVIYwjvfYPMTrRZ
         DZbEZ3XeFvWDOYrAd8Wh2YEFokkwQ26m2VpuZCz2teez9R/cJR3Zv+kvGudZ9ORA0LIu
         SkvD4I2y0JpI3tX9rVxtjg9bUKdKO/1WhqlYnb2qmco5BgK+8TMn7ugDlMiTnqDkCslZ
         1NeY7XmQAiFXIjhUEsJxs5hQMQHtjeQcnot/rXHlEcBT1toGck3qKfdUlQW/lZvYxyYs
         aBmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3JzDnJqgAe3+pYGPiNdB/5RrnT2DoCqs29ws5oQx+F8=;
        b=bk2hDqibjJ+Jy31QaNF/rmBRL7NtYbPsUHGbee4qAe6s0KhT0R7QiluG3+OAjZDSGn
         iiHBvBGXLYbwWVSsu6p32WC3LrDPsXdr79YKFYn/y46PgZhUYTpzSPoE0RAcNidNkTUn
         r/IxR50SmrrU+gl5vwAI5NVql088f62i0uyy1dd7tH6H3GyXMBuO3tyGINcyy320pz+H
         OSilPSDQwZ5olJVeS045z/v4Qa4Bu0ZWmFRe4jqGLcKniLwDOMefQWVObOG5ikIkhHF4
         cNHtNebNW36Asv/YW+Ll+PiGPHsACpAzX4PJVhEFIYRoSflvwG2hHgdoOoAy/iGGrYrH
         CVbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3JzDnJqgAe3+pYGPiNdB/5RrnT2DoCqs29ws5oQx+F8=;
        b=enZZglMGo+nvk/rFiKfjElx6xWUvMdYLOYJV/SisG9ZVkM+JXiFSEqdXOjPSNCmcIR
         5r47xQf+1E1o/+yELdwANLkHQZChJCSkjLdRezMV+X/uL3iC4A+dO9XsdtNG7JkDztln
         TEDNvA0M6pO9qkj62Nopjz8ycAMwRTv+QgVqDm1yVIBDPOrbiUZ67YTCNWaD5JCgzMkn
         JxJCElObtlA1Pf6Bc0WQIe+wIE7+MLScV0fnlWVcTFtLr1Mnaw2Bc+o2bLE6oMuzQzF/
         Bme8KmFh09ArZ1vgSWT+ATE0l8DsvQSi/5bGYpDOyBUUIVzSKxgEzv99tX7mi+wMf/Oh
         tR3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wHu+lbzmmYgt6xnxJMT5h4o4MAhfF6GxBdZJYv5ilhcZI1zp+
	B9pTPy0bP7lJa81nN5TLVu8=
X-Google-Smtp-Source: ABdhPJzKHkvyhE38Vs2/AFee+tmRqGD/S3OZuFwV4hqF0Z9Jtt47RxZ6gf7cWZIKaetNwlPW5X8hsQ==
X-Received: by 2002:a2e:8008:: with SMTP id j8mr896075ljg.72.1589925911780;
        Tue, 19 May 2020 15:05:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a417:: with SMTP id p23ls208797ljn.0.gmail; Tue, 19 May
 2020 15:05:11 -0700 (PDT)
X-Received: by 2002:a2e:9e45:: with SMTP id g5mr926519ljk.180.1589925911241;
        Tue, 19 May 2020 15:05:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589925911; cv=none;
        d=google.com; s=arc-20160816;
        b=os9TVybX8rtvKldTRueu95UALVflFVSQj6YrfWkCGKhg2jXINBsJLaTZtdstsZPVsv
         sqjlm+qN9jbEQFtqbsr7dI3C83FzzH+RzvrsPMmuzE2AZR83AomSNt9zkM1zqu1PeSIb
         4fH5T5lZoWb38YnnBV7dPmLJaQcsB2goTYuLk84YCGAMHnE9ubHhs3Z5PTqSmUcc/EvR
         t0O8u+NoyteSMUpzjiNKOmn1gSpfs8Ra4Cl997QiqWHFUqmN/t2mihhotomfh+g9Esdb
         PPgyhm0oUk0oTvbm16X99qIWsgWkdJgDjDyd+9ibxLk3dhUhliAGU30lHjp5lj/B0q/D
         jzvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=gxgghm6Iry1BPo7TrfsrSuwaAd/7nlUWdom8Em+Qj/g=;
        b=fJrdWwRFi7Y03wdpPjB28den8KxI7lJqyQHHtriFas9mlZIyaqBEFD5GFAKuOlhXY2
         Oy4JZ3gcEfRDi9TujkRidMmeeTNIyAbsgIBSuKYIueSVCvHuG/Hn13SaCNTCyh0Mf7B3
         vBmppEc1xlzFu/C5Hi4oywJhpB7dZcfmmq/a2N1/AHPUtR+o+/cj2PRHCGKq+d5aQG6C
         GSnXl5D3H0GrLi2Kq6ZtcuFjHi+YY4i6b0Z17BjQ65ZoGAJZIRkeQw6A0vWp4TXMy4fV
         4E05V30/wnUHV/Y6XcdwZWCPKyRUbCKrmcXyZ3+4Px9u6y4zO+3b/bNsI9PIWxrxvI00
         KzQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id d19si74395lji.3.2020.05.19.15.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Tue, 19 May 2020 15:05:10 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from p5de0bf0b.dip0.t-ipconnect.de ([93.224.191.11] helo=nanos.tec.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tglx@linutronix.de>)
	id 1jbAMH-0003FU-EL; Wed, 20 May 2020 00:05:09 +0200
Received: by nanos.tec.linutronix.de (Postfix, from userid 1000)
	id B6FD5100606; Wed, 20 May 2020 00:05:08 +0200 (CEST)
From: Thomas Gleixner <tglx@linutronix.de>
To: Qian Cai <cai@lca.pw>, Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>, "Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
In-Reply-To: <CAG=TAF7zVCMLj5US0uw-piwBUSmWpmPSPV3Thjbh7_kGsO88hQ@mail.gmail.com>
References: <20200512183839.2373-1-elver@google.com> <20200512190910.GM2957@hirez.programming.kicks-ass.net> <CAG=TAF5S+n_W4KM9F8QuCisyV+s6_QA_gO70y6ckt=V7SS2BXw@mail.gmail.com> <CANpmjNMxvMpr=KaJEoEeRMuS3PGZEyi-VkeSmNywpQTAzFMSVA@mail.gmail.com> <CAG=TAF7zVCMLj5US0uw-piwBUSmWpmPSPV3Thjbh7_kGsO88hQ@mail.gmail.com>
Date: Wed, 20 May 2020 00:05:08 +0200
Message-ID: <87y2pn60ob.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Linutronix-Spam-Score: -1.0
X-Linutronix-Spam-Level: -
X-Linutronix-Spam-Status: No , -1.0 points, 5.0 required,  ALL_TRUSTED=-1,SHORTCIRCUIT=-0.0001
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
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

Qian Cai <cai@lca.pw> writes:
> On Tue, May 19, 2020 at 5:26 PM Marco Elver <elver@google.com> wrote:
>> The new solution is here:
>>     https://lkml.kernel.org/r/20200515150338.190344-1-elver@google.com
>> While it's a little inconvenient that we'll require Clang 11
>> (currently available by building yourself from LLVM repo), but until
>> we get GCC fixed (my patch there still pending :-/), this is probably
>> the right solution going forward.   If possible, please do test!
>
> That would be quite unfortunate. The version here is still gcc-8.3.1
> and clang-9.0.1 on RHEL 8.2 here. It will probably need many years to
> be able to get the fixed compilers having versions that high. Sigh...
> Also, I want to avoid compiling compilers on my own.

Yes, it's unfortunate, but we have to stop making major concessions just
because tools are not up to the task.

We've done that way too much in the past and this particular problem
clearly demonstrates that there are limits.

Making brand new technology depend on sane tools is not asked too
much. And yes, it's inconvenient, but all of us have to build tools
every now and then to get our job done. It's not the end of the world.

Building clang is trivial enough and pointing the make to the right
compiler is not rocket science either.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2pn60ob.fsf%40nanos.tec.linutronix.de.
