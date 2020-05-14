Return-Path: <kasan-dev+bncBDAMN6NI5EERBP566X2QKGQEOBRRMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 27D381D3497
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 17:09:52 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k15sf435866ljj.5
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 08:09:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589468991; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHB15R+Dfw9XZ2vZ74XzZXvC3wOuAlQy1pVZfYkqoLnbQP4fCRdDC9kJBYLZ2UhvUm
         EGc2GMcS/QkjKjXqn7sZYP/QoVaH6HVwu8yhbkKavIDr0+5xaBOmvuM5brLmEB+KqNTf
         AXXqXL+NLwHMb5i2eR4m4b0WJ0qMCCVp93/fGJUeG3dprHRD54qQ+nUTRkxiIQAiEzZe
         z0ClmsGfPUG7lUW0ja6ma8+vMVlJznViBhzxvniNds73bV/TOCKXXWJKUOI90lBIUea2
         5UAXeIl+a+rlcaZtRcrOFIu+tvD9DkxQIMhyvESS5+rQfSYXrSw8Kt80qXvvCvRhDGkt
         TrwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=O1B4HyXFP9L0ezZ1pFoSpFdY/qN1k6p7JhKbYh5n2II=;
        b=gIHWFi6XoFydkJToAcTqWXokKUJQ48uikMdRUuGvXJV+7LPOKcCXfVZa+eCVWb61my
         N9+R1FK1Qnp1cAONXmU+N41m/kq2+4mOmVmdSa0UNKKadtwugyubry5psYcC6VZcAlE7
         GoRHgJMIg5PnOmDl8/rPf702pQ4warLDGAO/KaItjQMdMRQAwBX1w2FgBZBO4T/hR2py
         9ekPJ5m0MlNelY+litFTwnbzEXGWTbJhcPd5qzQL+B1QdfWmpmJ698qBNZWsioFLXitK
         yv1q07WYwWSLUt/fK0tLqgLvaAi29evH9dV5gNfJEzJXUIsEmgfcQveze03nFqRYOjUd
         TrWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O1B4HyXFP9L0ezZ1pFoSpFdY/qN1k6p7JhKbYh5n2II=;
        b=eGyqJ+FpUuLaxkyhek22dX1Ks8z5bh+kKddHjGpM1ExBBhbGyWGibCkGWNRYFY2hAx
         64bRy8H7577+5Z2OjVEV/xHDnS/th8MZB1lrvpRSwHWe/YTNXeUPn1rpzzetpFhy/CGK
         momCdB6F8zQq4FvB311/unIxXCBmJmiExKLSU+66sP1jVslmD3+C+bTDfpKTcRRywdSY
         kQkHZbtqOmuPc1AfL5NdTjEiP5RS46JBLXwYna0B+qp/FdG3uSSW/RvZFu6zqhsDgo9b
         xZ3EBNQIof903DOVvBKEoS82vfpkufvnbu0I607spTfu7XGbMg5ri5hDfM5S8jhAZDaB
         Sn7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O1B4HyXFP9L0ezZ1pFoSpFdY/qN1k6p7JhKbYh5n2II=;
        b=KrOCMn0gpnssrP4zcjmz1LYrlwzjDi3eqdXxfa+1iBG3iFZ41YjFulRjfGr7FL+dpr
         f2PI0PKV9pPcNMBT/SpG0/IGzW4rcUJPWX1opvDKgKgtfoDM5O7/uqwaU6fj3fLW+av8
         VRwOLYSX9qZrkFaoH1iS9Yu6kybFcWI/xHqswbla7WZb2jGJ0whDyVeioQzucFxCDtc0
         UcX/1vadZe3h+L9qNliuwfIVvTts4PsTlWrpKUOJhkMKLmXwBVgh84dgbgYQgtzlNhrH
         goldwvV0EuZ8PoI5GbckbQqc6L+ewfu/yMyauj829LIn9n6TelOU2YE8YsJLhqKY291P
         3jsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pFBhk7tUwgjl31N8qvrfNbD7uW/MfxILAOxPpMHa8hgJAwvp0
	uW8lM8jZmLDVM93aNYSwFOM=
X-Google-Smtp-Source: ABdhPJzxvmHPL3UTfArT9v23b7xFe9R7phqz5V3K9LsBeSKWsuW0QQXFk26ANEr0qs4F45AWhn/SAg==
X-Received: by 2002:a05:6512:1051:: with SMTP id c17mr3646162lfb.206.1589468991596;
        Thu, 14 May 2020 08:09:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86cf:: with SMTP id n15ls545286ljj.11.gmail; Thu, 14 May
 2020 08:09:51 -0700 (PDT)
X-Received: by 2002:a2e:a211:: with SMTP id h17mr3239300ljm.289.1589468990945;
        Thu, 14 May 2020 08:09:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589468990; cv=none;
        d=google.com; s=arc-20160816;
        b=cBYtT5eGP6gDMVide3fOGVfSCuHawYc8S3/ybiNX3YhkVBKFUUM8044FwRFeoTmrKj
         YdSNbVS9MTPymKy/syV7mQpk3svUKRwVmXvk5stdNSe7HSdEXITbcD6JV6k44eRACIbM
         rlnwpGqMKfCos2swOwUAwL1t0OGNK/FQ3EZcrWbZPcjuy+9mWV85rBb/wcvvLcrDjpo4
         CxaFJaBuK5XKQ9iwy4kMofR5w+5eCdyzsers5cV2LWNviDjI2O0MqAPuoowgrTHyk70f
         Zxa/cpfjr8Kp+f5xT9DLhHLMPQAyjLB7CLpCU07o1wE4m4Ql/PTR3fnFtWhTX3fl/FuB
         ejiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=YzhZYvGu3kNiphZcixpfz8aoE4ttET/Vtil/cQnh35M=;
        b=0jFuALqGZ9/s4eTomeW5V8p4iL7kADLL9NWl8vMcHHPc0OSfWSKPmCf3jAlVZbPCma
         nRXCz/TMsXrK3Kpqt/QQRyHY2aBYxefPOssQk9kqc4uTlJqvktsV1ErgF0+Z+iYFp3NP
         6UEZ9SkcifnrHYbdl5cQnjWfwTkjK9/23fLbYArdHGqxDOgMMuw1UiiXq+Zxjan7sHJx
         ALE7AjhfuIbOyUYKr34VhfFrZRXUS1rrPuze4VoSmIHI4yVFa4Ck9hMdVNU6NeCsxHY+
         1pWM07LG9NS6jByIOhrIsDLv+djwawfKH8HtJohKRaZGEE96d7GW9jtgaIkNos/f6kEq
         2kJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id d19si228086lji.3.2020.05.14.08.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Thu, 14 May 2020 08:09:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from p5de0bf0b.dip0.t-ipconnect.de ([93.224.191.11] helo=nanos.tec.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tglx@linutronix.de>)
	id 1jZFUb-0001hT-NA; Thu, 14 May 2020 17:09:49 +0200
Received: by nanos.tec.linutronix.de (Postfix, from userid 1000)
	id EFD8F1004CE; Thu, 14 May 2020 17:09:48 +0200 (CEST)
From: Thomas Gleixner <tglx@linutronix.de>
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
In-Reply-To: <20200514142450.GC2978@hirez.programming.kicks-ass.net>
References: <20200513124021.GB20278@willie-the-truck> <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com> <20200513165008.GA24836@willie-the-truck> <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com> <20200513174747.GB24836@willie-the-truck> <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com> <20200513212520.GC28594@willie-the-truck> <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com> <20200514110537.GC4280@willie-the-truck> <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com> <20200514142450.GC2978@hirez.programming.kicks-ass.net>
Date: Thu, 14 May 2020 17:09:48 +0200
Message-ID: <875zcyzh6r.fsf@nanos.tec.linutronix.de>
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

Peter Zijlstra <peterz@infradead.org> writes:
> On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
>> Any preferences?
>
> I suppose DTRT, if we then write the Makefile rule like:
>
> KCSAN_SANITIZE := KCSAN_FUNCTION_ATTRIBUTES
>
> and set that to either 'y'/'n' depending on the compiler at hand
> supporting enough magic to make it all work.
>
> I suppose all the sanitize stuff is most important for developers and
> we tend to have the latest compiler versions anyway, right?

Developers and CI/testing stuff. Yes we really should require a sane
compiler instead of introducing boatloads of horrible workarounds all
over the place which then break when the code changes slightly.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/875zcyzh6r.fsf%40nanos.tec.linutronix.de.
