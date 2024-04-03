Return-Path: <kasan-dev+bncBDAMN6NI5EERBF5OW6YAMGQEXC3DZOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 29E4A897B97
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 00:24:25 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-56dfcd45821sf1598a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 15:24:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712183064; cv=pass;
        d=google.com; s=arc-20160816;
        b=FawPX++4dalF0y/gC7AhRDu1MEuCIPjNANd1CUSjoREib8kR2yTQfVFDtWLGKeXsNs
         haqUR3qeFffcqu34ppGxs2DE3Tx1mKTQL6DVwlPthht8Eci/DX6ZB6akNTmRChBpBqMh
         VKDcC9/N/CZ4D67logLjSQ6Vs6dFcLIWD6ycfS7lGQl8EKnXqNT9sQSv9IgcfBzlrgXR
         NIXttA9aNrffY2w4Yobw/DwhVjEFGLJRgHC6zCZKr4TtyF5v3mV6S/kXQfpYdjA6hbOf
         Gg2CPnv9YSB/HnXUDgrNmxaEkaq7kVGM+Up0k5SeWYSaOLDNocivC5VtmUpa00aUYpdO
         LOSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=E+RKWxkNz2hKLvzVmZBNgEzb4f1hW+Wb3f2KC08nE6g=;
        fh=yHExu2zU2yOdru4UdizmRaNEYUCN39zgax1hHTXOoxw=;
        b=taHS3NshKVSl+TTRhqeP5xk5tlQ0lAlOY5yaE0ZBGxanUi0AfFWkJeL5Gy7FfVKNSN
         ugOlzMOMsgLD2sqn76eRVsRaoNHM5GfEXpdKQ7mo/erMPZl7nKd7Pz1ADngTAL8r6TDJ
         pg16zpb7kJwWljLVuEFVzi3gxvq6zratvhy96ByffEiwQ/9QOFD+kdasXVj+/a6RBIGA
         pRe2/IN7mQKnsdXFEQ6pAJPmt8XX2nEZmaenwpvbXl1pgtzkyM73PK5ru3XDPGTBBNCT
         XxoNLRux8WcND8JJdnrwxNbDFU1Sn4/O+zyYfJsIUyCrxU9c51jE5Z+LKEdz7mx9kf7V
         X7CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=iEzK0h73;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712183064; x=1712787864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E+RKWxkNz2hKLvzVmZBNgEzb4f1hW+Wb3f2KC08nE6g=;
        b=mnXY2P+zF73qZcUxdPV348U7PGRxJ04pVlvu5nnkvA6qi98t0ZfvWAccmWdUggNlHB
         PbtSg+OEip+HFbqBAAvhJRB2AKlJA/P/1Vit5wGqbYMu8gaTa5DskxgHQ7AEQfY4jiOU
         GrNzg8cW1MtUnNSBs7sqtdZBk1rxwvjfBU9gug5hX9nSBySrJb9sIX+lSLWqX9KY4xiT
         5P7Y0cimCKYCWshG5/WKD6cUhWjBsrZMlinqHJaYtnp56JiPsrp8rJEA5L2LeAURd2U1
         6mKUPsCSbpcF3xxYc9tJskUgQBMJgbsmTt/O2YrGbNebcbFE46xEGMhPCKMu3DMseQXW
         mh+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712183064; x=1712787864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E+RKWxkNz2hKLvzVmZBNgEzb4f1hW+Wb3f2KC08nE6g=;
        b=VJhfhtkUpMRjFDfXMjmgDFAVul6pEEjtilaQy9c7PDJEyvnNLdSVB5msJ2s0UBO177
         dQjZjHA+LRsSceg0Rn+6dHCRIQuTYigLJThLkDQWcFIYEq3uTlOwsuF3IImdGcVwo4eT
         xdZxKEz/QHomLUgNKPYZtV8c90aVu0yhOlBVPkqDWdmFUBFOkPEOa+1wAyoFRf4Olioa
         C/52vzi0JwROBTAagZk6+7qKZeT5P/edUl6LwW/ai/Uz6dhKWmtHn1P2CsAvlOtw5+of
         DRX4nkUuBH0CeVgt45GTN2oJ5EuGlieeX0LU+o3Rg89J7HZq0Nx2y4PGtdE8/avrL6iN
         UcYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVT7zRouBtebdAGi2KL2TZGIG7wQAEjbELe5HLihbSIDvTD6Df260gS3wYumfgGcHGfzgHgaFEmNmoECxvcWz2mk3FFe1LdLw==
X-Gm-Message-State: AOJu0YwXJaoYnslbUXpBs9FTurI2lSXugLgwoJhQMGpXGO45zOpvL4yn
	AWSyqSUca9W59CBJCzx2ymgCUrZy1z/Z7GYrUSUVaQwnGo6ptE/5
X-Google-Smtp-Source: AGHT+IFgBIAqxYy5CX6cH3uO2uPHrlpRsRmrG9lo1c72t7jNZJYUnTbaOAzLNRO8Lc3qrWsyTwNoYA==
X-Received: by 2002:a05:6402:1c87:b0:56c:2d40:7430 with SMTP id cy7-20020a0564021c8700b0056c2d407430mr251441edb.3.1712183064345;
        Wed, 03 Apr 2024 15:24:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1028:b0:2d8:243b:ec9b with SMTP id
 w8-20020a05651c102800b002d8243bec9bls284328ljm.2.-pod-prod-04-eu; Wed, 03 Apr
 2024 15:24:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZFjYgh9iZYwMhI3xvEZHOfF8/aLvHBXeNmtlDas1znSCsv262euluiwsMmIT7R+MXhGc/q5ktNa8tD/RTJrAoxGujE6gh+diGXw==
X-Received: by 2002:a2e:b0c3:0:b0:2d6:afdc:2a18 with SMTP id g3-20020a2eb0c3000000b002d6afdc2a18mr585960ljl.16.1712183061951;
        Wed, 03 Apr 2024 15:24:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712183061; cv=none;
        d=google.com; s=arc-20160816;
        b=r17t7VFKRJlsrxNc4OnVjXNZP0C1vT37cwrGHQl1Jt08fWLnS5k7RZ/afECw8DSh+/
         x0uEz3vTy4v+x+1Z4i8NRbFL8pHyGbh2uibXH8AuL07XNCEg8peRlVe3tVxq/Qlgs9ho
         uKpUnUoqCaTjGJvYOcy2l4tK/daipJzRjYdov5VaIrN3ler6FKJrTjzXIh15aOKgMLBS
         UX+FOgKrrQgW4m5iEk3UDeYQdet7PdvYm6zqWBYYe6ooIL5w1gYIJpEKCD9d5rbc/yFS
         fykSNvlt9HD6P+jmgccZDY7CKwA40RSEMslF2AaZXkk5ptsuWduWTHczhUJJrvlSJ5Rz
         x8lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=c3YFPvNQqpuZ+J4wj70XcY9sGKlu8GfBq1D4XGyQln4=;
        fh=G67xwWJgg4YQhqnTeUhp4AIhy/KgFs0OqB6nXUYmW+Q=;
        b=AkuEqGw+m5VVPbDlRerUSgCFXX4yvnU3sKzJO2KZNSjMYVvroh7PyzCTKMHstAKc4n
         jq9NQRItpW5rVlb19tRZ5+HQlcZzuEd/WCoCxGcJaKS/v0OoWDqptPzXWJ6mvPvCam7C
         EhishslX+fidoT2KP5xlVMNnr381edj2brRS121s6QjQD5N3vRS124SNkVO6fFk+xC7m
         wwook0EXo9clM9vUnYS+AmJibhiOypMWwr+rl6qfyDtx/mObkRV9IuqZlf/8iLA+xyB+
         S2QuU4/T/mdzdnh/xViiWlo4s/SfqQ17FxqN6SqL6VWxMRecX47piltlht6uT48Mxzwd
         NfPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=iEzK0h73;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id w11-20020a2e300b000000b002d83db42d33si76459ljw.6.2024.04.03.15.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 15:24:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: John Stultz <jstultz@google.com>
Cc: Oleg Nesterov <oleg@redhat.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
Date: Thu, 04 Apr 2024 00:24:19 +0200
Message-ID: <87frw2axv0.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=iEzK0h73;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Apr 03 2024 at 12:35, John Stultz wrote:
> On Wed, Apr 3, 2024 at 12:10=E2=80=AFPM Thomas Gleixner <tglx@linutronix.=
de> wrote:
>>
>> On Wed, Apr 03 2024 at 11:16, John Stultz wrote:
>> > On Wed, Apr 3, 2024 at 9:32=E2=80=AFAM Thomas Gleixner <tglx@linutroni=
xde> wrote:
>> > Thanks for this, Thomas!
>> >
>> > Just FYI: testing with 6.1, the test no longer hangs, but I don't see
>> > the SKIP behavior. It just fails:
>> > not ok 6 check signal distribution
>> > # Totals: pass:5 fail:1 xfail:0 xpass:0 skip:0 error:0
>> >
>> > I've not had time yet to dig into what's going on, but let me know if
>> > you need any further details.
>>
>> That's weird. I ran it on my laptop with 6.1.y ...
>>
>> What kind of machine is that?
>
> I was running it in a VM.
>
> Interestingly with 64cpus it sometimes will do the skip behavior, but
> with 4 cpus it seems to always fail.

Duh, yes. The problem is that any thread might grab the signal as it is
process wide.

What was I thinking? Not much obviously.

The distribution mechanism is only targeting the wakeup at signal
queuing time and therefore avoids the wakeup of idle tasks. But it does
not guarantee that the signal is evenly distributed to the threads on
actual signal delivery.

Even with the change to stop the worker threads when they got a signal
it's not guaranteed that the last worker will actually get one within
the timeout simply because the main thread can win the race to collect
the signal every time. I just managed to make the patched test fail in
one out of 100 runs.

IOW, we cannot test this reliably at all with the current approach.

I'll think about it tomorrow again with brain awake.

Thanks,

        tglx

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87frw2axv0.ffs%40tglx.
