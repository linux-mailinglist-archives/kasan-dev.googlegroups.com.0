Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEOIU64QMGQEOMAG6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9795B9BC90B
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:23:45 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a6b37c6dd4sf43904565ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:23:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730798610; cv=pass;
        d=google.com; s=arc-20240605;
        b=aHjPZSiwCA2kNDaa6opwwX+dDLpR78ixh+Pp34wbPmqv8yhDzdkiFArN2uJ4uydMB8
         +bcyQRMvM37NvsJcbEiZpSyFouQss4Nq1BfLzUSlRRUWoeSyeZDn5yUwYv9uQh0Nq4UY
         TWzdemLA6eszLFCrnsoNc7h74SzhK5uyJrqPKcKn1zzTAUvKH9XahSiedJbmRT0jxj+x
         3/FjJ0ZfzeWGyNtko9IBsv1MCxHYfuMGeSRoD82Gfg226mbChL3zmVR7aNWY7xF7p96V
         NwWhw+Ct8zVnMM8ZEjMnolyLyukjD5XPr33WF7aZKf8XtY3PUoYb29+NZ8iR3/mjwYMJ
         ga5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WVZSA+QLBYQEBiMAWkPiHi+cjqxb+opTJO9auEyU/bU=;
        fh=mGb/ZtvImiCwqjiwnTrWIOedIwMwE+8OcZrphq/BWlE=;
        b=BYUMzY3NS8/xhUbEGchsLd6pHETVz2+a0cPlx8cYw1H+vhtUZKzDZyd8M3BOapMECf
         Crg8tVsZQpVKDxawrMNTOGmdff6Ar/n3oMFW8ZTTQPy2Qq1Y3ULgWoDPSTxqKxYno0/h
         8ISBh3rR5xYtS+QkAr0yGbPRKoUcrRASctTll8mWoh2NCjY4SZyYbDquLWRyVT5xb+Qu
         K86/4SBrLBHgrr4eeF5jzDlmBx2iQ9/gGrEVfhQHe1HQKBU4ldtqMQuvEWB3fnAaa/2P
         lUcUKZxVGJjZ+cz14oD+CaSBhNaTi8aULMH05HNv47NTdmKWFCIRujEJ6w71Bh+SZqTP
         NRlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Md0SsVnU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730798610; x=1731403410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WVZSA+QLBYQEBiMAWkPiHi+cjqxb+opTJO9auEyU/bU=;
        b=cOKIOlHNLO/XI7yaoU3oBIayq9q36iIMOvtvsL9XhyjuVmkwYBQNwkzbPb78fxAk9A
         iXKLsTaMHlEbKU9lY3CDIpihWSxs8H+qSu7rU1j00J38+ZRwahwH2iigOmKOn/p0Nc0C
         zpjChOV3GJFavF44B4JOYPrvRQ34VS2Y5GYPGP0/KvW9MjbCzAtGVYX7ewFVM/cIHS/P
         et0hkPjXPXeYLQIXMmLg6/1dTiGlrQeC9mKYeQuCxA4GSMBt/ehaJKNMYWVrcNwettoF
         fvXVLlucDD31Mwg3RI8x2+6zj+yj7SRi8Fm2Yv2J4ESBM+f/HYJCNDWQy5edZ8A6dUE7
         z+Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730798610; x=1731403410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WVZSA+QLBYQEBiMAWkPiHi+cjqxb+opTJO9auEyU/bU=;
        b=l5oSU86qQ35wFYz+YWU+S9YeVwq/C7gGMvh+IXB2smtU3Ts3cJtX+qDVHu5j5rmC1t
         Y5yGeOrVOrVXfa6MOJla8D5RVV23oecDpQuHbszrmLddDpSTCeRumdHkxEPJqX6m/18t
         g6/MvXTL2rtEV0COpBNoLBDcgJ4MQz8DcpUO+ljR0uFB4sEvW8IZT5fpbkeEdvSGVlqK
         opic51Gi0wbdQ3HJrgNDoZEjFFtfg7Edn+o7FUujfCbSbvRpc7atOeeHo8UKk9bO4KQ6
         fGvwr57U2rXeH1KzgxyW76FYQTHgncICGjepB68psMciaNHvOXHVFTGzxSXm4T1AETDX
         61xw==
X-Forwarded-Encrypted: i=2; AJvYcCWrY2xwIu7lnh8ifrC1bErq2V0J1jNIuUIrIOTZrUWZ7WiB++e8WM1TM2s/sZRbiuSdQaz5kg==@lfdr.de
X-Gm-Message-State: AOJu0YzSqs5pXbW592trJxgLpKZl4fjQiEnlAYmRTO+dIReXP7wwb0fX
	MUuJhmG2yXgU6nc3Qtt8qDvjXdxJuNrXZ23j5bxDtLCqpTqZu1l5
X-Google-Smtp-Source: AGHT+IEONAT3P8uVj1K41z2UsbJCQLIVCjKcZxsE7fSRSrBzUqXQsg9iExUKnDDL4w26ERrQNWRaFw==
X-Received: by 2002:a05:6e02:1b07:b0:3a5:e5cf:c5b6 with SMTP id e9e14a558f8ab-3a5e5cfc68bmr220417305ab.10.1730798609826;
        Tue, 05 Nov 2024 01:23:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce0d:0:b0:3a6:c85f:d091 with SMTP id e9e14a558f8ab-3a6c85fd6dals13014905ab.0.-pod-prod-08-us;
 Tue, 05 Nov 2024 01:23:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbZ0RJc2uj4vfraUGqCimHGjwsXMzYI5aKK+NIloUg2c/piw6WBvLfwW0quoXbmnmgsZoRuddDQh0=@googlegroups.com
X-Received: by 2002:a05:6602:6d12:b0:835:46cb:6747 with SMTP id ca18e2360f4ac-83b1c3da9f8mr3914399839f.4.1730798608807;
        Tue, 05 Nov 2024 01:23:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730798608; cv=none;
        d=google.com; s=arc-20240605;
        b=JZIDElormGYxtAiZCZD8KZy1QcBPUSly9KVnBrBrHYtHVzYEwgLatMSHKtdSWwr/y5
         f/JCO93l5HVo/do83BaKLrTb+cQh4Fyzr0CFGtcDILPsBePA4h/KckVC/mU32pDtn/rA
         YIEO/+AqOGtz0io3e91orx9pMO8wTWhVTtk7ieuoAXL/6TU31JJpt9d4DgHEBIgE4SXo
         DXWywRgrqX4CtYuUKCEwE8K8m5Pc0laWS+eHNkMW75/+bb2sDNrE6H9Cz3BaezNEyr7k
         4nxmP8sgkFFcT95OeOw6dPPvLbAA8tGul4aQIGy4x2WtrNwTzESbAk4TyP1zTOihMVCT
         JqKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZdfrPdUPNGoog6Ndxomrc7QnMMuWaqWXqD47+NdPzQw=;
        fh=ECF1YsZubAWs/rpBaix5qMDOOBcLFUxKOSQAvybc15Q=;
        b=PAW/aGCJ5/tz0m6TdZlFieNJNMIQgD3YInZXz0IDZ3yElxzSGJnhLl854NinE0mkjG
         vIcaV/D86hTQSW7Br92/rAcIBpA4l6LDWnnPU9CntL38DLolWg92yrpTuwkxVsydPRSz
         Vh6cU0jnv+iGXYScWvgveJcF9m0cS0BWn8X6dibfwSWQw8Bq7p5YBpHH8LGwxZqDUzlE
         Yha/yLoHvzgseCeEHY3FfKUVqk0FGye6Oqpqi+ZN2rvP7yf9bSWlMxXyV4OT2lEhJasc
         2HHsWogaZAj8+InYtx/U8rICfOydPoQCstUmE3Dah4nrfjR+iTWd1OUJf2JW/a3JH4Wa
         SVVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Md0SsVnU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4de04b1be2esi420649173.5.2024.11.05.01.23.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 01:23:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-720c2db824eso4772134b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 01:23:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWvUp2aLlDjR7vAOR0yaz/NZJP8aMXdX3H3DwSQsajo5Z+TnhtgiW62WnPb2WEk1kAXiCeJh0BfrCM=@googlegroups.com
X-Received: by 2002:a05:6a20:1d98:b0:1d4:e68c:2eb9 with SMTP id
 adf61e73a8af0-1d9a83cfa9amr47833528637.20.1730798607856; Tue, 05 Nov 2024
 01:23:27 -0800 (PST)
MIME-Version: 1.0
References: <20241104161910.780003-1-elver@google.com> <20241104161910.780003-3-elver@google.com>
In-Reply-To: <20241104161910.780003-3-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2024 10:22:51 +0100
Message-ID: <CANpmjNNBo6SvESFxo6Kk2v4_HOa=CeAVR_unTJvQEP8UZQG6gg@mail.gmail.com>
Subject: Re: [PATCH v2 2/5] time/sched_clock: Broaden sched_clock()'s
 instrumentation coverage
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Md0SsVnU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as
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

Oops, typo'd the commit message:

On Mon, 4 Nov 2024 at 17:19, Marco Elver <elver@google.com> wrote:
>
> Most of sched_clock()'s implementation is ineligible for instrumentation
> due to relying on sched_clock_noinstr().
>
> Split the implementation off into an __always_inline function
> __sched_clock(), which is then used by the noinstr and instrumentable
> version, to allow more of sched_clock() to be covered by various
> instrumentation.
>
> This will allow instrumentation with the various sanitizers (KASAN,
> KCSAN, KMSAN, UBSAN). For KCSAN, we know that raw seqcount_latch usage
> without annotations will result in false positive reports: tell it that
> all of __sched_clock() is "atomic" for the latch writer; later changes

s/writer/reader/

> in this series will take care of the readers.

s/readers/writers/

... might be less confusing. If you apply, kindly fix up the commit
message, so that future people will be less confused. The code comment
is correct.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBo6SvESFxo6Kk2v4_HOa%3DCeAVR_unTJvQEP8UZQG6gg%40mail.gmail.com.
