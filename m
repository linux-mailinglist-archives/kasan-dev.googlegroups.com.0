Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBNN43WQKGQEH5V7UHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id C3DA5E9CC4
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 14:56:22 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id o141sf1797577yba.15
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 06:56:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572443781; cv=pass;
        d=google.com; s=arc-20160816;
        b=yLpglb7+cdYw3H5W81is76JSKkCyZW4aAms2zhSNAVD0d22MNOcQw4kOKnhJRXbco+
         K+knrvqo+FiJ6SJnE4mP1hfjNCnq01DPu5Wa5rCa8ONFIWXTgw0Ab2bEjAyzcbVR9ibh
         KELkFkh/gXXwAbuotDRgmGfWyWmWM4aW1aGHcrlhIoaZ5qe7Z91giHkSJRHBPJOdhFoR
         mmIaS+CPMEXTxV8NBtiF3QDfz2PeIk8g1RZ0r/7hxR0E5PdZRW+RKT1pWgZv1SIiErOc
         H1/2sOKwS5tX1y8rvwudHMgkqb+m+Ith79e3CU1dO33Q5vXsWN2vJMVmvv+BrCufN1kL
         jnfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/D56kiDZMIutUCYw0yDk2U5+mePrvkFly6I4rUOJz+I=;
        b=tgZe3XyRuLye7605xGX07ZDBXtmntv6OWjC05GY1NrB6sPzj/eGag4ZzD2I/tdwN/j
         5f0XrqgcKti71ra5qFUlGGs1R6Q9kA2WPHCkN0kF8QN3WgslHLIsTRV1qTxTw9PiDUW3
         WAdghMoJAJr7gEDh79u6VwcVdjJD68WY4w1J+NuSTQx13deMQvwjfyn6NYrglCKyHetf
         7Sv7dnDL+VOCrVfUYlmE0fK4xUnbtX0oJTcE2qYj8a0+fGqIR3MHZW0bhNPpusFPqx9k
         cAxfNhEIY8prI6tnREbf4YW4FWeCKGZ+7QyGFhxg1MIEUXopyUDfuO0EKrr4LvEdpnB8
         RS/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gx8GvXN4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/D56kiDZMIutUCYw0yDk2U5+mePrvkFly6I4rUOJz+I=;
        b=gRyA1mfthUaG0R4hYrYcmXYkQz9ecSLjBQZOlWix1sK2jVZPuELZDna28WRUz/q286
         ZN72/FSgH+zSSeMR5cqllmcGmk3HAU+hcHrmqs72rnEgY03r4JlEcq4IFffAzoJ7MRqj
         lxXisc1EQl0qZFcuVDopZCQmxpDrhf5gOKVv+04jsUUAjRnMo8Cnk5bmfs2Ej9jQQHwy
         JqbcoyvOfyj9CmROWwVQ0lg+a1H1vkW5VnFCFtUhcXVJ73c2SDekWmbc1FBXXQZCySDR
         tBUeBft7FclkoahVBawokPu5oAGsNZE8AZ5tbY+VXY/yUNvvjgiUKsjdQz+s9E6LnvrZ
         XQKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/D56kiDZMIutUCYw0yDk2U5+mePrvkFly6I4rUOJz+I=;
        b=lbt57cd9kGkW1qa7C2nx6wuaED36Esaf0fe+MBb9MqUg/+p37D9nOSa6Uq5K5rgSn2
         34AeFugFFu9YV8TIUWNiDDjB9ChrAZo3VMmNN/FNqoflyv4uxLqQVxD2ctTjmNrX9wT/
         dh4BBABIifmc41Tv38/puDal+IYrkbnLqgtq+1PZVcf48/9Mp7Rvp4waCoiUJrSq4rLa
         37CBv0b+k/LNPzwhrNTmTOs66Wf2BnPA4GSbbc6Ljg170J8NZRawEW+/+Rth8YHW1xmT
         Z2p1m4zpPbOzT6EeyIvKa2rA4N/frX70IGciBLQMneIWdHKjmX9jkNUtIL8Z1AKHICmL
         Yv+g==
X-Gm-Message-State: APjAAAUz3mhlJ8vSfJsn/D3WMrnB7EZb90ccTR8ywE+2An2pRr1ich6N
	UvLJSF1bgP7cOpkf1JgXAAE=
X-Google-Smtp-Source: APXvYqzZptvXhL3ovHLSeGwfJEyOLKBdMGGvxsvAWy3OTXyvgTwIu4HMKivfYe9kcI6lD/+flbI/Ow==
X-Received: by 2002:a25:3046:: with SMTP id w67mr3586719ybw.275.1572443781689;
        Wed, 30 Oct 2019 06:56:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2388:: with SMTP id j130ls277795ybj.7.gmail; Wed, 30 Oct
 2019 06:56:21 -0700 (PDT)
X-Received: by 2002:a25:9749:: with SMTP id h9mr3655651ybo.128.1572443781064;
        Wed, 30 Oct 2019 06:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572443781; cv=none;
        d=google.com; s=arc-20160816;
        b=lipSLkMTmxK1hxqbj63etUVRxv8oJ2sMxpr5h2+4SbKqBs/azSU5cOJiL1CNLYkNte
         zONN72CN9nH6USjVpleo7zmvcvLMIk6HjTFZs26eMg3BJf3gYZ47VzhLZdlWYwvnyEse
         T2A3cId2F8yntv/3+whQeVTyU0E+YZtfI+CQZVU12VlSDgvQQi9Iao/5Yrd7yC3nYheG
         wKcJYGn70ad8qvoAFCFihUtsehsFq+pN4x3sgLxSpf6YPKBA1q/VL9i2SVrzcO/+106b
         nE3bglGGCAW6iVHt98GaaqQ0zxNxqeePosO6scLuiJY1EDoKpdxTaXd9GrJJ0aDXLya2
         QHwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ovs9CQYvSKRtEjY+CnNWbmrVhSTfprl8aJOuk9gzXg8=;
        b=wLDe6+R7WGWVkkzg06TDxl77/GuLifsGxJVY5ZcIfZPxHqkYT0TySNf9bz4kr30VKR
         BZun4r4+ci92e6oK1jqE91P9zP4N2X/P/r1gggQixk+HPWFPJsEA34CZHaM6YXPtWrFu
         2n7CRC61SDZAWvGUcGS7IIorSwI6ofRXN7/GwCSQo+Hoeim62n7uGS7ft/49kfyMYKA3
         F9VcGPOHns+dSMu9NXjq/wjKscTr5Rj2dHOSpZSbscolGXc4YUCmlrckM+j77xg1/5Ug
         Ef0Izw6dd6x0E9I48QUg4Tmq+KgrPu3aPNd66RPz0zWcFVldasiwpmjbnjFpnovSq/4S
         woWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gx8GvXN4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id c5si148755ywn.5.2019.10.30.06.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2019 06:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id r4so1640000pfl.7
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2019 06:56:21 -0700 (PDT)
X-Received: by 2002:a17:90a:1f4b:: with SMTP id y11mr14130376pjy.123.1572443779855;
 Wed, 30 Oct 2019 06:56:19 -0700 (PDT)
MIME-Version: 1.0
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com> <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
 <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com> <CAAeHK+yP2vK06tnx2p=NT8cD_qz_gV_xkuPZ40b2OAe+zxM-EA@mail.gmail.com>
 <b135bdce-8fd3-c81b-72d1-6a162307f6be@arm.com>
In-Reply-To: <b135bdce-8fd3-c81b-72d1-6a162307f6be@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Oct 2019 14:56:08 +0100
Message-ID: <CAAeHK+zArL=ru9rmsbuJjertMtF+PwdqV_Dpd=xJ=mKF=Gfzsw@mail.gmail.com>
Subject: Re: Makefile kernel address tag sanitizer.
To: Matthew Malcomson <Matthew.Malcomson@arm.com>
Cc: "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, nd <nd@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gx8GvXN4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 30, 2019 at 2:30 PM Matthew Malcomson
<Matthew.Malcomson@arm.com> wrote:
>
> On 29/10/19 17:50, Andrey Konovalov wrote:
> > On Tue, Oct 29, 2019 at 6:45 PM Matthew Malcomson
> > <Matthew.Malcomson@arm.com> wrote:
> >>
> >> Hi Andrey,
> >
> > Hi Matthew,
> >
> >>
> >> Thanks for the clarification on that bit, could I ask another question?
> >>
> >> I seem to have non-stack compiling with GCC running ok, but would like
> >> to have some better testing than I've managed so far.
> >
> > Great! =)
> >
> >>
> >> I'm running on an instrumented kernel, but haven't seen a crash yet.
> >>
> >> Is there a KASAN testsuite to run somewhere so I can proove that bad
> >> accesses would be caught?
> >
> > Kind of. There's CONFIG_TEST_KASAN which produces lib/test_kasan.ko,
> > which you can insmod and it will do all kinds of bad accesses.
> > Unfortunately there's no automated checker for it, so you'll need to
> > look through the reports manually and check if they make sense.
>
> Great, that was really useful!
>
> I found one issue in my instrumentation through using these tests -- I
> haven't defined `__SANITIZE_ADDRESS__` (which means memset calls aren't
> sanitized here since a macro replaces them with __memset).
>
> Looking at the current kernel code it seems that for clang you use
> `__SANITIZE_ADDRESS__`, for either hwasan or asan.  (commit 2bd926b4).
>
> Do you (or anyone else) have any objections to using
> `__SANITIZE_HWADDRESS__` to indicate tagging address sanitizer so they
> can be distinguished?
>
> I can provide a patch to the kernel to account for the compiler
> behaviour if it's acceptable.
>
>
>
> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan
> equivalent of no_sanitize_address, which will require an update in the
> kernel given it seems you want KASAN to be used the same whether using
> tags or not.

We have intentionally reused the same macros to simplify things. Is
there any reason to use separate macros for GCC? Are there places
where we need to use specifically no_sanitize_hwaddress and
__SANITIZE_HWADDRESS__, but not no_sanitize_address and
__SANITIZE_ADDRESS__?

>
> Cheers,
> Matthew
>
> >
> > Thanks!
> >
> >>
> >> Cheers,
> >> Matthew
> >>
> >> On 16/10/19 14:47, Andrey Konovalov wrote:
> >>> On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
> >>> <Matthew.Malcomson@arm.com> wrote:
> >>>>
> >>>> Hello,
> >>>>
> >>>> If this is the wrong list & person to ask I'd appreciate being shown who
> >>>> to ask.
> >>>>
> >>>> I'm working on implementing hwasan (software tagging address sanitizer)
> >>>> for GCC (most recent upstream version here
> >>>> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
> >>>>
> >>>> I have a working implementation of hwasan for userspace and am now
> >>>> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
> >>>> CONFIG_KASAN_OUTLINE for now).
> >>>>
> >>>> I notice the current scripts/Makefile.kasan hard-codes the parameter
> >>>> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
> >>>> variables, and found an email mentioning that stack instrumentation is
> >>>> not yet supported.
> >>>> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
> >>>>
> >>>>
> >>>> What is the support that to be added for stack instrumentation?
> >>>
> >>> Hi Matthew,
> >>>
> >>> The plan was to upstream tag-based KASAN without stack instrumentation
> >>> first, and then enable stack instrumentation as a separate effort. I
> >>> didn't yet get to this last part. I remember when I tried enabling
> >>> stack instrumentation I was getting what looked like false-positive
> >>> reports coming from the printk related code. I didn't investigate them
> >>> though. It's possible that some tweaks to the runtime implementation
> >>> will be required.
> >>>
> >>> Thanks!
> >>>
> >>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzArL%3Dru9rmsbuJjertMtF%2BPwdqV_Dpd%3DxJ%3DmKF%3DGfzsw%40mail.gmail.com.
