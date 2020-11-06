Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG4QST6QKGQEEWL26WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 22D182A912E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 09:23:56 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id a1sf193105otb.14
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 00:23:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604651035; cv=pass;
        d=google.com; s=arc-20160816;
        b=pfXpclnBmz9mR8/7dBOR81LG3uxW6BuE+nZafCpaqNK84ibt9K5yANLY0M5ZLmDSFj
         DTA/8GbdnKLlTYgmIpO4rT1fLgZq55oRfOwl71+LEkvHMRQZYqX1+IS3lJkX24WYqhX4
         qfWWbPjOrCWvvGku0XvfD8mLwGdoRrTV6Ga+q8ywZ71dzaAR2eic0GKOok2RUIAcZAX9
         8KYbCyCpi9idTCTHp76Cgs5NhE5tatU/jzj1eVhgwfLQXbp3k20FcyGJjMfNGL2MjgKO
         yG/3MN4W5C+f6X3eb7oW/8ZyWUZ2rIYEeN20Ib0S4w7KvBeAV+o7MQVJIqtIcPCMcX0X
         vQAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ac+I6TbXoHbueX2pLXUJ06trAr8k4VZyHqkVqDpMT4M=;
        b=DTDp8QwesVTz87XuoMR3gVqL9Q12WG7A/X1veOg1zv4+gwqhKmG458trVY7l2gqpzC
         R/zJHwK0WfY3mo1bCMXwgleHpeXPfSDXUZG9fi+iiqfZarToPwu20tL5Wmb5O7u3iFuE
         2+nQ+OE5GP2JbPgT5UGd6MxDlWyS7IBGPuT22slRITKNl4k1knOeAPk+GFOBegmfvbt7
         DlVh0MjOrRqS+2sje1JMUgdmOV//uDKEAPLal+lj9+eCRoy6FXPv75XcLeD6uKyytUJc
         P/kgnBlT6sOb/+PJ5SB9bAN+h5fyxmZd8a1tH6qgFAnNrBJjSlekzQdgdez0KNDksBcv
         ZHjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ROKUlITX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ac+I6TbXoHbueX2pLXUJ06trAr8k4VZyHqkVqDpMT4M=;
        b=GUv90AJHIvRRjNwEbQp1+639BkYkCsK7V2N46o7nAgMSG/oY/q5NQn20pKBCXeiuT3
         7D1WxRg1to2Dmg6LCmHJOYtbfQl7DJXbDu+n/jqPg7cYxJK49T6vmPCQk2O431X+Fz1p
         3qHzmeEgKZTgNxA95i7Aru79HM8ETNMc7DRcgPWEXCddU+nPQdfU/Dc8GeeP4VJfC1ZQ
         MdS+RphTpYMI72kRakl70b0xh4b3u6EL9yCat7X2vJBBuMj1n/Qtv0StpXZ1unPNOr7j
         P7c6BjzuqfgfUt4Y4CcPdVHizyKqGQe9ZdkE9poYt1GFDvyhI6PJvZyU2q1U0lM2XTJF
         4V2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ac+I6TbXoHbueX2pLXUJ06trAr8k4VZyHqkVqDpMT4M=;
        b=THFb+KrbTuwuOhgHgmALzU9p7HSn6yLIkVnD9nMR12eImb9wsrCayBkLdG5N4KiCSn
         tsGNGSrbWBJ5EIRHAF6SuAd7nYDcYRvYxKeA60YtDJJErblypzGe4wZBFemLI6klXrjn
         Zh9mhu0RMaFDs/MiCE0WoJWfUnbe9zj4GX2KMM/qN3fh0DRbKD+icDGHazzAUfnA8t6Y
         awbHBVq4pKi41PvM+jqqB+QTuUgLaJTjaLdaj+Tr3vYTrSbK871iYUMO934pA51leVmg
         wUOjG5WsD72QMMbLk0QHLyCoSBujA34EYkg5H/D+wl8i6jIciecIKkLcmKtaMP/x3o0H
         TF6Q==
X-Gm-Message-State: AOAM533sZgxRR3OapimlGPYaVdp8O7X9sKYnYp8GpoEmvX/KjYgFbxBw
	BaJ+vOegcpqJvfEpnLrqG7c=
X-Google-Smtp-Source: ABdhPJx4mk4PajD0iR9TPEKYMbFAE4P8TtvsVMldskJ+5vuaOqeKq33wbRAxLhVPegCdC+QjkbYeUw==
X-Received: by 2002:a9d:896:: with SMTP id 22mr421653otf.55.1604651035127;
        Fri, 06 Nov 2020 00:23:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3108:: with SMTP id b8ls99502ots.5.gmail; Fri, 06
 Nov 2020 00:23:54 -0800 (PST)
X-Received: by 2002:a9d:4d09:: with SMTP id n9mr444238otf.334.1604651034721;
        Fri, 06 Nov 2020 00:23:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604651034; cv=none;
        d=google.com; s=arc-20160816;
        b=TPQbixvosR0B4m3V0hDoDQyFW/kJxQ5BxMYeQ54lTO6J1Q4YDE7aa1fsxmlQRqn8c3
         FNNqyZAH6NrnsU+7sfHJz6dlARubHo/8TNrx2ioVGASx5HU/V4ENd78GMW2nUVLSJIXf
         vPBWfP2IVH03KeQ86s7zAx0uIsAAnrNZxV33Dbr2I0Bm3ffb2+pQOm+B9NfZRbXnUZSy
         01mRYxU32KNVD7QuczGvlXlrBxCEl9d65NBsx//9VMfRFpjvzMi2/216oTqM3DWiw3lL
         u9GBwNC3FIdK66ul0oCpkLQDiA12ow9Z5YPDiq607QQVXXfty2sFNPvvIrR/0bep7qxM
         MeyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3Geod80nQDfQxEFT5M+Ug8lBXpvwz1ZaxYjoZxa0R3Y=;
        b=o9NHlKdyrVjhqo/jvVQV8WML5+CJyYh9x2Fjlod48SRpsre+LkdmjACWm8j5OzMQYQ
         VdQUCRjVp3JM9BGxjiL+UTShr8aW5a3hUBVvc9ZKGmaFaNuoZSaBGXOFk8INeB7XLA5g
         n5CoGzE8RwCoWoB5Vqo2WnuRPqkYoH8qDyPPhRgkZJJ+wLtIkzx6TRYEeYighyK2gzUq
         nt4UU47Sp4fkY9BZFcPu9Olclt3MU1bCQwqiY5O1K+2b1Ivty9CJmrArJpNDYcPOihZh
         YqWCgs2mH2I6ABSi0ZmC9fnjb650KL12trLsG7YnaD2Uocub+cLl+5zlPdA7o0HVST+7
         ILSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ROKUlITX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id e22si47285oti.2.2020.11.06.00.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 00:23:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id j7so547040oie.12
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 00:23:54 -0800 (PST)
X-Received: by 2002:a54:4812:: with SMTP id j18mr493798oij.70.1604651034335;
 Fri, 06 Nov 2020 00:23:54 -0800 (PST)
MIME-Version: 1.0
References: <20201106041046.GT3249@paulmck-ThinkPad-P72>
In-Reply-To: <20201106041046.GT3249@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Nov 2020 09:23:43 +0100
Message-ID: <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
Subject: Re: KCSAN build warnings
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ROKUlITX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Fri, 6 Nov 2020 at 05:10, Paul E. McKenney <paulmck@kernel.org> wrote:
> Hello!
>
> Some interesting code is being added to RCU, so I fired up KCSAN.
> Although KCSAN still seems to work, but I got the following build
> warnings.  Should I ignore these, or is this a sign that I need to
> upgrade from clang 11.0.0?
>
>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
> drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
> drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0

Interesting, I've not seen these before and they don't look directly
KCSAN related. Although it appears that due to the instrumentation the
compiler decided to uninline a memset(), and the other 2 are new to
me.

It might be wise to upgrade to a newer clang. If you haven't since
your first clang build, you might still be on a clang 11 pre-release.
Since then clang 11 was released (on 12 Oct), which would be my first
try: https://releases.llvm.org/download.html#11.0.0 -- they offer
prebuilt binaris just in case.

Otherwise, what's the branch + config this is on? I can try to debug.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g%40mail.gmail.com.
