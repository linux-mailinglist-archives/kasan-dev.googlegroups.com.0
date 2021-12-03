Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJWYVKGQMGQEQM63TVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3875B4680DB
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 00:45:44 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id h8-20020a05622a170800b002acc8656e05sf5324786qtk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 15:45:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638575143; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBrsI7UxhHGRDE2jGQFgt2YvdLB8hOpKHuZDhM1dghb76GmsKFB+VbtjEE6bLUcIjO
         +xGT1UhmyHFWFe+eCH90TwrNMVyOY7gBiGbGI0Oy2LkR+Jf6EJmT1zPvK5n8Z3E78upQ
         jXIgWOuiSj85JojSPVKpof9wH7fLwZQUlCgHUQyhuji82FFqmpu9psurFZmbEHBEidiI
         t4bozEdhHs03PTW2DhbtOaVMCp1i+jPRyz2pjY1T83hPZfef459JrAwRJWLXIvQGTBs/
         Ijl1BT2qj0VkKkpM5Kd5GCkYMzKSc3g+ijBQAgAA3ZauOQf+HJrMi/By5UdWVn1KdqWv
         Rs5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7GlqhssEpTO/XcoYrq1+0ztg5ptqr0pFv/fi9zo9zlE=;
        b=cpsE2qmBAe9FpMKZJmxGg1wzVidF0wlf9QhRP/bRtLgvNDyceNv9qN/Mx27Ha5PosU
         ywI5GEiaN9LgWjmBbUN8oBl0iMuf3hjPHIQlU+aiMqRQK+ZSLa1XrRe2HERf7zXBIOXl
         roqRBN3JFNynB94xdRKzU1EoSFDDs3x9foZ1f2cwxv8TfE7ctJsi+GoXqB0w8kWyKeLS
         VYTsTFk3yvipPqcpeyQMe7FIceMY2RMvLKVr09GlQDyYN1oAcOvIVljQ0CsQY7GKrLBp
         /Lq11liqRS8XxsDVe4jTYc08tmB3BX3dTKyJhAQgk1HHRbUKglq2nOD5ixruldplQX9K
         1uGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lwLR59to;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7GlqhssEpTO/XcoYrq1+0ztg5ptqr0pFv/fi9zo9zlE=;
        b=FAZpuXo4sna4JhhHYxJYNUk9KlquANKIuCxlOIU15240Zm7upSTB8joq3YbPt2Ll2o
         pRe7ZLx/pkhVBstxu6e3RjAAknRzARlgTORq0MuKepGzc2BeP9uWlQiEX65NsTR/5l+R
         DzqvC5WgeOJdvhERZehRm3W9hpcEHnwcx3MUvsoUtzot2RNEh1Y/LuEe+7e0NboKMglU
         q+qSwLQOJWlB6RVE6HWD6Ei8CutLpqjNiss25u1V1G8V0wnG/DnYk0S1YO3OgqmvCddD
         /nalYgnLwHZy5x6JfArU9hAowIYX7Isi2S6ZSYCcSnSTL1AF6x3/zshlp/wf8FLjCXcP
         oV6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7GlqhssEpTO/XcoYrq1+0ztg5ptqr0pFv/fi9zo9zlE=;
        b=lTOd6+wJ7Qcqc8byv7XimxztGQC6XpVzaI7GA7bPM3bXa/bSb+ZbQjvp/oEY06+THs
         b550EEnf8VopH3BL7zLBNavYj7NpS1JqTNXfOKsGfGh6YsLQDPA0OyT7j2URxLtHaAtv
         t643HL0sJf6unf8moakz8UXawN153wOP62pl3M1tWn3Eg07PzMrRZ7b+8D0O3HOdG2JE
         M9L/hH6OM0C0VBHfkRafWIM3PQ+/tFY40REU9Bpps22XRLegICqAR/+sae6cxLlIUCIR
         WCvfMSXOhwwGKy4+y9+xQTVV3I+SQMTDSfiV9SbPfzhi3/VGm8RH8u2lNCE8McWkFVfU
         3T9A==
X-Gm-Message-State: AOAM533XcEfQyay0c2rHXbsdK21cLsLeVeazgWNzHKn+DJNjY8xMdgG6
	MkGCv/rDK1qrSlZEIZeB+Ac=
X-Google-Smtp-Source: ABdhPJwvqQ0QzWiSO4/RCoQ5fV9CIAupg1ZvFmh5Z5KqQ+kxqruI1BQDoLM5FwItYtITGJm2upL8pQ==
X-Received: by 2002:ad4:54f2:: with SMTP id k18mr22459039qvx.63.1638575143055;
        Fri, 03 Dec 2021 15:45:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4728:: with SMTP id bs40ls7455408qkb.8.gmail; Fri,
 03 Dec 2021 15:45:42 -0800 (PST)
X-Received: by 2002:a37:2750:: with SMTP id n77mr20909656qkn.490.1638575142623;
        Fri, 03 Dec 2021 15:45:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638575142; cv=none;
        d=google.com; s=arc-20160816;
        b=QZA+sWdKdWR1z2EvfkMZ9hFh+539BObkA1XiFPdmGgm48EsYaxBmlsEHKRJ5VjUH+2
         35kfMug/1FHUIDFxMhSpEVF9ALGIiFjqgWCRAXGWkokTO/zv38l9GUU7uoA0AgTFb+SD
         arwNWDBnZafd1bErtmSvoyMr4Ckubt3Xn7rRtRTFMjvgfeDFRHVPr/EFJMmLXxAev7t6
         jj0V8vd6abus9XDhoWsg7SZeaOfnMGi0SSTKuoEPpKtayGfVAx3nL5IksoBnwDE8d3mR
         ove1TxjfGjzGB1L3aCDdhCwwHBCA9PtpGLMeD4IRhkyKO/9AbDBSx75CVRpuAZn785mk
         3VCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=60reH7R0DIOnYiDzjJxXKxDAKSmQYMrrZWuqMItQwS0=;
        b=HKZCdRxslR9t7Kk+/TtRKx5LBq3AiReFols6JLv6+mDaM5nEMY23fvuJYTAJdIFkXS
         N3lhTRiX2GgS8KrPlJ9NdPbQjv066dvtDQLRNGjgZj1jwFMdXm85MlvvxeYQVHWLSgbk
         4q+ECiqeGySZcJ06eMYrE/sZif4F9RUBIntj5qnovy+bIcEWkhoTghmfVuUQXgzlvew+
         /+ht1vsDofZjBLC+AweI+dUH3bcjKGVKMmD7LFPIaOdm9FCqNLq8eWycU1i8yUYPm4/F
         Xh00wt+kgYGRZTg+WACI+RvuSExD6y80Lmd30rMxt863vpBgeG1JAI8URlURITGvNFLi
         hcTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lwLR59to;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id w22si940304qkp.2.2021.12.03.15.45.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 15:45:42 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id v15-20020a9d604f000000b0056cdb373b82so5387196otj.7
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 15:45:42 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr18546120otl.329.1638575142007;
 Fri, 03 Dec 2021 15:45:42 -0800 (PST)
MIME-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com> <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com> <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
 <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1> <20211203234218.GA3308268@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211203234218.GA3308268@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 4 Dec 2021 00:45:30 +0100
Message-ID: <CANpmjNNUinNdBBOVbAgQQYCJVftgUfQQZyPSchWhyVRyjWpedA@mail.gmail.com>
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
To: paulmck@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lwLR59to;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Sat, 4 Dec 2021 at 00:42, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> And to further extend this bug report, the following patch suppresses
> the error.
>
>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> commit d157b802f05bd12cf40bef7a73ca6914b85c865e
> Author: Paul E. McKenney <paulmck@kernel.org>
> Date:   Fri Dec 3 15:35:29 2021 -0800
>
>     kcsan: selftest: Move test spinlock to static global

Indeed, that will fix the selftest. The kcsan_test has the same
problem (+1 extra problem).

We raced sending the fix. :-)
I hope this patch works for you:
https://lkml.kernel.org/r/20211203233817.2815340-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNUinNdBBOVbAgQQYCJVftgUfQQZyPSchWhyVRyjWpedA%40mail.gmail.com.
