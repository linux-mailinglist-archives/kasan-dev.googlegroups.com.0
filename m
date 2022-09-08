Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV6B42MAMGQETJNCY2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id CD5875B161A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:59:20 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id x25-20020a4a3959000000b0044896829889sf6995141oog.17
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:59:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662623959; cv=pass;
        d=google.com; s=arc-20160816;
        b=ImdIO4rnG8WovV/U6nBHJhBmgLCpRzPFWAe61uj+Y1LtjnmY16jJD+xbi9un4pE5Lx
         Z+W9zbzk0Z2GJbCQox1bh4H5x9LIjf+c8FTw1kSkkpam+fakONrsPez2XIJ9cp/vpXRZ
         7kpGvx4HehOAer1HZcjs40Wxr1L0Uyd9Wo134H5+eAvCAq7kY25kYOk0fUscf6BZMCg0
         JJ1Q7/JBJTmFn1KZetHyhZlPojv+lYQfPF03Y5cyZtF5CD648RrAxEk7o2aBx45qkoH5
         Ll7TcYLSYUoyKNn8p4BmLeGd50xZbk+D8LcttF/ASVyuz4peByxQblkx4ijOs08rTcl7
         5inA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GDsCqO3F5KymU2QhlD3nN9RnOgzTWtEfu2fBEycOUKs=;
        b=wvzDQDoOG1C+rWJDsuwPSvYKgr8uOZjXvgo0k8DozloNxLSyOmzv66sqe8twZ9Cqa1
         TP3LhWfNP0qHN1ckR4B1F7vywwo8Zm5pPE4MKiu/l8b3d0HDO9m8/Lg/mldDZgk/jdqF
         n0YRSspzGJvJToeSMF32TKAGsSRGExRkwMSgnFDYFL6172mz0FwJacckDpsBTDKD3WNr
         /TZhBU90ruM8zwiU10raiyB3Xfhrmj7qHK81WgLfT/bkiUFiiVilEFfEdsGpcCyS5Ie5
         khXRXeXYwgT5pOAruObMqqSpDAt40CdB33zXuEfpMuRe833SWczJvU54KWh7SZ1CUkK2
         kmGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HkUFRA8C;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=GDsCqO3F5KymU2QhlD3nN9RnOgzTWtEfu2fBEycOUKs=;
        b=QY4bHHHAZ3necciqviWPve2okA9AjojKFY5sN+MoGiA+GSVPMfE30lxyrYZMeoU1GC
         ELwdr5ASpj5s+PdTbKu9TNClHTAblWsBUPtNfW1IGGI1babg1JDHirqJOvLtv9BTKXns
         L2KYtjKpSeLCC1kNTLD2xCHEaQYT6GZibHNSySF/upt1WYo4/WBvYax0S4WRP0LLvsiN
         1SKTm+eAjVvmPUpgyYyp4tbfR2IIXZYl5k8v4VUtSpxmMFMtDW61dBd+Z6k5WsjYJtx4
         3PdwnhkZHxkZJt+7zIb7rG5ILKUZLkukm20u8lBnmmIvuO+zrnyIvsEC/Et9SL6w2fQk
         AV/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=GDsCqO3F5KymU2QhlD3nN9RnOgzTWtEfu2fBEycOUKs=;
        b=Wapq8cEpQYgecfyz0E4sBjGr8IlBIexYg2atoMitSn1J+tpoO0MuQ6AoQKhBT14V6T
         pYpUo1eSPwQihOuSGQm5OtWQaj9uwqzIBZRc9z8sVeUMei4q3tzpFSIcP5i8gFm7RYYF
         PmytPCsGUaqt93JtwAvFEReI99b2VXYRzzwhxY9z3vs+0b3Ts0NoqgipSQjKuNB/lfU/
         PBOQYf1jfV51UEECdjsP2FnlsP4+qm9lcPyBEnXMsj/VYx+MmBwVVdBqvW+IGY2Zxmrq
         z5qciDlxwiDZL/kpLKUMjpQ7lylufYgjGkAD+nFEypW15byngkK4LnwLNNES2ONioAN4
         t4rQ==
X-Gm-Message-State: ACgBeo2IS5RBJvp4ZI5P2u0A+UhojlN/N8Q4AZS5RNIzC4cunJL4hQxU
	XyQSDaZC4L4WwvAaDs1krBU=
X-Google-Smtp-Source: AA6agR6XaVGAd0x1S2O/C1eeJr5qk6HHlpFmz9Uoqo7uJz85s61IucGByyyHNG6dCL0nug0myoKCjw==
X-Received: by 2002:a05:6808:e8f:b0:34d:beb:49e4 with SMTP id k15-20020a0568080e8f00b0034d0beb49e4mr540896oil.100.1662623959558;
        Thu, 08 Sep 2022 00:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e1c2:b0:11c:88f5:79d7 with SMTP id
 g2-20020a056870e1c200b0011c88f579d7ls375113oab.3.-pod-prod-gmail; Thu, 08 Sep
 2022 00:59:19 -0700 (PDT)
X-Received: by 2002:a05:6870:c884:b0:118:ae35:e200 with SMTP id er4-20020a056870c88400b00118ae35e200mr1272377oab.244.1662623959158;
        Thu, 08 Sep 2022 00:59:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662623959; cv=none;
        d=google.com; s=arc-20160816;
        b=ybxopFNXZNIkiSilVS33lVDOHmgqyAOX9s1plsgayx3ZJb3etbUS+QI4bicQN+h5jr
         zIgpaViIPtiYI1kNXtVMY3fkzzRsLUrA4puGxZ1iOiEgjXOqzRMFRLppcAiDJXuyN3Iz
         /gzPvoIz/dEdziWKiO59iOo1l/LEVKn0SbzJ92GPKCeXigbyS77d7pA3pezqediNb7ZT
         bWyHr+BVK3aaf1LM4d6Jvf+J2gRoEhxjnHfS59qCz4klloPBd/hFuhC7o94QiGBV9HhH
         nvGiw+Sdh/7H3vwdWtIjxdR59c0th80X4SEf7lK7edeNmoXIbBl5AhYnFqv6cqXg+bVp
         eL/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AED3bGnj1lFXZEETrGBbS5jh6P5l9CcrTpBF9lOrNE0=;
        b=aZuZoN34S0faeiGIPFz+fjfzqu7JfiE1zpnZ4zKPUi9eHFKklPd4gYrHjfAhJSqOiU
         Ny3evHvvc8WnBMbz8GYb4CJ7svGkpKvi0d9byGNVpsQM+Ah65cqR10asyos4W0KwOxdW
         XQvhj/W40jRsAUwmZiunISvShUiXsc23vMR7tNnxUKuRHIwZ/GLRqqrcglxKzP/eLl7x
         BoTmpkcM7x8Y8B/CJS0G1gncTwRaJtQwyCclsPGePyA+4CPGPbbWSrfMFz4fNJaJkyOU
         SbmKfYp88KE5AaiRadutxPP8phjnNpoYz5BpjM6JSoEYkZqUbe9nG9eOpdx2ixleY7Of
         0Dqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HkUFRA8C;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id s32-20020a056870612000b001280826e23csi362951oae.5.2022.09.08.00.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Sep 2022 00:59:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-324ec5a9e97so155115977b3.7
        for <kasan-dev@googlegroups.com>; Thu, 08 Sep 2022 00:59:19 -0700 (PDT)
X-Received: by 2002:a81:a16:0:b0:345:afa:5961 with SMTP id 22-20020a810a16000000b003450afa5961mr6297647ywk.11.1662623958715;
 Thu, 08 Sep 2022 00:59:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220902100057.404817-1-elver@google.com> <YxiQ87X1eUB2rrtF@hirez.programming.kicks-ass.net>
In-Reply-To: <YxiQ87X1eUB2rrtF@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Sep 2022 09:58:42 +0200
Message-ID: <CANpmjNPwtmRbj3zRTWS9hL0wawuSQV_2SL0fvnb5e0J43MaNag@mail.gmail.com>
Subject: Re: [PATCH] perf: Allow restricted kernel breakpoints on user addresses
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HkUFRA8C;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
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

On Wed, 7 Sept 2022 at 14:39, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Sep 02, 2022 at 12:00:57PM +0200, Marco Elver wrote:
>
> > +/*
> > + * Check if unprivileged users are allowed to set up breakpoints on user
> > + * addresses that also count when the kernel accesses them.
> > + */
> > +static bool perf_allow_kernel_breakpoint(struct perf_event_attr *attr)
> > +{
> > +     if (attr->type != PERF_TYPE_BREAKPOINT)
> > +             return false;
> > +
> > +     /*
> > +      * The sample may contain IPs, registers, or other information that may
> > +      * disclose kernel addresses or timing information. Disallow any kind of
> > +      * additional sample information.
> > +      */
> > +     if (attr->sample_type)
> > +             return false;
>
> This feels a bit weird; should that perhaps be is_sampling_event()?

is_sampling_event() just checks for sample_period. In fact, we still
want to set sample_period to get overflow events. That in itself is
not dangerous.

What's problematic is if the samples contain additional information,
which can be specified in sample_type. For example if PERF_SAMPLE_IP
is set, it might leak kernel IPs, and that's bad. Since it's safest to
disallow any kind of extra information, we just check if sample_type
is zero.

> > +
> > +     /*
> > +      * Only allow kernel breakpoints on user addresses.
> > +      */
> > +     return access_ok((void __user *)(unsigned long)attr->bp_addr, attr->bp_len);
> > +}
> > +
> > +int perf_allow_kernel(struct perf_event_attr *attr)
> > +{
> > +     if (sysctl_perf_event_paranoid > 1 && !perfmon_capable() &&
> > +         !perf_allow_kernel_breakpoint(attr))
>
> I'm on the fence about this; one the one hand it feels weird to have a
> breakpoint exception here and not a pmu specific callback for instance;
> OTOH, leaving security policy like that up to pmu drivers sounds like a
> really bad idea too.
>
> Keep it as is I suppose, just me thinking out loud or so.

Ack. I also think this should stay in core, as it's also easier to audit.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPwtmRbj3zRTWS9hL0wawuSQV_2SL0fvnb5e0J43MaNag%40mail.gmail.com.
