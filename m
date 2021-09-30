Return-Path: <kasan-dev+bncBDVI5CPEWYGRB4VS2WFAMGQEF3WMD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C8B41D35F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 08:30:11 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id w26-20020a056808091a00b0027630e0f24asf3687494oih.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 23:30:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632983410; cv=pass;
        d=google.com; s=arc-20160816;
        b=bbcDpVvjyB4ClFEmY+mHnBoiv5as0XibYn+/CTK4CJsgBpMWvjrEX8ITHZjNDcZ6wK
         4CWCXSnZG2+QQF8wFcb3PmAMcoUt1QhThljms14vbX0zGZ/NTyi1U2f2L6fQTVAosVLF
         Ofp794/5++zr5/sJWlbvDM6fQ0z1CD7ygO1RTbXGbc6KMonI/Qc0DcG9DLdFisHg/BzP
         uwiFSYM0zUuFpzxsuslZkw04wIAYKLv2E9vyY2f/Ce0FMkskw2jGuWWBe/lDK1dDqzcz
         n7dEN47zAUenYYWQbcWX4Dwx3bQtk+TwHs/oK1Yg6YUCm02HXmT+us01s+eedfrnPrn9
         8ZMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mOSqMbSPSitkZ3DbLWN1Fm1bkKZr+Gc/5PN3/SW3ICQ=;
        b=rnEF2eXJDv2394+hCRtgWQzJqfab6oavHujgsy5zkDrfC0Mx2eFJFvoJUI+gjpv/pS
         dnkeUT9vgdkVGsc4C76JJMlvG5IqYNoB4rXSTETrBeLKOzHSJhWR8gmgXOscB86al6dG
         K6FHKmV7B77HPEigEMq2G+601iicWI6UiSKCXFknudZUkLmsYxvEMQL47dFCeDRmmfDV
         F5zWuE8I5Ypk95U9SPzrvAEBEuA+xbyXlY2O0js0GCsk+R0PxMB4VPOQMcaVs/BUsEBa
         Vrj1gKCTUVRiq/H5XQRqp3o6EQE62gooEPsT9vGKc7GJjfGr3/iDQOC2snoodYJf8A2l
         Fj+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JW8rsKyC;
       spf=pass (google.com: domain of zyjzyj2000@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=zyjzyj2000@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mOSqMbSPSitkZ3DbLWN1Fm1bkKZr+Gc/5PN3/SW3ICQ=;
        b=dhPHAMdWYPGIBxEQhKKtRqtAiXqcYBsPlH9zHX7pIpPdERGQgncuGbLutHPQQJpDbr
         cKw7APt8de2MpGP/bBK3Y1HVyg3mR51LekHyrj8n12B5WEuNXaOYr+y3pnaq+GtGlGGb
         19GQu+S5E2bA4innHGFjWcm13rm+Gm04dpu7cHsdV8RsnodHXAPraA7z6Z7O9nmCAtEb
         Vxg5lJPxnypbIZTz/Ix00tXaukWJRs5B0KpnSsLSnuhV5S1so2ENMiWj+M/ezE+hswjc
         FdtNi6xE/zQ9RolzH6sua9pooJRu6lMfuT9BrznpHeuuTYlq0bksCC6iECToMdo/dSCX
         FA5g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mOSqMbSPSitkZ3DbLWN1Fm1bkKZr+Gc/5PN3/SW3ICQ=;
        b=SvrnTOkKHahBE6h470AoSHylldUUF9kk++2OF0VhUBf6j71ukB9zMeGvmslXdYYZ1u
         0fOJPJgzgmgJ/ZxB9AKkePoXHyPUb9Zl5EwiA5RhDTRXYguRDINeMFh+WZqHLB/5i+8j
         +YQct5q5/St5s/GujmJ67J9Jr+MPjChkqcX7PGg603Vtb4SWsDDLzHuu1cyqwK4rXCgN
         7Q6/jxHvkKtaQBtNqs2qE4wzOo6WjbWAsLIqPXc2ztGU4v1sLY9HuPxy5OMyuJx5bPj8
         6sSRl30vafaSpKYaJl4W0xBMUG85NyyfCXzQKfyUHAyIO+wlYoO5RzJ9nqB+DoIqmgXk
         KLYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mOSqMbSPSitkZ3DbLWN1Fm1bkKZr+Gc/5PN3/SW3ICQ=;
        b=K50Cx0lVYNr1pXv1h/jP/7oSNhtpeaYhqtQrd/EcEG9OaiHRWM7eYFDn7jlldpJL08
         BHZcjR3Aw2V697RFPVoHq/FCNawcKz2ss6zZ6Cztxqzya5WMFV2ejVYuER9VbFluuMpK
         tmQa9eyRpzbBgJasNaF8LlNNl1emf1cDDrlQ9R9pdn6eyT6a3HDv5/tz4GETsEliE47S
         XiMBo+S+/izaE3q0ORDGuACIDlge4une1A0UN27E1U3guKYeuuBrpVh4LBmjUYUHY18i
         rUIJMhGVPpTNzTqPs7iDYrcmq1BY7LKt7jQJUvgEePJNoBjjJ1hpT/EiTAfCvvme5blz
         W/MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rS4hWicakhB7Ww4C9yrmKWY2Vfm5wdGqIBJBYYQ/eOy5UZvud
	qGVdgbrrvxjjQjN0jXsjgCY=
X-Google-Smtp-Source: ABdhPJyRSZJYbiNPZxPp/wgJyBmd6dT6dwpTAcSwLdxY6cMA1v4MSwyW2/BdTUsL1vN2bH5R0etROg==
X-Received: by 2002:a05:6808:1148:: with SMTP id u8mr1378673oiu.33.1632983410357;
        Wed, 29 Sep 2021 23:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1010:: with SMTP id 16ls1747072oiq.0.gmail; Wed, 29 Sep
 2021 23:30:09 -0700 (PDT)
X-Received: by 2002:aca:1717:: with SMTP id j23mr1436507oii.73.1632983409877;
        Wed, 29 Sep 2021 23:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632983409; cv=none;
        d=google.com; s=arc-20160816;
        b=txX6Sa90UKVFUASRb00v/hNtJayXOlVfCl/s1/TAI1/+vfwgt4DIJQoRUXHPD9ZVH8
         m/YYjw1I1R5qxo3DKH8+DuZVpAfO7VPCuT6CuhRDKyW2PloL6G4pzdvJFg///QdwKqNr
         6DOty1kzA62nRDBb+8JClwb26J5yWiKLYYpBg1vzxJWUQlFvAFl82T9UIfJP0CDAYI7u
         O4iNRp6u3f90E88wQZZeDv+yeGGMidBYhu74Jz/n5x0oLV6qq/aOclxAiRpFFizBzrxD
         AFz30mUAgRmb9BYc1kbKRXQFywpQZJQSMk7CgQI/ervkQLgBaSAb5DprcHQYlQZI1Tia
         x5PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GqfP8vBSqUYMX3sYTgLFInVLSzs5ln2/9w25WL/OS4Y=;
        b=AUodengzRNyLoigRVyTAAffb5lBJOp79dmTVb3otI0IJ24tdSOdnjP2TVuJbwXz5vJ
         xiNbNyJ+BdZ8dcPGoZVE5pLqeplA+9QeTg48RkJP3/T4RjrjwC8gvsplRsKaT7CbOJ3m
         Hj8m3Mz2wthW1YmeMoQoV1frhZBEAC98lXIco3/pLAUNwE2QYoN2VQ/mVnX5eg4N7Dla
         Hf1Dazo+0vqQ2o2qGku7zMiJ2JzUj/CaAX687FIRsVr7g8MiF5PMhBv4dRHg2fDJgCya
         TEfyEQpHAjbFVQ7ag4qWosBSC6EvGmcQMyvMRgfpmya7xJLlKoOQ4C6ZDALHHRpJuIwB
         Vv9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JW8rsKyC;
       spf=pass (google.com: domain of zyjzyj2000@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=zyjzyj2000@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id a9si463404oiw.5.2021.09.29.23.30.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Sep 2021 23:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of zyjzyj2000@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id 77-20020a9d0ed3000000b00546e10e6699so6010260otj.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 23:30:09 -0700 (PDT)
X-Received: by 2002:a05:6830:89:: with SMTP id a9mr3859332oto.121.1632983409679;
 Wed, 29 Sep 2021 23:30:09 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMKCmEHUnKz5rdUkd1HSuLj_S_vaMu+Hr7MuB79ghMERA@mail.gmail.com>
 <20210929234929.857611-1-yanjun.zhu@linux.dev> <YVRfQDK0bZwJdmik@elver.google.com>
 <606c859b9df4c8a1019a7fbc3c13afcb@linux.dev> <YVVXC450yCxgI3T3@elver.google.com>
In-Reply-To: <YVVXC450yCxgI3T3@elver.google.com>
From: Zhu Yanjun <zyjzyj2000@gmail.com>
Date: Thu, 30 Sep 2021 14:29:58 +0800
Message-ID: <CAD=hENez39qiGGi0bHvvxiby1wSWtoOqCme9vQCa9inF1907XA@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/kasan: avoid export __kasan_kmalloc
To: Marco Elver <elver@google.com>
Cc: yanjun.zhu@linux.dev, ryabinin.a.a@gmail.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: zyjzyj2000@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=JW8rsKyC;       spf=pass
 (google.com: domain of zyjzyj2000@gmail.com designates 2607:f8b0:4864:20::32f
 as permitted sender) smtp.mailfrom=zyjzyj2000@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 30, 2021 at 2:20 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Sep 30, 2021 at 03:50AM +0000, yanjun.zhu@linux.dev wrote:
>
> > >> -EXPORT_SYMBOL(__kasan_kmalloc);
> > >>
> > >> Sorry, but this will break all users of kmalloc() with KASAN on if
> > >> !TRACING:
> > >
> > > *module users.
> > >
> > > An allmodconfig but with CONFIG_TRACING=n will probably show you the problem.
> >
> > Follow your advice, I changed CONFIG_TRACING=n in .config. Then I run "make -jxx modules".
> > But CONFIG_TRACING is changed to y.
> > So what you mentioned does not appear.
>
> CONFIG_TRACING is not user selectable but auto-selected, just have to
> disable all those that select it. See .config, which breaks.

 Symbol: TRACING [=y]
  x Type  : bool
  x Defined at kernel/trace/Kconfig:114
  x Selects: RING_BUFFER [=y] && STACKTRACE [=y] && TRACEPOINTS [=y]
&& NOP_TRACER [=y] && BINARY_PRINTF [=y] && EVENT_TRACING [=y] &&
TRACE_CLOCK [=y]   x
  x Selected by [y]:
  x   - PREEMPTIRQ_TRACEPOINTS [=y] && (TRACE_PREEMPT_TOGGLE [=n] ||
TRACE_IRQFLAGS [=y])
  x   - GENERIC_TRACER [=y]
  x   - KPROBE_EVENTS [=y] && FTRACE [=y] && KPROBES [=y] &&
HAVE_REGS_AND_STACK_ACCESS_API [=y]
  x   - UPROBE_EVENTS [=y] && FTRACE [=y] && ARCH_SUPPORTS_UPROBES
[=y] && MMU [=y] && PERF_EVENTS [=y]
  x   - SYNTH_EVENTS [=y] && FTRACE [=y]
  x   - HIST_TRIGGERS [=y] && FTRACE [=y] &&
ARCH_HAVE_NMI_SAFE_CMPXCHG [=y]
  x Selected by [n]:
  x   - DRM_I915_TRACE_GEM [=n] && HAS_IOMEM [=y] && DRM_I915 [=m] &&
EXPERT [=y] && DRM_I915_DEBUG_GEM [=n]
  x   - DRM_I915_TRACE_GTT [=n] && HAS_IOMEM [=y] && DRM_I915 [=m] &&
EXPERT [=y] && DRM_I915_DEBUG_GEM [=n]
  x   - ENABLE_DEFAULT_TRACERS [=n] && FTRACE [=y] && !GENERIC_TRACER [=y]

From .config, I got the above. It seems that CONFIG_TRACING is
selected by a lot of things.

Is there any method to set CONFIG_TRACING=n?

Zhu Yanjun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAD%3DhENez39qiGGi0bHvvxiby1wSWtoOqCme9vQCa9inF1907XA%40mail.gmail.com.
