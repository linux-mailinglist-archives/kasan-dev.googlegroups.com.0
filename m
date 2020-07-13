Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2WZWD4AKGQEWHAK7CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id BEEF521D30F
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 11:44:11 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id 75sf6340963uai.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 02:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594633450; cv=pass;
        d=google.com; s=arc-20160816;
        b=akuSM6hkGqp/1oiC9EON3JuP/18RpqwtWAd7BOhIjesYL0ZRNuUymApT8IRYlpcBfU
         sINn7RT3V7AJ+JVC3txkTsB898z5R9DLSPWPumMws1Fl5Sy/IY4uHF8DS3u/Z+JtrTvY
         PsckaaJ32H+7rIqOKOJhDjZivRfB+vAG50b/xgNZQisu3q12KJlPKaZ0BqtmPXXSH+Wg
         NYNHCloO53SpwNQOUx3de0XDfyUK4AGn2MohJtrVTdefRHm53SLPSnEd2T8tPFgHn4gf
         k9trHJnh537UtIbqH2cttn+Q9J75q5GMgt330uA22rR0Za5Be/PkGLTTDIPQvj3jlJ7q
         Y1PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fbG36vvwZRL+nKmaDxVJm45M0b8DTXt5DFMW20CN6Dg=;
        b=Li6rkJnp/6HVCiQug+uEIYBz2gPQyxAbp18FHIhKXlr2/BbsciG2LIStLtk9D3BxVh
         nz5DOjuTS9ikIKlRKQDcololvJ9g4dkj2OCQl/IUA1hRlhqbauTa5Vm4eAk/s4+z6vHh
         7eZexK9G5Y0a2cdcOOVEqu3PRxvot9M+cXs20X61VuFNhP4PHfi7jb1MELvG2jnvl+0x
         4m2UJXrwzrzZYVKSTHmFqU7l/08tavFjR4uxKkd63jiVcjPkiiKbutaIxI6w7PThLRj0
         FXFLRr+XKbaePyiIFwb5jvO079pV4Fav4++KcXejSZPv8SnUE5+OiaQ5C6ArWvsj9y/P
         6TZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSMgQy5y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbG36vvwZRL+nKmaDxVJm45M0b8DTXt5DFMW20CN6Dg=;
        b=QG0ElJgD1B82QY5VmN0TqzAsmLvnsJifZSnpvi5OoofDS09U+G2q7f2rOxkrGLsPBe
         dPZSURhWDvRgWPmKqd9VsO/a+LdSxssE/9ODip2lWUwJANngLl25anJ9Rmjg/DjCzpl3
         sDpwydN4SHSwCrR2PqipRpdERiHeBts2ebg7nQo9/CMpvkFH6LUSv8wiyGT+eSG9ORyi
         Bpf14N6+fmDLCsMIcadgwHYR8weNIdgQKNpH1EtaKd9rnkW8HvHBhCnCyWYmGKgVUOZX
         cIWfv8OHF9V8qsh+aIZPPAuWMn8xkWA5dbgspSFgBdF7xFi5OtWqaGBGyEVYvP90gpI4
         MT9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbG36vvwZRL+nKmaDxVJm45M0b8DTXt5DFMW20CN6Dg=;
        b=CnVRxPpJQpm+ZAd66pQhij2q4p6ThI4gaUVDI0unk+j+7gtYxgsO+R2hg82o23bGei
         DnKKoauq+S9c/GzdbJP2Myaf98U971/IdeEkYwmoCWLm2YQhjYYoL2EAJ0kliPFehTXx
         ebGTu9upIjXZJzVprhoZN4CXw6/EoLGOTvrVi7B2F0UdN5wcl6mKWSXmcC86uGMqjJio
         gEHqlZiPfWDSXXWZ8GsFmCjVwWQF5C57B3YcS5tWg6l5fFFwc6TKWRO+QKSaVGGM31UB
         J/jPQUt+q5ebfKnLbC+Mor0D7TdzXxCYp6kGjwFMRszpUtegBIZxy76XDCibhyMpRvAz
         dk6Q==
X-Gm-Message-State: AOAM532GLMZlyTQebTMBgupWN+OovMPkY8kEz/9hjDeJbO7s7fFnRTjm
	hCAL0d/ZorU+QP8kNLdoYbQ=
X-Google-Smtp-Source: ABdhPJwOPkDVHivVO7/QYZeaQnX5KgVe0oKTahpsikEczn+EqHNHaIJDw+mZ6LCmopRrGwEyp6Q85A==
X-Received: by 2002:a9f:3ed4:: with SMTP id n20mr55791604uaj.39.1594633450582;
        Mon, 13 Jul 2020 02:44:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:634b:: with SMTP id f11ls1084158uap.5.gmail; Mon, 13 Jul
 2020 02:44:10 -0700 (PDT)
X-Received: by 2002:ab0:2408:: with SMTP id f8mr49713572uan.91.1594633450179;
        Mon, 13 Jul 2020 02:44:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594633450; cv=none;
        d=google.com; s=arc-20160816;
        b=Gcj3/NOKzUz6B8EUdk8w5Ox8BjsrwYz2Sk/ThChGiy7m8GD2sUxh9Xty+4xzPIz341
         Cnl+QxNcbqZR6haIgdrCmahmsoYrvft2t3YlAWr4aFFJU9TT3rb0NAbBK+ESi/KBk1aU
         3iJsKaOIgjNsXscnme9QJptOscTSI8BZwRQDyVekJUTXhYvgN5dFF9/bMuSUqo5v5n1T
         gIqlKw94mpiQxW3Wq14eAIskKc5VBv5pRS+ihDuyscSIJydBuRcECLLeoIuKCdtRKABs
         FByKBjFJV1O25Z1N/y995PeijlRdc+fKHnEXkLlCcAwhTqsMjyyst53D9pOr8ep4/PcZ
         /Www==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6jaIJflUL9k2e2UMM+JSLx1wjPZ/zAPnXmkJg4wz7mQ=;
        b=NnMju+U2Z7lmeso9IJB9M3sgDOVAmgnwIfcWlR0iAz0Kj6j9nMVadn546x8nNF5dId
         m7nOl9RYYKpPqlEpOUevfZobKVtT+z+63DIDdnWO1rBujRRFgVeG9G9UJsH0e/LQCIhm
         pMi93eLqmfygeBSci2K1lUWksn1PCAxKuBRwsfhm7l8tWhQqVOnDSKMqWzQtH9UKXZ3d
         EPugzmNgWbo5YjYXBvuN5+sscrS3PxGWoaQfuFHFXw+V2JWEgIIN1IxUm5CpFYsZTXaH
         SB4G3qyhcpeCfRPDDR8dDqz2jgurN/HJ+ovQIMEIk0LGBwDZBJfpMJa48iaVCFg7ckVH
         DCkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSMgQy5y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q20si660434uas.1.2020.07.13.02.44.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Jul 2020 02:44:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id h13so9079947otr.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Jul 2020 02:44:10 -0700 (PDT)
X-Received: by 2002:a9d:4b01:: with SMTP id q1mr53019086otf.17.1594633449383;
 Mon, 13 Jul 2020 02:44:09 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org> <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
In-Reply-To: <20200710175300.GA31697@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Jul 2020 11:43:57 +0200
Message-ID: <CANpmjNNetBqbqDbRS8OQ9z5P=73vAXG2xys6HKSg_dzqp9ksqA@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NSMgQy5y;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

[+Cc clang-built-linux]

On Fri, 10 Jul 2020 at 19:53, Mark Rutland <mark.rutland@arm.com> wrote:
> On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> > > release before sending the arm64 patch. I'd wanted to stress the result
> > > locally with my arm64 Syzkaller instsance etc before sending it out, and
> > > didn't fancy doing that from a locally-built clang on an arbitrary
> > > commit.
> > >
> > > If you think there'sa a sufficiently stable clang commit to test from,
> > > I'm happy to give that a go.
> >
> > Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
> > (famous last words ;-)). We've been using LLVM commit
> > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).
>
> I built that locally, and rebased my arm64 enablement patches, but it
> looks like there's a dodgy interaction with BTI, as the majority of
> files produce a build-time warning:
>
> |   CC      arch/arm64/kernel/psci.o
> | warning: some functions compiled with BTI and some compiled without BTI
> | warning: not setting BTI in feature flags
>
> Regardless of whether the kernel has BTI and BTI_KERNEL selected it
> doesn't produce any console output, but that may be something I need to
> fix up and I haven't tried to debug it yet.
>
> For now I've pushed out my rebased (and currently broken) patch to my
> arm64/kcsan-new branch:
>
> git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan-new
>
> ... with a note as to the brokenness.

Seems it's not KCSAN specific:
https://lore.kernel.org/linux-arm-kernel/20200507143332.GB1422@willie-the-truck/
and https://lore.kernel.org/lkml/202006191840.qO8NnNsK%25lkp@intel.com/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNetBqbqDbRS8OQ9z5P%3D73vAXG2xys6HKSg_dzqp9ksqA%40mail.gmail.com.
