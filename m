Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3UMQ6HAMGQE4FX3ZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E373747BF95
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 13:19:59 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id g2-20020a17090a67c200b001b1fe9bc843sf142513pjm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 04:19:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640089198; cv=pass;
        d=google.com; s=arc-20160816;
        b=qVaVXlbX89vy/lKWX7ahAih+CEWOPXM2ZuQ22+X+wxXuzqYy7YlWQBfd0COwu/WKr8
         M8ToLvCupVmMmFSd1snTdOu8frhF47EMwiKndrHFfbIf3hXpaWn6qY3Rg1fNJPi5CmfY
         wMETCdgE9iK9E58sI5u7+9/JDrYlI4gnaSE2mlCoV5W4LdT5vCES3Xajl+Vgr9MtzKVz
         GPt4PNLNb0MSbXVPhlRh0p/6/p4ABx8PseZMAfWAsaOGb6VgkYqbWBndkebIFVW+T2CQ
         xqqwPS6uuEAgP5eAcWkyyBn1Wr0QlkGm1EOfTXEw9Q1rt8Ob3x66V6RbgRtKRj0aWo58
         cGbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q7nXlLnEy7fzMkosmt9IZBgd509w+GQq/ZrbIKGIlGw=;
        b=lEewxKdeXCuoKeR7owE2DQPj579uIYvhCh7TGdNAZXXEXLVh/dop6yFr9A0oO4tA2I
         JCa2hWhgMxXF1THEkEV6eD5fzmKfu9evHQsggh9swfdsE4HiiTpgORJHlW1KjY81vVA7
         Bh5/c3498Srrx/xjL5gTDwim+QYwAkWcJfmywZA6INzjfwxmZWpEgbDJ73pDoOpkKXyy
         9dwL88EJrnFKHmTweGwyP1C2PnTbqpAgumGBOf6p5S1F7huGSpeUI4//pm6vZcmWIsb3
         m5U3lk8s+yWGcEkEHLXxKD1XIjHsRImwcdq0hffEVLRCRkQDXMyN/wRByB2A+MXjrCVw
         Wx0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DOY8PDnO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q7nXlLnEy7fzMkosmt9IZBgd509w+GQq/ZrbIKGIlGw=;
        b=Gz+PUvsOoemc+hZeGhNfxXDDcobVybI124ftX3S6x++o1zfiZwPrWJZ+9OsV4o3tNO
         dYNkPnU+rpm6Xv5WklGEPsalDCR7i0QAtPuT/aRvQukQ2I2eHfLWFwHDU2DqVqNt8msD
         xWc0DgYyVGZ8oPMk536fP6HE7YtlQ240zvH7qE1VYSoeYabLGLTjKEpnUYb2oswCK9eI
         GRzoBaiKmbSQbBKGV6IaEYyDUK74SCSsS2q8vmeyJPnBNEHtFN1oVO0sdkQEDWZDlNt/
         N5LJXuGdqg40Sv2D/z+ydAHDjj4LQ5FkBeRjQXVAwskApA1c7jenZzYI+kfMOEJ3T/t2
         vzMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q7nXlLnEy7fzMkosmt9IZBgd509w+GQq/ZrbIKGIlGw=;
        b=hdeD+BsxNaXj5k3nJxRQYnS8ubHuQL0CQ57/bdjT3hzCHuk0AfQ33S6y20YbZxkWFq
         9Q2/JLmdKSG2oz/8xd04a8A7x+f5jpUQFlSGAfq6THHPvcaX+smmzqmuIqj0g3ab5dly
         PrRzNnaGPWkN2kPbqOBuq+e3RaJUXFKP3Ai06ZUegAelI7i5p+Vj4FTmLj61EFTrIa4u
         SUERi4jpccBcq+SJqbEsPbvtbE0N4henwuNEq1X8WaB1oZ4zQvru86u/RbZW2rwAVdmC
         iOPwnENMtfWirV+5+Vet908sJFjYuMaNhcJf745G/EoTEODo1n3M1pqMsypuqANMTI9I
         5WFA==
X-Gm-Message-State: AOAM532MfDcBMGFFWZiFTOMKdT3eFJJg3mWf6+JcFopqXXTAi2zkMSM5
	8OkZfsEuYsu6H31LXRW5joM=
X-Google-Smtp-Source: ABdhPJx3UFIHdKAJaYe0fBzsGY5iyzFeyOoLqaQQezIGHUnDxtn56aw5JAajqXzrQiZ/+sLob8A+LA==
X-Received: by 2002:aa7:8f37:0:b0:4bb:a19:d3aa with SMTP id y23-20020aa78f37000000b004bb0a19d3aamr3094363pfr.1.1640089198232;
        Tue, 21 Dec 2021 04:19:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:13a0:: with SMTP id t32ls1938919pfg.10.gmail; Tue,
 21 Dec 2021 04:19:57 -0800 (PST)
X-Received: by 2002:a63:ef18:: with SMTP id u24mr2739785pgh.573.1640089197595;
        Tue, 21 Dec 2021 04:19:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640089197; cv=none;
        d=google.com; s=arc-20160816;
        b=MHCKFSchPmD2ui7Qt7GwYkJkj044rjn/SsB+FmGR3mgCE3Yb+I9uHgxNgFQqMOb2fY
         SOVDxcvi9M05V50JLnRyk8SQOcgS0RfT1JmhlR5a4kjo6kmWBg1AiCfRo4/fSmpHPE8z
         eOtFSsSYEDwbuWGDcExqPAYTQ4qitVgJ3vljErOvyu3uIgtOtD7/Cd9MMAocuwNGvswz
         Lzvcuv4p28dvyj9xiwX3+PssZVVJLu1zRqySU41G3zFPv4ppIA2pKGJ2VrndgH8koVI1
         pHdYkWEh21F5zO3ADQ6DNEj0xkzlAnXwqLOfjFcTtMxcCiIPkdDkF4LJu/3AtoWjF8S3
         ffkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BaXR+Sf/o4pHq2K7zFqOPHm0HQk54kBEfN6/GC5fgeM=;
        b=BFLNkOdGatGt+hIP0LAscLIS/uaHX58lIUANRQN1NLFzMERnr91VbL2Cj7lf1tfWmy
         GxiqXPftWz6RyFWYvt/RqqyH+GgpE93EkSl4wrhULtlvCbudTLj1OUczJjQdL0kSSKF3
         CnFRYS4r0E88KvDfjbSKRuqnutpNUXvwL8KD17CG+O9jd99KypaZuloDiBJC4tSORYON
         7m20lxz4mron15ncNPjDQvbz/L2OYoRfEZLzl80uDwYRqPUXVSDyBILJB5zoGyqBHhyK
         cKWZPglukLryvt+3TG7kojlTnArua1+eDf+rTRH8VUX6osEF7vMRtFerWrwB7ueOzBvM
         soPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DOY8PDnO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id q19si1275715pfj.0.2021.12.21.04.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 04:19:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id m6so20600718oim.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 04:19:57 -0800 (PST)
X-Received: by 2002:a05:6808:1903:: with SMTP id bf3mr2240565oib.7.1640089196762;
 Tue, 21 Dec 2021 04:19:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
 <YcHFKSNDI8KJKR7y@elver.google.com>
In-Reply-To: <YcHFKSNDI8KJKR7y@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 13:19:45 +0100
Message-ID: <CANpmjNPDsr36JQ4y_nkBVgaEXp+oqxuG3th8Ftr5rXMNX7V6JQ@mail.gmail.com>
Subject: Re: [PATCH mm v4 28/39] kasan, page_alloc: allow skipping unpoisoning
 for HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DOY8PDnO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Tue, 21 Dec 2021 at 13:14, Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
> [...]
> > +static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> > +{
> > +     /* Don't skip if a software KASAN mode is enabled. */
> > +     if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > +         IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +             return false;
> > +
> > +     /* Skip, if hardware tag-based KASAN is not enabled. */
> > +     if (!kasan_hw_tags_enabled())
> > +             return true;
>
> Same question here: why is IS_ENABLED(CONFIG_KASAN_{GENERIC,SW_TAGS})
> check required if kasan_hw_tags_enabled() is always false if one of
> those is configured?

Hmm, I pattern-matched too quickly. In this case there's probably no
way around it because the return value is different, so not exactly
like the should_skip_init().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDsr36JQ4y_nkBVgaEXp%2BoqxuG3th8Ftr5rXMNX7V6JQ%40mail.gmail.com.
