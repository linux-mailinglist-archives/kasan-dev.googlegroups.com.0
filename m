Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE52T3UAKGQEYGWAATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D251484C3
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 16:00:53 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id x72sf3574027oif.13
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 07:00:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560780052; cv=pass;
        d=google.com; s=arc-20160816;
        b=WGRoWta8V2mXOD5kEUHzsf0oslxco0FPgvXucUaP5Hz+OnyovDpsDjqFUmGh+iwqwr
         eXu8A+6B6dERS+XC+NrqYm+v2XKj1zCcX/OOQdZCdfRCvB+kVUGqdh/ECRsbWxLN+xm1
         jG63UxfYnnnnDnRIMjxTH6A8jIeI6vD7mYJsE6q6oq/m/hfSLIx9LXMZGHcvAthV2LHK
         vXSQ4ve0s5PgZ1OThKKT6dh+cNk0eHMZoty3kiHM38rVwCpcTIs+Ia11Jzw8KqIfl6Gs
         MpXQ2R8uf9ZlimEWA4Z/vB6c/I+wN3q7D8t5QFsMm/aLPkzsk+jMcYEA7ItA1djpQvzT
         Acew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R5jtrjo3NXkPzkOsib6nODue+gT50/dfNmyJzFdmwug=;
        b=E/46Q0H9Lksq8INASH4W5BZoPLmfPpZGV25jlaECmVMZebobhACn9+Oee4uhnXDIZU
         p5zvxV+bHpmq21N3qQ/0AawhV9QP/5yok3lr+OOebxMQF/ds3WoiKjcsyB+Ag7qUxKUF
         VPszfdF3b66owLSLhRgz9//89xBj723ysQ0T+jTrQVFah2CPskOVDnaL0Aj5TNJKlyid
         W3S96ZdhVcYUO8GGS8racfRMN1qVBkfgCPrXYcwo4bI5lhqHuI1bbqu0fyupbMBprCSa
         q4VKeupbMr+0G4ku2OlJ6TOeVXRuYrohsU9LxcAsaLOsbioabeXqWsQoLzPw93/+F9Dv
         S9ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfGwVzUy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5jtrjo3NXkPzkOsib6nODue+gT50/dfNmyJzFdmwug=;
        b=nTklL4BifVxNQP0HYkS1aIqkSCorRsuXYPh5aANZ3VHZObze7jJJ5a2w2SgxJ7vlKC
         nrTmQfXmbw0bDY9ZomF2Aa679FirlL140HDx4TGNXCNhHYRvRFc88ciNhnWDGrru/741
         nKu8Q9WIpPllsjmfhhP1TLOZCuSYWQgq302cAtvYLcsdnYk/4zMgHYLKb5ethYKxYHI1
         ePcWZq9u0wwFFbsgSkA4Oi4pim32uCuYIu10RecqU+AlbVUw/r8B4uCxs9PUq1a1pp/O
         Tl16asa+wpvup3T7c4qyTdhSBy5txY9nX35BM1cKRZNOFJN1cloGLaTYzbyR7hrRCQOH
         qFbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5jtrjo3NXkPzkOsib6nODue+gT50/dfNmyJzFdmwug=;
        b=Hm+MV/e/txdkc+uj36/vfk4kEweh+s1N6dpyUM4wMZMgvFB+sldBEQNcD0m6beVpgR
         aVn08PSbwD2D5zC0sjxStuHHIjiW4gpnEQupAXOV1gAH7fflvfW7/lTOQxx7uD8QxEEI
         bwaeWeyw4yym13d4CV7w1531lPhlQPTTCIZpX3SmgJQVuUNLhVe/kx8INXGSZ8tQg5IK
         49wgwtjQeyzM+xtNCdln3auOB8YsdE95ZcUrlL7kOEeqdoKW0HUTSlHErdkfJrFOzZAI
         IYR09gGBokrKHfqEUx3zXYJn/L7kIfzYmMWGDNx+StY4bMYPkVo6ZSi8fJ5LxO1d78/S
         nR4g==
X-Gm-Message-State: APjAAAVU/XM9WCt/Tf8bkWeYxM/bStWdaTKc259dBJJSNJQMISN1+jOE
	SDzmUw0Ioonds60hlF5O1UI=
X-Google-Smtp-Source: APXvYqxPkG1SAWX8XDBpSEsbsC5u4XUFCht5HQ9mwDQoNDQqtW7FNp+7xg3qigZTrxS8F86jhsyIAw==
X-Received: by 2002:aca:574e:: with SMTP id l75mr10517171oib.2.1560780052029;
        Mon, 17 Jun 2019 07:00:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3fc3:: with SMTP id m186ls2328218oia.15.gmail; Mon, 17
 Jun 2019 07:00:51 -0700 (PDT)
X-Received: by 2002:a54:4081:: with SMTP id i1mr10565770oii.121.1560780051652;
        Mon, 17 Jun 2019 07:00:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560780051; cv=none;
        d=google.com; s=arc-20160816;
        b=oV2XAILu8Ld9QvN8l8H0zKzKyo9/xHzqnzF8cwUhHxBNfcKm+3bsaC1mBr8x1Mb73c
         m3xlZzk7+AYQ5T+GEdhfyCUSe5r/j75i7r65RUYIkiivRrrBuPPwa7wFjlL1SiVpOOQd
         fvxtcY3uVqkoTsM6qBuOPUzqJpCm+2BFaM4lZaCMLLx/UFTlOQ2sO6JZ9Xz3a5/RmeH2
         mVvT4a4yLM76rxMxOAtOgw0BE3cKN/onjZoVnu37EihYEEfFthAnzElhvV0MJu41G1m7
         91R4v9Rl76gbP+b2jUm+bRURCyhwZIz53sCNwYOaBs1eBDCdbUYrwtCe2COX69Wr5m/s
         pqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v/0AosDiq0XlRMBf8oBwjVIp/eynr9o30+abHU130tU=;
        b=x2nCbsTDHR8qcljv+Y4shuxleqwtloQqfK7l3V2rpwjbvWNrFRdGFpTRjLMRugqL/c
         j0eKsDitURCa8n4Wbo3PTa4onzaAj7060lKiipFWaUFny8o1FE5qkirE+8yBFlhkGmbv
         VuEq7ni/5pgbSeO4BRsN4m+jSeKy2Ml4fB8OlPJO+gRpOTSjMS2Z8H+FecFWqhV3s+1c
         +P7jUulVKId/daeWUr96r0nXQ+jUkL66/K94Dyof1S4NjuMrizjvbHjlbs8daeorg/Vp
         8k1NYd5ZViX3HB38NOL8974qaEXRqbDre1lGk4ANsZxxJp9WCvz4SpnBOzbl9I0S9yBw
         XEfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfGwVzUy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id y133si473599oiy.3.2019.06.17.07.00.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 07:00:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id z23so9322036ote.13
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 07:00:51 -0700 (PDT)
X-Received: by 2002:a05:6830:1688:: with SMTP id k8mr9743899otr.233.1560780051018;
 Mon, 17 Jun 2019 07:00:51 -0700 (PDT)
MIME-Version: 1.0
References: <20190613125950.197667-1-elver@google.com>
In-Reply-To: <20190613125950.197667-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Jun 2019 16:00:38 +0200
Message-ID: <CANpmjNMCmcg8GS_pkKc2gsdtd7-A2t27mOXATY9OLb1vQW5Lsg@mail.gmail.com>
Subject: Re: [PATCH v5 0/3] Bitops instrumentation for KASAN
To: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QfGwVzUy;       spf=pass
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

All 3 patches have now been Acked and Reviewed. Which tree should this land in?

Since this is related to KASAN, would this belong into the MM tree?

Many thanks,
-- Marco




On Thu, 13 Jun 2019 at 15:00, Marco Elver <elver@google.com> wrote:
>
> Previous version:
> http://lkml.kernel.org/r/20190613123028.179447-1-elver@google.com
>
> * Only changed lib/test_kasan in this version.
>
> Marco Elver (3):
>   lib/test_kasan: Add bitops tests
>   x86: Use static_cpu_has in uaccess region to avoid instrumentation
>   asm-generic, x86: Add bitops instrumentation for KASAN
>
>  Documentation/core-api/kernel-api.rst     |   2 +-
>  arch/x86/ia32/ia32_signal.c               |   2 +-
>  arch/x86/include/asm/bitops.h             | 189 ++++------------
>  arch/x86/kernel/signal.c                  |   2 +-
>  include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
>  lib/test_kasan.c                          |  81 ++++++-
>  6 files changed, 382 insertions(+), 157 deletions(-)
>  create mode 100644 include/asm-generic/bitops-instrumented.h
>
> --
> 2.22.0.rc2.383.gf4fbbf30c2-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMCmcg8GS_pkKc2gsdtd7-A2t27mOXATY9OLb1vQW5Lsg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
