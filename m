Return-Path: <kasan-dev+bncBAABBYGA2WAQMGQEB4VFSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 759C43231C7
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 21:06:57 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id f81sf21704993yba.8
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 12:06:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614110816; cv=pass;
        d=google.com; s=arc-20160816;
        b=f8MVKGIhdlCplRySG2bYh5lHuGaspDxWd13+mKgz206832awQSnM6EM0tJneh+OQ5s
         CDppnTxLC1rSh+LmTJiNYlkoNwaS72ODnCNqv6+dKlagGuZJUEEDUJ7Lzz8j2U6BA2as
         VMNP18DGAohFXnR2lvhPnA37C4ojd9RGSsYLDxe7twhuDSImaryJiLAGEev8xnXihWwD
         X5AO1G0vH+hqvyMK+8ThRwkE+x1Xa0YGq4uwMQtOatFgOcZIcqwWUkQwpEGnRn8YNUBn
         4TcKkeQejeyaJBrLJ7BUKjAH1gXFucHbrrAOojk5+7N2V1aAQELJigrwb9AoRHaR/t6m
         qhTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=YyDqxXGRx4BzF8MG2hRdWxxdRTdDSU9Rb8PJiScT4Mo=;
        b=c6gIBizUyKAtqCPOutho4/gQbVbhnNHZ2BqXgH8cGo2LkycV/7FrpUcYcRJgZ6tOLL
         5vRQDjcE5RwMj/2SgSdw+9o4O3rrTiKuG0FHbZrRXV9CGDzy6ZWeE5VcChFN8Y2a1LEZ
         k4nxA0gYxvBPMqsF1W7a2yNn1TeDwCCvPx2+gexQ4JhtaHEGkqIoB5ATuz3RDYiJA9S8
         lOcp0syKCEKXm7UU/sKdlCiMEStXrlRYTQE+1Uc3a4iZdFwDIBK47OaPUSK6Do17T2gS
         N9fgdFVhNCqAcxXlZqhHU/U8UIJ3j9JDzWWUl8/o1j8WfnMYbX2tbqkWtZD4ZVzqzz+o
         jjgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Jme//fgH";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YyDqxXGRx4BzF8MG2hRdWxxdRTdDSU9Rb8PJiScT4Mo=;
        b=IiziwaDslSmRvAxgh7qrVl7EYXGduFJNonVRBIgb+y3Kcjr1kV4b7H1iYtGXw0cM7u
         YlXfjpO8eMHK+wIQBP/izmqemMq0gtxHoVPBj2iCa97ifeT3bxZdgHuQsFOjUsOqT8k7
         n9tDo2m2NX2GeO4Ac9kH9ZzJ5FvwFJtFmUnl32U1qohn2uKo6qnrk10A61+guJLpdAVW
         CBdanU5eYn7FkTmrSQbAPBS17R7VhoKoWMl0XJVFJ1pjIKrTRzjjG5OuVkCYK8bL7x5H
         BXzAgznczICr5a3a5Dceq8hyr6Ja/CZ8jkwSOTuKvcSBG97SRu1x3U2AD2U6MiFyrmXV
         zItQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YyDqxXGRx4BzF8MG2hRdWxxdRTdDSU9Rb8PJiScT4Mo=;
        b=I5jFSsmy69Vh7Ax+ni/ZD3+T+2/53LbFa9n0SSrj4ZaUMkaIq2mMSGDN5BAKeTju/T
         +JBLpu2aaKI5lhxL/VQIPIb3ja9m4Fx20ZtHge/IR/90mPNDisDxQMGPN3MMTyLridtR
         14Qlozio/7eDXWGGavhM1I7IdlGdtZPPGR8b0oYyg0ygb8z4eoy8IcrUucFQNi5LHaZa
         ZGsUUP6x56VhNVFsFYAbaPbEVX6/auH+3jE2SPR6VsShFfygYOySVDwlEdwJvHL7az73
         qaaBGSJ1+EkaRVJW8cvkN0UI0fKPy7rwk/xKTQNQgil0LxpNroMq/IHel8ir7lxmPuiF
         MK4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y7JGmuaZSt61UMeiPjCeKgt3e6EAh5BpdUwc/KvJjIuVjdveK
	0a+FCDV3g8mMbhVS9o/wjwI=
X-Google-Smtp-Source: ABdhPJwi6uUsNvMXhX/x1xQGR+l4h/Sy8Rw4PAKPgouTDctmLVX0fOvtTmTWIrzMaeBhUeotK3SHcw==
X-Received: by 2002:a25:adc9:: with SMTP id d9mr41511435ybe.144.1614110816519;
        Tue, 23 Feb 2021 12:06:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc49:: with SMTP id y70ls2302957ybe.4.gmail; Tue, 23 Feb
 2021 12:06:56 -0800 (PST)
X-Received: by 2002:a25:fc1d:: with SMTP id v29mr43664437ybd.472.1614110816120;
        Tue, 23 Feb 2021 12:06:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614110816; cv=none;
        d=google.com; s=arc-20160816;
        b=Md7I9k2RGqTdVE45MuLoLp52sCzhP9mQHw8TgewBAIJPetWC2dJhUc7hQeTdnuTlym
         P3x7XvnfsPieouyb+NGIsNdDCpTDkvANWndsr8Uy8ElPY8jZUOVJWkNDfuhGS1xKgCU2
         drieiS1MgPkRriRpbjgVlTQE5aUEs0Sped7nT9z2sMhxjUA9pt8hoYYFcJneZNtghgKx
         FspqmmXWDCBRKnQy2VZmifyg+B0cyU+wtPlAPOy1UsP6+RpAaltD6vXLeBdMdfL3TyGq
         Ur8mCIxPw6yls5QzpNLsv/J8uT9ov5/15Q++8D9B3jC0Kmb3AVWgTswiogKjE9Sv3zex
         57Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PkD3ioKzfkZ/PRIRoywRQ+beCpNpai9GngjtMVJLBrQ=;
        b=GIoRmQnTNUa1UirvcjBYRonQa3HxKTL8XH4BbEWNWLQul4z0Tw3Ln1ViYxuDxY7gaE
         p8Esb0/lCfjIykjC2M+RJ8Rf14MO6kMAoFrtnh+zi8//l1yBKOOMouBwpCF/yvkgp9g5
         Fd+ZuvZZHyQMNaF9zDaILXcRNYPciprpbm5Pa1twapDW/SP4eHBxo4BgIu3lLg/gA0lp
         hGrgCx1SqzLslGWp0Hmuqvy7qPtHWiakMdq2Gngh3aSQWne+DWyBKQtaNqpL1cxqoYJq
         /ZovWRFbkiEE4NagQbNk+OXfHKAAHqaQsWkkPdW87vGdP2tzz++5ufTpRt+U9YZa19z0
         DfHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Jme//fgH";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x7si1656600ybm.0.2021.02.23.12.06.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 12:06:56 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 02FDF64E22
	for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 20:06:54 +0000 (UTC)
Received: by mail-oo1-f43.google.com with SMTP id x23so4178726oop.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 12:06:54 -0800 (PST)
X-Received: by 2002:a4a:8ed2:: with SMTP id c18mr19775387ool.66.1614110814282;
 Tue, 23 Feb 2021 12:06:54 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-3-elver@google.com>
 <CAMuHMdXVZ+UvNgoaNC-ZZoiuJ=DOsZs4oZzd8DubA7D+4iLCow@mail.gmail.com>
In-Reply-To: <CAMuHMdXVZ+UvNgoaNC-ZZoiuJ=DOsZs4oZzd8DubA7D+4iLCow@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Tue, 23 Feb 2021 21:06:37 +0100
X-Gmail-Original-Message-ID: <CAK8P3a1nCxY=bF_Z_aDDqHFOFgOSJUmaN5X+46oXN7-x1o5z_g@mail.gmail.com>
Message-ID: <CAK8P3a1nCxY=bF_Z_aDDqHFOFgOSJUmaN5X+46oXN7-x1o5z_g@mail.gmail.com>
Subject: Re: [PATCH RFC 2/4] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, mascasa@google.com, Peter Collingbourne <pcc@google.com>, irogers@google.com, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-Arch <linux-arch@vger.kernel.org>, 
	Linux FS Devel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Jme//fgH";       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Feb 23, 2021 at 7:01 PM Geert Uytterhoeven <geert@linux-m68k.org> wrote:
>
> On Tue, Feb 23, 2021 at 3:52 PM Marco Elver <elver@google.com> wrote:
> > Introduces the TRAP_PERF si_code, and associated siginfo_t field
> > si_perf. These will be used by the perf event subsystem to send signals
> > (if requested) to the task where an event occurred.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> >  arch/m68k/kernel/signal.c          |  3 +++
>
> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org>
>

For asm-generic:

Acked-by: Arnd Bergmann <arnd@arndb.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1nCxY%3DbF_Z_aDDqHFOFgOSJUmaN5X%2B46oXN7-x1o5z_g%40mail.gmail.com.
