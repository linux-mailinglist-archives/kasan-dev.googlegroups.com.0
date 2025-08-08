Return-Path: <kasan-dev+bncBDAOJ6534YNBBR6N23CAMGQEWQ3ESBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 310A2B1E328
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 09:27:06 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-55b81da0daasf856134e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 00:27:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754638025; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqkWb1Mbtcpk97k4vSBt5DlvBeW0WFJUAmKBreiJlZ8jWWVrLNfifYHEpgZXDBraiK
         ZyrYNbwYFVs0h6iggNBhKCej+Wvw4WQI/MI+g2M3/0PeZyzGX16zumJZBAwGMLWQtlHS
         e9dEIHXb9/+BSwQuWcRmrK1Ie6ZXdnFmBkNgWYxJvh0iFnCfndGnKcOJX0W0TTKkaXup
         hq7+Eend9F0TqY9e7S6cST6mMV/KZZP8ruyPRZspXpYWTPsltBM9VsvaXlipmP7r4Pba
         iSFj6GXKcK0eMv2gsr+gfrbrQyt1QXOKoN4bro4DxsVDBfBHIkp8tayp0CpuKZ8hDDMc
         uzIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Ybjqk73gNGmCCAnEi2EhHUgxXYkyvvXdXUQ9Z5VGUNo=;
        fh=gUDDnxb1tTK6y990UELviWCgxUZIvcOu1UCtN42iz5M=;
        b=ABwx19hppQC/frKPKrxiVPRAigxP71iZOZ7wQ/RcxPSHNhaNjjWe+nVmOVar1lZWii
         wXxuKN4Ib+c5K3SnyIpyN7vBcAsE0jGrHxf0ZQ9nj/47cicWzXRXqmimUuHefgq3DuZx
         H4awt1huO1Y+i0APBVhT6IsqknMApWpwHXdDl9qd7prbY9bDQbfX3GtZDhMARQnVUilJ
         43NgtYlswMPX482D5gT6a0D0mRFXEt4nSbbd17y9FXAK9GREMGyUwMBYfuoZ4yNL0PPi
         WnFjyIDs/Qjkrs2gwd9f1v6n3IJG/ofTQFZuFg3vOeWb/Fi8YpnhhcQS5M6yB+rm0TBi
         XRog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W6RHYYdd;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754638025; x=1755242825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ybjqk73gNGmCCAnEi2EhHUgxXYkyvvXdXUQ9Z5VGUNo=;
        b=mHw/utTb+78NqhHu2cFcZvD3IPbLi/lxGfP+hfpgUhF8ZgRyiScI6pToSxvTiIaGH1
         JEYCR9kGlg6mw1ugF0FTzIqQ7E5M8iVSF1DL5Mx5aJypYNZgIf/CDo2GaxFIDU9V+LWY
         833Yg1G7VPG3p4bIAL+Oo7SkCwxMPzOJMJ1yM+Ko4A4u33MHy9a19j1bQE+lb39fqF5W
         KA686v8t9QFLMQyzTcI3SxwJwLZEd6jHrfAnsEiia/oRHKU40PPjZQIeZHeRAbcc/mJC
         l02g+p8RSZHK10l9LX7QMrw3IX2VD8fUGBLMwS6R1M5A7kf8vu0OWKYQ9QPoNpxU/RUn
         2oFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754638025; x=1755242825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ybjqk73gNGmCCAnEi2EhHUgxXYkyvvXdXUQ9Z5VGUNo=;
        b=JsYXXd8gd3sgFAUYqTKILWATuPjriZZkewkmDLSLeN4dG2AqLSf/FxbCBiPpFOE9IO
         PjM8WPWPEfGzQXbkDHOqN6369Un/xZ6eafaId2O7eJM/HgFekabrGwubb4L2W+CIaHBE
         PeKoCnWsyo+YKm1Pf1w5IKTZRV3hXHoyrykSQs4J5F5EPhob2AWyTp+UTpkdIe7FILXq
         G+VO7h4y7rEapjuuzqI/Uc0cpREn3vzcfgYMuQ9GAaceWVTo4+yctImGFgu7Le022Ign
         hUm6XTSj7Ar1oO3jQ2DfHNuy/ao/YeGBUTDjvyAfViJoORtuh6Gyl0+gm9eujvlyaxZ0
         Kebw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754638025; x=1755242825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ybjqk73gNGmCCAnEi2EhHUgxXYkyvvXdXUQ9Z5VGUNo=;
        b=PEe7SP/cc7g+BdAvt6AbPxKV4NVHhULcz7rObGb6jLfHd12HAkzPMYmzH6WLbK2wmd
         2OFwS+VIBk2VkkGvbgrfpAcT5hHw2pPCPY7SMRneGB5sIo8reulb1rv6ELhOIydaK8wo
         d6qFZCq5AuWXr0p33MuFr/XLkwNFUydv5JeZ5IxRDctSQg3l4IrWLJ3VJpCKcxOLS9PA
         hfZzdEcNUKE3bukJvyRjeCH4vJAT7Do/VUwowEE+5LRLYeUmVuE08iAiU3daviEPSToM
         BazfF4bGjGsudIKHwo+RCTDJ1y3B0MjjUaEosozk4/rmJmqpJJ9VuSpfOdT5uxvFGX/z
         coNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCvq0q8OocAKfQx+cuavQh1PQf/Id6qt1Q1y7aKK6z/TsgjVI1Ift4q+vt20ghsSDs0mZVCw==@lfdr.de
X-Gm-Message-State: AOJu0YyTSjDHw3RxozyIXY4xv4m1CCoOjTboO15BdqiHiGwAQWHuvUg1
	d3lbURiQGOxwcF8W2xPGg+ygkqTzqLKMDEZRQfnMgIv3Ot8ODVMWLoZs
X-Google-Smtp-Source: AGHT+IF6nFeDy2LF+fDchDuNFvMaHiB5jXj3qI4mwZwiTo2gYdIwRagvbv+kJMlEWkwZNNcy8H3vtw==
X-Received: by 2002:a05:6512:ac2:b0:55b:8e3e:2be6 with SMTP id 2adb3069b0e04-55cc00b40cbmr593627e87.24.1754638024313;
        Fri, 08 Aug 2025 00:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeNrcL6LDOKaeyQ7ErEwQaxRb0b/PadI/D4/8NvQ/nJUQ==
Received: by 2002:a05:6512:1418:b0:550:e048:74ff with SMTP id
 2adb3069b0e04-55cb5ea941dls665678e87.0.-pod-prod-06-eu; Fri, 08 Aug 2025
 00:27:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaD3Wv9xgZ+Wvf9LT553ccygVrUzG4aPnO3J+xGk6L1YbeI7FIlbZ3c3hi3V6S6VXDik6qr9Lygiw=@googlegroups.com
X-Received: by 2002:a05:6512:234e:b0:55a:3013:d890 with SMTP id 2adb3069b0e04-55cc010cca1mr359267e87.27.1754638021280;
        Fri, 08 Aug 2025 00:27:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754638021; cv=none;
        d=google.com; s=arc-20240605;
        b=Lr0Fu6txowgdmnZLez2OVdFFfwwPJxurr1JdA+G/5ka1PBZrr7O+2UAdATyjENmFwd
         vH3WXdF0N1C/5bdpYM1TwldgPO/NTNIbhl+CCegQ1vCDMg82SN4aoq6/jeuGXzR9tpIw
         PjfHn0CCPCU70wQBBTrqQ/4F0nC29/aCX+5/rU7mPbVTP+I4TOvVQxedIHg7KJ+QNvGL
         AholhHvO0v4LXaRwnxYx1dKKaXuNjHgZckL0dfxRbw/Xqq/9fZELlVM2nAxczzYNN1ir
         O8KXHtEzg92d7afmdMw5epc3wLurmsXkI0r2SO55jO2Ugi+EPYGuB7Jns9HhowhLVNb8
         QJGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S0Lr6jdhi3HlQ0scGIzDoa7E9fb+u+r4Rq5I03l2cMk=;
        fh=kkH3iCoBFjybwxPd5bPkP0BEXTw+MT2ph4vmOTdRaj0=;
        b=X4owlCeNzH2SCYJ1aTtSBdrj+rnawotc91+Vqt3+Fmj4vVGH3ZgKQdcnxg7cToYPe4
         F138rZg4hFBd7r9NrHlc0AcJ3EZxLmaRZy7ELoV97SbEsYJtvacRW4+Q0nAGpcV7r/iW
         un2o0RkBWqzV3mZHAk5kb6kYiRPDIaCCnaPzUJJbafeD6RKamIugXIC2r8ECv+oLvqA1
         jBKfRIXargiifMnz6fA3eb8KqhQj6yhibiM/d0vANwc1UkCz7dTA+DzR2cHvPQgZuIcu
         mmIrPXhtKh6d+auO+GjEIuFe2WvY70XhgqP4JdaVWpi9voDfWZqC8oqzuVPjB4ixBEsA
         NrdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W6RHYYdd;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8895b6cbsi499826e87.7.2025.08.08.00.27.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 00:27:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-32f1df58f21so17969811fa.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Aug 2025 00:27:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQf9vbNHzq0vfs5EAISSKRNyJp71f9wpZxNW2JkJKei3dV551vqnB+1ViXrGsipKoppi/WGFb4duI=@googlegroups.com
X-Gm-Gg: ASbGncsaJvWb8mcTSRLGxd0U85ny+1G6kdY1G+uJkp9SpDh3b9zoWgjiKrlGba4oAaB
	n53VXQNHoEV7sNAz8XCtXyqZgZ13PxVa7IvGNpZgwy2bgo/lgxLmsCM5Sl2MaotfgAmzptjm06k
	s5qK5KcGMOeDVIriM2LWQQ8AEZzVqc+MdRBDzdd8b+8YyGKPw8HqyFYFG5ldJ6mBzIBneIFkj6t
	K9qscAbd2Kpsw==
X-Received: by 2002:a2e:beaa:0:b0:32a:8764:ecf1 with SMTP id
 38308e7fff4ca-333a21454c4mr4563471fa.4.1754638020320; Fri, 08 Aug 2025
 00:27:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250807194012.631367-1-snovitoll@gmail.com> <20250807194012.631367-2-snovitoll@gmail.com>
 <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu>
In-Reply-To: <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 8 Aug 2025 12:26:42 +0500
X-Gm-Features: Ac12FXwqOepaFbJuWFIdFlcO01slh29-Z0i_A5zaLYrr59uLOpfriIwyCFHnO_M
Message-ID: <CACzwLxiVURgamkv2ws5sK9BQVMz7VPSWGy_aQb+MT8jtv03d3Q@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Christophe Leroy <christophe.leroy@csgroup.eu>, ryabinin.a.a@gmail.com
Cc: bhe@redhat.com, hca@linux.ibm.com, andreyknvl@gmail.com, 
	akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn, 
	davidgow@google.co, glider@google.com, dvyukov@google.com, alex@ghiti.fr, 
	agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=W6RHYYdd;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Aug 8, 2025 at 10:03=E2=80=AFAM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
> > Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that ne=
ed
> > to defer KASAN initialization until shadow memory is properly set up,
> > and unify the static key infrastructure across all KASAN modes.
>
> That probably desserves more details, maybe copy in informations from
> the top of cover letter.
>
> I think there should also be some exeplanations about
> kasan_arch_is_ready() becoming kasan_enabled(), and also why
> kasan_arch_is_ready() completely disappear from mm/kasan/common.c
> without being replaced by kasan_enabled().

I will try to explain in details in this git commit message. Will copy this=
 part
from my cover letter as well. Hopefully, this below is concise yet
informative description:

        The core issue is that different architectures have
inconsistent approaches
        to KASAN readiness tracking:
        - PowerPC, LoongArch, and UML arch, each implement own
kasan_arch_is_ready()
        - Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
        - Generic and SW_TAGS modes relied on arch-specific solutions
        or always-on behavior

        This patch addresses the fragmentation in KASAN initialization
        across architectures by introducing a unified approach that elimina=
tes
        duplicate static keys and arch-specific kasan_arch_is_ready()
        implementations.

        Let's replace kasan_arch_is_ready() with existing kasan_enabled() c=
heck,
        which examines the static key being enabled if arch selects
        ARCH_DEFER_KASAN or has HW_TAGS mode support.
        For other arch, kasan_enabled() checks the enablement during
compile time.

        Now KASAN users can use a single kasan_enabled() check everywhere.

>
> >
> > [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > Changes in v5:
> > - Unified patches where arch (powerpc, UML, loongarch) selects
> >    ARCH_DEFER_KASAN in the first patch not to break
> >    bisectability
> > - Removed kasan_arch_is_ready completely as there is no user
> > - Removed __wrappers in v4, left only those where it's necessary
> >    due to different implementations
> >
> > Changes in v4:
> > - Fixed HW_TAGS static key functionality (was broken in v3)
> > - Merged configuration and implementation for atomicity
> > ---
> >   arch/loongarch/Kconfig                 |  1 +
> >   arch/loongarch/include/asm/kasan.h     |  7 ------
> >   arch/loongarch/mm/kasan_init.c         |  8 +++----
> >   arch/powerpc/Kconfig                   |  1 +
> >   arch/powerpc/include/asm/kasan.h       | 12 ----------
> >   arch/powerpc/mm/kasan/init_32.c        |  2 +-
> >   arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
> >   arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
> >   arch/um/Kconfig                        |  1 +
> >   arch/um/include/asm/kasan.h            |  5 ++--
> >   arch/um/kernel/mem.c                   | 10 ++++++--
> >   include/linux/kasan-enabled.h          | 32 ++++++++++++++++++-------=
-
> >   include/linux/kasan.h                  |  6 +++++
> >   lib/Kconfig.kasan                      |  8 +++++++
> >   mm/kasan/common.c                      | 17 ++++++++++----
> >   mm/kasan/generic.c                     | 19 +++++++++++----
> >   mm/kasan/hw_tags.c                     |  9 +-------
> >   mm/kasan/kasan.h                       |  8 ++++++-
> >   mm/kasan/shadow.c                      | 12 +++++-----
> >   mm/kasan/sw_tags.c                     |  1 +
> >   mm/kasan/tags.c                        |  2 +-
> >   21 files changed, 100 insertions(+), 69 deletions(-)
> >
> > diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> > index f0abc38c40a..cd64b2bc12d 100644
> > --- a/arch/loongarch/Kconfig
> > +++ b/arch/loongarch/Kconfig
> > @@ -9,6 +9,7 @@ config LOONGARCH
> >       select ACPI_PPTT if ACPI
> >       select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
> >       select ARCH_BINFMT_ELF_STATE
> > +     select ARCH_DEFER_KASAN if KASAN
>
> Instead of adding 'if KASAN' in all users, you could do in two steps:
>
> Add a symbol ARCH_NEEDS_DEFER_KASAN.
>
> +config ARCH_NEEDS_DEFER_KASAN
> +       bool
>
> And then:
>
> +config ARCH_DEFER_KASAN
> +       def_bool
> +       depends on KASAN
> +       depends on ARCH_DEFER_KASAN
> +       help
> +         Architectures should select this if they need to defer KASAN
> +         initialization until shadow memory is properly set up. This
> +         enables runtime control via static keys. Otherwise, KASAN uses
> +         compile-time constants for better performance.
>

Thanks, will do it in v6 (during weekends though as I'm away from my PC)
unless anyone has objections to it.

FYI, I see that Andrew added yesterday v5 to mm-new:
https://lore.kernel.org/all/20250807222945.61E0AC4CEEB@smtp.kernel.org/
https://lore.kernel.org/all/20250807222941.88655C4CEEB@smtp.kernel.org/

Andrey Ryabinin, could you please also review if all comments are
addressed in v5?
So I could work on anything new in v6 during these weekends.

>
>
> >       select ARCH_DISABLE_KASAN_INLINE
> >       select ARCH_ENABLE_MEMORY_HOTPLUG
> >       select ARCH_ENABLE_MEMORY_HOTREMOVE
> > diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/includ=
e/asm/kasan.h
> > index 62f139a9c87..0e50e5b5e05 100644
> > --- a/arch/loongarch/include/asm/kasan.h
> > +++ b/arch/loongarch/include/asm/kasan.h
> > @@ -66,7 +66,6 @@
> >   #define XKPRANGE_WC_SHADOW_OFFSET   (KASAN_SHADOW_START + XKPRANGE_WC=
_KASAN_OFFSET)
> >   #define XKVRANGE_VC_SHADOW_OFFSET   (KASAN_SHADOW_START + XKVRANGE_VC=
_KASAN_OFFSET)
> >
> > -extern bool kasan_early_stage;
> >   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >
> >   #define kasan_mem_to_shadow kasan_mem_to_shadow
> > @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
> >   #define kasan_shadow_to_mem kasan_shadow_to_mem
> >   const void *kasan_shadow_to_mem(const void *shadow_addr);
> >
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -     return !kasan_early_stage;
> > -}
> > -
> >   #define addr_has_metadata addr_has_metadata
> >   static __always_inline bool addr_has_metadata(const void *addr)
> >   {
> > diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_i=
nit.c
> > index d2681272d8f..170da98ad4f 100644
> > --- a/arch/loongarch/mm/kasan_init.c
> > +++ b/arch/loongarch/mm/kasan_init.c
> > @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata _=
_aligned(PAGE_SIZE);
> >   #define __pte_none(early, pte) (early ? pte_none(pte) : \
> >   ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_sh=
adow_page)))
> >
> > -bool kasan_early_stage =3D true;
> > -
> >   void *kasan_mem_to_shadow(const void *addr)
> >   {
> > -     if (!kasan_arch_is_ready()) {
> > +     if (!kasan_enabled()) {
> >               return (void *)(kasan_early_shadow_page);
> >       } else {
> >               unsigned long maddr =3D (unsigned long)addr;
> > @@ -298,7 +296,8 @@ void __init kasan_init(void)
> >       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_S=
TART),
> >                                       kasan_mem_to_shadow((void *)KFENC=
E_AREA_END));
> >
> > -     kasan_early_stage =3D false;
> > +     /* Enable KASAN here before kasan_mem_to_shadow(). */
> > +     kasan_init_generic();
> >
> >       /* Populate the linear mapping */
> >       for_each_mem_range(i, &pa_start, &pa_end) {
> > @@ -329,5 +328,4 @@ void __init kasan_init(void)
> >
> >       /* At this point kasan is fully initialized. Enable error message=
s */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized.\n");
> >   }
> > diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> > index 93402a1d9c9..a324dcdb8eb 100644
> > --- a/arch/powerpc/Kconfig
> > +++ b/arch/powerpc/Kconfig
> > @@ -122,6 +122,7 @@ config PPC
> >       # Please keep this list sorted alphabetically.
> >       #
> >       select ARCH_32BIT_OFF_T if PPC32
> > +     select ARCH_DEFER_KASAN                 if KASAN && PPC_RADIX_MMU
> >       select ARCH_DISABLE_KASAN_INLINE        if PPC_RADIX_MMU
> >       select ARCH_DMA_DEFAULT_COHERENT        if !NOT_COHERENT_CACHE
> >       select ARCH_ENABLE_MEMORY_HOTPLUG
> > diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/as=
m/kasan.h
> > index b5bbb94c51f..957a57c1db5 100644
> > --- a/arch/powerpc/include/asm/kasan.h
> > +++ b/arch/powerpc/include/asm/kasan.h
> > @@ -53,18 +53,6 @@
> >   #endif
> >
> >   #ifdef CONFIG_KASAN
> > -#ifdef CONFIG_PPC_BOOK3S_64
> > -DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> > -
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -     if (static_branch_likely(&powerpc_kasan_enabled_key))
> > -             return true;
> > -     return false;
> > -}
> > -
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -#endif
> >
> >   void kasan_early_init(void);
> >   void kasan_mmu_init(void);
> > diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/in=
it_32.c
> > index 03666d790a5..1d083597464 100644
> > --- a/arch/powerpc/mm/kasan/init_32.c
> > +++ b/arch/powerpc/mm/kasan/init_32.c
> > @@ -165,7 +165,7 @@ void __init kasan_init(void)
> >
> >       /* At this point kasan is fully initialized. Enable error message=
s */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KASAN init done\n");
> > +     kasan_init_generic();
> >   }
> >
> >   void __init kasan_late_init(void)
> > diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/k=
asan/init_book3e_64.c
> > index 60c78aac0f6..0d3a73d6d4b 100644
> > --- a/arch/powerpc/mm/kasan/init_book3e_64.c
> > +++ b/arch/powerpc/mm/kasan/init_book3e_64.c
> > @@ -127,7 +127,7 @@ void __init kasan_init(void)
> >
> >       /* Enable error messages */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KASAN init done\n");
> > +     kasan_init_generic();
> >   }
> >
> >   void __init kasan_late_init(void) { }
> > diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/k=
asan/init_book3s_64.c
> > index 7d959544c07..dcafa641804 100644
> > --- a/arch/powerpc/mm/kasan/init_book3s_64.c
> > +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> > @@ -19,8 +19,6 @@
> >   #include <linux/memblock.h>
> >   #include <asm/pgalloc.h>
> >
> > -DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> > -
> >   static void __init kasan_init_phys_region(void *start, void *end)
> >   {
> >       unsigned long k_start, k_end, k_cur;
> > @@ -92,11 +90,9 @@ void __init kasan_init(void)
> >        */
> >       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >
> > -     static_branch_inc(&powerpc_kasan_enabled_key);
> > -
> >       /* Enable error messages */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KASAN init done\n");
> > +     kasan_init_generic();
> >   }
> >
> >   void __init kasan_early_init(void) { }
> > diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> > index 9083bfdb773..a12cc072ab1 100644
> > --- a/arch/um/Kconfig
> > +++ b/arch/um/Kconfig
> > @@ -5,6 +5,7 @@ menu "UML-specific options"
> >   config UML
> >       bool
> >       default y
> > +     select ARCH_DEFER_KASAN if STATIC_LINK
>
> No need to also verify KASAN here like powerpc and loongarch ?

Sorry, I didn't quite understand the question.
I've verified powerpc with KASAN enabled which selects KASAN_OUTLINE,
as far as I remember, and GENERIC mode.

I haven't tested LoongArch booting via QEMU, only tested compilation.
I guess, I need to test the boot, will try to learn how to do it for
qemu-system-loongarch64. Would be helpful LoongArch devs in CC can
assist as well.

STATIC_LINK is defined for UML only.

>
> >       select ARCH_WANTS_DYNAMIC_TASK_STRUCT
> >       select ARCH_HAS_CACHE_LINE_SIZE
> >       select ARCH_HAS_CPU_FINALIZE_INIT
> > diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> > index f97bb1f7b85..b54a4e937fd 100644
> > --- a/arch/um/include/asm/kasan.h
> > +++ b/arch/um/include/asm/kasan.h
> > @@ -24,10 +24,9 @@
> >
> >   #ifdef CONFIG_KASAN
> >   void kasan_init(void);
> > -extern int kasan_um_is_ready;
> >
> > -#ifdef CONFIG_STATIC_LINK
> > -#define kasan_arch_is_ready() (kasan_um_is_ready)
> > +#if defined(CONFIG_STATIC_LINK) && defined(CONFIG_KASAN_INLINE)
> > +#error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled=
!
> >   #endif
> >   #else
> >   static inline void kasan_init(void) { }
> > diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> > index 76bec7de81b..261fdcd21be 100644
> > --- a/arch/um/kernel/mem.c
> > +++ b/arch/um/kernel/mem.c
> > @@ -21,9 +21,9 @@
> >   #include <os.h>
> >   #include <um_malloc.h>
> >   #include <linux/sched/task.h>
> > +#include <linux/kasan.h>
> >
> >   #ifdef CONFIG_KASAN
> > -int kasan_um_is_ready;
> >   void kasan_init(void)
> >   {
> >       /*
> > @@ -32,7 +32,10 @@ void kasan_init(void)
> >        */
> >       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> >       init_task.kasan_depth =3D 0;
> > -     kasan_um_is_ready =3D true;
> > +     /* Since kasan_init() is called before main(),
> > +      * KASAN is initialized but the enablement is deferred after
> > +      * jump_label_init(). See arch_mm_preinit().
> > +      */
>
> Format standard is different outside network, see:
> https://docs.kernel.org/process/coding-style.html#commenting

Thanks! Will do in v6.

>
> >   }
> >
> >   static void (*kasan_init_ptr)(void)
> > @@ -58,6 +61,9 @@ static unsigned long brk_end;
> >
> >   void __init arch_mm_preinit(void)
> >   {
> > +     /* Safe to call after jump_label_init(). Enables KASAN. */
> > +     kasan_init_generic();
> > +
> >       /* clear the zero-page */
> >       memset(empty_zero_page, 0, PAGE_SIZE);
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enable=
d.h
> > index 6f612d69ea0..9eca967d852 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -4,32 +4,46 @@
> >
> >   #include <linux/static_key.h>
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> > +/*
> > + * Global runtime flag for KASAN modes that need runtime control.
> > + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> > + */
> >   DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > +/*
> > + * Runtime control for shadow memory initialization or HW_TAGS mode.
> > + * Uses static key for architectures that need deferred KASAN or HW_TA=
GS.
> > + */
> >   static __always_inline bool kasan_enabled(void)
> >   {
> >       return static_branch_likely(&kasan_flag_enabled);
> >   }
> >
> > -static inline bool kasan_hw_tags_enabled(void)
> > +static inline void kasan_enable(void)
> >   {
> > -     return kasan_enabled();
> > +     static_branch_enable(&kasan_flag_enabled);
> >   }
> > -
> > -#else /* CONFIG_KASAN_HW_TAGS */
> > -
> > -static inline bool kasan_enabled(void)
> > +#else
> > +/* For architectures that can enable KASAN early, use compile-time che=
ck. */
> > +static __always_inline bool kasan_enabled(void)
> >   {
> >       return IS_ENABLED(CONFIG_KASAN);
> >   }
> >
> > +static inline void kasan_enable(void) {}
> > +#endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
> > +
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +static inline bool kasan_hw_tags_enabled(void)
> > +{
> > +     return kasan_enabled();
> > +}
> > +#else
> >   static inline bool kasan_hw_tags_enabled(void)
> >   {
> >       return false;
> >   }
> > -
> >   #endif /* CONFIG_KASAN_HW_TAGS */
> >
> >   #endif /* LINUX_KASAN_ENABLED_H */
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 890011071f2..51a8293d1af 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -543,6 +543,12 @@ void kasan_report_async(void);
> >
> >   #endif /* CONFIG_KASAN_HW_TAGS */
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void __init kasan_init_generic(void);
> > +#else
> > +static inline void kasan_init_generic(void) { }
> > +#endif
> > +
> >   #ifdef CONFIG_KASAN_SW_TAGS
> >   void __init kasan_init_sw_tags(void);
> >   #else
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index f82889a830f..38456560c85 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -19,6 +19,14 @@ config ARCH_DISABLE_KASAN_INLINE
> >         Disables both inline and stack instrumentation. Selected by
> >         architectures that do not support these instrumentation types.
> >
> > +config ARCH_DEFER_KASAN
> > +     bool
> > +     help
> > +       Architectures should select this if they need to defer KASAN
> > +       initialization until shadow memory is properly set up. This
> > +       enables runtime control via static keys. Otherwise, KASAN uses
> > +       compile-time constants for better performance.
> > +
> >   config CC_HAS_KASAN_GENERIC
> >       def_bool $(cc-option, -fsanitize=3Dkernel-address)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 9142964ab9c..d9d389870a2 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -32,6 +32,15 @@
> >   #include "kasan.h"
> >   #include "../slab.h"
> >
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> > +/*
> > + * Definition of the unified static key declared in kasan-enabled.h.
> > + * This provides consistent runtime enable/disable across KASAN modes.
> > + */
> > +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +EXPORT_SYMBOL(kasan_flag_enabled);
>
> Shouldn't new exports be GPL ?

Hmm, I did it as it's currently EXPORT_SYMBOL for HW_TAGS
https://elixir.bootlin.com/linux/v6.16/source/mm/kasan/hw_tags.c#L53

but I see that in the same HW_TAGS file we have
        EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);

So I guess, we should also export kasan_flag_enabled as EXPORT_SYMBOL_GPL.
Will do in v6.

>
> > +#endif
> > +
> >   struct slab *kasan_addr_to_slab(const void *addr)
> >   {
> >       if (virt_addr_valid(addr))
> > @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem_c=
ache *cache, void *object,
> >   bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> >                               unsigned long ip)
> >   {
> > -     if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +     if (is_kfence_address(object))
>
> Here and below, no need to replace kasan_arch_is_ready() by
> kasan_enabled() ?

Both functions have __wrappers in include/linux/kasan.h [1],
where there's already kasan_enabled() check. Since we've replaced
kasan_arch_is_ready() with kasan_enabled(), these checks are not needed her=
e.

[1] https://elixir.bootlin.com/linux/v6.16/source/include/linux/kasan.h#L19=
7

>
> >               return false;
> >       return check_slab_allocation(cache, object, ip);
> >   }
> > @@ -254,7 +263,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache=
, void *object,
> >   bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool i=
nit,
> >                      bool still_accessible)
> >   {
> > -     if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +     if (is_kfence_address(object))
> >               return false;
> >
> >       /*
> > @@ -293,7 +302,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, vo=
id *object, bool init,
> >
> >   static inline bool check_page_allocation(void *ptr, unsigned long ip)
> >   {
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return false;
> >
> >       if (ptr !=3D page_address(virt_to_head_page(ptr))) {
> > @@ -522,7 +531,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
> >               return true;
> >       }
> >
> > -     if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> > +     if (is_kfence_address(ptr))
> >               return true;
> >
> >       slab =3D folio_slab(folio);
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index d54e89f8c3e..b413c46b3e0 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -36,6 +36,17 @@
> >   #include "kasan.h"
> >   #include "../slab.h"
> >
> > +/*
> > + * Initialize Generic KASAN and enable runtime checks.
> > + * This should be called from arch kasan_init() once shadow memory is =
ready.
> > + */
> > +void __init kasan_init_generic(void)
> > +{
> > +     kasan_enable();
> > +
> > +     pr_info("KernelAddressSanitizer initialized (generic)\n");
> > +}
> > +
> >   /*
> >    * All functions below always inlined so compiler could
> >    * perform better optimizations in each of __asan_loadX/__assn_storeX
> > @@ -165,7 +176,7 @@ static __always_inline bool check_region_inline(con=
st void *addr,
> >                                               size_t size, bool write,
> >                                               unsigned long ret_ip)
> >   {
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return true;
> >
> >       if (unlikely(size =3D=3D 0))
> > @@ -193,7 +204,7 @@ bool kasan_byte_accessible(const void *addr)
> >   {
> >       s8 shadow_byte;
> >
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return true;
> >
> >       shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
> > @@ -495,7 +506,7 @@ static void release_alloc_meta(struct kasan_alloc_m=
eta *meta)
> >
> >   static void release_free_meta(const void *object, struct kasan_free_m=
eta *meta)
> >   {
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return;
> >
> >       /* Check if free meta is valid. */
> > @@ -562,7 +573,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache=
, void *object, gfp_t flags)
> >       kasan_save_track(&alloc_meta->alloc_track, flags);
> >   }
> >
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> >   {
> >       struct kasan_free_meta *free_meta;
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9a6927394b5..c8289a3feab 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
> >   static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> >   static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> >
> > -/*
> > - * Whether KASAN is enabled at all.
> > - * The value remains false until KASAN is initialized by kasan_init_hw=
_tags().
> > - */
> > -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > -EXPORT_SYMBOL(kasan_flag_enabled);
> > -
> >   /*
> >    * Whether the selected mode is synchronous, asynchronous, or asymmet=
ric.
> >    * Defaults to KASAN_MODE_SYNC.
> > @@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
> >       kasan_init_tags();
> >
> >       /* KASAN is now initialized, enable it. */
> > -     static_branch_enable(&kasan_flag_enabled);
> > +     kasan_enable();
> >
> >       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
> >               kasan_mode_info(),
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 129178be5e6..8a9d8a6ea71 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -398,7 +398,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags,=
 depot_flags_t depot_flags);
> >   void kasan_set_track(struct kasan_track *track, depot_stack_handle_t =
stack);
> >   void kasan_save_track(struct kasan_track *track, gfp_t flags);
> >   void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gf=
p_t flags);
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object);
> > +
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object);
> > +static inline void kasan_save_free_info(struct kmem_cache *cache, void=
 *object)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_save_free_info(cache, object);
> > +}
> >
> >   #ifdef CONFIG_KASAN_GENERIC
> >   bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index d2c70cd2afb..2e126cb21b6 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -125,7 +125,7 @@ void kasan_poison(const void *addr, size_t size, u8=
 value, bool init)
> >   {
> >       void *shadow_start, *shadow_end;
> >
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return;
> >
> >       /*
> > @@ -150,7 +150,7 @@ EXPORT_SYMBOL_GPL(kasan_poison);
> >   #ifdef CONFIG_KASAN_GENERIC
> >   void kasan_poison_last_granule(const void *addr, size_t size)
> >   {
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return;
> >
> >       if (size & KASAN_GRANULE_MASK) {
> > @@ -390,7 +390,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsi=
gned long size)
> >       unsigned long shadow_start, shadow_end;
> >       int ret;
> >
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return 0;
> >
> >       if (!is_vmalloc_or_module_addr((void *)addr))
> > @@ -560,7 +560,7 @@ void kasan_release_vmalloc(unsigned long start, uns=
igned long end,
> >       unsigned long region_start, region_end;
> >       unsigned long size;
> >
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return;
> >
> >       region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
> > @@ -611,7 +611,7 @@ void *__kasan_unpoison_vmalloc(const void *start, u=
nsigned long size,
> >        * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ig=
nored.
> >        */
> >
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return (void *)start;
> >
> >       if (!is_vmalloc_or_module_addr(start))
> > @@ -636,7 +636,7 @@ void *__kasan_unpoison_vmalloc(const void *start, u=
nsigned long size,
> >    */
> >   void __kasan_poison_vmalloc(const void *start, unsigned long size)
> >   {
> > -     if (!kasan_arch_is_ready())
> > +     if (!kasan_enabled())
> >               return;
> >
> >       if (!is_vmalloc_or_module_addr(start))
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index b9382b5b6a3..c75741a7460 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -44,6 +44,7 @@ void __init kasan_init_sw_tags(void)
> >               per_cpu(prng_state, cpu) =3D (u32)get_cycles();
> >
> >       kasan_init_tags();
> > +     kasan_enable();
> >
> >       pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=
=3D%s)\n",
> >               str_on_off(kasan_stack_collection_enabled()));
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index d65d48b85f9..b9f31293622 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache=
, void *object, gfp_t flags)
> >       save_stack_info(cache, object, flags, false);
> >   }
> >
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> >   {
> >       save_stack_info(cache, object, 0, true);
> >   }
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxiVURgamkv2ws5sK9BQVMz7VPSWGy_aQb%2BMT8jtv03d3Q%40mail.gmail.com.
