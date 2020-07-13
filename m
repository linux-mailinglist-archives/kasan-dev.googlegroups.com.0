Return-Path: <kasan-dev+bncBDV37XP3XYDRBHUKWH4AKGQEWVF2D4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id F0F0C21D4ED
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 13:27:27 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id q6sf10527665qke.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 04:27:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594639646; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETE4rlvW5tV43bpMlqVHEgxdwtzYKsOeH4twiMHdRtaasMIZsFJeVZ9n9Zd7Ylc4WZ
         HQJC6CKLMq3eZybMFz+ctLmXRM6LRZr25Yz1S5LDCi4JIu0QE9dghvXWA40rMPDO361U
         uP1lZ/cXdqjJTCYQsqMUC74ZY8JnO9z6BYFjgyvTbY8ZzwK8aEnROwRziJdISbioo2cB
         vZPGsVT5M6FRuJ9OqIigl/ALjBa51k6wojgvnkrseshzFoyh4AMy8AZKUU4HuBUQ5sKP
         Fo1jUC8un4mShFhBF2xGK+buCYssvH4YQpmXL8uDG/A3Ej1P2NUHbyd1LoaCBx1t1VoN
         m3JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NFSNsYVfIHnQAm+vV1lggKbM2YIU7Cy/UbrIW6LjbYo=;
        b=sDPNRkUQIN3wnrwYww71tkksWoGYIkvjQTBbYvS7VDIMws2xo/m86IKQPIlk+QxPR4
         FixAsG7lglgt+KQy23s/aYF/6xqTesYq63evbswZsR9lTujf/yuyOeGq2YfcnRj7ql76
         6bWPdjOQY1gN3keSrmOMFE6QkNXXD/atL4qwI2Mapn/1FdxsyVPDBAj8EyQTUG1ZAygJ
         HBr61mWcWe4gDlxT1tbaHB2hY8WD17vqkaBnJ9p4Ia+fC8ebBCMHngiB6lkxQFEpPuic
         pVYlCpUzoWfSY7OpjRAYLfQpuYXjLzWGpcr9vgZ9vTWz7dRVToMXCyO0PFA7uAwA2MlZ
         LHVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NFSNsYVfIHnQAm+vV1lggKbM2YIU7Cy/UbrIW6LjbYo=;
        b=gEulhliUYOYIBzu8bSjCrafN22Dd7FUj//6ksDy/+mDNAVrxFSil5EqqirsKmGu4GE
         UqbJ5BNE7G6YkA8ed1z5x1BEL7srdB2NysfHf/nVVtzs0RDPsKzbfAroLqxk1VwWq+I2
         TP06Xe6DjXCNSN/jDEn8MnUyisrdJbeoQlgBxHVPPoVzQCfmJQWXdkk4P1vLmUwsymp3
         sx67xL4EzXWxDJ2V9IQE4IiSCZQGdv7oztXFz28e/mRSlEnKTwPTrDjBrmU28krL3Ldn
         GJudtch6bcktX95w+V9/RGHsqRQvAS4cmqp60UZuk09BBf01yde3mP4lAgbJJDq2jMdM
         aIzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NFSNsYVfIHnQAm+vV1lggKbM2YIU7Cy/UbrIW6LjbYo=;
        b=dX4x2pELT45UYxJhorEy8NyAmxazpCFALWamgzsuYPgVdkA41kZcS4fVTUF+uO6hfe
         aMHWKvMZBSdah3L3eyO5BfwBJPzgQ7kRDCQ00nZJiQFYbilB4rRkMnjG9MPqxAnK5CKq
         SucuGFEBMBw/GgD8FbW1biZRAZ4pp23UpUbxJfzp+ICyfQnT6HJCk/xDotsMy+Tf5HRc
         r29vcvWoB8T6O2ihfaZIdutRL4chMsacrqVucHksJUJUxIJ64p1iDq4w8GJJRC8WHsgc
         FhlhIhxivciPL0CjrT4VNEfjj+H07JKAU+ThFfQFf67vXBPfZkmVTybS1jHet6qcG4wD
         wRnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JawxlSAjy6ifMA26nt/6osofDu/aThsteUsbFJSo7zPV0XZdy
	I7jUredwUnYiqVRcCNSEGOI=
X-Google-Smtp-Source: ABdhPJyjeMsYQ/kWMUfgzmxZrpyMBHK23ZZzgs9eM/W4NCPFE8D0WNl5+iffA4LeY68EuS4OavnFEg==
X-Received: by 2002:a05:6214:851:: with SMTP id dg17mr81164905qvb.235.1594639646751;
        Mon, 13 Jul 2020 04:27:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea09:: with SMTP id f9ls7990879qkg.1.gmail; Mon, 13 Jul
 2020 04:27:26 -0700 (PDT)
X-Received: by 2002:a37:841:: with SMTP id 62mr78105557qki.487.1594639646345;
        Mon, 13 Jul 2020 04:27:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594639646; cv=none;
        d=google.com; s=arc-20160816;
        b=R7n7Sv18q/BnhMWT76hckrE2gWMAI2FB8yP2kahoyjZmNFIc/Y1h8gqD3BTEPLqC5d
         rTJNknicS89bPd01AkKmSohaX+NQQPuwGr0TQ8pIrb6ZaVbm96T/nTkAf9yZuW0erxI6
         pHjO1c4jX2iq9malMySI/gvetFMPugq2XF404CS18qfql/+mIu7cmlU93eY9H9NiBDbp
         v3CdWUeFv1t/BigZqosc8Lbistag/n7rWJQwLc0jCGpSUdsXzbf96KVapubvt3TDnot2
         oF1qcYMJ57d/UDw1J+8N9OKefVlYfgeoiWrrb0DoIzwb0yvoAkTEpA5CRYqnxdptECfH
         B54w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=mqX4Sb+fmsDyMlyeabc7H62RJiRWsyAOOioCTnV6psg=;
        b=KRVdoMupAmE1i2m6519ln/hs9Iu8FEMgena1aNFaoDIe/22LCiF9bfd8U3D+f2sqKt
         5TljhfplG3P5QuT7qVjBuNbWXRpOL9ILuYzB34kJNx5mXCh3yaFhCCs+YGcuPNonsmNq
         Wdw5jAEl+6bs7uhd45XbFpO3mM0k7WcMslGUBYVMF4ohcok+bMT2mTfic+EIr40Prs9J
         kdOdXNtmeH5OPYGF9+19KRnQCtbwVRoq9JwGXUGim/wSIpzrY5DTPRNlf56iNo7PP5z0
         4o9zmpPaWbxTaohAhWv04lpDWxOYAMtKOioppKdRGnUgNE6GO3sbTq9iBBtZGFi2tUQ1
         c7HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b26si797584qtq.3.2020.07.13.04.27.26;
        Mon, 13 Jul 2020 04:27:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B7ADC1FB;
	Mon, 13 Jul 2020 04:27:25 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.21.253])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 39ED43F7D8;
	Mon, 13 Jul 2020 04:27:24 -0700 (PDT)
Date: Mon, 13 Jul 2020 12:26:16 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20200713112616.GA51487@C02TD0UTHF1T.local>
References: <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org>
 <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
 <CANpmjNNetBqbqDbRS8OQ9z5P=73vAXG2xys6HKSg_dzqp9ksqA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNetBqbqDbRS8OQ9z5P=73vAXG2xys6HKSg_dzqp9ksqA@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Jul 13, 2020 at 11:43:57AM +0200, Marco Elver wrote:
> [+Cc clang-built-linux]
> 
> On Fri, 10 Jul 2020 at 19:53, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> > > > release before sending the arm64 patch. I'd wanted to stress the result
> > > > locally with my arm64 Syzkaller instsance etc before sending it out, and
> > > > didn't fancy doing that from a locally-built clang on an arbitrary
> > > > commit.
> > > >
> > > > If you think there'sa a sufficiently stable clang commit to test from,
> > > > I'm happy to give that a go.
> > >
> > > Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
> > > (famous last words ;-)). We've been using LLVM commit
> > > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).
> >
> > I built that locally, and rebased my arm64 enablement patches, but it
> > looks like there's a dodgy interaction with BTI, as the majority of
> > files produce a build-time warning:
> >
> > |   CC      arch/arm64/kernel/psci.o
> > | warning: some functions compiled with BTI and some compiled without BTI
> > | warning: not setting BTI in feature flags
> >
> > Regardless of whether the kernel has BTI and BTI_KERNEL selected it
> > doesn't produce any console output, but that may be something I need to
> > fix up and I haven't tried to debug it yet.
> >
> > For now I've pushed out my rebased (and currently broken) patch to my
> > arm64/kcsan-new branch:
> >
> > git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan-new
> >
> > ... with a note as to the brokenness.
> 
> Seems it's not KCSAN specific:
> https://lore.kernel.org/linux-arm-kernel/20200507143332.GB1422@willie-the-truck/
> and https://lore.kernel.org/lkml/202006191840.qO8NnNsK%25lkp@intel.com/

Ah, so KCSAN tickles this because it happens to have generated
functions, judging by the propsoed fix:

  https://reviews.llvm.org/D75181

... and practically speaking that means KCSAN isn't going to be usable
on arm64 until that's in. I'm not keen on making it mutually exclusive
with BTI as we've had to do for GCOV.

Regardless I'll try to dig into why it's failing to boot without BTI,
but it might be a few days before I have the free time.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200713112616.GA51487%40C02TD0UTHF1T.local.
