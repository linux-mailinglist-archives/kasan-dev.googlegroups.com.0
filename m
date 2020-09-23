Return-Path: <kasan-dev+bncBDV37XP3XYDRBZPLVT5QKGQEV6UCTGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 0128527576A
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 13:47:51 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id a16sf13603852pfk.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 04:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600861669; cv=pass;
        d=google.com; s=arc-20160816;
        b=ghS5dqtlDJEC8Flhla0VgVn3aEf4xn/t90YeT5TQmaqMHXDO6nc5kYel9ucjwwS+ld
         oPt4BhJjWM887pE6AqdKjqT/Un1hpsyaOcc3wcq8eJNqMYsg7Q8HriPE2U6HZpJbd9ry
         vGLQMkqaNk2CbvBI0OC2y7ktVbG52wslbt0N6LOKdgQuIRbZmJ0qNbyIDx/BEFNMU3hg
         JwDebDokofXUW9xPF/zBvjPxtlLNosGT/fSTJChS/nSN4T2nDAdDfmpScApO9wn1u5rY
         Js6NXrNvFPohyr13/PVSgCVZjTeothxrrC7R7Eo/nB5p/oaEXN3+vG14u5hIXBl/XzKv
         6QPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N2R02+xkTyFcXqsmi1QPzvUDnAnhZOByNNp7aUAHFG8=;
        b=UHRsTuG6yfOHSEgAY7jTx7F2e7fO2O2DcZ83jm3/69YLlgQNxEs4xe8f8uxyEc1S/J
         vI4DuA6YxlymEyZ9/qW3lFNVeroJa6nqsHEovffPc1qPNT/SGgpKJceDwd0XS+KtXPIa
         Or2Xf32kJMFz+v/pQ8IaOad6aFuCLCeUHcWSNXN6A1EOgl66zlbkbvZr/SieAtBeD4q/
         Ybtwz/ngJ1ueOL82L+FeRpVMXH814NAi2klfklbnkd22uov7RSN1yv8qPwuaLAkshuCB
         qH2LiSfkAGKBnlQKg2oh1IcU4WGFSVjxd9l/LHqIVs3DU9qtAvTFJUsxZbmVnkLvsT/d
         u4XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N2R02+xkTyFcXqsmi1QPzvUDnAnhZOByNNp7aUAHFG8=;
        b=VxeLqIOcyYAYPgfYXSkDLTPFXD+KheBPfUews0oaCtn0RXmHDpo+0k8TFh5FQPqVoh
         Im5JrupgT8q2EORWurdt/sGmL/fXcBtWF+BGz31sOnU9XT83U7hPvGMC6BF5QibPb4Fm
         TOws569Uqsp1SMO+guEjqaJxkbPVSagJt474k78Xndt+R0kD6wPYaWYvUVCo5aJIPwMd
         16ewp5p7MrxjH2xxpnbmx6Leng9chiwDfo6xap4fmKF3xP+NGcbzzKX46EuA+4mdKMJ4
         dNLXVyTGu2SFVCTJ7mx/ytUrdAea2pTM0vJzK4HHaUo0Tdic8MjaTIuq9Xw1f3ujAtwj
         DQrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=N2R02+xkTyFcXqsmi1QPzvUDnAnhZOByNNp7aUAHFG8=;
        b=lDOIL1N5hlpLQyw2rnnROH8MnVvbf121fymnZZTTHdrZCwYW6jYKrKliaA3MDOf0X6
         wDiQ0ZAQCLap/O5A55PmUPwG988NN/vl7lJQKKJVis5dl5r51AwL70XHoT2BpBWoUyQ6
         KnZYNcQcL1lkOfScl1iDCmDQ4ahNnZEO10f6b2Bh8LYMNKXhtCV7mEhpbZMuNLS9Kvoc
         UfXm2YJSm2vcyhFiogOplJS9WiYtkS/Y0ChP9Vvz3iHls1ugB3yrn4wUHV5FolcQL1RJ
         wtWhIUwiX9p1xcbQVDCNUjalufcV/yyufkAenV6MLDhrFMha/+x9lnnXieFSQUqQr/ml
         F1lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532arr1eZWep173vhVMYeE/3JC2/3VS52PvNJG5tS/JgYHptcfwG
	OqSJdEsZDWjw4qV88jgliKg=
X-Google-Smtp-Source: ABdhPJxOCDEg4i6a1NvFS0FxZNJKTlooUYeEzFRWq2ybY01EFJHiPdxz3jL5uDndiD05gPmW0BxIyQ==
X-Received: by 2002:a17:902:9006:b029:d2:341:6520 with SMTP id a6-20020a1709029006b02900d203416520mr9307900plp.37.1600861669570;
        Wed, 23 Sep 2020 04:47:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7808:: with SMTP id t8ls7000375pfc.4.gmail; Wed, 23 Sep
 2020 04:47:48 -0700 (PDT)
X-Received: by 2002:a63:e1a:: with SMTP id d26mr7649730pgl.190.1600861668798;
        Wed, 23 Sep 2020 04:47:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600861668; cv=none;
        d=google.com; s=arc-20160816;
        b=JuLEJIP/nqIbRFgvT+fzE3gXc0Kjll4M9FjmfslLYDm19eng3WKp2wO5+hIuNIjJrC
         zCKHJKFauHWs3iRL1obYOb8WJWNhUDcT9wT0dB2S0625cmGEdYoZ5Fgf4EgM2Cw2NL5t
         ghj2sjwcpYV/9ugJz1E6p2Vq1kjLVHUMvGV1UVyL6tzeWK9guzMPniU/UVgqxgSFTfsj
         ii2ZbxcAj0l6RCr2DxyG8gByRHCZTigMwEUafNbhiGdvf+KF1fEGvkHVOUulfZcqCiKn
         yktlGTnQl3SqUKNcVs+R1TgqRsVOT//tKQ+YBpwfTBadtSo6W5Rzy96tc3ZM3XnJAQRU
         fsDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=0RGqwjAl14P80n0BmwAyeq2oCoBKDvv5fy4MSl9bCC0=;
        b=qhBSJYtPxKbYh3bWvsG0zU5W1yYw5mhbmYwF/W2bfBALsjGf/o7VfzUiH/UoV9yyni
         E8D4xZ+8Q/fND5s0Bd9WlwxJIbjg4QIrIKwFsKDK0jNK4zUrbdnAZPxrIIEwPNwer+cv
         a5MVp9XE8Q/ccZi8kfcXltpbN/A7OaBXl5hw15lgePB5pnoLJXbrpVOOuf4LPX7JXdxB
         2KPO1LlLAp3LYxYeONDtK0O9hJPuQPGMljLwWpYNJLR5gT/Bt82N3AlGtPy3orA2eqhx
         qZMfkztUTxp9OhbnY4UJJ/3z6x04C3Qs10RQf0XMDz+mg/0OcVfMAxwevTsLRHMqNopg
         0rZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d3si1216720pld.1.2020.09.23.04.47.48
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 04:47:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E0503D6E;
	Wed, 23 Sep 2020 04:47:47 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.17.35])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 57DB33F70D;
	Wed, 23 Sep 2020 04:47:46 -0700 (PDT)
Date: Wed, 23 Sep 2020 12:47:39 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: sgrover@codeaurora.org
Cc: 'Marco Elver' <elver@google.com>, 'Will Deacon' <will@kernel.org>,
	'Dmitry Vyukov' <dvyukov@google.com>,
	'kasan-dev' <kasan-dev@googlegroups.com>,
	"'Paul E. McKenney'" <paulmck@kernel.org>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20200923114739.GA74273@C02TD0UTHF1T.local>
References: <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
 <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <000601d6909d$85b40100$911c0300$@codeaurora.org>
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

Hi,

On Tue, Sep 22, 2020 at 10:32:02AM +0530, sgrover@codeaurora.org wrote:
> Hi Mark/Other Maintainers,
> 
> Is there any update on KCSAN for arm64 now? 

Sorry for the delay on this -- I'm still working on this, but there are
a few issues. I've pushed out a WIP patchset to my arm64/kcsan branch:

  git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan

If you'd like to give that a try, you might get by for now by disabling
LSE atomics in Kconfig -- see below for details.

The main issues are:

* Current builds of clang miscompile generated functions when BTI is
  enabled, leading to build-time warnings (and potentially runtime
  issues). I was hoping this was going to be fixed soon (and was
  originally going to wait for the clang 11 release), but this seems to
  be a larger structural issue with LLVM that we will have to workaround
  for the timebeing.

  This needs some Makefile/Kconfig work to forbid the combination of BTI
  with any feature relying on compiler-generated functions, until clang
  handles this correctly.

* KCSAN currently instruments some functions which are not safe to
  instrument (e.g. code used during code patching, exception entry),
  leading to crashes and hangs for common configurations (e.g. with LSE
  atomics). This has also highlisted some existing issues in this area
  (e.g. with other instrumentation).

  I'm auditing and reworking code to address this, but I don't have a
  good enough patch series yet. I intend to post that prework after rc1,
  and hopefully the necessary bits are small enough that KCSAN can
  follow in the same merge window.

Thanks,
Mark.

> 
> Thanks,
> Sachin
> 
> -----Original Message-----
> From: Marco Elver <elver@google.com> 
> Sent: Monday, 27 July, 2020 11:49 PM
> To: Mark Rutland <mark.rutland@arm.com>
> Cc: sgrover@codeaurora.org; Will Deacon <will@kernel.org>; Dmitry Vyukov <dvyukov@google.com>; kasan-dev <kasan-dev@googlegroups.com>; Paul E. McKenney <paulmck@kernel.org>
> Subject: Re: KCSAN Support on ARM64 Kernel
> 
> On Mon, 27 Jul 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Fri, Jul 10, 2020 at 06:53:09PM +0100, Mark Rutland wrote:
> > > On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > > > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > > As a heads-up, since KCSAN now requires clang 11, I was waiting 
> > > > > for the release before sending the arm64 patch. I'd wanted to 
> > > > > stress the result locally with my arm64 Syzkaller instsance etc 
> > > > > before sending it out, and didn't fancy doing that from a 
> > > > > locally-built clang on an arbitrary commit.
> > > > >
> > > > > If you think there'sa a sufficiently stable clang commit to test 
> > > > > from, I'm happy to give that a go.
> > > >
> > > > Thanks, Mark. LLVM/Clang is usually quite stable even the 
> > > > pre-release (famous last words ;-)). We've been using LLVM commit 
> > > > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > > > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).
> >
> > > Regardless of whether the kernel has BTI and BTI_KERNEL selected it 
> > > doesn't produce any console output, but that may be something I need 
> > > to fix up and I haven't tried to debug it yet.
> >
> > I had the chance to dig into this, and the issue was that some 
> > instrumented code runs before we set up the per-cpu offset for the 
> > boot CPU, and this ended up causing a recursive fault.
> >
> > I have a preparatory patch to address that by changing the way we set 
> > up the offset.
> >
> > > For now I've pushed out my rebased (and currently broken) patch to 
> > > my arm64/kcsan-new branch:
> > >
> > > git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git 
> > > arm64/kcsan-new
> >
> > I've pushed out an updated branch with the preparatory patch, rebased 
> > atop today's arm64 for-next/core branch. Note that due to the BTI 
> > issue with generated functions this is still broken, and I won't be 
> > sending this for review until that's fixed in clang.
> 
> Great, thank you! Let's see which one comes first: BTI getting fixed with Clang; or mainlining GCC support [1] and having GCC 11 released.
> :-)
> 
> [1] https://lore.kernel.org/lkml/20200714173252.GA32057@paulmck-ThinkPad-P72/
> 
> Thanks,
> -- Marco
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200923114739.GA74273%40C02TD0UTHF1T.local.
