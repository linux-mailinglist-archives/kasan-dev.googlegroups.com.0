Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4XGZOBQMGQEUQS2JKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA7435B45C
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 15:02:43 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id b19-20020a170902b613b02900e7137bf43csf1576072pls.10
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 06:02:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618146162; cv=pass;
        d=google.com; s=arc-20160816;
        b=fSZ0gRdm0s44Qbq5BIZWs7Q0GntYhLlGHnkUIVuXUO1kJjn4TJbFSaalpnqorLs0F4
         gvUdlq91helDEFIvRK+PAD1zYpzDiNnjF/ltfHvwaKt8Lg8NoqrtIx51sUno13sj8XcZ
         COotTthMzXBdJIcrc9giXMSP+Z07nUnW7AIzXsuMWDCumTJGPwciZucReMDZdffjx0jC
         /6On1TSI19186DlYfcjTLpkZH02gkOS0N82FvNSW/krHU5SgYD7lf5HsEohma7jJIKOL
         W+kCWXpE7URd0XFow/436Cs1a/+SVAYGgUntmbwpcy5gchzyARbbBR5Fm3z1ulRhYcM5
         8fHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=irQGuVIR7Ycji8cZz1fRGyyVclg4a/8VQFVYpcP4eC8=;
        b=wB17pHsJLZxwViL3Dk+xou33g2X5Vi2pasIPK+Zq440tP3vYm8kQaVOX1+qQGt/VlX
         XnPDBMUK807YXgE4dn2uLG39MwwL4ZoRSKpEipEV4SiEPl2ZweBsvRs92I9uxtHDv8No
         hTvF+OnBmcetH7BPKII0nQlx0AVQraEU95W0gTcv+gwY7jKByOR3f6A2Ke6lv/93BrBr
         9AK9/9XdufB7jdBzzJMkKBmxXYLIldnhnd9iDdvxQDXcJCIluJZwuYrBs+97td1a1BYI
         cUX7rBGZgO8iJzZhJzakg4hIA3AqYU6DK3SgWGh/EFkUhHYqAE62wpeAib5fazNkmgcq
         hZjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=irQGuVIR7Ycji8cZz1fRGyyVclg4a/8VQFVYpcP4eC8=;
        b=alAvZjPuld+uaXSFvhynCd5f4k20o9pMel9ld1GRJrW0iYRmrTs7TJTN2Ert3H3mlu
         iKK2fvE13s6dCK59Vje6tVnqLHzfAvVO2oD4O+T/8o0rgkc7j+1jjGKj2Ra6nfJgY1CT
         zeD/7tbAJQqoUql+UYGORRW/R6ASUbxaJuD1zktHv19VK5ZDGoGn7nujdvY+z776YUm7
         1tL8tXl6vvAOJ0ooVysFPnNKSYsmSOOBpUS+ov9VpWZ9QoJj8EQUP8+QmE7cIVVayVWI
         2DzHAjxFZl5SQHIGoIkHcGyj7Cpe4/GXHz0caaiP0wE5nPkJOCVMLla8V/79VBT3WtKD
         0h5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=irQGuVIR7Ycji8cZz1fRGyyVclg4a/8VQFVYpcP4eC8=;
        b=ZDxzBhUpFZLazITzcGe7FMb/vSghtH0I88VHDo2OxSYNOt6oktlIBe719f/JmYLW78
         yRyP4x4hpQSc/FlxovfPE/C1u15JTmwaYO/XIatdaj6Bu9WzerQYx0OHvO0cYszla703
         BSkG791ib8EV7KMjMNxJYvBO4UEaJRneghVTyc4R1EGKP6woHa9gOt7JLmt8suyxt3Cs
         KkVsJWFOTIkzbfirxG2rN0bVy87rLR0GO0kTVJufWnf0lS8oYJblnkbNhpspUuYWNbWu
         Q28OEiFDpdQ4HPD+SOWiGefSW9IYc2/9mbua882By6l44N+gEmCX3qC7NRfeKDXfhCv9
         c6ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FI+ZCNE+4zpzj2rZgAC8mkKy9yzBLzyPCqlJjnq08SSxIFHuD
	wgc9QoZuXzrjh1hD1JzQsEE=
X-Google-Smtp-Source: ABdhPJzgAzTHrPKxWCIUSplMg3GuMOeo4mz/z14FJiHsVigmADaeE2fsAf+AT6tpKw6rchDOSNykCw==
X-Received: by 2002:a17:902:b107:b029:e8:e30c:5cb4 with SMTP id q7-20020a170902b107b02900e8e30c5cb4mr21810912plr.63.1618146162225;
        Sun, 11 Apr 2021 06:02:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:144:: with SMTP id 62ls6191289plb.11.gmail; Sun, 11
 Apr 2021 06:02:41 -0700 (PDT)
X-Received: by 2002:a17:902:9a84:b029:ea:e627:f7c2 with SMTP id w4-20020a1709029a84b02900eae627f7c2mr1937969plp.57.1618146161677;
        Sun, 11 Apr 2021 06:02:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618146161; cv=none;
        d=google.com; s=arc-20160816;
        b=FjwM/SM2o+dDJO8f7zN7Lms5mWNoVyaAZ0vG0nJtqjoXNqCcOquh8Ww0jZIMV3xcwx
         SirzcH0yaVmvK/sXxrh0NNddvplIIaLP1ULOyd7dyazqWeaA2istO6T3nwVOOn7U5mov
         GDHk6EpH+K2s0nIY3lbQgSAyALM39Ak5mJn0M+8gdnlrjOQrHhD1/yFnQ14aj7dheIFH
         FsLEGcStbSgYuaB7GZAh7+OgbKwEurioQ7T1iUQKqc/UXV6Kl1apnVZWi7cww4GhrdcQ
         Gg7XfGX326VRCdKGNUeNcVZpnG9t+wAbGZP5o5cCNsLCmPVctE+fkx4eUu7hchC51YmZ
         Yd8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=cRiMOoOY7LvnaXpw4J00nNmd8S9u1+6IWVegLCT3RTg=;
        b=hhgIqCsRC4QiTfIRJgGeQsZbCTH2MPIfUbyErF2ZUklb8KP4EHIhtfepa9BImGLN4c
         +tForWr79w6ykP8gkeo5AbblOXwpae+KafFAenYm5MsHjfhgPbF9MSW0PnLlVbzyjIuh
         Qa6WRQXHhrN0ZqKdP4WhxTn8RVDLbUcfk7nhIpJqdUQBqf1Tg6yz6onpYc1N/+MHVLLq
         azbdXzVJe6SH7ikhqwJE22aIxA4xVZog7JL5ebOHhb0BPO9ftO+CQwHZFuC8BW8fFhXs
         cg7ou/qmukwb4maY+YXPuvjXLCYGaPmZta5vK5S7i1res80Cys2V8n+0H/IBuoPUdUeQ
         AMmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w16si398443pjq.3.2021.04.11.06.02.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Apr 2021 06:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1EE7A610C8;
	Sun, 11 Apr 2021 13:02:38 +0000 (UTC)
Date: Sun, 11 Apr 2021 14:02:36 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
Message-ID: <20210411130236.GB23778@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
 <20210318185607.GD10758@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210318185607.GD10758@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Mar 18, 2021 at 06:56:07PM +0000, Catalin Marinas wrote:
> On Mon, Mar 15, 2021 at 01:20:10PM +0000, Vincenzo Frascino wrote:
> > This patchset implements the asynchronous mode support for ARMv8.5-A
> > Memory Tagging Extension (MTE), which is a debugging feature that allows
> > to detect with the help of the architecture the C and C++ programmatic
> > memory errors like buffer overflow, use-after-free, use-after-return, etc.
> > 
> > MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> > (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> > subset of its address space that is multiple of a 16 bytes granule. MTE
> > is based on a lock-key mechanism where the lock is the tag associated to
> > the physical memory and the key is the tag associated to the virtual
> > address.
> > When MTE is enabled and tags are set for ranges of address space of a task,
> > the PE will compare the tag related to the physical memory with the tag
> > related to the virtual address (tag check operation). Access to the memory
> > is granted only if the two tags match. In case of mismatch the PE will raise
> > an exception.
> > 
> > The exception can be handled synchronously or asynchronously. When the
> > asynchronous mode is enabled:
> >   - Upon fault the PE updates the TFSR_EL1 register.
> >   - The kernel detects the change during one of the following:
> >     - Context switching
> >     - Return to user/EL0
> >     - Kernel entry from EL1
> >     - Kernel exit to EL1
> >   - If the register has been updated by the PE the kernel clears it and
> >     reports the error.
> > 
> > The series is based on linux-next/akpm.
> 
> Andrew, could you please pick these patches up via the mm tree? They
> depend on kasan patches already queued.

Andrew, are you ok for me to queue these patches via the arm64 tree for
5.13 or you'd rather take them in the mm tree? There is a conflict with
the mm tree in lib/test_kasan.c, I think commit ce816b430b5a ("kasan:
detect false-positives in tests").

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411130236.GB23778%40arm.com.
