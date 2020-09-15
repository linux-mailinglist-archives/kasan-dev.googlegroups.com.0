Return-Path: <kasan-dev+bncBDYJPJO25UGBBDMDQX5QKGQETNGT6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EF1226B1B1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 00:34:54 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id l138sf2082768oib.17
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:34:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600209293; cv=pass;
        d=google.com; s=arc-20160816;
        b=RjlE6VJhDyrhQXLOcT4LpT/TCgVHO6DoIVRLJJyrJKM2/kYiQdcr5FLgDPZ7iCw4bL
         5kOqwnB2dQaTayiyJlLhdqJ4R2kGiib74Nz+Z1LVwkjXxqRPbhiUhJQFSFzTNvyAaxSE
         9TjoMYToAlkaJmndvohWl8X2Kkw0rZ9TG+s67gxLK/Z6WctY8anId6QRAnlGF6POdP+g
         q6wxxHvx6UORmUPFVCOOmopDBSacKPvnmuev6ibXQZBnXxqa7DCMkbSAyRv6AG02d/7d
         w5GmBr76jeMduS/RxZ4EFNmmHmZ6ZXbN/lBuqNBokp69GFotx50Yu5C8Yg5+1gM87Alr
         JRKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YRSvw5YIodHxoyptVG94GuEgGoiQd4mr9S3dqHDH67A=;
        b=085HyvGfMGuoxOnjWq8nbjMt0dwAWltI+5zyKrqTvqxi1brfjAVGdHIg7CP2hYeSLM
         3KvELKr4rHxCa4O5Kb6FjmAMoWp/Z5s3opZc4K3SV7Kj3sWZEv1WRtAgRY/LMSzsI8+5
         8t45F854QPkowQ7VL+6wQ6BgwfAhmQzQ8WqLstCSQ2rYMZHLlguWRIPFPZIIF/cFdSIB
         XoUfPd7ONzyWEvopeuvhCJX9QILPRGmHY0rKFsOOA8OB1AAwEa52spG1IpevuTl6HdZn
         cyGgMGrPn2qIdhaLeksgBEGqwhITMqlXkMe9hFtK+PtjdmxznHjf/+EdjiAbDgOa9UqS
         5C+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bGjml3eD;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YRSvw5YIodHxoyptVG94GuEgGoiQd4mr9S3dqHDH67A=;
        b=Xzc95kjJAwzqYSf/0OZ+4Kec9KBkOD+TbtoBVbCq7z8guvdoIocHFam40XjLsYQTkR
         sahJfMBQuTtHn7ikGwM3E+zqULajCKcv/cDbllQIRxREhYRmeweZJC3Nd4Lrh7zypgnu
         dUbsuZ5aoDA8GQV5+GnXR5z5KEAIET1GVByY7cvQCsM333UTdxtLwxk7Jnr2Ir+zV+Ww
         PoM/0fE9GwxbVzyrIYRWBVYRAwOKUgzQgByTCYy3+88rD1EQa/yFjQff91ZDUHdGTs1w
         ARuaQK8MMNhxGE7QZATgv6czevUIRHLLMRcs8NfaGM/QueG7n2r6NLefnHXRVl+Q2ugp
         qXew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YRSvw5YIodHxoyptVG94GuEgGoiQd4mr9S3dqHDH67A=;
        b=Ut4ZARYGdal0RqFHY601L3MBEewzVJADvShBP6uYu3697MGM713ZVN1/5yY8oGz2Kl
         zE2zrXxUja979XNPmcEdTiUkOfCL7p4+Mf171AIvMiYEiLhop2fM0GKEpRz7m3sokgfz
         3Bo3tw+0DbImpL11ZxVFSTa6x6wrsw28HqDCETpf+RCmYV2+2lvSEyC0WzVBIoBbzlWc
         UP4l3G4asVXSafY7naxdZB4GJ4agj/9EukF4/E0FUjPdgSGgUZXDgvl6yDpMqA6KOf0w
         eaN5uCdI0h/jfycwIyf3rv8pgOH6NtEAWJUpo/0nPOiwdIOiNSoFd6wKlJZ0F/i7qwwO
         Y8ZA==
X-Gm-Message-State: AOAM533cyLdjMi3S5xv3fO2oG6/uncf6clmJxYis38vzv3ltMh7zaW0w
	YJk+PiraHlFxtp+pnF4IBEM=
X-Google-Smtp-Source: ABdhPJx5glBoD5ynEwmFJ5rTsJgSZW58SmX7FzrrA5Zw0SbXYnnPoL9kS47AhglUBWZDB7EEQXRh4A==
X-Received: by 2002:aca:1205:: with SMTP id 5mr1113267ois.32.1600209293372;
        Tue, 15 Sep 2020 15:34:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:459:: with SMTP id d25ls23197otc.7.gmail; Tue, 15
 Sep 2020 15:34:53 -0700 (PDT)
X-Received: by 2002:a05:6830:230a:: with SMTP id u10mr15500122ote.48.1600209293043;
        Tue, 15 Sep 2020 15:34:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600209293; cv=none;
        d=google.com; s=arc-20160816;
        b=k8FORgIUR3bWBpoPOBDSTwhal7AzytAKgubN1Ct9MhexHpKk0zPnWGwC8eo6T6l3aB
         V81pRPiO5IwM91sH9nBNUxlxelXGINX97CNMhu5cyoeHPfH83m7DarVKG3TLMqJqLmzf
         OsWYY76+eKx4F+cW417F9xYwcIr8YbAqP4ZT8WsC2cFxZ3gbglfDViS5bB8MejECmCtF
         jyu+ZWsf3MOroDDMrn3Ob+tRxc8C0kZ++r2UvTrtJAzMUfR3qYQxqA7Cnz0D1ju4P3ED
         crzv2BWh/S9ttl0MqvVFyfyX3iBvV41OieV9UbjwrHBtR9uAooHH4IURsrtDjCUPpmyl
         eXeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+RefOWSaF/+yw4enLs3JNCZKSsuLRuxsPClHLLnrcCk=;
        b=E2IBwP4Z8tB0N80YtucLoVyWkG3d83ZqIWckuBBQlcyP3GERMkqnKF8oGSfjoTpg/c
         wnF4WkGVdhUrZyyjLc5oMoADM9jBuwClDgPUzdr7jAP3NHPFD4sFdPGYdf788mQUi3KR
         IblLeg6rZRCCSfttNpNhlhn1aHdz3c2i42qdMKFziMJw9havYqx3zeHrtoCT4zbb4OSU
         8a9hRKz93hMwAe9WZGM+Lff9sQ3z8tVYG95F8GGZqC2ohLFnnoX6x6nbehg02BdBz847
         bY3AovQChkLBlY8UbC54JKRKUr6eH2WSu4ARE7R4kVhA/dkRPmGBubh3ewXT4Ydp9qoE
         sudA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bGjml3eD;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id l18si935160otj.1.2020.09.15.15.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 15:34:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id md22so567595pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 15:34:53 -0700 (PDT)
X-Received: by 2002:a17:902:7295:b029:d1:e3bd:48cc with SMTP id
 d21-20020a1709027295b02900d1e3bd48ccmr5124412pll.10.1600209292167; Tue, 15
 Sep 2020 15:34:52 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <CAKwvOdnc8au10g8q8miab89j3tT8UhwnZOMAJdRgkXVrnkhwqQ@mail.gmail.com>
 <20200915204912.GA14436@zn.tnic> <20200915210231.ysaibtkeibdm4zps@treble>
In-Reply-To: <20200915210231.ysaibtkeibdm4zps@treble>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Sep 2020 15:34:39 -0700
Message-ID: <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Josh Poimboeuf <jpoimboe@redhat.com>, Marco Elver <elver@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>, 
	kernel test robot <lkp@intel.com>, "Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bGjml3eD;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1044
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Sep 15, 2020 at 2:02 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> panic() is noreturn, so the compiler is enforcing the fact that it
> doesn't return, by trapping if it does return.
>
> I seem to remember that's caused by CONFIG_UBSAN_TRAP.

Indeed, if I remove CONFIG_UBSAN_TRAP from the 0day report's
randconfig, these unreachable instruction warnings all go away.

So what's the right way to fix this?

CONFIG_UBSAN_TRAP enables -fsanitize-undefined-trap-on-error  (not
sure why that's wrapped in cc-option; it shouldn't be selectable via
Kconfig if unsupported by the toolchain).

Should clang not be emitting `ud2` trapping instructions for this flag
for no-return functions?

or

Should objtool be made aware of the config option and then not check
traps after no-returns?

I suspect the latter, but I'm not sure how feasible it is to
implement.  Josh, Marco, do you have thoughts on the above?
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdmptEpi8fiOyWUo%3DAiZJiX%2BZ%2BVHJOM2buLPrWsMTwLnyw%40mail.gmail.com.
