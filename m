Return-Path: <kasan-dev+bncBDX4HWEMTEBRB556TTWQKGQECYNG7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7E62D92D8
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 15:47:36 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id f80sf13713569oig.8
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 06:47:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571233655; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGPaOxxxXHnPX65Ir4rGUbMynlDUB6dj3fOB5k8K2CErjLxUgoeKP7/sVpuDH5Ebf/
         GnNMtpvOKA4WKKBkHj1VCySLK+akZgpN2WEws516OzN7Qe2pidX+OBsIdebDCfi6wkJ8
         DJmk5FwWpmp+auN9TE4DfnfNr9XmhcYLK6oBfo0JaM0Suj2bVJ/tOyA8mpuhNbsMdYjf
         WML/XqHZPf1pas9ivKsJkDeOoj+vo4xs7y4EP5zE7k5mY1V0nHVWjpTfhoovN1llniXP
         J1TdRBvWxR11XUxCjArqkF+VZ59s5KhnAyHfwCi5dWJj+Vx+Tvb0aVW2AnwM1Jqgs7jG
         VX6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x9/k2D0xfC7ZAFIDxrkn8W/aFTs13znCO4JzoYkjgvE=;
        b=xCV8V9IEJxAPnmtsHrJvqYYy/iWp0O20nltWdXH6mly2ma59lmwOvsITGB2AiWXdKF
         O3V8Q2CxTEwDRbANAUR5U+ZPomkpJeR9pNSwA7FvTZ6wSc80x/+v+EoNMtowlqNUdA4s
         knvB+CrDWOZ9EJNl76IJfBmoA3a0Rhm+SPhWysoBt5uKBlYYFWDbsE1JwOZlg+X2b1tM
         NFVFvh3L7kxaPk+cH9y7jHuJ0NWJU9740n8OpdknAvvYVC7djWkXJtXhIX2nor1Zvuhv
         jisuaDbmgiGqsP114m75cZPTn0A3lLITjJyRFzXr65/dRwGueApR4ZjTIC9mAHAyfGRx
         y9jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VbkALZgv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9/k2D0xfC7ZAFIDxrkn8W/aFTs13znCO4JzoYkjgvE=;
        b=mCQHhyOruo68fSt2CoSllvcexNs3U0k2HR4h2NzaqY5QhBX7tRTPGvqEb2rvZ9WNei
         NYAs0AXAow0t2BANhPWPY8fFMQYluwzxIJLt7noVEE+zOTF6BYmsRx5uitaUHqXzr9nh
         I2W9jA7suVsVytohIrq6Bdo5njUTgnhfsdz84GbJ9UZNaRmPAt8EJ8aww91zgjIGWvrg
         Zp+iGp0Xx3w0rdGNegqJq8WZSdbnF/CqLsiY2a9SlA8jlhjOTWm2nmLqhY1HPZhshcWJ
         v+8beWdQ20IKd50rd4wImJ63VfG41J3DSuD45YrgXuuQeGjAJcpMB9tgObVFkxyy2RBy
         3kHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9/k2D0xfC7ZAFIDxrkn8W/aFTs13znCO4JzoYkjgvE=;
        b=YOAbquDysWTCsF5TRdSiww1kt6MUmEnZhn1vLYwY/xSWpC1+99gn5pbte+qrfr5pCv
         5UA2KEAVzw+bmxw616PAGLhxR7fYPbxuiffgPBZzlRWHDWmPKpeHb330CM3I+DjgWab8
         B/S1WfCqazW8pXXsk94a3xDaeLNI//CMN3Xqo2mM6djCHLzC8WQbNhruLZns0LEyxmJ/
         DED6AH0ooUs4FR8ANIFmZiyUYQ88zmMLJhAzu0nS4y29W/ppFZ5txryI84Aep2+AkSo9
         qasFeBmRUQhGLrqhsuANR1Ljn3AbR9jPmLhTlwHM5n4+Jfgj0MBXg35v6bqVoCFX8J1f
         V++Q==
X-Gm-Message-State: APjAAAUi7gYETqa/wAG2CONbBYlCOxUsxCntpXWgMxoXnHuUauMv5toU
	ujY4fFno/2Ba56c5VESjaZ0=
X-Google-Smtp-Source: APXvYqwtEDKbOklKR7SjmutozplbpaCe1Lg32qqEJqAjssYyOFTYW3AvVDmxFhLkrmOGIlQtNJkRHg==
X-Received: by 2002:aca:ea55:: with SMTP id i82mr2891891oih.125.1571233655471;
        Wed, 16 Oct 2019 06:47:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1d1:: with SMTP id e75ls431861ote.15.gmail; Wed, 16 Oct
 2019 06:47:35 -0700 (PDT)
X-Received: by 2002:a9d:6c99:: with SMTP id c25mr10683639otr.157.1571233655194;
        Wed, 16 Oct 2019 06:47:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571233655; cv=none;
        d=google.com; s=arc-20160816;
        b=mwQ1d0ggVNLN8a+ImZ/xd23cvstW2iuZvvyfxioNykNBPLBfZrIsIgv13l6vsM0EdO
         XF5dHZc33F9XuHUBOELNQt/8UoQ+DZXofY4tNUHYXfbmhXGqBfI3s80R1+PlTLbeRmXY
         niVeo1YtifPxU92pKJWsQIrrUykmEEMfmbfGnfLLLyDCpWMPYE39OEhh7zgsD/YaZC2i
         aUnGCWu89I1fMdvWLbe7vd5ayCS2Kp5anF1Kq3MB8sMkalq2r3irRx92CSmU5s24pTcZ
         pLaYF/CiXr5P8uPEanW3MvhmAgP8IYDFumpSp72yML/oKwjACSyTfHiqWR7euuEyELNg
         cfcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1JVFdwKlaPYassS1P4vCJ7IRfc1G8OZB/8GG6B6QAKU=;
        b=aGds18/sjWVqNOb/Kb1QANBo6exwcDUyDOPvo+9Mo5iaLsBzOfGRV2FxQZUW+hLd8N
         PPTPClViMFCfgGoYeQiN/5+DyDLE7ys/+pGzUVj9H74866H1uM+xlY9CC+UbxsSjLkmD
         BjlOYCZ6G5OI623OiHmoZES9vRJ1esstKwVaWzNPHB9dQV2CP8D6iT5l6IQ6JkG1b4el
         ipskGbHUyu1gkSUZMCSi6BOWKz2767hBiKLIGsEObiNPTFSB8y+TisrDYIEdh8hrOfIg
         LBCUksTz3tsRZE/Sy2KYqTGSg01ts4lm3sW+hUjtkFJQ1FmR9z+Kl712M7Cc4od0QgTk
         eznQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VbkALZgv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id a22si848663otf.3.2019.10.16.06.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 06:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id q12so14766689pff.9
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 06:47:35 -0700 (PDT)
X-Received: by 2002:a17:90a:6509:: with SMTP id i9mr5126668pjj.47.1571233653976;
 Wed, 16 Oct 2019 06:47:33 -0700 (PDT)
MIME-Version: 1.0
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com>
In-Reply-To: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 15:47:22 +0200
Message-ID: <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
Subject: Re: Makefile kernel address tag sanitizer.
To: Matthew Malcomson <Matthew.Malcomson@arm.com>
Cc: "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VbkALZgv;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
<Matthew.Malcomson@arm.com> wrote:
>
> Hello,
>
> If this is the wrong list & person to ask I'd appreciate being shown who
> to ask.
>
> I'm working on implementing hwasan (software tagging address sanitizer)
> for GCC (most recent upstream version here
> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
>
> I have a working implementation of hwasan for userspace and am now
> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
> CONFIG_KASAN_OUTLINE for now).
>
> I notice the current scripts/Makefile.kasan hard-codes the parameter
> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
> variables, and found an email mentioning that stack instrumentation is
> not yet supported.
> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
>
>
> What is the support that to be added for stack instrumentation?

Hi Matthew,

The plan was to upstream tag-based KASAN without stack instrumentation
first, and then enable stack instrumentation as a separate effort. I
didn't yet get to this last part. I remember when I tried enabling
stack instrumentation I was getting what looked like false-positive
reports coming from the printk related code. I didn't investigate them
though. It's possible that some tweaks to the runtime implementation
will be required.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ%40mail.gmail.com.
