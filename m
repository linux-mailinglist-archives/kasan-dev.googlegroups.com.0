Return-Path: <kasan-dev+bncBDEKVJM7XAHRB5WJYDUQKGQE3YH6MFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 377B86CA4E
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 09:51:20 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id x5sf14867809otb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 00:51:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563436279; cv=pass;
        d=google.com; s=arc-20160816;
        b=ot8+jmq9JPc11KQNWVC1pykXDwNBPVwDAT2maNyEe4WEn5kVqgP7KAuoKBMOS/J1G2
         +gQh5s5H51XfYrRRCbMydvwrstBvVrZDp1a8Tmgo3a/rX45X3CrLyXsbUtagI3u4RnL6
         Ubv6iHo22CvYSyWcaTy/0nuiJ9qiFt/WQl12Y7ei8wBRteSVPpWu2j14wSkAiIpR4yPv
         sOsVemJb/A7PDuYG6JVdHNJ8G+ZBFcJPHhTMGrLRs3WEYaYZVpC5K7PqgeniqcYKUm5H
         NiBFRSdtB9BOXGKcGFaS5H6PcFWKQ5a+o972SBAQHWX3shegO3OFBmINTwtvzjfoJaou
         ENpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ILdOdmL1ihCeGCkrESuTIApD9gZjgVpA45lD2PWqFSE=;
        b=BWeeIW5WE7iVagLgZ52jG7fopGLg99x3xHHeGZRZaYuDvOxGe5XBG9Zq9TlmwuFTmL
         Co1wZY4SaKxfTd9J7g90zkHiqpqIs6SyXRt478S48zqyPULNRg/CvmKjRdQl60+7E7jr
         rUmPCykeBoC2HWQi4hIY1pElfuqsz1neX8DLor4TSXlKUW4tevO59ous7lpFjzisIpFO
         w1cB5y+/EB3k4RSrJjwftUc8u8zPYmCkAr5f0TlVeJfFrO9+M9XRLQebFnv2ua3lak8f
         AciSF2ZgESMNiOjAuVehNJavPbqjfdkwI5V7mUxNgnFXngbmLjcXsd2vPfdScQn7okHO
         coMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILdOdmL1ihCeGCkrESuTIApD9gZjgVpA45lD2PWqFSE=;
        b=Cou3SwdE4hE1kDH77duhWlAjt5/WswdvDt9h0tzKqz75u5goB1loS5X+JjT31pEdQY
         DJHc6JlRMwY/Y3s+uWgezE4xjO02VBT4+GNi7l7BpQsL2R3+4BpCY2VGY9/jfFV1SjlD
         eRfLxl7gCwIY6AsaS4v91EBFutWCwFTN4GssNrGt7FD7n6Pbl5wcmjb+DaFwVESoaDGd
         twiX0m5R4ERXdu0Ehjg5N1ypo9xBgAo2w2o53gv6POLNyZfWByAY+Wf2nsgpO0dL+AyU
         qZRd/egk4pb9dJ5pkh2SfL+oKQQPV08HScizhEfbjO57hRaM922Au0pTvnPBl7MEJM7A
         1jrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILdOdmL1ihCeGCkrESuTIApD9gZjgVpA45lD2PWqFSE=;
        b=kuTjDpRKpD6v4wV9APexhq/eANAnm5uRdPy3VhyjM1bfWnifmS7jNkFLP3GCs6Ulg7
         Aot2uig5EfTd/lKhRxWcabXo+iWDtrE7aXxfupCvd/xk22U59deht0Yi7w5kilrDBOP2
         DSneYeBRam05SKpjXhaLRV5F9842YYjcS6PZ/CG/cIXtjsH/6OqapBRcUaAecsw7x4bT
         nAUcEWozqQR3M/owrc2SyUeUb+TwmIOp1tdksaQMASEUuEKXibNfyJ2/CSp5qJ3kZ2K1
         VF3gf0yg8h9zsMdMaDhOk72Q+u5EiN/+wdGUvR4x1GG8/JEyKGZGyywgBltQt3DMyfrg
         nD6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULPZ5ML2Y1qvQQJQkl9a+woSJpO2IdG+KqkWmMSoKSf8L8t+ET
	XbZZ1speDW4AU4xuLn3iSA0=
X-Google-Smtp-Source: APXvYqwE1JlDmM7oCAgmF71o5y9LK0w3JH2HAeT5R0aIDFxK2olQkXnUrZSVPpFxLtEyWkV8OSohFg==
X-Received: by 2002:a9d:27c3:: with SMTP id c61mr31721896otb.291.1563436279021;
        Thu, 18 Jul 2019 00:51:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:5d4:: with SMTP id d20ls3529201oij.14.gmail; Thu,
 18 Jul 2019 00:51:18 -0700 (PDT)
X-Received: by 2002:aca:1b10:: with SMTP id b16mr21711745oib.13.1563436278665;
        Thu, 18 Jul 2019 00:51:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563436278; cv=none;
        d=google.com; s=arc-20160816;
        b=JdcuYkgQn0yzWBcsfX7EHHjwxcWiaueqbrXrKJlT3fPf0zkq1TQFQxYfsP3AXUbn5Y
         wupWgAGFqUXGlnXcCvsVdWa4/S5mO0cSbf+e0UPTQyo3Luh7AKGeNGkn5WJXJgb6lc6E
         7X/Fs1LHBaBkuT9JRsK4lJb8K/XNI5RmAadl7N211z8EnLj4gwvkgepAE8Dibk4f5fLq
         yy30Mv6JlOY4xJJveFnOP/+j9vVmFqqxQteKmCPjnubtNKLihPO5m57oEd8NtVs9KDKq
         Q0LFkFKAFiF/snIpjgxq/RoZimIgCxmNn45DqY/6Kn3w7v/24dgfqDgdEYUSrFlCuQkA
         +Ctw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=AMIbdcIyPjXgBsFnQdrxIvDXu584wusUv2Znj2VCflY=;
        b=VZo3pVZYoJZfWvuYfG+R5verqBw8TVr9WVc69trb1ve6sHnElGcl/+lzlw138ZyOwi
         VGA0Yf8x91IRA8mSqg6FQKpEzNeFw8EztmILbXZtLQsbqe/3zMeBhEYVILZ0TMjzalvR
         WidjbzQ/vJz5THG14HeU2tx/rSNfFqOPC+gtfydMmBOPk+cuspwpl5H5AF7o4n4OJ93q
         gxW32rWgoWGsaDszXiDmtMefV9sakYth0JlapCeKQUUuuRXNLwld2SarbIs6h8iXK9Ug
         GOim1ZWpktss0MVUeuFeILV0Xds6U+lwI/iHuJzL+hTPZDjGF9mwaQCWRuNsb6HDppIO
         4V3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
Received: from mail-qt1-f194.google.com (mail-qt1-f194.google.com. [209.85.160.194])
        by gmr-mx.google.com with ESMTPS id n27si1314467otj.1.2019.07.18.00.51.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jul 2019 00:51:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) client-ip=209.85.160.194;
Received: by mail-qt1-f194.google.com with SMTP id r6so22007977qtt.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Jul 2019 00:51:18 -0700 (PDT)
X-Received: by 2002:ac8:5311:: with SMTP id t17mr30079223qtn.304.1563436278053;
 Thu, 18 Jul 2019 00:51:18 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
 <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com>
In-Reply-To: <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 18 Jul 2019 09:51:01 +0200
Message-ID: <CAK8P3a2QBQrBU+bBBL20kR+qJfmspCNjiw05jHTa-q6EDfodMg@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Florian Fainelli <florian.fainelli@broadcom.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Michal Hocko <mhocko@suse.com>, Julien Thierry <julien.thierry@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, drjones@redhat.com, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Marc Zyngier <marc.zyngier@arm.com>, Andre Przywara <andre.przywara@arm.com>, philip@cog.systems, 
	Jinbum Park <jinb.park7@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Nicolas Pitre <nico@fluxnic.net>, 
	Greg KH <gregkh@linuxfoundation.org>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, Christoffer Dall <christoffer.dall@arm.com>, 
	Rob Landley <rob@landley.net>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Garnier <thgarnie@google.com>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as
 permitted sender) smtp.mailfrom=arndbergmann@gmail.com
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

On Thu, Jul 11, 2019 at 7:00 PM Florian Fainelli
<florian.fainelli@broadcom.com> wrote:
> On 7/2/19 2:06 PM, Linus Walleij wrote:

>
> Great, thanks a lot for taking a look. FYI, I will be on holiday from
> July 19th till August 12th, if you think you have more feedback between
> now and then, I can try to pick it up and submit a v7 with that feedback
> addressed, or it will happen when I return, or you can pick it up if you
> refer, all options are possible!
>
> @Arnd, should we squash your patches in as well?

Yes, please do. I don't remember if I sent you all of them already,
here is the list of patches that I have applied locally on top of your
series to get a clean randconfig build:

123c3262f872 KASAN: push back KASAN_STACK to clang-10
d63dd9e2afd9 [HACK] ARM: disable KASAN+XIP_KERNEL
879eb3c22240 kasan: increase 32-bit stack frame warning limit
053555034bdf kasan: disable CONFIG_KASAN_STACK with clang on arm32
6c1a78a448c2 ARM: fix kasan link failures

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2QBQrBU%2BbBBL20kR%2BqJfmspCNjiw05jHTa-q6EDfodMg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
