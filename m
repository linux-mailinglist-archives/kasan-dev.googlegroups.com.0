Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWH42TXAKGQED3XCR7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE53103B3C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 14:23:37 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 15sf13935445oti.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:23:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574256216; cv=pass;
        d=google.com; s=arc-20160816;
        b=Prf/Nw/+3wFrInsVbxupDfmsvXIkehdHuh36Ont+vXYnmKpewf9WpwDMMLItovQHJG
         cyt2n29sxzC4zkIFG7kD4/gMPscBZnT/3aLICjleSQW2NJksUNGBDeB6RQLzUqajjpm8
         dUxqEIHegc19AjBXW2NgEWWp4qRL7rjUpJix40gsAirk+1wyOwONFNTubFzYyrtyfkpc
         LD2Mg3EHW4BAn+corb6aNThg/lHMm0ip4XTdobHuJjzLzfzrdYUFdHoxm4NdVjfcs7fV
         MD+c3A5Xx/PIpZrZv/3H2obEWjeLlS1uZSJE9LMUpYQRe4s+yYJ95mGjx0rLEWcxsWIO
         2cfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7Sfp5IaU6Nnwk/nsN7bjvAw5l9QzZnu36mOSrpRf3rk=;
        b=wZVF/PJjBL0rU86RLYScrr3rstQTdeo7+8my4B3dcLB/r586Et6Wxrc0S1D7FoxBvp
         ffdNJMAfRMkxKFxt0xWjbyjfAUxTkEqflWXI1JAmJAhArQazc8i3RkWmr6K+eWRHWTy6
         Lua3njvfTiP1vfrwYN1JAxF+QtYkNHLexPv0Hw35I2AIgWUJbe/IX/akg67WgRdlEAU7
         ptMSMfC/N+sNLVHQO68jSWaW4C6TMCZoBtsTGFx5V9GNBLVIxwdxBHUvAB/8vMbzDj+P
         +SdEnmvk+CLZWOgWu7DXe7YPWV2ebTOrzcyLm35PFKKTlT5a5DuvEoXea4JhJPeGxl2u
         N3YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=URTIsW6t;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Sfp5IaU6Nnwk/nsN7bjvAw5l9QzZnu36mOSrpRf3rk=;
        b=TZzhwn9MFXkSVpWdrxtdio7Khzmdb+4GQbyUCogwvWF6O1CcW3cAiXL5Fp5Oa9wvD5
         i1xRk/45F7YD2L4Z5Dsl2lFTxoKVOcC5hdeKT2JvYnu3aDdLabR2PuRNDvEBDQckhJAT
         2HhRdYl3Lvrk/greUA0+cwlLJM+xBq8PXWlZRVzymsQc8t+wcvLzDRCsYtZz8e5qeuFy
         zpkDqAW4qx6lIOHRjOOv0X8U4rc8Sc3wliHpwec9VLh7DXMDkW8px+goa9esgKYNQVgQ
         PYUNVigWn8PW5USbC7duUMSAiIsXjGvRrYY9253MOSVfJRjjU/6RfSK0U3i52clC0hwA
         Whog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Sfp5IaU6Nnwk/nsN7bjvAw5l9QzZnu36mOSrpRf3rk=;
        b=Dj5BCX/E2TXePfKfUfnulPsgzv4/4enGtwJgi+gtXYxvS+FtWVYdInzow/nOa0pvYq
         zix0D0eRvC52V+H+Be5bIPNj/FE5j5dLu/x6rT8ukc5Y1lh6H4iUxUtjW/iU7V3zC5DU
         X3V1x9WHqRenk1TdtclTGghjDZcAKcBlSxtMSQ8tKf+sIDGo2h3Tc/UPbCoQSwjUAnQl
         NQwhwAQv5XUS0iFDlMKB0UktErm1PhFJub6kJjg6d8t3zMAqprIuSlyKfKlGf4bYFhLD
         b9UF6T7Nah8/BAe054EVBytUTPZm7NJ6C54aUqk9fCQW16a+neqF5gCXupmTjDJEIQ5O
         5rBQ==
X-Gm-Message-State: APjAAAXbAW1t74J77shVlus/vvLI94e9j1TOWJb2Ew/P6AxqF0fOBAE8
	qouiHfwIqVV51xDgi49N8Pg=
X-Google-Smtp-Source: APXvYqzoxOH0leRF/TFV+n87BBSsOtujnAfE25t8St7eqHm8z0pPQ8LREd6c8YqIux2orP1LZ2SebQ==
X-Received: by 2002:a9d:6c48:: with SMTP id g8mr1954945otq.252.1574256216044;
        Wed, 20 Nov 2019 05:23:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:62c5:: with SMTP id z5ls301703otk.7.gmail; Wed, 20 Nov
 2019 05:23:35 -0800 (PST)
X-Received: by 2002:a9d:6f15:: with SMTP id n21mr2061194otq.231.1574256215800;
        Wed, 20 Nov 2019 05:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574256215; cv=none;
        d=google.com; s=arc-20160816;
        b=V69J0lJ1WyonziBy7Jka7kBTgDft1PmkiLZxj/rwF1BOqxpJgSe/v36zPb8xENquxO
         RjCK/0Tj4HIKU8hICi+EigKt96+EC5UWzIxIKp0WbyZf5+Ma1O2DQEb6ryHpkC6bbLcU
         SaVqHDR0aju0JKzQ83wrQgfLGc4syKqtTUDvD1BcTstFoeFUE30v2pf0srGnVfrzirhR
         VI2OSGN7hOK5SUXZiBGxtMOEZXF375XPGraNlwYrHUW3gtOKz6aLknvRY0Cuuu+C4024
         gjmW9tvlVc/j6Td3NA7wfwvyjjr1DWUYpiLQDK2IZuu9gltdxSZ1+1R0LXi7XtGPjCEK
         pMFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HzMXI8CiEmUCb1T/mIucbXJe4tU8bP4I9jjwwuAfDKQ=;
        b=ihrQ4mY2cUxfppTSVAxTWkIK0F44bbeJthx3G5M+NIOBExdKTw08f3Jh9ONY43REtz
         OGWNBkehtSxemwhsJiUdAjFqCD1Ee4iQHHrM30BgvJwOy1RAscTi7wlh6UM56WDAN3n2
         MA8qYg7MXOaRHZPyuhl44rRqZc1lvxYAoOV/w5bE49dVMvf3TY2n7VmEgCr5ebhkDS/x
         URszLIegC1eKZ1jWlWbwNM/8Y8w49DjY03ihRxvEn0GGZ2wQbj+c/lwuwxIJxaiWYqHu
         rLht1ejE+kytuinGtCiSsBzBtr5g2GT+YEkHTl22KAWdqsEtVoVSfLqZujGtpkcRbZ7W
         huXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=URTIsW6t;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id i23si1389827oie.1.2019.11.20.05.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 05:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id d5so21150715otp.4
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 05:23:35 -0800 (PST)
X-Received: by 2002:a05:6830:1319:: with SMTP id p25mr2092594otq.110.1574256215221;
 Wed, 20 Nov 2019 05:23:35 -0800 (PST)
MIME-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com> <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com> <20191120112408.GC2634@zn.tnic>
 <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com> <20191120131627.GA54414@gmail.com>
In-Reply-To: <20191120131627.GA54414@gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 14:23:09 +0100
Message-ID: <CAG48ez0KscmTLf2_-tYPuoAxRjJtzUO8kmAPQ_SZTP1zvqvTtA@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
To: Ingo Molnar <mingo@kernel.org>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=URTIsW6t;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 20, 2019 at 2:16 PM Ingo Molnar <mingo@kernel.org> wrote:
> * Jann Horn <jannh@google.com> wrote:
>
> > On Wed, Nov 20, 2019 at 12:24 PM Borislav Petkov <bp@alien8.de> wrote:
> > > On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> > > > How was this maximum string length of '90' derived? In what way will
> > > > that have to change if someone changes the message?
> > >
> > > That was me counting the string length in a dirty patch in a previous
> > > thread. We probably should say why we decided for a certain length and
> > > maybe have a define for it.
> >
> > Do you think something like this would be better?
> >
> > char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
>
> I'd much prefer this for, because it's a big honking warning for people
> to not just assume things but double check the limits.

Sorry, I can't parse the start of this sentence. I _think_ you're
saying you want me to make the change to "char desc[sizeof(GPFSTR) +
50 + 2*sizeof(unsigned long) + 1]"?

> I.e. this mild obfuscation of the array size *helps* code quality in the
> long run :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0KscmTLf2_-tYPuoAxRjJtzUO8kmAPQ_SZTP1zvqvTtA%40mail.gmail.com.
