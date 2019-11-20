Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBLVM2TXAKGQEZPF63BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 10F1410379B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 11:32:16 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id m15sf3486287vsj.22
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:32:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574245935; cv=pass;
        d=google.com; s=arc-20160816;
        b=XhsY15cVRDiG+dFHyqduRAPURo6nEvcUUrwZwJHdKOyn6hVXlMZl+Gkyuxq9a5VlNm
         xZeXPCVUslgZmH3+7AjHphirPQCF2vS+kVqIUIwDu9nXP4Sbgr1XffG9Guf3brvZozMo
         6h34/zNbDnRFywwyrs2MV8p9O6D9Z7yHpVLUXC3Atg7RO0htYf5I33XghfP4hWqCWOtp
         /4/VN/hGevKnWPGLl/Nyi2rNWFl4s5inzcTiYWk/boUohJsRGr/algmjZ+B+zQgqqP3o
         haTyGn8O37qG9faK6cBWdYJtKw7YJRFwUX9sg4LklEkdwe2R4xS6jfX68e7cnzG/sRLZ
         IQSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uAdvjO9OvTg73NjZIDRknbJeNtDKjl2ucHBcrQ4pIU8=;
        b=jD1K3qixR8LmsE4nXpIn0fB9KkY7PRT92l1jDJP4PNQ5mi29HRxtCfgEJsFm1uKKRr
         Yct8EX4Bz3w13G7K8tibAy2pJX2mCFTkVF3piVFL2oa9x/60Sjvnw7akMCQTbcNyRpfd
         du24BscFByRN9VgtI39npZPgVTudC0ek+AR7yEAGRS4XSlY28IxA9TXnHcGH8tTDbMI+
         ZTmEXkq9ZRaGKCX2IwqKtWtU+Pn/cE19C1ml0kY5EsbZ6anKvPDchvq9GfEoxxhykecQ
         jQ+9/RAp1V+/yLhTfvhP6WMrcqObVsUgXEbl9oAF/Qa1QMYC3kG2GIDB115esdRUNE3R
         5JAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CE0dlbug;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uAdvjO9OvTg73NjZIDRknbJeNtDKjl2ucHBcrQ4pIU8=;
        b=g7sHVRR66QbKxITtoe09oTePjeMwIX66zFxdr0pPOf8zxpZ4600myB9oKfwOtt/Vwi
         qWPJ1vgccQaAOz2NyTYDAH1aW1egvc6VjfQNRq96YHdhRPdVvz8jiobok9HW3KNiGol4
         k1QhOlNgusW3eXj2cVtIFj/LVoW1bzAhfGEHBNIHLxaGDMgUFNsn+E3aqnK4EeJdP8AS
         eSVfxr4XylJ3H4G8UkJUyEY9C3hwYCODAarmbtaWMseq3KwD3Ri0Oi8T97lt0u3qK12z
         nz6VqOSfe4VMlqPGstOKInSDyp6Ip9cEzICHQdjlvrCBBoiTRDAfWMZrRHTqTaC3NB2Z
         K3JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uAdvjO9OvTg73NjZIDRknbJeNtDKjl2ucHBcrQ4pIU8=;
        b=gW49WIP0DxAKiyG8lT/w/3Xaq2WVP8FFwLUhJvqA5XXKqyZ1GR3afJ0TxQTXdmnW3h
         Q/PqOVUdniVgv+gVgcO8fYPaWOFgyzU3K4w1pLgQa/8fqFqxPs5dwMCbNi+05EhILXwi
         S8SRpde7KIvcjF/j7yiKoKSVexmC85d5INYFma1avZZeRvgrtSv4TXnPf2VPl9Aj8rzt
         /jEHxfBld8BurSjT01hTffHZ4UtMiSc3n5VPvDGShmPlmjPlNhtU/YfTJBsthDKrnVfC
         xHeuQ9ozMileDLT3THERBP4OU8MWj4MK6kTUys3miFi/sD12IWxUqGEoRRYOB/oIpVSR
         tJ7Q==
X-Gm-Message-State: APjAAAXmGYjGTBI46vyCJE0eE/UitiWicE8bDYhT1OTX0CEAyzkeI2Ut
	9EJlkueFnJ3XLPN522wVUPk=
X-Google-Smtp-Source: APXvYqw5zz27or8DK1hyaPCKIMF3VmOTg54x2InZpTB88S2DOtmHHD+LBfYAOuQFqKgC+lBRMjKV5Q==
X-Received: by 2002:a05:6102:50f:: with SMTP id l15mr1119193vsa.142.1574245934882;
        Wed, 20 Nov 2019 02:32:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c5ad:: with SMTP id f13ls55385vkl.2.gmail; Wed, 20 Nov
 2019 02:32:14 -0800 (PST)
X-Received: by 2002:a1f:b655:: with SMTP id g82mr996122vkf.16.1574245934545;
        Wed, 20 Nov 2019 02:32:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574245934; cv=none;
        d=google.com; s=arc-20160816;
        b=E29QQKs3fFwNQ4LGL7nd1zAvmWFS9VpGDGNIGQ5KE9Rhggl/+IekW5mzMyhYEEye5l
         fcc/xB/lvJ+hNQpKodtk50LMS+np5a3/0NuVW8bZpfLL8Wy1cJjx5Dldw3EWlW1hhoql
         MexA4ZFdFA57wExj2h46TWVsjoOH/9+KDMkJNhdyhYVjUkLqTLi6+8yLVWnAlcqdSXrM
         iRCoMAE27rZXJ1Kv2ZE//VNTuEmv9v5Z3jw4gvRkz+jVFHNUxugYe+zE+mMMA2+GuXM/
         vzw/lKD4vOuEnF9C5hLm3Yz0tDIDta43AKI7NGEviBBhphjFhFHaFuPKThYNRwQQGJhU
         chBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d1foUI+kEt19/UqgoFCikIfHMIMozwp3Ih3L2RLMTA8=;
        b=DgVdW1wczd4oxCcj8J2BOltVKD2F4yqYNf5jLoNatWLZJ7EYwEXJTIJQqy6y2Qvwnp
         /C/hNLTnL7ZoQsrGhurWCk7GJntQGHYA60b6RT9GFmHUWCWK+e8Sfl9Vd2fAMLq2hqsL
         vf0Gv7xWzUqcQVpxhWjACOfWYIM1GUUjoFeBLpQm7W3s1+usnKgrPcglJSqghutqPIUf
         b0zzfdtCyU7jCXTsmqVW3WmRjIJ6vuX1fhr+7nWR8WWwDrK5GLxVDjgEr1YobkdTCq7d
         JLs2tABVyQaZrrDD6aJVm8xjkp6asD9f05P1YgDDhCfxb+0cWQQnnu6alk7I51cUKI8D
         2q2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CE0dlbug;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id e11si1403584uaf.0.2019.11.20.02.32.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 02:32:14 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id j7so22040522oib.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 02:32:14 -0800 (PST)
X-Received: by 2002:aca:4a84:: with SMTP id x126mr2037189oia.47.1574245933839;
 Wed, 20 Nov 2019 02:32:13 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <87lfsbfa2q.fsf@linux.intel.com>
In-Reply-To: <87lfsbfa2q.fsf@linux.intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 11:31:47 +0100
Message-ID: <CAG48ez2QFz9zEQ65VTc0uGB=s3uwkegR=nrH6+yoW-j4ymtq7Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Andi Kleen <ak@linux.intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CE0dlbug;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, Nov 20, 2019 at 5:25 AM Andi Kleen <ak@linux.intel.com> wrote:
> Jann Horn <jannh@google.com> writes:
> > +             if (error_code)
> > +                     pr_alert("GPF is segment-related (see error code)\n");
> > +             else
> > +                     print_kernel_gp_address(regs);
>
> Is this really correct? There are a lot of instructions that can do #GP
> (it's the CPU's equivalent of EINVAL) and I'm pretty sure many of them
> don't set an error code, and many don't have operands either.
>
> You would need to make sure the instruction decoder handles these
> cases correctly, and ideally that you detect it instead of printing
> a bogus address.

Is there a specific concern you have about the instruction decoder? As
far as I can tell, all the paths of insn_get_addr_ref() only work if
the instruction has a mod R/M byte according to the instruction
tables, and then figures out the address based on that. While that
means that there's a wide variety of cases in which we won't be able
to figure out the address, I'm not aware of anything specific that is
likely to lead to false positives.

But Andy did suggest that we hedge a bit in the error message because
even if the address passed to the instruction is non-canonical, we
don't know for sure whether that's actually the reason why things
failed, and that's why it says "probably" in the message about the
address now.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2QFz9zEQ65VTc0uGB%3Ds3uwkegR%3DnrH6%2ByoW-j4ymtq7Q%40mail.gmail.com.
