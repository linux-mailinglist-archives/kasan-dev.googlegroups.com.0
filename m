Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY6JTHXQKGQEJR44E3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 28CDA10FEE9
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 14:36:37 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id h190sf1526970ybg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 05:36:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575380195; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSubNMg0e5NJjmoMf7QXdUpEXsMjh/jAL9fiILUR+JeggU/l1pzDhffdHGlUt4BGgn
         qyYHv+yurK86lpMKLAfVhptvmKyRCvt47oWrxWog2mKJUydw+2CZ3Lgf3Hfakg35tKIi
         bhYmZ3ige8rMhUJS6rKtnLaq2UVDdagkW1IjPJscIolmlMAWczJqR810l94NOCF0CkIW
         9Wrq5VvjdM1cE1cm41HpogBu3dttxcPxypoxFU+plTN6ys+3rkhk+Gj+3EMKn/KJ6p/H
         6mcrixq3AcGyeYK41Y349DtD0Y67ZnXzQPbb4lxbLX5oGxxZUzLkfyU1vcTbl/XrMhaP
         V0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Sg2JaDXxnapqwvE2P3bU4ch4oKDDPfFiKSBYdv+7+Jo=;
        b=gg85Lt+szC2X08Xv74KSFSkn/PPRpB7VLd/67AZIRPdHmZtJ4vksjqvmskui5DYXHe
         toxi0d1x44bZWDO4pBFMQopm0A9vDCx8jVemuBafbcUcf5sYd6aSz8HTM7u/mio6LkTv
         6GzVCo1proV5fUAhD0BNOVJocu4wQhasceD2VwzkA/CEOJsPDTbZslUEKMVMOVcOkSmZ
         k68PpaoxD7ehG+mPgNYzhiNZHkGAugX/TAfVJlUJtuXodbMocrFz3zh6U0p87za81zBY
         l5FmhB8Ukx4ouPgYDJLrNOsU5sW1Y6vQW/DU44MbUv0vV51M3iJIQ2UCvtE1Rb/IeEtw
         SgOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Plyt8WUH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sg2JaDXxnapqwvE2P3bU4ch4oKDDPfFiKSBYdv+7+Jo=;
        b=lqmLdWjYmBDO+VTLIHsnrPLsa0rMDIAkMFLW/8/tzDPES4h4P0HVww5ADFem90fd9i
         8/+ftc82hi2g2j337G2DNysYFwMpaDhFtq5e1FB4us6dmHuAAb4ATY/imzg8pJgFhocz
         dnNx7abHw6JHfyPYLD2h4LrgCBCFYp7cF0Lg41Tz93ndYGafG1dO7KJ7g25F7YzrvGZV
         xy5oJWzZDK0Tp7XdV/NezElaUY9RBw3tgWJPqhH0WgHnVR3Tyn13p1GOMRUHf7ESH97T
         fLE/GMgQ3uzPww/UT/UhEYVPjm33VXLUy0DhChOQ/zg2zoyLflfIGobDlUvGoZX7IWZp
         6/FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sg2JaDXxnapqwvE2P3bU4ch4oKDDPfFiKSBYdv+7+Jo=;
        b=kZh503gnYtf9fKaIQRk7jPF2iTaOdgac2BkXbkgKP7NHKF8FIAIlyeebNZFss2KWhL
         ZMZ913b513oZqYszd1F/AdmbChme3DKu4F671S2omiYI8rFQbkDkAqSqhEa2cG7vRsir
         jTGHd7DiMd9Ywc7cP6n4FIAEZJJcJldJTlVOVgFWRzf4BNS/vnCGNpyRaSotxrpQZyDO
         AzNGNxBZqxBrUC69mwKsSjxa5wFZFCYzSNVsgYGsGxTd82h3cNV+B4Z27f7LdKDDpG2G
         tGJyqMRAqKPumXI+3RHsYOD2wVe9qvD+l6krkmDtyH8yNxaq1KTTG28cEPrtoGICeBKG
         bZXg==
X-Gm-Message-State: APjAAAU+3FoI7T4oJcg8EJ4udRHjnwYPSJQzZzWIjgJN5JBjy4b5yndR
	b/eHyUQ8+SmIFBpFR/+Ra14=
X-Google-Smtp-Source: APXvYqxRX60R+GwDk/tYTYkJ7fcZUtqFcl1V098IpaEdQostqElkdo4NKCrFFlMgxD/RBRrTE9y7Tw==
X-Received: by 2002:a81:5a02:: with SMTP id o2mr3485892ywb.185.1575380195784;
        Tue, 03 Dec 2019 05:36:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6144:: with SMTP id v65ls532011ybb.12.gmail; Tue, 03 Dec
 2019 05:36:35 -0800 (PST)
X-Received: by 2002:a25:3d06:: with SMTP id k6mr4458984yba.496.1575380195257;
        Tue, 03 Dec 2019 05:36:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575380195; cv=none;
        d=google.com; s=arc-20160816;
        b=iUMkADB1i76dLF2SIEaWCt/4X0jA3EdLVJSdHmz7/wJcknhMYh+b4mL+tlDI1tTR4e
         F3DElUs1tF7GNfLGkoAtGBkjB6MXvRwkhCZIBUr7ygeWtrZTNqGvW9JJc9XrkCNjloDL
         xDNNbZXp97nXYTsSVtFbWzuod6gzWX5hfTkha3e+r5yp8qwzQIM8bhtuuxaVwkfkci9Y
         /3hvzMlqu8gksUxZR+qo6BdQnOM4AjHSVtRXx96CjdyVLt80kg++NDnpRlCU0c9TvSM4
         FeY/lBujTAHbJ56QJtl9SKnFGpwgSMxlpXZ8323JC420Fj9nTesGsk0BL5990c3PpIJB
         61Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p7E/g0ZgEG0SIrt/LMvG8aw0gP5PcAR7IiJAD9Z/f64=;
        b=iJp+6mZpQDXVrl1NeTFqKO6WdqziEq3Zjlo6sDxaQS5OsDelbhhHBM+ULt6nJaLiIP
         bTVx4yn8ivRBcIFlhn8JTK9O9OLlCupq0yiTVZ6RaBB9/zHIblxrBRzrsWQt2+EdXHmT
         Qxk2Ik5SY75v3TWnC1rZstdC19cuUhUkAIls9m52LYyI3gMg/rKF4v0ioPcPqyMML08E
         zWERXtpPsRw8IflOOY3CnGeVT/REO5URoJo7VQaDl42Q8DU4RcQzrWOzXtCHMJ9tGLAE
         uW+U7zqxijYNCmkrGzSZvaHGxdoANWOP3FAr+OcH+SMIr4J3BvWRgPGJ475GtmgE3Bfs
         TUFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Plyt8WUH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id k63si134580ywe.3.2019.12.03.05.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 05:36:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id l136so3301672oig.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 05:36:35 -0800 (PST)
X-Received: by 2002:a05:6808:8d5:: with SMTP id k21mr3650897oij.121.1575380194257;
 Tue, 03 Dec 2019 05:36:34 -0800 (PST)
MIME-Version: 1.0
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net>
 <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com>
 <87a78xgu8o.fsf@dja-thinkpad.axtens.net> <87y2wbf0xx.fsf@dja-thinkpad.axtens.net>
 <CANpmjNN-=F6GK_jHPUx8OdpboK7nMV=i=sKKfSsKwKEHnMTG0g@mail.gmail.com> <87r21lef1k.fsf@mpe.ellerman.id.au>
In-Reply-To: <87r21lef1k.fsf@mpe.ellerman.id.au>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Dec 2019 14:36:23 +0100
Message-ID: <CANpmjNO5MgoBGBxv5iTDCegF-Saxg7dxeiTBqQRKdeUf1F5wXQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with
 generic bitops
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Daniel Axtens <dja@axtens.net>, linux-s390@vger.kernel.org, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Plyt8WUH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 3 Dec 2019 at 14:04, Michael Ellerman <mpe@ellerman.id.au> wrote:
>
> Marco Elver <elver@google.com> writes:
> > On Wed, 20 Nov 2019 at 08:42, Daniel Axtens <dja@axtens.net> wrote:
> >>
> >> > But the docs do seem to indicate that it's atomic (for whatever that
> >> > means for a single read operation?), so you are right, it should live in
> >> > instrumented-atomic.h.
> >>
> >> Actually, on further inspection, test_bit has lived in
> >> bitops/non-atomic.h since it was added in 4117b02132d1 ("[PATCH] bitops:
> >> generic __{,test_and_}{set,clear,change}_bit() and test_bit()")
> >>
> >> So to match that, the wrapper should live in instrumented-non-atomic.h
> >> too.
> >>
> >> If test_bit should move, that would need to be a different patch. But I
> >> don't really know if it makes too much sense to stress about a read
> >> operation, as opposed to a read/modify/write...
> >
> > That's fair enough. I suppose this can stay where it is because it's
> > not hurting anyone per-se, but the only bad thing about it is that
> > kernel-api documentation will present test_bit() in non-atomic
> > operations.
>
> I only just noticed this thread as I was about to send a pull request
> for these two commits.
>
> I think I agree that test_bit() shouldn't move (yet), but I dislike that
> the documentation ends up being confusing due to this patch.
>
> So I'm inclined to append or squash in the patch below, which removes
> the new headers from the documentation. The end result is the docs look
> more or less the same, just the ordering of some of the functions
> changes. But we don't end up with test_bit() under the "Non-atomic"
> header, and then also documented in Documentation/atomic_bitops.txt.
>
> Thoughts?

For Documentation, this look reasonable to me.

Thanks,
-- Marco

> cheers
>
>
> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
> index 2caaeb55e8dd..4ac53a1363f6 100644
> --- a/Documentation/core-api/kernel-api.rst
> +++ b/Documentation/core-api/kernel-api.rst
> @@ -57,21 +57,12 @@ The Linux kernel provides more basic utility functions.
>  Bit Operations
>  --------------
>
> -Atomic Operations
> -~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
>     :internal:
>
> -Non-atomic Operations
> -~~~~~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
>     :internal:
>
> -Locking Operations
> -~~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
>     :internal:
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO5MgoBGBxv5iTDCegF-Saxg7dxeiTBqQRKdeUf1F5wXQ%40mail.gmail.com.
