Return-Path: <kasan-dev+bncBDEZDPVRZMARBBH23ONQMGQETV3KNVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F4C362EC5D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 04:33:34 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id r23-20020a1f2b17000000b003b89463c349sf1310419vkr.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 19:33:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668742404; cv=pass;
        d=google.com; s=arc-20160816;
        b=DngVjCZvGS+jUTknXwLLrksgurqxRiU2aQb8ULxvS94Ee8uHeY+HVAQld6gUQoy32c
         Sc0nuUsQqxu8r9FycrwVxx6p0eB8bDAmkEcEDETySylLlO096zS3DWox1aFmXhWSOK27
         N74BuDs9/Sss6eDKFiliTED+Rhb8ZBm2yFXyJIkzT7cxchLpZx+IorTJrSa6NbRZTFJb
         K0FtH70i0O4oDDRsSdyz9/TXBjriy50JeQix6mcqx/TXyhorHasozH+kQ3eUBrMe3oWC
         PaPaD1V+MDJCblepIN3aOHAfHKIVTupitkbCYvbQvvNcNIYGGiw7NxjsYMLsvX762yoz
         xYGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3F4w31U7jz83zxgwjgkuinSjpYgkLva757kVEvkcNno=;
        b=pcQ7GH5BXEFCsg1DnZyzLPEKGBH858yKbCnLojaPo3nskdxUb2gFXFLodtW7VZM1Li
         axfHlrZ5GunzYSarpkz80O8zkjdD7f8ytrjZQ8jBYL/SvPmLX0U5uz822mHF8rn8XHbR
         OWNvYQ2wdH6tdlxApIwrsfz9GXuE3JN7Zs3pkiBH159kSGFm3YNAOV4mRGxVHYsvlNzZ
         2fUeYseXdl2hgRRObyLnbZlXZgomk+gazIeFqKKhzPsWwX2wI0vHK3cFR0vZwYgs7iyI
         yjVyASL08UvGBWX2xfcVj3T6JYuj5hJDLttoS67kiIxoSAZYdNlMEUie/2/SxLqmtTz2
         d8oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=He0onnLI;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3F4w31U7jz83zxgwjgkuinSjpYgkLva757kVEvkcNno=;
        b=XEd2dwjvC0xu2/xFxSgOTO0nb5ZRVgoELCXgCi2ArdwaFTcIy5Djk609lP0VQ3Q0F4
         f6VcmEXSREkFViOIXzM7IIi/y84AzP8ol0HUeMX6S8/VcNeA6yXbHZD4uoMo3jypyvap
         NpUfYMRcogKjST0UI+CbXj+oTtITeCtvA/Km9upLkeS6SSW5jjauX4Mntvps0Gmd37z5
         XZNpgonAfBr+otAieZ9pM70wWhu6ZmSVfGFu/hooX+fEhImdb7s9NHN7SjwR6x5IGqap
         r8gtiGLoWTPbZPjHvnpbC9z+Vrw0oAKgbDD2lQlhwBHjw5TbvXjS5J/ylA+aEVI7vo6U
         jnSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3F4w31U7jz83zxgwjgkuinSjpYgkLva757kVEvkcNno=;
        b=fj5S0TBZbTgPBft467aJHkWFeDIwNXy5k2AakrpZQb0Xu3LfeY+qAWLSDa2c3dz8n+
         v/gkbuGC3lTcZ8++kLOHODuCXanx93sXC1k22zjHY2sXrmMpsq92NCDgf+T84Lpt+uno
         DRFdgc8b5yyyWxugPeciTawROkqGG3U3eXj3mzQSLfw1+Wmp1vwkIZUq38QdZayaFRJ0
         2oI4FoGkmgT1prlqCEL2XvUXYOsgEg7GlCjLI0BreDUKMBtpwxavViIVuscUuQYs76Mb
         tjoNO0L9hP8guc0O94OAVywk8lXBUJvXIK7xykVVWcHpnF+gbnCPb+OMq4Pdpi17SrjP
         A9eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk40//PS/3fzhJ+TiF6G3x1E5oAfI0eb9RBfAlrIQCUhg+uMCME
	kOVt5IaZmqRpPgu57IfUgEk=
X-Google-Smtp-Source: AA0mqf6mUKCVUZHcy+zjIjsh1NMf/uZz/CAbdQt2XYcbwRcPnmYseyw0oPLgztzU8vn9OCyoENNWZQ==
X-Received: by 2002:a67:fe01:0:b0:3af:5ff9:ed51 with SMTP id l1-20020a67fe01000000b003af5ff9ed51mr3232131vsr.46.1668742404446;
        Thu, 17 Nov 2022 19:33:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1b03:0:b0:3aa:ea29:71a5 with SMTP id b3-20020a1f1b03000000b003aaea2971a5ls445132vkb.8.-pod-prod-gmail;
 Thu, 17 Nov 2022 19:33:23 -0800 (PST)
X-Received: by 2002:ac5:cdc7:0:b0:3bb:ddbe:899d with SMTP id u7-20020ac5cdc7000000b003bbddbe899dmr2992286vkn.41.1668742403793;
        Thu, 17 Nov 2022 19:33:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668742403; cv=none;
        d=google.com; s=arc-20160816;
        b=w9PMTJx0rpVgaBjPEKLoREwD4yQLOY1Vb4/SH0EaVQ+30oy4bLSQ8AhxTBFbuV9gdA
         cNk25+CN0tK3dI/5EFTUEUamxmxSQVekKuK9rU2ieOgCEz+8RHqfFbgG36+fzeii+I6f
         BMuolbbzvNk+C7U42OmChitKYrBqiFi2ZTN2GsLVzXLCwof+p4+ksCEjQVc/IdfpEzU8
         m0AHkT0E0ffveR2SSUx3sR+WrEPQPUarOugEHbPafVzhH3sqsxvJ4WESibjtsH5kDsin
         zX3da9TaOttWqyr9CbJFVbm0n1t61l0iW2s+VglhG5p1z5D2RHi63dkzUsezfuOGBLHY
         F1TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RdQ4Wpm0oG6wCwcVAHNVtNpU18GLboO8YI77UCdhfb8=;
        b=nhxKgqrAsG+lpDxWPsd3ZM7jPnNMeyGJxGwUYlL3//3t//iavr/jlFcFVtgNP+fUCU
         xr5kAlH0KFG4DnWXuJpzmS+x+ZeyohaPYdVOVq1eAuHlj4U2zxItbi2GcYIwRAZ7Hn4V
         wb55Vr4OE0m+om30CMm7Lw/7HnAew5dxb3qItBgXRyoMij9NB5X7TgVdslyxNnKSaL9I
         pbA/5WF3oTxFKW0YAgaN3bXzlQqt1LEfHUMzULPOUnEeB2jP2WgvLjeORoTISA5g9kIZ
         aATxHOJTM793/1rc9P+sAq/RW1LKfuzCzkb2WTEBjgnmhN7nFbr97QGBwb7Du3sjmxdv
         6iFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=He0onnLI;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id az3-20020a056130038300b00414ee53149csi445277uab.1.2022.11.17.19.33.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Nov 2022 19:33:23 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 420C462213;
	Fri, 18 Nov 2022 03:33:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 76D65C433D6;
	Fri, 18 Nov 2022 03:33:22 +0000 (UTC)
Date: Thu, 17 Nov 2022 19:33:20 -0800
From: Eric Biggers <ebiggers@kernel.org>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: KMSAN broken with lockdep again?
Message-ID: <Y3b9AAEKp2Vr3e6O@sol.localdomain>
References: <Y3VEL0P0M3uSCxdk@sol.localdomain>
 <CAG_fn=XwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA@mail.gmail.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=He0onnLI;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Nov 17, 2022 at 02:46:29PM +0100, Alexander Potapenko wrote:
> On Wed, Nov 16, 2022 at 9:12 PM Eric Biggers <ebiggers@kernel.org> wrote:
> >
> > Hi,
> >
> > I'm trying v6.1-rc5 with CONFIG_KMSAN, but the kernel continuously spams
> > "BUG: KMSAN: uninit-value in __init_waitqueue_head".
> >
> > I tracked it down to lockdep (CONFIG_PROVE_LOCKING=y).  The problem goes away if
> > I disable that.
> >
> > I don't see any obvious use of uninitialized memory in __init_waitqueue_head().
> >
> > The compiler I'm using is tip-of-tree clang (LLVM commit 4155be339ba80fef).
> >
> > Is this a known issue?
> >
> > - Eric
> 
> Thanks for flagging this!
> 
> The reason behind that is that under lockdep we're accessing the
> contents of wq_head->lock->dep_map, which KMSAN considers
> uninitialized.
> The initialization of dep_map happens inside kernel/locking/lockdep.c,
> for which KMSAN is deliberately disabled, because lockep used to
> deadlock in the past.
> 
> As far as I can tell, removing `KMSAN_SANITIZE_lockdep.o := n` does
> not actually break anything now (although the kernel becomes quite
> slow with both lockdep and KMSAN). Let me experiment a bit and send a
> patch.
> If this won't work out, we'll need an explicit call to
> kmsan_unpoison_memory() somewhere in lockdep_init_map_type() to
> suppress these reports.

Thanks.

I tried just disabling CONFIG_PROVE_LOCKING, but now KMSAN warnings are being
spammed from check_stack_object() in mm/usercopy.c.

Commenting out the call to arch_within_stack_frames() makes it go away.

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3b9AAEKp2Vr3e6O%40sol.localdomain.
