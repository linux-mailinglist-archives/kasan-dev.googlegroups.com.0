Return-Path: <kasan-dev+bncBDW2JDUY5AORBPPYXGGQMGQEKXW7CCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A39F46A92D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:10:22 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id a18-20020a0568301dd200b0056328479effsf4481111otj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:10:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825021; cv=pass;
        d=google.com; s=arc-20160816;
        b=B7cnzPF/xzo1ftS3w3XdCL4e99zj/ER9E3rnGPRBX3IsAjPp+vWtqkr32plfXSvNtT
         Qh03BzPvdUESmFVMnDauhcNRtUMi58jrB1tiwbAimUW6qyLIJ5ZR5xGHprWLJ8Kl4kwt
         Q3YEHozKSxuS1fw4KGwn5AVT5IYJHMl5UZ+233qVhRqhVU6F3Kp09N29ZlQD6VO2C+jN
         DRVgD0O55RgLtwq6dGGG/sTeqxvb94dx5/pU49taXJ3ZlyzuNvuk4/goxMmmzpvjSpwF
         Gj4VAE4Ul2d6yHn+avJtwbVcM1Gr7dMWKaCSE9zH6Jcn8J2Yezqetis8olwbJNnk60wS
         bVGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ej6oXufJmQkDzHzD3A6aIk1Q4l1a+mGUVB9AKtWJud8=;
        b=cAK3nVwZ/qfaZgJJT6JtO9icNbagdodt9EIdOKzsYfq0EGCnwT63p6mZsgM+dzm+J5
         HT6Qm5w3fyZ47+HNdtxmWQ7H0e6hN3sM2b23+8MAlwz6xe708Ego/jZiBoG8OE3JpmY1
         akqGB8dRQaVYD7jpgeDVQ4P1FRY+lGUdGFz8qXgLUFJeAt0+0xOkFqQHv5Lx933ua0wr
         QoAa7315GlzmQlbGPJj+LSnGQbgQWneqCby/0Vlsco8X0i5MEbhhrATNaZH+6dGcsyMi
         GqF5AAfITlc+G5yKfDTSZtPqFS7+UgqmFYl0jdlmwOqwbPkUhB94Zaapag/pqvW1aGkJ
         Qm2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=h7sLOi98;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ej6oXufJmQkDzHzD3A6aIk1Q4l1a+mGUVB9AKtWJud8=;
        b=EaABhKetQCYRg3XZ1PPsKbnJdOKhGvgZ1i5FAm71Y0LAZVTUsAEMD4pGoUnCeslRB3
         o0ZzcPSHeHs1rXiKbQQDL+BpguZProOVvWgQOIPCzECPxthq7EWTtCoLgKMe/ag98Hag
         DLRadPGfQNicGPvefr5Rhi6dMWaE41ZNr39ClYVKsFLdwW8KbBSk0cM0JB7n8dnUk3Zc
         gIbBbx+Qc5Klrki1Bsqmr0w6VGhbznNbg+lpZfuAgSIUWHMdSw0c3zvfmYG2zoJ4igPW
         B+iox7/0sZVlNffrvoLmcXzryNUnchR13Dw+lIi9sLqIdkzFko38HI/bau5oyNj6Kdku
         FVEQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ej6oXufJmQkDzHzD3A6aIk1Q4l1a+mGUVB9AKtWJud8=;
        b=b2/+JZ9wchC+AGDIR+I/KDRv/y0rhYbByxbiMzTcXkxDLNNU9PWqRiTRdHxyGx6LV3
         eEi6I9W13vPDjw9uAGB5Y/CdT7nZwnn7RG/4EGy8SGqDv2YYK+ExrtR2JpyCk9sy6U80
         kvWWtc6wwFp3uUlDjPytEUC9wch9jc7Pg4yCssm6lphcvtfV3B9Pi+7cHzJkjLggvhZF
         iWQQxGF2mLJZRmk3AXBlwvNvKq9XONYNoSPtzm6S+ayJgsBQjYCEPSFqgFhOLRz/mD3t
         lVh9slXqDs8juMgj8H5PCYfJAMslUAiFPJ+bQeDFrcWljzsQxQ6MHaGsi7c4w91ATllA
         f09A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ej6oXufJmQkDzHzD3A6aIk1Q4l1a+mGUVB9AKtWJud8=;
        b=3t1m26NTM8K6jN/RzYy0zpPjIxj6gY0VS4K2GTIFq/0Z6pqBjGXd175Gxm1KO6UAtM
         Lfo2nDlXDlPLl8lPMnd6jzZCujoJS7TAWrCEMOJrC81JIe7mmIklpmuiJxrohWNKGQhe
         05wsrJlJ+LqgtL/DjY1BOXsE1p2CfbJHiuSL8zEfv1/cMeCRR9VhKU3bpSRs8nE6NIJY
         lUQ83fNjhQwKKiaaXie/O1Ymb7Z9hoPTrGGhb2OdNbV6cLJBPD0D+pjMO2qXT2Wr3Srk
         B0pb8RsVxDBinRTKW0tT6AT2x6wcXiyXsdPazE+wXBEHKrRJ4f3nJVVTRudql8aJCxKH
         uVrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/0B3pwF+KurXg2sQbJ/VFAqpQPiy1YCuShZW6r4117Gsu5n7l
	OrN+CYcgAZkX9PMsij+Z10s=
X-Google-Smtp-Source: ABdhPJxE0FHjdvE8iSQhDV2HpcCsmgA1esWvtWOirWCN6ONLs4HsmnhNdRbnhV4/FidZcT7/FJTfFg==
X-Received: by 2002:a4a:db77:: with SMTP id o23mr23978361ood.15.1638825021447;
        Mon, 06 Dec 2021 13:10:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:209f:: with SMTP id s31ls6644593oiw.8.gmail; Mon,
 06 Dec 2021 13:10:21 -0800 (PST)
X-Received: by 2002:a05:6808:199c:: with SMTP id bj28mr1200881oib.98.1638825021138;
        Mon, 06 Dec 2021 13:10:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825021; cv=none;
        d=google.com; s=arc-20160816;
        b=q38JXRcR6rGnI3XpjGqNxNWzWpPWhYK+TBhHT8y1CFDxV2Y82cLC4mjIFgSdOMjXuW
         YRReylG5PEsaU67R6uP+lUeGZf5ytOpqPLl6ne44elqLaIJDmTsSIxOD5KAkKGdBat4l
         u+nqd1wqWUtvHRDy81yPfXJc0Ix8Ol8GtYdbbBGu1SiEMqZsplAt941UgPQQ7+ATxVs1
         8xxzonkI0MexZdwf6DoUPHlJ3H9CvMSL1kVuIFf2FuhQ8NEm+u3Iqz0pCn+74p2OKtpm
         8n9gAzuxa12lrCi7BNcPvdWWk9/m/vgzeGvk0LRlcJyKBHw6ezGwNJCFwDKsVDSI7UzN
         93bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GUxfKoDv8z2/c9DMn4X/UBtkOA/EQ1ICoguN1dwTi3o=;
        b=vtueYwlrk3sKjOnBe5gKA1oYWZLCV4DTuuRasbf4yMnGkAoYtmXP0bxbzvyXg+2r5k
         Nv+adODCaWukxZVPfiyyYYL6Dd8h//q+gX6FkX9hcByXFhoqZhy0dnMOqBlU5Bv1J4vG
         xu9Jw7DWmPvV4OFbqOqPEws05/U9fvwnNk4IuiVCGsHfm9b7A/LzW9C1T+nD61Ugfr5c
         ojueRd0boCh21eH5q09e7xTiWpZ1pNVYx3hDveOas8ZPM4qA74D1JbvXwNfgGVrRW4Sd
         XHkjIqbxDhFpdIlBQymf2g59cnm5guayDAZmbg2rjeXNoCOViecKPAOmj0X0xDv3WeGl
         UCVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=h7sLOi98;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id y7si325759oon.2.2021.12.06.13.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:10:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id t8so11622100ilu.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:10:21 -0800 (PST)
X-Received: by 2002:a05:6e02:1d1b:: with SMTP id i27mr37211121ila.248.1638825020893;
 Mon, 06 Dec 2021 13:10:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <f90dfb0c02598aab3ad1b5b6ea4a4104b14e099d.1638308023.git.andreyknvl@google.com>
 <YaoPpPAKi0/OZB2f@elver.google.com>
In-Reply-To: <YaoPpPAKi0/OZB2f@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:10:10 +0100
Message-ID: <CA+fCnZf08U_nZzR2snKs_SBXjB8WhSDARNpP3d+wMwgFvDgoHg@mail.gmail.com>
Subject: Re: [PATCH 23/31] kasan, arm64: allow KASAN_VMALLOC with SW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=h7sLOi98;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 3, 2021 at 1:38 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > vmalloc support for SW_TAGS KASAN is now complete.
> >
> > Allow enabling CONFIG_KASAN_VMALLOC.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> This change is small enough that I would have expected the
> lib/Kconfig.kasan change to appear in "kasan, vmalloc: add vmalloc
> support to SW_TAGS" because that sounds like it would fully unlock
> core KASAN support.
>
> However, the arm64 change could be in its own patch, since there may be
> conflicts with arm64 tree or during backports, and only dropping that
> may be ok.
>
> I've been backporting too many patches lately, that I feel that would
> help.

Sounds good, will do in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf08U_nZzR2snKs_SBXjB8WhSDARNpP3d%2BwMwgFvDgoHg%40mail.gmail.com.
