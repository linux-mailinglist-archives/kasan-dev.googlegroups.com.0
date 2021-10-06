Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUU766FAMGQEREXE5LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 213B24242B8
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 18:33:23 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id a16-20020a0ccdd0000000b003830ff134ccsf3146783qvn.6
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 09:33:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633538002; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sq26eyNpzf7gHi8GASJluGSGkAvVpWecAnqZ0Q74DMo/wETscXogWwep2ECbZ2Bvsq
         pQeFXe/6DVv+P9bbTDtJ5Pu+HCo15vApRlqq98RKBX3ifgLkj6VW3RiuWnSFaAL39/0n
         vUbeZCiPlVIKKRyO4P8WQC72Qob7fIIbrFicIQ8hNCIUhvoTrWgrAvJ2zbXFkOKGB3bD
         coEQIR4NzTGuTnGWhY6wnuAqYcqmACJZ10kEBQJjWF4kMZHS41lZOZh4ZcwC/5sVJwa1
         RiaMJc1FvwIhbfVzvH8hHHhkIDeDOzTHDZamsMybZvmax9ilDwtlOSvuix5SO8aiLVlF
         Y2Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4m/aDLadNfkwbDRxsI4sBaQD/azbkdtB+ryjHOio0eo=;
        b=rP8gK4Ax1N91URbq9MNpUlzhCRb6fMWOzbOlbOVg137t8tz6hY7IHa3xhXn8axfaqd
         bniIXztxETzqqnpd6jHhUVYzYWSRAWmnuL99V6zPP4E8IGCYOXob2jmaBYj1mOWA8phV
         6Q/CtPw7tJ4Dy6SlYKTD93h2buKkjgeTjh5rDwBE18UUngTDoX3HAZNibCLiWW1+Xeqb
         9Ar4H7ALsXL9uM5ZIeyhc/nxhGrMBGm0B8v/WPr0QKIgt2qMTwEfCRPVLdBSNB9aiIsd
         pbNCTZdhoFz/TkqVDauXOpy4CS8eoUufXsBJWayhCIsvc85qSkCGh+qakMe8XvzrN0YO
         STig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DpEgsgBS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4m/aDLadNfkwbDRxsI4sBaQD/azbkdtB+ryjHOio0eo=;
        b=l3dFvPo21PG9GVDK40bpmEmNUZYvuzdRm10DjUyCiDaLZCgyesz1c0fP4IU7wQQLZr
         g6XMibE03uzVa6jSbY/Pwd51RCjUMy7e/3YsrxUaOPSWJ1P2NYryeV4zcR77+5hRju+T
         rYxDuJWY9DdPb6LC1R/LcWDvHUv9ycdI/RJTY/Il78aN2QCLfqkKVyYUzLjozISovpG4
         SvDsnDPJx2K67SEwC8uF5NO6siL7lXx5+NrldGVMGbesWEfEMQbnOIrT9nvdL9a3rsHF
         RuoVaXJIi1QkdgnKGabx5zfHa4iltG8TarPnzJelFRLz8KXU0FWaSstAVUSOFlNrJlBV
         eQlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4m/aDLadNfkwbDRxsI4sBaQD/azbkdtB+ryjHOio0eo=;
        b=Yo6YEyqlSK7rYOGJCHtpbN+BFV517Qj1TmP3mLzXMXrQ5d/whKf7H1DVXSgf3dsA0l
         9Lo+Bj5kYq5Vh/D/oaQPxAwiqI2r3Cm+bgMX0aUcw7iAtSqXM8E4D2Yfep4c2KZorM4r
         d3EyTvlqVtTPhTwmKltHN0J9ZrGuEYpaqfPx1TpFDG4QmhoxBR+rwffNoCNL2GyhM6SQ
         Wt2FhZHUgJA6zyF4bFQdRqi5cSTCjfMF9EZJSidB4v03dG7W4otzoUtI/Zk/RszPj1mp
         RgsHZgV/z0VJs5QB1K9PVj0rrBLXfZ03/B0bQxYfXPHPt0xnpUOiE5YCJDWZPuhwucXH
         6GzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+nBv7r2cfr6/2NusLhbTiZ4RmS8ctSAMjfn71TI+WJghg+5rd
	ZguKi2OPAEsHBuukrDHGdKE=
X-Google-Smtp-Source: ABdhPJy7mKfOAJhl5KUldktl5mzfOdvB3VyC37CTDW57sZWqgXso3TRit8JePFC3eoDCSBegp/3pnQ==
X-Received: by 2002:ad4:5445:: with SMTP id h5mr18634809qvt.64.1633538002218;
        Wed, 06 Oct 2021 09:33:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:444c:: with SMTP id r73ls297369qka.10.gmail; Wed, 06 Oct
 2021 09:33:21 -0700 (PDT)
X-Received: by 2002:a37:b087:: with SMTP id z129mr20483904qke.392.1633538000047;
        Wed, 06 Oct 2021 09:33:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633537999; cv=none;
        d=google.com; s=arc-20160816;
        b=pYFlVU2KemigDDZK14j3+DXW0Bb1BBNw+AKJYNugt0vhrL6N3qHX5eP8HtDb6d6Oi2
         xyVx5lWrA0kNIvxZLcwwcIQKbKcFy1R1xaZQel9Rv41gbaIHOo09pFl/UHPMfYFXBin/
         Y4VohBgMt/LWsR4nV/Sv0ivwgQyLcF3Vqh8QfzVJUQbHK5be0DQbQZdTek6X3cDG4SKT
         MKJGgkan2Pxu83VLUFwPiHinvh+5/4se6oKojQVxWKA7f4FgPUWdk07EDhZeMDDy2lnR
         zMzVmVtedWqo6OiUlJCJsYBY2wOfI2poT33wTs2u60H+Bqleo8Xf/7k4FyezY4uEIJvu
         B9Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7bOzvzte6+zR7QYRdFhrICgWaXgsnkrZk1AsUn5dUkM=;
        b=yWzQUgZz+/iRJ11hK02eDOskbwfMgn2FP5Cu5fYm2Vze33xmbdAm6YgEWWRhHiPCs0
         Jc7EV4q1sY0L35RCWUnLNYw2O82itiC/JAz1FX3JMnw0B0osT0wviLfp5gkHu53mcJkT
         P8YBBJCXaNcPBceDJE8WDnYP8WgYTTPdjBrsmx47upToGj3EffjhO2ikcF3I13R//1T6
         48/g1ujZh+vTeJBiqG7ik/eV5w+rYYtAuEuDC4/97i61lEDOZZzZAtKe63JvvMhaaz9g
         64OkHU5Lol5RRLDevCIDJYb3Mm3VtiLi6k9FrT0f+aSTLFgU2l9+/W1T9Dm7iChIRfJ2
         dVBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DpEgsgBS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id d28si1382592qtg.3.2021.10.06.09.33.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 09:33:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id nn3-20020a17090b38c300b001a03bb6c4ebso307766pjb.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 09:33:19 -0700 (PDT)
X-Received: by 2002:a17:902:8686:b0:13e:dade:e88c with SMTP id g6-20020a170902868600b0013edadee88cmr12057386plo.70.1633537999329;
        Wed, 06 Oct 2021 09:33:19 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id gn11sm5459105pjb.36.2021.10.06.09.33.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Oct 2021 09:33:19 -0700 (PDT)
Date: Wed, 6 Oct 2021 09:33:18 -0700
From: Kees Cook <keescook@chromium.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kasan: test: Bypass __alloc_size checks
Message-ID: <202110060932.0808BD6500@keescook>
References: <20211006035522.539346-1-keescook@chromium.org>
 <20211006113732.GA14159@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211006113732.GA14159@C02TD0UTHF1T.local>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=DpEgsgBS;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Oct 06, 2021 at 12:38:36PM +0100, Mark Rutland wrote:
> Hi Kees,
> 
> On Tue, Oct 05, 2021 at 08:55:22PM -0700, Kees Cook wrote:
> > Intentional overflows, as performed by the KASAN tests, are detected
> > at compile time[1] (instead of only at run-time) with the addition of
> > __alloc_size. Fix this by forcing the compiler into not being able to
> > trust the size used following the kmalloc()s.
> 
> It might be better to use OPTIMIZER_HIDE_VAR(), since that's intended to
> make the value opaque to the compiler, and volatile might not always do
> that depending on how the compiler tracks the variable.

Given both you and Jann[1] have suggested this, I'll send a v2 with that.
:) Thanks!

-Kees

[1] https://lore.kernel.org/lkml/CAG48ez19raco+s+UF8eiXqTvaDEoMAo6_qmW2KdO24QDpmZpFQ@mail.gmail.com/

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202110060932.0808BD6500%40keescook.
