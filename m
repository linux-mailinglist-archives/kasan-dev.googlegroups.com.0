Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FF4GBAMGQEY3DW4IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 02367343B8C
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 09:19:10 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id x7sf26605520plg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 01:19:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616401148; cv=pass;
        d=google.com; s=arc-20160816;
        b=umDYoMJ/uvH3SX2TDafhmjGk9wEwMoTVJ8oyidQ7E82UNNMwC/xBMWA31HNgm+oIJy
         OhMQEVaxx18aolS2XVAEhUPhNkKfJpr5Vah+IPeDgrcJg+mSysxYGpdV6KxqeS93oe/f
         OrZyqSmnrbkbB9sGGUPKDIzoOP5lo6sy/mvMgmTSQMkk7lzGS3bOCa+miADdRhvLTF7o
         0F18ddxd1BAk9rYTcl0d+M/pRSi2JLMVgJ46fpfgGmZEkI4nKzaz8Ybvd+wJwKHVuvxc
         BfJ/zOTlrNPCG9vBXWvRXUcN1hAlR1WoJ7coBWAsyUbntf4ALGxTy0DDyiTJMg3dB1Se
         UYmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=K2XJvAzkq9Ku8WjoDn3CDtsbi48eS8gBi2ksQk7j/iw=;
        b=fw4NKSdS5vfFCMebJ/C/ts3n21qR3fA5/rxo2K5QXjrlVo+kDTDKcHWZuIEJ+1xajm
         cCvQS4VqbPT/oFFnSBWGnjidpK/FzlXn/YCN7B0p2/3waQ4b4iOH+p7ZaEcTEKs+Ic+C
         8qOkJQVmOrtuaBsZyMznVtXbTVWLF4bhQwNkPBx6ZtjACFJyXPF9ccrS6f2U1bDkpr8K
         ifontVbsE76BA8PR3m0mEkPUIVOcXrvtUTW4dOwo42gWNwQPqoM3tv02QGTAVzqUxN0E
         P3uH9nC55bcqT71dtZBSYZDrDkimIcQ2qJT5/QGB2p7X8nN0Xri9qBx896C7j3m4imFY
         +GGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vbc/hSaV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K2XJvAzkq9Ku8WjoDn3CDtsbi48eS8gBi2ksQk7j/iw=;
        b=jrTpo8bCpAQX5I4hcb83ZM+lL4scM9i9EPhnc/OY7XZV96jZpxqf/v0QrSO04GJ6nx
         me+QaH78xnSpCjqomzSdm0RuJymPK2lpYtAhGvQxHd1tRJv3+cfKDivreqoG/j8s6SLy
         cJejFwkpyhFmY74SRvsqG5PtWUCF5189a910yNrmk1uKhnPIJjkCh6qTAsiC6/MljpE6
         x1+ThYpNN11PBMGl7U7Pu7FDmX57ofWVyZnThQLM1Hyx24KE6hVMgP+XbBbuhJWc4oxH
         8pP7evl1qEpobRIZx5UV4v4HeL0sQ1un8bhZIo32Q3XvKOuyIHxf1rLqNyVNWMhWzhrj
         48Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K2XJvAzkq9Ku8WjoDn3CDtsbi48eS8gBi2ksQk7j/iw=;
        b=Gvj+urKOOLPn4nwTVE6uYeT1XPf35KnaIghanxVvqtwxdPN5ou3WOem+3OgFSmk/SR
         AYMmOKfCH/98LvgQAuTFF36SxgkP2YOo9Hhs8+J69Cg1RT4QGWvhKooCWqNVk+opWadu
         GGSVSdolMZQIl6io4/qjLmTNY/d/QE7u83Rq0hwZvTvNqH2zurCKmuhn4dppay3JRXzd
         sLAJVpsJwswKiN2DCv3UkQ98OG0MHar5QlKLcNkG5v3Fz/xcnRXDH73l6jUTdMpii34K
         QsHNxrxT6q9wc+9qnjuV4MjnRQUx4r1GfFavp901XEBQohkeef4GG6wheuPzEPKw2Hhx
         yLJw==
X-Gm-Message-State: AOAM531AIllC7ITPDRtgT+eRiEemGnyBHInbrwMIbOjs+N2OjIPVy7vm
	UZCbOwYVmBAowHIyResPs6c=
X-Google-Smtp-Source: ABdhPJyuL7Ey3U/ROpZD2hCoyWDFWQdCmIJRFsszqvuNKWk9Ohl7pt/sZHAx18g26Tf/Z9812s2/ww==
X-Received: by 2002:a17:902:bd0b:b029:e5:f913:8c95 with SMTP id p11-20020a170902bd0bb02900e5f9138c95mr25778145pls.84.1616401148602;
        Mon, 22 Mar 2021 01:19:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f10:: with SMTP id a16ls5147958pfd.7.gmail; Mon, 22 Mar
 2021 01:19:08 -0700 (PDT)
X-Received: by 2002:a63:ea51:: with SMTP id l17mr21945251pgk.117.1616401147898;
        Mon, 22 Mar 2021 01:19:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616401147; cv=none;
        d=google.com; s=arc-20160816;
        b=cWOfTJmzyL7mpOJClSAdUQkd/51APs1LPMQ+b8AKVxBUwmR7tfXw9F9kwc9maJiV68
         vn6L0wgfD7piKifyZ/DXGXVwy2D4H8H+S1ZyUiC16xANkBAA0qJVWJaWXpbjLcxEpd/X
         l1UaOY5r+rUcAwt6wSwBnz6Oh566uA7ndPnT80OKIFNVXD+3tziqJ/TQLWDV73uAbI/N
         avQ+5cQcTJnRqI99/uGvKVD147jXevZfpq4C8NwlID7m5fh50EUb/25uQr4r2XwlFEuA
         fr8WZ1sXwjobqWZbrMrLMZ847CSU4mtg1evHrpWFYwe4xqD/YYoaTpuY73E76mZebGaA
         tR2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JBfYmKFZfBEnELsahissKGVzgwoqNgBhQO83P0Ky7Zc=;
        b=oRtMiVbtjTHIPDt6URqjQKOQ0GtS6X6aV+tWWo5tWPrc6eAWCvojsQWpHftfGXNhPl
         JDH8CUFYN0jR/D4l8FYtiQPMCiKihF88UuK7Nm7Un3DwqzXpEO1+n5bKWRz2xx0xjpLa
         ThyIdYqhWZE0SnqhOagZq13a1JGXRNdqljRPAqoOmae3bd4um/jGmmzpMHLYcgiLYoUw
         yyVqC0W+OUgOzqvZA4e8AVkbncRLC344TAJZ5mEwgau5b64xClhI0baZ8qBfnj9cj4d4
         Mx9d92v9j4Ej+AMTqLBRV6rDhJV9DTFnnmpiXfLpSDExS3cf5suMhG4t5Plui+0xs/L3
         WGrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vbc/hSaV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id s9si523858plg.2.2021.03.22.01.19.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 01:19:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id w1-20020a4adec10000b02901bc77feac3eso3893391oou.3
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 01:19:07 -0700 (PDT)
X-Received: by 2002:a4a:d0ce:: with SMTP id u14mr10172401oor.36.1616401147100;
 Mon, 22 Mar 2021 01:19:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210319144058.772525-1-dja@axtens.net> <20210319144058.772525-2-dja@axtens.net>
In-Reply-To: <20210319144058.772525-2-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Mar 2021 09:18:55 +0100
Message-ID: <CANpmjNOygpN7Aifd_+ycvxA+zNvyb9rF7mTA_yCfjbRK9evLGA@mail.gmail.com>
Subject: Re: [PATCH v11 1/6] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="vbc/hSaV";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as
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

On Fri, 19 Mar 2021 at 15:41, Daniel Axtens <dja@axtens.net> wrote:
>
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.
>
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/Kconfig.kasan | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..7e237dbb6df3 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
> +config ARCH_DISABLE_KASAN_INLINE
> +       def_bool n
> +

Does just "bool" work here?

>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=kernel-address)
>
> @@ -130,6 +133,7 @@ config KASAN_OUTLINE
>
>  config KASAN_INLINE
>         bool "Inline instrumentation"
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         help
>           Compiler directly inserts code checking shadow memory before
>           memory accesses. This is faster than outline (in some workloads
> @@ -142,6 +146,7 @@ config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
>         default y if CC_IS_GCC
> +       depends on !ARCH_DISABLE_KASAN_INLINE

Minor, but perhaps this 'depends on' line could be moved up 1 line to
be grouped with the other 'depends on'.


>         help
>           The LLVM stack address sanitizer has a know problem that
>           causes excessive stack usage in a lot of functions, see
> @@ -154,6 +159,9 @@ config KASAN_STACK
>           but clang users can still enable it for builds without
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
> +         If the architecture disables inline instrumentation, this is
> +         also disabled as it adds inline-style instrumentation that
> +         is run unconditionally.
>
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> --
> 2.27.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-2-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOygpN7Aifd_%2BycvxA%2BzNvyb9rF7mTA_yCfjbRK9evLGA%40mail.gmail.com.
