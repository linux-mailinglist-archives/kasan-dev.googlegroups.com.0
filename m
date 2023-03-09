Return-Path: <kasan-dev+bncBD52JJ7JXILRBT5CVGQAMGQETI3ZBPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A1416B2FAD
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 22:36:17 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id ls3-20020a17090b350300b0023a55f445ebsf1673814pjb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 13:36:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678397775; cv=pass;
        d=google.com; s=arc-20160816;
        b=XRG0n+89efj260gnO10CpvHjjhJoqCXMqd3gMN82xRkwHjUY7KCwDY5B7vBtoVNHSq
         300db4js78GX/3Pz+nw8FbBwfhoSLSrL27pWMZ8RrC82ZsONo6HD3PQzfzgmgKn22yxw
         Mg0RtRuOA3e4nj7Lf5Bq4gTJ0LmLmvg31yIIfgGZwCTD37b0MM9fxx6Wy/AwB+6btIhS
         dXHXSmtvNeOhe7k6UE7AujlAilcBv07CL8MGlD+mtXq/eA2o6xabSetYLRVChyMl3Ai0
         f4encl9bcViChYZhP5TFKS9YVIxv3nPGjDmI/xeqDUxqchGcyBM6/WC708lzfdmiuBZU
         W3XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=coeH9bkGizLYve9HTO11Xa+qyVrJlwq0LQxWElQh2VI=;
        b=Ahf4X5herYuBnEFniZs6Szchlp+K/aoI10Isz+SyjUtJELx4a65FTW4CHgWZTyow1v
         oAPUEML/bQ6TLDVP5QEy/PW3iQC0mO/x/CFkF/SmfNRmyQgxYLJMQTwAWiLrpPqXOAGI
         C042idSFuJ7EnhC0qCbkOOjzFGYdGqeWqINZW6FQwI8SCHaIlDvaGXs7APLM8XR/PFuK
         TAhAlcNESew6nMJ6ZhrXJe+5bwOX2v6pQ8yOXOSzKKvqC9Y4RmNdoHl9mUIf1t8vsDyk
         ErBgD12NLGM6LHOXjTsGO7j8jwNxx7hKPyUVfx4G4ICNfx0Lf6oi1QfpGt/GmdwBB9jj
         z1Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VnZTCI1O;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678397775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=coeH9bkGizLYve9HTO11Xa+qyVrJlwq0LQxWElQh2VI=;
        b=TM7IU9WQcKp0Bu+Xyl6QBfbqSZmmTtSR7bbvUQ0XGQ6Kb0kGyWCe2s908Rf0yB2v2v
         3UvurhmDF+CI21uLnidAxXfg0aqP1kfTmEMxQ48pigKaNqumAVnFv92UZ3/zdOjdWs2t
         XNyu+bcWmUfVlqnPRrBGXj7V58g7ur8KaRjhlSys/YaEFzVoRbrERBfyBswSw+6uKgkT
         c2x8UsGEF+ACGmHFa2F1/9kH72IjFKLgodjHe+St5jABQ0/O/rQfLkZdBunppt/tCiJk
         BBtH8eCp1+bcLGsivBRi7PVPlVn6FHeSx/XRF/KdkAprXgZaSVLrcmTCsRYOS55hi9q6
         MaAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678397775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=coeH9bkGizLYve9HTO11Xa+qyVrJlwq0LQxWElQh2VI=;
        b=cbmo6791Yxlu8W3X/drRusvPDJl2ZxcJbG2FyQECHWFMMP0F3W3vxDQj8Pm3ukjIHS
         sZAUZdlnzeLvQHtbnZYiweVqHGbpMODOHTmPYw8dTPM/hebbDAnJ0eLnzK3jb6WUluVi
         5KbPKZsCWSw8iWm5EYbSQ5OYJNcH3KY1vS03dI7YebxLMND22D/EUpr/tbzgZYIF6R2H
         QLRDhD276sJFOPR/dMCbmf3wNEPWnlZIljfQBUJKXlhJ+T/nFRLi3psWb7FELgdB1G5A
         fptZdzRddFccJMTG3njSslITru/LFvlpAU0LSd6V1lZUwNduNSM8pK+3cQfcyOeleTV2
         jV4g==
X-Gm-Message-State: AO0yUKXJj44tDmYHV36raIBcMx0NMHAtHDj9nnqPzehUHefgRdEQOo37
	Gt613UvKbuMvynX5ed7OuoM=
X-Google-Smtp-Source: AK7set85k98mtt+ffNlckZdeW1n5x6rzZTvyfnybRyJU3JTOQuCObOtNYuGhCFPQe6yXtokTvmBgzQ==
X-Received: by 2002:a05:6a00:2253:b0:603:51de:c0dd with SMTP id i19-20020a056a00225300b0060351dec0ddmr9687378pfu.6.1678397775287;
        Thu, 09 Mar 2023 13:36:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:344d:b0:237:18be:2595 with SMTP id
 lj13-20020a17090b344d00b0023718be2595ls2782552pjb.3.-pod-control-gmail; Thu,
 09 Mar 2023 13:36:14 -0800 (PST)
X-Received: by 2002:a17:902:ee89:b0:19a:841f:56 with SMTP id a9-20020a170902ee8900b0019a841f0056mr20274291pld.20.1678397774481;
        Thu, 09 Mar 2023 13:36:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678397774; cv=none;
        d=google.com; s=arc-20160816;
        b=WrNeBE06k8Xks98/SjULaxiJ3OMX7CFFc0ay+cHc3XaMQiGQwLPfntXOsNYmm768JX
         lhmOZcAlA47tD1t0dXFU9lu4RjnKdMWtmMQr0x9Z6WZme8gUcpz780ZggFqIxaHWkUlY
         +LzPHnxrzQBUQ+O/44emKkbVDkwk/wX7sx5Ob/k3sqQ8Ovdv1bd9uceGQqfDM7r5b+vD
         khBBTmdeoxj3XjUDZsKPB1OzX+3M24GRNLPy1tuZS5E3DQ7l7KKH+OEJT6KDTza/Mpd9
         2HDoGQ9LyGsDDHj4m4AvCuZTxPtsdvhTuEcSUMJBX506glsiFCa+4SLjy8Y9AbwzyD3e
         5pTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PFnIpAyFi7KEE0nQFD6hvfwa5ttoKe86kwhnOw55/ZU=;
        b=IJ4W0Z1L4RFQhQQ8eSveutgcy577tJu31EglgmKXBoQwVSsFMLM1PDWd6H2wB9haic
         b0ILktCpmfOmUIrEUS4Mv9lPs3sNpik07b2zFjaTHCoQfTkZ2Xjf7ctJ+BIUgaYdoFVU
         ZhwEJUKxIhWA9jcTIUxmTNMq771rpIbwNHzf1ycM3doXybeAsijNV081ckIs3jnGJ8cu
         V9Xcrtv6ApomImdLOlzvjVwiZn/vhITOX9PjZjWMoWJrAjLMeQkhgut8KrjckK+N19tC
         ncJWDNPaT0iIcX+8CK+qgWNmp0gYfJ0mNhhklYM63QTp7KMKWr9YyFHDu5MoF/qFLPdc
         xpfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VnZTCI1O;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id m20-20020a170902bb9400b0019c35405665si16902pls.1.2023.03.09.13.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 13:36:14 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-53852143afcso60648307b3.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 13:36:14 -0800 (PST)
X-Received: by 2002:a81:af46:0:b0:53c:70c5:45d9 with SMTP id
 x6-20020a81af46000000b0053c70c545d9mr14455374ywj.2.1678397773576; Thu, 09 Mar
 2023 13:36:13 -0800 (PST)
MIME-Version: 1.0
References: <20230301003545.282859-1-pcc@google.com> <20230301003545.282859-2-pcc@google.com>
 <20230308174608.e66ed98c97ea29934d99c596@linux-foundation.org>
In-Reply-To: <20230308174608.e66ed98c97ea29934d99c596@linux-foundation.org>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 13:36:02 -0800
Message-ID: <CAMn1gO4jne3JyXgP9fufDYVoF4-xfL7H_38syJDaUBYCzmRETw@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
To: Andrew Morton <akpm@linux-foundation.org>
Cc: catalin.marinas@arm.com, andreyknvl@gmail.com, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com, 
	will@kernel.org, eugenis@google.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VnZTCI1O;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::1132 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, Mar 8, 2023 at 5:46=E2=80=AFPM Andrew Morton <akpm@linux-foundation=
.org> wrote:
>
> On Tue, 28 Feb 2023 16:35:44 -0800 Peter Collingbourne <pcc@google.com> w=
rote:
>
> > This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.
> >
> > The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
> > flag from page->flags. However, this line of code in free_pages_prepare=
():
> >
> > page->flags &=3D ~PAGE_FLAGS_CHECK_AT_PREP;
> >
> > clears most of page->flags, including PG_skip_kasan_poison, before call=
ing
> > should_skip_kasan_poison(), which meant that it would never return true
> > as a result of the page flag being set. Therefore, fix the code to call
> > should_skip_kasan_poison() before clearing the flags, as we were doing
> > before the reverted patch.
>
> What are the user visible effects of this change?
>
> > Cc: <stable@vger.kernel.org> # 6.1
>
> Especially if it's cc:stable.

This fixes a measurable performance regression introduced in the
reverted commit, where munmap() takes longer than intended if HW tags
KASAN is supported and enabled at runtime. Without this patch, we see
a single-digit percentage performance regression in a particular
mmap()-heavy benchmark when enabling HW tags KASAN, and with the
patch, there is no statistically significant performance impact when
enabling HW tags KASAN.

That can be added as a paragraph to the end of my commit message, or I
can send a v4 if you prefer.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4jne3JyXgP9fufDYVoF4-xfL7H_38syJDaUBYCzmRETw%40mail.gmail.=
com.
