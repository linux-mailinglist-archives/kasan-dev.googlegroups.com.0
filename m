Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2NYWWUQMGQEPJM45MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F1717CAE40
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 17:53:14 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-419393cfde9sf51150721cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 08:53:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697471593; cv=pass;
        d=google.com; s=arc-20160816;
        b=oNL4pBLQrHBFxwDMGjbCMcW8s7Os+RMytaRh0BTVO3Wb9x/UsBuI2GvcJkfeY2ttEO
         tmul0sMZEu2uXf7MRrMYpsTk4PPilHWkHhlEeIAplj3ly5v8Sc4+dpeU8oqfrHiD0A6s
         8EMT4FSmXI+fh8sxvd+A7Lh1c/N/Yt3CcGw+M8e1hgeerppqBVO04I6+k4tWfzqLVBmX
         hKYf1e2j9XO4V93ThGa6fLUrhIOoH8huXsHRwdlvFs0gE4uRq3eTaSzYDHKcgn1679O3
         dZipqL7Ml0vz2u1VdlrWLO1rDo4pE+7b5c0fKfd+Xy1CZoFFNSy/E1Pcoj2dWAUgBLQE
         K/pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nhcyOK0Bg8ZFTU3lEQ4cORbDAPo+vgnqjktEswbWBHc=;
        fh=qHzrIxpYIOyJP7kenXxkLkDAYnrch2fZLsMg0SlFlLA=;
        b=olXpCeWWw2YCWIOz5u8rh/py/lA3SkP+yrl65XC5Rb7nQrB8X1V6bWShNES43hZmt9
         YRCqSR76Ze1rCdWwgtUhz4p+iMhmCyL56HhJxu0UbZSCz/XGjVH7c0oswQrhG1O9XoTL
         non5Q6Dg6tfe7uXDHxFChaKogVzDRnD2oQgcmP8ZypMf4s/AiRyd0QEUA3N4p/ddVnE/
         eQ5qg6ExJvrMDQNuPoo0V1JIUdwbPC/K1hdvrKZMZH8kXuEhQhgyYEpLadfUuowk6y30
         SvuImI+hadTS8CQqWgZP1WvgcdVBnuTPugkNe3dlhMZ9tYatZd1JIlged2KpLYzKqGd/
         4FNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zfLobR2g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697471593; x=1698076393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nhcyOK0Bg8ZFTU3lEQ4cORbDAPo+vgnqjktEswbWBHc=;
        b=jCwSCxlOhaQWgIXmHfT2Kcw0OD6bOSINZ+ab8XIWgFYyQMPAfvosEi+1fS3K5NhsuO
         ub2Y8UL8lo4MtnKkKOlqOoN8ZS1d/2lxZ0oyMefAkrPaQfkPndAIltQ+JjYSXsRqK9vr
         pdKhgHtvzl89pwjQ/2ukdheBSNy8v0AENugpDM2GDaO6TKy/RO6tXdKWDmXQ2/IIwMz4
         FdzR5kntfOQpigLX+GuyCM8TnPqj/a+YawbnwlZ70cu8COqRfevMfrHJiWsVOV5Srp4b
         e6KU5cF9/VpZuuJ1ZZH5JQDlGselcMFdawnTwgSTPlOBf44nG6bHQoQEYQuuBnM/6EA1
         Kieg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697471593; x=1698076393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nhcyOK0Bg8ZFTU3lEQ4cORbDAPo+vgnqjktEswbWBHc=;
        b=YMbtKaPkYjsZPNBBSLgyCE7CnFJbszI9o1lqETSBTmsRCF2lgpu8b5WHUTMP0UuHSK
         /HaJjOXszmyHRihmMKLrWW21i9a6dN6GT0D6DQH8hxMmm4ou563fp21UzZ3qKRhTBSsu
         xuhHK3h2WH/eSQA5bkcyys6gHkbzz71Aa56bkvoAXg4f5f3kGJsqfF107vhbdCzkfF/0
         KYoMms45UwTOM8BksuNmtIOyeJ7QUD0aBXKr3FIAEdzGd4fqA2ZSywiqOsgjC43Zfe2B
         bHxrFTslQGi1zcO+Sa+suWCP+O4uVQEQfRSSp4ib/fT8oK8IM0Gdc/VLf55/vXOzOJ2a
         mPTA==
X-Gm-Message-State: AOJu0Ywi8Fec43MRR9QtRiikCBI6/ACiDGmRuVXQ4ZsXhuvp4nIFAATw
	MQVC4cLdTaYvZ6aAPrKQIfo=
X-Google-Smtp-Source: AGHT+IFnf3UWiqw3XUiJTogUG/fXbbiKL8L5gh59VLylsfo58e/5Sm8gHyV2z9LuSrgKFnaJVS23KQ==
X-Received: by 2002:ac8:7c4f:0:b0:419:529e:dcfd with SMTP id o15-20020ac87c4f000000b00419529edcfdmr46852048qtv.3.1697471593361;
        Mon, 16 Oct 2023 08:53:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2510:b0:41b:ca1:7e24 with SMTP id
 cm16-20020a05622a251000b0041b0ca17e24ls3014247qtb.0.-pod-prod-05-us; Mon, 16
 Oct 2023 08:53:12 -0700 (PDT)
X-Received: by 2002:a05:620a:d8a:b0:775:7f6e:1af7 with SMTP id q10-20020a05620a0d8a00b007757f6e1af7mr41183594qkl.24.1697471592699;
        Mon, 16 Oct 2023 08:53:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697471592; cv=none;
        d=google.com; s=arc-20160816;
        b=svyfB8O0bQm4VWeC+GpaUwkaM1BwLRjQCUar0otXR9SALeFa9Qw5fBEijayma1TonJ
         sLgIA5omShYapPIF0JUVSznLrHoU61Z0q2ztxroKV/k6NrOpryVHwQ1MuqomVVTmXiKJ
         TMleMJ7HWVrRd1xEmvvB7rZlY5GiDWld1WzxaKqI0XQMkxNDDNF6/7BoBsMpDuAFOEZD
         7NtBZ9E3anSzYDI18Yu1E1dq0AF75OtoZrQQ7Jp0gFFquh9Oncwazjiy5gUSPGm4jHLv
         l4y6y5bBMFyoJ3zBb4iuiRrxy8I9yaB0JwtNn0tvoz1drCgJooLNAoWmycLPxnSxqkMW
         jOww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LYpi+Y74+blfqQ7+iyjrYGXZgsEgnThgUXh2i1YfeDY=;
        fh=qHzrIxpYIOyJP7kenXxkLkDAYnrch2fZLsMg0SlFlLA=;
        b=NOaZyfWdUBC2wQnkGPspU+h+uoLZjMyp+PJk9NtmC9aJEqpT/vIvQnKBzFBScQNkF2
         JFUf3RtnN7KrDS17HSufKqGhNvl99wgv5aoG8C0oVRimCz0aN+mqAp0FwdK+PAh7Cbdy
         35R11RYQVz0Jax5ehswgBh8mGi18pdIIbnWU8lbpl8nxoWdLS5xERA4jm70cjSI6Q24I
         438Up1fump+TgjtwkdOtDv2JRZEOP9wCMxwxcsLUJgo50lTLFe3MsH7cNU2GDB7gHa99
         t+v2WUqosjwXT78amrhCydXj+fJy9RcpstmScP/dR4mu9Io2cBBKurQX9JsAZNIpfr9Y
         MhrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zfLobR2g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id a7-20020a05620a438700b0076709fdb678si504544qkp.4.2023.10.16.08.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Oct 2023 08:53:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-5a7ac4c3666so57504757b3.3
        for <kasan-dev@googlegroups.com>; Mon, 16 Oct 2023 08:53:12 -0700 (PDT)
X-Received: by 2002:a0d:d713:0:b0:5a8:72ee:463d with SMTP id
 z19-20020a0dd713000000b005a872ee463dmr3725033ywd.49.1697471591735; Mon, 16
 Oct 2023 08:53:11 -0700 (PDT)
MIME-Version: 1.0
References: <20231016153446.132763-1-pedro.falcato@gmail.com>
In-Reply-To: <20231016153446.132763-1-pedro.falcato@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Oct 2023 17:52:29 +0200
Message-ID: <CAG_fn=XA5B4CO2q-+fSeKbT3DwYs+fExMP+h_x5qqdEKfejcow@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kmsan: Panic on failure to allocate early boot metadata
To: Pedro Falcato <pedro.falcato@gmail.com>
Cc: kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zfLobR2g;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1132
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Oct 16, 2023 at 5:34=E2=80=AFPM Pedro Falcato <pedro.falcato@gmail.=
com> wrote:
>
> Given large enough allocations and a machine with low enough memory (i.e
> a default QEMU VM), it's entirely possible that
> kmsan_init_alloc_meta_for_range's shadow+origin allocation fails.
>
> Instead of eating a NULL deref kernel oops, check explicitly for
> memblock_alloc() failure and panic with a nice error message.

For posterity, it is generally quite important for the allocated
shadow and origin to be contiguous, otherwise an unaligned memory
write may result in memory corruption (the corresponding unaligned
shadow write will be assuming that shadow pages are adjacent).
So instead of panicking we could have split the range into smaller
ones until the allocation succeeds, but that would've led to
hard-to-debug problems in the future.

>
> Signed-off-by: Pedro Falcato <pedro.falcato@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXA5B4CO2q-%2BfSeKbT3DwYs%2BfExMP%2Bh_x5qqdEKfejcow%40mai=
l.gmail.com.
