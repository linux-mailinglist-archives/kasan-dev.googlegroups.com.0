Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSHQ6SPQMGQEACMVVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EAFA76A4F8E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 00:10:01 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id k23-20020a5e8917000000b0074cbfb58b5bsf5102292ioj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 15:10:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677539400; cv=pass;
        d=google.com; s=arc-20160816;
        b=bfGzoRYBUQnSVBaODO1+tW1+trtQIb+RjXodx+ikGX8YbuXeX2maUd4u0yLIck+dvB
         bEvQtbx+7je8mLN1C/b3suR5PquXw5udZX0JrSRVGZMgL5awveL1AuSCYKyspfGWmJpf
         bfMA3uli62r9p+llNf+lDVb2+cZufVRvFOpJGz1JR7tcuG/C0VUwffwbwxpCNApms7dO
         jMnqlGCz+ds+keUTWvD0NiqDfu1RPCAFLUdhzYfrMBJY36zOgLRGmplCbp0ZMKShJDEW
         RSAxLSSma/zWSicvA72uQFTuqEspzt9UDFBo8u15B2c9HfDf8pHwF6Xg870oqqd/TbCn
         5SyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IfpMhBP+vMs56rPHZw8LF58+eJWYBl/QknP15ltUiBc=;
        b=sHvp3N7Rci/eqXTbphODzrfJYQus8hXIv8lutVPhvTikzfT6iS6ePjnldj0L5IdPVW
         PiNwq9QNXYdjtqKyvPdVN026sJBYFp0I9p6+Rh/cv/0buPef/Klz6ZaPlOD7yyuEAlAW
         9SaJHO3Q/iDYfFzvXbvXHik5TCndwcACQb7FyyjHl2vbmo57izttmiMv8DMpZ3E/R35d
         ULpXfjo82gq9lQTfvuKGN0WCEUQ7RyS8vase0LxVhRxiWHba+SNZocYry2teMy9ALMgF
         vOSiGjP6A3INsK7crps1/QQtm+iP40JY2YY/o9V5fkdXJ7E8nZTGxMyEks/r2v+ealM/
         Cs+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dE9jVGLG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IfpMhBP+vMs56rPHZw8LF58+eJWYBl/QknP15ltUiBc=;
        b=ByVIpokXH2GI09GwbrNtJHrHRiE/NAoT96xcny/8PqJYdnXRpcH/b54JoacFZhaXQq
         l41if6VC7+oQrXM3pjY0n6W9Cn0FVPfz2OPENG8NuAxc2K2/s5h66zWWfA4pXX7YCy76
         I5wrsUfzGbLR70X77rvBac7r+dXcfTOneVh7qpo/sltl+JKEJaqeHjP711AmJjh8qsJg
         Du7BFJJabG10wbe9TSZnZWzCnR/xirIaQcPs0MaHIRkzARTOW7iJVe/xvQPkMVEnEsLg
         xwLJfHhDt2GcjGKY1YK//laaxf6/PgdYkd3T6NSGMSIbbGNLS8O1Ligb54mcW1Bg4HYb
         B0bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=IfpMhBP+vMs56rPHZw8LF58+eJWYBl/QknP15ltUiBc=;
        b=0mqO9dxgk4zla7uOZlrWAF/7ESr6RQi62oQe++TYK0g/GJ5KB39Jar87fhjcuhd+rN
         6dyFdQG47rIcGKDJF2xNl1//lIim6tEvyjye31XY+bn3Mzs4+DACQjkLankEq1YiJUy6
         H3w1pHOn7E/jRbKLS1eHXRRduhlIS5JYSQ3EookzfO0m3vj/8bymc+w1dYYm0qy3T+rz
         VMay5mgXdRFvzXgaMQkULdfStF3J3Ll7hFIL5USkC2CvuDrsQXD30i3LmGi5Wjvc7BDs
         Nwe6xTBC6N/tG/zTE/IqY9prUorxnkzQ5dgiAmIhDfyDwybJ7eWME8KuGO+Hglf3CLVe
         mCEA==
X-Gm-Message-State: AO0yUKWQyHvBavblLAKZGY1nyznlxKycqKtvn/BIUtfaMB6jNh8BjEA/
	y5viiWQ2ROmyK1x+1tdLl2g=
X-Google-Smtp-Source: AK7set+oQ08CC+5AgrRgRADznz7w7TjXqoJGKUhBomSyUSjZwtlYrHUSqQmWPqGQsJpozc04BFjcJw==
X-Received: by 2002:a92:a811:0:b0:315:8d25:1eaf with SMTP id o17-20020a92a811000000b003158d251eafmr550504ilh.4.1677539400252;
        Mon, 27 Feb 2023 15:10:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:e302:0:b0:745:8dd7:55e3 with SMTP id u2-20020a6be302000000b007458dd755e3ls2707453ioc.5.-pod-prod-gmail;
 Mon, 27 Feb 2023 15:09:59 -0800 (PST)
X-Received: by 2002:a05:6602:4011:b0:74c:9907:e5b4 with SMTP id bk17-20020a056602401100b0074c9907e5b4mr7291491iob.6.1677539399667;
        Mon, 27 Feb 2023 15:09:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677539399; cv=none;
        d=google.com; s=arc-20160816;
        b=UnOXNd4/irIcNVbLigTIMu2igT6mFSa4dD1qF2udNkoCfCUEYRm81V+IpilMbAFTZa
         T2RutSRtFJpjUHEar5scmej9ticjTg0OqHEF2IKX+kqLyfzcN/C+K1pHzSZHKSX7SlGg
         zoJKI3BQF7lTh6k+5VcYZ1E+yPdU0oLSJkch4DPWqJ+/8pvq5WjHT6KI98mQ/FoW8Mdv
         BQMhiHJ/a9v34/n0mv/bBMGwKLhW/HokBTDQd7I45BowTvREm3JqKZNKgSRGKfsqk3DO
         PE8MEIsb3r/QVbyyTnkJns2Y1q/BYUbbEdRPDDpKfblMU+XqbO1alMX/vQtSQnFN18EB
         HYbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QFjaeE4eSo23upfyzVu9yFw6RjIFdreut8TNcWwSiF4=;
        b=npvlp4UQFq+EA3upeLs5rW9s3lSJB/Io8FQ5zQmkyTcZrhV8ghJ+XMEGZ6Zswm8EJz
         speQeOYVnOuV9z0yUjjuK8ZA5QQVg4+dqPkaa6gDybd40IMrQCJgy/2YbuB1ALyfTUr9
         h5UCkam9yRtEI/93ARH4ekab5xZB3D7Q3IhkYnqCqCE2jSuHa4F/VXkI/zW4wB3+tUDf
         eyyBwQ289X+7OdpVEnQsjxFFtr3GBePr6v2VRngpfM+hpVERPoz46i4cuZ8zHFC61oGv
         MYCn3TulQTIRdKaLG8Z1MxmBYZfdhwS+5GXfhNh25h5ZScucOfodcBPaWtiIpT9kNBIk
         xuZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dE9jVGLG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id q1-20020a056638344100b003636f49184dsi796249jav.7.2023.02.27.15.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 15:09:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-536c02c9dfbso220766917b3.11
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 15:09:59 -0800 (PST)
X-Received: by 2002:a25:e210:0:b0:a99:de9d:d504 with SMTP id
 h16-20020a25e210000000b00a99de9dd504mr213188ybe.12.1677539399179; Mon, 27 Feb
 2023 15:09:59 -0800 (PST)
MIME-Version: 1.0
References: <20230227094726.3833247-1-elver@google.com> <20230227141646.084c9a49fcae018852ca60f5@linux-foundation.org>
In-Reply-To: <20230227141646.084c9a49fcae018852ca60f5@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Feb 2023 00:09:13 +0100
Message-ID: <CANpmjNNtxW41H8ju6iog=ynMdEE0awa7GYabsuL6ZRihmVYQHw@mail.gmail.com>
Subject: Re: [PATCH mm] kasan, powerpc: Don't rename memintrinsics if compiler
 adds prefixes
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman <mpe@ellerman.id.au>, 
	Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Liam Howlett <liam.howlett@oracle.com>, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, Daniel Axtens <dja@axtens.net>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dE9jVGLG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Mon, 27 Feb 2023 at 23:16, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Mon, 27 Feb 2023 10:47:27 +0100 Marco Elver <elver@google.com> wrote:
>
> > With appropriate compiler support [1], KASAN builds use __asan prefixed
> > meminstrinsics, and KASAN no longer overrides memcpy/memset/memmove.
> >
> > If compiler support is detected (CC_HAS_KASAN_MEMINTRINSIC_PREFIX),
> > define memintrinsics normally (do not prefix '__').
> >
> > On powerpc, KASAN is the only user of __mem functions, which are used to
> > define instrumented memintrinsics. Alias the normal versions for KASAN
> > to use in its implementation.
> >
> > Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/ [1]
> > Link: https://lore.kernel.org/oe-kbuild-all/202302271348.U5lvmo0S-lkp@intel.com/
> > Reported-by: kernel test robot <lkp@intel.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Seems this is a fix against "kasan: treat meminstrinsic as builtins in
> uninstrumented files", so I'll plan to fold this patch into that patch.

Yes, that looks right.

If a powerpc maintainer could take a quick look as well would be good.
The maze of memcpy/memmove/memset definitions and redefinitions isn't
the simplest - I hope in a few years we can delete all the old code
(before CC_HAS_KASAN_MEMINTRINSIC_PREFIX), and let the compilers just
"do the right thing".

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtxW41H8ju6iog%3DynMdEE0awa7GYabsuL6ZRihmVYQHw%40mail.gmail.com.
