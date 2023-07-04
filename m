Return-Path: <kasan-dev+bncBDW2JDUY5AORB67VSCSQMGQEPWJ72KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 846A3747551
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 17:30:24 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-563693e552bsf4494252eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 08:30:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688484603; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGNPxiMBJnQUiAEW3mukyITcMVuiQkMK09lPyfL53XYTc2LLRsCUQeWNCQ56lHggub
         2WdlToZCe0YkqcSfhuRZvJTsmOFZvRnrLlfjjRrQj3yLjFUjcy2UQGlxTxiyilzBClOZ
         oQqeW+E85OTPcwJ1KxNlbatRzblkLsYLqLennwTHGmKeI8f+X4f/WKx0xrIbG/qDu0tq
         wyk5hRFLNKYBEIEk4kQnXkgGtHCfWJFdFz8bWKUCOZFSPvlYeVFWMYTLGv059hEZ7vhp
         es6N30JOF7XcxZ51UZZ6RdFkxiXYgBZDIVXMJQipk1b+WMLpX9WABVhMBitChSlkR31n
         cESg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qixQ8GFywvYnjesVyMQ9O5xhKWFSkbWt8fRqLJkFmi0=;
        fh=LlEk4PLq/wGhUmhFSdAQbhVQBJn9P3bOeQZtC1MfL9k=;
        b=YGp+XoZhLZodRb40oPyxeJJaqVaVC1ZSX7xR7BhHMDk8k5o1ZYiTV/ZDsJn7857cuv
         mBP8rzpUVsPD8u2BIBjABk57NBrt2Y1wmJW+2KXpSu7xS7UAOEJKAnUQEfSyINgtM0m2
         rQjCjYcXWCv6HxLqpHMVbAIFPSOgvAOVTJKOmKxKXN/Tug2B+z6nggyTdEm31a2lPRIG
         nqvKxdjqFbRorlCuCe8ViGzGZAw7a+ELDLM0e3YQpl0LQUJCAtsxDgI0m0YehRrQKcSO
         7Pq1VatVXCJj1mdDPPbZ6hrnokn2HtrIaFEVtT02WmYSG5GjBvhFgIpHLubRpXcRmfsu
         K4Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=C75PQ68i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688484603; x=1691076603;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qixQ8GFywvYnjesVyMQ9O5xhKWFSkbWt8fRqLJkFmi0=;
        b=ZV9A5Me0wW2UKLJkb5kYOX77c8ofC6gH69dfppprv6rxMCMtEv4/pw8QHdoPzZqyb+
         FcMrcNo1c7HAbeUbQ3/OZP/lbaLv5jNLFPeftY9a2XptIk3DKIma2TqrS4lKN5H9RulZ
         /Oypa0Ho71PjpUPxKOAZqsuUND+ywgY90Ol0nejzptQfjiDFWsWuWmjSZm2tZc5+c0wR
         ROkwTMX3dMPeQTMEK6YFEr8rK942OCpTU7v8IK/EmHzE6qxs9ABxK2htQ5W2kH3h6zac
         8gbl4CL5I+B4RnTxAZSnXrou+K1LOrdMr+fbHJUVrE1EHTxhYXQwpjOQpRyTUXtUah05
         x4fA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1688484603; x=1691076603;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qixQ8GFywvYnjesVyMQ9O5xhKWFSkbWt8fRqLJkFmi0=;
        b=bOEuv21KHw6umZPaFn5bxvCByN32dmrBNNbNQmjzikRR6/wwJav6Kga13NKhgah3mR
         o7wwiumDUH8GJWm9sKzTsVD4AvifyUKKKEym5WvqABLyd9JUk1e/qJOAFT3Lqb6BNFYb
         fQxhBchM5YJeO2Y/Tq3Wvw62Kbq742JwGxcS8e/bvwkubPHa4LwTmiNmmUBDsvTGc1uI
         3tmT2F30YkcQta+D8Df7Cp/Lt5/Lq4TF7IPZFK7bklX6m4rOZnVLP2rq4wSjL3GCU23Q
         hZvJk8GksnNDZY7oSOIuPIDDXlUO+LI0qfk6sDRzc1YdUxvznvEO9fmWSzB0Eyc25JI3
         enUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688484603; x=1691076603;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qixQ8GFywvYnjesVyMQ9O5xhKWFSkbWt8fRqLJkFmi0=;
        b=XE+1u4Cux2CsVQX7QX0a/VNoBHclEd3mHXhNIa2O34/4uFAQe4AnZQMhUXiukrVkLf
         OgSPZNYbIr2x811/hpYGflnOIrsZd0YtjQe74dFbljYkL6mnMSEcS7yH7mbz4TWEiFng
         M1fS6JU1SRUcCgGzMpfqfJ030d3y0pxEJfWfJ7mfWSkVAC2RCNDOQp9UaVKA90K13kZw
         OQDMI9eN45orJO+Xmf3d+8aIYYc32oJyHBi0NxH9W70B6MnwxfWRcsNla0rJKY3/ygi8
         l7foMiZOD6iCMzj2PSysqZ+4w6hIxVNgmZk9W/wwZYsukjEzg0Gfru/qXtNyuDbMoqZZ
         m7wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxF2QeoL4eENi/amXhHWuBHZNMSb1edmUOUTHMvduty5yGd4Amx
	7X97NWkyt0cPEjEqwGOjDN4=
X-Google-Smtp-Source: ACHHUZ5Ws9b51SoCw/LkqVGE1mbHX/btjuV8Pug4OpwudnR0tGHx62fJ4IpObtbQSAeVDQnWJETukw==
X-Received: by 2002:a4a:454f:0:b0:565:c2ab:5e4 with SMTP id y76-20020a4a454f000000b00565c2ab05e4mr9492529ooa.6.1688484603364;
        Tue, 04 Jul 2023 08:30:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:449:b0:565:bb37:9f5e with SMTP id
 p9-20020a056820044900b00565bb379f5els5107122oou.2.-pod-prod-07-us; Tue, 04
 Jul 2023 08:30:02 -0700 (PDT)
X-Received: by 2002:a9d:6392:0:b0:6b8:82ed:ea2e with SMTP id w18-20020a9d6392000000b006b882edea2emr12685690otk.4.1688484602683;
        Tue, 04 Jul 2023 08:30:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688484602; cv=none;
        d=google.com; s=arc-20160816;
        b=bYz8x7MXyn4qTVSPaX7Ig5Swtt9bAs9dyjwk+zloO5Wa0KZVdzdHC4rrGLUjOs0FTr
         KHMbz8JlXepw1AT08yFrEsbccGcnY2nzOl4o25Lw/Q9MQZVMYyOlXvrHqbzOf6wL+TWJ
         fZVlbmW5mS/LieUZ5EdW6+7+7CumI/yzgjW8PYZd/mgmEo+WgpGgAwAPE/npRIrfTMMn
         P676CHM/WsMnBM/8+BMayIb35Z2IpmWXI3pjS40ysw12Z5aWR6M0GTCsyg4fhsXpeY5S
         l2Zcpmmr6xjQRPTSwoVCHAkXUS5IqAY1Lpa6Yne25d0B+m1vmd8ySEx8AHNU7yg21yKy
         WPHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EvpFDN0Hme202Di1VXoYnHnrjjm4RarltdzmSusEO5o=;
        fh=4nDDcglGxfu3UoyLPAf1OtSoTzMJgDbRXi5Cr1hgTyE=;
        b=ptsVp56MssU1ayclXr5Zqt7F+jy6hIEfv4CJ+mNiAWqD8PYKF4antwIQmh3EgF5auD
         FvBVWi2S4I37HEKB5QE9mYEeRl+VMZs4xo7kUzjOfKihhPVkDyQ/YNSAo91G3A1hjiln
         YwjOod20s2UAuMZ7nFHLCyAKQKjKAu7gv59RcFfnAM9yg1HEIa9qv1QbF85P7Z7GDcZS
         WvqEJ/CgxXVGd5Pkavkmn8qDBG90VKQ8gCeeWXdwVV5zG8Z1pr4urx7ft+ZRfAQB7kQk
         EdHS4HAzCFjBWi16ObPY2WxRpQzYYSAuRVYexci75jXcydiSYWX/uuk4xb/iFZ8udzjX
         J5LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=C75PQ68i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id w3-20020a9d5a83000000b006b8ca9be753si593999oth.1.2023.07.04.08.30.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Jul 2023 08:30:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-262ea2ff59dso2637143a91.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Jul 2023 08:30:02 -0700 (PDT)
X-Received: by 2002:a17:90b:28f:b0:262:d029:69fc with SMTP id
 az15-20020a17090b028f00b00262d02969fcmr10732523pjb.34.1688484601910; Tue, 04
 Jul 2023 08:30:01 -0700 (PDT)
MIME-Version: 1.0
References: <20230628154714.GB22090@willie-the-truck> <CAG_fn=UW0pX5+kRqqr9LH5wYbvA=1rABW8K+trGd-Jt8aynTww@mail.gmail.com>
In-Reply-To: <CAG_fn=UW0pX5+kRqqr9LH5wYbvA=1rABW8K+trGd-Jt8aynTww@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 4 Jul 2023 17:29:50 +0200
Message-ID: <CA+fCnZfkmmdP1ewgVZBLKu9ctZfE61RU=q6oyxHAy5O_Uegs=w@mail.gmail.com>
Subject: Re: HW-KASAN and CONFIG_SLUB_DEBUG_ON=y screams about redzone corruption
To: Alexander Potapenko <glider@google.com>, Will Deacon <will@kernel.org>
Cc: catalin.marinas@arm.com, ryabinin.a.a@gmail.com, pcc@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=C75PQ68i;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
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

On Tue, Jul 4, 2023 at 9:42=E2=80=AFAM Alexander Potapenko <glider@google.c=
om> wrote:
>
> > While debugging something else, I ended up running v6.4 on an arm64 (v9=
)
> > fastmodel with both CONFIG_SLUB_DEBUG_ON=3Dy and CONFIG_KASAN_HW_TAGS=
=3Dy.
> > This makes the system pretty unusable, as I see a tonne of kmalloc
> > Redzone corruption messages pretty much straight out of startup (exampl=
e
> > below).

I've reproduced the issue, looking into the root cause.

> Does the problem reproduce with CONFIG_KASAN_SW_TAGS?

Looks like SW_TAGS is not affected.

> Also, any chance you could share the file:line info for the stack trace b=
elow?
>
> I myself haven't expected KASAN to work together with SLUB_DEBUG...

This was implemented at some point, so it should work.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfkmmdP1ewgVZBLKu9ctZfE61RU%3Dq6oyxHAy5O_Uegs%3Dw%40mail.=
gmail.com.
