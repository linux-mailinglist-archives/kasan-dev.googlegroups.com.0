Return-Path: <kasan-dev+bncBDW2JDUY5AORBZF3SKWAMGQEFK4A2XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0342181BF81
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:19:50 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-67f92d392d4sf1890516d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:19:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189989; cv=pass;
        d=google.com; s=arc-20160816;
        b=e6dUyEXS5iPWDdZB0ou3FVbttyiY4TPmyQVakAJncD3R40y5RKiGhLMgkjO8nSsBr0
         36LgXLx0KX8/Vq6vTYCJhE/PwW6pfcZZK5uKHfdumnhUR9TGzxBK0L6gIn1UukZbhk9m
         M72XNx7Pz/gm1l8LkE005u6sOnYz4YIGBC9Ku4yhKFEcX7P2zm576ZZurAiUgc4I8XlL
         uYJCwGkZhTyRyFtvJ8n6sz8v/Ym+0/1iJ8gSdlIy7JJpF0c9emkiL886tqYbYQmZ+K9H
         mH9w2nCmqFhs7ktbenkLvhnMkmuMkHQ4aumTEsarv23UMxlOC83ZaNxVGUDctxoYokiR
         gsCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OVHZ6NC0IEjKUqrBU7roJkpyTkxLigjke0mtZOQ94Zk=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=E71T1zF1BI8k3P29WuWF1Brj8aFhi4P5b2Ot6p20UyJYfOnQiUEnz4+ABN/VeKeHnH
         hOmwTq9I4vF1mP1qJci1fZI3HBWZOC9hoa/E6OTjYD1zm1q6VXAS/iPOvN/S7SErDZTl
         N+eGrf1256tzhyVQ42v3tf9D9SjCfnSYVbtENIu0Cys55ubA04QO4XaDE71oCe2CpGa8
         xCRf+Z1spUd9tk0IweQ0KKFisM4JWYcGuBlIGv1xM521u9RFC/YSRWTs7zxOhePcOiuA
         xwGaV2IXIzkj5JUWvMDSxBFZJddhUrKy+6JdEEcdlMk9M1cCU0LgdlSyVKjtuvqDElFh
         j1yQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c2HAiRX9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189989; x=1703794789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OVHZ6NC0IEjKUqrBU7roJkpyTkxLigjke0mtZOQ94Zk=;
        b=YS3G34MELz3mqqVvDQ/2O1xUxDhBL3JGjspalXWKeaQaT7XjiDHDS497WX1hOPnKCX
         gpwzF3BWCsuGHSUncIOfnDwgDxeB4Gv00mZDJbrqxVVDTICCEyDwLlb9vULa3QP4ypb3
         9rzMmNY84j9aozyfHJls+kLRjqq8+6tvbBdGWwRSyzVMd6BQneorEAoN7idTwoQtACtn
         z4TEQ5ZBFs9T4dsUGKtO9z1XSOVH9MVS8s9SsIbZJ0wrg4wARF8HAPjr3CHfAwgJvEo8
         PUP5PD+T/5lnRTZOSrJbZSm5T9UL6C+gZ7w+EBJL4WKo36PAaeeYcmxLzT6mopBjryQw
         XUhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703189989; x=1703794789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OVHZ6NC0IEjKUqrBU7roJkpyTkxLigjke0mtZOQ94Zk=;
        b=HPJzmrIyQ7+f8EaSkXR1hrGWqdcNoVJQBJZWNnWm/WNKSN8Oy7P94Cg+RXFYw9JXgf
         O3xk63bFi3k1BWG13kswI2Z/iLeDNZt64vnDkzudvyx8+/y/7PbZtUrlU7UM8ObUnnPc
         bon3dgFACcHkDVkxcpWJCY1qYj/unopoywqq/LVcRT8YAG4OoOwWtfO4J4UkcTaVlMTD
         K8x/IpxGe790f+5g9mtCEn6B4QtqLDTnIjyIcJL4gaEovZIG6+E3TjipFExG8sce/u0R
         Q2/iialJZmtRo/riXgFxsKgA9lEF7Yzl4b5Qgr79iZhvm5wI940ZXC2U1Cge3Njm2rpF
         a/1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189989; x=1703794789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OVHZ6NC0IEjKUqrBU7roJkpyTkxLigjke0mtZOQ94Zk=;
        b=r7ybIAsE7yPA5B5z3tRQu1kWB4z29uJmkyH0t4OD6Ya9NakTKa36IZYvOENqG3Irv5
         Anv8MgsS1m4TUd9NWZThVHF7IWLqtZMcQRhWCTPDcdT0u2inqNntBeE5EL6gTDzImqZC
         RdTbEjr+dhfIsbIDwGsDw2PYtrmuYsnwHxZWztsgPTr+jgESvZcdPMVfpkB5k5ZTUGmi
         PgyBhFgx/7NZCUbtOPjbmX/gSoRe9k8tZYNxb3zHag33iiRRtsAPcSBQFDXxjo3unZrT
         xKEGXgBFiThjAEd1XuzIJ75cgqO3p9yUkijS17SJRX7WmL+/OsD/BRAgagUCcTnRdAcJ
         ZPmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxnlNw8/hp5TsWIkVsA5o5uuP/s83DrrLtHsHIp0zFxMhz/mRXD
	/2/fMH66mjLmDTscdFNOZ/Q=
X-Google-Smtp-Source: AGHT+IHZSjo6kjUsKTpzZC6B2AfBbIYYkYww6maJsViNyc91lXBeAUD80hCZscTpCwWqVtOlwA87jA==
X-Received: by 2002:a05:6214:2526:b0:67a:d8db:57fe with SMTP id gg6-20020a056214252600b0067ad8db57femr329708qvb.99.1703189988826;
        Thu, 21 Dec 2023 12:19:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6a:0:b0:67f:7fe9:75 with SMTP id i10-20020ad45c6a000000b0067f7fe90075ls1930214qvh.1.-pod-prod-09-us;
 Thu, 21 Dec 2023 12:19:48 -0800 (PST)
X-Received: by 2002:a1f:c644:0:b0:4b6:e7f3:6cbd with SMTP id w65-20020a1fc644000000b004b6e7f36cbdmr198877vkf.20.1703189988143;
        Thu, 21 Dec 2023 12:19:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189988; cv=none;
        d=google.com; s=arc-20160816;
        b=l5Igg1kUf1DwlDYN0PafYKX0GKef1B6a+dF4nDx7yRbRK2PFHCMVXWwrWcm9kgFq5F
         Ohz/STQBCYsgFC/WuoR0ds9DHhVVzemul0ZFGPrCBJO3JjRbFl1wk+nND7YUE8IajXaz
         A19i0/WcCMnHjdsZe9XkYNjM4AHhxh27Ra7nho55iyBofftTYywQeo0P3N9U2E/7JXgx
         cKEQt/4GNnjlbkpYxOrul2kYFvjxpa3EU8mwjOMugD8D+IXHQAoR3DCZWkQ8fPYNkNLc
         FVsfIAWXGxKXIA3BNT+IpNwub1mzdHU37+I4pghuLvMA/coFMAQa8GPnKTqopdNg88p1
         NKsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Gssvy5smjz8a5SJrD6j08da6bZEPTZEaRbn1KUt4UuQ=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=XV8Ch5HZOzGOG7t6Nz5zMBIwJ5Fmw/cDyc/wGcs0AfOMAUCF28buufqNo3G+x4wHuQ
         d3AbIFGwWtJRowIWnWEnTqyJ6GTEBv1UH3wJq5RriVIJs9zpH2Z6RV/GJ1SfMe7mmNlk
         9cJf21nB69KoddHcKcXD8oeLi7h461PtMRz8YxXr4YOmCboxJep6jC/rHgS4SvVgJ86c
         k5JWOfn3BfIZ2w6trF08zyq8Ru4H7SHr4hR3IlYyc+lzbkiYvdmMwuAOQhqL5aGon1ZX
         aWOeeJrJVDVx40gebr/ZpLjSLIXxZGw0a4z3/VA/ukTwJIxWcNGdf9vJ9aRL1NBrfyHF
         KjAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c2HAiRX9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id f13-20020a056122134d00b004b6d37907f1si570840vkp.0.2023.12.21.12.19.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:19:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-28c0565df34so143979a91.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:19:48 -0800 (PST)
X-Received: by 2002:a17:90a:ad92:b0:28c:194:8de1 with SMTP id
 s18-20020a17090aad9200b0028c01948de1mr317153pjq.63.1703189987119; Thu, 21 Dec
 2023 12:19:47 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
 <20231221183540.168428-2-andrey.konovalov@linux.dev> <CANpmjNPGBMD6XsPpdL-ix8VTuWAwV-jmBjLpC66Z5y543j0DuA@mail.gmail.com>
In-Reply-To: <CANpmjNPGBMD6XsPpdL-ix8VTuWAwV-jmBjLpC66Z5y543j0DuA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 21:19:36 +0100
Message-ID: <CA+fCnZcMRT2p07PLqXnm3p=YFOq9SDR_74fbnA+x1BtFuotCjA@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: reuse kasan_track in kasan_stack_ring_entry
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Juntong Deng <juntong.deng@outlook.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=c2HAiRX9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Thu, Dec 21, 2023 at 9:11=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Avoid duplicating fields of kasan_track in kasan_stack_ring_entry:
> > reuse the structure.
>
> No functional change?

Yes, no functional changes in this and the following patches in the series.

> > Fixes: 5d4c6ac94694 ("kasan: record and report more information")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcMRT2p07PLqXnm3p%3DYFOq9SDR_74fbnA%2Bx1BtFuotCjA%40mail.=
gmail.com.
