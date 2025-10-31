Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNGISLEAMGQEY4Q4IZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 911EAC24E2C
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Oct 2025 12:57:42 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-87bf4ed75besf58554506d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Oct 2025 04:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761911861; cv=pass;
        d=google.com; s=arc-20240605;
        b=XNT2SbpLl8oeTuO/Ewc9i8ef4gcAVXFptQthTR22ZMBux1Y0iFOMoG5wXvuo62dzsq
         u3R+f4UOZIJd+8TTm+N09AgRBfxGevZJcOC21Tog+7L02VZNhUjmVx56sjL3UBY4pb5Y
         V9qNEEi7QyqumQ7EE4XaZHED9Vm0i6Zn/cVlGcUoR3r0YBd1og+Hr0Qj21RZR/ESJ6B0
         0WrAQJJhFP8Im0TP84qKOp6e6rL81jXRGcUNUqRh+lil63MP1b5GSZbE69LV5oDt36Vd
         wl/hQvQYCE3JLnmUr4uYA4DF29V9GGAR+YBEwoYDYcYbB4AsPP4UVttfOdIzB/sNr8kg
         m4YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d/45RkaYQn1o6Z1S9Xmx16U9BWrsJ26ctTqDqMXfmQM=;
        fh=hlTXe2cLNAJ8pKV+mqtK/ELhPM4OGOapZh1bJPfcRGE=;
        b=acFYwwQC9L5U8PXA0P9HGhz57O1ffub5pyB2NKPbQYLdvgUcOoZe4FyAndW3ttctZ1
         sORky457ot+vZFcqSMzZBZIYyZ21S/1VRepIloYvMaQBa4OM0JE4IBTGbr4JGu5khOzi
         WWYBuSsx1FNAL52H0PeU6k7xGgBn0FQjUiYUN8g1v044f52CWkrvC1HxFAi4lVJ7gkfa
         5ACDz2nxOyYpD1j4pcOOlCCnIP5DZsYkn2BHhkSaIF+YIk0ksAU29738f4rgLg1Jizu3
         Eeg/PcUhcmEPGkhKzWhpqVXkeIqObGvYGrhhU5myHsFeT0rVNFrt60iRL0vyXUImHOqK
         zR4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dss5AIq7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761911861; x=1762516661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d/45RkaYQn1o6Z1S9Xmx16U9BWrsJ26ctTqDqMXfmQM=;
        b=JjSn8L299cbVnKnWlEWxjdlKmpK1BZXyZUreWKKtqQ9psdx0OkGjaWygvr/HeFUkX3
         sc7Kgs5EwsSWn6DA1xG17BuKUIXu9izyfOn3/S0gI+Rh0vhcl+H0N+NSjYJsSDOI5ex9
         9Fq5FMttc2fBhxtzDbFHUGQBILFCV13CkJNXkSda5+poLABzxcqcmm5HfSVGkqNw8nKx
         uhguR+8gr36xVGIFQRTftH2F08nKrA2ycjrs7/51FCaclVXA0lNEGCvBZ09Z+DjLIzOp
         n1DZVMzUTC8DhEOa/kR2nCzGeBVl6rSMcTdO86NCrxYhLKy4AtRSLbXMF9TUl7UQSUt2
         xHqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761911861; x=1762516661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d/45RkaYQn1o6Z1S9Xmx16U9BWrsJ26ctTqDqMXfmQM=;
        b=FWnTJndU/t5eNIIY1FlTgbBitiwGMCS+mlKPTvdNEt6Be0KyxRRGLXUnSEkupolD9g
         yUct7kXi5nQ2VxldHZbkvcNHPhVSxNXS+3M+ozt2ho70Yt0d1Prq887chtOo4H/qdr35
         BkhKBqXdeVANiqa2By5fZEsyVi2H4KK4vrhH/k/EMkiEVh4JkWUoh1DxCuSGZE0Oy4if
         SX/t0kuAqBIrMOTUhCHVr7pf1ZzuN+tc5KMy6cx+sAQArrl+trc0UostMSz6INFmucMo
         ETjIAr/XxNAC+zbBYwcUQbJ482VLBNKb9ytI8+2BRf4cuZQHCdLUeZT5KfQqbygv6TGY
         LIPA==
X-Forwarded-Encrypted: i=2; AJvYcCWg0ypriLQzanIN5OduhCsl6uqYKEqegugOA7y+thrYYbkloT9mp+Z8kXV41n5p4dnjDmlC2w==@lfdr.de
X-Gm-Message-State: AOJu0Yz8AWGPQg9hoUMA+0uUjmCcO232Rw9rNiAFG26aWsLPjDFGa1Ux
	fjC23YfDGUXbAjWjlxzdqA2I1z/WX79CjXJTuw6K+Ug/Vi+FoZ+/GAIv
X-Google-Smtp-Source: AGHT+IE32szfVEllULxkcMkmRbyGSbWcDR3Gh//5bLL+8NKH9JaiGESCr8sR5h4ThwyKJs3dvkrC5A==
X-Received: by 2002:a05:6214:29c5:b0:87f:c4d2:91bc with SMTP id 6a1803df08f44-8802f2937c6mr39744876d6.2.1761911860917;
        Fri, 31 Oct 2025 04:57:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+boG3kMsenZibmxj+7GEok6xaAHrKCATyBphoesw8/uMg=="
Received: by 2002:a05:6214:4792:b0:78c:3f6:27af with SMTP id
 6a1803df08f44-8801b2d4576ls29955046d6.0.-pod-prod-05-us; Fri, 31 Oct 2025
 04:57:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXk52+wP7AA8L1u2BQx99Exnqe+N7EXVJQUjhD9Ixq15sbYq9+h/BoU9WhcZT+ilCx0/rlQSg5HOfY=@googlegroups.com
X-Received: by 2002:a05:6122:298c:b0:556:980d:3c79 with SMTP id 71dfb90a1353d-5593e58be24mr1056164e0c.14.1761911859963;
        Fri, 31 Oct 2025 04:57:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761911859; cv=none;
        d=google.com; s=arc-20240605;
        b=Wt4nG8+B4zFA4LC0g9BNsCphpKlq54f0LDYAPaBvsXJJy8MUGQvV0thaZuD3j6KUxb
         534WDImueog9fLl37nJ0xnSJs4GwxL7mdhlXJ5qnc2e5OCBGGIXFqx8JIvQFpk1WUtZd
         YV3SFMjCX4LvAWmpalfGNKWOktaHmbCMWg0H1RUOPo3HvaYwfYVRzO3Fj8PMgsEGDJ7E
         z9dz0Ua4NC1qV4n7lgkq1YyYIKUMviOcTRDHlgYMiI0flo7YwS5SzGyeBKnfyWYv0HJ6
         3vNgPjLQVa2Vm4j112ZynqvuXluL/J9ZQkPohKS9gLQPdSMI8RiSVfQT4GyqeZZCQ/X8
         qasQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dY7Z2MmzbkxuT2iz0v8W7dJrKa/ZUWsqjm3RZImAMKI=;
        fh=oVcqlJlnYD27N18vMwTz3ReW8CguZX1Xo6I+5yxnCLo=;
        b=QaRk6VyXsJZRAGm87aMjNabDER8qiJukeP/OxUgADYu4Nfa/c4neBJSaB5e2NrnTNm
         Qn2KbFv2bf8M37/ibW/z4QG4QejBN4MB7Um5y0xaNL1DRqdqFLZ7J0h8raucPhTxgFCQ
         jQLqB5EH8vA2nE2FmRTL8tNqRDg/Y27vCAIi2EJnboUhuxIbxMDzlMYfZKHyxDLpj4fE
         v24sgUf/6fEAHD/l4pxeVLGHKoe4FaWbny2twD/ygpsBq+W0jfH5xxVkwy1Wivep8Nze
         YPzdf8yPE53RUBVL4umDuua+8v/hTXtapTW2C+ht/TFZDmBmVwwT3a7bOUc9ZqMRyEG6
         Nj+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dss5AIq7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55944998040si135390e0c.2.2025.10.31.04.57.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Oct 2025 04:57:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-88032235d68so8250196d6.3
        for <kasan-dev@googlegroups.com>; Fri, 31 Oct 2025 04:57:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXULgmsy7Rx2UC3dXefkYNdo4lAR59acM6j2hwlFm4jPWmsLv6B2t5IAdvfZvy4Mj+/N6vUS53Baag=@googlegroups.com
X-Gm-Gg: ASbGncshbS8iOKPGxc26kER0v94kYUiBxuYooH9H4ZSV6cfLo4r7d61td1kEmSWX4UN
	X9nFIpXyj7QFsSv/8odQxskyeTX1SKn0n9F4LWtzb6/yOtM4lf0uwYJJK1uEyII56iC+3BVvzq/
	mk2ZCUsiveumlRt7yVi2ccSr6J08cPa9dmBvY9jRJJImB94O7UrWjY8iR1Xlr3ggjm+TcJNZLhm
	QmkJ3GQkZk4sFwN/2LGhQ4DURkMBCtGzcJU59usjG5ezNLZqsrAH/O4SCAWmy+zsoc+wS2cdK3z
	lFlcNFmGBnABrpI=
X-Received: by 2002:a05:6214:238e:b0:880:219c:34 with SMTP id
 6a1803df08f44-8802f316e39mr33232076d6.21.1761911859273; Fri, 31 Oct 2025
 04:57:39 -0700 (PDT)
MIME-Version: 1.0
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
 <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
 <335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com> <20251022030213.GA35717@sol>
 <20251022143604.1ac1fcb18bfaf730097081ab@linux-foundation.org> <CAADnVQ+o4kE84u05kCgDui-hdk2BK=9vvAOpktiTsRThYRK+Pw@mail.gmail.com>
In-Reply-To: <CAADnVQ+o4kE84u05kCgDui-hdk2BK=9vvAOpktiTsRThYRK+Pw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 31 Oct 2025 12:57:01 +0100
X-Gm-Features: AWmQ_bmooBOl4Jc73SKfuTO-ZNCvAEqNx0sukASP61H3kOcFqYTjm6P9qzvWG3E
Message-ID: <CAG_fn=UQYdGqiMbFxp+XTgP=zkZgDGgdcA74Zcs9HTo+zd3oYA@mail.gmail.com>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots are
 allocated yet
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Harry Yoo <harry.yoo@oracle.com>, Michal Hocko <mhocko@suse.com>, 
	Shakeel Butt <shakeel.butt@linux.dev>, Eric Biggers <ebiggers@kernel.org>, 
	Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-mm <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Alexei Starovoitov <ast@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dss5AIq7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> What's puzzling is that it took 9 month to discover it ?!
> and allegedly Eric is seeing it by running kmsan selftest,
> but Alexander couldn't repro it initially?

If I understand correctly, Eric was linking his tests into the kernel
(CONFIG_KMSAN_KUNIT_TEST=y was implicitly set because
CONFIG_MODULES=n), whereas I ran them as a module.
After the kernel booted up, the stack depot was already initialized,
so the tests behaved just fine.
KMSAN also continued to work normally on syzbot and report bugs (see
https://syzkaller.appspot.com/upstream/graph/found-bugs), so it wasn't
really obvious that something was broken.

> Looks like there is a gap in kmsan test coverage.
> People that care about kmsan should really step up.

You are right, we should add KMSAN KUnit tests to some CI (wonder if
there are KernelCI instances allowing that?)
I'll look into that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUQYdGqiMbFxp%2BXTgP%3DzkZgDGgdcA74Zcs9HTo%2Bzd3oYA%40mail.gmail.com.
