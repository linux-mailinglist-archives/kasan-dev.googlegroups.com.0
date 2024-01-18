Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNFQUSWQMGQEMV4LJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 467F183190A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 13:23:18 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-210cc863309sf155042fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 04:23:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705580597; cv=pass;
        d=google.com; s=arc-20160816;
        b=M147KSmTBVDInaq3CUutptp99y57hi8VCTBP/0NDfz/c/LzDKXMbWv/8VTx5W8jU/X
         Bk5/LL4jckfUznNuqtFZxnlgsVi8dKY5sXY2x4CVmffRL7t7HCfSrh+k3jEkqKJTYtK5
         su9jg82tPafezf5iNL8HcAlFCRTJXrORuIFpNQ3DgWGuXeWb1AA3bFf8/Q7zUq8X9Mds
         8Fgb/erwxLipbHVZvKjTHFyjyyRECDh587mVKjScl9T41jybK3DYr96sA6dPY/lteAn0
         B+Wpnhe3t6tebDjF9cv/0LiK8H5R0QVeQANxw6IPpOEhoXOHsDOU9Kexwpt7Qia+wazJ
         Ep4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IRwNiutNL2CF8wg4Z5FF1Kikb+4/vYLZeAc8knhKeA8=;
        fh=bvYsEM7Ok2V/a4sKALEX5c0KGrY55c0qjRuLh1virvs=;
        b=krFQmQI6z0kygzOKlXuJ7ZYBIc9uIqZK+Ei46Dtzm6riPgYZv//CxaJl7sSDhFrTFd
         DGv2yBOB9K+Q/9YAH7YnelL89iibYLuOEzKC6ArBV/BbX5lzLshKpqasU0bozn+DfXfJ
         kXbqGUK8TX7o28RFZwMnQPvAP0U1K91QC8iVv2j/Ls3gwYrIgeJqjRKJEW9eQ/wvuAyN
         KVlFQNHRt+mRC56b5nwIFlXUR27JjDcR8hkfIqejbcB8FT2gakUtZuUWSHlAbNWH2NTb
         y3MOYsynBLjgyQauKJsqcRSsg6fowKVdU+pNd7JTcYk/41wQ/mIc8mneN4MBkyjvvfMF
         T/Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NmTEjVu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705580597; x=1706185397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IRwNiutNL2CF8wg4Z5FF1Kikb+4/vYLZeAc8knhKeA8=;
        b=SxIQ6adbtlK8OYFYCx8Re8+0d5khTo8CmkB5PkjXfvn+8RbljigKhGVrlPqZtcS7ve
         x3Yw5zwpkGJVN4wCuFZ+Ld9o/Zsp3C1ag1mdQNWBCsjhfvlG05LKvySA0zv/r6iv3IAr
         2xkvjC1XnV8MdcyZPQGTH0ddjmr0lPuv8cfbOCzC7u97aCOUjymdJoo14Bl64+JE8a7R
         yfj+2doFFn6vbX46+7AY9mPFI1mAAMLaPrYGiZvE6H5zezrsSoVPlyzcUakvVO064uYR
         Ls/eEVXqDJmS3MHnWeHN2InbXO2lR9Aw3t/h4JF46+miAUS6POi3ga7s++HrdQ5yYoSC
         CCLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705580597; x=1706185397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IRwNiutNL2CF8wg4Z5FF1Kikb+4/vYLZeAc8knhKeA8=;
        b=dxB2ylU+T4Yk4e//4i4JUxywD4mGKBC5h/ClVOJXC/Rkc+XmuMy+Nzo31XCxpZ5XBO
         CMLy+ojXSMaHL6TKW296pLgeBAmDRfeplywhyM6ZvGaNzI65rZgyXv7MgKImGUA7jwpZ
         WqeiQjlQhENyx7YDNwCXpWRMvFx32puLsWZ0h5behLfOb52UcOajuLrlTvpM3RvdRAAY
         pG9molUvQodGf4r7ygANzo1EeMhHpkLzNsB7RHYZJMMHPvkvoU0Z1CCcI0c6SyhEdwUr
         WtLHh40poLdoSBUlnBaNzXoOtYUUBRNgnOUMzUp2/LxLhLab0lKUtHNRIbapIRgBxxoK
         tbTw==
X-Gm-Message-State: AOJu0Yxh254pTqvwMvEpgRsuotOxNZOSEFQubFfu++4FtKvxUum4YanH
	uN6xnZU/2/ubOUnFDM+xES9HSqf5acVcFkiCBQNUk8b6xxqMzKGE
X-Google-Smtp-Source: AGHT+IGj9nLydvxgVuMDKNOyhX8+onm5/pzYf7FqBBS+De+hoZ2EN+AmI/RxfXtFQnFhmN9/BiJ0ZA==
X-Received: by 2002:a05:6870:a10e:b0:210:a3f6:1a6e with SMTP id m14-20020a056870a10e00b00210a3f61a6emr720252oae.1.1705580596579;
        Thu, 18 Jan 2024 04:23:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:248c:b0:205:dad5:7ff1 with SMTP id
 s12-20020a056870248c00b00205dad57ff1ls182265oaq.0.-pod-prod-04-us; Thu, 18
 Jan 2024 04:23:16 -0800 (PST)
X-Received: by 2002:a05:6808:1403:b0:3bd:5242:9e59 with SMTP id w3-20020a056808140300b003bd52429e59mr809308oiv.74.1705580595824;
        Thu, 18 Jan 2024 04:23:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705580595; cv=none;
        d=google.com; s=arc-20160816;
        b=xFPswcvXrbv1r72mFbwEue60Mo2S5MCkwDIteUQKuyJHHeLvlmv9bIg71w7QlHjIM3
         tfca7A4ZbnotTMocZ5+YVJx5YYw9fX7v6QNmpZxdPcXE2GQP/S74gN283dO3ReLKhIjR
         oGrO/lMxovYpdKlBV7BYNWVjnCsjExq5XrGXNc3i6+mqhNbsk6chGzJxgtgPmiKmYk1i
         zeDgM86Ur4BYRPbQA8lKMmZxsK9wtimU0qaxroO2mcJGBSPHyz6GcUWYPdLLFfyBRNjW
         F7ThE7/0Q+JzpABTE8bj+gihPz0LKZcqESIiz/Rzj74A78EkOlwgB/GD+pDAq5j+n3pU
         Tk0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7AuSwgYsRLtQPaH9Hm2+jqJ8wMg7c1ufpWu5H7xj9V0=;
        fh=bvYsEM7Ok2V/a4sKALEX5c0KGrY55c0qjRuLh1virvs=;
        b=Y6YHipVM5c/RXwmD/MDC6mWBxWJf2WWh4/gTafg2wh9LdlDpusaBn0vzT2f/w8gRfK
         aEvvpzQZaDlbXxTEx8vr+fPRECzyfAoIIJmIOb/HflvSwJolYsLQV4I3MvEd0HxkX5kP
         7a2fdhsYIu7sbcjWvMP2h7l/zgHfPEBjRNBOMnBGMiiR0HGlHRfXbvkrEhvcu6M21uAu
         ed+4OWRc0zCHNTpUQVt3N4b6uEmfBdxWrvq6ru5YRm3fGzFM1xrWCIgBBKt+T8Wn/Y0H
         N9PCPATy/zS4auUtQq2yyiey58mkwjM5lLJ8bGhiDJd+d52WsYvf3Nxpps2ONauZ+XHn
         AsRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NmTEjVu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id v25-20020a056808005900b003bd285320a4si103484oic.1.2024.01.18.04.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 04:23:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id ada2fe7eead31-4696d3423aeso999896137.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 04:23:15 -0800 (PST)
X-Received: by 2002:a05:6102:3165:b0:467:b086:3ec3 with SMTP id
 l5-20020a056102316500b00467b0863ec3mr597178vsm.25.1705580595173; Thu, 18 Jan
 2024 04:23:15 -0800 (PST)
MIME-Version: 1.0
References: <20240118110022.2538350-1-elver@google.com> <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
 <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
In-Reply-To: <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jan 2024 13:22:37 +0100
Message-ID: <CANpmjNNZ6vV7DJ+SBGcSnV6qzkmH_J=WrofrfaAeidvSG2nHbQ@mail.gmail.com>
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical section
To: Charan Teja Kalla <quic_charante@quicinc.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3NmTEjVu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as
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

On Thu, 18 Jan 2024 at 12:28, Charan Teja Kalla
<quic_charante@quicinc.com> wrote:
>
> May I ask if KMSAN also instruments the access to the memory managed as
> ZONE_DEVICE. You know this is not the RAM and also these pages will
> never be onlined thus also not be available in buddy.
>
> Reason for the ask is that this patch is introduced because of a race
> between pfn walker ends up in pfn of zone device memory.
>
> If KMSAN never instruments this, does it look good to you to have the
> KMSAN version of pfn_valid(), as being suggested by Alexander in the
> other mail.

It would be nice to avoid duplicating functions - both options have downsides:
1. Shared pfn_valid(): it might break for KMSAN again in future if new
recursion is introduced.
2. KMSAN-version of pfn_valid(): it might break if pfn_valid() changes
in future.

I suspect #1 is less likely.

What is your main concern by switching to rcu_read_lock_sched()?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZ6vV7DJ%2BSBGcSnV6qzkmH_J%3DWrofrfaAeidvSG2nHbQ%40mail.gmail.com.
