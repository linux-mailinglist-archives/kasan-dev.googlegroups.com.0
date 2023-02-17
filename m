Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXSXWPQMGQET3ZINEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C071869ABF3
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 13:55:59 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id be26-20020a056a001f1a00b0059085684b50sf721088pfb.16
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 04:55:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676638558; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZsJCpvUmluTQwxPwh4Bal/CqRhTjMNsPvMIiyQK/VD6jI34SdCupNTjygI1a2ZY07i
         8AqkRUdnqeFHRblCD5j1ycOeMjyVXczKY53qsGAAnmOBTSoYURNJ01U2xB/acV2h3n/U
         PDAuq20d6rWGqizogrwfNRNW/kOgdNK+uBHo78x609oKs+edi2ZJmFoMkGyssQ6Q7N3E
         +rpLGt6jmCZiuSYfIFBkn97V3fQS0t0WUvY1j3b/+YabS6RKotuef5VgYA9JCIGlXTCa
         9qPdRWXNfxGT/vusWNARJMZVbMInD6d53g0rvo/bUe6bOMBsxcrbt7rOZaRJqETZHdZH
         6cug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pxyKTY6IfWVwUwaHt/B06KtZEYaP5d9PuhE0gfpVAU0=;
        b=FA8Yd16FCShOgNBfAJDnRBJ7kX/n3exHRvEsGePNnPb/LqzffRtP83bsK4S1kVzFxM
         TpmNY8r5SFDul5V9WlNEg6ANVf9dz/492bDlDKqCrKybXggSDlTyDMjBrSSOOUnDGMvU
         jTFmsDQdGeGpIc7QR1h/+Aw0AWNLORvj8XqbWA9b2gTUKImX6ZeeodO6WsVJbLJYBt5d
         wOmI8vx14421VMl0/DJGnP/xUyya9b1l2KlU6mxpKiUVwPDnT/ky7+wYsepQWhJVNSpT
         hEHBbYq2nN0gQP5ZNCqiZp/mQaOXr9mwB1JS/ztdTjTzAmzFVzq+nPWnIu597mKQaWtU
         ph/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QY0L+kPX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pxyKTY6IfWVwUwaHt/B06KtZEYaP5d9PuhE0gfpVAU0=;
        b=lNED5QWA2Dvbl2VZ60KK+0sp5qq2HxWS+hQYGVT87sgpO44CYT8eOsBZFn/x6L8j8i
         9GUzZUscwfC3iWuBumzkCdrru8sgAunsXQH4GxSFyriwdhxCrTAiNAPQ+exzzRUU1Dut
         S5xwRI8D/8eZ0HwNelp4cJwwMap1R3rFYzBAmRB6bCb3p9Pc9C314dbhwGusv5SDhJNK
         linDoxd0kW0lVSYe5DihlVaSh2zZayrAi/5LDAXsubmOHDMsKsJAZxhtEZhbeVMS+RGP
         fNRMgKWEUIvnIWDnUWdrj8vitSiuRyaKyaYbuoFNo4rCFb8+3BU6IqN5Tjb3PvEw89RY
         rqwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pxyKTY6IfWVwUwaHt/B06KtZEYaP5d9PuhE0gfpVAU0=;
        b=laBteD0FooF1J3f0Vp4a4yy85vMuOb+BuUX/rQVQv6amjg+ZNsRtFHozK3Eln4GvRt
         t93hOYtIgMIdIL4wE+bAQn7W8ZHeAOV2rWjSWfH1fgD2Dpm01vhBYUujbuKVAutMBqBy
         miRW6uRcdU7Rrv8HESiM2ig4WZSY23jkTuji3nrz7wH1PMbGdGuDvb1P9a722zfxtvV6
         wq08tLyQlJHNmcEd/YCwlJ/0z/QnLBHasryM1A0BgusOHruksvSByMSJ9D0zq1XL/pVG
         zHYIZXV88AJupJWZSiPgiHd5wsB8iQiCp8W/aDBVsSuvBUnG2/3POw4V9nBrlBxpcvWL
         r4dg==
X-Gm-Message-State: AO0yUKUo/q5goO0L5bdoXdDpdJAu/dLETUTz5zbUj90jtq8oOFd9HrcI
	iBLKw4oyqSSalxCjSKk9Bv0=
X-Google-Smtp-Source: AK7set8arA89rFlN7mtQBjNDxiA1nmFFr6I7OZwvJtgu4BnAx9q1bf9S4GwoSUR1ExNpcJkkcGDjWw==
X-Received: by 2002:a17:90b:394e:b0:236:73bc:f417 with SMTP id oe14-20020a17090b394e00b0023673bcf417mr378487pjb.112.1676638558256;
        Fri, 17 Feb 2023 04:55:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e84c:b0:198:ddfb:494 with SMTP id
 t12-20020a170902e84c00b00198ddfb0494ls1408315plg.8.-pod-prod-gmail; Fri, 17
 Feb 2023 04:55:57 -0800 (PST)
X-Received: by 2002:a17:90b:3511:b0:234:190d:e653 with SMTP id ls17-20020a17090b351100b00234190de653mr10868424pjb.6.1676638557447;
        Fri, 17 Feb 2023 04:55:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676638557; cv=none;
        d=google.com; s=arc-20160816;
        b=b4RRYebyPW0b7RF9bnpwfwSUC1mROwUGvOTrmUz0gXStbT01xmWUFUPzH8rbL6hW9L
         zyc+l8UNqYDLXxqKACRIJfRCcnOMtx5cioPBAAeZOVdJ6LO2r50cD3xhh2ifnjMUXOL+
         +22EqJXCtJUQPaJrAM51OuCL/3bmtbBy5YpALXV2I1O5uymrHwWF+hzQ4pP/2+BofiTQ
         65MkR+w9AAg7p2Eydo6l2AR9tyqwcjAIYF6+0yVXiD39q/2xY1pPd0AFcCbiTlQRSVMJ
         902KFoe3x+VssrbT1LY0jZNjs0d7PjXL5CyHKFiisFFsw40BaMEE35KvBiLm+1SWEOTi
         T1Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Niz+iUEDg12bkyQmg8bfO1CeSRErQ0TqE9j1iy2aNsg=;
        b=DJZXpiseXJuJSaT5KDVJb5T7I3ZcJ3SgkiPa5iSiz8PsgIGzOMr+g/55hfoAeiZe7S
         wqptnODNyN1eeXqbaUVLUKLKJSKhzR7sjB8/TFbVOQwYBYiDGUB3gWKygAzgAY2qc97r
         kf3L1zoowTl/UxUiBY56AyANmxk/gw++h+HxC0IP4ZnvIPAGqLMpSMv3tx6bKJItyklT
         qd+9wrDIii/WZuFooIfgqO6gSIwc/UffpOpYzgYjuBMVBtctZFp25wvoHgohYVu9OJRG
         Ow/lYFO/hMbFVEtvdv0CTlHvZRGDsZLnMFzZtB5KFkBG9DCzR1Oa1DZbtRNzzCGbZmrf
         y0gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QY0L+kPX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id ha7-20020a17090af3c700b00229ee755cffsi115867pjb.2.2023.02.17.04.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 04:55:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id h41so308525vsv.4
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 04:55:57 -0800 (PST)
X-Received: by 2002:a67:70c6:0:b0:412:2e92:21a6 with SMTP id
 l189-20020a6770c6000000b004122e9221a6mr1748513vsc.13.1676638556537; Fri, 17
 Feb 2023 04:55:56 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com> <20230216234522.3757369-2-elver@google.com>
 <CA+fCnZehvF1o4rQJah=SXaS-AXWs--h2CDaUca-hJK=ZTD8kTg@mail.gmail.com>
In-Reply-To: <CA+fCnZehvF1o4rQJah=SXaS-AXWs--h2CDaUca-hJK=ZTD8kTg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Feb 2023 13:55:19 +0100
Message-ID: <CANpmjNN9EPTLR5-HvpCtYjauMTT=Ud86wqV54anSYC=vgZ70zw@mail.gmail.com>
Subject: Re: [PATCH -tip v4 2/3] kasan: Treat meminstrinsic as builtins in
 uninstrumented files
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QY0L+kPX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as
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

On Fri, 17 Feb 2023 at 12:07, Andrey Konovalov <andreyknvl@gmail.com> wrote:

> Is it also safe to remove custom mem* definitions from
> arch/x86/include/asm/string_64.h now?
>
> https://elixir.bootlin.com/linux/v6.2-rc8/source/arch/x86/include/asm/string_64.h#L88

Yes, I think so - sent another patch:
https://lore.kernel.org/all/Y+94tm7xoeTGqPgs@elver.google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN9EPTLR5-HvpCtYjauMTT%3DUd86wqV54anSYC%3DvgZ70zw%40mail.gmail.com.
