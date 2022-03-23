Return-Path: <kasan-dev+bncBCA2BG6MWAHBBTM452IQMGQEQGLL36Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B6AD84E5A83
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 22:17:01 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id z16-20020a05600c0a1000b0038bebbd8548sf3280127wmp.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:17:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648070221; cv=pass;
        d=google.com; s=arc-20160816;
        b=uH/vhJdlB95wSXXT579ao4w4bLgMF7HKbSJASPoawxy/SffLCeixHH6/ZCh6m60YU+
         kA+7ZO8yuYi4JjDa1/wgf6nbpg6QWf990TDcvF0E3868ln8VHjCVOQQeFkKgqAjXZwdE
         hHf+q8snl6Mr7yZ+Lmeb0BFfoAHLugVorZOO1X9LAVApkfEkgZaSUjMunPtK1EThDkvy
         QtyyiW945weUDMUV0rYc0WXVyV1DnMA04BFomdK1dxErJIUu4fgSENQyO1oiLpfrBen2
         qnin5OqEojoo5EsP8lkKQmL/QdXVYkEK9NpEemOtCSuERVGDJlevixyxSB8vhe3SkM8M
         tdbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YsgNJtg2fpTlZ32hZawr6adjyM39mk0hxjCBoCDp2aw=;
        b=mGn3Mayds5+DWU+kwj6RJKvp3hb8vgRbMubg1LXdbH6UUsXjNiLZ8FHiZtSP30WXV9
         GYgE9mIcxh677WDpAJ2zjBaahE1J9ZkK3Ug1Tyjrqax0Z9GYYC9CRNEYYdPnO4vRrWu+
         vV0dIOLr6FEER60tNGeHaPiZ+OesWwknvR0fXm+cC2Rr3xbBJsnXkwbCJVcs+9HIigBi
         tfh+E3diY4JvYsWwRF/J8TlzghyW1UXLqVrYVFWmKwBMY0uGEG6OtRGGyE1CmeK27Vt+
         pVLaE5UTVWDQCWJZhgnd7VZ5O3vtKOmMjGdpH+tO7cbL5otdB+zddhZeMi6wSy6GLyAu
         vpbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TH81aSeE;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YsgNJtg2fpTlZ32hZawr6adjyM39mk0hxjCBoCDp2aw=;
        b=TgZmcipFPC7y8JMWvwiMNMDvt2aC1Zt/3ZPkuwIeJlw9U3FtAJ1C0Xi0i62bciwGYq
         Efp3fvOQhAFo1wnfb58JXg6DvTaZRrmGPcxJmZkDdkSp7UkSAJ1ATS9T/ggiRzlQdqhR
         EmQyyNauOu/qYtfPDCsjunFC1+Xh+YNtblxSkJOr8PBwF9xMHduLlLui2Fxu5b+6gpfH
         DJBZt4u++VjoIfyyDIKNuJMl2W77Uv0OD9A72XmedyMEkd4X7+oZtfxg6J+HY87likwx
         Z6lJf50o/LDLv9Dt6Bn66+bP6fgNcecfwaUtIEIxTbt1FAlcIBikzTp3vumLnAObfiGw
         IpKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YsgNJtg2fpTlZ32hZawr6adjyM39mk0hxjCBoCDp2aw=;
        b=Bjm9Su+SZaNglH4rPfK6BeYpwK5Svd11B3kNA68wXtTs0NP2mH8mMzt9r7X9ldCujd
         /C4rGAsAv76TT3HDbRwIJMz1o9ONadnLxftum+V3n+qJDs5HtCJu9BSo+jQzLsEwYyW2
         Yl2KgbTN8L2HxVChb7uQrTpzz+x9hp87qFT4DyoRwnAVFVaCEQeK2FkP6MSK1Z2LPymO
         8cozV3ykmtpgQO8yd21ma3i5Mhmc65DDKTemQbR8qP+3N6WF6OEG/PThmSKoQ8UkHO0h
         DCl3YSVSh8wAWDFR806AFTfbCeGJEdPpVa4tslu7/zsZks+Q6rDz6EmUmm2bK+QErcsU
         6FoA==
X-Gm-Message-State: AOAM53362g2NpGvcH3BiUmSqnKUCFBIx70pGyV8BscL4f83HP8aQ6qVv
	SBFfg67e+WoaCIe0ZJc5e/s=
X-Google-Smtp-Source: ABdhPJxpuXwkCnr8v+C+I9ItTQ1zvneIvPRy3/vzckUedg140EUaDzfx6oRvjSOWEcoixjhYPvZuOw==
X-Received: by 2002:a5d:6a45:0:b0:204:597:2708 with SMTP id t5-20020a5d6a45000000b0020405972708mr1840410wrw.2.1648070221375;
        Wed, 23 Mar 2022 14:17:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6f11:0:b0:205:92ad:ce90 with SMTP id ay17-20020a5d6f11000000b0020592adce90ls230921wrb.0.gmail;
 Wed, 23 Mar 2022 14:17:00 -0700 (PDT)
X-Received: by 2002:a5d:4204:0:b0:203:d794:93e0 with SMTP id n4-20020a5d4204000000b00203d79493e0mr1747285wrq.136.1648070220601;
        Wed, 23 Mar 2022 14:17:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648070220; cv=none;
        d=google.com; s=arc-20160816;
        b=PmFHYIKS92kBq8H7g4RXs4BSO8txUxQl0LM0yTQGNgugNxMxp9cfeRxY4vzRjubpAl
         3y8rhazBBHlPuqAoHFmOCyeVSrdViXovCMUPIzAfqSCKd8ixQhlwfPjBMvQAt58s67ae
         dwRpwFue6NEsnTFvitm0EWTl/cV6APW2aT0x+WHtXYII25KAb8xcpcJAtfgdUynbBGT7
         MYCX/49XGwOXX9kAo7TeGSwHNM9Qx3ECO8tjEeQ9BdBbr5m/n6OHLAfpRorqaIRqK7ar
         McRrcU6CX7PgBsTrJUemLO4MdFwtXOMBkyuQYby+TCCykacgg6obzsMAetmXzNPCOGAk
         H+tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n9Hg8/L/wr7RnygS3OokjP5227FjsrevJV37KK/fvWQ=;
        b=Ghm2zs5wVWx9FhqKxquHZUVS0LJrRLPtEaduRzdqenkpSdzYKpMVgAv4kBeVnrEMCg
         q1+XV5P7b024EY4Mi36+mnEAV2idrMzUn4SYgFR61gp3BMkcf3f1cJxHXrN29dAatp0A
         N5uO13hTG6db52aZ6gc+loXKsAieqfuZLAXQEbr9bwgzvQxxYsU3hzpH4u51u2hW0Uxy
         dMnl4u+7fK1uVYyYUbpT0NFR5kcRYwepObiTEbO6wwZMHhhVJVl92/lIu77IsQNpkDQp
         o9CT2Ui9sJPH2DWi6QgfniEg7LMwSoAcOSlDjUIz9YN9Qdlpxm8Z5RzKYwGYy/gd3DHI
         A9Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TH81aSeE;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id g15-20020adfd1ef000000b002040bf7c81csi75726wrd.7.2022.03.23.14.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Mar 2022 14:17:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id w25so3365083edi.11
        for <kasan-dev@googlegroups.com>; Wed, 23 Mar 2022 14:17:00 -0700 (PDT)
X-Received: by 2002:a05:6402:1cc1:b0:413:2b12:fc49 with SMTP id
 ds1-20020a0564021cc100b004132b12fc49mr2750389edb.118.1648070220127; Wed, 23
 Mar 2022 14:17:00 -0700 (PDT)
MIME-Version: 1.0
References: <20220211164246.410079-1-ribalda@chromium.org> <20220211164246.410079-5-ribalda@chromium.org>
In-Reply-To: <20220211164246.410079-5-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Mar 2022 17:16:49 -0400
Message-ID: <CAFd5g46fAbfgWdJD5Fcjn2v3nnQ0d_qXqQBZ_Cuk7WqRLnzEpQ@mail.gmail.com>
Subject: Re: [PATCH v6 5/6] mctp: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TH81aSeE;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Feb 11, 2022 at 11:42 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the PTR_EQ NULL checks wit the NULL macros. More idiomatic and
> specific.
>
> Acked-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46fAbfgWdJD5Fcjn2v3nnQ0d_qXqQBZ_Cuk7WqRLnzEpQ%40mail.gmail.com.
