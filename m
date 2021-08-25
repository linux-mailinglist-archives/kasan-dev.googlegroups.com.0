Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUNGTCEQMGQEZ7YXZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3705E3F7256
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:54:26 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id u5-20020a4a97050000b029026a71f65966sf13621872ooi.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629885265; cv=pass;
        d=google.com; s=arc-20160816;
        b=YaB0TozeCeq/bWO0RUgN0SlfsLgnXYNG6A8Oa9r5hj5UhYpxN6nRsXeuVYqsIwTRFc
         eQ0K+74YM4tPWRx48mjl1ZGkEIWITv36YXJHLRwmKk+FMbN6Wo+JEB8WKywrj0zS/Ryk
         CQsVH+6jgIkpvA38SlKjXKf50FVYvLZ2mEeubQXirVzFy+1FMPCm/vlAQAI0k4qrBuV4
         WqhUeiw4UbuGnERQheiLOjdt23rjlgF57l+WlOM5crHG308lqDemVt97kJMEqv9qVbGl
         CK6RMuNUJ0bFHOo4s110U6FN1/arwkGohyemNTHDcpChpNRd46wQnGF3jMGWOOuljkWf
         ZvkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jo27NIC+Ymolwl33a2hBIkkYgmGgjCm5qOnP3wBiNWs=;
        b=KSVLlovXXmEjWfOuIe7NFdBpq+SoiZKEPV6hPTJkJ7zyVGR6pvK1mwerXssQI0ks5P
         d8bsAViHVFuJ3UzIksCH4Vd+uggTpzlFLwYY68n6Xl3n2jNzLpNK+NlY9m7KJOIJ6JZB
         R+6OeA1VjIXIj+kd+tflUAz1SsN4o/23BhJV7KaOAUj5aiIfWoXjY/emMWP+r6I+lSdR
         6HpLh47krKwSYJvZoDs63tlmZupImekoPbEPisUb66ruEk1CsE7klHKwEoZ2PR5qsMBM
         4LSEfm+/cVe4murfsbj1I8mo6YmqO4IGp5tCXUJq3N7fL1dTDkNxgoCspnFxln6piEUg
         4Isg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdYoLhyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jo27NIC+Ymolwl33a2hBIkkYgmGgjCm5qOnP3wBiNWs=;
        b=rLmAkg7ak4JA78YnxaHB065qOn7bdbQny/TDOIX6d77rmb750C9JPsWwLCQAFNl/AM
         Zf5qHEbUZ/YX9DI0Iz3Iv9n5SaNKhv3VqcRVikxoTxmA5MONQKPQwykFHuHlHK90M4/o
         zQTcDeWnaBgyGpTaAh71E66CY/V80QymaVlHCy8q4esjzQl0jz4hAFlLmTw7F5GjMYhf
         VE21gngAhfwBzuNSPYei8hTMeVBk3Jj9wdKZMvowyC86VqzDKyTmqokhxXZSLplLDGXf
         dUY2pOPHpIO6wJFvyOhIzy8Hm027jfJtpVNw610cfiU/b1Ck7YfeYL6jBr7IDvJoDTH3
         UXUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jo27NIC+Ymolwl33a2hBIkkYgmGgjCm5qOnP3wBiNWs=;
        b=N9cQPZEg1LaRM8E381r8s/MYQG7dWVi0Ew2XIx0O0B24ld+fo4J/A8vbsvoRr5R4be
         ek70wtPfKgM1w3t9hoo/Fbvqwm0HH5VGDzYYoP0jXAoKLelSraWme/2byxc+SwEPqTOE
         /RIatEsF9QQYZRftsOPnKD5y0dUEFdBKo5MQn+JIMARVhDcqNabJ+M8eGE3MqPuWvPhs
         RIc3IO33FOPUhK6dB2XPCEMUxPpLB2F8ZvUrFbkzoc2eW/XDUjLrEmK7tiC+EYwRBi3Y
         14Qupb8mJYIPXdFYprWw1RL1OEXuy/2Ef+Rhu4I085Z5Pix6o3w7W4TA9SX5avynePOI
         lxvA==
X-Gm-Message-State: AOAM530ukJ8l0VbKVhwJ8mrvl/jlUS3H9keQWSxMr16T5907TNLkOvxc
	9Qm56xEhJq3yWmnIs0h/N4U=
X-Google-Smtp-Source: ABdhPJyTAiE74zJY7nRG0PeLTyKCj01hPYWMPCsITSsL2cN+cEN4qjp4AmtX5P/xtr1R1qG+aeDhbg==
X-Received: by 2002:a05:6830:1657:: with SMTP id h23mr27039715otr.315.1629885265149;
        Wed, 25 Aug 2021 02:54:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66c4:: with SMTP id t4ls406804otm.5.gmail; Wed, 25 Aug
 2021 02:54:24 -0700 (PDT)
X-Received: by 2002:a05:6830:158b:: with SMTP id i11mr12966286otr.79.1629885264774;
        Wed, 25 Aug 2021 02:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629885264; cv=none;
        d=google.com; s=arc-20160816;
        b=XP+mp+M8jFMhasrOAZbGXoijdvxJ3etisc5DB7TDhiGSZsWcimreyB6rSm/NHW7spj
         tp3I37Xw2nay7/0nV0hpIIU2Yzz8NAuTitP/oTMPVUBLmUyZVdcEmSD4Z4/JCcD/HMx6
         Ip1pPdTpewzKFHO7+nbFA0WK/97MPGMu/ar7hqnwAb3yjQv5rFlwqouIvJRcruNe8iw+
         CpgmN6wcFnfWEp8MojnM5fI05Uoy2GgwxGwjDe+iGKTsRm8idx1+xritDGoE/FzdC+cX
         j3SeZ5vkoY1EZS4pO1fnxXW8+LYxK2GjOyjvNmZoDdwTaOGYihBZXVBVQpCUjhkezA02
         Tn8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u292+T+PmNvvzzkHWgQqQyq2ET9S9Sd8vOWw3NIaxU8=;
        b=x6E/eNoVlF0Ywojnj8wGrXNWogm3elPl9KDsWLKljNyf6aVm+WFlIYS3B5upLuseka
         T27BMamVZl5A2zF8uTVCYmjwBkiQI2y5zCitwuGbTeO69naA1Hf3xDDMC4EljLhd8aMf
         KuWWvZkMNG92lIbrwUZZdMowsL45VHN3Ms5dAgn7U7V5A9Dk7DGG7rfs9hgIe/cdwcDQ
         9DVr1h1PZOLcvxKxYSX4o8drt2SiBu7o81WEQyI38xVIUP/W8CVgBnU5IPjjp+fVqiap
         OCjy0RNHGyBstUQvJBBoxLLrV8ktlM41Hdb5nEzIpNzlI+U+gb0jn4GOYWKWQwtGkZ2z
         UrFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdYoLhyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id p6si180466oto.0.2021.08.25.02.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id c19-20020a9d6153000000b0051829acbfc7so53979677otk.9
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 02:54:24 -0700 (PDT)
X-Received: by 2002:a05:6830:88:: with SMTP id a8mr36303165oto.233.1629885264254;
 Wed, 25 Aug 2021 02:54:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <20210825092116.149975-5-wangkefeng.wang@huawei.com> <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
In-Reply-To: <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Aug 2021 11:54:12 +0200
Message-ID: <CANpmjNN4=ckdTcSKJNurmW3BNyU-V4QTJbR0cm4s-whW3ykRHw@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm: kfence: Only load kfence_test when kfence is enabled
To: Alexander Potapenko <glider@google.com>
Cc: Kefeng Wang <wangkefeng.wang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fdYoLhyA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Wed, 25 Aug 2021 at 11:31, Alexander Potapenko <glider@google.com> wrote:
> On Wed, Aug 25, 2021 at 11:17 AM Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> >
> > Provide kfence_is_enabled() helper, only load kfence_test module
> > when kfence is enabled.
>
> What's wrong with the current behavior?
> I think we need at least some way to tell the developer that KFENCE
> does not work, and a failing test seems to be the perfect one.

Like Alex said, this is working as intended. The KFENCE test verifies
that everything is working as expected, *including* that KFENCE was
enabled, and has already helped us identify issues where we expected
it to be enabled! Trying to run the test when KFENCE was intentionally
disabled is therefore not a useful usecase.

Please drop this patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4%3DckdTcSKJNurmW3BNyU-V4QTJbR0cm4s-whW3ykRHw%40mail.gmail.com.
