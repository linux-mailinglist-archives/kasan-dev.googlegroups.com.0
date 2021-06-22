Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHEY2DAMGQEZHRIVLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C3313B00BE
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:48:57 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id 88-20020a9f21e10000b029027482b98ed8sf6205373uac.6
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 02:48:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624355336; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJt8waJvO/xrJloALs3YktGX5DcooaBRxJbS9oNqP5lh0JuSfzmOW8+IZTW2o4Vxa9
         W5O52LQoKMSE65iagffPggfi05AgRx219X5yqHVc2ZJFIZElSWrEuaxy9D1V2eSBdGQA
         CwlEnPIbp/HD2p9I8D91Y45iGMb/TOxz0QfZrV0t+bZYC6srwDxbZGLIvlRD+Hpl5gnr
         Xp1AgIxyAmoB3oLnZI6Xvyv1C9fUQRdAxrW8u0ZK9Eyu8/IOb+O8upJxDEVDB72vpqSJ
         hqnF9JFZ0bhoJNK+vqrSv5M+vu1glzWrv7gJHaanStPPJRxYBo2Ru+US5al18PqGZCbj
         6WoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lr3C4/IDveqM9CbU/Jq3c27LiUCMU6TsVZLEgHT/4kU=;
        b=KWjttZJryUT2KoSnw0k/oRlbmiDoqGiqLPzw9SVpcp2hra5WtY8rytCTCnOgVan6kE
         OY6LsA4KiRL3Nac1VqUSwk/a149DgIO7SIyztH28uVMO4s5GjQ6sDi8aO2B0idzj8+hS
         TlpN9291Xw70qffhes6RnraGGjBRJPJcKv8P+cASrNhMKBYrMr40vMwgsjyAhAFiAWN6
         R6EU9lGw62cWM93ulbKK/dEUia++8EjmvsyTpyidVpNb2qFfavsiUwiG8W4aHuZl6v9X
         t6tAbFd0xmSaCpwJ7WZlSlOfkNzsO4+OoDTYRXeQXmC547NMHqTmPlOVROoV5ATioqdS
         ZaDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BlLwkz0Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lr3C4/IDveqM9CbU/Jq3c27LiUCMU6TsVZLEgHT/4kU=;
        b=m8Oj4klCKn223MDv75wWcVOLkzKqt2OGJwP7WKpn4Qs0uZ2uoslsyNnjgcIPsrMtaL
         ndjz/E/Wt2XnlqQCfuFNjU0+twzwa+uyQG+RWw87VeZ9yh7H2MgMHD5eI+EbjmOIrE9o
         6wGyJxC4qDnYNQtRIuWbCEAuJeScFvNk6JPsPu0o1ym65iCdKsTzLyCnL/KWZbNUjGZS
         R8RZoI14MKswSTAz4qCmMDAx95PA+NNdFnLMbM4SjORPSODF3jRNBRXd2bZ7Udj79/gk
         f4PPVu2E1Hi4/Buj6ai/wYCE0t7hzGLxhg8/Z8TdA+RTVxV0Hr1elT5SEfssXVk4iP9A
         J1Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lr3C4/IDveqM9CbU/Jq3c27LiUCMU6TsVZLEgHT/4kU=;
        b=JtMMzknxyLbm6C+ODOiNea4582uVGJveEb5gtbP/6AIMlp23iBNzpKD89MV2iW5sbS
         NM6BYA4HxSzcHiE/bl6JFaE8KeDQv+2LgZL88ji9YEl2/2jNlAxYMh+8RXPhoabRfX4N
         NRpu6nakR4h0gKz0VDrH3c4Arwo6p3u1wBZZGFv432rVl43YUuLJyWPmFJskr/U1Kc18
         PVQGiAswyawmKLwCjwEOJ1OPinTwWg6LvO9SFfSHR+67CD0WF7PIgvCAgdRbU73a8c29
         Ka8eEtwGY4K6gW4cIBQSG0vohmI5yi3AHnRw4lb/LotaXkOlBPXNPNvSI5pA3OSFgwPd
         QD6g==
X-Gm-Message-State: AOAM5330tx0uKMUITSwSaek+GdUPZsec2U/qmq+G06hqS0Yp4Rv9DX1d
	pWJLyXhfNimK1Q6Zzks9h48=
X-Google-Smtp-Source: ABdhPJzwYwyB+bvbRPQtMRIQM9RYhwv6WZpTa7ABnlRVA6isLxTPbtZJhecdkmUGUGgtAuHcZuJeiw==
X-Received: by 2002:a9f:35e9:: with SMTP id u38mr2289308uad.131.1624355336297;
        Tue, 22 Jun 2021 02:48:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e9d5:: with SMTP id q21ls5120532vso.3.gmail; Tue, 22 Jun
 2021 02:48:55 -0700 (PDT)
X-Received: by 2002:a05:6102:3026:: with SMTP id v6mr11126817vsa.1.1624355335784;
        Tue, 22 Jun 2021 02:48:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624355335; cv=none;
        d=google.com; s=arc-20160816;
        b=XEAcsEVho5Ol2BHMtmcMVW33wf3mn2K6v0p/mbBQRiPvfmLj87mfydWntVDBVGpQcF
         I/194ZQcqqmAvf9aYplSmzmFg9V0mM/fsaQHkr+2J0N99fGV3l5hoV94XY2v0KT2e9Fe
         D5M73WO9tshh4l/Mr74uxKvjTvboBWuDclvvkG8nPf/wt4b/rTxEPcDMIWXhc4xj+96f
         F85osQMTehYjiUiDV2UDPwWwVN6HzmTEqTyGzDeYLj3tqh92v/FZ4AdBe+tAuOs5drdW
         IQXoRHtKvZ8FBMnrJdMW0OvGevjBT7lPZyaAQTTxepi6/eSSNDl8nEVCAU1MczwxSrGt
         /gQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nD+1l6o05xmy+VeXlqHaYhc8wOEE+zvUKMP+aUukBYM=;
        b=NsDpYnLjggH1iMN2ZQXuhcOa17iJXZPwMxmTBViLpDGmc9cxDgQ6ht2g/QPGMgD1kA
         UvxB2maBWgjMlGmcwJkHaJ9Q66bsUWSna8Zaf1UhCAK7hPY7wyGaGFZW+IxsfDxs8s7I
         bMwoE3g/jpmE4EI291DBLsk0VIAC9jP+ic3lzIEiVu2b4J6aXR7rpqoBeCIHifp8KDYq
         IP34VMsx6k+78SbvGAfeB2pzjEOR+629oEAvJ3/9v9QqdU2KO9AHK2nsor2il7EXpDcO
         PvWruul2sLKbIBkFW58kYjLlObfcC4jMnLYSQRQlQrLs+tMonvymG/KkQxpHnk44vuHg
         82Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BlLwkz0Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id t21si128343vkk.4.2021.06.22.02.48.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 02:48:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id w23-20020a9d5a970000b02903d0ef989477so20565572oth.9
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 02:48:55 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr2377707oto.17.1624355335059;
 Tue, 22 Jun 2021 02:48:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
 <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com> <CAG_fn=UTfR9yKrkdRDjxFn=vgR_B7kzytm9WDWT14Gh0PLXyJg@mail.gmail.com>
In-Reply-To: <CAG_fn=UTfR9yKrkdRDjxFn=vgR_B7kzytm9WDWT14Gh0PLXyJg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 11:48:43 +0200
Message-ID: <CANpmjNPdaXj0egTTX6CmJonNM2UgbQPqza5Ku9u+ariJ8CQx_Q@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Alexander Potapenko <glider@google.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BlLwkz0Q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Tue, 22 Jun 2021 at 11:28, Alexander Potapenko <glider@google.com> wrote:
>
> > diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> > new file mode 100644
> > index 000000000000..1cb872177904
> > --- /dev/null
> > +++ b/mm/kasan/report_tags.h
> Why don't you make it a C file instead?

Yes, good point. report_{hw,sw}_tags.c essentially define it, but it's
called by report.c code.

I think I suggested to make it a header first because there were still
parts that were report_{hw,sw}_tags.c specific, and the helper
function would be used by those 2 to build their version of
kasan_get_bug_type(), but that doesn't seem to be the case anymore.

> > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> If this function has to be in the header, it should be declared as
> static inline.
> But I don't think it has to be there in the first place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPdaXj0egTTX6CmJonNM2UgbQPqza5Ku9u%2BariJ8CQx_Q%40mail.gmail.com.
