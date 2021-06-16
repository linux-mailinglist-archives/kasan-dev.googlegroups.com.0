Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUAU6DAMGQE6GAEIFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F4683A95A3
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 11:12:07 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id b4-20020a920b040000b02901dc81bf7e72sf1266837ilf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 02:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623834726; cv=pass;
        d=google.com; s=arc-20160816;
        b=F4U3APilAkNwIWRt1JqBbXl8W772LG5vkKc0JCyAD+01bus0jHYFxI49Mr+ODGCzo/
         rjEuqtcL4VsNQImJE8qRPu3zyWoe9Si8wLDDpC+LDUMsj9IbQaPKfLmyycvimoSjkZxK
         Cm9vrFMMx0V37TgZGqRooA4pJ7nYu/cXZDDvkePDgDHL+T0yBAwut48hdP776PfYyxeQ
         0iWdeCqdY7I1LVzg7YbMkiJnhT4CH8/DXUv436mlx1jhUkt3Q+rHLz+GgF6kI00MPzf0
         ei66snDUwonEosjl8ao4QutIIs5KaVRc/ho6v9bMYTEWmGjigX1aQ3+k38Uyoxa51Iqz
         y18g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=654lv3xFyJ/P4StILGMTV8ZL5LoRtVGW9KSDDv5Se0w=;
        b=NKGL9A1etpgCCVmzrX70By3gcqve9pNY70LQy2qR1OT8ER4ONNIs+jI8RjNkPXTNLa
         oq5MBO74v2C+AMsE8NaM0mxE4YN7Y9tRYX58xY0/bFA9VbhlpzUHsXUOEtJoAvX2fiBa
         Nq+D0PIeA8TLBO+rJGVZw1NDZFHnhZbbtxABeQTl/QUsq+8J+RQsomMKn2+7e1mrHsvO
         WNA+XZfQqTnSKJiZiHq50V23yKFEzH3+z3pJwAbKmvpW4kIHNKeBVSLQ8hV1jUpdh4Ye
         QsA7UzwnR6S0txIVH/xu9o2jBFbagPrYTDr1MVflFXRzIiVxzjDV60JUp4dLM51x48iS
         Bnjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RElzJ2hc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=654lv3xFyJ/P4StILGMTV8ZL5LoRtVGW9KSDDv5Se0w=;
        b=XGnIz0ZeYhGm2UaZ7swSSjLN3pQcNJbmG2oK64OGE2q0O8VNbl2DMRpv/icQ+wGy57
         fC+GmALnummAAC4CkQXjsY/JsPafAWcPyVuEEz/xJWHW7Mxa8NpVb9kBC7zNgSOXBY8k
         8G4zJsxww16noD/UiHZZz92SPd2kzHURG0F8ma0FJh3Ro7taZXXkqNVXF4LHBQwdaomE
         iWeXv9aI2wJcSzZx3T30YazQTijcTiFr3XCrc+/xJBqSHXFC+NB+aO3thwEC1dSZJ2Sz
         9hCHKQ3nfTgbxA4T9WQtUNOfyWPQgtaNBjU2oTV05TPN+/R1AIXyDBBEFi0IYqq1Xj3o
         Clcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=654lv3xFyJ/P4StILGMTV8ZL5LoRtVGW9KSDDv5Se0w=;
        b=cPL3xoquRIyh22n+paKEBdxiA2NVFRKEefGq2DxDSvwo7rwO2paE0pHEC8l4fH/SQa
         +4+HxkvyEyRdkGkTi9WsKy1GxT7aGr75u/ug5dsRsIrJpT0xQssaUG/QpFOCqngmDcOt
         U29edL3jSoskezmtt6BM6miROeq2y1vlpOuYr5I/9NOEV/cWZQ+4/e1Kz5iqRx8J/f1K
         Pa73MmXSGLTRZhwCnF3dXRbth0HjNcpZRFwPrl0dDu3WVR2YgsLcraE9LVpZHu6Rn5Kj
         Py5BqVzUMkHuPtLrnrTdQnh2aE+awMPjjh41iuc9w0QqohRvYvs7lECYvnnRaRUgoOYO
         KhuQ==
X-Gm-Message-State: AOAM530he4rG140J9hdTVmb17K4s7OA3tTqDixjl0Mh77rIkBRtFe9te
	6Jrwqypjnz+4kp63wPJj96w=
X-Google-Smtp-Source: ABdhPJyMBeKkm/lWiAuAWGjY6jOZXr98eAc2tZClCba44twN0OPGxJOUXk67a9AIQiKkXzrxXdcWvw==
X-Received: by 2002:a05:6e02:1489:: with SMTP id n9mr2964774ilk.102.1623834726625;
        Wed, 16 Jun 2021 02:12:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:85e3:: with SMTP id d90ls264145jai.7.gmail; Wed, 16 Jun
 2021 02:12:06 -0700 (PDT)
X-Received: by 2002:a02:908a:: with SMTP id x10mr3233597jaf.30.1623834726306;
        Wed, 16 Jun 2021 02:12:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623834726; cv=none;
        d=google.com; s=arc-20160816;
        b=rBCBrz7l4EZFAwQ6tR/z1DiVl0BVztxU/Wm9WRYUkFIpTeEsOX6DIUsIr9BwfiyLWx
         R63MSgF93lpn588vwG09blnMU3aiZBZOw6AhS4wIH/ZLW3KwGL9Mg2uGXmL/+3SgqaV2
         g+a0i162M8cHE3U2e7MTkb9IPfK12uKQbWtkPtab1XGVTUhlev5coIsCv/jhPGNbdHZu
         RpmKebF7JOoRJsmEY0g/2elTtUlH81qoUZP+z5tGsTQLv7qYIV8OvTog8wlCPDcc1AAd
         w7dzWsj5l2SRsFj0rsiSNGk51YUEi6cWVfkyYys0a4IJyRLXzSNjHTMqk5fBXD9XLqAt
         DC9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zwXeE/T9A/OrTylBMfS7m9SAT845lCEQygKVQTKDO1g=;
        b=lN3/fkq6xV0D43uqXQ8xCkQ/GtYG335+2D5cyrwlvwuMpljOFo9vRiZuHkcag7/OBr
         E5/BbvP+h3/TWAl+tlJluuVTTSVDIgvywUZnfRnn/GF78adtyCDRHoapZUYfnzYu94zs
         AC7mcac4cfN0lU6Ze2kvP37KAt3B9x58xyMEXOtiCn5EaeO6c9CgLT01snX6CecyifV6
         lhltayhktQjMv2nS2d3nrVrJ1VDr5gKgLAPCMHacYgc+zDoNoXeG5vvGm6rPwcSM8HTN
         8XO2NDfhrDtxXqgVOhpXNzOPxSYQ4ryJy1I7O5NAn32xYO2VF5/ihX6NTfy0uvv2EYB2
         kwyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RElzJ2hc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc31.google.com (mail-oo1-xc31.google.com. [2607:f8b0:4864:20::c31])
        by gmr-mx.google.com with ESMTPS id x5si97614ilu.0.2021.06.16.02.12.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 02:12:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) client-ip=2607:f8b0:4864:20::c31;
Received: by mail-oo1-xc31.google.com with SMTP id y18-20020a4ae7120000b02902496b7708cfso499154oou.9
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 02:12:06 -0700 (PDT)
X-Received: by 2002:a4a:6049:: with SMTP id t9mr3118549oof.14.1623834725852;
 Wed, 16 Jun 2021 02:12:05 -0700 (PDT)
MIME-Version: 1.0
References: <20210615030734.2465923-1-liushixin2@huawei.com>
In-Reply-To: <20210615030734.2465923-1-liushixin2@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jun 2021 11:11:53 +0200
Message-ID: <CANpmjNMh9ef30N6LfTrKaAVFR5iKPt_pkKr9p4Ly=-BD7GbTQQ@mail.gmail.com>
Subject: Re: [PATCH -next v2] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Palmer Dabbelt <palmerdabbelt@google.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RElzJ2hc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as
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

On Tue, 15 Jun 2021 at 04:35, Liu Shixin <liushixin2@huawei.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the riscv64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped at
> page granularity.
>
> Testing this patch using the testcases in kfence_test.c and all passed.
>
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
> Acked-by: Marco Elver <elver@google.com>
> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>

I can't see this in -next yet. It would be nice if riscv64 could get
KFENCE support.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMh9ef30N6LfTrKaAVFR5iKPt_pkKr9p4Ly%3D-BD7GbTQQ%40mail.gmail.com.
