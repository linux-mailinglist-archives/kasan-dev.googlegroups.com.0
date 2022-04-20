Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUFAQKJQMGQE7VSH3TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 181AE509341
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 00:59:30 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-e2d0cb6766sf1426610fac.7
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 15:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650495568; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrPwx8VOF+M5cS4dWNdWdBbDreNtYwiC8tx2jt/O8fqA3ta7qdARHo7wcrCISyfhEb
         S2ybILCfOgp402hT3SxtL1jFmCn47QG/q+72qlgk233dO3uPL01hdBbbsqY6e9vq8dn4
         hZWUUOJlHGmAakuEScf2OKFftmbjSoaMU8afhfWyFmn6+TfAqzhecgnLB+35OCQbLjyb
         WSY0xFmiEhwtr1vCOmfAJZAvdM2uWrgvJOi1hcCeWh3K0uJsiVbvfg0/tXH+4pCmPSZR
         buQQihUj+ulQdcC86HxrYSxYeim6+tZ52xETB6LcqDKWhsiOuMnL1MrEiwwvxFrjxRCz
         r77g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VU0KDcgHYqQy9CQNIFHcMnMB1OhIlgs6R9EE5/aRgS4=;
        b=obRvDM97NVp3CXzJCBD/X2Pvv21zrnnbQI/oSyczXEqu6SQ6I6DCItRzwMGi/K4IEu
         Kaks/FnVbi6V9NEKkVH1KMuqkY2Q/oWfaM5qHSP3xWxa4JGWIv1FJchstU+fDFQNWqhS
         pVpsVWK8ub6jWTLHat450/oMnTitlJfW0NbaDFv19V/nRk1M5/JwQVIs7KDNA4njMLjf
         9JCwEiO0FiyrLSlXqBC3rowd8IYj99F01w7hMwCI5uHXn9OhsHa0QCHN7ISYhcqEc6x4
         UadEJoTFl2kY6peCilpioonKe0IJLzwL0DhzeuczGe2DoCNHKsH7vVY3288+VBjU8Cff
         gV3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=blu42ize;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VU0KDcgHYqQy9CQNIFHcMnMB1OhIlgs6R9EE5/aRgS4=;
        b=ZCaXUoa7TCLXCBZ19rPHcetwn9+aFyZrLaOzfQEzQYFabZJoZBxrjLJdKItnUnE0Ui
         aFnxk475cLocpNH8ovjy7azatkpb/rp0nhgpG54exnBqPS5ZKTo+oIf6fGjmCdYj+zAw
         Sbq2KnghlJud1g/fbgZJiQQ/51Ds5q/NXRdy9iaZam8YWk5cmv1LwwKbYN7V3PKQ0aiZ
         2KvAGpBTG3kEC0CEvREGZyLoeFrS7SqJNNNI9OBi72gVJ1u0rvYbXPnSj6eFA2uCPYjl
         OuHy6lWGV4tXOOIchao7aZZ1T/yPTtHqRXf35o6MbRQ1b//rONzQd+KWWovIl8rx5xgX
         /5pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VU0KDcgHYqQy9CQNIFHcMnMB1OhIlgs6R9EE5/aRgS4=;
        b=ZZ1bl1g9dKkeKCc0Mvlh6wPNjbVICWMQU+6GWekQ6tOAY4vWqex7mPHGGgpxOdxK7j
         s1oyTVtTALkUT1rVRo1ZaBeShEicp0mBmdI7m11V1p/95aJ+10Rlm9rxbBXnz1Qb+P5X
         IVppQ4VIuBlNvq0KRWv74IRACBWo+isoAzQ4xE3I3JlcZStSxclArgVu23olIEBjOZFp
         I4TrXmhV6V8zM+tlVPOaNepiICcFSXQa9xkme4+c+7Sy6U2oB4hjvaiCbxTrtXBSCnwH
         hXYqDsFhB/JPmrwe9vBK61+5o4rEnSzhv0HqM3qVNOB9txpYaGrntRHr727FqAFArhpt
         YdtA==
X-Gm-Message-State: AOAM532cQ5Q1rVDfe1Dz42nU/um4E+Ctwlsuuh0P6DDGGLV/zFFvmwVe
	aGcR4x0gSl/LcbP6RLFKHXs=
X-Google-Smtp-Source: ABdhPJyyxcHdI09yHn3Sw2U2BFNVQq+Q673FiSc2oI/lku+Of/pOmbyNzM4sdwViiny1/j8+27pc3Q==
X-Received: by 2002:aca:5b45:0:b0:2fa:7d3b:6997 with SMTP id p66-20020aca5b45000000b002fa7d3b6997mr2745980oib.258.1650495568566;
        Wed, 20 Apr 2022 15:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c145:b0:e6:6ee9:6279 with SMTP id
 g5-20020a056870c14500b000e66ee96279ls386253oad.1.gmail; Wed, 20 Apr 2022
 15:59:28 -0700 (PDT)
X-Received: by 2002:a05:6871:28c:b0:e5:cc9b:52b with SMTP id i12-20020a056871028c00b000e5cc9b052bmr2590611oae.139.1650495568126;
        Wed, 20 Apr 2022 15:59:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650495568; cv=none;
        d=google.com; s=arc-20160816;
        b=am0X9D8S53XF5Dw+R+ToaxnLTdisc42T+Qe7VOjekCdXdVN/1rc8fsSpNf2gwx76//
         Cj8J/PasIMgT7lIYZHDHNNZ0zI0EXNMsyugb4h/AXtBYs/uN0c64U6dVtMtmvsh6tL/d
         +4Z0LkODg8NcLHPXhbgMgMK8zExuV0uFBrPC+BjjUCMJy0fR9BN0zOZWj/q8iVbLWYcP
         SvulMoSoy8lWk3FVcrour/M6l1K4U1ax47GdZsOQXR2C5E3eGPWQOoV6pLOWaN1ErQac
         /1GBfGVTFqltDwbASLPCS+CrFHfCknqTQ+xff1goDUzAi/aiYxrOSEN/CD/8iyS/Ah4v
         UyzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Jt59HgPlqQAbr+xBdeeNro2Km6rxUizJSG+/mwm8z3E=;
        b=FmWk+cW9pwqLl11aUA4cKkKW6JiVdnXa3RcBrq2CqAckA+E/WJ30Ulz1z3HZLJ8RHP
         nYl3C0DBaf0O6A1fV/UI7GAJML6xz5kATq7fQAxot8bD0qSqwqKHRX5qdUULygxLbme6
         PxtY1/PPcb+VCYUsbAR2bNIVpk7N2lS+2UBPPtJ0nVa5VROLfI5pSE9rK2nRKPHBS4Cg
         7QkztZq9itvmefjGw778XIIBGSSXNa0Xq1PhgrRJ8TvPDBNFiYVfLnXt4UoEZwwnwB5I
         Gjpt0Qt69GLkOy9iS/YA0dLw/Y5qLzYIMnfSCSi0CruT0h4RL9RtBevwBPEkQkGdBINE
         IlAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=blu42ize;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id r41-20020a056870582900b000e217d47668si90862oap.5.2022.04.20.15.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Apr 2022 15:59:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-2ebf4b91212so34426437b3.8
        for <kasan-dev@googlegroups.com>; Wed, 20 Apr 2022 15:59:28 -0700 (PDT)
X-Received: by 2002:a81:1cd5:0:b0:2f4:c3fc:2174 with SMTP id
 c204-20020a811cd5000000b002f4c3fc2174mr4041623ywc.512.1650495567045; Wed, 20
 Apr 2022 15:59:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220416081355.2155050-1-jcmvbkbc@gmail.com> <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
 <CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX+RYvO1yft_K4hyLQ@mail.gmail.com>
 <Yl/Mh4gjG1hYW2nA@elver.google.com> <CAMo8BfLANCoLa4zXO4aYmX0Wk7fV7_wei04MveLHu=d2RDZ77w@mail.gmail.com>
In-Reply-To: <CAMo8BfLANCoLa4zXO4aYmX0Wk7fV7_wei04MveLHu=d2RDZ77w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 00:58:50 +0200
Message-ID: <CANpmjNO1WDCgv_cPVMKe3G31Kwqtbg__QqpsotkkVFY-5U2y6A@mail.gmail.com>
Subject: Re: [PATCH] xtensa: enable KCSAN
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: "open list:TENSILICA XTENSA PORT (xtensa)" <linux-xtensa@linux-xtensa.org>, Chris Zankel <chris@zankel.net>, 
	LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=blu42ize;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
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

On Wed, 20 Apr 2022 at 20:11, Max Filippov <jcmvbkbc@gmail.com> wrote:

> > Each test case is run with varying number of threads - am I correctly
> > inferring that out of all test cases, usually only one such run failed,
> > and runs with different number of threads (of the same test case)
> > succeeded?
>
> For most of the failures -- yes.
> For the test_missing_barrier and test_atomic_builtins_missing_barrier
> on the hardware it was the opposite: only one subtest succeeded while
> all others failed. Does it mean that the xtensa memory model is
> insufficiently weak?

No - KCSAN's weak memory modeling and detection of missing barriers
doesn't care what the HW does, it only approximates the LKMM. If the
test_barrier_nothreads case passed, there's nothing wrong with barrier
instrumentation. Regarding the test case failures, if at least 1
passed I'm guessing it's just flaky (not enough concurrency, or
unexpected barriers due to too many interrupts which can happen if we
enter the scheduler).

Unfortunately I don't know xtensa and if this is normal, but modulo
flakiness, I think it's fine. (I've made a note to try and deflake the
test if I can find time to try the xtensa version.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO1WDCgv_cPVMKe3G31Kwqtbg__QqpsotkkVFY-5U2y6A%40mail.gmail.com.
