Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEKRGNQMGQEHXDFL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 090806160BD
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 11:23:22 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id b13-20020ab0140d000000b003e39e1390f9sf7559275uae.18
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 03:23:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667384600; cv=pass;
        d=google.com; s=arc-20160816;
        b=LdFZmu06jy1O32G9bWtO0VIvZLF+fnyYQWJyYiv875nUlYbX3tq97GKeCT30NvuULf
         QAxVhhAoKu6246OzV1VgKexZ9tbF1CaxwjJxjY4NiOXTsKl+5bXx9h0v3rhlk/Od00+S
         n/vWR1ZM3IAiokZ0V45q1iIT/f43mYVeX1cQqm951JfUdu8IB5g19RG7y0H1j5iruAvP
         XmH0Gw5s0OXv8U/L98dQeTI/OnR4gTGEPger+ezPwK14AUcGIoOd9sUCBt9iYsR3nD1P
         vrJw1HuqqmChk3b1/eDV/jNC1a94TY4KgmKiPq97FHFIExAlyqY1MQgWVeYaUAh3cYMY
         gqZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tatjpVwYCF5krezsnLrdyWb17sC2yEmffnTR83Qg7Ks=;
        b=OBt9tlLKjNVHSz9toIQ9pNXqo5wFGEKwmLW7lSr5Ku8Gp1tZ/4+vUjkVeZX6QT2TNL
         eX6uCv1SQyRpR/v6B1bADJkYXa+9zSV2zcNbm4QeMcBkx2n9vmdu68tgnvv8znMklvr1
         h+KkBjXQ7vaCvhiMPBtTAe2oPlS6R1iPBTx4tY4feuLoFUU7uIZhHtHhDdPFJDZDUOrp
         VkkcsVIwKb4J4E4oeGmhH500LpxffeckmQUrL+sDBPMOlxGM7wdOhke/znNqu404+x4E
         VS/MZ+92MM+BZvJ+RsKkNT2knnvXOg465wQ4uQJU7jh6GM3tdWzQp3zkI/pqfGLS5111
         ML9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NPdjisJ5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tatjpVwYCF5krezsnLrdyWb17sC2yEmffnTR83Qg7Ks=;
        b=YqMVy8nXRw/3a2Xnzo2sjGiz+dv+gfPkQkq7+3HMuj+fyZMp6wVr7NdEVNamuv0L5k
         kIqVcJIaMqxUcoAc9//YqIxN+5XOUpbjfxBDqcDvDngd7UtKzjm1uscaab3WgG4hdUWG
         b3nGFuo9AnC2lf41LWJ1QZY/fQnWA+Olrul+UwevaUm4NoXf+B+KOLlF0EQhrubnj/ps
         upMtOdg7ezjlW50tUq0MhUfVgilO6d3obHPdSqLbarEyX05c7PJhYDnI6nkix562VIWX
         JWbHDqqDjHkGbTZZSrd2dVv8J6tVlCCKZmNfi2Vb4j0jFlsO9RPaelkBAT3KlPfxAt3T
         7e5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tatjpVwYCF5krezsnLrdyWb17sC2yEmffnTR83Qg7Ks=;
        b=QH2TbvYSyvCzECVVNCGugwz25D8GlXgDCHXlCEDBqKDu8Tum29LSZweGM3KvOrqkH1
         2d+mb9Wvio+gH1Cs9M2jmoyu3kMy/6as6DeS6P0I/jEu7GeMCgf5H0MEOif12zLUpnX0
         /AZMBX0VNZLvPDZIOY3S8QDamCOHbjm/DpxMgFRW4K7e6mkdTYf2mOlIGqTk1gjdtu1W
         n9t4aaf2W1H48Mu3du0iIiV47G+UWOf1VJ4awZA7wz9A5lKQtxhrsqEg0eLVFMGYcHeh
         ijOvMWqJBtaIbj8DZqzlzpzTuG6MzZ3dUkQ3FNJYqnx4YShUQx2qBBebFqKxKbfRDYUk
         AAWQ==
X-Gm-Message-State: ACrzQf2hIn4iITrk+lqjjUptQeNVgmK43CFXyuXENrmNBZA2Jt/W0gSp
	+20UmsJjIpPrQgC/DBs77yo=
X-Google-Smtp-Source: AMsMyM40/maumPm1ixZ19rbv3IE3dildor+84TdLaFGv/XXjXi8be5iJd9NhCX0K9b9iM6wHMnVfaQ==
X-Received: by 2002:ab0:6cae:0:b0:411:7409:fef with SMTP id j14-20020ab06cae000000b0041174090fefmr4860571uaa.91.1667384600818;
        Wed, 02 Nov 2022 03:23:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d38c:0:b0:3aa:190a:9431 with SMTP id b12-20020a67d38c000000b003aa190a9431ls3105646vsj.4.-pod-prod-gmail;
 Wed, 02 Nov 2022 03:23:20 -0700 (PDT)
X-Received: by 2002:a67:ed8e:0:b0:3aa:4fb:8ebd with SMTP id d14-20020a67ed8e000000b003aa04fb8ebdmr12146647vsp.23.1667384600133;
        Wed, 02 Nov 2022 03:23:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667384600; cv=none;
        d=google.com; s=arc-20160816;
        b=RZDHdt7NQd9hWTtacNmOv3qnis6Yuq4NQXJLncASXwLWWpKkofweIdpndyVCXdhHNM
         xjLTPOvUDlg9yiSNxS+ncYw1N1hJW455f+Qc5b85WZ04gTjDZu3JN1d4GUEvCJa8OPCi
         jBARp4BB4H2o2fU7XhJc6+OI6mJJXzlvd4vBvtgpjOQl33lgEQTaAv+Nlay4DE/MOTSa
         mPVm362mIdAFzwd2lMh1fxKppsIadUcOKE5idjFYgeLUCclN3xQYXZNmMS/1fkJzhQBb
         12RvojH9rW8Ef4q2ultQ0V4ZRhbZy4Cr0xa/YwiWgxsn6/+IpJ0qFAjGlprU2mNcBXmh
         AzBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BafOkd8SvWuco2I/Z6NsmvGa0Z/TQs4XgUWd22MNZzc=;
        b=FAhZrwl4z3eJWRqsZUdOLgNJj2oXOfWcQUkNAwjlkxzoewHHiwjaxknu/zzXZHrI8p
         dgu7ddqatIdC3XAMINGSheazVp8Ln7jhGOKICCXtkkShLWOK+OhqOWI5VeN2NnPuCkpa
         tb6R4/D3NoHMI1RcoT18qLeuOcmlCv9RpD8pgXS2rV1TRRxnbmf+v3Ip3PlxImF8QCU3
         qnMNd1jG6wCOJVUmBXoYpXBuxRtnCBLWdK0Rdq67SHCrYmeaqw9OKoqDTtVUnI1XOlof
         JrxHOZfY5w30F/cMtI9GwJ5hcxuSalLKNc11qAxFPE6pGw7ZL9+xdWCMYghVEnMFXIMp
         KzXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NPdjisJ5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id h185-20020a1f21c2000000b003b87d0d4e7bsi26664vkh.1.2022.11.02.03.23.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Nov 2022 03:23:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-370547b8ca0so82025937b3.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Nov 2022 03:23:20 -0700 (PDT)
X-Received: by 2002:a81:a04a:0:b0:369:1030:fbd3 with SMTP id
 x71-20020a81a04a000000b003691030fbd3mr22760635ywg.465.1667384599743; Wed, 02
 Nov 2022 03:23:19 -0700 (PDT)
MIME-Version: 1.0
References: <20221026141040.1609203-1-davidgow@google.com> <CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ=w@mail.gmail.com>
In-Reply-To: <CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ=w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Nov 2022 11:22:43 +0100
Message-ID: <CANpmjNOgADdGqze9ZA-o8cb6=isYfE3tEBf1HhwtwJkFJqNe=w@mail.gmail.com>
Subject: Re: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies unmet
To: Daniel Latypov <dlatypov@google.com>
Cc: David Gow <davidgow@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NPdjisJ5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
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

Hi David, Daniel,

On Wed, 26 Oct 2022 at 20:31, Daniel Latypov <dlatypov@google.com> wrote:
[...]
> > -               return -EINVAL;
> > +               kunit_skip(test, "not enough cpus");
>
> The only minor nit I have is that I'd personally prefer something like
>   kunit_skip(test, "need >=2 cpus");
> since that makes it clearer
> a) that we must only have 1 CPU by default
> b) roughly how one might address this.
>
> Note: b) is a bit more complicated than I would like. The final
> command is something like
> $ ./tools/testing/kunit/kunit.py run --arch x86_64 --qemu_args='-smp
> 2' --kconfig_add='CONFIG_SMP=y'
>
> But that's orthogonal to this patch.

Was there going to be a v2 to address (a), or is this patch ready to
be picked up?

I assume (unless I hear otherwise), this patch shall also go through -tip?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOgADdGqze9ZA-o8cb6%3DisYfE3tEBf1HhwtwJkFJqNe%3Dw%40mail.gmail.com.
