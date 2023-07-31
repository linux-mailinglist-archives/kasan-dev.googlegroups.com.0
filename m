Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWGST6TAMGQEHOW2Q5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E3E6769D95
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:03:22 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3491f5c3fabsf34235ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 10:03:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690823001; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZ/Trm7solX2Zb+yuhrAiPV8RBWeQMyRhIY1V/bgU1T1hS7eQeKQTBDSgmbutYczD5
         obkew8eKQQfB3qA8i7SR1sZYgdjnMn6NqU+QoDMH6v6YCPEJvL2NI1U7dvLmKNnA83Nb
         Ari9XBkcbtxlMW2JCCrXEZA0yfpS/PERmVF4yWwDAGzlSKJI+gk0vNapJlKIUxPtUKGZ
         kXm7V/LcJozM56NoJTE9xuT81betMUOjTxIb9CpRlcl/zbmVnZhA06Us131j+eP69jzK
         Go6m0YjcaJVBPj+mY54lw2ywPp8PdYduGH/XeqQLVELpHWRVLJMggK8s73mneJE5ciGi
         zKJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tJnPifpXgvFIK1VQkTFelPiZ7DjQ+Sb/HBmpBK1Aq44=;
        fh=FpmOSBwjI87+MAeyVxOnHPZs0VsW7pD6MuuYSDRIGhM=;
        b=fWRABXeIVA2IedlyLpT+o527IGCotZi7TuIJnY0DX6+hJNmXGoY229yLgGRvpeAZI+
         9Jw8iz5U9oc4+0YRQm/WMxojJ+/C9AG8UQF6WHAY7jW6fudjHNMD6N2QnJTlBWpsGdsK
         TFXmicxBP4qTddezdPd6ZHeQwWK3iJLsvah17W4BRLxNUtTPSC7XLfBMD5EPCW1CJRna
         bjPjocD2dqn9/1v3M0CUIbeZTNnK0w83yLxOFIs7byEcXJqzczgdpo1WpmX5cs85LW2v
         5TNG9BSnaAT/ZqPezNtfFsgzKrtXWcIdbUIyrl2WLh7Ba90bPt/gJWlsOjLDeTfBfo+K
         dMWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CuRZBemx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690823001; x=1691427801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tJnPifpXgvFIK1VQkTFelPiZ7DjQ+Sb/HBmpBK1Aq44=;
        b=bIdwA8AsBXBK914Rv3HogOLbNr1LTmW5y/XWGVg2zkPgHjlsmY3sECKhm4fv+eGRiA
         KyExTvZT//C0zYsE2VfZhUXP0bh+STLM19ErRc+mwvKyxMhYNqL16POyvspS242E7Lss
         6Qpq1MmIH3ZP755nEumcIwaBxlHZUgq03vui/uyBsan7eBLeD8+IVKOzuyYodCJyTzBB
         m6gxB1hcmYNvrQQ1OLYS0Ni9/HMMqnD3Q9E5utpYNxDsI4W/zW+YMTwp/XmKASuxur6i
         hXe7OPJgmcvqg0styXvYorkpuSEaGqjXNH/beKVd7gQh2QPN6dGfx/ryqLV7XoFu7DGC
         XBsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690823001; x=1691427801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tJnPifpXgvFIK1VQkTFelPiZ7DjQ+Sb/HBmpBK1Aq44=;
        b=LSbUd1Ew7sK8Atq4kV5IoHoYnF/FiBpwSwwSY5vV3olzsW2QZaxnaND6cHJH1P8Pyb
         Jbd0ZV8Zq1Oa7mMWsB3/t33qufUyBclUbmyUB7i8CWrJY1YZ8UY6E/7kJkCDYmjtBrBX
         tHPuAbImBNOJtpqbwWX+o5r93AJ62SBkdfzMXEzPWwYsdgqOMYeX1fX39nX7LPZCuN0D
         FA0heQbIX7LgI/c6isdGJNuCFJaWEQO76xq4XboJcy6h6k0ZQVUv7V/+Cxd2K8z6y728
         M6qCl1awoPSoNbFnr4rSwPVy0R6ST6/ESvH2fs/vTidTehfaVx2dwbqiYx8Ng1Tv3W1S
         rCdw==
X-Gm-Message-State: ABy/qLY0v+gBXhXs/6tyd+Qes+VyS0Gojjq/tca+lnY2nCYcWTjy4mJa
	dqk7BKA0WviegUx3+/9CVUI=
X-Google-Smtp-Source: APBJJlEpXAviImxIolHxHWu7Z+t0/wXOnEEAdstNlwIRzPswHQUR83VcpdnTMLUnawXSwx+qcIuPxA==
X-Received: by 2002:a05:6e02:218e:b0:32f:7715:4482 with SMTP id j14-20020a056e02218e00b0032f77154482mr561677ila.4.1690823000952;
        Mon, 31 Jul 2023 10:03:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:468c:b0:1bb:933b:e6ae with SMTP id
 a12-20020a056870468c00b001bb933be6aels412638oap.2.-pod-prod-03-us; Mon, 31
 Jul 2023 10:03:20 -0700 (PDT)
X-Received: by 2002:a05:6870:b48b:b0:1bb:8d8f:9c6e with SMTP id y11-20020a056870b48b00b001bb8d8f9c6emr13695599oap.10.1690823000283;
        Mon, 31 Jul 2023 10:03:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690823000; cv=none;
        d=google.com; s=arc-20160816;
        b=U8LcxrdA+DNcBoFQGfvyAG+ijBKRTWYJLK5xviPSO+kuBl+9n9+2N1HFI2PKaDsZQ4
         01KxfNgQqwMxQ3jdALhzLtMlhPWGYxITcuwe4+kK1Pwa2n/j5zY/RPU/rdK8FgFm3A/d
         CwTe7VwWcvhzSShLI7MMC47ZJ4ZzxnhKM7p5WoxTloHRfCktTFhoNB9ovuYR7G0hFm9X
         mOCo8GHpRJgvA6qibmRRyabkMcU8xlF9yDXA4ki9VxOrtPyKo3Whu/eE2vG1pZE+KB3r
         fR5tQo9N789uAgFvGV+UgzAcXfhi1JH6tf7U+af6TxLYvcs98L881y/Z/n2B5tX4+KDl
         blkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=D3We0Pjfeto6x+8/3+vWSKZAky3jpjh0KVMoTtJoMJk=;
        fh=/L/BfydENXJ5eWZhj6DuxRELOnbBRK5NL0Fx2I2Ns/k=;
        b=LcgMDxMHj/gxrXjeiPkk+0SMWoAp3EtwbtWAAt/THZoddJJ4xPXLqFY4L55z9A/GL9
         llmqSPUcQJbP9NQFk2VoAXGlmuYstP0A27TN/pR1vnTw6iwua1au6O+cYsk1g2c8U3MQ
         i6OhjiSs6RJcT2OWzd20ZVknm3I0q/dREWNp2u2ZNKndYLwyUejtYhkryH9fvVoKqQMr
         4aMfEwyftJHXaZY2Z0WaqN4QoBiN0TUDbaGmiDeiFm2u9OUxLT2KOYXbqc0IAHkAFgUK
         AWK/ZkGfOWT6wic5lRobAJH7FODacwNnU1iJpccIXUlJR5/zSvDTK/XokZE4BkpvSzVV
         xkUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CuRZBemx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id t14-20020a05687044ce00b001bb6f89348esi872543oai.1.2023.07.31.10.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jul 2023 10:03:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id ca18e2360f4ac-7907d03b0aeso123251139f.3
        for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 10:03:20 -0700 (PDT)
X-Received: by 2002:a6b:db01:0:b0:787:5ca:d4f with SMTP id t1-20020a6bdb01000000b0078705ca0d4fmr8694429ioc.8.1690822999821;
 Mon, 31 Jul 2023 10:03:19 -0700 (PDT)
MIME-Version: 1.0
References: <20230727011612.2721843-1-zhangpeng362@huawei.com>
 <20230727011612.2721843-4-zhangpeng362@huawei.com> <CAG_fn=WK4Wyh-xeV_-71p3Yms6ZyXbSduAqMZknh1+3XHbgYfg@mail.gmail.com>
In-Reply-To: <CAG_fn=WK4Wyh-xeV_-71p3Yms6ZyXbSduAqMZknh1+3XHbgYfg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 Jul 2023 19:02:43 +0200
Message-ID: <CAG_fn=Vi3WH1fTQRT_KGvRxGmBg3b8pd29OgLRvxHB3556Ffrg@mail.gmail.com>
Subject: Re: [PATCH 3/3] mm: kmsan: use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN
To: Peng Zhang <zhangpeng362@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	wangkefeng.wang@huawei.com, sunnanyong@huawei.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=CuRZBemx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Jul 31, 2023 at 7:02=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Thu, Jul 27, 2023 at 3:16=E2=80=AFAM 'Peng Zhang' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > From: ZhangPeng <zhangpeng362@huawei.com>
> >
> > Use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN to improve code
> > readability. No functional modification involved.
> >
> > Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks for the series!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVi3WH1fTQRT_KGvRxGmBg3b8pd29OgLRvxHB3556Ffrg%40mail.gmai=
l.com.
