Return-Path: <kasan-dev+bncBCA2BG6MWAHBBVGWS6LAMGQELVN6OSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A47569303
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 22:06:44 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id o7-20020a05600c510700b003a18addaaa9sf9005526wms.4
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 13:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657138004; cv=pass;
        d=google.com; s=arc-20160816;
        b=syBLUbnpqx6D3iHZ4ryQdlCJiH1JemyUCb3DfZG7BT3ZjIBlCUu5zVl2XyfTO/KMvu
         6NDkT7PpgCPOP0ARsaAlhAKg9ZtXwHsWsYWPFBxOrcPWuSTxa5JsfzoFOilm477XsjAk
         YsiqS0YacIhLQtjotxdMGkDrnmSQ99VLBq0IR5EqK/LBFhVoXnA0EsFc1EZsn6XeMmDT
         ON1riE+lJ0SbvOz6IYE/jINmOS8f0+vkSTiWv5mUjdSgwvtR4ZKJCXTLIXcYMLeh/fvB
         1H4SQTgxJuA4GcZgbzFVh5iuai9CiYm9uDhzdssO1cqnSKoZgkkvljQafniNZ1WrYWod
         nmGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=whYcKBm3vg8oAiHKQMUIetg81CV81EnkpqjslJgfPwI=;
        b=IR7usz+HwzjMjjJggWbN8qqNphYbam1em+U73LuQ/oCRWc5LmqWqbsJcWvKANeuiDB
         2IMcS7mXnUBjeZBuvneB/m+HJvU++cJeilAFHFLOkY9lVf8loEfrnb/6hlz3HxPPvlN8
         XBlD4ypZtlA/fyUjwGLlB2hvcQ+UU/aePtayR0GqqDqEMed1999a/u/vyD71tj9JuVk7
         kN2JTgEMtF5XxoESWF1C7LKcBNzygCKqjftJK3D0a4XUvrXO2B+GQbWMpu8dEFvVVEiD
         6Zk4Tq/+/ELexYdvfplI5u9Pg9dhzplZIGeWWaqKkRL3f/VYHcd7SwCdvLQMXKUF/fHj
         j8jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nP8OozGQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whYcKBm3vg8oAiHKQMUIetg81CV81EnkpqjslJgfPwI=;
        b=evGM6UOtAsuTiF78sGEDNnROClD0X6ZlS1EHGsMt2wvjp3RMNXp2M+jMOAveT6QsOO
         kzVV99Fg45HElbEmDcQxDXfSyvFeGSjsEzZR/mC1FN5mpOh84uxungA62buPShaQPuMo
         YUhplc+r9PuoPpIWrkUXQtya34RZOMH2fxf2psPwz3iU9D/fxM23g9lA9WRSnVKdajIn
         SrhUL0iihRsLE9MCO4HuXP8a0srDpY87zyAhv/Dhk6ufUZ+lHRBwGspSNOX2qmXb/sZf
         KMwM+Lj7D65CB4nQP2qHaxyMAMrjtjnVQGa/GB64R2Cl3dHUF5cOKSgDtGQU1ay15hkJ
         Yv4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whYcKBm3vg8oAiHKQMUIetg81CV81EnkpqjslJgfPwI=;
        b=3c+htz5MnJYrHI1KJl1pmlKz9DrmI/QOaTLjMmMcB827fpcbdytawhVNEk4IgvLgL4
         6ah25lsQvjlL8MwfprjR67gHCqRQ+MmA32wlA9p2RGEHU6oM3csYPBPGl0SmfRMP7rDG
         OeqPsWpWHRb8iErFtFIleWuUFp3EadhFRrNfdvSh0yy/ctvJjoO68Xr90179LQ0SrF73
         04mVj3b7/3cNaz/ltOt51R5VoFegLJOorOhPnxpxR4wDI1YWKznrLBQPtOA0a/MsL1C/
         DYi3HdftmOlMP1w2itVHJJzKbtgbfMJhK9PpK79N66kxEqH3IV6TuQHTj/pHxxAVS5bi
         fBCg==
X-Gm-Message-State: AJIora/aripfolQqdtfUCpwhNN1B3vPMxTVFlDfB0a6fDdyDuZG1rA6a
	1DKhg21UM8TL6HuJzfHYeKg=
X-Google-Smtp-Source: AGRyM1ufhU3W/DzbjERJy0DNBh1T21PMx1iwP8E62tEANRzaR6eVWBLJbwTr5cZbno0FyWiLT0yXhw==
X-Received: by 2002:a05:600c:284a:b0:3a1:996f:3cad with SMTP id r10-20020a05600c284a00b003a1996f3cadmr324209wmb.95.1657138004472;
        Wed, 06 Jul 2022 13:06:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c6:b0:3a0:4f27:977f with SMTP id
 d6-20020a05600c34c600b003a04f27977fls10587034wmq.2.gmail; Wed, 06 Jul 2022
 13:06:43 -0700 (PDT)
X-Received: by 2002:a05:600c:a14e:b0:3a1:87ab:a4c4 with SMTP id ib14-20020a05600ca14e00b003a187aba4c4mr309980wmb.187.1657138003493;
        Wed, 06 Jul 2022 13:06:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657138003; cv=none;
        d=google.com; s=arc-20160816;
        b=Nt1QoG6KN4d4z7es33+tGPg3/a8Sax2trmiljZybYZ6SLiugFZ1PCxWhA7h/8UQ82o
         WphRXNseKv0puVtPtu5LamPnlpQzwA/hgZWhpGf8gX8PrU5d01dphAyToVwXEKLbRr5W
         iZpY0Zbf1bRQpolmN12jIy3qiFWX71We7mVsGfOArZXxrKJEImhls1z9rVkfbQVUFgAC
         HZTUwSNB/XFfzT0ZBlOGensF9GwSVO1eY9xQ5K6XgKcHykjnXu6bW8i+vvUI2q5e0JXX
         54k5RbMWkClpSdcwalc5a3Vp1tcbIORZMuvkujlGqWKK0A4jCtv6f4BXer8j+bw5xpTN
         /6nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7PiCfuqqFQMm4Z7Pxo/Mkp0vSHbF19ROVfmwHiEwIp8=;
        b=uS375sQw58HCqPB3crGktX/TrADPDPZvDhID3VBifdQSHfEnHQyB2eqpqOF57Unjdn
         oakedehfjbD3e2FqHWy9DQvbdTk/V3BfAVqtKyY2B4H3tx2gMWefXQtU+GVGrB1wn6Uc
         Ba/izsTQpumIdZgRbRL27cy08mumDVf0IoQ6DthkQHnVEcbRPSwa5O99Qj1Mus2wLLOv
         DADu6KeVFqkOk26dzWzaQBOjwKt+w40YvguDChO5yjbC+HJFeppl1Dc5A4TyAVq11TbO
         wM8FCUAjuv0a9F5IQM/EbNWz6p5ULldj2JCzxgoHeceAcyh6cYC2yYgiODKah8cAtudc
         5V2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nP8OozGQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id f127-20020a1c3885000000b0039c4d96e9efsi1832wma.1.2022.07.06.13.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 13:06:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id y8so14872614eda.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 13:06:43 -0700 (PDT)
X-Received: by 2002:a05:6402:40c3:b0:439:6b72:483e with SMTP id
 z3-20020a05640240c300b004396b72483emr43951638edb.154.1657138003142; Wed, 06
 Jul 2022 13:06:43 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-3-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-3-dlatypov@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 16:06:31 -0400
Message-ID: <CAFd5g44RLKbDHLeMMsJYeBK+smeioJKQVeBmHwk5uccD-vKvUA@mail.gmail.com>
Subject: Re: [PATCH 2/3] kunit: tool: simplify creating LinuxSourceTreeOperations
To: Daniel Latypov <dlatypov@google.com>
Cc: davidgow@google.com, elver@google.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nP8OozGQ;       spf=pass
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

On Wed, May 18, 2022 at 1:01 PM Daniel Latypov <dlatypov@google.com> wrote:
>
> Drop get_source_tree_ops() and just call what used to be
> get_source_tree_ops_from_qemu_config() in both cases.
>
> Also rename the functions to have shorter names and add a "_" prefix to
> note they're not meant to be used outside this function.
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44RLKbDHLeMMsJYeBK%2BsmeioJKQVeBmHwk5uccD-vKvUA%40mail.gmail.com.
