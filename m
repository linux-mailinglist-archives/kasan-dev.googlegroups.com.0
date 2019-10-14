Return-Path: <kasan-dev+bncBCMIZB7QWENRBS47SHWQKGQEOWHC7KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D891D6051
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:37:01 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id m20sf12366581pgv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:37:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049420; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbx7Y0d2gxLA89eu1IuvxDfP/p5GB41H/70xiif4/lSHQk5TbzS1yW/kKaxi/suESr
         XCBkEtmkL/7U/ph17gNqcQvJKlADoC39uFPoUVyLPJwV8neN1EZMxCqNcqGc+iVPc3hF
         5XuE0nf950vqPWfMMDf0s5/ZGcc3fxrss4bscpbJFhgIYHVTX2Q/qkR8T4yZ0j1/yiD1
         SKCvLIDuu2U1GNr0tSBSLP59vt36MJCULub3RJIvOqt4itqLuqctrhAjLH057xo5P3V+
         +Avtq0Zn5Cdkn+/4lpIw4d7ygQpiqxu4veVvasdHxHBzS+j/WfesJYqJ/i16bgNH+fCd
         dltw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Alge9EJ62Mv5I1Yz+IKLZL6OWgrVVcn9MYnEd5AbQ/0=;
        b=SwPI0OSg9Uyucct3vSUMHee85ZhgHqk1sLIAgHJ+YbyMQRkpzOkp6NI+hoBSOYNLP5
         R4X57Jfn6mUwQrFRKfdY4HpivtxG+sMzAnPA4m74ZGuH0ABRXWLY98CNDYs7sg9Vp1JK
         Hwp5iql5BkmniHo4Xz20tuLdsD2VUYQZC6+4JhytOb5hGoZrpM6XuEMylJg1Kb4tqoMa
         JIjSyLqUlcP5I9h2B84UsxLM5eZuvdy65tF7nrgdz/SuEBwbVcJ83nBMfEoqe6uBYRiE
         IKpHzRAusAJvaZg4oEMFTpYUoslWKSwZg78lHAkILU6BC3qgjMBadDx1y8gZ0dK8o/tv
         nGug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vhfeBhIb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Alge9EJ62Mv5I1Yz+IKLZL6OWgrVVcn9MYnEd5AbQ/0=;
        b=tC5+vVvntaZdUOGA42MOudg/ffaQ2Xo89Di115+I3+ZUabwqoN4UszhboZEt9VwUS3
         D4r3Bfb6FAc8w2RyF0jf5PLdR8CCJk8DWS93S1wHnTXH+GWiM0F0EwnVycSqyJr/IdNw
         ORIKakXevrrz4qHjDFWl4i/suX8l/DFQFirpSx50RZZk0mlutBhxBi2E3EJz6m6iICNP
         5l5iWzQYabvUYx9VsJ9jcvhcfcLiZr4Yt13+BZgMDEss7mxt51rAvUGn+fSoM3+yguMz
         Zain2yKl8d3F6V3yH5B7CKBrqGha95OpKEhBq+HYF5SXz9H6jlJukbkTCv9f+g2/fuV1
         r0YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Alge9EJ62Mv5I1Yz+IKLZL6OWgrVVcn9MYnEd5AbQ/0=;
        b=L/s0pHTzRkzICDnotCd2JRgId3Opy/ildlvhwDCrJTDKp3oGDBwnJDWrMGPI5GqEAn
         iJt0gcu3c3ygn0XyIwWLmkswU7r2qfdPdNWUtno+DnSVtyfE5+uzi/AWF5TBS36HUfKv
         hD4zqTKisus+hVPE/2exjf2r5ckMqhePfmR+5cfCYXkrlMiTj9OQyw236GaqS/KFDMGl
         WUC0p71x32EaD5aqt3t6+sLjae9pEaqJmW9O/uNZM1aPCPmg0VRbqVk9QmvH9sWzlTYq
         8r3jeJ3nDgX7EsXZ7TPILzp7KqATPl9tHQGBuHKjcY5PcgHHnghWMhVspibOItiQqhWc
         z4og==
X-Gm-Message-State: APjAAAUdPCxwa1OU0yjFppK0sNrqHdaqNjt5dQnb/pcTSVQMhkZ46bfo
	CDScct57bIlrulWvbTbKEV0=
X-Google-Smtp-Source: APXvYqwroFVvWWstA+zY9l8SxwjSDnEj4RkXeaEdnQRBYiCyCNWZ6YEcCUH8PVDjliumtzeLGf72pA==
X-Received: by 2002:aa7:96d1:: with SMTP id h17mr32050767pfq.187.1571049419897;
        Mon, 14 Oct 2019 03:36:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ff13:: with SMTP id f19ls3915949plj.4.gmail; Mon, 14
 Oct 2019 03:36:59 -0700 (PDT)
X-Received: by 2002:a17:902:700b:: with SMTP id y11mr6761596plk.29.1571049419552;
        Mon, 14 Oct 2019 03:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049419; cv=none;
        d=google.com; s=arc-20160816;
        b=u+y6kZxP47QbCjBNxli9loTociJcfwDAMnn0RvfGxqnfNzhjvN3QnsoSUJircEAzBP
         PAyu6KmduwDNygfjzr5J8g2pTjSET55aWxmLe5CWnIKwxacVhfs/KMNPwXrom6FaVNLV
         TqMD4Sf47xGQ7sygrshldIZiY3mKbeI21zW3t32M7C01GK6dPwccs+jTOT4M+zu0AZk8
         ct0/rjHZme7hddk3eOaoLIhh0KpcyeXrfyddPee1AZ6yJ61w0tQrCjTrOZ/nX5VgwuzV
         mkC3py0MNl4fLxBTzY7L+Fvmn9/YtPcDAFpCw7TkTZIRiy44RTFz+g1JdYVPAeP+YD1U
         u40g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=26plC+LB/ET6lKUK8GUr/NZh4YTG4I5vCBM0xWKfjSY=;
        b=qww+T6a/p/MQxlKKE3p6wdazcJqhU+/Zx82pengRm5fADesxvGI+Kj05MhSchUBd3S
         k+78NyExUgknDP3Y9IHQXA3vZhmLy0ENcuymphwZIeGw+bsKlSZ4ocKPeDOYUHevYbQv
         cDXqxOu59zEYFgPOvqZboxfC0T/vihQ5NzWDFXJikcQCwLacav+joKV9ipTbpHlxE/7f
         fL3p0Egbi+Qj0NwEURPD4tTgcjsIyrm7m64btFAYoLnEIpt6Cy1I+enpEg8/5c6cDkiU
         M4IzB3c72wVBBffuUijD5FsKOGrHdYEaCskdRGPk254fRz4kb7ovFNYkfaimIfRcR6Ek
         UuNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vhfeBhIb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id x13si486810pll.1.2019.10.14.03.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 03:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id 3so24791175qta.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 03:36:59 -0700 (PDT)
X-Received: by 2002:ac8:37e8:: with SMTP id e37mr30909144qtc.57.1571049418182;
 Mon, 14 Oct 2019 03:36:58 -0700 (PDT)
MIME-Version: 1.0
References: <20191014103148.17816-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20191014103148.17816-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 12:36:45 +0200
Message-ID: <CACT4Y+aSybD6Z0YHuhbaTKK+fd4c3t4z8WneYdRRqA4N-G0fkA@mail.gmail.com>
Subject: Re: [PATCH 0/2] fix the missing underflow in memory operation function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vhfeBhIb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 14, 2019 at 12:32 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> The patchsets help to produce KASAN report when size is negative numbers
> in memory operation function. It is helpful for programmer to solve the
> undefined behavior issue. Patch 1 based on Dmitry's review and
> suggestion, patch 2 is a test in order to verify the patch 1.

Hi Walter,

I only received this cover letter, but not the actual patches. I also
don't see them in the group:
https://groups.google.com/forum/#!forum/kasan-dev
nor on internet. Have you mailed them? Where are they?

> [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
>
> Walter Wu (2):
> kasan: detect negative size in memory operation function
> kasan: add test for invalid size in memmove
>
> ---
>  lib/test_kasan.c          | 18 ++++++++++++++++++
>  mm/kasan/common.c         | 13 ++++++++-----
>  mm/kasan/generic.c        |  5 +++++
>  mm/kasan/generic_report.c | 18 ++++++++++++++++++
>  mm/kasan/tags.c           |  5 +++++
>  mm/kasan/tags_report.c    | 17 +++++++++++++++++
>  6 files changed, 71 insertions(+), 5 deletions(-)
>
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103148.17816-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaSybD6Z0YHuhbaTKK%2Bfd4c3t4z8WneYdRRqA4N-G0fkA%40mail.gmail.com.
