Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM6GSWAAMGQED2EHNCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19D7C2F9C55
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:30:13 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id x4sf2836143vsq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:30:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610965812; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKEDo96Y3ArPUPlGoTn7KaVkGgRJd9s933/xdf/44TTh+LTJ5XdxAoomV/bsAiigQr
         Ho7+L0B4whDbGKMMgnCIEElNQx+uon89d3e40mNsQsC6ssdAybbjmkyRwF37othFJYCl
         joJK4b330O4UR68z+B7Jv9ek5C1DqU7T/v2NqCTgK74L6o6s7Tfk3hk2Vz1HMyz4EddP
         BtEueDluyOg2AHFNQMugT015a4HT1YLIiS/+KZ6K6drUkI+nAVwULSgUTPnAH88rL/bs
         oTJqbGo3ONFXkdEXg6jgHlD5A3KV4EdlY0ysGmDKJ445AOes85jEAZDlW7vl9+83nqHW
         wwsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OFxl0VUBKuIvQZNGfHVLGJ0Wqcgy5I7dCcIbUecsPrE=;
        b=ijiOE/A3ZhzYriuaD/NCZLohdpxTVLcwjYq7bUDJvP4uJKh0QSqgKis382VeCqszUs
         vThopb5M3N01bNg0l5+HVhXEhnw5bschRj3LUvWQR1nKHnyAkET91Fo8ls8RJhkVT3O8
         v3tLo+GAN55p/xDVAa6pjeSFI/A7WLX25tDDtr1CV3VVDP2nD32NXoHAG0fwDAO/2wFh
         tdrN+Ke5kQQYM/rsraH5zMxvC0utwsNTh5152tNwUBwTam1hzwpF+BCEa/zS0rgwzG3H
         uf0xDuNN6tdJEPEGHdAt3x9bIs0zqXe7iQRNsGE8GjzxUShzoCJ3Qnft1pWDw6XzENMN
         EHIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjNg4zLu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFxl0VUBKuIvQZNGfHVLGJ0Wqcgy5I7dCcIbUecsPrE=;
        b=DIk85Ax9Y1DMw/yS01EXAWu+YkMARo3/tOmKSObJPcc9EP2PJ7S30N/xvgJBNRFmZb
         y9yG++lkRbxFDe0t3wnKFbpq6Be/mC1pX1lUH2I9ZkDN8idJpPL33asg4z3eTeS0SiuR
         p1Ck87yw99A4ePalXuXRkteax7ht4ZU09FQaEz32z6Zv3hwevxqUE9V9igL/XZMI1sQP
         SFxuHdTAT5h5RUeO3zr4RvuhOJCQYfqDhKj2QNXUOIp8io1/LsnuSHK4uyWODBM1YP9g
         Ep4oQw+VqRWTCmKOHwE+OIMF085kFzM4XPz1Qi5iwrJ82hy6zQKX/9V+wtqPivhCdH1R
         R+3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFxl0VUBKuIvQZNGfHVLGJ0Wqcgy5I7dCcIbUecsPrE=;
        b=CaR+Z1hDv5eo3IB4BzRlcczPbAwBcttr4qUJT1YwnFrgXObyAAFAPpaqN5fPYcD0s3
         nObD6j27wdsDmAcajBQDaEynF25qd7ijpIsYzSblx/BfzBj/KN977w6+yGRKFE1uE1tb
         ctkwqTY3cytmE3sd2O0gPfxh6+Z9ebfku38w6rtMEpSWq/b73FmDLYo3ErH9IqOgnYu2
         GEP4HkvU9JKkPM4tWyQSplXrHSFShMz9HRVVOVBAOA5XPmp6jX+/J5cH6HpGtMbWbGCB
         1TzmempBIIrzX8EVuRNDLH4waHCNLhJ29nHNJoUGG8+Jzqs2qMSAaqvm7z0jLEuQJuYQ
         PqAg==
X-Gm-Message-State: AOAM5307NxuU4URJGlERaL3EmljxidIXrG3ejdh3ctMOrsxqdOhdvxjP
	38AnubnuBEmLzGz7J9tmfnI=
X-Google-Smtp-Source: ABdhPJzDjWdnKWvf6FcNAwDlXSyzqyUm0dEW59mGpzGfTKgdt/f/FKe7OPPm4J0KL1U2TEDZm3HvEw==
X-Received: by 2002:a1f:a988:: with SMTP id s130mr17479791vke.7.1610965812093;
        Mon, 18 Jan 2021 02:30:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls2281817vsm.3.gmail; Mon, 18 Jan
 2021 02:30:11 -0800 (PST)
X-Received: by 2002:a67:d786:: with SMTP id q6mr2341404vsj.1.1610965811666;
        Mon, 18 Jan 2021 02:30:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610965811; cv=none;
        d=google.com; s=arc-20160816;
        b=cpWWd6S8vDuzECGOSWrLg92bvf8r/SqOmDR1teOzJMx0rDol4E/lzu2tUfvuUQ1KcE
         zb8vWQjDTYlDSnQ1NUalN537AmjdtFxZ/1FkFAREc3CWlb7qcocEAXLAmFuBmogDtSPn
         QGROpEbbTYQqzZhFKvMGohNyghytxUsB0jcDbXnO0Fe+pwQJQi8++oivIrvohW8E89gS
         aleGODoDCabUXDMb89281Zx3OoIYHNVuc3xuPBe3aTydsEGvhktRmwXeRJfOcIAKvJ69
         /2toKgOZCeJMGjbHSXceSInFSDcRtwA3YkYTSDdxPj4Umjo+/5iUTF8OQJR1SfO8/I3D
         0SLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VbkyeBFzYjwcxmtCDsWtL2PYj9SLKn4d8JmpXs8sh3E=;
        b=0d0Txmh8WATNbclLoGv8hEbqB5kMIv5zhlDciP+RSuxla5yzpFblXfrrJHnWBny79T
         pzSkXqiq3rwFUg8tRyKlcaBZtY2YwQ3hNNlh1+335bfbjJLApLSRI4UoOyju82mFw5IE
         upHGn3fw3ftLQhb+3QofekLbfchhs+jmCNHBUDgktLKAsnrccQN3gvYAy53ieU2cHWhR
         iEepmue8kM+rzRjr//kgzYTpwBYJkPF/8sfDG/T3slu+W39XbYbrzSpupK7VEFZiLNJ0
         sY4uW1DGecFnzhpWijtVP4eKq4NCJ9KydHE/5EzE4jqPfYcb07PFVncPSqIUD75LhaNt
         +LrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjNg4zLu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id y127si1144747vsc.0.2021.01.18.02.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 02:30:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id l7so7252554qvt.4
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 02:30:11 -0800 (PST)
X-Received: by 2002:a05:6214:1511:: with SMTP id e17mr24033003qvy.4.1610965811211;
 Mon, 18 Jan 2021 02:30:11 -0800 (PST)
MIME-Version: 1.0
References: <20210118092159.145934-1-elver@google.com> <20210118092159.145934-4-elver@google.com>
In-Reply-To: <20210118092159.145934-4-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jan 2021 11:29:59 +0100
Message-ID: <CAG_fn=W6vHmFs+FhCja_4XkSOUqkWTGOrw73=YY5Rz-O=SpU9g@mail.gmail.com>
Subject: Re: [PATCH mm 4/4] kfence: add missing copyright header to documentation
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tjNg4zLu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
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

On Mon, Jan 18, 2021 at 10:22 AM Marco Elver <elver@google.com> wrote:
>
> Add missing copyright header to KFENCE documentation.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW6vHmFs%2BFhCja_4XkSOUqkWTGOrw73%3DYY5Rz-O%3DSpU9g%40mail.gmail.com.
