Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYNT3OUAMGQEV5F6P2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id E20407B343A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Sep 2023 16:06:26 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-d848694462asf21099661276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Sep 2023 07:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695996385; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q03HU5ceuxrf6og950ML7ghUlzJf/XGK3NBIBijDW9+53S5jFaBxr1Od+JCbwiuZRF
         lLDZSiRTW4WFFgwprTXuzWswAaD8qnSIZ56DB4GRGIdzlHjdhz3S7RxB4iMTIKBIjRPi
         dfTTbpu9xhcrhk3OGNMT7G/IJ43Aff5f7tPtSh3k1AI2d+RqF9lHUWlOlfe3DYqb+hQ1
         gFvPluYSKflySBUWcDqEsQmOQfAQYew8gHo2g0ZuvNnhIqoRsXkV1XPinRo2RAgVMN0b
         PGe4iqz8PuxargUy3+xG+dhtCktKAU1aO305yfqx70L0kk4pUV4h11auurFtjQjRKDfW
         +DWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tlyFskx6YKBsZ2FO5Tr+wnUNuBrzzUMZvW0EvcpwSJM=;
        fh=EEi1EVxdnYkgFJ+MkGIHTJZp1OnrNsst8m6gzmuzLIg=;
        b=gkQjYWcGSVaDtBYJtZrIXJDnjO/lrz+ZMW4vggw9x6OBPy2VV2bmRSapQeJWt0SyoG
         p3PbNOONgYsF1bPpOW3WUEMzupPshbrbCcurUmK6LanNxqew4JJrLoUWsxghqvS19xGE
         1hIp5I+JBk/2woMlwdGsBlk1CIt1qU5n9NrzckaJkJrwAr46dH18mrOLa6+odpscW3Be
         kNPR0QmAA9/cvWp0aB1KAV18fk+lGlEeaWsRwLUaP+3G1X64tUSrdaTwK4ZOuKkAaC0h
         X1HSOA95Hi8ZQpAISlX0tYh+e6/65PvECGxmz1+KFEmTJNjmGQE2A3r5oF0iSP/58Zeo
         5Lzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TLR7TiJP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695996385; x=1696601185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tlyFskx6YKBsZ2FO5Tr+wnUNuBrzzUMZvW0EvcpwSJM=;
        b=YBVamb/8/b7sjwC6CxEjPr/izO+7owD0jgBgm3uZZq8qMWoeQKqtZkZfFJnW6OJExi
         BwdJjN6xWUe3o4qPdy/b9BQjEoCgjfqV0NhNbPgd8+7ELdJGOFHmrpiRD673eZTBwVBz
         ec4OHrin6BmSsVBgwQvm4OPBzsTKfKHQ01+7Xnoh4Z3hd7UYZgYz8NClY0teVW1wF0bl
         7dCw5psHxU2P4Fe1u7M7vwKGaQ95TYD/f8v1txyD/893fB3FYsvULsi7AOdJEvvhYBPQ
         xTfKapc5c/rtzr2Nyvz9AkL31B2FoEhyaTOqwHlO/jlBGIoDgh3jdO2SDvp5NpDSkq8z
         /X5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695996385; x=1696601185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tlyFskx6YKBsZ2FO5Tr+wnUNuBrzzUMZvW0EvcpwSJM=;
        b=fnBJ3wm+QatsoWZvW2fWZz+g0amIHbiC7XrLxeahsY6a4QytPY3whi/u2mDakvKCub
         2I2OjTX6IYx/EzhA+m5ORR6s5DciY40V2lzvk0maxKZZYxuL1x6RmC8O8W0S9NhnfyU9
         BPk1JXqbM6F7KC5nraQlWUGXLjd5iZ6jhu8vwHOOkGGAI0m9F5hJZA8Vw6iBpAaIWq2r
         B9hIjJr69cLnDTtXhlgrq09fCZTrYUlH5JZtbQH5ltje0EybfDf+2CRvfeGjQ8oayGGv
         wm5FzESkXaj88gC1Qx4Pz3BNNsBB1ACmzg7e/Isxrg4+vcSspVvuVUV/n1WuSt5YMMER
         wWnQ==
X-Gm-Message-State: AOJu0YzhaDgnqvYmAZkVeh+/kWte0irNAIV+wpTlexb0qonPi7T5aBfE
	FHy+n1cX7GfLBV85r7tEnDo=
X-Google-Smtp-Source: AGHT+IFQgnjqFie8wXCcnBBkuinPZapeaG7A8ZOCognFB6TyJ58J82/U+9EiVXW8YNoB+sbRFP19rQ==
X-Received: by 2002:a25:1887:0:b0:d78:15ab:58d3 with SMTP id 129-20020a251887000000b00d7815ab58d3mr1254797yby.0.1695996385527;
        Fri, 29 Sep 2023 07:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1022:b0:d7a:fe87:df2a with SMTP id
 x2-20020a056902102200b00d7afe87df2als444007ybt.1.-pod-prod-09-us; Fri, 29 Sep
 2023 07:06:23 -0700 (PDT)
X-Received: by 2002:a25:2381:0:b0:d6b:1531:bc6d with SMTP id j123-20020a252381000000b00d6b1531bc6dmr4004932ybj.30.1695996383480;
        Fri, 29 Sep 2023 07:06:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695996383; cv=none;
        d=google.com; s=arc-20160816;
        b=BngzW6cFcZtnkI8fZtr1ier/45GmeXfZoDUVkL25Jm3qJPftoe8S65I+3IqmbQAY5b
         aRhQ2sUS6wY2xwGM++wukFccsXNySQniMOdPmdFXgTKNN47F6M1DyNTYmrIhiULi/xJp
         jm7gcxHHGBq4ikzFNzeL6JJKHSsI7/jfgMcd7/S8Oat1SZym4mPBxUviPP6UiiDgXXkH
         X7IPKNIY/c/7i/Tc3CUebDT2xvbkguBbU8LrH2+HVrtvS4Akfbjbu6GMexgGeUfWd/Do
         CE9eTbTZ7dd8/tyfCmBKD09HdAAu6s2pmagoH9Kc9WKBVlJ77KIlcKlzQnXJmk47Albs
         BE+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=g1Xb6/JdWi+Gm2zCwL2CbD8VY1Bh4rRC3O4UR/n/oiI=;
        fh=EEi1EVxdnYkgFJ+MkGIHTJZp1OnrNsst8m6gzmuzLIg=;
        b=S1ChZFItmYbeWAun7ZskyR489zTKxUXEQ0kcfMEq/TySmfrshw77BjV5iy+C1E734Q
         y/ajRomyGgK+vzsXqFQXb/oocbqqYIkUua7AJ0wqAmJGrdrIS03gM4y5dMQAZl500MBm
         mp46Aa8kWi4kKIfZqNj4wMa9NyR8vBoiZd3HNRIwJhJONR/6lt6hKesrW+yTaSf4XOE9
         qeDmOk83uDp6qT3wsrVHvWAg/MMGwBtm9DGbisMCdakNHQTq7Cah5eQsltwhG4KkCjBX
         SwFDcKoI8NsA88IqXB9zlxQxQGGn3XOxhGdQylF1/XlelzrlJvkXtkRmfOjJdU0ky27h
         0T5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TLR7TiJP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id p62-20020a25d841000000b00d866d666ad6si1417655ybg.0.2023.09.29.07.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Sep 2023 07:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-65cff300946so23972876d6.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Sep 2023 07:06:23 -0700 (PDT)
X-Received: by 2002:a0c:a791:0:b0:65b:e04:e0a2 with SMTP id
 v17-20020a0ca791000000b0065b0e04e0a2mr3663653qva.28.1695996382933; Fri, 29
 Sep 2023 07:06:22 -0700 (PDT)
MIME-Version: 1.0
References: <20230928041600.15982-1-quic_jiangenj@quicinc.com>
In-Reply-To: <20230928041600.15982-1-quic_jiangenj@quicinc.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Sep 2023 16:05:42 +0200
Message-ID: <CAG_fn=V9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk=XQy=kg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
To: Joey Jiao <quic_jiangenj@quicinc.com>, Masahiro Yamada <masahiroy@kernel.org>
Cc: kasan-dev@googlegroups.com, quic_likaid@quicinc.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kernel@vger.kernel.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TLR7TiJP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

(CC Masahiro Yamada)

On Thu, Sep 28, 2023 at 6:16=E2=80=AFAM Joey Jiao <quic_jiangenj@quicinc.co=
m> wrote:
>
> Fow low memory device, full enabled kasan just not work.
> Set KASAN_SANITIZE to n when CONFIG_KASAN_WHITELIST_ONLY=3Dy.
> So we can enable kasan for single file or module.

I don't have technical objections here, but it bothers me a bit that
we are adding support for KASAN_SANITIZE:=3Dy, although nobody will be
adding KASAN_SANITIZE:=3Dy to upstream Makefiles - only development
kernels when debugging on low-end devices.

Masahiro, is this something worth having in upstream Kconfig code?

> Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk%3DXQy%3Dkg%40mail.=
gmail.com.
