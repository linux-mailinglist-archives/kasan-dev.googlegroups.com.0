Return-Path: <kasan-dev+bncBDW2JDUY5AORBSPUSOQQMGQEQYEVRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04F3A6CF953
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 04:56:11 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-5458dde029bsf175950657b3.13
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 19:56:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680144969; cv=pass;
        d=google.com; s=arc-20160816;
        b=FK+AKq75ELkGzVSfaEZoYZZom7o5B0Q9wtZUhiL+OMZikutjh6XYTg+sVmTQOoKT+V
         wQfOEYKaSpcvXwMq1OZNLWLpRyAYngeoHYDjFmB4yKa10crX0zFp2yNApJBn/mC9UCmS
         ubQneMmMw4342/0eHBs0BQ1E/5cHrxRdUzNSaglr59f7re0okzhg/R2XAwKFPWS1uMAa
         JKQ6ElKU0/Hw5wdovVh1IDRASKMVYJ4hIwwvWai53dM+6I97QAnkvTNxjTq8snMboyPw
         nZm1bmpfaHs4p6Hb13TROKW5X7vkdLfLaBmkBr3sPje6SI9uROn2SIOdb8/DhG5eK/OR
         FgRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7vsDWuCNM9Mme6zd4KbItcOC71fuRRNCV5F8r4I4ICM=;
        b=ACKn67Z/dwIHocQy3HejDjIJNXgG0ukm6I6wfr2t6BKVpzYLI3Q0zJ0A9Yzm8EB+NW
         66mBsNb/qJBW6RKmH9mq0orjrGw2WuTtA1iKLMHULx7wLmrJ2oOtexsEdgluQ5L3fMlo
         rm5YBRLhQaWBqgg+zcQykNXbSvXp2asMzyyWkTnY+fbz/TJe0d/xL1PuiB2MfNMMkA+M
         wENklkOUCEFp7I7cM2urWjhYUlvzQAAQoLLtrbCm2OvR0wLu4LfnOB3w5DL0bsTOPZyH
         2rSz5SfvVlWnlh1Ss3pZQRIJm1q3VQEwHt40zIK37LjEhl7Klxj68hErJC6gnN1Utze5
         zuDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zec5lJk4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680144969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7vsDWuCNM9Mme6zd4KbItcOC71fuRRNCV5F8r4I4ICM=;
        b=bS0eAXCoGl+dJ/ZJIfeUd2wDveDO00cmmgHs9G6UHwncc4W5/6dTO/+B92w6zqP26m
         WgxgNNdyBjNMa9jPL5qlvh04jdxk82/CUDFzaa1jLbOCs5oF4nGutS9UEck/mLW//TPh
         luJVgfwK2M6NJPqOYTvBA8+Lm+t/dBp+qXPRh2fmfGWNnEqq448cEfxx6NBi13mxAj1I
         1oW9avA7r9oexai1jnfeaUDHqOsLa8no2g6x3l05ajTI1bUwg9bF7mda7n8e7emDCMY7
         53YXKIpNC//NpUJn+AmddQm3x76Xr6eQ1/i+zaX93k4rqbPLeLm8YFa6zt4oY/chTzu8
         EjKQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680144969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7vsDWuCNM9Mme6zd4KbItcOC71fuRRNCV5F8r4I4ICM=;
        b=HQ/qzE3pplFdwKvOP/p5lkCf1n96BGNA26Ig62ULynhHqjR8YIrtrCRrDHB96JMzoi
         Wh0Z5x1bUk5Xzot0Hy9KHioaLBHyjIp5di7R2VWnd+UMD1bOjerhRd0cjr3v9Ggmv9mC
         hMqvyVwznLEw64Iov8p0k2td7cpL5oVIIuT4nbj7pbuHIDy0pwUHXQ33JD3uhoDSqqmz
         0rhNG/IYmNJYlEM4x3yUSsDM7UjWERr+eO66QY1dMabDKmC3dXfpkkFz6QwysLkKd9Hm
         /fsA09NIKUeTPLBrqmfIprpgi/ru8J6biUco7Oiij/AA5vtlT1VZhf8jM0M7m1n/82si
         zITw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680144969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7vsDWuCNM9Mme6zd4KbItcOC71fuRRNCV5F8r4I4ICM=;
        b=kcsQ5gtsHclItrBfLo3Ex+cW5rX3HQN4m+AEPhraDBNd2m+/WHgRGAS1LU5mvj//0F
         +i3Dk11Ka+ewC4J2Y92QwTTi5M98TI+F0amZ8/DqRbl02oPDRLViSSRea+xDtYk/DoDt
         HswCSPs3/xM43dL8LjbW07cF7bBCfGm/mBvjil3nx+fsAfxr3AAauw30klRHUMGG8mf+
         JF4sCo8QKCbCJhnBXwnbVGiCWo48JBbHlQvC6zFYZup3kfqkYw9ip1T0iG4Di7e8MP8V
         I/hv2SI4esuNGVcyhgGXGdNkjLe/rcfI1iY8ExMxAybc3J1/482jP26j4RVy/2tWdJVk
         SBgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ekncx6mn/24odWIo+wbaHKrlFLVuscq+c57Mo7OBDXCBDf0SFq
	5dcg+cSJiN5sMxOF02n0T6E=
X-Google-Smtp-Source: AKy350YmcqKWZC3NjO+WRugr1gRH4bNS5BAtUJhDtQnMMmLLeCoCaPi59ouFYSzP0jVr2suAaYCKXA==
X-Received: by 2002:a25:2749:0:b0:a99:de9d:d504 with SMTP id n70-20020a252749000000b00a99de9dd504mr14216830ybn.12.1680144969675;
        Wed, 29 Mar 2023 19:56:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:543:b0:b7a:4d20:a84f with SMTP id
 z3-20020a056902054300b00b7a4d20a84fls445907ybs.3.-pod-prod-gmail; Wed, 29 Mar
 2023 19:56:09 -0700 (PDT)
X-Received: by 2002:a05:6902:150d:b0:b7c:7738:db5e with SMTP id q13-20020a056902150d00b00b7c7738db5emr12795917ybu.10.1680144969154;
        Wed, 29 Mar 2023 19:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680144969; cv=none;
        d=google.com; s=arc-20160816;
        b=OmR656ZNNGk/dCfl137NlV5+5HJ7/aefIYChvZlZ6zmPFLPvb88YjkjAgV6kwZmKuf
         3GLrAigpNzMeuc3oQPWuztFAE4Tecd3M78HDARhw6Bm62aFCR+tC21lfQ1L5T9k006A8
         XcyqCeoC+gumVOBfH7R/3PNvISK0PO0dPo7jRZWP9S0vDM/NHSo34MMZleCkgYlyj6kJ
         fPNPBKnE9hmzbAtIyLvyqJfrB8pBg/yjjNC0oPoCkEyC5TIBCX0noMYc3mQOr0u10mBV
         KBpwTYAf3RZpYkngcM0kIGQFazJIKS3oDM5jlfI3qYPz6tTzpkpn13vFF8QY0nkiLbFv
         zOPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zcIEVyxOQ9ThEvdTZ3QimlrlYxsMccblwZq0nJEQf8Q=;
        b=XyXmtM3X9hZbKi2YF9Sy/c61JITnvX3Laht3T+NZSz46wOFu5xta62THhJXsFMCR4Y
         PXY7F9liCPQFpRfdNlRPKn6ok9uA4L3+JudMP7yNaczOseg0xUZQyzGeOfspZlJvTu3Z
         q2VtgC5FaTmznb1roYDlkawFft8o5xK6akKuCDBbtIw9ViFGxA96LHWre5ThtXYUz/9q
         XcZ2By3ZuoA2tVWhpalt5tif+VwbCffFf8AJ2O/wLyAibBrXTXnwsDzgtGAPI3Gr2W1r
         9b/hNlWdrT7jZbcS8BIGoahOrNCshcodmnFmvEzydBd3bXRn6oPw4oK8wWmdLlXDpkHK
         hQIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zec5lJk4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id k4-20020a056902070400b00b633f199b9dsi170708ybt.1.2023.03.29.19.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Mar 2023 19:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id d13so16002450pjh.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 19:56:09 -0700 (PDT)
X-Received: by 2002:a17:902:ecc2:b0:1a0:7630:8ef1 with SMTP id
 a2-20020a170902ecc200b001a076308ef1mr8673024plh.11.1680144968218; Wed, 29 Mar
 2023 19:56:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230328111714.2056-1-zhangqing@loongson.cn> <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
 <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn>
In-Reply-To: <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Mar 2023 04:55:57 +0200
Message-ID: <CA+fCnZddt50+10SZ+hZRKBudsmMF0W9XpsDG6=58p1ot62LjXQ@mail.gmail.com>
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Zec5lJk4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Mar 30, 2023 at 4:06=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> > But I don't think you need this check here at all: addr_has_metadata
> > already checks that shadow exists.
> >
> On LongArch, there's a lot of holes between different segments, so kasan
> shadow area is some different type of memory that we concatenate, we
> can't use if (unlikely((void *)addr <
> kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) to determine the
> validity, and in arch/loongarch/include/asm/kasan.h I construct invalid
> NULL.

I get that, but you already added a special case for
__HAVE_ARCH_SHADOW_MAP to addr_has_metadata, so you can just call it?

> This is because in pagetable_init on loongarch/mips, we populate pmd/pud
> with invalid_pmd_table/invalid_pud_table,

I see. Please add this into the patch description for v2.

> So pmd_init/pud_init(p) is required, perhaps we define them as __weak in
> mm/kasan/init.c, like mm/sparse-vmemmap.c.

Yes, this makes sense to do, so that KASAN doesn't depend on
definitions from sparse-vmemmap.c.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZddt50%2B10SZ%2BhZRKBudsmMF0W9XpsDG6%3D58p1ot62LjXQ%40mai=
l.gmail.com.
