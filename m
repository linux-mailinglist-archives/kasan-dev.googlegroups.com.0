Return-Path: <kasan-dev+bncBCMIZB7QWENRBF75V7VAKGQEO3Z3AHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 14C248605D
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 12:51:05 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id l12sf10798045pgt.9
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 03:51:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565261463; cv=pass;
        d=google.com; s=arc-20160816;
        b=ya3T1BTi2vDNCgy2HWMHCsy5J2AvWy9s5S0XnZ/Vwun2BO+iKTVt4H+J6Ofkg2DFtt
         HzPs/JtEYPFByKRY8LddNHkqwyBPKvgA2ygL8JYSJufjreBXtzd8YuqMPkf+v+BF1ftN
         Bkb4KLzJDTcLereOnSd14U5k6zvx9qDj620dpc8sPl84C2jqMfTVmvRKASnj3RFXNdbb
         ahV1Bkqm9+uDwqc/1w6LjsZejL6h/CgInjo61QHGrjbTrFNGZtXWC06Ws260ZKrqFTDZ
         AhnF5WkK7qmjcNBqDeeRN/QRc4qeBeaNk6AJX+s69VifW2wG7KqF+1kw11vvqsJbYCnW
         Qa9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GKqq6dIKAfjJv/qfye2b94kM6hoqzK3wul0ziTDahS8=;
        b=ggICZsLKqo14phGJHgEFxIwCWVn121SBLGc5M2InBAH3SbmgiQDNknvb2eRjK14/3q
         VtbOKndPbSv6vte84HxnQC8q2lgrvitZ7erbZMH36d5G0N4R3kEL0V9AYdq7Sofn/9W3
         o7g/9LYzG+1dQWXfeYPCTaMnMbPqV7KRHwBXbtykoNaISEWexkctVtEFcCBH09n8Jp7G
         uOjkGrHUoYVHK7Kbv8QwNuHPvMSEnjRSEUeFP7mGJK3I4OOltq4H3Ma/PHv8xyO22EKO
         fcSgaCDT15mo11qsVksZncxfdD5K03eunULIMigiGr6lnmPUuNxuCAEVMqlxcjNjMCEp
         xKOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fa4sOszz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GKqq6dIKAfjJv/qfye2b94kM6hoqzK3wul0ziTDahS8=;
        b=OoXaYK4z3pMj4moY1Vrtg+7Ovl0J668/L4FxA5e5gVKio4BPpLN5N74bCOLolLTUU2
         tOSUfbQSTU5UwIEa3XVdulU/hBRN96lG1jWxR89qpOvfnidZpt02zspKQoefTT1kAfwn
         VYprPN1PtbWG1VIyxU/B6SDz1pgVwECpEotOeSEZUKi7F1vDUP/5Gnt0GoyUeolG9apw
         etnj9FsIG/HOrXRImkvtGi4vthwV7MEKiiwugSWIlrIAWExhgcAcWP7v9P6DtzOuvauR
         E6+jcQZpZst6nE3/kIY4SPDgWZ4pbh23KPygH5TYkLyvhYrpLcObnmKoAyiZ8uPEfaF3
         awMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GKqq6dIKAfjJv/qfye2b94kM6hoqzK3wul0ziTDahS8=;
        b=SIIs3QyBu7ynwBFSb1KZHPwG/skD34hSNMWyCP3BJlY72lg5/Fp6ucFtx+gDtsIrTk
         Bqj3V/JJ+ZrL4ivr+obTxfpMhqdIEJQcrRJHpo75056FhGhlpaIZENDsi7tT2MSs3fDG
         esEu9JSBs4pSwtjTZovyuTnbTBQKXE49jOcZDxMt0EtFBgUbjQlELGU1M31vHQg+/90y
         HJ0l7q8I/TlMBhNEG/pAOUmowj4bzAFEZjmaLyWbSf9u9mrLiHsvGMy8wMd2481b16kp
         dkw4KjOSK0YL1d2DJafraAXK8pNvijxXql0zyLm8qlRx55dCFsRmDVNX7gSyKgxJCaiX
         eZYQ==
X-Gm-Message-State: APjAAAVH6DaQFL7rBaDcAKAzcnrDLZVLi6PLI8Pe5Z74oPUQpMTiMIEe
	tXlCFKt3r3JeqPyGarMsZ1Y=
X-Google-Smtp-Source: APXvYqy5jM7DI03pi6c/fDqq5GnW0ejOgY8qqvqdVH4Xr4reWZWBByU4HVE/JcYgN0VNVm1zYzPcSA==
X-Received: by 2002:a17:90a:5207:: with SMTP id v7mr3275931pjh.127.1565261463149;
        Thu, 08 Aug 2019 03:51:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc15:: with SMTP id j21ls9870733pgi.9.gmail; Thu, 08 Aug
 2019 03:51:02 -0700 (PDT)
X-Received: by 2002:a63:7a01:: with SMTP id v1mr12491600pgc.310.1565261462819;
        Thu, 08 Aug 2019 03:51:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565261462; cv=none;
        d=google.com; s=arc-20160816;
        b=MdEbnnupu3+3QMrfwLSnSZQ+5v8IQa4bTfDCYxsrax6ubGaTqGNE6N6ertPg24qMN2
         AiWnCyrjJJPLquSy3P5QG+4O3fYPgl/tZWF11Mbt0KBChMPDAZqARRmPzhD+mKDsIN06
         udY6RjsSo4GVsjez0CT06ZSCnb96Kdh5+xkA9PEwnya7uF+Hu63yuuN2IbVbAasqiikY
         MqPBo3JVYtb9bLjTRp5QHXas2jTDsuuY9aFE/+QOwEVoBICj6fucJt2/ahBB5vFGkjGo
         qMRuP4HSAqsHHBlqkCZu6rVibJ6JPFlqCQCkbS3ap79eHgIzDAUw6n94alHmJWiw3zdS
         it6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+3RJuk9n7GcykBZk2M2X3HLTiEm6wX1l92t5W4LSMoc=;
        b=oVcihwuwscSgI+R2tPTj6xi28toPNf+fwOIJ6DsWo3yTy0n2pW86blXplD/4MlY7cq
         3e4c91CvDcLhv2Ifdgjysau4RXiWXd7sVG2eNn3UGO8IbuZ9+vxINrEYqo9JkI4SJttg
         hc3xx+eQP25nR0Bu8rAbrEc8uV2luClURzo/EBR7pIviOKzvr1VHhy7BnNl+bFkzNduO
         cRK7fjaev0meYAhnqJPg9O3rfsJ4ahV4xlQXr/YlYhq8MOl5lT3y28QOzJmRQEutrVSe
         euDW5k73OKRCLg6QXlXeWIADDefZCcdZw2etBac7MONywV+HnDrQ35RylNC5JaHqWs8h
         WMNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fa4sOszz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id m93si95263pje.2.2019.08.08.03.51.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 03:51:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id l15so59482276oth.7
        for <kasan-dev@googlegroups.com>; Thu, 08 Aug 2019 03:51:02 -0700 (PDT)
X-Received: by 2002:a02:c00c:: with SMTP id y12mr5534387jai.65.1565261462139;
 Thu, 08 Aug 2019 03:51:02 -0700 (PDT)
MIME-Version: 1.0
References: <CAMGGO8pWt=me-sYGfG5Szqx1b3doWRrbnamM_mc8SsMANBLg1w@mail.gmail.com>
In-Reply-To: <CAMGGO8pWt=me-sYGfG5Szqx1b3doWRrbnamM_mc8SsMANBLg1w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Aug 2019 12:50:51 +0200
Message-ID: <CACT4Y+ZtkTqHcVSM=VaBF=GnrWZ_pKRoMSqz5xHyVWDcd=8LHA@mail.gmail.com>
Subject: Re: Kasan Syzkaller Comptability
To: Yevgeny Pats <yp@fuzzit.dev>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fa4sOszz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::343
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

On Thu, Aug 8, 2019 at 12:41 PM Yevgeny Pats <yp@fuzzit.dev> wrote:
>
> Hi Dmitry,
>
> I have a bit unrelated question. I was playing with Syzkaller on differen=
t old Android devices. I have a compilation problem related to Kasan that m=
aybe you can direct me to the right solution:
>
> I'm compiling 4.14.85 kernel with KCOV/KASAN support, it seems the clangs=
 I use are looking for symbols that do not exist in my kernel (__asan_alloc=
a_poison, __asan_allocas_unpoison, __asan_set_shadow_00) yet they appear in=
 later versions, so maybe my clang is too new, when I try to use an older o=
ne (3.6) it says it/gcc doesn't support CONFIG_GCC_PLUGINS so Im kinda stuc=
k.
>
> Maybe you know which clang should I use or how do I tell my clang to use =
a newer gcc that will support CONFIG_GCC_PLUGINS? Or maybe I should recompi=
le the clang from source?
>
> Much appreciated,
> Yevgeny

+syzkaller and kasan-dev mailing lists

Hi Yevgeny,

clang support for upstream kernel is very fresh, esp for x86. Only the
most recent kernel versions can be compiled with clang on x86. Stick
with gcc for older releases.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZtkTqHcVSM%3DVaBF%3DGnrWZ_pKRoMSqz5xHyVWDcd%3D8LHA%40mai=
l.gmail.com.
