Return-Path: <kasan-dev+bncBCMIZB7QWENRBQPMTKAAMGQEERACVZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E7282FB564
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:36:50 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id p13sf15785216oos.14
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:36:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611052609; cv=pass;
        d=google.com; s=arc-20160816;
        b=dkFr3olN5JjKDL0lIzkbLxsytqwbtWqQZZ6arLOsrWfWtPV/RTgROxtjGAwDydQnQC
         EyKXpuAKPyDSfQqi8AvhENJbVs3COCF2F2iuVZaR7H6l06PDe/b87Prx/Vzj5MCaObzG
         MyIev8a1ccu/79C/tP27izceCiPff7DQPrJ8ukUPWRSbo+9Bi+YctdY57tb8uW11LYxV
         SQWQHVrCKCV/i7sdPc6QB+gie/czOfLO3ker7n3SdeqY8Ipk5EDqFn849rUnVsz8H55Z
         CFTWOJA4MQoncsQnaVjdJ1EdUsmCxJ7ucl0ci4krPpt1aK7mI6K0F+r72pfVnywX0OYG
         mCQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DfZPOwK0GJ3r7N3Xs65gXzmuoPBR2/Ba1A+PQWGJjDk=;
        b=XI8JNnyk5v/MZQlO15XgjIudM+j2jkBaCwqZ43b7zoKJoCBEuFIVtX+tdpZ3WOExlw
         c/nInivg4l4wzZsLgBYI0eugff2X5ZfaLXYIz/0XrI55xsNDcdeJAtblc6wENBnbEqTI
         RjITQzrghrPbAm22gltzvNkyIfOeSrWHn+WXrLNfEUj6x6u+cmFIWqu4B4EKLHOpmw1l
         JONNFC2m9yliCDxc7/VvOTLRlH3lqhkEWEdN39AInUchRwVslUvQd0J3/htUAzhPpFLi
         +yAp7Rw44X32NsVlo7O9oxCBQdbyoeNGQ16M7NcwnooycgMtVn/KZeaxjYWVmoR2Qimv
         NDtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U0rWXiOS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DfZPOwK0GJ3r7N3Xs65gXzmuoPBR2/Ba1A+PQWGJjDk=;
        b=mx4CZSyPcJghYpZ1RPWARMeRROKBKYjsHEq90pj1gAmHbC9L8S8hpzyGHwDPueC/WI
         ev1NmSSP8pUKnkgj6DT8Aw/xEj9l0oTbn6ee3NWBIHaGQSP9habJJQ+rugV1lACkAP8u
         8MVBExbu+shsewHoTODCsusRLNvAhx+gNLykBmcNNojJvcMOUt1QQCM4QChKRef5RySK
         DqaXLxB9I5QzDIz2AdopQf0P2qBc4gjE+fXoaSUVemERbRTvhGfU13D7i3jrmj5eLL44
         ZwClYqImkvydGZgZ52oj0SaOD80JfB60EuBTE2bmWPuI0RRsEK/j63jadlHZ5nzNq0vj
         ePdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DfZPOwK0GJ3r7N3Xs65gXzmuoPBR2/Ba1A+PQWGJjDk=;
        b=BFVcu9MFIbmDCn/oRGOdWbbP+rw64TiLIOe+Pnk5pUWbeyU8F4TGYkSrG5az/DKxSM
         k0yo2bB+HB63+KVvu0kRbZbgGtJYFTRjT+ZrPSY4HsWxV0UswwLDIXkmJaDcVa63rMTv
         uB2cnJHtzMPdJ6+AHKy+3+cRKzJfzBNX2K4XowtijE246JkiFAxmD8o42WU/BmIc72Ty
         jE+WxDCyJmZvZAtVMEEzGGeLLJSn61M2Gw+eSa8WDk3usVMYnMo9IaE2B50CcJ1bfW0U
         pDlG2We3b1dvNiB37SjG6diy1lz9G7zsxzeVtbm6vMX3bqTpzgYRFIHzSOcB08P8sySk
         9c3A==
X-Gm-Message-State: AOAM5334rJ1HfFm2PZbsu0pf0SooRetETpC3dg/paDaxiuSPH+EZ5WW8
	qfLd2aACFDEfIOISQH4XWZ0=
X-Google-Smtp-Source: ABdhPJxdbIr6b4go0srAjtfKGCFkHZAywcvToYmN/TPpU/nF16XGsRmmfKqWGxkWsFrAScn/CkF6PQ==
X-Received: by 2002:a9d:6c51:: with SMTP id g17mr2949902otq.81.1611052609383;
        Tue, 19 Jan 2021 02:36:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0d:: with SMTP id u13ls1988936otg.8.gmail; Tue,
 19 Jan 2021 02:36:49 -0800 (PST)
X-Received: by 2002:a9d:1ca8:: with SMTP id l40mr2941911ota.135.1611052609067;
        Tue, 19 Jan 2021 02:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611052609; cv=none;
        d=google.com; s=arc-20160816;
        b=CFxl6uJJYT6AEe08pnoV3EGgGXsH4OhvcGG7KF447JU8F2IRtxDIKwrTLvnILAK1Ax
         Baiijh9ftfN+vQoFsNF/U2Ze+VgfU/CCVE5z3EeuI0SSrUovtH9XSiGJ41baHovwvoxn
         hSO2jyWHzo426ZbB43h9pkNo9DT/FtRX+k6BPsPwJJctB32/yTa/0b8Nl+wFKgCXvYO4
         73/tOpEvoN9CDGTw5WZuqg8buKoxUXt+byKsGnorF13EvEW0C0RLCcsshj1MsUvkzItL
         rn/D01zP/bWamEWcR0M272UtyMlGAI54wkfBjUug5szam/oMPoyPMXGuxym5xoeErAlO
         NP5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N8qAAHpqy1dmPPLxthqLJuYymTvCZgzpVaSD47NzuPE=;
        b=c4dNcmD5zL9x27f8HiN3uNtAhNS3V9Ch7NSKzTRfFlYpcHLijsL1ut2ctgT+6IXonp
         7O68JjYQS+MLMlJWduvrCp61P2yj8auY/5eTDnUx/XTnqcB4TDshh+RngFbqSksi0HBg
         8pn5tBW2IbMTVYQ2p9ADtIy4vzSEIWtq9QPly1Pb/89TFUINyS2t2iJHPphcu7L6qGYh
         37JSzZ0sS6RdQJwOPE1jZPc7P++T30Asoo45boPtPYfjFNThYLl2KKqV/TRPxdNAfM78
         rPS6bANUjSj3WtqwsGrDVUPzkLqsjxlwFdOxtmuLNoOGu3mJkaCCfDPVf6q1D67/vMfK
         K6Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U0rWXiOS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id k4si85318oib.1.2021.01.19.02.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d15so7863904qtw.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:36:49 -0800 (PST)
X-Received: by 2002:a05:622a:c9:: with SMTP id p9mr1783461qtw.337.1611052608367;
 Tue, 19 Jan 2021 02:36:48 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
 <CACT4Y+Ykw64aRm9xRxqiyD4h-bDNgXG7EnQOp56r82EA6Rzgow@mail.gmail.com> <CACRpkda+jhPO3-BP_F-eBE+9bT2U9bb920YJUi=-PbNN-mfJZg@mail.gmail.com>
In-Reply-To: <CACRpkda+jhPO3-BP_F-eBE+9bT2U9bb920YJUi=-PbNN-mfJZg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:36:35 +0100
Message-ID: <CACT4Y+aHogGR+aDLxUk=GXb+oOD5JbWWf1h=mEXOZyiHuwAbYQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U0rWXiOS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836
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

On Tue, Jan 19, 2021 at 11:27 AM Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Tue, Jan 19, 2021 at 11:18 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > > Here is my config:
> > > https://dflund.se/~triad/krad/vexpress_config.txt
> >
> > See my previous reply to Krzysztof re syzbot configs. syzbot can't use
> > random configs.
>
> What I'm using is based on vexpress_defconfig with a bunch of
> stuff added on top (like activating KASAN)...
>
> I derive my .config from vexpress_defconfig using this
> Makefile:
> https://dflund.se/~triad/krad/makefiles/vexpress.mak

The syzbot config I referenced is also based on vexpress_defconfig
with a bunch stuff added on top:
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/arm.yml#L10-L11
(but what you see in that single fragment file is not all).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaHogGR%2BaDLxUk%3DGXb%2BoOD5JbWWf1h%3DmEXOZyiHuwAbYQ%40mail.gmail.com.
