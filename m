Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBQ6FVKIAMGQEAEF2SMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB7A54B5A18
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 19:43:15 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id c21-20020a2ebf15000000b00244de1e4d37sf142031ljr.5
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 10:43:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644864195; cv=pass;
        d=google.com; s=arc-20160816;
        b=muPWOZhMjMQI9RG7dcwKbM968KDltHt/mdfKIGCHOH0fugDlhvBA36KtBrULVk9gmX
         liLVWASVvd3TvbFX54yyU7UgA/4OvtrcGX7ZiSJZff+CBWOS2gTbqdo9BfEd0WzesgBl
         8jB/4vohcQ03YDCtaNlugJJioiIktu50prM0C/gCRhMFr30WGLMpxo+fhiBERMjzW5KO
         5DrRz7NywkNOEutt8uQQdsCYbKdGktNp2hLEsqhy2xbu4cehgNXAb1GkM4bKTUYmE7SN
         rpCfcBS7vPgV5wjN5r6R1hEZwrviSFcYKi16xlaUdPb6z2iIzuL7CcRQWw5UK9IIwdBw
         AU+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2odqzeNenWuBxwy6ytzfEf0V4MOeIUy+cZDo7aFst/k=;
        b=j/AxfvSPPGXX3P+/zkz1QYmn/rEnEyIiasLH15VfnDgnsWf23JPY87ejcgAF8Dwtmt
         /nVoCgiRS+PwJ2QIaBQj+QYyB0IoK2KZ6EeMpsc4Elxvhucq1olUFGztXb7MI1/9vHFS
         7+Lg812d7AvA3AgSyWNMO0IZj+9s/knz8yGTsXPnB8zYrkPUUl9nMRzzZ3aw+aiCQpqL
         V0QrTjpihd6/wIu/cu/hGG5UqbgVKZgWKmsj6D/ljuFWdy2wa57zmKP0gqgRKIgLEuFY
         pDwOfxVlJYrLf3cwd55QFAtFRWU6dtl4k8xPxg0E19yfLMKLoHNRro6b59VYSq/5LrZ+
         D3jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="XL4260/0";
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2odqzeNenWuBxwy6ytzfEf0V4MOeIUy+cZDo7aFst/k=;
        b=D+6YpKsy7kbIjd6TzAaxKF3s7MCSDDF+ZcAL+yJeavavWhzYcfFLd4AcuEpUo8B8U8
         d1U/UQTMHsa92ayVKJklUtmNhy65I9TUdUzm03xyUfL4mQ0CAL7oRRQjGrQFz0Z1hOS1
         jKH48wrlvJcUq0DSbdla3EgOEQEpjUxPaCPgpJAA0L+RIdDzq/4dbmZX21m1fdjMfSCF
         WUjpPwbPKXNCWsHtT1rU838rwnB1HMvIYARWqFWe+pD0jSFF4kA6s69clpVb+e76gPkz
         eoePRGBgy5ZQ+QJgMqZdf1JxZ3o9tR0KfiDRcRUNfgR9FapdWk6mCln95PLuvgRnSuCK
         g9UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2odqzeNenWuBxwy6ytzfEf0V4MOeIUy+cZDo7aFst/k=;
        b=2MlqiWem/fcve2tlLDH5vCcEmv2Y2eS5LBrBL4Ak/yaAo1PE5+UADboxBz9QoK310a
         Y6Kk3HwQm6JcXX9ORKITu4ykKj8KHVWyMgSI1hZTldGnQLmZCPb+Yk0nrdLyEwcYatpB
         CjldgYt95dQDgGPIgu/SKdnt+xfl4luTWGw9hkmmyUPOSSEAYi21n7wTlhtnoDY2NSO8
         nNDBJ50eQimkydEcqNlCbJZCLigfJzRUKTw3tmx3WXfY4S49F6oU7yEp/4FEpwAxIVlu
         3zToInU84rhf53e6ftO19Oym5ujyX8BxgmFRVQwmI+FEvlZtB+zFUpwQjJ4bt7h4jDXA
         +e2w==
X-Gm-Message-State: AOAM530WLy0nFzInJPfZWtvZ5Vig8Chni+cYOvJDXYTwbgyNkdwKgYRO
	up+p52KDWQEG9Ijg29XtMVk=
X-Google-Smtp-Source: ABdhPJyPX0l7kkkCDIpvq6x+0cmK/Vz+fk3O3wPKw+C1/1IDcoNfZNU7rDPr+ZpokQ0MF5bfpX5CAQ==
X-Received: by 2002:a05:6512:c10:: with SMTP id z16mr259417lfu.387.1644864195304;
        Mon, 14 Feb 2022 10:43:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1990:: with SMTP id bx16ls110680ljb.3.gmail; Mon,
 14 Feb 2022 10:43:14 -0800 (PST)
X-Received: by 2002:a2e:9d07:: with SMTP id t7mr7879lji.433.1644864194327;
        Mon, 14 Feb 2022 10:43:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644864194; cv=none;
        d=google.com; s=arc-20160816;
        b=HllbkqC//pIXYb1cbjfpaNbTLVOSTcfsnZxVbRUh8hJhiuopDabtSxSCe5L1A/AP2n
         nJT7oSda8v/0CU7RIWE7fF/WVIx8TD1WWVq3eRpnWd4cNIq1fEjBwBfmfZ7UnxrOBCTH
         3fRgsnV7kKCVxOHBdPSdP6d0UPgAk3Pry5M7VfceBiE0y2ssEapxtNF40twIplyw2dIB
         VBYE8PbNOo2UEfKHI6qnwOM7gFDXFh7e1AZ0MNCAN1PihThPMrVyh0xW5vGmO5VBZqUM
         zrRfWbbt13wu5TsBrCT5aPG1l8yWt7RenXRCvVTYVCJJnYKqE+d7JLlJYkwXsI7Mx/PH
         K4Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vljzReEDh1YRn3bh+4c8BFvDCk/NtDbpZzL5W1vanqE=;
        b=YzoC4VbjV2ABS7nFVo6FxtdmPYmBhE1xrUMzi36oW37difPdcEY1VEeIiV/t1ds1Mb
         v/wpAajQdUjNdZPYJfuCytvsS0doL+aeqrxkx6nKtCMdSi1CMGG5iYZuAvJWx8F8035X
         pJgZkx3lxvv9OCrKs8kpIsbe+I74/D4M/QYVC952O8mK6ZBh3/6KGEHvXO1FV1QofwDJ
         ufYaCw/NzBiJlxjq72G0GjE9lw6MDRSwL8hg3NJ6P3qdsvVoK7/O7l9Io6JZQgVvdzaj
         C5/kt4fd6M88MjSTEthWKLfo3FZn2ceX/rpVyM7reT2kZmLAoOZ0sbn4BL0TJC8nnm6L
         Jp3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="XL4260/0";
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id e6si208497lfs.9.2022.02.14.10.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Feb 2022 10:43:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id p15so39333644ejc.7
        for <kasan-dev@googlegroups.com>; Mon, 14 Feb 2022 10:43:14 -0800 (PST)
X-Received: by 2002:a17:906:4fca:: with SMTP id i10mr103247ejw.542.1644864193577;
 Mon, 14 Feb 2022 10:43:13 -0800 (PST)
MIME-Version: 1.0
References: <20220211094133.265066-1-ribalda@chromium.org> <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna> <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
 <YgaOS8BLz23k6JVq@lahna> <YgaPXhOr/lFny4IS@lahna> <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
 <CAGS_qxp3OHFwK__wCHBGr9cMsLR=gfD2rhjejXcmFNJ276_ciw@mail.gmail.com> <Ygn1nPpPsM/DDqr1@lahna>
In-Reply-To: <Ygn1nPpPsM/DDqr1@lahna>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Feb 2022 10:43:02 -0800
Message-ID: <CAGS_qxo7caqjJCwcOM1E9o8r-FsMpkULc1G8BdN1VEuN_-zz3g@mail.gmail.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
To: Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="XL4260/0";       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62f
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Sun, Feb 13, 2022 at 10:24 PM Mika Westerberg
<mika.westerberg@linux.intel.com> wrote:
> > Mika, should I propose a patch that updates the test and adds a
> > drivers/thunderbolt/.kunitconfig with the above contents?
> >
> > Then it could be invoked as
> > $ ./tools/testing/kunit/kunit.py run --kunitconfig=drivers/thunderbolt
>
> Yes please :)

Sounds good! Sent out
https://lore.kernel.org/lkml/20220214184104.1710107-1-dlatypov@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxo7caqjJCwcOM1E9o8r-FsMpkULc1G8BdN1VEuN_-zz3g%40mail.gmail.com.
