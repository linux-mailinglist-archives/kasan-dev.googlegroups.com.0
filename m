Return-Path: <kasan-dev+bncBDR5N7WPRQGRBGOPZWQAMGQEQRS7IAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54F7F6BD878
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 20:01:47 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-177c2fb86b7sf1671707fac.20
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 12:01:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678993306; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCn/fXCq4Qf3RA3RmJwB9bWaGm7igl9bwNweFI8piRhY11r5NwsRgNLNvZtYBo8Lc3
         8fTugjqPBbjVSVrUfP+7IK32EBPA8HHMsZdDHsmlUSC4omjBIb8v+sA7QCUmntq6bRNe
         ABkdOpIoFkhxuBpOkdcjj3yfDte/DVcopwCjRZkbIao7nC90AoOYClac8QXlOQ+LTWSZ
         MOnU1arrXmEGhqSjxvIC3Jy5YnQ3m4n5tHEpkKg20Y2/60XlDg3A09eMTzAwAtQXgVkp
         PK97Zt5M5CDh+S+aLQH7+HVoXBvhAMaQXhVlUavIrLudQQ4b9ZB8+4uF9aFBjHLbcqxm
         xcYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=Voeu1aoIvM2ywPLz0O0QlyoJROoPYfttXzq0Ki3WZS4=;
        b=WPYXkdHGASR2y0HJ7Ca/nbtuVQvA5ON5kpvMZMc3MBkJXwCqZnmn+1qRwUoY4hFwDe
         Ozeg6FKKkIaaAoPXD1lzDzP3u5RRDYLp7LSCmYtDvv7xiqvQEu1vU/Y6X5BZSwj2gKbp
         bv8G5bef5rt7EBkvj/G8oFeLbMT+PD59euRryR+efozwxUs71pNK85MfjnHp6K9c5BtU
         z1rGexWy+CVVm3upncuj1jSwXI0TJjH2X8Fy3vbwNBSdYuI/k51HOqdral31DcKDrY9J
         kqhbAQRZtPMCRA4XA2REwn12fcjyM8wF5lzgkvnkT6umhZ04gdZuSQ95GwrNKa5HiUdd
         2Vqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=MszB2l6u;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678993306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Voeu1aoIvM2ywPLz0O0QlyoJROoPYfttXzq0Ki3WZS4=;
        b=RU/prfhzoU67ONYIacBHU/JrV46v3z46VbQKV0VKlTjmpVH026LwdsQBC86SEIXbyF
         KrR6MQ7TxoE3MjfH3A9SZVIpwAOE96V0jCLrlNfdYEmhz6U1gxNXBQlGiIY5sefNKP2W
         qPPgHlUk7dIVeD9vECZb0il1xUlVHy4b3XUWYK2ARUShVeQYNADPcjkN9Kq0yj/eZZGi
         HPDjROcv39uV5FRf0SRVUFGThhp/oAywRTHjW7mltDCWQ7CMDyls5sFy3bLMgPMAzuxy
         GlgN5RycHpBsQESvvPPme3QAFIDxxnSAtUJMpq7jOhB/9mNC+ENtALO5UaNixoB4ErTY
         A9fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678993306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Voeu1aoIvM2ywPLz0O0QlyoJROoPYfttXzq0Ki3WZS4=;
        b=XyhqBebAoEYO9HojBzVhAxVuA1t9fPI4mLfzgg20IQsZ67duN4+rPu8tRtxoBqLkMp
         SW/xLPMKZNIsndoduQyz7iQI1AzL3tMJpl3hdcasOAF9UFeSZM/M2Kq/9Tff8GzQpj31
         ZDK0nxv/e2lNNA7M4SC9iqDOlL0oKjPFxkxi2+B8SE+zkspsq5I0EzG+BtKiPNNHhBzG
         dygviVA2dQEGfLqveOG98H1ysA/VJtcGG5WMjsotJTASKYl+lLqoH0d5mHXC2UEcOAKg
         MUPVR2J3Zh9aZL4Ns3JQ6Xc4gcmSjnMK+2lpbRLWfz+2O52NGVrSqpR8YjuYkgQGWI7y
         GSAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU4KgjK93d/Z5W5nwpDava1Mvv1sejpombmEXuSfW0uBB6SQ+is
	zrI1La/Qa0xRCkNVvYhMBz4=
X-Google-Smtp-Source: AK7set+sSigNpRY4g4GadslSSZBx44SZeux/Fd2lwzd4BO5hFDAKiARgmR/Bis5Pn1M90ly9g/DYPQ==
X-Received: by 2002:a05:6870:3290:b0:177:9150:e7ba with SMTP id q16-20020a056870329000b001779150e7bamr7549945oac.3.1678993305883;
        Thu, 16 Mar 2023 12:01:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd2:0:b0:661:b84b:eb5e with SMTP id k18-20020a9d7dd2000000b00661b84beb5els490826otn.3.-pod-prod-gmail;
 Thu, 16 Mar 2023 12:01:45 -0700 (PDT)
X-Received: by 2002:a9d:17f0:0:b0:68b:c938:878a with SMTP id j103-20020a9d17f0000000b0068bc938878amr22691257otj.16.1678993305370;
        Thu, 16 Mar 2023 12:01:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678993305; cv=none;
        d=google.com; s=arc-20160816;
        b=NaUO6XobOgQiD28uXd73+zu3x6uKO2bWcdOm+29qxknlwWHq1Vy6N2X/DIYYUjxe4S
         2vt6nZhcKE/TAmAHDsgCaNtN3CbrG9dZb21URmZwHXoIRoV/XYr3cIFj28PKTC4XNfi3
         1rMOHtxFLDF6EdpXpP1rL2zl3C0tLlGnxJQZrezFymH4kPf4hkuhphA0bx0pn/rqcKzg
         9S5dL3qDohAbqYJuYeiHfS3rWPeSNywEKtBGI5JoUvwJRVC3HIWNO2OnqOd5UtUJ5oPn
         HO1Pm6abjJWgJOCGwGJclEkv8br/aD3VFrCx1fJLPhOFb1WLWbFTLb+L7T2baFzE8dL5
         3lKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=Dr0JenSZTfgvBDt5ctYqmIxEaiHBoB1L+lvdc14PxbY=;
        b=EBtYNcG5/PJobKjdz8eMvDZOLIh4J35EbsTcu6j+MSC7SazhikD9VaxrGVuHfFmjaZ
         LgYsj6aH2GzS0S4D1euWG1/NX2ieoBBuahcAAxhcnry7M2e+QjzxgEf8BoHnZEjRl6TL
         GpTfswCI61DSPXMWU7pzwCHueIej6CHtLUlE2hMrD88FrF9AhcgaHqSju0ZqDG/fr/AX
         Bsh+11zOpW/xQFweCWj+aXooczLjvKXg00bq7BTWXZOGrio6mpnBvGlPvNqI1ibK7/8P
         p4eKkSz1XZSRs26zQCrLfvgpYJsHv52cagurvsDtU9t+1W7N5g6BMV92f2JvP/ITizIf
         DB1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=MszB2l6u;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id g15-20020a056830308f00b00693ccf8c864si46157ots.2.2023.03.16.12.01.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 12:01:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id r4so1544166ilt.8
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 12:01:45 -0700 (PDT)
X-Received: by 2002:a05:6e02:dd3:b0:317:2f8d:528f with SMTP id l19-20020a056e020dd300b003172f8d528fmr2084878ilj.2.1678993304850;
        Thu, 16 Mar 2023 12:01:44 -0700 (PDT)
Received: from [127.0.0.1] ([96.43.243.2])
        by smtp.gmail.com with ESMTPSA id 71-20020a020a4a000000b004040f9898ebsm6279jaw.148.2023.03.16.12.01.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Mar 2023 12:01:44 -0700 (PDT)
From: Jens Axboe <axboe@kernel.dk>
To: asml.silence@gmail.com, io-uring@vger.kernel.org, 
 Breno Leitao <leitao@debian.org>
Cc: linux-kernel@vger.kernel.org, gustavold@meta.com, leit@meta.com, 
 kasan-dev@googlegroups.com
In-Reply-To: <20230223164353.2839177-1-leitao@debian.org>
References: <20230223164353.2839177-1-leitao@debian.org>
Subject: Re: [PATCH v3 0/2] io_uring: Add KASAN support for alloc caches
Message-Id: <167899330412.128512.9758823252493186358.b4-ty@kernel.dk>
Date: Thu, 16 Mar 2023 13:01:44 -0600
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.13-dev-2eb1a
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=MszB2l6u;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
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


On Thu, 23 Feb 2023 08:43:51 -0800, Breno Leitao wrote:
> This patchset enables KASAN for alloc cache buffers. These buffers are
> used by apoll and netmsg code path. These buffers will now be poisoned
> when not used, so, if randomly touched, a KASAN warning will pop up.
> 
> This patchset moves the alloc_cache from using double linked list to single
> linked list, so, we do not need to touch the poisoned node when adding
> or deleting a sibling node.
> 
> [...]

Applied, thanks!

[1/2] io_uring: Move from hlist to io_wq_work_node
      commit: 80d5ea4e019d5ac0257c9bf06a7bcf30c9500adc
[2/2] io_uring: Add KASAN support for alloc_caches
      commit: 80d5ea4e019d5ac0257c9bf06a7bcf30c9500adc

Best regards,
-- 
Jens Axboe



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167899330412.128512.9758823252493186358.b4-ty%40kernel.dk.
