Return-Path: <kasan-dev+bncBCSPXK5ZWUBBB5VK7KSQMGQEXAPR5RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B14475FA81
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 17:15:04 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-39cdf9f9d10sf7584685b6e.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 08:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690211702; cv=pass;
        d=google.com; s=arc-20160816;
        b=u8AWl4pTvjG/gtxmyDWq7GhkKuWRE4rEF40Nt3R7c1hbVtP3tCglxxg30fyTSN5pkq
         RHLC+6h8gyEYmrpbG2ydkym1hNs1zFgOi9oPh7ZEoIEDbknpl0ikoMJ5ulju/WXq+4O6
         kJqg4OrrAZb7c3Om2D6ZSyrkHkfc7WGEANlC4BjososzDUnPxAEAWf4nxJLNmzh8z66L
         LhII+I4gYCyPQx9yk+KRX4aTjRnHRD2eXesywpOD6I1v5MZRZPmQt47Wbimgna8p171H
         fFBIwc0Rs3gtelKFoKqvlfKTP/2WjfXdQm+FPkIkU9+NjHRWHWn3Cls/+3WZYPvVZBJk
         siDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :sender:mime-version:dkim-signature;
        bh=e1TEuhv8qXxKA/zwRxRtgBoQ9JS+fcZbh+KB/pHBXNo=;
        fh=mB40FCSRNhhGFRdfR69fQqYR2wGTjP+5I5pSjyHLOb8=;
        b=N4H9miMYkaxWCldsuQJ0ieapiHeBCyiMWUKCfAKdstOZSqp/BsF7QGwxeYLK0XSSKW
         oeLlR74T1IXvT3+QVp85bATorC3+y8ohHMiYLuLy8XUbakOozg+YFKN804t2qPhlQKwi
         +NNHgI/BNTy7q3PedIFBaKXWEkIXLUKKoEpy7FEbL7DpjHS6sUpvvEHQb63YkX4Zf2Vt
         ynYCCXli5zZHnzKteptILlxzeT6Ao+w+RvdxO4m2TzTmuGnn/d8HE79gzK0ZwTf5zoIR
         0C7PHKHf/0ScUgdlSelvdlSsvpt2mQJNCkFRQY/BlME4AyknqDNcG77KuYWvC2EPKWFH
         h47g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=TSctdY1V;
       spf=pass (google.com: domain of fataoouedraogo65@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=fataoouedraogo65@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1690211702; x=1690816502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:sender
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=e1TEuhv8qXxKA/zwRxRtgBoQ9JS+fcZbh+KB/pHBXNo=;
        b=Xs6EC2ckPvHMQyk6u27bPALVHo+DsFn6KG2MvABR/kcCgsd/dC4pcvVCPaGw/XBqeR
         e2yaj9Z4gYkJlfV1rxXb6P663Y6BSFOrYxRZz9sdHmmWkZzv0F7alVvkS3mcUo5V1gMZ
         aV/UJYNBDQToe6J7NDJ/DeuQE9OSyeCAqvRrGHR2HIAPfEWvrEk0f/V/ZrLfBdpawLEM
         54NO2vzeUusiF+kKg7LRC589BCFL9uaZjgxq2DmnQNczbiVDKzS7mbBzyyKmU3TQl1kl
         uX9+eadoDPzW16EtDl0gyAGmtkHW7ZNKzgII6Ffaxzhs5e/Ax4BRvxB2LpwtTmB2Hke4
         OaCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690211702; x=1690816502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:sender:mime-version:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=e1TEuhv8qXxKA/zwRxRtgBoQ9JS+fcZbh+KB/pHBXNo=;
        b=DQwlGTxsHIaU/8i/p/8/oWyk8W/ymD9hd3b3ku5hno7dx11BzjIblAdapKB4UZNrUj
         +S4iGIIw8QA7svVPIsBWsGo0r8T0sItt7J1a60kgnH3m5irfW3YYlos5ww2mrGrY7zNK
         ylGDvA/Zs9ct/x1F52rUQiFtKQ3bSYTKET5dsWYJvJWnV9j/f6JjgTf9mPix+XnXzOFL
         wlUEzbpjp8nWz+5ShnPyIw0J60Q+T6bqCzKyI0RzuAcBIySMSzPGmrFUVn6nH1vFaYFO
         BH1QNuZ/XaNy93EG9W0ZP1ZfYxZ2POVK9djMDHEysOo9WD7YCz156bfD/TIdzFrFiHn4
         1h/w==
X-Gm-Message-State: ABy/qLZOhlY8OFc8RvXehMX5VXULGP5Q+wgArp5oRu3Jn+Zs/75XsAf3
	7nUpSojIdEzw2ZPQRDKQFnY=
X-Google-Smtp-Source: APBJJlGdOdAbTCt466G+/CMTcsOvRtNhVeFDMzXCnNDAr16UFmirIWb5A/PgeOnzF+nLm8qUnHHCDg==
X-Received: by 2002:a05:6870:5b8a:b0:1b0:454b:1c3d with SMTP id em10-20020a0568705b8a00b001b0454b1c3dmr7498837oab.36.1690211702285;
        Mon, 24 Jul 2023 08:15:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7a2:b0:1bb:6485:7986 with SMTP id
 en34-20020a05687007a200b001bb64857986ls258106oab.2.-pod-prod-06-us; Mon, 24
 Jul 2023 08:15:01 -0700 (PDT)
X-Received: by 2002:a05:6870:e24a:b0:1ba:8c54:6722 with SMTP id d10-20020a056870e24a00b001ba8c546722mr9388938oac.14.1690211701588;
        Mon, 24 Jul 2023 08:15:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690211701; cv=none;
        d=google.com; s=arc-20160816;
        b=qtne+4lv1SfLpjcV7vw/BzUHvwXgjOixFrXBnt1GkzOv5Hh3Q7vbK1wQFFiW6wOGC9
         KdzpcemviTbsPBoHBirV0F1duKWhizQi2eXuCdNwHgb16z99DYwSL04F7suJwPh1vgKG
         ZRo34R7V/JB6JD2SreKkIqUC06svCNzMQrGH69opI6iaz2epUKpBviHrJpkRMsZyb0Km
         0jtqzXNR0dmKWu5jWzJ8GEFvIo/Q5BA4RJXga+aIqBI+KZGDrtyESKisIUAp0ZU16MFz
         eDxcquWN9Pn7TZAzhaF9W/3ridadnun6ZirfQIEXlhElTVFg0AQ1wKK8RdsJv7X2nZtt
         PQTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:sender:mime-version:dkim-signature;
        bh=NWkV50YOzgQJBdohl3s0zg3/xIEHH7MV3ugGVsiWbUo=;
        fh=mB40FCSRNhhGFRdfR69fQqYR2wGTjP+5I5pSjyHLOb8=;
        b=gQjH3HavUjfpEMJisVz+xznsZ0ye4z76TKugubRuWiBZaPwLghwaidiEHHWHdDSPjY
         H35y3jGFqJ1Zzbh6cndnJeSsONxufHfoHfdrOsXQ9DDPcPadqaRwfHI1bv0KvVf+3vl/
         5O81mRk68gjgKQtKfjVtqdd4puP81DoSvZRUOIfMOGQsPfJHn8o2jPavrddaLekupf+l
         6Je0geVBE/hKK5WLY83QxEinzLcGxWphyXc4ewhXobUPxD1XN5KNDXssdJW3BaadmtYJ
         n9prCQKWJ59tTD2i51ZyJmf8Py40vGSWLcvhguaOqlsyutEnJLayHMkF15SvXClRe1NK
         0pDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=TSctdY1V;
       spf=pass (google.com: domain of fataoouedraogo65@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=fataoouedraogo65@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id le14-20020a0568700c0e00b001bad45ecee4si596054oab.5.2023.07.24.08.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jul 2023 08:15:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of fataoouedraogo65@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-403c6a0f3aaso37359921cf.2
        for <kasan-dev@googlegroups.com>; Mon, 24 Jul 2023 08:15:01 -0700 (PDT)
X-Received: by 2002:a05:622a:104c:b0:403:a9aa:571f with SMTP id
 f12-20020a05622a104c00b00403a9aa571fmr100171qte.16.1690211700641; Mon, 24 Jul
 2023 08:15:00 -0700 (PDT)
MIME-Version: 1.0
Sender: fataoouedraogo65@gmail.com
Received: by 2002:ac8:7e95:0:b0:403:a8d5:2432 with HTTP; Mon, 24 Jul 2023
 08:14:59 -0700 (PDT)
From: Dr Lisa Williams <lw4666555@gmail.com>
Date: Mon, 24 Jul 2023 08:14:59 -0700
Message-ID: <CALAg1jTifLEEOgcewjtMuWXvivgg726zx3c3iuJuOftHpr+Pdw@mail.gmail.com>
Subject: Hi,
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lw4666555@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=TSctdY1V;       spf=pass
 (google.com: domain of fataoouedraogo65@gmail.com designates
 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=fataoouedraogo65@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Dear,

My name is Dr Lisa Williams from the United States presently living in the UK.

I hope you consider my friend request. I will share some of my pics
and more details about myself when I get your response.

With love
Lisa

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALAg1jTifLEEOgcewjtMuWXvivgg726zx3c3iuJuOftHpr%2BPdw%40mail.gmail.com.
