Return-Path: <kasan-dev+bncBCP2DOOU5EMBBSXH5DWAKGQEVN4ZGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 95A55CD8A0
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Oct 2019 20:34:51 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 19sf6927963oii.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Oct 2019 11:34:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HUZBig/e1rtnx59e1XVrshZccTRNxSnFYGJHCJzZiSY=;
        b=PmgmuC38ZZR0j68NDO4y6X89aKUuwgup9GQMk1NlANdD5s/JEzvRNxLTwyYpbdVq5x
         Z6nsL+sQdUljE1N5C26iPXrJpTrAkYETXSugRFLjQOTo2zEoRYjEbYz/gLDdfqgSVTcx
         Ypra2snZkLmpTXmcFv88rwcC5vGmMTRcpXpdhpPq7Sq7fYufeez3nS2rsjGC3y8m5qwX
         mcgeGZvxOnEVHQ1fTt9KkDvruOv76OdAf7AN/GGlHDMNrYBOZ2W782rdPHRoIp8UXnxM
         EByXzsF+5JPPRQ50oVywYDlLmd3qgG8v7lR4X4OdPceK8meE/mL0GQB8uBgeRcDoglm2
         vOyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HUZBig/e1rtnx59e1XVrshZccTRNxSnFYGJHCJzZiSY=;
        b=XZXDiz1BV/Qc2bK0FCrHftZ0QJqDp34ZkBReXtYekBzAO9wXQb0lB1mSYkcuGn4WrL
         3OneNboC2mdw0yBx2Vg0LGw6B+AtY0jEQdKRV+WZAvvct9wGeYp2+Bt5o0f9M1PhboFB
         glAxRk9pOHOmlOTsTaYY/PSfVsVEa5OuORjgFFMXb2X8I8GN0ATASECKGU3CJqVdS4Dr
         G9ObMg/vLQJ/wRk3d3rxXEZQpwZSE5j077A3b1VJtAgNhfk66R//6yCeFyu+u3tr8eQd
         mEnoMgc/rGtASdb50S+I0L1VqgbHpiQHJw4QzKzc8S68flZy/4LOGbbI0rwc60GFR+ap
         kH4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HUZBig/e1rtnx59e1XVrshZccTRNxSnFYGJHCJzZiSY=;
        b=m1AnRwo/N6Mb3mQdExDsGXd90S56IiBZbAx2gxh7bfTQSwa7uToerwaNDRLQfpqlZN
         lnaJP0fT2NHM+oIQN1vAMMuNV0S58sU59BlqzMW8V3sRaI30QbkSKb1bXTa7YV4ZLP/0
         AsGMXSlJGZqvFT17lzQg44tzOT2b1DMkiiP90P1AGM9Zi1I/yMMVmhr/upf7B5O+0XVt
         yo/YwDVBv1d0h8Y6eFm122JbEz6u6wgZvgKJmcSwAGxUxgCdxq+UBoEMvpk0cB7MP0ja
         A07cgW7sDSbWrnNW/cyjcHyMcE4mQZS8cPaw2hOo0FvakXqReMF8hclS0c+YfxTPR8DP
         fpBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWS2mcR25B/rSySpEcR+xOdNQ6xkDJNJdyOskA9zRN7zLHOlON3
	vYYFBfzeZTLRtTkCKws0lvA=
X-Google-Smtp-Source: APXvYqxFnRoLN+d8q9L+XxSVOZDvCQWUSuZspXBT+Xp0u2BnPOfDaKEwglif7GJx0lyePbSoFvfExA==
X-Received: by 2002:a9d:7a98:: with SMTP id l24mr13360905otn.311.1570386890402;
        Sun, 06 Oct 2019 11:34:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:53:: with SMTP id v19ls2659208oic.13.gmail; Sun, 06
 Oct 2019 11:34:50 -0700 (PDT)
X-Received: by 2002:aca:3d44:: with SMTP id k65mr15507867oia.9.1570386889850;
        Sun, 06 Oct 2019 11:34:49 -0700 (PDT)
Date: Sun, 6 Oct 2019 11:34:49 -0700 (PDT)
From: djk4ad@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <7afc6f00-3a5d-40da-9ab5-549dfd1eac18@googlegroups.com>
In-Reply-To: <AM6PR07MB38943EC002ACAF95FCA5910E85990@AM6PR07MB3894.eurprd07.prod.outlook.com>
References: <AM6PR07MB38943EC002ACAF95FCA5910E85990@AM6PR07MB3894.eurprd07.prod.outlook.com>
Subject: Hello
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_464_1166458134.1570386889359"
X-Original-Sender: DjK4AD@gmail.com
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

------=_Part_464_1166458134.1570386889359
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=C3=96k

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7afc6f00-3a5d-40da-9ab5-549dfd1eac18%40googlegroups.com.

------=_Part_464_1166458134.1570386889359--
