Return-Path: <kasan-dev+bncBDGPTM5BQUDRBKHFTT3AKGQERLFHQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3036E1DDCF7
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 04:02:18 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id u76sf6775351pgc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 19:02:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590112936; cv=pass;
        d=google.com; s=arc-20160816;
        b=crnPspWgC+6A2W6Wh9Vdxd8PyWrKHtLiC9KblkIE+AbfPGrm8j1U79Ua5kPFgDIDPA
         t9s3EQOXvruam5T+xX0SdSks8F1Fkj8J0HyOANLTfxOVsQOKWFaY+VCRKVFB5n02gFDc
         cn3Dfvq4nB8ECw0XZSqfROR7cVS2kWvcc5CyVKOuv+5RG45WYhGB8Br6e7z8L/S1+djb
         TDJ1MuKiJRwlblS60Hks7Idn3oTQy8nk+bANmS3faURYiOsHWEFv1uCnsou1dQ9so8Fj
         baxd/SPwh1Edq9KDN8Ofd9DlnyKkJub/OPYm9i42LKKJ0yjaZzaZxnCsiWOXPdSwB+TD
         eRZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VV7cBB8c8dcbiMRMHFvKS+Iyvz1TvJCq/iizmpwowuw=;
        b=0MUIrbE1sW1Z65pA5TOjwProCdtmFtnOGdcl+Vabao53NCXCX1i5oLvM8P7U1vmH5z
         gaa0z3XG57+A0yFm4QWoDTdU9dFY3rWaQGdeCljrA5uZ0RaSxVwMCKWWIPbDFeVXC10A
         GtvZyHPdSdK/yAvgRG6qR22hKxHuFj+kyZkmQWO9QI+VSELKYIbL5CqBVWfP1zIehkIT
         pKj/VeghvndDftC66uMobUL4ybkQU+If0H5UlVMVzo54ThMX1/PZ4HkRqTO2fz+Fzclb
         YxjjGAWBxi4LpcP/NzNnQqBGUCHyltbvNGSD2yy+VBDwccTnEbx6yv5vE9QcTiMbLwh3
         0m8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="W4d4mS/l";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VV7cBB8c8dcbiMRMHFvKS+Iyvz1TvJCq/iizmpwowuw=;
        b=qcMpNalT7RyLGDqYq5cEo9bgoPmE5wtkW+xQBIgEQBzffgR5SgMSVyO2qwOfFqHq8I
         OeXZCBW+NtPyUZtX3C5HyoaSHxHEOhQKs0EEszAqDRS2PNnz9rTXhAdtOGOtCtDcOpeX
         c3FP9ueMP9ILm8doMYxrLnpIwcUlDNLIESEVAQGFyW9jLMAwB1IuPDlPV7FkJh4mGNZr
         WQOtGSp2tAdgcb4I18nvDVMmiG1or6qcapTHD6FAYEApnbKR0TtERo8GDjkl7BnB7ReT
         FYKiHtDKYuHY6Yw8m3qdU03yhL4VNBkJ+MnLdpJagcgTVlxq/J2rRBfa0PYmONiYk5KE
         LiWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VV7cBB8c8dcbiMRMHFvKS+Iyvz1TvJCq/iizmpwowuw=;
        b=qlaiwluqcXlLrDIed2Mn+juXFpDs392YD2pxfNIQOLTbPxWY5vb6EzuKmuYr4Btths
         4glGWZtn4M4fRHKoYwCUfSFC9e9XiwjJL5gXr7glymzu6b2wJI+nGe3PQN1gvCyCzLp+
         qw0YEXXdQn3cadtLFG5ckLcQfEERlAXOCob3Vnmai9RPmoaZeviRo47dOURI4HLwnoZP
         nytlbofgrCXI8S7XJwQVeI51Oyi1vAavX6dH28lC37NbtDf8YHSuSiNW27DCwkX2Jdvt
         1wBAacsdfTiyveHLeNYSoBkpr1wryms7ox0PmyvM0s0U4KPxxr750iu4Civ8wxeen7hA
         hT3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321YcaCYvk0N8jtanF5tLgxyk1AAXYFn6e/BQTCbWQZ9/bSEX06
	gMWahUjafWf2ElXPYBTzCOU=
X-Google-Smtp-Source: ABdhPJxRhV6P5y6lh3iBes6EFS8rYK+KSgpNp+esT+o33FjcBAZWJtEYmI1y2A3G3YQRpQMPVIBL0g==
X-Received: by 2002:a63:64b:: with SMTP id 72mr11841579pgg.437.1590112936733;
        Thu, 21 May 2020 19:02:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:12c:: with SMTP id 41ls160592plb.2.gmail; Thu, 21
 May 2020 19:02:16 -0700 (PDT)
X-Received: by 2002:a17:902:bb87:: with SMTP id m7mr2563070pls.270.1590112936334;
        Thu, 21 May 2020 19:02:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590112936; cv=none;
        d=google.com; s=arc-20160816;
        b=F+ubJkYc/O0q7qwwBNFX+nLF4vFll2ZkjswwbD0EskCpRDBEQvPB4dVQ77QVfyG4pi
         id1vM863D6khoeyyKrAsgaQiBv5+qBMnny5YqQmtXNnxdPFgYe5BRpF0ujKfTT1Phvyr
         xq6GFgN7jFprXtnwoIGlMOo/inlP2RyKGcCcf+VoXM/ZXFohjXEGpmheiOEE8eJqJPKK
         1e9NhZ/45W/oXQczOIdbnHCH35bM/upHlwDIh9K7VHcw/FUN5dvWniHHhgKvKyOmWaun
         1CWQhHHKobgqStVMo94uzRttsK0/+C16hZp7TSun+insoNg/oU6AdAVLmft0IePeE1ks
         d+oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=qIWtxoGuZ5P6mO49eH/CrXHztmv7j3tYchUpE2BMWOE=;
        b=0C4dMPkxfWq94oZW6amjvXU426jc50vVGWdI2CZHUJVKBKcc4vfcWwAZ5hhhyAkosY
         OmvANZ7YB7vgKoXcQsYolZ96qTNzVjG2Y7ZJvIfF3IPiQEbDs9IKvFWdBqvESR8cITGg
         7fBeYDedrHGucSAcMPdktFL0fBN5rD+ULQzSQRb3nm7Suyo+77Fwf61w11Bu0f4FMiun
         z3ky1cGVz0tjU7oQVmuVA5qaWiXiHAwgNgdNCNWbOjMntUF7mXyZJutJvv22XpnoJdra
         D2/v+FQCNcnpKYQZGtq2n/fvHBt92V5jduUdoFxlHIQQtRptdbJZyniETXuE8krL/2g4
         1gSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="W4d4mS/l";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y7si641237pjv.0.2020.05.21.19.02.15
        for <kasan-dev@googlegroups.com>;
        Thu, 21 May 2020 19:02:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 7421c5cce6cf45d086d0431ffc9b90f3-20200522
X-UUID: 7421c5cce6cf45d086d0431ffc9b90f3-20200522
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 944133403; Fri, 22 May 2020 10:02:14 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 22 May 2020 10:02:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 22 May 2020 10:02:12 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v6 4/4] kasan: update documentation for generic kasan
Date: Fri, 22 May 2020 10:02:12 +0800
Message-ID: <20200522020212.23460-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 96CB23A265DA29919D6ADF75D54BB85AE65E7498DE570CC72449AA74EB4B50CD2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="W4d4mS/l";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Generic KASAN will support to record the last two call_rcu() call stacks
and print them in KASAN report. So that need to update documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..fede42e6536b 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,6 +193,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
+Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
+and the second to last.
+
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020212.23460-1-walter-zh.wu%40mediatek.com.
