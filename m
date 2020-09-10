Return-Path: <kasan-dev+bncBDT2NE7U5UFRB6O35D5AKGQEGGWVHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C5803264731
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 15:45:30 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id z5sf1357742oti.21
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 06:45:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599745529; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rz0ierRtY9BwjuVWfEBqq7c6/8/Tq5UNK5VFEB4Izv4ftaKMiYT+cq0NUZVAF98sSJ
         GcgqYuzwR7Ln3E/e1SHWOEt2M1NORyrBpVGsp6BkUarYAdUCmS0DB561wNDdsNSaYmCG
         p2WhpBsjnAd4XMUtR55I+x51gGO+uCCJP5E0fJJ+9IXtlKukSGuneXAGOHvvdE1M70Fk
         I8dl9jPhhpXYYwUqOSArT4XfFOjgBDuiKcDv1uBWU2JIOH7qORjOFWLVi+3qh478SpGp
         MG94WSKldcdNLFmJ67Y7nipFCYOXKqhhrbXWn/7ej4vHJVPyBvzAawFHAu7RDdA6OY/r
         kJEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:dkim-filter:sender:dkim-signature;
        bh=cIoPG0FD8+OdE62JOcU3IlVCThcKoKrAQ/iA4jiQx8M=;
        b=tm0F/kLDug2xTzJ3PMHkdTmKQJzn3AUqdaMUcDEW/Z1vRhLf14yhfc5r23g8cCAURf
         SgmE7lrz936LtRf1gfD0AtHHHlOdQwbKTSoAyB0SE28sDlh9kAqk6rSgd3jgzEJnoREN
         JjpfBV8is86jjWAqXhmE3nIcrvLZ9b4P6LjSukK+gIJG31DBHx8DVv3Ume4jvLYQLKOY
         hbCC2qmuG6uVVGKBjIkoUKcUr1AwEmiwK3cnN3jL1EAHU5/bTdfWpHx0Xj0k3s1p4dfz
         lREgG1DoDb0iyWJKo/shJ2SAiWyLuxchrD4vs7RcFDRMOsZwHx1APBu5twqgLI6Zb/0V
         SIGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=uMHg8B9h;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cIoPG0FD8+OdE62JOcU3IlVCThcKoKrAQ/iA4jiQx8M=;
        b=FPc+/uVzY4Ao24edyvhpTbxE1VGMFYKbmwgdIsAUTTmx4qKhOJyzQOeF/QAEMdMtph
         2ART1ZJAFC3VMyVDWU2Bpba1FMXYN98XEf6pMUDtRDDGhiU7NwTqwV+iMV28soGkvez5
         gxe4b64giltLf3k3rsV/9wsrozS7HgJjmWzpSso7zh33WOUyPxmo839sdxXwaqmHAUpH
         UQOhECdsj0zIkRWhGfe8hMflFD9wFtqTtL1kHAJAoMdkVOvA1oNL0liUAxFqej+xQPqh
         7RGrDrBEEa9SZmOv4K0Sy2N9s+hAdngT6aCLZBVsn+sgrHFqdNbK+oEdC/SdeQYBbb9G
         z4JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cIoPG0FD8+OdE62JOcU3IlVCThcKoKrAQ/iA4jiQx8M=;
        b=aNlfW2cS+RaH6lfwn3ne8pAT/tj/NQDNoFmxccfylQAEQVlc0YzesMMKxoYa35ni6X
         LIBaNF0pDD4OaXODGxoCK4ezZp/8WsvRu3bN41Ex3YF7phTxMizHJAm2q3Hqk8S+Uwxc
         KI81LpnirtosnWYFnU7JswW9GcaGtmvmYu75HGCQqxOOJZFW/zmbCpX1HVUgPVodh/DS
         YaieuIMP5CTvmmLLoGu+3RirD0TeqA4Is8LskTKOj5P8akUMSfmRc3lkweh+rdUacCRg
         D/ykZEzg9CoY9UbaNjmUEP0+8l6SSArMwFO4hHXmc9SW4EL2GuUFz1aKemsa0YisUxkr
         CPug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531futyFI589dd/FF3mPsSEt6lXROUrZW6MElXuiQIDX57u3Un84
	SR3a6Vi0U/Cg63msGxTIdy4=
X-Google-Smtp-Source: ABdhPJwpHpYkhN15YWeQeubkyw9n3s4PJYIqB39bcPw/afU0/RX7/ljk9EAUYunuSqpzlrPTn6qY1A==
X-Received: by 2002:a9d:75d1:: with SMTP id c17mr3806027otl.59.1599745529793;
        Thu, 10 Sep 2020 06:45:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:85:: with SMTP id a5ls1448236oto.10.gmail; Thu, 10
 Sep 2020 06:45:29 -0700 (PDT)
X-Received: by 2002:a9d:4818:: with SMTP id c24mr4194029otf.128.1599745529461;
        Thu, 10 Sep 2020 06:45:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599745529; cv=none;
        d=google.com; s=arc-20160816;
        b=K2U3spZvpEOTmUUaGmsiHloDaOocGAwvWGfT29sjtYX7ph6WT+1SFr7QAjViutq8hK
         mNxFQJovBenZdIzKllwOGycBk84K1unsUkm8HwCvCeVI9459bimSdQKc1tQRzdeAjZEb
         A6rRavtlH+SXT0M9zYnJzKFRPoKJEeVp6CNvD2DPcyeNwqqiJknrKT4D70p22ngkKOGj
         mYvtHg25ovNIxSS0qRNA+97UHeEWMPn/fJ0icKtbv/yKFhqdThh+BQKt2DbvYKCm5cR5
         H8k7YcPLBQvUrTyy7pCgyGjKpSqQ2QcciLm5FAGkLAX1HZ9h5x6qY6MEZCF7BQuAS5gW
         gXGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-filter;
        bh=WL98q/7s+UmiqnVaDR4JUCigpcZ/zOKRJsU9m2uipak=;
        b=ug/vQsKqNVU+rhXvcNy1Vbc1MtCM3HFqUiYXqejt2gBwB1ITcaE0AK4g1/VTESABYV
         ra32neIz0ZHkOyBcFBjWJGhabeqSmolXmFCyVsNMifNEaUyiplvmuMp4ijY0RqdCLkQR
         rLRMlReIfQCiUnsHMFCabLLMtXaqDZK2FVINED652cTRIPFUKjRCurHfW5IMXMy3rU1M
         r4Jr04Ms6ZJR2u4U+5D+5yGZ+9XQfO6g0DWVcKgUgXnCL+gy5ALuGLj2edlomobO3ADB
         N4AzSPcguXaNPH845/1AOcPq/6o+BLbVaWPm7I13SVDKatsPK/UyFZ6nWjWs79z4XoRc
         lpKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=uMHg8B9h;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from conuserg-09.nifty.com (conuserg-09.nifty.com. [210.131.2.76])
        by gmr-mx.google.com with ESMTPS id k7si401685oif.3.2020.09.10.06.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 06:45:29 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.76 as permitted sender) client-ip=210.131.2.76;
Received: from oscar.flets-west.jp (softbank126090211135.bbtec.net [126.90.211.135]) (authenticated)
	by conuserg-09.nifty.com with ESMTP id 08ADiY4U001894;
	Thu, 10 Sep 2020 22:44:34 +0900
DKIM-Filter: OpenDKIM Filter v2.10.3 conuserg-09.nifty.com 08ADiY4U001894
X-Nifty-SrcIP: [126.90.211.135]
From: Masahiro Yamada <masahiroy@kernel.org>
To: linux-kbuild@vger.kernel.org
Cc: Ingo Molnar <mingo@redhat.com>, Masahiro Yamada <masahiroy@kernel.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Michal Marek <michal.lkml@markovi.net>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org
Subject: [PATCH 1/2] kbuild: remove redundant CONFIG_KASAN check from scripts/Makefile.kasan
Date: Thu, 10 Sep 2020 22:44:28 +0900
Message-Id: <20200910134429.3525408-1-masahiroy@kernel.org>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nifty.com header.s=dec2015msa header.b=uMHg8B9h;       spf=softfail
 (google.com: domain of transitioning masahiroy@kernel.org does not designate
 210.131.2.76 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

Since commit e0fe0bbe57b8 ("kbuild: include scripts/Makefile.* only
when relevant CONFIG is enabled"), this file is included only when
CONFIG_KASAN=y.

This ifdef is redundant.

Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>
---

 scripts/Makefile.kasan | 2 --
 1 file changed, 2 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index f4beee1b0013..1532f1a41a8f 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -1,8 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
-ifdef CONFIG_KASAN
 CFLAGS_KASAN_NOSANITIZE := -fno-builtin
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
-endif
 
 ifdef CONFIG_KASAN_GENERIC
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910134429.3525408-1-masahiroy%40kernel.org.
