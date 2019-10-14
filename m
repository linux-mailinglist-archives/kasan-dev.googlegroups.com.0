Return-Path: <kasan-dev+bncBAABBJE5SHWQKGQEWR45NGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 49B77D6033
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:32:06 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id b11sf3783833vkn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:32:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049125; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOvSCaTzx32TQ78Q7sQQJF6xpQcD4izjfsQvJMmfSoF5wGUbXnDmQTh1N1pxLb3KZe
         /iveJNSsh7yr+Nj0v8kADCAC6vinIjVaiXMhrWAHt0I1VPHDA+aWZ0A+sAlGLpNQqNmE
         a+2qsBJnGYqSQvrhucTCM4e26eyVGuwjTOUPmKNAafFj6mzpBEkrbWPe8FpCBxKIflkz
         w3agxnBbsyfRQ6GwEqxVajtRywi45KlywSx39wbsyiKGdqFvc5j/wFKAVXT6IH5Yg2ds
         JVAcf1c4A5flFkfa8WhNfdXhgnaRZLkzpTpbD167rnTbq+XAe6qfV7+ORiElOz0Yno2w
         imog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5Af3+swHoKsTVhot1Y19Aor+9VXXa5GPx+pm/Kh1d6s=;
        b=EYr9rZDlKIEPXNcxoWE0wNNd2rfvG4ZZXpwjtGPAXL4Uq/PPD1PXwTWVeCDtCq3R+t
         K78Xn+iPNkYu1mbk2IMax5RPXBLViiQBlZXbOqD+bH8uJvt3PF4NT56A9Kar9oZwk3oL
         Lhp1CIdQJaHpaYA0iSVLAgrAq+BKl8dAtO+0IxTD5Fvznw/8MLytCcyVY2x0N1rP0+X5
         KmPxYvb/C1a7R3NCuGRXXuWOSEPnXDfsmwmzyIxdzHKLvIu+ChGm+FyZaCPQLQi11T7t
         adv6NdR6YMIyZcGyARSRb9CyFJG7rWSXcFhBNbVaBrjXo/Xo1i8YVtfhu+4IW35M3mp0
         e8UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Af3+swHoKsTVhot1Y19Aor+9VXXa5GPx+pm/Kh1d6s=;
        b=estJ839/uhP+msDjGgySqtjqMXfdpYXOhQ/860nAp1/h+n9DuLPJwHZC6I75O+UMM0
         m69HsoVGURvLTTgh+RiF6etjU6kbfd3xyxZPtNVMbm2I/0OjUUxX2L3YkJJ0ok4P4kfE
         hliYvjcEEyIt71GIRUwRzRZpbpoFFi0/g68PRnlj7gG+gb6xuGS1xRZsZudiezPFpAnM
         7bOxVYwHMR0gkgZSFyj3vifwb7FbrYF8btyfEHsTH1nsq9puH1pRLOF48iIY1RZhxPlu
         5B11ByiDnugAmicamjAzBfBvUMlS+dJ2MfcJt+OFc5snUD1iZkcCO9UesaLmeL+d/Yob
         FWWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Af3+swHoKsTVhot1Y19Aor+9VXXa5GPx+pm/Kh1d6s=;
        b=lgn8ibT03LaVZqilkhHjbsnDo3Rv/HFNqYwjhPVAyDTgcPccJbUZYOikUUCWRGzoYr
         P9HK7H1Q/zWwY/25bW1ifEqj3jY0m9XvzWV6/GStylS1hyVfmsTPf1+rbvvrAHin+nXu
         rwolC/v2S3S5BVbvRrLI4YlW9LUzrNT0oyJ5F7+ef38gf+z9ZBfudQETEi7REZzYWgBA
         WXVpKZZN7cEUOZupIWE9A0pw98iiAoX70HK1onPEMf+1XKNudiwdeURyWxXIAwM/GFyX
         LJY/ScO/lrJED7yXiW4jeLRQzFROzQZ8hi7YFBRUmKDW0nDEbwKCNfSTRyuM2Fga1EnU
         3Snw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW8ClTGZmkeePHyOmKVAbsZAHHRuCP36g+yUAAILMmry//9hwwE
	CoslQLmwKUdfpRuzEqGBA1w=
X-Google-Smtp-Source: APXvYqxDzEgE+Hdg8n2th1JOTDeX+XZBmFaZNSSVz3fB9p3jcsGYwd++TSUqHLvjl50cZa0a4u+RIA==
X-Received: by 2002:a1f:9e8e:: with SMTP id h136mr15424450vke.8.1571049124883;
        Mon, 14 Oct 2019 03:32:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1684:: with SMTP id 126ls1348710vsw.4.gmail; Mon, 14 Oct
 2019 03:32:04 -0700 (PDT)
X-Received: by 2002:a67:6911:: with SMTP id e17mr16847379vsc.44.1571049124629;
        Mon, 14 Oct 2019 03:32:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049124; cv=none;
        d=google.com; s=arc-20160816;
        b=L9ie1jXqySrzTzGLhudt0UB9ENLgveiv3NNcwt/fDs190GeN67bcUHCaWSO7rH4ncn
         PGSFjuViNWKwSrF5hGXQAqKxzwoVFV/bqmqNgtPjxTXAXeW72z6HT0NpyY14x8YuVhim
         hrmAeSPQaKHK5xC4Tn67Hca3YaOrt2HQxOvwNyTy3Wv3potIc+kCR9n7ddy6AUQIkmqc
         YhAAUA4OZz37QPnmivjsE+Jthk9qCZFsdbkavVVcHpuw5Fabtt1E+Jea2tC23bKVWDX6
         nlNcUQhJMoQjhGqG4iKBzlN+ytLG0T1ujl0UMc2CJE97g98UVkEfqB/9yAFSPein8TUk
         gBfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=ekJNpESIgfQv5XYcvnni+dMzANptHYbcKQ4cfKW4hfI=;
        b=FuICHHfVPx68bPzQjBcI/jXyd1pju9BPYWjGnR3uDtuQKaUGGRXVZrtvvNC+GYH/3I
         gOxANfmZj/OrS0YiOey8GJdzxGmaj/bJ4sBGTwYu8yXByzOenWOKWy3Ps9WK6HKrV+oE
         eGV912VcR+f2Rtx1Uz0QKGy1kxSKTLG1GKKR5knHxeW3b2/XfFtQHbwPj/Z8fWi2CJjk
         Z7Rl8twC7+rG/bPwpk7rl+vttqvwQRCZu5mkGG2d/6Wfu31T/A0thTY5DalYV6xyZArK
         fF/n3UFIAli3/TgLjCR57oXvk7+hykEtBH2xAuQYxiDYWnBGifASKei8k+uLGmRnQzhw
         WcGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id i13si1068172uan.1.2019.10.14.03.32.03
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 03:32:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 69246c0437ad43a995a203276ea7a8a6-20191014
X-UUID: 69246c0437ad43a995a203276ea7a8a6-20191014
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 653775818; Mon, 14 Oct 2019 18:31:59 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 18:31:48 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 18:31:48 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH 0/2] fix the missing underflow in memory operation function
Date: Mon, 14 Oct 2019 18:31:48 +0800
Message-ID: <20191014103148.17816-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: B0FC585DE902AF415BBF2DF73DCE4769D5BBE65605E5E2F26222F2C9D0F93BC92000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

The patchsets help to produce KASAN report when size is negative numbers
in memory operation function. It is helpful for programmer to solve the 
undefined behavior issue. Patch 1 based on Dmitry's review and
suggestion, patch 2 is a test in order to verify the patch 1. 

[1]https://bugzilla.kernel.org/show_bug.cgi?id=199341 
[2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/ 

Walter Wu (2): 
kasan: detect negative size in memory operation function 
kasan: add test for invalid size in memmove

---
 lib/test_kasan.c          | 18 ++++++++++++++++++
 mm/kasan/common.c         | 13 ++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 17 +++++++++++++++++
 6 files changed, 71 insertions(+), 5 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103148.17816-1-walter-zh.wu%40mediatek.com.
