Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRPS4L2QKGQEUF7BEZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 59E931CCFC9
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:32:39 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id v2sf8238765qvy.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 May 2020 19:32:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589164358; cv=pass;
        d=google.com; s=arc-20160816;
        b=A2GVVVh11fpCD3C4clYPNWrkXHazW1QnThPYJsydUOq1hCmyE7GgMuCS6lyNy1tPJL
         yuYX4jr36vkht+hv+Zzx/lDZGysGPNR7Qk69XAuYILesRwX16worUx8gjyqzyB+0b92a
         JpEQH35eC7IP3fyFFu15p5xtF+xmJaURQYU+xZKeJgm4zRVlFtpghrEWR9aUcCMwFGev
         2g3B4CwJL+t+41CKH2vmtl7GuYbzNA9Enue0B1Ippc9zTvbFmz+672/r4AaqX2CEEkbb
         RMbTSA5IL55SoQgjhBJwmt2x+jafU+QOiumWyCu5yrXTHe3vUahSg0Mys3ZvDyNtuw/s
         G1UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WVqHvz4wsTzCqCy6djeL+Hnkq381qXmZtu5YiIujdiY=;
        b=atDF+60Db8Pz9A+efOHUl3LKBMU9KfatejiHF9kxWb9Zsiu3UbmFuM9WD9UM3KRbpy
         3mSc1MUNFE2/0kJES+s4cXC1aeQfN3exiVbdRzcFmRYKokSFkWDxcjqXJyndx5CxMNno
         AxAPgJ5gPJI0+nXodDhcxggpDvOr2AiQxvdrTJtkMentd4HiEXDXUP4T6LVM7lsndhFp
         33rZyElUlRCIQYnb9acmlSO0a0KAr9ABlu2+yogLf/IncAo1Zrd7aiOFX+3uaYNb9qJ+
         ciXmYR15nCzhErb6xSOYcndxb1OekRA5iMRwddfu36PSVcqFJGYaDzw19RvdPVxjUuK5
         cLCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RCuxbCE7;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WVqHvz4wsTzCqCy6djeL+Hnkq381qXmZtu5YiIujdiY=;
        b=T/wLlLdNI4oIh2n+NmKNxR4uMMV5Pk+9TyeGweSDjJjyT228j6Ks38zZqdvcsIHZBy
         ZubkeIxswthmhrsEUus1/X6tNqHqM18nEF5pCaVDbp5+7Jj+zcxDFQN870EBFMpVQA0n
         jHEBgzRuKCyXQd2OBwuqtt31kO5tEMtmUu6+In4QPH4mSzcLhulNTBRhSwEoETavaAoO
         Q+fDcmfo1/X4Kf1X/3SnyPcxB9IDeT38cnPrrIbYP0H68z/+pNqF6i+KrclzTPyqYDeu
         gLpw3cTsVmfjFhOpwkIGkhlqi9eUEcyX0NcNz1367JI+dvUhPmdEf56jWNtyd9Im7Vrz
         l5sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WVqHvz4wsTzCqCy6djeL+Hnkq381qXmZtu5YiIujdiY=;
        b=bpSc5vtDIN2KWWracU7FcJrf+HhQHf7gZK11zYmf8aeNUwTIohJCMUq03+1xfYgyJs
         8wY+dRO/VAXYquxI2Th8ok6qsVUC/hkLo2X5q2piy3BbLTD1CErVzVhs9O6l2cg+9zYX
         FmyFdMenW4AiyAkaJcP33e+m3p6/GWa15G7hSKL+hvCucMMKxzXSYBYMSROHXcMQ0KOq
         v98ZFEZVwO6B7PbjOo3MPXLZ/bDgOuUj3q6jbxzS7oT1zI/hPyGgjqX+DC20hELPYwep
         0YuchBmfGTkeKIeDpo9G8YwmX+VEE5M70xKOZ2bImNLU3YqBKGxN4WA69QXOSXBuCcSw
         McIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZUskqjSg45/073Q/aOx4uAiUspVD3g1s7hA55wvsxagvE9IFOn
	G0MycBTiAtt/uwMrXKsnIDo=
X-Google-Smtp-Source: APiQypJQXZ2kZ7Dc4Ld414iGO5rV+ndHyETK29RuUBT/QcBmoiOG2y3XFwEXtlAbzqHNt0KbXrMg3g==
X-Received: by 2002:ac8:550a:: with SMTP id j10mr14071834qtq.193.1589164357948;
        Sun, 10 May 2020 19:32:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9b12:: with SMTP id d18ls4749257qke.5.gmail; Sun, 10 May
 2020 19:32:37 -0700 (PDT)
X-Received: by 2002:a37:5b47:: with SMTP id p68mr7091743qkb.120.1589164357498;
        Sun, 10 May 2020 19:32:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589164357; cv=none;
        d=google.com; s=arc-20160816;
        b=Em2js637DerX2VeHusZZ0Ym/CkO+llBRNg+NgSRg7wPzXZyoKMVex1lhbX8zRIE85H
         ydbdZZ3xOmSoSEww1aASJ9kAaR7AcJU7eoEbRuorDv/dKD7BooH6kUYc8fs4yx0X4M7L
         WYnZ/MHtVmHVsCiTBgCjtoKEM5iQDftYTuJrqGSyI9i3mzRDcfVn1xiQnz+qcC4ig7qP
         DUDa8m8jCxdy012CF1ElKlc4N2WobQEAKmiJcCANwTADcrfVaJpu3a6WZ7LvciP+0ZY1
         XiRIrWuWB9rpE8wtGJiv5ye9biHBDJnREVicm+MsNT+eBP4XkIIgGb/dbzL0/45AWquW
         dvZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Q+QJySbZSKJn63iVkOIGiMVFBu2s5kjFXMpG7KKjPkw=;
        b=URQIjbCs09L7hXkeFizwaBSUTAVmAoe+t22i/05xwepK9ZqUwsvGTH03fb1KIg5wXA
         fbOcLQ8LyTiGdUa1iMWPu3dT6m5ShkOETB7wF7ssEVetS7laSrL3AKH398pgUk4YUsSq
         sql/YsQWxHStqr+tmoXuHs4seksetZtmlC9N4Tft4S9Ec8C74stEvbCCh1vPoNaI7oTc
         RteIYucbyFhdZoDliuQs9FRgeX4W5nkr0nb10b4vpwykqcJJj22Jz99AaYjF4vOWs3BP
         hijV81Bn0U3BEv7x0YAKNpI29yUJ+yNFPrN0JnTOAlTsyW4iSqLtbKG2UPfwpWITzKZf
         H9Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RCuxbCE7;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id m128si708190qke.3.2020.05.10.19.32.36
        for <kasan-dev@googlegroups.com>;
        Sun, 10 May 2020 19:32:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 227923f835d44eaab8c33af54d6c954c-20200511
X-UUID: 227923f835d44eaab8c33af54d6c954c-20200511
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1754945740; Mon, 11 May 2020 10:32:33 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 10:32:31 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 10:32:31 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 3/3] kasan: update documentation for generic kasan
Date: Mon, 11 May 2020 10:32:31 +0800
Message-ID: <20200511023231.15437-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=RCuxbCE7;       spf=pass
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

Generic KASAN will support to record first and last call_rcu() call
stack and print them in KASAN report. so we update documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..d4efcfde9fff 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,6 +193,12 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
+Currently generic KASAN can print call_rcu() call stack in KASAN report, it
+can't increase the cost of memory consumption, but it has one limitations.
+It can't get both call_rcu() call stack and free stack, so that it can't
+print free stack for allocation objects in KASAN report. This feature is
+only suitable for generic KASAN.
+
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023231.15437-1-walter-zh.wu%40mediatek.com.
