Return-Path: <kasan-dev+bncBD4L7DEGYINBBIHIYKDAMGQEZUXMQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 602713AECB5
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 17:45:38 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 17-20020a630b110000b029022064e7cdcfsf9599263pgl.10
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 08:45:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624290337; cv=pass;
        d=google.com; s=arc-20160816;
        b=zUXWtXIVqgMo57xWOnTUPEON7xFTDMmrb/uHfKxDjHWJeu/x245v0zBEe2AOrnQkHo
         hOR/l2k2bymccbUn6S4HwzkGSf8Z6tlxjYGjk90G1vajaT9YiaLiZsdGrVIhm1XoMjal
         /Y796uIYKYpBlVCT3so4ZfpeObfK01jHPddwN8GQY72eH8JLeJaGWKjroTt1Vc1ovWGE
         RRHsTuNn99tjfrAVDHFqr4aWjRSPGU1UT0+Uo+jpvovRBm4XZA+1iMbvfHjqy2zGiaCZ
         pQi5l6Njebh3jZfgGAkcsrqjZytTOwpdZ3W5tzvj4dc5q2piNFpR3I3f3Cop4ZYyomOG
         tdkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bd5HrhHUb9gl2aL3xg3Ebu4x+K8nIsAxU48LYRH4Uqs=;
        b=OwmKSAkT7uKXppBjWGqy/xxE2+f8xPPzLCMcJEYL06fYO8UpO5h7GqPlDfvzkOpRiX
         75zINPeNPhTx7/7CDM8UIYpGpcJMp2bB+RirdUvZJYl/QtVYgHRaTMZA3r7lYKwyHiLv
         nqxtjDeYVD1WAlG0v9DwCXOjMvVRCvlaGdeTTjh+QEVC56Sfnp7+TTLv4kIqE83oKLWJ
         srF3dLDZ8uGvs/h+z9qIL6PBeWlzaSwwmVsmoo5yYbpBRR1LF+kHTR/t+BIY56YcfscC
         yQu7Ks2QxunYnLEuzILHTVzHaidMG5KaJnf71sDpnEb7lreGIqDiq1YUgOgfgcAkMsJ6
         ufvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bd5HrhHUb9gl2aL3xg3Ebu4x+K8nIsAxU48LYRH4Uqs=;
        b=PH5PYv0VpAKqXMW68UbVyIew+mVr9g5E3olWV0z+jO2zWFHVOLKFivoeIArfLBW6R5
         LWxVjebqJNw7FqMaxlCX+q1t9RiTMYhrabBXWPRHzHQ5nVdojgyjjl3RZ9t/niDg1bHL
         LIGEhA1LZfQeXuvhkZzi8JC6zepu5qai5Eek2KLgepIW8ZWeu1JeAAe/A8Wip42rhK2V
         d/R3I2VdXADvlRIV10LewmqjNnIVaZ/RNLizYAK86lrh9z8F6Ho56/3WMPmOZYDjtAoP
         9Jvu7fNMGcPV0Qm+UJ1UNqaBTfbywTXBmprQmrH9/yv6xgNw8NGjGzZbzlB1KdfMxIsG
         txMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bd5HrhHUb9gl2aL3xg3Ebu4x+K8nIsAxU48LYRH4Uqs=;
        b=X24zbavaGngASyO/sjJhIDVrj9A/Hfv/MXPKomS6PX64qyy0sT3+mupHLvpMBl9kZw
         efn0ai22IvEwMCJ7oEebDUqwAkp231T4eIykrZHXjOW5QwcPauTn0Il7IeS6enQRBoNH
         X0z/cXHTEiKAf1YAbcpIRZNCePQJQEdx67tDCW3kEIS3IpYObTXBCvfwjYExe083kSMB
         hjgW32x9+TWa78gxcWsf7DujnBkAhwxD5E2vokny+JG5iPDa/m4JfZhKn7PbYRKJOqPG
         FTQqdtlkMiovADuZN/YowJGR8HMJDmkRsgW9k/yBpa1ffuWyzqf7GM/drsiWapjTI+nr
         /r0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nWl/JTf6oK/80FGarYZsgnRhCS2f+tx4eArh+90ntLw7BHNgZ
	Fm9EUQ/14y0uteRuljxqVVM=
X-Google-Smtp-Source: ABdhPJxf9taA9Jh0YwaGjjhQZoAZVEhwP01QbDcjGwgr1TRsepVvWkOIxHRDnBqEIjSPWbNSMLsFlA==
X-Received: by 2002:a17:90a:db98:: with SMTP id h24mr24601247pjv.62.1624290337044;
        Mon, 21 Jun 2021 08:45:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:47:: with SMTP id 65ls9004718pla.11.gmail; Mon, 21
 Jun 2021 08:45:36 -0700 (PDT)
X-Received: by 2002:a17:90b:3147:: with SMTP id ip7mr28279938pjb.8.1624290336486;
        Mon, 21 Jun 2021 08:45:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624290336; cv=none;
        d=google.com; s=arc-20160816;
        b=lzaaY4ZtRXc9Z2isajkQS0J1+YLyCm9K2oz9ZxFvEC68tYa3IAG1DGciBJsvZ1isML
         gqhXigTMBA+1TiDkHiLzsS7GvTook0dD8RJzeiDM46SboXmhSOsurA/uFFs4lJ9xc3lt
         CigKzodpVXffacaQBBOze1eMOlj7DvgpgBOlFvtnXhrJrcotRtLcX2LNPuwn6eFjJtNm
         h+G4N79TKg5PZ5gEMr0oRa5kq+X6VF5bTKFzdZhJJ3Zl7LXcqHU3zlcVKiZ5CHALpUUo
         bPPJfG0hXPO2Rt5MYbdPrsKP5ah5Zuc9GA6XuV5I3m/l+WPo1CTEIHIz6vDLF0td2WZ1
         HFBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=hlWl5Yy89WPgOYRPYSqSNy03hJwdq94/dWvDHZsSeDc=;
        b=XMG/DasrkdMezn+5PdkUT4UPiC3jTPPIz4YjUZXH6jv5NBaT3vq7Eg359CwKXa3d92
         uuIfTPJugsYzugXviGYv+ZNpYY1FwPuVmuggkgRLNLLTlPUOjxd8Xwwbht0DpmrrIVuC
         vSLYuwNYFkO1r8gMofe68PI3gRnPX1SXsXjgs6pCkrcFvlA4eMCOhdiewLYMV47a2gZa
         B5ErPKln1gA9CBUmjz3uKAP2uQRXzRXIalH/Bu8Evu80kP7+YCMZNV/xSs2lr1BZGb5t
         3TqSR8QkV0ggZeyFH6N7MfSoB2xMt7EGaa/Lg29GfOf824TLXodj7LgIsiUopH5NVspv
         AnCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id q7si1572900pgf.3.2021.06.21.08.45.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Jun 2021 08:45:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4d3fb1b3cf1e47ee99897b930936ce1e-20210621
X-UUID: 4d3fb1b3cf1e47ee99897b930936ce1e-20210621
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1944458588; Mon, 21 Jun 2021 23:45:34 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 21 Jun 2021 23:45:32 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 21 Jun 2021 23:45:32 +0800
From: <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Yee Lee <yee.lee@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KASAN" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH] kasan: unpoison use memset to init unaligned object size
Date: Mon, 21 Jun 2021 23:44:41 +0800
Message-ID: <20210621154442.18463-1-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
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

From: Yee Lee <yee.lee@mediatek.com>

This patch adds a memset to initialize object of unaligned size.
Duing to the MTE granulrity, the integrated initialization using
hwtag instruction will force clearing out bytes in granular size,
which may cause undesired effect, such as overwriting to the redzone
of SLUB debug. In this patch, for the unaligned object size, function
uses memset to initailize context instead of the hwtag instruction.

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
---
 mm/kasan/kasan.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..d8faa64614b7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -387,8 +387,11 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+	if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+		init = false;
+		memset((void *)addr, 0, size);
+	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
-
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
 }
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210621154442.18463-1-yee.lee%40mediatek.com.
