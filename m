Return-Path: <kasan-dev+bncBAABBDP7S2VQMGQELXUT4YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7128A7FB70E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Nov 2023 11:23:11 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35b48b8fb7fsf181685ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Nov 2023 02:23:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701166990; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjdHZjwrQP7N0hZ5Pbdv2auYE46btRWwo7vq0vzjuKa6Fv54kG9HaetXhrg4JgOtEf
         FN5El6dC3OhtGimLA89MywJsszdUyFxfR/CGJXe1iumF4ozSRzDIwoJf9MJmj+6CBaS8
         JRvZsNstty90pjO+YSXUaBS6RvY3JneJUVgDdX8OUoGSmFgGA2HmpKtIDCCjSHTTV/Nj
         UTuwSJRKTlCldYafjTLxqJ8Hwc/hioMoj/mzqbuKm1JCs5sy34SnpjEctDqfQKNLodbk
         uXOsCRRG+FsAl4YMSYFG4xoYNy2FNgG3dWkTGebcgm1UoK9ISNgScgCLVdgzsf91fCpZ
         CQ2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=DpX1/Ziq3mwvWxdd5Vzwt00OtGLUbQTUsSCVEM8p38U=;
        fh=uAklwYpXEGtDKNZgxEAPfoFxfjdS+Hk0v3HkyV4V+1s=;
        b=A7BLINzL6fgVmgHkKv7YnwYTaZBGQJa/DVy7ff4Qw8suIibihnWhYNleTPKNl+yUGt
         xbwSBmgwYF9WchnoNcAhggOVSrCyr8KRw75lNfCspzODtFtHN0/gBbw62rEbq3PH5g3w
         lVsehJy1q7WaCBZPBzhwyH+GV6TZKzPhpjwVXtqjUh2fI1UtGSdeQ8TwzMNJdVVitfxk
         ZFpwXhewzI8nbYdFcTXk7Obrb6unwUy2J43MG/uC4vyKOpyU2MHNbdDSN/yux+jNVFQl
         uBKNgm29ysxG8U1OJpcN3wdmJWkUaiTxFZwCEBiSp8P4A/barxdMmzqDsgdpnQNxOUdc
         zsBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=isnw1ekp;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701166990; x=1701771790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DpX1/Ziq3mwvWxdd5Vzwt00OtGLUbQTUsSCVEM8p38U=;
        b=O/1qcmUS28bsen6Rr1vE2Xp6YxNC4Mdl+MoT4YJcOw2I8s87/0uzZwFsCCgHI4zpp2
         cUZj0OCByhLRFF56pZjEHfrzGSbiaUufx4FmsgZuvwlXy+agn7QTNYSxt4cYAARQIDEG
         Oe4SPgP21N3rtks7NiOUSOzhOnCv/7qShV1z0LWITJk7AEW9r6xfg7XDhiL/ZWul1ZRN
         vpJUEmbd0DzmebS7ny7YIJn4OvyyshLNnO78xK3Mbw85zaUWfo/kOBRHpJRD9r+38rBq
         76yR5YrhBVGTim4MQxbxr0I1ISLc7+HTz9fgUyPvMFl2g6g3TsHTdN+ir7UL1obM4/p0
         UOeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701166990; x=1701771790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DpX1/Ziq3mwvWxdd5Vzwt00OtGLUbQTUsSCVEM8p38U=;
        b=LC/8Xf6rfZDGCtGgqEDefR3PugXqLHoSMpiZSOwzJJYqkM6ez59XQrKu3gq268Gwgv
         UoLSFIEvVQnB+XBLUSDABR/SUOFUxn7BzXoXuHd3ggGrNDRS1F1IND28AaUReTYY14ru
         kb9Tj3tKcN3UqPPGg+FKwxUby5nx9kD6xYbU4vuUDnerCpDmgG/e1apu0w44cW2e0lu/
         MDpcp8euhE9SOIZQF2EvJ8YYtbwHEx3q5pEzKAk2a+gz8yplNKD/Q1u6ICFjUHLbKFZE
         cMshZeKaeQk9eufn9Ootwjj9ob+WPbzTRLCa/D9QpY0pmm4UVi+L8pslIqgimwp5ZdGZ
         YZag==
X-Gm-Message-State: AOJu0YyzMO43PsgsM8rq5lSsRIyIhrm4hEKNiQv7PEcTNroi1/9jJTOn
	kSfmqXALc6S17lXarX76z1A=
X-Google-Smtp-Source: AGHT+IFzRnZEkrNdsicvRvv48MPcFoCnZg1i0UNZB5inRstCyIsAeVqCQDWAJXUWW2NasS3ZQPy1AQ==
X-Received: by 2002:a05:6e02:11a6:b0:35c:cc6c:96ab with SMTP id 6-20020a056e0211a600b0035ccc6c96abmr353830ilj.25.1701166989970;
        Tue, 28 Nov 2023 02:23:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1f16:b0:1fa:4e81:9897 with SMTP id
 pd22-20020a0568701f1600b001fa4e819897ls296885oab.1.-pod-prod-01-us; Tue, 28
 Nov 2023 02:23:09 -0800 (PST)
X-Received: by 2002:a05:6870:d60f:b0:1fa:31ab:dfb3 with SMTP id a15-20020a056870d60f00b001fa31abdfb3mr277919oaq.0.1701166989715;
        Tue, 28 Nov 2023 02:23:09 -0800 (PST)
Received: by 2002:a05:6808:179f:b0:3b8:5d96:faea with SMTP id 5614622812f47-3b85d96ffa8msb6e;
        Mon, 27 Nov 2023 23:55:43 -0800 (PST)
X-Received: by 2002:a05:6870:3c05:b0:1fa:1ebc:df4b with SMTP id gk5-20020a0568703c0500b001fa1ebcdf4bmr15615495oab.28.1701158143162;
        Mon, 27 Nov 2023 23:55:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701158143; cv=none;
        d=google.com; s=arc-20160816;
        b=h25tHi24ENzuSifW9sswiilIJpckVgokVrKucl8oeVORIwpd71JzieozVtYOclNXwH
         lKoX/sYO2YFxYDxeGNOVlf4v/4426zlx2w1o2He5ZiQG1CKTROlqEi58JYRoTo0CUVE0
         ESWf2UNXg+vqYAi1KuXRgOUgNy1LiYwwKws2u5z30MfdnDMN+53o7xAvtS+XWlxCUYJN
         zYm2Z9TIRJZAmBxMYFswEGLBPBPJkACXoCe0wx+s7Ypwl55kTwMW9mYXHSJoLKdUt5YR
         fudm/xWuKT1jN7d9EhzSvrBF50TFGEE8h/KOB6+C6CcVWJrqCzfFcUUWKE1KXwsI0cH3
         Z0Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EIqL2tD5DZPZv4cReb9xm7HmNydPz9ibyBpjJNHePvQ=;
        fh=uAklwYpXEGtDKNZgxEAPfoFxfjdS+Hk0v3HkyV4V+1s=;
        b=MlD85AkEFWaQEEylAi5V2G/fuTx8U0a+Ga/yAX8mDLy6Ov96tDBk9HWHBh/btW0ZGD
         ADrkoZln5XNVicDrjcuDbujj5Jo7Sm6QAiSMnHHz4MLXSlE8IcSgLrBjOf9FBTy0/HO1
         Uz3100kqzJ8oB0SrmxO2UZUJ5nyfpZf8pHa7RjFACXLiAnoXhKmL5yE19YGSD9H688cw
         MQJL8UFZk4LFF16rjnKT7hFdJiD4FPwEXkAMKqQmtMtVKwhVWVUOQ9Mjl0aFDeFmHo3G
         j0PT43Lrv5LXkYJyO17/If7BGvlkel9WwzA98wvQc5S27uDnrf8o6eK3JC9y0cnFkFcw
         ZCnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=isnw1ekp;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id u27-20020a056870f29b00b001dcf3f50667si2039199oap.0.2023.11.27.23.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Nov 2023 23:55:42 -0800 (PST)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 839542ea8dc311ee8051498923ad61e6-20231128
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.34,REQID:4a3aa1d3-ec6a-4d77-8b8f-f09482cef926,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:abefa75,CLOUDID:5ca19060-c89d-4129-91cb-8ebfae4653fc,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:
	NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: 839542ea8dc311ee8051498923ad61e6-20231128
Received: from mtkmbs11n2.mediatek.inc [(172.21.101.187)] by mailgw02.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 877891212; Tue, 28 Nov 2023 15:55:36 +0800
Received: from mtkmbs11n1.mediatek.inc (172.21.101.185) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Tue, 28 Nov 2023 15:55:34 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs11n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Tue, 28 Nov 2023 15:55:34 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <xiaoming.yu@mediatek.com>, Haibo Li
	<haibo.li@mediatek.com>, kernel test robot <lkp@intel.com>
Subject: [PATCH] fix comparison of unsigned expression < 0
Date: Tue, 28 Nov 2023 15:55:32 +0800
Message-ID: <20231128075532.110251-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--2.749500-8.000000
X-TMASE-MatchedRID: iv01+ZwXeFIryFHbNnBLG0Zakoam9+aebT2gc93yznn9Ez/5IpHqp8lm
	7UT8OKjb009cKtuMq44lKzzhiO1jPncna+FgAjo0nVTWWiNp+v/jxSCk4x2AYd9RlPzeVuQQObA
	90TJq6C8/ApdYBbUVKYAy6p60ZV621gi3JUE8ePKSkBrqwsq4PfoLR4+zsDTttrrTuahHzlFU1G
	84il7EfntKKivhCrlfE0eoKE0hYr807dg5hv5gH9S5x4PKrQ/8rxK9BaJJfxtRJt1IVZ02lKixa
	UIRQLoOAGAn9m+WxPvyNp7g4PXe0BXsxz6ujBxUq1f8XSkHBUmNJXmEMVvLtpRMZUCEHkRt
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--2.749500-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: 181391F854EACAAB2F00F5A6344B770795AAFA39D774CB1EEFDEC7134135C8032000:8
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=isnw1ekp;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Kernel test robot reported:

'''
mm/kasan/report.c:637 kasan_non_canonical_hook() warn:
unsigned 'addr' is never less than zero.
'''
The KASAN_SHADOW_OFFSET is 0 on loongarch64.

To fix it,check the KASAN_SHADOW_OFFSET before do comparison.

Signed-off-by: Haibo Li <haibo.li@mediatek.com>
Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/
  202311270743.3oTCwYPd-lkp@intel.com/
---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e77facb62900..dafec2df0268 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -634,10 +634,10 @@ void kasan_non_canonical_hook(unsigned long addr)
 {
 	unsigned long orig_addr;
 	const char *bug_type;
-
+#if KASAN_SHADOW_OFFSET > 0
 	if (addr < KASAN_SHADOW_OFFSET)
 		return;
-
+#endif
 	orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
 	/*
 	 * For faults near the shadow address for NULL, we can be fairly certain
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231128075532.110251-1-haibo.li%40mediatek.com.
