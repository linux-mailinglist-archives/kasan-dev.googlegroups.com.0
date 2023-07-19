Return-Path: <kasan-dev+bncBAABB6V532SQMGQEMZICGZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id A264F759044
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 10:29:47 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-57704aa6c69sf58831267b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 01:29:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689755386; cv=pass;
        d=google.com; s=arc-20160816;
        b=XYjx7cQd585PzRbtifVs+5MTN4donIHOh/2dFg6DKR+XvRFC/243amdkGzxaCtqH5N
         F/aG7WVg2qWMa3y8ZyPSzSNjU8OzpBmyNYiLZSfpBXzPWgRsdn1LB2Y9w9qmzjgTr09J
         QtjTQ0D3I/NEfTAqoMefrQE31qdxIg93ci0wyq2iuDIE1zCeFbQfIPUruxnkEI/4ijTS
         Vwi5RTzkWF3WgpRke/18om3uiLxQUQ1sghOe+cRwKkUAe8f7UXmsNIsIOW382PxgQ072
         AYLy75Ha71TjvmXnEajZbSKy+aOvhhfDQzAqlHggxTvZ3lIlmRP+4XIz7Fi1PGb6M8NM
         nFOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sDhrsaFAjTs6PRpAP0uyi9zrjAcDcEDAlVlUjazxE8U=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=cJItZlfYZkEeHayU52anonkJfkLAO1TYexSF9m7bdrcHify9hMk9CjakHj7r9+3ajC
         Pmwxoj7qcgCsfbIYkXi8fsxiKYkrSLPuHSk4/S3X8NIzTU8C5wAv7n/tzHqAuSvcFuI+
         8xAOZYijC2cCAE3HzAFbjCgU1Hp8uBek2U1FZG2TpooltI9n/qQfi05cMHSJLcqlB5Rg
         gPqa/KT/jZUMC4Ze+k72t2WN1eOU09odtLv0cV8KnpDaQUcd4ytt9P3++J9nKnIgXf+Z
         sR88oXT0OrZs8JyRlg5scj7uQFxx0iKwp60G27x5ZZmZH0fH64UMiKhsczzdQMqXMYq3
         LMaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689755386; x=1692347386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sDhrsaFAjTs6PRpAP0uyi9zrjAcDcEDAlVlUjazxE8U=;
        b=BmvbIB8pdBjYwy1cILzJsqFzZdOnZYo8kV4fFzJj5sMW7nxQSkI0jB0W9NGwyxzvvL
         c0dDymjO1hdzU/vwANdH158NJcbb11YUJKRb3UeuopfzfxOYfhGzAiifs/+ZO6O+VYYD
         8YMVFg0CQDR5OoGb7ts/fZS1RU1ejtAA6/uUIO/hBQYuaMtU1Zl9p0uXLdB5uLVXnO+W
         GRXPHqG2BWgQR+hThb7Xz4gKC3bJbZwWta0Q1OoeM4KZFM54JqsAYu2QikCSUd4jpYny
         0CVAin3ofV/3A6qSkmu1WX7e7QzvuKZtXaSDwB/zvGK9fQOyWJU5tqTPpCDhqluQKoP6
         Jkwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689755386; x=1692347386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sDhrsaFAjTs6PRpAP0uyi9zrjAcDcEDAlVlUjazxE8U=;
        b=PYIAYkxKO1SdqhoDohStmEUFSmL8lBSNzZheg/xoJ+fGm8yL3LeRXbGK7KByNxO+iQ
         tXnF+uk1Nt4Ha4Qle9R68Tfq8Hu9PLRwMQWsB9X5hEigcj2gRilHqrhqLYvcgh2MfL15
         ITT76S39Fzjio+DkxElIrz8qnL8tsaHAEUtUdqhc01L0RueYBX/0Cyr8FHk4dtw4U8R7
         JCqlGHUynT05UAaS9X7WugZwx5HJNzdi3SbTWMg8Kwm62Gwq/lZZB+Pvdh8vnkVP+w7p
         v2/IafqJSOuxMvXMe0zi8Z9HeACDy3CLEL0Y7LClHyv7/BQzS79UfI5VQ6vs7HAPVxKt
         e4BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbOivbTn5nlHgYsMBpicw3DTfljDPF9IzStCGmRVPEFv/Ab9M+t
	ZSW9PoOoxmVYW69fIcMWqhw=
X-Google-Smtp-Source: APBJJlGVcAkCSVVfyMU1IiHJQKN0Yl8bsVXwwvZIFinnsAZ8p8l8jvNedISycDMmoutk5nKk5sGvSg==
X-Received: by 2002:a25:9904:0:b0:c6b:74e3:d4d4 with SMTP id z4-20020a259904000000b00c6b74e3d4d4mr1660564ybn.40.1689755386199;
        Wed, 19 Jul 2023 01:29:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1028:b0:bfc:565b:9306 with SMTP id
 x8-20020a056902102800b00bfc565b9306ls708031ybt.2.-pod-prod-06-us; Wed, 19 Jul
 2023 01:29:45 -0700 (PDT)
X-Received: by 2002:a81:924c:0:b0:579:e606:6ce2 with SMTP id j73-20020a81924c000000b00579e6066ce2mr16934885ywg.40.1689755385621;
        Wed, 19 Jul 2023 01:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689755385; cv=none;
        d=google.com; s=arc-20160816;
        b=cD9vQu9yunz8Ffvc0cdtgTGcDxc1XL/tVD9GnEyjMMF9OH/9gU5nF67IrRZt48SEkh
         sqBSSLlazIHY1QQoGR3rZM0bWeHrLREkAS4OXzUTK7IyivMMKgtF2i2zPUYQ2ls8LOSi
         AyTKFKjYaH1dkWHE4DOjWdHHQi5F8UgSgL4L9bv28KZi8U0J8W1CksK0LRznl46Bf0pU
         zBluOELyXww3oF6O9yGFKYof4cgkU8w5R29r+w+Ur7tVR9fgoFyi/ucvD4N27T4BP9Hs
         LM4FpyjohegqnS5kLXQ1Bgd6x5s9PLmsBYjEtvPf5sU+Xk2vFW87Rx5W9X4P+D2fdsMC
         poSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=lykMfvlKarYOxceN2J0mA5IMHhYMI9RIdlJZI5hom3A=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=CUFVrNg1GzznP5PDTR2PfljxGfajCvs8q0cgnJjseUxmdZ7/BZNS8QPvMXTmr77ziK
         oOkIXILbIqA563zeaFN6Y3I0RpHW7hhIdr1qPgCLj3fuPrhQuWCNR7inX1Ygtvn10s+a
         QM65XWlVGm2IbaCWp+n4mSxxflO0VBoBT15sBNPVztZAYz7gSqW0kFJYSfWAjhjA8CPc
         g7QwRauDcWLMDuMpgwjLGwVFtUzlOJZj80MId4W1X0Rr/+W8WMZK/ytxA3DFCF3pc6h9
         qCmvQgAyyUMTBbCt9QcE1VEku8Zb3x5J3JPCsWD1LDtEVP38PnehhamGIPd829pIR0L4
         jR5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id db18-20020a05690c0dd200b005835c0a3992si138344ywb.4.2023.07.19.01.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jul 2023 01:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 3439a2eb271147a5a78e7a938c3948d3-20230719
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:eba608f6-b7f5-4435-a8c7-db8af9869d8f,IP:25,
	URL:0,TC:0,Content:-25,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,AC
	TION:release,TS:-15
X-CID-INFO: VERSION:1.1.28,REQID:eba608f6-b7f5-4435-a8c7-db8af9869d8f,IP:25,UR
	L:0,TC:0,Content:-25,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:-15
X-CID-META: VersionHash:176cd25,CLOUDID:f617c5dc-dc79-4898-9235-1134b97257a8,B
	ulkID:2307191614510XI4YAKB,BulkQuantity:1,Recheck:0,SF:17|19|44|38|24|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 3439a2eb271147a5a78e7a938c3948d3-20230719
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1885092020; Wed, 19 Jul 2023 16:28:18 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 0/4] Add KFENCE support for LoongArch
Date: Wed, 19 Jul 2023 16:27:28 +0800
Message-Id: <20230719082732.2189747-1-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

Hi all,

This patchset adds KFENCE support on LoongArch.

To run the testcases, you will need to enable the following options,

-> Kernel hacking
   [*] Tracers
       [*] Support for tracing block IO actions (NEW)
   -> Kernel Testing and Coverage
      <*> KUnit - Enable support for unit tests

and then,

-> Kernel hacking
   -> Memory Debugging
      [*] KFENCE: low-overhead sampling-based memory safety error detector (NEW)
          <*> KFENCE integration test suite (NEW)

With these options enabled, KFENCE will be tested during kernel startup.
And normally, you might get the following feedback,

========================================================
[   35.326363 ] # kfence: pass:23 fail:0 skip:2 total:25
[   35.326486 ] # Totals: pass:23 fail:0 skip:2 total:25
[   35.326621 ] ok 1 kfence
========================================================

you might notice that 2 testcases have been skipped.  If you tend to run
all testcases, please enable CONFIG_INIT_ON_FREE_DEFAULT_ON, you can
find it here,

-> Security options
   -> Kernel hardening options
      -> Memory initialization
         [*] Enable heap memory zeroing on free by default

and you might get all testcases passed.
========================================================
[   35.531860 ] # kfence: pass:25 fail:0 skip:0 total:25
[   35.531999 ] # Totals: pass:25 fail:0 skip:0 total:25
[   35.532135 ] ok 1 kfence
========================================================

Thanks,
Enze

Enze Li (4):
  LoongArch: mm: Add page table mapped mode support
  LoongArch: Get stack without NMI when providing regs parameter
  KFENCE: Deferring the assignment of the local variable addr
  LoongArch: Add KFENCE support

 arch/loongarch/Kconfig               |  1 +
 arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/page.h    | 10 +++++
 arch/loongarch/include/asm/pgtable.h | 12 ++++++
 arch/loongarch/kernel/stacktrace.c   | 16 ++++---
 arch/loongarch/mm/fault.c            | 22 ++++++----
 arch/loongarch/mm/pgtable.c          | 25 +++++++++++
 mm/kfence/core.c                     |  5 ++-
 8 files changed, 137 insertions(+), 16 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230719082732.2189747-1-lienze%40kylinos.cn.
