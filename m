Return-Path: <kasan-dev+bncBAABBN6R7WSQMGQEGWHFFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 33CC5760A1D
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:16:25 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5667afccc45sf8920534eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265784; cv=pass;
        d=google.com; s=arc-20160816;
        b=eHgLSaRHT0Lpx2dSb5Z3XPeir99vVQ5bBeNNv9+ti6VbeqOVb7HTkyRjAR3NmLJ7xk
         nGUbTvXmlotmAZc1VorqsrrKTc/E3BDZWICjWfouIyflkLVFX3EFUO8EdTPhbHLJc2gK
         fvwZ05LGUBIjWDJkXg2jUj+WshyFHjMUFCJqMgBayTjosTxbGQFvf9758ZMSsWVCQSBD
         YVQBeDVdDedZyYEFiYqTAud/croWloZdm1d8pVi5d3rPcp6C6QpxWapeOp51t0/xVvpa
         RUGQn0cxsZmK50X/wxSsLLhkuMZtK6VYOAeD4eBhK/iICInVJwiw+Af36WOPBLVjrfY8
         jD1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UbS16yzxIKdta7YUQMqAh4HxkLUqIBL7TZ4ejS5drWI=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=yxK5Hin5JW0b4D0bndgB8lfdGH4JHBE7QcbDVo3QFYhtW18BAm9HVnPydO6PAMYeKx
         WrcThqIAaATYfQhHMW97pg/HxpYfuM4gKrzhN6/1XqA8uSoNuenZ9x1XO+98i98NuJPF
         syozN0KIDE3UZTjBL2osP1pjkkfpKTK949zbG2Uu9bqZ5IK8exKJiNV4zIySHjXfPchh
         zsj1kRArwPgEjBAJww250/RkJp4/hNX2H4FZ/yXgWvfS8eDeaqG16ggCnNaUsW8XbhYZ
         cTasH/CZANl1Z/vSXiua85+7l2UpY8HxODwwneos5MENJiTmu7XM2dS6hBIXwDLbHwMC
         LjiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265784; x=1690870584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UbS16yzxIKdta7YUQMqAh4HxkLUqIBL7TZ4ejS5drWI=;
        b=oXN4WL1j9jsdBxjW50tGJ6gPCLYqNbk1sG6s4hxQLlvLYILLYYQEd4iuYqgafpcTZv
         +1nXYK5sGmhFYOX5omMoDbTao+zWxbnbCBkmNbmY04r7PmtSBiId1YjxnrmY+d0iwIZE
         pfzI4oxkh9WJSrn+kdleqaAI2aeGWUDacesMtvTqUjHnbKeoGEaZFnuBffblwYrjfeXA
         KzCUjvNXFDbT7myrLnVeYjO7tPSMezQ9yBGeHOeOpefbTx9nQ+OYvjYYBBP+kKzcGzfJ
         jbX4S5oJsEiFxc5AKoA/wzAeVdM2i0CmBK7kIY1E0LNru1D//CD2g/+5S3z1//pHEXc3
         ttkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265784; x=1690870584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UbS16yzxIKdta7YUQMqAh4HxkLUqIBL7TZ4ejS5drWI=;
        b=KclTjlsTg06ovqKOwuC9zPsEQVuzmpmeZaLRzQMjBWQQWLwcVgk80xj7DiXKp/ThrT
         GmIL1nLXwQhR0WRN67pTXZ37UTx9zyM0vj2pg11P2x2syLwR6eLK5hFDzm8S7CCddgCn
         22DM+hJGpAAlcSicAYHWIfCSRRZ5OtXpT+114nDDjB+ZC+1/YA3IR7oOoifKXPmitLji
         Yox/pntTn4O1weP8PR1mRAdwUoyH2cAnoo9dil57x5P+vdG1L52HYtifClG9I16YVvJn
         IEz9wbZNdwrtRyLrM08GELhV6ieXcK5Z4vlwdWQc2ygsQFfM2o9NS1F9JhcFZBjVGlB1
         8g+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYlWC29AddOuSOm0zedr4xYcDNskM4uRUrrOvXl/rXz41lAf7L/
	mlbVhIhhb1Sa/PejJ+s1N0A=
X-Google-Smtp-Source: APBJJlHuubjAQV/76ap1DKqZQWr7eT7aHHVczSta3rAtq4UmTXnOlkFR6TXvGNZwMRiIS1LLTyFWwQ==
X-Received: by 2002:a4a:868c:0:b0:566:ef1e:f11c with SMTP id x12-20020a4a868c000000b00566ef1ef11cmr7886879ooh.3.1690265783749;
        Mon, 24 Jul 2023 23:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5248:0:b0:567:867c:82cc with SMTP id d69-20020a4a5248000000b00567867c82ccls24369oob.2.-pod-prod-01-us;
 Mon, 24 Jul 2023 23:16:23 -0700 (PDT)
X-Received: by 2002:a05:6808:1a26:b0:3a4:8251:5f43 with SMTP id bk38-20020a0568081a2600b003a482515f43mr15317597oib.40.1690265783124;
        Mon, 24 Jul 2023 23:16:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265783; cv=none;
        d=google.com; s=arc-20160816;
        b=wGci3Oi0r8sb3p4m51qkDZekaOwgjDR8rmpcskHA0reP+Yd+vf8hUtmXiZ4pWcBh4R
         fYbt+wDp4SoILPMCoHyCV3Qy0DAEFV105dOF+ehTZgXlzjj2U9vWdUM+uF3c6kZ8ipqO
         ceRlz6A+jQPl3VscANlQLEvQ1NJVAOtHEJoV1v0XqX85KGSD1znHusl5KHJB9gc2pwjI
         58iXkcMjJ/qgOebkS3y7jtma/CJdg4w+E43Tj4b3zKpNbZC+J3q9EkGtGXwRFS9VA6ag
         SehfPwdTn1nCZ5f9nwLV9Ve/aOxNZEA+KSo6qXzPztl8aMsx5J5Qu2jmeU/xsiNGJLMr
         Bwcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=mOOVW6S6bs9Y+rDFTcpMRgwg/78teBVmrkMNgmzjB3c=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=JTc1vp1RlIez8oshCa+KSVbq1OFBSi2Pu9lFqRgppFtoH6YKDoWngXvMOEAJnnBHqV
         LaZD3I0iDXlydACpEnOObxVR1Rx7+5NtW5Z3QpTnvvDrmf+Ms9M3574cEMuav9OqKTHG
         8z9X7det8q2fOVNsy8vzOVquF+yumRIO2x0YRRXhqgJyUEknrpE1MgBeBa+6U9dUoz8/
         I8Atdq7YfQGE1+tVBvGH26CHCXgTu8Zafjo3pOmFZGjOUpG3Z0kKGOJPRhbnKITH8m7W
         qNypdoD02edOWvqfplLGc5PBDQDwMCPHBUQzhss5dJENN71ouMJD0PbpPLpwhAjOk8ER
         pBvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id s12-20020a170902c64c00b001bb8a6255c1si374188pls.12.2023.07.24.23.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 23:16:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: dfbab49fd60a4e0dabc0f21bb2a2da4c-20230725
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:3a22af29-da51-4ad3-87f2-7eee7ef58c26,IP:15,
	URL:0,TC:0,Content:-25,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,AC
	TION:release,TS:-25
X-CID-INFO: VERSION:1.1.28,REQID:3a22af29-da51-4ad3-87f2-7eee7ef58c26,IP:15,UR
	L:0,TC:0,Content:-25,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:-25
X-CID-META: VersionHash:176cd25,CLOUDID:1c3b7fa0-0933-4333-8d4f-6c3c53ebd55b,B
	ulkID:230725141513XFGXOQYJ,BulkQuantity:0,Recheck:0,SF:24|17|19|44|38|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: dfbab49fd60a4e0dabc0f21bb2a2da4c-20230725
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 69104657; Tue, 25 Jul 2023 14:15:11 +0800
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
Subject: [PATCH 0/4 v2] Add KFENCE support for LoongArch
Date: Tue, 25 Jul 2023 14:14:47 +0800
Message-Id: <20230725061451.1231480-1-lienze@kylinos.cn>
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

v2:
   * Address Huacai's comments.
   * Fix typos in commit message.

Thanks,
Enze

Enze Li (4):
  LoongArch: mm: Add page table mapped mode support
  LoongArch: Get stack without NMI when providing regs parameter
  KFENCE: Defer the assignment of the local variable addr
  LoongArch: Add KFENCE support

 arch/loongarch/Kconfig               |  1 +
 arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/page.h    | 19 ++++++++-
 arch/loongarch/include/asm/pgtable.h | 16 ++++++-
 arch/loongarch/kernel/stacktrace.c   | 20 ++++++---
 arch/loongarch/mm/fault.c            | 22 ++++++----
 arch/loongarch/mm/pgtable.c          |  6 +++
 mm/kfence/core.c                     |  5 ++-
 8 files changed, 133 insertions(+), 18 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230725061451.1231480-1-lienze%40kylinos.cn.
