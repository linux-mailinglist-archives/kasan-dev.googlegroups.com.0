Return-Path: <kasan-dev+bncBAABB4PJUGTAMGQEV7Z3E3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 1478276A73D
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Aug 2023 04:58:59 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-403ad49c647sf52079951cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690858737; cv=pass;
        d=google.com; s=arc-20160816;
        b=WrYuTiQkGt/AUsPgLxcqpAZECjAO55HKh3qriP3EutgRcDNRsPa+d1NAtgx0VeTWQi
         teE7xp7rvwGDu2ud+bc+TkfDlog3RRbhvLyli80bNDcBydfW6sqDsEkmiIKqbPxz8I0+
         YoPcA9qO1Kqs9/P7+xuIdMAD4BwGt5P6cDENglm9MMj00W/8CIyxoVQIVXj3tWut3acu
         1PkA0cjQ1rxYARWFob22Ex5JvMoqcL9uPSH/tXK6pz8UdkpgJ+1dm4MKM4VZRt8YQVBP
         md+IUKVsBA3kXoozc17zRu63d5Fjsjnv+QnbjzENtADVWCuqExZOaUvCwHjgU/yvqyew
         P+Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=A0NJeC4r0cLVVhl2Hte0keJbaHBdcA1r7dFLdCZnOoQ=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=MXJIBATnqGCy8QeZt9ZJrCuzU4mHs4RlJKr+g3oVU06FVQbxGMC/SNDGOQH4F3OBiv
         hWtvv0OQZzkWxo6Bul0azmy5B0/H5WScLQgty/a5/IGSRhFVB34OKFFslE4+TTdRCU4a
         Ac7Yl++jxiyoJmUzi+sRXHOM/d2LTM9y2VOWtKXgbCMKM0lLI4x1yUvTmm+Xald9qWon
         xZz8wvOwr9bUq2HOzv4+Ohnfvjj/V84Mo12qKd9ONmxNg9DBfQaDX0yIw5lWuB014VeN
         giYEuI32RfumZFICoTw+QLQP99TMYvri3CXff2AA8+GY7HkTiO0xaoRqMciHIQxEV5kQ
         zkTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690858737; x=1691463537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A0NJeC4r0cLVVhl2Hte0keJbaHBdcA1r7dFLdCZnOoQ=;
        b=I3+jSnoRgV2exADaRbc4ROnRxzPIdF+1L4w8lMeycGvA+y+jcnzXDZOVhMXMQkFpzn
         s8gZ71/oz5yIo+yfOMKcUetFQu0PYPlx4NjjY5EO4+h4v+WIWxWRXl8Jx4HmBw58ir21
         ElcfKzqmugXWPmMB9Ig3MM87qyyWZtNBN0ZfG84wJP0FZza6A9t2OvwvTWRVEvbsYn2+
         u6R/LyuNuVZKwnLqcP1QLVEcfcFxmV0UWPfoiBrNJXPQl22gpeNMf22LydT8Urj8ORob
         OUl6h5WUU/RprRjD7zmMGPWIFrwv8JGmZZudMAXLqx9jx+Y4/OtYQYRIK4GvMtoagpIM
         3zJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690858737; x=1691463537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A0NJeC4r0cLVVhl2Hte0keJbaHBdcA1r7dFLdCZnOoQ=;
        b=I+qphnJ6CUVpVAstWLRWJ6YZXEjlVVwLBo95gzcFYC15HjBaypc4xq3CUfY9nECiAl
         aO9LzMVSuETRRHFofNMIcgCJ/ecuT40aka/Rx8khRjCqRWg8HAzxF8UtUxIUR+NlrB8m
         gFNrwXT1mk/VGy2LSEVL4hdf3MSXQwAG2AZRHrUtISTFiiJIiTmPQhtAIeeHY96JZO+p
         YgFJrkx8oTThtvPioGIxGxDDrN1Pp7NoNC1mOR8/+sZ6Au+k69IlzYGSKdIaT5jdTJMt
         NfkU6EG4Lp932Etnm5qU5s5sXCbtXtZ9BbRRCVKt2Ej+NnThyZqq+YNVR+BOBAWwcNmx
         6lSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLayvuMDIW7lKoS4kNEirpeZ9ffUhZXWYV78990YBynxoYW68owN
	OZrityY9+CVMwezYCIeERQc=
X-Google-Smtp-Source: APBJJlFNTHH4bF9meKC4xCQVk571u/GxkcAARMnq9anuhsLrplYy6CvlCdHQYsyZnEYsOnuI+fmh2g==
X-Received: by 2002:ac8:7e81:0:b0:403:a63d:9a2e with SMTP id w1-20020ac87e81000000b00403a63d9a2emr10830460qtj.10.1690858737730;
        Mon, 31 Jul 2023 19:58:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e0cc:0:b0:62f:e5ab:e5f4 with SMTP id x12-20020a0ce0cc000000b0062fe5abe5f4ls4115137qvk.0.-pod-prod-05-us;
 Mon, 31 Jul 2023 19:58:57 -0700 (PDT)
X-Received: by 2002:a37:9301:0:b0:767:2a66:b792 with SMTP id v1-20020a379301000000b007672a66b792mr10523166qkd.42.1690858737114;
        Mon, 31 Jul 2023 19:58:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690858737; cv=none;
        d=google.com; s=arc-20160816;
        b=tvQTRvCH0osvayb1WeIQhnf+RjYn69iFXtgPdp1b4izfzxesH287qhNmfdcC5uXZPF
         MM/rAvfr+fUqXDaEPhGbegZLag7MeALCEENhmfEK2MsIPwJf8xiCCAdkWGmZsGKsM8W2
         FI9Wl61Uao+F3a/CPwvRQtf0LepXlLsEUJpWlRx6QgBDwpv0hWpaLvCz2yngsiGGKVrs
         mTMR8iLaiT+G+4crvImxY8H897KRGBHYsfWbaV1BZe7g+32vYkyD2MMiOwAYuaOpYCaC
         NQnD36HLEPq5QgcfHcf4VU+YaZgC4Pvga8lpi9xj9KVBOCUFY3ujDNq+P9ry8WpS8zYX
         j91Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=0BF3lT/0xiTOm5QquCDJySjWwvInryKlMrYrobIM5mA=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=js/1E8XMqOcdnr1ht1rFbQVVuavI7IoeLQq/6XEprfKJ5mQqUDp96IWbkx7fqVA23D
         Q4rdtUehSdfPfTGNavvGIiOqqWkUFJQ+f59f8ekXVF/WVEEFOacO/OhkeBQywWgiYbGV
         vwv7sYId7rmLw4yDs0VShDHStCdpH0Uq7aldUZ+sHUgQZ63ml4dDitCO2p3l5DIEoKVX
         ZCoO3tbd7S/8aqPGbqgWub0pgfQMRXyMAGsEvamrt3H4rSU8b8B56J27yy+DeGOxLWsH
         RuY3Rdho4KVJRwtyLE3cuoTdrZTsVGDDAKt+M6RxGmilhT7tfJmHp1n/Tq4743GXjgzG
         j4hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id cn8-20020a056a00340800b0068730bbed1esi221310pfb.2.2023.07.31.19.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Jul 2023 19:58:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 27a11fa6c27a40fd83e2eacc12f470c1-20230801
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:e37cdbcf-b500-4d46-a435-69cda3722b0a,IP:15,
	URL:0,TC:0,Content:-25,EDM:25,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,A
	CTION:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:e37cdbcf-b500-4d46-a435-69cda3722b0a,IP:15,UR
	L:0,TC:0,Content:-25,EDM:25,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACT
	ION:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:fb48bfa0-0933-4333-8d4f-6c3c53ebd55b,B
	ulkID:23080110584231HYNJKY,BulkQuantity:0,Recheck:0,SF:17|19|44|38|24|102,
	TC:nil,Content:0,EDM:5,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 27a11fa6c27a40fd83e2eacc12f470c1-20230801
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 769058494; Tue, 01 Aug 2023 10:58:41 +0800
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
Subject: [PATCH 0/4 v3] Add KFENCE support for LoongArch
Date: Tue,  1 Aug 2023 10:58:11 +0800
Message-Id: <20230801025815.2436293-1-lienze@kylinos.cn>
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

v3:
   * Address Huacai's comments.
   * Fix a bug that Jackie Liu pointed out.
   * Rewrite arch_stack_walk() with the suggestion of Jinyang He.

v2:
   * Address Huacai's comments.
   * Fix typos in commit message.

Thanks,
Enze

Enze Li (4):
  KFENCE: Defer the assignment of the local variable addr
  LoongArch: mm: Add page table mapped mode support
  LoongArch: Get stack without NMI when providing regs parameter
  LoongArch: Add KFENCE support

 arch/loongarch/Kconfig               |  1 +
 arch/loongarch/include/asm/kfence.h  | 66 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/page.h    |  8 +++-
 arch/loongarch/include/asm/pgtable.h | 16 ++++++-
 arch/loongarch/kernel/stacktrace.c   | 18 ++++----
 arch/loongarch/mm/fault.c            | 22 ++++++----
 arch/loongarch/mm/pgtable.c          |  7 +++
 mm/kfence/core.c                     |  5 ++-
 8 files changed, 123 insertions(+), 20 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230801025815.2436293-1-lienze%40kylinos.cn.
