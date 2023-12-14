Return-Path: <kasan-dev+bncBAABBENS5KVQMGQEBKBTWJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C6A281272C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:35 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-590caa98510sf5737446eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533394; cv=pass;
        d=google.com; s=arc-20160816;
        b=kqb0k/mM85vYUNJMBa1koQD5f5ja4yjqI9JnUYsdGuzBlo4EQKi/odbA1QyhAuCSGD
         gKkl/VWiWFGHN8xiCZGfsI8yawWFFO9GEBxQyTmUGSRxXY8O4sMjGvn5kwTj9dsndfyf
         KnkN+opCK0AJL17WWSwMiPXNnbAeVAMCWgLPPnpPp4W4RJeq4/qqypIfd7v/aVlw51kx
         P9UdQwMrqq9LqGI1fT0mb94aN0V2dXKvblgMcqTQVLYr95rB1gPgLEOrV/AHMrsGwkvO
         715J6mlrvFxkc+kAObtEJj+Sljp2CSidgVh5fhaXn52kdIdoVjxeIhadr3pkEaENKBDH
         yXhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FH0DMN4HN4kdw0qi3KAuUmsYl5mls/8XMcX7kv5vzkw=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=JFHCKXe1zrwurvdSRV0KHOxC/8iKTZRxIISm+xWObutdClLo3F7Ypg8cp8dGVs2027
         9vnmMcy0fbztxHfSdCkkzhvUV03tESGN6XHSo2CUK4HBpXlzo8Oz81d1Dk+wPzGovIaN
         SL91O3Y9HRAc3F3FCibuj8ljyps3Ftp4qucxsq4qIPzR3FjLhqAIMxF27w84TjhSlhH2
         fquvCELKwmwpYk1tmT76ZuWImixqrIdqS5d86zo8KwS7OY4yO+rHA8gNJdydeTsZVMCw
         DKgIJtovqJpxm796X0iy58cvP5inAHvogVGlPAUk299g2ITriz8viMk0nlKy7THTcIZU
         6OJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YmKLz6IQ;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533394; x=1703138194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FH0DMN4HN4kdw0qi3KAuUmsYl5mls/8XMcX7kv5vzkw=;
        b=drZ+VCAgHviiP6nMdopNug0gKMgoWmR2Hp310P6QY3CiifBxHRJ2G8m8F2qP3Wnftx
         zopliaYCKyp8T0wSej8c9ljb5hd8JBFM+m5CD63iW2BuZXGt1fu9p1K6ApiNR5HDI53E
         xVlyNo5N992FriG8y6ASo9jNF6mA3X0pNjIC3qoIBbDddKc1Kcednan77hez18RKg3zP
         1EeRi7eKgro12l5E35ZFN/LSxo2ICdwnF973rYKkLGa5Apyil0BZrg9sQGKRa4R4ijwe
         3aWi8VqLjwaTVNnNPE28qKbntCrpfYA0vLfxxmZVaOsbikl9UwPzdCJCM5fyD/sS3B2H
         hcyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533394; x=1703138194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FH0DMN4HN4kdw0qi3KAuUmsYl5mls/8XMcX7kv5vzkw=;
        b=rqxB35I4P0Ol/xgYUoLu4O49+6IEZIdiVsxRK+NEf3eO2xwqIIyGZCoEllOU5rIxRm
         kGgi8G4iWmMPkWJe1Z9yY+DLygA1ZYNDSj7GjwvJGO43AyN3twmIMosxrBqC7LSDP9NW
         gypVmptIh2noBQROKwjBuFA63R4YPD81G4dZ5EGRnVgOjVINKCMN/wPZXyVdjmkxCNdT
         QNL9iM4yQ0wQG03gAIAqIX//oA4Kspq0mFks30G5X9pmjXSIlyEMKkKPbURtdG5ZAgu8
         uBMvj8SDUzuhWhUM6ktEXU9qVTbJEocQ51pHWKhZbL7eagQMrYIT/C3QK6ep1MY9nOE/
         mIdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzXo8UXfw9AeQt2A7X6TqJAzpG48nqJQ4hUIOABlWSsdOnou2az
	xZ9z9hHY+FLAL6XCIMTsjBE=
X-Google-Smtp-Source: AGHT+IEEMiYpfSvvSs4jhWpnZgJivKUuaqz5xQHibC4umlxzHnVYr0PQZetJRcinFzvOLvn4yPcp0g==
X-Received: by 2002:a05:6870:7020:b0:203:27fe:2808 with SMTP id u32-20020a056870702000b0020327fe2808mr2186309oae.65.1702533393776;
        Wed, 13 Dec 2023 21:56:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:972a:b0:203:3d9c:bcc9 with SMTP id
 n42-20020a056870972a00b002033d9cbcc9ls1199498oaq.0.-pod-prod-04-us; Wed, 13
 Dec 2023 21:56:33 -0800 (PST)
X-Received: by 2002:a05:6870:eca6:b0:203:f47:512e with SMTP id eo38-20020a056870eca600b002030f47512emr3977560oab.40.1702533393198;
        Wed, 13 Dec 2023 21:56:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533393; cv=none;
        d=google.com; s=arc-20160816;
        b=AY53F74ycM8ogdkEv4rWbfqdpecTkagm3pJA6QDpGZ5nZyiiXHisT2jX5gVRpl4J0C
         HnNf6AH7ksMmi0KA0Ml3/on8O/KbcgPuvtB1hoEqntUHSNX76pwR9f0LP8Q8S5dgm+0o
         3orZDFlnRU24v76EqXdLo92W75Nr536ES9xEU4ffTW7TeMRQsMlOZuuHv58bHC4Bd32J
         w6aqYXIa6yB7FzECi7UU1pWxScd90+sD87rPEERQPOJux0Y3ZWFTh3qe1qD+0Wg63GEc
         xRHMERYpydMt1k8pwA2BC9A4tHshchdYIXCoIuJgVNJUaFUlsxQvD3d0fRzOlG+0oCq9
         snog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=p9tiV4nTklswyY7I8vqjXvodsbwP2/R00p0R5CSoBKo=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=VGovgoaGzDS07wHlgKYwsBEcyYwu3Ad9EQXyixN5gKW5H449h2apIla4HNcflkzIzG
         JN65DIEjipwHB1IfEzRY+owf28Ug9vwPp09xAQNj3a3LIGYDZ5rumKMCDF9gQhlJdrCU
         FsQEpkOMuhKmUbM7Q6r+kHsa3NIUcVmGXMhOWGFWig4gE0Vmbh8iPePzD7Mwh8yLLIvQ
         CAAng96kyWYiYlP9q346Ru4y1qgXz0jjKMA2znyqoYrzs3jy027GJFZ/5UEFYoKB2F4h
         hM4HKP6Ia9LupRgavSgz7X6wpPOeeWx7TrCDm18FAbuR1HpNJdSnzWHPgd/Ej/kFCHEF
         buFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YmKLz6IQ;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id lw12-20020a0568708e0c00b001fab154c144si1513147oab.1.2023.12.13.21.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:32 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5oGtB019316;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6eth-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5tbS8001481;
	Thu, 14 Dec 2023 05:56:25 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6et6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5dhOG013874;
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592dwew-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:23 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uMC723593570
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:22 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4C99A2004B;
	Thu, 14 Dec 2023 05:56:22 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7601220043;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 43CFD602FD;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 00/13] kmsan: Enable on powerpc
Date: Thu, 14 Dec 2023 05:55:26 +0000
Message-Id: <20231214055539.9420-1-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: yQupUEE0NnA-p1u8dDPUOZxgnN7Q8ytt
X-Proofpoint-ORIG-GUID: Hrlr57hH7l5Uyw8vyCdTKsVIagZWLZcD
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 clxscore=1015 malwarescore=0 bulkscore=0 mlxlogscore=838
 priorityscore=1501 suspectscore=0 phishscore=0 lowpriorityscore=0
 impostorscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YmKLz6IQ;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

This series provides the minimal support for Kernal Memory Sanitizer on 
powerpc pseries le guests. Kernal Memory Sanitizer is a tool which detects
uses of uninitialized memory. Currently KMSAN is clang only.

The clang support for powerpc has not yet been merged, the pull request can
be found here [1].

In addition to this series, there are a number of changes required in
generic kmsan code. These changes are already on mailing lists as part of
the series implementing KMSAN for s390 [2]. This series is intended to be
rebased on top of the s390 series.

In addition, I found a bug in the rtc driver used on powerpc. I have sent
a fix to this in a seperate series [3].

With this series and the two series mentioned above, I can successfully
boot pseries le defconfig without KMSAN warnings. I have not tested other
powerpc platforms.

[1] https://github.com/llvm/llvm-project/pull/73611
[2] https://lore.kernel.org/linux-mm/20231121220155.1217090-1-iii@linux.ibm.com/
[3] https://lore.kernel.org/linux-rtc/20231129073647.2624497-1-nicholas@linux.ibm.com/

Nicholas Miehlbradt (13):
  kmsan: Export kmsan_handle_dma
  hvc: Fix use of uninitialized array in udbg_hvc_putc
  powerpc: Disable KMSAN santitization for prom_init, vdso and purgatory
  powerpc: Disable CONFIG_DCACHE_WORD_ACCESS when KMSAN is enabled
  powerpc: Unpoison buffers populated by hcalls
  powerpc/pseries/nvram: Unpoison buffer populated by rtas_call
  powerpc/kprobes: Unpoison instruction in kprobe struct
  powerpc: Unpoison pt_regs
  powerpc: Disable KMSAN checks on functions which walk the stack
  powerpc: Define KMSAN metadata address ranges for vmalloc and ioremap
  powerpc: Implement architecture specific KMSAN interface
  powerpc/string: Add KMSAN support
  powerpc: Enable KMSAN on powerpc

 arch/powerpc/Kconfig                          |  3 +-
 arch/powerpc/include/asm/book3s/64/pgtable.h  | 42 +++++++++++++++
 arch/powerpc/include/asm/interrupt.h          |  2 +
 arch/powerpc/include/asm/kmsan.h              | 51 +++++++++++++++++++
 arch/powerpc/include/asm/string.h             | 18 ++++++-
 arch/powerpc/kernel/Makefile                  |  2 +
 arch/powerpc/kernel/irq_64.c                  |  2 +
 arch/powerpc/kernel/kprobes.c                 |  2 +
 arch/powerpc/kernel/module.c                  |  2 +-
 arch/powerpc/kernel/process.c                 |  6 +--
 arch/powerpc/kernel/stacktrace.c              | 10 ++--
 arch/powerpc/kernel/vdso/Makefile             |  1 +
 arch/powerpc/lib/Makefile                     |  2 +
 arch/powerpc/lib/mem_64.S                     |  5 +-
 arch/powerpc/lib/memcpy_64.S                  |  2 +
 arch/powerpc/perf/callchain.c                 |  2 +-
 arch/powerpc/platforms/pseries/hvconsole.c    |  2 +
 arch/powerpc/platforms/pseries/nvram.c        |  4 ++
 arch/powerpc/purgatory/Makefile               |  1 +
 arch/powerpc/sysdev/xive/spapr.c              |  3 ++
 drivers/tty/hvc/hvc_vio.c                     |  2 +-
 mm/kmsan/hooks.c                              |  1 +
 .../selftests/powerpc/copyloops/asm/kmsan.h   |  0
 .../powerpc/copyloops/linux/export.h          |  1 +
 24 files changed, 152 insertions(+), 14 deletions(-)
 create mode 100644 arch/powerpc/include/asm/kmsan.h
 create mode 100644 tools/testing/selftests/powerpc/copyloops/asm/kmsan.h

-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-1-nicholas%40linux.ibm.com.
