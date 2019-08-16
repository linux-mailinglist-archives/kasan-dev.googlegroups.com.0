Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBNOD3TVAKGQEJAOR57Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B48A90A52
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 23:35:51 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id x1sf4642254pfq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 14:35:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565991350; cv=pass;
        d=google.com; s=arc-20160816;
        b=pbijEaNAsa4eqVka2Kbgy9LFDXhjD7C0zzcrAAgERy5+/TbxI/JO/293enexDVytYU
         MAVG3F1LyERoEzFeECTBN2Y0BWrEiJiQ3T/QJ0VTaXKZMn772si6UxcO4CLg4eK/M6nW
         35lqsYdKIO/3ohSw1wYMl2Fgznv3gMi5+HmQcIpcCHT1W/MOhkv34al/1M2ODp4at7t2
         VQsJW5N78sDBZtVl9oD0agjuLsNUcfFF/xlBLdQ2j/sb77CfJkgznQMD4BuJthuBsSg2
         NtkWA1tDdP9lL6gcQ3bnPB8YxD5rfnn7pMZ6LB/AB1BU/f5jB5LUf8QAvQRI7cyiB3cY
         uS7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=aaLbkbaIRZQHUpGto7GV68St9sRtP58Cb4dQ+k6wai8=;
        b=w3yP9SK+sUSeYdD0j8syBhDg5jdBsDfTxzJmOPPLqoC0FSjkzyuRsFvAipqwUjnhVj
         6zow0BRHUXkhxNNWOYLTnkxNlpemg/26489AqEZAGbNu2xhagm50vGvRPHoJjBzT9sr1
         SuuJwL07HRZ0WIGwMcGJCAMJLwSPSeRPgktLA/BDcXAzLXjbfLupn/D2i6zsrBHCr2VE
         Bkwyw5OrUh2VJiQvdlNOVluT8huDAgsAys46b+E3UCu/Bit1z+Rpb9uZubdcYe/E3EmU
         1H5VyBRUbH1UvxOS0SbQGusSE35d8Mohs22F2iLWZsfvnsDFyM4a/rDwr1GRB5GEYXm2
         31qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=oTA7ozdW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aaLbkbaIRZQHUpGto7GV68St9sRtP58Cb4dQ+k6wai8=;
        b=qErQlrmx1OGbiEdwtyiOlDQ5PfgIgF/TX+Sh91Zda63wbtkDYaaADiIMu0M5vJqbjx
         5BT+X28EgaDQaomk5RUfdG00r10/db+usxEu6Wzyf2kxo/yLVGPvdhPLbN2DRoIrPdPa
         /Ca7cwXRDrXavpiT/6WqovTZeAk7OOhxHfPmAnhFS3/6mjRH03Gm98vH/Q0CeXsBr+BF
         YfpvDilujDvZoAI2UizTbkiMFEa6lcpcTzVOKa1aUryr4LnjgdCCfJGkNfgbreiJj+St
         vCWxKrBk8Qvtvoff2399G7s1HSLVbpaQ80qV9YLg+XK2rgGWxNeIGXFIcmIK955kfODD
         lBbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aaLbkbaIRZQHUpGto7GV68St9sRtP58Cb4dQ+k6wai8=;
        b=ljkGOKCxGs6Mb2GEocZEFWefoY/3qdntQXJ/ghoGFn6ISsEjDRqbkBY6cStmgqtGsR
         xsa1nSG6oTLBPEiFnRQBU6POcHIFomGGEiuefnhDtYQLJ8B/6a66FFqn0amkg/lSY3qq
         ZIfFShI+1VgqAPCRJPYt5HZfb1GODGNknUxVn4XibOmcG0b0ogenUuXHkbaJyHscB7ge
         TdMbxB7HAu3/i/XMyT6kdQaz9zfProBj9dF6QEe2ZfFSosB7tS261FgEUMXy2w2vMc7I
         fLdaT0tMZQT7VqOLUN3eRsGqWyNzC7YRUQYBmgXdNFQdZn99ZLVdJF4xCChTJJKhqDo2
         XhgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtPYp2qYzHiKFS4scmcEaYR7NlDT2UphRZh2sNo8D253dEY8Tj
	Eh4hVIcUs9bIcbtigGTQBP0=
X-Google-Smtp-Source: APXvYqy6xJX2oS6UbR74MHoh2TvT1N2+iA4uhzcwLSvHUnnz6lnub9twR9Un4i5oHOUgOnHYyl8yiw==
X-Received: by 2002:a65:64ce:: with SMTP id t14mr9378381pgv.137.1565991349768;
        Fri, 16 Aug 2019 14:35:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:47ca:: with SMTP id f10ls2034023pgs.13.gmail; Fri, 16
 Aug 2019 14:35:49 -0700 (PDT)
X-Received: by 2002:aa7:8b52:: with SMTP id i18mr13023870pfd.194.1565991349417;
        Fri, 16 Aug 2019 14:35:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565991349; cv=none;
        d=google.com; s=arc-20160816;
        b=dhD21BUJGgvdSgyyT83vSGQJle+IuM1EM2KNUel1gjhXcbvY/3UlqMmYhxtPqYofZ8
         3rMRm2TPSgQy34sleOj2n6n0f8w5l09XQdReYYSaAg02/tr53xEv074ksZado/e7o27r
         cAgvR9fLve/qmgYyGLVRjBVhMIDNst0FZ98klwz2laz1qa3FIUyOERP12UshETWbg3e0
         cr2XrW+cwAJp6eyPAta7JeBoHjRCLaWNhVA4pgkp4/70sBPaVBGcELCB7ufLe3B2K8/b
         kT9k8cPDAiFlkdTKD1Mw6ByY3/3y3XKDuhjsdgulnpFJ+xcgPApjdFMnZiX29kW30XN9
         oVQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:cc:to:from:subject
         :message-id:dkim-signature;
        bh=yu9YfNsqZTz0N34i23hzcYnxaf08XkUKNrfLRroWKrw=;
        b=EZaLiABGPcRRhFAt5zKbmt9gRGFJxiOXVIEVydYgRGfGYCnFVRNghjGGWKrZ0RrX8J
         EfX8/gBo62G6IWz1VvAOvLf8iMNR4rRM7LlmjdSqQ3Aaml485JjVMeW3C8pG2IfpbsV3
         FezXZRT3LRjMkcCIu9SxmJBal0Nee+Zp4QjmUFBFxi6DrkhjI3CKnAuUJb5TYq5rHiQH
         XQU1uJMdUJAvAu8H2s07fG8DOBMlFu5gVpGZPa4YG+qKiHrkE45n7JZjftQfC7mdFGsR
         19IJ+OTt7axqD+YBloO9j7VM2R27VvelkUOYjP6Ecjd+ipbRIfQhIqiKsl/npaomtVNj
         oMQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=oTA7ozdW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id o9si282454pjt.2.2019.08.16.14.35.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2019 14:35:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id e8so7647670qtp.7
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 14:35:49 -0700 (PDT)
X-Received: by 2002:ac8:5343:: with SMTP id d3mr10783829qto.50.1565991348387;
        Fri, 16 Aug 2019 14:35:48 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id k49sm1410047qtc.9.2019.08.16.14.35.46
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Aug 2019 14:35:47 -0700 (PDT)
Message-ID: <1565991345.8572.28.camel@lca.pw>
Subject: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
To: Dan Williams <dan.j.williams@intel.com>
Cc: linux-mm@kvack.org, linux-nvdimm@lists.01.org,
 linux-kernel@vger.kernel.org,  Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev@googlegroups.com
Date: Fri, 16 Aug 2019 17:35:45 -0400
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=oTA7ozdW;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

Every so often recently, booting Intel CPU server on linux-next triggers th=
is
warning. Trying to figure out if  the commit 7cc7867fb061
("mm/devm_memremap_pages: enable sub-section remap") is the culprit here.

# ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
devm_memremap_pages+0x894/0xc70:
devm_memremap_pages at mm/memremap.c:307

[=C2=A0=C2=A0=C2=A032.074412][=C2=A0=C2=A0T294] WARNING: CPU: 31 PID: 294 a=
t mm/kasan/init.c:496
kasan_add_zero_shadow.cold.2+0xc/0x39
[=C2=A0=C2=A0=C2=A032.077448][=C2=A0=C2=A0T294] Modules linked in:
[=C2=A0=C2=A0=C2=A032.078614][=C2=A0=C2=A0T294] CPU: 31 PID: 294 Comm: kwor=
ker/u97:1 Not tainted 5.3.0-
rc4-next-20190816+ #7
[=C2=A0=C2=A0=C2=A032.081299][=C2=A0=C2=A0T294] Hardware name: HP ProLiant =
XL420 Gen9/ProLiant XL420
Gen9, BIOS U19 12/27/2015
[=C2=A0=C2=A0=C2=A032.084430][=C2=A0=C2=A0T294] Workqueue: events_unbound a=
sync_run_entry_fn
[=C2=A0=C2=A0=C2=A032.086347][=C2=A0=C2=A0T294] RIP: 0010:kasan_add_zero_sh=
adow.cold.2+0xc/0x39
[=C2=A0=C2=A0=C2=A032.088303][=C2=A0=C2=A0T294] Code: ff 48 c7 c7 b0 06 74 =
86 e8 0e e2 db ff 0f 0b e9 64
f7 ff ff 48 8b 45 98 48 89 45 b8 eb be 48 c7 c7 b0 06 74 86 e8 f1 e1 db ff =
<0f>
0b b8 ea ff ff ff e9 ad fe ff ff 48 c7 c7 b0 06 74 86 e8 d9 e1
[=C2=A0=C2=A0=C2=A032.094183][=C2=A0=C2=A0T294] RSP: 0000:ffff8884428cf738 =
EFLAGS: 00010282
[=C2=A0=C2=A0=C2=A032.096030][=C2=A0=C2=A0T294] RAX: 0000000000000024 RBX: =
ffff88833c1b8100 RCX:
ffffffff85730ba8
[=C2=A0=C2=A0=C2=A032.098391][=C2=A0=C2=A0T294] RDX: 0000000000000000 RSI: =
dffffc0000000000 RDI:
ffffffff86964740
[=C2=A0=C2=A0=C2=A032.100802][=C2=A0=C2=A0T294] RBP: ffff8884428cf750 R08: =
fffffbfff0d2c8e9 R09:
fffffbfff0d2c8e9
[=C2=A0=C2=A0=C2=A032.103229][=C2=A0=C2=A0T294] R10: fffffbfff0d2c8e8 R11: =
ffffffff86964743 R12:
1ffff11088519ef3
[=C2=A0=C2=A0=C2=A032.105581][=C2=A0=C2=A0T294] R13: ffff88833dbc8010 R14: =
000000017a02c000 R15:
ffff88833c1b8128
[=C2=A0=C2=A0=C2=A032.107956][=C2=A0=C2=A0T294] FS:=C2=A0=C2=A0000000000000=
0000(0000) GS:ffff88844db80000(0000)
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A032.110585][=C2=A0=C2=A0T294] CS:=C2=A0=C2=A00010 DS: 000=
0 ES: 0000 CR0: 0000000080050033
[=C2=A0=C2=A0=C2=A032.112606][=C2=A0=C2=A0T294] CR2: 0000000000000000 CR3: =
0000000163012001 CR4:
00000000001606a0
[=C2=A0=C2=A0=C2=A032.112610][=C2=A0=C2=A0T294] Call Trace:
[=C2=A0=C2=A0=C2=A032.112622][=C2=A0=C2=A0T294]=C2=A0=C2=A0devm_memremap_pa=
ges+0x894/0xc70
[=C2=A0=C2=A0=C2=A032.112635][=C2=A0=C2=A0T294]=C2=A0=C2=A0? devm_memremap_=
pages_release+0x510/0x510
[=C2=A0=C2=A0=C2=A032.119291][=C2=A0=C2=A0T294]=C2=A0=C2=A0? do_raw_read_un=
lock+0x2c/0x60
[=C2=A0=C2=A0=C2=A032.122470][=C2=A0=C2=A0T332] namespace0.0 initialised, 4=
00896 pages in 50ms
[=C2=A0=C2=A0=C2=A032.143086][=C2=A0=C2=A0T294]=C2=A0=C2=A0? _raw_read_unlo=
ck+0x27/0x40
[=C2=A0=C2=A0=C2=A032.143094][=C2=A0=C2=A0T294]=C2=A0=C2=A0pmem_attach_disk=
+0x490/0x880
[=C2=A0=C2=A0=C2=A032.143106][=C2=A0=C2=A0T294]=C2=A0=C2=A0? pmem_pagemap_k=
ill+0x30/0x30
[=C2=A0=C2=A0=C2=A032.186834][=C2=A0=C2=A0=C2=A0=C2=A0T1] debug: unmapping =
init [mem 0xffffffff9d602000-
0xffffffff9d7fffff]
[=C2=A0=C2=A0=C2=A032.195383][=C2=A0=C2=A0T294]=C2=A0=C2=A0? kfree+0x106/0x=
400
[=C2=A0=C2=A0=C2=A032.195394][=C2=A0=C2=A0T294]=C2=A0=C2=A0? kfree_const+0x=
17/0x30
[=C2=A0=C2=A0=C2=A032.314107][=C2=A0=C2=A0T294]=C2=A0=C2=A0? kobject_put+0x=
fb/0x250
[=C2=A0=C2=A0=C2=A032.334569][=C2=A0=C2=A0T294]=C2=A0=C2=A0? put_device+0x1=
3/0x20
[=C2=A0=C2=A0=C2=A032.354169][=C2=A0=C2=A0T294]=C2=A0=C2=A0nd_pmem_probe+0x=
83/0xa0
[=C2=A0=C2=A0=C2=A032.374162][=C2=A0=C2=A0T294]=C2=A0=C2=A0nvdimm_bus_probe=
+0xaa/0x1f0
[=C2=A0=C2=A0=C2=A032.395901][=C2=A0=C2=A0T294]=C2=A0=C2=A0really_probe+0x1=
a2/0x630
[=C2=A0=C2=A0=C2=A032.416352][=C2=A0=C2=A0T294]=C2=A0=C2=A0driver_probe_dev=
ice+0xcd/0x1f0
[=C2=A0=C2=A0=C2=A032.438901][=C2=A0=C2=A0T294]=C2=A0=C2=A0__device_attach_=
driver+0xed/0x150
[=C2=A0=C2=A0=C2=A032.463074][=C2=A0=C2=A0T294]=C2=A0=C2=A0? driver_allows_=
async_probing+0x90/0x90
[=C2=A0=C2=A0=C2=A032.489538][=C2=A0=C2=A0T294]=C2=A0=C2=A0bus_for_each_drv=
+0xfa/0x160
[=C2=A0=C2=A0=C2=A032.511038][=C2=A0=C2=A0T294]=C2=A0=C2=A0? bus_rescan_dev=
ices+0x20/0x20
[=C2=A0=C2=A0=C2=A032.731179][=C2=A0=C2=A0T294]=C2=A0=C2=A0? do_raw_spin_un=
lock+0xa8/0x140
[=C2=A0=C2=A0=C2=A032.754475][=C2=A0=C2=A0T294]=C2=A0=C2=A0__device_attach+=
0x16d/0x220
[=C2=A0=C2=A0=C2=A032.775648][=C2=A0=C2=A0T294]=C2=A0=C2=A0? device_bind_dr=
iver+0x80/0x80
[=C2=A0=C2=A0=C2=A032.798379][=C2=A0=C2=A0T294]=C2=A0=C2=A0? __kasan_check_=
write+0x14/0x20
[=C2=A0=C2=A0=C2=A032.821550][=C2=A0=C2=A0T294]=C2=A0=C2=A0? wait_for_compl=
etion_io+0x20/0x20
[=C2=A0=C2=A0=C2=A032.846143][=C2=A0=C2=A0T294]=C2=A0=C2=A0device_initial_p=
robe+0x13/0x20
[=C2=A0=C2=A0=C2=A032.868959][=C2=A0=C2=A0T294]=C2=A0=C2=A0bus_probe_device=
+0x10f/0x130
[=C2=A0=C2=A0=C2=A032.891093][=C2=A0=C2=A0T294]=C2=A0=C2=A0device_add+0xadb=
/0xd00
[=C2=A0=C2=A0=C2=A032.910946][=C2=A0=C2=A0T294]=C2=A0=C2=A0? root_device_un=
register+0x40/0x40
[=C2=A0=C2=A0=C2=A032.935477][=C2=A0=C2=A0T294]=C2=A0=C2=A0? nd_synchronize=
+0x20/0x20
[=C2=A0=C2=A0=C2=A032.956715][=C2=A0=C2=A0T294]=C2=A0=C2=A0nd_async_device_=
register+0x12/0x40
[=C2=A0=C2=A0=C2=A032.981106][=C2=A0=C2=A0T294]=C2=A0=C2=A0async_run_entry_=
fn+0x7f/0x2d0
[=C2=A0=C2=A0=C2=A033.003537][=C2=A0=C2=A0T294]=C2=A0=C2=A0process_one_work=
+0x53b/0xa70
[=C2=A0=C2=A0=C2=A033.026673][=C2=A0=C2=A0T294]=C2=A0=C2=A0? pwq_dec_nr_in_=
flight+0x170/0x170
[=C2=A0=C2=A0=C2=A033.051060][=C2=A0=C2=A0T294]=C2=A0=C2=A0worker_thread+0x=
63/0x5b0
[=C2=A0=C2=A0=C2=A033.071431][=C2=A0=C2=A0T294]=C2=A0=C2=A0kthread+0x1df/0x=
200
[=C2=A0=C2=A0=C2=A033.089767][=C2=A0=C2=A0T294]=C2=A0=C2=A0? process_one_wo=
rk+0xa70/0xa70
[=C2=A0=C2=A0=C2=A033.112635][=C2=A0=C2=A0T294]=C2=A0=C2=A0? kthread_park+0=
xc0/0xc0
[=C2=A0=C2=A0=C2=A033.132698][=C2=A0=C2=A0T294]=C2=A0=C2=A0ret_from_fork+0x=
35/0x40
[=C2=A0=C2=A0=C2=A033.155214][=C2=A0=C2=A0T294] ---[ end trace 6917fee95b72=
ffee ]---
[=C2=A0=C2=A0=C2=A033.182365][=C2=A0=C2=A0=C2=A0=C2=A0T1] debug: unmapping =
init [mem 0xffffffff86e7b000-
0xffffffff87031fff]
[=C2=A0=C2=A0=C2=A033.184491][=C2=A0=C2=A0T332] pmem0: detected capacity ch=
ange from 0 to 1642070016
[=C2=A0=C2=A0=C2=A033.251029][=C2=A0=C2=A0T294] nd_pmem: probe of namespace=
1.0 failed with error -22

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1565991345.8572.28.camel%40lca.pw.
