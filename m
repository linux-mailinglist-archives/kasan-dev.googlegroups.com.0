Return-Path: <kasan-dev+bncBCKPFB7SXUERBF55SXCQMGQEWLWAMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E8D5EB2D384
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:35:20 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b28434045asf72847371cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668120; cv=pass;
        d=google.com; s=arc-20240605;
        b=c/wz2N67psO1URfKz7sqEahIl2Mk06/z3JnOoI4G3xznmIC+b+tqH0p8LiiGgRXHNH
         I8GBBavJm3wapGHbG94Ny64+CD0HoNQ0ij/x+Hd7+MOgDCoD1QeJ6YorIA76qWA8Du4p
         pt22Ic3pT/2lDVAS46BkXJQ2qR6O1odeFoRlwvOogBmWsJZj8pl5krDStnQU2IbuK8c6
         1i0a5Sg9lw+6eoaxfdTcNqDo/Y0buz+XJ2xR6iL4g5Mnldi8NbUi/oMEwpWc82KFSyVd
         jrgUsRO2oSPNhd2xBbVjMHRBGk9Jkgen6tprMLYPwlcdnyfDjezhODVWpw2xOt1ZOoD9
         a32g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=a2EOnyxBO/NpTpURqF8PY7niulJHqYOIQSAAArOBeFM=;
        fh=/j57afICtGiXz2hHEk4aNp5aXjvKVVpgx2SYza+v/sc=;
        b=FU7oilnVqwJUHn1uSXS2rBKQXKLlZhFGeOr7yTAJoYR1lwa+JOZQgQmRNlxxNIOAmj
         4R/vVj5az6Vhp4Fbs44xioQnpfg73jQRTBVX6Ehz2RXhzr/pmVpbpapH37ySbs6xtFXL
         hYXWlSY8x5lMgifNa5hBpRt+M/+xcJ7M02yUocn42ji776k9DiWSKichhYh3oGjYUpA9
         JUTssWjVbe73DKuzyXV9ONsMDjF+otBuDwAeJT1p3Q5iWygoZSczWMr4MEn/UyGSW+go
         1gdwugNXv6kHYBDYGC6gZzH+h+mpLyXCkYxga2E2YosXomUGj8kOQC7IGIf/S1nlsvbH
         E+Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fMBlWmnR;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668120; x=1756272920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a2EOnyxBO/NpTpURqF8PY7niulJHqYOIQSAAArOBeFM=;
        b=SfvJOO93aQGeEUJNiQfFZ/Ws0DGo8ZPNCKGBm4dgqWPY5ajr/6WnchHhbSXiZrqwkC
         XriswklbUhOt4dvFS7UMTmiK3mB+l09DD5P9BsJj+gvfnUFqPyUJ+6QLVYYnxNlbUog1
         3ef4+YcZRvfh57uwAVVqGsT+5A8lXAxXoeGfRBJsVHYaTmphB08JW1ER36nsGHWObG4o
         677+EUioN9o4LNei8wTrDVAypODi5u2KB4SxotPk7dy49EQeoERak6h88O4VZXXp1CWB
         f5chAK4mF0Ej5HrkOeneGFFVlHz/6UstBM70226jXT6u8ep4F1ukIiAmxR0chlClkAcB
         BA4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668120; x=1756272920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=a2EOnyxBO/NpTpURqF8PY7niulJHqYOIQSAAArOBeFM=;
        b=pkthjEuMMNwERwxQ/m6C1K0o6NgUgP8FicQBA8tdo9bJ2+oJhRaO7xozkUdJoJPusQ
         Zoe0QiBOvYWmsN5ePyUylwP32U/bygy4Smy11bG0gt8+ja+BMqVm71qxtrSChmI14nlZ
         PdHlbHOPHoNaVKp0omqZdPIhbjnbeXjb9nZH+9z/xfAc/dkQ49fkPnsxvJNkREk44rqR
         7A9pXf14sjd4sfTB7EdGCW4H0Dd+ngoN807mnUF3I6dn6i/idyq3yw/F4Ef0B2kdM1vJ
         GlC2tA3peEkyqRUdFRIlEZ+VmQPeCDgLlZGjhbVzOh2Zfb7wNWXkir2OyekhNh7DD8rg
         aMvw==
X-Forwarded-Encrypted: i=2; AJvYcCUEQkqhtbXM+ChbbOIdre4VhGJoQ1vE7NkxWTnYANZvAWhIkiD1egR+VN3XXGwbZPO0oWEkiA==@lfdr.de
X-Gm-Message-State: AOJu0YwMplqRiMF9uYATymK7g/SktuM3Of3HXEs1NcT3Ib13yFtP42Ee
	rOBNbgdNnurmq01nIlorjLzwvKfoNi1M67NSUmPHDKT9HS0VlpdnfgAv
X-Google-Smtp-Source: AGHT+IGO9+pYrwqcstGGg38mawQ7hcE+9cztff7JU/2gRZIXZRsKN4e9lDmEd0BktrMJYdsLghPd0Q==
X-Received: by 2002:a05:622a:4d99:b0:4b1:103b:bb84 with SMTP id d75a77b69052e-4b291bd1e9dmr16962961cf.62.1755668119499;
        Tue, 19 Aug 2025 22:35:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCQLcnH4Fjcvp2n8zjbbR9glGwcGVA5Dl2QBLxuDtW6g==
Received: by 2002:ac8:5a48:0:b0:4b0:9e11:a24b with SMTP id d75a77b69052e-4b12a2807e8ls76557421cf.0.-pod-prod-06-us;
 Tue, 19 Aug 2025 22:35:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWX3H4fgkI5PzE6ToUuEy6e6HATkEmCKJjTWX6a4U88tPUDrXeMPZr3w6x9ZC5QQOyDHm9w4ArJlMY=@googlegroups.com
X-Received: by 2002:a05:6102:5111:b0:4e7:db33:5980 with SMTP id ada2fe7eead31-51a4f53cd8fmr511391137.11.1755668117741;
        Tue, 19 Aug 2025 22:35:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668117; cv=none;
        d=google.com; s=arc-20240605;
        b=S16RQ8ovgvH8gM2aJLEHnfqYIJlUGAdGL5nwgqVZ7gNQ/Z5jlXErcYuBPY5YRRp4Gt
         U70aGXvylbSVVwYqeMtiht7NCGdLzII2sEwACnJNdr56RiNxIcQhK3dCMmuiDMzZNDG5
         gPNQxmnR6jhHLqnS02m3r1mtKr5e/hm729Ec/Kb166x7tn9d41TYB+ZsFlGhp/XaHXWU
         xBE8eVNGYrZBm/1W3YrsvLXJBI26zl5Zt8nkAMoJJ1PA0kmYIy6VjRu/0Xi7IyoLtj/i
         mFZJIv1Jm09oKmt6YtjYfXqjuG2WIl3jvCm1s2nKm/spp+o1PUhM399AomxdYSpiCHr8
         yuSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z74jlNhSBHrs3/SSQ+V392Z6lfqsJ86AC9wBk3eVnUU=;
        fh=yx2TOEA8OAv6JgprDRqBo1i40dkdP17DWUnpFH3PSuc=;
        b=kYtQRNDD/seuysw/3p7jSCnce7UBYWeBMLEnQ4bmPx9JMcX3kFFwiIM4PqZckcjrwK
         08ypHV7I5c/PA3eJyA1G6dECcPF1hHwPLe1MD/zjHCb+pBGcQ1PTKXZZVlsMqmOOrHqy
         pmqbLkTz31YesrzA4eMAHGKTRAZRqJJEXIGMJGNsjTFIUHW9t8hmcDvn9egM756mDnMk
         cjo04A6s8v8My7p/i2CSDHnDuWdBTwblYzvpkc8h5CrEXFn/WZLWjLS3nUIqCoAobtTv
         OgsH8hcuM5iAixnuyBOMd+BOhYEMWu0AyEfsFUtcnnVQmyngPLJ+iGcLU0xHFSlx4g38
         H8Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fMBlWmnR;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-890277e552csi515035241.1.2025.08.19.22.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:35:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-502-2hNAHMbvMa2UgQhFl-leGA-1; Wed,
 20 Aug 2025 01:35:14 -0400
X-MC-Unique: 2hNAHMbvMa2UgQhFl-leGA-1
X-Mimecast-MFC-AGG-ID: 2hNAHMbvMa2UgQhFl-leGA_1755668112
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 38944197753E;
	Wed, 20 Aug 2025 05:35:11 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3145B19560B0;
	Wed, 20 Aug 2025 05:35:02 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
Date: Wed, 20 Aug 2025 13:34:47 +0800
Message-ID: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fMBlWmnR;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Currently only hw_tags mode of kasan can be enabled or disabled with
kernel parameter kasan=on|off for built kernel. For kasan generic and
sw_tags mode, there's no way to disable them once kernel is built.
This is not convenient sometime, e.g in system kdump is configured.
When the 1st kernel has KASAN enabled and crash triggered to switch to
kdump kernel, the generic or sw_tags mode will cost much extra memory
for kasan shadow while in fact it's meaningless to have kasan in kdump
kernel.

So this patchset moves the kasan=on|off out of hw_tags scope and into
common code to make it visible in generic and sw_tags mode too. Then we
can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
kasan.

Changelog:
====
v2->v3:
- Fix a building error on UML ARCH when CONFIG_KASAN is not set. The
  change of fixing is appended into patch patch 11. This is reported
  by LKP, thanks to them.

v1->v2:
- Add __ro_after_init for kasan_arg_disabled, and remove redundant blank
  lines in mm/kasan/common.c. Thanks to Marco.
- Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
  this is found out by SeongJae and Lorenzo, and also reported by LKP
  report, thanks to them.
- Add a missing kasan_enabled() checking in kasan_report(). This will
  cause below KASAN report info even though kasan=off is set:
     ==================================================================
     BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
     Read of size 4 at addr ffff00005f747778 by task swapper/0/1

     CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMPT(voluntary)
     Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2.10.20220810) 09/30/2022
     Call trace:
      show_stack+0x30/0x90 (C)
      dump_stack_lvl+0x7c/0xa0
      print_address_description.constprop.0+0x90/0x310
      print_report+0x104/0x1f0
      kasan_report+0xc8/0x110
      __asan_report_load4_noabort+0x20/0x30
      tick_program_event+0x130/0x150
      ......snip...
     ==================================================================

- Add jump_label_init() calling before kasan_init() in setup_arch() in these
  architectures: xtensa, arm. Because they currenly rely on
  jump_label_init() in main() which is a little late. Then the early static
  key kasan_flag_enabled in kasan_init() won't work.

- In UML architecture, change to enable kasan_flag_enabled in arch_mm_preinit()
  because kasan_init() is enabled before main(), there's no chance to operate
  on static key in kasan_init().

Test:
=====
In v1, I took test on x86_64 for generic mode, and on arm64 for
generic, sw_tags and hw_tags mode. All of them works well.

In v2, I only tested on arm64 for generic, sw_tags and hw_tags mode, it
works. For powerpc, I got a BOOK3S/64 machine, while it says
'KASAN not enabled as it requires radix' and KASAN is disabled. Will
look for other POWER machine to test this.

In v3, I only built UML kernel successfully w and w/o CONFIG_KASAN
setting with LKP's testing steps.
====


Baoquan He (12):
  mm/kasan: add conditional checks in functions to return directly if
    kasan is disabled
  mm/kasan: move kasan= code to common place
  mm/kasan/sw_tags: don't initialize kasan if it's disabled
  arch/arm: don't initialize kasan if it's disabled
  arch/arm64: don't initialize kasan if it's disabled
  arch/loongarch: don't initialize kasan if it's disabled
  arch/powerpc: don't initialize kasan if it's disabled
  arch/riscv: don't initialize kasan if it's disabled
  arch/x86: don't initialize kasan if it's disabled
  arch/xtensa: don't initialize kasan if it's disabled
  arch/um: don't initialize kasan if it's disabled
  mm/kasan: make kasan=on|off take effect for all three modes

 arch/arm/kernel/setup.c                |  6 +++++
 arch/arm/mm/kasan_init.c               |  6 +++++
 arch/arm64/mm/kasan_init.c             |  7 ++++++
 arch/loongarch/mm/kasan_init.c         |  5 ++++
 arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
 arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
 arch/riscv/mm/kasan_init.c             |  6 +++++
 arch/um/kernel/mem.c                   |  7 ++++++
 arch/x86/mm/kasan_init_64.c            |  6 +++++
 arch/xtensa/kernel/setup.c             |  1 +
 arch/xtensa/mm/kasan_init.c            |  6 +++++
 include/linux/kasan-enabled.h          | 18 ++++++-------
 mm/kasan/common.c                      | 25 ++++++++++++++++++
 mm/kasan/generic.c                     | 20 +++++++++++++--
 mm/kasan/hw_tags.c                     | 35 ++------------------------
 mm/kasan/init.c                        |  6 +++++
 mm/kasan/quarantine.c                  |  3 +++
 mm/kasan/report.c                      |  4 ++-
 mm/kasan/shadow.c                      | 23 ++++++++++++++++-
 mm/kasan/sw_tags.c                     |  9 +++++++
 21 files changed, 166 insertions(+), 47 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-1-bhe%40redhat.com.
