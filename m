Return-Path: <kasan-dev+bncBCKPFB7SXUERBFUXRTCQMGQELLVMACA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7EC4B2A025
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 13:16:40 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-30cceb0a741sf7212365fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 04:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755515799; cv=pass;
        d=google.com; s=arc-20240605;
        b=LFR8nM//cqaxxSDB9vuJLKxGETXhBJ8W+vBua1hmVvtfEPocVddn5HeGZJu8629Wtj
         hu8DpRyvOPEEdwSSyAyo3dyYcNKZjwvGQJvJZmC1mQw4liglGReCd6bWngPrDQr0FrDD
         gXoh4C1scgErCR102FFIg2UOMIDg34FBIBPA1fejhyQ2FjpMnXQIeOtKPtYPYOaNhzOV
         r25u7HPNajny6PgfleuOK7PpusrNgqptybxTcDNXJSrHRDabTd8zCIelmLTvVd3UZos4
         Zj4/5VQ8E2MdmI87kse08Vakj41QAnVi5h/kTPo0CectI5Z3QuDLKuKadU6SM0fl1OQO
         rN2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:dkim-signature;
        bh=LxZhgbTSsAYq0MXyx2FowqCYPTJziRf526Er9GMOwvY=;
        fh=BLT0lAmjRg1/xoRgwNWGY9eEXOmzBjmzdAU1iH16Zts=;
        b=TY2uATn0p5uNBXvZxf0ALrZ+YbgJ3hsZgKwKoB6Au6ULtmCxCgG5mXr4w1l9hoG/wR
         ndqTtsoGlBxNxZjOMyc9lgvlAc7INavGZfq3qpUcwItLR5Zp4r+PG/xn0NE8dAcJJrGx
         ztnHk+NWouD/MDk2ZyKcrjlpv7lUXI25oFvQxHYnhQEdQXSOnptRAnC8X/XGO+z7+1H6
         buyVptw/vjtOq8J81Az9UYUI0l8MsavM1erMMwd5B8xd50giIz9zeXyBbNa8bRKEvW+w
         h0nPTenUZqDXTklm7QWAs9BzpGhD/oFu48aqiiKVf76HNfCSSMny2eGHnMVHYrvuE+YG
         6yvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KiB5Vset;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755515799; x=1756120599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LxZhgbTSsAYq0MXyx2FowqCYPTJziRf526Er9GMOwvY=;
        b=WlSc3pBPOHvw5W9G4GhD8MwudYrB3VXshSDhwWMQPNXb7/uyq9W3SGQni+JKAy8v0r
         xXVhrBmEkNt/GvA9R8PUNL3jWzeRUx8W6gH5BP6Sgv0Z6poeR08llazsn33W2CvosoP/
         j0/+hd1vIfpcrfqAfp3rBB55lQ+eAg1VM1Eo8gIKO4DaHshE15QDLq2uSjXxGu97+0DP
         t09qqIn8DvzSSDzNdB4oD9bMYbzn2CeiJfwLimb8jIe9gLXXHtncbGkA79rKUeCI+yYa
         qQ7ZXBYd+muiIqTu3NVVButJM0h9uzmZ8CBn04l38Rtl0yb148yOkQIWuSGS/frPOVZZ
         JMqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755515799; x=1756120599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LxZhgbTSsAYq0MXyx2FowqCYPTJziRf526Er9GMOwvY=;
        b=r0gJ8Ra7LBioN4O/LsZqhd2aOdvKGEQEgNz0BQNPEwsBtfMSd9adKPC6HDsHgFUnRW
         nPGXbIVn1xHGblKRYr9VQn9guT988yHb6JQ+ub/r6eeOh4G6GKfdpT5qw5W79W7gfI7g
         FTTHh39kfgHgeoQQ1EZGhBZfmkBTXYZZ7a/dC+8mST1CHQwximAphXgmW1FwMRIlr1pj
         DR0cxT8LyYBkk5rBEu90jRdctxxnXtC1N/1Tllm+CIPiWNQ7x3oFATgMEqA9PyVYN3Aw
         iUG8xu6RSPN7DVnbh3la2/cYXBZ3ecPExkaqDsCRKkkoD5K+DQZS72rtDLwGcWdBSE7D
         nPMw==
X-Forwarded-Encrypted: i=2; AJvYcCWTQFbeKcgCvYf3WIDZw19vij0x/vlMLBuOFV3pCvGjxWWu8k0qBfz9dEJPwME2GEdD/R2TAA==@lfdr.de
X-Gm-Message-State: AOJu0Yzz/kNQTxb9Y1LFqdUU3yM9BCFQLSES1ypkIpSkqRo96FONz4RZ
	J+zbCfwk4YvJ1XNidiebPHNdsKGazyetki07xVInY3fPk3FBd+KuO/p1
X-Google-Smtp-Source: AGHT+IFNgZQAnAW5D/AFfx2ZF3STYU0UkpFB4EFLNS68jG4+y+zuDIlW0t+wVWbHHoZhsxduZIATxg==
X-Received: by 2002:a05:6871:81d3:10b0:310:b6e5:ec29 with SMTP id 586e51a60fabf-310b6e613fbmr3683499fac.13.1755515798891;
        Mon, 18 Aug 2025 04:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZercRK+anPuaL+zJ2CWGdyj2zM6JR+1PdEqf6xJ7NWJOA==
Received: by 2002:a05:6870:b68d:b0:30b:b8a1:c8d0 with SMTP id
 586e51a60fabf-30cceae6f04ls2059238fac.1.-pod-prod-07-us; Mon, 18 Aug 2025
 04:16:37 -0700 (PDT)
X-Received: by 2002:a05:6870:450e:b0:30b:90f4:ca08 with SMTP id 586e51a60fabf-310aae21eb5mr6538338fac.22.1755515797384;
        Mon, 18 Aug 2025 04:16:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755515797; cv=none;
        d=google.com; s=arc-20240605;
        b=QUBuDubYsQeFUuV8DqVADQSNBw+OYyxz49ZG8yd9Eh5jA0gHBoInwehHlH1+vHhewf
         vC1iyD/G9S1IGODP8xv8L7uyqhiw+UNmF3mwioCnIiTzuO+k9VYz3b9nEJUEYX9Ssc4U
         gDkSjYkNUNnbYt3plYo8Gyh1Mo1Kg2GyB7t6jDRi7kBFtpHw2a95ie6pnfwoCJKPyzSe
         a3l50pw8KH6e3/IMGEh2eWl2KINsi+g1ZUZ9Ifux8kxuVkHYGzQTquNipaeCRC6N/3gT
         kK5Pu/OUi0HdlOO6oW8y7tvU1zIIC3bCxFPZLWrxR2lXM5AkP1lev/JVPQWHK2YS5hnY
         4oVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=g+q8SHzvpxV2hTr/EJGZ0e5gsEJLwzjoj0zsxIlZo6I=;
        fh=8sgM/qUUkKRrDFPQCIAPIO36Oumi/s1sm2MEsgrCDt8=;
        b=Pj3HjJATudoexUAIe6NLXCBuLf9u6RrGBFrOBB7SzACHuMou4HDHocA1YWgDT5PASN
         VRUnLbcELC4RJCkTgQzRGmvfUxnmP7fWiWzrGlhV2O9CGMA8JqvHvG9Ik5oaguUFTFCi
         lqITM7JNyhOJg+JLUeBtIhaSjBcNa+FIDh4nefHS8c0TL4B2Hek45CdTNxNTKxxdPLNs
         JJ3HP3yuk/EBGkaRjLo8rFnvo4HcmYMGRP+eev9SZhr4IDRAEVJi8hOs/xcRy7DFLZCg
         wFE5HpzpWEa5gjKzkO5mA0BnudOaNFLJ9MblwmBV3s1zc2XLWNn+EoGWRnW0W1evuSWo
         uA7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KiB5Vset;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310abb4abadsi372147fac.4.2025.08.18.04.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 04:16:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-390-f9-B0kUAO6upr9QlVYax8w-1; Mon,
 18 Aug 2025 07:16:27 -0400
X-MC-Unique: f9-B0kUAO6upr9QlVYax8w-1
X-Mimecast-MFC-AGG-ID: f9-B0kUAO6upr9QlVYax8w_1755515786
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E93B21800347;
	Mon, 18 Aug 2025 11:16:25 +0000 (UTC)
Received: from localhost (unknown [10.72.112.210])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 35A0930001A5;
	Mon, 18 Aug 2025 11:16:20 +0000 (UTC)
Date: Mon, 18 Aug 2025 19:16:16 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-mm@kvack.org
Subject: System is broken in KASAN sw_tags mode during bootup
Message-ID: <aKMLgHdTOEf9B92E@MiWiFi-R3L-srv>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: N4vhq7qDOLHSZcnq5UWMTSuoJ3eGcb6WiVXueT0fjI8_1755515786
X-Mimecast-Originator: redhat.com
Content-Type: multipart/mixed; boundary="EEo2Efafy6WV2cN3"
Content-Disposition: inline
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KiB5Vset;
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

--EEo2Efafy6WV2cN3
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi,

This can be reproduced stably on hpe-apollo arm64 system with the latest
upstream kernel. I have this system at hand now, the boot log and kernel
config are attached for reference.

[   89.257633] ==================================================================
[   89.257646] BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8
[   89.257672] Write of size 528 at addr ddfffd7fbdc00000 by task systemd/1
[   89.257685] Pointer tag: [dd], memory tag: [ca]
[   89.257692] 
[   89.257703] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc2 #1 PREEMPT(voluntary) 
[   89.257719] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[   89.257726] Call trace:
[   89.257731]  show_stack+0x30/0x90 (C)
[   89.257753]  dump_stack_lvl+0x7c/0xa0
[   89.257769]  print_address_description.isra.0+0x90/0x2b8
[   89.257789]  print_report+0x120/0x208
[   89.257804]  kasan_report+0xc8/0x110
[   89.257823]  kasan_check_range+0x7c/0xa0
[   89.257835]  __asan_memset+0x30/0x68
[   89.257847]  pcpu_alloc_noprof+0x42c/0x9a8
[   89.257859]  mem_cgroup_alloc+0x2bc/0x560
[   89.257873]  mem_cgroup_css_alloc+0x78/0x780
[   89.257893]  cgroup_apply_control_enable+0x230/0x578
[   89.257914]  cgroup_mkdir+0xf0/0x330
[   89.257928]  kernfs_iop_mkdir+0xb0/0x120
[   89.257947]  vfs_mkdir+0x250/0x380
[   89.257965]  do_mkdirat+0x254/0x298
[   89.257979]  __arm64_sys_mkdirat+0x80/0xc0
[   89.257994]  invoke_syscall.constprop.0+0x88/0x148
[   89.258011]  el0_svc_common.constprop.0+0x78/0x148
[   89.258025]  do_el0_svc+0x38/0x50
[   89.258037]  el0_svc+0x3c/0x168
[   89.258050]  el0t_64_sync_handler+0xa0/0xf0
[   89.258063]  el0t_64_sync+0x1b0/0x1b8
[   89.258076] 
[   89.258080] The buggy address belongs to a 0-page vmalloc region starting at 0xcafffd7fbdc00000 allocated at pcpu_get_vm_areas+0x0/0x1da0
[   89.258111] The buggy address belongs to the physical page:
[   89.258117] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x881ddac
[   89.258129] flags: 0xa5c00000000000(node=1|zone=2|kasantag=0x5c)
[   89.258148] raw: 00a5c00000000000 0000000000000000 dead000000000122 0000000000000000
[   89.258160] raw: 0000000000000000 f3ff000813efa600 00000001ffffffff 0000000000000000
[   89.258168] raw: 00000000000fffff 0000000000000000
[   89.258173] page dumped because: kasan: bad access detected
[   89.258178] 
[   89.258181] Memory state around the buggy address:
[   89.258192] Unable to handle kernel paging request at virtual address ffff7fd7fbdbffe0
[   89.258199] KASAN: probably wild-memory-access in range [0xfffffd7fbdbffe00-0xfffffd7fbdbffe0f]
[   89.258207] Mem abort info:
[   89.258211]   ESR = 0x0000000096000007
[   89.258216]   EC = 0x25: DABT (current EL), IL = 32 bits
[   89.258223]   SET = 0, FnV = 0
[   89.258228]   EA = 0, S1PTW = 0
[   89.258232]   FSC = 0x07: level 3 translation fault
[   89.258238] Data abort info:
[   89.258241]   ISV = 0, ISS = 0x00000007, ISS2 = 0x00000000
[   89.258246]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
[   89.258252]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[   89.258260] swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000008ff8b8f000
[   89.258267] [ffff7fd7fbdbffe0] pgd=1000008ff0275403, p4d=1000008ff0275403, pud=1000008ff0274403, pmd=1000000899079403, pte=0000000000000000
[   89.258296] Internal error: Oops: 0000000096000007 [#1]  SMP
[   89.540859] Modules linked in: i2c_dev
[   89.544619] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc2 #1 PREEMPT(voluntary) 
[   89.553234] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[   89.562970] pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   89.569933] pc : __pi_memcpy_generic+0x24/0x230
[   89.574472] lr : kasan_metadata_fetch_row+0x20/0x30
[   89.579350] sp : ffff8000859d76c0
[   89.582660] x29: ffff8000859d76c0 x28: 0000000000000100 x27: ffff008ec626d800
[   89.589807] x26: 0000000000000210 x25: 0000000000000000 x24: fffffd7fbdbfff00
[   89.596952] x23: ffff8000826cbeb8 x22: fffffd7fbdc00000 x21: 00000000fffffffe
[   89.604097] x20: ffff800082682ee0 x19: fffffd7fbdbffe00 x18: 00000000049016ff
[   89.611242] x17: 3030303030303030 x16: 2066666666666666 x15: 6631303030303030
[   89.618386] x14: 0000000000000001 x13: 0000000000000001 x12: 0000000000000001
[   89.625530] x11: 687420646e756f72 x10: 0000000000000020 x9 : 0000000000000000
[   89.632674] x8 : ffff78000859d766 x7 : 0000000000000000 x6 : 000000000000003a
[   89.639818] x5 : ffff8000859d7728 x4 : ffff7fd7fbdbfff0 x3 : efff800000000000
[   89.646963] x2 : 0000000000000010 x1 : ffff7fd7fbdbffe0 x0 : ffff8000859d7718
[   89.654107] Call trace:
[   89.656549]  __pi_memcpy_generic+0x24/0x230 (P)
[   89.661086]  print_report+0x180/0x208
[   89.664753]  kasan_report+0xc8/0x110
[   89.668333]  kasan_check_range+0x7c/0xa0
[   89.672258]  __asan_memset+0x30/0x68
[   89.675836]  pcpu_alloc_noprof+0x42c/0x9a8
[   89.679935]  mem_cgroup_alloc+0x2bc/0x560
[   89.683947]  mem_cgroup_css_alloc+0x78/0x780
[   89.688222]  cgroup_apply_control_enable+0x230/0x578
[   89.693191]  cgroup_mkdir+0xf0/0x330
[   89.696771]  kernfs_iop_mkdir+0xb0/0x120
[   89.700697]  vfs_mkdir+0x250/0x380
[   89.704103]  do_mkdirat+0x254/0x298
[   89.707596]  __arm64_sys_mkdirat+0x80/0xc0
[   89.711697]  invoke_syscall.constprop.0+0x88/0x148
[   89.716491]  el0_svc_common.constprop.0+0x78/0x148
[   89.721286]  do_el0_svc+0x38/0x50
[   89.724602]  el0_svc+0x3c/0x168
[   89.727746]  el0t_64_sync_handler+0xa0/0xf0
[   89.731933]  el0t_64_sync+0x1b0/0x1b8
[   89.735603] Code: f100805f 540003c8 f100405f 540000c3 (a9401c26) 
[   89.741695] ---[ end trace 0000000000000000 ]---
[   89.746308] note: systemd[1] exi
=========================


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKMLgHdTOEf9B92E%40MiWiFi-R3L-srv.

--EEo2Efafy6WV2cN3
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="sw_tags-boot.log"
Content-Transfer-Encoding: 8bit

  Booting `Fedora Linux (6.17.0-rc2) 42 (Adams)'

[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x431f0af1]
[    0.000000] Linux version 6.17.0-rc2 (root@hpe-apollo-cn99xx-06.khw.eng.rdu2.dc.redhat.com) (gcc (GCC) 15.2.1 20250808 (Red Hat 15.2.1-1), GNU ld version 2.44-6.fc42) #1 SMP PREEMPT_DYNAMIC Mon Aug 18 01:17:33 EDT 2025
[    0.000000] KASLR disabled due to lack of seed
[    0.000000] efi: EFI v2.7 by American Megatrends
[    0.000000] efi: ESRT=0xf924f798 SMBIOS=0xfcca0000 SMBIOS 3.0=0xfcc90000 ACPI 2.0=0xf8920000 MOKvar=0xf96b0000 INITRD=0xf9730918 MEMRESERVE=0xf9730998 
[    0.000000] esrt: Reserving ESRT space from 0x00000000f924f798 to 0x00000000f924f7d0.
[    0.000000] ACPI: Early table checksum verification disabled
[    0.000000] ACPI: RSDP 0x00000000F8920000 000024 (v02 HPE   )
[    0.000000] ACPI: XSDT 0x00000000F8920028 0000DC (v01 HPE    ServerCL 01072009 AMI  00010013)
[    0.000000] ACPI: FACP 0x00000000F8920108 000114 (v06 HPE    ServerCL 01072009 AMI  00010013)
[    0.000000] ACPI: DSDT 0x00000000F8920220 000714 (v02 HPE    ServerCL 20150406 INTL 20170831)
[    0.000000] ACPI: FACS 0x00000000FED90040 000040
[    0.000000] ACPI: FIDT 0x00000000F8920938 00009C (v01 HPE    ServerCL 01072009 AMI  00010013)
[    0.000000] ACPI: DBG2 0x00000000F89209D8 000062 (v00 HPE    ServerCL 00000000 INTL 20170831)
[    0.000000] ACPI: SPMI 0x00000000F8920A40 000041 (v05 HPE    ServerCL 00000000 AMI. 00000000)
[    0.000000] ACPI: PCCT 0x00000000F8920A88 000FB0 (v01 HPE    ServerCL 00000001 INTL 20170831)
[    0.000000] ACPI: SLIT 0x00000000F8921A38 000030 (v01 HPE    ServerCL 00000001 INTL 20170831)
[    0.000000] ACPI: SPMI 0x00000000F8921A68 000041 (v04 HPE    ServerCL 00000001 INTL 20170831)
[    0.000000] ACPI: SSDT 0x00000000F8921AB0 004217 (v02 HPE    N0BXPCI  20150406 INTL 20170831)
[    0.000000] ACPI: SSDT 0x00000000F8925CC8 02DA97 (v02 HPE    ServerCL 20150406 INTL 20170831)
[    0.000000] ACPI: SSDT 0x00000000F8953760 0041CB (v02 HPE    N1BXPCI  20150406 INTL 20170831)
[    0.000000] ACPI: SSDT 0x00000000F8957930 02E44F (v02 HPE    ServerCL 20150406 INTL 20170831)
[    0.000000] ACPI: BERT 0x00000000F8985D80 000030 (v01 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: GTDT 0x00000000F8985DB0 00007C (v02 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: HEST 0x00000000F8985E30 0000E0 (v01 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: APIC 0x00000000F8985F10 00508C (v04 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: MCFG 0x00000000F898AFA0 00003C (v01 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: NFIT 0x00000000F898AFE0 000028 (v01 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: PPTT 0x00000000F898B008 001C14 (v01 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: SRAT 0x00000000F898CC20 0012E8 (v03 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: IORT 0x00000000F898DF08 000688 (v00 HPE    ServerCL 20150406 CAVM 00000099)
[    0.000000] ACPI: SPCR 0x00000000F898E590 000050 (v02 HPE    ServerCL 01072009 AMI. 0005000D)
[    0.000000] ACPI: BGRT 0x00000000F898E5E0 000038 (v01 HPE    ServerCL 01072009 AMI  00010013)
[    0.000000] ACPI: WSMT 0x00000000F898E618 000028 (v01 HPE    ServerCL 01072009 AMI  00010013)
[    0.000000] ACPI: SPCR: [Firmware Bug]: Unexpected SPCR Access Width. Defaulting to byte size
[    0.000000] ACPI: SPCR: console: pl011,mmio,0x402020000,115200
[    0.000000] ACPI: Use ACPI SPCR as default console: No
[    0.000000] ACPI: SRAT: Node 0 PXM 0 [mem 0x80000000-0xfeffffff]
[    0.000000] ACPI: SRAT: Node 0 PXM 0 [mem 0x880000000-0xffcffffff]
[    0.000000] ACPI: SRAT: Node 1 PXM 1 [mem 0xffd000000-0xfffffffff]
[    0.000000] ACPI: SRAT: Node 1 PXM 1 [mem 0x8800000000-0x8ffcffffff]
[    0.000000] NUMA: Node 0 [mem 0x802f0000-0xfeffffff] + [mem 0x880000000-0xffcffffff] -> [mem 0x802f0000-0xffcffffff]
[    0.000000] NUMA: Node 1 [mem 0xffd000000-0xfffffffff] + [mem 0x8800000000-0x8ffcffffff] -> [mem 0xffd000000-0x8ffcffffff]
[    0.000000] NODE_DATA(0) allocated [mem 0xffcfe92c0-0xffcffffff]
[    0.000000] NODE_DATA(1) allocated [mem 0x8ff07132c0-0x8ff0729fff]
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x00000000802f0000-0x00000000ffffffff]
[    0.000000]   DMA32    empty
[    0.000000]   Normal   [mem 0x0000000100000000-0x0000008ffcffffff]
[    0.000000]   Device   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x00000000802f0000-0x000000008030ffff]
[    0.000000]   node   0: [mem 0x0000000080310000-0x00000000bfffffff]
[    0.000000]   node   0: [mem 0x00000000c0000000-0x00000000c0cbffff]
[    0.000000]   node   0: [mem 0x00000000c0cc0000-0x00000000f89fffff]
[    0.000000]   node   0: [mem 0x00000000f8a00000-0x00000000f8a2ffff]
[    0.000000]   node   0: [mem 0x00000000f8a30000-0x00000000f8afffff]
[    0.000000]   node   0: [mem 0x00000000f8b00000-0x00000000f8b2ffff]
[    0.000000]   node   0: [mem 0x00000000f8b30000-0x00000000f96affff]
[    0.000000]   node   0: [mem 0x00000000f96b0000-0x00000000f96bffff]
[    0.000000]   node   0: [mem 0x00000000f96c0000-0x00000000f96cffff]
[    0.000000]   node   0: [mem 0x00000000f96d0000-0x00000000f972ffff]
[    0.000000]   node   0: [mem 0x00000000f9730000-0x00000000f97cffff]
[    0.000000]   node   0: [mem 0x00000000f97d0000-0x00000000f998ffff]
[    0.000000]   node   0: [mem 0x00000000f9990000-0x00000000faa0ffff]
[    0.000000]   node   0: [mem 0x00000000faa10000-0x00000000fabaffff]
[    0.000000]   node   0: [mem 0x00000000fabb0000-0x00000000fad1ffff]
[    0.000000]   node   0: [mem 0x00000000fad20000-0x00000000fad7ffff]
[    0.000000]   node   0: [mem 0x00000000fad80000-0x00000000fc83ffff]
[    0.000000]   node   0: [mem 0x00000000fc840000-0x00000  node   0: [mem000fcb4ffff]
[ m 0x00000000fd20[    0.000000]   d40000-0x00000000fedeffff]
[    0.000000]   node   0: [mem 0x00000000fedf0000-0x00000000feffffff]
[    0.000000]   node   0: [mem 0x0000000880000000-0x0000000ffcffffff]
[    0.000000]   node   1: [mem 0x0000000ffd000000-0x0000000fffffffff]
[    0.000000]   node   1: [mem 0x0000008800000000-0x0000008ffcffffff]
[    0.000000] Initmem setup node 0 [mem 0x00000000802f0000-0x0000000ffcffffff]
[    0.000000] Initmem setup node 1 [mem 0x0000000ffd000000-0x0000008ffcffffff]
[    0.000000] On node 0, zone DMA: 752 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 4096 pages in unavailable ranges
[    0.000000] On node 1, zone Normal: 12288 pages in unavailable ranges
[    0.000000] cma: Reserved 64 MiB at 0x00000000f0c00000
[    0.000000] psci: probing for conduit method from ACPI.
[    0.000000] psci: PSCIv1.0 detected in firmware.
[    0.000000] psci: Using standard PSCI v0.2 function IDs
[    0.000000] psci: MIGRATE_INFO_TYPE not supported.
[    0.000000] psci: SMC Calling Convention v1.1
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x0 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x2 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x3 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x100 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x101 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x102 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x103 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x200 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x201 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x202 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x203 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x300 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x301 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x302 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x303 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x400 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x401 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x402 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x403 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x500 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x501 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x502 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x503 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x600 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x601 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x602 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x603 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x700 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x701 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x702 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x703 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x800 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x801 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x802 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x803 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x900 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x901 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x902 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x903 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xa00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xa01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xa02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xa03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xb00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xb01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xb02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xb03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xc00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xc01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xc02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xc03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xd00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xd01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xd02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xd03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xe00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xe01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xe02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xe03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xf00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xf01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xf02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0xf03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1000 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1001 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1002 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1003 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1100 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1101 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1102 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1103 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1200 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1201 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1202 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1203 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1300 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1301 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1302 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1303 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1400 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1401 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1402 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1403 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1500 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1501 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1502 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1503 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1600 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1601 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1602 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1603 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1700 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1701 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1702 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1703 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1800 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1801 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1802 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1803 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1900 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1901 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1902 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1903 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1a00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1a01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1a02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1a03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1b00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1b01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1b02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1b03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1c00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1c01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1c02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1c03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1d00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1d01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1d02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1d03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1e00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1e01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1e02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1e03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1f00 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1f01 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1f02 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 0 -> MPIDR 0x1f03 -> Node 0
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10000 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10001 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10002 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10003 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10100 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10101 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10102 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10103 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10200 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10201 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10202 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10203 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10300 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10301 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10302 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10303 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10400 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10401 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10402 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10403 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10500 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10501 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10502 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10503 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10600 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10601 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10602 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10603 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10700 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10701 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10702 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10703 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10800 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10801 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10802 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10803 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10900 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10901 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10902 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10903 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10a00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10a01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10a02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10a03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10b00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10b01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10b02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10b03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10c00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10c01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10c02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10c03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10d00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10d01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10d02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10d03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10e00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10e01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10e02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10e03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10f00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10f01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10f02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x10f03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11000 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11001 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11002 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11003 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11100 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11101 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11102 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11103 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11200 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11201 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11202 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11203 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11300 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11301 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11302 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11303 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11400 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11401 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11402 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11403 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11500 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11501 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11502 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11503 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11600 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11601 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11602 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11603 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11700 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11701 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11702 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11703 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11800 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11801 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11802 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11803 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11900 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11901 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11902 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11903 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11a00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11a01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11a02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11a03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11b00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11b01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11b02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11b03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11c00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11c01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11c02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11c03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11d00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11d01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11d02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11d03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11e00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11e01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11e02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11e03 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11f00 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11f01 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11f02 -> Node 1
[    0.000000] ACPI: NUMA: SRAT: PXM 1 -> MPIDR 0x11f03 -> Node 1
[    0.000000] percpu: Embedded 56 pages/cpu s105624 r8192 d115560 u229376
[    0.000000] Detected PIPT I-cache on CPU0
[    0.000000] CPU features: detected: GICv3 CPU interface
[    0.000000] CPU features: detected: Virtualization Host Extensions
[    0.000000] CPU features: detected: Spectre-v2
[    0.000000] CPU features: detected: Spectre-v4
[    0.000000] CPU features: detected: Spectre-BHB
[    0.000000] CPU features: detected: Cavium ThunderX2 erratum 219 (PRFM removal)
[    0.000000] CPU features: detected: Cavium ThunderX2 erratum 219 (KVM guest sysreg trapping)
[    0.000000] alternatives: applying boot alternatives
[    0.000000] kasan: KernelAddressSanitizer initialized (sw-tags, stacktrace=on)
[    0.000000] Kernel command line: BOOT_IMAGE=(hd13,gpt2)/vmlinuz-6.17.0-rc2 root=/dev/mapper/anaconda_hpe--apollo--cn99xx--06-root ro rd.lvm.lv=anaconda_hpe-apollo-cn99xx-06/root
[    0.000000] Unknown kernel command line parameters "BOOT_IMAGE=(hd13,gpt2)/vmlinuz-6.17.0-rc2", will be passed to user space.
[    0.000000] printk: log_buf_len individual max cpu contribution: 4096 bytes
[    0.000000] printk: log_buf_len total cpu_extra contributions: 1044480 bytes
[    0.000000] printk: log_buf_len min size: 262144 bytes
[    0.000000] printk: log buffer data + meta data: 2097152 + 7340032 = 9437184 bytes
[    0.000000] printk: early log buf free: 234472(89%)
[    0.000000] software IO TLB: area num 256.
[    0.000000] software IO TLB: mapped [mem 0x00000000ecc00000-0x00000000f0c00000] (64MB)
[    0.000000] Fallback order for Node 0: 0 1 
[    0.000000] Fallback order for Node 1: 1 0 
[    0.000000] Built 2 zonelists, mobility grouping on.  Total pages: 16760080
[    0.000000] Policy zone: Normal
[    0.000000] mem auto-init: stack:all(zero), heap alloc:on, heap free:off
[    0.000000] stackdepot: allocating hash table via alloc_large_system_hash
[    0.000000] stackdepot hash table entries: 1048576 (order: 12, 16777216 bytes, linear)
[    0.000000] stackdepot: allocating space for 8192 stack pools via memblock
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=256, Nodes=2
[    0.000000] ftrace: allocating 66697 entries in 262 pages
[    0.000000] ftrace: allocated 262 pages with 3 groups
[    0.000000] Dynamic Preempt: voluntary
[    0.000000] rcu: Preemptible hierarchical RCU implementation.
[    0.000000] rcu:     RCU event tracing is enabled.
[    0.000000] rcu:     RCU restricting CPUs from NR_CPUS=4096 to nr_cpu_ids=256.
[    0.000000]  Trampoline variant of Tasks RCU enabled.
[    0.000000]  Rude variant of Tasks RCU enabled.
[    0.000000]  Tracing variant of Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 101 jiffies.
[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=256
[    0.000000] RCU Tasks: Setting shift to 8 and lim to 1 rcu_task_cb_adjust=1 rcu_task_cpu_ids=256.
[    0.000000] RCU Tasks Rude: Setting shift to 8 and lim to 1 rcu_task_cb_adjust=1 rcu_task_cpu_ids=256.
[    0.000000] RCU Tasks Trace: Setting shift to 8 and lim to 1 rcu_task_cb_adjust=1 rcu_task_cpu_ids=256.
[    0.000000] NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
[    0.000000] GICv3: GIC: Using split EOI/Deactivate mode
[    0.000000] GICv3: 480 SPIs implemented
[    0.000000] GICv3: 0 Extended SPIs implemented
[    0.000000] Root IRQ handler: gic_handle_irq
[    0.000000] GICv3: GICv3 features: 16 PPIs
[    0.000000] GICv3: GICD_CTLR.DS=0, SCR_EL3.FIQ=1
[    0.000000] GICv3: CPU0: found redistributor 0 region 0:0x0000000401000000
[    0.000000] SRAT: PXM 0 -> ITS 0 -> Node 0
[    0.000000] SRAT: PXM 1 -> ITS 1 -> Node 1
[    0.000000] ITS [mem 0x400100000-0x40011ffff]
[    0.000000] ITS@0x0000000400100000: allocated 65536 Devices @881080000 (flat, esz 8, psz 64K, shr 0)
[    0.000000] ITS@0x0000000400100000: allocated 8192 Interrupt Collections @881034000 (flat, esz 2, psz 16K, shr 0)
[    0.000000] ITS: using cache flushing for cmd queue
[    0.000000] ITS [mem 0x440100000-0x44011ffff]
[    0.000000] ITS@0x0000000440100000: allocated 65536 Devices @ffd500000 (flat, esz 8, psz 64K, shr 0)
[    0.000000] ITS@0x0000000440100000: allocated 8192 Interrupt Collections @ffd4c8000 (flat, esz 2, psz 16K, shr 0)
[    0.000000] ITS: using cache flushing for cmd queue
[    0.000000] GICv3: using LPI property table @0x0000000881060000
[    0.000000] GIC: using cache flushing for LPI property table
[    0.000000] GICv3: CPU0: using allocated LPI pending table @0x0000000881070000
[    0.000000] rcu: srcu_init: Setting srcu_struct sizes to big.
[    0.000000] arch_timer: cp15 timer(s) running at 200.00MHz (phys).
[    0.000000] clocksource: arch_sys_counter: mask: 0x3ffffffffffffff max_cycles: 0x2e2049d3e8, max_idle_ns: 440795210634 ns
[    0.000001] sched_clock: 58 bits at 200MHz, resolution 5ns, wraps every 4398046511102ns
[    0.005883] kfence: initialized - using 2097152 bytes for 255 objects at 0x(____ptrval____)-0x(____ptrval____)
[    0.010392] Console: colour dummy device 80x25
[    0.011838] mempolicy: Enabling automatic NUMA balancing. Configure with numa_balancing= or the kernel.numa_balancing sysctl
[    0.011855] ACPI: Core revision 20250404
[    0.017155] Calibrating delay loop (skipped), value calculated using timer frequency.. 400.00 BogoMIPS (lpj=200000)
[    0.017176] pid_max: default: 262144 minimum: 2048
[    0.021894] LSM: initializing lsm=lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
[    0.023373] Yama: becoming mindful.
[    0.023403] SELinux:  Initializing.
[    0.029764] LSM support for eBPF active
[    0.029882] landlock: Up and running.
[    0.050453] Dentry cache hash table entries: 8388608 (order: 14, 67108864 bytes, vmalloc hugepage)
[    0.057601] Inode-cache hash table entries: 4194304 (order: 13, 33554432 bytes, vmalloc hugepage)
[    0.059136] Mount-cache hash table entries: 131072 (order: 8, 1048576 bytes, vmalloc hugepage)
[    0.059399] Mountpoint-cache hash table entries: 131072 (order: 8, 1048576 bytes, vmalloc hugepage)
[    0.087494] rcu: Hierarchical SRCU implementation.
[    0.087502] rcu:     Max phase no-delay instances is 400.
[    0.088118] Timer migration: 4 hierarchy levels; 8 children per group; 3 crossnode level
[    0.091079] fsl-mc MSI: ITS@0x400100000 domain created
[    0.091103] fsl-mc MSI: ITS@0x440100000 domain created
[    0.091157] Remapping and enabling EFI services.
[    0.115476] smp: Bringing up secondary CPUs ...
[    0.181853] Detected PIPT I-cache on CPU1
[    0.181928] GICv3: CPU1: found redistributor 100 region 0:0x0000000401080000
[    0.181951] GICv3: CPU1: using allocated LPI pending table @0x0000000881100000
[    0.182036] CPU1: Booted secondary processor 0x0000000100 [0x431f0af1]
[    0.249822] Detected PIPT I-cache on CPU2
[    0.249886] GICv3: CPU2: found redistributor 200 region 0:0x0000000401100000
[    0.249902] GICv3: CPU2: using allocated LPI pending table @0x0000000881110000
[    0.249968] CPU2: Booted secondary processor 0x0000000200 [0x431f0af1]
[    0.317373] Detected PIPT I-cache on CPU3
[    0.317440] GICv3: CPU3: found redistributor 300 region 0:0x0000000401180000
[    0.317457] GICv3: CPU3: using allocated LPI pending table @0x0000000881120000
[    0.317522] CPU3: Booted secondary processor 0x0000000300 [0x431f0af1]
[    0.387355] Detected PIPT I-cache on CPU4
[    0.387426] GICv3: CPU4: found redistributor 400 region 0:0x0000000401200000
[    0.387443] GICv3: CPU4: using allocated LPI pending table @0x0000000881130000
[    0.387508] CPU4: Booted secondary processor 0x0000000400 [0x431f0af1]
[    0.455504] Detected PIPT I-cache on CPU5
[    0.455577] GICv3: CPU5: found redistributor 500 region 0:0x0000000401280000
[    0.455594] GICv3: CPU5: using allocated LPI pending table @0x0000000881140000
[    0.455660] CPU5: Booted secondary processor 0x0000000500 [0x431f0af1]
[    0.524389] Detected PIPT I-cache on CPU6
[    0.524466] GICv3: CPU6: found redistributor 600 region 0:0x0000000401300000
[    0.524483] GICv3: CPU6: using allocated LPI pending table @0x0000000881150000
[    0.524548] CPU6: Booted secondary processor 0x0000000600 [0x431f0af1]
[    0.592054] Detected PIPT I-cache on CPU7
[    0.592134] GICv3: CPU7: found redistributor 700 region 0:0x0000000401380000
[    0.592151] GICv3: CPU7: using allocated LPI pending table @0x0000000881160000
[    0.592216] CPU7: Booted secondary processor 0x0000000700 [0x431f0af1]
[    0.662431] Detected PIPT I-cache on CPU8
[    0.662515] GICv3: CPU8: found redistributor 800 region 0:0x0000000401400000
[    0.662532] GICv3: CPU8: using allocated LPI pending table @0x0000000881170000
[    0.662598] CPU8: Booted secondary processor 0x0000000800 [0x431f0af1]
[    0.733527] Detected PIPT I-cache on CPU9
[    0.733614] GICv3: CPU9: found redistributor 900 region 0:0x0000000401480000
[    0.733632] GICv3: CPU9: using allocated LPI pending table @0x0000000881180000
[    0.733698] CPU9: Booted secondary processor 0x0000000900 [0x431f0af1]
[    0.801502] Detected PIPT I-cache on CPU10
[    0.801594] GICv3: CPU10: found redistributor a00 region 0:0x0000000401500000
[    0.801612] GICv3: CPU10: using allocated LPI pending table @0x0000000881190000
[    0.801678] CPU10: Booted secondary processor 0x0000000a00 [0x431f0af1]
[    0.869576] Detected PIPT I-cache on CPU11
[    0.869671] GICv3: CPU11: found redistributor b00 region 0:0x0000000401580000
[    0.869689] GICv3: CPU11: using allocated LPI pending table @0x00000008811a0000
[    0.869754] CPU11: Booted secondary processor 0x0000000b00 [0x431f0af1]
[    0.937794] Detected PIPT I-cache on CPU12
[    0.937892] GICv3: CPU12: found redistributor c00 region 0:0x0000000401600000
[    0.937910] GICv3: CPU12: using allocated LPI pending table @0x00000008811b0000
[    0.937976] CPU12: Booted secondary processor 0x0000000c00 [0x431f0af1]
[    1.008643] Detected PIPT I-cache on CPU13
[    1.008744] GICv3: CPU13: found redistributor d00 region 0:0x0000000401680000
[    1.008762] GICv3: CPU13: using allocated LPI pending table @0x00000008811c0000
[    1.008828] CPU13: Booted secondary processor 0x0000000d00 [0x431f0af1]
[    1.077605] Detected PIPT I-cache on CPU14
[    1.077710] GICv3: CPU14: found redistributor e00 region 0:0x0000000401700000
[    1.077728] GICv3: CPU14: using allocated LPI pending table @0x00000008811d0000
[    1.077793] CPU14: Booted secondary processor 0x0000000e00 [0x431f0af1]
[    1.146135] Detected PIPT I-cache on CPU15
[    1.146242] GICv3: CPU15: found redistributor f00 region 0:0x0000000401780000
[    1.146260] GICv3: CPU15: using allocated LPI pending table @0x00000008811e0000
[    1.146326] CPU15: Booted secondary processor 0x0000000f00 [0x431f0af1]
[    1.217323] Detected PIPT I-cache on CPU16
[    1.217435] GICv3: CPU16: found redistributor 1000 region 0:0x0000000401800000
[    1.217453] GICv3: CPU16: using allocated LPI pending table @0x00000008811f0000
[    1.217520] CPU16: Booted secondary processor 0x0000001000 [0x431f0af1]
[    1.286521] Detected PIPT I-cache on CPU17
[    1.286637] GICv3: CPU17: found redistributor 1100 region 0:0x0000000401880000
[    1.286656] GICv3: CPU17: using allocated LPI pending table @0x0000000881200000
[    1.286722] CPU17: Booted secondary processor 0x0000001100 [0x431f0af1]
[    1.356311] Detected PIPT I-cache on CPU18
[    1.356430] GICv3: CPU18: found redistributor 1200 region 0:0x0000000401900000
[    1.356449] GICv3: CPU18: using allocated LPI pending table @0x0000000881210000
[    1.356515] CPU18: Booted secondary processor 0x0000001200 [0x431f0af1]
[    1.426268] Detected PIPT I-cache on CPU19
[    1.426390] GICv3: CPU19: found redistributor 1300 region 0:0x0000000401980000
[    1.426409] GICv3: CPU19: using allocated LPI pending table @0x0000000881220000
[    1.426477] CPU19: Booted secondary processor 0x0000001300 [0x431f0af1]
[    1.495431] Detected PIPT I-cache on CPU20
[    1.495556] GICv3: CPU20: found redistributor 1400 region 0:0x0000000401a00000
[    1.495575] GICv3: CPU20: using allocated LPI pending table @0x0000000881230000
[    1.495642] CPU20: Booted secondary processor 0x0000001400 [0x431f0af1]
[    1.565353] Detected PIPT I-cache on CPU21
[    1.565482] GICv3: CPU21: found redistributor 1500 region 0:0x0000000401a80000
[    1.565501] GICv3: CPU21: using allocated LPI pending table @0x0000000881240000
[    1.565568] CPU21: Booted secondary processor 0x0000001500 [0x431f0af1]
[    1.635304] Detected PIPT I-cache on CPU22
[    1.635437] GICv3: CPU22: found redistributor 1600 region 0:0x0000000401b00000
[    1.635456] GICv3: CPU22: using allocated LPI pending table @0x0000000881250000
[    1.635522] CPU22: Booted secondary processor 0x0000001600 [0x431f0af1]
[    1.705320] Detected PIPT I-cache on CPU23
[    1.705456] GICv3: CPU23: found redistributor 1700 region 0:0x0000000401b80000
[    1.705474] GICv3: CPU23: using allocated LPI pending table @0x0000000881260000
[    1.705541] CPU23: Booted secondary processor 0x0000001700 [0x431f0af1]
[    1.775442] Detected PIPT I-cache on CPU24
[    1.775581] GICv3: CPU24: found redistributor 1800 region 0:0x0000000401c00000
[    1.775601] GICv3: CPU24: using allocated LPI pending table @0x0000000881270000
[    1.775666] CPU24: Booted secondary processor 0x0000001800 [0x431f0af1]
[    1.845367] Detected PIPT I-cache on CPU25
[    1.845509] GICv3: CPU25: found redistributor 1900 region 0:0x0000000401c80000
[    1.845529] GICv3: CPU25: using allocated LPI pending table @0x0000000881280000
[    1.845594] CPU25: Booted secondary processor 0x0000001900 [0x431f0af1]
[    1.915506] Detected PIPT I-cache on CPU26
[    1.915651] GICv3: CPU26: found redistributor 1a00 region 0:0x0000000401d00000
[    1.915671] GICv3: CPU26: using allocated LPI pending table @0x0000000881290000
[    1.915738] CPU26: Booted secondary processor 0x0000001a00 [0x431f0af1]
[    1.985640] Detected PIPT I-cache on CPU27
[    1.985789] GICv3: CPU27: found redistributor 1b00 region 0:0x0000000401d80000
[    1.985809] GICv3: CPU27: using allocated LPI pending table @0x00000008812a0000
[    1.985876] CPU27: Booted secondary processor 0x0000001b00 [0x431f0af1]
[    2.055631] Detected PIPT I-cache on CPU28
[    2.055783] GICv3: CPU28: found redistributor 1c00 region 0:0x0000000401e00000
[    2.055802] GICv3: CPU28: using allocated LPI pending table @0x00000008812b0000
[    2.055868] CPU28: Booted secondary processor 0x0000001c00 [0x431f0af1]
[    2.125761] Detected PIPT I-cache on CPU29
[    2.125916] GICv3: CPU29: found redistributor 1d00 region 0:0x0000000401e80000
[    2.125936] GICv3: CPU29: using allocated LPI pending table @0x00000008812c0000
[    2.126002] CPU29: Booted secondary processor 0x0000001d00 [0x431f0af1]
[    2.195478] Detected PIPT I-cache on CPU30
[    2.195637] GICv3: CPU30: found redistributor 1e00 region 0:0x0000000401f00000
[    2.195657] GICv3: CPU30: using allocated LPI pending table @0x00000008812d0000
[    2.195723] CPU30: Booted secondary processor 0x0000001e00 [0x431f0af1]
[    2.266056] Detected PIPT I-cache on CPU31
[    2.266218] GICv3: CPU31: found redistributor 1f00 region 0:0x0000000401f80000
[    2.266238] GICv3: CPU31: using allocated LPI pending table @0x00000008812e0000
[    2.266305] CPU31: Booted secondary processor 0x0000001f00 [0x431f0af1]
[    2.332404] Detected PIPT I-cache on CPU32
[    2.332505] GICv3: CPU32: found redistributor 1 region 0:0x0000000401020000
[    2.332524] GICv3: CPU32: using allocated LPI pending table @0x00000008812f0000
[    2.332588] CPU32: Booted secondary processor 0x0000000001 [0x431f0af1]
[    2.397809] Detected PIPT I-cache on CPU33
[    2.397909] GICv3: CPU33: found redistributor 101 region 0:0x00000004010a0000
[    2.397927] GICv3: CPU33: using allocated LPI pending table @0x0000000881300000
[    2.397990] CPU33: Booted secondary processor 0x0000000101 [0x431f0af1]
[    2.463099] Detected PIPT I-cache on CPU34
[    2.463203] GICv3: CPU34: found redistributor 201 region 0:0x0000000401120000
[    2.463221] GICv3: CPU34: using allocated LPI pending table @0x0000000881310000
[    2.463284] CPU34: Booted secondary processor 0x0000000201 [0x431f0af1]
[    2.528875] Detected PIPT I-cache on CPU35
[    2.528981] GICv3: CPU35: found redistributor 301 region 0:0x00000004011a0000
[    2.529000] GICv3: CPU35: using allocated LPI pending table @0x0000000881320000
[    2.529062] CPU35: Booted se1] GICv3: CPU36:PI pending table    2.659506] Det04012a0000
[   7: Booted secondary processor 0x0000000501 [0x431f0af1]
[    2.724812] Detected PIPT I-cache on CPU38
[    2.724929] GICv3: CPU38: found redistributor 601 region 0:0x0000000401320000
[    2.724948] GICv3: CPU38: using allocated LPI pending table @0x0000000881350000
[    2.725010] CPU38: Booted secondary processor 0x0000000601 [0x431f0af1]
[    2.790045] Detected PIPT I-cache on CPU39
[    2.790165] GICv3: CPU39: found redistributor 701 region 0:0x00000004013a0000
[    2.790184] GICv3: CPU39: using allocated LPI pending table @0x0000000881360000
[    2.790246] CPU39: Booted secondary processor 0x0000000701 [0x431f0af1]
[    2.855767] Detected PIPT I-cache on CPU40
[    2.855891] GICv3: CPU40: found redistributor 801 region 0:0x0000000401420000
[    2.855909] GICv3: CPU40: using allocated LPI pending table @0x0000000881370000
[    2.855972] CPU40: Booted secondary processor 0x0000000801 [0x431f0af1]
[    2.921115] Detected PIPT I-cache on CPU41
[    2.921242] GICv3: CPU41: found redistributor 901 region 0:0x00000004014a0000
[    2.921260] GICv3: CPU41: using allocated LPI pending table @0x0000000881380000
[    2.921322] CPU41: Booted secondary processor 0x0000000901 [0x431f0af1]
[    2.986852] Detected PIPT I-cache on CPU42
[    2.986982] GICv3: CPU42: found redistributor a01 region 0:0x0000000401520000
[    2.987000] GICv3: CPU42: using allocated LPI pending table @0x0000000881390000
[    2.987063] CPU42: Booted secondary processor 0x0000000a01 [0x431f0af1]
[    3.052791] Detected PIPT I-cache on CPU43
[    3.052924] GICv3: CPU43: found redistributor b01 region 0:0x00000004015a0000
[    3.052942] GICv3: CPU43: using allocated LPI pending table @0x00000008813a0000
[    3.053005] CPU43: Booted secondary processor 0x0000000b01 [0x431f0af1]
[    3.118108] Detected PIPT I-cache on CPU44
[    3.118245] GICv3: CPU44: found redistributor c01 region 0:0x0000000401620000
[    3.118264] GICv3: CPU44: using allocated LPI pending table @0x00000008813b0000
[    3.118327] CPU44: Booted secondary processor 0x0000000c01 [0x431f0af1]
[    3.183495] Detected PIPT I-cache on CPU45
[    3.183635] GICv3: CPU45: found redistributor d01 region 0:0x00000004016a0000
[    3.183654] GICv3: CPU45: using allocated LPI pending table @0x00000008813c0000
[    3.183717] CPU45: Booted secondary processor 0x0000000d01 [0x431f0af1]
[    3.248978] Detected PIPT I-cache on CPU46
[    3.249120] GICv3: CPU46: found redistributor e01 region 0:0x0000000401720000
[    3.249139] GICv3: CPU46: using allocated LPI pending table @0x00000008813d0000
[    3.249202] CPU46: Booted secondary processor 0x0000000e01 [0x431f0af1]
[    3.314315] Detected PIPT I-cache on CPU47
[    3.314462] GICv3: CPU47: found redistributor f01 region 0:0x00000004017a0000
[    3.314481] GICv3: CPU47: using allocated LPI pending table @0x00000008813e0000
[    3.314543] CPU47: Booted secondary processor 0x0000000f01 [0x431f0af1]
[    3.380053] Detected PIPT I-cache on CPU48
[    3.380206] GICv3: CPU48: found redistributor 1001 region 0:0x0000000401820000
[    3.380225] GICv3: CPU48: using allocated LPI pending table @0x00000008813f0000
[    3.380288] CPU48: Booted secondary processor 0x0000001001 [0x431f0af1]
[    3.445535] Detected PIPT I-cache on CPU49
[    3.445692] GICv3: CPU49: found redistributor 1101 region 0:0x00000004018a0000
[    3.445711] GICv3: CPU49: using allocated LPI pending table @0x0000000881400000
[    3.445775] CPU49: Booted secondary processor 0x0000001101 [0x431f0af1]
[    3.511131] Detected PIPT I-cache on CPU50
[    3.511287] GICv3: CPU50: found redistributor 1201 region 0:0x0000000401920000
[    3.511306] GICv3: CPU50: using allocated LPI pending table @0x0000000881410000
[    3.511370] CPU50: Booted secondary processor 0x0000001201 [0x431f0af1]
[    3.576651] Detected PIPT I-cache on CPU51
[    3.576811] GICv3: CPU51: found redistributor 1301 region 0:0x00000004019a0000
[    3.576830] GICv3: CPU51: using allocated LPI pending table @0x0000000881420000
[    3.576893] CPU51: Booted secondary processor 0x0000001301 [0x431f0af1]
[    3.642235] Detected PIPT I-cache on CPU52
[    3.642398] GICv3: CPU52: found redistributor 1401 region 0:0x0000000401a20000
[    3.642417] GICv3: CPU52: using allocated LPI pending table @0x0000000881430000
[    3.642481] CPU52: Booted secondary processor 0x0000001401 [0x431f0af1]
[    3.707905] Detected PIPT I-cache on CPU53
[    3.708071] GICv3: CPU53: found redistributor 1501 region 0:0x0000000401aa0000
[    3.708091] GICv3: CPU53: using allocated LPI pending table @0x0000000881440000
[    3.708155] CPU53: Booted secondary processor 0x0000001501 [0x431f0af1]
[    3.773378] Detected PIPT I-cache on CPU54
[    3.773551] GICv3: CPU54: found redistributor 1601 region 0:0x0000000401b20000
[    3.773571] GICv3: CPU54: using allocated LPI pending table @0x0000000881450000
[    3.773634] CPU54: Booted secondary processor 0x0000001601 [0x431f0af1]
[    3.838862] Detected PIPT I-cache on CPU55
[    3.839034] GICv3: CPU55: found redistributor 1701 region 0:0x0000000401ba0000
[    3.839053] GICv3: CPU55: using allocated LPI pending table @0x0000000881460000
[    3.839116] CPU55: Booted secondary processor 0x0000001701 [0x431f0af1]
[    3.904439] Detected PIPT I-cache on CPU56
[    3.904615] GICv3: CPU56: found redistributor 1801 region 0:0x0000000401c20000
[    3.904635] GICv3: CPU56: using allocated LPI pending table @0x0000000881470000
[    3.904697] CPU56: Booted secondary processor 0x0000001801 [0x431f0af1]
[    3.969914] Detected PIPT I-cache on CPU57
[    3.970093] GICv3: CPU57: found redistributor 1901 region 0:0x0000000401ca0000
[    3.970114] GICv3: CPU57: using allocated LPI pending table @0x0000000881480000
[    3.970176] CPU57: Booted secondary processor 0x0000001901 [0x431f0af1]
[    4.035474] Detected PIPT I-cache on CPU58
[    4.035661] GICv3: CPU58: found redistributor 1a01 region 0:0x0000000401d20000
[    4.035682] GICv3: CPU58: using allocated LPI pending table @0x0000000881490000
[    4.035745] CPU58: Booted secondary processor 0x0000001a01 [0x431f0af1]
[    4.101048] Detected PIPT I-cache on CPU59
[    4.101235] GICv3: CPU59: found redistributor 1b01 region 0:0x0000000401da0000
[    4.101255] GICv3: CPU59: using allocated LPI pending table @0x00000008814a0000
[    4.101320] CPU59: Booted secondary processor 0x0000001b01 [0x431f0af1]
[    4.167042] Detected PIPT I-cache on CPU60
[    4.167232] GICv3: CPU60: found redistributor 1c01 region 0:0x0000000401e20000
[    4.167252] GICv3: CPU60: using allocated LPI pending table @0x00000008814b0000
[    4.167315] CPU60: Booted secondary processor 0x0000001c01 [0x431f0af1]
[    4.232894] Detected PIPT I-cache on CPU61
[    4.233091] GICv3: CPU61: found redistributor 1d01 region 0:0x0000000401ea0000
[    4.233112] GICv3: CPU61: using allocated LPI pending table @0x00000008814c0000
[    4.233176] CPU61: Booted secondary processor 0x0000001d01 [0x431f0af1]
[    4.298397] Detected PIPT I-cache on CPU62
[    4.298595] GICv3: CPU62: found redistributor 1e01 region 0:0x0000000401f20000
[    4.298616] GICv3: CPU62: using allocated LPI pending table @0x00000008814d0000
[    4.298680] CPU62: Booted secondary processor 0x0000001e01 [0x431f0af1]
[    4.364025] Detected PIPT I-cache on CPU63
[    4.364228] GICv3: CPU63: found redistributor 1f01 region 0:0x0000000401fa0000
[    4.364249] GICv3: CPU63: using allocated LPI pending table @0x00000008814e0000
[    4.364312] CPU63: Booted secondary processor 0x0000001f01 [0x431f0af1]
[    4.430686] Detected PIPT I-cache on CPU64
[    4.430832] GICv3: CPU64: found redistributor 2 region 0:0x0000000401040000
[    4.430853] GICv3: CPU64: using allocated LPI pending table @0x00000008814f0000
[    4.430916] CPU64: Booted secondary processor 0x0000000002 [0x431f0af1]
[    4.496350] Detected PIPT I-cache on CPU65
[    4.496496] GICv3: CPU65: found redistributor 102 region 0:0x00000004010c0000
[    4.496516] GICv3: CPU65: using allocated LPI pending table @0x0000000881500000
[    4.496578] CPU65: Booted secondary processor 0x0000000102 [0x431f0af1]
[    4.561991] Detected PIPT I-cache on CPU66
[    4.562141] GICv3: CPU66: found redistributor 202 region 0:0x0000000401140000
[    4.562161] GICv3: CPU66: using allocated LPI pending table @0x0000000881510000
[    4.562224] CPU66: Booted secondary processor 0x0000000202 [0x431f0af1]
[    4.627863] Detected PIPT I-cache on CPU67
[    4.628017] GICv3: CPU67: found redistributor 302 region 0:0x00000004011c0000
[    4.628037] GICv3: CPU67: using allocated LPI pending table @0x0000000881520000
[    4.628099] CPU67: Booted secondary processor 0x0000000302 [0x431f0af1]
[    4.693411] Detected PIPT I-cache on CPU68
[    4.693569] GICv3: CPU68: found redistributor 402 region 0:0x0000000401240000
[    4.693589] GICv3: CPU68: using allocated LPI pending table @0x0000000881530000
[    4.693652] CPU68: Booted secondary processor 0x0000000402 [0x431f0af1]
[    4.758963] Detected PIPT I-cache on CPU69
[    4.759125] GICv3: CPU69: found redistributor 502 region 0:0x00000004012c0000
[    4.759146] GICv3: CPU69: using allocated LPI pending table @0x0000000881540000
[    4.759207] CPU69: Booted secondary processor 0x0000000502 [0x431f0af1]
[    4.824432] Detected PIPT I-cache on CPU70
[    4.824598] GICv3: CPU70: found redistributor 602 region 0:0x0000000401340000
[    4.824619] GICv3: CPU70: using allocated LPI pending table @0x0000000881550000
[    4.824682] CPU70: Booted secondary processor 0x0000000602 [0x431f0af1]
[    4.890463] Detected PIPT I-cache on CPU71
[    4.890633] GICv3: CPU71: found redistributor 702 region 0:0x00000004013c0000
[    4.890659] GICv3: CPU71: using allocated LPI pending table @0x0000000881560000
[    4.890721] CPU71: Booted secondary processor 0x0000000702 [0x431f0af1]
[    4.956244] Detected PIPT I-cache on CPU72
[    4.956417] GICv3: CPU72: found redistributor 802 region 0:0x0000000401440000
[    4.956438] GICv3: CPU72: using allocated LPI pending table @0x0000000881570000
[    4.956499] CPU72: Booted secondary processor 0x0000000802 [0x431f0af1]
[    5.021812] Detected PIPT I-cache on CPU73
[    5.021990] GICv3: CPU73: found redistributor 902 region 0:0x00000004014c0000
[    5.022011] GICv3: CPU73: using allocated LPI pending table @0x0000000881580000
[    5.022072] CPU73: Booted secondary processor 0x0000000902 [0x431f0af1]
[    5.087851] Detected PIPT I-cache on CPU74
[    5.088032] GICv3: CPU74: found redistributor a02 region 0:0x0000000401540000
[    5.088053] GICv3: CPU74: using allocated LPI pending table @0x0000000881590000
[    5.088116] CPU74: Booted secondary processor 0x0000000a02 [0x431f0af1]
[    5.153697] Detected PIPT I-cache on CPU75
[    5.153881] GICv3: CPU75: found redistributor b02 region 0:0x00000004015c0000
[    5.153902] GICv3: CPU75: using allocated LPI pending table @0x00000008815a0000
[    5.153964] CPU75: Booted secondary processor 0x0000000b02 [0x431f0af1]
[    5.219206] Detected PIPT I-cache on CPU76
[    5.219394] GICv3: CPU76: found redistributor c02 region 0:0x0000000401640000
[    5.219415] GICv3: CPU76: using allocated LPI pending table @0x00000008815b0000
[    5.219478] CPU76: Booted secondary processor 0x0000000c02 [0x431f0af1]
[    5.285087] Detected PIPT I-cache on CPU77
[    5.285283] GICv3: CPU77: found redistributor d02 region 0:0x00000004016c0000
[    5.285305] GICv3: CPU77: using allocated LPI pending table @0x00000008815c0000
[    5.285367] CPU77: Booted secondary processor 0x0000000d02 [0x431f0af1]
[    5.350601] Detected PIPT I-cache on CPU78
[    5.350794] GICv3: CPU78: found redistributor e02 region 0:0x0000000401740000
[    5.350815] GICv3: CPU78: using allocated LPI pending table @0x00000008815d0000
[    5.350878] CPU78: Booted secondary processor 0x0000000e02 [0x431f0af1]
[    5.416180] Detected PIPT I-cache on CPU79
[    5.416378] GICv3: CPU79: found redistributor f02 region 0:0x00000004017c0000
[    5.416399] GICv3: CPU79: using allocated LPI pending table @0x00000008815e0000
[    5.416461] CPU79: Booted secondary processor 0x0000000f02 [0x431f0af1]
[    5.482184] Detected PIPT I-cache on CPU80
[    5.482386] GICv3: CPU80: found redistributor 1002 region 0:0x0000000401840000
[    5.482413] GICv3: CPU80: using allocated LPI pending table @0x00000008815f0000
[    5.482475] CPU80: Booted secondary processor 0x0000001002 [0x431f0af1]
[    5.547871] Detected PIPT I-cache on CPU81
[    5.548077] GICv3: CPU81: found redistributor 1102 region 0:0x00000004018c0000
[    5.548098] GICv3: CPU81: using allocated LPI pending table @0x0000000881600000
[    5.548161] CPU81: Booted secondary processor 0x0000001102 [0x431f0af1]
[    5.613634] Detected PIPT I-cache on CPU82
[    5.613844] GICv3: CPU82: found redistributor 1202 region 0:0x0000000401940000
[    5.613867] GICv3: CPU82: using allocated LPI pending table @0x0000000881610000
[    5.613928] CPU82: Booted secondary processor 0x0000001202 [0x431f0af1]
[    5.679310] Detected PIPT I-cache on CPU83
[    5.679522] GICv3: CPU83: found redistributor 1302 region 0:0x00000004019c0000
[    5.679547] GICv3: CPU83: using allocated LPI pending table @0x0000000881620000
[    5.679610] CPU83: Booted secondary processor 0x0000001302 [0x431f0af1]
[    5.745035] Detected PIPT I-cache on CPU84
[    5.745258] GICv3: CPU84: found redistributor 1402 region 0:0x0000000401a40000
[    5.745280] GICv3: CPU84: using allocated LPI pending table @0x0000000881630000
[    5.745343] CPU84: Booted secondary processor 0x0000001402 [0x431f0af1]
[    5.810778] Detected PIPT I-cache on CPU85
[    5.810997] GICv3: CPU85: found redistributor 1502 region 0:0x0000000401ac0000
[    5.811020] GICv3: CPU85: using allocated LPI pending table @0x0000000881640000
[    5.811081] CPU85: Booted secondary processor 0x0000001502 [0x431f0af1]
[    5.876369] Detected PIPT I-cache on CPU86
[    5.876598] GICv3: CPU86: found redistributor 1602 region 0:0x0000000401b40000
[    5.876621] GICv3: CPU86: using allocated LPI pending table @0x0000000881650000
[    5.876683] CPU86: Booted secondary processor 0x0000001602 [0x431f0af1]
[    5.941978] Detected PIPT I-cache on CPU87
[    5.942203] GICv3: CPU87: found redistributor 1702 region 0:0x0000000401bc0000
[    5.942225] GICv3: CPU87: using allocated LPI pending table @0x0000000881660000
[    5.942288] CPU87: Booted secondary processor 0x0000001702 [0x431f0af1]
[    6.007751] Detected PIPT I-cache on CPU88
[    6.007980] GICv3: CPU88: found redistributor 1802 region 0:0x0000000401c40000
[    6.008003] GICv3: CPU88: using allocated LPI pending table @0x0000000881670000
[    6.008065] CPU88: Booted secondary processor 0x0000001802 [0x431f0af1]
[    6.073415] Detected PIPT I-cache on CPU89
[    6.073648] GICv3: CPU89: found redistributor 1902 region 0:0x0000000401cc0000
[    6.073670] GICv3: CPU89: using allocated LPI pending table @0x0000000881680000
[    6.073732] CPU89: Booted secondary processor 0x0000001902 [0x431f0af1]
[    6.139144] Detected PIPT I-cache on CPU90
[    6.139380] GICv3: CPU90: found redistributor 1a02 region 0:0x0000000401d40000
[    6.139402] GICv3: CPU90: using allocated LPI pending table @0x0000000881690000
[    6.139465] CPU90: Booted secondary processor 0x0000001a02 [0x431f0af1]
[    6.204850] Detected PIPT I-cache on CPU91
[    6.205095] GICv3: CPU91: found redistributor 1b02 region 0:0x0000000401dc0000
[    6.205118] GICv3: CPU91: using allocated LPI pending table @0x00000008816a0000
[    6.205181] CPU91: Booted secondary processor 0x0000001b02 [0x431f0af1]
[    6.270570] Detected PIPT I-cache on CPU92
[    6.270813] GICv3: CPU92: found redistributor 1c02 region 0:0x0000000401e40000
[    6.270835] GICv3: CPU92: using allocated LPI pending table @0x00000008816b0000
[    6.270897] CPU92: Booted secondary processor 0x0000001c02 [0x431f0af1]
[    6.336247] Detected PIPT I-cache on CPU93
[    6.336493] GICv3: CPU93: found redistributor 1d02 region 0:0x0000000401ec0000
[    6.336517] GICv3: CPU93: using allocated LPI pending table @0x00000008816c0000
[    6.336580] CPU93: Booted secondary processor 0x0000001d02 [0x431f0af1]
[    6.401896] Detected PIPT I-cache on CPU94
[    6.402145] GICv3: CPU94: found redistributor 1e02 region 0:0x0000000401f40000
[    6.402169] GICv3: CPU94: using allocated LPI pending table @0x00000008816d0000
[    6.402231] CPU94: Booted secondary processor 0x0000001e02 [0x431f0af1]
[    6.467545] Detected PIPT I-cache on CPU95
[    6.467798] GICv3: CPU95: found redistributor 1f02 region 0:0x0000000401fc0000
[    6.467821] GICv3: CPU95: using allocated LPI pending table @0x00000008816e0000
[    6.467883] CPU95: Booted secondary processor 0x0000001f02 [0x431f0af1]
[    6.534031] Detected PIPT I-cache on CPU96
[    6.534228] GICv3: CPU96: found redistributor 3 region 0:0x0000000401060000
[    6.534253] GICv3: CPU96: using allocated LPI pending table @0x00000008816f0000
[    6.534317] CPU96: Booted secondary processor 0x0000000003 [0x431f0af1]
[    6.599941] Detected PIPT I-cache on CPU97
[    6.600139] GICv3: CPU97: found redistributor 103 region 0:0x00000004010e0000
[    6.600162] GICv3: CPU97: using allocated LPI pending table @0x0000000881700000
[    6.600224] CPU97: Booted secondary processor 0x0000000103 [0x431f0af1]
[    6.665896] Detected PIPT I-cache on CPU98
[    6.666097] GICv3: CPU98: found redistributor 203 region 0:0x0000000401160000
[    6.666121] GICv3: CPU98: using allocated LPI pending table @0x0000000881710000
[    6.666182] CPU98: Booted secondary processor 0x0000000203 [0x431f0af1]
[    6.731652] Detected PIPT I-cache on CPU99
[    6.731856] GICv3: CPU99: found redistributor 303 region 0:0x00000004011e0000
[    6.731880] GICv3: CPU99: using allocated LPI pending table @0x0000000881720000
[    6.731942] CPU99: Booted secondary processor 0x0000000303 [0x431f0af1]
[    6.797347] Detected PIPT I-cache on CPU100
[    6.797555] GICv3: CPU100: found redistributor 403 region 0:0x0000000401260000
[    6.797578] GICv3: CPU100: using allocated LPI pending table @0x0000000881730000
[    6.797641] CPU100: Booted secondary processor 0x0000000403 [0x431f0af1]
[    6.863106] Detected PIPT I-cache on CPU101
[    6.863317] GICv3: CPU101: found redistributor 503 region 0:0x00000004012e0000
[    6.863341] GICv3: CPU101: using allocated LPI pending table @0x0000000881740000
[    6.863404] CPU101: Booted secondary processor 0x0000000503 [0x431f0af1]
[    6.929043] Detected PIPT I-cache on CPU102
[    6.929258] GICv3: CPU102: found redistributor 603 region 0:0x0000000401360000
[    6.929282] GICv3: CPU102: using allocated LPI pending table @0x0000000881750000
[    6.929345] CPU102: Booted secondary processor 0x0000000603 [0x431f0af1]
[    6.994675] Detected PIPT I-cache on CPU103
[    6.994894] GICv3: CPU103: found redistributor 703 region 0:0x00000004013e0000
[    6.994927] GICv3: CPU103: using allocated LPI pending table @0x0000000881760000
[    6.994989] CPU103: Booted secondary processor 0x0000000703 [0x431f0af1]
[    7.060393] Detected PIPT I-cache on CPU104
[    7.060616] GICv3: CPU104: found redistributor 803 region 0:0x0000000401460000
[    7.060640] GICv3: CPU104: using allocated LPI pending table @0x0000000881770000
[    7.060701] CPU104: Booted secondary processor 0x0000000803 [0x431f0af1]
[    7.126123] Detected PIPT I-cache on CPU105
[    7.126348] GICv3: CPU105: found redistributor 903 region 0:0x00000004014e0000
[    7.126372] GICv3: CPU105: using allocated LPI pending table @0x0000000881780000
[    7.126434] CPU105: Booted secondary processor 0x0000000903 [0x431f0af1]
[    7.191863] Detected PIPT I-cache on CPU106
[    7.192091] GICv3: CPU106: found redistributor a03 region 0:0x0000000401560000
[    7.192115] GICv3: CPU106: using allocated LPI pending table @0x0000000881790000
[    7.192177] CPU106: Booted secondary processor 0x0000000a03 [0x431f0af1]
[    7.257853] Detected PIPT I-cache on CPU107
[    7.258085] GICv3: CPU107: found redistributor b03 region 0:0x00000004015e0000
[    7.258109] GICv3: CPU107: using allocated LPI pending table @0x00000008817a0000
[    7.258171] CPU107: Booted secondary processor 0x0000000b03 [0x431f0af1]
[    7.323589] Detected PIPT I-cache on CPU108
[    7.323823] GICv3: CPU108: found redistributor c03 region 0:0x0000000401660000
[    7.323847] GICv3: CPU108: using allocated LPI pending table @0x00000008817b0000
[    7.323909] CPU108: Booted secondary processor 0x0000000c03 [0x431f0af1]
[    7.389434] Detected PIPT I-cache on CPU109
[    7.389673] GICv3: CPU109: found redistributor d03 region 0:0x00000004016e0000
[    7.389697] GICv3: CPU109: using allocated LPI pending table @0x00000008817c0000
[    7.389759] CPU109: Booted secondary processor 0x0000000d03 [0x431f0af1]
[    7.455152] Detected PIPT I-cache on CPU110
[    7.455403] GICv3: CPU110: found redistributor e03 region 0:0x0000000401760000
[    7.455428] GICv3: CPU110: using allocated LPI pending table @0x00000008817d0000
[    7.455490] CPU110: Booted secondary processor 0x0000000e03 [0x431f0af1]
[    7.520835] Detected PIPT I-cache on CPU111
[    7.521080] GICv3: CPU111: found redistributor f03 region 0:0x00000004017e0000
[    7.521105] GICv3: CPU111: using allocated LPI pending table @0x00000008817e0000
[    7.521166] CPU111: Booted secondary processor 0x0000000f03 [0x431f0af1]
[    7.586877] Detected PIPT I-cache on CPU112
[    7.587125] GICv3: CPU112: found redistributor 1003 region 0:0x0000000401860000
[    7.587150] GICv3: CPU112: using allocated LPI pending table @0x00000008817f0000
[    7.587212] CPU112: Booted secondary processor 0x0000001003 [0x431f0af1]
[    7.653154] Detected PIPT I-cache on CPU113
[    7.653407] GICv3: CPU113: found redistributor 1103 region 0:0x00000004018e0000
[    7.653431] GICv3: CPU113: using allocated LPI pending table @0x0000000881800000
[    7.653493] CPU113: Booted secondary processor 0x0000001103 [0x431f0af1]
[    7.719043] Detected PIPT I-cache on CPU114
[    7.719299] GICv3: CPU114: found redistributor 1203 region 0:0x0000000401960000
[    7.719323] GICv3: CPU114: using allocated LPI pending table @0x0000000881810000
[    7.719385] CPU114: Booted secondary processor 0x0000001203 [0x431f0af1]
[    7.784899] Detected PIPT I-cache on CPU115
[    7.785159] GICv3: CPU115: found redistributor 1303 region 0:0x00000004019e0000
[    7.785184] GICv3: CPU115: using allocated LPI pending table @0x0000000881820000
[    7.785246] CPU115: Booted secondary processor 0x0000001303 [0x431f0af1]
[    7.850783] Detected PIPT I-cache on CPU116
[    7.851046] GICv3: CPU116: found redistributor 1403 region 0:0x0000000401a60000
[    7.851071] GICv3: CPU116: using allocated LPI pending table @0x0000000881830000
[    7.851133] CPU116: Booted secondary processor 0x0000001403 [0x431f0af1]
[    7.917216] Detected PIPT I-cache on CPU117
[    7.917482] GICv3: CPU117: found redistributor 1503 region 0:0x0000000401ae0000
[    7.917507] GICv3: CPU117: using allocated LPI pending table @0x0000000881840000
[    7.917569] CPU117: Booted secondary processor 0x0000001503 [0x431f0af1]
[    7.983057] Detected PIPT I-cache on CPU118
[    7.983326] GICv3: CPU118: found redistributor 1603 region 0:0x0000000401b60000
[    7.983352] GICv3: CPU118: using allocated LPI pending table @0x0000000881850000
[    7.983413] CPU118: Booted secondary processor 0x0000001603 [0x431f0af1]
[    8.048792] Detected PIPT I-cache on CPU119
[    8.049072] GICv3: CPU119: found redistributor 1703 region 0:0x0000000401be0000
[    8.049098] GICv3: CPU119: using allocated LPI pending table @0x0000000881860000
[    8.049161] CPU119: Booted secondary processor 0x0000001703 [0x431f0af1]
[    8.114721] Detected PIPT I-cache on CPU120
[    8.115007] GICv3: CPU120: found redistributor 1803 region 0:0x0000000401c60000
[    8.115033] GICv3: CPU120: using allocated LPI pending table @0x0000000881870000
[    8.115095] CPU120: Booted secondary processor 0x0000001803 [0x431f0af1]
[    8.180898] Detected PIPT I-cache on CPU121
[    8.181178] GICv3: CPU121: found redistributor 1903 region 0:0x0000000401ce0000
[    8.181203] GICv3: CPU121: using allocated LPI pending table @0x0000000881880000
[    8.181265] CPU121: Booted secondary processor 0x0000001903 [0x431f0af1]
[    8.246810] Detected PIPT I-cache on CPU122
[    8.247093] GICv3: CPU122: found redistributor 1a03 region 0:0x0000000401d60000
[    8.247118] GICv3: CPU122: using allocated LPI pending table @0x0000000881890000
[    8.247180] CPU122: Booted secondary processor 0x0000001a03 [0x431f0af1]
[    8.312738] Detected PIPT I-cache on CPU123
[    8.313025] GICv3: CPU123: found redistributor 1b03 region 0:0x0000000401de0000
[    8.313052] GICv3: CPU123: using allocated LPI pending table @0x00000008818a0000
[    8.313114] CPU123: Booted secondary processor 0x0000001b03 [0x431f0af1]
[    8.378942] Detected PIPT I-cache on CPU124
[    8.379232] GICv3: CPU124: found redistributor 1c03 region 0:0x0000000401e60000
[    8.379258] GICv3: CPU124: using allocated LPI pending table @0x00000008818b0000
[    8.379320] CPU124: Booted secondary processor 0x0000001c03 [0x431f0af1]
[    8.445114] Detected PIPT I-cache on CPU125
[    8.445418] GICv3: CPU125: found redistributor 1d03 region 0:0x0000000401ee0000
[    8.445444] GICv3: CPU125: using allocated LPI pending table @0x00000008818c0000
[    8.445506] CPU125: Booted secondary processor 0x0000001d03 [0x431f0af1]
[    8.510919] Detected PIPT I-cache on CPU126
[    8.511216] GICv3: CPU126: found redistributor 1e03 region 0:0x0000000401f60000
[    8.511242] GICv3: CPU126: using allocated LPI pending table @0x00000008818d0000
[    8.511303] CPU126: Booted secondary processor 0x0000001e03 [0x431f0af1]
[    8.576801] Detected PIPT I-cache on CPU127
[    8.577101] GICv3: CPU127: found redistributor 1f03 region 0:0x0000000401fe0000
[    8.577127] GICv3: CPU127: using allocated LPI pending table @0x00000008818e0000
[    8.577188] CPU127: Booted secondary processor 0x0000001f03 [0x431f0af1]
[    8.724561] Detected PIPT I-cache on CPU128
[    8.725052] GICv3: CPU128: found redistributor 10000 region 1:0x0000000441000000
[    8.725103] GICv3: CPU128: using allocated LPI pending table @0x00000008818f0000
[    8.725212] CPU128: Booted secondary processor 0x0000010000 [0x431f0af1]
[    8.874075] Detected PIPT I-cache on CPU129
[    8.874374] GICv3: CPU129: found redistributor 10100 region 1:0x0000000441080000
[    8.874403] GICv3: CPU129: using allocated LPI pending table @0x0000000881900000
[    8.874483] CPU129: Booted secondary processor 0x0000010100 [0x431f0af1]
[    9.022145] Detected PIPT I-cache on CPU130
[    9.022447] GICv3: CPU130: found redistributor 10200 region 1:0x0000000441100000
[    9.022476] GICv3: CPU130: using allocated LPI pending table @0x0000000881910000
[    9.022557] CPU130: Booted secondary processor 0x0000010200 [0x431f0af1]
[    9.171763] Detected PIPT I-cache on CPU131
[    9.172069] GICv3: CPU131: found redistributor 10300 region 1:0x0000000441180000
[    9.172098] GICv3: CPU131: using allocated LPI pending table @0x0000000881920000
[    9.172182] CPU131: Booted secondary processor 0x0000010300 [0x431f0af1]
[    9.322199] Detected PIPT I-cache on CPU132
[    9.322508] GICv3: CPU132: found redistributor 10400 region 1:0x0000000441200000
[    9.322538] GICv3: CPU132: using allocated LPI pending table @0x0000000881930000
[    9.322619] CPU132: Booted secondary processor 0x0000010400 [0x431f0af1]
[    9.471266] Detected PIPT I-cache on CPU133
[    9.471579] GICv3: CPU133: found redistributor 10500 region 1:0x0000000441280000
[    9.471608] GICv3: CPU133: using allocated LPI pending table @0x0000000881940000
[    9.471689] CPU133: Booted secondary processor 0x0000010500 [0x431f0af1]
[    9.619265] Detected PIPT I-cache on CPU134
[    9.619580] GICv3: CPU134: found redistributor 10600 region 1:0x0000000441300000
[    9.619610] GICv3: CPU134: using allocated LPI pending table @0x0000000881950000
[    9.619691] CPU134: Booted secondary processor 0x0000010600 [0x431f0af1]
[    9.770318] Detected PIPT I-cache on CPU135
[    9.770638] GICv3: CPU135: found redistributor 10700 region 1:0x0000000441380000
[    9.770667] GICv3: CPU135: using allocated LPI pending table @0x0000000881960000
[    9.770746] CPU135: Booted secondary processor 0x0000010700 [0x431f0af1]
[    9.918475] Detected PIPT I-cache on CPU136
[    9.918797] GICv3: CPU136: found redistributor 10800 region 1:0x0000000441400000
[    9.918827] GICv3: CPU136: using allocated LPI pending table @0x0000000881970000
[    9.918908] CPU136: Booted secondary processor 0x0000010800 [0x431f0af1]
[   10.066937] Detected PIPT I-cache on CPU137
[   10.067264] GICv3: CPU137: found redistributor 10900 region 1:0x0000000441480000
[   10.067294] GICv3: CPU137: using allocated LPI pending table @0x0000000881980000
[   10.067374] CPU137: Booted secondary processor 0x0000010900 [0x431f0af1]
[   10.215540] Detected PIPT I-cache on CPU138
[   10.215869] GICv3: CPU138: found redistributor 10a00 region 1:0x0000000441500000
[   10.215899] GICv3: CPU138: using allocated LPI pending table @0x0000000881990000
[   10.215978] CPU138: Booted secondary processor 0x0000010a00 [0x431f0af1]
[   10.364782] Detected PIPT I-cache on CPU139
[   10.365115] GICv3: CPU139: found redistributor 10b00 region 1:0x0000000441580000
[   10.365145] GICv3: CPU139: using allocated LPI pending table @0x00000008819a0000
[   10.365227] CPU139: Booted secondary processor 0x0000010b00 [0x431f0af1]
[   10.513022] Detected PIPT I-cache on CPU140
[   10.513358] GICv3: CPU140: found redistributor 10c00 region 1:0x0000000441600000
[   10.513388] GICv3: CPU140: using allocated LPI pending table @0x00000008819b0000
[   10.513467] CPU140: Booted secondary processor 0x0000010c00 [0x431f0af1]
[   10.661491] Detected PIPT I-cache on CPU141
[   10.661831] GICv3: CPU141: found redistributor 10d00 region 1:0x0000000441680000
[   10.661861] GICv3: CPU141: using allocated LPI pending table @0x00000008819c0000
[   10.661940] CPU141: Booted secondary processor 0x0000010d00 [0x431f0af1]
[   10.813676] Detected PIPT I-cache on CPU142
[   10.814018] GICv3: CPU142: found redistributor 10e00 region 1:0x0000000441700000
[   10.814048] GICv3: CPU142: using allocated LPI pending table @0x00000008819d0000
[   10.814129] CPU142: Booted secondary processor 0x0000010e00 [0x431f0af1]
[   10.962897] Detected PIPT I-cache on CPU143
[   10.963241] GICv3: CPU143: found redistributor 10f00 region 1:0x0000000441780000
[   10.963271] GICv3: CPU143: using allocated LPI pending table @0x00000008819e0000
[   10.963351] CPU143: Booted secondary processor 0x0000010f00 [0x431f0af1]
[   11.114650] Detected PIPT I-cache on CPU144
[   11.115001] GICv3: CPU144: found redistributor 11000 region 1:0x0000000441800000
[   11.115031] GICv3: CPU144: using allocated LPI pending table @0x00000008819f0000
[   11.115112] CPU144: Booted secondary processor 0x0000011000 [0x431f0af1]
[   11.265689] Detected PIPT I-cache on CPU145
[   11.266042] GICv3: CPU145: found redistributor 11100 region 1:0x0000000441880000
[   11.266073] GICv3: CPU145: using allocated LPI pending table @0x0000000881a00000
[   11.266155] CPU145: Booted secondary processor 0x0000011100 [0x431f0af1]
[   11.416746] Detected PIPT I-cache on CPU146
[   11.417102] GICv3: CPU146: found redistributor 11200 region 1:0x0000000441900000
[   11.417133] GICv3: CPU146: using allocated LPI pending table @0x0000000881a10000
[   11.417215] CPU146: Booted secondary processor 0x0000011200 [0x431f0af1]
[   11.567595] Detected PIPT I-cache on CPU147
[   11.567954] GICv3: CPU147: found redistributor 11300 region 1:0x0000000441980000
[   11.567985] GICv3: CPU147: using allocated LPI pending table @0x0000000881a20000
[   11.568067] CPU147: Booted secondary processor 0x0000011300 [0x431f0af1]
[   11.717718] Detected PIPT I-cache on CPU148
[   11.718082] GICv3: CPU148: found redistributor 11400 region 1:0x0000000441a00000
[   11.718113] GICv3: CPU148: using allocated LPI pending table @0x0000000881a30000
[   11.718193] CPU148: Booted secondary processor 0x0000011400 [0x431f0af1]
[   11.867616] Detected PIPT I-cache on CPU149
[   11.867982] GICv3: CPU149: found redistributor 11500 region 1:0x0000000441a80000
[   11.868014] GICv3: CPU149: using allocated LPI pending table @0x0000000881a40000
[   11.868096] CPU149: Booted secondary processor 0x0000011500 [0x431f0af1]
[   12.017560] Detected PIPT I-cache on CPU150
[   12.017930] GICv3: CPU150: found redistributor 11600 region 1:0x0000000441b00000
[   12.017961] GICv3: CPU150: using allocated LPI pending table @0x0000000881a50000
[   12.018042] CPU150: Booted secondary processor 0x0000011600 [0x431f0af1]
[   12.167606] Detected PIPT I-cache on CPU151
[   12.167979] GICv3: CPU151: found redistributor 11700 region 1:0x0000000441b80000
[   12.168010] GICv3: CPU151: using allocated LPI pending table @0x0000000881a60000
[   12.168091] CPU151: Booted secondary processor 0x0000011700 [0x431f0af1]
[   12.318897] Detected PIPT I-cache on CPU152
[   12.319274] GICv3: CPU152: found redistributor 11800 region 1:0x0000000441c00000
[   12.319305] GICv3: CPU152: using allocated LPI pending table @0x0000000881a70000
[   12.319387] CPU152: Booted secondary processor 0x0000011800 [0x431f0af1]
[   12.468960] Detected PIPT I-cache on CPU153
[   12.469341] GICv3: CPU153: found redistributor 11900 region 1:0x0000000441c80000
[   12.469372] GICv3: CPU153: using allocated LPI pending table @0x0000000881a80000
[   12.469453] CPU153: Booted secondary processor 0x0000011900 [0x431f0af1]
[   12.621918] Detected PIPT I-cache on CPU154
[   12.622302] GICv3: CPU154: found redistributor 11a00 region 1:0x0000000441d00000
[   12.622334] GICv3: CPU154: using allocated LPI pending table @0x0000000881a90000
[   12.622414] CPU154: Booted secondary processor 0x0000011a00 [0x431f0af1]
[   12.771865] Detected PIPT I-cache on CPU155
[   12.772251] GICv3: CPU155: found redistributor 11b00 region 1:0x0000000441d80000
[   12.772283] GICv3: CPU155: using allocated LPI pending table @0x0000000881aa0000
[   12.772366] CPU155: Booted secondary processor 0x0000011b00 [0x431f0af1]
[   12.922035] Detected PIPT I-cache on CPU156
[   12.922424] GICv3: CPU156: found redistributor 10881ab0000
[   PT I-cache on CP73332] GICv3: CPy processor 0x000: found redistributor 11e00 region 1:0x0000000441f00000
[   13.223789] GICv3: CPU158: using allocated LPI pending table @0x0000000881ad0000
[   13.223870] CPU158: Booted secondary processor 0x0000011e00 [0x431f0af1]
[   13.373548] Detected PIPT I-cache on CPU159
[   13.373946] GICv3: CPU159: found redistributor 11f00 region 1:0x0000000441f80000
[   13.373977] GICv3: CPU159: using allocated LPI pending table @0x0000000881ae0000
[   13.374058] CPU159: Booted secondary processor 0x0000011f00 [0x431f0af1]
[   13.519908] Detected PIPT I-cache on CPU160
[   13.520241] GICv3: CPU160: found redistributor 10001 region 1:0x0000000441020000
[   13.520271] GICv3: CPU160: using allocated LPI pending table @0x0000000881af0000
[   13.520348] CPU160: Booted secondary processor 0x0000010001 [0x431f0af1]
[   13.666066] Detected PIPT I-cache on CPU161
[   13.666404] GICv3: CPU161: found redistributor 10101 region 1:0x00000004410a0000
[   13.666435] GICv3: CPU161: using allocated LPI pending table @0x0000000881b00000
[   13.666515] CPU161: Booted secondary processor 0x0000010101 [0x431f0af1]
[   13.812384] Detected PIPT I-cache on CPU162
[   13.812725] GICv3: CPU162: found redistributor 10201 region 1:0x0000000441120000
[   13.812756] GICv3: CPU162: using allocated LPI pending table @0x0000000881b10000
[   13.812832] CPU162: Booted secondary processor 0x0000010201 [0x431f0af1]
[   13.958599] Detected PIPT I-cache on CPU163
[   13.958944] GICv3: CPU163: found redistributor 10301 region 1:0x00000004411a0000
[   13.958974] GICv3: CPU163: using allocated LPI pending table @0x0000000881b20000
[   13.959053] CPU163: Booted secondary processor 0x0000010301 [0x431f0af1]
[   14.104651] Detected PIPT I-cache on CPU164
[   14.104998] GICv3: CPU164: found redistributor 10401 region 1:0x0000000441220000
[   14.105028] GICv3: CPU164: using allocated LPI pending table @0x0000000881b30000
[   14.105107] CPU164: Booted secondary processor 0x0000010401 [0x431f0af1]
[   14.251042] Detected PIPT I-cache on CPU165
[   14.251394] GICv3: CPU165: found redistributor 10501 region 1:0x00000004412a0000
[   14.251425] GICv3: CPU165: using allocated LPI pending table @0x0000000881b40000
[   14.251504] CPU165: Booted secondary processor 0x0000010501 [0x431f0af1]
[   14.396999] Detected PIPT I-cache on CPU166
[   14.397353] GICv3: CPU166: found redistributor 10601 region 1:0x0000000441320000
[   14.397384] GICv3: CPU166: using allocated LPI pending table @0x0000000881b50000
[   14.397462] CPU166: Booted secondary processor 0x0000010601 [0x431f0af1]
[   14.543673] Detected PIPT I-cache on CPU167
[   14.544032] GICv3: CPU167: found redistributor 10701 region 1:0x00000004413a0000
[   14.544064] GICv3: CPU167: using allocated LPI pending table @0x0000000881b60000
[   14.544143] CPU167: Booted secondary processor 0x0000010701 [0x431f0af1]
[   14.690292] Detected PIPT I-cache on CPU168
[   14.690654] GICv3: CPU168: found redistributor 10801 region 1:0x0000000441420000
[   14.690684] GICv3: CPU168: using allocated LPI pending table @0x0000000881b70000
[   14.690763] CPU168: Booted secondary processor 0x0000010801 [0x431f0af1]
[   14.836552] Detected PIPT I-cache on CPU169
[   14.836919] GICv3: CPU169: found redistributor 10901 region 1:0x00000004414a0000
[   14.836950] GICv3: CPU169: using allocated LPI pending table @0x0000000881b80000
[   14.837030] CPU169: Booted secondary processor 0x0000010901 [0x431f0af1]
[   14.983080] Detected PIPT I-cache on CPU170
[   14.983446] GICv3: CPU170: found redistributor 10a01 region 1:0x0000000441520000
[   14.983476] GICv3: CPU170: using allocated LPI pending table @0x0000000881b90000
[   14.983554] CPU170: Booted secondary processor 0x0000010a01 [0x431f0af1]
[   15.129298] Detected PIPT I-cache on CPU171
[   15.129671] GICv3: CPU171: found redistributor 10b01 region 1:0x00000004415a0000
[   15.129703] GICv3: CPU171: using allocated LPI pending table @0x0000000881ba0000
[   15.129780] CPU171: Booted secondary processor 0x0000010b01 [0x431f0af1]
[   15.275861] Detected PIPT I-cache on CPU172
[   15.276235] GICv3: CPU172: found redistributor 10c01 region 1:0x0000000441620000
[   15.276266] GICv3: CPU172: using allocated LPI pending table @0x0000000881bb0000
[   15.276345] CPU172: Booted secondary processor 0x0000010c01 [0x431f0af1]
[   15.422347] Detected PIPT I-cache on CPU173
[   15.422723] GICv3: CPU173: found redistributor 10d01 region 1:0x00000004416a0000
[   15.422754] GICv3: CPU173: using allocated LPI pending table @0x0000000881bc0000
[   15.422832] CPU173: Booted secondary processor 0x0000010d01 [0x431f0af1]
[   15.568455] Detected PIPT I-cache on CPU174
[   15.568834] GICv3: CPU174: found redistributor 10e01 region 1:0x0000000441720000
[   15.568865] GICv3: CPU174: using allocated LPI pending table @0x0000000881bd0000
[   15.568945] CPU174: Booted secondary processor 0x0000010e01 [0x431f0af1]
[   15.714949] Detected PIPT I-cache on CPU175
[   15.715333] GICv3: CPU175: found redistributor 10f01 region 1:0x00000004417a0000
[   15.715364] GICv3: CPU175: using allocated LPI pending table @0x0000000881be0000
[   15.715443] CPU175: Booted secondary processor 0x0000010f01 [0x431f0af1]
[   15.861833] Detected PIPT I-cache on CPU176
[   15.862220] GICv3: CPU176: found redistributor 11001 region 1:0x0000000441820000
[   15.862251] GICv3: CPU176: using allocated LPI pending table @0x0000000881bf0000
[   15.862330] CPU176: Booted secondary processor 0x0000011001 [0x431f0af1]
[   16.008126] Detected PIPT I-cache on CPU177
[   16.008519] GICv3: CPU177: found redistributor 11101 region 1:0x00000004418a0000
[   16.008551] GICv3: CPU177: using allocated LPI pending table @0x0000000881c00000
[   16.008628] CPU177: Booted secondary processor 0x0000011101 [0x431f0af1]
[   16.154466] Detected PIPT I-cache on CPU178
[   16.154860] GICv3: CPU178: found redistributor 11201 region 1:0x0000000441920000
[   16.154892] GICv3: CPU178: using allocated LPI pending table @0x0000000881c10000
[   16.154971] CPU178: Booted secondary processor 0x0000011201 [0x431f0af1]
[   16.300939] Detected PIPT I-cache on CPU179
[   16.301337] GICv3: CPU179: found redistributor 11301 region 1:0x00000004419a0000
[   16.301368] GICv3: CPU179: using allocated LPI pending table @0x0000000881c20000
[   16.301445] CPU179: Booted secondary processor 0x0000011301 [0x431f0af1]
[   16.447677] Detected PIPT I-cache on CPU180
[   16.448079] GICv3: CPU180: found redistributor 11401 region 1:0x0000000441a20000
[   16.448110] GICv3: CPU180: using allocated LPI pending table @0x0000000881c30000
[   16.448188] CPU180: Booted secondary processor 0x0000011401 [0x431f0af1]
[   16.594309] Detected PIPT I-cache on CPU181
[   16.594717] GICv3: CPU181: found redistributor 11501 region 1:0x0000000441aa0000
[   16.594749] GICv3: CPU181: using allocated LPI pending table @0x0000000881c40000
[   16.594828] CPU181: Booted secondary processor 0x0000011501 [0x431f0af1]
[   16.740537] Detected PIPT I-cache on CPU182
[   16.740943] GICv3: CPU182: found redistributor 11601 region 1:0x0000000441b20000
[   16.740975] GICv3: CPU182: using allocated LPI pending table @0x0000000881c50000
[   16.741053] CPU182: Booted secondary processor 0x0000011601 [0x431f0af1]
[   16.886749] Detected PIPT I-cache on CPU183
[   16.887159] GICv3: CPU183: found redistributor 11701 region 1:0x0000000441ba0000
[   16.887192] GICv3: CPU183: using allocated LPI pending table @0x0000000881c60000
[   16.887269] CPU183: Booted secondary processor 0x0000011701 [0x431f0af1]
[   17.033214] Detected PIPT I-cache on CPU184
[   17.033630] GICv3: CPU184: found redistributor 11801 region 1:0x0000000441c20000
[   17.033662] GICv3: CPU184: using allocated LPI pending table @0x0000000881c70000
[   17.033741] CPU184: Booted secondary processor 0x0000011801 [0x431f0af1]
[   17.179522] Detected PIPT I-cache on CPU185
[   17.179938] GICv3: CPU185: found redistributor 11901 region 1:0x0000000441ca0000
[   17.179970] GICv3: CPU185: using allocated LPI pending table @0x0000000881c80000
[   17.180048] CPU185: Booted secondary processor 0x0000011901 [0x431f0af1]
[   17.326207] Detected PIPT I-cache on CPU186
[   17.326628] GICv3: CPU186: found redistributor 11a01 region 1:0x0000000441d20000
[   17.326661] GICv3: CPU186: using allocated LPI pending table @0x0000000881c90000
[   17.326740] CPU186: Booted secondary processor 0x0000011a01 [0x431f0af1]
[   17.472538] Detected PIPT I-cache on CPU187
[   17.472962] GICv3: CPU187: found redistributor 11b01 region 1:0x0000000441da0000
[   17.472994] GICv3: CPU187: using allocated LPI pending table @0x0000000881ca0000
[   17.473072] CPU187: Booted secondary processor 0x0000011b01 [0x431f0af1]
[   17.619258] Detected PIPT I-cache on CPU188
[   17.619687] GICv3: CPU188: found redistributor 11c01 region 1:0x0000000441e20000
[   17.619719] GICv3: CPU188: using allocated LPI pending table @0x0000000881cb0000
[   17.619798] CPU188: Booted secondary processor 0x0000011c01 [0x431f0af1]
[   17.765606] Detected PIPT I-cache on CPU189
[   17.766040] GICv3: CPU189: found redistributor 11d01 region 1:0x0000000441ea0000
[   17.766073] GICv3: CPU189: using allocated LPI pending table @0x0000000881cc0000
[   17.766153] CPU189: Booted secondary processor 0x0000011d01 [0x431f0af1]
[   17.911888] Detected PIPT I-cache on CPU190
[   17.912321] GICv3: CPU190: found redistributor 11e01 region 1:0x0000000441f20000
[   17.912353] GICv3: CPU190: using allocated LPI pending table @0x0000000881cd0000
[   17.912432] CPU190: Booted secondary processor 0x0000011e01 [0x431f0af1]
[   18.058407] Detected PIPT I-cache on CPU191
[   18.058844] GICv3: CPU191: found redistributor 11f01 region 1:0x0000000441fa0000
[   18.058876] GICv3: CPU191: using allocated LPI pending table @0x0000000881ce0000
[   18.058954] CPU191: Booted secondary processor 0x0000011f01 [0x431f0af1]
[   18.205248] Detected PIPT I-cache on CPU192
[   18.205625] GICv3: CPU192: found redistributor 10002 region 1:0x0000000441040000
[   18.205657] GICv3: CPU192: using allocated LPI pending table @0x0000000881cf0000
[   18.205736] CPU192: Booted secondary processor 0x0000010002 [0x431f0af1]
[   18.352316] Detected PIPT I-cache on CPU193
[   18.352695] GICv3: CPU193: found redistributor 10102 region 1:0x00000004410c0000
[   18.352732] GICv3: CPU193: using allocated LPI pending table @0x0000000881d00000
[   18.352810] CPU193: Booted secondary processor 0x0000010102 [0x431f0af1]
[   18.498839] Detected PIPT I-cache on CPU194
[   18.499228] GICv3: CPU194: found redistributor 10202 region 1:0x0000000441140000
[   18.499260] GICv3: CPU194: using allocated LPI pending table @0x0000000881d10000
[   18.499336] CPU194: Booted secondary processor 0x0000010202 [0x431f0af1]
[   18.645337] Detected PIPT I-cache on CPU195
[   18.645723] GICv3: CPU195: found redistributor 10302 region 1:0x00000004411c0000
[   18.645755] GICv3: CPU195: using allocated LPI pending table @0x0000000881d20000
[   18.645831] CPU195: Booted secondary processor 0x0000010302 [0x431f0af1]
[   18.791697] Detected PIPT I-cache on CPU196
[   18.792094] GICv3: CPU196: found redistributor 10402 region 1:0x0000000441240000
[   18.792126] GICv3: CPU196: using allocated LPI pending table @0x0000000881d30000
[   18.792203] CPU196: Booted secondary processor 0x0000010402 [0x431f0af1]
[   18.938335] Detected PIPT I-cache on CPU197
[   18.938726] GICv3: CPU197: found redistributor 10502 region 1:0x00000004412c0000
[   18.938758] GICv3: CPU197: using allocated LPI pending table @0x0000000881d40000
[   18.938837] CPU197: Booted secondary processor 0x0000010502 [0x431f0af1]
[   19.085096] Detected PIPT I-cache on CPU198
[   19.085491] GICv3: CPU198: found redistributor 10602 region 1:0x0000000441340000
[   19.085523] GICv3: CPU198: using allocated LPI pending table @0x0000000881d50000
[   19.085600] CPU198: Booted secondary processor 0x0000010602 [0x431f0af1]
[   19.231410] Detected PIPT I-cache on CPU199
[   19.231808] GICv3: CPU199: found redistributor 10702 region 1:0x00000004413c0000
[   19.231840] GICv3: CPU199: using allocated LPI pending table @0x0000000881d60000
[   19.231922] CPU199: Booted secondary processor 0x0000010702 [0x431f0af1]
[   19.377744] Detected PIPT I-cache on CPU200
[   19.378147] GICv3: CPU200: found redistributor 10802 region 1:0x0000000441440000
[   19.378179] GICv3: CPU200: using allocated LPI pending table @0x0000000881d70000
[   19.378257] CPU200: Booted secondary processor 0x0000010802 [0x431f0af1]
[   19.524970] Detected PIPT I-cache on CPU201
[   19.525377] GICv3: CPU201: found redistributor 10902 region 1:0x00000004414c0000
[   19.525410] GICv3: CPU201: using allocated LPI pending table @0x0000000881d80000
[   19.525488] CPU201: Booted secondary processor 0x0000010902 [0x431f0af1]
[   19.671391] Detected PIPT I-cache on CPU202
[   19.671806] GICv3: CPU202: found redistributor 10a02 region 1:0x0000000441540000
[   19.671839] GICv3: CPU202: using allocated LPI pending table @0x0000000881d90000
[   19.671918] CPU202: Booted secondary processor 0x0000010a02 [0x431f0af1]
[   19.817941] Detected PIPT I-cache on CPU203
[   19.818355] GICv3: CPU203: found redistributor 10b02 region 1:0x00000004415c0000
[   19.818388] GICv3: CPU203: using allocated LPI pending table @0x0000000881da0000
[   19.818466] CPU203: Booted secondary processor 0x0000010b02 [0x431f0af1]
[   19.964475] Detected PIPT I-cache on CPU204
[   19.964890] GICv3: CPU204: found redistributor 10c02 region 1:0x0000000441640000
[   19.964923] GICv3: CPU204: using allocated LPI pending table @0x0000000881db0000
[   19.965001] CPU204: Booted secondary processor 0x0000010c02 [0x431f0af1]
[   20.111020] Detected PIPT I-cache on CPU205
[   20.111445] GICv3: CPU205: found redistributor 10d02 region 1:0x00000004416c0000
[   20.111479] GICv3: CPU205: using allocated LPI pending table @0x0000000881dc0000
[   20.111557] CPU205: Booted secondary processor 0x0000010d02 [0x431f0af1]
[   20.257408] Detected PIPT I-cache on CPU206
[   20.257830] GICv3: CPU206: found redistributor 10e02 region 1:0x0000000441740000
[   20.257863] GICv3: CPU206: using allocated LPI pending table @0x0000000881dd0000
[   20.257939] CPU206: Booted secondary processor 0x0000010e02 [0x431f0af1]
[   20.403764] Detected PIPT I-cache on CPU207
[   20.404190] GICv3: CPU207: found redistributor 10f02 region 1:0x00000004417c0000
[   20.404223] GICv3: CPU207: using allocated LPI pending table @0x0000000881de0000
[   20.404299] CPU207: Booted secondary processor 0x0000010f02 [0x431f0af1]
[   20.551377] Detected PIPT I-cache on CPU208
[   20.551813] GICv3: CPU208: found redistributor 11002 region 1:0x0000000441840000
[   20.551848] GICv3: CPU208: using allocated LPI pending table @0x0000000881df0000
[   20.551927] CPU208: Booted secondary processor 0x0000011002 [0x431f0af1]
[   20.698238] Detected PIPT I-cache on CPU209
[   20.698671] GICv3: CPU209: found redistributor 11102 region 1:0x00000004418c0000
[   20.698705] GICv3: CPU209: using allocated LPI pending table @0x0000000881e00000
[   20.698782] CPU209: Booted secondary processor 0x0000011102 [0x431f0af1]
[   20.844808] Detected PIPT I-cache on CPU210
[   20.845244] GICv3: CPU210: found redistributor 11202 region 1:0x0000000441940000
[   20.845278] GICv3: CPU210: using allocated LPI pending table @0x0000000881e10000
[   20.845355] CPU210: Booted secondary processor 0x0000011202 [0x431f0af1]
[   20.991229] Detected PIPT I-cache on CPU211
[   20.991670] GICv3: CPU211: found redistributor 11302 region 1:0x00000004419c0000
[   20.991704] GICv3: CPU211: using allocated LPI pending table @0x0000000881e20000
[   20.991786] CPU211: Booted secondary processor 0x0000011302 [0x431f0af1]
[   21.137883] Detected PIPT I-cache on CPU212
[   21.138326] GICv3: CPU212: found redistributor 11402 region 1:0x0000000441a40000
[   21.138360] GICv3: CPU212: using allocated LPI pending table @0x0000000881e30000
[   21.138439] CPU212: Booted secondary processor 0x0000011402 [0x431f0af1]
[   21.284449] Detected PIPT I-cache on CPU213
[   21.284902] GICv3: CPU213: found redistributor 11502 region 1:0x0000000441ac0000
[   21.284938] GICv3: CPU213: using allocated LPI pending table @0x0000000881e40000
[   21.285017] CPU213: Booted secondary processor 0x0000011502 [0x431f0af1]
[   21.430999] Detected PIPT I-cache on CPU214
[   21.431449] GICv3: CPU214: found redistributor 11602 region 1:0x0000000441b40000
[   21.431483] GICv3: CPU214: using allocated LPI pending table @0x0000000881e50000
[   21.431561] CPU214: Booted secondary processor 0x0000011602 [0x431f0af1]
[   21.577618] Detected PIPT I-cache on CPU215
[   21.578069] GICv3: CPU215: found redistributor 11702 region 1:0x0000000441bc0000
[   21.578103] GICv3: CPU215: using allocated LPI pending table @0x0000000881e60000
[   21.578181] CPU215: Booted secondary processor 0x0000011702 [0x431f0af1]
[   21.724703] Detected PIPT I-cache on CPU216
[   21.725159] GICv3: CPU216: found redistributor 11802 region 1:0x0000000441c40000
[   21.725193] GICv3: CPU216: using allocated LPI pending table @0x0000000881e70000
[   21.725270] CPU216: Booted secondary processor 0x0000011802 [0x431f0af1]
[   21.871234] Detected PIPT I-cache on CPU217
[   21.871693] GICv3: CPU217: found redistributor 11902 region 1:0x0000000441cc0000
[   21.871727] GICv3: CPU217: using allocated LPI pending table @0x0000000881e80000
[   21.871804] CPU217: Booted secondary processor 0x0000011902 [0x431f0af1]
[   22.017912] Detected PIPT I-cache on CPU218
[   22.018374] GICv3: CPU218: found redistributor 11a02 region 1:0x0000000441d40000
[   22.018409] GICv3: CPU218: using allocated LPI pending table @0x0000000881e90000
[   22.018488] CPU218: Booted secondary processor 0x0000011a02 [0x431f0af1]
[   22.164480] Detected PIPT I-cache on CPU219
[   22.164946] GICv3: CPU219: found redistributor 11b02 region 1:0x0000000441dc0000
[   22.164982] GICv3: CPU219: using allocated LPI pending table @0x0000000881ea0000
[   22.165060] CPU219: Booted secondary processor 0x0000011b02 [0x431f0af1]
[   22.311396] Detected PIPT I-cache on CPU220
[   22.311871] GICv3: CPU220: found redistributor 11c02 region 1:0x0000000441e40000
[   22.311907] GICv3: CPU220: using allocated LPI pending table @0x0000000881eb0000
[   22.311985] CPU220: Booted secondary processor 0x0000011c02 [0x431f0af1]
[   22.457969] Detected PIPT I-cache on CPU221
[   22.458442] GICv3: CPU221: found redistributor 11d02 region 1:0x0000000441ec0000
[   22.458477] GICv3: CPU221: using allocated LPI pending table @0x0000000881ec0000
[   22.458554] CPU221: Booted secondary processor 0x0000011d02 [0x431f0af1]
[   22.604667] Detected PIPT I-cache on CPU222
[   22.605147] GICv3: CPU222: found redistributor 11e02 region 1:0x0000000441f40000
[   22.605183] GICv3: CPU222: using allocated LPI pending table @0x0000000881ed0000
[   22.605260] CPU222: Booted secondary processor 0x0000011e02 [0x431f0af1]
[   22.751637] Detected PIPT I-cache on CPU223
[   22.752117] GICv3: CPU223: found redistributor 11f02 region 1:0x0000000441fc0000
[   22.752152] GICv3: CPU223: using allocated LPI pending table @0x0000000881ee0000
[   22.752229] CPU223: Booted secondary processor 0x0000011f02 [0x431f0af1]
[   22.898668] Detected PIPT I-cache on CPU224
[   22.899089] GICv3: CPU224: found redistributor 10003 region 1:0x0000000441060000
[   22.899125] GICv3: CPU224: using allocated LPI pending table @0x0000000881ef0000
[   22.899202] CPU224: Booted secondary processor 0x0000010003 [0x431f0af1]
[   23.045323] Detected PIPT I-cache on CPU225
[   23.045747] GICv3: CPU225: found redistributor 10103 region 1:0x00000004410e0000
[   23.045783] GICv3: CPU225: using allocated LPI pending table @0x0000000881f00000
[   23.045860] CPU225: Booted secondary processor 0x0000010103 [0x431f0af1]
[   23.192057] Detected PIPT I-cache on CPU226
[   23.192484] GICv3: CPU226: found redistributor 10203 region 1:0x0000000441160000
[   23.192520] GICv3: CPU226: using allocated LPI pending table @0x0000000881f10000
[   23.192598] CPU226: Booted secondary processor 0x0000010203 [0x431f0af1]
[   23.338700] Detected PIPT I-cache on CPU227
[   23.339131] GICv3: CPU227: found redistributor 10303 region 1:0x00000004411e0000
[   23.339167] GICv3: CPU227: using allocated LPI pending table @0x0000000881f20000
[   23.339244] CPU227: Booted secondary processor 0x0000010303 [0x431f0af1]
[   23.485273] Detected PIPT I-cache on CPU228
[   23.485706] GICv3: CPU228: found redistributor 10403 region 1:0x0000000441260000
[   23.485742] GICv3: CPU228: using allocated LPI pending table @0x0000000881f30000
[   23.485821] CPU228: Booted secondary processor 0x0000010403 [0x431f0af1]
[   23.632470] Detected PIPT I-cache on CPU229
[   23.632907] GICv3: CPU229: found redistributor 10503 region 1:0x00000004412e0000
[   23.632943] GICv3: CPU229: using allocated LPI pending table @0x0000000881f40000
[   23.633020] CPU229: Booted secondary processor 0x0000010503 [0x431f0af1]
[   23.778935] Detected PIPT I-cache on CPU230
[   23.779374] GICv3: CPU230: found redistributor 10603 region 1:0x0000000441360000
[   23.779410] GICv3: CPU230: using allocated LPI pending table @0x0000000881f50000
[   23.779488] CPU230: Booted secondary processor 0x0000010603 [0x431f0af1]
[   23.925453] Detected PIPT I-cache on CPU231
[   23.925897] GICv3: CPU231: found redistributor 10703 region 1:0x00000004413e0000
[   23.925934] GICv3: CPU231: using allocated LPI pending table @0x0000000881f60000
[   23.926010] CPU231: Booted secondary processor 0x0000010703 [0x431f0af1]
[   24.072017] Detected PIPT I-cache on CPU232
[   24.072465] GICv3: CPU232: found redistributor 10803 region 1:0x0000000441460000
[   24.072501] GICv3: CPU232: using allocated LPI pending table @0x0000000881f70000
[   24.072578] CPU232: Booted secondary processor 0x0000010803 [0x431f0af1]
[   24.218687] Detected PIPT I-cache on CPU233
[   24.219138] GICv3: CPU233: found redistributor 10903 region 1:0x00000004414e0000
[   24.219174] GICv3: CPU233: using allocated LPI pending table @0x0000000881f80000
[   24.219250] CPU233: Booted secondary processor 0x0000010903 [0x431f0af1]
[   24.365843] Detected PIPT I-cache on CPU234
[   24.366297] GICv3: CPU234: found redistributor 10a03 region 1:0x0000000441560000
[   24.366334] GICv3: CPU234: using allocated LPI pending table @0x0000000881f90000
[   24.366412] CPU234: Booted secondary processor 0x0000010a03 [0x431f0af1]
[   24.512593] Detected PIPT I-cache on CPU235
[   24.513050] GICv3: CPU235: found redistributor 10b03 region 1:0x00000004415e0000
[   24.513087] GICv3: CPU235: using allocated LPI pending table @0x0000000881fa0000
[   24.513164] CPU235: Booted secondary processor 0x0000010b03 [0x431f0af1]
[   24.659542] Detected PIPT I-cache on CPU236
[   24.660002] GICv3: CPU236: found redistributor 10c03 region 1:0x0000000441660000
[   24.660039] GICv3: CPU236: using allocated LPI pending table @0x0000000881fb0000
[   24.660117] CPU236: Booted secondary processor 0x0000010c03 [0x431f0af1]
[   24.806458] Detected PIPT I-cache on CPU237
[   24.806929] GICv3: CPU237: found redistributor 10d03 region 1:0x00000004416e0000
[   24.806967] GICv3: CPU237: using allocated LPI pending table @0x0000000881fc0000
[   24.807045] CPU237: Booted secondary processor 0x0000010d03 [0x431f0af1]
[   24.953028] Detected PIPT I-cache on CPU238
[   24.953495] GICv3: CPU238: found redistributor 10e03 region 1:0x0000000441760000
[   24.953532] GICv3: CPU238: using allocated LPI pending table @0x0000000881fd0000
[   24.953607] CPU238: Booted secondary processor 0x0000010e03 [0x431f0af1]
[   25.099686] Detected PIPT I-cache on CPU239
[   25.100155] GICv3: CPU239: found redistributor 10f03 region 1:0x00000004417e0000
[   25.100192] GICv3: CPU239: using allocated LPI pending table @0x0000000881fe0000
[   25.100271] CPU239: Booted secondary processor 0x0000010f03 [0x431f0af1]
[   25.246659] Detected PIPT I-cache on CPU240
[   25.247133] GICv3: CPU240: found redistributor 11003 region 1:0x0000000441860000
[   25.247171] GICv3: CPU240: using allocated LPI pending table @0x0000000881ff0000
[   25.247249] CPU240: Booted secondary processor 0x0000011003 [0x431f0af1]
[   25.393384] Detected PIPT I-cache on CPU241
[   25.393861] GICv3: CPU241: found redistributor 11103 region 1:0x00000004418e0000
[   25.393905] GICv3: CPU241: using allocated LPI pending table @0x0000000882000000
[   25.393982] CPU241: Booted secondary processor 0x0000011103 [0x431f0af1]
[   25.540201] Detected PIPT I-cache on CPU242
[   25.540681] GICv3: CPU242: found redistributor 11203 region 1:0x0000000441960000
[   25.540718] GICv3: CPU242: using allocated LPI pending table @0x0000000882010000
[   25.540796] CPU242: Booted secondary processor 0x0000011203 [0x431f0af1]
[   25.687330] Detected PIPT I-cache on CPU243
[   25.687814] GICv3: CPU243: found redistributor 11303 region 1:0x00000004419e0000
[   25.687852] GICv3: CPU243: using allocated LPI pending table @0x0000000882020000
[   25.687929] CPU243: Booted secondary processor 0x0000011303 [0x431f0af1]
[   25.834199] Detected PIPT I-cache on CPU244
[   25.834686] GICv3: CPU244: found redistributor 11403 region 1:0x0000000441a60000
[   25.834724] GICv3: CPU244: using allocated LPI pending table @0x0000000882030000
[   25.834801] CPU244: Booted secondary processor 0x0000011403 [0x431f0af1]
[   25.981017] Detected PIPT I-cache on CPU245
[   25.981507] GICv3: CPU245: found redistributor 11503 region 1:0x0000000441ae0000
[   25.981545] GICv3: CPU245: using allocated LPI pending table @0x0000000882040000
[   25.981622] CPU245: Booted secondary processor 0x0000011503 [0x431f0af1]
[   26.127684] Detected PIPT I-cache on CPU246
[   26.128177] GICv3: CPU246: found redistributor 11603 region 1:0x0000000441b60000
[   26.128215] GICv3: CPU246: using allocated LPI pending table @0x0000000882050000
[   26.128292] CPU246: Booted secondary processor 0x0000011603 [0x431f0af1]
[   26.274362] Detected PIPT I-cache on CPU247
[   26.274858] GICv3: CPU247: found redistributor 11703 region 1:0x0000000441be0000
[   26.274896] GICv3: CPU247: using allocated LPI pending table @0x0000000882060000
[   26.274973] CPU247: Booted secondary processor 0x0000011703 [0x431f0af1]
[   26.421858] Detected PIPT I-cache on CPU248
[   26.422359] GICv3: CPU248: found redistributor 11803 region 1:0x0000000441c60000
[   26.422397] GICv3: CPU248: using allocated LPI pending table @0x0000000882070000
[   26.422475] CPU248: Booted secondary processor 0x0000011803 [0x431f0af1]
[   26.569258] Detected PIPT I-cache on CPU249
[   26.569762] GICv3: CPU249: found redistributor 11903 region 1:0x0000000441ce0000
[   26.569800] GICv3: CPU249: using allocated LPI pending table @0x0000000882080000
[   26.569877] CPU249: Booted secondary processor 0x0000011903 [0x431f0af1]
[   26.716814] Detected PIPT I-cache on CPU250
[   26.717320] GICv3: CPU250: found redistributor 11a03 region 1:0x0000000441d60000
[   26.717359] GICv3: CPU250: using allocated LPI pending table @0x0000000882090000
[   26.717439] CPU250: Booted secondary processor 0x0000011a03 [0x431f0af1]
[   26.863599] Detected PIPT I-cache on CPU251
[   26.864110] GICv3: CPU251: found redistributor 11b03 region 1:0x0000000441de0000
[   26.864149] GICv3: CPU251: using allocated LPI pending table @0x00000008820a0000
[   26.864225] CPU251: Booted secondary processor 0x0000011b03 [0x431f0af1]
[   27.011044] Detected PIPT I-cache on CPU252
[   27.011558] GICv3: CPU252: found redistributor 11c03 region 1:0x0000000441e60000
[   27.011596] GICv3: CPU252: using allocated LPI pending table @0x00000008820b0000
[   27.011673] CPU252: Booted secondary processor 0x0000011c03 [0x431f0af1]
[   27.157912] Detected PIPT I-cache on CPU253
[   27.158430] GICv3: CPU253: found redistributor 11d03 region 1:0x0000000441ee0000
[   27.158468] GICv3: CPU253: using allocated LPI pending table @0x00000008820c0000
[   27.158552] CPU253: Booted secondary processor 0x0000011d03 [0x431f0af1]
[   27.304662] Detected PIPT I-cache on CPU254
[   27.305181] GICv3: CPU254: found redistributor 11e03 region 1:0x0000000441f60000
[   27.305220] GICv3: CPU254: using allocated LPI pending table @0x00000008820d0000
[   27.305298] CPU254: Booted secondary processor 0x0000011e03 [0x431f0af1]
[   27.451778] Detected PIPT I-cache on CPU255
[   27.452307] GICv3: CPU255: found redistributor 11f03 region 1:0x0000000441fe0000
[   27.452347] GICv3: CPU255: using allocated LPI pending table @0x00000008820e0000
[   27.452424] CPU255: Booted secondary processor 0x0000011f03 [0x431f0af1]
[   27.453682] smp: Brought up 2 nodes, 256 CPUs
[   27.453698] SMP: Total of 256 processors activated.
[   27.453704] CPU: All CPU(s) started at EL2
[   27.453712] CPU features: detected: CRC32 instructions
[   27.453723] CPU features: detected: LSE atomic instructions
[   27.453728] CPU features: detected: Privileged Access Never
[   27.453733] CPU features: detected: PMUv3
[   27.453737] CPU features: detected: RAS Extension Support
[   27.489577] alternatives: applying system-wide alternatives
[   27.554168] Memory: 60735892K/67040320K available (31424K kernel code, 5902K rwdata, 10820K rodata, 13888K init, 10272K bss, 5928180K reserved, 65536K cma-reserved)
[   27.555953] devtmpfs: initialized
[   27.626241] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 1911260446275000 ns
[   27.626861] posixtimers hash table entries: 131072 (order: 9, 2097152 bytes, vmalloc hugepage)
[   27.632368] futex hash table entries: 32768 (2097152 bytes on 2 NUMA nodes, total 4096 KiB, linear).
[   27.635234] 14624 pages in range for non-PLT usage
[   27.635241] 506144 pages in range for PLT usage
[   27.638205] pinctrl core: initialized pinctrl subsystem
[   27.640496] SMBIOS 3.1.1 present.
[   27.640530] DMI: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[   27.640655] DMI: Memory slots populated: 4/4
[   27.660729] NET: Registered PF_NETLINK/PF_ROUTE protocol family
[   27.670502] DMA: preallocated 4096 KiB GFP_KERNEL pool for atomic allocations
[   27.671982] DMA: preallocated 4096 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
[   27.673442] DMA: preallocated 4096 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
[   27.674281] audit: initializing netlink subsys (disabled)
[   27.674676] audit: type=2000 audit(25.769:1): state=initialized audit_enabled=0 res=1
[   27.676629] thermal_sys: Registered thermal governor 'fair_share'
[   27.676636] thermal_sys: Registered thermal governor 'step_wise'
[   27.676642] thermal_sys: Registered thermal governor 'user_space'
[   27.676799] cpuidle: using governor menu
[   27.678168] Detected 64 PCC Subspaces
[   27.678176] Registering PCC driver as Mailbox controller
[   27.679496] hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.
[   27.686222] ASID allocator initialised with 65536 entries
[   27.687184] acpiphp: ACPI Hot Plug PCI Controller Driver version: 0.5
[   27.688619] Serial: AMBA PL011 UART driver
[   27.699486] HugeTLB: allocation took 0ms with hugepage_allocation_threads=64
[   27.699497] HugeTLB: allocation took 0ms with hugepage_allocation_threads=64
[   27.699879] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
[   27.699887] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
[   27.699896] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages
[   27.699901] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page
[   27.699909] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages
[   27.699914] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page
[   27.699921] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages
[   27.699926] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page
[   27.716922] raid6: skipped pq benchmark and selected neonx8
[   27.716932] raid6: using neon recovery algorithm
[   27.720184] ACPI: Added _OSI(Module Device)
[   27.720194] ACPI: Added _OSI(Processor Device)
[   27.720200] ACPI: Added _OSI(Processor Aggregator Device)
[   30.559669] ACPI: 5 ACPI AML tables successfully acquired and loaded
[   30.692803] ACPI: Interpreter enabled
[   30.692811] ACPI: Using GIC for interrupt routing
[   30.703743] ACPI: MCFG table detected, 1 entries
[   30.704234] HEST: Table parsing has been initialized.
[   30.705062] GHES: Failed to enable APEI firmware first mode.
[   30.705111] ACPI: IORT: SMMU-v3[402300000] Mapped to Proximity domain 0
[   30.705550] ACPI: IORT: SMMU-v3[402320000] Mapped to Proximity domain 0
[   30.705822] ACPI: IORT: SMMU-v3[402340000] Mapped to Proximity domain 0
[   30.706102] ACPI: IORT: SMMU-v3[442300000] Mapped to Proximity domain 1
[   30.706374] ACPI: IORT: SMMU-v3[442320000] Mapped to Proximity domain 1
[   30.706638] ACPI: IORT: SMMU-v3[442340000] Mapped to Proximity domain 1
[   32.062012] sched: DL replenish lagged too much
[   55.843109] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-7f])
[   55.843160] acpi PNP0A08:00: _OSC: OS supports [ExtendedConfig ASPM ClockPM Segments MSI EDR HPX-Type3]
[   55.844608] acpi PNP0A08:00: _OSC: platform does not support [PME AER LTR DPC]
[   55.847242] acpi PNP0A08:00: _OSC: OS now controls [PCIeHotplug PCIeCapability]
[   55.847576] acpi PNP0A08:00: ECAM area [mem 0x30000000-0x37ffffff] reserved by PNP0C02:00
[   55.851057] acpi PNP0A08:00: ECAM at [mem 0x30000000-0x37ffffff] for [bus 00-7f]
[   55.853708] PCI host bridge to bus 0000:00
[   55.853784] pci_bus 0000:00: root bus resource [mem 0x40000000-0x5fffffff window]
[   55.853803] pci_bus 0000:00: root bus resource [mem 0x10000000000-0x13fffffffff window]
[   55.853822] pci_bus 0000:00: root bus resource [bus 00-7f]
[   55.853901] pci 0000:00:00.0: [177d:af00] type 00 class 0x060000 conventional PCI endpoint
[   55.854438] pci 0000:00:01.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.854467] pci 0000:00:01.0: PCI bridge to [bus 01]
[   55.854559] pci 0000:00:01.0: PME# supported from D0 D3hot D3cold
[   55.855868] pci 0000:00:02.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.855896] pci 0000:00:02.0: PCI bridge to [bus 02]
[   55.855981] pci 0000:00:02.0: PME# supported from D0 D3hot D3cold
[   55.857177] pci 0000:00:03.0: [177d:a   55.857289] pcype 01 class 0x0000:00:04.0: PME00 PCIe Root Porupported from D0 D3hot D3cold
[   55.861051] pci 0000:00:06.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.861076] pci 0000:00:06.0: PCI bridge to [bus 06]
[   55.861170] pci 0000:00:06.0: PME# supported from D0 D3hot D3cold
[   55.862330] pci 0000:00:07.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.862355] pci 0000:00:07.0: PCI bridge to [bus 07]
[   55.862453] pci 0000:00:07.0: PME# supported from D0 D3hot D3cold
[   55.863651] pci 0000:00:08.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.863677] pci 0000:00:08.0: PCI bridge to [bus 08]
[   55.863762] pci 0000:00:08.0: PME# supported from D0 D3hot D3cold
[   55.864919] pci 0000:00:09.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.864945] pci 0000:00:09.0: PCI bridge to [bus 09]
[   55.865029] pci 0000:00:09.0: PME# supported from D0 D3hot D3cold
[   55.866231] pci 0000:00:0a.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.866257] pci 0000:00:0a.0: PCI bridge to [bus 0a]
[   55.866341] pci 0000:00:0a.0: PME# supported from D0 D3hot D3cold
[   55.867505] pci 0000:00:0b.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.867532] pci 0000:00:0b.0: PCI bridge to [bus 0b-0c]
[   55.867550] pci 0000:00:0b.0:   bridge window [mem 0x10000000000-0x10004ffffff 64bit pref]
[   55.867630] pci 0000:00:0b.0: PME# supported from D0 D3hot D3cold
[   55.868799] pci 0000:00:0c.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.868825] pci 0000:00:0c.0: PCI bridge to [bus 0d]
[   55.868907] pci 0000:00:0c.0: PME# supported from D0 D3hot D3cold
[   55.870062] pci 0000:00:0d.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.870088] pci 0000:00:0d.0: PCI bridge to [bus 0e]
[   55.870170] pci 0000:00:0d.0: PME# supported from D0 D3hot D3cold
[   55.871346] pci 0000:00:0e.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   55.871373] pci 0000:00:0e.0: PCI bridge to [bus 0f-10]
[   55.871387] pci 0000:00:0e.0:   bridge window [mem 0x40000000-0x420fffff]
[   55.871482] pci 0000:00:0e.0: PME# supported from D0 D3hot D3cold
[   55.872630] pci 0000:00:0f.0: [14e4:9026] type 00 class 0x0c0330 conventional PCI endpoint
[   55.872664] pci 0000:00:0f.0: BAR 0 [mem 0x10005050000-0x1000505ffff 64bit pref]
[   55.872680] pci 0000:00:0f.0: BAR 2 [mem 0x10005040000-0x1000504ffff 64bit pref]
[   55.873080] pci 0000:00:0f.1: [14e4:9026] type 00 class 0x0c0330 conventional PCI endpoint
[   55.873112] pci 0000:00:0f.1: BAR 0 [mem 0x10005030000-0x1000503ffff 64bit pref]
[   55.873127] pci 0000:00:0f.1: BAR 2 [mem 0x10005020000-0x1000502ffff 64bit pref]
[   55.873544] pci 0000:00:10.0: [14e4:9027] type 00 class 0x010601 conventional PCI endpoint
[   55.873579] pci 0000:00:10.0: BAR 2 [mem 0x10005010000-0x1000501ffff 64bit pref]
[   55.873593] pci 0000:00:10.0: BAR 5 [mem 0x42110000-0x4211ffff]
[   55.873977] pci 0000:00:10.1: [14e4:9027] type 00 class 0x010601 conventional PCI endpoint
[   55.874011] pci 0000:00:10.1: BAR 2 [mem 0x10005000000-0x1000500ffff 64bit pref]
[   55.874027] pci 0000:00:10.1: BAR 5 [mem 0x42100000-0x4210ffff]
[   55.876400] pci 0000:0b:00.0: [15b3:1015] type 00 class 0x020000 PCIe Endpoint
[   55.876750] pci 0000:0b:00.0: BAR 0 [mem 0x10002000000-0x10003ffffff 64bit pref]
[   55.876802] pci 0000:0b:00.0: ROM [mem 0xfff00000-0xffffffff pref]
[   55.877632] pci 0000:0b:00.0: PME# supported from D3cold
[   55.878133] pci 0000:0b:00.0: VF BAR 0 [mem 0x10004800000-0x100048fffff 64bit pref]
[   55.878148] pci 0000:0b:00.0: VF BAR 0 [mem 0x10004800000-0x10004ffffff 64bit pref]: contains BAR 0 for 8 VFs
[   55.879883] pci 0000:0b:00.1: [15b3:1015] type 00 class 0x020000 PCIe Endpoint
[   55.880221] pci 0000:0b:00.1: BAR 0 [mem 0x10000000000-0x10001ffffff 64bit pref]
[   55.880271] pci 0000:0b:00.1: ROM [mem 0xfff00000-0xffffffff pref]
[   55.881040] pci 0000:0b:00.1: PME# supported from D3cold
[   55.881502] pci 0000:0b:00.1: VF BAR 0 [mem 0x10004000000-0x100040fffff 64bit pref]
[   55.881516] pci 0000:0b:00.1: VF BAR 0 [mem 0x10004000000-0x100047fffff 64bit pref]: cPCI-X bridge
[ dow [mem 0x40000f:00.0: supportspci_bus 0000:10: 030000 conventio] pci 0000:10:00.0: BAR 1 [mem 0x42000000-0x4201ffff]
[   55.884690] pci 0000:10:00.0: BAR 2 [io  0x0000-0x007f]
[   55.884827] pci 0000:10:00.0: supports D1 D2
[   55.884837] pci 0000:10:00.0: PME# supported from D0 D1 D2 D3hot D3cold
[   55.885403] pci 0000:00:0b.0: bridge window [mem 0x02000000-0x05ffffff 64bit pref] to [bus 0b-0c] add_size 2000000 add_align 2000000
[   55.885433] pci 0000:00:0b.0: bridge window [mem 0x00100000-0x000fffff] to [bus 0b-0c] add_size 200000 add_align 100000
[   55.885549] pci 0000:00:0b.0: bridge window [mem 0x10000000000-0x10005ffffff 64bit pref]: assigned
[   55.885566] pci 0000:00:0e.0: bridge window [mem 0x40000000-0x42ffffff]: assigned
[   55.885580] pci 0000:00:0b.0: bridge window [mem 0x43000000-0x431fffff]: assigned
[   55.885594] pci 0000:00:0f.0: BAR 0 [mem 0x10006000000-0x1000600ffff 64bit pref]: assigned
[   55.885615] pci 0000:00:0f.0: BAR 2 [mem 0x10006010000-0x1000601ffff 64bit pref]: assigned
[   55.885651] pci 0000:00:0f.1: BAR 0 [mem 0x10006020000-0x1000602ffff 64bit pref]: assigned
[   55.885672] pci 0000:00:0f.1: BAR 2 [mem 0x10006030000-0x1000603ffff 64bit pref]: assigned
[   55.885690] pci 0000:00:10.0: BAR 2 [mem 0x10006040000-0x1000604ffff 64bit pref]: assigned
[   55.885708] pci 0000:00:10.0: BAR 5 [mem 0x43200000-0x4320ffff]: assigned
[   55.885724] pci 0000:00:10.1: BAR 2 [mem 0x10006050000-0x1000605ffff 64bit pref]: assigned
[   55.885741] pci 0000:00:10.1: BAR 5 [mem 0x43210000-0x4321ffff]: assigned
[   55.885810] pci 0000:00:01.0: PCI bridge to [bus 01]
[   55.885826] pci 0000:00:02.0: PCI bridge to [bus 02]
[   55.885840] pci 0000:00:03.0: PCI bridge to [bus 03]
[   55.885854] pci 0000:00:04.0: PCI bridge to [bus 04]
[   55.885867] pci 0000:00:05.0: PCI bridge to [bus 05]
[   55.885881] pci 0000:00:06.0: PCI bridge to [bus 06]
[   55.885894] pci 0000:00:07.0: PCI bridge to [bus 07]
[   55.885908] pci 0000:00:08.0: PCI bridge to [bus 08]
[   55.885922] pci 0000:00:09.0: PCI bridge to [bus 09]
[   55.885935] pci 0000:00:0a.0: PCI bridge to [bus 0a]
[   55.885986] pci 0000:0b:00.0: BAR 0 [mem 0x10000000000-0x10001ffffff 64bit pref]: assigned
[   55.886067] pci 0000:0b:00.1: BAR 0 [mem 0x10002000000-0x10003ffffff 64bit pref]: assigned
[   55.886146] pci 0000:0b:00.0: ROM [mem 0x43000000-0x430fffff pref]: assigned
[   55.886160] pci 0000:0b:00.0: VF BAR 0 [mem 0x10004000000-0x100047fffff 64bit pref]: assigned
[   55.886209] pci 0000:0b:00.1: ROM [mem 0x43100000-0x431fffff pref]: assigned
[   55.886222] pci 0000:0b:00.1: VF BAR 0 [mem 0x10004800000-0x10004ffffff 64bit pref]: assigned
[   55.886306] pci 0000:00:0b.0: PCI bridge to [bus 0b-0c]
[   55.886319] pci 0000:00:0b.0:   bridge window [mem 0x43000000-0x431fffff]
[   55.886332] pci 0000:00:0b.0:   bridge window [mem 0x10000000000-0x10005ffffff 64bit pref]
[   55.886347] pci 0000:00:0c.0: PCI bridge to [bus 0d]
[   55.886362] pci 0000:00:0d.0: PCI bridge to [bus 0e]
[   55.886384] pci 0000:0f:00.0: bridge window [mem 0x40000000-0x42ffffff]: assigned
[   55.886396] pci 0000:0f:00.0: bridge window [io  size 0x1000]: can't assign; no space
[   55.886408] pci 0000:0f:00.0: bridge window [io  size 0x1000]: failed to assign
[   55.886429] pci 0000:0f:00.0: bridge window [io  size 0x1000]: can't assign; no space
[   55.886440] pci 0000:0f:00.0: bridge window [io  size 0x1000]: failed to assign
[   55.886467] pci 0000:10:00.0: BAR 0 [mem 0x40000000-0x41ffffff]: assigned
[   55.886483] pci 0000:10:00.0: BAR 1 [mem 0x42000000-0x4201ffff]: assigned
[   55.886498] pci 0000:10:00.0: BAR 2 [io  size 0x0080]: can't assign; no space
[   55.886508] pci 0000:10:00.0: BAR 2 [io  size 0x0080]: failed to assign
[   55.886531] pci 0000:10:00.0: BAR 2 [io  size 0x0080]: can't assign; no space
[   55.886542] pci 0000:10:00.0: BAR 2 [io  size 0x0080]: failed to assign
[   55.886559] pci 0000:0f:00.0: PCI bridge to [bus 10]
[   55.886572] pci 0000:0f:00.0:   bridge window [mem 0x40000000-0x42ffffff]
[   55.886590] pci 0000:00:0e.0: PCI bridge to [bus 0f-10]
[   55.886602] pci 0000:00:0e.0:   bridge window [mem 0x40000000-0x42ffffff]
[   55.886618] pci_bus 0000:00: Some PCI device resources are unassigned, try booting with pci=realloc
[   55.886632] pci_bus 0000:00: resource 4 [mem 0x40000000-0x5fffffff window]
[   55.886663] pci_bus 0000:00: resource 5 [mem 0x10000000000-0x13fffffffff window]
[   55.886678] pci_bus 0000:0b: resource 1 [mem 0x43000000-0x431fffff]
[   55.886689] pci_bus 0000:0b: resource 2 [mem 0x10000000000-0x10005ffffff 64bit pref]
[   55.886702] pci_bus 0000:0f: resource 1 [mem 0x40000000-0x42ffffff]
[   55.886713] pci_bus 0000:10: resource 1 [mem 0x40000000-0x42ffffff]
[   55.900705] ACPI: CPU0 has been hot-added
[   55.942318] ACPI: CPU32 has been hot-added
[   55.983951] ACPI: CPU64 has been hot-added
[   56.025523] ACPI: CPU96 has been hot-added
[   56.075671] ACPI: CPU1 has been hot-added
[   56.118015] ACPI: CPU33 has been hot-added
[   56.160219] ACPI: CPU65 has been hot-added
[   56.202400] ACPI: CPU97 has been hot-added
[   56.252625] ACPI: CPU2 has been hot-added
[   56.295664] ACPI: CPU34 has been hot-added
[   56.338743] ACPI: CPU66 has been hot-added
[   56.381876] ACPI: CPU98 has been hot-added
[   56.433047] ACPI: CPU3 has been hot-added
[   56.476910] ACPI: CPU35 has been hot-added
[   56.520877] ACPI: CPU67 has been hot-added
[   56.564710] ACPI: CPU99 has been hot-added
[   56.616702] ACPI: CPU4 has been hot-added
[   56.661476] ACPI: CPU36 has been hot-added
[   56.706399] ACPI: CPU68 has been hot-added
[   56.751112] ACPI: CPU100 has been hot-added
[   56.803923] ACPI: CPU5 has been hot-added
[   56.849601] ACPI: CPU37 has been hot-added
[   56.895159] ACPI: CPU69 has been hot-added
[   56.940685] ACPI: CPU101 has been hot-added
[   56.994448] ACPI: CPU6 has been hot-added
[   57.040838] ACPI: CPU38 has been hot-added
[   57.087214] ACPI: CPU70 has been hot-added
[   57.133595] ACPI: CPU102 has been hot-added
[   57.188294] ACPI: CPU7 has been hot-added
[   57.235463] ACPI: CPU39 has been hot-added
[   57.282704] ACPI: CPU71 has been hot-added
[   57.329934] ACPI: CPU103 has been hot-added
[   57.385259] ACPI: CPU8 has been hot-added
[   57.433314] ACPI: CPU40 has been hot-added
[   57.481372] ACPI: CPU72 has been hot-added
[   57.529467] ACPI: CPU104 has been hot-added
[   57.585801] ACPI: CPU9 has been hot-added
[   57.634737] ACPI: CPU41 has been hot-added
[   57.683615] ACPI: CPU73 has been hot-added
[   57.732467] ACPI: CPU105 has been hot-added
[   57.789770] ACPI: CPU10 has been hot-added
[   57.839493] ACPI: CPU42 has been hot-added
[   57.889272] ACPI: CPU74 has been hot-added
[   57.939010] ACPI: CPU106 has been hot-added
[   57.997032] ACPI: CPU11 has been hot-added
[   58.047592] ACPI: CPU43 has been hot-added
[   58.099159] ACPI: CPU75 has been hot-added
[   58.150519] ACPI: CPU107 has been hot-added
[   58.209431] ACPI: CPU12 has been hot-added
[   58.260856] ACPI: CPU44 has been hot-added
[   58.312298] ACPI: CPU76 has been hot-added
[   58.363676] ACPI: CPU108 has been hot-added
[   58.423483] ACPI: CPU13 has been hot-added
[   58.475776] ACPI: CPU45 has been hot-added
[   58.527980] ACPI: CPU77 has been hot-added
[   58.580235] ACPI: CPU109 has been hot-added
[   58.640737] ACPI: CPU14 has been hot-added
[   58.693799] ACPI: CPU46 has been hot-added
[   58.746938] ACPI: CPU78 has been hot-added
[   58.800063] ACPI: CPU110 has been hot-added
[   58.861364] ACPI: CPU15 has been hot-added
[   58.915935] ACPI: CPU47 has been hot-added
[   58.969855] ACPI: CPU79 has been hot-added
[   59.023816] ACPI: CPU111 has been hot-added
[   59.085913] ACPI: CPU16 has been hot-added
[   59.140807] ACPI: CPU48 has been hot-added
[   59.195668] ACPI: CPU80 has been hot-added
[   59.250413] ACPI: CPU112 has been hot-added
[   59.313413] ACPI: CPU17 has been hot-added
[   59.369117] ACPI: CPU49 has been hot-added
[   59.424731] ACPI: CPU81 has been hot-added
[   59.480261] ACPI: CPU113 has been hot-added
[   59.544061] ACPI: CPU18 has been hot-added
[   59.600644] ACPI: CPU50 has been hot-added
[   59.657050] ACPI: CPU82 has been hot-added
[   59.713555] ACPI: CPU114 has been hot-added
[   59.778219] ACPI: CPU19 has been hot-added
[   59.835509] ACPI: CPU51 has been hot-added
[   59.892799] ACPI: CPU83 has been hot-added
[   59.950164] ACPI: CPU115 has been hot-added
[   60.015535] ACPI: CPU20 has been hot-added
[   60.073697] ACPI: CPU52 has been hot-added
[   60.131968] ACPI: CPU84 has been hot-added
[   60.190072] ACPI: CPU116 has been hot-added
[   60.256291] ACPI: CPU21 has been hot-added
[   60.315378] ACPI: CPU53 has been hot-added
[   60.374304] ACPI: CPU85 has been hot-added
[   60.433305] ACPI: CPU117 has been hot-added
[   60.500373] ACPI: CPU22 has been hot-added
[   60.560171] ACPI: CPU54 has been hot-added
[   60.619961] ACPI: CPU86 has been hot-added
[   60.680005] ACPI: CPU118 has been hot-added
[   60.747924] ACPI: CPU23 has been hot-added
[   60.808600] ACPI: CPU55 has been hot-added
[   60.869327] ACPI: CPU87 has been hot-added
[   60.930002] ACPI: CPU119 has been hot-added
[   60.998693] ACPI: CPU24 has been hot-added
[   61.060299] ACPI: CPU56 has been hot-added
[   61.121713] ACPI: CPU88 has been hot-added
[   61.183257] ACPI: CPU120 has been hot-added
[   61.252743] ACPI: CPU25 has been hot-added
[   61.315230] ACPI: CPU57 has been hot-added
[   61.377630] ACPI: CPU89 has been hot-added
[   61.440097] ACPI: CPU121 has been hot-added
[   61.510497] ACPI: CPU26 has been hot-added
[   61.573646] ACPI: CPU58 has been hot-added
[   61.636752] ACPI: CPU90 has been hot-added
[   61.700052] ACPI: CPU122 has been hot-added
[   61.771218] ACPI: CPU27 has been hot-added
[   61.835222] ACPI: CPU59 has been hot-added
[   61.899351] ACPI: CPU91 has been hot-added
[   61.963512] ACPI: CPU123 has been hot-added
[   62.035570] ACPI: CPU28 has been hot-added
[   62.100479] ACPI: CPU60 has been hot-added
[   62.165360] ACPI: CPU92 has been hot-added
[   62.230259] ACPI: CPU124 has been hot-added
[   62.303073] ACPI: CPU29 has been hot-added
[   62.368850] ACPI: CPU61 has been hot-added
[   62.434534] ACPI: CPU93 has been hot-added
[   62.500216] ACPI: CPU125 has been hot-added
[   62.573914] ACPI: CPU30 has been hot-added
[   62.640534] ACPI: CPU62 has been hot-added
[   62.707060] ACPI: CPU94 has been hot-added
[   62.773728] ACPI: CPU126 has been hot-added
[   62.848191] ACPI: CPU31 has been hot-added
[   62.915576] ACPI: CPU63 has been hot-added
[   62.982889] ACPI: CPU95 has been hot-added
[   63.050166] ACPI: CPU127 has been hot-added
[   63.167658] ARMH0011:00: ttyAMA0 at MMIO 0x402020000 (irq = 24, base_baud = 0) is a SBSA
[   63.167982] printk: console [ttyAMA0] enabled
[   72.766781] ACPI: PCI Root Bridge [PCI1] (domain 0000 [bus 80-ff])
[   72.766826] acpi PNP0A08:01: _OSC: OS supports [ExtendedConfig ASPM ClockPM Segments MSI EDR HPX-Type3]
[   72.768290] acpi PNP0A08:01: _OSC: platform does not support [PME AER LTR DPC]
[   72.770875] acpi PNP0A08:01: _OSC: OS now controls [PCIeHotplug PCIeCapability]
[   72.771218] acpi PNP0A08:01: ECAM area [mem 0x38000000-0x3fffffff] reserved by PNP0C02:00
[   72.774645] acpi PNP0A08:01: ECAM at [mem 0x38000000-0x3fffffff] for [bus 80-ff]
[   72.777216] PCI host bridge to bus 0000:80
[   72.777286] pci_bus 0000:80: root bus resource [mem 0x60000000-0x7fffffff window]
[   72.777305] pci_bus 0000:80: root bus resource [mem 0x14000000000-0x17fffffffff window]
[   72.777319] pci_bus 0000:80: root bus resource [bus 80-ff]
[   72.777385] pci 0000:80:00.0: [177d:af00] type 00 class 0x060000 conventional PCI endpoint
[   72.777866] pci 0000:80:01.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.777899] pci 0000:80:01.0: PCI bridge to [bus 81]
[   72.777995] pci 0000:80:01.0: PME# supported from D0 D3hot D3cold
[   72.779254] pci 0000:80:02.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.779286] pci 0000:80:02.0: PCI bridge to [bus 82]
[   72.779381] pci 0000:80:02.0: PME# supported from D0 D3hot D3cold
[   72.780568] pci 0000:80:03.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.780599] pci 0000:80:03.0: PCI bridge to [bus 83]
[   72.780693] pci 0000:80:03.0: PME# supported from D0 D3hot D3cold
[   72.781883] pci 0000:80:04.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.781915] pci 0000:80:04.0: PCI bridge to [bus 84]
[   72.782007] pci 0000:80:04.0: PME# supported from D0 D3hot D3cold
[   72.783193] pci 0000:80:05.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.783224] pci 0000:80:05.0: PCI bridge to [bus 85]
[   72.783317] pci 0000:80:05.0: PME# supported from D0 D3hot D3cold
[   72.784495] pci 0000:80:06.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.784526] pci 0000:80:06.0: PCI bridge to [bus 86]
[   72.784618] pci 0000:80:06.0: PME# supported from D0 D3hot D3cold
[   72.785879] pci 0000:80:07.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.785910] pci 0000:80:07.0: PCI bridge to [bus 87]
[   72.786003] pci 0000:80:07.0: PME# supported from D0 D3hot D3cold
[   72.787225] pci 0000:80:08.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.787256] pci 0000:80:08.0: PCI bridge to [bus 88]
[   72.787351] pci 0000:80:08.0: PME# supported from D0 D3hot D3cold
[   72.788520] pci 0000:80:09.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.788551] pci 0000:80:09.0: PCI bridge to [bus 89]
[   72.788644] pci 0000:80:09.0: PME# supported from D0 D3hot D3cold
[   72.789838] pci 0000:80:0a.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.789869] pci 0000:80:0a.0: PCI bridge to [bus 8a]
[   72.789962] pci 0000:80:0a.0: PME# supported from D0 D3hot D3cold
[   72.791122] pci 0000:80:0b.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.791153] pci 0000:80:0b.0: PCI bridge to [bus 8b]
[   72.791266] pci 0000:80:0b.0: PME# supported from D0 D3hot D3cold
[   72.792444] pci 0000:80:0c.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.792475] pci 0000:80:0c.0: PCI bridge to [bus 8c]
[   72.792567] pci 0000:80:0c.0: PME# supported from D0 D3hot D3cold
[   72.793733] pci 0000:80:0d.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.793763] pci 0000:80:0d.0: PCI bridge to [bus 8d]
[   72.793856] pci 0000:80:0d.0: PME# supported from D0 D3hot D3cold
[   72.795035] pci 0000:80:0e.0: [177d:af84] type 01 class 0x060400 PCIe Root Port
[   72.795066] pci 0000:80:0e.0: PCI bridge to [bus 8e]
[   72.795158] pci 0000:80:0e.0: PME# supported from D0 D3hot D3cold
[   72.796365] pci 0000:80:0f.0: [14e4:9026] type 00 class 0x0c0330 conventional PCI endpoint
[   72.796405] pci 0000:80:0f.0: BAR 0 [mem 0x14000050000-0x1400005ffff 64bit pref]
[   72.796422] pci 0000:80:0f.0: BAR 2 [mem 0x14000040000-0x1400004ffff 64bit pref]
[   72.796836] pci 0000:80:0f.1: [14e4:9026] type 00 class 0x0c0330 conventional PCI endpoint
[   72.796875] pci 0000:80:0f.1: BAR 0 [mem 0x14000030000-0x1400003ffff 64bit pref]
[   72.796891] pci 0000:80:0f.1: BAR 2 [mem 0x14000020000-0x1400002ffff 64bit pref]
[   72.797271] pci 0000:80:10.0: [14e4:9027] type 00 class 0x010601 conventional PCI endpoint
[   72.797336] pci 0000:80:10.0: BAR 2 [mem 0x14000010000-0x1400001ffff 64bit pref]
[   72.797352] pci 0000:80:10.0: BAR 5 [mem 0x60010000-0x6001ffff]
[   72.797748] pci 0000:80:10.1: [14e4:9027] type 00 class 0x010601 conventional PCI endpoint
[   72.797789] pci 0000:80:10.1: BAR 2 [mem 0x14000000000-0x1400000ffff 64bit pref]
[   72.797804] pci 0000:80:10.1: BAR 5 [mem 0x60000000-0x6000ffff]
[   72.800686] pci 0000:80:0f.0: BAR 0 [mem 0x14000000000-0x1400000ffff 64bit pref]: assigned
[   72.800711] pci 0000:80:0f.0: BAR 2 [mem 0x14000010000-0x1400001ffff 64bit pref]: assigned
[   72.800732] pci 0000:80:0f.1: BAR 0 [mem 0x14000020000-0x1400002ffff 64bit pref]: assigned
[   72.800753] pci 0000:80:0f.1: BAR 2 [mem 0x14000030000-0x1400003ffff 64bit pref]: assigned
[   72.800774] pci 0000:80:10.0: BAR 2 [mem 0x14000040000-0x1400004ffff 64bit pref]: assigned
[   72.800793] pci 0000:80:10.0: BAR 5 [mem 0x60000000-0x6000ffff]: assigned
[   72.800809] pci 0000:80:10.1: BAR 2 [mem 0x14000050000-0x1400005ffff 64bit pref]: assigned
[   72.800828] pci 0000:80:10.1: BAR 5 [mem 0x60010000-0x6001ffff]: assigned
[   72.800863] pci 0000:80:01.0: PCI bridge to [bus 81]
[   72.800883] pci 0000:80:02.0: PCI bridge to [bus 82]
[   72.800902] pci 0000:80:03.0: PCI bridge to [bus 83]
[   72.800921] pci 0000:80:04.0: PCI bridge to [bus 84]
[   72.800939] pci 0000:80:05.0: PCI bridge to [bus 85]
[   72.800957] pci 0000:80:06.0: PCI bridge to [bus 86]
[   72.800975] pci 0000:80:07.0: PCI bridge to [bus 87]
[   72.800992] pci 0000:80:08.0: PCI bridge to [bus 88]
[   72.801010] pci 0000:80:09.0: PCI bridge to [bus 89]
[   72.801029] pci 0000:80:0a.0: PCI bridge to [bus 8a]
[   72.801047] pci 0000:80:0b.0: PCI bridge to [bus 8b]
[   72.801065] pci 0000:80:0c.0: PCI bridge to [bus 8c]
[   72.801083] pci 0000:80:0d.0: PCI bridge to [bus 8d]
[   72.801100] pci 0000:80:0e.0: PCI bridge to [bus 8e]
[   72.801120] pci_bus 0000:80: resource 4 [mem 0x60000000-0x7fffffff window]
[   72.801133] pci_bus 0000:80: resource 5 [mem 0x14000000000-0x17fffffffff window]
[   72.817819] ACPI: CPU128 has been hot-added
[   72.866838] ACPI: CPU160 has been hot-added
[   72.917008] ACPI: CPU192 has been hot-added
[   72.972119] ACPI: CPU224 has been hot-added
[   73.035737] ACPI: CPU129 has been hot-added
[   73.084516] ACPI: CPU161 has been hot-added
[   73.136758] ACPI: CPU193 has been hot-added
[   73.187135] ACPI: CPU225 has been hot-added
[   73.249717] ACPI: CPU130 has been hot-added
[   73.303107] ACPI: CPU162 has been hot-added
[   73.357425] ACPI: CPU194 has been hot-added
[   73.408569] ACPI: CPU226 has been hot-added
[   73.470119] ACPI: CPU131 has been hot-added
[   73.521441] ACPI: CPU163 has been hot-added
[   73.572862] ACPI: CPU195 has been hot-added
[   73.627360] ACPI: CPU227 has been hot-added
[   73.694514] ACPI: CPU132 has been hot-added
[   73.747551] ACPI: CPU164 has been hot-added
[   73.800530] ACPI: CPU196 has been hot-added
[   73.853730] ACPI: CPU228 has been hot-added
[   73.915338] ACPI: CPU133 has been hot-added
[   73.968863] ACPI: CPU165 has been hot-added
[   74.022381] ACPI: CPU197 has been hot-added
[   74.075934] ACPI: CPU229 has been hot-added
[   74.137751] ACPI: CPU134 has been hot-added
[   74.191261] ACPI: CPU166 has been hot-added
[   74.244881] ACPI: CPU198 has been hot-added
[   74.303920] ACPI: CPU230 has been hot-added
[   74.371262] ACPI: CPU135 has been hot-added
[   74.426316] ACPI: CPU167 has been hot-added
[   74.481504] ACPI: CPU199 has been hot-added
[   74.536582] ACPI: CPU231 has been hot-added
[   74.603960] ACPI: CPU136 has been hot-added
[   74.664452] ACPI: CPU168 has been hot-added
[   74.724163] ACPI: CPU200 has been hot-added
[   74.782421] ACPI: CPU232 has been hot-added
[   74.850582] ACPI: CPU137 has been hot-added
[   74.909214] ACPI: CPU169 has been hot-added
[   74.967713] ACPI: CPU201 has been hot-added
[   75.022859] ACPI: CPU233 has been hot-added
[   75.087522] ACPI: CPU138 has been hot-added
[   75.143483] ACPI: CPU170 has been hot-added
[   75.199352] ACPI: CPU202 has been hot-added
[   75.255342] ACPI: CPU234 has been hot-added
[   75.320722] ACPI: CPU139 has been hot-added
[   75.377445] ACPI: CPU171 has been hot-added
[   75.434195] ACPI: CPU203 has been hot-added
[   75.491048] ACPI: CPU235 has been hot-added
[   75.557309] ACPI: CPU140 has been hot-added
[   75.615122] ACPI: CPU172 has been hot-added
[   75.672901] ACPI: CPU204 has been hot-added
[   75.730505] ACPI: CPU236 has been hot-added
[   75.797697] ACPI: CPU141 has been hot-added
[   75.856087] ACPI: CPU173 has been hot-added
[   75.914584] ACPI: CPU205 has [   75.973096] ACPI: CPU237 has been hot-added
[   76.041037] ACPI: CPU142 has been hot-added
[   76.100291] ACPI: CPU174 has been hot-added
[   76.159536] ACPI: CPU206 has been hot-added
[   76.218956] ACPI: CPU238 has been hot-added
[   76.287675] ACPI: CPU143 has been hot-added
[   76.347763] ACPI: CPU175 has been hot-added
[   76.407836] ACPI: CPU207 has been hot-added
[   76.468066] ACPI: CPU239 has been hot-added
[   76.537693] ACPI: CPU144 has been hot-added
[   76.598579] ACPI: CPU176 has been hot-added
[   76.659527] ACPI: CPU208 has been hot-added
[   76.720623] ACPI: CPU240 has been hot-added
[   76.791003] ACPI: CPU145 has been hot-added
[   76.852784] ACPI: CPU177 has been hot-added
[   76.914536] ACPI: CPU209 has been hot-added
[   76.976665] ACPI: CPU241 has been hot-added
[   77.047824] ACPI: CPU146 has been hot-added
[   77.110423] ACPI: CPU178 has been hot-added
[   77.173041] ACPI: CPU210 has been hot-added
[   77.236048] ACPI: CPU242 has been hot-added
[   77.308124] ACPI: CPU147 has been hot-added
[   77.371551] ACPI: CPU179 has been hot-added
[   77.435123] ACPI: CPU211 has been hot-added
[   77.498837] ACPI: CPU243 has been hot-added
[   77.571705] ACPI: CPU148 has been hot-added
[   77.635953] ACPI: CPU180 has been hot-added
[   77.700279] ACPI: CPU212 has been hot-added
[   77.764721] ACPI: CPU244 has been hot-added
[   77.838455] ACPI: CPU149 has been hot-added
[   77.903730] ACPI: CPU181 has been hot-added
[   77.968903] ACPI: CPU213 has been hot-added
[   78.034081] ACPI: CPU245 has been hot-added
[   78.108603] ACPI: CPU150 has been hot-added
[   78.174629] ACPI: CPU182 has been hot-added
[   78.240718] ACPI: CPU214 has been hot-added
[   78.306782] ACPI: CPU246 has been hot-added
[   78.382183] ACPI: CPU151 has been hot-added
[   78.449151] ACPI: CPU183 has been hot-added
[   78.516076] ACPI: CPU215 has been hot-added
[   78.583019] ACPI: CPU247 has been hot-added
[   78.659240] ACPI: CPU152 has been hot-added
[   78.727183] ACPI: CPU184 has been hot-added
[   78.794964] ACPI: CPU216 has been hot-added
[   78.862636] ACPI: CPU248 has been hot-added
[   78.939794] ACPI: CPU153 has been hot-added
[   79.008542] A[   79.077169] ACPI: CPU217 has been hot-added
[   79.145825] ACPI: CPU249 has been hot-added
[   79.223680] ACPI: CPU154 has been hot-added
[   79.293159] ACPI: CPU186 has been hot-added
[   79.362530] ACPI: CPU218 has been hot-added
[   79.431910] ACPI: CPU250 has been hot-added
[   79.510605] ACPI: CPU155 has been hot-added
[   79.580871] ACPI: CPU187 has been hot-added
[   79.651075] ACPI: CPU219 has been hot-added
[   79.721494] ACPI: CPU251 has been hot-added
[   79.801183] ACPI: CPU156 has been hot-added
[   79.872327] ACPI: CPU188 has been hot-added
[   79.943265] ACPI: CPU220 has been hot-added
[   80.014410] ACPI: CPU252 has been hot-added
[   80.094863] ACPI: CPU157 has been hot-added
[   80.166731] ACPI: CPU189 has been hot-added
[   80.238448] ACPI: CPU221 has been hot-added
[   80.310555] ACPI: CPU253 has been hot-added
[   80.391767] ACPI: CPU158 has been hot-added
[   80.464394] ACPI: CPU190 has been hot-added
[   80.537135] ACPI: CPU222 has been hot-added
[   80.609884] ACPI: CPU254 has been hot-added
[   80.691931] ACPI: CPU159 has been hot-added
[   80.765539] ACPI: CPU191 has been hot-added
[   80.839131] ACPI: CPU223 has been hot-added
[   80.912835] ACPI: CPU255 has been hot-added
[   81.090444] iommu: Default domain type: Translated
[   81.090461] iommu: DMA domain TLB invalidation policy: lazy mode
[   81.126882] SCSI subsystem initialized
[   81.128222] ACPI: bus type USB registered
[   81.128428] usbcore: registered new interface driver usbfs
[   81.128535] usbcore: registered new interface driver hub
[   81.129147] usbcore: registered new device driver usb
[   81.130616] pps_core: LinuxPPS API ver. 1 registered
[   81.130623] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[   81.130673] PTP clock support registered
[   81.133189] EDAC MC: Ver: 3.0.0
[   81.134147] scmi_core: SCMI protocol bus registered
[   81.134498] efivars: Registered efivars operations
[   81.145328] NetLabel: Initializing
[   81.145336] NetLabel:  domain hash size = 128
[   81.145342] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO
[   81.145586] NetLabel:  unlabeled traffic allowed by default
[   81.145630] mctp: management component transport protocol core
[   81.145636] NET: Registered PF_MCTP protocol family
[   81.146504] pci 0000:10:00.0: vgaarb: setting as boot VGA device
[   81.146518] pci 0000:10:00.0: vgaarb: bridge control possible
[   81.146528] pci 0000:10:00.0: vgaarb: VGA device added: decodes=io+mem,owns=none,locks=none
[   81.146559] vgaarb: loaded
[   81.151381] clocksource: Switched to clocksource arch_sys_counter
[   81.164612] VFS: Disk quotas dquot_6.6.0
[   81.165048] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[   81.166878] pnp: PnP ACPI init
[   81.168063] system 00:00: [mem 0x30000000-0x3fffffff] could not be reserved
[   81.821343] pnp: PnP ACPI: found 1 devices
[   81.839782] NET: Registered PF_INET protocol family
[   81.840365] IP idents hash table entries: 262144 (order: 9, 2097152 bytes, vmalloc hugepage)
[   81.863200] tcp_listen_portaddr_hash hash table entries: 32768 (order: 7, 524288 bytes, vmalloc hugepage)
[   81.864130] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, vmalloc hugepage)
[   81.865822] TCP established hash table entries: 524288 (order: 10, 4194304 bytes, vmalloc hugepage)
[   81.870648] TCP bind hash table entries: 65536 (order: 9, 2097152 bytes, vmalloc hugepage)
[   81.872630] TCP: Hash tables configured (established 524288 bind 65536)
[   81.879786] MPTCP token hash table entries: 65536 (order: 8, 1572864 bytes, vmalloc hugepage)
[   81.882040] UDP hash table entries: 32768 (order: 9, 2097152 bytes, vmalloc hugepage)
[   81.884906] UDP-Lite hash table entries: 32768 (order: 9, 2097152 bytes, vmalloc hugepage)
[   81.892513] NET: Registered PF_UNIX/PF_LOCAL protocol family
[   81.892598] NET: Registered PF_XDP protocol family
[   81.893426] PCI: CLS 64 bytes, default 64
[   81.893550] ACPI: bus type thunderbolt registered
[   81.893811] Trying to unpack rootfs image as initramfs...
[   81.932665] kvm [1]: nv: 567 coarse grained trap handlers
[   81.933396] kvm [1]: IPA Size Limit: 44 bits
[   81.935758] kvm [1]: GICv3: no GICV resource entry
[   81.935767] kvm [1]: disabling GICv2 emulation
[   81.940541] kvm [1]: GIC system register CPU interface enabled
[   81.940594] kvm [1]: vgic interrupt IRQ9
[   81.949270] kvm [1]: VHE mode initialized successfully
[   81.996999] Initialise system trusted keyrings
[   81.997129] Key type blacklist registered
[   81.997795] workingset: timestamp_bits=37 max_order=24 bucket_order=0
[   82.015428] integrity: Platform Keyring initialized
[   82.015475] integrity: Machine keyring initialized
[   82.016456] cryptd: max_cpu_qlen set to 1000
[   82.099564] NET: Registered PF_ALG protocol family
[   82.099638] xor: measuring software checksum speed
[   82.105547]    8regs           :   555 MB/sec
[   82.111354]    32regs          :   565 MB/sec
[   82.114612]    arm64_neon      :  1009 MB/sec
[   82.114619] xor: using function: arm64_neon (1009 MB/sec)
[   82.114633] Key type asymmetric registered
[   82.114640] Asymmetric key parser 'x509' registered
[   82.115143] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 241)
[   82.116046] io scheduler mq-deadline registered
[   82.116055] io scheduler kyber registered
[   82.116610] io scheduler bfq registered
[   82.132097] atomic64_test: passed
[   82.177984] ledtrig-cpu: registered to indicate activity on CPUs
[   82.233343] input: Power Button as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0
[   82.233649] ACPI: button: Power Button [PWRB]
[   82.317673] pcieport 0000:00:01.0: Refused to change power state from D0 to D3hot
[   82.317730] pcieport 0000:00:02.0: Refused to change power state from D0 to D3hot
[   82.317764] pcieport 0000:00:03.0: Refused to change power state from D0 to D3hot
[   82.317795] pcieport 0000:00:04.0: Refused to change power state from D0 to D3hot
[   82.317826] pcieport 0000:00:05.0: Refused to change power state from D0 to D3hot
[   82.317853] pcieport 0000:00:06.0: Refused to change power state from D0 to D3hot
[   82.319983] pcieport 0000:00:07.0: Refused to change power state from D0 to D3hot
[   82.320018] pcieport 0000:00:08.0: Refused to change power state from D0 to D3hot
[   82.320038] pcieport 0000:00:09.0: Refused to change power state from D0 to D3hot
[   82.320061] pcieport 0000:00:0a.0: Refused to change power state from D0 to D3hot
[   82.338438] thermal LNXTHERM:00: registered as thermal_zone0
[   82.338452] ACPI: thermal: Thermal Zone [TZN0] (75 C)
[   82.342424] thermal LNXTHERM:01: registered as thermal_zone1
[   82.342436] ACPI: thermal: Thermal Zone [T000] (74 C)
[   82.345827] thermal LNXTHERM:02: registered as thermal_zone2
[   82.345839] ACPI: thermal: Thermal Zone [T001] (77 C)
[   82.349618] thermal LNXTHERM:03: registered as thermal_zone3
[   82.349629] ACPI: thermal: Thermal Zone [T002] (76 C)
[   82.353413] thermal LNXTHERM:04: registered as thermal_zone4
[   82.353424] ACPI: thermal: Thermal Zone [T003] (74 C)
[   82.356661] thermal LNXTHERM:05: registered as thermal_zone5
[   82.356671] ACPI: thermal: Thermal Zone [T004] (73 C)
[   82.360108] thermal LNXTHERM:06: registered as thermal_zone6
[   82.360119] ACPI: thermal: Thermal Zone [T005] (75 C)
[   82.363634] thermal LNXTHERM:07: registered as thermal_zone7
[   82.363644] ACPI: thermal: Thermal Zone [T006] (74 C)
[   82.367085] thermal LNXTHERM:08: registered as thermal_zone8
[   82.367095] ACPI: thermal: Thermal Zone [T007] (72 C)
[   82.370517] thermal LNXTHERM:09: registered as thermal_zone9
[   82.370528] ACPI: thermal: Thermal Zone [T008] (74 C)
[   82.373652] thermal LNXTHERM:0a: registered as thermal_zone10
[   82.373663] ACPI: thermal: Thermal Zone [T009] (76 C)
[   82.377143] thermal LNXTHERM:0b: registered as thermal_zone11
[   82.377154] ACPI: thermal: Thermal Zone [T00A] (74 C)
[   82.380600] thermal LNXTHERM:0c: registered as thermal_zone12
[   82.380611] ACPI: thermal: Thermal Zone [T00B] (75 C)
[   82.383805] thermal LNXTHERM:0d: registered as thermal_zone13
[   82.383815] ACPI: thermal: Thermal Zone [T00C] (75 C)
[   82.386996] thermal LNXTHERM:0e: registered as thermal_zone14
[   82.387007] ACPI: thermal: Thermal Zone [T00D] (73 C)
[   82.390773] thermal LNXTHERM:0f: registered as thermal_zone15
[   82.390784] ACPI: thermal: Thermal Zone [T00E] (74 C)
[   82.394333] thermal LNXTHERM:10: registered as thermal_zone16
[   82.394343] ACPI: thermal: Thermal Zone [T00F] (75 C)
[   82.397441] thermal LNXTHERM:11: registered as thermal_zone17
[   82.397452] ACPI: thermal: Thermal Zone [T010] (76 C)
[   82.400891] thermal LNXTHERM:12: registered as thermal_zone18
[   82.400902] ACPI: thermal: Thermal Zone [T011] (74 C)
[   82.404143] thermal LNXTHERM:13: registered as thermal_zone19
[   82.404154] ACPI: thermal: Thermal Zone [T012] (75 C)
[   82.407500] thermal LNXTHERM:14: registered as thermal_zone20
[   82.407511] ACPI: thermal: Thermal Zone [T013] (76 C)
[   82.410728] thermal LNXTHERM:15: registered as thermal_zone21
[   82.410738] ACPI: thermal: Thermal Zone [T014] (75 C)
[   82.414129] thermal LNXTHERM:16: registered as thermal_zone22
[   82.414139] ACPI: thermal: Thermal Zone [T015] (74 C)
[   82.417702] thermal LNXTHERM:17: registered as thermal_zone23
[   82.417712] ACPI: thermal: Thermal Zone [T016] (76 C)
[   82.421077] thermal LNXTHERM:18: registered as thermal_zone24
[   82.421087] ACPI: thermal: Thermal Zone [T017] (74 C)
[   82.424231] thermal LNXTHERM:19: registered as thermal_zone25
[   82.424241] ACPI: thermal: Thermal Zone [T018] (75 C)
[   82.427421] thermal LNXTHERM:1a: registered as thermal_zone26
[   82.427431] ACPI: thermal: Thermal Zone [T019] (73 C)
[   82.430878] thermal LNXTHERM:1b: registered as thermal_zone27
[   82.430889] ACPI: thermal: Thermal Zone [T01A] (75 C)
[   82.434070] thermal LNXTHERM:1c: registered as thermal_zone28
[   82.434080] ACPI: thermal: Thermal Zone [T01B] (73 C)
[   82.437470] thermal LNXTHERM:1d: registered as thermal_zone29
[   82.437480] ACPI: thermal: Thermal Zone [T01C] (74 C)
[   82.440538] thermal LNXTHERM:1e: registered as thermal_zone30
[   82.440549] ACPI: thermal: Thermal Zone [T01D] (75 C)
[   82.443898] thermal LNXTHERM:1f: registered as thermal_zone31
[   82.443908] ACPI: thermal: Thermal Zone [T01E] (76 C)
[   82.447043] thermal LNXTHERM:20: registered as thermal_zone32
[   82.447054] ACPI: thermal: Thermal Zone [T01F] (71 C)
[   82.450223] thermal LNXTHERM:21: registered as thermal_zone33
[   82.450234] ACPI: thermal: Thermal Zone [TZN1] (59 C)
[   82.453595] thermal LNXTHERM:22: registered as thermal_zone34
[   82.453605] ACPI: thermal: Thermal Zone [T100] (60 C)
[   82.456876] thermal LNXTHERM:23: registered as thermal_zone35
[   82.456887] ACPI: thermal: Thermal Zone [T101] (61 C)
[   82.460028] thermal LNXTHERM:24: registered as thermal_zone36
[   82.460039] ACPI: thermal: Thermal Zone [T102] (58 C)
[   82.463625] thermal LNXTHERM:25: registered as thermal_zone37
[   82.463636] ACPI: thermal: Thermal Zone [T103] (59 C)
[   82.466888] thermal LNXTHERM:26: registered as thermal_zone38
[   82.466899] ACPI: thermal: Thermal Zone [T104] (62 C)
[   82.469974] thermal LNXTHERM:27: registered as thermal_zone39
[   82.469985] ACPI: thermal: Thermal Zone [T105] (62 C)
[   82.473111] thermal LNXTHERM:28: registered as thermal_zone40
[   82.473122] ACPI: thermal: Thermal Zone [T106] (61 C)
[   82.476023] thermal LNXTHERM:29: registered as thermal_zone41
[   82.476034] ACPI: thermal: Thermal Zone [T107] (61 C)
[   82.478966] thermal LNXTHERM:2a: registered as thermal_zone42
[   82.478977] ACPI: thermal: Thermal Zone [T108] (59 C)
[   82.481822] thermal LNXTHERM:2b: registered as thermal_zone43
[   82.481832] ACPI: thermal: Thermal Zone [T109] (62 C)
[   82.484668] thermal LNXTHERM:2c: registered as thermal_zone44
[   82.484678] ACPI: thermal: Thermal Zone [T10A] (61 C)
[   82.487884] thermal LNXTHERM:2d: registered as thermal_zone45
[   82.487895] ACPI: thermal: Thermal Zone [T10B] (61 C)
[   82.490927] thermal LNXTHERM:2e: registered as thermal_zone46
[   82.490938] ACPI: thermal: Thermal Zone [T10C] (61 C)
[   82.493895] thermal LNXTHERM:2f: registered as thermal_zone47
[   82.493905] ACPI: thermal: Thermal Zone [T10D] (58 C)
[   82.497146] thermal LNXTHERM:30: registered as thermal_zone48
[   82.497156] ACPI: thermal: Thermal Zone [T10E] (62 C)
[   82.500039] thermal LNXTHERM:31: registered as thermal_zone49
[   82.500050] ACPI: thermal: Thermal Zone [T10F] (60 C)
[   82.503316] thermal LNXTHERM:32: registered as thermal_zone50
[   82.503327] ACPI: thermal: Thermal Zone [T110] (61 C)
[   82.506231] thermal LNXTHERM:33: registered as thermal_zone51
[   82.506241] ACPI: thermal: Thermal Zone [T111] (59 C)
[   82.509455] thermal LNXTHERM:34: registered as thermal_zone52
[   82.509465] ACPI: thermal: Thermal Zone [T112] (58 C)
[   82.512589] thermal LNXTHERM:35: registered as thermal_zone53
[   82.512600] ACPI: thermal: Thermal Zone [T113] (59 C)
[   82.515536] thermal LNXTHERM:36: registered as thermal_zone54
[   82.515547] ACPI: thermal: Thermal Zone [T114] (62 C)
[   82.518501] thermal LNXTHERM:37: registered as thermal_zone55
[   82.518511] ACPI: thermal: Thermal Zone [T115] (61 C)
[   82.521483] thermal LNXTHERM:38: registered as thermal_zone56
[   82.521493] ACPI: thermal: Thermal Zone [T116] (62 C)
[   82.524376] thermal LNXTHERM:39: registered as thermal_zone57
[   82.524386] ACPI: thermal: Thermal Zone [T117] (61 C)
[   82.527615] thermal LNXTHERM:3a: registered as thermal_zone58
[   82.527626] ACPI: thermal: Thermal Zone [T118] (59 C)
[   82.530576] thermal LNXTHERM:3b: registered as thermal_zone59
[   82.530587] ACPI: thermal: Thermal Zone [T119] (57 C)
[   82.533545] thermal LNXTHERM:3c: registered as thermal_zone60
[   82.533555] ACPI: thermal: Thermal Zone [T11A] (59 C)
[   82.536549] thermal LNXTHERM:3d: registered as thermal_zone61
[   82.536560] ACPI: thermal: Thermal Zone [T11B] (60 C)
[   82.539495] thermal LNXTHERM:3e: registered as thermal_zone62
[   82.539506] ACPI: thermal: Thermal Zone [T11C] (61 C)
[   82.542754] thermal LNXTHERM:3f: registered as thermal_zone63
[   82.542764] ACPI: thermal: Thermal Zone [T11D] (59 C)
[   82.545761] thermal LNXTHERM:40: registered as thermal_zone64
[   82.545772] ACPI: thermal: Thermal Zone [T11E] (60 C)
[   82.548885] thermal LNXTHERM:41: registered as thermal_zone65
[   82.548895] ACPI: thermal: Thermal Zone [T11F] (61 C)
[   82.581897] Serial: 8250/16550 driver, 32 ports, IRQ sharing enabled
[   82.609530] msm_serial: driver initialized
[   82.610295] SuperH (H)SCI(F) driver initialized
[   82.614951] arm-smmu-v3 arm-smmu-v3.0.auto: option mask 0x2
[   82.615067] arm-smmu-v3 arm-smmu-v3.0.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.615086] arm-smmu-v3 arm-smmu-v3.0.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.619676] arm-smmu-v3 arm-smmu-v3.0.auto: allocated 65536 entries for cmdq
[   82.624926] arm-smmu-v3 arm-smmu-v3.0.auto: allocated 32768 entries for evtq
[   82.629534] arm-smmu-v3 arm-smmu-v3.1.auto: option mask 0x2
[   82.629586] arm-smmu-v3 arm-smmu-v3.1.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.629601] arm-smmu-v3 arm-smmu-v3.1.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.636042] arm-smmu-v3 arm-smmu-v3.1.auto: allocated 65536 entries for cmdq
[   82.640800] arm-smmu-v3 arm-smmu-v3.1.auto: allocated 32768 entries for evtq
[   82.644905] arm-smmu-v3 arm-smmu-v3.2.auto: option mask 0x2
[   82.644955] arm-smmu-v3 arm-smmu-v3.2.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.644969] arm-smmu-v3 arm-smmu-v3.2.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.646867] arm-smmu-v3 arm-smmu-v3.2.auto: allocated 65536 entries for cmdq
[   82.651619] arm-smmu-v3 arm-smmu-v3.2.auto: allocated 32768 entries for evtq
[   82.658044] pci 0000:0b:00.0: Adding to iommu group 0
[   82.658263] pci 0000:0b:00.1: AddAdding to iommu group 2
[   82.668115] pci 0000:10:00.0: Adding to iommu group 2
[   82.695372] arm-smmu-v3 arm-smmu-v3.3.auto: option mask 0x2
[   82.695479] arm-smmu-v3 arm-smmu-v3.3.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.695495] arm-smmu-v3 arm-smmu-v3.3.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.700740] arm-smmu-v3 arm-smmu-v3.3.auto: allocated 65536 entries for cmdq
[   82.706039] arm-smmu-v3 arm-smmu-v3.3.auto: allocated 32768 entries for evtq
[   82.709926] arm-smmu-v3 arm-smmu-v3.4.auto: option mask 0x2
[   82.709994] arm-smmu-v3 arm-smmu-v3.4.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.710008] arm-smmu-v3 arm-smmu-v3.4.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.711506] arm-smmu-v3 arm-smmu-v3.4.auto: allocated 65536 entries for cmdq
[   82.716863] arm-smmu-v3 arm-smmu-v3.4.auto: allocated 32768 entries for evtq
[   82.720769] arm-smmu-v3 arm-smmu-v3.5.auto: option mask 0x2
[   82.720836] arm-smmu-v3 arm-smmu-v3.5.auto: IDR0.HTTU features(0x600000) overridden by FW configuration (0x0)
[   82.720850] arm-smmu-v3 arm-smmu-v3.5.auto: ias 44-bit, oas 44-bit (features 0x000e172d)
[   82.722460] arm-smmu-v3 arm-smmu-v3.5.auto: allocated 65536 entries for cmdq
[   82.727678] arm-sfbs slum part 
SATA max UDMA/13l 3
[   82.9329 disabled
[   8ommand slots, 6  ports implementelags: 64bit ncq sntf sta
                                                              [   82.947123] 43210100 irq 38 t, parallel bus rs 0001.0300, 32 0000:80:10.0: 1ci 0000:80:10.0: flags:  scsi host2: ahc@0x60000000 port:80:10.1: SSS fli 0000:80:10.1: ode
[   82.975240] ahci 0000:80:10.1: 1/1 ports implemented (port mask 0x1)
[   82.975263] ahci 0000:80:10.1: flags: 64bit ncq sntf stag clo pmp fbs slum part 
[   82.979387] scsi host3: ahci
[   82.979920] ata4: SATA max UDMA/133 abar m65536@0x60010000 port 0x60010100 irq 40 lpm-pol 3
[   82.985267] xhci_hcd 0000:00:0f.0: xHCI Host Controller
[   82.985737] xhci_hcd 0000:00:0f.0: new USB bus registered, assigned bus number 1
[   82.985982] xhci_hcd 0000:00:0f.0: hcc params 0x0250f16d hci version 0x100 quirks 0x0000000400000010
[   82.987912] xhci_hcd 0000:00:0f.0: xHCI Host Controller
[   82.988215] xhci_hcd 0000:00:0f.0: new USB bus registered, assigned bus number 2
[   82.988238] xhci_hcd 0000:00:0f.0: Host supports USB 3.0 SuperSpeed
[   82.988704] usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 6.17
[   82.988720] usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[   82.988731] usb usb1: Product: xHCI Host Controller
[   82.988741] usb usb1: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   82.988750] usb usb1: SerialNumber: 0000:00:0f.0
[   82.989785] hub 1-0:1.0: USB hub found
[   82.989878] hub 1-0:1.0: 1 port detected
[   82.990763] us host, disabling LPM.
[   82.991061] uct=0003, bcdDevice= 6.17
[   82.991076] rialNumber=1
[   82.991] usb usb2: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   82.9911ub 2-0:1.0: USB hub found
[   82.9921200000:00:0f.1: xHCI Host Controller
[   82.99345d bus number 3
[   82.993564] xon 0x100 quirks 0x0000000400000010
[   82.995365646] xhci_hcd 0000:00:0f.1: new USB bus registered, assigned bus number 4
[   82.995668] xhci_hcd 0000:00:0f.1: Host supports USB 3.0 SuperSpeed
[   82.996010] usb usb3: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 6.17
[   82.996025] usb usb3: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[   82.996036] usb usb3: Product: xHCI Host Controller
[   82.996045] usb usb3: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   82.996055] usb usb3: SerialNumber: 0000:00:0f.1
[   82.996884] hub 3-0:1.0: USB hub found
[   82.996958] hub 3-0:1.0: 1 port detected
[   82.997717] usb usb4: We don't know the algorithms for LPM for this host, disabling LPM.
[   82.997972] usb usb4: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 6.17
[   82.997987] usb usb4: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[   82.997997] usb usb4: Product: xHCI Host Controller
[   82.998007] usb usb4: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   82.998016] usb usb4: SerialNumber: 0000:00:0f.1
[   82.998928] hub 4-0:1.0: USB hub found
[   82.999001] hub 4-0:1.0: 1 port detected
[   83.000003] xhci_hcd 0000:80:0f.0: xHCI Host Controller
[   83.000513] xhci_hcd 0000:80:0f.0: new USB bus registered, assigned bus number 5
[   83.000742] xhci_hcd 0000:80:0f.0: hcc params 0x0250f16d hci version 0x100 quirks 0x0000000400000010
[   83.00273010] xhci_hcd 0000:80:0f.0: new USB bus registered, assigned bus number 6
[   83.003033] xhci_hcd 0000:80:0f.0rings: Mfr=3, Product=2, SerialNumber=1
[   83.003556] usb usb5: Product: xHCI Host Controller
[   83.003566] usb usb5: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   83.003575ub 5-0:1.0: USB h
                              [   83.005566] usb usb6: We don't know the algorithms for LPM for this host, disabling LPM.
[   83.005855] usb usb6: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 6.17
[   83.005870] usb usb6: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[   83.005881] usb usb6: Product: xHCI Host Controller
[   83.005890] usb usb6: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   83.005899] usb usb6: SerialNumber: 0000:80:0f.0
[   83.006838] hub 6-0:1.0: USB hub found
[   83.006915] hub 6-0:1.0: 1 port detected
[   83.007898] xhci_hcd 0000:80:0f.1: xHCI Host Controller
  83.010468] xhci_hcd 0000:80:0f.1: new USB bus registered, assigned bus number 8
[   83.010489] xhci_hcd 0000:80:0f.1: Host supports USB 3.0 SuperSpeed
[   83.010806t=0002, bcdDevics: Mfr=3, Product=2, SerialNumber=1
[   83.010831] usb usb7: Product: xHCI Host Controller
[   83.010841] usb usb7: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   83.010850] usb usb7: SerialNumber: 0000:80:0f.1
[   83.011723] hub 7-0:1.0: USB hub found
[   83.011796] hub 7-0:1.0: 1 port detected
[   83.012566] usb usb8: We don't know the algorithms for LPM for this host, disabling LPM.
[   83.012824] usb usb8: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 6.17
[   83.012838] usb usb8: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[   83.012849] usb usb8: Product: xHCI Host Controller
[   83.012858] usb usb8: Manufacturer: Linux 6.17.0-rc2 xhci-hcd
[   83.012867] usb usb8: SerialNumber: 0000:80:0f.1
[   83.013753] hub 8-0:1.0: USB hub found
[   83.0138 usbcore: regist  83.015652] usbseric
[   83.016 mice
[   83.02
         [   83.032517] 25-08-18T09:02:3er: core: CONFIG_IMA_DISABLE_HTABLE is disabled. Duplicate IMA measurements will not be recorded in the  version 1.0.3
[   83.039374] device-mapper: iosts.linux.dev
[   83.042214] simple-framebuffer simple-framebuffer.0: [drm] Registered 1 planes with drm panic
[   83.049228] [drm] Initialized simpledrm 1.0.0 for simple-framebuffer.0 on minor 0
[   83.053le-framebuffer sfer device
[   83.062662] hid: raw HID events driver (C) Jiri Kosina
[   83.063109] usbcore: registered new interface driver usbhid
[   83.063117] usbhid: USB HID core driver
[   83.084421] hw perfevents: enabled with armv8_pmuv3_0 PMU driver, 7 (0,8000003f) counters available
[   83.084488] watchdog: NMI not fully supported
[   83.084493] watchdog: Hard watchdog permanently disabled
[   83.092234] drop_monitor: Initializing network drop monitor service
[   83.092756] Initializing XFRM netlink socket
[   83.094277] NET: Registered PF_INET6 protocol family
[   83.109455] Segment Routing with IPv6
[   83.109462] RPL-situ OAM (IOAM)oading compiled-in X.509 certificates
[   83.215287] Loaded X.509 cert 'Build time autogenerated kernel key: a3a393c2df2b1ca4ce14ae671b2691acf485bce9'
[   83.241453] hcd
[   83.2759 83.285586] Demotion targets for Node 0: null
[   83.285595] Demotion targets for Node 1: null
[   83.285623] page_owner is disabled
[   83.288189] Key type .fscrypt registered
[   83.288198] Key type fscrypt-provisioning registered
[   83.291176] ata4: SATA link down (SStatus 0 SControl 300)
[   83.301586] Btrfs loaded, zoned=yes, fsverity=yes
[   83.301771] Key type big_key registered
[   83.301806] Key type encrypted registered
[   83.302316] ima: secureboot mode disabled
[   83.302330] ima: No TPM chip found, activating TPM-bypass!
[   83.302368] Loading compiled-in module X.509 certificates
[   83.305175] Loaded X.509 cert 'Build time autogenerated kernel key: a3a393c2df2b1ca4ce14ae671b2691acf485bce9'
[   83.305192] ima: Allocated hash algorithm: sha256
isabled)0305470] evm: Ini05474] evm: securACK64 (disabled)
[   83sabled)
[   83.3[   83.305499] e04] evm: security.ima
[   83.305508] evm: security.capability
[   83.3 Disabling unused clocks
[   83.393816][   83.394737] ata1.00: .404050] ata1.00: configured for UDMA/133
[   83.406621] scsi 0:0:0:0: Direct-Access     ATA      VR000480GWFMD    HPGB PQ: 0 ANSI: 5
[   83.410055] s11177] sd 0:0:0:GiB)
[   83.411214] sd 0:0:0:0: [sda] 4096-byte physical blocks
[   83.411305] sd 0:0:0:0: [sda] Write Protect is off
[   83.411445] sd 0:0:0:0: [sda] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
[   83.411635] sd 0:0:0:0: [sda] Preferred minimum I/O size 4096 bytes
[   83.417276] ata2: SATA link up 6.0 Gbps (SStatus 133 SControl 300)
[   83.420232] ata2.00: ATA-10: MB8000GFECR, HPG6, max UDMA/133
[   83.420400] ata2.00: 15628053168 sectors, multi 16: LBA48 NCQ (depth 32), AA
[   83.423121] ata2.00: configured for UDMA/133
[   83.425642] scsi 1:0:0:0: Direct-Access     ATA      MB8000GFECR      HPG6 PQ: 0 ANSI: 5
[   83.429353]  83.429415] sd 1 Protect is off
[   83.429646] sd 1:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
[   83.429826] sd 1:0:0:0: [sdb] Preferred minimum I/O size 4096 bytes
[   83.436569]t=ff01, bcdDevic: Mfr=1, Product=2, SerialNumber=3
[   83.436602] usb 3-1: Product: Virtual Hub
[   83.436612] usb 3-1: Manufacturer: American Megatrends Inc.
[   83.436622] usb 3-1: SerialNumber: serial
[   83.456216] hub 3-1:1.0: USB hub found
[   83.462377] hub 3-1:1.0: 5 ports detected
[   83.470020]  sda: sda1 sda2 sda3
[   83.471324] sd 0:0:0:0: [sda] Attached SCSI disk
[   83.520894]  sdb: sdb1
[   83.521410] sd 1:0:0:0: [sdb] Attached SCSI disk
[   83.785015] Freeing initrd memory: 32784K
[   83.825799] Freeing unused kernel memory: 13888K
[   83.914662] usb 3-1.1: new high-speed USB device number 3 using xhci_hcd
[   84.068737] usb 3-1.1: New USB device found, idVendor=046b, idProduct=ff20, bcdDevice= 1.00
[   84.068844] usb 3-1.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[   84.06  84.068982] usb
[   84.069044]  84.188457] usbing xhci_hcd
[ , idVendor=046b,54] usb 3-1.2: NalNumber=3
[   84.340806] usb 3-1.2: Product: Virtual Floppy Device
[   84.340nds Inc.
[   84.340896] usb 3-1.2: SerialNumbereed USB device number 5 oduct=2, SerialNumber=3
[   84.616135] usb 3-1.3: Product: Virtual HardDisk Device
[   84.616181] usb 3-1.3: Manufacturer: American Megatrends Inc.
[   84.616[   84.728289] u using xhci_hcd
[   84.999735] usb 3-1.4: New USB device found, idVendor=046b, idProduct=ff10, bcdDevicece strings: Mfr= usb 3-1.4: Prod99] usb 3-1.4: M[   85.088017] input: American Megatrends Inc. Virtual Keyboard and Mouse as /devices/pci0000:00/0000:00:0f.1/usb3/3-1/3-1.4/3-1.4:1.0/0003:046B:FF10.0001/input/input1
[   85.105784] hid-generic 0003:oard [American Meusb-0000:00:0f.1[   85.178963] input: American Megatrends Inc. Virtual Keyboard and Mouse as /devices/pci0000:00/0000:00B:FF10.0002: inp:0f.1-1.4/input1[   86.283951] Checked W+X mappings: passed, no W+X pages found
[   86.284194] Run /init as init process
[   86.377906] systemd[1]: Successfully made /usr/ read-only.
[   86.387412] systemd[1]: systemd 257.7-1.fc42 running in system mode (+PAM +AUDIT +SELINUX -APPARMOR +IMA +IPE +SMACK +SECCOMP -GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN -IPTC +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK +PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF +XKBCOMMON +UTMP +SYSVINIT +LIBARCHIVE)
[   86.387467] systemd[1]: Detected architecture arm64.
[   86.387490] systemd[1]: Running in initrd.
Booting initrd of Fedora Linux 42 (Adams) dracut-107-2.fc42 (Initramfs).
[   86.442751] systemd[1]: Hostname set to <hpe-apollo-cn99xx-06.khw.eng.rdu2.dc.redhat.com>.
[   87.441324] systemd[1]: bpf-restrict-fs: Failed to load BPF object: No such process
[   87.735243] systemd[1]: Queued start job for default target initrd.target.
[   87.771314] systemd[1]: Expecting device dev-mapper-anaconda_hpe\x2d\x2dapollo\x2d\x2dcn99xx\x2d\x2d06\x2droot.device - /dev/mapper/anaconda_hpe--apollo--cn99xx--06-root...
         Expecting device dev-mapper-anacon…nda_hpe--apollo--cn99xx--06-root...
[   87.796467] systemd[1]: Reached target initrd-usr-fs.target - Initrd /usr File System.
[  OK  ] Reached target initrd-usr-fs.target - Initrd /usr File System.
[   87.813413] systemd[1]: Reached target slices.target - Slice Units.
[  OK  ] Reached target slices.target - Slice Units.
[   87.827403] systemd[1]: Reached target swap.target - Swaps.
[  OK  ] Reached target swap.target - Swaps.
[   87.839397] systemd[1]: Reached target timers.target - Timer Units.
[  OK  ] Reached target timers.target - Timer Units.
[   87.854166] systemd[1]: Listening on systemd-journald-dev-log.socket - Journal Socket (/dev/log).
[  OK  ] Listening on systemd-journald-dev-…socket - Journal Socket (/dev/log).
[   87.874103] systemd[1]: Listening on systemd-journald.socket - Journal Sockets.
[  OK  ] Listening on systemd-journald.socket - Journal Sockets.
[   87.891000] systemd[1]: Listening on systemd-udevd-control.socket - udev Control Socket.
[  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
[   87.909690] systemd[1]: Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
[  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
[   87.926407] systemd[1]: Reached target sockets.target - Socket Units.
[  OK  ] Reached target sockets.target - Socket Units.
[   87.950401] systemd[1]: Starting kmod-static-nodes.service - Create List of Static Device Nodes...
         Starting kmod-static-nodes.service…eate List of Static Device Nodes...
[   87.968609] systemd[1]: memstrack.service - Memstrack Anylazing Service was skipped because no trigger condition checks were met.
[   88.009912] systemd[1]: Starting systemd-journald.service - Journal Service...
         Starting systemd-journald.service - Journal Service...
[   88.033281] systemd[1]: Starting systemd-modules-load.service - Load Kernel Modules...
         Starting systemd-modules-load.service - Load Kernel Modules...
[   88.050429] systemd[1]: systemd-pcrphase-initrd.service - TPM PCR Barrier (initrd) was skipped because of an unmet condition check (ConditionSecurity=measured-uki).
[   88.082017] systemd[1]: Starting systemd-vconsole-setup.service - Virtual Console Setup...
         Starting systemd-vconsole-setup.service - Virtual Console Setup...
[   88.106375] systemd[1]: Finished kmod-static-nodes.service - Create List of Static Device Nodes.
[  OK  ] Finished kmod-static-nodes.service…Create List of Static Device Nodes.
[   88.135409] i2c_dev: i2c /dev entries driver
[   88.135551] systemd[1]: Starting systemd-tmpfiles-setup-dev-early.service - Create Static Device Nodes in /dev gracefully...
[   88.148091] systemd-journald[1702]: Collecting audit messages is disabled.
         Starting systemd-tmpfiles-setup-de… Devic[   88.160727] systemd[1]: Finished systemd-modules-load.service - Load Kernel Modules.
e Nodes in /dev gracefully...
[  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
[   88.203381] systemd[1]: Starting systemd-sysctl.service - Apply Kernel Variables...
         Starting systemd-sysctl.service - Apply Kernel Variables...
[   88.304137] systemd[1]: Finished systemd-sysctl.service - Apply Kernel Variables.
[  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
[   88.437570] systemd[1]: Finished systemd-tmpfiles-setup-dev-early.service - Create Static Device Nodes in /dev gracefully.
[  OK  ] Finished systemd-tmpfiles-setup-de…ic Device Nodes in /dev gracefully.
[   88.459738] systemd[1]: Starting systemd-sysusers.service - Create System Users...
         Starting systemd-sysusers.service - Create System Users...
[   88.507463] systemd[1]: Finished systemd-vconsole-setup.service - Virtual Console Setup.
[  OK  ] Finished systemd-vconsole-setup.service - Virtual Console Setup.
[   88.544455] systemd[1]: Starting dracut-cmdline-ask.service - dracut ask for additional cmdline parameters...
         Starting dracut-cmdline-ask.servic…or additional cmdline parameters...
[   88.607406] systemd[1]: Finished systemd-sysusers.service - Create System Users.
[  OK  ] Finished systemd-sysusers.service - Create System Users.
[   88.624574] systemd[1]: Starting systemd-tmpfiles-setup-dev.service - Create Static Device Nodes in /dev...
         Starting systemd-tmpfiles-setup-de…eate Static Device Nodes in /dev...
[   88.674974] systemd[1]: Finished dracut-cmdline-ask.service - dracut ask for additional cmdline parameters.
[  OK  ] Finished dracut-cmdline-ask.servic… for additional cmdline parameters.
[   88.703919] systemd[1]: Starting dracut-cmdline.service - dracut cmdline hook...
         Starting dracut-cmdline.service - dracut cmdline hook...
[   88.878954] systemd[1]: Finished systemd-tmpfiles-setup-dev.service - Create Static Device Nodes in /dev.
[  OK  ] Finished systemd-tmpfiles-setup-de…Create Static Device Nodes in /dev.
[   88.899072] systemd[1]: Reached target local-fs-pre.target - Preparation for Local File Systems.
[  OK  ] Reached target local-fs-pre.target…Preparation for Local File Systems.
[   88.919459] systemd[1]: Reached target local-fs.target - Local File Systems.
[  OK  ] Reached target local-fs.target - Local File Systems.
[   89.240001] systemd[1]: Finished dracut-cmdline.service - dracut cmdline hook.
[  OK  ] Finished dracut-cmdline.service - dracut cmdline hook.
[   89.257633] ==================================================================
[   89.257646] BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8
[   89.257672] Write of size 528 at addr ddfffd7fbdc00000 by task systemd/1
[   89.257685] Pointer tag: [dd], memory tag: [ca]
[   89.257692] 
[   89.257703] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc2 #1 PREEMPT(voluntary) 
[   89.257719] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[   89.257726] Call trace:
[   89.257731]  show_stack+0x30/0x90 (C)
[   89.257753]  dump_stack_lvl+0x7c/0xa0
[   89.257769]  print_address_description.isra.0+0x90/0x2b8
[   89.257789]  print_report+0x120/0x208
[   89.257804]  kasan_report+0xc8/0x110
[   89.257823]  kasan_check_range+0x7c/0xa0
[   89.257835]  __asan_memset+0x30/0x68
[   89.257847]  pcpu_alloc_noprof+0x42c/0x9a8
[   89.257859]  mem_cgroup_alloc+0x2bc/0x560
[   89.257873]  mem_cgroup_css_alloc+0x78/0x780
[   89.257893]  cgroup_apply_control_enable+0x230/0x578
[   89.257914]  cgroup_mkdir+0xf0/0x330
[   89.257928]  kernfs_iop_mkdir+0xb0/0x120
[   89.257947]  vfs_mkdir+0x250/0x380
[   89.257965]  do_mkdirat+0x254/0x298
[   89.257979]  __arm64_sys_mkdirat+0x80/0xc0
[   89.257994]  invoke_syscall.constprop.0+0x88/0x148
[   89.258011]  el0_svc_common.constprop.0+0x78/0x148
[   89.258025]  do_el0_svc+0x38/0x50
[   89.258037]  el0_svc+0x3c/0x168
[   89.258050]  el0t_64_sync_handler+0xa0/0xf0
[   89.258063]  el0t_64_sync+0x1b0/0x1b8
[   89.258076] 
[   89.258080] The buggy address belongs to a 0-page vmalloc region starting at 0xcafffd7fbdc00000 allocated at pcpu_get_vm_areas+0x0/0x1da0
[   89.258111] The buggy address belongs to the physical page:
[   89.258117] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x881ddac
[   89.258129] flags: 0xa5c00000000000(node=1|zone=2|kasantag=0x5c)
[   89.258148] raw: 00a5c00000000000 0000000000000000 dead000000000122 0000000000000000
[   89.258160] raw: 0000000000000000 f3ff000813efa600 00000001ffffffff 0000000000000000
[   89.258168] raw: 00000000000fffff 0000000000000000
[   89.258173] page dumped because: kasan: bad access detected
[   89.258178] 
[   89.258181] Memory state around the buggy address:
[   89.258192] Unable to handle kernel paging request at virtual address ffff7fd7fbdbffe0
[   89.258199] KASAN: probably wild-memory-access in range [0xfffffd7fbdbffe00-0xfffffd7fbdbffe0f]
[   89.258207] Mem abort info:
[   89.258211]   ESR = 0x0000000096000007
[   89.258216]   EC = 0x25: DABT (current EL), IL = 32 bits
[   89.258223]   SET = 0, FnV = 0
[   89.258228]   EA = 0, S1PTW = 0
[   89.258232]   FSC = 0x07: level 3 translation fault
[   89.258238] Data abort info:
[   89.258241]   ISV = 0, ISS = 0x00000007, ISS2 = 0x00000000
[   89.258246]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
[   89.258252]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[   89.258260] swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000008ff8b8f000
[   89.258267] [ffff7fd7fbdbffe0] pgd=1000008ff0275403, p4d=1000008ff0275403, pud=1000008ff0274403, pmd=1000000899079403, pte=0000000000000000
[   89.258296] Internal error: Oops: 0000000096000007 [#1]  SMP
[   89.540859] Modules linked in: i2c_dev
[   89.544619] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc2 #1 PREEMPT(voluntary) 
[   89.553234] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[   89.562970] pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   89.569933] pc : __pi_memcpy_generic+0x24/0x230
[   89.574472] lr : kasan_metadata_fetch_row+0x20/0x30
[   89.579350] sp : ffff8000859d76c0
[   89.582660] x29: ffff8000859d76c0 x28: 0000000000000100 x27: ffff008ec626d800
[   89.589807] x26: 0000000000000210 x25: 0000000000000000 x24: fffffd7fbdbfff00
[   89.596952] x23: ffff8000826cbeb8 x22: fffffd7fbdc00000 x21: 00000000fffffffe
[   89.604097] x20: ffff800082682ee0 x19: fffffd7fbdbffe00 x18: 00000000049016ff
[   89.611242] x17: 3030303030303030 x16: 2066666666666666 x15: 6631303030303030
[   89.618386] x14: 0000000000000001 x13: 0000000000000001 x12: 0000000000000001
[   89.625530] x11: 687420646e756f72 x10: 0000000000000020 x9 : 0000000000000000
[   89.632674] x8 : ffff78000859d766 x7 : 0000000000000000 x6 : 000000000000003a
[   89.639818] x5 : ffff8000859d7728 x4 : ffff7fd7fbdbfff0 x3 : efff800000000000
[   89.646963] x2 : 0000000000000010 x1 : ffff7fd7fbdbffe0 x0 : ffff8000859d7718
[   89.654107] Call trace:
[   89.656549]  __pi_memcpy_generic+0x24/0x230 (P)
[   89.661086]  print_report+0x180/0x208
[   89.664753]  kasan_report+0xc8/0x110
[   89.668333]  kasan_check_range+0x7c/0xa0
[   89.672258]  __asan_memset+0x30/0x68
[   89.675836]  pcpu_alloc_noprof+0x42c/0x9a8
[   89.679935]  mem_cgroup_alloc+0x2bc/0x560
[   89.683947]  mem_cgroup_css_alloc+0x78/0x780
[   89.688222]  cgroup_apply_control_enable+0x230/0x578
[   89.693191]  cgroup_mkdir+0xf0/0x330
[   89.696771]  kernfs_iop_mkdir+0xb0/0x120
[   89.700697]  vfs_mkdir+0x250/0x380
[   89.704103]  do_mkdirat+0x254/0x298
[   89.707596]  __arm64_sys_mkdirat+0x80/0xc0
[   89.711697]  invoke_syscall.constprop.0+0x88/0x148
[   89.716491]  el0_svc_common.constprop.0+0x78/0x148
[   89.721286]  do_el0_svc+0x38/0x50
[   89.724602]  el0_svc+0x3c/0x168
[   89.727746]  el0t_64_sync_handler+0xa0/0xf0
[   89.731933]  el0t_64_sync+0x1b0/0x1b8
[   89.735603] Code: f100805f 540003c8 f100405f 540000c3 (a9401c26) 
[   89.741695] ---[ end trace 0000000000000000 ]---
[   89.746308] note: systemd[1] exi
** replaying previous printk message **
[   89.746308] note: systemd[1] exited with irqs disabled
[   89.746410] note: systemd[1] exited with preempt_count 1
[   89.746463] Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
[   89.771182] SMP: stopping secondary CPUs
[   89.775158] Kernel Offset: 0x20000 from 0xffff800080000000
[   89.780642] PHYS_OFFSET: 0x80000000
[   89.784126] CPU features: 0x00300,00001a00,12023101,04004203
[   89.789784] Memory Limit: none
[   89.882954] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---

--EEo2Efafy6WV2cN3
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename="sw_tags.config"

#
# Automatically generated file; DO NOT EDIT.
# Linux/arm64 6.17.0-rc2 Kernel Configuration
#
CONFIG_CC_VERSION_TEXT="gcc (GCC) 15.2.1 20250808 (Red Hat 15.2.1-1)"
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=150201
CONFIG_CLANG_VERSION=0
CONFIG_AS_IS_GNU=y
CONFIG_AS_VERSION=24400
CONFIG_LD_IS_BFD=y
CONFIG_LD_VERSION=24400
CONFIG_LLD_VERSION=0
CONFIG_RUSTC_VERSION=0
CONFIG_RUSTC_LLVM_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_HAS_ASM_GOTO_OUTPUT=y
CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT=y
CONFIG_TOOLS_SUPPORT_RELR=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_NO_PROFILE_FN_ATTR=y
CONFIG_CC_HAS_COUNTED_BY=y
CONFIG_CC_HAS_MULTIDIMENSIONAL_NONSTRING=y
CONFIG_LD_CAN_USE_KEEP_IN_OVERLAY=y
CONFIG_PAHOLE_VERSION=0
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_TABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
# CONFIG_WERROR is not set
CONFIG_UAPI_HEADER_TEST=y
CONFIG_LOCALVERSION=""
# CONFIG_LOCALVERSION_AUTO is not set
CONFIG_BUILD_SALT="6.15.9-201.fc42.aarch64"
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_ZSTD=y
# CONFIG_KERNEL_GZIP is not set
CONFIG_KERNEL_ZSTD=y
CONFIG_DEFAULT_INIT=""
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SYSVIPC=y
CONFIG_SYSVIPC_SYSCTL=y
CONFIG_SYSVIPC_COMPAT=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
CONFIG_WATCH_QUEUE=y
CONFIG_CROSS_MEMORY_ATTACH=y
CONFIG_AUDIT=y
CONFIG_HAVE_ARCH_AUDITSYSCALL=y
CONFIG_AUDITSYSCALL=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_SHOW_LEVEL=y
CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=y
CONFIG_GENERIC_IRQ_MIGRATION=y
CONFIG_GENERIC_IRQ_INJECTION=y
CONFIG_HARDIRQS_SW_RESEND=y
CONFIG_GENERIC_IRQ_CHIP=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_SIM=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_IRQ_FASTEOI_HIERARCHY_HANDLERS=y
CONFIG_GENERIC_IRQ_IPI=y
CONFIG_GENERIC_IRQ_IPI_MUX=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_IRQ_MSI_IOMMU=y
CONFIG_GENERIC_IRQ_STAT_SNAPSHOT=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
# CONFIG_GENERIC_IRQ_DEBUGFS is not set
CONFIG_GENERIC_IRQ_KEXEC_CLEAR_VM_FORWARD=y
# end of IRQ subsystem

CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_ARCH_HAS_TICK_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_TIME_KUNIT_TEST=m
CONFIG_CONTEXT_TRACKING=y
CONFIG_CONTEXT_TRACKING_IDLE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
# CONFIG_NO_HZ_IDLE is not set
CONFIG_NO_HZ_FULL=y
CONFIG_CONTEXT_TRACKING_USER=y
# CONFIG_CONTEXT_TRACKING_USER_FORCE is not set
CONFIG_NO_HZ=y
CONFIG_HIGH_RES_TIMERS=y
# CONFIG_POSIX_AUX_CLOCKS is not set
# end of Timers subsystem

CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y

#
# BPF subsystem
#
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_BPF_PRELOAD=y
CONFIG_BPF_PRELOAD_UMD=m
CONFIG_BPF_LSM=y
# end of BPF subsystem

CONFIG_PREEMPT_BUILD=y
CONFIG_ARCH_HAS_PREEMPT_LAZY=y
# CONFIG_PREEMPT_NONE is not set
CONFIG_PREEMPT_VOLUNTARY=y
# CONFIG_PREEMPT is not set
# CONFIG_PREEMPT_LAZY is not set
# CONFIG_PREEMPT_RT is not set
CONFIG_PREEMPT_COUNT=y
CONFIG_PREEMPTION=y
CONFIG_PREEMPT_DYNAMIC=y
CONFIG_SCHED_CORE=y

#
# CPU/Task time and stats accounting
#
CONFIG_VIRT_CPU_ACCOUNTING=y
CONFIG_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_SCHED_AVG_IRQ=y
CONFIG_SCHED_HW_PRESSURE=y
CONFIG_BSD_PROCESS_ACCT=y
CONFIG_BSD_PROCESS_ACCT_V3=y
CONFIG_TASKSTATS=y
CONFIG_TASK_DELAY_ACCT=y
CONFIG_TASK_XACCT=y
CONFIG_TASK_IO_ACCOUNTING=y
CONFIG_PSI=y
# CONFIG_PSI_DEFAULT_DISABLED is not set
# end of CPU/Task time and stats accounting

CONFIG_CPU_ISOLATION=y

#
# RCU Subsystem
#
CONFIG_TREE_RCU=y
CONFIG_PREEMPT_RCU=y
# CONFIG_RCU_EXPERT is not set
CONFIG_TREE_SRCU=y
CONFIG_TASKS_RCU_GENERIC=y
CONFIG_NEED_TASKS_RCU=y
CONFIG_TASKS_RCU=y
CONFIG_TASKS_RUDE_RCU=y
CONFIG_TASKS_TRACE_RCU=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_RCU_NEED_SEGCBLIST=y
CONFIG_RCU_NOCB_CPU=y
# CONFIG_RCU_NOCB_CPU_DEFAULT_ALL is not set
# CONFIG_RCU_LAZY is not set
# end of RCU Subsystem

# CONFIG_IKCONFIG is not set
CONFIG_IKHEADERS=m
CONFIG_LOG_BUF_SHIFT=18
CONFIG_LOG_CPU_MAX_BUF_SHIFT=12
CONFIG_PRINTK_INDEX=y
CONFIG_GENERIC_SCHED_CLOCK=y

#
# Scheduler features
#
CONFIG_UCLAMP_TASK=y
CONFIG_UCLAMP_BUCKETS_COUNT=5
# CONFIG_SCHED_PROXY_EXEC is not set
# end of Scheduler features

CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_CC_HAS_INT128=y
CONFIG_CC_IMPLICIT_FALLTHROUGH="-Wimplicit-fallthrough=5"
CONFIG_GCC10_NO_ARRAY_BOUNDS=y
CONFIG_CC_NO_ARRAY_BOUNDS=y
CONFIG_GCC_NO_STRINGOP_OVERFLOW=y
CONFIG_CC_NO_STRINGOP_OVERFLOW=y
CONFIG_ARCH_SUPPORTS_INT128=y
CONFIG_NUMA_BALANCING=y
CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
CONFIG_SLAB_OBJ_EXT=y
CONFIG_CGROUPS=y
CONFIG_PAGE_COUNTER=y
# CONFIG_CGROUP_FAVOR_DYNMODS is not set
CONFIG_MEMCG=y
CONFIG_MEMCG_V1=y
CONFIG_BLK_CGROUP=y
CONFIG_CGROUP_WRITEBACK=y
CONFIG_CGROUP_SCHED=y
CONFIG_GROUP_SCHED_WEIGHT=y
CONFIG_GROUP_SCHED_BANDWIDTH=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_CFS_BANDWIDTH=y
# CONFIG_RT_GROUP_SCHED is not set
CONFIG_SCHED_MM_CID=y
CONFIG_UCLAMP_TASK_GROUP=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_DMEM=y
CONFIG_CGROUP_FREEZER=y
# CONFIG_CGROUP_HUGETLB is not set
CONFIG_CPUSETS=y
# CONFIG_CPUSETS_V1 is not set
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_MISC=y
# CONFIG_CGROUP_DEBUG is not set
CONFIG_SOCK_CGROUP_DATA=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_TIME_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CHECKPOINT_RESTORE=y
CONFIG_SCHED_AUTOGROUP=y
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
CONFIG_RD_XZ=y
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_RD_ZSTD=y
CONFIG_BOOT_CONFIG=y
# CONFIG_BOOT_CONFIG_FORCE is not set
# CONFIG_BOOT_CONFIG_EMBED is not set
# CONFIG_INITRAMFS_PRESERVE_MTIME is not set
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_LD_ORPHAN_WARN=y
CONFIG_LD_ORPHAN_WARN_LEVEL="warn"
CONFIG_SYSCTL=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_SYSFS_SYSCALL=y
CONFIG_EXPERT=y
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
# CONFIG_BASE_SMALL is not set
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_FUTEX_PRIVATE_HASH=y
CONFIG_FUTEX_MPOL=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
CONFIG_AIO=y
CONFIG_IO_URING=y
# CONFIG_IO_URING_MOCK_FILE is not set
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_KCMP=y
CONFIG_RSEQ=y
# CONFIG_DEBUG_RSEQ is not set
CONFIG_CACHESTAT_SYSCALL=y
CONFIG_KALLSYMS=y
# CONFIG_KALLSYMS_SELFTEST is not set
CONFIG_KALLSYMS_ALL=y
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
CONFIG_ARCH_SUPPORTS_MSEAL_SYSTEM_MAPPINGS=y
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_GUEST_PERF_EVENTS=y

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
# CONFIG_DEBUG_PERF_USE_VMALLOC is not set
# end of Kernel Performance Events And Counters

CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y

#
# Kexec and crash features
#
CONFIG_CRASH_RESERVE=y
CONFIG_VMCORE_INFO=y
CONFIG_KEXEC_CORE=y
CONFIG_HAVE_IMA_KEXEC=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_IMAGE_VERIFY_SIG=y
# CONFIG_KEXEC_HANDOVER is not set
CONFIG_CRASH_DUMP=y
# CONFIG_CRASH_DM_CRYPT is not set
# end of Kexec and crash features
# end of General setup

CONFIG_ARM64=y
CONFIG_RUSTC_SUPPORTS_ARM64=y
CONFIG_GCC_SUPPORTS_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_64BIT=y
CONFIG_MMU=y
CONFIG_ARM64_CONT_PTE_SHIFT=4
CONFIG_ARM64_CONT_PMD_SHIFT=4
CONFIG_ARCH_MMAP_RND_BITS_MIN=18
CONFIG_ARCH_MMAP_RND_BITS_MAX=33
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=11
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_GENERIC_HWEIGHT=y
CONFIG_GENERIC_CSUM=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_SMP=y
CONFIG_KERNEL_MODE_NEON=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_PGTABLE_LEVELS=4
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_ARCH_PROC_KCORE_TEXT=y
CONFIG_BUILTIN_RETURN_ADDRESS_STRIPS_PAC=y
CONFIG_KASAN_SHADOW_OFFSET=0xefff800000000000

#
# Platform selection
#
# CONFIG_ARCH_ACTIONS is not set
# CONFIG_ARCH_AIROHA is not set
CONFIG_ARCH_SUNXI=y
# CONFIG_ARCH_ALPINE is not set
CONFIG_ARCH_APPLE=y
# CONFIG_ARCH_AXIADO is not set
CONFIG_ARCH_BCM=y
CONFIG_ARCH_BCM2835=y
# CONFIG_ARCH_BCM_IPROC is not set
# CONFIG_ARCH_BCMBCA is not set
# CONFIG_ARCH_BRCMSTB is not set
# CONFIG_ARCH_BERLIN is not set
# CONFIG_ARCH_BITMAIN is not set
# CONFIG_ARCH_BLAIZE is not set
# CONFIG_ARCH_CIX is not set
# CONFIG_ARCH_EXYNOS is not set
# CONFIG_ARCH_SPARX5 is not set
CONFIG_ARCH_K3=y
# CONFIG_ARCH_LG1K is not set
CONFIG_ARCH_HISI=y
# CONFIG_ARCH_KEEMBAY is not set
# CONFIG_ARCH_MEDIATEK is not set
CONFIG_ARCH_MESON=y
# CONFIG_ARCH_MMP is not set
CONFIG_ARCH_MVEBU=y
CONFIG_ARCH_NXP=y
CONFIG_ARCH_LAYERSCAPE=y
CONFIG_ARCH_MXC=y
CONFIG_ARCH_S32=y
# CONFIG_ARCH_MA35 is not set
# CONFIG_ARCH_NPCM is not set
# CONFIG_ARCH_PENSANDO is not set
CONFIG_ARCH_QCOM=y
# CONFIG_ARCH_REALTEK is not set
CONFIG_ARCH_RENESAS=y
CONFIG_ARCH_ROCKCHIP=y
CONFIG_ARCH_SEATTLE=y
# CONFIG_ARCH_INTEL_SOCFPGA is not set
# CONFIG_ARCH_SOPHGO is not set
# CONFIG_ARCH_STM32 is not set
CONFIG_ARCH_SYNQUACER=y
CONFIG_ARCH_TEGRA=y
# CONFIG_ARCH_SPRD is not set
CONFIG_ARCH_THUNDER=y
CONFIG_ARCH_THUNDER2=y
# CONFIG_ARCH_UNIPHIER is not set
CONFIG_ARCH_VEXPRESS=y
# CONFIG_ARCH_VISCONTI is not set
CONFIG_ARCH_XGENE=y
CONFIG_ARCH_ZYNQMP=y
# end of Platform selection

#
# Kernel Features
#

#
# ARM errata workarounds via the alternatives framework
#
CONFIG_AMPERE_ERRATUM_AC03_CPU_38=y
CONFIG_AMPERE_ERRATUM_AC04_CPU_23=y
CONFIG_ARM64_WORKAROUND_CLEAN_CACHE=y
CONFIG_ARM64_ERRATUM_826319=y
CONFIG_ARM64_ERRATUM_827319=y
CONFIG_ARM64_ERRATUM_824069=y
CONFIG_ARM64_ERRATUM_819472=y
CONFIG_ARM64_ERRATUM_832075=y
CONFIG_ARM64_ERRATUM_834220=y
CONFIG_ARM64_ERRATUM_1742098=y
CONFIG_ARM64_ERRATUM_845719=y
CONFIG_ARM64_ERRATUM_843419=y
CONFIG_ARM64_ERRATUM_1024718=y
CONFIG_ARM64_ERRATUM_1418040=y
CONFIG_ARM64_WORKAROUND_SPECULATIVE_AT=y
CONFIG_ARM64_ERRATUM_1165522=y
CONFIG_ARM64_ERRATUM_1319367=y
CONFIG_ARM64_ERRATUM_1530923=y
CONFIG_ARM64_WORKAROUND_REPEAT_TLBI=y
CONFIG_ARM64_ERRATUM_2441007=y
CONFIG_ARM64_ERRATUM_1286807=y
CONFIG_ARM64_ERRATUM_1463225=y
CONFIG_ARM64_ERRATUM_1542419=y
CONFIG_ARM64_ERRATUM_1508412=y
CONFIG_ARM64_WORKAROUND_TRBE_OVERWRITE_FILL_MODE=y
CONFIG_ARM64_ERRATUM_2051678=y
CONFIG_ARM64_ERRATUM_2077057=y
CONFIG_ARM64_ERRATUM_2658417=y
CONFIG_ARM64_ERRATUM_2119858=y
CONFIG_ARM64_ERRATUM_2139208=y
CONFIG_ARM64_WORKAROUND_TSB_FLUSH_FAILURE=y
CONFIG_ARM64_ERRATUM_2054223=y
CONFIG_ARM64_ERRATUM_2067961=y
CONFIG_ARM64_WORKAROUND_TRBE_WRITE_OUT_OF_RANGE=y
CONFIG_ARM64_ERRATUM_2253138=y
CONFIG_ARM64_ERRATUM_2224489=y
CONFIG_ARM64_ERRATUM_2441009=y
CONFIG_ARM64_ERRATUM_2064142=y
CONFIG_ARM64_ERRATUM_2038923=y
CONFIG_ARM64_ERRATUM_1902691=y
CONFIG_ARM64_ERRATUM_2457168=y
CONFIG_ARM64_ERRATUM_2645198=y
CONFIG_ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD=y
CONFIG_ARM64_ERRATUM_2966298=y
CONFIG_ARM64_ERRATUM_3117295=y
CONFIG_ARM64_ERRATUM_3194386=y
CONFIG_CAVIUM_ERRATUM_22375=y
CONFIG_CAVIUM_ERRATUM_23144=y
CONFIG_CAVIUM_ERRATUM_23154=y
CONFIG_CAVIUM_ERRATUM_27456=y
CONFIG_CAVIUM_ERRATUM_30115=y
CONFIG_CAVIUM_TX2_ERRATUM_219=y
CONFIG_FUJITSU_ERRATUM_010001=y
CONFIG_HISILICON_ERRATUM_161600802=y
CONFIG_HISILICON_ERRATUM_162100801=y
# CONFIG_QCOM_FALKOR_ERRATUM_1003 is not set
CONFIG_QCOM_FALKOR_ERRATUM_1009=y
CONFIG_QCOM_QDF2400_ERRATUM_0065=y
CONFIG_QCOM_FALKOR_ERRATUM_E1041=y
CONFIG_NVIDIA_CARMEL_CNP_ERRATUM=y
CONFIG_ROCKCHIP_ERRATUM_3568002=y
CONFIG_ROCKCHIP_ERRATUM_3588001=y
CONFIG_SOCIONEXT_SYNQUACER_PREITS=y
# end of ARM errata workarounds via the alternatives framework

CONFIG_ARM64_4K_PAGES=y
# CONFIG_ARM64_16K_PAGES is not set
# CONFIG_ARM64_64K_PAGES is not set
# CONFIG_ARM64_VA_BITS_39 is not set
CONFIG_ARM64_VA_BITS_48=y
# CONFIG_ARM64_VA_BITS_52 is not set
CONFIG_ARM64_VA_BITS=48
CONFIG_ARM64_PA_BITS_48=y
CONFIG_ARM64_PA_BITS=48
# CONFIG_CPU_BIG_ENDIAN is not set
CONFIG_CPU_LITTLE_ENDIAN=y
CONFIG_SCHED_MC=y
# CONFIG_SCHED_CLUSTER is not set
CONFIG_SCHED_SMT=y
CONFIG_NR_CPUS=4096
CONFIG_HOTPLUG_CPU=y
CONFIG_NUMA=y
CONFIG_NODES_SHIFT=9
# CONFIG_HZ_100 is not set
# CONFIG_HZ_250 is not set
# CONFIG_HZ_300 is not set
CONFIG_HZ_1000=y
CONFIG_HZ=1000
CONFIG_SCHED_HRTICK=y
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_HW_PERF_EVENTS=y
CONFIG_CC_HAVE_SHADOW_CALL_STACK=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_TIME_ACCOUNTING=y
CONFIG_ARCH_SUPPORTS_KEXEC=y
CONFIG_ARCH_SUPPORTS_KEXEC_FILE=y
CONFIG_ARCH_SELECTS_KEXEC_FILE=y
CONFIG_ARCH_SUPPORTS_KEXEC_SIG=y
CONFIG_ARCH_SUPPORTS_KEXEC_IMAGE_VERIFY_SIG=y
CONFIG_ARCH_DEFAULT_KEXEC_IMAGE_VERIFY_SIG=y
CONFIG_ARCH_SUPPORTS_KEXEC_HANDOVER=y
CONFIG_ARCH_SUPPORTS_CRASH_DUMP=y
CONFIG_ARCH_DEFAULT_CRASH_DUMP=y
CONFIG_ARCH_HAS_GENERIC_CRASHKERNEL_RESERVATION=y
CONFIG_TRANS_TABLE=y
# CONFIG_XEN is not set
CONFIG_ARCH_FORCE_MAX_ORDER=10
CONFIG_UNMAP_KERNEL_AT_EL0=y
CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY=y
CONFIG_RODATA_FULL_DEFAULT_ENABLED=y
CONFIG_ARM64_SW_TTBR0_PAN=y
CONFIG_ARM64_TAGGED_ADDR_ABI=y
CONFIG_COMPAT=y
CONFIG_KUSER_HELPERS=y
# CONFIG_COMPAT_ALIGNMENT_FIXUPS is not set
CONFIG_ARMV8_DEPRECATED=y
CONFIG_SWP_EMULATION=y
CONFIG_CP15_BARRIER_EMULATION=y
CONFIG_SETEND_EMULATION=y

#
# ARMv8.1 architectural features
#
CONFIG_ARM64_HW_AFDBM=y
CONFIG_ARM64_PAN=y
CONFIG_ARM64_LSE_ATOMICS=y
CONFIG_ARM64_USE_LSE_ATOMICS=y
# end of ARMv8.1 architectural features

#
# ARMv8.2 architectural features
#
CONFIG_ARM64_PMEM=y
CONFIG_ARM64_RAS_EXTN=y
CONFIG_ARM64_CNP=y
# end of ARMv8.2 architectural features

#
# ARMv8.3 architectural features
#
CONFIG_ARM64_PTR_AUTH=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y
CONFIG_CC_HAS_BRANCH_PROT_PAC_RET=y
CONFIG_AS_HAS_CFI_NEGATE_RA_STATE=y
# end of ARMv8.3 architectural features

#
# ARMv8.4 architectural features
#
CONFIG_ARM64_AMU_EXTN=y
CONFIG_ARM64_TLB_RANGE=y
# end of ARMv8.4 architectural features

#
# ARMv8.5 architectural features
#
CONFIG_AS_HAS_ARMV8_5=y
CONFIG_ARM64_BTI=y
CONFIG_CC_HAS_BRANCH_PROT_PAC_RET_BTI=y
CONFIG_ARM64_E0PD=y
CONFIG_ARM64_AS_HAS_MTE=y
CONFIG_ARM64_MTE=y
# end of ARMv8.5 architectural features

#
# ARMv8.7 architectural features
#
CONFIG_ARM64_EPAN=y
# end of ARMv8.7 architectural features

CONFIG_AS_HAS_MOPS=y

#
# ARMv8.9 architectural features
#
CONFIG_ARM64_POE=y
CONFIG_ARCH_PKEY_BITS=3
CONFIG_ARM64_HAFT=y
# end of ARMv8.9 architectural features

#
# v9.4 architectural features
#
# end of v9.4 architectural features

CONFIG_ARM64_SVE=y
CONFIG_ARM64_SME=y
CONFIG_ARM64_PSEUDO_NMI=y
# CONFIG_ARM64_DEBUG_PRIORITY_MASKING is not set
CONFIG_RELOCATABLE=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MODULE_REGION_FULL=y
CONFIG_CC_HAVE_STACKPROTECTOR_SYSREG=y
CONFIG_STACKPROTECTOR_PER_TASK=y
CONFIG_ARM64_CONTPTE=y
# end of Kernel Features

#
# Boot options
#
CONFIG_ARM64_ACPI_PARKING_PROTOCOL=y
CONFIG_CMDLINE=""
CONFIG_EFI_STUB=y
CONFIG_EFI=y
CONFIG_COMPRESSED_INSTALL=y
CONFIG_DMI=y
# end of Boot options

#
# Power management options
#
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
# CONFIG_SUSPEND_SKIP_SYNC is not set
CONFIG_HIBERNATE_CALLBACKS=y
CONFIG_HIBERNATION=y
CONFIG_HIBERNATION_SNAPSHOT_DEV=y
CONFIG_HIBERNATION_COMP_LZO=y
# CONFIG_HIBERNATION_COMP_LZ4 is not set
CONFIG_HIBERNATION_DEF_COMP="lzo"
CONFIG_PM_STD_PARTITION=""
CONFIG_PM_SLEEP=y
CONFIG_PM_SLEEP_SMP=y
# CONFIG_PM_AUTOSLEEP is not set
# CONFIG_PM_USERSPACE_AUTOSLEEP is not set
# CONFIG_PM_WAKELOCKS is not set
CONFIG_PM=y
CONFIG_PM_DEBUG=y
# CONFIG_PM_ADVANCED_DEBUG is not set
CONFIG_PM_TEST_SUSPEND=y
CONFIG_PM_SLEEP_DEBUG=y
# CONFIG_DPM_WATCHDOG is not set
CONFIG_PM_CLK=y
CONFIG_PM_GENERIC_DOMAINS=y
# CONFIG_WQ_POWER_EFFICIENT_DEFAULT is not set
CONFIG_PM_GENERIC_DOMAINS_SLEEP=y
CONFIG_PM_GENERIC_DOMAINS_OF=y
CONFIG_CPU_PM=y
CONFIG_ENERGY_MODEL=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_HIBERNATION_HEADER=y
CONFIG_ARCH_SUSPEND_POSSIBLE=y
# end of Power management options

#
# CPU Power Management
#

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
CONFIG_CPU_IDLE_MULTIPLE_DRIVERS=y
# CONFIG_CPU_IDLE_GOV_LADDER is not set
CONFIG_CPU_IDLE_GOV_MENU=y
# CONFIG_CPU_IDLE_GOV_TEO is not set
CONFIG_DT_IDLE_STATES=y
CONFIG_DT_IDLE_GENPD=y

#
# ARM CPU Idle Drivers
#
CONFIG_ARM_PSCI_CPUIDLE=y
CONFIG_ARM_PSCI_CPUIDLE_DOMAIN=y
# end of ARM CPU Idle Drivers
# end of CPU Idle

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
CONFIG_CPU_FREQ_STAT=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_ONDEMAND is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_CONSERVATIVE is not set
CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=y
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y

#
# CPU frequency scaling drivers
#
CONFIG_CPUFREQ_DT=m
CONFIG_CPUFREQ_VIRT=m
CONFIG_CPUFREQ_DT_PLATDEV=y
CONFIG_ARM_ALLWINNER_SUN50I_CPUFREQ_NVMEM=m
CONFIG_ARM_APPLE_SOC_CPUFREQ=m
CONFIG_ARM_ARMADA_37XX_CPUFREQ=m
CONFIG_ARM_ARMADA_8K_CPUFREQ=m
CONFIG_ARM_SCPI_CPUFREQ=m
# CONFIG_ARM_IMX6Q_CPUFREQ is not set
CONFIG_ARM_IMX_CPUFREQ_DT=m
CONFIG_ARM_QCOM_CPUFREQ_NVMEM=m
CONFIG_ARM_QCOM_CPUFREQ_HW=m
CONFIG_ARM_RASPBERRYPI_CPUFREQ=m
CONFIG_ARM_SCMI_CPUFREQ=m
# CONFIG_ARM_TEGRA20_CPUFREQ is not set
CONFIG_ARM_TEGRA124_CPUFREQ=m
CONFIG_ARM_TEGRA186_CPUFREQ=m
CONFIG_ARM_TEGRA194_CPUFREQ=m
CONFIG_ARM_TI_CPUFREQ=y
CONFIG_QORIQ_CPUFREQ=m
CONFIG_ACPI_CPPC_CPUFREQ=m
# CONFIG_ACPI_CPPC_CPUFREQ_FIE is not set
# end of CPU Frequency scaling
# end of CPU Power Management

CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_GENERIC_GSI=y
CONFIG_ACPI_CCA_REQUIRED=y
CONFIG_ACPI_TABLE_LIB=y
CONFIG_ACPI_THERMAL_LIB=y
# CONFIG_ACPI_DEBUGGER is not set
CONFIG_ACPI_SPCR_TABLE=y
CONFIG_ACPI_FPDT=y
CONFIG_ACPI_EC=y
# CONFIG_ACPI_EC_DEBUGFS is not set
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=m
CONFIG_ACPI_FAN=y
CONFIG_ACPI_TAD=m
CONFIG_ACPI_DOCK=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_MCFG=y
CONFIG_ACPI_CPPC_LIB=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_ACPI_IPMI=m
CONFIG_ACPI_HOTPLUG_CPU=y
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_PLATFORM_PROFILE=m
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_DEBUG=y
CONFIG_ACPI_PCI_SLOT=y
CONFIG_ACPI_CONTAINER=y
CONFIG_ACPI_HOTPLUG_MEMORY=y
CONFIG_ACPI_HED=y
CONFIG_ACPI_BGRT=y
CONFIG_ACPI_REDUCED_HARDWARE_ONLY=y
CONFIG_ACPI_NHLT=y
CONFIG_ACPI_NFIT=m
# CONFIG_NFIT_SECURITY_DEBUG is not set
CONFIG_ACPI_NUMA=y
CONFIG_ACPI_HMAT=y
CONFIG_HAVE_ACPI_APEI=y
CONFIG_ACPI_APEI=y
CONFIG_ACPI_APEI_GHES=y
CONFIG_ACPI_APEI_PCIEAER=y
CONFIG_ACPI_APEI_SEA=y
CONFIG_ACPI_APEI_MEMORY_FAILURE=y
CONFIG_ACPI_APEI_EINJ=m
CONFIG_ACPI_APEI_EINJ_CXL=y
# CONFIG_ACPI_APEI_ERST_DEBUG is not set
CONFIG_ACPI_WATCHDOG=y
# CONFIG_ACPI_CONFIGFS is not set
CONFIG_ACPI_PFRUT=m
CONFIG_ACPI_IORT=y
CONFIG_ACPI_GTDT=y
CONFIG_ACPI_AGDI=y
CONFIG_ACPI_APMT=y
CONFIG_ACPI_PPTT=y
CONFIG_ACPI_PCC=y
CONFIG_ACPI_FFH=y
# CONFIG_PMIC_OPREGION is not set
CONFIG_ACPI_VIOT=y
CONFIG_ACPI_PRMT=y
CONFIG_KVM_COMMON=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_DIRTY_RING=y
CONFIG_HAVE_KVM_DIRTY_RING_ACQ_REL=y
CONFIG_NEED_KVM_DIRTY_RING_WITH_BITMAP=y
CONFIG_KVM_MMIO=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_HAVE_KVM_READONLY_MEM=y
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_KVM_VFIO=y
CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT=y
CONFIG_HAVE_KVM_IRQ_BYPASS=y
CONFIG_HAVE_KVM_VCPU_RUN_PID_CHANGE=y
CONFIG_KVM_XFER_TO_GUEST_WORK=y
CONFIG_KVM_GENERIC_HARDWARE_ENABLING=y
CONFIG_KVM_GENERIC_MMU_NOTIFIER=y
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=y
# CONFIG_NVHE_EL2_DEBUG is not set
# CONFIG_PTDUMP_STAGE2_DEBUGFS is not set
CONFIG_HAVE_LIVEPATCH=y
# CONFIG_LIVEPATCH is not set
CONFIG_CPU_MITIGATIONS=y

#
# General architecture-dependent options
#
CONFIG_ARCH_HAS_SUBPAGE_FAULTS=y
CONFIG_HOTPLUG_SMT=y
CONFIG_HOTPLUG_CORE_SYNC=y
CONFIG_HOTPLUG_CORE_SYNC_DEAD=y
CONFIG_KPROBES=y
CONFIG_JUMP_LABEL=y
# CONFIG_STATIC_KEYS_SELFTEST is not set
CONFIG_UPROBES=y
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_KRETPROBES=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_TRACE_IRQFLAGS_NMI_SUPPORT=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_GENERIC_IDLE_POLL_SETUP=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_KEEPINITRD=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_SET_DIRECT_MAP=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_NO_INSTR=y
CONFIG_HAVE_ASM_MODVERSIONS=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_RUST=y
CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=y
CONFIG_MMU_GATHER_TABLE_FREE=y
CONFIG_MMU_GATHER_RCU_TABLE_FREE=y
CONFIG_MMU_LAZY_TLB_REFCOUNT=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_ARCH_HAS_NMI_SAFE_THIS_CPU_OPS=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_HAVE_ARCH_SECCOMP=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
# CONFIG_SECCOMP_CACHE_DEBUG is not set
CONFIG_HAVE_ARCH_KSTACK_ERASE=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK=y
# CONFIG_SHADOW_CALL_STACK is not set
CONFIG_ARCH_SUPPORTS_LTO_CLANG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=y
CONFIG_LTO_NONE=y
CONFIG_ARCH_SUPPORTS_CFI_CLANG=y
CONFIG_HAVE_CONTEXT_TRACKING_USER=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_MOVE_PUD=y
CONFIG_HAVE_MOVE_PMD=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_HAVE_ARCH_HUGE_VMALLOC=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_ARCH_WANT_PMD_MKWRITE=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_ARCH_WANTS_EXECMEM_LATE=y
CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK=y
CONFIG_SOFTIRQ_ON_OWN_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_ARCH_MMAP_RND_BITS=18
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=11
CONFIG_HAVE_PAGE_SIZE_4KB=y
CONFIG_PAGE_SIZE_4KB=y
CONFIG_PAGE_SIZE_LESS_THAN_64KB=y
CONFIG_PAGE_SIZE_LESS_THAN_256KB=y
CONFIG_PAGE_SHIFT=12
CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_CLONE_BACKWARDS=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_ARCH_SUPPORTS_RT=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_VMAP_STACK=y
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HAVE_ARCH_COMPILER_H=y
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y
# CONFIG_LOCK_EVENT_COUNTS is not set
CONFIG_ARCH_HAS_RELR=y
# CONFIG_RELR is not set
CONFIG_ARCH_HAS_MEM_ENCRYPT=y
CONFIG_ARCH_HAS_CC_PLATFORM=y
CONFIG_HAVE_PREEMPT_DYNAMIC=y
CONFIG_HAVE_PREEMPT_DYNAMIC_KEY=y
CONFIG_ARCH_WANT_LD_ORPHAN_WARN=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_ARCH_SUPPORTS_PAGE_TABLE_CHECK=y
CONFIG_ARCH_HAVE_TRACE_MMIO_ACCESS=y
CONFIG_ARCH_HAS_HW_PTE_YOUNG=y
CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG=y
CONFIG_ARCH_HAS_KERNEL_FPU_SUPPORT=y

#
# GCOV-based kernel profiling
#
# CONFIG_GCOV_KERNEL is not set
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
# end of GCOV-based kernel profiling

CONFIG_HAVE_GCC_PLUGINS=y
CONFIG_FUNCTION_ALIGNMENT_4B=y
CONFIG_FUNCTION_ALIGNMENT_8B=y
CONFIG_FUNCTION_ALIGNMENT=8
CONFIG_CC_HAS_MIN_FUNCTION_ALIGNMENT=y
CONFIG_CC_HAS_SANE_FUNCTION_ALIGNMENT=y
# end of General architecture-dependent options

CONFIG_RT_MUTEXES=y
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULES=y
CONFIG_MODULE_DEBUGFS=y
# CONFIG_MODULE_DEBUG is not set
# CONFIG_MODULE_FORCE_LOAD is not set
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_FORCE_UNLOAD is not set
CONFIG_MODULE_UNLOAD_TAINT_TRACKING=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_SHA1 is not set
# CONFIG_MODULE_SIG_SHA256 is not set
# CONFIG_MODULE_SIG_SHA384 is not set
CONFIG_MODULE_SIG_SHA512=y
# CONFIG_MODULE_SIG_SHA3_256 is not set
# CONFIG_MODULE_SIG_SHA3_384 is not set
# CONFIG_MODULE_SIG_SHA3_512 is not set
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_MODULE_COMPRESS=y
# CONFIG_MODULE_COMPRESS_GZIP is not set
CONFIG_MODULE_COMPRESS_XZ=y
# CONFIG_MODULE_COMPRESS_ZSTD is not set
# CONFIG_MODULE_COMPRESS_ALL is not set
CONFIG_MODULE_DECOMPRESS=y
# CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS is not set
CONFIG_MODPROBE_PATH="/usr/sbin/modprobe"
# CONFIG_TRIM_UNUSED_KSYMS is not set
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLOCK_LEGACY_AUTOLOAD=y
CONFIG_BLK_RQ_ALLOC_TIME=y
CONFIG_BLK_CGROUP_RWSTAT=y
CONFIG_BLK_CGROUP_PUNT_BIO=y
CONFIG_BLK_DEV_BSG_COMMON=y
CONFIG_BLK_ICQ=y
CONFIG_BLK_DEV_BSGLIB=y
CONFIG_BLK_DEV_INTEGRITY=y
CONFIG_BLK_DEV_WRITE_MOUNTED=y
CONFIG_BLK_DEV_ZONED=y
CONFIG_BLK_DEV_THROTTLING=y
CONFIG_BLK_WBT=y
CONFIG_BLK_WBT_MQ=y
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_FC_APPID=y
CONFIG_BLK_CGROUP_IOCOST=y
CONFIG_BLK_CGROUP_IOPRIO=y
CONFIG_BLK_DEBUG_FS=y
CONFIG_BLK_SED_OPAL=y
CONFIG_BLK_INLINE_ENCRYPTION=y
# CONFIG_BLK_INLINE_ENCRYPTION_FALLBACK is not set

#
# Partition Types
#
CONFIG_PARTITION_ADVANCED=y
# CONFIG_ACORN_PARTITION is not set
CONFIG_AIX_PARTITION=y
CONFIG_OSF_PARTITION=y
# CONFIG_AMIGA_PARTITION is not set
# CONFIG_ATARI_PARTITION is not set
CONFIG_MAC_PARTITION=y
CONFIG_MSDOS_PARTITION=y
CONFIG_BSD_DISKLABEL=y
CONFIG_MINIX_SUBPARTITION=y
CONFIG_SOLARIS_X86_PARTITION=y
CONFIG_UNIXWARE_DISKLABEL=y
CONFIG_LDM_PARTITION=y
# CONFIG_LDM_DEBUG is not set
CONFIG_SGI_PARTITION=y
# CONFIG_ULTRIX_PARTITION is not set
CONFIG_SUN_PARTITION=y
# CONFIG_KARMA_PARTITION is not set
CONFIG_EFI_PARTITION=y
# CONFIG_SYSV68_PARTITION is not set
# CONFIG_CMDLINE_PARTITION is not set
CONFIG_OF_PARTITION=y
# end of Partition Types

CONFIG_BLK_PM=y
CONFIG_BLOCK_HOLDER_DEPRECATED=y
CONFIG_BLK_MQ_STACKING=y

#
# IO Schedulers
#
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
CONFIG_IOSCHED_BFQ=y
CONFIG_BFQ_GROUP_IOSCHED=y
# CONFIG_BFQ_CGROUP_DEBUG is not set
# end of IO Schedulers

CONFIG_PREEMPT_NOTIFIERS=y
CONFIG_PADATA=y
CONFIG_ASN1=y
CONFIG_UNINLINE_SPIN_UNLOCK=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_MUTEX_SPIN_ON_OWNER=y
CONFIG_RWSEM_SPIN_ON_OWNER=y
CONFIG_LOCK_SPIN_ON_OWNER=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ARCH_BINFMT_ELF_STATE=y
CONFIG_ARCH_BINFMT_ELF_EXTRA_PHDRS=y
CONFIG_ARCH_HAVE_ELF_PROT=y
CONFIG_ARCH_USE_GNU_PROPERTY=y
CONFIG_ELFCORE=y
CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=m
CONFIG_COREDUMP=y
# end of Executable file formats

#
# Memory Management options
#
CONFIG_ZPOOL=y
CONFIG_SWAP=y
CONFIG_ZSWAP=y
# CONFIG_ZSWAP_DEFAULT_ON is not set
CONFIG_ZSWAP_SHRINKER_DEFAULT_ON=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_DEFLATE is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZO=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_842 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4HC is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_ZSTD is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT="lzo"
CONFIG_ZSWAP_ZPOOL_DEFAULT_ZSMALLOC=y
CONFIG_ZSWAP_ZPOOL_DEFAULT="zsmalloc"
CONFIG_ZSMALLOC=y
# CONFIG_ZSMALLOC_STAT is not set
CONFIG_ZSMALLOC_CHAIN_SIZE=8

#
# Slab allocator options
#
CONFIG_SLUB=y
CONFIG_KVFREE_RCU_BATCHED=y
# CONFIG_SLUB_TINY is not set
# CONFIG_SLAB_MERGE_DEFAULT is not set
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_BUCKETS=y
# CONFIG_SLUB_STATS is not set
CONFIG_SLUB_CPU_PARTIAL=y
CONFIG_RANDOM_KMALLOC_CACHES=y
# end of Slab allocator options

CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
# CONFIG_COMPAT_BRK is not set
CONFIG_SPARSEMEM=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_GUP_FAST=y
CONFIG_ARCH_KEEP_MEMBLOCK=y
CONFIG_NUMA_KEEP_MEMINFO=y
CONFIG_MEMORY_ISOLATION=y
CONFIG_EXCLUSIVE_SYSTEM_RAM=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
CONFIG_MEMORY_HOTPLUG=y
# CONFIG_MHP_DEFAULT_ONLINE_TYPE_OFFLINE is not set
CONFIG_MHP_DEFAULT_ONLINE_TYPE_ONLINE_AUTO=y
# CONFIG_MHP_DEFAULT_ONLINE_TYPE_ONLINE_KERNEL is not set
# CONFIG_MHP_DEFAULT_ONLINE_TYPE_ONLINE_MOVABLE is not set
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_MHP_MEMMAP_ON_MEMORY=y
CONFIG_ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE=y
CONFIG_SPLIT_PTE_PTLOCKS=y
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y
CONFIG_SPLIT_PMD_PTLOCKS=y
CONFIG_MEMORY_BALLOON=y
CONFIG_BALLOON_COMPACTION=y
CONFIG_COMPACTION=y
CONFIG_COMPACT_UNEVICTABLE_DEFAULT=1
CONFIG_PAGE_REPORTING=y
CONFIG_MIGRATION=y
CONFIG_DEVICE_MIGRATION=y
CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=y
CONFIG_ARCH_ENABLE_THP_MIGRATION=y
CONFIG_CONTIG_ALLOC=y
CONFIG_PCP_BATCH_SCALE_MAX=5
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_MMU_NOTIFIER=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
CONFIG_MEMORY_FAILURE=y
CONFIG_HWPOISON_INJECT=m
CONFIG_ARCH_WANTS_THP_SWAP=y
CONFIG_MM_ID=y
CONFIG_TRANSPARENT_HUGEPAGE=y
# CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS is not set
CONFIG_TRANSPARENT_HUGEPAGE_MADVISE=y
# CONFIG_TRANSPARENT_HUGEPAGE_NEVER is not set
CONFIG_THP_SWAP=y
CONFIG_READ_ONLY_THP_FOR_FS=y
# CONFIG_NO_PAGE_MAPCOUNT is not set
CONFIG_PAGE_MAPCOUNT=y
CONFIG_PGTABLE_HAS_HUGE_LEAVES=y
CONFIG_ARCH_SUPPORTS_HUGE_PFNMAP=y
CONFIG_ARCH_SUPPORTS_PMD_PFNMAP=y
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_USE_PERCPU_NUMA_NODE_ID=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_CMA=y
# CONFIG_CMA_DEBUGFS is not set
CONFIG_CMA_SYSFS=y
CONFIG_CMA_AREAS=7
CONFIG_PAGE_BLOCK_MAX_ORDER=10
CONFIG_GENERIC_EARLY_IOREMAP=y
# CONFIG_DEFERRED_STRUCT_PAGE_INIT is not set
CONFIG_PAGE_IDLE_FLAG=y
CONFIG_IDLE_PAGE_TRACKING=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_CURRENT_STACK_POINTER=y
CONFIG_ARCH_HAS_ZONE_DMA_SET=y
CONFIG_ZONE_DMA=y
CONFIG_ZONE_DMA32=y
CONFIG_ZONE_DEVICE=y
CONFIG_HMM_MIRROR=y
CONFIG_GET_FREE_REGION=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_VMAP_PFN=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_ARCH_USES_PG_ARCH_2=y
CONFIG_ARCH_USES_PG_ARCH_3=y
CONFIG_VM_EVENT_COUNTERS=y
# CONFIG_PERCPU_STATS is not set
# CONFIG_GUP_TEST is not set
# CONFIG_DMAPOOL_TEST is not set
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_MAPPING_DIRTY_HELPERS=y
CONFIG_MEMFD_CREATE=y
CONFIG_SECRETMEM=y
# CONFIG_ANON_VMA_NAME is not set
CONFIG_HAVE_ARCH_USERFAULTFD_WP=y
CONFIG_HAVE_ARCH_USERFAULTFD_MINOR=y
CONFIG_USERFAULTFD=y
CONFIG_PTE_MARKER_UFFD_WP=y
CONFIG_LRU_GEN=y
CONFIG_LRU_GEN_ENABLED=y
# CONFIG_LRU_GEN_STATS is not set
CONFIG_LRU_GEN_WALKS_MMU=y
CONFIG_ARCH_SUPPORTS_PER_VMA_LOCK=y
CONFIG_PER_VMA_LOCK=y
CONFIG_LOCK_MM_AND_FIND_VMA=y
CONFIG_IOMMU_MM_DATA=y
CONFIG_EXECMEM=y
CONFIG_NUMA_MEMBLKS=y
# CONFIG_NUMA_EMU is not set

#
# Data Access Monitoring
#
CONFIG_DAMON=y
CONFIG_DAMON_VADDR=y
CONFIG_DAMON_PADDR=y
CONFIG_DAMON_SYSFS=y
CONFIG_DAMON_RECLAIM=y
# CONFIG_DAMON_LRU_SORT is not set
# CONFIG_DAMON_STAT is not set
# CONFIG_DAMON_STAT_ENABLED_DEFAULT is not set
# end of Data Access Monitoring
# end of Memory Management options

CONFIG_NET=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_XGRESS=y
CONFIG_NET_REDIRECT=y
CONFIG_SKB_DECRYPTED=y
CONFIG_SKB_EXTENSIONS=y
CONFIG_NET_DEVMEM=y
CONFIG_NET_SHAPER=y
CONFIG_NET_CRC32C=y

#
# Networking options
#
CONFIG_PACKET=y
CONFIG_PACKET_DIAG=y
CONFIG_UNIX=y
CONFIG_AF_UNIX_OOB=y
CONFIG_UNIX_DIAG=y
CONFIG_TLS=m
CONFIG_TLS_DEVICE=y
# CONFIG_TLS_TOE is not set
CONFIG_XFRM=y
CONFIG_XFRM_OFFLOAD=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
CONFIG_XFRM_INTERFACE=m
CONFIG_XFRM_SUB_POLICY=y
CONFIG_XFRM_MIGRATE=y
CONFIG_XFRM_STATISTICS=y
CONFIG_XFRM_AH=m
CONFIG_XFRM_ESP=m
CONFIG_XFRM_IPCOMP=m
CONFIG_NET_KEY=m
CONFIG_NET_KEY_MIGRATE=y
CONFIG_XFRM_IPTFS=m
CONFIG_XFRM_ESPINTCP=y
CONFIG_SMC=m
CONFIG_SMC_DIAG=m
# CONFIG_SMC_LO is not set
CONFIG_XDP_SOCKETS=y
CONFIG_XDP_SOCKETS_DIAG=m
CONFIG_NET_HANDSHAKE=y
CONFIG_NET_HANDSHAKE_KUNIT_TEST=m
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_FIB_TRIE_STATS=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_ROUTE_CLASSID=y
# CONFIG_IP_PNP is not set
CONFIG_NET_IPIP=m
CONFIG_NET_IPGRE_DEMUX=m
CONFIG_NET_IP_TUNNEL=m
CONFIG_NET_IPGRE=m
CONFIG_NET_IPGRE_BROADCAST=y
CONFIG_IP_MROUTE_COMMON=y
CONFIG_IP_MROUTE=y
CONFIG_IP_MROUTE_MULTIPLE_TABLES=y
CONFIG_IP_PIMSM_V1=y
CONFIG_IP_PIMSM_V2=y
CONFIG_SYN_COOKIES=y
CONFIG_NET_IPVTI=m
CONFIG_NET_UDP_TUNNEL=m
CONFIG_NET_FOU=m
CONFIG_NET_FOU_IP_TUNNELS=y
CONFIG_INET_AH=m
CONFIG_INET_ESP=m
CONFIG_INET_ESP_OFFLOAD=m
CONFIG_INET_ESPINTCP=y
CONFIG_INET_IPCOMP=m
CONFIG_INET_TABLE_PERTURB_ORDER=16
CONFIG_INET_XFRM_TUNNEL=m
CONFIG_INET_TUNNEL=m
CONFIG_INET_DIAG=y
CONFIG_INET_TCP_DIAG=y
CONFIG_INET_UDP_DIAG=y
CONFIG_INET_RAW_DIAG=y
CONFIG_INET_DIAG_DESTROY=y
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BIC=m
CONFIG_TCP_CONG_CUBIC=y
CONFIG_TCP_CONG_WESTWOOD=m
CONFIG_TCP_CONG_HTCP=m
CONFIG_TCP_CONG_HSTCP=m
CONFIG_TCP_CONG_HYBLA=m
CONFIG_TCP_CONG_VEGAS=m
CONFIG_TCP_CONG_NV=m
CONFIG_TCP_CONG_SCALABLE=m
CONFIG_TCP_CONG_LP=m
CONFIG_TCP_CONG_VENO=m
CONFIG_TCP_CONG_YEAH=m
CONFIG_TCP_CONG_ILLINOIS=m
CONFIG_TCP_CONG_DCTCP=m
CONFIG_TCP_CONG_CDG=m
CONFIG_TCP_CONG_BBR=m
CONFIG_DEFAULT_CUBIC=y
# CONFIG_DEFAULT_RENO is not set
CONFIG_DEFAULT_TCP_CONG="cubic"
CONFIG_TCP_SIGPOOL=y
CONFIG_TCP_AO=y
CONFIG_TCP_MD5SIG=y
CONFIG_IPV6=y
CONFIG_IPV6_ROUTER_PREF=y
CONFIG_IPV6_ROUTE_INFO=y
CONFIG_IPV6_OPTIMISTIC_DAD=y
CONFIG_INET6_AH=m
CONFIG_INET6_ESP=m
CONFIG_INET6_ESP_OFFLOAD=m
CONFIG_INET6_ESPINTCP=y
CONFIG_INET6_IPCOMP=m
CONFIG_IPV6_MIP6=y
CONFIG_IPV6_ILA=m
CONFIG_INET6_XFRM_TUNNEL=m
CONFIG_INET6_TUNNEL=m
CONFIG_IPV6_VTI=m
CONFIG_IPV6_SIT=m
CONFIG_IPV6_SIT_6RD=y
CONFIG_IPV6_NDISC_NODETYPE=y
CONFIG_IPV6_TUNNEL=m
CONFIG_IPV6_GRE=m
CONFIG_IPV6_FOU=m
CONFIG_IPV6_FOU_TUNNEL=m
CONFIG_IPV6_MULTIPLE_TABLES=y
CONFIG_IPV6_SUBTREES=y
CONFIG_IPV6_MROUTE=y
CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y
CONFIG_IPV6_PIMSM_V2=y
CONFIG_IPV6_SEG6_LWTUNNEL=y
CONFIG_IPV6_SEG6_HMAC=y
CONFIG_IPV6_SEG6_BPF=y
CONFIG_IPV6_RPL_LWTUNNEL=y
CONFIG_IPV6_IOAM6_LWTUNNEL=y
CONFIG_NETLABEL=y
CONFIG_MPTCP=y
CONFIG_INET_MPTCP_DIAG=y
CONFIG_MPTCP_IPV6=y
CONFIG_MPTCP_KUNIT_TEST=m
CONFIG_NETWORK_SECMARK=y
CONFIG_NET_PTP_CLASSIFY=y
CONFIG_NETWORK_PHY_TIMESTAMPING=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_BRIDGE_NETFILTER=m

#
# Core Netfilter Configuration
#
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_EGRESS=y
CONFIG_NETFILTER_SKIP_EGRESS=y
CONFIG_NETFILTER_NETLINK=m
CONFIG_NETFILTER_FAMILY_BRIDGE=y
CONFIG_NETFILTER_FAMILY_ARP=y
CONFIG_NETFILTER_BPF_LINK=y
CONFIG_NETFILTER_NETLINK_HOOK=m
CONFIG_NETFILTER_NETLINK_ACCT=m
CONFIG_NETFILTER_NETLINK_QUEUE=m
CONFIG_NETFILTER_NETLINK_LOG=m
CONFIG_NETFILTER_NETLINK_OSF=m
CONFIG_NF_CONNTRACK=m
CONFIG_NF_LOG_SYSLOG=m
CONFIG_NETFILTER_CONNCOUNT=m
CONFIG_NF_CONNTRACK_MARK=y
CONFIG_NF_CONNTRACK_SECMARK=y
CONFIG_NF_CONNTRACK_ZONES=y
CONFIG_NF_CONNTRACK_PROCFS=y
CONFIG_NF_CONNTRACK_EVENTS=y
CONFIG_NF_CONNTRACK_TIMEOUT=y
CONFIG_NF_CONNTRACK_TIMESTAMP=y
CONFIG_NF_CONNTRACK_LABELS=y
CONFIG_NF_CONNTRACK_OVS=y
CONFIG_NF_CT_PROTO_GRE=y
CONFIG_NF_CT_PROTO_SCTP=y
CONFIG_NF_CT_PROTO_UDPLITE=y
CONFIG_NF_CONNTRACK_AMANDA=m
CONFIG_NF_CONNTRACK_FTP=m
CONFIG_NF_CONNTRACK_H323=m
CONFIG_NF_CONNTRACK_IRC=m
CONFIG_NF_CONNTRACK_BROADCAST=m
CONFIG_NF_CONNTRACK_NETBIOS_NS=m
CONFIG_NF_CONNTRACK_SNMP=m
CONFIG_NF_CONNTRACK_PPTP=m
CONFIG_NF_CONNTRACK_SANE=m
CONFIG_NF_CONNTRACK_SIP=m
CONFIG_NF_CONNTRACK_TFTP=m
CONFIG_NF_CT_NETLINK=m
CONFIG_NF_CT_NETLINK_TIMEOUT=m
CONFIG_NF_CT_NETLINK_HELPER=m
CONFIG_NETFILTER_NETLINK_GLUE_CT=y
CONFIG_NF_NAT=m
CONFIG_NF_NAT_AMANDA=m
CONFIG_NF_NAT_FTP=m
CONFIG_NF_NAT_IRC=m
CONFIG_NF_NAT_SIP=m
CONFIG_NF_NAT_TFTP=m
CONFIG_NF_NAT_REDIRECT=y
CONFIG_NF_NAT_MASQUERADE=y
CONFIG_NF_NAT_OVS=y
CONFIG_NETFILTER_SYNPROXY=m
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_NETDEV=y
CONFIG_NFT_NUMGEN=m
CONFIG_NFT_CT=m
# CONFIG_NFT_EXTHDR_DCCP is not set
CONFIG_NFT_FLOW_OFFLOAD=m
CONFIG_NFT_CONNLIMIT=m
CONFIG_NFT_LOG=m
CONFIG_NFT_LIMIT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_REDIR=m
CONFIG_NFT_NAT=m
CONFIG_NFT_TUNNEL=m
CONFIG_NFT_QUEUE=m
CONFIG_NFT_QUOTA=m
CONFIG_NFT_REJECT=m
CONFIG_NFT_REJECT_INET=m
CONFIG_NFT_COMPAT=m
CONFIG_NFT_HASH=m
CONFIG_NFT_FIB=m
CONFIG_NFT_FIB_INET=m
CONFIG_NFT_XFRM=m
CONFIG_NFT_SOCKET=m
# CONFIG_NFT_OSF is not set
CONFIG_NFT_TPROXY=m
CONFIG_NFT_SYNPROXY=m
CONFIG_NF_DUP_NETDEV=m
CONFIG_NFT_DUP_NETDEV=m
CONFIG_NFT_FWD_NETDEV=m
CONFIG_NFT_FIB_NETDEV=m
CONFIG_NFT_REJECT_NETDEV=m
CONFIG_NF_FLOW_TABLE_INET=m
CONFIG_NF_FLOW_TABLE=m
CONFIG_NF_FLOW_TABLE_PROCFS=y
CONFIG_NETFILTER_XTABLES=y
# CONFIG_NETFILTER_XTABLES_COMPAT is not set
# CONFIG_NETFILTER_XTABLES_LEGACY is not set

#
# Xtables combined modules
#
CONFIG_NETFILTER_XT_MARK=m
CONFIG_NETFILTER_XT_CONNMARK=m
CONFIG_NETFILTER_XT_SET=m

#
# Xtables targets
#
CONFIG_NETFILTER_XT_TARGET_AUDIT=m
CONFIG_NETFILTER_XT_TARGET_CHECKSUM=m
CONFIG_NETFILTER_XT_TARGET_CLASSIFY=m
CONFIG_NETFILTER_XT_TARGET_CONNMARK=m
CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=m
CONFIG_NETFILTER_XT_TARGET_CT=m
CONFIG_NETFILTER_XT_TARGET_DSCP=m
CONFIG_NETFILTER_XT_TARGET_HL=m
CONFIG_NETFILTER_XT_TARGET_HMARK=m
CONFIG_NETFILTER_XT_TARGET_IDLETIMER=m
CONFIG_NETFILTER_XT_TARGET_LED=m
CONFIG_NETFILTER_XT_TARGET_LOG=m
CONFIG_NETFILTER_XT_TARGET_MARK=m
CONFIG_NETFILTER_XT_NAT=m
CONFIG_NETFILTER_XT_TARGET_NETMAP=m
CONFIG_NETFILTER_XT_TARGET_NFLOG=m
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m
CONFIG_NETFILTER_XT_TARGET_RATEEST=m
CONFIG_NETFILTER_XT_TARGET_REDIRECT=m
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=m
CONFIG_NETFILTER_XT_TARGET_TEE=m
CONFIG_NETFILTER_XT_TARGET_TPROXY=m
CONFIG_NETFILTER_XT_TARGET_SECMARK=m
CONFIG_NETFILTER_XT_TARGET_TCPMSS=m
CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP=m

#
# Xtables matches
#
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=m
CONFIG_NETFILTER_XT_MATCH_BPF=m
CONFIG_NETFILTER_XT_MATCH_CGROUP=m
CONFIG_NETFILTER_XT_MATCH_CLUSTER=m
CONFIG_NETFILTER_XT_MATCH_COMMENT=m
CONFIG_NETFILTER_XT_MATCH_CONNBYTES=m
CONFIG_NETFILTER_XT_MATCH_CONNLABEL=m
CONFIG_NETFILTER_XT_MATCH_CONNLIMIT=m
CONFIG_NETFILTER_XT_MATCH_CONNMARK=m
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=m
CONFIG_NETFILTER_XT_MATCH_CPU=m
CONFIG_NETFILTER_XT_MATCH_DCCP=m
CONFIG_NETFILTER_XT_MATCH_DEVGROUP=m
CONFIG_NETFILTER_XT_MATCH_DSCP=m
CONFIG_NETFILTER_XT_MATCH_ECN=m
CONFIG_NETFILTER_XT_MATCH_ESP=m
CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=m
CONFIG_NETFILTER_XT_MATCH_HELPER=m
CONFIG_NETFILTER_XT_MATCH_HL=m
CONFIG_NETFILTER_XT_MATCH_IPCOMP=m
CONFIG_NETFILTER_XT_MATCH_IPRANGE=m
CONFIG_NETFILTER_XT_MATCH_IPVS=m
CONFIG_NETFILTER_XT_MATCH_L2TP=m
CONFIG_NETFILTER_XT_MATCH_LENGTH=m
CONFIG_NETFILTER_XT_MATCH_LIMIT=m
CONFIG_NETFILTER_XT_MATCH_MAC=m
CONFIG_NETFILTER_XT_MATCH_MARK=m
CONFIG_NETFILTER_XT_MATCH_MULTIPORT=m
CONFIG_NETFILTER_XT_MATCH_NFACCT=m
CONFIG_NETFILTER_XT_MATCH_OSF=m
CONFIG_NETFILTER_XT_MATCH_OWNER=m
CONFIG_NETFILTER_XT_MATCH_POLICY=m
CONFIG_NETFILTER_XT_MATCH_PHYSDEV=m
CONFIG_NETFILTER_XT_MATCH_PKTTYPE=m
CONFIG_NETFILTER_XT_MATCH_QUOTA=m
CONFIG_NETFILTER_XT_MATCH_RATEEST=m
CONFIG_NETFILTER_XT_MATCH_REALM=m
CONFIG_NETFILTER_XT_MATCH_RECENT=m
CONFIG_NETFILTER_XT_MATCH_SCTP=m
CONFIG_NETFILTER_XT_MATCH_SOCKET=m
CONFIG_NETFILTER_XT_MATCH_STATE=m
CONFIG_NETFILTER_XT_MATCH_STATISTIC=m
CONFIG_NETFILTER_XT_MATCH_STRING=m
CONFIG_NETFILTER_XT_MATCH_TCPMSS=m
CONFIG_NETFILTER_XT_MATCH_TIME=m
CONFIG_NETFILTER_XT_MATCH_U32=m
# end of Core Netfilter Configuration

CONFIG_IP_SET=m
CONFIG_IP_SET_MAX=256
CONFIG_IP_SET_BITMAP_IP=m
CONFIG_IP_SET_BITMAP_IPMAC=m
CONFIG_IP_SET_BITMAP_PORT=m
CONFIG_IP_SET_HASH_IP=m
CONFIG_IP_SET_HASH_IPMARK=m
CONFIG_IP_SET_HASH_IPPORT=m
CONFIG_IP_SET_HASH_IPPORTIP=m
CONFIG_IP_SET_HASH_IPPORTNET=m
CONFIG_IP_SET_HASH_IPMAC=m
CONFIG_IP_SET_HASH_MAC=m
CONFIG_IP_SET_HASH_NETPORTNET=m
CONFIG_IP_SET_HASH_NET=m
CONFIG_IP_SET_HASH_NETNET=m
CONFIG_IP_SET_HASH_NETPORT=m
CONFIG_IP_SET_HASH_NETIFACE=m
CONFIG_IP_SET_LIST_SET=m
CONFIG_IP_VS=m
CONFIG_IP_VS_IPV6=y
# CONFIG_IP_VS_DEBUG is not set
CONFIG_IP_VS_TAB_BITS=12

#
# IPVS transport protocol load balancing support
#
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_PROTO_AH_ESP=y
CONFIG_IP_VS_PROTO_ESP=y
CONFIG_IP_VS_PROTO_AH=y
CONFIG_IP_VS_PROTO_SCTP=y

#
# IPVS scheduler
#
CONFIG_IP_VS_RR=m
CONFIG_IP_VS_WRR=m
CONFIG_IP_VS_LC=m
CONFIG_IP_VS_WLC=m
CONFIG_IP_VS_FO=m
CONFIG_IP_VS_OVF=m
CONFIG_IP_VS_LBLC=m
CONFIG_IP_VS_LBLCR=m
CONFIG_IP_VS_DH=m
CONFIG_IP_VS_SH=m
CONFIG_IP_VS_MH=m
CONFIG_IP_VS_SED=m
CONFIG_IP_VS_NQ=m
CONFIG_IP_VS_TWOS=m

#
# IPVS SH scheduler
#
CONFIG_IP_VS_SH_TAB_BITS=8

#
# IPVS MH scheduler
#
CONFIG_IP_VS_MH_TAB_INDEX=12

#
# IPVS application helper
#
CONFIG_IP_VS_FTP=m
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PE_SIP=m

#
# IP: Netfilter Configuration
#
CONFIG_NF_DEFRAG_IPV4=m
CONFIG_NF_SOCKET_IPV4=m
CONFIG_NF_TPROXY_IPV4=m
CONFIG_NF_TABLES_IPV4=y
CONFIG_NFT_REJECT_IPV4=m
CONFIG_NFT_DUP_IPV4=m
CONFIG_NFT_FIB_IPV4=m
CONFIG_NF_TABLES_ARP=y
CONFIG_NF_DUP_IPV4=m
CONFIG_NF_LOG_ARP=m
CONFIG_NF_LOG_IPV4=m
CONFIG_NF_REJECT_IPV4=m
CONFIG_NF_NAT_SNMP_BASIC=m
CONFIG_NF_NAT_PPTP=m
CONFIG_NF_NAT_H323=m
CONFIG_IP_NF_IPTABLES=m
CONFIG_IP_NF_MATCH_AH=m
CONFIG_IP_NF_MATCH_ECN=m
CONFIG_IP_NF_MATCH_RPFILTER=m
CONFIG_IP_NF_MATCH_TTL=m
CONFIG_IP_NF_TARGET_REJECT=m
CONFIG_IP_NF_TARGET_SYNPROXY=m
CONFIG_IP_NF_TARGET_ECN=m
CONFIG_NFT_COMPAT_ARP=m
CONFIG_IP_NF_ARP_MANGLE=m
# end of IP: Netfilter Configuration

#
# IPv6: Netfilter Configuration
#
CONFIG_NF_SOCKET_IPV6=m
CONFIG_NF_TPROXY_IPV6=m
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_REJECT_IPV6=m
CONFIG_NFT_DUP_IPV6=m
CONFIG_NFT_FIB_IPV6=m
CONFIG_NF_DUP_IPV6=m
CONFIG_NF_REJECT_IPV6=m
CONFIG_NF_LOG_IPV6=m
CONFIG_IP6_NF_IPTABLES=m
CONFIG_IP6_NF_MATCH_AH=m
CONFIG_IP6_NF_MATCH_EUI64=m
CONFIG_IP6_NF_MATCH_FRAG=m
CONFIG_IP6_NF_MATCH_OPTS=m
CONFIG_IP6_NF_MATCH_HL=m
CONFIG_IP6_NF_MATCH_IPV6HEADER=m
CONFIG_IP6_NF_MATCH_MH=m
CONFIG_IP6_NF_MATCH_RPFILTER=m
CONFIG_IP6_NF_MATCH_RT=m
CONFIG_IP6_NF_MATCH_SRH=m
CONFIG_IP6_NF_TARGET_REJECT=m
CONFIG_IP6_NF_TARGET_SYNPROXY=m
CONFIG_IP6_NF_TARGET_NPT=m
# end of IPv6: Netfilter Configuration

CONFIG_NF_DEFRAG_IPV6=m
CONFIG_NF_TABLES_BRIDGE=m
CONFIG_NFT_BRIDGE_META=m
CONFIG_NFT_BRIDGE_REJECT=m
CONFIG_NF_CONNTRACK_BRIDGE=m
CONFIG_BRIDGE_NF_EBTABLES=m
CONFIG_BRIDGE_EBT_802_3=m
CONFIG_BRIDGE_EBT_AMONG=m
CONFIG_BRIDGE_EBT_ARP=m
CONFIG_BRIDGE_EBT_IP=m
CONFIG_BRIDGE_EBT_IP6=m
CONFIG_BRIDGE_EBT_LIMIT=m
CONFIG_BRIDGE_EBT_MARK=m
CONFIG_BRIDGE_EBT_PKTTYPE=m
CONFIG_BRIDGE_EBT_STP=m
CONFIG_BRIDGE_EBT_VLAN=m
CONFIG_BRIDGE_EBT_ARPREPLY=m
CONFIG_BRIDGE_EBT_DNAT=m
CONFIG_BRIDGE_EBT_MARK_T=m
CONFIG_BRIDGE_EBT_REDIRECT=m
CONFIG_BRIDGE_EBT_SNAT=m
CONFIG_BRIDGE_EBT_LOG=m
CONFIG_BRIDGE_EBT_NFLOG=m
CONFIG_IP_SCTP=m
# CONFIG_SCTP_DBG_OBJCNT is not set
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5 is not set
CONFIG_SCTP_DEFAULT_COOKIE_HMAC_SHA1=y
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_NONE is not set
CONFIG_SCTP_COOKIE_HMAC_MD5=y
CONFIG_SCTP_COOKIE_HMAC_SHA1=y
CONFIG_INET_SCTP_DIAG=m
# CONFIG_RDS is not set
CONFIG_TIPC=m
# CONFIG_TIPC_MEDIA_IB is not set
CONFIG_TIPC_MEDIA_UDP=y
CONFIG_TIPC_CRYPTO=y
CONFIG_TIPC_DIAG=m
CONFIG_ATM=m
CONFIG_ATM_CLIP=m
# CONFIG_ATM_CLIP_NO_ICMP is not set
CONFIG_ATM_LANE=m
# CONFIG_ATM_MPOA is not set
CONFIG_ATM_BR2684=m
# CONFIG_ATM_BR2684_IPFILTER is not set
CONFIG_L2TP=m
CONFIG_L2TP_DEBUGFS=m
CONFIG_L2TP_V3=y
CONFIG_L2TP_IP=m
CONFIG_L2TP_ETH=m
CONFIG_STP=m
CONFIG_GARP=m
CONFIG_MRP=m
CONFIG_BRIDGE=m
CONFIG_BRIDGE_IGMP_SNOOPING=y
CONFIG_BRIDGE_VLAN_FILTERING=y
CONFIG_BRIDGE_MRP=y
CONFIG_BRIDGE_CFM=y
CONFIG_NET_DSA=m
CONFIG_NET_DSA_TAG_NONE=m
# CONFIG_NET_DSA_TAG_AR9331 is not set
CONFIG_NET_DSA_TAG_BRCM_COMMON=m
CONFIG_NET_DSA_TAG_BRCM=m
CONFIG_NET_DSA_TAG_BRCM_LEGACY=m
CONFIG_NET_DSA_TAG_BRCM_LEGACY_FCS=m
CONFIG_NET_DSA_TAG_BRCM_PREPEND=m
CONFIG_NET_DSA_TAG_HELLCREEK=m
CONFIG_NET_DSA_TAG_GSWIP=m
CONFIG_NET_DSA_TAG_DSA_COMMON=m
CONFIG_NET_DSA_TAG_DSA=m
CONFIG_NET_DSA_TAG_EDSA=m
CONFIG_NET_DSA_TAG_MTK=m
CONFIG_NET_DSA_TAG_KSZ=m
CONFIG_NET_DSA_TAG_OCELOT=m
CONFIG_NET_DSA_TAG_OCELOT_8021Q=m
CONFIG_NET_DSA_TAG_QCA=m
CONFIG_NET_DSA_TAG_RTL4_A=m
CONFIG_NET_DSA_TAG_RTL8_4=m
# CONFIG_NET_DSA_TAG_RZN1_A5PSW is not set
CONFIG_NET_DSA_TAG_LAN9303=m
CONFIG_NET_DSA_TAG_SJA1105=m
CONFIG_NET_DSA_TAG_TRAILER=m
# CONFIG_NET_DSA_TAG_VSC73XX_8021Q is not set
CONFIG_NET_DSA_TAG_XRS700X=m
CONFIG_VLAN_8021Q=m
CONFIG_VLAN_8021Q_GVRP=y
CONFIG_VLAN_8021Q_MVRP=y
CONFIG_LLC=m
# CONFIG_LLC2 is not set
CONFIG_ATALK=m
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_PHONET is not set
CONFIG_6LOWPAN=m
CONFIG_6LOWPAN_DEBUGFS=y
CONFIG_6LOWPAN_NHC=m
CONFIG_6LOWPAN_NHC_DEST=m
CONFIG_6LOWPAN_NHC_FRAGMENT=m
CONFIG_6LOWPAN_NHC_HOP=m
CONFIG_6LOWPAN_NHC_IPV6=m
CONFIG_6LOWPAN_NHC_MOBILITY=m
CONFIG_6LOWPAN_NHC_ROUTING=m
CONFIG_6LOWPAN_NHC_UDP=m
CONFIG_6LOWPAN_GHC_EXT_HDR_HOP=m
CONFIG_6LOWPAN_GHC_UDP=m
CONFIG_6LOWPAN_GHC_ICMPV6=m
CONFIG_6LOWPAN_GHC_EXT_HDR_DEST=m
CONFIG_6LOWPAN_GHC_EXT_HDR_FRAG=m
CONFIG_6LOWPAN_GHC_EXT_HDR_ROUTE=m
CONFIG_IEEE802154=m
# CONFIG_IEEE802154_NL802154_EXPERIMENTAL is not set
CONFIG_IEEE802154_SOCKET=m
CONFIG_IEEE802154_6LOWPAN=m
CONFIG_MAC802154=m
CONFIG_NET_SCHED=y

#
# Queueing/Scheduling
#
CONFIG_NET_SCH_HTB=m
CONFIG_NET_SCH_HFSC=m
CONFIG_NET_SCH_PRIO=m
CONFIG_NET_SCH_MULTIQ=m
CONFIG_NET_SCH_RED=m
CONFIG_NET_SCH_SFB=m
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_SCH_TEQL=m
CONFIG_NET_SCH_TBF=m
CONFIG_NET_SCH_CBS=m
CONFIG_NET_SCH_ETF=m
CONFIG_NET_SCH_MQPRIO_LIB=m
CONFIG_NET_SCH_TAPRIO=m
CONFIG_NET_SCH_GRED=m
CONFIG_NET_SCH_NETEM=m
CONFIG_NET_SCH_DRR=m
CONFIG_NET_SCH_MQPRIO=m
# CONFIG_NET_SCH_SKBPRIO is not set
CONFIG_NET_SCH_CHOKE=m
CONFIG_NET_SCH_QFQ=m
CONFIG_NET_SCH_CODEL=m
CONFIG_NET_SCH_FQ_CODEL=y
CONFIG_NET_SCH_CAKE=m
CONFIG_NET_SCH_FQ=m
CONFIG_NET_SCH_HHF=m
CONFIG_NET_SCH_PIE=m
CONFIG_NET_SCH_FQ_PIE=m
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_SCH_PLUG=m
CONFIG_NET_SCH_ETS=m
# CONFIG_NET_SCH_DUALPI2 is not set
# CONFIG_NET_SCH_DEFAULT is not set

#
# Classification
#
CONFIG_NET_CLS=y
CONFIG_NET_CLS_BASIC=m
CONFIG_NET_CLS_ROUTE4=m
CONFIG_NET_CLS_FW=m
CONFIG_NET_CLS_U32=m
CONFIG_CLS_U32_PERF=y
CONFIG_CLS_U32_MARK=y
CONFIG_NET_CLS_FLOW=m
CONFIG_NET_CLS_CGROUP=y
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_FLOWER=m
CONFIG_NET_CLS_MATCHALL=m
CONFIG_NET_EMATCH=y
CONFIG_NET_EMATCH_STACK=32
CONFIG_NET_EMATCH_CMP=m
CONFIG_NET_EMATCH_NBYTE=m
CONFIG_NET_EMATCH_U32=m
CONFIG_NET_EMATCH_META=m
CONFIG_NET_EMATCH_TEXT=m
CONFIG_NET_EMATCH_CANID=m
CONFIG_NET_EMATCH_IPSET=m
CONFIG_NET_EMATCH_IPT=m
CONFIG_NET_CLS_ACT=y
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_GACT_PROB=y
CONFIG_NET_ACT_MIRRED=m
CONFIG_NET_ACT_SAMPLE=m
CONFIG_NET_ACT_NAT=m
CONFIG_NET_ACT_PEDIT=m
CONFIG_NET_ACT_SIMP=m
CONFIG_NET_ACT_SKBEDIT=m
CONFIG_NET_ACT_CSUM=m
CONFIG_NET_ACT_MPLS=m
CONFIG_NET_ACT_VLAN=m
CONFIG_NET_ACT_BPF=m
CONFIG_NET_ACT_CONNMARK=m
CONFIG_NET_ACT_CTINFO=m
CONFIG_NET_ACT_SKBMOD=m
CONFIG_NET_ACT_IFE=m
CONFIG_NET_ACT_TUNNEL_KEY=m
CONFIG_NET_ACT_CT=m
CONFIG_NET_ACT_GATE=m
CONFIG_NET_IFE_SKBMARK=m
CONFIG_NET_IFE_SKBPRIO=m
CONFIG_NET_IFE_SKBTCINDEX=m
CONFIG_NET_TC_SKB_EXT=y
CONFIG_NET_SCH_FIFO=y
CONFIG_DCB=y
CONFIG_DNS_RESOLVER=m
CONFIG_BATMAN_ADV=m
CONFIG_BATMAN_ADV_BATMAN_V=y
CONFIG_BATMAN_ADV_BLA=y
CONFIG_BATMAN_ADV_DAT=y
CONFIG_BATMAN_ADV_NC=y
CONFIG_BATMAN_ADV_MCAST=y
# CONFIG_BATMAN_ADV_DEBUG is not set
CONFIG_BATMAN_ADV_TRACING=y
CONFIG_OPENVSWITCH=m
CONFIG_OPENVSWITCH_GRE=m
CONFIG_OPENVSWITCH_VXLAN=m
CONFIG_OPENVSWITCH_GENEVE=m
CONFIG_VSOCKETS=m
CONFIG_VSOCKETS_DIAG=m
CONFIG_VSOCKETS_LOOPBACK=m
CONFIG_VMWARE_VMCI_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS_COMMON=m
CONFIG_HYPERV_VSOCKETS=m
CONFIG_NETLINK_DIAG=y
CONFIG_MPLS=y
CONFIG_NET_MPLS_GSO=m
CONFIG_MPLS_ROUTING=m
CONFIG_MPLS_IPTUNNEL=m
CONFIG_NET_NSH=m
CONFIG_HSR=m
CONFIG_PRP_DUP_DISCARD_KUNIT_TEST=m
CONFIG_NET_SWITCHDEV=y
CONFIG_NET_L3_MASTER_DEV=y
CONFIG_QRTR=m
CONFIG_QRTR_SMD=m
# CONFIG_QRTR_TUN is not set
CONFIG_QRTR_MHI=m
CONFIG_NET_NCSI=y
CONFIG_NCSI_OEM_CMD_GET_MAC=y
CONFIG_NCSI_OEM_CMD_KEEP_PHY=y
CONFIG_PCPU_DEV_REFCNT=y
CONFIG_MAX_SKB_FRAGS=17
CONFIG_RPS=y
CONFIG_RFS_ACCEL=y
CONFIG_SOCK_RX_QUEUE_MAPPING=y
CONFIG_XPS=y
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CGROUP_NET_CLASSID=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_NET_FLOW_LIMIT=y

#
# Network testing
#
CONFIG_NET_PKTGEN=m
CONFIG_NET_DROP_MONITOR=y
# end of Network testing
# end of Networking options

CONFIG_HAMRADIO=y

#
# Packet Radio protocols
#
CONFIG_AX25=m
CONFIG_AX25_DAMA_SLAVE=y
CONFIG_NETROM=m
CONFIG_ROSE=m

#
# AX.25 network device drivers
#
CONFIG_MKISS=m
CONFIG_6PACK=m
CONFIG_BPQETHER=m
CONFIG_BAYCOM_SER_FDX=m
CONFIG_BAYCOM_SER_HDX=m
CONFIG_YAM=m
# end of AX.25 network device drivers

CONFIG_CAN=m
CONFIG_CAN_RAW=m
CONFIG_CAN_BCM=m
CONFIG_CAN_GW=m
CONFIG_CAN_J1939=m
CONFIG_CAN_ISOTP=m
CONFIG_BT=m
CONFIG_BT_BREDR=y
CONFIG_BT_RFCOMM=m
CONFIG_BT_RFCOMM_TTY=y
CONFIG_BT_BNEP=m
CONFIG_BT_BNEP_MC_FILTER=y
CONFIG_BT_BNEP_PROTO_FILTER=y
CONFIG_BT_HIDP=m
CONFIG_BT_LE=y
CONFIG_BT_LE_L2CAP_ECRED=y
CONFIG_BT_6LOWPAN=m
CONFIG_BT_LEDS=y
CONFIG_BT_MSFTEXT=y
CONFIG_BT_AOSPEXT=y
# CONFIG_BT_DEBUGFS is not set
# CONFIG_BT_SELFTEST is not set

#
# Bluetooth device drivers
#
CONFIG_BT_INTEL=m
CONFIG_BT_BCM=m
CONFIG_BT_RTL=m
CONFIG_BT_QCA=m
CONFIG_BT_MTK=m
CONFIG_BT_HCIBTUSB=m
CONFIG_BT_HCIBTUSB_AUTOSUSPEND=y
CONFIG_BT_HCIBTUSB_POLL_SYNC=y
CONFIG_BT_HCIBTUSB_BCM=y
CONFIG_BT_HCIBTUSB_MTK=y
CONFIG_BT_HCIBTUSB_RTL=y
CONFIG_BT_HCIBTSDIO=m
CONFIG_BT_HCIUART=m
CONFIG_BT_HCIUART_SERDEV=y
CONFIG_BT_HCIUART_H4=y
CONFIG_BT_HCIUART_NOKIA=m
CONFIG_BT_HCIUART_BCSP=y
CONFIG_BT_HCIUART_ATH3K=y
CONFIG_BT_HCIUART_LL=y
CONFIG_BT_HCIUART_3WIRE=y
CONFIG_BT_HCIUART_INTEL=y
CONFIG_BT_HCIUART_BCM=y
CONFIG_BT_HCIUART_RTL=y
CONFIG_BT_HCIUART_QCA=y
CONFIG_BT_HCIUART_AG6XX=y
CONFIG_BT_HCIUART_MRVL=y
# CONFIG_BT_HCIUART_AML is not set
CONFIG_BT_HCIBCM203X=m
CONFIG_BT_HCIBCM4377=m
CONFIG_BT_HCIBPA10X=m
CONFIG_BT_HCIBFUSB=m
CONFIG_BT_HCIVHCI=m
CONFIG_BT_MRVL=m
CONFIG_BT_MRVL_SDIO=m
CONFIG_BT_ATH3K=m
CONFIG_BT_MTKSDIO=m
CONFIG_BT_MTKUART=m
CONFIG_BT_QCOMSMD=m
CONFIG_BT_HCIRSI=m
CONFIG_BT_VIRTIO=m
CONFIG_BT_NXPUART=m
CONFIG_BT_INTEL_PCIE=m
# end of Bluetooth device drivers

CONFIG_AF_RXRPC=m
CONFIG_AF_RXRPC_IPV6=y
# CONFIG_AF_RXRPC_INJECT_LOSS is not set
# CONFIG_AF_RXRPC_INJECT_RX_DELAY is not set
CONFIG_AF_RXRPC_DEBUG=y
CONFIG_RXKAD=y
# CONFIG_RXGK is not set
# CONFIG_RXPERF is not set
CONFIG_AF_KCM=m
CONFIG_STREAM_PARSER=y
CONFIG_MCTP=y
CONFIG_FIB_RULES=y
CONFIG_WIRELESS=y
CONFIG_CFG80211=m
# CONFIG_NL80211_TESTMODE is not set
# CONFIG_CFG80211_DEVELOPER_WARNINGS is not set
# CONFIG_CFG80211_CERTIFICATION_ONUS is not set
CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y
CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y
CONFIG_CFG80211_DEFAULT_PS=y
CONFIG_CFG80211_DEBUGFS=y
CONFIG_CFG80211_CRDA_SUPPORT=y
# CONFIG_CFG80211_WEXT is not set
CONFIG_CFG80211_KUNIT_TEST=m
CONFIG_MAC80211=m
CONFIG_MAC80211_HAS_RC=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT="minstrel_ht"
CONFIG_MAC80211_KUNIT_TEST=m
CONFIG_MAC80211_MESH=y
CONFIG_MAC80211_LEDS=y
CONFIG_MAC80211_DEBUGFS=y
# CONFIG_MAC80211_MESSAGE_TRACING is not set
# CONFIG_MAC80211_DEBUG_MENU is not set
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
CONFIG_RFKILL=m
CONFIG_RFKILL_LEDS=y
CONFIG_RFKILL_INPUT=y
CONFIG_RFKILL_GPIO=m
CONFIG_NET_9P=m
CONFIG_NET_9P_FD=m
CONFIG_NET_9P_VIRTIO=m
CONFIG_NET_9P_USBG=m
CONFIG_NET_9P_RDMA=m
# CONFIG_NET_9P_DEBUG is not set
# CONFIG_CAIF is not set
CONFIG_CEPH_LIB=m
# CONFIG_CEPH_LIB_PRETTYDEBUG is not set
# CONFIG_CEPH_LIB_USE_DNS_RESOLVER is not set
CONFIG_NFC=m
CONFIG_NFC_DIGITAL=m
CONFIG_NFC_NCI=m
CONFIG_NFC_NCI_SPI=m
# CONFIG_NFC_NCI_UART is not set
CONFIG_NFC_HCI=m
CONFIG_NFC_SHDLC=y

#
# Near Field Communication (NFC) devices
#
CONFIG_NFC_TRF7970A=m
CONFIG_NFC_SIM=m
CONFIG_NFC_PORT100=m
# CONFIG_NFC_VIRTUAL_NCI is not set
# CONFIG_NFC_FDP is not set
CONFIG_NFC_PN544=m
CONFIG_NFC_PN544_I2C=m
CONFIG_NFC_PN533=m
CONFIG_NFC_PN533_USB=m
CONFIG_NFC_PN533_I2C=m
CONFIG_NFC_PN532_UART=m
CONFIG_NFC_MICROREAD=m
CONFIG_NFC_MICROREAD_I2C=m
CONFIG_NFC_MRVL=m
CONFIG_NFC_MRVL_USB=m
# CONFIG_NFC_MRVL_I2C is not set
# CONFIG_NFC_MRVL_SPI is not set
CONFIG_NFC_ST21NFCA=m
CONFIG_NFC_ST21NFCA_I2C=m
# CONFIG_NFC_ST_NCI_I2C is not set
# CONFIG_NFC_ST_NCI_SPI is not set
CONFIG_NFC_NXP_NCI=m
CONFIG_NFC_NXP_NCI_I2C=m
# CONFIG_NFC_S3FWRN5_I2C is not set
# CONFIG_NFC_S3FWRN82_UART is not set
# CONFIG_NFC_ST95HF is not set
# end of Near Field Communication (NFC) devices

CONFIG_PSAMPLE=m
CONFIG_NET_IFE=m
CONFIG_LWTUNNEL=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
CONFIG_SOCK_VALIDATE_XMIT=y
CONFIG_NET_SELFTESTS=y
CONFIG_NET_SOCK_MSG=y
CONFIG_NET_DEVLINK=y
CONFIG_PAGE_POOL=y
CONFIG_PAGE_POOL_STATS=y
CONFIG_FAILOVER=m
CONFIG_ETHTOOL_NETLINK=y
CONFIG_NETDEV_ADDR_LIST_TEST=m
CONFIG_NET_TEST=m

#
# Device Drivers
#
CONFIG_ARM_AMBA=y
CONFIG_TEGRA_AHB=y
CONFIG_HAVE_PCI=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_PCI=y
CONFIG_PCI_DOMAINS=y
CONFIG_PCI_DOMAINS_GENERIC=y
CONFIG_PCI_SYSCALL=y
CONFIG_PCIEPORTBUS=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_PCIEAER=y
CONFIG_PCIEAER_INJECT=m
CONFIG_PCIEAER_CXL=y
CONFIG_PCIE_ECRC=y
CONFIG_PCIEASPM=y
CONFIG_PCIEASPM_DEFAULT=y
# CONFIG_PCIEASPM_POWERSAVE is not set
# CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
# CONFIG_PCIEASPM_PERFORMANCE is not set
CONFIG_PCIE_PME=y
CONFIG_PCIE_DPC=y
CONFIG_PCIE_PTM=y
CONFIG_PCIE_EDR=y
CONFIG_PCI_MSI=y
CONFIG_PCI_QUIRKS=y
# CONFIG_PCI_DEBUG is not set
# CONFIG_PCI_REALLOC_ENABLE_AUTO is not set
CONFIG_PCI_STUB=y
CONFIG_PCI_PF_STUB=m
CONFIG_PCI_ATS=y
CONFIG_PCI_DOE=y
CONFIG_PCI_ECAM=y
CONFIG_PCI_BRIDGE_EMUL=y
CONFIG_PCI_IOV=y
CONFIG_PCI_NPEM=y
CONFIG_PCI_PRI=y
CONFIG_PCI_PASID=y
CONFIG_PCIE_TPH=y
CONFIG_PCI_P2PDMA=y
CONFIG_PCI_LABEL=y
CONFIG_PCI_HYPERV=m
# CONFIG_PCI_DYNAMIC_OF_NODES is not set
# CONFIG_PCIE_BUS_TUNE_OFF is not set
CONFIG_PCIE_BUS_DEFAULT=y
# CONFIG_PCIE_BUS_SAFE is not set
# CONFIG_PCIE_BUS_PERFORMANCE is not set
# CONFIG_PCIE_BUS_PEER2PEER is not set
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=16
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_ACPI=y
CONFIG_HOTPLUG_PCI_ACPI_AMPERE_ALTRA=m
CONFIG_HOTPLUG_PCI_ACPI_IBM=m
# CONFIG_HOTPLUG_PCI_CPCI is not set
CONFIG_HOTPLUG_PCI_OCTEONEP=y
# CONFIG_HOTPLUG_PCI_SHPC is not set

#
# PCI controller drivers
#
CONFIG_PCI_HOST_COMMON=y
CONFIG_PCI_AARDVARK=y
# CONFIG_PCIE_ALTERA is not set
CONFIG_PCIE_APPLE_MSI_DOORBELL_ADDR=0xfffff000
CONFIG_PCIE_APPLE=y
CONFIG_PCIE_BRCMSTB=y
CONFIG_PCI_HOST_THUNDER_PEM=y
CONFIG_PCI_HOST_THUNDER_ECAM=y
# CONFIG_PCI_FTPCI100 is not set
CONFIG_PCI_HOST_GENERIC=y
# CONFIG_PCIE_HISI_ERR is not set
CONFIG_PCI_HYPERV_INTERFACE=m
CONFIG_PCI_TEGRA=y
# CONFIG_PCIE_RCAR_HOST is not set
CONFIG_PCIE_ROCKCHIP=y
CONFIG_PCIE_ROCKCHIP_HOST=y
CONFIG_PCI_XGENE=y
CONFIG_PCI_XGENE_MSI=y
CONFIG_PCIE_XILINX=y
CONFIG_PCIE_XILINX_DMA_PL=y
CONFIG_PCIE_XILINX_NWL=y
CONFIG_PCIE_XILINX_CPM=y

#
# Cadence-based PCIe controllers
#
CONFIG_PCIE_CADENCE=y
CONFIG_PCIE_CADENCE_HOST=y
CONFIG_PCIE_CADENCE_PLAT=y
CONFIG_PCIE_CADENCE_PLAT_HOST=y
CONFIG_PCI_J721E=y
CONFIG_PCI_J721E_HOST=y
# end of Cadence-based PCIe controllers

#
# DesignWare-based PCIe controllers
#
CONFIG_PCIE_DW=y
# CONFIG_PCIE_DW_DEBUGFS is not set
CONFIG_PCIE_DW_HOST=y
# CONFIG_PCIE_AL is not set
# CONFIG_PCIE_AMD_MDB is not set
CONFIG_PCI_MESON=y
CONFIG_PCI_IMX6=y
CONFIG_PCI_IMX6_HOST=y
CONFIG_PCI_LAYERSCAPE=y
CONFIG_PCI_HISI=y
CONFIG_PCIE_KIRIN=y
CONFIG_PCIE_HISI_STB=y
CONFIG_PCIE_ARMADA_8K=y
CONFIG_PCIE_TEGRA194=y
CONFIG_PCIE_TEGRA194_HOST=y
CONFIG_PCIE_DW_PLAT=y
CONFIG_PCIE_DW_PLAT_HOST=y
CONFIG_PCIE_QCOM_COMMON=y
CONFIG_PCIE_QCOM=y
# CONFIG_PCIE_RCAR_GEN4_HOST is not set
CONFIG_PCIE_ROCKCHIP_DW=y
CONFIG_PCIE_ROCKCHIP_DW_HOST=y
CONFIG_PCI_KEYSTONE=y
CONFIG_PCI_KEYSTONE_HOST=y
# end of DesignWare-based PCIe controllers

#
# Mobiveil-based PCIe controllers
#
CONFIG_PCIE_MOBIVEIL=y
CONFIG_PCIE_MOBIVEIL_HOST=y
CONFIG_PCIE_LAYERSCAPE_GEN4=y
CONFIG_PCIE_MOBIVEIL_PLAT=y
# end of Mobiveil-based PCIe controllers

#
# PLDA-based PCIe controllers
#
CONFIG_PCIE_PLDA_HOST=y
CONFIG_PCIE_MICROCHIP_HOST=y
# end of PLDA-based PCIe controllers
# end of PCI controller drivers

#
# PCI Endpoint
#
# CONFIG_PCI_ENDPOINT is not set
# end of PCI Endpoint

#
# PCI switch controller drivers
#
CONFIG_PCI_SW_SWITCHTEC=m
# end of PCI switch controller drivers

CONFIG_HAVE_PWRCTRL=y
CONFIG_PCI_PWRCTRL=m
CONFIG_PCI_PWRCTRL_PWRSEQ=m
# CONFIG_PCI_PWRCTRL_SLOT is not set
CONFIG_CXL_BUS=m
CONFIG_CXL_PCI=m
# CONFIG_CXL_MEM_RAW_COMMANDS is not set
CONFIG_CXL_ACPI=m
CONFIG_CXL_PMEM=m
CONFIG_CXL_MEM=m
CONFIG_CXL_FEATURES=y
# CONFIG_CXL_EDAC_MEM_FEATURES is not set
CONFIG_CXL_PORT=m
CONFIG_CXL_SUSPEND=y
CONFIG_CXL_REGION=y
# CONFIG_CXL_REGION_INVALIDATION_TEST is not set
# CONFIG_PCCARD is not set
CONFIG_RAPIDIO=m
CONFIG_RAPIDIO_TSI721=m
CONFIG_RAPIDIO_DISC_TIMEOUT=30
# CONFIG_RAPIDIO_ENABLE_RX_TX_PORTS is not set
CONFIG_RAPIDIO_DMA_ENGINE=y
# CONFIG_RAPIDIO_DEBUG is not set
CONFIG_RAPIDIO_ENUM_BASIC=m
CONFIG_RAPIDIO_CHMAN=m
CONFIG_RAPIDIO_MPORT_CDEV=m

#
# RapidIO Switch drivers
#
CONFIG_RAPIDIO_CPS_XX=m
CONFIG_RAPIDIO_CPS_GEN2=m
CONFIG_RAPIDIO_RXS_GEN3=m
# end of RapidIO Switch drivers

# CONFIG_PC104 is not set

#
# Generic Driver Options
#
CONFIG_AUXILIARY_BUS=y
# CONFIG_UEVENT_HELPER is not set
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_DEVTMPFS_SAFE=y
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_DEBUG=y
CONFIG_FW_LOADER_PAGED_BUF=y
CONFIG_FW_LOADER_SYSFS=y
CONFIG_EXTRA_FIRMWARE=""
# CONFIG_FW_LOADER_USER_HELPER is not set
CONFIG_FW_LOADER_COMPRESS=y
CONFIG_FW_LOADER_COMPRESS_XZ=y
CONFIG_FW_LOADER_COMPRESS_ZSTD=y
CONFIG_FW_CACHE=y
CONFIG_FW_UPLOAD=y
# end of Firmware loader

CONFIG_WANT_DEV_COREDUMP=y
CONFIG_ALLOW_DEV_COREDUMP=y
CONFIG_DEV_COREDUMP=y
# CONFIG_DEBUG_DRIVER is not set
# CONFIG_DEBUG_DEVRES is not set
# CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
CONFIG_HMEM_REPORTING=y
# CONFIG_TEST_ASYNC_DRIVER_PROBE is not set
# CONFIG_DM_KUNIT_TEST is not set
CONFIG_DRIVER_PE_KUNIT_TEST=m
CONFIG_GENERIC_CPU_DEVICES=y
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_SOC_BUS=y
CONFIG_REGMAP=y
CONFIG_REGMAP_KUNIT=m
# CONFIG_REGMAP_BUILD is not set
CONFIG_REGMAP_I2C=y
CONFIG_REGMAP_SLIMBUS=m
CONFIG_REGMAP_SPI=m
CONFIG_REGMAP_SPMI=y
CONFIG_REGMAP_MMIO=y
CONFIG_REGMAP_IRQ=y
CONFIG_REGMAP_RAM=m
CONFIG_REGMAP_SOUNDWIRE=m
CONFIG_REGMAP_SOUNDWIRE_MBQ=m
CONFIG_REGMAP_SCCB=m
CONFIG_REGMAP_I3C=m
CONFIG_REGMAP_SPI_AVMM=m
CONFIG_DMA_SHARED_BUFFER=y
# CONFIG_DMA_FENCE_TRACE is not set
CONFIG_GENERIC_ARCH_TOPOLOGY=y
CONFIG_GENERIC_ARCH_NUMA=y
# CONFIG_FW_DEVLINK_SYNC_STATE_TIMEOUT is not set
# end of Generic Driver Options

#
# Bus devices
#
CONFIG_ARM_CCI=y
CONFIG_ARM_CCI400_COMMON=y
CONFIG_MOXTET=m
CONFIG_HISILICON_LPC=y
# CONFIG_IMX_AIPSTZ is not set
# CONFIG_IMX_WEIM is not set
# CONFIG_QCOM_EBI2 is not set
CONFIG_QCOM_SSC_BLOCK_BUS=y
CONFIG_SUN50I_DE2_BUS=y
CONFIG_SUNXI_RSB=m
CONFIG_TEGRA_ACONNECT=m
CONFIG_TEGRA_GMI=m
CONFIG_TI_SYSC=y
CONFIG_VEXPRESS_CONFIG=y
CONFIG_FSL_MC_BUS=y
CONFIG_FSL_MC_UAPI_SUPPORT=y
CONFIG_MHI_BUS=m
# CONFIG_MHI_BUS_DEBUG is not set
CONFIG_MHI_BUS_PCI_GENERIC=m
# CONFIG_MHI_BUS_EP is not set
# end of Bus devices

#
# Cache Drivers
#
# end of Cache Drivers

CONFIG_CONNECTOR=y
CONFIG_PROC_EVENTS=y

#
# Firmware Drivers
#

#
# ARM System Control and Management Interface Protocol
#
CONFIG_ARM_SCMI_PROTOCOL=y
# CONFIG_ARM_SCMI_RAW_MODE_SUPPORT is not set
# CONFIG_ARM_SCMI_DEBUG_COUNTERS is not set
CONFIG_ARM_SCMI_QUIRKS=y

#
# SCMI Transport Drivers
#
CONFIG_ARM_SCMI_HAVE_TRANSPORT=y
CONFIG_ARM_SCMI_HAVE_SHMEM=y
CONFIG_ARM_SCMI_HAVE_MSG=y
CONFIG_ARM_SCMI_TRANSPORT_MAILBOX=y
CONFIG_ARM_SCMI_TRANSPORT_SMC=y
# CONFIG_ARM_SCMI_TRANSPORT_SMC_ATOMIC_ENABLE is not set
CONFIG_ARM_SCMI_TRANSPORT_OPTEE=m
CONFIG_ARM_SCMI_TRANSPORT_VIRTIO=y
CONFIG_ARM_SCMI_TRANSPORT_VIRTIO_VERSION1_COMPLIANCE=y
# CONFIG_ARM_SCMI_TRANSPORT_VIRTIO_ATOMIC_ENABLE is not set
# end of SCMI Transport Drivers

#
# ARM SCMI NXP i.MX Vendor Protocols
#
CONFIG_IMX_SCMI_BBM_EXT=y
CONFIG_IMX_SCMI_CPU_EXT=y
CONFIG_IMX_SCMI_LMM_EXT=y
CONFIG_IMX_SCMI_MISC_EXT=m
# end of ARM SCMI NXP i.MX Vendor Protocols

CONFIG_ARM_SCMI_POWER_CONTROL=y
# end of ARM System Control and Management Interface Protocol

CONFIG_ARM_SCPI_PROTOCOL=m
CONFIG_ARM_SDE_INTERFACE=y
CONFIG_FIRMWARE_MEMMAP=y
CONFIG_DMIID=y
CONFIG_DMI_SYSFS=y
CONFIG_ISCSI_IBFT=m
CONFIG_RASPBERRYPI_FIRMWARE=y
CONFIG_FW_CFG_SYSFS=m
# CONFIG_FW_CFG_SYSFS_CMDLINE is not set
CONFIG_SYSFB=y
CONFIG_SYSFB_SIMPLEFB=y
CONFIG_TI_SCI_PROTOCOL=y
CONFIG_TURRIS_MOX_RWTM=m
CONFIG_TURRIS_MOX_RWTM_KEYCTL=y
CONFIG_ARM_FFA_TRANSPORT=y
CONFIG_ARM_FFA_SMCCC=y
CONFIG_FW_CS_DSP=m
CONFIG_FW_CS_DSP_KUNIT_TEST_UTILS=m
CONFIG_FW_CS_DSP_KUNIT_TEST=m
# CONFIG_GOOGLE_FIRMWARE is not set

#
# EFI (Extensible Firmware Interface) Support
#
CONFIG_EFI_ESRT=y
CONFIG_EFI_VARS_PSTORE=y
CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE=y
CONFIG_EFI_SOFT_RESERVE=y
CONFIG_EFI_PARAMS_FROM_FDT=y
CONFIG_EFI_RUNTIME_WRAPPERS=y
CONFIG_EFI_GENERIC_STUB=y
CONFIG_EFI_ZBOOT=y
CONFIG_EFI_ARMSTUB_DTB_LOADER=y
# CONFIG_EFI_BOOTLOADER_CONTROL is not set
# CONFIG_EFI_CAPSULE_LOADER is not set
CONFIG_EFI_TEST=m
# CONFIG_RESET_ATTACK_MITIGATION is not set
# CONFIG_EFI_DISABLE_PCI_DMA is not set
CONFIG_EFI_EARLYCON=y
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=y
# CONFIG_EFI_DISABLE_RUNTIME is not set
CONFIG_EFI_COCO_SECRET=y
# CONFIG_OVMF_DEBUG_LOG is not set
CONFIG_EFI_SBAT_FILE=""
# end of EFI (Extensible Firmware Interface) Support

CONFIG_UEFI_CPER=y
CONFIG_UEFI_CPER_ARM=y
CONFIG_TEE_STMM_EFI=m
CONFIG_IMX_DSP=m
CONFIG_IMX_SCU=y
CONFIG_IMX_SCMI_CPU_DRV=y
CONFIG_IMX_SCMI_LMM_DRV=y
CONFIG_IMX_SCMI_MISC_DRV=m
CONFIG_MESON_SM=y
CONFIG_ARM_PSCI_FW=y
# CONFIG_ARM_PSCI_CHECKER is not set

#
# Qualcomm firmware drivers
#
CONFIG_QCOM_SCM=y
CONFIG_QCOM_TZMEM=y
CONFIG_QCOM_TZMEM_MODE_GENERIC=y
# CONFIG_QCOM_TZMEM_MODE_SHMBRIDGE is not set
CONFIG_QCOM_QSEECOM=y
CONFIG_QCOM_QSEECOM_UEFISECAPP=y
# end of Qualcomm firmware drivers

CONFIG_HAVE_ARM_SMCCC=y
CONFIG_HAVE_ARM_SMCCC_DISCOVERY=y
CONFIG_ARM_SMCCC_SOC_ID=y

#
# Tegra firmware driver
#
CONFIG_TEGRA_IVC=y
CONFIG_TEGRA_BPMP=y
# end of Tegra firmware driver

#
# Zynq MPSoC Firmware Drivers
#
CONFIG_ZYNQMP_FIRMWARE=y
# CONFIG_ZYNQMP_FIRMWARE_DEBUG is not set
# end of Zynq MPSoC Firmware Drivers
# end of Firmware Drivers

CONFIG_FWCTL=m
CONFIG_FWCTL_MLX5=m
CONFIG_FWCTL_PDS=m
CONFIG_GNSS=m
CONFIG_GNSS_SERIAL=m
CONFIG_GNSS_MTK_SERIAL=m
CONFIG_GNSS_SIRF_SERIAL=m
CONFIG_GNSS_UBX_SERIAL=m
CONFIG_GNSS_USB=m
CONFIG_MTD=m
# CONFIG_MTD_TESTS is not set

#
# Partition parsers
#
# CONFIG_MTD_CMDLINE_PARTS is not set
CONFIG_MTD_OF_PARTS=m
# CONFIG_MTD_AFS_PARTS is not set
# CONFIG_MTD_REDBOOT_PARTS is not set
# CONFIG_MTD_QCOMSMEM_PARTS is not set
# end of Partition parsers

#
# User Modules And Translation Layers
#
CONFIG_MTD_BLKDEVS=m
CONFIG_MTD_BLOCK=m
# CONFIG_MTD_BLOCK_RO is not set

#
# Note that in some cases UBI block is preferred. See MTD_UBI_BLOCK.
#
# CONFIG_FTL is not set
# CONFIG_NFTL is not set
# CONFIG_INFTL is not set
# CONFIG_RFD_FTL is not set
# CONFIG_SSFDC is not set
# CONFIG_SM_FTL is not set
# CONFIG_MTD_OOPS is not set
# CONFIG_MTD_SWAP is not set
# CONFIG_MTD_PARTITIONED_MASTER is not set

#
# RAM/ROM/Flash chip drivers
#
CONFIG_MTD_CFI=m
# CONFIG_MTD_JEDECPROBE is not set
CONFIG_MTD_GEN_PROBE=m
# CONFIG_MTD_CFI_ADV_OPTIONS is not set
CONFIG_MTD_MAP_BANK_WIDTH_1=y
CONFIG_MTD_MAP_BANK_WIDTH_2=y
CONFIG_MTD_MAP_BANK_WIDTH_4=y
CONFIG_MTD_CFI_I1=y
CONFIG_MTD_CFI_I2=y
CONFIG_MTD_CFI_INTELEXT=m
CONFIG_MTD_CFI_AMDSTD=m
CONFIG_MTD_CFI_STAA=m
CONFIG_MTD_CFI_UTIL=m
# CONFIG_MTD_RAM is not set
# CONFIG_MTD_ROM is not set
# CONFIG_MTD_ABSENT is not set
# end of RAM/ROM/Flash chip drivers

#
# Mapping drivers for chip access
#
# CONFIG_MTD_COMPLEX_MAPPINGS is not set
CONFIG_MTD_PHYSMAP=m
# CONFIG_MTD_PHYSMAP_COMPAT is not set
CONFIG_MTD_PHYSMAP_OF=y
# CONFIG_MTD_PHYSMAP_VERSATILE is not set
# CONFIG_MTD_PHYSMAP_GEMINI is not set
# CONFIG_MTD_PLATRAM is not set
# end of Mapping drivers for chip access

#
# Self-contained MTD device drivers
#
# CONFIG_MTD_PMC551 is not set
CONFIG_MTD_DATAFLASH=m
CONFIG_MTD_DATAFLASH_WRITE_VERIFY=y
CONFIG_MTD_DATAFLASH_OTP=y
# CONFIG_MTD_MCHP23K256 is not set
CONFIG_MTD_MCHP48L640=m
CONFIG_MTD_SST25L=m
# CONFIG_MTD_SLRAM is not set
# CONFIG_MTD_PHRAM is not set
CONFIG_MTD_MTDRAM=m
CONFIG_MTDRAM_TOTAL_SIZE=4096
CONFIG_MTDRAM_ERASE_SIZE=128
CONFIG_MTD_BLOCK2MTD=m
# CONFIG_MTD_INTEL_DG is not set

#
# Disk-On-Chip Device Drivers
#
# CONFIG_MTD_DOCG3 is not set
# end of Self-contained MTD device drivers

#
# NAND
#
CONFIG_MTD_NAND_CORE=m
# CONFIG_MTD_ONENAND is not set
CONFIG_MTD_RAW_NAND=m

#
# Raw/parallel NAND flash controllers
#
# CONFIG_MTD_NAND_DENALI_PCI is not set
# CONFIG_MTD_NAND_DENALI_DT is not set
# CONFIG_MTD_NAND_OMAP2 is not set
# CONFIG_MTD_NAND_CAFE is not set
CONFIG_MTD_NAND_MARVELL=m
# CONFIG_MTD_NAND_BRCMNAND is not set
# CONFIG_MTD_NAND_MXC is not set
# CONFIG_MTD_NAND_SUNXI is not set
# CONFIG_MTD_NAND_HISI504 is not set
# CONFIG_MTD_NAND_QCOM is not set
# CONFIG_MTD_NAND_MXIC is not set
CONFIG_MTD_NAND_TEGRA=m
# CONFIG_MTD_NAND_MESON is not set
# CONFIG_MTD_NAND_GPIO is not set
# CONFIG_MTD_NAND_PLATFORM is not set
CONFIG_MTD_NAND_CADENCE=m
# CONFIG_MTD_NAND_ARASAN is not set
# CONFIG_MTD_NAND_INTEL_LGM is not set
# CONFIG_MTD_NAND_ROCKCHIP is not set
# CONFIG_MTD_NAND_RENESAS is not set

#
# Misc
#
CONFIG_MTD_NAND_NANDSIM=m
# CONFIG_MTD_NAND_RICOH is not set
# CONFIG_MTD_NAND_DISKONCHIP is not set
CONFIG_MTD_SPI_NAND=m

#
# ECC engine support
#
CONFIG_MTD_NAND_ECC=y
CONFIG_MTD_NAND_ECC_SW_HAMMING=y
# CONFIG_MTD_NAND_ECC_SW_HAMMING_SMC is not set
# CONFIG_MTD_NAND_ECC_SW_BCH is not set
CONFIG_MTD_NAND_ECC_MXIC=y
# end of ECC engine support
# end of NAND

#
# LPDDR & LPDDR2 PCM memory drivers
#
# CONFIG_MTD_LPDDR is not set
# end of LPDDR & LPDDR2 PCM memory drivers

CONFIG_MTD_SPI_NOR=m
# CONFIG_MTD_SPI_NOR_USE_4K_SECTORS is not set
# CONFIG_MTD_SPI_NOR_SWP_DISABLE is not set
CONFIG_MTD_SPI_NOR_SWP_DISABLE_ON_VOLATILE=y
# CONFIG_MTD_SPI_NOR_SWP_KEEP is not set
CONFIG_SPI_HISI_SFC=m
CONFIG_MTD_UBI=m
CONFIG_MTD_UBI_WL_THRESHOLD=4096
CONFIG_MTD_UBI_BEB_LIMIT=20
# CONFIG_MTD_UBI_FASTMAP is not set
# CONFIG_MTD_UBI_GLUEBI is not set
# CONFIG_MTD_UBI_BLOCK is not set
CONFIG_MTD_UBI_NVMEM=m
# CONFIG_MTD_HYPERBUS is not set
CONFIG_DTC=y
CONFIG_OF=y
# CONFIG_OF_UNITTEST is not set
CONFIG_OF_KUNIT_TEST=m
CONFIG_OF_FLATTREE=y
CONFIG_OF_EARLY_FLATTREE=y
CONFIG_OF_KOBJ=y
CONFIG_OF_DYNAMIC=y
CONFIG_OF_ADDRESS=y
CONFIG_OF_IRQ=y
CONFIG_OF_RESERVED_MEM=y
CONFIG_OF_RESOLVE=y
CONFIG_OF_OVERLAY=y
CONFIG_OF_OVERLAY_KUNIT_TEST=m
CONFIG_OF_NUMA=y
# CONFIG_PARPORT is not set
CONFIG_PNP=y
# CONFIG_PNP_DEBUG_MESSAGES is not set

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_NULL_BLK=m
CONFIG_CDROM=y
# CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
CONFIG_ZRAM=m
CONFIG_ZRAM_BACKEND_LZ4=y
CONFIG_ZRAM_BACKEND_LZ4HC=y
CONFIG_ZRAM_BACKEND_ZSTD=y
CONFIG_ZRAM_BACKEND_DEFLATE=y
CONFIG_ZRAM_BACKEND_842=y
CONFIG_ZRAM_BACKEND_LZO=y
CONFIG_ZRAM_DEF_COMP_LZORLE=y
# CONFIG_ZRAM_DEF_COMP_LZO is not set
# CONFIG_ZRAM_DEF_COMP_LZ4 is not set
# CONFIG_ZRAM_DEF_COMP_LZ4HC is not set
# CONFIG_ZRAM_DEF_COMP_ZSTD is not set
# CONFIG_ZRAM_DEF_COMP_DEFLATE is not set
# CONFIG_ZRAM_DEF_COMP_842 is not set
CONFIG_ZRAM_DEF_COMP="lzo-rle"
CONFIG_ZRAM_WRITEBACK=y
# CONFIG_ZRAM_TRACK_ENTRY_ACTIME is not set
# CONFIG_ZRAM_MEMORY_TRACKING is not set
CONFIG_ZRAM_MULTI_COMP=y
CONFIG_BLK_DEV_LOOP=m
CONFIG_BLK_DEV_LOOP_MIN_COUNT=0
CONFIG_BLK_DEV_DRBD=m
# CONFIG_DRBD_FAULT_INJECTION is not set
CONFIG_BLK_DEV_NBD=m
CONFIG_BLK_DEV_RAM=m
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=16384
CONFIG_ATA_OVER_ETH=m
CONFIG_VIRTIO_BLK=y
CONFIG_BLK_DEV_RBD=m
CONFIG_BLK_DEV_UBLK=m
CONFIG_BLKDEV_UBLK_LEGACY_OPCODES=y
CONFIG_BLK_DEV_RNBD=y
CONFIG_BLK_DEV_RNBD_CLIENT=m
CONFIG_BLK_DEV_RNBD_SERVER=m
# CONFIG_BLK_DEV_ZONED_LOOP is not set

#
# NVME Support
#
CONFIG_NVME_KEYRING=m
CONFIG_NVME_AUTH=m
CONFIG_NVME_CORE=m
CONFIG_BLK_DEV_NVME=m
CONFIG_NVME_MULTIPATH=y
# CONFIG_NVME_VERBOSE_ERRORS is not set
CONFIG_NVME_HWMON=y
CONFIG_NVME_FABRICS=m
CONFIG_NVME_RDMA=m
CONFIG_NVME_FC=m
CONFIG_NVME_TCP=m
CONFIG_NVME_TCP_TLS=y
CONFIG_NVME_HOST_AUTH=y
CONFIG_NVME_APPLE=m
CONFIG_NVME_TARGET=m
# CONFIG_NVME_TARGET_DEBUGFS is not set
CONFIG_NVME_TARGET_PASSTHRU=y
CONFIG_NVME_TARGET_LOOP=m
CONFIG_NVME_TARGET_RDMA=m
CONFIG_NVME_TARGET_FC=m
CONFIG_NVME_TARGET_FCLOOP=m
CONFIG_NVME_TARGET_TCP=m
CONFIG_NVME_TARGET_TCP_TLS=y
CONFIG_NVME_TARGET_AUTH=y
# end of NVME Support

#
# Misc devices
#
CONFIG_SENSORS_LIS3LV02D=m
# CONFIG_AD525X_DPOT is not set
# CONFIG_DUMMY_IRQ is not set
# CONFIG_PHANTOM is not set
CONFIG_RPMB=m
# CONFIG_TI_FPC202 is not set
CONFIG_TIFM_CORE=m
CONFIG_TIFM_7XX1=m
# CONFIG_ICS932S401 is not set
CONFIG_ENCLOSURE_SERVICES=m
CONFIG_SMPRO_ERRMON=m
CONFIG_SMPRO_MISC=m
CONFIG_HI6421V600_IRQ=m
# CONFIG_HP_ILO is not set
CONFIG_QCOM_COINCELL=m
CONFIG_QCOM_FASTRPC=m
CONFIG_APDS9802ALS=m
CONFIG_ISL29003=m
CONFIG_ISL29020=m
CONFIG_SENSORS_TSL2550=m
CONFIG_SENSORS_BH1770=m
CONFIG_SENSORS_APDS990X=m
# CONFIG_HMC6352 is not set
# CONFIG_DS1682 is not set
# CONFIG_LATTICE_ECP3_CONFIG is not set
CONFIG_SRAM=y
CONFIG_DW_XDATA_PCIE=m
# CONFIG_PCI_ENDPOINT_TEST is not set
CONFIG_XILINX_SDFEC=m
CONFIG_MISC_RTSX=m
CONFIG_HISI_HIKEY_USB=m
CONFIG_OPEN_DICE=m
CONFIG_NTSYNC=m
CONFIG_VCPU_STALL_DETECTOR=m
CONFIG_TPS6594_ESM=m
CONFIG_TPS6594_PFSM=m
CONFIG_NSM=m
# CONFIG_MARVELL_CN10K_DPI is not set
# CONFIG_MCHP_LAN966X_PCI is not set
# CONFIG_C2PORT is not set

#
# EEPROM support
#
CONFIG_EEPROM_AT24=m
CONFIG_EEPROM_AT25=m
CONFIG_EEPROM_MAX6875=m
CONFIG_EEPROM_93CX6=m
CONFIG_EEPROM_93XX46=m
CONFIG_EEPROM_IDT_89HPESX=m
CONFIG_EEPROM_EE1004=m
# end of EEPROM support

CONFIG_CB710_CORE=m
# CONFIG_CB710_DEBUG is not set
CONFIG_CB710_DEBUG_ASSUMPTIONS=y
CONFIG_SENSORS_LIS3_I2C=m
CONFIG_ALTERA_STAPL=m
CONFIG_VMWARE_VMCI=m
# CONFIG_GENWQE is not set
CONFIG_BCM_VK=m
CONFIG_BCM_VK_TTY=y
CONFIG_MISC_ALCOR_PCI=m
CONFIG_MISC_RTSX_PCI=m
CONFIG_MISC_RTSX_USB=m
CONFIG_UACCE=m
CONFIG_PVPANIC=y
# CONFIG_PVPANIC_MMIO is not set
CONFIG_PVPANIC_PCI=m
CONFIG_GP_PCI1XXXX=m
CONFIG_KEBA_CP500=m
CONFIG_KEBA_LAN9252=m
# CONFIG_AMD_SBRMI_I2C is not set
# CONFIG_MISC_RP1 is not set
# end of Misc devices

#
# SCSI device support
#
CONFIG_SCSI_MOD=y
CONFIG_RAID_ATTRS=m
CONFIG_SCSI_COMMON=y
CONFIG_SCSI=y
CONFIG_SCSI_DMA=y
CONFIG_SCSI_NETLINK=y
CONFIG_SCSI_PROC_FS=y
CONFIG_SCSI_LIB_KUNIT_TEST=m

#
# SCSI support type (disk, tape, CD-ROM)
#
CONFIG_BLK_DEV_SD=y
CONFIG_CHR_DEV_ST=m
CONFIG_BLK_DEV_SR=y
CONFIG_CHR_DEV_SG=y
CONFIG_BLK_DEV_BSG=y
CONFIG_CHR_DEV_SCH=m
CONFIG_SCSI_ENCLOSURE=m
CONFIG_SCSI_CONSTANTS=y
CONFIG_SCSI_LOGGING=y
CONFIG_SCSI_SCAN_ASYNC=y
CONFIG_SCSI_PROTO_TEST=m

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=m
CONFIG_SCSI_FC_ATTRS=m
CONFIG_SCSI_ISCSI_ATTRS=m
CONFIG_SCSI_SAS_ATTRS=m
CONFIG_SCSI_SAS_LIBSAS=m
CONFIG_SCSI_SAS_ATA=y
CONFIG_SCSI_SAS_HOST_SMP=y
CONFIG_SCSI_SRP_ATTRS=m
# end of SCSI Transports

CONFIG_SCSI_LOWLEVEL=y
CONFIG_ISCSI_TCP=m
CONFIG_ISCSI_BOOT_SYSFS=m
CONFIG_SCSI_CXGB3_ISCSI=m
CONFIG_SCSI_CXGB4_ISCSI=m
CONFIG_SCSI_BNX2_ISCSI=m
CONFIG_SCSI_BNX2X_FCOE=m
CONFIG_BE2ISCSI=m
# CONFIG_BLK_DEV_3W_XXXX_RAID is not set
CONFIG_SCSI_HPSA=m
# CONFIG_SCSI_3W_9XXX is not set
# CONFIG_SCSI_3W_SAS is not set
# CONFIG_SCSI_ACARD is not set
# CONFIG_SCSI_AACRAID is not set
# CONFIG_SCSI_AIC7XXX is not set
# CONFIG_SCSI_AIC79XX is not set
# CONFIG_SCSI_AIC94XX is not set
# CONFIG_SCSI_HISI_SAS is not set
CONFIG_SCSI_MVSAS=m
# CONFIG_SCSI_MVSAS_DEBUG is not set
CONFIG_SCSI_MVSAS_TASKLET=y
CONFIG_SCSI_MVUMI=m
# CONFIG_SCSI_ADVANSYS is not set
CONFIG_SCSI_ARCMSR=m
CONFIG_SCSI_ESAS2R=m
CONFIG_MEGARAID_NEWGEN=y
CONFIG_MEGARAID_MM=m
CONFIG_MEGARAID_MAILBOX=m
CONFIG_MEGARAID_LEGACY=m
CONFIG_MEGARAID_SAS=m
CONFIG_SCSI_MPT3SAS=m
CONFIG_SCSI_MPT2SAS_MAX_SGE=128
CONFIG_SCSI_MPT3SAS_MAX_SGE=128
# CONFIG_SCSI_MPT2SAS is not set
CONFIG_SCSI_MPI3MR=m
CONFIG_SCSI_SMARTPQI=m
CONFIG_SCSI_HPTIOP=m
# CONFIG_SCSI_BUSLOGIC is not set
CONFIG_SCSI_MYRB=m
CONFIG_SCSI_MYRS=m
CONFIG_HYPERV_STORAGE=m
CONFIG_LIBFC=m
CONFIG_LIBFCOE=m
CONFIG_FCOE=m
CONFIG_SCSI_SNIC=m
# CONFIG_SCSI_SNIC_DEBUG_FS is not set
CONFIG_SCSI_DMX3191D=m
CONFIG_SCSI_FDOMAIN=m
CONFIG_SCSI_FDOMAIN_PCI=m
# CONFIG_SCSI_IPS is not set
CONFIG_SCSI_INITIO=m
CONFIG_SCSI_INIA100=m
CONFIG_SCSI_STEX=m
CONFIG_SCSI_SYM53C8XX_2=m
CONFIG_SCSI_SYM53C8XX_DMA_ADDRESSING_MODE=1
CONFIG_SCSI_SYM53C8XX_DEFAULT_TAGS=16
CONFIG_SCSI_SYM53C8XX_MAX_TAGS=64
CONFIG_SCSI_SYM53C8XX_MMIO=y
CONFIG_SCSI_IPR=m
CONFIG_SCSI_IPR_TRACE=y
CONFIG_SCSI_IPR_DUMP=y
CONFIG_SCSI_QLOGIC_1280=m
CONFIG_SCSI_QLA_FC=m
CONFIG_TCM_QLA2XXX=m
# CONFIG_TCM_QLA2XXX_DEBUG is not set
CONFIG_SCSI_QLA_ISCSI=m
CONFIG_QEDI=m
CONFIG_QEDF=m
CONFIG_SCSI_LPFC=m
# CONFIG_SCSI_LPFC_DEBUG_FS is not set
CONFIG_SCSI_EFCT=m
CONFIG_SCSI_DC395x=m
CONFIG_SCSI_AM53C974=m
CONFIG_SCSI_WD719X=m
CONFIG_SCSI_DEBUG=m
CONFIG_SCSI_PMCRAID=m
# CONFIG_SCSI_PM8001 is not set
# CONFIG_SCSI_BFA_FC is not set
CONFIG_SCSI_VIRTIO=m
CONFIG_SCSI_CHELSIO_FCOE=m
CONFIG_SCSI_DH=y
CONFIG_SCSI_DH_RDAC=m
CONFIG_SCSI_DH_HP_SW=m
CONFIG_SCSI_DH_EMC=m
CONFIG_SCSI_DH_ALUA=m
# end of SCSI device support

CONFIG_ATA=y
CONFIG_SATA_HOST=y
CONFIG_PATA_TIMINGS=y
CONFIG_ATA_VERBOSE_ERROR=y
CONFIG_ATA_FORCE=y
CONFIG_ATA_ACPI=y
# CONFIG_SATA_ZPODD is not set
CONFIG_SATA_PMP=y

#
# Controllers with non-SFF native interface
#
CONFIG_SATA_AHCI=y
CONFIG_SATA_MOBILE_LPM_POLICY=3
CONFIG_SATA_AHCI_PLATFORM=m
CONFIG_AHCI_DWC=m
CONFIG_AHCI_IMX=m
CONFIG_AHCI_CEVA=m
CONFIG_AHCI_MVEBU=m
CONFIG_AHCI_SUNXI=m
CONFIG_AHCI_TEGRA=m
CONFIG_AHCI_XGENE=m
CONFIG_AHCI_QORIQ=m
CONFIG_SATA_AHCI_SEATTLE=m
# CONFIG_SATA_INIC162X is not set
CONFIG_SATA_ACARD_AHCI=m
CONFIG_SATA_SIL24=m
CONFIG_ATA_SFF=y

#
# SFF controllers with custom DMA interface
#
CONFIG_PDC_ADMA=m
# CONFIG_SATA_QSTOR is not set
# CONFIG_SATA_SX4 is not set
CONFIG_ATA_BMDMA=y

#
# SATA SFF controllers with BMDMA
#
CONFIG_ATA_PIIX=y
# CONFIG_SATA_DWC is not set
CONFIG_SATA_MV=m
# CONFIG_SATA_NV is not set
# CONFIG_SATA_PROMISE is not set
# CONFIG_SATA_RCAR is not set
# CONFIG_SATA_SIL is not set
# CONFIG_SATA_SIS is not set
# CONFIG_SATA_SVW is not set
# CONFIG_SATA_ULI is not set
# CONFIG_SATA_VIA is not set
# CONFIG_SATA_VITESSE is not set

#
# PATA SFF controllers with BMDMA
#
# CONFIG_PATA_ALI is not set
# CONFIG_PATA_AMD is not set
# CONFIG_PATA_ARTOP is not set
# CONFIG_PATA_ATIIXP is not set
# CONFIG_PATA_ATP867X is not set
# CONFIG_PATA_CMD64X is not set
# CONFIG_PATA_CYPRESS is not set
# CONFIG_PATA_EFAR is not set
# CONFIG_PATA_HPT366 is not set
# CONFIG_PATA_HPT37X is not set
# CONFIG_PATA_HPT3X2N is not set
# CONFIG_PATA_HPT3X3 is not set
# CONFIG_PATA_IMX is not set
# CONFIG_PATA_IT8213 is not set
# CONFIG_PATA_IT821X is not set
# CONFIG_PATA_JMICRON is not set
CONFIG_PATA_MARVELL=m
# CONFIG_PATA_NETCELL is not set
# CONFIG_PATA_NINJA32 is not set
# CONFIG_PATA_NS87415 is not set
# CONFIG_PATA_OLDPIIX is not set
# CONFIG_PATA_OPTIDMA is not set
# CONFIG_PATA_PDC2027X is not set
# CONFIG_PATA_PDC_OLD is not set
# CONFIG_PATA_RADISYS is not set
# CONFIG_PATA_RDC is not set
# CONFIG_PATA_SCH is not set
# CONFIG_PATA_SERVERWORKS is not set
# CONFIG_PATA_SIL680 is not set
# CONFIG_PATA_SIS is not set
# CONFIG_PATA_TOSHIBA is not set
# CONFIG_PATA_TRIFLEX is not set
# CONFIG_PATA_VIA is not set
# CONFIG_PATA_WINBOND is not set

#
# PIO-only SFF controllers
#
# CONFIG_PATA_CMD640_PCI is not set
# CONFIG_PATA_MPIIX is not set
# CONFIG_PATA_NS87410 is not set
# CONFIG_PATA_OPTI is not set
# CONFIG_PATA_OF_PLATFORM is not set
# CONFIG_PATA_RZ1000 is not set

#
# Generic fallback / legacy drivers
#
CONFIG_PATA_ACPI=m
CONFIG_ATA_GENERIC=m
# CONFIG_PATA_LEGACY is not set
CONFIG_MD=y
CONFIG_BLK_DEV_MD=y
CONFIG_MD_AUTODETECT=y
CONFIG_MD_BITMAP_FILE=y
CONFIG_MD_LINEAR=m
CONFIG_MD_RAID0=m
CONFIG_MD_RAID1=m
CONFIG_MD_RAID10=m
CONFIG_MD_RAID456=m
# CONFIG_MD_CLUSTER is not set
CONFIG_BCACHE=m
# CONFIG_BCACHE_DEBUG is not set
# CONFIG_BCACHE_ASYNC_REGISTRATION is not set
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_DEBUG=y
CONFIG_DM_BUFIO=y
# CONFIG_DM_DEBUG_BLOCK_MANAGER_LOCKING is not set
CONFIG_DM_BIO_PRISON=m
CONFIG_DM_PERSISTENT_DATA=m
CONFIG_DM_UNSTRIPED=m
CONFIG_DM_CRYPT=m
CONFIG_DM_SNAPSHOT=y
CONFIG_DM_THIN_PROVISIONING=m
CONFIG_DM_CACHE=m
CONFIG_DM_CACHE_SMQ=m
CONFIG_DM_WRITECACHE=m
CONFIG_DM_EBS=m
CONFIG_DM_ERA=m
CONFIG_DM_CLONE=m
CONFIG_DM_MIRROR=y
CONFIG_DM_LOG_USERSPACE=m
CONFIG_DM_RAID=m
CONFIG_DM_ZERO=y
CONFIG_DM_MULTIPATH=m
CONFIG_DM_MULTIPATH_QL=m
CONFIG_DM_MULTIPATH_ST=m
CONFIG_DM_MULTIPATH_HST=m
CONFIG_DM_MULTIPATH_IOA=m
CONFIG_DM_DELAY=m
CONFIG_DM_DUST=m
CONFIG_DM_INIT=y
CONFIG_DM_UEVENT=y
CONFIG_DM_FLAKEY=m
CONFIG_DM_VERITY=m
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING=y
CONFIG_DM_VERITY_FEC=y
CONFIG_DM_SWITCH=m
CONFIG_DM_LOG_WRITES=m
CONFIG_DM_INTEGRITY=m
CONFIG_DM_ZONED=m
CONFIG_DM_AUDIT=y
CONFIG_DM_VDO=m
CONFIG_TARGET_CORE=m
CONFIG_TCM_IBLOCK=m
CONFIG_TCM_FILEIO=m
CONFIG_TCM_PSCSI=m
CONFIG_TCM_USER2=m
CONFIG_LOOPBACK_TARGET=m
CONFIG_TCM_FC=m
CONFIG_ISCSI_TARGET=m
CONFIG_ISCSI_TARGET_CXGB4=m
CONFIG_REMOTE_TARGET=m
# CONFIG_FUSION is not set

#
# IEEE 1394 (FireWire) support
#
# CONFIG_FIREWIRE is not set
# CONFIG_FIREWIRE_NOSY is not set
# end of IEEE 1394 (FireWire) support

CONFIG_NETDEVICES=y
CONFIG_MII=m
CONFIG_NET_CORE=y
CONFIG_BONDING=m
CONFIG_DUMMY=m
CONFIG_WIREGUARD=m
# CONFIG_WIREGUARD_DEBUG is not set
# CONFIG_OVPN is not set
CONFIG_EQUALIZER=m
CONFIG_NET_FC=y
CONFIG_IFB=m
CONFIG_NET_TEAM=m
CONFIG_NET_TEAM_MODE_BROADCAST=m
CONFIG_NET_TEAM_MODE_ROUNDROBIN=m
CONFIG_NET_TEAM_MODE_RANDOM=m
CONFIG_NET_TEAM_MODE_ACTIVEBACKUP=m
CONFIG_NET_TEAM_MODE_LOADBALANCE=m
CONFIG_MACVLAN=m
CONFIG_MACVTAP=m
CONFIG_IPVLAN_L3S=y
CONFIG_IPVLAN=m
CONFIG_IPVTAP=m
CONFIG_VXLAN=m
CONFIG_GENEVE=m
CONFIG_BAREUDP=m
CONFIG_GTP=m
CONFIG_PFCP=m
CONFIG_AMT=m
CONFIG_MACSEC=m
CONFIG_NETCONSOLE=m
CONFIG_NETCONSOLE_DYNAMIC=y
# CONFIG_NETCONSOLE_EXTENDED_LOG is not set
CONFIG_NETPOLL=y
CONFIG_NET_POLL_CONTROLLER=y
CONFIG_RIONET=m
CONFIG_RIONET_TX_SIZE=128
CONFIG_RIONET_RX_SIZE=128
CONFIG_TUN=m
CONFIG_TAP=m
# CONFIG_TUN_VNET_CROSS_LE is not set
CONFIG_VETH=m
CONFIG_VIRTIO_NET=m
CONFIG_NLMON=m
CONFIG_NETKIT=y
CONFIG_NET_VRF=m
CONFIG_VSOCKMON=m
CONFIG_MHI_NET=m
# CONFIG_ARCNET is not set
# CONFIG_ATM_DRIVERS is not set

#
# Distributed Switch Architecture drivers
#
CONFIG_B53=m
CONFIG_B53_SPI_DRIVER=m
CONFIG_B53_MDIO_DRIVER=m
CONFIG_B53_MMAP_DRIVER=m
CONFIG_B53_SRAB_DRIVER=m
CONFIG_B53_SERDES=m
CONFIG_NET_DSA_BCM_SF2=m
CONFIG_NET_DSA_LOOP=m
CONFIG_NET_DSA_HIRSCHMANN_HELLCREEK=m
# CONFIG_NET_DSA_LANTIQ_GSWIP is not set
CONFIG_NET_DSA_MT7530=m
CONFIG_NET_DSA_MT7530_MDIO=m
CONFIG_NET_DSA_MT7530_MMIO=m
# CONFIG_NET_DSA_MV88E6060 is not set
# CONFIG_NET_DSA_MICROCHIP_KSZ_COMMON is not set
CONFIG_NET_DSA_MV88E6XXX=m
CONFIG_NET_DSA_MV88E6XXX_PTP=y
CONFIG_NET_DSA_MV88E6XXX_LEDS=y
# CONFIG_NET_DSA_AR9331 is not set
CONFIG_NET_DSA_QCA8K=m
CONFIG_NET_DSA_QCA8K_LEDS_SUPPORT=y
# CONFIG_NET_DSA_SJA1105 is not set
CONFIG_NET_DSA_XRS700X=m
CONFIG_NET_DSA_XRS700X_I2C=m
CONFIG_NET_DSA_XRS700X_MDIO=m
CONFIG_NET_DSA_REALTEK=m
# CONFIG_NET_DSA_REALTEK_MDIO is not set
# CONFIG_NET_DSA_REALTEK_SMI is not set
CONFIG_NET_DSA_SMSC_LAN9303=m
CONFIG_NET_DSA_SMSC_LAN9303_I2C=m
CONFIG_NET_DSA_SMSC_LAN9303_MDIO=m
# CONFIG_NET_DSA_VITESSE_VSC73XX_SPI is not set
# CONFIG_NET_DSA_VITESSE_VSC73XX_PLATFORM is not set
# end of Distributed Switch Architecture drivers

CONFIG_ETHERNET=y
CONFIG_MDIO=m
# CONFIG_NET_VENDOR_3COM is not set
# CONFIG_NET_VENDOR_ADAPTEC is not set
CONFIG_NET_VENDOR_AGERE=y
CONFIG_ET131X=m
# CONFIG_NET_VENDOR_ALACRITECH is not set
CONFIG_NET_VENDOR_ALLWINNER=y
# CONFIG_SUN4I_EMAC is not set
CONFIG_NET_VENDOR_ALTEON=y
CONFIG_ACENIC=m
# CONFIG_ACENIC_OMIT_TIGON_I is not set
CONFIG_ALTERA_TSE=m
CONFIG_NET_VENDOR_AMAZON=y
CONFIG_ENA_ETHERNET=m
CONFIG_NET_VENDOR_AMD=y
CONFIG_AMD8111_ETH=m
CONFIG_PCNET32=m
CONFIG_AMD_XGBE=m
CONFIG_AMD_XGBE_DCB=y
CONFIG_PDS_CORE=m
CONFIG_NET_XGENE=m
CONFIG_NET_XGENE_V2=m
CONFIG_NET_VENDOR_AQUANTIA=y
CONFIG_AQTION=m
CONFIG_NET_VENDOR_ARC=y
CONFIG_ARC_EMAC_CORE=m
CONFIG_EMAC_ROCKCHIP=m
CONFIG_NET_VENDOR_ASIX=y
CONFIG_SPI_AX88796C=m
CONFIG_SPI_AX88796C_COMPRESSION=y
CONFIG_NET_VENDOR_ATHEROS=y
CONFIG_ATL2=m
CONFIG_ATL1=m
CONFIG_ATL1E=m
CONFIG_ATL1C=m
CONFIG_ALX=m
CONFIG_NET_VENDOR_BROADCOM=y
CONFIG_B44=m
CONFIG_B44_PCI_AUTOSELECT=y
CONFIG_B44_PCICORE_AUTOSELECT=y
CONFIG_B44_PCI=y
CONFIG_BCMGENET=m
CONFIG_BNX2=m
CONFIG_CNIC=m
CONFIG_TIGON3=m
CONFIG_TIGON3_HWMON=y
CONFIG_BNX2X=m
CONFIG_BNX2X_SRIOV=y
# CONFIG_SYSTEMPORT is not set
CONFIG_BNXT=m
CONFIG_BNXT_SRIOV=y
CONFIG_BNXT_FLOWER_OFFLOAD=y
CONFIG_BNXT_DCB=y
CONFIG_BNXT_HWMON=y
# CONFIG_BNGE is not set
CONFIG_NET_VENDOR_CADENCE=y
CONFIG_MACB=m
CONFIG_MACB_USE_HWSTAMP=y
CONFIG_MACB_PCI=m
CONFIG_NET_VENDOR_CAVIUM=y
CONFIG_THUNDER_NIC_PF=m
CONFIG_THUNDER_NIC_VF=m
CONFIG_THUNDER_NIC_BGX=m
CONFIG_THUNDER_NIC_RGX=m
CONFIG_CAVIUM_PTP=m
# CONFIG_LIQUIDIO is not set
# CONFIG_LIQUIDIO_VF is not set
CONFIG_NET_VENDOR_CHELSIO=y
CONFIG_CHELSIO_T1=m
CONFIG_CHELSIO_T1_1G=y
CONFIG_CHELSIO_T3=m
CONFIG_CHELSIO_T4=m
CONFIG_CHELSIO_T4_DCB=y
# CONFIG_CHELSIO_T4_FCOE is not set
CONFIG_CHELSIO_T4VF=m
CONFIG_CHELSIO_LIB=m
CONFIG_CHELSIO_INLINE_CRYPTO=y
CONFIG_CHELSIO_IPSEC_INLINE=m
CONFIG_CHELSIO_TLS_DEVICE=m
# CONFIG_NET_VENDOR_CISCO is not set
# CONFIG_NET_VENDOR_CORTINA is not set
CONFIG_NET_VENDOR_DAVICOM=y
CONFIG_DM9051=m
CONFIG_DNET=m
# CONFIG_NET_VENDOR_DEC is not set
CONFIG_NET_VENDOR_DLINK=y
CONFIG_DL2K=m
CONFIG_NET_VENDOR_EMULEX=y
CONFIG_BE2NET=m
# CONFIG_BE2NET_HWMON is not set
CONFIG_BE2NET_BE2=y
CONFIG_BE2NET_BE3=y
CONFIG_BE2NET_LANCER=y
CONFIG_BE2NET_SKYHAWK=y
CONFIG_NET_VENDOR_ENGLEDER=y
CONFIG_TSNEP=m
# CONFIG_TSNEP_SELFTESTS is not set
# CONFIG_NET_VENDOR_EZCHIP is not set
CONFIG_NET_VENDOR_FREESCALE=y
CONFIG_FEC=m
CONFIG_FSL_FMAN=m
CONFIG_DPAA_ERRATUM_A050385=y
CONFIG_FSL_PQ_MDIO=m
CONFIG_FSL_XGMAC_MDIO=m
CONFIG_GIANFAR=m
CONFIG_FSL_DPAA_ETH=m
CONFIG_FSL_DPAA2_ETH=m
CONFIG_FSL_DPAA2_ETH_DCB=y
CONFIG_FSL_DPAA2_PTP_CLOCK=m
CONFIG_FSL_DPAA2_SWITCH=m
CONFIG_FSL_ENETC_CORE=m
CONFIG_NXP_ENETC_PF_COMMON=m
CONFIG_FSL_ENETC=m
# CONFIG_NXP_ENETC4 is not set
CONFIG_FSL_ENETC_VF=m
CONFIG_FSL_ENETC_IERB=m
CONFIG_FSL_ENETC_MDIO=m
CONFIG_FSL_ENETC_PTP_CLOCK=m
CONFIG_FSL_ENETC_QOS=y
# CONFIG_NXP_NETC_BLK_CTRL is not set
CONFIG_NET_VENDOR_FUNGIBLE=y
CONFIG_FUN_CORE=m
CONFIG_FUN_ETH=m
CONFIG_NET_VENDOR_GOOGLE=y
CONFIG_GVE=m
CONFIG_NET_VENDOR_HISILICON=y
# CONFIG_HIX5HD2_GMAC is not set
# CONFIG_HISI_FEMAC is not set
# CONFIG_HIP04_ETH is not set
CONFIG_HNS_MDIO=m
CONFIG_HNS=m
CONFIG_HNS_DSAF=m
CONFIG_HNS_ENET=m
CONFIG_HNS3=m
CONFIG_HNS3_HCLGE=m
CONFIG_HNS3_DCB=y
CONFIG_HNS3_HCLGEVF=m
CONFIG_HNS3_ENET=m
CONFIG_HIBMCGE=m
# CONFIG_NET_VENDOR_HUAWEI is not set
# CONFIG_NET_VENDOR_I825XX is not set
CONFIG_NET_VENDOR_INTEL=y
CONFIG_LIBETH=m
CONFIG_LIBIE=m
CONFIG_LIBIE_ADMINQ=m
CONFIG_E100=m
CONFIG_E1000=m
CONFIG_E1000E=m
CONFIG_IGB=m
CONFIG_IGB_HWMON=y
CONFIG_IGBVF=m
CONFIG_IXGBE=m
CONFIG_IXGBE_HWMON=y
CONFIG_IXGBE_DCB=y
CONFIG_IXGBE_IPSEC=y
CONFIG_IXGBEVF=m
CONFIG_IXGBEVF_IPSEC=y
CONFIG_I40E=m
# CONFIG_I40E_DCB is not set
CONFIG_IAVF=m
CONFIG_I40EVF=m
CONFIG_ICE=m
CONFIG_ICE_HWMON=y
CONFIG_ICE_SWITCHDEV=y
CONFIG_FM10K=m
CONFIG_IGC=m
CONFIG_IGC_LEDS=y
CONFIG_IDPF=m
CONFIG_IDPF_SINGLEQ=y
CONFIG_JME=m
CONFIG_NET_VENDOR_ADI=y
CONFIG_ADIN1110=m
CONFIG_NET_VENDOR_LITEX=y
CONFIG_LITEX_LITEETH=m
CONFIG_NET_VENDOR_MARVELL=y
CONFIG_MVMDIO=m
CONFIG_MVNETA=m
CONFIG_MVPP2=m
CONFIG_MVPP2_PTP=y
CONFIG_SKGE=m
# CONFIG_SKGE_DEBUG is not set
CONFIG_SKGE_GENESIS=y
CONFIG_SKY2=m
# CONFIG_SKY2_DEBUG is not set
CONFIG_OCTEONTX2_MBOX=m
CONFIG_OCTEONTX2_AF=m
# CONFIG_NDC_DIS_DYNAMIC_CACHING is not set
CONFIG_OCTEONTX2_PF=m
CONFIG_OCTEONTX2_VF=m
CONFIG_RVU_ESWITCH=m
CONFIG_OCTEON_EP=m
CONFIG_OCTEON_EP_VF=m
CONFIG_PRESTERA=m
CONFIG_PRESTERA_PCI=m
CONFIG_NET_VENDOR_MELLANOX=y
CONFIG_MLX4_EN=m
CONFIG_MLX4_EN_DCB=y
CONFIG_MLX4_CORE=m
CONFIG_MLX4_DEBUG=y
CONFIG_MLX4_CORE_GEN2=y
CONFIG_MLX5_CORE=m
CONFIG_MLX5_FPGA=y
CONFIG_MLX5_CORE_EN=y
CONFIG_MLX5_EN_ARFS=y
CONFIG_MLX5_EN_RXNFC=y
CONFIG_MLX5_MPFS=y
CONFIG_MLX5_ESWITCH=y
CONFIG_MLX5_BRIDGE=y
CONFIG_MLX5_CLS_ACT=y
CONFIG_MLX5_TC_CT=y
CONFIG_MLX5_TC_SAMPLE=y
CONFIG_MLX5_CORE_EN_DCB=y
CONFIG_MLX5_CORE_IPOIB=y
CONFIG_MLX5_MACSEC=y
CONFIG_MLX5_EN_IPSEC=y
CONFIG_MLX5_EN_TLS=y
CONFIG_MLX5_SW_STEERING=y
CONFIG_MLX5_HW_STEERING=y
CONFIG_MLX5_SF=y
CONFIG_MLX5_SF_MANAGER=y
CONFIG_MLX5_DPLL=m
CONFIG_MLXSW_CORE=m
CONFIG_MLXSW_CORE_HWMON=y
CONFIG_MLXSW_CORE_THERMAL=y
CONFIG_MLXSW_PCI=m
CONFIG_MLXSW_I2C=m
CONFIG_MLXSW_SPECTRUM=m
CONFIG_MLXSW_SPECTRUM_DCB=y
CONFIG_MLXSW_MINIMAL=m
CONFIG_MLXFW=m
CONFIG_MLXBF_GIGE=m
CONFIG_NET_VENDOR_META=y
CONFIG_NET_VENDOR_MICREL=y
# CONFIG_KS8842 is not set
# CONFIG_KS8851 is not set
# CONFIG_KS8851_MLL is not set
CONFIG_KSZ884X_PCI=m
CONFIG_NET_VENDOR_MICROCHIP=y
# CONFIG_ENC28J60 is not set
# CONFIG_ENCX24J600 is not set
CONFIG_LAN743X=m
# CONFIG_LAN865X is not set
CONFIG_LAN966X_SWITCH=m
CONFIG_LAN966X_DCB=y
CONFIG_VCAP=y
CONFIG_FDMA=y
# CONFIG_NET_VENDOR_MICROSEMI is not set
CONFIG_NET_VENDOR_MICROSOFT=y
CONFIG_MICROSOFT_MANA=m
CONFIG_NET_VENDOR_MYRI=y
CONFIG_MYRI10GE=m
CONFIG_FEALNX=m
# CONFIG_NET_VENDOR_NI is not set
CONFIG_NET_VENDOR_NATSEMI=y
CONFIG_NATSEMI=m
CONFIG_NS83820=m
CONFIG_NET_VENDOR_NETERION=y
CONFIG_S2IO=m
CONFIG_NET_VENDOR_NETRONOME=y
CONFIG_NFP=m
CONFIG_NFP_APP_FLOWER=y
# CONFIG_NFP_APP_ABM_NIC is not set
CONFIG_NFP_NET_IPSEC=y
# CONFIG_NFP_DEBUG is not set
CONFIG_NET_VENDOR_8390=y
CONFIG_NE2K_PCI=m
CONFIG_NET_VENDOR_NVIDIA=y
CONFIG_FORCEDETH=m
CONFIG_NET_VENDOR_OKI=y
CONFIG_ETHOC=m
CONFIG_NET_VENDOR_PACKET_ENGINES=y
CONFIG_HAMACHI=m
CONFIG_YELLOWFIN=m
CONFIG_NET_VENDOR_PENSANDO=y
CONFIG_IONIC=m
CONFIG_NET_VENDOR_QLOGIC=y
CONFIG_QLA3XXX=m
CONFIG_QLCNIC=m
CONFIG_QLCNIC_SRIOV=y
CONFIG_QLCNIC_DCB=y
CONFIG_QLCNIC_HWMON=y
CONFIG_NETXEN_NIC=m
CONFIG_QED=m
CONFIG_QED_LL2=y
CONFIG_QED_SRIOV=y
CONFIG_QEDE=m
CONFIG_QED_RDMA=y
CONFIG_QED_ISCSI=y
CONFIG_QED_FCOE=y
CONFIG_QED_OOO=y
# CONFIG_NET_VENDOR_BROCADE is not set
CONFIG_NET_VENDOR_QUALCOMM=y
# CONFIG_QCA7000_SPI is not set
# CONFIG_QCA7000_UART is not set
CONFIG_QCOM_EMAC=m
CONFIG_RMNET=m
CONFIG_NET_VENDOR_RDC=y
CONFIG_R6040=m
CONFIG_NET_VENDOR_REALTEK=y
CONFIG_8139CP=m
CONFIG_8139TOO=m
# CONFIG_8139TOO_PIO is not set
# CONFIG_8139TOO_TUNE_TWISTER is not set
CONFIG_8139TOO_8129=y
# CONFIG_8139_OLD_RX_RESET is not set
CONFIG_R8169=m
CONFIG_R8169_LEDS=y
# CONFIG_RTASE is not set
CONFIG_NET_VENDOR_RENESAS=y
# CONFIG_SH_ETH is not set
CONFIG_RAVB=m
# CONFIG_RENESAS_ETHER_SWITCH is not set
CONFIG_RENESAS_GEN4_PTP=m
CONFIG_RTSN=m
CONFIG_NET_VENDOR_ROCKER=y
CONFIG_ROCKER=m
# CONFIG_NET_VENDOR_SAMSUNG is not set
# CONFIG_NET_VENDOR_SEEQ is not set
CONFIG_NET_VENDOR_SILAN=y
CONFIG_SC92031=m
CONFIG_NET_VENDOR_SIS=y
CONFIG_SIS900=m
CONFIG_SIS190=m
# CONFIG_NET_VENDOR_SOLARFLARE is not set
CONFIG_NET_VENDOR_SMSC=y
CONFIG_SMC91X=m
CONFIG_EPIC100=m
CONFIG_SMSC911X=m
CONFIG_SMSC9420=m
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_SNI_NETSEC=m
CONFIG_NET_VENDOR_STMICRO=y
CONFIG_STMMAC_ETH=m
# CONFIG_STMMAC_SELFTESTS is not set
CONFIG_STMMAC_PLATFORM=m
CONFIG_DWMAC_DWC_QOS_ETH=m
CONFIG_DWMAC_GENERIC=m
CONFIG_DWMAC_IPQ806X=m
CONFIG_DWMAC_MESON=m
CONFIG_DWMAC_QCOM_ETHQOS=m
CONFIG_DWMAC_RENESAS_GBETH=m
CONFIG_DWMAC_ROCKCHIP=m
CONFIG_DWMAC_S32=m
CONFIG_DWMAC_SUNXI=m
CONFIG_DWMAC_SUN8I=m
CONFIG_DWMAC_IMX8=m
# CONFIG_DWMAC_INTEL_PLAT is not set
CONFIG_DWMAC_TEGRA=m
# CONFIG_STMMAC_PCI is not set
# CONFIG_NET_VENDOR_SUN is not set
# CONFIG_NET_VENDOR_SYNOPSYS is not set
CONFIG_NET_VENDOR_TEHUTI=y
CONFIG_TEHUTI=m
CONFIG_TEHUTI_TN40=m
CONFIG_NET_VENDOR_TI=y
CONFIG_TI_DAVINCI_MDIO=m
# CONFIG_TI_CPSW_PHY_SEL is not set
CONFIG_TI_K3_CPPI_DESC_POOL=m
CONFIG_TI_K3_AM65_CPSW_NUSS=m
CONFIG_TI_K3_AM65_CPSW_SWITCHDEV=y
CONFIG_TI_K3_AM65_CPTS=m
CONFIG_TI_AM65_CPSW_QOS=y
# CONFIG_TLAN is not set
CONFIG_TI_ICSSG_PRUETH=m
CONFIG_TI_ICSSG_PRUETH_SR1=m
CONFIG_TI_ICSS_IEP=m
CONFIG_NET_VENDOR_VERTEXCOM=y
CONFIG_MSE102X=m
CONFIG_NET_VENDOR_VIA=y
CONFIG_VIA_RHINE=m
CONFIG_VIA_RHINE_MMIO=y
CONFIG_VIA_VELOCITY=m
CONFIG_NET_VENDOR_WANGXUN=y
CONFIG_LIBWX=m
CONFIG_NGBE=m
CONFIG_TXGBE=m
# CONFIG_TXGBEVF is not set
# CONFIG_NGBEVF is not set
# CONFIG_NET_VENDOR_WIZNET is not set
CONFIG_NET_VENDOR_XILINX=y
CONFIG_XILINX_EMACLITE=m
CONFIG_XILINX_LL_TEMAC=m
# CONFIG_FDDI is not set
# CONFIG_HIPPI is not set
CONFIG_QCOM_IPA=m
CONFIG_PHYLINK=m
CONFIG_PHYLIB=y
CONFIG_SWPHY=y
CONFIG_PHY_PACKAGE=m
CONFIG_LED_TRIGGER_PHY=y
CONFIG_OPEN_ALLIANCE_HELPERS=y
CONFIG_PHYLIB_LEDS=y
CONFIG_FIXED_PHY=y
CONFIG_SFP=m

#
# MII PHY device drivers
#
# CONFIG_AS21XXX_PHY is not set
CONFIG_AIR_EN8811H_PHY=m
CONFIG_AMD_PHY=m
CONFIG_MESON_GXL_PHY=m
CONFIG_ADIN_PHY=m
# CONFIG_ADIN1100_PHY is not set
CONFIG_AQUANTIA_PHY=m
CONFIG_AX88796B_PHY=m
CONFIG_BROADCOM_PHY=m
CONFIG_BCM54140_PHY=m
CONFIG_BCM7XXX_PHY=m
# CONFIG_BCM84881_PHY is not set
CONFIG_BCM87XX_PHY=m
CONFIG_BCM_NET_PHYLIB=m
CONFIG_BCM_NET_PHYPTP=m
CONFIG_CICADA_PHY=m
CONFIG_CORTINA_PHY=m
CONFIG_DAVICOM_PHY=m
CONFIG_ICPLUS_PHY=m
CONFIG_LXT_PHY=m
CONFIG_INTEL_XWAY_PHY=m
CONFIG_LSI_ET1011C_PHY=m
CONFIG_MARVELL_PHY=m
CONFIG_MARVELL_10G_PHY=m
CONFIG_MARVELL_88Q2XXX_PHY=m
CONFIG_MARVELL_88X2222_PHY=m
CONFIG_MAXLINEAR_GPHY=m
# CONFIG_MAXLINEAR_86110_PHY is not set
CONFIG_MEDIATEK_GE_PHY=m
# CONFIG_MEDIATEK_GE_SOC_PHY is not set
CONFIG_MTK_NET_PHYLIB=m
CONFIG_MICREL_PHY=m
CONFIG_MICROCHIP_T1S_PHY=m
CONFIG_MICROCHIP_PHY=m
# CONFIG_MICROCHIP_T1_PHY is not set
CONFIG_MICROSEMI_PHY=m
CONFIG_MOTORCOMM_PHY=m
CONFIG_NATIONAL_PHY=m
CONFIG_NXP_CBTX_PHY=m
CONFIG_NXP_C45_TJA11XX_PHY=m
# CONFIG_NXP_TJA11XX_PHY is not set
CONFIG_NCN26000_PHY=m
CONFIG_QCOM_NET_PHYLIB=m
CONFIG_AT803X_PHY=m
CONFIG_QCA83XX_PHY=m
CONFIG_QCA808X_PHY=m
CONFIG_QCA807X_PHY=m
CONFIG_QSEMI_PHY=m
CONFIG_REALTEK_PHY=m
CONFIG_REALTEK_PHY_HWMON=y
# CONFIG_RENESAS_PHY is not set
CONFIG_ROCKCHIP_PHY=m
CONFIG_SMSC_PHY=m
CONFIG_STE10XP=m
CONFIG_TERANETICS_PHY=m
CONFIG_DP83822_PHY=m
# CONFIG_DP83TC811_PHY is not set
CONFIG_DP83848_PHY=m
CONFIG_DP83867_PHY=m
CONFIG_DP83869_PHY=m
CONFIG_DP83TD510_PHY=m
CONFIG_DP83TG720_PHY=m
CONFIG_VITESSE_PHY=m
CONFIG_XILINX_GMII2RGMII=m
# CONFIG_MICREL_KS8995MA is not set
# CONFIG_PSE_CONTROLLER is not set
CONFIG_CAN_DEV=m
CONFIG_CAN_VCAN=m
CONFIG_CAN_VXCAN=m
CONFIG_CAN_NETLINK=y
CONFIG_CAN_CALC_BITTIMING=y
CONFIG_CAN_RX_OFFLOAD=y
CONFIG_CAN_CAN327=m
CONFIG_CAN_FLEXCAN=m
# CONFIG_CAN_GRCAN is not set
# CONFIG_CAN_KVASER_PCIEFD is not set
CONFIG_CAN_SLCAN=m
CONFIG_CAN_XILINXCAN=m
# CONFIG_CAN_C_CAN is not set
# CONFIG_CAN_CC770 is not set
CONFIG_CAN_CTUCANFD=m
CONFIG_CAN_CTUCANFD_PCI=m
CONFIG_CAN_CTUCANFD_PLATFORM=m
# CONFIG_CAN_ESD_402_PCI is not set
CONFIG_CAN_IFI_CANFD=m
CONFIG_CAN_M_CAN=m
CONFIG_CAN_M_CAN_PCI=m
CONFIG_CAN_M_CAN_PLATFORM=m
# CONFIG_CAN_M_CAN_TCAN4X5X is not set
CONFIG_CAN_PEAK_PCIEFD=m
# CONFIG_CAN_RCAR is not set
CONFIG_CAN_RCAR_CANFD=m
CONFIG_CAN_ROCKCHIP_CANFD=m
# CONFIG_CAN_SJA1000 is not set
# CONFIG_CAN_SOFTING is not set

#
# CAN SPI interfaces
#
CONFIG_CAN_HI311X=m
CONFIG_CAN_MCP251X=m
CONFIG_CAN_MCP251XFD=m
# CONFIG_CAN_MCP251XFD_SANITY is not set
# end of CAN SPI interfaces

#
# CAN USB interfaces
#
CONFIG_CAN_8DEV_USB=m
CONFIG_CAN_EMS_USB=m
CONFIG_CAN_ESD_USB=m
# CONFIG_CAN_ETAS_ES58X is not set
CONFIG_CAN_F81604=m
CONFIG_CAN_GS_USB=m
CONFIG_CAN_KVASER_USB=m
CONFIG_CAN_MCBA_USB=m
CONFIG_CAN_PEAK_USB=m
# CONFIG_CAN_UCAN is not set
# end of CAN USB interfaces

# CONFIG_CAN_DEBUG_DEVICES is not set

#
# MCTP Device Drivers
#
CONFIG_MCTP_SERIAL=m
# CONFIG_MCTP_TRANSPORT_I2C is not set
# CONFIG_MCTP_TRANSPORT_I3C is not set
CONFIG_MCTP_TRANSPORT_USB=m
# end of MCTP Device Drivers

CONFIG_MDIO_BUS=y
CONFIG_FWNODE_MDIO=y
CONFIG_OF_MDIO=y
CONFIG_ACPI_MDIO=y
# CONFIG_MDIO_SUN4I is not set
CONFIG_MDIO_XGENE=m
CONFIG_MDIO_BITBANG=m
CONFIG_MDIO_BCM_UNIMAC=m
CONFIG_MDIO_CAVIUM=m
CONFIG_MDIO_GPIO=m
CONFIG_MDIO_HISI_FEMAC=m
CONFIG_MDIO_I2C=m
CONFIG_MDIO_MVUSB=m
# CONFIG_MDIO_MSCC_MIIM is not set
CONFIG_MDIO_OCTEON=m
# CONFIG_MDIO_IPQ4019 is not set
CONFIG_MDIO_IPQ8064=m
CONFIG_MDIO_REGMAP=m
CONFIG_MDIO_THUNDER=m

#
# MDIO Multiplexers
#
CONFIG_MDIO_BUS_MUX=m
CONFIG_MDIO_BUS_MUX_MESON_G12A=m
CONFIG_MDIO_BUS_MUX_MESON_GXL=m
CONFIG_MDIO_BUS_MUX_GPIO=m
CONFIG_MDIO_BUS_MUX_MULTIPLEXER=m
CONFIG_MDIO_BUS_MUX_MMIOREG=m

#
# PCS device drivers
#
CONFIG_PCS_XPCS=m
CONFIG_PCS_LYNX=m
CONFIG_PCS_MTK_LYNXI=m
# end of PCS device drivers

CONFIG_PPP=m
CONFIG_PPP_BSDCOMP=m
CONFIG_PPP_DEFLATE=m
CONFIG_PPP_FILTER=y
CONFIG_PPP_MPPE=m
CONFIG_PPP_MULTILINK=y
CONFIG_PPPOATM=m
CONFIG_PPPOE=m
# CONFIG_PPPOE_HASH_BITS_1 is not set
# CONFIG_PPPOE_HASH_BITS_2 is not set
CONFIG_PPPOE_HASH_BITS_4=y
# CONFIG_PPPOE_HASH_BITS_8 is not set
CONFIG_PPPOE_HASH_BITS=4
CONFIG_PPTP=m
CONFIG_PPPOL2TP=m
CONFIG_PPP_ASYNC=m
CONFIG_PPP_SYNC_TTY=m
CONFIG_SLIP=m
CONFIG_SLHC=m
CONFIG_SLIP_COMPRESSED=y
CONFIG_SLIP_SMART=y
# CONFIG_SLIP_MODE_SLIP6 is not set
CONFIG_USB_NET_DRIVERS=y
CONFIG_USB_CATC=m
CONFIG_USB_KAWETH=m
CONFIG_USB_PEGASUS=m
CONFIG_USB_RTL8150=m
CONFIG_USB_RTL8152=m
CONFIG_USB_LAN78XX=m
CONFIG_USB_USBNET=m
CONFIG_USB_NET_AX8817X=m
CONFIG_USB_NET_AX88179_178A=m
CONFIG_USB_NET_CDCETHER=m
CONFIG_USB_NET_CDC_EEM=m
CONFIG_USB_NET_CDC_NCM=m
CONFIG_USB_NET_HUAWEI_CDC_NCM=m
CONFIG_USB_NET_CDC_MBIM=m
CONFIG_USB_NET_DM9601=m
CONFIG_USB_NET_SR9700=m
# CONFIG_USB_NET_SR9800 is not set
CONFIG_USB_NET_SMSC75XX=m
CONFIG_USB_NET_SMSC95XX=m
CONFIG_USB_NET_GL620A=m
CONFIG_USB_NET_NET1080=m
CONFIG_USB_NET_PLUSB=m
CONFIG_USB_NET_MCS7830=m
CONFIG_USB_NET_RNDIS_HOST=m
CONFIG_USB_NET_CDC_SUBSET_ENABLE=m
CONFIG_USB_NET_CDC_SUBSET=m
CONFIG_USB_ALI_M5632=y
CONFIG_USB_AN2720=y
CONFIG_USB_BELKIN=y
CONFIG_USB_ARMLINUX=y
CONFIG_USB_EPSON2888=y
CONFIG_USB_KC2190=y
CONFIG_USB_NET_ZAURUS=m
CONFIG_USB_NET_CX82310_ETH=m
CONFIG_USB_NET_KALMIA=m
CONFIG_USB_NET_QMI_WWAN=m
CONFIG_USB_HSO=m
CONFIG_USB_NET_INT51X1=m
CONFIG_USB_IPHETH=m
CONFIG_USB_SIERRA_NET=m
CONFIG_USB_VL600=m
CONFIG_USB_NET_CH9200=m
CONFIG_USB_NET_AQC111=m
CONFIG_USB_RTL8153_ECM=m
CONFIG_WLAN=y
# CONFIG_WLAN_VENDOR_ADMTEK is not set
CONFIG_ATH_COMMON=m
CONFIG_WLAN_VENDOR_ATH=y
# CONFIG_ATH_DEBUG is not set
CONFIG_ATH5K=m
CONFIG_ATH5K_DEBUG=y
# CONFIG_ATH5K_TRACER is not set
CONFIG_ATH5K_PCI=y
CONFIG_ATH9K_HW=m
CONFIG_ATH9K_COMMON=m
CONFIG_ATH9K_COMMON_DEBUG=y
CONFIG_ATH9K_BTCOEX_SUPPORT=y
CONFIG_ATH9K=m
CONFIG_ATH9K_PCI=y
CONFIG_ATH9K_AHB=y
CONFIG_ATH9K_DEBUGFS=y
# CONFIG_ATH9K_STATION_STATISTICS is not set
# CONFIG_ATH9K_DYNACK is not set
# CONFIG_ATH9K_WOW is not set
CONFIG_ATH9K_RFKILL=y
# CONFIG_ATH9K_CHANNEL_CONTEXT is not set
CONFIG_ATH9K_PCOEM=y
CONFIG_ATH9K_PCI_NO_EEPROM=m
CONFIG_ATH9K_HTC=m
# CONFIG_ATH9K_HTC_DEBUGFS is not set
# CONFIG_ATH9K_HWRNG is not set
# CONFIG_ATH9K_COMMON_SPECTRAL is not set
CONFIG_CARL9170=m
CONFIG_CARL9170_LEDS=y
# CONFIG_CARL9170_DEBUGFS is not set
CONFIG_CARL9170_WPC=y
# CONFIG_CARL9170_HWRNG is not set
CONFIG_ATH6KL=m
CONFIG_ATH6KL_SDIO=m
CONFIG_ATH6KL_USB=m
CONFIG_ATH6KL_DEBUG=y
# CONFIG_ATH6KL_TRACING is not set
CONFIG_AR5523=m
CONFIG_WIL6210=m
CONFIG_WIL6210_ISR_COR=y
# CONFIG_WIL6210_TRACING is not set
CONFIG_WIL6210_DEBUGFS=y
CONFIG_ATH10K=m
CONFIG_ATH10K_CE=y
CONFIG_ATH10K_PCI=m
CONFIG_ATH10K_AHB=y
CONFIG_ATH10K_SDIO=m
CONFIG_ATH10K_USB=m
CONFIG_ATH10K_SNOC=m
# CONFIG_ATH10K_DEBUG is not set
CONFIG_ATH10K_DEBUGFS=y
CONFIG_ATH10K_LEDS=y
# CONFIG_ATH10K_SPECTRAL is not set
# CONFIG_ATH10K_TRACING is not set
CONFIG_WCN36XX=m
# CONFIG_WCN36XX_DEBUGFS is not set
CONFIG_ATH11K=m
CONFIG_ATH11K_AHB=m
CONFIG_ATH11K_PCI=m
# CONFIG_ATH11K_DEBUG is not set
# CONFIG_ATH11K_DEBUGFS is not set
# CONFIG_ATH11K_TRACING is not set
CONFIG_ATH12K=m
# CONFIG_ATH12K_AHB is not set
# CONFIG_ATH12K_DEBUG is not set
# CONFIG_ATH12K_DEBUGFS is not set
# CONFIG_ATH12K_TRACING is not set
# CONFIG_ATH12K_COREDUMP is not set
# CONFIG_WLAN_VENDOR_ATMEL is not set
CONFIG_WLAN_VENDOR_BROADCOM=y
CONFIG_B43=m
CONFIG_B43_BCMA=y
CONFIG_B43_SSB=y
CONFIG_B43_BUSES_BCMA_AND_SSB=y
# CONFIG_B43_BUSES_BCMA is not set
# CONFIG_B43_BUSES_SSB is not set
CONFIG_B43_PCI_AUTOSELECT=y
CONFIG_B43_PCICORE_AUTOSELECT=y
CONFIG_B43_SDIO=y
CONFIG_B43_BCMA_PIO=y
CONFIG_B43_PIO=y
CONFIG_B43_PHY_G=y
CONFIG_B43_PHY_N=y
CONFIG_B43_PHY_LP=y
CONFIG_B43_PHY_HT=y
CONFIG_B43_LEDS=y
CONFIG_B43_HWRNG=y
# CONFIG_B43_DEBUG is not set
CONFIG_B43LEGACY=m
CONFIG_B43LEGACY_PCI_AUTOSELECT=y
CONFIG_B43LEGACY_PCICORE_AUTOSELECT=y
CONFIG_B43LEGACY_LEDS=y
CONFIG_B43LEGACY_HWRNG=y
# CONFIG_B43LEGACY_DEBUG is not set
CONFIG_B43LEGACY_DMA=y
CONFIG_B43LEGACY_PIO=y
CONFIG_B43LEGACY_DMA_AND_PIO_MODE=y
# CONFIG_B43LEGACY_DMA_MODE is not set
# CONFIG_B43LEGACY_PIO_MODE is not set
CONFIG_BRCMUTIL=m
CONFIG_BRCMSMAC=m
CONFIG_BRCMSMAC_LEDS=y
CONFIG_BRCMFMAC=m
CONFIG_BRCMFMAC_PROTO_BCDC=y
CONFIG_BRCMFMAC_PROTO_MSGBUF=y
CONFIG_BRCMFMAC_SDIO=y
CONFIG_BRCMFMAC_USB=y
CONFIG_BRCMFMAC_PCIE=y
# CONFIG_BRCM_TRACING is not set
# CONFIG_BRCMDBG is not set
CONFIG_WLAN_VENDOR_INTEL=y
# CONFIG_IPW2100 is not set
# CONFIG_IPW2200 is not set
CONFIG_IWLEGACY=m
CONFIG_IWL4965=m
CONFIG_IWL3945=m

#
# iwl3945 / iwl4965 Debugging Options
#
CONFIG_IWLEGACY_DEBUG=y
CONFIG_IWLEGACY_DEBUGFS=y
# end of iwl3945 / iwl4965 Debugging Options

CONFIG_IWLWIFI=m
CONFIG_IWLWIFI_KUNIT_TESTS=m
CONFIG_IWLWIFI_LEDS=y
CONFIG_IWLDVM=m
CONFIG_IWLMVM=m
CONFIG_IWLMLD=m
CONFIG_IWLWIFI_OPMODE_MODULAR=y

#
# Debugging Options
#
CONFIG_IWLWIFI_DEBUG=y
CONFIG_IWLWIFI_DEBUGFS=y
# CONFIG_IWLWIFI_DEVICE_TRACING is not set
# end of Debugging Options

# CONFIG_WLAN_VENDOR_INTERSIL is not set
CONFIG_WLAN_VENDOR_MARVELL=y
# CONFIG_LIBERTAS is not set
CONFIG_LIBERTAS_THINFIRM=m
# CONFIG_LIBERTAS_THINFIRM_DEBUG is not set
CONFIG_LIBERTAS_THINFIRM_USB=m
CONFIG_MWIFIEX=m
CONFIG_MWIFIEX_SDIO=m
CONFIG_MWIFIEX_PCIE=m
CONFIG_MWIFIEX_USB=m
CONFIG_MWL8K=m
CONFIG_WLAN_VENDOR_MEDIATEK=y
CONFIG_MT7601U=m
CONFIG_MT76_CORE=m
CONFIG_MT76_LEDS=y
CONFIG_MT76_USB=m
CONFIG_MT76_SDIO=m
CONFIG_MT76x02_LIB=m
CONFIG_MT76x02_USB=m
CONFIG_MT76_CONNAC_LIB=m
CONFIG_MT792x_LIB=m
CONFIG_MT792x_USB=m
CONFIG_MT76x0_COMMON=m
CONFIG_MT76x0U=m
CONFIG_MT76x0E=m
CONFIG_MT76x2_COMMON=m
CONFIG_MT76x2E=m
CONFIG_MT76x2U=m
CONFIG_MT7603E=m
CONFIG_MT7615_COMMON=m
CONFIG_MT7615E=m
CONFIG_MT7663_USB_SDIO_COMMON=m
CONFIG_MT7663U=m
CONFIG_MT7663S=m
CONFIG_MT7915E=m
CONFIG_MT7921_COMMON=m
CONFIG_MT7921E=m
CONFIG_MT7921S=m
CONFIG_MT7921U=m
CONFIG_MT7996E=m
CONFIG_MT7925_COMMON=m
CONFIG_MT7925E=m
CONFIG_MT7925U=m
CONFIG_WLAN_VENDOR_MICROCHIP=y
# CONFIG_WILC1000_SDIO is not set
# CONFIG_WILC1000_SPI is not set
# CONFIG_WLAN_VENDOR_PURELIFI is not set
CONFIG_WLAN_VENDOR_RALINK=y
CONFIG_RT2X00=m
CONFIG_RT2400PCI=m
CONFIG_RT2500PCI=m
CONFIG_RT61PCI=m
CONFIG_RT2800PCI=m
CONFIG_RT2800PCI_RT33XX=y
CONFIG_RT2800PCI_RT35XX=y
CONFIG_RT2800PCI_RT53XX=y
CONFIG_RT2800PCI_RT3290=y
CONFIG_RT2500USB=m
CONFIG_RT73USB=m
CONFIG_RT2800USB=m
CONFIG_RT2800USB_RT33XX=y
CONFIG_RT2800USB_RT35XX=y
CONFIG_RT2800USB_RT3573=y
CONFIG_RT2800USB_RT53XX=y
CONFIG_RT2800USB_RT55XX=y
CONFIG_RT2800USB_UNKNOWN=y
CONFIG_RT2800_LIB=m
CONFIG_RT2800_LIB_MMIO=m
CONFIG_RT2X00_LIB_MMIO=m
CONFIG_RT2X00_LIB_PCI=m
CONFIG_RT2X00_LIB_USB=m
CONFIG_RT2X00_LIB=m
CONFIG_RT2X00_LIB_FIRMWARE=y
CONFIG_RT2X00_LIB_CRYPTO=y
CONFIG_RT2X00_LIB_LEDS=y
CONFIG_RT2X00_LIB_DEBUGFS=y
# CONFIG_RT2X00_DEBUG is not set
CONFIG_WLAN_VENDOR_REALTEK=y
CONFIG_RTL8180=m
CONFIG_RTL8187=m
CONFIG_RTL8187_LEDS=y
CONFIG_RTL_CARDS=m
CONFIG_RTL8192CE=m
CONFIG_RTL8192SE=m
CONFIG_RTL8192DE=m
CONFIG_RTL8723AE=m
CONFIG_RTL8723BE=m
CONFIG_RTL8188EE=m
CONFIG_RTL8192EE=m
CONFIG_RTL8821AE=m
# CONFIG_RTL8192CU is not set
CONFIG_RTL8192DU=m
CONFIG_RTLWIFI=m
CONFIG_RTLWIFI_PCI=m
CONFIG_RTLWIFI_USB=m
# CONFIG_RTLWIFI_DEBUG is not set
CONFIG_RTL8192C_COMMON=m
CONFIG_RTL8192D_COMMON=m
CONFIG_RTL8723_COMMON=m
CONFIG_RTLBTCOEXIST=m
CONFIG_RTL8XXXU=m
CONFIG_RTL8XXXU_UNTESTED=y
CONFIG_RTW88=m
CONFIG_RTW88_CORE=m
CONFIG_RTW88_PCI=m
CONFIG_RTW88_SDIO=m
CONFIG_RTW88_USB=m
CONFIG_RTW88_8822B=m
CONFIG_RTW88_8822C=m
CONFIG_RTW88_8723X=m
CONFIG_RTW88_8703B=m
CONFIG_RTW88_8723D=m
CONFIG_RTW88_8821C=m
CONFIG_RTW88_88XXA=m
CONFIG_RTW88_8821A=m
CONFIG_RTW88_8812A=m
CONFIG_RTW88_8814A=m
CONFIG_RTW88_8822BE=m
CONFIG_RTW88_8822BS=m
CONFIG_RTW88_8822BU=m
CONFIG_RTW88_8822CE=m
CONFIG_RTW88_8822CS=m
CONFIG_RTW88_8822CU=m
CONFIG_RTW88_8723DE=m
CONFIG_RTW88_8723DS=m
CONFIG_RTW88_8723CS=m
CONFIG_RTW88_8723DU=m
CONFIG_RTW88_8821CE=m
CONFIG_RTW88_8821CS=m
CONFIG_RTW88_8821CU=m
CONFIG_RTW88_8821AU=m
CONFIG_RTW88_8812AU=m
CONFIG_RTW88_8814AE=m
CONFIG_RTW88_8814AU=m
# CONFIG_RTW88_DEBUG is not set
# CONFIG_RTW88_DEBUGFS is not set
CONFIG_RTW88_LEDS=y
CONFIG_RTW89=m
CONFIG_RTW89_CORE=m
CONFIG_RTW89_PCI=m
CONFIG_RTW89_8851B=m
CONFIG_RTW89_8852A=m
CONFIG_RTW89_8852B_COMMON=m
CONFIG_RTW89_8852B=m
CONFIG_RTW89_8852BT=m
CONFIG_RTW89_8852C=m
CONFIG_RTW89_8922A=m
CONFIG_RTW89_8851BE=m
# CONFIG_RTW89_8851BU is not set
CONFIG_RTW89_8852AE=m
CONFIG_RTW89_8852BE=m
# CONFIG_RTW89_8852BU is not set
CONFIG_RTW89_8852BTE=m
CONFIG_RTW89_8852CE=m
CONFIG_RTW89_8922AE=m
# CONFIG_RTW89_DEBUGMSG is not set
# CONFIG_RTW89_DEBUGFS is not set
CONFIG_WLAN_VENDOR_RSI=y
CONFIG_RSI_91X=m
CONFIG_RSI_DEBUGFS=y
CONFIG_RSI_SDIO=m
CONFIG_RSI_USB=m
CONFIG_RSI_COEX=y
# CONFIG_WLAN_VENDOR_SILABS is not set
CONFIG_WLAN_VENDOR_ST=y
CONFIG_CW1200=m
CONFIG_CW1200_WLAN_SDIO=m
CONFIG_CW1200_WLAN_SPI=m
CONFIG_WLAN_VENDOR_TI=y
CONFIG_WL1251=m
CONFIG_WL1251_SPI=m
CONFIG_WL1251_SDIO=m
CONFIG_WL12XX=m
CONFIG_WL18XX=m
CONFIG_WLCORE=m
CONFIG_WLCORE_SPI=m
CONFIG_WLCORE_SDIO=m
CONFIG_WLAN_VENDOR_ZYDAS=y
CONFIG_ZD1211RW=m
# CONFIG_ZD1211RW_DEBUG is not set
CONFIG_WLAN_VENDOR_QUANTENNA=y
CONFIG_QTNFMAC=m
CONFIG_QTNFMAC_PCIE=m
CONFIG_MAC80211_HWSIM=m
CONFIG_VIRT_WIFI=m
# CONFIG_WAN is not set
CONFIG_IEEE802154_DRIVERS=m
CONFIG_IEEE802154_FAKELB=m
CONFIG_IEEE802154_AT86RF230=m
CONFIG_IEEE802154_MRF24J40=m
CONFIG_IEEE802154_CC2520=m
CONFIG_IEEE802154_ATUSB=m
CONFIG_IEEE802154_ADF7242=m
CONFIG_IEEE802154_CA8210=m
# CONFIG_IEEE802154_CA8210_DEBUGFS is not set
CONFIG_IEEE802154_MCR20A=m
# CONFIG_IEEE802154_HWSIM is not set

#
# Wireless WAN
#
CONFIG_WWAN=y
CONFIG_WWAN_DEBUGFS=y
CONFIG_WWAN_HWSIM=m
CONFIG_MHI_WWAN_CTRL=m
CONFIG_MHI_WWAN_MBIM=m
CONFIG_QCOM_BAM_DMUX=m
CONFIG_RPMSG_WWAN_CTRL=m
CONFIG_IOSM=m
CONFIG_MTK_T7XX=m
# end of Wireless WAN

CONFIG_VMXNET3=m
# CONFIG_FUJITSU_ES is not set
CONFIG_USB4_NET=m
CONFIG_HYPERV_NET=m
CONFIG_NETDEVSIM=m
CONFIG_NET_FAILOVER=m
# CONFIG_ISDN is not set

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=y
CONFIG_INPUT_FF_MEMLESS=m
CONFIG_INPUT_SPARSEKMAP=m
CONFIG_INPUT_MATRIXKMAP=m
CONFIG_INPUT_VIVALDIFMAP=y

#
# Userland interfaces
#
CONFIG_INPUT_MOUSEDEV=y
# CONFIG_INPUT_MOUSEDEV_PSAUX is not set
CONFIG_INPUT_MOUSEDEV_SCREEN_X=1024
CONFIG_INPUT_MOUSEDEV_SCREEN_Y=768
CONFIG_INPUT_JOYDEV=m
CONFIG_INPUT_EVDEV=y
CONFIG_INPUT_KUNIT_TEST=m

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
CONFIG_KEYBOARD_ADC=m
# CONFIG_KEYBOARD_ADP5585 is not set
# CONFIG_KEYBOARD_ADP5588 is not set
CONFIG_KEYBOARD_ATKBD=y
CONFIG_KEYBOARD_QT1050=m
CONFIG_KEYBOARD_QT1070=m
# CONFIG_KEYBOARD_QT2160 is not set
# CONFIG_KEYBOARD_DLINK_DIR685 is not set
# CONFIG_KEYBOARD_LKKBD is not set
CONFIG_KEYBOARD_GPIO=m
CONFIG_KEYBOARD_GPIO_POLLED=m
# CONFIG_KEYBOARD_TCA6416 is not set
# CONFIG_KEYBOARD_TCA8418 is not set
# CONFIG_KEYBOARD_MATRIX is not set
# CONFIG_KEYBOARD_LM8323 is not set
# CONFIG_KEYBOARD_LM8333 is not set
# CONFIG_KEYBOARD_MAX7359 is not set
# CONFIG_KEYBOARD_MPR121 is not set
CONFIG_KEYBOARD_SNVS_PWRKEY=m
# CONFIG_KEYBOARD_IMX is not set
CONFIG_KEYBOARD_IMX_BBM_SCMI=y
CONFIG_KEYBOARD_IMX_SC_KEY=m
# CONFIG_KEYBOARD_NEWTON is not set
CONFIG_KEYBOARD_TEGRA=m
# CONFIG_KEYBOARD_OPENCORES is not set
CONFIG_KEYBOARD_PINEPHONE=m
# CONFIG_KEYBOARD_SAMSUNG is not set
# CONFIG_KEYBOARD_STOWAWAY is not set
# CONFIG_KEYBOARD_SUNKBD is not set
CONFIG_KEYBOARD_STMPE=m
# CONFIG_KEYBOARD_SUN4I_LRADC is not set
# CONFIG_KEYBOARD_OMAP4 is not set
CONFIG_KEYBOARD_TM2_TOUCHKEY=m
# CONFIG_KEYBOARD_XTKBD is not set
CONFIG_KEYBOARD_CROS_EC=m
# CONFIG_KEYBOARD_CAP11XX is not set
# CONFIG_KEYBOARD_BCM is not set
CONFIG_KEYBOARD_CYPRESS_SF=m
CONFIG_INPUT_MOUSE=y
# CONFIG_MOUSE_PS2 is not set
# CONFIG_MOUSE_SERIAL is not set
CONFIG_MOUSE_APPLETOUCH=m
CONFIG_MOUSE_BCM5974=m
CONFIG_MOUSE_CYAPA=m
CONFIG_MOUSE_ELAN_I2C=m
CONFIG_MOUSE_ELAN_I2C_I2C=y
CONFIG_MOUSE_ELAN_I2C_SMBUS=y
CONFIG_MOUSE_VSXXXAA=m
# CONFIG_MOUSE_GPIO is not set
CONFIG_MOUSE_SYNAPTICS_I2C=m
CONFIG_MOUSE_SYNAPTICS_USB=m
CONFIG_INPUT_JOYSTICK=y
CONFIG_JOYSTICK_ANALOG=m
CONFIG_JOYSTICK_A3D=m
CONFIG_JOYSTICK_ADC=m
CONFIG_JOYSTICK_ADI=m
CONFIG_JOYSTICK_COBRA=m
CONFIG_JOYSTICK_GF2K=m
CONFIG_JOYSTICK_GRIP=m
CONFIG_JOYSTICK_GRIP_MP=m
CONFIG_JOYSTICK_GUILLEMOT=m
CONFIG_JOYSTICK_INTERACT=m
CONFIG_JOYSTICK_SIDEWINDER=m
CONFIG_JOYSTICK_TMDC=m
CONFIG_JOYSTICK_IFORCE=m
CONFIG_JOYSTICK_IFORCE_USB=m
CONFIG_JOYSTICK_IFORCE_232=m
# CONFIG_JOYSTICK_WARRIOR is not set
# CONFIG_JOYSTICK_MAGELLAN is not set
# CONFIG_JOYSTICK_SPACEORB is not set
# CONFIG_JOYSTICK_SPACEBALL is not set
# CONFIG_JOYSTICK_STINGER is not set
# CONFIG_JOYSTICK_TWIDJOY is not set
# CONFIG_JOYSTICK_ZHENHUA is not set
# CONFIG_JOYSTICK_AS5011 is not set
CONFIG_JOYSTICK_JOYDUMP=m
CONFIG_JOYSTICK_XPAD=m
CONFIG_JOYSTICK_XPAD_FF=y
CONFIG_JOYSTICK_XPAD_LEDS=y
CONFIG_JOYSTICK_PSXPAD_SPI=m
CONFIG_JOYSTICK_PSXPAD_SPI_FF=y
CONFIG_JOYSTICK_PXRC=m
CONFIG_JOYSTICK_QWIIC=m
# CONFIG_JOYSTICK_FSIA6B is not set
CONFIG_JOYSTICK_SENSEHAT=m
# CONFIG_JOYSTICK_SEESAW is not set
CONFIG_INPUT_TABLET=y
CONFIG_TABLET_USB_ACECAD=m
CONFIG_TABLET_USB_AIPTEK=m
CONFIG_TABLET_USB_HANWANG=m
CONFIG_TABLET_USB_KBTAB=m
CONFIG_TABLET_USB_PEGASUS=m
CONFIG_TABLET_SERIAL_WACOM4=m
CONFIG_INPUT_TOUCHSCREEN=y
CONFIG_TOUCHSCREEN_ADS7846=m
# CONFIG_TOUCHSCREEN_AD7877 is not set
# CONFIG_TOUCHSCREEN_AD7879 is not set
CONFIG_TOUCHSCREEN_ADC=m
CONFIG_TOUCHSCREEN_APPLE_Z2=m
# CONFIG_TOUCHSCREEN_AR1021_I2C is not set
CONFIG_TOUCHSCREEN_ATMEL_MXT=m
# CONFIG_TOUCHSCREEN_ATMEL_MXT_T37 is not set
CONFIG_TOUCHSCREEN_AUO_PIXCIR=m
# CONFIG_TOUCHSCREEN_BU21013 is not set
# CONFIG_TOUCHSCREEN_BU21029 is not set
# CONFIG_TOUCHSCREEN_CHIPONE_ICN8318 is not set
# CONFIG_TOUCHSCREEN_CHIPONE_ICN8505 is not set
CONFIG_TOUCHSCREEN_CY8CTMA140=m
# CONFIG_TOUCHSCREEN_CY8CTMG110 is not set
# CONFIG_TOUCHSCREEN_CYTTSP_CORE is not set
CONFIG_TOUCHSCREEN_CYTTSP5=m
# CONFIG_TOUCHSCREEN_DYNAPRO is not set
# CONFIG_TOUCHSCREEN_HAMPSHIRE is not set
CONFIG_TOUCHSCREEN_EETI=m
CONFIG_TOUCHSCREEN_EGALAX=m
# CONFIG_TOUCHSCREEN_EGALAX_SERIAL is not set
CONFIG_TOUCHSCREEN_EXC3000=m
# CONFIG_TOUCHSCREEN_FUJITSU is not set
CONFIG_TOUCHSCREEN_GOODIX=m
# CONFIG_TOUCHSCREEN_GOODIX_BERLIN_I2C is not set
# CONFIG_TOUCHSCREEN_GOODIX_BERLIN_SPI is not set
# CONFIG_TOUCHSCREEN_HIDEEP is not set
CONFIG_TOUCHSCREEN_HYCON_HY46XX=m
CONFIG_TOUCHSCREEN_HYNITRON_CSTXXX=m
CONFIG_TOUCHSCREEN_ILI210X=m
CONFIG_TOUCHSCREEN_ILITEK=m
# CONFIG_TOUCHSCREEN_S6SY761 is not set
# CONFIG_TOUCHSCREEN_GUNZE is not set
# CONFIG_TOUCHSCREEN_EKTF2127 is not set
CONFIG_TOUCHSCREEN_ELAN=m
# CONFIG_TOUCHSCREEN_ELO is not set
# CONFIG_TOUCHSCREEN_WACOM_W8001 is not set
CONFIG_TOUCHSCREEN_WACOM_I2C=m
# CONFIG_TOUCHSCREEN_MAX11801 is not set
CONFIG_TOUCHSCREEN_MMS114=m
# CONFIG_TOUCHSCREEN_MELFAS_MIP4 is not set
CONFIG_TOUCHSCREEN_MSG2638=m
# CONFIG_TOUCHSCREEN_MTOUCH is not set
CONFIG_TOUCHSCREEN_NOVATEK_NVT_TS=m
CONFIG_TOUCHSCREEN_IMAGIS=m
# CONFIG_TOUCHSCREEN_IMX6UL_TSC is not set
# CONFIG_TOUCHSCREEN_INEXIO is not set
# CONFIG_TOUCHSCREEN_PENMOUNT is not set
CONFIG_TOUCHSCREEN_EDT_FT5X06=m
CONFIG_TOUCHSCREEN_RASPBERRYPI_FW=m
# CONFIG_TOUCHSCREEN_TOUCHRIGHT is not set
# CONFIG_TOUCHSCREEN_TOUCHWIN is not set
CONFIG_TOUCHSCREEN_TI_AM335X_TSC=m
CONFIG_TOUCHSCREEN_PIXCIR=m
# CONFIG_TOUCHSCREEN_WDT87XX_I2C is not set
# CONFIG_TOUCHSCREEN_WM97XX is not set
CONFIG_TOUCHSCREEN_USB_COMPOSITE=m
CONFIG_TOUCHSCREEN_USB_EGALAX=y
CONFIG_TOUCHSCREEN_USB_PANJIT=y
CONFIG_TOUCHSCREEN_USB_3M=y
CONFIG_TOUCHSCREEN_USB_ITM=y
CONFIG_TOUCHSCREEN_USB_ETURBO=y
CONFIG_TOUCHSCREEN_USB_GUNZE=y
CONFIG_TOUCHSCREEN_USB_DMC_TSC10=y
CONFIG_TOUCHSCREEN_USB_IRTOUCH=y
CONFIG_TOUCHSCREEN_USB_IDEALTEK=y
CONFIG_TOUCHSCREEN_USB_GENERAL_TOUCH=y
CONFIG_TOUCHSCREEN_USB_GOTOP=y
CONFIG_TOUCHSCREEN_USB_JASTEC=y
CONFIG_TOUCHSCREEN_USB_ELO=y
CONFIG_TOUCHSCREEN_USB_E2I=y
CONFIG_TOUCHSCREEN_USB_ZYTRONIC=y
CONFIG_TOUCHSCREEN_USB_ETT_TC45USB=y
CONFIG_TOUCHSCREEN_USB_NEXIO=y
CONFIG_TOUCHSCREEN_USB_EASYTOUCH=y
# CONFIG_TOUCHSCREEN_TOUCHIT213 is not set
# CONFIG_TOUCHSCREEN_TSC_SERIO is not set
# CONFIG_TOUCHSCREEN_TSC2004 is not set
# CONFIG_TOUCHSCREEN_TSC2005 is not set
CONFIG_TOUCHSCREEN_TSC2007=m
CONFIG_TOUCHSCREEN_TSC2007_IIO=y
CONFIG_TOUCHSCREEN_RM_TS=m
CONFIG_TOUCHSCREEN_SILEAD=m
CONFIG_TOUCHSCREEN_SIS_I2C=m
CONFIG_TOUCHSCREEN_ST1232=m
# CONFIG_TOUCHSCREEN_STMFTS is not set
CONFIG_TOUCHSCREEN_STMPE=m
# CONFIG_TOUCHSCREEN_SUN4I is not set
# CONFIG_TOUCHSCREEN_SUR40 is not set
# CONFIG_TOUCHSCREEN_SURFACE3_SPI is not set
# CONFIG_TOUCHSCREEN_SX8654 is not set
# CONFIG_TOUCHSCREEN_TPS6507X is not set
CONFIG_TOUCHSCREEN_ZET6223=m
CONFIG_TOUCHSCREEN_ZFORCE=m
CONFIG_TOUCHSCREEN_COLIBRI_VF50=m
# CONFIG_TOUCHSCREEN_ROHM_BU21023 is not set
CONFIG_TOUCHSCREEN_IQS5XX=m
CONFIG_TOUCHSCREEN_IQS7211=m
CONFIG_TOUCHSCREEN_ZINITIX=m
CONFIG_TOUCHSCREEN_HIMAX_HX83112B=m
CONFIG_INPUT_MISC=y
CONFIG_INPUT_88PM886_ONKEY=m
# CONFIG_INPUT_AD714X is not set
# CONFIG_INPUT_ATMEL_CAPTOUCH is not set
CONFIG_INPUT_BBNSM_PWRKEY=m
# CONFIG_INPUT_BMA150 is not set
CONFIG_INPUT_CS40L50_VIBRA=m
CONFIG_INPUT_E3X0_BUTTON=m
CONFIG_INPUT_PM8941_PWRKEY=m
CONFIG_INPUT_PM8XXX_VIBRATOR=m
CONFIG_INPUT_MAX77650_ONKEY=m
CONFIG_INPUT_MAX77693_HAPTIC=m
# CONFIG_INPUT_MMA8450 is not set
# CONFIG_INPUT_GPIO_BEEPER is not set
# CONFIG_INPUT_GPIO_DECODER is not set
CONFIG_INPUT_GPIO_VIBRA=m
# CONFIG_INPUT_ATI_REMOTE2 is not set
# CONFIG_INPUT_KEYSPAN_REMOTE is not set
CONFIG_INPUT_KXTJ9=m
# CONFIG_INPUT_POWERMATE is not set
# CONFIG_INPUT_YEALINK is not set
# CONFIG_INPUT_CM109 is not set
# CONFIG_INPUT_REGULATOR_HAPTIC is not set
CONFIG_INPUT_TPS65219_PWRBUTTON=m
CONFIG_INPUT_AXP20X_PEK=m
CONFIG_INPUT_UINPUT=m
# CONFIG_INPUT_PCF8574 is not set
CONFIG_INPUT_PWM_BEEPER=m
# CONFIG_INPUT_PWM_VIBRA is not set
CONFIG_INPUT_RK805_PWRKEY=m
# CONFIG_INPUT_GPIO_ROTARY_ENCODER is not set
# CONFIG_INPUT_DA7280_HAPTICS is not set
# CONFIG_INPUT_ADXL34X is not set
# CONFIG_INPUT_IBM_PANEL is not set
# CONFIG_INPUT_IMS_PCU is not set
CONFIG_INPUT_IQS269A=m
CONFIG_INPUT_IQS626A=m
CONFIG_INPUT_IQS7222=m
CONFIG_INPUT_CMA3000=m
CONFIG_INPUT_CMA3000_I2C=m
CONFIG_INPUT_SOC_BUTTON_ARRAY=m
# CONFIG_INPUT_DRV260X_HAPTICS is not set
# CONFIG_INPUT_DRV2665_HAPTICS is not set
# CONFIG_INPUT_DRV2667_HAPTICS is not set
CONFIG_INPUT_HISI_POWERKEY=y
CONFIG_INPUT_QNAP_MCU=m
CONFIG_INPUT_RT5120_PWRKEY=m
CONFIG_RMI4_CORE=m
CONFIG_RMI4_I2C=m
CONFIG_RMI4_SPI=m
CONFIG_RMI4_SMB=m
CONFIG_RMI4_F03=y
CONFIG_RMI4_F03_SERIO=m
CONFIG_RMI4_2D_SENSOR=y
CONFIG_RMI4_F11=y
CONFIG_RMI4_F12=y
# CONFIG_RMI4_F1A is not set
# CONFIG_RMI4_F21 is not set
CONFIG_RMI4_F30=y
CONFIG_RMI4_F34=y
CONFIG_RMI4_F3A=y
# CONFIG_RMI4_F54 is not set
CONFIG_RMI4_F55=y

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_SERIO_SERPORT=m
CONFIG_SERIO_AMBAKMI=m
# CONFIG_SERIO_PCIPS2 is not set
CONFIG_SERIO_LIBPS2=y
CONFIG_SERIO_RAW=m
CONFIG_SERIO_ALTERA_PS2=m
# CONFIG_SERIO_PS2MULT is not set
CONFIG_SERIO_ARC_PS2=m
# CONFIG_SERIO_APBPS2 is not set
CONFIG_HYPERV_KEYBOARD=m
# CONFIG_SERIO_SUN4I_PS2 is not set
# CONFIG_SERIO_GPIO_PS2 is not set
# CONFIG_USERIO is not set
CONFIG_GAMEPORT=m
CONFIG_GAMEPORT_EMU10K1=m
CONFIG_GAMEPORT_FM801=m
# end of Hardware I/O ports
# end of Input device support

#
# Character devices
#
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_CONSOLE_TRANSLATIONS=y
CONFIG_VT_CONSOLE=y
CONFIG_VT_CONSOLE_SLEEP=y
CONFIG_VT_HW_CONSOLE_BINDING=y
CONFIG_UNIX98_PTYS=y
# CONFIG_LEGACY_PTYS is not set
# CONFIG_LEGACY_TIOCSTI is not set
CONFIG_LDISC_AUTOLOAD=y

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
# CONFIG_SERIAL_8250_DEPRECATED_OPTIONS is not set
CONFIG_SERIAL_8250_PNP=y
# CONFIG_SERIAL_8250_16550A_VARIANTS is not set
# CONFIG_SERIAL_8250_FINTEK is not set
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCILIB=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=m
CONFIG_SERIAL_8250_NR_UARTS=32
CONFIG_SERIAL_8250_RUNTIME_UARTS=32
CONFIG_SERIAL_8250_EXTENDED=y
CONFIG_SERIAL_8250_MANY_PORTS=y
CONFIG_SERIAL_8250_PCI1XXXX=y
CONFIG_SERIAL_8250_SHARE_IRQ=y
# CONFIG_SERIAL_8250_DETECT_IRQ is not set
CONFIG_SERIAL_8250_RSA=y
CONFIG_SERIAL_8250_DWLIB=y
CONFIG_SERIAL_8250_BCM2835AUX=y
CONFIG_SERIAL_8250_FSL=y
CONFIG_SERIAL_8250_DFL=m
CONFIG_SERIAL_8250_DW=y
CONFIG_SERIAL_8250_EM=y
CONFIG_SERIAL_8250_RT288X=y
CONFIG_SERIAL_8250_OMAP=y
CONFIG_SERIAL_8250_OMAP_TTYO_FIXUP=y
CONFIG_SERIAL_8250_PERICOM=y
CONFIG_SERIAL_8250_TEGRA=y
CONFIG_SERIAL_OF_PLATFORM=y

#
# Non-8250 serial port support
#
# CONFIG_SERIAL_AMBA_PL010 is not set
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_SERIAL_EARLYCON_SEMIHOST=y
CONFIG_SERIAL_MESON=y
CONFIG_SERIAL_MESON_CONSOLE=y
CONFIG_SERIAL_SAMSUNG=y
CONFIG_SERIAL_SAMSUNG_UARTS=4
CONFIG_SERIAL_SAMSUNG_CONSOLE=y
CONFIG_SERIAL_TEGRA=y
CONFIG_SERIAL_TEGRA_TCU=y
CONFIG_SERIAL_TEGRA_TCU_CONSOLE=y
CONFIG_SERIAL_TEGRA_UTC=m
CONFIG_SERIAL_TEGRA_UTC_CONSOLE=y
# CONFIG_SERIAL_MAX3100 is not set
# CONFIG_SERIAL_MAX310X is not set
CONFIG_SERIAL_IMX=y
CONFIG_SERIAL_IMX_CONSOLE=y
# CONFIG_SERIAL_IMX_EARLYCON is not set
# CONFIG_SERIAL_UARTLITE is not set
CONFIG_SERIAL_SH_SCI=y
CONFIG_SERIAL_SH_SCI_NR_UARTS=18
CONFIG_SERIAL_SH_SCI_CONSOLE=y
CONFIG_SERIAL_SH_SCI_EARLYCON=y
CONFIG_SERIAL_SH_SCI_DMA=y
# CONFIG_SERIAL_RSCI is not set
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
CONFIG_CONSOLE_POLL=y
CONFIG_SERIAL_JSM=m
CONFIG_SERIAL_MSM=y
CONFIG_SERIAL_MSM_CONSOLE=y
CONFIG_SERIAL_QCOM_GENI=y
CONFIG_SERIAL_QCOM_GENI_CONSOLE=y
# CONFIG_SERIAL_SIFIVE is not set
# CONFIG_SERIAL_SCCNXP is not set
CONFIG_SERIAL_SC16IS7XX=m
CONFIG_SERIAL_SC16IS7XX_I2C=m
CONFIG_SERIAL_SC16IS7XX_SPI=m
# CONFIG_SERIAL_ALTERA_JTAGUART is not set
# CONFIG_SERIAL_ALTERA_UART is not set
CONFIG_SERIAL_XILINX_PS_UART=y
CONFIG_SERIAL_XILINX_PS_UART_CONSOLE=y
CONFIG_SERIAL_ARC=m
CONFIG_SERIAL_ARC_NR_PORTS=1
# CONFIG_SERIAL_RP2 is not set
CONFIG_SERIAL_FSL_LPUART=y
CONFIG_SERIAL_FSL_LPUART_CONSOLE=y
CONFIG_SERIAL_FSL_LINFLEXUART=y
CONFIG_SERIAL_FSL_LINFLEXUART_CONSOLE=y
# CONFIG_SERIAL_CONEXANT_DIGICOLOR is not set
# CONFIG_SERIAL_SPRD is not set
CONFIG_SERIAL_MVEBU_UART=y
CONFIG_SERIAL_MVEBU_CONSOLE=y
# end of Serial drivers

CONFIG_SERIAL_MCTRL_GPIO=y
# CONFIG_SERIAL_NONSTANDARD is not set
# CONFIG_N_GSM is not set
CONFIG_NOZOMI=m
CONFIG_NULL_TTY=m
CONFIG_HVC_DRIVER=y
# CONFIG_HVC_DCC is not set
CONFIG_RPMSG_TTY=m
CONFIG_SERIAL_DEV_BUS=y
CONFIG_SERIAL_DEV_CTRL_TTYPORT=y
# CONFIG_TTY_PRINTK is not set
CONFIG_VIRTIO_CONSOLE=y
CONFIG_IPMI_HANDLER=m
CONFIG_IPMI_DMI_DECODE=y
CONFIG_IPMI_PLAT_DATA=y
# CONFIG_IPMI_PANIC_EVENT is not set
CONFIG_IPMI_DEVICE_INTERFACE=m
CONFIG_IPMI_SI=m
CONFIG_IPMI_SSIF=m
CONFIG_IPMI_IPMB=m
CONFIG_IPMI_WATCHDOG=m
CONFIG_IPMI_POWEROFF=m
CONFIG_SSIF_IPMI_BMC=m
CONFIG_IPMB_DEVICE_INTERFACE=m
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_TIMERIOMEM=m
# CONFIG_HW_RANDOM_BA431 is not set
CONFIG_HW_RANDOM_BCM2835=m
CONFIG_HW_RANDOM_IPROC_RNG200=m
CONFIG_HW_RANDOM_OMAP=m
CONFIG_HW_RANDOM_VIRTIO=y
CONFIG_HW_RANDOM_HISI=m
CONFIG_HW_RANDOM_HISTB=y
CONFIG_HW_RANDOM_XGENE=m
CONFIG_HW_RANDOM_MESON=m
CONFIG_HW_RANDOM_CAVIUM=m
CONFIG_HW_RANDOM_OPTEE=m
# CONFIG_HW_RANDOM_CCTRNG is not set
CONFIG_HW_RANDOM_XIPHERA=m
CONFIG_HW_RANDOM_ARM_SMCCC_TRNG=y
CONFIG_HW_RANDOM_CN10K=m
CONFIG_HW_RANDOM_ROCKCHIP=m
# CONFIG_APPLICOM is not set
CONFIG_DEVMEM=y
CONFIG_DEVPORT=y
CONFIG_TCG_TPM=y
CONFIG_TCG_TPM2_HMAC=y
CONFIG_HW_RANDOM_TPM=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_TIS=y
CONFIG_TCG_TIS_SPI=m
CONFIG_TCG_TIS_SPI_CR50=y
CONFIG_TCG_TIS_I2C=m
CONFIG_TCG_TIS_SYNQUACER=m
CONFIG_TCG_TIS_I2C_CR50=m
CONFIG_TCG_TIS_I2C_ATMEL=m
CONFIG_TCG_TIS_I2C_INFINEON=m
CONFIG_TCG_TIS_I2C_NUVOTON=m
CONFIG_TCG_ATMEL=m
# CONFIG_TCG_INFINEON is not set
CONFIG_TCG_CRB=y
CONFIG_TCG_ARM_CRB_FFA=y
CONFIG_TCG_VTPM_PROXY=m
CONFIG_TCG_FTPM_TEE=m
# CONFIG_TCG_TIS_ST33ZP24_I2C is not set
# CONFIG_TCG_TIS_ST33ZP24_SPI is not set
CONFIG_XILLYBUS_CLASS=m
CONFIG_XILLYBUS=m
CONFIG_XILLYBUS_PCIE=m
CONFIG_XILLYBUS_OF=m
CONFIG_XILLYUSB=m
# end of Character devices

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
CONFIG_I2C_CHARDEV=m
CONFIG_I2C_MUX=m

#
# Multiplexer I2C Chip support
#
CONFIG_I2C_ARB_GPIO_CHALLENGE=m
CONFIG_I2C_MUX_GPIO=m
CONFIG_I2C_MUX_GPMUX=m
CONFIG_I2C_MUX_LTC4306=m
CONFIG_I2C_MUX_PCA9541=m
CONFIG_I2C_MUX_PCA954x=m
CONFIG_I2C_MUX_PINCTRL=m
CONFIG_I2C_MUX_REG=m
# CONFIG_I2C_DEMUX_PINCTRL is not set
CONFIG_I2C_MUX_MLXCPLD=m
CONFIG_I2C_MUX_MULE=m
# end of Multiplexer I2C Chip support

CONFIG_I2C_ATR=m
CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=m
CONFIG_I2C_ALGOBIT=m
CONFIG_I2C_ALGOPCA=m

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
CONFIG_I2C_CCGX_UCSI=m
# CONFIG_I2C_ALI1535 is not set
# CONFIG_I2C_ALI1563 is not set
# CONFIG_I2C_ALI15X3 is not set
# CONFIG_I2C_AMD756 is not set
# CONFIG_I2C_AMD8111 is not set
CONFIG_I2C_AMD_MP2=m
# CONFIG_I2C_HIX5HD2 is not set
# CONFIG_I2C_I801 is not set
# CONFIG_I2C_ISCH is not set
# CONFIG_I2C_PIIX4 is not set
CONFIG_I2C_NFORCE2=m
CONFIG_I2C_NVIDIA_GPU=m
# CONFIG_I2C_SIS5595 is not set
# CONFIG_I2C_SIS630 is not set
# CONFIG_I2C_SIS96X is not set
# CONFIG_I2C_VIA is not set
# CONFIG_I2C_VIAPRO is not set
CONFIG_I2C_ZHAOXIN=m

#
# ACPI drivers
#
CONFIG_I2C_SCMI=m

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
CONFIG_I2C_BCM2835=m
CONFIG_I2C_BRCMSTB=m
CONFIG_I2C_CADENCE=m
# CONFIG_I2C_CBUS_GPIO is not set
CONFIG_I2C_DESIGNWARE_CORE=y
CONFIG_I2C_DESIGNWARE_SLAVE=y
CONFIG_I2C_DESIGNWARE_PLATFORM=y
# CONFIG_I2C_DESIGNWARE_AMDISP is not set
CONFIG_I2C_DESIGNWARE_PCI=m
# CONFIG_I2C_EMEV2 is not set
CONFIG_I2C_GPIO=m
# CONFIG_I2C_GPIO_FAULT_INJECTOR is not set
# CONFIG_I2C_HISI is not set
CONFIG_I2C_IMX=m
CONFIG_I2C_IMX_LPI2C=m
CONFIG_I2C_KEBA=m
CONFIG_I2C_MLXBF=m
CONFIG_I2C_MESON=m
CONFIG_I2C_MV64XXX=m
# CONFIG_I2C_NOMADIK is not set
# CONFIG_I2C_OCORES is not set
CONFIG_I2C_OMAP=m
CONFIG_I2C_APPLE=m
CONFIG_I2C_PCA_PLATFORM=m
CONFIG_I2C_PXA=m
# CONFIG_I2C_PXA_SLAVE is not set
CONFIG_I2C_QCOM_CCI=m
CONFIG_I2C_QCOM_GENI=m
CONFIG_I2C_QUP=m
CONFIG_I2C_RIIC=m
CONFIG_I2C_RK3X=y
# CONFIG_I2C_RZV2M is not set
# CONFIG_I2C_SH_MOBILE is not set
CONFIG_I2C_SIMTEC=m
CONFIG_I2C_SYNQUACER=m
CONFIG_I2C_TEGRA=m
CONFIG_I2C_TEGRA_BPMP=m
CONFIG_I2C_VERSATILE=m
CONFIG_I2C_THUNDERX=m
# CONFIG_I2C_XILINX is not set
CONFIG_I2C_XLP9XX=m
# CONFIG_I2C_RCAR is not set

#
# External I2C/SMBus adapter drivers
#
CONFIG_I2C_DIOLAN_U2C=m
CONFIG_I2C_DLN2=m
CONFIG_I2C_CP2615=m
CONFIG_I2C_PCI1XXXX=m
# CONFIG_I2C_ROBOTFUZZ_OSIF is not set
# CONFIG_I2C_TAOS_EVM is not set
CONFIG_I2C_TINY_USB=m

#
# Other I2C/SMBus bus drivers
#
CONFIG_I2C_MLXCPLD=m
CONFIG_I2C_CROS_EC_TUNNEL=m
CONFIG_I2C_XGENE_SLIMPRO=m
CONFIG_I2C_VIRTIO=m
# end of I2C Hardware Bus support

CONFIG_I2C_STUB=m
CONFIG_I2C_SLAVE=y
CONFIG_I2C_SLAVE_EEPROM=m
# CONFIG_I2C_SLAVE_TESTUNIT is not set
# CONFIG_I2C_DEBUG_CORE is not set
# CONFIG_I2C_DEBUG_ALGO is not set
# CONFIG_I2C_DEBUG_BUS is not set
# end of I2C support

CONFIG_I3C=m
# CONFIG_CDNS_I3C_MASTER is not set
# CONFIG_DW_I3C_MASTER is not set
CONFIG_SVC_I3C_MASTER=m
CONFIG_MIPI_I3C_HCI=m
CONFIG_MIPI_I3C_HCI_PCI=m
# CONFIG_RENESAS_I3C is not set
CONFIG_SPI=y
# CONFIG_SPI_DEBUG is not set
CONFIG_SPI_MASTER=y
CONFIG_SPI_MEM=y
CONFIG_SPI_OFFLOAD=y

#
# SPI Master Controller Drivers
#
# CONFIG_SPI_ALTERA is not set
CONFIG_SPI_ALTERA_CORE=m
CONFIG_SPI_ALTERA_DFL=m
CONFIG_SPI_AMLOGIC_SPIFC_A1=m
# CONFIG_SPI_AMLOGIC_SPISG is not set
CONFIG_SPI_APPLE=m
CONFIG_SPI_ARMADA_3700=m
# CONFIG_SPI_AXI_SPI_ENGINE is not set
CONFIG_SPI_BCM2835=m
CONFIG_SPI_BCM2835AUX=m
# CONFIG_SPI_BCM_QSPI is not set
CONFIG_SPI_BITBANG=m
CONFIG_SPI_CADENCE=m
CONFIG_SPI_CADENCE_QUADSPI=m
CONFIG_SPI_CADENCE_XSPI=m
CONFIG_SPI_CH341=m
# CONFIG_SPI_CS42L43 is not set
CONFIG_SPI_DESIGNWARE=m
CONFIG_SPI_DW_DMA=y
CONFIG_SPI_DW_PCI=m
CONFIG_SPI_DW_MMIO=m
CONFIG_SPI_DLN2=m
CONFIG_SPI_FSL_LPSPI=m
CONFIG_SPI_FSL_QUADSPI=m
# CONFIG_SPI_HISI_KUNPENG is not set
# CONFIG_SPI_HISI_SFC_V3XX is not set
CONFIG_SPI_NXP_FLEXSPI=m
CONFIG_SPI_GPIO=m
CONFIG_SPI_IMX=m
CONFIG_SPI_KSPI2=m
# CONFIG_SPI_FSL_SPI is not set
CONFIG_SPI_FSL_DSPI=m
CONFIG_SPI_MESON_SPICC=m
CONFIG_SPI_MESON_SPIFC=m
CONFIG_SPI_MICROCHIP_CORE=m
CONFIG_SPI_MICROCHIP_CORE_QSPI=m
# CONFIG_SPI_OC_TINY is not set
CONFIG_SPI_OMAP24XX=m
CONFIG_SPI_ORION=m
CONFIG_SPI_PCI1XXXX=m
CONFIG_SPI_PL022=m
CONFIG_SPI_ROCKCHIP=m
CONFIG_SPI_ROCKCHIP_SFC=m
CONFIG_SPI_RSPI=m
# CONFIG_SPI_RZV2H_RSPI is not set
# CONFIG_SPI_RZV2M_CSI is not set
CONFIG_SPI_QCOM_QSPI=m
CONFIG_SPI_QPIC_SNAND=m
CONFIG_SPI_QUP=m
CONFIG_SPI_QCOM_GENI=m
# CONFIG_SPI_SC18IS602 is not set
# CONFIG_SPI_SH_MSIOF is not set
# CONFIG_SPI_SH_HSPI is not set
# CONFIG_SPI_SIFIVE is not set
CONFIG_SPI_SN_F_OSPI=m
# CONFIG_SPI_SUN4I is not set
CONFIG_SPI_SUN6I=m
CONFIG_SPI_SYNQUACER=m
# CONFIG_SPI_MXIC is not set
CONFIG_SPI_TEGRA210_QUAD=y
CONFIG_SPI_TEGRA114=m
# CONFIG_SPI_TEGRA20_SFLASH is not set
# CONFIG_SPI_TEGRA20_SLINK is not set
CONFIG_SPI_THUNDERX=m
# CONFIG_SPI_XCOMM is not set
# CONFIG_SPI_XILINX is not set
CONFIG_SPI_XLP=m
CONFIG_SPI_ZYNQMP_GQSPI=m
CONFIG_SPI_AMD=y

#
# SPI Multiplexer support
#
CONFIG_SPI_MUX=m

#
# SPI Protocol Masters
#
CONFIG_SPI_SPIDEV=m
# CONFIG_SPI_LOOPBACK_TEST is not set
# CONFIG_SPI_TLE62X0 is not set
# CONFIG_SPI_SLAVE is not set
CONFIG_SPI_DYNAMIC=y

#
# SPI Offload triggers
#
# CONFIG_SPI_OFFLOAD_TRIGGER_ADI_UTIL_SD is not set
CONFIG_SPI_OFFLOAD_TRIGGER_PWM=m
CONFIG_SPMI=y
# CONFIG_SPMI_APPLE is not set
CONFIG_SPMI_HISI3670=m
CONFIG_SPMI_MSM_PMIC_ARB=y
# CONFIG_HSI is not set
CONFIG_PPS=y
# CONFIG_PPS_DEBUG is not set

#
# PPS clients support
#
# CONFIG_PPS_CLIENT_KTIMER is not set
CONFIG_PPS_CLIENT_LDISC=m
CONFIG_PPS_CLIENT_GPIO=m
CONFIG_PPS_GENERATOR=m
# CONFIG_PPS_GENERATOR_DUMMY is not set

#
# PTP clock support
#
CONFIG_PTP_1588_CLOCK=y
CONFIG_PTP_1588_CLOCK_OPTIONAL=y
CONFIG_PTP_1588_CLOCK_QORIQ=m
CONFIG_DP83640_PHY=m
# CONFIG_PTP_1588_CLOCK_INES is not set
CONFIG_PTP_1588_CLOCK_KVM=m
CONFIG_PTP_1588_CLOCK_VMCLOCK=m
CONFIG_PTP_1588_CLOCK_IDT82P33=m
CONFIG_PTP_1588_CLOCK_IDTCM=m
CONFIG_PTP_1588_CLOCK_FC3W=m
CONFIG_PTP_1588_CLOCK_MOCK=m
# CONFIG_PTP_1588_CLOCK_OCP is not set
CONFIG_PTP_DFL_TOD=m
# end of PTP clock support

#
# DPLL device support
#
CONFIG_DPLL=y
# CONFIG_ZL3073X_I2C is not set
# CONFIG_ZL3073X_SPI is not set
# end of DPLL device support

CONFIG_PINCTRL=y
CONFIG_GENERIC_PINCTRL_GROUPS=y
CONFIG_PINMUX=y
CONFIG_GENERIC_PINMUX_FUNCTIONS=y
CONFIG_PINCONF=y
CONFIG_GENERIC_PINCONF=y
# CONFIG_DEBUG_PINCTRL is not set
CONFIG_PINCTRL_AMD=y
CONFIG_PINCTRL_AMDISP=m
CONFIG_PINCTRL_APPLE_GPIO=m
CONFIG_PINCTRL_AS3722=y
CONFIG_PINCTRL_AXP209=m
# CONFIG_PINCTRL_AW9523 is not set
CONFIG_PINCTRL_CY8C95X0=m
CONFIG_PINCTRL_MAX77620=y
# CONFIG_PINCTRL_MCP23S08 is not set
# CONFIG_PINCTRL_MICROCHIP_SGPIO is not set
# CONFIG_PINCTRL_OCELOT is not set
CONFIG_PINCTRL_RK805=m
CONFIG_PINCTRL_ROCKCHIP=y
CONFIG_PINCTRL_SCMI=y
CONFIG_PINCTRL_SINGLE=y
# CONFIG_PINCTRL_STMFX is not set
# CONFIG_PINCTRL_SX150X is not set
CONFIG_PINCTRL_TPS6594=m
CONFIG_PINCTRL_ZYNQMP=y
CONFIG_PINCTRL_MLXBF3=m
CONFIG_PINCTRL_BCM2835=y
CONFIG_PINCTRL_CS42L43=m
CONFIG_PINCTRL_IMX=y
CONFIG_PINCTRL_IMX_SCMI=y
CONFIG_PINCTRL_IMX_SCU=y
CONFIG_PINCTRL_IMX8MM=y
CONFIG_PINCTRL_IMX8MN=y
CONFIG_PINCTRL_IMX8MP=y
CONFIG_PINCTRL_IMX8MQ=y
CONFIG_PINCTRL_IMX8QM=y
CONFIG_PINCTRL_IMX8QXP=y
CONFIG_PINCTRL_IMX8DXL=y
CONFIG_PINCTRL_IMX8ULP=y
CONFIG_PINCTRL_IMX91=y
CONFIG_PINCTRL_IMX93=y
CONFIG_PINCTRL_MESON=y
CONFIG_PINCTRL_MESON_GXBB=y
CONFIG_PINCTRL_MESON_GXL=y
CONFIG_PINCTRL_MESON8_PMX=y
CONFIG_PINCTRL_MESON_AXG=y
CONFIG_PINCTRL_MESON_AXG_PMX=y
CONFIG_PINCTRL_MESON_G12A=y
CONFIG_PINCTRL_MESON_A1=y
CONFIG_PINCTRL_MESON_S4=y
CONFIG_PINCTRL_AMLOGIC_A4=y
CONFIG_PINCTRL_AMLOGIC_C3=y
CONFIG_PINCTRL_AMLOGIC_T7=y
CONFIG_PINCTRL_MVEBU=y
CONFIG_PINCTRL_ARMADA_AP806=y
CONFIG_PINCTRL_ARMADA_CP110=y
CONFIG_PINCTRL_AC5=y
CONFIG_PINCTRL_ARMADA_37XX=y
CONFIG_PINCTRL_S32CC=y
CONFIG_PINCTRL_S32G2=y
CONFIG_PINCTRL_MSM=y
# CONFIG_PINCTRL_IPQ5018 is not set
# CONFIG_PINCTRL_IPQ5332 is not set
# CONFIG_PINCTRL_IPQ5424 is not set
# CONFIG_PINCTRL_IPQ8074 is not set
# CONFIG_PINCTRL_IPQ6018 is not set
# CONFIG_PINCTRL_IPQ9574 is not set
# CONFIG_PINCTRL_MDM9607 is not set
CONFIG_PINCTRL_MSM8916=m
# CONFIG_PINCTRL_MSM8917 is not set
# CONFIG_PINCTRL_MSM8953 is not set
# CONFIG_PINCTRL_MSM8976 is not set
# CONFIG_PINCTRL_MSM8994 is not set
CONFIG_PINCTRL_MSM8996=m
CONFIG_PINCTRL_MSM8998=m
CONFIG_PINCTRL_QCM2290=m
# CONFIG_PINCTRL_QCS404 is not set
# CONFIG_PINCTRL_QCS615 is not set
# CONFIG_PINCTRL_QCS8300 is not set
CONFIG_PINCTRL_QDF2XXX=m
# CONFIG_PINCTRL_QDU1000 is not set
CONFIG_PINCTRL_SA8775P=y
# CONFIG_PINCTRL_SAR2130P is not set
CONFIG_PINCTRL_SC7180=y
CONFIG_PINCTRL_SC7280=y
CONFIG_PINCTRL_SC8180X=y
CONFIG_PINCTRL_SC8280XP=y
# CONFIG_PINCTRL_SDM660 is not set
# CONFIG_PINCTRL_SDM670 is not set
CONFIG_PINCTRL_SDM845=m
# CONFIG_PINCTRL_SDX75 is not set
# CONFIG_PINCTRL_SM4450 is not set
CONFIG_PINCTRL_SM6115=m
# CONFIG_PINCTRL_SM6125 is not set
# CONFIG_PINCTRL_SM6350 is not set
# CONFIG_PINCTRL_SM6375 is not set
# CONFIG_PINCTRL_SM7150 is not set
# CONFIG_PINCTRL_MILOS is not set
# CONFIG_PINCTRL_SM8150 is not set
# CONFIG_PINCTRL_SM8250 is not set
# CONFIG_PINCTRL_SM8350 is not set
CONFIG_PINCTRL_SM8450=m
# CONFIG_PINCTRL_SM8550 is not set
# CONFIG_PINCTRL_SM8650 is not set
# CONFIG_PINCTRL_SM8750 is not set
CONFIG_PINCTRL_X1E80100=y
# CONFIG_PINCTRL_TLMM_TEST is not set
CONFIG_PINCTRL_QCOM_SPMI_PMIC=y
# CONFIG_PINCTRL_QCOM_SSBI_PMIC is not set
CONFIG_PINCTRL_LPASS_LPI=m
CONFIG_PINCTRL_SC7280_LPASS_LPI=m
CONFIG_PINCTRL_SM4250_LPASS_LPI=m
CONFIG_PINCTRL_SM6115_LPASS_LPI=m
CONFIG_PINCTRL_SM8250_LPASS_LPI=m
CONFIG_PINCTRL_SM8350_LPASS_LPI=m
CONFIG_PINCTRL_SM8450_LPASS_LPI=m
CONFIG_PINCTRL_SC8280XP_LPASS_LPI=m
# CONFIG_PINCTRL_SM8550_LPASS_LPI is not set
# CONFIG_PINCTRL_SM8650_LPASS_LPI is not set

#
# Renesas pinctrl drivers
#
CONFIG_PINCTRL_RENESAS=y
CONFIG_PINCTRL_SH_PFC=y
CONFIG_PINCTRL_PFC_R8A774A1=y
CONFIG_PINCTRL_RZG2L=y
CONFIG_PINCTRL_RZV2M=y
# end of Renesas pinctrl drivers

CONFIG_PINCTRL_SUNXI=y
# CONFIG_PINCTRL_SUN4I_A10 is not set
# CONFIG_PINCTRL_SUN5I is not set
# CONFIG_PINCTRL_SUN6I_A31 is not set
# CONFIG_PINCTRL_SUN6I_A31_R is not set
# CONFIG_PINCTRL_SUN8I_A23 is not set
# CONFIG_PINCTRL_SUN8I_A33 is not set
# CONFIG_PINCTRL_SUN8I_A83T is not set
# CONFIG_PINCTRL_SUN8I_A83T_R is not set
# CONFIG_PINCTRL_SUN8I_A23_R is not set
CONFIG_PINCTRL_SUN8I_H3=y
CONFIG_PINCTRL_SUN8I_H3_R=y
# CONFIG_PINCTRL_SUN8I_V3S is not set
# CONFIG_PINCTRL_SUN9I_A80 is not set
# CONFIG_PINCTRL_SUN9I_A80_R is not set
CONFIG_PINCTRL_SUN20I_D1=y
CONFIG_PINCTRL_SUN50I_A64=y
CONFIG_PINCTRL_SUN50I_A64_R=y
CONFIG_PINCTRL_SUN50I_A100=y
CONFIG_PINCTRL_SUN50I_A100_R=y
CONFIG_PINCTRL_SUN50I_H5=y
CONFIG_PINCTRL_SUN50I_H6=y
CONFIG_PINCTRL_SUN50I_H6_R=y
CONFIG_PINCTRL_SUN50I_H616=y
CONFIG_PINCTRL_SUN50I_H616_R=y
CONFIG_PINCTRL_SUN55I_A523=y
CONFIG_PINCTRL_SUN55I_A523_R=y
CONFIG_PINCTRL_TEGRA=y
CONFIG_PINCTRL_TEGRA124=y
CONFIG_PINCTRL_TEGRA210=y
CONFIG_PINCTRL_TEGRA194=y
CONFIG_PINCTRL_TEGRA234=y
CONFIG_PINCTRL_TEGRA_XUSB=y
CONFIG_GPIOLIB=y
CONFIG_GPIOLIB_LEGACY=y
CONFIG_GPIOLIB_FASTPATH_LIMIT=512
CONFIG_OF_GPIO=y
CONFIG_GPIO_ACPI=y
CONFIG_GPIOLIB_IRQCHIP=y
# CONFIG_DEBUG_GPIO is not set
# CONFIG_GPIO_SYSFS is not set
CONFIG_GPIO_CDEV=y
CONFIG_GPIO_CDEV_V1=y
CONFIG_GPIO_GENERIC=y
CONFIG_GPIO_REGMAP=m
CONFIG_GPIO_IDIO_16=m

#
# Memory mapped GPIO drivers
#
# CONFIG_GPIO_74XX_MMIO is not set
# CONFIG_GPIO_ALTERA is not set
# CONFIG_GPIO_AMDPT is not set
CONFIG_GPIO_RASPBERRYPI_EXP=m
CONFIG_GPIO_BRCMSTB=m
CONFIG_GPIO_CADENCE=m
CONFIG_GPIO_DAVINCI=m
CONFIG_GPIO_DWAPB=m
CONFIG_GPIO_EXAR=m
# CONFIG_GPIO_FTGPIO010 is not set
CONFIG_GPIO_GENERIC_PLATFORM=y
# CONFIG_GPIO_GRGPIO is not set
# CONFIG_GPIO_HISI is not set
# CONFIG_GPIO_HLWD is not set
CONFIG_GPIO_IMX_SCU=y
# CONFIG_GPIO_LOGICVC is not set
CONFIG_GPIO_MB86S7X=m
CONFIG_GPIO_MPC8XXX=y
CONFIG_GPIO_MVEBU=y
CONFIG_GPIO_MXC=m
CONFIG_GPIO_PL061=y
# CONFIG_GPIO_POLARFIRE_SOC is not set
CONFIG_GPIO_RCAR=m
CONFIG_GPIO_ROCKCHIP=y
# CONFIG_GPIO_SIFIVE is not set
CONFIG_GPIO_SYSCON=m
CONFIG_GPIO_TEGRA=y
CONFIG_GPIO_TEGRA186=y
CONFIG_GPIO_THUNDERX=m
CONFIG_GPIO_VF610=y
CONFIG_GPIO_WCD934X=m
CONFIG_GPIO_XGENE=y
CONFIG_GPIO_XGENE_SB=m
# CONFIG_GPIO_XILINX is not set
CONFIG_GPIO_XLP=m
CONFIG_GPIO_ZYNQ=m
CONFIG_GPIO_ZYNQMP_MODEPIN=y
# CONFIG_GPIO_AMD_FCH is not set
# end of Memory mapped GPIO drivers

#
# I2C GPIO expanders
#
# CONFIG_GPIO_ADNP is not set
CONFIG_GPIO_FXL6408=m
CONFIG_GPIO_DS4520=m
# CONFIG_GPIO_GW_PLD is not set
# CONFIG_GPIO_MAX7300 is not set
CONFIG_GPIO_MAX732X=m
CONFIG_GPIO_PCA953X=y
CONFIG_GPIO_PCA953X_IRQ=y
CONFIG_GPIO_PCA9570=m
CONFIG_GPIO_PCF857X=m
CONFIG_GPIO_TPIC2810=m
# end of I2C GPIO expanders

#
# MFD GPIO expanders
#
CONFIG_GPIO_ADP5585=m
CONFIG_GPIO_BD9571MWV=m
CONFIG_GPIO_CROS_EC=m
CONFIG_GPIO_DLN2=m
CONFIG_GPIO_MAX77620=y
CONFIG_GPIO_MAX77650=m
CONFIG_GPIO_STMPE=y
CONFIG_GPIO_TPS65086=m
CONFIG_GPIO_TPS65219=m
CONFIG_GPIO_WM8994=m
# end of MFD GPIO expanders

#
# PCI GPIO expanders
#
CONFIG_GPIO_MLXBF=m
CONFIG_GPIO_MLXBF2=m
CONFIG_GPIO_MLXBF3=m
CONFIG_GPIO_PCI_IDIO_16=m
# CONFIG_GPIO_PCIE_IDIO_24 is not set
# CONFIG_GPIO_RDC321X is not set
# end of PCI GPIO expanders

#
# SPI GPIO expanders
#
# CONFIG_GPIO_74X164 is not set
# CONFIG_GPIO_MAX3191X is not set
# CONFIG_GPIO_MAX7301 is not set
# CONFIG_GPIO_MC33880 is not set
# CONFIG_GPIO_PISOSR is not set
# CONFIG_GPIO_XRA1403 is not set
CONFIG_GPIO_MOXTET=m
# end of SPI GPIO expanders

#
# USB GPIO expanders
#
CONFIG_GPIO_MPSSE=m
# end of USB GPIO expanders

#
# Virtual GPIO drivers
#
CONFIG_GPIO_AGGREGATOR=m
# CONFIG_GPIO_LATCH is not set
# CONFIG_GPIO_MOCKUP is not set
CONFIG_GPIO_VIRTIO=m
CONFIG_GPIO_SIM=m
# end of Virtual GPIO drivers

#
# GPIO Debugging utilities
#
# CONFIG_GPIO_SLOPPY_LOGIC_ANALYZER is not set
CONFIG_GPIO_VIRTUSER=m
# end of GPIO Debugging utilities

CONFIG_DEV_SYNC_PROBE=m
CONFIG_W1=m
CONFIG_W1_CON=y

#
# 1-wire Bus Masters
#
# CONFIG_W1_MASTER_AMD_AXI is not set
# CONFIG_W1_MASTER_MATROX is not set
CONFIG_W1_MASTER_DS2490=m
CONFIG_W1_MASTER_DS2482=m
# CONFIG_W1_MASTER_MXC is not set
CONFIG_W1_MASTER_GPIO=m
# CONFIG_W1_MASTER_SGI is not set
CONFIG_W1_MASTER_UART=m
# end of 1-wire Bus Masters

#
# 1-wire Slaves
#
CONFIG_W1_SLAVE_THERM=m
CONFIG_W1_SLAVE_SMEM=m
CONFIG_W1_SLAVE_DS2405=m
CONFIG_W1_SLAVE_DS2408=m
# CONFIG_W1_SLAVE_DS2408_READBACK is not set
CONFIG_W1_SLAVE_DS2413=m
CONFIG_W1_SLAVE_DS2406=m
CONFIG_W1_SLAVE_DS2423=m
CONFIG_W1_SLAVE_DS2805=m
CONFIG_W1_SLAVE_DS2430=m
CONFIG_W1_SLAVE_DS2431=m
CONFIG_W1_SLAVE_DS2433=m
CONFIG_W1_SLAVE_DS2433_CRC=y
CONFIG_W1_SLAVE_DS2438=m
# CONFIG_W1_SLAVE_DS250X is not set
CONFIG_W1_SLAVE_DS2780=m
CONFIG_W1_SLAVE_DS2781=m
CONFIG_W1_SLAVE_DS28E04=m
# CONFIG_W1_SLAVE_DS28E17 is not set
# end of 1-wire Slaves

CONFIG_POWER_RESET=y
CONFIG_POWER_RESET_AS3722=y
CONFIG_POWER_RESET_GPIO=y
CONFIG_POWER_RESET_GPIO_RESTART=y
CONFIG_POWER_RESET_HISI=y
# CONFIG_POWER_RESET_LINKSTATION is not set
CONFIG_POWER_RESET_MSM=y
CONFIG_POWER_RESET_QCOM_PON=m
CONFIG_POWER_RESET_ODROID_GO_ULTRA_POWEROFF=y
# CONFIG_POWER_RESET_LTC2952 is not set
CONFIG_POWER_RESET_REGULATOR=y
CONFIG_POWER_RESET_RESTART=y
# CONFIG_POWER_RESET_TORADEX_EC is not set
CONFIG_POWER_RESET_TPS65086=y
CONFIG_POWER_RESET_VEXPRESS=y
CONFIG_POWER_RESET_XGENE=y
CONFIG_POWER_RESET_SYSCON=y
CONFIG_POWER_RESET_SYSCON_POWEROFF=y
CONFIG_REBOOT_MODE=y
CONFIG_SYSCON_REBOOT_MODE=y
CONFIG_NVMEM_REBOOT_MODE=m
CONFIG_POWER_MLXBF=m
CONFIG_POWER_SEQUENCING=m
CONFIG_POWER_SEQUENCING_QCOM_WCN=m
CONFIG_POWER_SUPPLY=y
# CONFIG_POWER_SUPPLY_DEBUG is not set
CONFIG_POWER_SUPPLY_HWMON=y
# CONFIG_GENERIC_ADC_BATTERY is not set
CONFIG_IP5XXX_POWER=m
# CONFIG_TEST_POWER is not set
# CONFIG_CHARGER_ADP5061 is not set
# CONFIG_BATTERY_CHAGALL is not set
CONFIG_BATTERY_CW2015=m
# CONFIG_BATTERY_DS2760 is not set
# CONFIG_BATTERY_DS2780 is not set
# CONFIG_BATTERY_DS2781 is not set
# CONFIG_BATTERY_DS2782 is not set
CONFIG_BATTERY_LENOVO_YOGA_C630=m
CONFIG_BATTERY_QCOM_BATTMGR=m
CONFIG_BATTERY_SAMSUNG_SDI=y
CONFIG_BATTERY_SBS=m
# CONFIG_CHARGER_SBS is not set
# CONFIG_MANAGER_SBS is not set
CONFIG_BATTERY_BQ27XXX=m
CONFIG_BATTERY_BQ27XXX_I2C=m
# CONFIG_BATTERY_BQ27XXX_HDQ is not set
# CONFIG_BATTERY_BQ27XXX_DT_UPDATES_NVM is not set
CONFIG_CHARGER_AXP20X=m
CONFIG_BATTERY_AXP20X=m
CONFIG_AXP20X_POWER=m
CONFIG_BATTERY_MAX17040=m
CONFIG_BATTERY_MAX17042=m
CONFIG_BATTERY_MAX1720X=m
# CONFIG_BATTERY_MAX1721X is not set
# CONFIG_CHARGER_ISP1704 is not set
# CONFIG_CHARGER_MAX8903 is not set
# CONFIG_CHARGER_LP8727 is not set
CONFIG_CHARGER_GPIO=m
# CONFIG_CHARGER_MANAGER is not set
CONFIG_CHARGER_LT3651=m
CONFIG_CHARGER_LTC4162L=m
# CONFIG_CHARGER_DETECTOR_MAX14656 is not set
CONFIG_CHARGER_MAX77650=m
CONFIG_CHARGER_MAX77705=m
CONFIG_CHARGER_MAX77976=m
# CONFIG_CHARGER_MAX8971 is not set
CONFIG_CHARGER_QCOM_SMBB=m
# CONFIG_BATTERY_PM8916_BMS_VM is not set
# CONFIG_CHARGER_PM8916_LBC is not set
# CONFIG_CHARGER_BQ2415X is not set
# CONFIG_CHARGER_BQ24190 is not set
# CONFIG_CHARGER_BQ24257 is not set
CONFIG_CHARGER_BQ24735=m
CONFIG_CHARGER_BQ2515X=m
# CONFIG_CHARGER_BQ25890 is not set
CONFIG_CHARGER_BQ25980=m
CONFIG_CHARGER_BQ256XX=m
CONFIG_CHARGER_RK817=m
CONFIG_CHARGER_SMB347=m
CONFIG_BATTERY_GAUGE_LTC2941=m
# CONFIG_BATTERY_GOLDFISH is not set
CONFIG_BATTERY_RT5033=m
CONFIG_CHARGER_RT5033=m
# CONFIG_CHARGER_RT9455 is not set
CONFIG_CHARGER_RT9467=m
CONFIG_CHARGER_RT9471=m
CONFIG_CHARGER_CROS_USBPD=m
CONFIG_CHARGER_CROS_PCHG=m
CONFIG_CHARGER_CROS_CONTROL=m
CONFIG_FUEL_GAUGE_STC3117=m
CONFIG_CHARGER_UCS1002=m
CONFIG_CHARGER_BD99954=m
CONFIG_BATTERY_SURFACE=m
CONFIG_CHARGER_SURFACE=m
CONFIG_BATTERY_UG3105=m
CONFIG_CHARGER_QCOM_SMB2=m
CONFIG_FUEL_GAUGE_MM8013=m
CONFIG_HWMON=y
CONFIG_HWMON_VID=m
# CONFIG_HWMON_DEBUG_CHIP is not set

#
# Native drivers
#
CONFIG_SENSORS_SMPRO=m
CONFIG_SENSORS_AD7314=m
CONFIG_SENSORS_AD7414=m
CONFIG_SENSORS_AD7418=m
CONFIG_SENSORS_ADM1025=m
CONFIG_SENSORS_ADM1026=m
CONFIG_SENSORS_ADM1029=m
CONFIG_SENSORS_ADM1031=m
# CONFIG_SENSORS_ADM1177 is not set
CONFIG_SENSORS_ADM9240=m
CONFIG_SENSORS_ADT7X10=m
CONFIG_SENSORS_ADT7310=m
CONFIG_SENSORS_ADT7410=m
CONFIG_SENSORS_ADT7411=m
CONFIG_SENSORS_ADT7462=m
CONFIG_SENSORS_ADT7470=m
CONFIG_SENSORS_ADT7475=m
# CONFIG_SENSORS_AHT10 is not set
CONFIG_SENSORS_AQUACOMPUTER_D5NEXT=m
# CONFIG_SENSORS_AS370 is not set
CONFIG_SENSORS_ASC7621=m
CONFIG_SENSORS_ASUS_ROG_RYUJIN=m
CONFIG_SENSORS_AXI_FAN_CONTROL=m
# CONFIG_SENSORS_KBATT is not set
# CONFIG_SENSORS_KFAN is not set
CONFIG_SENSORS_ARM_SCMI=m
CONFIG_SENSORS_ARM_SCPI=m
CONFIG_SENSORS_ATXP1=m
CONFIG_SENSORS_CHIPCAP2=m
CONFIG_SENSORS_CORSAIR_CPRO=m
CONFIG_SENSORS_CORSAIR_PSU=m
CONFIG_SENSORS_CROS_EC=m
CONFIG_SENSORS_DRIVETEMP=m
CONFIG_SENSORS_DS620=m
CONFIG_SENSORS_DS1621=m
# CONFIG_SENSORS_I5K_AMB is not set
CONFIG_SENSORS_F71805F=m
CONFIG_SENSORS_F71882FG=m
CONFIG_SENSORS_F75375S=m
CONFIG_SENSORS_FTSTEUTATES=m
CONFIG_SENSORS_GIGABYTE_WATERFORCE=m
CONFIG_SENSORS_GL518SM=m
CONFIG_SENSORS_GL520SM=m
CONFIG_SENSORS_G760A=m
CONFIG_SENSORS_G762=m
CONFIG_SENSORS_GPIO_FAN=m
# CONFIG_SENSORS_HIH6130 is not set
CONFIG_SENSORS_HS3001=m
CONFIG_SENSORS_HTU31=m
CONFIG_SENSORS_IBMAEM=m
CONFIG_SENSORS_IBMPEX=m
CONFIG_SENSORS_IIO_HWMON=m
CONFIG_SENSORS_ISL28022=m
CONFIG_SENSORS_IT87=m
CONFIG_SENSORS_JC42=m
CONFIG_SENSORS_POWERZ=m
CONFIG_SENSORS_POWR1220=m
CONFIG_SENSORS_LINEAGE=m
CONFIG_SENSORS_LTC2945=m
CONFIG_SENSORS_LTC2947=m
CONFIG_SENSORS_LTC2947_I2C=m
CONFIG_SENSORS_LTC2947_SPI=m
CONFIG_SENSORS_LTC2990=m
CONFIG_SENSORS_LTC2991=m
# CONFIG_SENSORS_LTC2992 is not set
CONFIG_SENSORS_LTC4151=m
CONFIG_SENSORS_LTC4215=m
CONFIG_SENSORS_LTC4222=m
CONFIG_SENSORS_LTC4245=m
CONFIG_SENSORS_LTC4260=m
CONFIG_SENSORS_LTC4261=m
# CONFIG_SENSORS_LTC4282 is not set
CONFIG_SENSORS_MAX1111=m
# CONFIG_SENSORS_MAX127 is not set
CONFIG_SENSORS_MAX16065=m
CONFIG_SENSORS_MAX1619=m
CONFIG_SENSORS_MAX1668=m
CONFIG_SENSORS_MAX197=m
CONFIG_SENSORS_MAX31722=m
# CONFIG_SENSORS_MAX31730 is not set
CONFIG_SENSORS_MAX31760=m
CONFIG_MAX31827=m
CONFIG_SENSORS_MAX6620=m
# CONFIG_SENSORS_MAX6621 is not set
CONFIG_SENSORS_MAX6639=m
CONFIG_SENSORS_MAX6650=m
CONFIG_SENSORS_MAX6697=m
CONFIG_SENSORS_MAX31790=m
# CONFIG_SENSORS_MAX77705 is not set
CONFIG_SENSORS_MC34VR500=m
CONFIG_SENSORS_MCP3021=m
CONFIG_SENSORS_MLXREG_FAN=m
CONFIG_SENSORS_TC654=m
# CONFIG_SENSORS_TPS23861 is not set
CONFIG_SENSORS_MR75203=m
CONFIG_SENSORS_ADCXX=m
CONFIG_SENSORS_LM63=m
CONFIG_SENSORS_LM70=m
CONFIG_SENSORS_LM73=m
CONFIG_SENSORS_LM75=m
CONFIG_SENSORS_LM77=m
CONFIG_SENSORS_LM78=m
CONFIG_SENSORS_LM80=m
CONFIG_SENSORS_LM83=m
CONFIG_SENSORS_LM85=m
CONFIG_SENSORS_LM87=m
CONFIG_SENSORS_LM90=m
CONFIG_SENSORS_LM92=m
CONFIG_SENSORS_LM93=m
CONFIG_SENSORS_LM95234=m
CONFIG_SENSORS_LM95241=m
CONFIG_SENSORS_LM95245=m
CONFIG_SENSORS_PC87360=m
CONFIG_SENSORS_PC87427=m
CONFIG_SENSORS_NTC_THERMISTOR=m
CONFIG_SENSORS_NCT6683=m
CONFIG_SENSORS_NCT6775_CORE=m
CONFIG_SENSORS_NCT6775=m
CONFIG_SENSORS_NCT6775_I2C=m
CONFIG_SENSORS_NCT7363=m
CONFIG_SENSORS_NCT7802=m
CONFIG_SENSORS_NCT7904=m
CONFIG_SENSORS_NPCM7XX=m
CONFIG_SENSORS_NZXT_KRAKEN2=m
CONFIG_SENSORS_NZXT_KRAKEN3=m
CONFIG_SENSORS_NZXT_SMART2=m
# CONFIG_SENSORS_OCC_P8_I2C is not set
CONFIG_SENSORS_PCF8591=m
CONFIG_PMBUS=m
CONFIG_SENSORS_PMBUS=m
# CONFIG_SENSORS_ACBEL_FSG032 is not set
CONFIG_SENSORS_ADM1266=m
CONFIG_SENSORS_ADM1275=m
CONFIG_SENSORS_ADP1050=m
# CONFIG_SENSORS_ADP1050_REGULATOR is not set
CONFIG_SENSORS_BEL_PFE=m
CONFIG_SENSORS_BPA_RS600=m
CONFIG_SENSORS_CRPS=m
CONFIG_SENSORS_DELTA_AHE50DC_FAN=m
CONFIG_SENSORS_FSP_3Y=m
# CONFIG_SENSORS_IBM_CFFPS is not set
CONFIG_SENSORS_DPS920AB=m
CONFIG_SENSORS_INA233=m
# CONFIG_SENSORS_INSPUR_IPSPS is not set
# CONFIG_SENSORS_IR35221 is not set
# CONFIG_SENSORS_IR36021 is not set
# CONFIG_SENSORS_IR38064 is not set
# CONFIG_SENSORS_IRPS5401 is not set
# CONFIG_SENSORS_ISL68137 is not set
CONFIG_SENSORS_LM25066=m
CONFIG_SENSORS_LM25066_REGULATOR=y
# CONFIG_SENSORS_LT3074 is not set
CONFIG_SENSORS_LT7182S=m
CONFIG_SENSORS_LTC2978=m
# CONFIG_SENSORS_LTC2978_REGULATOR is not set
CONFIG_SENSORS_LTC3815=m
# CONFIG_SENSORS_LTC4286 is not set
# CONFIG_SENSORS_MAX15301 is not set
CONFIG_SENSORS_MAX16064=m
# CONFIG_SENSORS_MAX16601 is not set
# CONFIG_SENSORS_MAX20730 is not set
CONFIG_SENSORS_MAX20751=m
# CONFIG_SENSORS_MAX31785 is not set
CONFIG_SENSORS_MAX34440=m
CONFIG_SENSORS_MAX8688=m
# CONFIG_SENSORS_MP2856 is not set
CONFIG_SENSORS_MP2888=m
CONFIG_SENSORS_MP2891=m
CONFIG_SENSORS_MP2975=m
CONFIG_SENSORS_MP2993=m
CONFIG_SENSORS_MP2975_REGULATOR=y
CONFIG_SENSORS_MP5023=m
CONFIG_SENSORS_MP5920=m
# CONFIG_SENSORS_MP5990 is not set
CONFIG_SENSORS_MP9941=m
CONFIG_SENSORS_MPQ7932_REGULATOR=y
CONFIG_SENSORS_MPQ7932=m
CONFIG_SENSORS_MPQ8785=m
CONFIG_SENSORS_PIM4328=m
CONFIG_SENSORS_PLI1209BC=m
CONFIG_SENSORS_PLI1209BC_REGULATOR=y
CONFIG_SENSORS_PM6764TR=m
# CONFIG_SENSORS_PXE1610 is not set
CONFIG_SENSORS_Q54SJ108A2=m
# CONFIG_SENSORS_STPDDC60 is not set
CONFIG_SENSORS_TDA38640=m
CONFIG_SENSORS_TDA38640_REGULATOR=y
CONFIG_SENSORS_TPS25990=m
CONFIG_SENSORS_TPS25990_REGULATOR=y
CONFIG_SENSORS_TPS40422=m
CONFIG_SENSORS_TPS53679=m
CONFIG_SENSORS_TPS546D24=m
CONFIG_SENSORS_UCD9000=m
CONFIG_SENSORS_UCD9200=m
CONFIG_SENSORS_XDP710=m
CONFIG_SENSORS_XDPE152=m
# CONFIG_SENSORS_XDPE122 is not set
CONFIG_SENSORS_ZL6100=m
CONFIG_SENSORS_PT5161L=m
CONFIG_SENSORS_PWM_FAN=m
CONFIG_SENSORS_QNAP_MCU_HWMON=m
CONFIG_SENSORS_RASPBERRYPI_HWMON=m
CONFIG_SENSORS_SBTSI=m
CONFIG_SENSORS_SHT15=m
CONFIG_SENSORS_SHT21=m
CONFIG_SENSORS_SHT3x=m
# CONFIG_SENSORS_SHT4x is not set
CONFIG_SENSORS_SHTC1=m
CONFIG_SENSORS_SIS5595=m
CONFIG_SENSORS_SY7636A=m
CONFIG_SENSORS_DME1737=m
CONFIG_SENSORS_EMC1403=m
# CONFIG_SENSORS_EMC2103 is not set
CONFIG_SENSORS_EMC2305=m
CONFIG_SENSORS_EMC6W201=m
CONFIG_SENSORS_SMSC47M1=m
CONFIG_SENSORS_SMSC47M192=m
CONFIG_SENSORS_SMSC47B397=m
CONFIG_SENSORS_SCH56XX_COMMON=m
CONFIG_SENSORS_SCH5627=m
CONFIG_SENSORS_SCH5636=m
# CONFIG_SENSORS_STTS751 is not set
CONFIG_SENSORS_SURFACE_FAN=m
CONFIG_SENSORS_SURFACE_TEMP=m
CONFIG_SENSORS_ADC128D818=m
CONFIG_SENSORS_ADS7828=m
CONFIG_SENSORS_ADS7871=m
CONFIG_SENSORS_AMC6821=m
CONFIG_SENSORS_INA209=m
CONFIG_SENSORS_INA2XX=m
CONFIG_SENSORS_INA238=m
CONFIG_SENSORS_INA3221=m
CONFIG_SENSORS_SPD5118=m
CONFIG_SENSORS_SPD5118_DETECT=y
CONFIG_SENSORS_TC74=m
CONFIG_SENSORS_THMC50=m
CONFIG_SENSORS_TMP102=m
CONFIG_SENSORS_TMP103=m
CONFIG_SENSORS_TMP108=m
CONFIG_SENSORS_TMP401=m
CONFIG_SENSORS_TMP421=m
CONFIG_SENSORS_TMP464=m
CONFIG_SENSORS_TMP513=m
CONFIG_SENSORS_VEXPRESS=m
CONFIG_SENSORS_VIA686A=m
CONFIG_SENSORS_VT1211=m
CONFIG_SENSORS_VT8231=m
CONFIG_SENSORS_W83773G=m
CONFIG_SENSORS_W83781D=m
CONFIG_SENSORS_W83791D=m
CONFIG_SENSORS_W83792D=m
CONFIG_SENSORS_W83793=m
CONFIG_SENSORS_W83795=m
# CONFIG_SENSORS_W83795_FANCTRL is not set
CONFIG_SENSORS_W83L785TS=m
CONFIG_SENSORS_W83L786NG=m
CONFIG_SENSORS_W83627HF=m
CONFIG_SENSORS_W83627EHF=m
CONFIG_SENSORS_XGENE=m
CONFIG_SENSORS_INTEL_M10_BMC_HWMON=m

#
# ACPI drivers
#
CONFIG_SENSORS_ACPI_POWER=m
CONFIG_THERMAL=y
CONFIG_THERMAL_NETLINK=y
CONFIG_THERMAL_STATISTICS=y
# CONFIG_THERMAL_DEBUGFS is not set
# CONFIG_THERMAL_CORE_TESTING is not set
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_OF=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
CONFIG_THERMAL_GOV_FAIR_SHARE=y
CONFIG_THERMAL_GOV_STEP_WISE=y
# CONFIG_THERMAL_GOV_BANG_BANG is not set
CONFIG_THERMAL_GOV_USER_SPACE=y
# CONFIG_THERMAL_GOV_POWER_ALLOCATOR is not set
CONFIG_CPU_THERMAL=y
CONFIG_CPU_FREQ_THERMAL=y
CONFIG_DEVFREQ_THERMAL=y
CONFIG_PCIE_THERMAL=y
# CONFIG_THERMAL_EMULATION is not set
CONFIG_THERMAL_MMIO=m
CONFIG_HISI_THERMAL=m
# CONFIG_IMX_THERMAL is not set
CONFIG_IMX_SC_THERMAL=m
CONFIG_IMX8MM_THERMAL=m
CONFIG_K3_THERMAL=m
CONFIG_MAX77620_THERMAL=m
CONFIG_QORIQ_THERMAL=m
CONFIG_SUN8I_THERMAL=m
CONFIG_ROCKCHIP_THERMAL=m
CONFIG_ARMADA_THERMAL=m
CONFIG_AMLOGIC_THERMAL=m

#
# Broadcom thermal drivers
#
CONFIG_BCM2711_THERMAL=m
CONFIG_BCM2835_THERMAL=m
# end of Broadcom thermal drivers

# CONFIG_RCAR_THERMAL is not set
# CONFIG_RCAR_GEN3_THERMAL is not set
CONFIG_RZG2L_THERMAL=m

#
# NVIDIA Tegra thermal drivers
#
CONFIG_TEGRA_SOCTHERM=m
CONFIG_TEGRA_BPMP_THERMAL=m
# end of NVIDIA Tegra thermal drivers

# CONFIG_GENERIC_ADC_THERMAL is not set

#
# Qualcomm thermal drivers
#
CONFIG_QCOM_TSENS=m
CONFIG_QCOM_SPMI_ADC_TM5=m
CONFIG_QCOM_SPMI_TEMP_ALARM=m
CONFIG_QCOM_LMH=m
# end of Qualcomm thermal drivers

CONFIG_KHADAS_MCU_FAN_THERMAL=m
CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_CORE=y
# CONFIG_WATCHDOG_NOWAYOUT is not set
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_OPEN_TIMEOUT=0
CONFIG_WATCHDOG_SYSFS=y
# CONFIG_WATCHDOG_HRTIMER_PRETIMEOUT is not set

#
# Watchdog Pretimeout Governors
#
# CONFIG_WATCHDOG_PRETIMEOUT_GOV is not set

#
# Watchdog Device Drivers
#
CONFIG_SOFT_WATCHDOG=m
CONFIG_BD96801_WATCHDOG=m
CONFIG_CROS_EC_WATCHDOG=m
CONFIG_GPIO_WATCHDOG=m
CONFIG_WDAT_WDT=m
# CONFIG_XILINX_WATCHDOG is not set
CONFIG_XILINX_WINDOW_WATCHDOG=m
# CONFIG_ZIIRAVE_WATCHDOG is not set
CONFIG_MLX_WDT=m
CONFIG_ARM_SP805_WATCHDOG=m
CONFIG_ARM_SBSA_WATCHDOG=m
CONFIG_ARMADA_37XX_WATCHDOG=m
CONFIG_CADENCE_WATCHDOG=m
CONFIG_DW_WATCHDOG=m
CONFIG_K3_RTI_WATCHDOG=m
CONFIG_SUNXI_WATCHDOG=m
# CONFIG_MAX63XX_WATCHDOG is not set
CONFIG_MAX77620_WATCHDOG=m
CONFIG_IMX2_WDT=m
CONFIG_IMX_SC_WDT=m
CONFIG_IMX7ULP_WDT=m
# CONFIG_S32G_WDT is not set
CONFIG_TEGRA_WATCHDOG=m
CONFIG_QCOM_WDT=m
CONFIG_MESON_GXBB_WATCHDOG=m
CONFIG_MESON_WATCHDOG=m
CONFIG_ARM_SMC_WATCHDOG=m
# CONFIG_RENESAS_WDT is not set
# CONFIG_RENESAS_RZAWDT is not set
# CONFIG_RENESAS_RZN1WDT is not set
CONFIG_RENESAS_RZG2LWDT=m
CONFIG_RENESAS_RZV2HWDT=m
CONFIG_PM8916_WATCHDOG=m
CONFIG_APPLE_WATCHDOG=m
CONFIG_ALIM7101_WDT=m
CONFIG_I6300ESB_WDT=m
CONFIG_HP_WATCHDOG=m
CONFIG_NIC7018_WDT=m
CONFIG_MARVELL_GTI_WDT=y
CONFIG_BCM2835_WDT=m
# CONFIG_MEN_A21_WDT is not set

#
# PCI-based Watchdog Cards
#
CONFIG_PCIPCWATCHDOG=m
CONFIG_WDTPCI=m

#
# USB-based Watchdog Cards
#
CONFIG_USBPCWATCHDOG=m
CONFIG_SSB_POSSIBLE=y
CONFIG_SSB=m
CONFIG_SSB_SPROM=y
CONFIG_SSB_BLOCKIO=y
CONFIG_SSB_PCIHOST_POSSIBLE=y
CONFIG_SSB_PCIHOST=y
CONFIG_SSB_B43_PCI_BRIDGE=y
CONFIG_SSB_SDIOHOST_POSSIBLE=y
CONFIG_SSB_SDIOHOST=y
CONFIG_SSB_DRIVER_PCICORE_POSSIBLE=y
CONFIG_SSB_DRIVER_PCICORE=y
CONFIG_SSB_DRIVER_GPIO=y
CONFIG_BCMA_POSSIBLE=y
CONFIG_BCMA=m
CONFIG_BCMA_BLOCKIO=y
CONFIG_BCMA_HOST_PCI_POSSIBLE=y
CONFIG_BCMA_HOST_PCI=y
# CONFIG_BCMA_HOST_SOC is not set
CONFIG_BCMA_DRIVER_PCI=y
CONFIG_BCMA_DRIVER_GMAC_CMN=y
CONFIG_BCMA_DRIVER_GPIO=y
# CONFIG_BCMA_DEBUG is not set

#
# Multifunction device drivers
#
CONFIG_MFD_CORE=y
CONFIG_MFD_ADP5585=m
# CONFIG_MFD_ACT8945A is not set
# CONFIG_MFD_SUN4I_GPADC is not set
# CONFIG_MFD_AS3711 is not set
CONFIG_MFD_SMPRO=m
CONFIG_MFD_AS3722=y
# CONFIG_PMIC_ADP5520 is not set
# CONFIG_MFD_AAT2870_CORE is not set
# CONFIG_MFD_ATMEL_FLEXCOM is not set
# CONFIG_MFD_ATMEL_HLCDC is not set
# CONFIG_MFD_BCM590XX is not set
CONFIG_MFD_BD9571MWV=m
CONFIG_MFD_AC100=m
CONFIG_MFD_AXP20X=y
CONFIG_MFD_AXP20X_I2C=y
CONFIG_MFD_AXP20X_RSB=m
CONFIG_MFD_CROS_EC_DEV=m
CONFIG_MFD_CS40L50_CORE=m
CONFIG_MFD_CS40L50_I2C=m
CONFIG_MFD_CS40L50_SPI=m
CONFIG_MFD_CS42L43=m
CONFIG_MFD_CS42L43_I2C=m
CONFIG_MFD_CS42L43_SDW=m
# CONFIG_MFD_LOCHNAGAR is not set
# CONFIG_MFD_MACSMC is not set
# CONFIG_MFD_MADERA is not set
# CONFIG_PMIC_DA903X is not set
# CONFIG_MFD_DA9052_SPI is not set
# CONFIG_MFD_DA9052_I2C is not set
# CONFIG_MFD_DA9055 is not set
# CONFIG_MFD_DA9062 is not set
# CONFIG_MFD_DA9063 is not set
# CONFIG_MFD_DA9150 is not set
CONFIG_MFD_DLN2=m
# CONFIG_MFD_GATEWORKS_GSC is not set
# CONFIG_MFD_MC13XXX_SPI is not set
# CONFIG_MFD_MC13XXX_I2C is not set
# CONFIG_MFD_MP2629 is not set
CONFIG_MFD_HI6421_PMIC=m
CONFIG_MFD_HI6421_SPMI=m
CONFIG_MFD_HI655X_PMIC=m
# CONFIG_LPC_ICH is not set
# CONFIG_LPC_SCH is not set
# CONFIG_MFD_IQS62X is not set
# CONFIG_MFD_JANZ_CMODIO is not set
# CONFIG_MFD_KEMPLD is not set
# CONFIG_MFD_88PM800 is not set
# CONFIG_MFD_88PM805 is not set
# CONFIG_MFD_88PM860X is not set
CONFIG_MFD_88PM886_PMIC=y
CONFIG_MFD_MAX5970=m
# CONFIG_MFD_MAX14577 is not set
# CONFIG_MFD_MAX77541 is not set
CONFIG_MFD_MAX77620=y
CONFIG_MFD_MAX77650=m
CONFIG_MFD_MAX77686=y
# CONFIG_MFD_MAX77693 is not set
CONFIG_MFD_MAX77705=m
CONFIG_MFD_MAX77714=m
# CONFIG_MFD_MAX77759 is not set
# CONFIG_MFD_MAX77843 is not set
# CONFIG_MFD_MAX8907 is not set
# CONFIG_MFD_MAX8925 is not set
# CONFIG_MFD_MAX8997 is not set
# CONFIG_MFD_MAX8998 is not set
# CONFIG_MFD_MT6360 is not set
# CONFIG_MFD_MT6370 is not set
# CONFIG_MFD_MT6397 is not set
# CONFIG_MFD_MENF21BMC is not set
# CONFIG_MFD_OCELOT is not set
# CONFIG_EZX_PCAP is not set
# CONFIG_MFD_CPCAP is not set
# CONFIG_MFD_VIPERBOARD is not set
# CONFIG_MFD_NTXEC is not set
# CONFIG_MFD_RETU is not set
# CONFIG_MFD_QCOM_RPM is not set
CONFIG_MFD_SPMI_PMIC=m
CONFIG_MFD_SY7636A=m
# CONFIG_MFD_RDC321X is not set
CONFIG_MFD_RT4831=m
CONFIG_MFD_RT5033=m
CONFIG_MFD_RT5120=m
# CONFIG_MFD_RC5T583 is not set
CONFIG_MFD_RK8XX=m
CONFIG_MFD_RK8XX_I2C=m
CONFIG_MFD_RK8XX_SPI=m
# CONFIG_MFD_RN5T618 is not set
# CONFIG_MFD_SEC_I2C is not set
# CONFIG_MFD_SI476X_CORE is not set
CONFIG_MFD_SIMPLE_MFD_I2C=m
# CONFIG_MFD_SL28CPLD is not set
CONFIG_MFD_SM501=m
CONFIG_MFD_SM501_GPIO=y
# CONFIG_MFD_SKY81452 is not set
# CONFIG_RZ_MTU3 is not set
CONFIG_MFD_STMPE=y

#
# STMicroelectronics STMPE Interface Drivers
#
CONFIG_STMPE_I2C=y
CONFIG_STMPE_SPI=y
# end of STMicroelectronics STMPE Interface Drivers

# CONFIG_MFD_SUN6I_PRCM is not set
CONFIG_MFD_SYSCON=y
CONFIG_MFD_TI_AM335X_TSCADC=m
# CONFIG_MFD_LP3943 is not set
# CONFIG_MFD_LP8788 is not set
# CONFIG_MFD_TI_LMU is not set
# CONFIG_MFD_PALMAS is not set
# CONFIG_TPS6105X is not set
# CONFIG_TPS65010 is not set
# CONFIG_TPS6507X is not set
CONFIG_MFD_TPS65086=m
# CONFIG_MFD_TPS65090 is not set
# CONFIG_MFD_TPS65217 is not set
# CONFIG_MFD_TI_LP873X is not set
# CONFIG_MFD_TI_LP87565 is not set
# CONFIG_MFD_TPS65218 is not set
CONFIG_MFD_TPS65219=m
# CONFIG_MFD_TPS6586X is not set
# CONFIG_MFD_TPS65910 is not set
# CONFIG_MFD_TPS65912_I2C is not set
# CONFIG_MFD_TPS65912_SPI is not set
CONFIG_MFD_TPS6594=m
CONFIG_MFD_TPS6594_I2C=m
# CONFIG_MFD_TPS6594_SPI is not set
# CONFIG_TWL4030_CORE is not set
# CONFIG_TWL6040_CORE is not set
CONFIG_MFD_WL1273_CORE=m
# CONFIG_MFD_LM3533 is not set
# CONFIG_MFD_TC3589X is not set
# CONFIG_MFD_TQMX86 is not set
CONFIG_MFD_VX855=m
# CONFIG_MFD_ARIZONA_I2C is not set
# CONFIG_MFD_ARIZONA_SPI is not set
# CONFIG_MFD_WM8400 is not set
# CONFIG_MFD_WM831X_I2C is not set
# CONFIG_MFD_WM831X_SPI is not set
# CONFIG_MFD_WM8350_I2C is not set
CONFIG_MFD_WM8994=m
CONFIG_MFD_ROHM_BD718XX=y
# CONFIG_MFD_ROHM_BD71828 is not set
# CONFIG_MFD_ROHM_BD957XMUF is not set
CONFIG_MFD_ROHM_BD96801=m
# CONFIG_MFD_STPMIC1 is not set
# CONFIG_MFD_STMFX is not set
CONFIG_MFD_WCD934X=m
# CONFIG_MFD_ATC260X_I2C is not set
CONFIG_MFD_KHADAS_MCU=m
CONFIG_MFD_QCOM_PM8008=m
CONFIG_MFD_VEXPRESS_SYSREG=y
# CONFIG_RAVE_SP_CORE is not set
CONFIG_MFD_INTEL_M10_BMC_CORE=m
CONFIG_MFD_INTEL_M10_BMC_SPI=m
CONFIG_MFD_INTEL_M10_BMC_PMCI=m
CONFIG_MFD_QNAP_MCU=m
CONFIG_MFD_RSMU_I2C=m
CONFIG_MFD_RSMU_SPI=m
# end of Multifunction device drivers

CONFIG_REGULATOR=y
# CONFIG_REGULATOR_DEBUG is not set
CONFIG_REGULATOR_FIXED_VOLTAGE=y
CONFIG_REGULATOR_VIRTUAL_CONSUMER=m
CONFIG_REGULATOR_USERSPACE_CONSUMER=m
# CONFIG_REGULATOR_NETLINK_EVENTS is not set
# CONFIG_REGULATOR_88PG86X is not set
CONFIG_REGULATOR_88PM886=m
CONFIG_REGULATOR_ACT8865=m
# CONFIG_REGULATOR_AD5398 is not set
# CONFIG_REGULATOR_ADP5055 is not set
CONFIG_REGULATOR_ANATOP=m
CONFIG_REGULATOR_ARM_SCMI=y
CONFIG_REGULATOR_AS3722=m
CONFIG_REGULATOR_AW37503=m
CONFIG_REGULATOR_AXP20X=m
CONFIG_REGULATOR_BD718XX=m
CONFIG_REGULATOR_BD9571MWV=m
CONFIG_REGULATOR_BD96801=m
CONFIG_REGULATOR_CROS_EC=m
# CONFIG_REGULATOR_DA9121 is not set
# CONFIG_REGULATOR_DA9210 is not set
# CONFIG_REGULATOR_DA9211 is not set
CONFIG_REGULATOR_FAN53555=y
# CONFIG_REGULATOR_FAN53880 is not set
CONFIG_REGULATOR_GPIO=y
CONFIG_REGULATOR_HI6421=m
CONFIG_REGULATOR_HI6421V530=m
CONFIG_REGULATOR_HI655X=m
CONFIG_REGULATOR_HI6421V600=m
# CONFIG_REGULATOR_ISL9305 is not set
# CONFIG_REGULATOR_ISL6271A is not set
# CONFIG_REGULATOR_LP3971 is not set
# CONFIG_REGULATOR_LP3972 is not set
# CONFIG_REGULATOR_LP872X is not set
# CONFIG_REGULATOR_LP8755 is not set
# CONFIG_REGULATOR_LTC3589 is not set
# CONFIG_REGULATOR_LTC3676 is not set
# CONFIG_REGULATOR_MAX1586 is not set
CONFIG_REGULATOR_MAX5970=m
CONFIG_REGULATOR_MAX77503=m
CONFIG_REGULATOR_MAX77620=y
CONFIG_REGULATOR_MAX77650=m
CONFIG_REGULATOR_MAX77857=m
# CONFIG_REGULATOR_MAX8649 is not set
# CONFIG_REGULATOR_MAX8660 is not set
CONFIG_REGULATOR_MAX8893=m
# CONFIG_REGULATOR_MAX8952 is not set
CONFIG_REGULATOR_MAX8973=m
# CONFIG_REGULATOR_MAX20086 is not set
CONFIG_REGULATOR_MAX20411=m
CONFIG_REGULATOR_MAX77686=m
CONFIG_REGULATOR_MAX77802=m
# CONFIG_REGULATOR_MAX77826 is not set
# CONFIG_REGULATOR_MCP16502 is not set
CONFIG_REGULATOR_MP5416=m
CONFIG_REGULATOR_MP8859=m
CONFIG_REGULATOR_MP886X=m
# CONFIG_REGULATOR_MPQ7920 is not set
# CONFIG_REGULATOR_MT6311 is not set
# CONFIG_REGULATOR_MT6315 is not set
CONFIG_REGULATOR_PCA9450=m
CONFIG_REGULATOR_PF9453=m
CONFIG_REGULATOR_PF8X00=m
CONFIG_REGULATOR_PFUZE100=m
# CONFIG_REGULATOR_PV88060 is not set
# CONFIG_REGULATOR_PV88080 is not set
# CONFIG_REGULATOR_PV88090 is not set
CONFIG_REGULATOR_PWM=y
CONFIG_REGULATOR_QCOM_PM8008=m
CONFIG_REGULATOR_QCOM_REFGEN=m
CONFIG_REGULATOR_QCOM_RPMH=y
CONFIG_REGULATOR_QCOM_SMD_RPM=m
CONFIG_REGULATOR_QCOM_SPMI=m
CONFIG_REGULATOR_QCOM_USB_VBUS=m
CONFIG_REGULATOR_RAA215300=m
CONFIG_REGULATOR_RASPBERRYPI_TOUCHSCREEN_ATTINY=m
# CONFIG_REGULATOR_RASPBERRYPI_TOUCHSCREEN_V2 is not set
CONFIG_REGULATOR_RK808=m
CONFIG_REGULATOR_ROHM=m
CONFIG_REGULATOR_RT4801=m
CONFIG_REGULATOR_RT4803=m
CONFIG_REGULATOR_RT4831=m
CONFIG_REGULATOR_RT5033=m
CONFIG_REGULATOR_RT5120=m
CONFIG_REGULATOR_RT5190A=m
CONFIG_REGULATOR_RT5739=m
CONFIG_REGULATOR_RT5759=m
CONFIG_REGULATOR_RT6160=m
CONFIG_REGULATOR_RT6190=m
CONFIG_REGULATOR_RT6245=m
CONFIG_REGULATOR_RTQ2134=m
CONFIG_REGULATOR_RTMV20=m
CONFIG_REGULATOR_RTQ6752=m
CONFIG_REGULATOR_RTQ2208=m
# CONFIG_REGULATOR_SLG51000 is not set
# CONFIG_REGULATOR_SUN20I is not set
CONFIG_REGULATOR_SY7636A=m
CONFIG_REGULATOR_SY8106A=m
# CONFIG_REGULATOR_SY8824X is not set
CONFIG_REGULATOR_SY8827N=m
# CONFIG_REGULATOR_TPS51632 is not set
CONFIG_REGULATOR_TPS62360=m
CONFIG_REGULATOR_TPS6286X=m
# CONFIG_REGULATOR_TPS6287X is not set
# CONFIG_REGULATOR_TPS65023 is not set
# CONFIG_REGULATOR_TPS6507X is not set
CONFIG_REGULATOR_TPS65086=m
CONFIG_REGULATOR_TPS65132=m
CONFIG_REGULATOR_TPS65219=m
CONFIG_REGULATOR_TPS6594=m
# CONFIG_REGULATOR_TPS6524X is not set
CONFIG_REGULATOR_RZG2L_VBCTRL=m
CONFIG_REGULATOR_VCTRL=m
CONFIG_REGULATOR_VEXPRESS=m
# CONFIG_REGULATOR_VQMMC_IPQ4019 is not set
CONFIG_REGULATOR_WM8994=m
CONFIG_REGULATOR_QCOM_LABIBB=m
CONFIG_RC_CORE=y
CONFIG_BPF_LIRC_MODE2=y
CONFIG_LIRC=y
CONFIG_RC_MAP=m
CONFIG_RC_DECODERS=y
CONFIG_IR_IMON_DECODER=m
CONFIG_IR_JVC_DECODER=m
CONFIG_IR_MCE_KBD_DECODER=m
CONFIG_IR_NEC_DECODER=m
CONFIG_IR_RC5_DECODER=m
CONFIG_IR_RC6_DECODER=m
CONFIG_IR_RCMM_DECODER=m
CONFIG_IR_SANYO_DECODER=m
CONFIG_IR_SHARP_DECODER=m
CONFIG_IR_SONY_DECODER=m
CONFIG_IR_XMP_DECODER=m
CONFIG_RC_DEVICES=y
CONFIG_IR_ENE=m
CONFIG_IR_FINTEK=m
CONFIG_IR_GPIO_CIR=m
CONFIG_IR_GPIO_TX=m
CONFIG_IR_HIX5HD2=m
CONFIG_IR_IGORPLUGUSB=m
CONFIG_IR_IGUANA=m
CONFIG_IR_IMON=m
CONFIG_IR_IMON_RAW=m
CONFIG_IR_ITE_CIR=m
CONFIG_IR_MCEUSB=m
CONFIG_IR_MESON=m
# CONFIG_IR_MESON_TX is not set
CONFIG_IR_NUVOTON=m
CONFIG_IR_PWM_TX=m
CONFIG_IR_REDRAT3=m
CONFIG_IR_SERIAL=m
CONFIG_IR_SERIAL_TRANSMITTER=y
CONFIG_IR_SPI=m
CONFIG_IR_STREAMZAP=m
CONFIG_IR_SUNXI=m
CONFIG_IR_TOY=m
CONFIG_IR_TTUSBIR=m
CONFIG_RC_ATI_REMOTE=m
CONFIG_RC_LOOPBACK=m
CONFIG_RC_XBOX_DVD=m
CONFIG_CEC_CORE=m
CONFIG_CEC_NOTIFIER=y
CONFIG_CEC_PIN=y

#
# CEC support
#
CONFIG_MEDIA_CEC_RC=y
# CONFIG_CEC_PIN_ERROR_INJ is not set
CONFIG_MEDIA_CEC_SUPPORT=y
CONFIG_CEC_CH7322=m
CONFIG_CEC_NXP_TDA9950=m
CONFIG_CEC_CROS_EC=m
CONFIG_CEC_MESON_AO=m
CONFIG_CEC_MESON_G12A_AO=m
CONFIG_CEC_GPIO=m
CONFIG_CEC_TEGRA=m
# CONFIG_USB_EXTRON_DA_HD_4K_PLUS_CEC is not set
CONFIG_USB_PULSE8_CEC=m
CONFIG_USB_RAINSHADOW_CEC=m
# end of CEC support

CONFIG_MEDIA_SUPPORT=m
CONFIG_MEDIA_SUPPORT_FILTER=y
CONFIG_MEDIA_SUBDRV_AUTOSELECT=y

#
# Media device types
#
CONFIG_MEDIA_CAMERA_SUPPORT=y
CONFIG_MEDIA_ANALOG_TV_SUPPORT=y
CONFIG_MEDIA_DIGITAL_TV_SUPPORT=y
CONFIG_MEDIA_RADIO_SUPPORT=y
# CONFIG_MEDIA_SDR_SUPPORT is not set
CONFIG_MEDIA_PLATFORM_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
# end of Media device types

CONFIG_VIDEO_DEV=m
CONFIG_MEDIA_CONTROLLER=y
CONFIG_DVB_CORE=m

#
# Video4Linux options
#
CONFIG_VIDEO_V4L2_I2C=y
CONFIG_VIDEO_V4L2_SUBDEV_API=y
# CONFIG_VIDEO_ADV_DEBUG is not set
# CONFIG_VIDEO_FIXED_MINOR_RANGES is not set
CONFIG_VIDEO_TUNER=m
CONFIG_V4L2_JPEG_HELPER=m
CONFIG_V4L2_H264=m
CONFIG_V4L2_VP9=m
CONFIG_V4L2_MEM2MEM_DEV=m
# CONFIG_V4L2_FLASH_LED_CLASS is not set
CONFIG_V4L2_FWNODE=m
CONFIG_V4L2_ASYNC=m
CONFIG_V4L2_CCI=m
CONFIG_V4L2_CCI_I2C=m
# end of Video4Linux options

#
# Media controller options
#
CONFIG_MEDIA_CONTROLLER_DVB=y
# end of Media controller options

#
# Digital TV options
#
# CONFIG_DVB_MMAP is not set
CONFIG_DVB_NET=y
CONFIG_DVB_MAX_ADAPTERS=16
CONFIG_DVB_DYNAMIC_MINORS=y
# CONFIG_DVB_DEMUX_SECTION_LOSS_LOG is not set
# CONFIG_DVB_ULE_DEBUG is not set
# end of Digital TV options

#
# Media drivers
#

#
# Drivers filtered as selected at 'Filter media drivers'
#

#
# Media drivers
#
CONFIG_MEDIA_USB_SUPPORT=y

#
# Webcam devices
#
CONFIG_USB_GSPCA=m
CONFIG_USB_GSPCA_BENQ=m
CONFIG_USB_GSPCA_CONEX=m
CONFIG_USB_GSPCA_CPIA1=m
CONFIG_USB_GSPCA_DTCS033=m
CONFIG_USB_GSPCA_ETOMS=m
CONFIG_USB_GSPCA_FINEPIX=m
CONFIG_USB_GSPCA_JEILINJ=m
CONFIG_USB_GSPCA_JL2005BCD=m
CONFIG_USB_GSPCA_KINECT=m
CONFIG_USB_GSPCA_KONICA=m
CONFIG_USB_GSPCA_MARS=m
CONFIG_USB_GSPCA_MR97310A=m
CONFIG_USB_GSPCA_NW80X=m
CONFIG_USB_GSPCA_OV519=m
CONFIG_USB_GSPCA_OV534=m
CONFIG_USB_GSPCA_OV534_9=m
CONFIG_USB_GSPCA_PAC207=m
CONFIG_USB_GSPCA_PAC7302=m
CONFIG_USB_GSPCA_PAC7311=m
CONFIG_USB_GSPCA_SE401=m
CONFIG_USB_GSPCA_SN9C2028=m
CONFIG_USB_GSPCA_SN9C20X=m
CONFIG_USB_GSPCA_SONIXB=m
CONFIG_USB_GSPCA_SONIXJ=m
CONFIG_USB_GSPCA_SPCA1528=m
CONFIG_USB_GSPCA_SPCA500=m
CONFIG_USB_GSPCA_SPCA501=m
CONFIG_USB_GSPCA_SPCA505=m
CONFIG_USB_GSPCA_SPCA506=m
CONFIG_USB_GSPCA_SPCA508=m
CONFIG_USB_GSPCA_SPCA561=m
CONFIG_USB_GSPCA_SQ905=m
CONFIG_USB_GSPCA_SQ905C=m
CONFIG_USB_GSPCA_SQ930X=m
CONFIG_USB_GSPCA_STK014=m
CONFIG_USB_GSPCA_STK1135=m
CONFIG_USB_GSPCA_STV0680=m
CONFIG_USB_GSPCA_SUNPLUS=m
CONFIG_USB_GSPCA_T613=m
CONFIG_USB_GSPCA_TOPRO=m
CONFIG_USB_GSPCA_TOUPTEK=m
CONFIG_USB_GSPCA_TV8532=m
CONFIG_USB_GSPCA_VC032X=m
CONFIG_USB_GSPCA_VICAM=m
CONFIG_USB_GSPCA_XIRLINK_CIT=m
CONFIG_USB_GSPCA_ZC3XX=m
CONFIG_USB_GL860=m
CONFIG_USB_M5602=m
CONFIG_USB_STV06XX=m
CONFIG_USB_PWC=m
# CONFIG_USB_PWC_DEBUG is not set
CONFIG_USB_PWC_INPUT_EVDEV=y
CONFIG_USB_S2255=m
CONFIG_VIDEO_USBTV=m
CONFIG_USB_VIDEO_CLASS=m
CONFIG_USB_VIDEO_CLASS_INPUT_EVDEV=y

#
# Analog TV USB devices
#
CONFIG_VIDEO_GO7007=m
CONFIG_VIDEO_GO7007_USB=m
CONFIG_VIDEO_GO7007_LOADER=m
CONFIG_VIDEO_GO7007_USB_S2250_BOARD=m
CONFIG_VIDEO_HDPVR=m
CONFIG_VIDEO_PVRUSB2=m
CONFIG_VIDEO_PVRUSB2_SYSFS=y
CONFIG_VIDEO_PVRUSB2_DVB=y
# CONFIG_VIDEO_PVRUSB2_DEBUGIFC is not set
CONFIG_VIDEO_STK1160=m

#
# Analog/digital TV USB devices
#
CONFIG_VIDEO_AU0828=m
CONFIG_VIDEO_AU0828_V4L2=y
# CONFIG_VIDEO_AU0828_RC is not set
CONFIG_VIDEO_CX231XX=m
CONFIG_VIDEO_CX231XX_RC=y
CONFIG_VIDEO_CX231XX_ALSA=m
CONFIG_VIDEO_CX231XX_DVB=m

#
# Digital TV USB devices
#
CONFIG_DVB_AS102=m
# CONFIG_DVB_B2C2_FLEXCOP_USB is not set
CONFIG_DVB_USB_V2=m
CONFIG_DVB_USB_AF9015=m
CONFIG_DVB_USB_AF9035=m
CONFIG_DVB_USB_ANYSEE=m
CONFIG_DVB_USB_AU6610=m
CONFIG_DVB_USB_AZ6007=m
CONFIG_DVB_USB_CE6230=m
CONFIG_DVB_USB_DVBSKY=m
CONFIG_DVB_USB_EC168=m
CONFIG_DVB_USB_GL861=m
CONFIG_DVB_USB_LME2510=m
CONFIG_DVB_USB_MXL111SF=m
CONFIG_DVB_USB_RTL28XXU=m
CONFIG_DVB_USB_ZD1301=m
CONFIG_DVB_USB=m
# CONFIG_DVB_USB_DEBUG is not set
CONFIG_DVB_USB_A800=m
CONFIG_DVB_USB_AF9005=m
CONFIG_DVB_USB_AF9005_REMOTE=m
CONFIG_DVB_USB_AZ6027=m
CONFIG_DVB_USB_CINERGY_T2=m
CONFIG_DVB_USB_CXUSB=m
CONFIG_DVB_USB_CXUSB_ANALOG=y
CONFIG_DVB_USB_DIB0700=m
CONFIG_DVB_USB_DIB3000MC=m
CONFIG_DVB_USB_DIBUSB_MB=m
# CONFIG_DVB_USB_DIBUSB_MB_FAULTY is not set
CONFIG_DVB_USB_DIBUSB_MC=m
CONFIG_DVB_USB_DIGITV=m
CONFIG_DVB_USB_DTT200U=m
CONFIG_DVB_USB_DTV5100=m
CONFIG_DVB_USB_DW2102=m
CONFIG_DVB_USB_GP8PSK=m
CONFIG_DVB_USB_M920X=m
CONFIG_DVB_USB_NOVA_T_USB2=m
CONFIG_DVB_USB_OPERA1=m
CONFIG_DVB_USB_PCTV452E=m
CONFIG_DVB_USB_TECHNISAT_USB2=m
CONFIG_DVB_USB_TTUSB2=m
CONFIG_DVB_USB_UMT_010=m
CONFIG_DVB_USB_VP702X=m
CONFIG_DVB_USB_VP7045=m
CONFIG_SMS_USB_DRV=m
CONFIG_DVB_TTUSB_BUDGET=m
CONFIG_DVB_TTUSB_DEC=m

#
# Webcam, TV (analog/digital) USB devices
#
CONFIG_VIDEO_EM28XX=m
CONFIG_VIDEO_EM28XX_V4L2=m
CONFIG_VIDEO_EM28XX_ALSA=m
CONFIG_VIDEO_EM28XX_DVB=m
CONFIG_VIDEO_EM28XX_RC=m
CONFIG_MEDIA_PCI_SUPPORT=y

#
# Media capture support
#
# CONFIG_VIDEO_MGB4 is not set
CONFIG_VIDEO_SOLO6X10=m
# CONFIG_VIDEO_TW5864 is not set
# CONFIG_VIDEO_TW68 is not set
CONFIG_VIDEO_TW686X=m
# CONFIG_VIDEO_ZORAN is not set

#
# Media capture/analog TV support
#
# CONFIG_VIDEO_DT3155 is not set
CONFIG_VIDEO_IVTV=m
# CONFIG_VIDEO_IVTV_ALSA is not set
CONFIG_VIDEO_FB_IVTV=m
CONFIG_VIDEO_HEXIUM_GEMINI=m
CONFIG_VIDEO_HEXIUM_ORION=m
CONFIG_VIDEO_MXB=m

#
# Media capture/analog/hybrid TV support
#
CONFIG_VIDEO_BT848=m
CONFIG_DVB_BT8XX=m
CONFIG_VIDEO_CX18=m
CONFIG_VIDEO_CX18_ALSA=m
CONFIG_VIDEO_CX23885=m
CONFIG_MEDIA_ALTERA_CI=m
# CONFIG_VIDEO_CX25821 is not set
CONFIG_VIDEO_CX88=m
CONFIG_VIDEO_CX88_ALSA=m
CONFIG_VIDEO_CX88_BLACKBIRD=m
CONFIG_VIDEO_CX88_DVB=m
CONFIG_VIDEO_CX88_ENABLE_VP3054=y
CONFIG_VIDEO_CX88_VP3054=m
CONFIG_VIDEO_CX88_MPEG=m
CONFIG_VIDEO_SAA7134=m
CONFIG_VIDEO_SAA7134_ALSA=m
CONFIG_VIDEO_SAA7134_RC=y
CONFIG_VIDEO_SAA7134_DVB=m
CONFIG_VIDEO_SAA7134_GO7007=m
CONFIG_VIDEO_SAA7164=m

#
# Media digital TV PCI Adapters
#
CONFIG_DVB_B2C2_FLEXCOP_PCI=m
# CONFIG_DVB_B2C2_FLEXCOP_PCI_DEBUG is not set
CONFIG_DVB_DDBRIDGE=m
# CONFIG_DVB_DDBRIDGE_MSIENABLE is not set
CONFIG_DVB_DM1105=m
CONFIG_MANTIS_CORE=m
CONFIG_DVB_MANTIS=m
CONFIG_DVB_HOPPER=m
CONFIG_DVB_NETUP_UNIDVB=m
CONFIG_DVB_NGENE=m
CONFIG_DVB_PLUTO2=m
CONFIG_DVB_PT1=m
# CONFIG_DVB_PT3 is not set
CONFIG_DVB_SMIPCIE=m
CONFIG_DVB_BUDGET_CORE=m
CONFIG_DVB_BUDGET=m
CONFIG_DVB_BUDGET_CI=m
CONFIG_DVB_BUDGET_AV=m
CONFIG_IPU_BRIDGE=m
CONFIG_RADIO_ADAPTERS=m
CONFIG_RADIO_MAXIRADIO=m
CONFIG_RADIO_SAA7706H=m
CONFIG_RADIO_SHARK=m
CONFIG_RADIO_SHARK2=m
CONFIG_RADIO_SI4713=m
CONFIG_RADIO_TEA575X=m
CONFIG_RADIO_TEA5764=m
# CONFIG_RADIO_TEF6862 is not set
CONFIG_RADIO_WL1273=m
CONFIG_USB_DSBR=m
CONFIG_USB_KEENE=m
CONFIG_USB_MA901=m
CONFIG_USB_MR800=m
# CONFIG_USB_RAREMONO is not set
CONFIG_RADIO_SI470X=m
CONFIG_USB_SI470X=m
CONFIG_I2C_SI470X=m
# CONFIG_USB_SI4713 is not set
# CONFIG_PLATFORM_SI4713 is not set
# CONFIG_I2C_SI4713 is not set
CONFIG_MEDIA_PLATFORM_DRIVERS=y
CONFIG_V4L_PLATFORM_DRIVERS=y
# CONFIG_DVB_PLATFORM_DRIVERS is not set
CONFIG_V4L_MEM2MEM_DRIVERS=y
# CONFIG_VIDEO_MEM2MEM_DEINTERLACE is not set
CONFIG_VIDEO_MUX=m

#
# Allegro DVT media platform drivers
#
CONFIG_VIDEO_ALLEGRO_DVT=m

#
# Amlogic media platform drivers
#
# CONFIG_VIDEO_C3_ISP is not set
# CONFIG_VIDEO_C3_MIPI_ADAPTER is not set
# CONFIG_VIDEO_C3_MIPI_CSI2 is not set
CONFIG_VIDEO_MESON_GE2D=m

#
# Amphion drivers
#
CONFIG_VIDEO_AMPHION_VPU=m

#
# Aspeed media platform drivers
#

#
# Atmel media platform drivers
#
CONFIG_VIDEO_BCM2835_UNICAM=m

#
# Cadence media platform drivers
#
CONFIG_VIDEO_CADENCE_CSI2RX=m
CONFIG_VIDEO_CADENCE_CSI2TX=m

#
# Chips&Media media platform drivers
#
CONFIG_VIDEO_CODA=m
CONFIG_VIDEO_WAVE_VPU=m
CONFIG_VIDEO_E5010_JPEG_ENC=m

#
# Intel media platform drivers
#

#
# Marvell media platform drivers
#
# CONFIG_VIDEO_CAFE_CCIC is not set

#
# Mediatek media platform drivers
#

#
# Microchip Technology, Inc. media platform drivers
#

#
# Nuvoton media platform drivers
#

#
# NVidia media platform drivers
#
CONFIG_VIDEO_TEGRA_VDE=m

#
# NXP media platform drivers
#
CONFIG_VIDEO_IMX7_CSI=m
CONFIG_VIDEO_IMX8MQ_MIPI_CSI2=m
CONFIG_VIDEO_IMX_MIPI_CSIS=m
CONFIG_VIDEO_IMX8_ISI=m
CONFIG_VIDEO_IMX8_ISI_M2M=y
CONFIG_VIDEO_IMX_PXP=m
CONFIG_VIDEO_DW100=m
CONFIG_VIDEO_IMX8_JPEG=m

#
# Qualcomm media platform drivers
#
CONFIG_VIDEO_QCOM_CAMSS=m
CONFIG_VIDEO_QCOM_IRIS=m
CONFIG_VIDEO_QCOM_VENUS=m

#
# Raspberry Pi media platform drivers
#
CONFIG_VIDEO_RASPBERRYPI_PISP_BE=m
CONFIG_VIDEO_RP1_CFE=m

#
# Renesas media platform drivers
#
# CONFIG_VIDEO_RCAR_CSI2 is not set
# CONFIG_VIDEO_RCAR_ISP is not set
# CONFIG_VIDEO_RCAR_VIN is not set
CONFIG_VIDEO_RZG2L_CSI2=m
CONFIG_VIDEO_RZG2L_CRU=m
CONFIG_VIDEO_RENESAS_FCP=m
CONFIG_VIDEO_RENESAS_FDP1=m
# CONFIG_VIDEO_RENESAS_JPU is not set
CONFIG_VIDEO_RENESAS_VSP1=m

#
# Rockchip media platform drivers
#
CONFIG_VIDEO_ROCKCHIP_RGA=m
CONFIG_VIDEO_ROCKCHIP_ISP1=m
CONFIG_VIDEO_ROCKCHIP_VDEC=m

#
# Samsung media platform drivers
#

#
# STMicroelectronics media platform drivers
#

#
# Sunxi media platform drivers
#
CONFIG_VIDEO_SUN4I_CSI=m
CONFIG_VIDEO_SUN6I_CSI=m
# CONFIG_VIDEO_SUN6I_MIPI_CSI2 is not set
# CONFIG_VIDEO_SUN8I_A83T_MIPI_CSI2 is not set
CONFIG_VIDEO_SUN8I_DEINTERLACE=m
CONFIG_VIDEO_SUN8I_ROTATE=m
CONFIG_VIDEO_SYNOPSYS_HDMIRX=m
CONFIG_VIDEO_SYNOPSYS_HDMIRX_LOAD_DEFAULT_EDID=y

#
# Texas Instruments drivers
#
CONFIG_VIDEO_TI_CAL=m
CONFIG_VIDEO_TI_CAL_MC=y
CONFIG_VIDEO_TI_J721E_CSI2RX=m

#
# Verisilicon media platform drivers
#
CONFIG_VIDEO_HANTRO=m
CONFIG_VIDEO_HANTRO_HEVC_RFC=y
CONFIG_VIDEO_HANTRO_IMX8M=y
CONFIG_VIDEO_HANTRO_ROCKCHIP=y
CONFIG_VIDEO_HANTRO_SUNXI=y

#
# VIA media platform drivers
#

#
# Xilinx media platform drivers
#
# CONFIG_VIDEO_XILINX is not set

#
# MMC/SDIO DVB adapters
#
CONFIG_SMS_SDIO_DRV=m
CONFIG_V4L_TEST_DRIVERS=y
CONFIG_VIDEO_VIM2M=m
CONFIG_VIDEO_VICODEC=m
CONFIG_VIDEO_VIMC=m
CONFIG_VIDEO_VIVID=m
CONFIG_VIDEO_VIVID_CEC=y
CONFIG_VIDEO_VIVID_OSD=y
CONFIG_VIDEO_VIVID_MAX_DEVS=64
CONFIG_VIDEO_VISL=m
# CONFIG_VISL_DEBUGFS is not set
# CONFIG_DVB_TEST_DRIVERS is not set
CONFIG_MEDIA_COMMON_OPTIONS=y

#
# common driver options
#
CONFIG_CYPRESS_FIRMWARE=m
CONFIG_TTPCI_EEPROM=m
CONFIG_UVC_COMMON=m
CONFIG_VIDEO_CX2341X=m
CONFIG_VIDEO_TVEEPROM=m
CONFIG_DVB_B2C2_FLEXCOP=m
CONFIG_VIDEO_SAA7146=m
CONFIG_VIDEO_SAA7146_VV=m
CONFIG_SMS_SIANO_MDTV=m
CONFIG_SMS_SIANO_RC=y
# CONFIG_SMS_SIANO_DEBUGFS is not set
CONFIG_VIDEO_V4L2_TPG=m
CONFIG_VIDEOBUF2_CORE=m
CONFIG_VIDEOBUF2_V4L2=m
CONFIG_VIDEOBUF2_MEMOPS=m
CONFIG_VIDEOBUF2_DMA_CONTIG=m
CONFIG_VIDEOBUF2_VMALLOC=m
CONFIG_VIDEOBUF2_DMA_SG=m
CONFIG_VIDEOBUF2_DVB=m
# end of Media drivers

#
# Media ancillary drivers
#
CONFIG_MEDIA_ATTACH=y

#
# IR I2C driver auto-selected by 'Autoselect ancillary drivers'
#
CONFIG_VIDEO_IR_I2C=m
CONFIG_VIDEO_CAMERA_SENSOR=y
CONFIG_VIDEO_APTINA_PLL=m
CONFIG_VIDEO_CCS_PLL=m
# CONFIG_VIDEO_ALVIUM_CSI2 is not set
CONFIG_VIDEO_AR0521=m
CONFIG_VIDEO_GC0308=m
# CONFIG_VIDEO_GC05A2 is not set
# CONFIG_VIDEO_GC08A3 is not set
CONFIG_VIDEO_GC2145=m
CONFIG_VIDEO_HI556=m
CONFIG_VIDEO_HI846=m
CONFIG_VIDEO_HI847=m
CONFIG_VIDEO_IMX208=m
CONFIG_VIDEO_IMX214=m
CONFIG_VIDEO_IMX219=m
CONFIG_VIDEO_IMX258=m
CONFIG_VIDEO_IMX274=m
CONFIG_VIDEO_IMX283=m
CONFIG_VIDEO_IMX290=m
CONFIG_VIDEO_IMX296=m
CONFIG_VIDEO_IMX319=m
CONFIG_VIDEO_IMX334=m
CONFIG_VIDEO_IMX335=m
CONFIG_VIDEO_IMX355=m
CONFIG_VIDEO_IMX412=m
CONFIG_VIDEO_IMX415=m
CONFIG_VIDEO_MAX9271_LIB=m
CONFIG_VIDEO_MT9M001=m
# CONFIG_VIDEO_MT9M111 is not set
CONFIG_VIDEO_MT9M114=m
CONFIG_VIDEO_MT9P031=m
CONFIG_VIDEO_MT9T112=m
CONFIG_VIDEO_MT9V011=m
CONFIG_VIDEO_MT9V032=m
CONFIG_VIDEO_MT9V111=m
CONFIG_VIDEO_OG01A1B=m
CONFIG_VIDEO_OV01A10=m
CONFIG_VIDEO_OV02A10=m
CONFIG_VIDEO_OV02E10=m
CONFIG_VIDEO_OV02C10=m
CONFIG_VIDEO_OV08D10=m
CONFIG_VIDEO_OV08X40=m
CONFIG_VIDEO_OV13858=m
CONFIG_VIDEO_OV13B10=m
CONFIG_VIDEO_OV2640=m
CONFIG_VIDEO_OV2659=m
CONFIG_VIDEO_OV2680=m
CONFIG_VIDEO_OV2685=m
CONFIG_VIDEO_OV2740=m
CONFIG_VIDEO_OV4689=m
CONFIG_VIDEO_OV5640=m
CONFIG_VIDEO_OV5645=m
CONFIG_VIDEO_OV5647=m
CONFIG_VIDEO_OV5648=m
CONFIG_VIDEO_OV5670=m
CONFIG_VIDEO_OV5675=m
CONFIG_VIDEO_OV5693=m
CONFIG_VIDEO_OV5695=m
CONFIG_VIDEO_OV64A40=m
CONFIG_VIDEO_OV6650=m
CONFIG_VIDEO_OV7251=m
CONFIG_VIDEO_OV7640=m
# CONFIG_VIDEO_OV7670 is not set
CONFIG_VIDEO_OV772X=m
CONFIG_VIDEO_OV7740=m
CONFIG_VIDEO_OV8856=m
CONFIG_VIDEO_OV8858=m
CONFIG_VIDEO_OV8865=m
CONFIG_VIDEO_OV9282=m
CONFIG_VIDEO_OV9640=m
CONFIG_VIDEO_OV9650=m
CONFIG_VIDEO_OV9734=m
CONFIG_VIDEO_RDACM20=m
# CONFIG_VIDEO_RDACM21 is not set
CONFIG_VIDEO_RJ54N1=m
CONFIG_VIDEO_S5C73M3=m
CONFIG_VIDEO_S5K5BAF=m
CONFIG_VIDEO_S5K6A3=m
# CONFIG_VIDEO_VD55G1 is not set
# CONFIG_VIDEO_VD56G3 is not set
# CONFIG_VIDEO_VGXY61 is not set
CONFIG_VIDEO_CCS=m
CONFIG_VIDEO_ET8EK8=m

#
# Camera ISPs
#
# CONFIG_VIDEO_THP7312 is not set
# end of Camera ISPs

CONFIG_VIDEO_CAMERA_LENS=y
CONFIG_VIDEO_AD5820=m
CONFIG_VIDEO_AK7375=m
CONFIG_VIDEO_DW9714=m
CONFIG_VIDEO_DW9719=m
CONFIG_VIDEO_DW9768=m
CONFIG_VIDEO_DW9807_VCM=m

#
# Flash devices
#
CONFIG_VIDEO_ADP1653=m
CONFIG_VIDEO_LM3560=m
CONFIG_VIDEO_LM3646=m
# end of Flash devices

#
# Audio decoders, processors and mixers
#
CONFIG_VIDEO_CS3308=m
CONFIG_VIDEO_CS5345=m
CONFIG_VIDEO_CS53L32A=m
CONFIG_VIDEO_MSP3400=m
CONFIG_VIDEO_SONY_BTF_MPX=m
CONFIG_VIDEO_TDA1997X=m
CONFIG_VIDEO_TDA7432=m
CONFIG_VIDEO_TDA9840=m
CONFIG_VIDEO_TEA6415C=m
CONFIG_VIDEO_TEA6420=m
CONFIG_VIDEO_TLV320AIC23B=m
CONFIG_VIDEO_TVAUDIO=m
CONFIG_VIDEO_UDA1342=m
CONFIG_VIDEO_VP27SMPX=m
CONFIG_VIDEO_WM8739=m
CONFIG_VIDEO_WM8775=m
# end of Audio decoders, processors and mixers

#
# RDS decoders
#
CONFIG_VIDEO_SAA6588=m
# end of RDS decoders

#
# Video decoders
#
CONFIG_VIDEO_ADV7180=m
CONFIG_VIDEO_ADV7183=m
CONFIG_VIDEO_ADV748X=m
CONFIG_VIDEO_ADV7604=m
# CONFIG_VIDEO_ADV7604_CEC is not set
CONFIG_VIDEO_ADV7842=m
# CONFIG_VIDEO_ADV7842_CEC is not set
CONFIG_VIDEO_BT819=m
CONFIG_VIDEO_BT856=m
CONFIG_VIDEO_BT866=m
CONFIG_VIDEO_ISL7998X=m
CONFIG_VIDEO_LT6911UXE=m
CONFIG_VIDEO_KS0127=m
CONFIG_VIDEO_MAX9286=m
CONFIG_VIDEO_ML86V7667=m
CONFIG_VIDEO_SAA7110=m
CONFIG_VIDEO_SAA711X=m
CONFIG_VIDEO_TC358743=m
CONFIG_VIDEO_TC358743_CEC=y
CONFIG_VIDEO_TC358746=m
CONFIG_VIDEO_TVP514X=m
CONFIG_VIDEO_TVP5150=m
CONFIG_VIDEO_TVP7002=m
CONFIG_VIDEO_TW2804=m
# CONFIG_VIDEO_TW9900 is not set
CONFIG_VIDEO_TW9903=m
CONFIG_VIDEO_TW9906=m
CONFIG_VIDEO_TW9910=m
CONFIG_VIDEO_VPX3220=m

#
# Video and audio decoders
#
CONFIG_VIDEO_SAA717X=m
CONFIG_VIDEO_CX25840=m
# end of Video decoders

#
# Video encoders
#
CONFIG_VIDEO_ADV7170=m
CONFIG_VIDEO_ADV7175=m
CONFIG_VIDEO_ADV7343=m
CONFIG_VIDEO_ADV7393=m
CONFIG_VIDEO_AK881X=m
CONFIG_VIDEO_SAA7127=m
CONFIG_VIDEO_SAA7185=m
CONFIG_VIDEO_THS8200=m
# end of Video encoders

#
# Video improvement chips
#
CONFIG_VIDEO_UPD64031A=m
CONFIG_VIDEO_UPD64083=m
# end of Video improvement chips

#
# Audio/Video compression chips
#
CONFIG_VIDEO_SAA6752HS=m
# end of Audio/Video compression chips

#
# SDR tuner chips
#
# end of SDR tuner chips

#
# Miscellaneous helper chips
#
CONFIG_VIDEO_I2C=m
CONFIG_VIDEO_M52790=m
CONFIG_VIDEO_ST_MIPID02=m
CONFIG_VIDEO_THS7303=m
# end of Miscellaneous helper chips

#
# Video serializers and deserializers
#
CONFIG_VIDEO_DS90UB913=m
CONFIG_VIDEO_DS90UB953=m
CONFIG_VIDEO_DS90UB960=m
CONFIG_VIDEO_MAX96714=m
CONFIG_VIDEO_MAX96717=m
# end of Video serializers and deserializers

#
# Media SPI Adapters
#
CONFIG_CXD2880_SPI_DRV=m
CONFIG_VIDEO_GS1662=m
# end of Media SPI Adapters

CONFIG_MEDIA_TUNER=m

#
# Customize TV tuners
#
CONFIG_MEDIA_TUNER_E4000=m
CONFIG_MEDIA_TUNER_FC0011=m
CONFIG_MEDIA_TUNER_FC0012=m
CONFIG_MEDIA_TUNER_FC0013=m
CONFIG_MEDIA_TUNER_FC2580=m
CONFIG_MEDIA_TUNER_IT913X=m
CONFIG_MEDIA_TUNER_M88RS6000T=m
CONFIG_MEDIA_TUNER_MAX2165=m
CONFIG_MEDIA_TUNER_MC44S803=m
# CONFIG_MEDIA_TUNER_MSI001 is not set
CONFIG_MEDIA_TUNER_MT2060=m
CONFIG_MEDIA_TUNER_MT2063=m
CONFIG_MEDIA_TUNER_MT20XX=m
CONFIG_MEDIA_TUNER_MT2131=m
CONFIG_MEDIA_TUNER_MT2266=m
# CONFIG_MEDIA_TUNER_MXL301RF is not set
CONFIG_MEDIA_TUNER_MXL5005S=m
CONFIG_MEDIA_TUNER_MXL5007T=m
CONFIG_MEDIA_TUNER_QM1D1B0004=m
CONFIG_MEDIA_TUNER_QM1D1C0042=m
CONFIG_MEDIA_TUNER_QT1010=m
CONFIG_MEDIA_TUNER_R820T=m
CONFIG_MEDIA_TUNER_SI2157=m
CONFIG_MEDIA_TUNER_SIMPLE=m
CONFIG_MEDIA_TUNER_TDA18212=m
CONFIG_MEDIA_TUNER_TDA18218=m
CONFIG_MEDIA_TUNER_TDA18250=m
CONFIG_MEDIA_TUNER_TDA18271=m
CONFIG_MEDIA_TUNER_TDA827X=m
CONFIG_MEDIA_TUNER_TDA8290=m
CONFIG_MEDIA_TUNER_TDA9887=m
CONFIG_MEDIA_TUNER_TEA5761=m
CONFIG_MEDIA_TUNER_TEA5767=m
CONFIG_MEDIA_TUNER_TUA9001=m
CONFIG_MEDIA_TUNER_XC2028=m
CONFIG_MEDIA_TUNER_XC4000=m
CONFIG_MEDIA_TUNER_XC5000=m
# end of Customize TV tuners

#
# Customise DVB Frontends
#

#
# Multistandard (satellite) frontends
#
CONFIG_DVB_M88DS3103=m
CONFIG_DVB_MXL5XX=m
CONFIG_DVB_STB0899=m
CONFIG_DVB_STB6100=m
CONFIG_DVB_STV090x=m
CONFIG_DVB_STV0910=m
CONFIG_DVB_STV6110x=m
CONFIG_DVB_STV6111=m

#
# Multistandard (cable + terrestrial) frontends
#
CONFIG_DVB_DRXK=m
CONFIG_DVB_MN88472=m
CONFIG_DVB_MN88473=m
CONFIG_DVB_SI2165=m
CONFIG_DVB_TDA18271C2DD=m

#
# DVB-S (satellite) frontends
#
CONFIG_DVB_CX24110=m
CONFIG_DVB_CX24116=m
CONFIG_DVB_CX24117=m
CONFIG_DVB_CX24120=m
CONFIG_DVB_CX24123=m
CONFIG_DVB_DS3000=m
CONFIG_DVB_MB86A16=m
CONFIG_DVB_MT312=m
CONFIG_DVB_S5H1420=m
CONFIG_DVB_SI21XX=m
CONFIG_DVB_STB6000=m
CONFIG_DVB_STV0288=m
CONFIG_DVB_STV0299=m
CONFIG_DVB_STV0900=m
CONFIG_DVB_STV6110=m
CONFIG_DVB_TDA10071=m
CONFIG_DVB_TDA10086=m
CONFIG_DVB_TDA8083=m
CONFIG_DVB_TDA8261=m
CONFIG_DVB_TDA826X=m
CONFIG_DVB_TS2020=m
CONFIG_DVB_TUA6100=m
CONFIG_DVB_TUNER_CX24113=m
CONFIG_DVB_TUNER_ITD1000=m
CONFIG_DVB_VES1X93=m
CONFIG_DVB_ZL10036=m
CONFIG_DVB_ZL10039=m

#
# DVB-T (terrestrial) frontends
#
CONFIG_DVB_AF9013=m
CONFIG_DVB_AS102_FE=m
CONFIG_DVB_CX22700=m
CONFIG_DVB_CX22702=m
CONFIG_DVB_CXD2820R=m
CONFIG_DVB_CXD2841ER=m
CONFIG_DVB_DIB3000MB=m
CONFIG_DVB_DIB3000MC=m
CONFIG_DVB_DIB7000M=m
CONFIG_DVB_DIB7000P=m
# CONFIG_DVB_DIB9000 is not set
CONFIG_DVB_DRXD=m
CONFIG_DVB_EC100=m
CONFIG_DVB_GP8PSK_FE=m
CONFIG_DVB_L64781=m
CONFIG_DVB_MT352=m
CONFIG_DVB_NXT6000=m
CONFIG_DVB_RTL2830=m
CONFIG_DVB_RTL2832=m
# CONFIG_DVB_S5H1432 is not set
CONFIG_DVB_SI2168=m
CONFIG_DVB_SP887X=m
CONFIG_DVB_STV0367=m
CONFIG_DVB_TDA10048=m
CONFIG_DVB_TDA1004X=m
CONFIG_DVB_ZD1301_DEMOD=m
CONFIG_DVB_ZL10353=m
# CONFIG_DVB_CXD2880 is not set

#
# DVB-C (cable) frontends
#
CONFIG_DVB_STV0297=m
CONFIG_DVB_TDA10021=m
CONFIG_DVB_TDA10023=m
CONFIG_DVB_VES1820=m

#
# ATSC (North American/Korean Terrestrial/Cable DTV) frontends
#
CONFIG_DVB_AU8522=m
CONFIG_DVB_AU8522_DTV=m
CONFIG_DVB_AU8522_V4L=m
CONFIG_DVB_BCM3510=m
CONFIG_DVB_LG2160=m
CONFIG_DVB_LGDT3305=m
CONFIG_DVB_LGDT3306A=m
CONFIG_DVB_LGDT330X=m
CONFIG_DVB_MXL692=m
CONFIG_DVB_NXT200X=m
CONFIG_DVB_OR51132=m
CONFIG_DVB_OR51211=m
CONFIG_DVB_S5H1409=m
CONFIG_DVB_S5H1411=m

#
# ISDB-T (terrestrial) frontends
#
CONFIG_DVB_DIB8000=m
CONFIG_DVB_MB86A20S=m
CONFIG_DVB_S921=m

#
# ISDB-S (satellite) & ISDB-T (terrestrial) frontends
#
# CONFIG_DVB_MN88443X is not set
CONFIG_DVB_TC90522=m

#
# Digital terrestrial only tuners/PLL
#
CONFIG_DVB_PLL=m
CONFIG_DVB_TUNER_DIB0070=m
CONFIG_DVB_TUNER_DIB0090=m

#
# SEC control devices for DVB-S
#
CONFIG_DVB_A8293=m
CONFIG_DVB_AF9033=m
CONFIG_DVB_ASCOT2E=m
CONFIG_DVB_ATBM8830=m
CONFIG_DVB_HELENE=m
CONFIG_DVB_HORUS3A=m
CONFIG_DVB_ISL6405=m
CONFIG_DVB_ISL6421=m
CONFIG_DVB_ISL6423=m
CONFIG_DVB_IX2505V=m
# CONFIG_DVB_LGS8GL5 is not set
CONFIG_DVB_LGS8GXX=m
CONFIG_DVB_LNBH25=m
# CONFIG_DVB_LNBH29 is not set
CONFIG_DVB_LNBP21=m
CONFIG_DVB_LNBP22=m
CONFIG_DVB_M88RS2000=m
CONFIG_DVB_TDA665x=m
CONFIG_DVB_DRX39XYJ=m

#
# Common Interface (EN50221) controller drivers
#
CONFIG_DVB_CXD2099=m
CONFIG_DVB_SP2=m
# end of Customise DVB Frontends

#
# Tools to develop new frontends
#
# CONFIG_DVB_DUMMY_FE is not set
# end of Media ancillary drivers

#
# Graphics support
#
CONFIG_APERTURE_HELPERS=y
CONFIG_SCREEN_INFO=y
CONFIG_VIDEO=y
CONFIG_AUXDISPLAY=y
CONFIG_CHARLCD=m
CONFIG_HD44780_COMMON=m
CONFIG_HD44780=m
# CONFIG_LCD2S is not set
# CONFIG_PANEL_CHANGE_MESSAGE is not set
# CONFIG_CHARLCD_BL_OFF is not set
# CONFIG_CHARLCD_BL_ON is not set
CONFIG_CHARLCD_BL_FLASH=y
CONFIG_LINEDISP=m
# CONFIG_IMG_ASCII_LCD is not set
CONFIG_HT16K33=m
# CONFIG_MAX6959 is not set
# CONFIG_SEG_LED_GPIO is not set
CONFIG_TEGRA_HOST1X_CONTEXT_BUS=y
CONFIG_TEGRA_HOST1X=m
CONFIG_TEGRA_HOST1X_FIREWALL=y
CONFIG_DRM=y

#
# DRM debugging options
#
CONFIG_DRM_WERROR=y
# CONFIG_DRM_DEBUG_MM is not set
CONFIG_DRM_KUNIT_TEST_HELPERS=m
CONFIG_DRM_KUNIT_TEST=m
CONFIG_DRM_SCHED_KUNIT_TEST=m
CONFIG_DRM_EXPORT_FOR_TESTS=y
# end of DRM debugging options

CONFIG_DRM_MIPI_DBI=m
CONFIG_DRM_MIPI_DSI=y
CONFIG_DRM_KMS_HELPER=y
CONFIG_DRM_DRAW=y
CONFIG_DRM_PANIC=y
CONFIG_DRM_PANIC_FOREGROUND_COLOR=0xffffff
CONFIG_DRM_PANIC_BACKGROUND_COLOR=0x000000
# CONFIG_DRM_PANIC_DEBUG is not set
CONFIG_DRM_PANIC_SCREEN="user"
# CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS is not set
# CONFIG_DRM_DEBUG_MODESET_LOCK is not set
CONFIG_DRM_CLIENT=y
CONFIG_DRM_CLIENT_LIB=y
CONFIG_DRM_CLIENT_SELECTION=y
CONFIG_DRM_CLIENT_SETUP=y

#
# Supported DRM clients
#
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
# CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM is not set
# CONFIG_DRM_CLIENT_LOG is not set
CONFIG_DRM_CLIENT_DEFAULT_FBDEV=y
CONFIG_DRM_CLIENT_DEFAULT="fbdev"
# end of Supported DRM clients

CONFIG_DRM_LOAD_EDID_FIRMWARE=y
CONFIG_DRM_DISPLAY_DP_AUX_BUS=m
CONFIG_DRM_DISPLAY_HELPER=m
CONFIG_DRM_BRIDGE_CONNECTOR=y
CONFIG_DRM_DISPLAY_DP_AUX_CEC=y
CONFIG_DRM_DISPLAY_DP_AUX_CHARDEV=y
CONFIG_DRM_DISPLAY_DP_HELPER=y
CONFIG_DRM_DISPLAY_DP_TUNNEL=y
CONFIG_DRM_DISPLAY_DSC_HELPER=y
CONFIG_DRM_DISPLAY_HDCP_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_AUDIO_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_CEC_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_CEC_NOTIFIER_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_STATE_HELPER=y
CONFIG_DRM_TTM=m
CONFIG_DRM_EXEC=m
CONFIG_DRM_GPUVM=m
CONFIG_DRM_GPUSVM=m
CONFIG_DRM_BUDDY=m
CONFIG_DRM_TTM_HELPER=m
CONFIG_DRM_GEM_DMA_HELPER=m
CONFIG_DRM_GEM_SHMEM_HELPER=y
CONFIG_DRM_SUBALLOC_HELPER=m
CONFIG_DRM_SCHED=m

#
# Drivers for system framebuffers
#
CONFIG_DRM_SYSFB_HELPER=y
CONFIG_DRM_SIMPLEDRM=y
# end of Drivers for system framebuffers

#
# ARM devices
#
CONFIG_DRM_HDLCD=m
# CONFIG_DRM_HDLCD_SHOW_UNDERRUN is not set
CONFIG_DRM_MALI_DISPLAY=m
CONFIG_DRM_KOMEDA=m
# end of ARM devices

CONFIG_DRM_RADEON=m
CONFIG_DRM_RADEON_USERPTR=y
CONFIG_DRM_AMDGPU=m
CONFIG_DRM_AMDGPU_SI=y
CONFIG_DRM_AMDGPU_CIK=y
CONFIG_DRM_AMDGPU_USERPTR=y
CONFIG_DRM_AMD_ISP=y
# CONFIG_DRM_AMDGPU_WERROR is not set

#
# ACP (Audio CoProcessor) Configuration
#
CONFIG_DRM_AMD_ACP=y
# end of ACP (Audio CoProcessor) Configuration

#
# Display Engine Configuration
#
CONFIG_DRM_AMD_DC=y
CONFIG_DRM_AMD_DC_FP=y
CONFIG_DRM_AMD_DC_SI=y
# CONFIG_DEBUG_KERNEL_DC is not set
CONFIG_DRM_AMD_SECURE_DISPLAY=y
# end of Display Engine Configuration

CONFIG_HSA_AMD=y
CONFIG_HSA_AMD_SVM=y
CONFIG_DRM_NOUVEAU=m
CONFIG_NOUVEAU_PLATFORM_DRIVER=y
CONFIG_NOUVEAU_DEBUG=5
CONFIG_NOUVEAU_DEBUG_DEFAULT=3
# CONFIG_NOUVEAU_DEBUG_MMU is not set
# CONFIG_NOUVEAU_DEBUG_PUSH is not set
CONFIG_DRM_NOUVEAU_BACKLIGHT=y
# CONFIG_DRM_NOUVEAU_SVM is not set
CONFIG_DRM_NOUVEAU_GSP_DEFAULT=y
CONFIG_DRM_NOUVEAU_CH7006=m
CONFIG_DRM_NOUVEAU_SIL164=m
CONFIG_DRM_XE=m
CONFIG_DRM_XE_DISPLAY=y
CONFIG_DRM_XE_DP_TUNNEL=y
CONFIG_DRM_XE_GPUSVM=y
CONFIG_DRM_XE_PAGEMAP=y
CONFIG_DRM_XE_FORCE_PROBE=""

#
# drm/Xe Debugging
#
# CONFIG_DRM_XE_WERROR is not set
# CONFIG_DRM_XE_DEBUG is not set
# CONFIG_DRM_XE_DEBUG_VM is not set
# CONFIG_DRM_XE_DEBUG_MEMIRQ is not set
# CONFIG_DRM_XE_DEBUG_SRIOV is not set
# CONFIG_DRM_XE_DEBUG_MEM is not set
# CONFIG_DRM_XE_KUNIT_TEST is not set
# CONFIG_DRM_XE_USERPTR_INVAL_INJECT is not set
# end of drm/Xe Debugging

#
# drm/xe Profile Guided Optimisation
#
CONFIG_DRM_XE_JOB_TIMEOUT_MAX=10000
CONFIG_DRM_XE_JOB_TIMEOUT_MIN=1
CONFIG_DRM_XE_TIMESLICE_MAX=10000000
CONFIG_DRM_XE_TIMESLICE_MIN=1
CONFIG_DRM_XE_PREEMPT_TIMEOUT=640000
CONFIG_DRM_XE_PREEMPT_TIMEOUT_MAX=10000000
CONFIG_DRM_XE_PREEMPT_TIMEOUT_MIN=1
CONFIG_DRM_XE_ENABLE_SCHEDTIMEOUT_LIMIT=y
# end of drm/xe Profile Guided Optimisation

CONFIG_DRM_VGEM=m
CONFIG_DRM_VKMS=m
CONFIG_DRM_VKMS_KUNIT_TEST=m
CONFIG_DRM_ROCKCHIP=m
CONFIG_ROCKCHIP_VOP=y
CONFIG_ROCKCHIP_VOP2=y
CONFIG_ROCKCHIP_ANALOGIX_DP=y
CONFIG_ROCKCHIP_CDN_DP=y
CONFIG_ROCKCHIP_DW_HDMI=y
CONFIG_ROCKCHIP_DW_HDMI_QP=y
CONFIG_ROCKCHIP_DW_MIPI_DSI=y
CONFIG_ROCKCHIP_DW_MIPI_DSI2=y
CONFIG_ROCKCHIP_INNO_HDMI=y
CONFIG_ROCKCHIP_LVDS=y
CONFIG_ROCKCHIP_RGB=y
CONFIG_ROCKCHIP_RK3066_HDMI=y
CONFIG_DRM_VMWGFX=m
CONFIG_DRM_UDL=m
CONFIG_DRM_AST=m
CONFIG_DRM_MGAG200=m
# CONFIG_DRM_RCAR_DU is not set
CONFIG_DRM_RZG2L_DU=m
CONFIG_DRM_RZG2L_USE_MIPI_DSI=y
CONFIG_DRM_RZG2L_MIPI_DSI=m
# CONFIG_DRM_SHMOBILE is not set
CONFIG_DRM_SUN4I=m
CONFIG_DRM_SUN6I_DSI=m
CONFIG_DRM_SUN8I_DW_HDMI=m
CONFIG_DRM_SUN8I_MIXER=m
CONFIG_DRM_SUN8I_TCON_TOP=m
CONFIG_DRM_QXL=m
CONFIG_DRM_VIRTIO_GPU=m
CONFIG_DRM_VIRTIO_GPU_KMS=y
CONFIG_DRM_MSM=m
CONFIG_DRM_MSM_GPU_STATE=y
# CONFIG_DRM_MSM_GPU_SUDO is not set
CONFIG_DRM_MSM_KMS=y
CONFIG_DRM_MSM_KMS_FBDEV=y
CONFIG_DRM_MSM_MDSS=y
# CONFIG_DRM_MSM_MDP4 is not set
CONFIG_DRM_MSM_MDP5=y
CONFIG_DRM_MSM_DPU=y
CONFIG_DRM_MSM_DP=y
CONFIG_DRM_MSM_DSI=y
CONFIG_DRM_MSM_DSI_28NM_PHY=y
CONFIG_DRM_MSM_DSI_20NM_PHY=y
# CONFIG_DRM_MSM_DSI_28NM_8960_PHY is not set
CONFIG_DRM_MSM_DSI_14NM_PHY=y
CONFIG_DRM_MSM_DSI_10NM_PHY=y
CONFIG_DRM_MSM_DSI_7NM_PHY=y
CONFIG_DRM_MSM_HDMI=y
CONFIG_DRM_MSM_HDMI_HDCP=y
CONFIG_DRM_TEGRA=m
# CONFIG_DRM_TEGRA_DEBUG is not set
CONFIG_DRM_TEGRA_STAGING=y
CONFIG_DRM_PANEL=y

#
# Display Panels
#
# CONFIG_DRM_PANEL_ABT_Y030XX067A is not set
CONFIG_DRM_PANEL_ARM_VERSATILE=m
# CONFIG_DRM_PANEL_ASUS_Z00T_TM5P5_NT35596 is not set
# CONFIG_DRM_PANEL_AUO_A030JTN01 is not set
CONFIG_DRM_PANEL_BOE_BF060Y8M_AJ0=m
# CONFIG_DRM_PANEL_BOE_HIMAX8279D is not set
# CONFIG_DRM_PANEL_BOE_TD4320 is not set
CONFIG_DRM_PANEL_BOE_TH101MB31UIG002_28A=m
CONFIG_DRM_PANEL_BOE_TV101WUM_NL6=m
CONFIG_DRM_PANEL_BOE_TV101WUM_LL2=m
# CONFIG_DRM_PANEL_EBBG_FT8719 is not set
CONFIG_DRM_PANEL_ELIDA_KD35T133=m
CONFIG_DRM_PANEL_FEIXIN_K101_IM2BA02=m
CONFIG_DRM_PANEL_FEIYANG_FY07024DI26A30D=m
CONFIG_DRM_PANEL_DSI_CM=m
# CONFIG_DRM_PANEL_LVDS is not set
# CONFIG_DRM_PANEL_HIMAX_HX8279 is not set
CONFIG_DRM_PANEL_HIMAX_HX83102=m
# CONFIG_DRM_PANEL_HIMAX_HX83112A is not set
# CONFIG_DRM_PANEL_HIMAX_HX83112B is not set
CONFIG_DRM_PANEL_HIMAX_HX8394=m
CONFIG_DRM_PANEL_ILITEK_IL9322=m
CONFIG_DRM_PANEL_ILITEK_ILI9341=m
# CONFIG_DRM_PANEL_ILITEK_ILI9805 is not set
CONFIG_DRM_PANEL_ILITEK_ILI9806E=m
CONFIG_DRM_PANEL_ILITEK_ILI9881C=m
CONFIG_DRM_PANEL_ILITEK_ILI9882T=m
CONFIG_DRM_PANEL_INNOLUX_EJ030NA=m
# CONFIG_DRM_PANEL_INNOLUX_P079ZCA is not set
CONFIG_DRM_PANEL_JADARD_JD9365DA_H3=m
CONFIG_DRM_PANEL_JDI_LPM102A188A=m
# CONFIG_DRM_PANEL_JDI_LT070ME05000 is not set
CONFIG_DRM_PANEL_JDI_R63452=m
CONFIG_DRM_PANEL_KHADAS_TS050=m
CONFIG_DRM_PANEL_KINGDISPLAY_KD097D04=m
# CONFIG_DRM_PANEL_LEADTEK_LTK050H3146W is not set
# CONFIG_DRM_PANEL_LEADTEK_LTK500HD1829 is not set
CONFIG_DRM_PANEL_LINCOLNTECH_LCD197=m
# CONFIG_DRM_PANEL_LG_LB035Q02 is not set
CONFIG_DRM_PANEL_LG_LG4573=m
# CONFIG_DRM_PANEL_LG_SW43408 is not set
CONFIG_DRM_PANEL_MAGNACHIP_D53E6EA8966=m
CONFIG_DRM_PANEL_MANTIX_MLAF057WE51=m
# CONFIG_DRM_PANEL_NEC_NL8048HL11 is not set
CONFIG_DRM_PANEL_NEWVISION_NV3051D=m
# CONFIG_DRM_PANEL_NEWVISION_NV3052C is not set
CONFIG_DRM_PANEL_NOVATEK_NT35510=m
CONFIG_DRM_PANEL_NOVATEK_NT35560=m
CONFIG_DRM_PANEL_NOVATEK_NT35950=m
# CONFIG_DRM_PANEL_NOVATEK_NT36523 is not set
# CONFIG_DRM_PANEL_NOVATEK_NT36672A is not set
# CONFIG_DRM_PANEL_NOVATEK_NT36672E is not set
# CONFIG_DRM_PANEL_NOVATEK_NT37801 is not set
# CONFIG_DRM_PANEL_NOVATEK_NT39016 is not set
CONFIG_DRM_PANEL_OLIMEX_LCD_OLINUXINO=m
# CONFIG_DRM_PANEL_ORISETECH_OTA5601A is not set
CONFIG_DRM_PANEL_ORISETECH_OTM8009A=m
# CONFIG_DRM_PANEL_OSD_OSD101T2587_53TS is not set
CONFIG_DRM_PANEL_PANASONIC_VVX10F034N00=m
CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN=m
# CONFIG_DRM_PANEL_RAYDIUM_RM67191 is not set
CONFIG_DRM_PANEL_RAYDIUM_RM67200=m
CONFIG_DRM_PANEL_RAYDIUM_RM68200=m
CONFIG_DRM_PANEL_RAYDIUM_RM692E5=m
CONFIG_DRM_PANEL_RAYDIUM_RM69380=m
# CONFIG_DRM_PANEL_RENESAS_R61307 is not set
# CONFIG_DRM_PANEL_RENESAS_R69328 is not set
CONFIG_DRM_PANEL_RONBO_RB070D30=m
CONFIG_DRM_PANEL_SAMSUNG_AMS581VF01=m
CONFIG_DRM_PANEL_SAMSUNG_AMS639RQ08=m
CONFIG_DRM_PANEL_SAMSUNG_S6E88A0_AMS427AP24=m
CONFIG_DRM_PANEL_SAMSUNG_S6E88A0_AMS452EF01=m
CONFIG_DRM_PANEL_SAMSUNG_ATNA33XC20=m
CONFIG_DRM_PANEL_SAMSUNG_DB7430=m
CONFIG_DRM_PANEL_SAMSUNG_LD9040=m
# CONFIG_DRM_PANEL_SAMSUNG_S6E3FA7 is not set
# CONFIG_DRM_PANEL_SAMSUNG_S6D16D0 is not set
# CONFIG_DRM_PANEL_SAMSUNG_S6D27A1 is not set
# CONFIG_DRM_PANEL_SAMSUNG_S6D7AA0 is not set
CONFIG_DRM_PANEL_SAMSUNG_S6E3HA2=m
CONFIG_DRM_PANEL_SAMSUNG_S6E3HA8=m
CONFIG_DRM_PANEL_SAMSUNG_S6E63J0X03=m
# CONFIG_DRM_PANEL_SAMSUNG_S6E63M0 is not set
CONFIG_DRM_PANEL_SAMSUNG_S6E8AA0=m
CONFIG_DRM_PANEL_SAMSUNG_SOFEF00=m
CONFIG_DRM_PANEL_SEIKO_43WVF1G=m
CONFIG_DRM_PANEL_SHARP_LQ101R1SX01=m
# CONFIG_DRM_PANEL_SHARP_LS037V7DW01 is not set
CONFIG_DRM_PANEL_SHARP_LS043T1LE01=m
# CONFIG_DRM_PANEL_SHARP_LS060T1SX01 is not set
CONFIG_DRM_PANEL_SITRONIX_ST7701=m
CONFIG_DRM_PANEL_SITRONIX_ST7703=m
CONFIG_DRM_PANEL_SITRONIX_ST7789V=m
# CONFIG_DRM_PANEL_SONY_ACX565AKM is not set
# CONFIG_DRM_PANEL_SONY_TD4353_JDI is not set
CONFIG_DRM_PANEL_SONY_TULIP_TRULY_NT35521=m
CONFIG_DRM_PANEL_STARTEK_KD070FHFID015=m
CONFIG_DRM_PANEL_EDP=m
CONFIG_DRM_PANEL_SIMPLE=m
CONFIG_DRM_PANEL_SUMMIT=m
# CONFIG_DRM_PANEL_SYNAPTICS_R63353 is not set
# CONFIG_DRM_PANEL_TDO_TL070WSH30 is not set
# CONFIG_DRM_PANEL_TPO_TD028TTEC1 is not set
# CONFIG_DRM_PANEL_TPO_TD043MTEA1 is not set
CONFIG_DRM_PANEL_TPO_TPG110=m
CONFIG_DRM_PANEL_TRULY_NT35597_WQXGA=m
# CONFIG_DRM_PANEL_VISIONOX_G2647FB105 is not set
CONFIG_DRM_PANEL_VISIONOX_R66451=m
CONFIG_DRM_PANEL_VISIONOX_RM69299=m
CONFIG_DRM_PANEL_VISIONOX_RM692E5=m
CONFIG_DRM_PANEL_VISIONOX_VTDR6130=m
CONFIG_DRM_PANEL_WIDECHIPS_WS2401=m
# CONFIG_DRM_PANEL_XINPENG_XPP055C272 is not set
# end of Display Panels

CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y
CONFIG_DRM_AUX_BRIDGE=m
CONFIG_DRM_AUX_HPD_BRIDGE=m

#
# Display Interface Bridges
#
CONFIG_DRM_CHIPONE_ICN6211=m
CONFIG_DRM_CHRONTEL_CH7033=m
CONFIG_DRM_CROS_EC_ANX7688=m
CONFIG_DRM_DISPLAY_CONNECTOR=m
CONFIG_DRM_FSL_LDB=m
CONFIG_DRM_I2C_NXP_TDA998X=m
CONFIG_DRM_ITE_IT6263=m
CONFIG_DRM_ITE_IT6505=m
CONFIG_DRM_LONTIUM_LT8912B=m
# CONFIG_DRM_LONTIUM_LT9211 is not set
CONFIG_DRM_LONTIUM_LT9611=m
CONFIG_DRM_LONTIUM_LT9611UXC=m
CONFIG_DRM_ITE_IT66121=m
# CONFIG_DRM_LVDS_CODEC is not set
# CONFIG_DRM_MEGACHIPS_STDPXXXX_GE_B850V3_FW is not set
CONFIG_DRM_NWL_MIPI_DSI=m
CONFIG_DRM_NXP_PTN3460=m
CONFIG_DRM_PARADE_PS8622=m
CONFIG_DRM_PARADE_PS8640=m
CONFIG_DRM_SAMSUNG_DSIM=m
# CONFIG_DRM_SIL_SII8620 is not set
CONFIG_DRM_SII902X=m
CONFIG_DRM_SII9234=m
CONFIG_DRM_SIMPLE_BRIDGE=m
# CONFIG_DRM_THINE_THC63LVD1024 is not set
CONFIG_DRM_TOSHIBA_TC358762=m
CONFIG_DRM_TOSHIBA_TC358764=m
CONFIG_DRM_TOSHIBA_TC358767=m
CONFIG_DRM_TOSHIBA_TC358768=m
CONFIG_DRM_TOSHIBA_TC358775=m
CONFIG_DRM_TI_DLPC3433=m
# CONFIG_DRM_TI_TDP158 is not set
CONFIG_DRM_TI_TFP410=m
CONFIG_DRM_TI_SN65DSI83=m
CONFIG_DRM_TI_SN65DSI86=m
CONFIG_DRM_TI_TPD12S015=m
CONFIG_DRM_ANALOGIX_ANX6345=m
CONFIG_DRM_ANALOGIX_ANX78XX=m
CONFIG_DRM_ANALOGIX_DP=m
CONFIG_DRM_ANALOGIX_ANX7625=m
CONFIG_DRM_I2C_ADV7511=m
CONFIG_DRM_I2C_ADV7511_AUDIO=y
CONFIG_DRM_I2C_ADV7511_CEC=y
CONFIG_DRM_CDNS_DSI=m
CONFIG_DRM_CDNS_DSI_J721E=y
CONFIG_DRM_CDNS_MHDP8546=m
CONFIG_DRM_CDNS_MHDP8546_J721E=y
CONFIG_DRM_IMX_LDB_HELPER=m
CONFIG_DRM_IMX8MP_DW_HDMI_BRIDGE=m
CONFIG_DRM_IMX8MP_HDMI_PVI=m
CONFIG_DRM_IMX8QM_LDB=m
CONFIG_DRM_IMX8QXP_LDB=m
CONFIG_DRM_IMX8QXP_PIXEL_COMBINER=m
CONFIG_DRM_IMX8QXP_PIXEL_LINK=m
CONFIG_DRM_IMX8QXP_PIXEL_LINK_TO_DPI=m
CONFIG_DRM_IMX93_MIPI_DSI=m
CONFIG_DRM_DW_HDMI=m
CONFIG_DRM_DW_HDMI_AHB_AUDIO=m
CONFIG_DRM_DW_HDMI_I2S_AUDIO=m
CONFIG_DRM_DW_HDMI_GP_AUDIO=m
CONFIG_DRM_DW_HDMI_CEC=m
CONFIG_DRM_DW_HDMI_QP=m
CONFIG_DRM_DW_MIPI_DSI=m
CONFIG_DRM_DW_MIPI_DSI2=m
# end of Display Interface Bridges

# CONFIG_DRM_IMX8_DC is not set
CONFIG_DRM_IMX_DCSS=m
CONFIG_DRM_IMX_LCDC=m
CONFIG_DRM_V3D=m
CONFIG_DRM_VC4=m
CONFIG_DRM_VC4_HDMI_CEC=y
# CONFIG_DRM_VC4_KUNIT_TEST is not set
CONFIG_DRM_ETNAVIV=m
CONFIG_DRM_ETNAVIV_THERMAL=y
# CONFIG_DRM_HISI_HIBMC is not set
CONFIG_DRM_HISI_KIRIN=m
# CONFIG_DRM_LOGICVC is not set
CONFIG_DRM_MXS=y
# CONFIG_DRM_MXSFB is not set
CONFIG_DRM_IMX_LCDIF=m
CONFIG_DRM_MESON=m
CONFIG_DRM_MESON_DW_HDMI=m
CONFIG_DRM_MESON_DW_MIPI_DSI=m
# CONFIG_DRM_ARCPGU is not set
CONFIG_DRM_BOCHS=m
CONFIG_DRM_CIRRUS_QEMU=m
CONFIG_DRM_GM12U320=m
CONFIG_DRM_PANEL_MIPI_DBI=m
CONFIG_TINYDRM_HX8357D=m
CONFIG_TINYDRM_ILI9163=m
CONFIG_TINYDRM_ILI9225=m
CONFIG_TINYDRM_ILI9341=m
CONFIG_TINYDRM_ILI9486=m
CONFIG_TINYDRM_MI0283QT=m
CONFIG_TINYDRM_REPAPER=m
CONFIG_TINYDRM_SHARP_MEMORY=m
CONFIG_DRM_PL111=m
CONFIG_DRM_LIMA=m
CONFIG_DRM_PANFROST=m
CONFIG_DRM_PANTHOR=m
CONFIG_DRM_TIDSS=m
CONFIG_DRM_ADP=m
CONFIG_DRM_ZYNQMP_DPSUB=m
CONFIG_DRM_ZYNQMP_DPSUB_AUDIO=y
CONFIG_DRM_GUD=m
# CONFIG_DRM_ST7571_I2C is not set
# CONFIG_DRM_ST7586 is not set
# CONFIG_DRM_ST7735R is not set
CONFIG_DRM_SSD130X=m
CONFIG_DRM_SSD130X_I2C=m
CONFIG_DRM_SSD130X_SPI=m
CONFIG_DRM_POWERVR=m
CONFIG_DRM_HYPERV=m
CONFIG_DRM_PANEL_BACKLIGHT_QUIRKS=m
CONFIG_DRM_LIB_RANDOM=y
CONFIG_DRM_PRIVACY_SCREEN=y
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=y

#
# Frame buffer Devices
#
CONFIG_FB=y
# CONFIG_FB_CIRRUS is not set
# CONFIG_FB_PM2 is not set
# CONFIG_FB_IMX is not set
# CONFIG_FB_CYBER2000 is not set
# CONFIG_FB_ASILIANT is not set
# CONFIG_FB_IMSTT is not set
# CONFIG_FB_UVESA is not set
CONFIG_FB_EFI=y
# CONFIG_FB_OPENCORES is not set
# CONFIG_FB_S1D13XXX is not set
# CONFIG_FB_NVIDIA is not set
# CONFIG_FB_RIVA is not set
# CONFIG_FB_I740 is not set
# CONFIG_FB_MATROX is not set
# CONFIG_FB_RADEON is not set
# CONFIG_FB_ATY128 is not set
# CONFIG_FB_ATY is not set
# CONFIG_FB_S3 is not set
# CONFIG_FB_SAVAGE is not set
# CONFIG_FB_SIS is not set
# CONFIG_FB_NEOMAGIC is not set
# CONFIG_FB_KYRO is not set
# CONFIG_FB_3DFX is not set
# CONFIG_FB_VOODOO1 is not set
# CONFIG_FB_VT8623 is not set
# CONFIG_FB_TRIDENT is not set
# CONFIG_FB_ARK is not set
# CONFIG_FB_PM3 is not set
# CONFIG_FB_CARMINE is not set
# CONFIG_FB_SM501 is not set
# CONFIG_FB_SMSCUFX is not set
# CONFIG_FB_IBM_GXT4500 is not set
# CONFIG_FB_XILINX is not set
# CONFIG_FB_VIRTUAL is not set
# CONFIG_FB_METRONOME is not set
# CONFIG_FB_MB862XX is not set
# CONFIG_FB_HYPERV is not set
# CONFIG_FB_SSD1307 is not set
# CONFIG_FB_SM712 is not set
CONFIG_FB_CORE=y
CONFIG_FB_NOTIFY=y
# CONFIG_FB_DEVICE is not set
CONFIG_FB_CFB_FILLRECT=y
CONFIG_FB_CFB_COPYAREA=y
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_FILLRECT=y
CONFIG_FB_SYS_COPYAREA=y
CONFIG_FB_SYS_IMAGEBLIT=y
# CONFIG_FB_FOREIGN_ENDIAN is not set
CONFIG_FB_SYSMEM_FOPS=y
CONFIG_FB_DEFERRED_IO=y
CONFIG_FB_DMAMEM_HELPERS=y
CONFIG_FB_DMAMEM_HELPERS_DEFERRED=y
CONFIG_FB_IOMEM_FOPS=y
CONFIG_FB_IOMEM_HELPERS=y
CONFIG_FB_SYSMEM_HELPERS=y
CONFIG_FB_SYSMEM_HELPERS_DEFERRED=y
CONFIG_FB_BACKLIGHT=y
CONFIG_FB_MODE_HELPERS=y
CONFIG_FB_TILEBLITTING=y
# end of Frame buffer Devices

#
# Backlight & LCD device support
#
CONFIG_LCD_CLASS_DEVICE=m
# CONFIG_LCD_L4F00242T03 is not set
# CONFIG_LCD_LMS283GF05 is not set
# CONFIG_LCD_LTV350QV is not set
# CONFIG_LCD_ILI922X is not set
# CONFIG_LCD_ILI9320 is not set
# CONFIG_LCD_TDO24M is not set
# CONFIG_LCD_VGG2432A4 is not set
CONFIG_LCD_PLATFORM=m
# CONFIG_LCD_AMS369FG06 is not set
# CONFIG_LCD_LMS501KF03 is not set
# CONFIG_LCD_HX8357 is not set
# CONFIG_LCD_OTM3225A is not set
CONFIG_BACKLIGHT_CLASS_DEVICE=y
CONFIG_BACKLIGHT_KTD253=m
# CONFIG_BACKLIGHT_KTD2801 is not set
CONFIG_BACKLIGHT_KTZ8866=m
CONFIG_BACKLIGHT_PWM=m
# CONFIG_BACKLIGHT_APPLE_DWI is not set
CONFIG_BACKLIGHT_QCOM_WLED=m
CONFIG_BACKLIGHT_RT4831=m
# CONFIG_BACKLIGHT_ADP8860 is not set
# CONFIG_BACKLIGHT_ADP8870 is not set
CONFIG_BACKLIGHT_LM3509=m
CONFIG_BACKLIGHT_LM3630A=m
# CONFIG_BACKLIGHT_LM3639 is not set
CONFIG_BACKLIGHT_LP855X=m
CONFIG_BACKLIGHT_MP3309C=m
CONFIG_BACKLIGHT_GPIO=m
# CONFIG_BACKLIGHT_LV5207LP is not set
# CONFIG_BACKLIGHT_BD6107 is not set
CONFIG_BACKLIGHT_ARCXCNN=m
CONFIG_BACKLIGHT_LED=m
# end of Backlight & LCD device support

CONFIG_VIDEOMODE_HELPERS=y
CONFIG_HDMI=y

#
# Console display driver support
#
CONFIG_DUMMY_CONSOLE=y
CONFIG_DUMMY_CONSOLE_COLUMNS=80
CONFIG_DUMMY_CONSOLE_ROWS=25
CONFIG_FRAMEBUFFER_CONSOLE=y
# CONFIG_FRAMEBUFFER_CONSOLE_LEGACY_ACCELERATION is not set
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
CONFIG_FRAMEBUFFER_CONSOLE_ROTATION=y
CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER=y
# end of Console display driver support

CONFIG_LOGO=y
# CONFIG_LOGO_LINUX_MONO is not set
# CONFIG_LOGO_LINUX_VGA16 is not set
CONFIG_LOGO_LINUX_CLUT224=y
CONFIG_TRACE_GPU_MEM=y
# end of Graphics support

CONFIG_DRM_ACCEL=y
CONFIG_DRM_ACCEL_QAIC=m
CONFIG_SOUND=m
CONFIG_SOUND_OSS_CORE=y
CONFIG_SOUND_OSS_CORE_PRECLAIM=y
CONFIG_SND=m
CONFIG_SND_TIMER=m
CONFIG_SND_PCM=m
CONFIG_SND_PCM_ELD=y
CONFIG_SND_PCM_IEC958=y
CONFIG_SND_DMAENGINE_PCM=m
CONFIG_SND_HWDEP=m
CONFIG_SND_SEQ_DEVICE=m
CONFIG_SND_RAWMIDI=m
CONFIG_SND_UMP=m
CONFIG_SND_UMP_LEGACY_RAWMIDI=y
CONFIG_SND_CORE_TEST=m
CONFIG_SND_COMPRESS_OFFLOAD=m
CONFIG_SND_COMPRESS_ACCEL=y
CONFIG_SND_JACK=y
CONFIG_SND_JACK_INPUT_DEV=y
CONFIG_SND_OSSEMUL=y
CONFIG_SND_MIXER_OSS=m
CONFIG_SND_PCM_OSS=m
CONFIG_SND_PCM_OSS_PLUGINS=y
CONFIG_SND_PCM_TIMER=y
CONFIG_SND_HRTIMER=m
CONFIG_SND_DYNAMIC_MINORS=y
CONFIG_SND_MAX_CARDS=32
# CONFIG_SND_SUPPORT_OLD_API is not set
CONFIG_SND_PROC_FS=y
CONFIG_SND_VERBOSE_PROCFS=y
CONFIG_SND_CTL_FAST_LOOKUP=y
# CONFIG_SND_DEBUG is not set
# CONFIG_SND_CTL_INPUT_VALIDATION is not set
CONFIG_SND_UTIMER=y
CONFIG_SND_VMASTER=y
CONFIG_SND_CTL_LED=m
CONFIG_SND_SEQUENCER=m
CONFIG_SND_SEQ_DUMMY=m
CONFIG_SND_SEQUENCER_OSS=m
CONFIG_SND_SEQ_HRTIMER_DEFAULT=y
CONFIG_SND_SEQ_MIDI_EVENT=m
CONFIG_SND_SEQ_MIDI=m
CONFIG_SND_SEQ_MIDI_EMUL=m
CONFIG_SND_SEQ_VIRMIDI=m
CONFIG_SND_SEQ_UMP=y
CONFIG_SND_SEQ_UMP_CLIENT=m
CONFIG_SND_MPU401_UART=m
CONFIG_SND_OPL3_LIB=m
CONFIG_SND_OPL3_LIB_SEQ=m
CONFIG_SND_VX_LIB=m
CONFIG_SND_AC97_CODEC=m
CONFIG_SND_DRIVERS=y
CONFIG_SND_DUMMY=m
CONFIG_SND_ALOOP=m
CONFIG_SND_PCMTEST=m
CONFIG_SND_VIRMIDI=m
CONFIG_SND_MTPAV=m
CONFIG_SND_SERIAL_U16550=m
CONFIG_SND_SERIAL_GENERIC=m
CONFIG_SND_MPU401=m
CONFIG_SND_AC97_POWER_SAVE=y
CONFIG_SND_AC97_POWER_SAVE_DEFAULT=0
CONFIG_SND_PCI=y
# CONFIG_SND_AD1889 is not set
CONFIG_SND_ALS300=m
# CONFIG_SND_ALI5451 is not set
# CONFIG_SND_ATIIXP is not set
# CONFIG_SND_ATIIXP_MODEM is not set
CONFIG_SND_AU8810=m
CONFIG_SND_AU8820=m
CONFIG_SND_AU8830=m
# CONFIG_SND_AW2 is not set
CONFIG_SND_AZT3328=m
CONFIG_SND_BT87X=m
# CONFIG_SND_BT87X_OVERCLOCK is not set
CONFIG_SND_CA0106=m
CONFIG_SND_CMIPCI=m
CONFIG_SND_OXYGEN_LIB=m
CONFIG_SND_OXYGEN=m
CONFIG_SND_CS4281=m
CONFIG_SND_CS46XX=m
CONFIG_SND_CS46XX_NEW_DSP=y
CONFIG_SND_CTXFI=m
CONFIG_SND_DARLA20=m
CONFIG_SND_GINA20=m
CONFIG_SND_LAYLA20=m
CONFIG_SND_DARLA24=m
CONFIG_SND_GINA24=m
CONFIG_SND_LAYLA24=m
CONFIG_SND_MONA=m
CONFIG_SND_MIA=m
CONFIG_SND_ECHO3G=m
CONFIG_SND_INDIGO=m
CONFIG_SND_INDIGOIO=m
CONFIG_SND_INDIGODJ=m
CONFIG_SND_INDIGOIOX=m
CONFIG_SND_INDIGODJX=m
CONFIG_SND_EMU10K1=m
CONFIG_SND_EMU10K1_SEQ=m
CONFIG_SND_EMU10K1X=m
CONFIG_SND_ENS1370=m
CONFIG_SND_ENS1371=m
CONFIG_SND_ES1938=m
CONFIG_SND_ES1968=m
CONFIG_SND_ES1968_INPUT=y
CONFIG_SND_ES1968_RADIO=y
CONFIG_SND_FM801=m
CONFIG_SND_FM801_TEA575X_BOOL=y
CONFIG_SND_HDSP=m
CONFIG_SND_HDSPM=m
CONFIG_SND_ICE1712=m
CONFIG_SND_ICE1724=m
# CONFIG_SND_INTEL8X0 is not set
# CONFIG_SND_INTEL8X0M is not set
CONFIG_SND_KORG1212=m
CONFIG_SND_LOLA=m
CONFIG_SND_LX6464ES=m
CONFIG_SND_MAESTRO3=m
CONFIG_SND_MAESTRO3_INPUT=y
CONFIG_SND_MIXART=m
CONFIG_SND_NM256=m
CONFIG_SND_PCXHR=m
CONFIG_SND_RIPTIDE=m
CONFIG_SND_RME32=m
CONFIG_SND_RME96=m
CONFIG_SND_RME9652=m
CONFIG_SND_SONICVIBES=m
CONFIG_SND_TRIDENT=m
# CONFIG_SND_VIA82XX is not set
# CONFIG_SND_VIA82XX_MODEM is not set
CONFIG_SND_VIRTUOSO=m
CONFIG_SND_VX222=m
CONFIG_SND_YMFPCI=m

#
# HD-Audio
#
CONFIG_SND_HDA=m
CONFIG_SND_HDA_HWDEP=y
CONFIG_SND_HDA_RECONFIG=y
CONFIG_SND_HDA_INPUT_BEEP=y
CONFIG_SND_HDA_INPUT_BEEP_MODE=0
CONFIG_SND_HDA_PATCH_LOADER=y
CONFIG_SND_HDA_POWER_SAVE_DEFAULT=1
# CONFIG_SND_HDA_CTL_DEV_ID is not set
CONFIG_SND_HDA_PREALLOC_SIZE=2048
CONFIG_SND_HDA_INTEL=m
CONFIG_SND_HDA_TEGRA=m
# CONFIG_SND_HDA_ACPI is not set
CONFIG_SND_HDA_GENERIC_LEDS=y
CONFIG_SND_HDA_CODEC_ANALOG=m
CONFIG_SND_HDA_CODEC_SIGMATEL=m
CONFIG_SND_HDA_CODEC_VIA=m
CONFIG_SND_HDA_CODEC_CONEXANT=m
CONFIG_SND_HDA_CODEC_SENARYTECH=m
CONFIG_SND_HDA_CODEC_CA0110=m
CONFIG_SND_HDA_CODEC_CA0132=m
CONFIG_SND_HDA_CODEC_CA0132_DSP=y
CONFIG_SND_HDA_CODEC_CMEDIA=m
# CONFIG_SND_HDA_CODEC_CM9825 is not set
CONFIG_SND_HDA_CODEC_SI3054=m
CONFIG_SND_HDA_GENERIC=m
CONFIG_SND_HDA_CODEC_REALTEK=m
CONFIG_SND_HDA_CODEC_REALTEK_LIB=m
CONFIG_SND_HDA_CODEC_ALC260=m
CONFIG_SND_HDA_CODEC_ALC262=m
CONFIG_SND_HDA_CODEC_ALC268=m
CONFIG_SND_HDA_CODEC_ALC269=m
CONFIG_SND_HDA_CODEC_ALC662=m
CONFIG_SND_HDA_CODEC_ALC680=m
CONFIG_SND_HDA_CODEC_ALC861=m
CONFIG_SND_HDA_CODEC_ALC861VD=m
CONFIG_SND_HDA_CODEC_ALC880=m
CONFIG_SND_HDA_CODEC_ALC882=m
CONFIG_SND_HDA_CODEC_CIRRUS=m
CONFIG_SND_HDA_CODEC_CS420X=m
CONFIG_SND_HDA_CODEC_CS421X=m
CONFIG_SND_HDA_CODEC_CS8409=m
CONFIG_SND_HDA_CODEC_HDMI=m
CONFIG_SND_HDA_CODEC_HDMI_GENERIC=m
CONFIG_SND_HDA_CODEC_HDMI_SIMPLE=m
CONFIG_SND_HDA_CODEC_HDMI_INTEL=m
CONFIG_SND_HDA_INTEL_HDMI_SILENT_STREAM=y
CONFIG_SND_HDA_CODEC_HDMI_ATI=m
CONFIG_SND_HDA_CODEC_HDMI_NVIDIA=m
CONFIG_SND_HDA_CODEC_HDMI_NVIDIA_MCP=m
CONFIG_SND_HDA_CODEC_HDMI_TEGRA=m
CONFIG_SND_HDA_CIRRUS_SCODEC=m
CONFIG_SND_HDA_CIRRUS_SCODEC_KUNIT_TEST=m
CONFIG_SND_HDA_SCODEC_CS35L41=m
CONFIG_SND_HDA_SCODEC_COMPONENT=m
CONFIG_SND_HDA_SCODEC_CS35L41_I2C=m
CONFIG_SND_HDA_SCODEC_CS35L41_SPI=m
CONFIG_SND_HDA_SCODEC_CS35L56=m
CONFIG_SND_HDA_SCODEC_CS35L56_I2C=m
CONFIG_SND_HDA_SCODEC_CS35L56_SPI=m
CONFIG_SND_HDA_SCODEC_TAS2781=m
CONFIG_SND_HDA_SCODEC_TAS2781_I2C=m
CONFIG_SND_HDA_SCODEC_TAS2781_SPI=m
CONFIG_SND_HDA_CORE=m
CONFIG_SND_HDA_DSP_LOADER=y
CONFIG_SND_HDA_ALIGNED_MMIO=y
CONFIG_SND_HDA_COMPONENT=y
CONFIG_SND_HDA_I915=y
CONFIG_SND_HDA_EXT_CORE=m
CONFIG_SND_INTEL_NHLT=y
CONFIG_SND_INTEL_DSP_CONFIG=m
CONFIG_SND_INTEL_SOUNDWIRE_ACPI=m
# end of HD-Audio

# CONFIG_SND_SPI is not set
CONFIG_SND_USB=y
CONFIG_SND_USB_AUDIO=m
CONFIG_SND_USB_AUDIO_MIDI_V2=y
CONFIG_SND_USB_AUDIO_USE_MEDIA_CONTROLLER=y
CONFIG_SND_USB_UA101=m
CONFIG_SND_USB_CAIAQ=m
CONFIG_SND_USB_CAIAQ_INPUT=y
CONFIG_SND_USB_6FIRE=m
CONFIG_SND_USB_HIFACE=m
CONFIG_SND_BCD2000=m
CONFIG_SND_USB_LINE6=m
CONFIG_SND_USB_POD=m
CONFIG_SND_USB_PODHD=m
CONFIG_SND_USB_TONEPORT=m
CONFIG_SND_USB_VARIAX=m
CONFIG_SND_SOC=m
CONFIG_SND_SOC_AC97_BUS=y
CONFIG_SND_SOC_GENERIC_DMAENGINE_PCM=y
CONFIG_SND_SOC_COMPRESS=y
CONFIG_SND_SOC_TOPOLOGY=y
# CONFIG_SND_SOC_TOPOLOGY_BUILD is not set
CONFIG_SND_SOC_TOPOLOGY_KUNIT_TEST=m
CONFIG_SND_SOC_CARD_KUNIT_TEST=m
CONFIG_SND_SOC_UTILS_KUNIT_TEST=m
CONFIG_SND_SOC_OPS_KUNIT_TEST=m
# CONFIG_SND_SOC_USB is not set

#
# Analog Devices
#
CONFIG_SND_SOC_ADI_AXI_I2S=m
CONFIG_SND_SOC_ADI_AXI_SPDIF=m
# end of Analog Devices

#
# AMD
#
# CONFIG_SND_SOC_AMD_ACP is not set
# CONFIG_SND_AMD_ACP_CONFIG is not set
# end of AMD

#
# Apple
#
CONFIG_SND_SOC_APPLE_MCA=m
# end of Apple

#
# Atmel
#
# CONFIG_SND_SOC_MIKROE_PROTO is not set
# end of Atmel

#
# Au1x
#
# end of Au1x

#
# Broadcom
#
CONFIG_SND_BCM2835_SOC_I2S=m
# CONFIG_SND_BCM63XX_I2S_WHISTLER is not set
# end of Broadcom

#
# Cirrus Logic
#
# end of Cirrus Logic

#
# DesignWare
#
CONFIG_SND_DESIGNWARE_I2S=m
CONFIG_SND_DESIGNWARE_PCM=y
# end of DesignWare

#
# Freescale
#

#
# Common SoC Audio options for Freescale CPUs:
#
CONFIG_SND_SOC_FSL_ASRC=m
CONFIG_SND_SOC_FSL_SAI=m
CONFIG_SND_SOC_FSL_MQS=m
CONFIG_SND_SOC_FSL_AUDMIX=m
CONFIG_SND_SOC_FSL_SSI=m
CONFIG_SND_SOC_FSL_SPDIF=m
CONFIG_SND_SOC_FSL_ESAI=m
CONFIG_SND_SOC_FSL_MICFIL=m
CONFIG_SND_SOC_FSL_EASRC=m
CONFIG_SND_SOC_FSL_XCVR=m
CONFIG_SND_SOC_FSL_AUD2HTX=m
CONFIG_SND_SOC_FSL_UTILS=m
CONFIG_SND_SOC_FSL_RPMSG=m
CONFIG_SND_SOC_IMX_PCM_DMA=m
CONFIG_SND_SOC_IMX_AUDIO_RPMSG=m
CONFIG_SND_SOC_IMX_PCM_RPMSG=m
CONFIG_SND_SOC_IMX_AUDMUX=m
CONFIG_SND_IMX_SOC=m

#
# SoC Audio support for Freescale i.MX boards:
#
CONFIG_SND_SOC_IMX_ES8328=m
CONFIG_SND_SOC_IMX_SGTL5000=m
CONFIG_SND_SOC_FSL_ASOC_CARD=m
CONFIG_SND_SOC_IMX_AUDMIX=m
CONFIG_SND_SOC_IMX_HDMI=m
CONFIG_SND_SOC_IMX_RPMSG=m
CONFIG_SND_SOC_IMX_CARD=m
# end of Freescale

#
# Google
#
CONFIG_SND_SOC_CHV3_I2S=m
# end of Google

#
# Hisilicon
#
CONFIG_SND_I2S_HI6210_I2S=m
# end of Hisilicon

#
# JZ4740
#
# end of JZ4740

#
# Kirkwood
#
# CONFIG_SND_KIRKWOOD_SOC is not set
# end of Kirkwood

#
# Loongson
#
# end of Loongson

#
# Intel
#
# end of Intel

#
# Mediatek
#
# CONFIG_SND_SOC_MTK_BTCVSD is not set
# end of Mediatek

#
# Amlogic
#
CONFIG_SND_MESON_AIU=m
CONFIG_SND_MESON_AXG_FIFO=m
CONFIG_SND_MESON_AXG_FRDDR=m
CONFIG_SND_MESON_AXG_TODDR=m
CONFIG_SND_MESON_AXG_TDM_FORMATTER=m
CONFIG_SND_MESON_AXG_TDM_INTERFACE=m
CONFIG_SND_MESON_AXG_TDMIN=m
CONFIG_SND_MESON_AXG_TDMOUT=m
CONFIG_SND_MESON_AXG_SOUND_CARD=m
CONFIG_SND_MESON_AXG_SPDIFOUT=m
CONFIG_SND_MESON_AXG_SPDIFIN=m
CONFIG_SND_MESON_AXG_PDM=m
CONFIG_SND_MESON_CARD_UTILS=m
CONFIG_SND_MESON_CODEC_GLUE=m
CONFIG_SND_MESON_GX_SOUND_CARD=m
CONFIG_SND_MESON_G12A_TOACODEC=m
CONFIG_SND_MESON_G12A_TOHDMITX=m
CONFIG_SND_SOC_MESON_T9015=m
# end of Amlogic

#
# PXA
#
# end of PXA

CONFIG_SND_SOC_QCOM=m
CONFIG_SND_SOC_LPASS_CPU=m
CONFIG_SND_SOC_LPASS_HDMI=m
CONFIG_SND_SOC_LPASS_PLATFORM=m
CONFIG_SND_SOC_LPASS_CDC_DMA=m
CONFIG_SND_SOC_LPASS_APQ8016=m
CONFIG_SND_SOC_LPASS_SC7180=m
CONFIG_SND_SOC_LPASS_SC7280=m
# CONFIG_SND_SOC_STORM is not set
CONFIG_SND_SOC_APQ8016_SBC=m
CONFIG_SND_SOC_QCOM_COMMON=m
CONFIG_SND_SOC_QCOM_SDW=m
CONFIG_SND_SOC_QDSP6_COMMON=m
CONFIG_SND_SOC_QDSP6_CORE=m
CONFIG_SND_SOC_QDSP6_AFE=m
CONFIG_SND_SOC_QDSP6_AFE_DAI=m
CONFIG_SND_SOC_QDSP6_AFE_CLOCKS=m
CONFIG_SND_SOC_QDSP6_ADM=m
CONFIG_SND_SOC_QDSP6_ROUTING=m
CONFIG_SND_SOC_QDSP6_ASM=m
CONFIG_SND_SOC_QDSP6_ASM_DAI=m
CONFIG_SND_SOC_QDSP6_APM_DAI=m
CONFIG_SND_SOC_QDSP6_APM_LPASS_DAI=m
CONFIG_SND_SOC_QDSP6_APM=m
CONFIG_SND_SOC_QDSP6_PRM_LPASS_CLOCKS=m
CONFIG_SND_SOC_QDSP6_PRM=m
CONFIG_SND_SOC_QDSP6=m
CONFIG_SND_SOC_MSM8996=m
CONFIG_SND_SOC_SDM845=m
# CONFIG_SND_SOC_SM8250 is not set
CONFIG_SND_SOC_SC8280XP=m
CONFIG_SND_SOC_SC7180=m
CONFIG_SND_SOC_SC7280=m
CONFIG_SND_SOC_X1E80100=m

#
# Renesas
#
# CONFIG_SND_SOC_SH4_FSI is not set
# CONFIG_SND_SOC_RCAR is not set
# CONFIG_SND_SOC_MSIOF is not set
CONFIG_SND_SOC_RZ=m
# end of Renesas

#
# Rockchip
#
CONFIG_SND_SOC_ROCKCHIP_I2S=m
CONFIG_SND_SOC_ROCKCHIP_I2S_TDM=m
CONFIG_SND_SOC_ROCKCHIP_PDM=m
# CONFIG_SND_SOC_ROCKCHIP_SAI is not set
CONFIG_SND_SOC_ROCKCHIP_SPDIF=m
CONFIG_SND_SOC_ROCKCHIP_MAX98090=m
CONFIG_SND_SOC_ROCKCHIP_RT5645=m
CONFIG_SND_SOC_RK3288_HDMI_ANALOG=m
CONFIG_SND_SOC_RK3399_GRU_SOUND=m
# end of Rockchip

#
# SoundWire (SDCA)
#
CONFIG_SND_SOC_SDCA_OPTIONAL=m
# end of SoundWire (SDCA)

#
# ST SPEAr
#
# end of ST SPEAr

#
# Spreadtrum
#
# end of Spreadtrum

#
# STMicroelectronics STM32
#
# end of STMicroelectronics STM32

#
# Allwinner
#
CONFIG_SND_SUN4I_CODEC=m
CONFIG_SND_SUN8I_CODEC=m
CONFIG_SND_SUN8I_CODEC_ANALOG=m
CONFIG_SND_SUN50I_CODEC_ANALOG=m
CONFIG_SND_SUN4I_I2S=m
CONFIG_SND_SUN4I_SPDIF=m
CONFIG_SND_SUN50I_DMIC=m
CONFIG_SND_SUN8I_ADDA_PR_REGMAP=m
# end of Allwinner

#
# Tegra
#
CONFIG_SND_SOC_TEGRA=m
CONFIG_SND_SOC_TEGRA20_AC97=m
CONFIG_SND_SOC_TEGRA20_DAS=m
CONFIG_SND_SOC_TEGRA20_I2S=m
CONFIG_SND_SOC_TEGRA20_SPDIF=m
CONFIG_SND_SOC_TEGRA30_AHUB=m
CONFIG_SND_SOC_TEGRA30_I2S=m
CONFIG_SND_SOC_TEGRA210_AHUB=m
CONFIG_SND_SOC_TEGRA210_DMIC=m
CONFIG_SND_SOC_TEGRA210_I2S=m
CONFIG_SND_SOC_TEGRA210_OPE=m
CONFIG_SND_SOC_TEGRA186_ASRC=m
CONFIG_SND_SOC_TEGRA186_DSPK=m
CONFIG_SND_SOC_TEGRA210_ADMAIF=m
CONFIG_SND_SOC_TEGRA210_MVC=m
CONFIG_SND_SOC_TEGRA210_SFC=m
CONFIG_SND_SOC_TEGRA210_AMX=m
CONFIG_SND_SOC_TEGRA210_ADX=m
CONFIG_SND_SOC_TEGRA210_MIXER=m
CONFIG_SND_SOC_TEGRA_AUDIO_GRAPH_CARD=m
CONFIG_SND_SOC_TEGRA_MACHINE_DRV=m
CONFIG_SND_SOC_TEGRA_RT5631=m
CONFIG_SND_SOC_TEGRA_RT5640=m
# CONFIG_SND_SOC_TEGRA_WM8753 is not set
# CONFIG_SND_SOC_TEGRA_WM8903 is not set
# CONFIG_SND_SOC_TEGRA_WM9712 is not set
# CONFIG_SND_SOC_TEGRA_TRIMSLICE is not set
# CONFIG_SND_SOC_TEGRA_ALC5632 is not set
CONFIG_SND_SOC_TEGRA_MAX98090=m
CONFIG_SND_SOC_TEGRA_MAX98088=m
CONFIG_SND_SOC_TEGRA_RT5677=m
CONFIG_SND_SOC_TEGRA_SGTL5000=m
# end of Tegra

#
# Texas Instruments
#
CONFIG_SND_SOC_TI_EDMA_PCM=m
CONFIG_SND_SOC_TI_SDMA_PCM=m
CONFIG_SND_SOC_TI_UDMA_PCM=m

#
# Texas Instruments DAI support for:
#
CONFIG_SND_SOC_DAVINCI_MCASP=m

#
# Audio support for boards with Texas Instruments SoCs
#
CONFIG_SND_SOC_J721E_EVM=m
# end of Texas Instruments

#
# Xilinx
#
CONFIG_SND_SOC_XILINX_I2S=m
CONFIG_SND_SOC_XILINX_AUDIO_FORMATTER=m
CONFIG_SND_SOC_XILINX_SPDIF=m
# end of Xilinx

#
# Xtensa
#
# CONFIG_SND_SOC_XTFPGA_I2S is not set
# end of Xtensa

CONFIG_SND_SOC_SOF_TOPLEVEL=y
CONFIG_SND_SOC_SOF_PCI=m
CONFIG_SND_SOC_SOF_ACPI=m
CONFIG_SND_SOC_SOF_OF=m
CONFIG_SND_SOC_SOF_OF_DEV=m
CONFIG_SND_SOC_SOF_COMPRESS=y
# CONFIG_SND_SOC_SOF_DEVELOPER_SUPPORT is not set
CONFIG_SND_SOC_SOF=m
CONFIG_SND_SOC_SOF_IPC3=y
CONFIG_SND_SOC_SOF_IMX_TOPLEVEL=y
CONFIG_SND_SOC_SOF_IMX_COMMON=m
CONFIG_SND_SOC_SOF_IMX8=m
CONFIG_SND_SOC_SOF_IMX9=m
CONFIG_SND_SOC_SOF_MTK_TOPLEVEL=y
CONFIG_SND_SOC_SOF_XTENSA=m
CONFIG_SND_SOC_I2C_AND_SPI=m

#
# CODEC drivers
#
CONFIG_SND_SOC_WM_HUBS=m
CONFIG_SND_SOC_WM_ADSP=m
CONFIG_SND_SOC_AC97_CODEC=m
CONFIG_SND_SOC_ADAU_UTILS=m
CONFIG_SND_SOC_ADAU1372=m
CONFIG_SND_SOC_ADAU1372_I2C=m
CONFIG_SND_SOC_ADAU1372_SPI=m
CONFIG_SND_SOC_ADAU1373=m
# CONFIG_SND_SOC_ADAU1701 is not set
CONFIG_SND_SOC_ADAU17X1=m
CONFIG_SND_SOC_ADAU1761=m
CONFIG_SND_SOC_ADAU1761_I2C=m
CONFIG_SND_SOC_ADAU1761_SPI=m
CONFIG_SND_SOC_ADAU7002=m
CONFIG_SND_SOC_ADAU7118=m
CONFIG_SND_SOC_ADAU7118_HW=m
CONFIG_SND_SOC_ADAU7118_I2C=m
# CONFIG_SND_SOC_AK4104 is not set
# CONFIG_SND_SOC_AK4118 is not set
# CONFIG_SND_SOC_AK4375 is not set
CONFIG_SND_SOC_AK4458=m
# CONFIG_SND_SOC_AK4554 is not set
# CONFIG_SND_SOC_AK4613 is not set
CONFIG_SND_SOC_AK4619=m
# CONFIG_SND_SOC_AK4642 is not set
# CONFIG_SND_SOC_AK5386 is not set
CONFIG_SND_SOC_AK5558=m
# CONFIG_SND_SOC_ALC5623 is not set
CONFIG_SND_SOC_AUDIO_IIO_AUX=m
CONFIG_SND_SOC_AW8738=m
CONFIG_SND_SOC_AW88395_LIB=m
CONFIG_SND_SOC_AW88395=m
CONFIG_SND_SOC_AW88166=m
CONFIG_SND_SOC_AW88261=m
CONFIG_SND_SOC_AW88081=m
CONFIG_SND_SOC_AW87390=m
CONFIG_SND_SOC_AW88399=m
CONFIG_SND_SOC_BD28623=m
CONFIG_SND_SOC_BT_SCO=m
CONFIG_SND_SOC_CHV3_CODEC=m
CONFIG_SND_SOC_CROS_EC_CODEC=m
CONFIG_SND_SOC_CS_AMP_LIB=m
CONFIG_SND_SOC_CS_AMP_LIB_TEST=m
# CONFIG_SND_SOC_CS35L32 is not set
# CONFIG_SND_SOC_CS35L33 is not set
CONFIG_SND_SOC_CS35L34=m
CONFIG_SND_SOC_CS35L35=m
CONFIG_SND_SOC_CS35L36=m
CONFIG_SND_SOC_CS35L41_LIB=m
# CONFIG_SND_SOC_CS35L41_SPI is not set
# CONFIG_SND_SOC_CS35L41_I2C is not set
CONFIG_SND_SOC_CS35L45=m
CONFIG_SND_SOC_CS35L45_SPI=m
CONFIG_SND_SOC_CS35L45_I2C=m
CONFIG_SND_SOC_CS35L56=m
CONFIG_SND_SOC_CS35L56_SHARED=m
CONFIG_SND_SOC_CS35L56_I2C=m
CONFIG_SND_SOC_CS35L56_SPI=m
CONFIG_SND_SOC_CS35L56_SDW=m
CONFIG_SND_SOC_CS40L50=m
CONFIG_SND_SOC_CS42L42_CORE=m
CONFIG_SND_SOC_CS42L42=m
CONFIG_SND_SOC_CS42L42_SDW=m
CONFIG_SND_SOC_CS42L43=m
CONFIG_SND_SOC_CS42L43_SDW=m
# CONFIG_SND_SOC_CS42L51_I2C is not set
# CONFIG_SND_SOC_CS42L52 is not set
# CONFIG_SND_SOC_CS42L56 is not set
# CONFIG_SND_SOC_CS42L73 is not set
CONFIG_SND_SOC_CS42L83=m
CONFIG_SND_SOC_CS42L84=m
CONFIG_SND_SOC_CS4234=m
CONFIG_SND_SOC_CS4265=m
# CONFIG_SND_SOC_CS4270 is not set
CONFIG_SND_SOC_CS4271=m
CONFIG_SND_SOC_CS4271_I2C=m
# CONFIG_SND_SOC_CS4271_SPI is not set
CONFIG_SND_SOC_CS42XX8=m
CONFIG_SND_SOC_CS42XX8_I2C=m
CONFIG_SND_SOC_CS43130=m
# CONFIG_SND_SOC_CS4341 is not set
# CONFIG_SND_SOC_CS4349 is not set
# CONFIG_SND_SOC_CS48L32 is not set
# CONFIG_SND_SOC_CS53L30 is not set
CONFIG_SND_SOC_CS530X=m
CONFIG_SND_SOC_CS530X_I2C=m
CONFIG_SND_SOC_CX2072X=m
CONFIG_SND_SOC_DA7213=m
CONFIG_SND_SOC_DA7219=m
CONFIG_SND_SOC_DMIC=m
CONFIG_SND_SOC_HDMI_CODEC=m
CONFIG_SND_SOC_ES7134=m
# CONFIG_SND_SOC_ES7241 is not set
CONFIG_SND_SOC_ES8311=m
CONFIG_SND_SOC_ES8316=m
CONFIG_SND_SOC_ES8323=m
CONFIG_SND_SOC_ES8326=m
CONFIG_SND_SOC_ES8328=m
CONFIG_SND_SOC_ES8328_I2C=m
CONFIG_SND_SOC_ES8328_SPI=m
# CONFIG_SND_SOC_ES8375 is not set
# CONFIG_SND_SOC_ES8389 is not set
# CONFIG_SND_SOC_GTM601 is not set
CONFIG_SND_SOC_HDA=m
CONFIG_SND_SOC_ICS43432=m
CONFIG_SND_SOC_IDT821034=m
# CONFIG_SND_SOC_INNO_RK3036 is not set
CONFIG_SND_SOC_MAX98088=m
CONFIG_SND_SOC_MAX98090=m
CONFIG_SND_SOC_MAX98357A=m
# CONFIG_SND_SOC_MAX98504 is not set
CONFIG_SND_SOC_MAX9867=m
CONFIG_SND_SOC_MAX98927=m
CONFIG_SND_SOC_MAX98520=m
CONFIG_SND_SOC_MAX98363=m
CONFIG_SND_SOC_MAX98373=m
CONFIG_SND_SOC_MAX98373_I2C=m
CONFIG_SND_SOC_MAX98373_SDW=m
# CONFIG_SND_SOC_MAX98388 is not set
CONFIG_SND_SOC_MAX98390=m
CONFIG_SND_SOC_MAX98396=m
# CONFIG_SND_SOC_MAX9860 is not set
CONFIG_SND_SOC_MSM8916_WCD_ANALOG=m
CONFIG_SND_SOC_MSM8916_WCD_DIGITAL=m
# CONFIG_SND_SOC_PCM1681 is not set
CONFIG_SND_SOC_PCM1789=m
CONFIG_SND_SOC_PCM1789_I2C=m
# CONFIG_SND_SOC_PCM179X_I2C is not set
# CONFIG_SND_SOC_PCM179X_SPI is not set
CONFIG_SND_SOC_PCM186X=m
CONFIG_SND_SOC_PCM186X_I2C=m
CONFIG_SND_SOC_PCM186X_SPI=m
CONFIG_SND_SOC_PCM3060=m
CONFIG_SND_SOC_PCM3060_I2C=m
CONFIG_SND_SOC_PCM3060_SPI=m
CONFIG_SND_SOC_PCM3168A=m
CONFIG_SND_SOC_PCM3168A_I2C=m
# CONFIG_SND_SOC_PCM3168A_SPI is not set
CONFIG_SND_SOC_PCM5102A=m
CONFIG_SND_SOC_PCM512x=m
CONFIG_SND_SOC_PCM512x_I2C=m
CONFIG_SND_SOC_PCM512x_SPI=m
CONFIG_SND_SOC_PCM6240=m
# CONFIG_SND_SOC_PEB2466 is not set
CONFIG_SND_SOC_RK3308=m
CONFIG_SND_SOC_RK3328=m
CONFIG_SND_SOC_RK817=m
CONFIG_SND_SOC_RL6231=m
CONFIG_SND_SOC_RT1017_SDCA_SDW=m
# CONFIG_SND_SOC_RT1308_SDW is not set
# CONFIG_SND_SOC_RT1316_SDW is not set
CONFIG_SND_SOC_RT1318_SDW=m
CONFIG_SND_SOC_RT1320_SDW=m
CONFIG_SND_SOC_RT5514=m
CONFIG_SND_SOC_RT5514_SPI=m
CONFIG_SND_SOC_RT5616=m
CONFIG_SND_SOC_RT5631=m
CONFIG_SND_SOC_RT5640=m
CONFIG_SND_SOC_RT5645=m
CONFIG_SND_SOC_RT5659=m
CONFIG_SND_SOC_RT5663=m
CONFIG_SND_SOC_RT5677=m
CONFIG_SND_SOC_RT5677_SPI=m
CONFIG_SND_SOC_RT5682=m
CONFIG_SND_SOC_RT5682_I2C=m
CONFIG_SND_SOC_RT5682_SDW=m
CONFIG_SND_SOC_RT5682S=m
CONFIG_SND_SOC_RT700=m
CONFIG_SND_SOC_RT700_SDW=m
CONFIG_SND_SOC_RT711=m
CONFIG_SND_SOC_RT711_SDW=m
CONFIG_SND_SOC_RT711_SDCA_SDW=m
# CONFIG_SND_SOC_RT712_SDCA_SDW is not set
CONFIG_SND_SOC_RT712_SDCA_DMIC_SDW=m
# CONFIG_SND_SOC_RT721_SDCA_SDW is not set
CONFIG_SND_SOC_RT722_SDCA_SDW=m
CONFIG_SND_SOC_RT715=m
CONFIG_SND_SOC_RT715_SDW=m
CONFIG_SND_SOC_RT715_SDCA_SDW=m
# CONFIG_SND_SOC_RT9120 is not set
# CONFIG_SND_SOC_RT9123 is not set
# CONFIG_SND_SOC_RT9123P is not set
# CONFIG_SND_SOC_RTQ9124 is not set
CONFIG_SND_SOC_RTQ9128=m
# CONFIG_SND_SOC_SDW_MOCKUP is not set
CONFIG_SND_SOC_SGTL5000=m
CONFIG_SND_SOC_SIGMADSP=m
CONFIG_SND_SOC_SIGMADSP_REGMAP=m
CONFIG_SND_SOC_SIMPLE_AMPLIFIER=m
CONFIG_SND_SOC_SIMPLE_MUX=m
CONFIG_SND_SOC_SMA1303=m
CONFIG_SND_SOC_SMA1307=m
CONFIG_SND_SOC_SPDIF=m
# CONFIG_SND_SOC_SRC4XXX_I2C is not set
# CONFIG_SND_SOC_SSM2305 is not set
# CONFIG_SND_SOC_SSM2518 is not set
# CONFIG_SND_SOC_SSM2602_SPI is not set
# CONFIG_SND_SOC_SSM2602_I2C is not set
CONFIG_SND_SOC_SSM3515=m
# CONFIG_SND_SOC_SSM4567 is not set
# CONFIG_SND_SOC_STA32X is not set
# CONFIG_SND_SOC_STA350 is not set
# CONFIG_SND_SOC_STI_SAS is not set
# CONFIG_SND_SOC_TAS2552 is not set
CONFIG_SND_SOC_TAS2562=m
CONFIG_SND_SOC_TAS2764=m
CONFIG_SND_SOC_TAS2770=m
CONFIG_SND_SOC_TAS2780=m
CONFIG_SND_SOC_TAS2781_COMLIB=m
CONFIG_SND_SOC_TAS2781_COMLIB_I2C=m
CONFIG_SND_SOC_TAS2781_FMWLIB=m
CONFIG_SND_SOC_TAS2781_I2C=m
# CONFIG_SND_SOC_TAS5086 is not set
# CONFIG_SND_SOC_TAS571X is not set
# CONFIG_SND_SOC_TAS5720 is not set
CONFIG_SND_SOC_TAS5805M=m
CONFIG_SND_SOC_TAS6424=m
CONFIG_SND_SOC_TDA7419=m
# CONFIG_SND_SOC_TFA9879 is not set
CONFIG_SND_SOC_TFA989X=m
CONFIG_SND_SOC_TLV320ADC3XXX=m
CONFIG_SND_SOC_TLV320AIC23=m
CONFIG_SND_SOC_TLV320AIC23_I2C=m
CONFIG_SND_SOC_TLV320AIC23_SPI=m
CONFIG_SND_SOC_TLV320AIC31XX=m
CONFIG_SND_SOC_TLV320AIC32X4=m
CONFIG_SND_SOC_TLV320AIC32X4_I2C=m
CONFIG_SND_SOC_TLV320AIC32X4_SPI=m
CONFIG_SND_SOC_TLV320AIC3X=m
CONFIG_SND_SOC_TLV320AIC3X_I2C=m
CONFIG_SND_SOC_TLV320AIC3X_SPI=m
CONFIG_SND_SOC_TLV320ADCX140=m
CONFIG_SND_SOC_TS3A227E=m
CONFIG_SND_SOC_TSCS42XX=m
# CONFIG_SND_SOC_TSCS454 is not set
# CONFIG_SND_SOC_UDA1334 is not set
CONFIG_SND_SOC_UDA1342=m
CONFIG_SND_SOC_WCD_CLASSH=m
CONFIG_SND_SOC_WCD9335=m
CONFIG_SND_SOC_WCD_MBHC=m
CONFIG_SND_SOC_WCD934X=m
CONFIG_SND_SOC_WCD937X=m
CONFIG_SND_SOC_WCD937X_SDW=m
CONFIG_SND_SOC_WCD938X=m
CONFIG_SND_SOC_WCD938X_SDW=m
CONFIG_SND_SOC_WCD939X=m
CONFIG_SND_SOC_WCD939X_SDW=m
# CONFIG_SND_SOC_WM8510 is not set
# CONFIG_SND_SOC_WM8523 is not set
CONFIG_SND_SOC_WM8524=m
# CONFIG_SND_SOC_WM8580 is not set
# CONFIG_SND_SOC_WM8711 is not set
# CONFIG_SND_SOC_WM8728 is not set
CONFIG_SND_SOC_WM8731=m
CONFIG_SND_SOC_WM8731_I2C=m
CONFIG_SND_SOC_WM8731_SPI=m
# CONFIG_SND_SOC_WM8737 is not set
CONFIG_SND_SOC_WM8741=m
# CONFIG_SND_SOC_WM8750 is not set
CONFIG_SND_SOC_WM8753=m
# CONFIG_SND_SOC_WM8770 is not set
# CONFIG_SND_SOC_WM8776 is not set
# CONFIG_SND_SOC_WM8782 is not set
CONFIG_SND_SOC_WM8804=m
CONFIG_SND_SOC_WM8804_I2C=m
CONFIG_SND_SOC_WM8804_SPI=m
CONFIG_SND_SOC_WM8903=m
# CONFIG_SND_SOC_WM8904 is not set
CONFIG_SND_SOC_WM8940=m
CONFIG_SND_SOC_WM8960=m
CONFIG_SND_SOC_WM8961=m
CONFIG_SND_SOC_WM8962=m
# CONFIG_SND_SOC_WM8974 is not set
# CONFIG_SND_SOC_WM8978 is not set
# CONFIG_SND_SOC_WM8985 is not set
CONFIG_SND_SOC_WM8994=m
# CONFIG_SND_SOC_WSA881X is not set
CONFIG_SND_SOC_WSA883X=m
CONFIG_SND_SOC_WSA884X=m
CONFIG_SND_SOC_ZL38060=m
CONFIG_SND_SOC_MAX9759=m
# CONFIG_SND_SOC_MT6351 is not set
CONFIG_SND_SOC_MT6357=m
# CONFIG_SND_SOC_MT6358 is not set
# CONFIG_SND_SOC_MT6660 is not set
# CONFIG_SND_SOC_NAU8315 is not set
# CONFIG_SND_SOC_NAU8540 is not set
# CONFIG_SND_SOC_NAU8810 is not set
# CONFIG_SND_SOC_NAU8821 is not set
# CONFIG_SND_SOC_NAU8822 is not set
CONFIG_SND_SOC_NAU8824=m
CONFIG_SND_SOC_NTPFW=m
CONFIG_SND_SOC_NTP8918=m
CONFIG_SND_SOC_NTP8835=m
CONFIG_SND_SOC_TPA6130A2=m
CONFIG_SND_SOC_LPASS_MACRO_COMMON=m
CONFIG_SND_SOC_LPASS_WSA_MACRO=m
CONFIG_SND_SOC_LPASS_VA_MACRO=m
CONFIG_SND_SOC_LPASS_RX_MACRO=m
CONFIG_SND_SOC_LPASS_TX_MACRO=m
# end of CODEC drivers

#
# Generic drivers
#
CONFIG_SND_SIMPLE_CARD_UTILS=m
CONFIG_SND_SIMPLE_CARD=m
CONFIG_SND_AUDIO_GRAPH_CARD=m
CONFIG_SND_AUDIO_GRAPH_CARD2=m
CONFIG_SND_AUDIO_GRAPH_CARD2_CUSTOM_SAMPLE=m
# CONFIG_SND_TEST_COMPONENT is not set
# end of Generic drivers

CONFIG_SND_SYNTH_EMUX=m
CONFIG_SND_VIRTIO=m
CONFIG_AC97_BUS=m
CONFIG_HID_SUPPORT=y
CONFIG_HID=y
CONFIG_HID_BATTERY_STRENGTH=y
CONFIG_HIDRAW=y
CONFIG_UHID=m
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
CONFIG_HID_A4TECH=m
CONFIG_HID_ACCUTOUCH=m
CONFIG_HID_ACRUX=m
CONFIG_HID_ACRUX_FF=y
CONFIG_HID_APPLE=m
CONFIG_HID_APPLEIR=m
# CONFIG_HID_ASUS is not set
CONFIG_HID_AUREAL=m
CONFIG_HID_BELKIN=m
CONFIG_HID_BETOP_FF=m
CONFIG_HID_BIGBEN_FF=m
CONFIG_HID_CHERRY=m
CONFIG_HID_CHICONY=m
CONFIG_HID_CORSAIR=m
CONFIG_HID_COUGAR=m
CONFIG_HID_MACALLY=m
CONFIG_HID_PRODIKEYS=m
CONFIG_HID_CMEDIA=m
CONFIG_HID_CP2112=m
CONFIG_HID_CREATIVE_SB0540=m
CONFIG_HID_CYPRESS=m
CONFIG_HID_DRAGONRISE=m
CONFIG_DRAGONRISE_FF=y
CONFIG_HID_EMS_FF=m
CONFIG_HID_ELAN=m
CONFIG_HID_ELECOM=m
CONFIG_HID_ELO=m
CONFIG_HID_EVISION=m
CONFIG_HID_EZKEY=m
CONFIG_HID_FT260=m
CONFIG_HID_GEMBIRD=m
CONFIG_HID_GFRM=m
CONFIG_HID_GLORIOUS=m
CONFIG_HID_HOLTEK=m
CONFIG_HOLTEK_FF=y
CONFIG_HID_VIVALDI_COMMON=m
CONFIG_HID_GOODIX_SPI=m
# CONFIG_HID_GOOGLE_HAMMER is not set
CONFIG_HID_GOOGLE_STADIA_FF=m
CONFIG_HID_VIVALDI=m
CONFIG_HID_GT683R=m
CONFIG_HID_KEYTOUCH=m
CONFIG_HID_KYE=m
CONFIG_HID_KYSONA=m
CONFIG_HID_UCLOGIC=m
CONFIG_HID_WALTOP=m
CONFIG_HID_VIEWSONIC=m
# CONFIG_HID_VRC2 is not set
CONFIG_HID_XIAOMI=m
CONFIG_HID_GYRATION=m
CONFIG_HID_ICADE=m
CONFIG_HID_ITE=m
CONFIG_HID_JABRA=m
CONFIG_HID_TWINHAN=m
CONFIG_HID_KENSINGTON=m
CONFIG_HID_LCPOWER=m
CONFIG_HID_LED=m
CONFIG_HID_LENOVO=m
CONFIG_HID_LETSKETCH=m
CONFIG_HID_LOGITECH=m
CONFIG_HID_LOGITECH_DJ=m
CONFIG_HID_LOGITECH_HIDPP=m
CONFIG_LOGITECH_FF=y
CONFIG_LOGIRUMBLEPAD2_FF=y
CONFIG_LOGIG940_FF=y
CONFIG_LOGIWHEELS_FF=y
CONFIG_HID_MAGICMOUSE=y
CONFIG_HID_MALTRON=m
CONFIG_HID_MAYFLASH=m
CONFIG_HID_MEGAWORLD_FF=m
# CONFIG_HID_REDRAGON is not set
CONFIG_HID_MICROSOFT=m
CONFIG_HID_MONTEREY=m
CONFIG_HID_MULTITOUCH=m
CONFIG_HID_NINTENDO=m
CONFIG_NINTENDO_FF=y
CONFIG_HID_NTI=m
CONFIG_HID_NTRIG=y
CONFIG_HID_NVIDIA_SHIELD=m
CONFIG_NVIDIA_SHIELD_FF=y
CONFIG_HID_ORTEK=m
CONFIG_HID_PANTHERLORD=m
CONFIG_PANTHERLORD_FF=y
CONFIG_HID_PENMOUNT=m
CONFIG_HID_PETALYNX=m
CONFIG_HID_PICOLCD=m
CONFIG_HID_PICOLCD_FB=y
CONFIG_HID_PICOLCD_BACKLIGHT=y
CONFIG_HID_PICOLCD_LCD=y
CONFIG_HID_PICOLCD_LEDS=y
# CONFIG_HID_PICOLCD_CIR is not set
CONFIG_HID_PLANTRONICS=m
CONFIG_HID_PLAYSTATION=m
CONFIG_PLAYSTATION_FF=y
CONFIG_HID_PXRC=m
CONFIG_HID_RAZER=m
CONFIG_HID_PRIMAX=m
CONFIG_HID_RETRODE=m
CONFIG_HID_ROCCAT=m
CONFIG_HID_SAITEK=m
CONFIG_HID_SAMSUNG=m
CONFIG_HID_SEMITEK=m
CONFIG_HID_SIGMAMICRO=m
CONFIG_HID_SONY=m
CONFIG_SONY_FF=y
CONFIG_HID_SPEEDLINK=m
CONFIG_HID_STEAM=m
CONFIG_STEAM_FF=y
CONFIG_HID_STEELSERIES=m
CONFIG_HID_SUNPLUS=m
CONFIG_HID_RMI=m
CONFIG_HID_GREENASIA=m
CONFIG_GREENASIA_FF=y
CONFIG_HID_HYPERV_MOUSE=m
CONFIG_HID_SMARTJOYPLUS=m
CONFIG_SMARTJOYPLUS_FF=y
CONFIG_HID_TIVO=m
CONFIG_HID_TOPSEED=m
CONFIG_HID_TOPRE=m
CONFIG_HID_THINGM=m
CONFIG_HID_THRUSTMASTER=m
CONFIG_THRUSTMASTER_FF=y
CONFIG_HID_UDRAW_PS3=m
CONFIG_HID_U2FZERO=m
CONFIG_HID_UNIVERSAL_PIDFF=m
CONFIG_HID_WACOM=m
CONFIG_HID_WIIMOTE=m
CONFIG_HID_WINWING=m
CONFIG_HID_XINMO=m
CONFIG_HID_ZEROPLUS=m
CONFIG_ZEROPLUS_FF=y
CONFIG_HID_ZYDACRON=m
CONFIG_HID_SENSOR_HUB=m
# CONFIG_HID_SENSOR_CUSTOM_SENSOR is not set
CONFIG_HID_ALPS=m
# CONFIG_HID_MCP2200 is not set
CONFIG_HID_MCP2221=m
CONFIG_HID_KUNIT_TEST=m
# end of Special HID drivers

#
# HID-BPF support
#
CONFIG_HID_BPF=y
# end of HID-BPF support

CONFIG_I2C_HID=y
CONFIG_I2C_HID_ACPI=m
CONFIG_I2C_HID_OF=m
CONFIG_I2C_HID_OF_ELAN=m
CONFIG_I2C_HID_OF_GOODIX=m
CONFIG_I2C_HID_CORE=m

#
# Surface System Aggregator Module HID support
#
CONFIG_SURFACE_HID=m
CONFIG_SURFACE_KBD=m
# end of Surface System Aggregator Module HID support

CONFIG_SURFACE_HID_CORE=m

#
# USB HID support
#
CONFIG_USB_HID=y
CONFIG_HID_PID=y
CONFIG_USB_HIDDEV=y
# end of USB HID support

CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
CONFIG_USB_COMMON=y
CONFIG_USB_LED_TRIG=y
CONFIG_USB_ULPI_BUS=m
CONFIG_USB_CONN_GPIO=m
CONFIG_USB_ARCH_HAS_HCD=y
CONFIG_USB=y
CONFIG_USB_PCI=y
CONFIG_USB_PCI_AMD=y
CONFIG_USB_ANNOUNCE_NEW_DEVICES=y

#
# Miscellaneous USB options
#
CONFIG_USB_DEFAULT_PERSIST=y
# CONFIG_USB_FEW_INIT_RETRIES is not set
# CONFIG_USB_DYNAMIC_MINORS is not set
CONFIG_USB_OTG=y
# CONFIG_USB_OTG_PRODUCTLIST is not set
# CONFIG_USB_OTG_DISABLE_EXTERNAL_HUB is not set
CONFIG_USB_OTG_FSM=m
CONFIG_USB_LEDS_TRIGGER_USBPORT=m
CONFIG_USB_AUTOSUSPEND_DELAY=2
CONFIG_USB_DEFAULT_AUTHORIZATION_MODE=1
CONFIG_USB_MON=y

#
# USB Host Controller Drivers
#
# CONFIG_USB_C67X00_HCD is not set
CONFIG_USB_XHCI_HCD=y
CONFIG_USB_XHCI_DBGCAP=y
CONFIG_USB_XHCI_PCI=y
CONFIG_USB_XHCI_PCI_RENESAS=y
CONFIG_USB_XHCI_PLATFORM=m
# CONFIG_USB_XHCI_HISTB is not set
CONFIG_USB_XHCI_MVEBU=m
CONFIG_USB_XHCI_RCAR=m
CONFIG_USB_XHCI_RZV2M=y
# CONFIG_USB_XHCI_SIDEBAND is not set
CONFIG_USB_XHCI_TEGRA=m
CONFIG_USB_EHCI_HCD=y
CONFIG_USB_EHCI_ROOT_HUB_TT=y
CONFIG_USB_EHCI_TT_NEWSCHED=y
CONFIG_USB_EHCI_PCI=y
CONFIG_USB_EHCI_FSL=m
CONFIG_USB_EHCI_HCD_ORION=m
CONFIG_USB_EHCI_TEGRA=m
CONFIG_USB_EHCI_HCD_PLATFORM=m
# CONFIG_USB_OXU210HP_HCD is not set
# CONFIG_USB_ISP116X_HCD is not set
# CONFIG_USB_MAX3421_HCD is not set
CONFIG_USB_OHCI_HCD=m
CONFIG_USB_OHCI_HCD_PCI=m
# CONFIG_USB_OHCI_HCD_SSB is not set
CONFIG_USB_OHCI_HCD_PLATFORM=m
CONFIG_USB_UHCI_HCD=m
CONFIG_USB_SL811_HCD=m
CONFIG_USB_SL811_HCD_ISO=y
# CONFIG_USB_R8A66597_HCD is not set
# CONFIG_USB_HCD_BCMA is not set
# CONFIG_USB_HCD_SSB is not set
# CONFIG_USB_HCD_TEST_MODE is not set
# CONFIG_USB_RENESAS_USBHS is not set

#
# USB Device Class drivers
#
CONFIG_USB_ACM=m
CONFIG_USB_PRINTER=m
CONFIG_USB_WDM=m
CONFIG_USB_TMC=m

#
# NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may also be needed; see USB_STORAGE Help for more info
#
CONFIG_USB_STORAGE=m
# CONFIG_USB_STORAGE_DEBUG is not set
CONFIG_USB_STORAGE_REALTEK=m
CONFIG_REALTEK_AUTOPM=y
CONFIG_USB_STORAGE_DATAFAB=m
CONFIG_USB_STORAGE_FREECOM=m
CONFIG_USB_STORAGE_ISD200=m
CONFIG_USB_STORAGE_USBAT=m
CONFIG_USB_STORAGE_SDDR09=m
CONFIG_USB_STORAGE_SDDR55=m
CONFIG_USB_STORAGE_JUMPSHOT=m
CONFIG_USB_STORAGE_ALAUDA=m
CONFIG_USB_STORAGE_ONETOUCH=m
CONFIG_USB_STORAGE_KARMA=m
CONFIG_USB_STORAGE_CYPRESS_ATACB=m
CONFIG_USB_STORAGE_ENE_UB6250=m
CONFIG_USB_UAS=m

#
# USB Imaging devices
#
CONFIG_USB_MDC800=m
CONFIG_USB_MICROTEK=m
CONFIG_USBIP_CORE=m
CONFIG_USBIP_VHCI_HCD=m
CONFIG_USBIP_VHCI_HC_PORTS=8
CONFIG_USBIP_VHCI_NR_HCS=1
CONFIG_USBIP_HOST=m
CONFIG_USBIP_VUDC=m
# CONFIG_USBIP_DEBUG is not set

#
# USB dual-mode controller drivers
#
CONFIG_USB_CDNS_SUPPORT=m
CONFIG_USB_CDNS_HOST=y
CONFIG_USB_CDNS3=m
CONFIG_USB_CDNS3_GADGET=y
CONFIG_USB_CDNS3_HOST=y
CONFIG_USB_CDNS3_PCI_WRAP=m
CONFIG_USB_CDNS3_TI=m
CONFIG_USB_CDNS3_IMX=m
CONFIG_USB_CDNSP_PCI=m
# CONFIG_USB_CDNSP_GADGET is not set
# CONFIG_USB_CDNSP_HOST is not set
CONFIG_USB_MUSB_HDRC=m
# CONFIG_USB_MUSB_HOST is not set
# CONFIG_USB_MUSB_GADGET is not set
CONFIG_USB_MUSB_DUAL_ROLE=y

#
# Platform Glue Layer
#
CONFIG_USB_MUSB_SUNXI=m

#
# MUSB DMA mode
#
# CONFIG_MUSB_PIO_ONLY is not set
CONFIG_USB_DWC3=m
CONFIG_USB_DWC3_ULPI=y
# CONFIG_USB_DWC3_HOST is not set
# CONFIG_USB_DWC3_GADGET is not set
CONFIG_USB_DWC3_DUAL_ROLE=y

#
# Platform Glue Driver Support
#
CONFIG_USB_DWC3_PCI=m
CONFIG_USB_DWC3_HAPS=m
CONFIG_USB_DWC3_KEYSTONE=m
CONFIG_USB_DWC3_MESON_G12A=m
CONFIG_USB_DWC3_OF_SIMPLE=m
CONFIG_USB_DWC3_QCOM=m
CONFIG_USB_DWC3_IMX8MP=m
CONFIG_USB_DWC3_XILINX=m
CONFIG_USB_DWC3_AM62=m
CONFIG_USB_DWC2=m
# CONFIG_USB_DWC2_HOST is not set

#
# Gadget/Dual-role mode requires USB Gadget support to be enabled
#
# CONFIG_USB_DWC2_PERIPHERAL is not set
CONFIG_USB_DWC2_DUAL_ROLE=y
CONFIG_USB_DWC2_PCI=m
# CONFIG_USB_DWC2_DEBUG is not set
# CONFIG_USB_DWC2_TRACK_MISSED_SOFS is not set
CONFIG_USB_CHIPIDEA=m
CONFIG_USB_CHIPIDEA_UDC=y
CONFIG_USB_CHIPIDEA_HOST=y
CONFIG_USB_CHIPIDEA_PCI=m
CONFIG_USB_CHIPIDEA_MSM=m
CONFIG_USB_CHIPIDEA_NPCM=m
CONFIG_USB_CHIPIDEA_IMX=m
CONFIG_USB_CHIPIDEA_GENERIC=m
CONFIG_USB_CHIPIDEA_TEGRA=m
CONFIG_USB_ISP1760=m
CONFIG_USB_ISP1760_HCD=y
CONFIG_USB_ISP1761_UDC=y
# CONFIG_USB_ISP1760_HOST_ROLE is not set
# CONFIG_USB_ISP1760_GADGET_ROLE is not set
CONFIG_USB_ISP1760_DUAL_ROLE=y

#
# USB port drivers
#
CONFIG_USB_SERIAL=y
CONFIG_USB_SERIAL_CONSOLE=y
CONFIG_USB_SERIAL_GENERIC=y
CONFIG_USB_SERIAL_SIMPLE=m
CONFIG_USB_SERIAL_AIRCABLE=m
CONFIG_USB_SERIAL_ARK3116=m
CONFIG_USB_SERIAL_BELKIN=m
CONFIG_USB_SERIAL_CH341=m
CONFIG_USB_SERIAL_WHITEHEAT=m
CONFIG_USB_SERIAL_DIGI_ACCELEPORT=m
CONFIG_USB_SERIAL_CP210X=m
CONFIG_USB_SERIAL_CYPRESS_M8=m
CONFIG_USB_SERIAL_EMPEG=m
CONFIG_USB_SERIAL_FTDI_SIO=m
CONFIG_USB_SERIAL_VISOR=m
CONFIG_USB_SERIAL_IPAQ=m
CONFIG_USB_SERIAL_IR=m
CONFIG_USB_SERIAL_EDGEPORT=m
CONFIG_USB_SERIAL_EDGEPORT_TI=m
CONFIG_USB_SERIAL_F81232=m
CONFIG_USB_SERIAL_F8153X=m
CONFIG_USB_SERIAL_GARMIN=m
CONFIG_USB_SERIAL_IPW=m
CONFIG_USB_SERIAL_IUU=m
CONFIG_USB_SERIAL_KEYSPAN_PDA=m
CONFIG_USB_SERIAL_KEYSPAN=m
CONFIG_USB_SERIAL_KLSI=m
CONFIG_USB_SERIAL_KOBIL_SCT=m
CONFIG_USB_SERIAL_MCT_U232=m
# CONFIG_USB_SERIAL_METRO is not set
CONFIG_USB_SERIAL_MOS7720=m
CONFIG_USB_SERIAL_MOS7840=m
# CONFIG_USB_SERIAL_MXUPORT is not set
CONFIG_USB_SERIAL_NAVMAN=m
CONFIG_USB_SERIAL_PL2303=m
CONFIG_USB_SERIAL_OTI6858=m
CONFIG_USB_SERIAL_QCAUX=m
CONFIG_USB_SERIAL_QUALCOMM=m
CONFIG_USB_SERIAL_SPCP8X5=m
CONFIG_USB_SERIAL_SAFE=m
CONFIG_USB_SERIAL_SAFE_PADDED=y
CONFIG_USB_SERIAL_SIERRAWIRELESS=m
CONFIG_USB_SERIAL_SYMBOL=m
CONFIG_USB_SERIAL_TI=m
CONFIG_USB_SERIAL_CYBERJACK=m
CONFIG_USB_SERIAL_WWAN=m
CONFIG_USB_SERIAL_OPTION=m
CONFIG_USB_SERIAL_OMNINET=m
CONFIG_USB_SERIAL_OPTICON=m
CONFIG_USB_SERIAL_XSENS_MT=m
# CONFIG_USB_SERIAL_WISHBONE is not set
CONFIG_USB_SERIAL_SSU100=m
CONFIG_USB_SERIAL_QT2=m
CONFIG_USB_SERIAL_UPD78F0730=m
CONFIG_USB_SERIAL_XR=m
CONFIG_USB_SERIAL_DEBUG=m

#
# USB Miscellaneous drivers
#
CONFIG_USB_EMI62=m
CONFIG_USB_EMI26=m
CONFIG_USB_ADUTUX=m
CONFIG_USB_SEVSEG=m
CONFIG_USB_LEGOTOWER=m
CONFIG_USB_LCD=m
# CONFIG_USB_CYPRESS_CY7C63 is not set
# CONFIG_USB_CYTHERM is not set
CONFIG_USB_IDMOUSE=m
CONFIG_USB_APPLEDISPLAY=m
CONFIG_USB_QCOM_EUD=m
CONFIG_APPLE_MFI_FASTCHARGE=m
# CONFIG_USB_LJCA is not set
CONFIG_USB_SISUSBVGA=m
CONFIG_USB_LD=m
CONFIG_USB_TRANCEVIBRATOR=m
CONFIG_USB_IOWARRIOR=m
# CONFIG_USB_TEST is not set
# CONFIG_USB_EHSET_TEST_FIXTURE is not set
CONFIG_USB_ISIGHTFW=m
CONFIG_USB_YUREX=m
CONFIG_USB_EZUSB_FX2=m
CONFIG_USB_HUB_USB251XB=m
CONFIG_USB_HSIC_USB3503=m
CONFIG_USB_HSIC_USB4604=m
# CONFIG_USB_LINK_LAYER_TEST is not set
CONFIG_USB_CHAOSKEY=m
CONFIG_USB_ONBOARD_DEV=m
CONFIG_USB_ONBOARD_DEV_USB5744=y
CONFIG_USB_ATM=m
# CONFIG_USB_SPEEDTOUCH is not set
CONFIG_USB_CXACRU=m
CONFIG_USB_UEAGLEATM=m
CONFIG_USB_XUSBATM=m

#
# USB Physical Layer drivers
#
CONFIG_USB_PHY=y
CONFIG_NOP_USB_XCEIV=m
CONFIG_USB_GPIO_VBUS=m
# CONFIG_USB_ISP1301 is not set
# CONFIG_USB_MXS_PHY is not set
CONFIG_USB_TEGRA_PHY=m
CONFIG_USB_ULPI=y
CONFIG_USB_ULPI_VIEWPORT=y
# end of USB Physical Layer drivers

CONFIG_USB_GADGET=m
# CONFIG_USB_GADGET_DEBUG is not set
# CONFIG_USB_GADGET_DEBUG_FILES is not set
# CONFIG_USB_GADGET_DEBUG_FS is not set
CONFIG_USB_GADGET_VBUS_DRAW=100
CONFIG_USB_GADGET_STORAGE_NUM_BUFFERS=2
CONFIG_U_SERIAL_CONSOLE=y

#
# USB Peripheral Controller
#
# CONFIG_USB_GR_UDC is not set
# CONFIG_USB_R8A66597 is not set
CONFIG_USB_RZV2M_USB3DRD=m
# CONFIG_USB_RENESAS_USB3 is not set
# CONFIG_USB_RENESAS_USBF is not set
# CONFIG_USB_PXA27X is not set
CONFIG_USB_SNP_CORE=m
CONFIG_USB_SNP_UDC_PLAT=m
# CONFIG_USB_M66592 is not set
# CONFIG_USB_BDC_UDC is not set
# CONFIG_USB_AMD5536UDC is not set
# CONFIG_USB_NET2280 is not set
# CONFIG_USB_GOKU is not set
# CONFIG_USB_EG20T is not set
# CONFIG_USB_GADGET_XILINX is not set
CONFIG_USB_MAX3420_UDC=m
CONFIG_USB_TEGRA_XUDC=m
CONFIG_USB_CDNS2_UDC=m
# CONFIG_USB_DUMMY_HCD is not set
# end of USB Peripheral Controller

CONFIG_USB_LIBCOMPOSITE=m
CONFIG_USB_F_ACM=m
CONFIG_USB_U_SERIAL=m
CONFIG_USB_U_ETHER=m
CONFIG_USB_F_SERIAL=m
CONFIG_USB_F_OBEX=m
CONFIG_USB_F_NCM=m
CONFIG_USB_F_ECM=m
CONFIG_USB_F_EEM=m
CONFIG_USB_F_SUBSET=m
CONFIG_USB_F_MASS_STORAGE=m
CONFIG_USB_F_FS=m
CONFIG_USB_F_MIDI2=m
CONFIG_USB_F_HID=m
CONFIG_USB_F_TCM=m
CONFIG_USB_CONFIGFS=m
CONFIG_USB_CONFIGFS_SERIAL=y
CONFIG_USB_CONFIGFS_ACM=y
CONFIG_USB_CONFIGFS_OBEX=y
CONFIG_USB_CONFIGFS_NCM=y
CONFIG_USB_CONFIGFS_ECM=y
CONFIG_USB_CONFIGFS_ECM_SUBSET=y
# CONFIG_USB_CONFIGFS_RNDIS is not set
CONFIG_USB_CONFIGFS_EEM=y
CONFIG_USB_CONFIGFS_MASS_STORAGE=y
# CONFIG_USB_CONFIGFS_F_LB_SS is not set
CONFIG_USB_CONFIGFS_F_FS=y
# CONFIG_USB_CONFIGFS_F_UAC1 is not set
# CONFIG_USB_CONFIGFS_F_UAC1_LEGACY is not set
# CONFIG_USB_CONFIGFS_F_UAC2 is not set
# CONFIG_USB_CONFIGFS_F_MIDI is not set
CONFIG_USB_CONFIGFS_F_MIDI2=y
CONFIG_USB_CONFIGFS_F_HID=y
# CONFIG_USB_CONFIGFS_F_UVC is not set
# CONFIG_USB_CONFIGFS_F_PRINTER is not set
CONFIG_USB_CONFIGFS_F_TCM=y

#
# USB Gadget precomposed configurations
#
# CONFIG_USB_ZERO is not set
# CONFIG_USB_AUDIO is not set
# CONFIG_USB_ETH is not set
# CONFIG_USB_G_NCM is not set
# CONFIG_USB_GADGETFS is not set
# CONFIG_USB_FUNCTIONFS is not set
# CONFIG_USB_MASS_STORAGE is not set
# CONFIG_USB_GADGET_TARGET is not set
CONFIG_USB_G_SERIAL=m
# CONFIG_USB_MIDI_GADGET is not set
# CONFIG_USB_G_PRINTER is not set
# CONFIG_USB_CDC_COMPOSITE is not set
# CONFIG_USB_G_ACM_MS is not set
# CONFIG_USB_G_MULTI is not set
# CONFIG_USB_G_HID is not set
# CONFIG_USB_G_DBGP is not set
# CONFIG_USB_G_WEBCAM is not set
CONFIG_USB_RAW_GADGET=m
# end of USB Gadget precomposed configurations

CONFIG_TYPEC=m
CONFIG_TYPEC_TCPM=m
CONFIG_TYPEC_TCPCI=m
# CONFIG_TYPEC_RT1711H is not set
CONFIG_TYPEC_TCPCI_MAXIM=m
CONFIG_TYPEC_FUSB302=m
CONFIG_TYPEC_QCOM_PMIC=m
CONFIG_TYPEC_UCSI=m
CONFIG_UCSI_CCG=m
CONFIG_UCSI_ACPI=m
CONFIG_UCSI_STM32G0=m
CONFIG_UCSI_PMIC_GLINK=m
CONFIG_CROS_EC_UCSI=m
CONFIG_UCSI_LENOVO_YOGA_C630=m
CONFIG_TYPEC_TPS6598X=m
CONFIG_TYPEC_ANX7411=m
CONFIG_TYPEC_RT1719=m
CONFIG_TYPEC_HD3SS3220=m
CONFIG_TYPEC_STUSB160X=m
CONFIG_TYPEC_WUSB3801=m

#
# USB Type-C Multiplexer/DeMultiplexer Switch support
#
CONFIG_TYPEC_MUX_FSA4480=m
CONFIG_TYPEC_MUX_GPIO_SBU=m
CONFIG_TYPEC_MUX_PI3USB30532=m
CONFIG_TYPEC_MUX_IT5205=m
CONFIG_TYPEC_MUX_NB7VPQ904M=m
CONFIG_TYPEC_MUX_PS883X=m
CONFIG_TYPEC_MUX_PTN36502=m
CONFIG_TYPEC_MUX_TUSB1046=m
# CONFIG_TYPEC_MUX_WCD939X_USBSS is not set
# end of USB Type-C Multiplexer/DeMultiplexer Switch support

#
# USB Type-C Alternate Mode drivers
#
CONFIG_TYPEC_DP_ALTMODE=m
CONFIG_TYPEC_NVIDIA_ALTMODE=m
CONFIG_TYPEC_TBT_ALTMODE=m
# end of USB Type-C Alternate Mode drivers

CONFIG_USB_ROLE_SWITCH=y
CONFIG_MMC=m
CONFIG_PWRSEQ_EMMC=m
CONFIG_PWRSEQ_SD8787=m
CONFIG_PWRSEQ_SIMPLE=m
CONFIG_MMC_BLOCK=m
CONFIG_MMC_BLOCK_MINORS=8
CONFIG_SDIO_UART=m
# CONFIG_MMC_TEST is not set
# CONFIG_MMC_CRYPTO is not set

#
# MMC/SD/SDIO Host Controller Drivers
#
# CONFIG_MMC_DEBUG is not set
CONFIG_MMC_ARMMMCI=m
CONFIG_MMC_QCOM_DML=y
# CONFIG_MMC_STM32_SDMMC is not set
CONFIG_MMC_SDHCI=m
CONFIG_MMC_SDHCI_IO_ACCESSORS=y
CONFIG_MMC_SDHCI_UHS2=m
CONFIG_MMC_SDHCI_PCI=m
CONFIG_MMC_RICOH_MMC=y
CONFIG_MMC_SDHCI_ACPI=m
CONFIG_MMC_SDHCI_PLTFM=m
CONFIG_MMC_SDHCI_OF_ARASAN=m
# CONFIG_MMC_SDHCI_OF_AT91 is not set
CONFIG_MMC_SDHCI_OF_ESDHC=m
CONFIG_MMC_SDHCI_OF_DWCMSHC=m
CONFIG_MMC_SDHCI_CADENCE=m
CONFIG_MMC_SDHCI_ESDHC_IMX=m
CONFIG_MMC_SDHCI_TEGRA=m
CONFIG_MMC_SDHCI_PXAV3=m
CONFIG_MMC_SDHCI_F_SDH30=m
# CONFIG_MMC_SDHCI_MILBEAUT is not set
CONFIG_MMC_SDHCI_IPROC=m
CONFIG_MMC_MESON_GX=m
CONFIG_MMC_MESON_MX_SDIO=m
CONFIG_MMC_ALCOR=m
CONFIG_MMC_SDHCI_MSM=m
# CONFIG_MMC_MXC is not set
CONFIG_MMC_TIFM_SD=m
CONFIG_MMC_SPI=m
CONFIG_MMC_TMIO_CORE=m
CONFIG_MMC_SDHI=m
# CONFIG_MMC_SDHI_SYS_DMAC is not set
CONFIG_MMC_SDHI_INTERNAL_DMAC=m
CONFIG_MMC_CB710=m
CONFIG_MMC_VIA_SDMMC=m
CONFIG_MMC_CAVIUM_THUNDERX=m
CONFIG_MMC_DW=m
CONFIG_MMC_DW_PLTFM=m
CONFIG_MMC_DW_BLUEFIELD=m
CONFIG_MMC_DW_EXYNOS=m
CONFIG_MMC_DW_HI3798CV200=m
CONFIG_MMC_DW_HI3798MV200=m
CONFIG_MMC_DW_K3=m
CONFIG_MMC_DW_PCI=m
CONFIG_MMC_DW_ROCKCHIP=m
# CONFIG_MMC_SH_MMCIF is not set
CONFIG_MMC_VUB300=m
CONFIG_MMC_USHC=m
# CONFIG_MMC_USDHI6ROL0 is not set
CONFIG_MMC_REALTEK_PCI=m
CONFIG_MMC_REALTEK_USB=m
CONFIG_MMC_SUNXI=m
CONFIG_MMC_CQHCI=m
CONFIG_MMC_HSQ=m
# CONFIG_MMC_TOSHIBA_PCI is not set
CONFIG_MMC_BCM2835=m
# CONFIG_MMC_MTK is not set
CONFIG_MMC_SDHCI_BRCMSTB=m
CONFIG_MMC_SDHCI_XENON=m
CONFIG_MMC_SDHCI_AM654=m
CONFIG_SCSI_UFSHCD=m
CONFIG_SCSI_UFS_BSG=y
CONFIG_SCSI_UFS_CRYPTO=y
CONFIG_SCSI_UFS_HWMON=y
CONFIG_SCSI_UFSHCD_PCI=m
# CONFIG_SCSI_UFS_DWC_TC_PCI is not set
CONFIG_SCSI_UFSHCD_PLATFORM=m
CONFIG_SCSI_UFS_CDNS_PLATFORM=m
# CONFIG_SCSI_UFS_DWC_TC_PLATFORM is not set
CONFIG_SCSI_UFS_QCOM=m
CONFIG_SCSI_UFS_HISI=m
# CONFIG_SCSI_UFS_RENESAS is not set
CONFIG_SCSI_UFS_TI_J721E=m
CONFIG_SCSI_UFS_ROCKCHIP=m
CONFIG_MEMSTICK=m
# CONFIG_MEMSTICK_DEBUG is not set

#
# MemoryStick drivers
#
# CONFIG_MEMSTICK_UNSAFE_RESUME is not set
CONFIG_MSPRO_BLOCK=m
# CONFIG_MS_BLOCK is not set

#
# MemoryStick Host Controller Drivers
#
CONFIG_MEMSTICK_TIFM_MS=m
CONFIG_MEMSTICK_JMICRON_38X=m
CONFIG_MEMSTICK_R592=m
CONFIG_MEMSTICK_REALTEK_USB=m
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=y
CONFIG_LEDS_CLASS_FLASH=m
CONFIG_LEDS_CLASS_MULTICOLOR=m
CONFIG_LEDS_BRIGHTNESS_HW_CHANGED=y
CONFIG_LEDS_KUNIT_TEST=m

#
# LED drivers
#
CONFIG_LEDS_AN30259A=m
CONFIG_LEDS_AW200XX=m
# CONFIG_LEDS_AW2013 is not set
# CONFIG_LEDS_BCM6328 is not set
# CONFIG_LEDS_BCM6358 is not set
CONFIG_LEDS_CR0014114=m
CONFIG_LEDS_CROS_EC=m
# CONFIG_LEDS_EL15203000 is not set
CONFIG_LEDS_LM3530=m
CONFIG_LEDS_LM3532=m
# CONFIG_LEDS_LM3642 is not set
CONFIG_LEDS_LM3692X=m
# CONFIG_LEDS_SUN50I_A100 is not set
CONFIG_LEDS_PCA9532=m
CONFIG_LEDS_PCA9532_GPIO=y
CONFIG_LEDS_GPIO=m
CONFIG_LEDS_LP3944=m
CONFIG_LEDS_LP3952=m
CONFIG_LEDS_LP50XX=m
# CONFIG_LEDS_LP55XX_COMMON is not set
# CONFIG_LEDS_LP8860 is not set
CONFIG_LEDS_LP8864=m
# CONFIG_LEDS_PCA955X is not set
CONFIG_LEDS_PCA963X=m
CONFIG_LEDS_PCA995X=m
CONFIG_LEDS_QNAP_MCU=m
# CONFIG_LEDS_DAC124S085 is not set
CONFIG_LEDS_PWM=m
CONFIG_LEDS_REGULATOR=m
# CONFIG_LEDS_BD2606MVV is not set
# CONFIG_LEDS_BD2802 is not set
CONFIG_LEDS_LT3593=m
CONFIG_LEDS_MAX5970=m
# CONFIG_LEDS_TCA6507 is not set
CONFIG_LEDS_TLC591XX=m
CONFIG_LEDS_MAX77650=m
CONFIG_LEDS_MAX77705=m
# CONFIG_LEDS_LM355x is not set
# CONFIG_LEDS_IS31FL319X is not set
CONFIG_LEDS_IS31FL32XX=m

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
CONFIG_LEDS_BLINKM=m
CONFIG_LEDS_BLINKM_MULTICOLOR=y
CONFIG_LEDS_SYSCON=y
CONFIG_LEDS_MLXREG=m
CONFIG_LEDS_USER=m
# CONFIG_LEDS_SPI_BYTE is not set
# CONFIG_LEDS_LM3697 is not set
CONFIG_LEDS_ST1202=m

#
# Flash and Torch LED drivers
#
# CONFIG_LEDS_AAT1290 is not set
CONFIG_LEDS_AS3645A=m
# CONFIG_LEDS_KTD2692 is not set
CONFIG_LEDS_LM3601X=m
CONFIG_LEDS_QCOM_FLASH=m
# CONFIG_LEDS_RT4505 is not set
# CONFIG_LEDS_RT8515 is not set
CONFIG_LEDS_SGM3140=m
CONFIG_LEDS_SY7802=m
# CONFIG_LEDS_TPS6131X is not set

#
# RGB LED drivers
#
CONFIG_LEDS_GROUP_MULTICOLOR=m
CONFIG_LEDS_KTD202X=m
CONFIG_LEDS_NCP5623=m
CONFIG_LEDS_PWM_MULTICOLOR=m
CONFIG_LEDS_QCOM_LPG=m

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
CONFIG_LEDS_TRIGGER_TIMER=m
CONFIG_LEDS_TRIGGER_ONESHOT=m
CONFIG_LEDS_TRIGGER_DISK=y
CONFIG_LEDS_TRIGGER_MTD=y
CONFIG_LEDS_TRIGGER_HEARTBEAT=m
CONFIG_LEDS_TRIGGER_BACKLIGHT=m
CONFIG_LEDS_TRIGGER_CPU=y
CONFIG_LEDS_TRIGGER_ACTIVITY=m
CONFIG_LEDS_TRIGGER_GPIO=m
CONFIG_LEDS_TRIGGER_DEFAULT_ON=m

#
# iptables trigger is under Netfilter config (LED target)
#
CONFIG_LEDS_TRIGGER_TRANSIENT=m
CONFIG_LEDS_TRIGGER_CAMERA=m
CONFIG_LEDS_TRIGGER_PANIC=y
CONFIG_LEDS_TRIGGER_NETDEV=m
CONFIG_LEDS_TRIGGER_PATTERN=m
CONFIG_LEDS_TRIGGER_TTY=m
CONFIG_LEDS_TRIGGER_INPUT_EVENTS=m

#
# Simatic LED drivers
#
CONFIG_ACCESSIBILITY=y
CONFIG_A11Y_BRAILLE_CONSOLE=y

#
# Speakup console speech
#
CONFIG_SPEAKUP=m
CONFIG_SPEAKUP_SYNTH_ACNTSA=m
CONFIG_SPEAKUP_SYNTH_APOLLO=m
CONFIG_SPEAKUP_SYNTH_AUDPTR=m
CONFIG_SPEAKUP_SYNTH_BNS=m
CONFIG_SPEAKUP_SYNTH_DECTLK=m
# CONFIG_SPEAKUP_SYNTH_DECEXT is not set
CONFIG_SPEAKUP_SYNTH_LTLK=m
CONFIG_SPEAKUP_SYNTH_SOFT=m
CONFIG_SPEAKUP_SYNTH_SPKOUT=m
CONFIG_SPEAKUP_SYNTH_TXPRT=m
# CONFIG_SPEAKUP_SYNTH_DUMMY is not set
# end of Speakup console speech

CONFIG_INFINIBAND=m
CONFIG_INFINIBAND_USER_MAD=m
CONFIG_INFINIBAND_USER_ACCESS=m
CONFIG_INFINIBAND_USER_MEM=y
CONFIG_INFINIBAND_ON_DEMAND_PAGING=y
CONFIG_INFINIBAND_ADDR_TRANS=y
CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS=y
CONFIG_INFINIBAND_VIRT_DMA=y
# CONFIG_INFINIBAND_BNXT_RE is not set
CONFIG_INFINIBAND_CXGB4=m
CONFIG_INFINIBAND_EFA=m
CONFIG_INFINIBAND_ERDMA=m
# CONFIG_INFINIBAND_HNS_HIP08 is not set
CONFIG_INFINIBAND_IRDMA=m
CONFIG_MANA_INFINIBAND=m
CONFIG_MLX4_INFINIBAND=m
CONFIG_MLX5_INFINIBAND=m
CONFIG_INFINIBAND_MTHCA=m
CONFIG_INFINIBAND_MTHCA_DEBUG=y
CONFIG_INFINIBAND_OCRDMA=m
CONFIG_INFINIBAND_QEDR=m
# CONFIG_INFINIBAND_VMWARE_PVRDMA is not set
CONFIG_RDMA_RXE=m
CONFIG_RDMA_SIW=m
CONFIG_INFINIBAND_IPOIB=m
CONFIG_INFINIBAND_IPOIB_CM=y
CONFIG_INFINIBAND_IPOIB_DEBUG=y
CONFIG_INFINIBAND_IPOIB_DEBUG_DATA=y
CONFIG_INFINIBAND_SRP=m
CONFIG_INFINIBAND_SRPT=m
CONFIG_INFINIBAND_ISER=m
CONFIG_INFINIBAND_ISERT=m
CONFIG_INFINIBAND_RTRS=m
CONFIG_INFINIBAND_RTRS_CLIENT=m
CONFIG_INFINIBAND_RTRS_SERVER=m
CONFIG_EDAC_SUPPORT=y
CONFIG_EDAC=y
CONFIG_EDAC_LEGACY_SYSFS=y
# CONFIG_EDAC_DEBUG is not set
CONFIG_EDAC_GHES=y
CONFIG_EDAC_SCRUB=y
CONFIG_EDAC_ECS=y
CONFIG_EDAC_MEM_REPAIR=y
CONFIG_EDAC_LAYERSCAPE=m
CONFIG_EDAC_THUNDERX=m
CONFIG_EDAC_SYNOPSYS=m
CONFIG_EDAC_XGENE=m
CONFIG_EDAC_QCOM=m
CONFIG_EDAC_BLUEFIELD=m
CONFIG_EDAC_DMC520=m
CONFIG_EDAC_ZYNQMP=m
CONFIG_EDAC_VERSAL=m
CONFIG_RTC_LIB=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_HCTOSYS=y
CONFIG_RTC_HCTOSYS_DEVICE="rtc0"
CONFIG_RTC_SYSTOHC=y
CONFIG_RTC_SYSTOHC_DEVICE="rtc0"
# CONFIG_RTC_DEBUG is not set
CONFIG_RTC_LIB_KUNIT_TEST=m
CONFIG_RTC_NVMEM=y

#
# RTC interfaces
#
CONFIG_RTC_INTF_SYSFS=y
CONFIG_RTC_INTF_PROC=y
CONFIG_RTC_INTF_DEV=y
# CONFIG_RTC_INTF_DEV_UIE_EMUL is not set
# CONFIG_RTC_DRV_TEST is not set

#
# I2C RTC drivers
#
CONFIG_RTC_DRV_88PM886=m
# CONFIG_RTC_DRV_ABB5ZES3 is not set
CONFIG_RTC_DRV_ABEOZ9=m
CONFIG_RTC_DRV_ABX80X=m
CONFIG_RTC_DRV_AC100=m
CONFIG_RTC_DRV_AS3722=m
CONFIG_RTC_DRV_DS1307=m
# CONFIG_RTC_DRV_DS1307_CENTURY is not set
CONFIG_RTC_DRV_DS1374=m
CONFIG_RTC_DRV_DS1374_WDT=y
CONFIG_RTC_DRV_DS1672=m
CONFIG_RTC_DRV_HYM8563=m
CONFIG_RTC_DRV_MAX6900=m
CONFIG_RTC_DRV_MAX31335=m
CONFIG_RTC_DRV_MAX77686=m
CONFIG_RTC_DRV_NCT3018Y=m
CONFIG_RTC_DRV_RK808=m
CONFIG_RTC_DRV_RS5C372=m
CONFIG_RTC_DRV_ISL1208=m
CONFIG_RTC_DRV_ISL12022=m
CONFIG_RTC_DRV_ISL12026=m
CONFIG_RTC_DRV_X1205=m
CONFIG_RTC_DRV_PCF8523=m
CONFIG_RTC_DRV_PCF85363=m
CONFIG_RTC_DRV_PCF8563=m
CONFIG_RTC_DRV_PCF8583=m
CONFIG_RTC_DRV_M41T80=m
CONFIG_RTC_DRV_M41T80_WDT=y
CONFIG_RTC_DRV_BQ32K=m
CONFIG_RTC_DRV_TPS6594=m
CONFIG_RTC_DRV_S35390A=m
CONFIG_RTC_DRV_FM3130=m
CONFIG_RTC_DRV_RX8010=m
# CONFIG_RTC_DRV_RX8111 is not set
CONFIG_RTC_DRV_RX8581=m
CONFIG_RTC_DRV_RX8025=m
CONFIG_RTC_DRV_EM3027=m
CONFIG_RTC_DRV_RV3028=m
CONFIG_RTC_DRV_RV3032=m
CONFIG_RTC_DRV_RV8803=m
# CONFIG_RTC_DRV_SD2405AL is not set
CONFIG_RTC_DRV_SD3078=m

#
# SPI RTC drivers
#
CONFIG_RTC_DRV_M41T93=m
CONFIG_RTC_DRV_M41T94=m
# CONFIG_RTC_DRV_DS1302 is not set
CONFIG_RTC_DRV_DS1305=m
CONFIG_RTC_DRV_DS1343=m
CONFIG_RTC_DRV_DS1347=m
CONFIG_RTC_DRV_DS1390=m
CONFIG_RTC_DRV_MAX6916=m
CONFIG_RTC_DRV_R9701=m
CONFIG_RTC_DRV_RX4581=m
CONFIG_RTC_DRV_RS5C348=m
CONFIG_RTC_DRV_MAX6902=m
CONFIG_RTC_DRV_PCF2123=m
CONFIG_RTC_DRV_MCP795=m
CONFIG_RTC_I2C_AND_SPI=y

#
# SPI and I2C RTC drivers
#
CONFIG_RTC_DRV_DS3232=m
# CONFIG_RTC_DRV_DS3232_HWMON is not set
CONFIG_RTC_DRV_PCF2127=m
CONFIG_RTC_DRV_PCF85063=m
CONFIG_RTC_DRV_RV3029C2=m
CONFIG_RTC_DRV_RV3029_HWMON=y
# CONFIG_RTC_DRV_RX6110 is not set

#
# Platform RTC drivers
#
CONFIG_RTC_DRV_DS1286=m
CONFIG_RTC_DRV_DS1511=m
CONFIG_RTC_DRV_DS1553=m
CONFIG_RTC_DRV_DS1685_FAMILY=m
CONFIG_RTC_DRV_DS1685=y
# CONFIG_RTC_DRV_DS1689 is not set
# CONFIG_RTC_DRV_DS17285 is not set
# CONFIG_RTC_DRV_DS17485 is not set
# CONFIG_RTC_DRV_DS17885 is not set
CONFIG_RTC_DRV_DS1742=m
CONFIG_RTC_DRV_DS2404=m
CONFIG_RTC_DRV_EFI=y
CONFIG_RTC_DRV_STK17TA8=m
# CONFIG_RTC_DRV_M48T86 is not set
CONFIG_RTC_DRV_M48T35=m
CONFIG_RTC_DRV_M48T59=m
CONFIG_RTC_DRV_MSM6242=m
CONFIG_RTC_DRV_RP5C01=m
CONFIG_RTC_DRV_OPTEE=m
CONFIG_RTC_DRV_ZYNQMP=m
CONFIG_RTC_DRV_CROS_EC=m

#
# on-CPU RTC drivers
#
# CONFIG_RTC_DRV_IMXDI is not set
CONFIG_RTC_DRV_FSL_FTM_ALARM=m
CONFIG_RTC_DRV_MESON_VRTC=m
# CONFIG_RTC_DRV_SH is not set
# CONFIG_RTC_DRV_PL030 is not set
CONFIG_RTC_DRV_PL031=y
CONFIG_RTC_DRV_SUN6I=y
CONFIG_RTC_DRV_MV=m
CONFIG_RTC_DRV_ARMADA38X=m
CONFIG_RTC_DRV_CADENCE=m
# CONFIG_RTC_DRV_FTRTC010 is not set
CONFIG_RTC_DRV_PM8XXX=m
CONFIG_RTC_DRV_TEGRA=m
# CONFIG_RTC_DRV_MXC is not set
# CONFIG_RTC_DRV_MXC_V2 is not set
CONFIG_RTC_DRV_SNVS=m
CONFIG_RTC_DRV_BBNSM=m
CONFIG_RTC_DRV_IMX_BBM_SCMI=m
CONFIG_RTC_DRV_IMX_SC=m
CONFIG_RTC_DRV_XGENE=m
CONFIG_RTC_DRV_R7301=m
CONFIG_RTC_DRV_TI_K3=m
# CONFIG_RTC_DRV_RENESAS_RTCA3 is not set

#
# HID Sensor RTC drivers
#
# CONFIG_RTC_DRV_HID_SENSOR_TIME is not set
# CONFIG_RTC_DRV_GOLDFISH is not set
CONFIG_RTC_DRV_AMLOGIC_A4=y
# CONFIG_RTC_DRV_S32G is not set
CONFIG_DMADEVICES=y
# CONFIG_DMADEVICES_DEBUG is not set

#
# DMA Devices
#
CONFIG_ASYNC_TX_ENABLE_CHANNEL_SWITCH=y
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
CONFIG_DMA_OF=y
CONFIG_ALTERA_MSGDMA=m
# CONFIG_AMBA_PL08X is not set
CONFIG_APPLE_ADMAC=m
# CONFIG_ARM_DMA350 is not set
CONFIG_AXI_DMAC=m
CONFIG_BCM_SBA_RAID=m
CONFIG_DMA_BCM2835=m
CONFIG_DMA_SUN6I=m
CONFIG_DW_AXI_DMAC=m
CONFIG_FSL_EDMA=m
CONFIG_FSL_QDMA=m
CONFIG_HISI_DMA=m
# CONFIG_IMX_DMA is not set
CONFIG_IMX_SDMA=m
# CONFIG_INTEL_IDMA64 is not set
CONFIG_K3_DMA=m
CONFIG_MV_XOR=y
CONFIG_MV_XOR_V2=y
# CONFIG_MXS_DMA is not set
CONFIG_PL330_DMA=m
# CONFIG_PLX_DMA is not set
CONFIG_TEGRA186_GPC_DMA=m
CONFIG_TEGRA20_APB_DMA=y
CONFIG_TEGRA210_ADMA=m
# CONFIG_XGENE_DMA is not set
# CONFIG_XILINX_DMA is not set
CONFIG_XILINX_XDMA=m
CONFIG_XILINX_ZYNQMP_DMA=m
CONFIG_XILINX_ZYNQMP_DPDMA=m
CONFIG_AMD_QDMA=m
CONFIG_QCOM_BAM_DMA=y
CONFIG_QCOM_GPI_DMA=m
CONFIG_QCOM_HIDMA_MGMT=m
CONFIG_QCOM_HIDMA=m
CONFIG_DW_DMAC_CORE=m
CONFIG_DW_DMAC=m
CONFIG_DW_DMAC_PCI=m
CONFIG_DW_EDMA=m
CONFIG_DW_EDMA_PCIE=m
# CONFIG_SF_PDMA is not set
CONFIG_RENESAS_DMA=y
# CONFIG_RCAR_DMAC is not set
# CONFIG_RENESAS_USB_DMAC is not set
CONFIG_RZ_DMAC=m
CONFIG_TI_K3_UDMA=m
CONFIG_TI_K3_UDMA_GLUE_LAYER=m
CONFIG_TI_K3_PSIL=m
CONFIG_FSL_DPAA2_QDMA=m

#
# DMA Clients
#
CONFIG_ASYNC_TX_DMA=y
# CONFIG_DMATEST is not set
CONFIG_DMA_ENGINE_RAID=y

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
# CONFIG_SW_SYNC is not set
CONFIG_UDMABUF=y
# CONFIG_DMABUF_MOVE_NOTIFY is not set
# CONFIG_DMABUF_DEBUG is not set
# CONFIG_DMABUF_SELFTESTS is not set
CONFIG_DMABUF_HEAPS=y
# CONFIG_DMABUF_SYSFS_STATS is not set
CONFIG_DMABUF_HEAPS_SYSTEM=y
CONFIG_DMABUF_HEAPS_CMA=y
CONFIG_DMABUF_HEAPS_CMA_LEGACY=y
# end of DMABUF options

CONFIG_UIO=m
# CONFIG_UIO_CIF is not set
# CONFIG_UIO_PDRV_GENIRQ is not set
# CONFIG_UIO_DMEM_GENIRQ is not set
# CONFIG_UIO_AEC is not set
# CONFIG_UIO_SERCOS3 is not set
CONFIG_UIO_PCI_GENERIC=m
# CONFIG_UIO_NETX is not set
# CONFIG_UIO_MF624 is not set
CONFIG_UIO_HV_GENERIC=m
CONFIG_UIO_DFL=m
CONFIG_VFIO=m
# CONFIG_VFIO_DEVICE_CDEV is not set
CONFIG_VFIO_GROUP=y
CONFIG_VFIO_CONTAINER=y
CONFIG_VFIO_IOMMU_TYPE1=m
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_VIRQFD=y
# CONFIG_VFIO_DEBUGFS is not set

#
# VFIO support for PCI devices
#
CONFIG_VFIO_PCI_CORE=m
CONFIG_VFIO_PCI_INTX=y
CONFIG_VFIO_PCI=m
CONFIG_MLX5_VFIO_PCI=m
CONFIG_PDS_VFIO_PCI=m
CONFIG_VIRTIO_VFIO_PCI=m
CONFIG_NVGRACE_GPU_VFIO_PCI=m
CONFIG_QAT_VFIO_PCI=m
# end of VFIO support for PCI devices

#
# VFIO support for platform devices
#
CONFIG_VFIO_PLATFORM_BASE=m
CONFIG_VFIO_PLATFORM=m
CONFIG_VFIO_AMBA=m

#
# VFIO platform reset drivers
#
# CONFIG_VFIO_PLATFORM_CALXEDAXGMAC_RESET is not set
CONFIG_VFIO_PLATFORM_AMDXGBE_RESET=m
# end of VFIO platform reset drivers
# end of VFIO support for platform devices

#
# VFIO support for FSL_MC bus devices
#
CONFIG_VFIO_FSL_MC=m
# end of VFIO support for FSL_MC bus devices

CONFIG_VFIO_CDX=m
CONFIG_IRQ_BYPASS_MANAGER=y
CONFIG_VIRT_DRIVERS=y
CONFIG_VMGENID=y
CONFIG_VBOXGUEST=m
CONFIG_NITRO_ENCLAVES=m
CONFIG_ARM_PKVM_GUEST=y
CONFIG_ARM_CCA_GUEST=m
CONFIG_TSM_GUEST=y
CONFIG_TSM_REPORTS=m
CONFIG_VIRTIO_ANCHOR=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI_LIB=y
CONFIG_VIRTIO_PCI_LIB_LEGACY=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_VDPA=m
# CONFIG_VIRTIO_PMEM is not set
CONFIG_VIRTIO_BALLOON=m
CONFIG_VIRTIO_MEM=m
CONFIG_VIRTIO_INPUT=m
CONFIG_VIRTIO_MMIO=m
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO_DMA_SHARED_BUFFER=m
# CONFIG_VIRTIO_DEBUG is not set
# CONFIG_VIRTIO_RTC is not set
CONFIG_VDPA=m
CONFIG_VDPA_SIM=m
CONFIG_VDPA_SIM_NET=m
CONFIG_VDPA_SIM_BLOCK=m
CONFIG_IFCVF=m
CONFIG_MLX5_VDPA=y
CONFIG_MLX5_VDPA_NET=m
# CONFIG_MLX5_VDPA_STEERING_DEBUG is not set
CONFIG_VP_VDPA=m
CONFIG_SNET_VDPA=m
CONFIG_PDS_VDPA=m
CONFIG_OCTEONEP_VDPA=m
CONFIG_VHOST_IOTLB=m
CONFIG_VHOST_RING=m
CONFIG_VHOST_TASK=y
CONFIG_VHOST=m
CONFIG_VHOST_MENU=y
CONFIG_VHOST_NET=m
CONFIG_VHOST_SCSI=m
CONFIG_VHOST_VSOCK=m
CONFIG_VHOST_VDPA=m
# CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set
CONFIG_VHOST_ENABLE_FORK_OWNER_CONTROL=y

#
# Microsoft Hyper-V guest support
#
CONFIG_HYPERV=m
# CONFIG_HYPERV_VTL_MODE is not set
CONFIG_HYPERV_UTILS=m
CONFIG_HYPERV_BALLOON=m
CONFIG_MSHV_ROOT=m
# end of Microsoft Hyper-V guest support

# CONFIG_GREYBUS is not set
# CONFIG_COMEDI is not set
CONFIG_STAGING=y
CONFIG_RTL8723BS=m

#
# IIO staging drivers
#

#
# Accelerometers
#
# CONFIG_ADIS16203 is not set
# end of Accelerometers

#
# Analog to digital converters
#
# CONFIG_AD7816 is not set
# end of Analog to digital converters

#
# Analog digital bi-direction converters
#
# CONFIG_ADT7316 is not set
# end of Analog digital bi-direction converters

#
# Direct Digital Synthesis
#
# CONFIG_AD9832 is not set
# CONFIG_AD9834 is not set
# end of Direct Digital Synthesis

#
# Network Analyzer, Impedance Converters
#
# CONFIG_AD5933 is not set
# end of Network Analyzer, Impedance Converters
# end of IIO staging drivers

# CONFIG_FB_SM750 is not set
# CONFIG_MFD_NVEC is not set
CONFIG_STAGING_MEDIA=y
# CONFIG_DVB_AV7110 is not set
CONFIG_VIDEO_MAX96712=m
CONFIG_VIDEO_MESON_VDEC=m

#
# StarFive media platform drivers
#
CONFIG_VIDEO_SUNXI=y
CONFIG_VIDEO_SUNXI_CEDRUS=m
CONFIG_VIDEO_SUN6I_ISP=m
CONFIG_VIDEO_TEGRA=m
# CONFIG_VIDEO_TEGRA_TPG is not set
# CONFIG_STAGING_MEDIA_DEPRECATED is not set
CONFIG_BCM_VIDEOCORE=m
CONFIG_BCM2835_VCHIQ=m
CONFIG_VCHIQ_CDEV=y
CONFIG_SND_BCM2835=m
CONFIG_VIDEO_BCM2835=m
CONFIG_BCM2835_VCHIQ_MMAL=m
# CONFIG_XIL_AXIS_FIFO is not set
# CONFIG_VME_BUS is not set
# CONFIG_GPIB is not set
# CONFIG_GOLDFISH is not set
CONFIG_CHROME_PLATFORMS=y
CONFIG_CHROMEOS_ACPI=m
CONFIG_CHROMEOS_TBMC=y
CONFIG_CHROMEOS_OF_HW_PROBER=y
CONFIG_CROS_EC=m
CONFIG_CROS_EC_I2C=m
CONFIG_CROS_EC_RPMSG=m
CONFIG_CROS_EC_SPI=m
CONFIG_CROS_EC_UART=m
CONFIG_CROS_EC_PROTO=m
CONFIG_CROS_KBD_LED_BACKLIGHT=m
CONFIG_CROS_EC_CHARDEV=m
# CONFIG_CROS_EC_LIGHTBAR is not set
CONFIG_CROS_EC_VBC=m
# CONFIG_CROS_EC_DEBUGFS is not set
CONFIG_CROS_EC_SENSORHUB=m
CONFIG_CROS_EC_SYSFS=m
CONFIG_CROS_EC_TYPEC_ALTMODES=y
CONFIG_CROS_EC_TYPEC=m
CONFIG_CROS_HPS_I2C=m
CONFIG_CROS_USBPD_LOGGER=m
CONFIG_CROS_USBPD_NOTIFY=m
CONFIG_CHROMEOS_PRIVACY_SCREEN=m
CONFIG_CROS_TYPEC_SWITCH=m
CONFIG_CROS_KUNIT_EC_PROTO_TEST=m
CONFIG_CZNIC_PLATFORMS=y
CONFIG_TURRIS_SIGNING_KEY=m
CONFIG_MELLANOX_PLATFORM=y
CONFIG_MLX_PLATFORM=m
# CONFIG_MLXREG_DPU is not set
CONFIG_MLXREG_HOTPLUG=m
CONFIG_MLXREG_IO=m
CONFIG_MLXREG_LC=m
CONFIG_MLXBF_TMFIFO=m
CONFIG_MLXBF_BOOTCTL=m
CONFIG_MLXBF_PMC=m
# CONFIG_NVSW_SN2201 is not set
CONFIG_SURFACE_PLATFORMS=y
# CONFIG_SURFACE_3_POWER_OPREGION is not set
CONFIG_SURFACE_ACPI_NOTIFY=m
CONFIG_SURFACE_AGGREGATOR_CDEV=m
CONFIG_SURFACE_AGGREGATOR_HUB=m
CONFIG_SURFACE_AGGREGATOR_REGISTRY=m
CONFIG_SURFACE_AGGREGATOR_TABLET_SWITCH=m
CONFIG_SURFACE_DTX=m
CONFIG_SURFACE_GPE=m
CONFIG_SURFACE_HOTPLUG=m
CONFIG_SURFACE_PLATFORM_PROFILE=m
CONFIG_SURFACE_PRO3_BUTTON=m
CONFIG_SURFACE_AGGREGATOR=m
CONFIG_SURFACE_AGGREGATOR_BUS=y
# CONFIG_SERIAL_MULTI_INSTANTIATE is not set
CONFIG_ARM64_PLATFORM_DEVICES=y
CONFIG_EC_ACER_ASPIRE1=m
# CONFIG_EC_HUAWEI_GAOKUN is not set
CONFIG_EC_LENOVO_YOGA_C630=m
CONFIG_HAVE_CLK=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y

#
# Clock driver for ARM Reference designs
#
CONFIG_CLK_ICST=y
CONFIG_CLK_SP810=y
CONFIG_CLK_VEXPRESS_OSC=y
# end of Clock driver for ARM Reference designs

# CONFIG_LMK04832 is not set
CONFIG_COMMON_CLK_APPLE_NCO=m
CONFIG_COMMON_CLK_MAX77686=y
# CONFIG_COMMON_CLK_MAX9485 is not set
CONFIG_COMMON_CLK_RK808=m
CONFIG_COMMON_CLK_HI655X=m
CONFIG_COMMON_CLK_SCMI=y
CONFIG_COMMON_CLK_SCPI=m
CONFIG_COMMON_CLK_SI5341=m
# CONFIG_COMMON_CLK_SI5351 is not set
# CONFIG_COMMON_CLK_SI514 is not set
CONFIG_COMMON_CLK_SI544=m
# CONFIG_COMMON_CLK_SI570 is not set
# CONFIG_COMMON_CLK_CDCE706 is not set
# CONFIG_COMMON_CLK_CDCE925 is not set
# CONFIG_COMMON_CLK_CS2000_CP is not set
CONFIG_COMMON_CLK_FSL_FLEXSPI=m
# CONFIG_COMMON_CLK_FSL_SAI is not set
CONFIG_COMMON_CLK_AXI_CLKGEN=m
CONFIG_CLK_QORIQ=y
CONFIG_CLK_LS1028A_PLLDIG=y
CONFIG_COMMON_CLK_XGENE=y
CONFIG_COMMON_CLK_PWM=m
CONFIG_COMMON_CLK_RS9_PCIE=m
CONFIG_COMMON_CLK_SI521XX=y
CONFIG_COMMON_CLK_VC3=m
# CONFIG_COMMON_CLK_VC5 is not set
CONFIG_COMMON_CLK_VC7=m
CONFIG_COMMON_CLK_BD718XX=m
# CONFIG_COMMON_CLK_FIXED_MMIO is not set
CONFIG_CLK_BCM2711_DVP=m
CONFIG_CLK_BCM2835=y
CONFIG_CLK_RASPBERRYPI=y
# CONFIG_COMMON_CLK_HI3516CV300 is not set
CONFIG_COMMON_CLK_HI3519=m
CONFIG_COMMON_CLK_HI3559A=y
CONFIG_COMMON_CLK_HI3660=y
CONFIG_COMMON_CLK_HI3670=y
# CONFIG_COMMON_CLK_HI3798CV200 is not set
CONFIG_COMMON_CLK_HI6220=y
CONFIG_RESET_HISI=y
CONFIG_STUB_CLK_HI6220=y
CONFIG_STUB_CLK_HI3660=y
CONFIG_MXC_CLK=y
CONFIG_MXC_CLK_SCU=y
CONFIG_CLK_IMX8MM=y
CONFIG_CLK_IMX8MN=y
CONFIG_CLK_IMX8MP=y
CONFIG_CLK_IMX8MQ=y
CONFIG_CLK_IMX8QXP=y
CONFIG_CLK_IMX8ULP=y
CONFIG_CLK_IMX93=y
CONFIG_CLK_IMX95_BLK_CTL=m
CONFIG_TI_SCI_CLK=y
# CONFIG_TI_SCI_CLK_PROBE_FROM_FW is not set
CONFIG_TI_SYSCON_CLK=m

#
# Clock support for Amlogic platforms
#
CONFIG_COMMON_CLK_MESON_REGMAP=y
CONFIG_COMMON_CLK_MESON_DUALDIV=y
CONFIG_COMMON_CLK_MESON_MPLL=y
CONFIG_COMMON_CLK_MESON_PHASE=y
CONFIG_COMMON_CLK_MESON_PLL=y
CONFIG_COMMON_CLK_MESON_SCLK_DIV=y
CONFIG_COMMON_CLK_MESON_VID_PLL_DIV=y
CONFIG_COMMON_CLK_MESON_VCLK=y
CONFIG_COMMON_CLK_MESON_CLKC_UTILS=y
CONFIG_COMMON_CLK_MESON_AO_CLKC=y
CONFIG_COMMON_CLK_MESON_EE_CLKC=y
CONFIG_COMMON_CLK_MESON_CPU_DYNDIV=y
CONFIG_COMMON_CLK_GXBB=y
CONFIG_COMMON_CLK_AXG=y
CONFIG_COMMON_CLK_AXG_AUDIO=y
# CONFIG_COMMON_CLK_A1_PLL is not set
# CONFIG_COMMON_CLK_A1_PERIPHERALS is not set
CONFIG_COMMON_CLK_C3_PLL=y
CONFIG_COMMON_CLK_C3_PERIPHERALS=y
CONFIG_COMMON_CLK_G12A=y
CONFIG_COMMON_CLK_S4_PLL=y
CONFIG_COMMON_CLK_S4_PERIPHERALS=y
# end of Clock support for Amlogic platforms

CONFIG_ARMADA_AP_CP_HELPER=y
CONFIG_ARMADA_37XX_CLK=y
CONFIG_ARMADA_AP806_SYSCON=y
CONFIG_ARMADA_AP_CPU_CLK=y
CONFIG_ARMADA_CP110_SYSCON=y
CONFIG_QCOM_GDSC=y
CONFIG_COMMON_CLK_QCOM=y
CONFIG_CLK_X1E80100_CAMCC=m
CONFIG_CLK_X1E80100_DISPCC=m
CONFIG_CLK_X1E80100_GCC=y
CONFIG_CLK_X1E80100_GPUCC=m
CONFIG_CLK_X1E80100_TCSRCC=y
# CONFIG_CLK_X1P42100_GPUCC is not set
CONFIG_CLK_QCM2290_GPUCC=m
CONFIG_QCOM_A53PLL=m
# CONFIG_QCOM_A7PLL is not set
CONFIG_QCOM_CLK_APCS_MSM8916=m
# CONFIG_QCOM_CLK_APCC_MSM8996 is not set
CONFIG_QCOM_CLK_SMD_RPM=m
CONFIG_QCOM_CLK_RPMH=y
# CONFIG_IPQ_APSS_PLL is not set
# CONFIG_IPQ_APSS_6018 is not set
CONFIG_IPQ_CMN_PLL=m
# CONFIG_IPQ_GCC_4019 is not set
CONFIG_IPQ_GCC_5018=m
# CONFIG_IPQ_GCC_5332 is not set
# CONFIG_IPQ_GCC_5424 is not set
# CONFIG_IPQ_GCC_6018 is not set
# CONFIG_IPQ_GCC_8074 is not set
# CONFIG_IPQ_GCC_9574 is not set
CONFIG_IPQ_NSSCC_QCA8K=m
CONFIG_MSM_GCC_8916=y
# CONFIG_MSM_GCC_8917 is not set
CONFIG_MSM_GCC_8939=m
# CONFIG_MSM_GCC_8953 is not set
# CONFIG_MSM_GCC_8976 is not set
# CONFIG_MSM_MMCC_8994 is not set
# CONFIG_MSM_GCC_8994 is not set
CONFIG_MSM_GCC_8996=y
CONFIG_MSM_MMCC_8996=m
CONFIG_MSM_GCC_8998=y
CONFIG_MSM_GPUCC_8998=m
# CONFIG_MSM_MMCC_8998 is not set
CONFIG_QCM_GCC_2290=m
# CONFIG_QCM_DISPCC_2290 is not set
# CONFIG_QCS_DISPCC_615 is not set
# CONFIG_QCS_CAMCC_615 is not set
CONFIG_QCS_GCC_404=m
CONFIG_SA_CAMCC_8775P=m
# CONFIG_QCS_GCC_8300 is not set
# CONFIG_QCS_GCC_615 is not set
# CONFIG_QCS_GPUCC_615 is not set
# CONFIG_QCS_VIDEOCC_615 is not set
CONFIG_SC_CAMCC_7180=m
CONFIG_SC_CAMCC_7280=m
# CONFIG_SC_CAMCC_8180X is not set
CONFIG_SC_CAMCC_8280XP=m
CONFIG_SA_DISPCC_8775P=m
CONFIG_SC_DISPCC_7180=m
CONFIG_SC_DISPCC_7280=m
CONFIG_SC_DISPCC_8280XP=m
CONFIG_SA_GCC_8775P=y
CONFIG_SA_GPUCC_8775P=m
# CONFIG_SAR_GCC_2130P is not set
# CONFIG_SAR_GPUCC_2130P is not set
CONFIG_SC_GCC_7180=y
CONFIG_SC_GCC_7280=y
# CONFIG_SC_GCC_8180X is not set
CONFIG_SC_GCC_8280XP=y
CONFIG_SC_GPUCC_7180=m
CONFIG_SC_GPUCC_7280=m
CONFIG_SC_GPUCC_8280XP=m
CONFIG_SC_LPASSCC_7280=m
CONFIG_SC_LPASSCC_8280XP=m
CONFIG_SC_LPASS_CORECC_7180=m
CONFIG_SC_LPASS_CORECC_7280=m
CONFIG_SC_VIDEOCC_7180=m
CONFIG_SC_VIDEOCC_7280=m
CONFIG_SDM_CAMCC_845=m
CONFIG_SDM_GCC_660=m
# CONFIG_SDM_MMCC_660 is not set
# CONFIG_SDM_GPUCC_660 is not set
# CONFIG_QCS_TURING_404 is not set
# CONFIG_QCS_Q6SSTOP_404 is not set
# CONFIG_QDU_GCC_1000 is not set
# CONFIG_QDU_ECPRICC_1000 is not set
CONFIG_SDM_GCC_845=m
CONFIG_SDM_GPUCC_845=m
CONFIG_SDM_VIDEOCC_845=m
CONFIG_SDM_DISPCC_845=m
CONFIG_SDM_LPASSCC_845=m
# CONFIG_SDX_GCC_75 is not set
# CONFIG_SM_CAMCC_4450 is not set
# CONFIG_SM_CAMCC_6350 is not set
CONFIG_SM_CAMCC_7150=m
# CONFIG_SM_CAMCC_MILOS is not set
# CONFIG_SM_CAMCC_8150 is not set
CONFIG_SM_CAMCC_8250=m
# CONFIG_SM_CAMCC_8450 is not set
# CONFIG_SM_CAMCC_8550 is not set
CONFIG_SM_CAMCC_8650=m
CONFIG_SM_DISPCC_6115=m
CONFIG_SM_DISPCC_7150=m
CONFIG_SM_DISPCC_8250=m
CONFIG_SM_DISPCC_8450=m
# CONFIG_SM_DISPCC_8550 is not set
# CONFIG_SM_GCC_4450 is not set
CONFIG_SM_GCC_6115=m
# CONFIG_SM_GCC_6125 is not set
# CONFIG_SM_GCC_6350 is not set
# CONFIG_SM_GCC_6375 is not set
CONFIG_SM_GCC_7150=m
# CONFIG_SM_GCC_MILOS is not set
CONFIG_SM_GCC_8150=y
CONFIG_SM_GCC_8250=m
CONFIG_SM_GCC_8350=m
CONFIG_SM_GCC_8450=m
CONFIG_SM_GCC_8550=m
CONFIG_SM_GCC_8650=m
# CONFIG_SM_GCC_8750 is not set
# CONFIG_SM_GPUCC_4450 is not set
CONFIG_SM_GPUCC_6115=m
# CONFIG_SM_GPUCC_6125 is not set
# CONFIG_SM_GPUCC_6375 is not set
# CONFIG_SM_GPUCC_6350 is not set
# CONFIG_SM_GPUCC_MILOS is not set
# CONFIG_SM_GPUCC_8150 is not set
# CONFIG_SM_GPUCC_8250 is not set
# CONFIG_SM_GPUCC_8350 is not set
# CONFIG_SM_GPUCC_8450 is not set
# CONFIG_SM_GPUCC_8550 is not set
CONFIG_SM_GPUCC_8650=m
# CONFIG_SM_LPASSCC_6115 is not set
# CONFIG_SM_TCSRCC_8550 is not set
CONFIG_SM_TCSRCC_8650=m
# CONFIG_SM_TCSRCC_8750 is not set
CONFIG_SA_VIDEOCC_8775P=m
# CONFIG_SM_VIDEOCC_6350 is not set
CONFIG_SM_VIDEOCC_7150=m
# CONFIG_SM_VIDEOCC_MILOS is not set
# CONFIG_SM_VIDEOCC_8150 is not set
CONFIG_SM_VIDEOCC_8250=m
CONFIG_SM_VIDEOCC_8350=m
# CONFIG_SM_VIDEOCC_8550 is not set
CONFIG_SPMI_PMIC_CLKDIV=m
CONFIG_QCOM_HFPLL=m
CONFIG_KPSS_XCC=m
CONFIG_CLK_GFM_LPASS_SM8250=m
# CONFIG_SM_VIDEOCC_8450 is not set
CONFIG_CLK_RENESAS=y
CONFIG_CLK_R8A774A1=y
CONFIG_CLK_R9A07G043=y
CONFIG_CLK_R9A07G044=y
CONFIG_CLK_R9A07G054=y
CONFIG_CLK_R9A08G045=y
CONFIG_CLK_R9A09G011=y
CONFIG_CLK_R9A09G056=y
CONFIG_CLK_R9A09G057=y
CONFIG_CLK_R9A09G077=y
CONFIG_CLK_R9A09G087=y
CONFIG_CLK_RCAR_CPG_LIB=y
CONFIG_CLK_RCAR_GEN3_CPG=y
# CONFIG_CLK_RCAR_USB2_CLOCK_SEL is not set
CONFIG_CLK_RZG2L=y
CONFIG_CLK_RZV2H=y
# CONFIG_CLK_RENESAS_VBATTB is not set
CONFIG_CLK_RENESAS_CPG_MSSR=y
CONFIG_CLK_RENESAS_DIV6=y
CONFIG_COMMON_CLK_ROCKCHIP=y
CONFIG_CLK_PX30=y
CONFIG_CLK_RK3308=y
CONFIG_CLK_RK3328=y
CONFIG_CLK_RK3368=y
CONFIG_CLK_RK3399=y
CONFIG_CLK_RK3528=y
CONFIG_CLK_RK3562=y
CONFIG_CLK_RK3568=y
CONFIG_CLK_RK3576=y
CONFIG_CLK_RK3588=y
CONFIG_SUNXI_CCU=y
CONFIG_SUN50I_A64_CCU=y
CONFIG_SUN50I_A100_CCU=y
CONFIG_SUN50I_A100_R_CCU=y
CONFIG_SUN50I_H6_CCU=y
CONFIG_SUN50I_H616_CCU=y
CONFIG_SUN50I_H6_R_CCU=y
CONFIG_SUN55I_A523_CCU=m
CONFIG_SUN55I_A523_R_CCU=m
CONFIG_SUN6I_RTC_CCU=y
CONFIG_SUN8I_H3_CCU=y
CONFIG_SUN8I_DE2_CCU=y
CONFIG_SUN8I_R_CCU=y
CONFIG_CLK_TEGRA_BPMP=y
CONFIG_TEGRA_CLK_DFLL=y
CONFIG_XILINX_VCU=m
# CONFIG_COMMON_CLK_XLNX_CLKWZRD is not set
CONFIG_COMMON_CLK_ZYNQMP=y
CONFIG_CLK_KUNIT_TEST=m
CONFIG_CLK_FIXED_RATE_KUNIT_TEST=m
CONFIG_CLK_GATE_KUNIT_TEST=m
CONFIG_CLK_FD_KUNIT_TEST=m
CONFIG_HWSPINLOCK=y
CONFIG_HWSPINLOCK_OMAP=m
CONFIG_HWSPINLOCK_QCOM=m
CONFIG_HWSPINLOCK_SUN6I=m

#
# Clock Source drivers
#
CONFIG_TIMER_OF=y
CONFIG_TIMER_ACPI=y
CONFIG_TIMER_PROBE=y
CONFIG_CLKSRC_MMIO=y
CONFIG_OMAP_DM_TIMER=y
CONFIG_ROCKCHIP_TIMER=y
CONFIG_SUN4I_TIMER=y
CONFIG_TEGRA_TIMER=y
CONFIG_TEGRA186_TIMER=y
CONFIG_ARM_ARCH_TIMER=y
CONFIG_ARM_ARCH_TIMER_EVTSTREAM=y
CONFIG_ARM_ARCH_TIMER_OOL_WORKAROUND=y
CONFIG_FSL_ERRATUM_A008585=y
CONFIG_HISILICON_ERRATUM_161010101=y
CONFIG_ARM64_ERRATUM_858921=y
CONFIG_SUN50I_ERRATUM_UNKNOWN1=y
CONFIG_ARM_TIMER_SP804=y
CONFIG_SYS_SUPPORTS_SH_CMT=y
CONFIG_SYS_SUPPORTS_SH_TMU=y
CONFIG_SH_TIMER_CMT=y
CONFIG_RENESAS_OSTM=y
CONFIG_SH_TIMER_TMU=y
CONFIG_TIMER_IMX_SYS_CTR=y
# CONFIG_NXP_STM_TIMER is not set
# end of Clock Source drivers

CONFIG_MAILBOX=y
CONFIG_ARM_MHU=m
# CONFIG_ARM_MHU_V2 is not set
CONFIG_ARM_MHU_V3=m
CONFIG_IMX_MBOX=m
CONFIG_PLATFORM_MHU=m
# CONFIG_PL320_MBOX is not set
CONFIG_ARMADA_37XX_RWTM_MBOX=m
CONFIG_OMAP2PLUS_MBOX=m
CONFIG_ROCKCHIP_MBOX=y
CONFIG_PCC=y
# CONFIG_ALTERA_MBOX is not set
CONFIG_BCM2835_MBOX=y
CONFIG_TI_MESSAGE_MANAGER=y
CONFIG_HI3660_MBOX=y
CONFIG_HI6220_MBOX=y
# CONFIG_MAILBOX_TEST is not set
CONFIG_QCOM_APCS_IPC=m
CONFIG_TEGRA_HSP_MBOX=y
CONFIG_XGENE_SLIMPRO_MBOX=m
CONFIG_ZYNQMP_IPI_MBOX=y
CONFIG_SUN6I_MSGBOX=y
CONFIG_QCOM_CPUCP_MBOX=m
CONFIG_QCOM_IPCC=m
CONFIG_IOMMU_IOVA=y
CONFIG_IOMMU_API=y
CONFIG_IOMMUFD_DRIVER=y
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
CONFIG_IOMMU_IO_PGTABLE=y
CONFIG_IOMMU_IO_PGTABLE_LPAE=y
# CONFIG_IOMMU_IO_PGTABLE_LPAE_SELFTEST is not set
# CONFIG_IOMMU_IO_PGTABLE_ARMV7S is not set
CONFIG_IOMMU_IO_PGTABLE_DART=y
# end of Generic IOMMU Pagetable Support

# CONFIG_IOMMU_DEBUGFS is not set
# CONFIG_IOMMU_DEFAULT_DMA_STRICT is not set
CONFIG_IOMMU_DEFAULT_DMA_LAZY=y
# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
CONFIG_OF_IOMMU=y
CONFIG_IOMMU_DMA=y
CONFIG_IOMMU_SVA=y
CONFIG_IOMMU_IOPF=y
CONFIG_ARM_SMMU=y
# CONFIG_ARM_SMMU_LEGACY_DT_BINDINGS is not set
CONFIG_ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT=y
CONFIG_ARM_SMMU_MMU_500_CPRE_ERRATA=y
CONFIG_ARM_SMMU_QCOM=y
# CONFIG_ARM_SMMU_QCOM_DEBUG is not set
CONFIG_ARM_SMMU_V3=y
CONFIG_ARM_SMMU_V3_SVA=y
CONFIG_ARM_SMMU_V3_IOMMUFD=y
CONFIG_ARM_SMMU_V3_KUNIT_TEST=m
CONFIG_TEGRA241_CMDQV=y
CONFIG_QCOM_IOMMU=y
CONFIG_IOMMUFD_DRIVER_CORE=y
CONFIG_IOMMUFD=m
CONFIG_ROCKCHIP_IOMMU=y
CONFIG_SUN50I_IOMMU=y
CONFIG_TEGRA_IOMMU_SMMU=y
# CONFIG_IPMMU_VMSA is not set
CONFIG_APPLE_DART=m
CONFIG_VIRTIO_IOMMU=y

#
# Remoteproc drivers
#
CONFIG_REMOTEPROC=y
# CONFIG_REMOTEPROC_CDEV is not set
CONFIG_IMX_REMOTEPROC=m
CONFIG_IMX_DSP_REMOTEPROC=m
CONFIG_PRU_REMOTEPROC=m
CONFIG_QCOM_PIL_INFO=m
CONFIG_QCOM_RPROC_COMMON=m
CONFIG_QCOM_Q6V5_COMMON=m
CONFIG_QCOM_Q6V5_ADSP=m
CONFIG_QCOM_Q6V5_MSS=m
CONFIG_QCOM_Q6V5_PAS=m
CONFIG_QCOM_Q6V5_WCSS=m
CONFIG_QCOM_SYSMON=m
CONFIG_QCOM_WCNSS_PIL=m
# CONFIG_RCAR_REMOTEPROC is not set
CONFIG_TI_K3_DSP_REMOTEPROC=m
CONFIG_TI_K3_M4_REMOTEPROC=m
CONFIG_TI_K3_R5_REMOTEPROC=m
CONFIG_XLNX_R5_REMOTEPROC=m
# end of Remoteproc drivers

#
# Rpmsg drivers
#
CONFIG_RPMSG=m
CONFIG_RPMSG_CHAR=m
CONFIG_RPMSG_CTRL=m
CONFIG_RPMSG_NS=m
CONFIG_RPMSG_QCOM_GLINK=m
CONFIG_RPMSG_QCOM_GLINK_RPM=m
CONFIG_RPMSG_QCOM_GLINK_SMEM=m
CONFIG_RPMSG_QCOM_SMD=m
CONFIG_RPMSG_VIRTIO=m
# end of Rpmsg drivers

CONFIG_SOUNDWIRE=m

#
# SoundWire Devices
#
# CONFIG_SOUNDWIRE_AMD is not set
# CONFIG_SOUNDWIRE_INTEL is not set
CONFIG_SOUNDWIRE_QCOM=m

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#
CONFIG_MESON_CANVAS=m
# CONFIG_MESON_CLK_MEASURE is not set
CONFIG_MESON_GX_SOCINFO=y
# end of Amlogic SoC drivers

#
# Apple SoC drivers
#
CONFIG_APPLE_MAILBOX=m
CONFIG_APPLE_RTKIT=m
CONFIG_APPLE_SART=m
# end of Apple SoC drivers

#
# Broadcom SoC drivers
#
# end of Broadcom SoC drivers

#
# NXP/Freescale QorIQ SoC drivers
#
CONFIG_FSL_DPAA=y
# CONFIG_FSL_DPAA_CHECKING is not set
# CONFIG_FSL_BMAN_TEST is not set
# CONFIG_FSL_QMAN_TEST is not set
# CONFIG_QUICC_ENGINE is not set
CONFIG_FSL_GUTS=y
CONFIG_FSL_MC_DPIO=m
CONFIG_DPAA2_CONSOLE=m
CONFIG_FSL_RCPM=y
# end of NXP/Freescale QorIQ SoC drivers

#
# fujitsu SoC drivers
#
CONFIG_A64FX_DIAG=y
# end of fujitsu SoC drivers

#
# Hisilicon SoC drivers
#
# CONFIG_KUNPENG_HCCS is not set
# end of Hisilicon SoC drivers

#
# i.MX SoC drivers
#
CONFIG_SOC_IMX8M=y
CONFIG_SOC_IMX9=m
# end of i.MX SoC drivers

#
# Enable LiteX SoC Builder specific drivers
#
# CONFIG_LITEX_SOC_CONTROLLER is not set
# end of Enable LiteX SoC Builder specific drivers

CONFIG_WPCM450_SOC=m

#
# Qualcomm SoC drivers
#
CONFIG_QCOM_AOSS_QMP=m
CONFIG_QCOM_COMMAND_DB=y
CONFIG_QCOM_GENI_SE=y
CONFIG_QCOM_GSBI=y
CONFIG_QCOM_LLCC=m
CONFIG_QCOM_KRYO_L2_ACCESSORS=y
CONFIG_QCOM_MDT_LOADER=m
CONFIG_QCOM_OCMEM=m
CONFIG_QCOM_PD_MAPPER=m
CONFIG_QCOM_PDR_HELPERS=m
CONFIG_QCOM_PDR_MSG=m
CONFIG_QCOM_PMIC_PDCHARGER_ULOG=m
CONFIG_QCOM_PMIC_GLINK=m
CONFIG_QCOM_QMI_HELPERS=m
CONFIG_QCOM_RAMP_CTRL=m
CONFIG_QCOM_RMTFS_MEM=m
CONFIG_QCOM_RPM_MASTER_STATS=m
CONFIG_QCOM_RPMH=y
CONFIG_QCOM_SMEM=m
CONFIG_QCOM_SMD_RPM=m
CONFIG_QCOM_SMEM_STATE=y
CONFIG_QCOM_SMP2P=m
CONFIG_QCOM_SMSM=m
CONFIG_QCOM_SOCINFO=m
CONFIG_QCOM_SPM=y
CONFIG_QCOM_STATS=m
CONFIG_QCOM_WCNSS_CTRL=m
CONFIG_QCOM_APR=m
CONFIG_QCOM_ICC_BWMON=m
CONFIG_QCOM_INLINE_CRYPTO_ENGINE=m
CONFIG_QCOM_PBS=m
# end of Qualcomm SoC drivers

CONFIG_QCOM_UBWC_CONFIG=m
CONFIG_SOC_RENESAS=y
CONFIG_ARCH_RCAR_GEN3=y
CONFIG_ARCH_RZG2L=y
CONFIG_ARCH_R8A774A1=y
# CONFIG_ARCH_R8A774B1 is not set
# CONFIG_ARCH_R8A774C0 is not set
# CONFIG_ARCH_R8A774E1 is not set
# CONFIG_ARCH_R8A77951 is not set
# CONFIG_ARCH_R8A77960 is not set
# CONFIG_ARCH_R8A77961 is not set
# CONFIG_ARCH_R8A77965 is not set
# CONFIG_ARCH_R8A77970 is not set
# CONFIG_ARCH_R8A77980 is not set
# CONFIG_ARCH_R8A77990 is not set
# CONFIG_ARCH_R8A77995 is not set
# CONFIG_ARCH_R8A779A0 is not set
# CONFIG_ARCH_R8A779F0 is not set
# CONFIG_ARCH_R8A779G0 is not set
# CONFIG_ARCH_R8A779H0 is not set
CONFIG_ARCH_R9A07G043=y
CONFIG_ARCH_R9A07G044=y
CONFIG_ARCH_R9A07G054=y
CONFIG_ARCH_R9A08G045=y
CONFIG_ARCH_R9A09G011=y
# CONFIG_ARCH_R9A09G047 is not set
CONFIG_ARCH_R9A09G056=y
CONFIG_ARCH_R9A09G057=y
CONFIG_ARCH_R9A09G077=y
CONFIG_ARCH_R9A09G087=y
CONFIG_PWC_RZV2M=y
CONFIG_RST_RCAR=y
CONFIG_SYSC_RZ=y
CONFIG_SYSC_R9A08G045=y
CONFIG_SYS_R9A09G056=y
CONFIG_SYS_R9A09G057=y
CONFIG_ROCKCHIP_GRF=y
CONFIG_ROCKCHIP_IODOMAIN=m
CONFIG_ROCKCHIP_DTPM=m
CONFIG_SUNXI_MBUS=y
CONFIG_SUNXI_SRAM=y
CONFIG_ARCH_TEGRA_132_SOC=y
CONFIG_ARCH_TEGRA_210_SOC=y
CONFIG_ARCH_TEGRA_186_SOC=y
CONFIG_ARCH_TEGRA_194_SOC=y
CONFIG_ARCH_TEGRA_234_SOC=y
CONFIG_ARCH_TEGRA_241_SOC=y
# CONFIG_ARCH_TEGRA_264_SOC is not set
CONFIG_SOC_TEGRA_FUSE=y
CONFIG_SOC_TEGRA_FLOWCTRL=y
CONFIG_SOC_TEGRA_PMC=y
CONFIG_SOC_TEGRA_CBB=m
CONFIG_SOC_TI=y
CONFIG_TI_K3_RINGACC=m
CONFIG_TI_K3_SOCINFO=y
CONFIG_TI_PRUSS=m
CONFIG_TI_SCI_INTA_MSI_DOMAIN=y

#
# Xilinx SoC drivers
#
CONFIG_ZYNQMP_POWER=y
CONFIG_XLNX_EVENT_MANAGER=y
# end of Xilinx SoC drivers
# end of SOC (System On Chip) specific Drivers

#
# PM Domains
#

#
# Amlogic PM Domains
#
CONFIG_MESON_EE_PM_DOMAINS=y
CONFIG_MESON_SECURE_PM_DOMAINS=y
# end of Amlogic PM Domains

CONFIG_APPLE_PMGR_PWRSTATE=y
CONFIG_ARM_SCMI_PERF_DOMAIN=y
CONFIG_ARM_SCMI_POWER_DOMAIN=y
CONFIG_ARM_SCPI_POWER_DOMAIN=m

#
# Broadcom PM Domains
#
CONFIG_BCM2835_POWER=y
CONFIG_RASPBERRYPI_POWER=y
# end of Broadcom PM Domains

#
# i.MX PM Domains
#
CONFIG_IMX_GPCV2_PM_DOMAINS=y
CONFIG_IMX8M_BLK_CTRL=y
CONFIG_IMX9_BLK_CTRL=y
CONFIG_IMX_SCU_PD=y
# end of i.MX PM Domains

#
# Qualcomm PM Domains
#
CONFIG_QCOM_CPR=m
CONFIG_QCOM_RPMHPD=y
CONFIG_QCOM_RPMPD=m
# end of Qualcomm PM Domains

#
# Renesas PM Domains
#
CONFIG_SYSC_RCAR=y
CONFIG_SYSC_R8A774A1=y
# end of Renesas PM Domains

CONFIG_ROCKCHIP_PM_DOMAINS=y
# CONFIG_SUN20I_PPU is not set
# CONFIG_SUN50I_H6_PRCM_PPU is not set
CONFIG_SUN55I_PCK600=y
CONFIG_SOC_TEGRA_POWERGATE_BPMP=y
CONFIG_TI_SCI_PM_DOMAINS=y
CONFIG_ZYNQMP_PM_DOMAINS=y
# end of PM Domains

CONFIG_PM_DEVFREQ=y

#
# DEVFREQ Governors
#
CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=m
CONFIG_DEVFREQ_GOV_PERFORMANCE=m
CONFIG_DEVFREQ_GOV_POWERSAVE=m
CONFIG_DEVFREQ_GOV_USERSPACE=m
CONFIG_DEVFREQ_GOV_PASSIVE=m

#
# DEVFREQ Drivers
#
# CONFIG_ARM_HISI_UNCORE_DEVFREQ is not set
CONFIG_ARM_IMX_BUS_DEVFREQ=m
CONFIG_ARM_IMX8M_DDRC_DEVFREQ=m
CONFIG_ARM_TEGRA_DEVFREQ=m
CONFIG_ARM_RK3399_DMC_DEVFREQ=m
CONFIG_ARM_SUN8I_A33_MBUS_DEVFREQ=m
CONFIG_PM_DEVFREQ_EVENT=y
CONFIG_DEVFREQ_EVENT_ROCKCHIP_DFI=m
CONFIG_EXTCON=y

#
# Extcon Device Drivers
#
CONFIG_EXTCON_ADC_JACK=m
# CONFIG_EXTCON_FSA9480 is not set
CONFIG_EXTCON_GPIO=m
CONFIG_EXTCON_LC824206XA=m
# CONFIG_EXTCON_MAX3355 is not set
CONFIG_EXTCON_PTN5150=m
# CONFIG_EXTCON_QCOM_SPMI_MISC is not set
# CONFIG_EXTCON_RT8973A is not set
CONFIG_EXTCON_SM5502=m
CONFIG_EXTCON_USB_GPIO=m
CONFIG_EXTCON_USBC_CROS_EC=m
CONFIG_EXTCON_USBC_TUSB320=m
CONFIG_MEMORY=y
CONFIG_ARM_PL172_MPMC=m
CONFIG_OMAP_GPMC=y
# CONFIG_OMAP_GPMC_DEBUG is not set
CONFIG_FPGA_DFL_EMIF=m
# CONFIG_FSL_IFC is not set
# CONFIG_RENESAS_RPCIF is not set
CONFIG_TEGRA_MC=y
CONFIG_TEGRA210_EMC_TABLE=y
CONFIG_TEGRA210_EMC=m
CONFIG_IIO=m
CONFIG_IIO_BUFFER=y
CONFIG_IIO_BUFFER_CB=m
CONFIG_IIO_BUFFER_DMA=m
CONFIG_IIO_BUFFER_DMAENGINE=m
CONFIG_IIO_BUFFER_HW_CONSUMER=m
CONFIG_IIO_KFIFO_BUF=m
CONFIG_IIO_TRIGGERED_BUFFER=m
CONFIG_IIO_CONFIGFS=m
CONFIG_IIO_GTS_HELPER=m
CONFIG_IIO_TRIGGER=y
CONFIG_IIO_CONSUMERS_PER_TRIGGER=2
CONFIG_IIO_SW_DEVICE=m
CONFIG_IIO_SW_TRIGGER=m
CONFIG_IIO_TRIGGERED_EVENT=m
CONFIG_IIO_BACKEND=m

#
# Accelerometers
#
# CONFIG_ADIS16201 is not set
# CONFIG_ADIS16209 is not set
CONFIG_ADXL313=m
CONFIG_ADXL313_I2C=m
CONFIG_ADXL313_SPI=m
# CONFIG_ADXL345_I2C is not set
# CONFIG_ADXL345_SPI is not set
CONFIG_ADXL355=m
CONFIG_ADXL355_I2C=m
CONFIG_ADXL355_SPI=m
CONFIG_ADXL367=m
CONFIG_ADXL367_SPI=m
CONFIG_ADXL367_I2C=m
CONFIG_ADXL372=m
CONFIG_ADXL372_SPI=m
CONFIG_ADXL372_I2C=m
CONFIG_ADXL380=m
CONFIG_ADXL380_SPI=m
CONFIG_ADXL380_I2C=m
CONFIG_BMA180=m
# CONFIG_BMA220 is not set
# CONFIG_BMA400 is not set
CONFIG_BMC150_ACCEL=m
CONFIG_BMC150_ACCEL_I2C=m
CONFIG_BMC150_ACCEL_SPI=m
# CONFIG_BMI088_ACCEL is not set
CONFIG_DA280=m
CONFIG_DA311=m
# CONFIG_DMARD06 is not set
# CONFIG_DMARD09 is not set
CONFIG_DMARD10=m
# CONFIG_FXLS8962AF_I2C is not set
# CONFIG_FXLS8962AF_SPI is not set
CONFIG_HID_SENSOR_ACCEL_3D=m
CONFIG_IIO_CROS_EC_ACCEL_LEGACY=m
CONFIG_IIO_ST_ACCEL_3AXIS=m
CONFIG_IIO_ST_ACCEL_I2C_3AXIS=m
CONFIG_IIO_ST_ACCEL_SPI_3AXIS=m
CONFIG_IIO_KX022A=m
CONFIG_IIO_KX022A_SPI=m
CONFIG_IIO_KX022A_I2C=m
CONFIG_KXSD9=m
CONFIG_KXSD9_SPI=m
CONFIG_KXSD9_I2C=m
CONFIG_KXCJK1013=m
# CONFIG_MC3230 is not set
# CONFIG_MMA7455_I2C is not set
# CONFIG_MMA7455_SPI is not set
CONFIG_MMA7660=m
CONFIG_MMA8452=m
# CONFIG_MMA9551 is not set
# CONFIG_MMA9553 is not set
CONFIG_MSA311=m
CONFIG_MXC4005=m
CONFIG_MXC6255=m
# CONFIG_SCA3000 is not set
CONFIG_SCA3300=m
# CONFIG_STK8312 is not set
# CONFIG_STK8BA50 is not set
# end of Accelerometers

#
# Analog to digital converters
#
CONFIG_IIO_ADC_HELPER=m
CONFIG_AD_SIGMA_DELTA=m
CONFIG_AD4000=m
CONFIG_AD4030=m
# CONFIG_AD4080 is not set
CONFIG_AD4130=m
# CONFIG_AD4170_4 is not set
CONFIG_AD4695=m
CONFIG_AD4851=m
CONFIG_AD7091R=m
# CONFIG_AD7091R5 is not set
CONFIG_AD7091R8=m
CONFIG_AD7124=m
# CONFIG_AD7173 is not set
CONFIG_AD7191=m
# CONFIG_AD7192 is not set
# CONFIG_AD7266 is not set
# CONFIG_AD7280 is not set
# CONFIG_AD7291 is not set
CONFIG_AD7292=m
# CONFIG_AD7298 is not set
CONFIG_AD7380=m
# CONFIG_AD7405 is not set
# CONFIG_AD7476 is not set
# CONFIG_AD7606_IFACE_PARALLEL is not set
# CONFIG_AD7606_IFACE_SPI is not set
CONFIG_AD7625=m
CONFIG_AD7766=m
# CONFIG_AD7768_1 is not set
CONFIG_AD7779=m
# CONFIG_AD7780 is not set
# CONFIG_AD7791 is not set
# CONFIG_AD7793 is not set
# CONFIG_AD7887 is not set
# CONFIG_AD7923 is not set
# CONFIG_AD7944 is not set
CONFIG_AD7949=m
# CONFIG_AD799X is not set
CONFIG_AD9467=m
# CONFIG_ADI_AXI_ADC is not set
CONFIG_AXP20X_ADC=m
CONFIG_AXP288_ADC=m
# CONFIG_CC10001_ADC is not set
CONFIG_DLN2_ADC=m
CONFIG_ENVELOPE_DETECTOR=m
# CONFIG_GEHC_PMC_ADC is not set
# CONFIG_HI8435 is not set
# CONFIG_HX711 is not set
CONFIG_INA2XX_ADC=m
CONFIG_IMX7D_ADC=m
CONFIG_IMX8QXP_ADC=m
CONFIG_IMX93_ADC=m
# CONFIG_LTC2309 is not set
# CONFIG_LTC2471 is not set
# CONFIG_LTC2485 is not set
# CONFIG_LTC2496 is not set
# CONFIG_LTC2497 is not set
# CONFIG_MAX1027 is not set
# CONFIG_MAX11100 is not set
# CONFIG_MAX1118 is not set
CONFIG_MAX11205=m
CONFIG_MAX11410=m
CONFIG_MAX1241=m
CONFIG_MAX1363=m
CONFIG_MAX34408=m
# CONFIG_MAX9611 is not set
CONFIG_MCP320X=m
CONFIG_MCP3422=m
# CONFIG_MCP3564 is not set
CONFIG_MCP3911=m
CONFIG_MESON_SARADC=m
# CONFIG_NAU7802 is not set
# CONFIG_NCT7201 is not set
CONFIG_PAC1921=m
CONFIG_PAC1934=m
CONFIG_QCOM_VADC_COMMON=m
CONFIG_QCOM_SPMI_RRADC=m
CONFIG_QCOM_SPMI_IADC=m
CONFIG_QCOM_SPMI_VADC=m
CONFIG_QCOM_SPMI_ADC5=m
# CONFIG_ROHM_BD79124 is not set
CONFIG_ROCKCHIP_SARADC=m
CONFIG_RICHTEK_RTQ6056=m
CONFIG_RZG2L_ADC=m
CONFIG_SD_ADC_MODULATOR=m
CONFIG_STMPE_ADC=m
CONFIG_SUN20I_GPADC=m
# CONFIG_TI_ADC081C is not set
# CONFIG_TI_ADC0832 is not set
# CONFIG_TI_ADC084S021 is not set
# CONFIG_TI_ADC108S102 is not set
# CONFIG_TI_ADC12138 is not set
CONFIG_TI_ADC128S052=m
# CONFIG_TI_ADC161S626 is not set
CONFIG_TI_ADS1015=m
CONFIG_TI_ADS1100=m
# CONFIG_TI_ADS1119 is not set
# CONFIG_TI_ADS124S08 is not set
# CONFIG_TI_ADS1298 is not set
CONFIG_TI_ADS131E08=m
CONFIG_TI_ADS7138=m
CONFIG_TI_ADS7924=m
# CONFIG_TI_ADS7950 is not set
CONFIG_TI_ADS8344=m
# CONFIG_TI_ADS8688 is not set
CONFIG_TI_AM335X_ADC=m
CONFIG_TI_LMP92064=m
# CONFIG_TI_TLC4541 is not set
CONFIG_TI_TSC2046=m
# CONFIG_VF610_ADC is not set
CONFIG_XILINX_XADC=m
CONFIG_XILINX_AMS=m
# end of Analog to digital converters

#
# Analog to digital and digital to analog converters
#
CONFIG_AD74115=m
CONFIG_AD74413R=m
# end of Analog to digital and digital to analog converters

#
# Analog Front Ends
#
CONFIG_IIO_RESCALE=m
# end of Analog Front Ends

#
# Amplifiers
#
# CONFIG_AD8366 is not set
# CONFIG_ADA4250 is not set
CONFIG_HMC425=m
# end of Amplifiers

#
# Capacitance to digital converters
#
# CONFIG_AD7150 is not set
# CONFIG_AD7746 is not set
# end of Capacitance to digital converters

#
# Chemical Sensors
#
# CONFIG_AOSONG_AGS02MA is not set
# CONFIG_ATLAS_PH_SENSOR is not set
# CONFIG_ATLAS_EZO_SENSOR is not set
CONFIG_BME680=m
CONFIG_BME680_I2C=m
CONFIG_BME680_SPI=m
# CONFIG_CCS811 is not set
# CONFIG_ENS160 is not set
# CONFIG_IAQCORE is not set
# CONFIG_MHZ19B is not set
CONFIG_PMS7003=m
CONFIG_SCD30_CORE=m
CONFIG_SCD30_I2C=m
CONFIG_SCD30_SERIAL=m
# CONFIG_SCD4X is not set
# CONFIG_SEN0322 is not set
# CONFIG_SENSIRION_SGP30 is not set
# CONFIG_SENSIRION_SGP40 is not set
# CONFIG_SPS30_I2C is not set
# CONFIG_SPS30_SERIAL is not set
# CONFIG_SENSEAIR_SUNRISE_CO2 is not set
# CONFIG_VZ89X is not set
# end of Chemical Sensors

CONFIG_IIO_CROS_EC_SENSORS_CORE=m
CONFIG_IIO_CROS_EC_SENSORS=m
CONFIG_IIO_CROS_EC_SENSORS_LID_ANGLE=m
# CONFIG_IIO_CROS_EC_ACTIVITY is not set

#
# Hid Sensor IIO Common
#
CONFIG_HID_SENSOR_IIO_COMMON=m
CONFIG_HID_SENSOR_IIO_TRIGGER=m
# end of Hid Sensor IIO Common

CONFIG_IIO_INV_SENSORS_TIMESTAMP=m
CONFIG_IIO_MS_SENSORS_I2C=m

#
# IIO SCMI Sensors
#
CONFIG_IIO_SCMI=m
# end of IIO SCMI Sensors

#
# SSP Sensor Common
#
# CONFIG_IIO_SSP_SENSORHUB is not set
# end of SSP Sensor Common

CONFIG_IIO_ST_SENSORS_I2C=m
CONFIG_IIO_ST_SENSORS_SPI=m
CONFIG_IIO_ST_SENSORS_CORE=m

#
# Digital to analog converters
#
# CONFIG_AD3530R is not set
CONFIG_AD3552R_HS=m
CONFIG_AD3552R_LIB=m
CONFIG_AD3552R=m
# CONFIG_AD5064 is not set
# CONFIG_AD5360 is not set
# CONFIG_AD5380 is not set
# CONFIG_AD5421 is not set
# CONFIG_AD5446 is not set
# CONFIG_AD5449 is not set
# CONFIG_AD5592R is not set
# CONFIG_AD5593R is not set
# CONFIG_AD5504 is not set
# CONFIG_AD5624R_SPI is not set
# CONFIG_AD9739A is not set
# CONFIG_ADI_AXI_DAC is not set
CONFIG_LTC2688=m
# CONFIG_AD5686_SPI is not set
# CONFIG_AD5696_I2C is not set
# CONFIG_AD5755 is not set
# CONFIG_AD5758 is not set
# CONFIG_AD5761 is not set
# CONFIG_AD5764 is not set
CONFIG_AD5766=m
CONFIG_AD5770R=m
# CONFIG_AD5791 is not set
CONFIG_AD7293=m
# CONFIG_AD7303 is not set
CONFIG_AD8460=m
# CONFIG_AD8801 is not set
CONFIG_BD79703=m
CONFIG_DPOT_DAC=m
# CONFIG_DS4424 is not set
CONFIG_LTC1660=m
# CONFIG_LTC2632 is not set
CONFIG_LTC2664=m
# CONFIG_M62332 is not set
# CONFIG_MAX517 is not set
CONFIG_MAX5522=m
# CONFIG_MAX5821 is not set
# CONFIG_MCP4725 is not set
CONFIG_MCP4728=m
CONFIG_MCP4821=m
# CONFIG_MCP4922 is not set
# CONFIG_TI_DAC082S085 is not set
# CONFIG_TI_DAC5571 is not set
CONFIG_TI_DAC7311=m
# CONFIG_TI_DAC7612 is not set
# CONFIG_VF610_DAC is not set
# end of Digital to analog converters

#
# IIO dummy driver
#
# CONFIG_IIO_SIMPLE_DUMMY is not set
# end of IIO dummy driver

#
# Filters
#
# CONFIG_ADMV8818 is not set
# end of Filters

#
# Frequency Synthesizers DDS/PLL
#

#
# Clock Generator/Distribution
#
# CONFIG_AD9523 is not set
# end of Clock Generator/Distribution

#
# Phase-Locked Loop (PLL) frequency synthesizers
#
# CONFIG_ADF4350 is not set
# CONFIG_ADF4371 is not set
CONFIG_ADF4377=m
# CONFIG_ADMFM2000 is not set
# CONFIG_ADMV1013 is not set
# CONFIG_ADMV1014 is not set
# CONFIG_ADMV4420 is not set
# CONFIG_ADRF6780 is not set
# end of Phase-Locked Loop (PLL) frequency synthesizers
# end of Frequency Synthesizers DDS/PLL

#
# Digital gyroscope sensors
#
# CONFIG_ADIS16080 is not set
# CONFIG_ADIS16130 is not set
# CONFIG_ADIS16136 is not set
# CONFIG_ADIS16260 is not set
CONFIG_ADXRS290=m
# CONFIG_ADXRS450 is not set
# CONFIG_BMG160 is not set
CONFIG_FXAS21002C=m
CONFIG_FXAS21002C_I2C=m
CONFIG_FXAS21002C_SPI=m
CONFIG_HID_SENSOR_GYRO_3D=m
CONFIG_MPU3050=m
CONFIG_MPU3050_I2C=m
CONFIG_IIO_ST_GYRO_3AXIS=m
CONFIG_IIO_ST_GYRO_I2C_3AXIS=m
CONFIG_IIO_ST_GYRO_SPI_3AXIS=m
# CONFIG_ITG3200 is not set
# end of Digital gyroscope sensors

#
# Health Sensors
#

#
# Heart Rate Monitors
#
# CONFIG_AFE4403 is not set
# CONFIG_AFE4404 is not set
CONFIG_MAX30100=m
# CONFIG_MAX30102 is not set
# end of Heart Rate Monitors
# end of Health Sensors

#
# Humidity sensors
#
# CONFIG_AM2315 is not set
CONFIG_DHT11=m
# CONFIG_ENS210 is not set
CONFIG_HDC100X=m
CONFIG_HDC2010=m
# CONFIG_HDC3020 is not set
CONFIG_HID_SENSOR_HUMIDITY=m
CONFIG_HTS221=m
CONFIG_HTS221_I2C=m
CONFIG_HTS221_SPI=m
CONFIG_HTU21=m
# CONFIG_SI7005 is not set
CONFIG_SI7020=m
# end of Humidity sensors

#
# Inertial measurement units
#
# CONFIG_ADIS16400 is not set
# CONFIG_ADIS16460 is not set
CONFIG_ADIS16475=m
# CONFIG_ADIS16480 is not set
CONFIG_ADIS16550=m
CONFIG_BMI160=m
CONFIG_BMI160_I2C=m
CONFIG_BMI160_SPI=m
CONFIG_BMI270=m
CONFIG_BMI270_I2C=m
CONFIG_BMI270_SPI=m
# CONFIG_BMI323_I2C is not set
# CONFIG_BMI323_SPI is not set
CONFIG_BOSCH_BNO055=m
CONFIG_BOSCH_BNO055_SERIAL=m
CONFIG_BOSCH_BNO055_I2C=m
CONFIG_FXOS8700=m
CONFIG_FXOS8700_I2C=m
CONFIG_FXOS8700_SPI=m
# CONFIG_KMX61 is not set
CONFIG_INV_ICM42600=m
CONFIG_INV_ICM42600_I2C=m
CONFIG_INV_ICM42600_SPI=m
CONFIG_INV_MPU6050_IIO=m
CONFIG_INV_MPU6050_I2C=m
# CONFIG_INV_MPU6050_SPI is not set
# CONFIG_SMI240 is not set
CONFIG_IIO_ST_LSM6DSX=m
CONFIG_IIO_ST_LSM6DSX_I2C=m
CONFIG_IIO_ST_LSM6DSX_SPI=m
CONFIG_IIO_ST_LSM6DSX_I3C=m
# CONFIG_IIO_ST_LSM9DS0 is not set
# end of Inertial measurement units

CONFIG_IIO_ADIS_LIB=m
CONFIG_IIO_ADIS_LIB_BUFFER=y

#
# Light sensors
#
CONFIG_ACPI_ALS=m
# CONFIG_ADJD_S311 is not set
CONFIG_ADUX1020=m
CONFIG_AL3000A=m
CONFIG_AL3010=m
# CONFIG_AL3320A is not set
CONFIG_APDS9160=m
# CONFIG_APDS9300 is not set
CONFIG_APDS9306=m
CONFIG_APDS9960=m
# CONFIG_AS73211 is not set
CONFIG_BH1745=m
CONFIG_BH1750=m
# CONFIG_BH1780 is not set
CONFIG_CM32181=m
# CONFIG_CM3232 is not set
# CONFIG_CM3323 is not set
CONFIG_CM3605=m
# CONFIG_CM36651 is not set
CONFIG_IIO_CROS_EC_LIGHT_PROX=m
CONFIG_GP2AP002=m
# CONFIG_GP2AP020A00F is not set
CONFIG_SENSORS_ISL29018=m
CONFIG_SENSORS_ISL29028=m
# CONFIG_ISL29125 is not set
# CONFIG_ISL76682 is not set
CONFIG_HID_SENSOR_ALS=m
# CONFIG_HID_SENSOR_PROX is not set
# CONFIG_JSA1212 is not set
CONFIG_ROHM_BU27034=m
CONFIG_RPR0521=m
# CONFIG_LTR390 is not set
CONFIG_LTR501=m
CONFIG_LTRF216A=m
CONFIG_LV0104CS=m
# CONFIG_MAX44000 is not set
CONFIG_MAX44009=m
# CONFIG_NOA1305 is not set
CONFIG_OPT3001=m
CONFIG_OPT4001=m
CONFIG_OPT4060=m
CONFIG_PA12203001=m
# CONFIG_SI1133 is not set
# CONFIG_SI1145 is not set
CONFIG_STK3310=m
CONFIG_ST_UVIS25=m
CONFIG_ST_UVIS25_I2C=m
CONFIG_ST_UVIS25_SPI=m
# CONFIG_TCS3414 is not set
CONFIG_TCS3472=m
# CONFIG_SENSORS_TSL2563 is not set
# CONFIG_TSL2583 is not set
# CONFIG_TSL2591 is not set
CONFIG_TSL2772=m
CONFIG_TSL4531=m
# CONFIG_US5182D is not set
CONFIG_VCNL4000=m
CONFIG_VCNL4035=m
CONFIG_VEML3235=m
CONFIG_VEML6030=m
# CONFIG_VEML6040 is not set
CONFIG_VEML6070=m
# CONFIG_VEML6075 is not set
CONFIG_VL6180=m
CONFIG_ZOPT2201=m
# end of Light sensors

#
# Magnetometer sensors
#
CONFIG_AF8133J=m
# CONFIG_AK8974 is not set
CONFIG_AK8975=m
# CONFIG_AK09911 is not set
# CONFIG_ALS31300 is not set
CONFIG_BMC150_MAGN=m
CONFIG_BMC150_MAGN_I2C=m
CONFIG_BMC150_MAGN_SPI=m
CONFIG_MAG3110=m
CONFIG_HID_SENSOR_MAGNETOMETER_3D=m
# CONFIG_MMC35240 is not set
CONFIG_IIO_ST_MAGN_3AXIS=m
CONFIG_IIO_ST_MAGN_I2C_3AXIS=m
CONFIG_IIO_ST_MAGN_SPI_3AXIS=m
# CONFIG_SENSORS_HMC5843_I2C is not set
# CONFIG_SENSORS_HMC5843_SPI is not set
CONFIG_SENSORS_RM3100=m
CONFIG_SENSORS_RM3100_I2C=m
CONFIG_SENSORS_RM3100_SPI=m
# CONFIG_SI7210 is not set
# CONFIG_TI_TMAG5273 is not set
# CONFIG_YAMAHA_YAS530 is not set
# end of Magnetometer sensors

#
# Multiplexers
#
CONFIG_IIO_MUX=m
# end of Multiplexers

#
# Inclinometer sensors
#
CONFIG_HID_SENSOR_INCLINOMETER_3D=m
CONFIG_HID_SENSOR_DEVICE_ROTATION=m
# end of Inclinometer sensors

CONFIG_IIO_GTS_KUNIT_TEST=m
CONFIG_IIO_RESCALE_KUNIT_TEST=m
CONFIG_IIO_FORMAT_KUNIT_TEST=m

#
# Triggers - standalone
#
# CONFIG_IIO_HRTIMER_TRIGGER is not set
CONFIG_IIO_INTERRUPT_TRIGGER=m
CONFIG_IIO_TIGHTLOOP_TRIGGER=m
CONFIG_IIO_SYSFS_TRIGGER=m
# end of Triggers - standalone

#
# Linear and angular position sensors
#
CONFIG_HID_SENSOR_CUSTOM_INTEL_HINGE=m
# end of Linear and angular position sensors

#
# Digital potentiometers
#
CONFIG_AD5110=m
CONFIG_AD5272=m
# CONFIG_DS1803 is not set
# CONFIG_MAX5432 is not set
# CONFIG_MAX5481 is not set
# CONFIG_MAX5487 is not set
CONFIG_MCP4018=m
# CONFIG_MCP4131 is not set
# CONFIG_MCP4531 is not set
CONFIG_MCP41010=m
# CONFIG_TPL0102 is not set
CONFIG_X9250=m
# end of Digital potentiometers

#
# Digital potentiostats
#
CONFIG_LMP91000=m
# end of Digital potentiostats

#
# Pressure sensors
#
CONFIG_ABP060MG=m
# CONFIG_ROHM_BM1390 is not set
CONFIG_BMP280=m
CONFIG_BMP280_I2C=m
CONFIG_BMP280_SPI=m
CONFIG_IIO_CROS_EC_BARO=m
# CONFIG_DLHL60D is not set
# CONFIG_DPS310 is not set
# CONFIG_HID_SENSOR_PRESS is not set
# CONFIG_HP03 is not set
# CONFIG_HSC030PA is not set
CONFIG_ICP10100=m
CONFIG_MPL115=m
CONFIG_MPL115_I2C=m
# CONFIG_MPL115_SPI is not set
# CONFIG_MPL3115 is not set
# CONFIG_MPRLS0025PA is not set
# CONFIG_MS5611 is not set
# CONFIG_MS5637 is not set
# CONFIG_SDP500 is not set
CONFIG_IIO_ST_PRESS=m
CONFIG_IIO_ST_PRESS_I2C=m
CONFIG_IIO_ST_PRESS_SPI=m
# CONFIG_T5403 is not set
# CONFIG_HP206C is not set
# CONFIG_ZPA2326 is not set
# end of Pressure sensors

#
# Lightning sensors
#
# CONFIG_AS3935 is not set
# end of Lightning sensors

#
# Proximity and distance sensors
#
CONFIG_CROS_EC_MKBP_PROXIMITY=m
# CONFIG_D3323AA is not set
# CONFIG_HX9023S is not set
# CONFIG_IRSD200 is not set
# CONFIG_ISL29501 is not set
# CONFIG_LIDAR_LITE_V2 is not set
CONFIG_MB1232=m
# CONFIG_PING is not set
# CONFIG_RFD77402 is not set
# CONFIG_SRF04 is not set
CONFIG_SX_COMMON=m
CONFIG_SX9310=m
CONFIG_SX9324=m
CONFIG_SX9360=m
# CONFIG_SX9500 is not set
# CONFIG_SRF08 is not set
CONFIG_VCNL3020=m
CONFIG_VL53L0X_I2C=m
# CONFIG_AW96103 is not set
# end of Proximity and distance sensors

#
# Resolver to digital converters
#
# CONFIG_AD2S90 is not set
# CONFIG_AD2S1200 is not set
# CONFIG_AD2S1210 is not set
# end of Resolver to digital converters

#
# Temperature sensors
#
CONFIG_LTC2983=m
CONFIG_MAXIM_THERMOCOUPLE=m
CONFIG_HID_SENSOR_TEMP=m
CONFIG_MLX90614=m
CONFIG_MLX90632=m
# CONFIG_MLX90635 is not set
CONFIG_TMP006=m
# CONFIG_TMP007 is not set
CONFIG_TMP117=m
# CONFIG_TSYS01 is not set
# CONFIG_TSYS02D is not set
CONFIG_MAX30208=m
CONFIG_MAX31856=m
CONFIG_MAX31865=m
CONFIG_MCP9600=m
# end of Temperature sensors

# CONFIG_NTB is not set
CONFIG_PWM=y
# CONFIG_PWM_DEBUG is not set
CONFIG_PWM_ADP5585=m
CONFIG_PWM_APPLE=m
# CONFIG_PWM_ARGON_FAN_HAT is not set
# CONFIG_PWM_ATMEL_TCB is not set
CONFIG_PWM_AXI_PWMGEN=m
CONFIG_PWM_BCM2835=m
CONFIG_PWM_CLK=m
CONFIG_PWM_CROS_EC=m
CONFIG_PWM_DWC_CORE=m
CONFIG_PWM_DWC=m
# CONFIG_PWM_FSL_FTM is not set
CONFIG_PWM_GPIO=m
CONFIG_PWM_HIBVT=m
# CONFIG_PWM_IMX1 is not set
CONFIG_PWM_IMX27=m
CONFIG_PWM_IMX_TPM=m
# CONFIG_PWM_MC33XS2410 is not set
CONFIG_PWM_MESON=m
CONFIG_PWM_OMAP_DMTIMER=m
CONFIG_PWM_PCA9685=m
CONFIG_PWM_RASPBERRYPI_POE=m
# CONFIG_PWM_RENESAS_RCAR is not set
# CONFIG_PWM_RENESAS_RZG2L_GPT is not set
# CONFIG_PWM_RENESAS_TPU is not set
CONFIG_PWM_ROCKCHIP=m
CONFIG_PWM_STMPE=y
CONFIG_PWM_SUN4I=m
CONFIG_PWM_TEGRA=y
CONFIG_PWM_TIECAP=m
CONFIG_PWM_TIEHRPWM=m
CONFIG_PWM_XILINX=m

#
# IRQ chip support
#
CONFIG_IRQCHIP=y
CONFIG_ARM_GIC=y
CONFIG_ARM_GIC_PM=y
CONFIG_ARM_GIC_MAX_NR=1
CONFIG_ARM_GIC_V2M=y
CONFIG_ARM_GIC_V3=y
CONFIG_ARM_GIC_ITS_PARENT=y
CONFIG_ARM_GIC_V3_ITS=y
CONFIG_ARM_GIC_V3_ITS_FSL_MC=y
CONFIG_ARM_GIC_V5=y
CONFIG_IRQ_MSI_LIB=y
CONFIG_AL_FIC=y
CONFIG_BCM2712_MIP=y
CONFIG_BRCMSTB_L2_IRQ=y
CONFIG_HISILICON_IRQ_MBIGEN=y
CONFIG_RENESAS_IRQC=y
CONFIG_RENESAS_RZG2L_IRQC=y
CONFIG_RENESAS_RZV2H_ICU=y
CONFIG_SUN6I_R_INTC=y
CONFIG_SUNXI_NMI_INTC=y
CONFIG_XILINX_INTC=y
CONFIG_IMX_GPCV2=y
CONFIG_MVEBU_GICP=y
CONFIG_MVEBU_ICU=y
CONFIG_MVEBU_ODMI=y
CONFIG_MVEBU_PIC=y
CONFIG_MVEBU_SEI=y
CONFIG_LS_EXTIRQ=y
CONFIG_LS_SCFG_MSI=y
CONFIG_PARTITION_PERCPU=y
CONFIG_QCOM_IRQ_COMBINER=y
CONFIG_MESON_IRQ_GPIO=y
CONFIG_QCOM_PDC=y
CONFIG_QCOM_MPM=m
CONFIG_IMX_IRQSTEER=y
CONFIG_IMX_INTMUX=y
CONFIG_IMX_MU_MSI=m
CONFIG_TI_SCI_INTR_IRQCHIP=m
CONFIG_TI_SCI_INTA_IRQCHIP=m
CONFIG_TI_PRUSS_INTC=m
CONFIG_APPLE_AIC=y
# end of IRQ chip support

# CONFIG_IPACK_BUS is not set
CONFIG_ARCH_HAS_RESET_CONTROLLER=y
CONFIG_RESET_CONTROLLER=y
CONFIG_RESET_BRCMSTB=y
CONFIG_RESET_BRCMSTB_RESCAL=y
CONFIG_RESET_GPIO=m
CONFIG_RESET_IMX_SCU=m
CONFIG_RESET_IMX7=y
CONFIG_RESET_IMX8MP_AUDIOMIX=m
CONFIG_RESET_QCOM_AOSS=y
CONFIG_RESET_QCOM_PDC=m
CONFIG_RESET_RASPBERRYPI=y
CONFIG_RESET_RZG2L_USBPHY_CTRL=m
# CONFIG_RESET_RZV2H_USB2PHY is not set
CONFIG_RESET_SCMI=y
CONFIG_RESET_SIMPLE=y
CONFIG_RESET_SUNXI=y
CONFIG_RESET_TI_SCI=m
CONFIG_RESET_TI_SYSCON=m
CONFIG_RESET_TI_TPS380X=m
CONFIG_RESET_ZYNQMP=y
CONFIG_RESET_MESON_COMMON=y
CONFIG_RESET_MESON=m
CONFIG_RESET_MESON_AUX=y
CONFIG_RESET_MESON_AUDIO_ARB=m
CONFIG_COMMON_RESET_HI3660=m
CONFIG_COMMON_RESET_HI6220=m
CONFIG_RESET_TEGRA_BPMP=y

#
# PHY Subsystem
#
CONFIG_GENERIC_PHY=y
CONFIG_GENERIC_PHY_MIPI_DPHY=y
# CONFIG_PHY_SNPS_EUSB2 is not set
CONFIG_PHY_XGENE=y
CONFIG_PHY_CAN_TRANSCEIVER=m
CONFIG_PHY_NXP_PTN3222=m
CONFIG_PHY_SUN4I_USB=m
CONFIG_PHY_SUN6I_MIPI_DPHY=m
# CONFIG_PHY_SUN9I_USB is not set
CONFIG_PHY_SUN50I_USB3=m
CONFIG_PHY_MESON8B_USB2=m
CONFIG_PHY_MESON_GXL_USB2=m
CONFIG_PHY_MESON_G12A_MIPI_DPHY_ANALOG=y
CONFIG_PHY_MESON_G12A_USB2=y
CONFIG_PHY_MESON_G12A_USB3_PCIE=m
CONFIG_PHY_MESON_AXG_PCIE=m
CONFIG_PHY_MESON_AXG_MIPI_PCIE_ANALOG=y
CONFIG_PHY_MESON_AXG_MIPI_DPHY=m

#
# PHY drivers for Broadcom platforms
#
# CONFIG_BCM_KONA_USB2_PHY is not set
# end of PHY drivers for Broadcom platforms

CONFIG_PHY_CADENCE_TORRENT=m
CONFIG_PHY_CADENCE_DPHY=m
CONFIG_PHY_CADENCE_DPHY_RX=m
CONFIG_PHY_CADENCE_SIERRA=m
CONFIG_PHY_CADENCE_SALVO=m
CONFIG_PHY_FSL_IMX8MQ_USB=m
CONFIG_PHY_MIXEL_LVDS_PHY=m
CONFIG_PHY_MIXEL_MIPI_DPHY=m
CONFIG_PHY_FSL_IMX8M_PCIE=y
CONFIG_PHY_FSL_IMX8QM_HSIO=m
CONFIG_PHY_FSL_SAMSUNG_HDMI_PHY=m
CONFIG_PHY_FSL_LYNX_28G=m
CONFIG_PHY_HI6220_USB=m
CONFIG_PHY_HI3660_USB=m
CONFIG_PHY_HI3670_USB=m
# CONFIG_PHY_HI3670_PCIE is not set
CONFIG_PHY_HISTB_COMBPHY=m
CONFIG_PHY_HISI_INNO_USB2=m
CONFIG_PHY_MVEBU_A3700_COMPHY=m
CONFIG_PHY_MVEBU_A3700_UTMI=m
CONFIG_PHY_MVEBU_A38X_COMPHY=m
CONFIG_PHY_MVEBU_CP110_COMPHY=m
CONFIG_PHY_MVEBU_CP110_UTMI=m
# CONFIG_PHY_PXA_28NM_HSIC is not set
# CONFIG_PHY_PXA_28NM_USB2 is not set
# CONFIG_PHY_CPCAP_USB is not set
# CONFIG_PHY_MAPPHONE_MDM6600 is not set
# CONFIG_PHY_OCELOT_SERDES is not set
# CONFIG_PHY_QCOM_APQ8064_SATA is not set
CONFIG_PHY_QCOM_EDP=m
# CONFIG_PHY_QCOM_IPQ4019_USB is not set
# CONFIG_PHY_QCOM_IPQ806X_SATA is not set
CONFIG_PHY_QCOM_PCIE2=m
CONFIG_PHY_QCOM_QMP=m
CONFIG_PHY_QCOM_QMP_COMBO=m
CONFIG_PHY_QCOM_QMP_PCIE=m
CONFIG_PHY_QCOM_QMP_PCIE_8996=m
CONFIG_PHY_QCOM_QMP_UFS=m
CONFIG_PHY_QCOM_QMP_USB=m
CONFIG_PHY_QCOM_QMP_USB_LEGACY=m
CONFIG_PHY_QCOM_QUSB2=m
CONFIG_PHY_QCOM_EUSB2_REPEATER=m
# CONFIG_PHY_QCOM_M31_USB is not set
CONFIG_PHY_QCOM_UNIPHY_PCIE_28LP=y
# CONFIG_PHY_QCOM_M31_EUSB is not set
CONFIG_PHY_QCOM_USB_HS=m
CONFIG_PHY_QCOM_USB_SNPS_FEMTO_V2=m
CONFIG_PHY_QCOM_USB_HSIC=m
CONFIG_PHY_QCOM_USB_HS_28NM=m
CONFIG_PHY_QCOM_USB_SS=m
# CONFIG_PHY_QCOM_IPQ806X_USB is not set
CONFIG_PHY_QCOM_SGMII_ETH=m
# CONFIG_PHY_R8A779F0_ETHERNET_SERDES is not set
# CONFIG_PHY_RCAR_GEN2 is not set
# CONFIG_PHY_RCAR_GEN3_PCIE is not set
CONFIG_PHY_RCAR_GEN3_USB2=m
# CONFIG_PHY_RCAR_GEN3_USB3 is not set
CONFIG_PHY_ROCKCHIP_DP=m
CONFIG_PHY_ROCKCHIP_DPHY_RX0=m
CONFIG_PHY_ROCKCHIP_EMMC=m
CONFIG_PHY_ROCKCHIP_INNO_HDMI=m
CONFIG_PHY_ROCKCHIP_INNO_USB2=m
CONFIG_PHY_ROCKCHIP_INNO_CSIDPHY=m
CONFIG_PHY_ROCKCHIP_INNO_DSIDPHY=m
CONFIG_PHY_ROCKCHIP_NANENG_COMBO_PHY=m
CONFIG_PHY_ROCKCHIP_PCIE=y
# CONFIG_PHY_ROCKCHIP_SAMSUNG_DCPHY is not set
CONFIG_PHY_ROCKCHIP_SAMSUNG_HDPTX=m
CONFIG_PHY_ROCKCHIP_SNPS_PCIE3=m
CONFIG_PHY_ROCKCHIP_TYPEC=m
CONFIG_PHY_ROCKCHIP_USB=m
CONFIG_PHY_ROCKCHIP_USBDP=m
# CONFIG_PHY_SAMSUNG_USB2 is not set
CONFIG_PHY_TEGRA_XUSB=m
CONFIG_PHY_TEGRA194_P2U=y
CONFIG_PHY_AM654_SERDES=m
CONFIG_PHY_J721E_WIZ=m
CONFIG_OMAP_USB2=m
# CONFIG_PHY_TUSB1210 is not set
CONFIG_PHY_TI_GMII_SEL=m
CONFIG_PHY_XILINX_ZYNQMP=m
# end of PHY Subsystem

CONFIG_POWERCAP=y
# CONFIG_IDLE_INJECT is not set
CONFIG_ARM_SCMI_POWERCAP=m
CONFIG_DTPM=y
CONFIG_DTPM_CPU=y
CONFIG_DTPM_DEVFREQ=y
# CONFIG_MCB is not set

#
# Performance monitor support
#
CONFIG_ARM_CCI_PMU=m
CONFIG_ARM_CCI400_PMU=y
CONFIG_ARM_CCI5xx_PMU=y
CONFIG_ARM_CCN=y
CONFIG_ARM_CMN=m
CONFIG_ARM_NI=m
CONFIG_ARM_PMU=y
CONFIG_ARM_PMU_ACPI=y
CONFIG_ARM_SMMU_V3_PMU=m
CONFIG_ARM_PMUV3=y
CONFIG_ARM_DSU_PMU=m
CONFIG_FSL_IMX8_DDR_PMU=m
# CONFIG_FSL_IMX9_DDR_PMU is not set
CONFIG_QCOM_L2_PMU=y
CONFIG_QCOM_L3_PMU=y
CONFIG_THUNDERX2_PMU=m
CONFIG_XGENE_PMU=y
CONFIG_ARM_SPE_PMU=m
CONFIG_ARM64_BRBE=y
CONFIG_ARM_DMC620_PMU=m
CONFIG_MARVELL_CN10K_TAD_PMU=m
CONFIG_APPLE_M1_CPU_PMU=y
CONFIG_ALIBABA_UNCORE_DRW_PMU=m
CONFIG_HISI_PMU=y
# CONFIG_HISI_PCIE_PMU is not set
# CONFIG_HNS3_PMU is not set
CONFIG_MARVELL_CN10K_DDR_PMU=m
CONFIG_DWC_PCIE_PMU=m
CONFIG_ARM_CORESIGHT_PMU_ARCH_SYSTEM_PMU=m
CONFIG_NVIDIA_CORESIGHT_PMU_ARCH_SYSTEM_PMU=m
CONFIG_AMPERE_CORESIGHT_PMU_ARCH_SYSTEM_PMU=m
CONFIG_MESON_DDR_PMU=m
CONFIG_CXL_PMU=m
CONFIG_MARVELL_PEM_PMU=m
# end of Performance monitor support

CONFIG_RAS=y
CONFIG_USB4=y
# CONFIG_USB4_DEBUGFS_WRITE is not set
# CONFIG_USB4_DMA_TEST is not set

#
# Android
#
CONFIG_ANDROID_BINDER_IPC=y
CONFIG_ANDROID_BINDERFS=y
CONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"
CONFIG_ANDROID_BINDER_ALLOC_KUNIT_TEST=m
# end of Android

CONFIG_LIBNVDIMM=y
CONFIG_BLK_DEV_PMEM=y
CONFIG_ND_CLAIM=y
# CONFIG_BTT is not set
CONFIG_ND_PFN=y
CONFIG_NVDIMM_PFN=y
CONFIG_NVDIMM_DAX=y
CONFIG_OF_PMEM=y
CONFIG_NVDIMM_KEYS=y
# CONFIG_NVDIMM_SECURITY_TEST is not set
CONFIG_DAX=y
CONFIG_DEV_DAX=y
CONFIG_DEV_DAX_PMEM=y
CONFIG_DEV_DAX_HMEM=m
CONFIG_DEV_DAX_CXL=m
CONFIG_DEV_DAX_HMEM_DEVICES=y
CONFIG_DEV_DAX_KMEM=m
CONFIG_NVMEM=y
CONFIG_NVMEM_SYSFS=y
CONFIG_NVMEM_LAYOUTS=y

#
# Layout Types
#
CONFIG_NVMEM_LAYOUT_SL28_VPD=m
CONFIG_NVMEM_LAYOUT_ONIE_TLV=m
CONFIG_NVMEM_LAYOUT_U_BOOT_ENV=m
# end of Layout Types

CONFIG_NVMEM_APPLE_EFUSES=m
# CONFIG_NVMEM_APPLE_SPMI is not set
# CONFIG_NVMEM_IMX_IIM is not set
CONFIG_NVMEM_IMX_OCOTP=m
# CONFIG_NVMEM_IMX_OCOTP_ELE is not set
CONFIG_NVMEM_IMX_OCOTP_SCU=m
CONFIG_NVMEM_LAYERSCAPE_SFP=m
CONFIG_NVMEM_MESON_EFUSE=m
CONFIG_NVMEM_MESON_MX_EFUSE=m
CONFIG_NVMEM_QCOM_QFPROM=m
CONFIG_NVMEM_QCOM_SEC_QFPROM=m
CONFIG_NVMEM_RCAR_EFUSE=m
CONFIG_NVMEM_RMEM=m
CONFIG_NVMEM_ROCKCHIP_EFUSE=m
CONFIG_NVMEM_ROCKCHIP_OTP=m
# CONFIG_NVMEM_SNVS_LPGPR is not set
CONFIG_NVMEM_SPMI_SDAM=m
CONFIG_NVMEM_SUNXI_SID=m
CONFIG_NVMEM_U_BOOT_ENV=m
CONFIG_NVMEM_ZYNQMP=m

#
# HW tracing support
#
CONFIG_STM=m
# CONFIG_STM_PROTO_BASIC is not set
# CONFIG_STM_PROTO_SYS_T is not set
# CONFIG_STM_DUMMY is not set
# CONFIG_STM_SOURCE_CONSOLE is not set
# CONFIG_STM_SOURCE_HEARTBEAT is not set
# CONFIG_STM_SOURCE_FTRACE is not set
# CONFIG_INTEL_TH is not set
# CONFIG_HISI_PTT is not set
# end of HW tracing support

CONFIG_FPGA=m
CONFIG_ALTERA_PR_IP_CORE=m
CONFIG_ALTERA_PR_IP_CORE_PLAT=m
CONFIG_FPGA_MGR_ALTERA_PS_SPI=m
CONFIG_FPGA_MGR_ALTERA_CVP=m
CONFIG_FPGA_MGR_XILINX_CORE=m
CONFIG_FPGA_MGR_XILINX_SELECTMAP=m
CONFIG_FPGA_MGR_XILINX_SPI=m
CONFIG_FPGA_MGR_ICE40_SPI=m
CONFIG_FPGA_MGR_MACHXO2_SPI=m
CONFIG_FPGA_BRIDGE=m
# CONFIG_ALTERA_FREEZE_BRIDGE is not set
CONFIG_XILINX_PR_DECOUPLER=m
CONFIG_FPGA_REGION=m
CONFIG_OF_FPGA_REGION=m
CONFIG_FPGA_DFL=m
CONFIG_FPGA_DFL_FME=m
CONFIG_FPGA_DFL_FME_MGR=m
CONFIG_FPGA_DFL_FME_BRIDGE=m
CONFIG_FPGA_DFL_FME_REGION=m
CONFIG_FPGA_DFL_AFU=m
CONFIG_FPGA_DFL_NIOS_INTEL_PAC_N3000=m
CONFIG_FPGA_DFL_PCI=m
CONFIG_FPGA_MGR_ZYNQMP_FPGA=m
# CONFIG_FPGA_MGR_VERSAL_FPGA is not set
CONFIG_FPGA_M10_BMC_SEC_UPDATE=m
# CONFIG_FPGA_MGR_MICROCHIP_SPI is not set
CONFIG_FPGA_MGR_LATTICE_SYSCONFIG=m
CONFIG_FPGA_MGR_LATTICE_SYSCONFIG_SPI=m
# CONFIG_FSI is not set
CONFIG_TEE=m
CONFIG_OPTEE=m
# CONFIG_OPTEE_INSECURE_LOAD_IMAGE is not set
CONFIG_ARM_TSTEE=m
CONFIG_MULTIPLEXER=m

#
# Multiplexer drivers
#
CONFIG_MUX_ADG792A=m
# CONFIG_MUX_ADGS1408 is not set
CONFIG_MUX_GPIO=m
CONFIG_MUX_MMIO=m
# end of Multiplexer drivers

CONFIG_PM_OPP=y
# CONFIG_SIOX is not set
CONFIG_SLIMBUS=m
CONFIG_SLIM_QCOM_CTRL=m
CONFIG_SLIM_QCOM_NGD_CTRL=m
CONFIG_INTERCONNECT=y
CONFIG_INTERCONNECT_IMX=m
CONFIG_INTERCONNECT_IMX8MM=m
CONFIG_INTERCONNECT_IMX8MN=m
CONFIG_INTERCONNECT_IMX8MQ=m
CONFIG_INTERCONNECT_IMX8MP=m
CONFIG_INTERCONNECT_QCOM=y
CONFIG_INTERCONNECT_QCOM_BCM_VOTER=y
# CONFIG_INTERCONNECT_QCOM_MSM8909 is not set
CONFIG_INTERCONNECT_QCOM_MSM8916=m
# CONFIG_INTERCONNECT_QCOM_MSM8937 is not set
# CONFIG_INTERCONNECT_QCOM_MSM8939 is not set
CONFIG_INTERCONNECT_QCOM_MSM8953=m
# CONFIG_INTERCONNECT_QCOM_MSM8974 is not set
# CONFIG_INTERCONNECT_QCOM_MSM8976 is not set
CONFIG_INTERCONNECT_QCOM_MSM8996=m
CONFIG_INTERCONNECT_QCOM_OSM_L3=m
CONFIG_INTERCONNECT_QCOM_QCM2290=m
# CONFIG_INTERCONNECT_QCOM_QCS404 is not set
# CONFIG_INTERCONNECT_QCOM_QCS615 is not set
# CONFIG_INTERCONNECT_QCOM_QCS8300 is not set
# CONFIG_INTERCONNECT_QCOM_QDU1000 is not set
CONFIG_INTERCONNECT_QCOM_RPMH_POSSIBLE=y
CONFIG_INTERCONNECT_QCOM_RPMH=y
CONFIG_INTERCONNECT_QCOM_SA8775P=y
# CONFIG_INTERCONNECT_QCOM_SAR2130P is not set
CONFIG_INTERCONNECT_QCOM_SC7180=y
CONFIG_INTERCONNECT_QCOM_SC7280=y
CONFIG_INTERCONNECT_QCOM_SC8180X=y
CONFIG_INTERCONNECT_QCOM_SC8280XP=y
# CONFIG_INTERCONNECT_QCOM_SDM660 is not set
# CONFIG_INTERCONNECT_QCOM_SDM670 is not set
CONFIG_INTERCONNECT_QCOM_SDM845=m
# CONFIG_INTERCONNECT_QCOM_SDX55 is not set
# CONFIG_INTERCONNECT_QCOM_SDX65 is not set
CONFIG_INTERCONNECT_QCOM_SDX75=m
CONFIG_INTERCONNECT_QCOM_SM6115=m
# CONFIG_INTERCONNECT_QCOM_SM6350 is not set
# CONFIG_INTERCONNECT_QCOM_SM7150 is not set
# CONFIG_INTERCONNECT_QCOM_MILOS is not set
CONFIG_INTERCONNECT_QCOM_SM8150=m
CONFIG_INTERCONNECT_QCOM_SM8250=m
# CONFIG_INTERCONNECT_QCOM_SM8350 is not set
CONFIG_INTERCONNECT_QCOM_SM8450=m
# CONFIG_INTERCONNECT_QCOM_SM8550 is not set
# CONFIG_INTERCONNECT_QCOM_SM8650 is not set
# CONFIG_INTERCONNECT_QCOM_SM8750 is not set
CONFIG_INTERCONNECT_QCOM_X1E80100=y
CONFIG_INTERCONNECT_QCOM_SMD_RPM=m
CONFIG_INTERCONNECT_CLK=y
CONFIG_COUNTER=m
CONFIG_INTERRUPT_CNT=m
CONFIG_TI_ECAP_CAPTURE=m
CONFIG_TI_EQEP=m
# CONFIG_MOST is not set
# CONFIG_PECI is not set
CONFIG_HTE=y
CONFIG_HTE_TEGRA194=m
# CONFIG_HTE_TEGRA194_TEST is not set
CONFIG_CDX_BUS=y
CONFIG_CDX_CONTROLLER=m
# end of Device Drivers

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
CONFIG_VALIDATE_FS_PARSER=y
CONFIG_FS_IOMAP=y
CONFIG_FS_STACK=y
CONFIG_BUFFER_HEAD=y
CONFIG_LEGACY_DIRECT_IO=y
# CONFIG_EXT2_FS is not set
# CONFIG_EXT3_FS is not set
CONFIG_EXT4_FS=y
CONFIG_EXT4_USE_FOR_EXT2=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
# CONFIG_EXT4_DEBUG is not set
CONFIG_EXT4_KUNIT_TESTS=m
CONFIG_JBD2=y
# CONFIG_JBD2_DEBUG is not set
CONFIG_FS_MBCACHE=y
CONFIG_JFS_FS=m
CONFIG_JFS_POSIX_ACL=y
CONFIG_JFS_SECURITY=y
# CONFIG_JFS_DEBUG is not set
# CONFIG_JFS_STATISTICS is not set
CONFIG_XFS_FS=m
CONFIG_XFS_SUPPORT_V4=y
CONFIG_XFS_SUPPORT_ASCII_CI=y
CONFIG_XFS_QUOTA=y
CONFIG_XFS_POSIX_ACL=y
CONFIG_XFS_RT=y
CONFIG_XFS_DRAIN_INTENTS=y
CONFIG_XFS_LIVE_HOOKS=y
CONFIG_XFS_MEMORY_BUFS=y
CONFIG_XFS_ONLINE_SCRUB=y
# CONFIG_XFS_ONLINE_SCRUB_STATS is not set
# CONFIG_XFS_ONLINE_REPAIR is not set
# CONFIG_XFS_WARN is not set
# CONFIG_XFS_DEBUG is not set
CONFIG_GFS2_FS=m
CONFIG_GFS2_FS_LOCKING_DLM=y
# CONFIG_OCFS2_FS is not set
CONFIG_BTRFS_FS=y
CONFIG_BTRFS_FS_POSIX_ACL=y
# CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set
# CONFIG_BTRFS_DEBUG is not set
# CONFIG_BTRFS_ASSERT is not set
# CONFIG_BTRFS_EXPERIMENTAL is not set
# CONFIG_BTRFS_FS_REF_VERIFY is not set
CONFIG_NILFS2_FS=m
CONFIG_F2FS_FS=m
CONFIG_F2FS_STAT_FS=y
CONFIG_F2FS_FS_XATTR=y
CONFIG_F2FS_FS_POSIX_ACL=y
CONFIG_F2FS_FS_SECURITY=y
# CONFIG_F2FS_CHECK_FS is not set
# CONFIG_F2FS_FAULT_INJECTION is not set
CONFIG_F2FS_FS_COMPRESSION=y
CONFIG_F2FS_FS_LZO=y
CONFIG_F2FS_FS_LZORLE=y
CONFIG_F2FS_FS_LZ4=y
CONFIG_F2FS_FS_LZ4HC=y
CONFIG_F2FS_FS_ZSTD=y
CONFIG_F2FS_IOSTAT=y
CONFIG_F2FS_UNFAIR_RWSEM=y
CONFIG_BCACHEFS_FS=m
CONFIG_BCACHEFS_QUOTA=y
# CONFIG_BCACHEFS_ERASURE_CODING is not set
CONFIG_BCACHEFS_POSIX_ACL=y
# CONFIG_BCACHEFS_DEBUG is not set
# CONFIG_BCACHEFS_TESTS is not set
# CONFIG_BCACHEFS_LOCK_TIME_STATS is not set
# CONFIG_BCACHEFS_NO_LATENCY_ACCT is not set
CONFIG_BCACHEFS_SIX_OPTIMISTIC_SPIN=y
# CONFIG_BCACHEFS_PATH_TRACEPOINTS is not set
# CONFIG_BCACHEFS_TRANS_KMALLOC_TRACE is not set
# CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS is not set
CONFIG_MEAN_AND_VARIANCE_UNIT_TEST=m
CONFIG_ZONEFS_FS=m
CONFIG_FS_DAX=y
CONFIG_FS_DAX_PMD=y
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
CONFIG_EXPORTFS_BLOCK_OPS=y
CONFIG_FILE_LOCKING=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION_ALGS=y
CONFIG_FS_ENCRYPTION_INLINE_CRYPT=y
CONFIG_FS_VERITY=y
# CONFIG_FS_VERITY_BUILTIN_SIGNATURES is not set
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
# CONFIG_QUOTA_DEBUG is not set
CONFIG_QUOTA_TREE=y
# CONFIG_QFMT_V1 is not set
CONFIG_QFMT_V2=y
CONFIG_QUOTACTL=y
CONFIG_AUTOFS_FS=y
CONFIG_FUSE_FS=m
CONFIG_CUSE=m
CONFIG_VIRTIO_FS=m
CONFIG_FUSE_DAX=y
CONFIG_FUSE_PASSTHROUGH=y
CONFIG_FUSE_IO_URING=y
CONFIG_OVERLAY_FS=m
# CONFIG_OVERLAY_FS_REDIRECT_DIR is not set
CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y
# CONFIG_OVERLAY_FS_INDEX is not set
# CONFIG_OVERLAY_FS_XINO_AUTO is not set
# CONFIG_OVERLAY_FS_METACOPY is not set
# CONFIG_OVERLAY_FS_DEBUG is not set

#
# Caches
#
CONFIG_NETFS_SUPPORT=m
CONFIG_NETFS_STATS=y
# CONFIG_NETFS_DEBUG is not set
CONFIG_FSCACHE=y
CONFIG_FSCACHE_STATS=y
CONFIG_CACHEFILES=m
# CONFIG_CACHEFILES_DEBUG is not set
# CONFIG_CACHEFILES_ERROR_INJECTION is not set
CONFIG_CACHEFILES_ONDEMAND=y
# end of Caches

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=m
CONFIG_JOLIET=y
CONFIG_ZISOFS=y
CONFIG_UDF_FS=m
# end of CD-ROM/DVD Filesystems

#
# DOS/FAT/EXFAT/NT Filesystems
#
CONFIG_FAT_FS=m
CONFIG_MSDOS_FS=m
CONFIG_VFAT_FS=m
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="ascii"
# CONFIG_FAT_DEFAULT_UTF8 is not set
CONFIG_FAT_KUNIT_TEST=m
CONFIG_EXFAT_FS=m
CONFIG_EXFAT_DEFAULT_IOCHARSET="utf8"
CONFIG_NTFS3_FS=m
# CONFIG_NTFS3_64BIT_CLUSTER is not set
CONFIG_NTFS3_LZX_XPRESS=y
CONFIG_NTFS3_FS_POSIX_ACL=y
# CONFIG_NTFS_FS is not set
# end of DOS/FAT/EXFAT/NT Filesystems

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_PROC_KCORE=y
CONFIG_PROC_VMCORE=y
CONFIG_PROC_VMCORE_DEVICE_DUMP=y
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
CONFIG_PROC_CHILDREN=y
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_INODE64=y
CONFIG_TMPFS_QUOTA=y
CONFIG_ARCH_SUPPORTS_HUGETLBFS=y
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_HUGETLB_PMD_PAGE_TABLE_SHARING=y
CONFIG_ARCH_HAS_GIGANTIC_PAGE=y
CONFIG_CONFIGFS_FS=y
CONFIG_EFIVAR_FS=y
# end of Pseudo filesystems

CONFIG_MISC_FILESYSTEMS=y
CONFIG_ORANGEFS_FS=m
# CONFIG_ADFS_FS is not set
# CONFIG_AFFS_FS is not set
CONFIG_ECRYPT_FS=m
# CONFIG_ECRYPT_FS_MESSAGING is not set
CONFIG_HFS_FS=m
CONFIG_HFSPLUS_FS=m
# CONFIG_BEFS_FS is not set
# CONFIG_BFS_FS is not set
# CONFIG_EFS_FS is not set
CONFIG_JFFS2_FS=m
CONFIG_JFFS2_FS_DEBUG=0
CONFIG_JFFS2_FS_WRITEBUFFER=y
# CONFIG_JFFS2_FS_WBUF_VERIFY is not set
CONFIG_JFFS2_SUMMARY=y
CONFIG_JFFS2_FS_XATTR=y
CONFIG_JFFS2_FS_POSIX_ACL=y
CONFIG_JFFS2_FS_SECURITY=y
# CONFIG_JFFS2_COMPRESSION_OPTIONS is not set
CONFIG_JFFS2_ZLIB=y
CONFIG_JFFS2_RTIME=y
CONFIG_UBIFS_FS=m
# CONFIG_UBIFS_FS_ADVANCED_COMPR is not set
CONFIG_UBIFS_FS_LZO=y
CONFIG_UBIFS_FS_ZLIB=y
CONFIG_UBIFS_FS_ZSTD=y
CONFIG_UBIFS_ATIME_SUPPORT=y
CONFIG_UBIFS_FS_XATTR=y
CONFIG_UBIFS_FS_SECURITY=y
CONFIG_UBIFS_FS_AUTHENTICATION=y
# CONFIG_CRAMFS is not set
CONFIG_SQUASHFS=m
# CONFIG_SQUASHFS_FILE_CACHE is not set
CONFIG_SQUASHFS_FILE_DIRECT=y
CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU=y
# CONFIG_SQUASHFS_CHOICE_DECOMP_BY_MOUNT is not set
# CONFIG_SQUASHFS_COMPILE_DECOMP_SINGLE is not set
# CONFIG_SQUASHFS_COMPILE_DECOMP_MULTI is not set
CONFIG_SQUASHFS_COMPILE_DECOMP_MULTI_PERCPU=y
CONFIG_SQUASHFS_XATTR=y
# CONFIG_SQUASHFS_COMP_CACHE_FULL is not set
CONFIG_SQUASHFS_ZLIB=y
CONFIG_SQUASHFS_LZ4=y
CONFIG_SQUASHFS_LZO=y
CONFIG_SQUASHFS_XZ=y
CONFIG_SQUASHFS_ZSTD=y
# CONFIG_SQUASHFS_4K_DEVBLK_SIZE is not set
# CONFIG_SQUASHFS_EMBEDDED is not set
CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3
# CONFIG_VXFS_FS is not set
CONFIG_MINIX_FS=m
# CONFIG_OMFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX6FS_FS is not set
CONFIG_ROMFS_FS=m
CONFIG_ROMFS_BACKED_BY_BLOCK=y
# CONFIG_ROMFS_BACKED_BY_MTD is not set
# CONFIG_ROMFS_BACKED_BY_BOTH is not set
CONFIG_ROMFS_ON_BLOCK=y
CONFIG_PSTORE=y
CONFIG_PSTORE_DEFAULT_KMSG_BYTES=10240
CONFIG_PSTORE_COMPRESS=y
# CONFIG_PSTORE_CONSOLE is not set
# CONFIG_PSTORE_PMSG is not set
# CONFIG_PSTORE_FTRACE is not set
CONFIG_PSTORE_RAM=m
# CONFIG_PSTORE_BLK is not set
CONFIG_UFS_FS=m
# CONFIG_UFS_FS_WRITE is not set
# CONFIG_UFS_DEBUG is not set
CONFIG_EROFS_FS=m
# CONFIG_EROFS_FS_DEBUG is not set
CONFIG_EROFS_FS_XATTR=y
CONFIG_EROFS_FS_POSIX_ACL=y
CONFIG_EROFS_FS_SECURITY=y
CONFIG_EROFS_FS_BACKED_BY_FILE=y
CONFIG_EROFS_FS_ZIP=y
CONFIG_EROFS_FS_ZIP_LZMA=y
CONFIG_EROFS_FS_ZIP_DEFLATE=y
CONFIG_EROFS_FS_ZIP_ZSTD=y
# CONFIG_EROFS_FS_ZIP_ACCEL is not set
CONFIG_EROFS_FS_ONDEMAND=y
# CONFIG_EROFS_FS_PCPU_KTHREAD is not set
CONFIG_VBOXSF_FS=m
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=m
# CONFIG_NFS_V2 is not set
CONFIG_NFS_V3=m
CONFIG_NFS_V3_ACL=y
CONFIG_NFS_V4=m
CONFIG_NFS_SWAP=y
CONFIG_NFS_V4_1=y
CONFIG_NFS_V4_2=y
CONFIG_PNFS_FILE_LAYOUT=m
CONFIG_PNFS_BLOCK=m
CONFIG_PNFS_FLEXFILE_LAYOUT=m
CONFIG_NFS_V4_1_IMPLEMENTATION_ID_DOMAIN="kernel.org"
# CONFIG_NFS_V4_1_MIGRATION is not set
CONFIG_NFS_V4_SECURITY_LABEL=y
CONFIG_NFS_FSCACHE=y
# CONFIG_NFS_USE_LEGACY_DNS is not set
CONFIG_NFS_USE_KERNEL_DNS=y
CONFIG_NFS_DEBUG=y
CONFIG_NFS_DISABLE_UDP_SUPPORT=y
# CONFIG_NFS_V4_2_READ_PLUS is not set
CONFIG_NFSD=m
# CONFIG_NFSD_V2 is not set
CONFIG_NFSD_V3_ACL=y
CONFIG_NFSD_V4=y
CONFIG_NFSD_PNFS=y
CONFIG_NFSD_BLOCKLAYOUT=y
CONFIG_NFSD_SCSILAYOUT=y
CONFIG_NFSD_FLEXFILELAYOUT=y
CONFIG_NFSD_V4_2_INTER_SSC=y
CONFIG_NFSD_V4_SECURITY_LABEL=y
# CONFIG_NFSD_LEGACY_CLIENT_TRACKING is not set
CONFIG_NFSD_V4_DELEG_TIMESTAMPS=y
CONFIG_GRACE_PERIOD=m
CONFIG_LOCKD=m
CONFIG_LOCKD_V4=y
CONFIG_NFS_ACL_SUPPORT=m
CONFIG_NFS_COMMON=y
CONFIG_NFS_COMMON_LOCALIO_SUPPORT=m
CONFIG_NFS_LOCALIO=y
CONFIG_NFS_V4_2_SSC_HELPER=y
CONFIG_SUNRPC=m
CONFIG_SUNRPC_GSS=m
CONFIG_SUNRPC_BACKCHANNEL=y
CONFIG_SUNRPC_SWAP=y
CONFIG_RPCSEC_GSS_KRB5=m
CONFIG_RPCSEC_GSS_KRB5_ENCTYPES_AES_SHA1=y
CONFIG_RPCSEC_GSS_KRB5_ENCTYPES_CAMELLIA=y
CONFIG_RPCSEC_GSS_KRB5_ENCTYPES_AES_SHA2=y
CONFIG_RPCSEC_GSS_KRB5_KUNIT_TEST=m
CONFIG_SUNRPC_DEBUG=y
CONFIG_SUNRPC_XPRT_RDMA=m
CONFIG_CEPH_FS=m
CONFIG_CEPH_FSCACHE=y
CONFIG_CEPH_FS_POSIX_ACL=y
CONFIG_CEPH_FS_SECURITY_LABEL=y
CONFIG_CIFS=m
# CONFIG_CIFS_STATS2 is not set
CONFIG_CIFS_ALLOW_INSECURE_LEGACY=y
CONFIG_CIFS_UPCALL=y
CONFIG_CIFS_XATTR=y
CONFIG_CIFS_POSIX=y
CONFIG_CIFS_DEBUG=y
# CONFIG_CIFS_DEBUG2 is not set
# CONFIG_CIFS_DEBUG_DUMP_KEYS is not set
CONFIG_CIFS_DFS_UPCALL=y
CONFIG_CIFS_SWN_UPCALL=y
# CONFIG_CIFS_SMB_DIRECT is not set
CONFIG_CIFS_FSCACHE=y
# CONFIG_CIFS_COMPRESSION is not set
# CONFIG_SMB_SERVER is not set
CONFIG_SMBFS=m
# CONFIG_CODA_FS is not set
CONFIG_AFS_FS=m
CONFIG_AFS_DEBUG=y
CONFIG_AFS_FSCACHE=y
# CONFIG_AFS_DEBUG_CURSOR is not set
CONFIG_9P_FS=m
CONFIG_9P_FSCACHE=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_CODEPAGE_737=m
CONFIG_NLS_CODEPAGE_775=m
CONFIG_NLS_CODEPAGE_850=m
CONFIG_NLS_CODEPAGE_852=m
CONFIG_NLS_CODEPAGE_855=m
CONFIG_NLS_CODEPAGE_857=m
CONFIG_NLS_CODEPAGE_860=m
CONFIG_NLS_CODEPAGE_861=m
CONFIG_NLS_CODEPAGE_862=m
CONFIG_NLS_CODEPAGE_863=m
CONFIG_NLS_CODEPAGE_864=m
CONFIG_NLS_CODEPAGE_865=m
CONFIG_NLS_CODEPAGE_866=m
CONFIG_NLS_CODEPAGE_869=m
CONFIG_NLS_CODEPAGE_936=m
CONFIG_NLS_CODEPAGE_950=m
CONFIG_NLS_CODEPAGE_932=m
CONFIG_NLS_CODEPAGE_949=m
CONFIG_NLS_CODEPAGE_874=m
CONFIG_NLS_ISO8859_8=m
CONFIG_NLS_CODEPAGE_1250=m
CONFIG_NLS_CODEPAGE_1251=m
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=m
CONFIG_NLS_ISO8859_2=m
CONFIG_NLS_ISO8859_3=m
CONFIG_NLS_ISO8859_4=m
CONFIG_NLS_ISO8859_5=m
CONFIG_NLS_ISO8859_6=m
CONFIG_NLS_ISO8859_7=m
CONFIG_NLS_ISO8859_9=m
CONFIG_NLS_ISO8859_13=m
CONFIG_NLS_ISO8859_14=m
CONFIG_NLS_ISO8859_15=m
CONFIG_NLS_KOI8_R=m
CONFIG_NLS_KOI8_U=m
CONFIG_NLS_MAC_ROMAN=m
CONFIG_NLS_MAC_CELTIC=m
CONFIG_NLS_MAC_CENTEURO=m
CONFIG_NLS_MAC_CROATIAN=m
CONFIG_NLS_MAC_CYRILLIC=m
CONFIG_NLS_MAC_GAELIC=m
CONFIG_NLS_MAC_GREEK=m
CONFIG_NLS_MAC_ICELAND=m
CONFIG_NLS_MAC_INUIT=m
CONFIG_NLS_MAC_ROMANIAN=m
CONFIG_NLS_MAC_TURKISH=m
CONFIG_NLS_UTF8=m
CONFIG_NLS_UCS2_UTILS=m
CONFIG_DLM=m
CONFIG_DLM_DEBUG=y
CONFIG_UNICODE=y
CONFIG_UNICODE_NORMALIZATION_KUNIT_TEST=m
CONFIG_IO_WQ=y
# end of File systems

#
# Security options
#
CONFIG_KEYS=y
CONFIG_KEYS_REQUEST_CACHE=y
CONFIG_PERSISTENT_KEYRINGS=y
CONFIG_BIG_KEYS=y
CONFIG_TRUSTED_KEYS=y
CONFIG_HAVE_TRUSTED_KEYS=y
CONFIG_TRUSTED_KEYS_TPM=y
CONFIG_ENCRYPTED_KEYS=y
# CONFIG_USER_DECRYPTED_DATA is not set
CONFIG_KEY_DH_OPERATIONS=y
CONFIG_KEY_NOTIFICATIONS=y
CONFIG_SECURITY_DMESG_RESTRICT=y
CONFIG_PROC_MEM_ALWAYS_FORCE=y
# CONFIG_PROC_MEM_FORCE_PTRACE is not set
# CONFIG_PROC_MEM_NO_FORCE is not set
CONFIG_SECURITY=y
CONFIG_HAS_SECURITY_AUDIT=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_INFINIBAND=y
CONFIG_SECURITY_NETWORK_XFRM=y
CONFIG_SECURITY_PATH=y
CONFIG_LSM_MMAP_MIN_ADDR=65535
# CONFIG_STATIC_USERMODEHELPER is not set
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE=256
# CONFIG_SECURITY_SELINUX_DEBUG is not set
# CONFIG_SECURITY_SMACK is not set
CONFIG_SECURITY_TOMOYO=y
CONFIG_SECURITY_TOMOYO_MAX_ACCEPT_ENTRY=2048
CONFIG_SECURITY_TOMOYO_MAX_AUDIT_LOG=1024
# CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER is not set
CONFIG_SECURITY_TOMOYO_POLICY_LOADER="/sbin/tomoyo-init"
CONFIG_SECURITY_TOMOYO_ACTIVATION_TRIGGER="/usr/lib/systemd/systemd"
# CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING is not set
# CONFIG_SECURITY_APPARMOR is not set
# CONFIG_SECURITY_LOADPIN is not set
CONFIG_SECURITY_YAMA=y
# CONFIG_SECURITY_SAFESETID is not set
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set
# CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY is not set
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_IPE=y
CONFIG_IPE_BOOT_POLICY=""
CONFIG_IPE_POLICY_SIG_SECONDARY_KEYRING=y
CONFIG_IPE_POLICY_SIG_PLATFORM_KEYRING=y

#
# IPE Trust Providers
#
CONFIG_IPE_PROP_DM_VERITY=y
CONFIG_IPE_PROP_DM_VERITY_SIGNATURE=y
CONFIG_IPE_PROP_FS_VERITY=y
# end of IPE Trust Providers

CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG_INTEGRITY_PLATFORM_KEYRING=y
CONFIG_INTEGRITY_MACHINE_KEYRING=y
CONFIG_INTEGRITY_CA_MACHINE_KEYRING=y
CONFIG_INTEGRITY_CA_MACHINE_KEYRING_MAX=y
CONFIG_LOAD_UEFI_KEYS=y
CONFIG_INTEGRITY_AUDIT=y
CONFIG_IMA=y
CONFIG_IMA_KEXEC=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_NG_TEMPLATE=y
# CONFIG_IMA_SIG_TEMPLATE is not set
CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng"
# CONFIG_IMA_DEFAULT_HASH_SHA1 is not set
CONFIG_IMA_DEFAULT_HASH_SHA256=y
# CONFIG_IMA_DEFAULT_HASH_SHA512 is not set
CONFIG_IMA_DEFAULT_HASH="sha256"
CONFIG_IMA_WRITE_POLICY=y
CONFIG_IMA_READ_POLICY=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_ARCH_POLICY=y
# CONFIG_IMA_APPRAISE_BUILD_POLICY is not set
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_APPRAISE_MODSIG=y
CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y
# CONFIG_IMA_BLACKLIST_KEYRING is not set
# CONFIG_IMA_LOAD_X509 is not set
CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS=y
CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS=y
CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y
# CONFIG_IMA_DISABLE_HTABLE is not set
CONFIG_IMA_KEXEC_EXTRA_MEMORY_KB=0
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
# CONFIG_EVM_ADD_XATTRS is not set
# CONFIG_EVM_LOAD_X509 is not set
CONFIG_DEFAULT_SECURITY_SELINUX=y
# CONFIG_DEFAULT_SECURITY_TOMOYO is not set
# CONFIG_DEFAULT_SECURITY_DAC is not set
CONFIG_LSM="lockdown,yama,integrity,selinux,bpf,landlock,ipe"

#
# Kernel hardening options
#

#
# Memory initialization
#
CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN=y
CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_BARE=y
CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO=y
# CONFIG_INIT_STACK_NONE is not set
# CONFIG_INIT_STACK_ALL_PATTERN is not set
CONFIG_INIT_STACK_ALL_ZERO=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
CONFIG_CC_HAS_ZERO_CALL_USED_REGS=y
# CONFIG_ZERO_CALL_USED_REGS is not set
# end of Memory initialization

#
# Bounds checking
#
CONFIG_FORTIFY_SOURCE=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y
# end of Bounds checking

#
# Hardening of kernel data structures
#
CONFIG_LIST_HARDENED=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
# end of Hardening of kernel data structures

CONFIG_RANDSTRUCT_NONE=y
# end of Kernel hardening options
# end of Security options

CONFIG_XOR_BLOCKS=y
CONFIG_ASYNC_CORE=m
CONFIG_ASYNC_MEMCPY=m
CONFIG_ASYNC_XOR=m
CONFIG_ASYNC_PQ=m
CONFIG_ASYNC_RAID6_RECOV=m
CONFIG_ASYNC_TX_DISABLE_PQ_VAL_DMA=y
CONFIG_ASYNC_TX_DISABLE_XOR_VAL_DMA=y
CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_SIG=y
CONFIG_CRYPTO_SIG2=y
CONFIG_CRYPTO_SKCIPHER=y
CONFIG_CRYPTO_SKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_KPP=y
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_HKDF=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
CONFIG_CRYPTO_USER=m
# CONFIG_CRYPTO_SELFTESTS is not set
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_PCRYPT=m
CONFIG_CRYPTO_CRYPTD=y
CONFIG_CRYPTO_AUTHENC=y
CONFIG_CRYPTO_KRB5ENC=m
# CONFIG_CRYPTO_BENCHMARK is not set
CONFIG_CRYPTO_ENGINE=y
# end of Crypto core or helper

#
# Public-key cryptography
#
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_DH=y
CONFIG_CRYPTO_DH_RFC7919_GROUPS=y
CONFIG_CRYPTO_ECC=y
CONFIG_CRYPTO_ECDH=y
CONFIG_CRYPTO_ECDSA=y
CONFIG_CRYPTO_ECRDSA=m
CONFIG_CRYPTO_CURVE25519=m
# end of Public-key cryptography

#
# Block ciphers
#
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_AES_TI=m
# CONFIG_CRYPTO_ARIA is not set
CONFIG_CRYPTO_BLOWFISH=m
CONFIG_CRYPTO_BLOWFISH_COMMON=m
CONFIG_CRYPTO_CAMELLIA=m
CONFIG_CRYPTO_CAST_COMMON=m
CONFIG_CRYPTO_CAST5=m
CONFIG_CRYPTO_CAST6=m
CONFIG_CRYPTO_DES=m
CONFIG_CRYPTO_FCRYPT=m
CONFIG_CRYPTO_SERPENT=m
# CONFIG_CRYPTO_SM4_GENERIC is not set
CONFIG_CRYPTO_TWOFISH=m
CONFIG_CRYPTO_TWOFISH_COMMON=m
# end of Block ciphers

#
# Length-preserving ciphers and modes
#
CONFIG_CRYPTO_ADIANTUM=m
CONFIG_CRYPTO_CHACHA20=m
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_CTS=y
CONFIG_CRYPTO_ECB=y
CONFIG_CRYPTO_HCTR2=m
CONFIG_CRYPTO_LRW=m
CONFIG_CRYPTO_PCBC=m
CONFIG_CRYPTO_XCTR=m
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_NHPOLY1305=m
# end of Length-preserving ciphers and modes

#
# AEAD (authenticated encryption with associated data) ciphers
#
CONFIG_CRYPTO_AEGIS128=m
CONFIG_CRYPTO_AEGIS128_SIMD=y
CONFIG_CRYPTO_CHACHA20POLY1305=m
CONFIG_CRYPTO_CCM=y
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_GENIV=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=m
CONFIG_CRYPTO_ESSIV=m
# end of AEAD (authenticated encryption with associated data) ciphers

#
# Hashes, digests, and MACs
#
CONFIG_CRYPTO_BLAKE2B=y
CONFIG_CRYPTO_CMAC=y
CONFIG_CRYPTO_GHASH=y
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_MD4=m
CONFIG_CRYPTO_MD5=y
CONFIG_CRYPTO_MICHAEL_MIC=m
CONFIG_CRYPTO_POLYVAL=m
CONFIG_CRYPTO_RMD160=m
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=y
# CONFIG_CRYPTO_SM3_GENERIC is not set
CONFIG_CRYPTO_STREEBOG=m
CONFIG_CRYPTO_WP512=m
CONFIG_CRYPTO_XCBC=m
CONFIG_CRYPTO_XXHASH=y
# end of Hashes, digests, and MACs

#
# CRCs (cyclic redundancy checks)
#
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_CRC32=m
# end of CRCs (cyclic redundancy checks)

#
# Compression
#
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZO=y
CONFIG_CRYPTO_842=y
CONFIG_CRYPTO_LZ4=m
CONFIG_CRYPTO_LZ4HC=m
CONFIG_CRYPTO_ZSTD=m
# end of Compression

#
# Random number generation
#
CONFIG_CRYPTO_ANSI_CPRNG=m
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
CONFIG_CRYPTO_DRBG_HASH=y
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
CONFIG_CRYPTO_JITTERENTROPY_MEMORY_BLOCKS=64
CONFIG_CRYPTO_JITTERENTROPY_MEMORY_BLOCKSIZE=32
CONFIG_CRYPTO_JITTERENTROPY_OSR=1
CONFIG_CRYPTO_KDF800108_CTR=y
# end of Random number generation

#
# Userspace interface
#
CONFIG_CRYPTO_USER_API=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
CONFIG_CRYPTO_USER_API_RNG=y
# CONFIG_CRYPTO_USER_API_RNG_CAVP is not set
CONFIG_CRYPTO_USER_API_AEAD=y
# CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE is not set
# end of Userspace interface

CONFIG_CRYPTO_NHPOLY1305_NEON=m

#
# Accelerated Cryptographic Algorithms for CPU (arm64)
#
CONFIG_CRYPTO_GHASH_ARM64_CE=m
CONFIG_CRYPTO_SHA3_ARM64=m
# CONFIG_CRYPTO_SM3_NEON is not set
# CONFIG_CRYPTO_SM3_ARM64_CE is not set
CONFIG_CRYPTO_POLYVAL_ARM64_CE=m
CONFIG_CRYPTO_AES_ARM64=y
CONFIG_CRYPTO_AES_ARM64_CE=y
CONFIG_CRYPTO_AES_ARM64_CE_BLK=y
CONFIG_CRYPTO_AES_ARM64_NEON_BLK=y
CONFIG_CRYPTO_AES_ARM64_BS=m
# CONFIG_CRYPTO_SM4_ARM64_CE is not set
# CONFIG_CRYPTO_SM4_ARM64_CE_BLK is not set
# CONFIG_CRYPTO_SM4_ARM64_NEON_BLK is not set
CONFIG_CRYPTO_AES_ARM64_CE_CCM=y
# CONFIG_CRYPTO_SM4_ARM64_CE_CCM is not set
# CONFIG_CRYPTO_SM4_ARM64_CE_GCM is not set
# end of Accelerated Cryptographic Algorithms for CPU (arm64)

CONFIG_CRYPTO_HW=y
CONFIG_CRYPTO_DEV_ALLWINNER=y
CONFIG_CRYPTO_DEV_SUN4I_SS=m
CONFIG_CRYPTO_DEV_SUN4I_SS_PRNG=y
# CONFIG_CRYPTO_DEV_SUN4I_SS_DEBUG is not set
CONFIG_CRYPTO_DEV_SUN8I_CE=m
# CONFIG_CRYPTO_DEV_SUN8I_CE_DEBUG is not set
CONFIG_CRYPTO_DEV_SUN8I_CE_HASH=y
CONFIG_CRYPTO_DEV_SUN8I_CE_PRNG=y
CONFIG_CRYPTO_DEV_SUN8I_CE_TRNG=y
CONFIG_CRYPTO_DEV_SUN8I_SS=m
# CONFIG_CRYPTO_DEV_SUN8I_SS_DEBUG is not set
CONFIG_CRYPTO_DEV_SUN8I_SS_PRNG=y
CONFIG_CRYPTO_DEV_SUN8I_SS_HASH=y
CONFIG_CRYPTO_DEV_FSL_CAAM_COMMON=m
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_DESC=m
CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API_DESC=m
CONFIG_CRYPTO_DEV_FSL_CAAM=m
# CONFIG_CRYPTO_DEV_FSL_CAAM_DEBUG is not set
CONFIG_CRYPTO_DEV_FSL_CAAM_JR=m
CONFIG_CRYPTO_DEV_FSL_CAAM_RINGSIZE=3
CONFIG_CRYPTO_DEV_FSL_CAAM_INTC=y
CONFIG_CRYPTO_DEV_FSL_CAAM_INTC_COUNT_THLD=8
CONFIG_CRYPTO_DEV_FSL_CAAM_INTC_TIME_THLD=8192
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_QI=y
CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_PKC_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_PRNG_API=y
# CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_TEST is not set
CONFIG_CRYPTO_DEV_FSL_DPAA2_CAAM=m
# CONFIG_CRYPTO_DEV_SAHARA is not set
CONFIG_CRYPTO_DEV_ATMEL_I2C=m
CONFIG_CRYPTO_DEV_ATMEL_ECC=m
CONFIG_CRYPTO_DEV_ATMEL_SHA204A=m
CONFIG_CRYPTO_DEV_CCP=y
CONFIG_CRYPTO_DEV_CCP_DD=m
CONFIG_CRYPTO_DEV_SP_CCP=y
CONFIG_CRYPTO_DEV_CCP_CRYPTO=m
# CONFIG_CRYPTO_DEV_CCP_DEBUGFS is not set
# CONFIG_CRYPTO_DEV_MXS_DCP is not set
CONFIG_CRYPTO_DEV_CPT=m
CONFIG_CAVIUM_CPT=m
CONFIG_CRYPTO_DEV_NITROX=m
CONFIG_CRYPTO_DEV_NITROX_CNN55XX=m
CONFIG_CRYPTO_DEV_MARVELL=m
CONFIG_CRYPTO_DEV_MARVELL_CESA=m
CONFIG_CRYPTO_DEV_OCTEONTX_CPT=m
CONFIG_CRYPTO_DEV_OCTEONTX2_CPT=m
CONFIG_CRYPTO_DEV_QAT=m
CONFIG_CRYPTO_DEV_QAT_DH895xCC=m
CONFIG_CRYPTO_DEV_QAT_C3XXX=m
CONFIG_CRYPTO_DEV_QAT_C62X=m
CONFIG_CRYPTO_DEV_QAT_4XXX=m
CONFIG_CRYPTO_DEV_QAT_420XX=m
CONFIG_CRYPTO_DEV_QAT_DH895xCCVF=m
CONFIG_CRYPTO_DEV_QAT_C3XXXVF=m
CONFIG_CRYPTO_DEV_QAT_C62XVF=m
# CONFIG_CRYPTO_DEV_QAT_ERROR_INJECTION is not set
CONFIG_CRYPTO_DEV_QCE=m
CONFIG_CRYPTO_DEV_QCE_SKCIPHER=y
CONFIG_CRYPTO_DEV_QCE_SHA=y
CONFIG_CRYPTO_DEV_QCE_AEAD=y
CONFIG_CRYPTO_DEV_QCE_ENABLE_ALL=y
# CONFIG_CRYPTO_DEV_QCE_ENABLE_SKCIPHER is not set
# CONFIG_CRYPTO_DEV_QCE_ENABLE_SHA is not set
# CONFIG_CRYPTO_DEV_QCE_ENABLE_AEAD is not set
CONFIG_CRYPTO_DEV_QCE_SW_MAX_LEN=512
CONFIG_CRYPTO_DEV_QCOM_RNG=m
CONFIG_CRYPTO_DEV_ROCKCHIP=m
# CONFIG_CRYPTO_DEV_ROCKCHIP_DEBUG is not set
CONFIG_CRYPTO_DEV_TEGRA=m
CONFIG_CRYPTO_DEV_ZYNQMP_AES=m
# CONFIG_CRYPTO_DEV_ZYNQMP_SHA3 is not set
CONFIG_CRYPTO_DEV_CHELSIO=m
CONFIG_CRYPTO_DEV_VIRTIO=m
CONFIG_CRYPTO_DEV_SAFEXCEL=m
# CONFIG_CRYPTO_DEV_CCREE is not set
# CONFIG_CRYPTO_DEV_HISI_SEC is not set
# CONFIG_CRYPTO_DEV_HISI_SEC2 is not set
CONFIG_CRYPTO_DEV_HISI_QM=m
# CONFIG_CRYPTO_DEV_HISI_ZIP is not set
CONFIG_CRYPTO_DEV_HISI_HPRE=m
CONFIG_CRYPTO_DEV_HISI_TRNG=m
CONFIG_CRYPTO_DEV_AMLOGIC_GXL=y
# CONFIG_CRYPTO_DEV_AMLOGIC_GXL_DEBUG is not set
CONFIG_CRYPTO_DEV_SA2UL=m
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS8_PRIVATE_KEY_PARSER=m
CONFIG_PKCS7_MESSAGE_PARSER=y
# CONFIG_PKCS7_TEST_KEY is not set
CONFIG_SIGNED_PE_FILE_VERIFICATION=y
# CONFIG_FIPS_SIGNATURE_SELFTEST is not set

#
# Certificates for signature checking
#
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
# CONFIG_MODULE_SIG_KEY_TYPE_ECDSA is not set
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_EXTRA_CERTIFICATE=y
CONFIG_SYSTEM_EXTRA_CERTIFICATE_SIZE=4096
CONFIG_SECONDARY_TRUSTED_KEYRING=y
# CONFIG_SECONDARY_TRUSTED_KEYRING_SIGNED_BY_BUILTIN is not set
CONFIG_SYSTEM_BLACKLIST_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
# CONFIG_SYSTEM_REVOCATION_LIST is not set
CONFIG_SYSTEM_BLACKLIST_AUTH_UPDATE=y
# end of Certificates for signature checking

CONFIG_CRYPTO_KRB5=m
# CONFIG_CRYPTO_KRB5_SELFTESTS is not set
CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_RAID6_PQ=y
# CONFIG_RAID6_PQ_BENCHMARK is not set
CONFIG_LINEAR_RANGES=y
CONFIG_PACKING=y
CONFIG_PACKING_KUNIT_TEST=m
CONFIG_BITREVERSE=y
CONFIG_HAVE_ARCH_BITREVERSE=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_CORDIC=m
CONFIG_PRIME_NUMBERS=m
CONFIG_RATIONAL=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
CONFIG_ARCH_USE_SYM_ANNOTATIONS=y
CONFIG_INDIRECT_PIO=y
# CONFIG_TRACE_MMIO_ACCESS is not set
CONFIG_CRC7=m
CONFIG_CRC8=y
CONFIG_CRC16=y
CONFIG_CRC_CCITT=y
CONFIG_CRC_ITU_T=m
CONFIG_CRC_T10DIF=y
CONFIG_CRC_T10DIF_ARCH=y
CONFIG_CRC32=y
CONFIG_CRC32_ARCH=y
CONFIG_CRC64=y
CONFIG_CRC_OPTIMIZATIONS=y
CONFIG_CRC_KUNIT_TEST=m
# CONFIG_CRC_BENCHMARK is not set

#
# Crypto library routines
#
CONFIG_CRYPTO_HASH_INFO=y
CONFIG_CRYPTO_LIB_UTILS=y
CONFIG_CRYPTO_LIB_AES=y
CONFIG_CRYPTO_LIB_AESCFB=y
CONFIG_CRYPTO_LIB_ARC4=m
CONFIG_CRYPTO_LIB_GF128MUL=y
CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=y
CONFIG_CRYPTO_LIB_CHACHA_GENERIC=y
CONFIG_CRYPTO_LIB_CHACHA=y
CONFIG_CRYPTO_LIB_CURVE25519_GENERIC=m
CONFIG_CRYPTO_LIB_CURVE25519_INTERNAL=m
CONFIG_CRYPTO_LIB_CURVE25519=m
CONFIG_CRYPTO_LIB_DES=m
CONFIG_CRYPTO_LIB_POLY1305_RSIZE=9
CONFIG_CRYPTO_ARCH_HAVE_LIB_POLY1305=y
CONFIG_CRYPTO_LIB_POLY1305_GENERIC=m
CONFIG_CRYPTO_LIB_POLY1305=y
CONFIG_CRYPTO_LIB_CHACHA20POLY1305=y
CONFIG_CRYPTO_LIB_SHA1=y
CONFIG_CRYPTO_LIB_SHA1_ARCH=y
CONFIG_CRYPTO_LIB_SHA256=y
CONFIG_CRYPTO_LIB_SHA256_ARCH=y
CONFIG_CRYPTO_LIB_SHA512=y
CONFIG_CRYPTO_LIB_SHA512_ARCH=y
CONFIG_CRYPTO_LIB_POLY1305_KUNIT_TEST=m
CONFIG_CRYPTO_LIB_SHA1_KUNIT_TEST=m
CONFIG_CRYPTO_LIB_SHA256_KUNIT_TEST=m
CONFIG_CRYPTO_LIB_SHA512_KUNIT_TEST=m
CONFIG_CRYPTO_LIB_BENCHMARK_VISIBLE=y
# CONFIG_CRYPTO_LIB_BENCHMARK is not set
CONFIG_CRYPTO_CHACHA20_NEON=y
CONFIG_CRYPTO_POLY1305_NEON=y
# end of Crypto library routines

CONFIG_XXHASH=y
CONFIG_AUDIT_GENERIC=y
CONFIG_AUDIT_ARCH_COMPAT_GENERIC=y
CONFIG_AUDIT_COMPAT_GENERIC=y
# CONFIG_RANDOM32_SELFTEST is not set
CONFIG_842_COMPRESS=y
CONFIG_842_DECOMPRESS=y
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_COMPRESS=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4_COMPRESS=m
CONFIG_LZ4HC_COMPRESS=m
CONFIG_LZ4_DECOMPRESS=y
CONFIG_ZSTD_COMMON=y
CONFIG_ZSTD_COMPRESS=y
CONFIG_ZSTD_DECOMPRESS=y
CONFIG_XZ_DEC=y
CONFIG_XZ_DEC_X86=y
CONFIG_XZ_DEC_POWERPC=y
CONFIG_XZ_DEC_ARM=y
CONFIG_XZ_DEC_ARMTHUMB=y
CONFIG_XZ_DEC_ARM64=y
CONFIG_XZ_DEC_SPARC=y
CONFIG_XZ_DEC_RISCV=y
CONFIG_XZ_DEC_MICROLZMA=y
CONFIG_XZ_DEC_BCJ=y
# CONFIG_XZ_DEC_TEST is not set
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_XZ=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_DECOMPRESS_ZSTD=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_REED_SOLOMON=m
CONFIG_REED_SOLOMON_ENC8=y
CONFIG_REED_SOLOMON_DEC8=y
CONFIG_TEXTSEARCH=y
CONFIG_TEXTSEARCH_KMP=m
CONFIG_TEXTSEARCH_BM=m
CONFIG_TEXTSEARCH_FSM=m
CONFIG_BTREE=y
CONFIG_INTERVAL_TREE=y
CONFIG_INTERVAL_TREE_SPAN_ITER=y
CONFIG_XARRAY_MULTI=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_CLOSURES=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_DMA_OPS_HELPERS=y
CONFIG_NEED_SG_DMA_FLAGS=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_DMA_DECLARE_COHERENT=y
CONFIG_ARCH_HAS_SETUP_DMA_OPS=y
CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE=y
CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU=y
CONFIG_ARCH_HAS_DMA_PREP_COHERENT=y
CONFIG_ARCH_HAS_FORCE_DMA_UNENCRYPTED=y
CONFIG_SWIOTLB=y
# CONFIG_SWIOTLB_DYNAMIC is not set
CONFIG_DMA_BOUNCE_UNALIGNED_KMALLOC=y
CONFIG_DMA_NEED_SYNC=y
# CONFIG_DMA_RESTRICTED_POOL is not set
CONFIG_DMA_NONCOHERENT_MMAP=y
CONFIG_DMA_COHERENT_POOL=y
CONFIG_DMA_DIRECT_REMAP=y
CONFIG_DMA_CMA=y
CONFIG_DMA_NUMA_CMA=y

#
# Default contiguous memory area size:
#
CONFIG_CMA_SIZE_MBYTES=64
CONFIG_CMA_SIZE_SEL_MBYTES=y
# CONFIG_CMA_SIZE_SEL_PERCENTAGE is not set
# CONFIG_CMA_SIZE_SEL_MIN is not set
# CONFIG_CMA_SIZE_SEL_MAX is not set
CONFIG_CMA_ALIGNMENT=8
# CONFIG_DMA_API_DEBUG is not set
# CONFIG_DMA_MAP_BENCHMARK is not set
CONFIG_SGL_ALLOC=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_CPUMASK_OFFSTACK=y
CONFIG_CPU_RMAP=y
CONFIG_DQL=y
CONFIG_GLOB=y
# CONFIG_GLOB_SELFTEST is not set
CONFIG_NLATTR=y
CONFIG_LRU_CACHE=m
CONFIG_CLZ_TAB=y
CONFIG_IRQ_POLL=y
CONFIG_MPILIB=y
CONFIG_SIGNATURE=y
CONFIG_DIMLIB=y
CONFIG_LIBFDT=y
CONFIG_OID_REGISTRY=y
CONFIG_UCS2_STRING=y
CONFIG_HAVE_GENERIC_VDSO=y
CONFIG_GENERIC_GETTIMEOFDAY=y
CONFIG_GENERIC_VDSO_TIME_NS=y
CONFIG_VDSO_GETRANDOM=y
CONFIG_GENERIC_VDSO_DATA_STORE=y
CONFIG_FONT_SUPPORT=y
# CONFIG_FONTS is not set
CONFIG_FONT_8x8=y
CONFIG_FONT_8x16=y
CONFIG_SG_SPLIT=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_MEMREGION=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_STACKWALK=y
CONFIG_STACKDEPOT=y
CONFIG_STACKDEPOT_ALWAYS_INIT=y
CONFIG_STACKDEPOT_MAX_FRAMES=64
CONFIG_SBITMAP=y
CONFIG_PARMAN=m
CONFIG_OBJAGG=m
# CONFIG_LWQ_TEST is not set
# end of Library routines

CONFIG_GENERIC_IOREMAP=y
CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED=y
CONFIG_PLDMFW=y
CONFIG_ASN1_ENCODER=y
CONFIG_POLYNOMIAL=m
CONFIG_FIRMWARE_TABLE=y
CONFIG_UNION_FIND=y
CONFIG_MIN_HEAP=y

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
# CONFIG_PRINTK_CALLER is not set
# CONFIG_STACKTRACE_BUILD_ID is not set
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=3
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
CONFIG_BOOT_PRINTK_DELAY=y
CONFIG_DYNAMIC_DEBUG=y
CONFIG_DYNAMIC_DEBUG_CORE=y
CONFIG_SYMBOLIC_ERRNAME=y
CONFIG_DEBUG_BUGVERBOSE=y
# end of printk and dmesg options

CONFIG_DEBUG_KERNEL=y
# CONFIG_DEBUG_MISC is not set

#
# Compile-time checks and compiler options
#
CONFIG_AS_HAS_NON_CONST_ULEB128=y
CONFIG_DEBUG_INFO_NONE=y
# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set
# CONFIG_DEBUG_INFO_DWARF4 is not set
# CONFIG_DEBUG_INFO_DWARF5 is not set
CONFIG_FRAME_WARN=2048
CONFIG_STRIP_ASM_SYMS=y
# CONFIG_READABLE_ASM is not set
CONFIG_HEADERS_INSTALL=y
CONFIG_DEBUG_SECTION_MISMATCH=y
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
# CONFIG_DEBUG_FORCE_FUNCTION_ALIGN_64B is not set
CONFIG_ARCH_WANT_FRAME_POINTERS=y
CONFIG_FRAME_POINTER=y
# CONFIG_VMLINUX_MAP is not set
# CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
# end of Compile-time checks and compiler options

#
# Generic Kernel Debugging Instruments
#
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x0
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_MAGIC_SYSRQ_SERIAL_SEQUENCE=""
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_FS_ALLOW_ALL=y
# CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
# CONFIG_DEBUG_FS_ALLOW_NONE is not set
CONFIG_HAVE_ARCH_KGDB=y
CONFIG_KGDB=y
CONFIG_KGDB_HONOUR_BLOCKLIST=y
CONFIG_KGDB_SERIAL_CONSOLE=y
CONFIG_KGDB_TESTS=y
# CONFIG_KGDB_TESTS_ON_BOOT is not set
# CONFIG_KGDB_KDB is not set
CONFIG_ARCH_HAS_UBSAN=y
CONFIG_UBSAN=y
# CONFIG_UBSAN_TRAP is not set
CONFIG_CC_HAS_UBSAN_BOUNDS_STRICT=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_UBSAN_BOUNDS_STRICT=y
CONFIG_UBSAN_SHIFT=y
# CONFIG_UBSAN_DIV_ZERO is not set
# CONFIG_UBSAN_UNREACHABLE is not set
# CONFIG_UBSAN_BOOL is not set
# CONFIG_UBSAN_ENUM is not set
# CONFIG_UBSAN_ALIGNMENT is not set
# CONFIG_TEST_UBSAN is not set
# CONFIG_UBSAN_KVM_EL2 is not set
CONFIG_HAVE_ARCH_KCSAN=y
CONFIG_HAVE_KCSAN_COMPILER=y
# end of Generic Kernel Debugging Instruments

#
# Networking Debugging
#
# CONFIG_NET_DEV_REFCNT_TRACKER is not set
# CONFIG_NET_NS_REFCNT_TRACKER is not set
# CONFIG_DEBUG_NET is not set
# CONFIG_DEBUG_NET_SMALL_RTNL is not set
# end of Networking Debugging

#
# Memory Debugging
#
CONFIG_PAGE_EXTENSION=y
# CONFIG_DEBUG_PAGEALLOC is not set
CONFIG_SLUB_DEBUG=y
# CONFIG_SLUB_DEBUG_ON is not set
CONFIG_SLUB_RCU_DEBUG=y
CONFIG_PAGE_OWNER=y
# CONFIG_PAGE_TABLE_CHECK is not set
CONFIG_PAGE_POISONING=y
# CONFIG_DEBUG_PAGE_REF is not set
# CONFIG_DEBUG_RODATA_TEST is not set
CONFIG_ARCH_HAS_DEBUG_WX=y
CONFIG_DEBUG_WX=y
CONFIG_ARCH_HAS_PTDUMP=y
CONFIG_PTDUMP=y
# CONFIG_PTDUMP_DEBUGFS is not set
CONFIG_HAVE_DEBUG_KMEMLEAK=y
# CONFIG_DEBUG_KMEMLEAK is not set
# CONFIG_PER_VMA_LOCK_STATS is not set
# CONFIG_DEBUG_OBJECTS is not set
# CONFIG_SHRINKER_DEBUG is not set
# CONFIG_DEBUG_STACK_USAGE is not set
CONFIG_SCHED_STACK_END_CHECK=y
CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=y
# CONFIG_DEBUG_VFS is not set
# CONFIG_DEBUG_VM is not set
# CONFIG_DEBUG_VM_PGTABLE is not set
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
# CONFIG_DEBUG_VIRTUAL is not set
CONFIG_DEBUG_MEMORY_INIT=y
# CONFIG_DEBUG_PER_CPU_MAPS is not set
# CONFIG_MEM_ALLOC_PROFILING is not set
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_SW_TAGS=y
CONFIG_HAVE_ARCH_KASAN_HW_TAGS=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_CC_HAS_KASAN_SW_TAGS=y
CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS=y
CONFIG_KASAN=y
CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=y
# CONFIG_KASAN_GENERIC is not set
CONFIG_KASAN_SW_TAGS=y
# CONFIG_KASAN_HW_TAGS is not set
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y
CONFIG_KASAN_KUNIT_TEST=m
# CONFIG_KASAN_EXTRA_INFO is not set
CONFIG_HAVE_ARCH_KFENCE=y
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100
CONFIG_KFENCE_NUM_OBJECTS=255
# CONFIG_KFENCE_DEFERRABLE is not set
# CONFIG_KFENCE_STATIC_KEYS is not set
CONFIG_KFENCE_STRESS_TEST_FAULTS=0
CONFIG_KFENCE_KUNIT_TEST=m
# end of Memory Debugging

CONFIG_DEBUG_SHIRQ=y

#
# Debug Oops, Lockups and Hangs
#
# CONFIG_PANIC_ON_OOPS is not set
CONFIG_PANIC_ON_OOPS_VALUE=0
CONFIG_PANIC_TIMEOUT=0
CONFIG_LOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR_INTR_STORM=y
# CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC is not set
CONFIG_HAVE_HARDLOCKUP_DETECTOR_BUDDY=y
CONFIG_HARDLOCKUP_DETECTOR=y
# CONFIG_HARDLOCKUP_DETECTOR_PREFER_BUDDY is not set
CONFIG_HARDLOCKUP_DETECTOR_PERF=y
# CONFIG_HARDLOCKUP_DETECTOR_BUDDY is not set
# CONFIG_HARDLOCKUP_DETECTOR_ARCH is not set
CONFIG_HARDLOCKUP_DETECTOR_COUNTS_HRTIMER=y
# CONFIG_BOOTPARAM_HARDLOCKUP_PANIC is not set
# CONFIG_DETECT_HUNG_TASK is not set
# CONFIG_WQ_WATCHDOG is not set
# CONFIG_WQ_CPU_INTENSIVE_REPORT is not set
CONFIG_TEST_LOCKUP=m
# end of Debug Oops, Lockups and Hangs

#
# Scheduler Debugging
#
CONFIG_SCHED_INFO=y
CONFIG_SCHEDSTATS=y
# end of Scheduler Debugging

# CONFIG_DEBUG_PREEMPT is not set

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
# CONFIG_DEBUG_RT_MUTEXES is not set
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_MUTEXES is not set
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
# CONFIG_DEBUG_RWSEMS is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
# CONFIG_DEBUG_ATOMIC_SLEEP is not set
# CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
CONFIG_LOCK_TORTURE_TEST=m
# CONFIG_WW_MUTEX_SELFTEST is not set
# CONFIG_SCF_TORTURE_TEST is not set
# CONFIG_CSD_LOCK_WAIT_DEBUG is not set
# end of Lock Debugging (spinlocks, mutexes, etc...)

# CONFIG_DEBUG_IRQFLAGS is not set
CONFIG_STACKTRACE=y
# CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
# CONFIG_DEBUG_KOBJECT is not set

#
# Debug kernel data structures
#
CONFIG_DEBUG_LIST=y
# CONFIG_DEBUG_PLIST is not set
# CONFIG_DEBUG_SG is not set
# CONFIG_DEBUG_NOTIFIERS is not set
# CONFIG_DEBUG_CLOSURES is not set
# CONFIG_DEBUG_MAPLE_TREE is not set
# end of Debug kernel data structures

#
# RCU Debugging
#
CONFIG_TORTURE_TEST=m
# CONFIG_RCU_SCALE_TEST is not set
CONFIG_RCU_TORTURE_TEST=m
# CONFIG_RCU_TORTURE_TEST_CHK_RDR_STATE is not set
# CONFIG_RCU_TORTURE_TEST_LOG_CPU is not set
# CONFIG_RCU_TORTURE_TEST_LOG_GP is not set
# CONFIG_RCU_REF_SCALE_TEST is not set
CONFIG_RCU_CPU_STALL_TIMEOUT=60
CONFIG_RCU_EXP_CPU_STALL_TIMEOUT=0
# CONFIG_RCU_CPU_STALL_CPUTIME is not set
CONFIG_RCU_TRACE=y
# CONFIG_RCU_EQS_DEBUG is not set
# end of RCU Debugging

# CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
# CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
CONFIG_LATENCYTOP=y
# CONFIG_DEBUG_CGROUP_REF is not set
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_FREGS=y
CONFIG_HAVE_FTRACE_GRAPH_FUNC=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_CALL_OPS=y
CONFIG_HAVE_EXTRA_IPI_TRACEPOINTS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_HAVE_BUILDTIME_MCOUNT_SORT=y
CONFIG_BUILDTIME_MCOUNT_SORT=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
CONFIG_TRACEFS_AUTOMOUNT_DEPRECATED=y
CONFIG_BOOTTIME_TRACING=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_FUNCTION_GRAPH_RETVAL=y
# CONFIG_FUNCTION_GRAPH_RETADDR is not set
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DYNAMIC_FTRACE_WITH_CALL_OPS=y
CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_FPROBE=y
CONFIG_FUNCTION_PROFILER=y
CONFIG_STACK_TRACER=y
# CONFIG_IRQSOFF_TRACER is not set
# CONFIG_PREEMPT_TRACER is not set
CONFIG_SCHED_TRACER=y
CONFIG_HWLAT_TRACER=y
CONFIG_OSNOISE_TRACER=y
CONFIG_TIMERLAT_TRACER=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
# CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP is not set
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
CONFIG_BLK_DEV_IO_TRACE=y
CONFIG_FPROBE_EVENTS=y
CONFIG_KPROBE_EVENTS=y
# CONFIG_KPROBE_EVENTS_ON_NOTRACE is not set
CONFIG_UPROBE_EVENTS=y
CONFIG_EPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
CONFIG_DYNAMIC_EVENTS=y
CONFIG_PROBE_EVENTS=y
CONFIG_FTRACE_MCOUNT_USE_PATCHABLE_FUNCTION_ENTRY=y
CONFIG_TRACING_MAP=y
CONFIG_SYNTH_EVENTS=y
# CONFIG_USER_EVENTS is not set
CONFIG_HIST_TRIGGERS=y
# CONFIG_TRACE_EVENT_INJECT is not set
# CONFIG_TRACEPOINT_BENCHMARK is not set
CONFIG_RING_BUFFER_BENCHMARK=m
CONFIG_TRACE_EVAL_MAP_FILE=y
# CONFIG_FTRACE_RECORD_RECURSION is not set
# CONFIG_FTRACE_VALIDATE_RCU_IS_WATCHING is not set
# CONFIG_FTRACE_STARTUP_TEST is not set
# CONFIG_FTRACE_SORT_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS is not set
# CONFIG_PREEMPTIRQ_DELAY_TEST is not set
# CONFIG_SYNTH_EVENT_GEN_TEST is not set
# CONFIG_KPROBE_EVENT_GEN_TEST is not set
# CONFIG_HIST_TRIGGERS_DEBUG is not set
CONFIG_RV_MON_EVENTS=y
CONFIG_RV_MON_MAINTENANCE_EVENTS=y
CONFIG_DA_MON_EVENTS_ID=y
CONFIG_RV=y
CONFIG_RV_PER_TASK_MONITORS=2
CONFIG_RV_MON_WWNR=y
# CONFIG_RV_MON_RTAPP is not set
CONFIG_RV_REACTORS=y
CONFIG_RV_REACT_PRINTK=y
CONFIG_RV_REACT_PANIC=y
# CONFIG_SAMPLES is not set
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT=y
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT_MULTI=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y

#
# arm64 Debugging
#
CONFIG_PID_IN_CONTEXTIDR=y
# CONFIG_ARM64_RELOC_TEST is not set
CONFIG_CORESIGHT=m
CONFIG_CORESIGHT_LINKS_AND_SINKS=m
CONFIG_CORESIGHT_LINK_AND_SINK_TMC=m
CONFIG_CORESIGHT_CATU=m
CONFIG_CORESIGHT_SINK_TPIU=m
CONFIG_CORESIGHT_SINK_ETBV10=m
CONFIG_CORESIGHT_SOURCE_ETM4X=m
# CONFIG_ETM4X_IMPDEF_FEATURE is not set
CONFIG_CORESIGHT_STM=m
CONFIG_CORESIGHT_CTCU=m
CONFIG_CORESIGHT_CPU_DEBUG=m
# CONFIG_CORESIGHT_CPU_DEBUG_DEFAULT_ON is not set
CONFIG_CORESIGHT_CTI=m
# CONFIG_CORESIGHT_CTI_INTEGRATION_REGS is not set
CONFIG_CORESIGHT_TRBE=m
CONFIG_ULTRASOC_SMB=m
CONFIG_CORESIGHT_TPDM=m
CONFIG_CORESIGHT_TPDA=m
# CONFIG_CORESIGHT_DUMMY is not set
CONFIG_CORESIGHT_KUNIT_TESTS=m
# end of arm64 Debugging

#
# Kernel Testing and Coverage
#
CONFIG_KUNIT=m
CONFIG_KUNIT_DEBUGFS=y
# CONFIG_KUNIT_FAULT_TEST is not set
CONFIG_KUNIT_TEST=m
CONFIG_KUNIT_EXAMPLE_TEST=m
CONFIG_KUNIT_ALL_TESTS=m
# CONFIG_KUNIT_DEFAULT_ENABLED is not set
CONFIG_KUNIT_AUTORUN_ENABLED=y
CONFIG_KUNIT_DEFAULT_TIMEOUT=300
# CONFIG_NOTIFIER_ERROR_INJECTION is not set
# CONFIG_FUNCTION_ERROR_INJECTION is not set
# CONFIG_FAULT_INJECTION is not set
CONFIG_ARCH_HAS_KCOV=y
# CONFIG_KCOV is not set
CONFIG_RUNTIME_TESTING_MENU=y
# CONFIG_TEST_DHRY is not set
# CONFIG_LKDTM is not set
CONFIG_CPUMASK_KUNIT_TEST=m
# CONFIG_TEST_LIST_SORT is not set
# CONFIG_TEST_MIN_HEAP is not set
CONFIG_TEST_SORT=m
# CONFIG_TEST_DIV64 is not set
# CONFIG_TEST_MULDIV64 is not set
CONFIG_TEST_IOV_ITER=m
CONFIG_KPROBES_SANITY_TEST=m
# CONFIG_BACKTRACE_SELF_TEST is not set
# CONFIG_TEST_REF_TRACKER is not set
# CONFIG_RBTREE_TEST is not set
# CONFIG_REED_SOLOMON_TEST is not set
# CONFIG_INTERVAL_TREE_TEST is not set
# CONFIG_PERCPU_TEST is not set
CONFIG_ATOMIC64_SELFTEST=y
CONFIG_ASYNC_RAID6_TEST=m
# CONFIG_TEST_HEXDUMP is not set
CONFIG_PRINTF_KUNIT_TEST=m
CONFIG_SCANF_KUNIT_TEST=m
CONFIG_SEQ_BUF_KUNIT_TEST=m
CONFIG_STRING_KUNIT_TEST=m
CONFIG_STRING_HELPERS_KUNIT_TEST=m
CONFIG_TEST_KSTRTOX=y
# CONFIG_TEST_BITMAP is not set
# CONFIG_TEST_UUID is not set
# CONFIG_TEST_XARRAY is not set
# CONFIG_TEST_MAPLE_TREE is not set
# CONFIG_TEST_RHASHTABLE is not set
# CONFIG_TEST_IDA is not set
# CONFIG_TEST_PARMAN is not set
# CONFIG_TEST_LKM is not set
# CONFIG_TEST_BITOPS is not set
CONFIG_TEST_VMALLOC=m
CONFIG_TEST_BPF=m
# CONFIG_FIND_BIT_BENCHMARK is not set
# CONFIG_TEST_FIRMWARE is not set
# CONFIG_TEST_SYSCTL is not set
CONFIG_BITFIELD_KUNIT=m
CONFIG_CHECKSUM_KUNIT=m
CONFIG_UTIL_MACROS_KUNIT=m
CONFIG_HASH_KUNIT_TEST=m
CONFIG_RESOURCE_KUNIT_TEST=m
CONFIG_SYSCTL_KUNIT_TEST=m
CONFIG_KFIFO_KUNIT_TEST=m
CONFIG_LIST_KUNIT_TEST=m
CONFIG_HASHTABLE_KUNIT_TEST=m
CONFIG_LINEAR_RANGES_TEST=m
CONFIG_CMDLINE_KUNIT_TEST=m
CONFIG_BITS_TEST=m
CONFIG_SLUB_KUNIT_TEST=m
CONFIG_RATIONAL_KUNIT_TEST=m
CONFIG_MEMCPY_KUNIT_TEST=m
CONFIG_IS_SIGNED_TYPE_KUNIT_TEST=m
CONFIG_OVERFLOW_KUNIT_TEST=m
CONFIG_RANDSTRUCT_KUNIT_TEST=m
CONFIG_STACKINIT_KUNIT_TEST=m
CONFIG_FORTIFY_KUNIT_TEST=m
CONFIG_LONGEST_SYM_KUNIT_TEST=m
CONFIG_SIPHASH_KUNIT_TEST=m
CONFIG_USERCOPY_KUNIT_TEST=m
CONFIG_BLACKHOLE_DEV_KUNIT_TEST=m
# CONFIG_TEST_UDELAY is not set
# CONFIG_TEST_STATIC_KEYS is not set
# CONFIG_TEST_DYNAMIC_DEBUG is not set
# CONFIG_TEST_KMOD is not set
# CONFIG_TEST_KALLSYMS is not set
# CONFIG_TEST_MEMCAT_P is not set
# CONFIG_TEST_OBJAGG is not set
# CONFIG_TEST_MEMINIT is not set
CONFIG_TEST_HMM=m
# CONFIG_TEST_FREE_PAGES is not set
# CONFIG_TEST_FPU is not set
# CONFIG_TEST_OBJPOOL is not set
CONFIG_RATELIMIT_KUNIT_TEST=m
CONFIG_INT_POW_KUNIT_TEST=m
CONFIG_INT_SQRT_KUNIT_TEST=m
CONFIG_INT_LOG_KUNIT_TEST=m
CONFIG_GCD_KUNIT_TEST=m
CONFIG_PRIME_NUMBERS_KUNIT_TEST=m
CONFIG_ARCH_USE_MEMTEST=y
CONFIG_MEMTEST=y
# CONFIG_HYPERV_TESTING is not set
# end of Kernel Testing and Coverage

#
# Rust hacking
#
# end of Rust hacking
# end of Kernel hacking

CONFIG_IO_URING_ZCRX=y

--EEo2Efafy6WV2cN3--

