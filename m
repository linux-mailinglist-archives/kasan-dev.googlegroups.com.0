Return-Path: <kasan-dev+bncBC32535MUICBBH6BTKAQMGQE6DCKUXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BA5331A1CD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 16:37:05 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id s4sf7954913pgi.7
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 07:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613144224; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4itT2nAjl4gA2MWZwTxAQBxJmkwCntvJ0feOoaDzLFECIV6NxDXtrOBkijlOCv9P9
         DzeagitT8LvN60Cb9SV+Tr7i0ers0lN/wxBPkAkNNfQbUksXBds1zyTWtZRoq1Z0Hh+J
         e54mvP2tVbCCMFZoJ+Rg+q9+bwQiNxiYMDNwF4M1CW6sk6lmoMYVAwRLHO/TpNJgb7YC
         yYjVxWROPw7/g1Q0xg/aBLKEgYWSKt2m9aJEH0vQgJctnkIpkD6B72fKiv1XdRVgoMKX
         4E78rOUOgPPB0o4Ff0jruMNyWETbrK1CPmsCms9Upd/GkBqxx70xUV7pNV4FFeKgTSyI
         x52Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:subject:organization:from
         :references:cc:to:sender:dkim-signature;
        bh=QtWygb6q+dEr7szQlVS3NU+YASmDQdvxKzsxiiwwu2Y=;
        b=vw5GJUMiHnchHncZ7Met7loCVLa7qZvUUBpUleTkFDR7Dn8Md280xHTyWH85dtobGF
         A/MSnQRRWwY8HGY+l+SxHekYGQ0ySA9QsclZ0hS0qIRYAC1CNea6mY4oEyq2Rj/biYSx
         Tz6xhCN12ewY31Dh59bvOnQ887bm1sDv1LcUOtk42mQQZOIQotSpFDEpu3UYtvJiv8Hc
         IY+IIwT0sEnkInaBbjNJKYOjbarKwrIJpWuQ31ZZwokd2kssLw9r9LcZLepzjTMNXE6M
         WD2Owi3ovLUlAPvP/1uRrK4oYXBB8dyS85n48jYBF/awifLvWud3l5v7/NzBIu1p7TVc
         YaPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="g742lB/f";
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:organization:subject:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QtWygb6q+dEr7szQlVS3NU+YASmDQdvxKzsxiiwwu2Y=;
        b=kcSofePZyVF+dmtUe5YHfvM47V1kdFYoooLL7FRubPIK6vkuHQmOnCi36/ryG9XXmv
         qU3/2dHLHWPbgS9zKewjx4hieb0hiaJEk+Pso17NWpfAYGSgQ5wpvQ/6wFzAIzavEey7
         X9kOdxvv5Ks7YiRX95AmoC0fFs5/kybyQ2Q2grW43TqzLfg4XnyX7E+eIPiXvhQURlHT
         fuIe/TSHibBabbyVG0xZKkLjAAS5ZZTleP02oTUo32HjPdPb/ubhVH4IernVQQWfJpM6
         GuwTcsnTwjxUM+5cHH8EXCFn6OfKOV1tePVEJYJUxBcVIUaLznx4AjG/NTFT92qQWtmV
         60vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:organization
         :subject:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QtWygb6q+dEr7szQlVS3NU+YASmDQdvxKzsxiiwwu2Y=;
        b=spZ+h6u2wfkZmmi1M2eBGyllhxldCF6VtMiMtb8q+J8df4vSJy/+Ii0W9+8dWMqwDB
         DkFQM2HXM/wMosXOpFcQ3AZPiCC2CbHYiqKW6cTUtxb0l8p58/gDMWfA+X42gEtA8QRI
         u+qufaZIA3++K39Vr3QNJSwHODXmnCAkRQmr72oD/B3jg82sUfsuB8wqXu+YP2RbCLa3
         iPbKumrKhJ7839Yb6S/FrZb00/JqZUHbHj9bvIJpA0gIYQ+Abh3MVhjYwzCb/LYRCL+O
         QWHY25+xjxvPXMQLRyUGB7qkL8cabhzLCt8TNp8XXrcB7Px5S7sPCJO2NFccd25qqlt6
         6jVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5337YoSU2albszTWG/g75rPRw6b1iEJeQQ/ufB9BuNJfFbe6YDj5
	yqXEQf+ROE0wCglUxex/QoE=
X-Google-Smtp-Source: ABdhPJydfEdly7QGlJ0avvfK+OrFlll7IOtPlAkN6N3nRj+UsbadIPC0Wt11URy3VmRmWvVy52qnlA==
X-Received: by 2002:a63:1c12:: with SMTP id c18mr3753358pgc.356.1613144224001;
        Fri, 12 Feb 2021 07:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8607:: with SMTP id f7ls3410275plo.9.gmail; Fri, 12
 Feb 2021 07:37:03 -0800 (PST)
X-Received: by 2002:a17:902:f54e:b029:de:19f9:c45f with SMTP id h14-20020a170902f54eb02900de19f9c45fmr3116322plf.48.1613144223177;
        Fri, 12 Feb 2021 07:37:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613144223; cv=none;
        d=google.com; s=arc-20160816;
        b=0FKyRFbQEbplShBSa19v+6cQ92mocuongqAgfoH+tXX3+shw+3hPPo1Pm8XGV4byxA
         3aSlmA4F7kpXKmsj3FNLMdThKHkhtfled51DppmtJufKiN1cwYgpDM0OubRbFW+QhUuG
         jHzalKd5UpFkK0nyc/kEujDFxPFI8aOnnGa9FZKRncLH4mhGIEiNyv5RXI0DMPenzOm+
         zH8WhfgSwQ1J9udpNGfQH5H72XJyldqG2bw+ZAIfTx9vE498fDwDkebw3gpEKuLPM7qP
         vqOShD4XgxDMABooYchsuiHp5xqP27f56yZhKlozMQBL6yfbhgLnsYog4JWVfnZYq4uH
         Kq9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:organization:from:references:cc
         :to:dkim-signature;
        bh=TqHtQDq8snd1VedRSoR/HjI7yI2kIRTV2wl6BN81jHk=;
        b=QcLgQ9yntlRyeracvvwJIkluNR+IZzmoLkeun+rBcpltLG2sBl9ad4GT59lnDkwJCD
         Q0W1C/7aIUVCsNIwG3DWxpxnyZaro1cUoZ8jjZvhXbjqaSZZlHcq1C3M/2pR6DbWQX70
         5gcR8pUc/+qmNdBQff91ysZ1+Da8pngZ1nLFIzSi2mIvEZazni7vhafy70Ce4/U3eSfi
         LrtjlbKuxaB7T1HB2fcdelYFBXyXybaN2iaGSpJao9l3nNRdOGolMgXS0kg/n5dUsgGZ
         ySfk/2Ds1aM2+B7tIcSbHzZ7E8PjmFPIY8KyIBl84+7Are4XZgyBxsWrYfipE2UAAKz1
         U3MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="g742lB/f";
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id 11si486443plj.3.2021.02.12.07.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 07:37:03 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-360-Dtfka1tFMu--kXOoS1L1Fw-1; Fri, 12 Feb 2021 10:36:56 -0500
X-MC-Unique: Dtfka1tFMu--kXOoS1L1Fw-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 3F001107ACF9;
	Fri, 12 Feb 2021 15:36:54 +0000 (UTC)
Received: from [10.36.114.178] (ovpn-114-178.ams2.redhat.com [10.36.114.178])
	by smtp.corp.redhat.com (Postfix) with ESMTP id A976560CDE;
	Fri, 12 Feb 2021 15:36:49 +0000 (UTC)
To: Dmitry Vyukov <dvyukov@google.com>,
 George Kennedy <george.kennedy@oracle.com>
Cc: Konrad Rzeszutek Wilk <konrad@darnok.org>,
 "Rafael J. Wysocki" <rjw@rjwysocki.net>,
 Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com,
 konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 Dhaval Giani <dhaval.giani@oracle.com>
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
 <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com>
 <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
 <20210203192856.GA324708@fedora>
 <CACT4Y+bscZGpMK-UXXzeFDeJtGYt-royR_=iTzTmBrwe3wOmTw@mail.gmail.com>
 <14124734-326e-87b3-a04a-b7190f1e1282@oracle.com>
 <bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com>
 <CACT4Y+Ze3J5L7vBt7hmqbMrxhRg=k1hZkPTJpCG83Gc=Wr-Fsg@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
Message-ID: <b2399990-0464-4041-5dd1-d2828ee0c910@redhat.com>
Date: Fri, 12 Feb 2021 16:36:48 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Ze3J5L7vBt7hmqbMrxhRg=k1hZkPTJpCG83Gc=Wr-Fsg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="g742lB/f";
       spf=pass (google.com: domain of david@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 12.02.21 14:51, Dmitry Vyukov wrote:
> On Fri, Feb 12, 2021 at 2:31 PM George Kennedy
> <george.kennedy@oracle.com> wrote:
>> On 2/10/2021 4:51 PM, George Kennedy wrote:
>>> On 2/3/2021 2:35 PM, Dmitry Vyukov wrote:
>>>> On Wed, Feb 3, 2021 at 8:29 PM Konrad Rzeszutek Wilk
>>>> <konrad@darnok.org> wrote:
>>>>> Hey Dmitry, Rafael, George, please see below..
>>>>>
>>>>> On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
>>>>>> On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
>>>>>> <george.kennedy@oracle.com> wrote:
>>>>>>> Hi Dmitry,
>>>>>>>
>>>>>>> On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
>>>>>>>
>>>>>>> On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
>>>>>>> <konrad.wilk@oracle.com> wrote:
>>>>>>>
>>>>>>> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
>>>>>>>
>>>>>>> During boot of kernel with CONFIG_KASAN the following KASAN false
>>>>>>> positive failure will occur when ibft_init() reads the
>>>>>>> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
>>>>>>>
>>>>>>> The ACPI iBFT table is not allocated, and the iscsi driver uses
>>>>>>> a pointer to it to calculate checksum, etc. KASAN complains
>>>>>>> about this pointer with use-after-free, which this is not.
>>>>>>>
>>>>>>> Andrey, Alexander, Dmitry,
>>>>>>>
>>>>>>> I think this is the right way for this, but was wondering if you have
>>>>>>> other suggestions?
>>>>>>>
>>>>>>> Thanks!
>>>>>>>
>>>>>>> Hi George, Konrad,
>>>>>>>
>>>>>>> Please provide a sample KASAN report and kernel version to match
>>>>>>> line numbers.
>>>>>>>
>>>>>>> 5.4.17-2102.200.0.0.20210106_0000
>>>>>>>
>>>>>>> [   24.413536] iBFT detected.
>>>>>>> [   24.414074]
>>>>>>> ==================================================================
>>>>>>> [   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
>>>>>>> [   24.407342] Read of size 4 at addr ffff8880be452004 by task
>>>>>>> swapper/0/1
>>>>>>> [   24.407342]
>>>>>>> [   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted
>>>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>>>> [   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX,
>>>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>>>> [   24.407342] Call Trace:
>>>>>>> [   24.407342]  dump_stack+0xd4/0x119
>>>>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.407342] print_address_description.constprop.6+0x20/0x220
>>>>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.407342]  __kasan_report.cold.9+0x37/0x77
>>>>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.407342]  kasan_report+0x14/0x1b
>>>>>>> [   24.407342]  __asan_report_load_n_noabort+0xf/0x11
>>>>>>> [   24.407342]  ibft_init+0x134/0xb8b
>>>>>>> [   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
>>>>>>> [   24.407342]  ? dmi_walk+0x72/0x89
>>>>>>> [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
>>>>>>> [   24.407342]  ? rvt_init_port+0x110/0x101
>>>>>>> [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
>>>>>>> [   24.407342]  do_one_initcall+0xc3/0x44d
>>>>>>> [   24.407342]  ? perf_trace_initcall_level+0x410/0x405
>>>>>>> [   24.407342]  kernel_init_freeable+0x551/0x673
>>>>>>> [   24.407342]  ? start_kernel+0x94b/0x94b
>>>>>>> [   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
>>>>>>> [   24.407342]  ? __kasan_check_write+0x14/0x16
>>>>>>> [   24.407342]  ? rest_init+0xe6/0xe6
>>>>>>> [   24.407342]  kernel_init+0x16/0x1bd
>>>>>>> [   24.407342]  ? rest_init+0xe6/0xe6
>>>>>>> [   24.407342]  ret_from_fork+0x2b/0x36
>>>>>>> [   24.407342]
>>>>>>> [   24.407342] The buggy address belongs to the page:
>>>>>>> [   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0
>>>>>>> mapping:0000000000000000 index:0x1
>>>>>>> [   24.407342] flags: 0xfffffc0000000()
>>>>>>> [   24.407342] raw: 000fffffc0000000 ffffea0002fca588
>>>>>>> ffffea0002fb1a88 0000000000000000
>>>>>>> [   24.407342] raw: 0000000000000001 0000000000000000
>>>>>>> 00000000ffffffff 0000000000000000
>>>>>>> [   24.407342] page dumped because: kasan: bad access detected
>>>>>>> [   24.407342]
>>>>>>> [   24.407342] Memory state around the buggy address:
>>>>>>> [   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff
>>>>>>> ff ff ff ff ff
>>>>>>> [   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff
>>>>>>> ff ff ff ff ff
>>>>>>> [   24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff
>>>>>>> ff ff ff ff ff
>>>>>>> [   24.407342]                    ^
>>>>>>> [   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff
>>>>>>> ff ff ff ff ff
>>>>>>> [   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff
>>>>>>> ff ff ff ff ff
>>>>>>> [   24.407342]
>>>>>>> ==================================================================
>>>>>>> [   24.407342] Disabling lock debugging due to kernel taint
>>>>>>> [   24.451021] Kernel panic - not syncing: panic_on_warn set ...
>>>>>>> [   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G B
>>>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>>>> [   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX,
>>>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>>>> [   24.452002] Call Trace:
>>>>>>> [   24.452002]  dump_stack+0xd4/0x119
>>>>>>> [   24.452002]  ? ibft_init+0x102/0xb8b
>>>>>>> [   24.452002]  panic+0x28f/0x6e0
>>>>>>> [   24.452002]  ? __warn_printk+0xe0/0xe0
>>>>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.452002]  ? add_taint+0x68/0xb3
>>>>>>> [   24.452002]  ? add_taint+0x68/0xb3
>>>>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.452002]  end_report+0x4c/0x54
>>>>>>> [   24.452002]  __kasan_report.cold.9+0x55/0x77
>>>>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
>>>>>>> [   24.452002]  kasan_report+0x14/0x1b
>>>>>>> [   24.452002]  __asan_report_load_n_noabort+0xf/0x11
>>>>>>> [   24.452002]  ibft_init+0x134/0xb8b
>>>>>>> [   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
>>>>>>> [   24.452002]  ? dmi_walk+0x72/0x89
>>>>>>> [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
>>>>>>> [   24.452002]  ? rvt_init_port+0x110/0x101
>>>>>>> [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
>>>>>>> [   24.452002]  do_one_initcall+0xc3/0x44d
>>>>>>> [   24.452002]  ? perf_trace_initcall_level+0x410/0x405
>>>>>>> [   24.452002]  kernel_init_freeable+0x551/0x673
>>>>>>> [   24.452002]  ? start_kernel+0x94b/0x94b
>>>>>>> [   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
>>>>>>> [   24.452002]  ? __kasan_check_write+0x14/0x16
>>>>>>> [   24.452002]  ? rest_init+0xe6/0xe6
>>>>>>> [   24.452002]  kernel_init+0x16/0x1bd
>>>>>>> [   24.452002]  ? rest_init+0xe6/0xe6
>>>>>>> [   24.452002]  ret_from_fork+0x2b/0x36
>>>>>>> [   24.452002] Dumping ftrace buffer:
>>>>>>> [   24.452002] ---------------------------------
>>>>>>> [   24.452002] swapper/-1         1.... 24564337us : rdmaip_init:
>>>>>>> 2924: rdmaip_init: Active Bonding is DISABLED
>>>>>>> [   24.452002] ---------------------------------
>>>>>>> [   24.452002] Kernel Offset: disabled
>>>>>>> [   24.452002] Rebooting in 1 seconds..
>>>>>>>
>>>>>>> Why does KASAN think the address is freed? For that to happen that
>>>>>>> memory should have been freed. I don't remember any similar false
>>>>>>> positives from KASAN, so this looks a bit suspicious.
>>>>>>>
>>>>>>> I'm not sure why KASAN thinks the address is freed. There are
>>>>>>> other modules where KASAN/KCOV is disabled on boot.
>>>>>>> Could this be for a similar reason?
>>>>>> Most of these files are disabled because they cause recursion in
>>>>>> instrumentation, or execute too early in bootstrap process (before
>>>>>> kasan_init).
>>>>>>
>>>>>> Somehow the table pointer in ibft_init points to a freed page. I
>>>>>> tracked it down to here:
>>>>>> https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica/tbutils.c#L399
>>>>>>
>>>>>> but I can't find where this table_desc->pointer comes from. Perhaps it
>>>>> It is what the BIOS generated. It usually points to some memory
>>>>> location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
>>>>> other tables in there.
>>>>>
>>>>>> uses some allocation method that's not supported by KASAN? However,
>>>>>> it's the only such case that I've seen, so it's a bit weird. Could it
>>>>>> use something like memblock_alloc? Or maybe that page was in fact
>>>>>> freed?... Too bad KASAN does not print free stack for pages, maybe
>>>>>> it's not too hard to do if CONFIG_PAGE_OWNER is enabled...
>>>>> Hm, there is a comment in the acpi_get_table speaking about the
>>>>> requirement of having a acpi_put_table and:
>>>>>
>>>>>
>>>>>    * DESCRIPTION: Finds and verifies an ACPI table. Table must be in the
>>>>>    *              RSDT/XSDT.
>>>>>    *              Note that an early stage acpi_get_table() call must
>>>>> be paired
>>>>>    *              with an early stage acpi_put_table() call.
>>>>> otherwise the table
>>>>>    *              pointer mapped by the early stage mapping
>>>>> implementation may be
>>>>>    *              erroneously unmapped by the late stage unmapping
>>>>> implementation
>>>>>    *              in an acpi_put_table() invoked during the late stage.
>>>>>    *
>>>>>
>>>>> Which would imply that I should use acpi_put_table in the error path
>>>>> (see below a patch), but also copy the structure instead of depending
>>>>> on ACPI keeping it mapped for me. I think.
>>>> Hi Konrad,
>>>>
>>>> Thanks for looking into this.
>>>> If ACPI unmaps this page, that would perfectly explain the KASAN report.
>>>>
>>>> George, does this patch eliminate the KASAN report for you?
>>>
>>> Hi Dmitry,
>>>
>>> No luck with the patch. Tried high level bisect instead. Here are the
>>> results:
>>>
>>> BUG: KASAN: use-after-free in ibft_init+0x134/0xc49
>>>
>>> Bisect status:
>>> v5.11-rc6 Sun Jan 31 13:50:09 2021 -0800     Failed
>>> v5.11-rc1 Sun Dec 27 15:30:22 2020 -0800    Failed
>>> v5.10 Sun Dec 13 14:41:30 2020 -0800           Failed
>>> v5.10-rc6 Sun Nov 29 15:50:50 2020 -0800    Failed
>>> v5.10-rc5 Sun Nov 22 15:36:08 2020 -0800    Failed
>>> v5.10-rc4 Sun Nov 15 16:44:31 2020 -0800    Failed
>>> v5.10-rc3 Sun Nov 8 16:10:16 2020 -0800      Failed
>>> v5.10-rc2 Sun Nov 1 14:43:52 2020 -0800      Failed
>>> v5.10-rc1 Sun Oct 25 15:14:11 2020 -0700     Failed
>>> v5.9 Sun Oct 11 14:15:50 2020 -0700              OK - 10 reboots so
>>> far w/o kasan failure
>>>
>>> So, will look at what changed between v5.9 and v5.10-rc1
>>
>> git bisect has identified the following as the offending commit:
>>
>> 2020-10-16 torvalds@linux-foundation.org - 7fef431 2020-10-15 David
>> Hildenbrand mm/page_alloc: place pages to tail in __free_pages_core()
> 
> I think this suggests that this is a real use-after-free and the
> page_alloc change just exposed a latent bug.

That commit is ridiculously good at finding latent BUGs. Memory gets 
allocated and used in the reverse order. So could be that this is 
exposing yet another latent bug.

For example: 
https://lkml.kernel.org/r/20201213225517.3838501-1-linus.walleij@linaro.org

Or a longer discussion at: 
https://lkml.kernel.org/r/87361onphy.fsf_-_@codeaurora.org


Anyhow, let me know in case it looks like this time it's actually my 
commit that broke something (although somewhat unlikely I have to say).

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b2399990-0464-4041-5dd1-d2828ee0c910%40redhat.com.
