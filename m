Return-Path: <kasan-dev+bncBDYZHQ6J7ENRB54MU6XQMGQECRILPXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id AA2B08750E8
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 14:51:52 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42f138874e7sf389321cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 05:51:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709819511; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0WnhOwBt4nF69DNa5yiVwtAzz3yo3zmJrmC/YIbdMrqYsOyKysBx83ab/XCnZq0IH
         YttHp+Q375B06a5J91XDIhasEmrR1y+UCio++3CkNeik72b3kba5GDcX1R609zh3Gzhf
         2yaLUUq0IikjW9hRKb2/b4t9cfGeZwAernaaLBdbqAKfTJoyc0J79zWWce3AhQ5JlL7P
         iKZTkl4A1w4PHQPVqY3fxmv9DgilARCkalbKXtdVjiGCX4gPVYqAtW9SEjz2pWSnlPAQ
         MVhZR9/gWFyPXzYxn8lLYJkKJ9v0OYBpG1VIRxsK4RFGCV3oE8aS79kf1dQ44KfkjMPx
         XT8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=ImZYCdDuSigdNStoaZiT2hHpFJvetdDx4or1TVIk6WM=;
        fh=n3rUhXobndHPf04mHLVKrCTCLj+0Q9crp0xcDEGUSh0=;
        b=P1MZ+bVWBNP+jpHQqJ7ecSdlu6s1+H6mzqN6uV+aqPLefKE7k7QVM2E5k1PZEzfuI2
         KhlEPKMM/sWpdTTqndLLEYETyQ2dagYMYkHZ9e+c+ukUpJKzJRh1/ZlbuWvRXCfywwDM
         baZeSVWJdB7/nqIClkylr+/tvr3QXC8QSrgrad3DBTR5mb6Ipp5s7xvZ2lJvsVhOxtrs
         5OHrdJmivmzL9AlPiyboQpL8cXI0D6QgFF6+OrDS/pQkV4WM/lRBE2qGyzLUK0YzOZd7
         KWY06IR2hL1c6fsZOx2i09lk9xQzQvfqCRTcXmPs4S0ny+d2pfQoNoc3QAxxKh3yPwg5
         afXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UZnssOTE;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709819511; x=1710424311; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ImZYCdDuSigdNStoaZiT2hHpFJvetdDx4or1TVIk6WM=;
        b=MyU4i/i6OEn9Po8BjAjb/gpfdS0Z8+GF7akOUdO7yZGTwj33SDmhuJOuZPCfRAe96d
         gvrcuXToDc2MXpYyzJ4UAeULv7d3Iv7K+9d1ddmcp87IOStgBjq5xgaha2PkIuvaw5TO
         T2KapupsCsPoUIL2niY0QFoZEsyKFiRU99E01v/wCZ5b9NfJVLkQi7qktUmyZN34s+Bv
         8j7BSMkYptq6mvt1teZ09Ri25z8uU7/yIBl4ysgWwSSCayGobkYUcqxiLKuo6ei6GrZA
         OnW8FBkc+9OHGa5iJZjoGRJv9E1+sd8c7oTCw1odg8DHRxl0AxZf7jO8f8cxVWLzeN1X
         rnPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709819511; x=1710424311;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ImZYCdDuSigdNStoaZiT2hHpFJvetdDx4or1TVIk6WM=;
        b=Ov/qdgtCuYDDCPQ3H25gXKE1dSJoZV8VEeiBFrzvFQOMMwDbNsKmKpY8Kxi4t2nz+w
         TaDjGZT0INsXmuQ3mxx5soBTYZdICt9aqA9DzxTSrq33OVbwopoxr81W5CnoXNvZ9LKP
         UV/K5um9lgFtS+aMlMwtvSXCwZZ4568RWoSBMFmDmkWVsbeDUz6dS+DQUTJUIYjKPF56
         xOKFie9F3idIL1TDbe1P5mph80rgy4N5CGu1+KBenWVHK0LZWI76W+cpl6Q1y/8Uc8gW
         XmVLU6GAaNLKP2hwywHkZVyll3xSapR1i/UkxYmpdD8BOHb4gd9gcoXChJGv+/FHNHBW
         fM9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4uMKqdlemM5Tmz01hOlk7ImJyPANCfweAZMZ1sZAgXGM1XQcGmo+tFeqXnRHIYB1YTVRfyh7Zm7y3b0XatsK4YCuxrzwzHw==
X-Gm-Message-State: AOJu0YzB2kddj21QOXFXylgB2UiCla1URZs5F5A10+yLyHg/6TIoDDlY
	6QofslXaXssuS/BE4ndHReDgI3gD82ARjSOfN4ClBdQIUJlUY7gw
X-Google-Smtp-Source: AGHT+IFbNvXRhNFTvBF0L3fIMQl750/1PYG6g0eX0kL5Nd3MnsXVSDpCw9Zpaijyv8Cue/c5QWJbHQ==
X-Received: by 2002:a05:622a:1ba4:b0:42f:a3c:2d4d with SMTP id bp36-20020a05622a1ba400b0042f0a3c2d4dmr364683qtb.14.1709819511374;
        Thu, 07 Mar 2024 05:51:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5762:0:b0:690:3968:96c2 with SMTP id r2-20020ad45762000000b00690396896c2ls1665102qvx.1.-pod-prod-00-us;
 Thu, 07 Mar 2024 05:51:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWS0XNNfgj1dJtVtongGA1gJIbXPohiGja+Y4DhVdjn04S4DZFhPw+3OK/9NtWLc+YqHoNfYe56jA4yB1U4CFvydtEs2YLiB8+X/Q==
X-Received: by 2002:a05:6214:3012:b0:68f:88d3:c470 with SMTP id ke18-20020a056214301200b0068f88d3c470mr1642889qvb.5.1709819509431;
        Thu, 07 Mar 2024 05:51:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709819509; cv=none;
        d=google.com; s=arc-20160816;
        b=g5GKi4w5aWt7xI1c5pNyZSycxAqz6VCDFw2jTedGiwMYti1etgCMXVe9IQPauSlzTM
         2aBCohN6qOUYoT9esg6fxbPb4oqiZ5MyO7T2LMyoRpxYAskonnQKj2JGpyWEA4A4YJCS
         bx4ZLHrwQLRv3ezmzM7SaVk6TzkN1YR0Lsr77l4iRyZIH34aXMyqpneahPD5UgdDciRL
         dVF7Lgow0Tz7rBeeU4zZyXvqtEPR2rwX8J83kG/39seLv8X2Bp3uUsynkV+uFhE6HokM
         IBGOFwyf/9cyCjcqQp5TFc5lQD8gDbfVz0i/0OG7v0sWnGejf0zJ2UXvTnnY7AF5W04L
         Vo2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=XEoTXVV4izjzqO6wk/yL2szD6NbvApcgsu712fpdToA=;
        fh=rNO1sFYZ1J5k9xp3x3Ckn0laOHLU2kpY8tCXsL09e1g=;
        b=WZVspQ9a5A98sCgpHrDV1UHLyNbr0Sjtj8E56HqrvglrzwawcrozjyRLY2hQ49MiOQ
         KHRxyJ3ViiAI5rzRRhbur3IDKHzbBPJSyDcJu8KXRCdlnl6C9V4anuCNXBbk1VKahwov
         wnEupTywHny5+KTrLpM1J5ZPXarLWZW9lQjPmJLcYu5EEPRSnMBSlW9LBQ/TeGgFUPIe
         cM1R/w7CbjAswRkMUk6cyN/hUz70GCTnlH3sEidCpAAYa0W6Ie/8yovHZG3D3sx5ZcnX
         X4cwOmZcXAyirvtMU5Gk2CSWp7W4KW2uvUCv16VNNKl1Np/6tVpGOIV0LnokxW9RBGua
         3WwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UZnssOTE;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id fv2-20020a056214240200b0068f6c8ab31asi1289106qvb.5.2024.03.07.05.51.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 05:51:49 -0800 (PST)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-61-_aJL51ahObOgmoDa83T8wA-1; Thu,
 07 Mar 2024 08:51:45 -0500
X-MC-Unique: _aJL51ahObOgmoDa83T8wA-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.rdu2.redhat.com [10.11.54.2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 8D39B3C5CF2B;
	Thu,  7 Mar 2024 13:51:45 +0000 (UTC)
Received: from localhost.redhat.com (unknown [10.22.8.198])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 459A540C6CB8;
	Thu,  7 Mar 2024 13:51:45 +0000 (UTC)
From: Nico Pache <npache@redhat.com>
To: walter-zh.wu@mediatek.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com
Subject: [BUG REPORT] Multiple KASAN kunit test failures
Date: Thu,  7 Mar 2024 06:51:30 -0700
Message-ID: <20240307135130.14919-1-npache@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.2
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UZnssOTE;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
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

Hi,

A number of KASAN KUnit tests have been failing on the upstream rhel/fedora 
kernels.

cki-project data warehouse : https://datawarehouse.cki-project.org/issue/1972

The kmalloc_oob_in_memset* tests are failing and the 
kmalloc_memmove_negative_size is panicing.

Arches: X86_64, ARM64, S390x, ppc64le
First Appeared: ~6.3.rc5

Failing Tests:
 - kmalloc_oob_in_memset
 - kmalloc_oob_memset_2
 - kmalloc_oob_memset_4
 - kmalloc_oob_memset_8
 - kmalloc_oob_memset_16
 - kmalloc_memmove_negative_size (PANIC)

trace:
     # kmalloc_oob_in_memset: EXPECTATION FAILED at mm/kasan/kasan_test.c:565
     KASAN failure expected in "memset(ptr, 0, size + KASAN_GRANULE_SIZE)", but none occurred
     not ok 17 kmalloc_oob_in_memset
     # kmalloc_oob_memset_2: EXPECTATION FAILED at mm/kasan/kasan_test.c:495
     KASAN failure expected in "memset(ptr + size - 1, 0, memset_size)", but none occurred
     not ok 18 kmalloc_oob_memset_2
     # kmalloc_oob_memset_4: EXPECTATION FAILED at mm/kasan/kasan_test.c:513
     KASAN failure expected in "memset(ptr + size - 3, 0, memset_size)", but none occurred
     not ok 19 kmalloc_oob_memset_4
     # kmalloc_oob_memset_8: EXPECTATION FAILED at mm/kasan/kasan_test.c:531
     KASAN failure expected in "memset(ptr + size - 7, 0, memset_size)", but none occurred
     not ok 20 kmalloc_oob_memset_8
     # kmalloc_oob_memset_16: EXPECTATION FAILED at mm/kasan/kasan_test.c:549
     KASAN failure expected in "memset(ptr + size - 15, 0, memset_size)", but none occurred
     not ok 21 kmalloc_oob_memset_16
 BUG: unable to handle page fault for address: ffff888109480000
 #PF: supervisor write access in kernel mode
 #PF: error_code(0x0003) - permissions violation
 PGD 13dc01067 P4D 13dc01067 PUD 100276063 PMD 104440063 PTE 8000000109480021
 Oops: 0003 [#1] PREEMPT SMP KASAN PTI
 CPU: 0 PID: 216780 Comm: kunit_try_catch Tainted: G    B   W  OE  X N-------  ---  6.8.0-0.rc7.57.test.eln.x86_64+debug #1
 Hardware name: Red Hat KVM, BIOS 1.15.0-2.module+el8.6.0+14757+c25ee005 04/01/2014
 RIP: 0010:memmove+0x28/0x1b0
 Code: 90 90 f3 0f 1e fa 48 89 f8 48 39 fe 7d 0f 49 89 f0 49 01 d0 49 39 f8 0f 8f b5 00 00 00 48 83 fa 20 0f 82 01 01 00 00 48 89 d1 <f3> a4 c3 cc cc cc cc 48 81 fa a8 02 00 00 72 05 40 38 fe 74 43 48
 RSP: 0018:ffffc9000160fd50 EFLAGS: 00010286
 RAX: ffff888109448500 RBX: ffff888109448500 RCX: fffffffffffc84fe
 RDX: fffffffffffffffe RSI: ffff888109480004 RDI: ffff888109480000
 RBP: 1ffff920002c1fab R08: 0000000000000000 R09: 0000000000000000
 R10: ffff888109448500 R11: ffffffff9a1d1bb4 R12: ffffc900019c7610
 R13: fffffffffffffffe R14: ffff888060919000 R15: ffffc9000160fe48
 FS:  0000000000000000(0000) GS:ffff888111e00000(0000) knlGS:0000000000000000
 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
 CR2: ffff888109480000 CR3: 000000013b120004 CR4: 0000000000770ef0
 DR0: 0000000000430c70 DR1: 0000000000000000 DR2: 0000000000000000
 DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000600
 PKRU: 55555554
 Call Trace:
  <TASK>
  ? __die+0x23/0x70
  ? page_fault_oops+0x136/0x250
  ? __pfx_page_fault_oops+0x10/0x10
  ? memmove+0x28/0x1b0
  ? exc_page_fault+0xf9/0x100
  ? asm_exc_page_fault+0x26/0x30
  ? kasan_save_track+0x14/0x30
  ? memmove+0x28/0x1b0
  kmalloc_memmove_negative_size+0xdf/0x200 [kasan_test]
  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10 [kasan_test]
  ? kvm_clock_get_cycles+0x18/0x30
  ? ktime_get_ts64+0xce/0x280
  kunit_try_run_case+0x1b1/0x490 [kunit]
  ? do_raw_spin_trylock+0xb4/0x180
  ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
  ? trace_irq_enable.constprop.0+0x13d/0x180
  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10 [kunit]
  ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
  kunit_generic_run_threadfn_adapter+0x4e/0xa0 [kunit]
  kthread+0x2f2/0x3c0
  ? trace_irq_enable.constprop.0+0x13d/0x180
  ? __pfx_kthread+0x10/0x10
  ret_from_fork+0x31/0x70
  ? __pfx_kthread+0x10/0x10
  ret_from_fork_asm+0x1b/0x30
  </TASK>
  ...
-- 
2.44.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240307135130.14919-1-npache%40redhat.com.
