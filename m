Return-Path: <kasan-dev+bncBC24VNFHTMIBBUWS5T3QKGQEJRTQILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id E413120F40E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 14:00:19 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id t32sf14337348qth.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 05:00:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593518418; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwfkC8RTBo+51jpdv6YOAPGgHvPwPgb9HKSAujhfgUfLhlIEFCLDgIqp0QzExZMjQM
         L/sLzWDqONRlsoEM40qwckHCn54jBCZqxfI5nf8+b3PSTu/CCZXZ5En4ot/Z2ISafArC
         NrzfxEcjyjkzRlky2Xzw5Apd3qn4zaWiDRX0QoS/Xys/Gt2QD/AYVbyvfg6S8Xm0G6ds
         rwbuchf9xu9fKRFYTJEdC+RIZK/c1NwR1fMvLHu7aE46hQp30iDKyFxBUW71r5o4jGEw
         gW1JMLcK1HWJH0AjT7PYDWfLvDmbctf2PQu82BVcCsPeO2+shtlMkxOxAImMwKzklzvv
         UpxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=VrQy4MMELxN+aah/pL2oDHRtaTUkayfv1xb9gW0CmE0=;
        b=vp803OO9/5/cd+MUapTI8ELjwIfHdIdiFAj2oD2WHbZt7MuHUYHFkFvtS/Hu30vlFq
         aoIoEyviCI1eaQTno+zPDP/5nN0M1C9KWNVdSBfK6itx2QiwCTbsaRXmGXLov9EWILYu
         1TDXLKkyMkfnL1q8fR4EmY1+G/EXzYN0uD2U+u++7XabEt2km7RZ4QfxtbIJTOIu7rPY
         oU1V1K3T6jt+eB5yXGbaGK9RnQSs+gHfjogwNtvh/EgQEyRxPLapjmY6kcZadiI2YlaR
         893JTUGuReVHS1fz4YaVf70xIpczOfx8NSAUoc0Cy8xPMfJbPusEkvpFoP8/Z6ydpmEa
         vJBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VrQy4MMELxN+aah/pL2oDHRtaTUkayfv1xb9gW0CmE0=;
        b=stg/muZ312bVq5wvEgqPSPGCQHRHo4F/3G3m6pYs+JYrpGsqWisa30jPncTqCm2R1P
         ZHcbi7rvfUe/VkuG4rou8d8moHEeGf66zhkkoZZUcBpMXgSDVmh15dOaTZApVWGpBmdk
         hVWPQqmmRQyMRute864nj1m7cgQ1AgPFkwBV0lbaJA2ZdjqNJYpThj2dCXyM0Eedj1Lp
         QkKJTJdZu5pTM0SjGD2O7nAQKBVJQircG0uRD4vOX9aq8EFuBI14kudZb0gZoXzaJsjz
         cYjg9EJvRN9DUZeIjKPXn0EMWQJVV3NQQKjPCuEJ8VZFLqaz8bL6M80GPHj3Cz9YF1ni
         HkNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VrQy4MMELxN+aah/pL2oDHRtaTUkayfv1xb9gW0CmE0=;
        b=O0lBXPUFoo+70u65pjYPMeojB4TgSlysIYqyrAnClroTH1AYbFv9b6Pk0CN54g5zcV
         4I8L4yageMBa1YNwwMoV1S7vR36J+6djWwUffFfkmpmZo0aLOq9eTIiumggPutibiMek
         y3Q+kMEFWXM46pD469LMgxTskl4A7kjd2Htk+r9OVvbC0CrhAr6bEbrxgu0w9TUDY5B0
         M9JtqUTXgSy4Toqx5Ed1YDMstcYB9QRIJUFYkAWaWQPjk97uDTbzmL18LC4YYuL+he7u
         zGtMaPCBEbPjFWDNPjatK35BYwEsy4RocNtLgZNaJWkOYEsQGmTyP+QIwj48cPtyKHtE
         0xgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530e1LbSb44vR+px00743xhDSrqutW5sR4sDgl50N31ehHdGeoVy
	LHDvsh6CWxTMU/g4sVxmPfI=
X-Google-Smtp-Source: ABdhPJyQfzeDVQ2VGA7yQWej4LHHw8iruxiQyEKJfu0NQCLspwdFfCxWjlIWyUSQKLHcYWt8eszbpw==
X-Received: by 2002:ad4:4105:: with SMTP id i5mr9445859qvp.170.1593518418721;
        Tue, 30 Jun 2020 05:00:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3612:: with SMTP id m18ls2762432qtb.9.gmail; Tue, 30 Jun
 2020 05:00:17 -0700 (PDT)
X-Received: by 2002:ac8:710f:: with SMTP id z15mr20047539qto.153.1593518417668;
        Tue, 30 Jun 2020 05:00:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593518417; cv=none;
        d=google.com; s=arc-20160816;
        b=Kf6+thArSt53psqZWIqHoD0P00ZASw/q25TPc+jWNi4cxQGfp75X6dcm4xWS++uUbE
         af6E8uSRGwu+Oj6BNcFlDHZOfdyo5zTcPiqqEVNuqBHpSvUun0e9KvagO6rJXSxCZdRJ
         7WI40bUwRyMuLXV7MiLyIGrfyW62PH5P25F8hy3ZnnDW/Gh1BqtSydpBJlZfTLg3e/li
         L7RAsYHomtZ5zfha4beNtsIZi7k+4DB1GtWVWU+/CSMWa+6Z2Kn+8LErwsBmvltAz00e
         hsoW50aau+f3wre602fdkde4NpWOaZL1HQSzQeaz8WBUJTkJRGNzyLrFsK17BOt8u2lp
         tvsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=KSLstW8V63a6LlgroPHIM0TRQo6xG+fy0plpJEMU+kM=;
        b=uP7hGT7WvrVSwgpRjCUi70vVVu1tihxx++OSiyWvVqqSn0yS1WBA5nOvOuEvLEzt9B
         60PbSzC27fUgC4x7V6cJS9bEzTHncVBt+xDHRtFwh7CFPJ3P2XhUZ5di1DWIy/VyJriU
         74REV29QbGjB5RrYtC/gGSN4ccZS/UIfD+/rbA9Fo3ei6694k4Mmv7q9xwgcb93vO6CJ
         E3P0Poi3rGrKeHPd29APff3V9BHzY0Vcbh+ZMdcOt4vbv3tYF4kJKAuNVGImY/eqCvqF
         M51CQZf8n/Xn1OqRKtuU7snN9xG0GlCDh39uQad8H0QKw1l5Uuwhmc1eL6kp4v7fR1mt
         Kbjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q14si104360qtn.4.2020.06.30.05.00.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 05:00:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208381] New: KASAN: crash with percpu_alloc=page
Date: Tue, 30 Jun 2020 12:00:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression attachments.created
Message-ID: <bug-208381-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=208381

            Bug ID: 208381
           Summary: KASAN: crash with percpu_alloc=page
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.7.0
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 289969
  --> https://bugzilla.kernel.org/attachment.cgi?id=289969&action=edit
kernel config

Kernel with KASAN enabled and percpu_alloc=page command line argument fails to
boot with:

BUG: unable to handle page fault for address: fffff52000000000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 7ffd0067 P4D 7ffd0067 PUD 0 
Oops: 0000 [#1] PREEMPT SMP KASAN
CPU: 0 PID: 0 Comm: swapper Not tainted 5.7.0 #2
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
RIP: 0010:memory_is_nonzero mm/kasan/generic.c:120 [inline]
RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:134 [inline]
RIP: 0010:memory_is_poisoned mm/kasan/generic.c:165 [inline]
RIP: 0010:check_memory_region_inline mm/kasan/generic.c:183 [inline]
RIP: 0010:check_memory_region+0x9d/0x1b0 mm/kasan/generic.c:192
Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 1a 01 00 00 41 83 e8 01 4e 8d
44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 c9 00 00 00 <48> 83 38 000
RSP: 0000:ffffffff89807d28 EFLAGS: 00010006
RAX: fffff52000000000 RBX: fffff52000000000 RCX: ffffffff8b976fe6
RDX: 0000000000000001 RSI: 00000000000390c8 RDI: ffffc90000000000
RBP: fffff52000007219 R08: fffff52000007218 R09: 0000000000007219
R10: ffffc900000390c7 R11: fffff52000007218 R12: 00000000000390c8
R13: ffffc90000000000 R14: dffffc0000000000 R15: ffff88807ffc5018
FS:  0000000000000000(0000) GS:ffffffff8b8d0000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52000000000 CR3: 0000000009879000 CR4: 00000000000606b0
Call Trace:
 memcpy+0x39/0x60 mm/kasan/common.c:107
 memcpy include/linux/string.h:381 [inline]
 pcpu_page_first_chunk+0x590/0x6f0 mm/percpu.c:2888
 setup_per_cpu_areas+0x1a3/0x631 arch/x86/kernel/setup_percpu.c:214
 start_kernel+0x324/0x9ba init/main.c:854
 secondary_startup_64+0xa4/0xb0 arch/x86/kernel/head_64.S:242
Modules linked in:
CR2: fffff52000000000
random: get_random_bytes called from init_oops_id kernel/panic.c:528 [inline]
with crng_init=0
random: get_random_bytes called from init_oops_id kernel/panic.c:525 [inline]
with crng_init=0
random: get_random_bytes called from print_oops_end_marker+0x36/0x50
kernel/panic.c:538 with crng_init=0
---[ end trace 58d96ce325734210 ]---

Reported-by: Brad Spengler <@spendergrsec>

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208381-199747%40https.bugzilla.kernel.org/.
