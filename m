Return-Path: <kasan-dev+bncBAABBDO2ULFAMGQEZCOCCGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D4123CD48F4
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 03:29:36 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a0e9e0fd49sf44462995ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Dec 2025 18:29:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766370574; cv=pass;
        d=google.com; s=arc-20240605;
        b=GRsdUvQ+cQ5SbbVrre6uJ8xJHew9A/tTJv1nfhRYbvwltoqui28s6Bu+kr9e3o1C0V
         HDpdT+jXynVnA3IcHGR8LJtOzkbIEMuZn9nUKQatDK0Bk73g36WHIP5i5YXSmUS6Z478
         yTpYtoFAbd4KU6WCZ3yTmmlF1VwjcXCAUiE8c51KMW1sBZQgnCQf1MzHQMBUmwv2bD/2
         ybXYMsF60keAOh+aQqiicnSAhNBtnXYFblDkp0gqf33tNRKe21BldwIubTE8Yopt3B5u
         qOhS8vS+9rnHrcku2FgNDat10mmbVmu779x6Gs1GNYRtYPfNZT0M8M3VIpspI4YqdZ6p
         T2Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=476fkJ2N7CcBIy6YgY0Yba+KKLkXGu7wmhQWauRSWmc=;
        fh=FOI6c8WRukpawQfCBEUzbPS5wC0YoFn6jGPJTSjFpeU=;
        b=kW2pCH+L6du4R+ZRGjb8ELlTtlzj13Fh4SFzs0THYsD0ZOmyCCQFkIYacf7B/MiuEY
         U53Wx6U30ephlrb248ZYzJ+kB68vgrRuVCLdXSumlnFz71aMKLhZUVbl3lgl82knlpUK
         UyvAKgTdOei6bxeEZExP3CjTfjeyaeq4skvIiagFiuO2I8q0ysCJrwyuY8cpxIWcJjw/
         pN0maVFHqqDBsX7Wn6250TsUE6xxWdn1JZGqFD+QRXULRNrE6SHWL0Ne/Bi+n/oGXjyo
         ctSZc+sYUE1iRNgPaWGFadPLTxymlWSJwS46Ji2aCPHh195bxzG2x8H37NwMr4+VXJyK
         YTZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zl32QyNi;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766370574; x=1766975374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=476fkJ2N7CcBIy6YgY0Yba+KKLkXGu7wmhQWauRSWmc=;
        b=HjXNX0wR76En4QzR6k1mJO0WU2nwOA/b76HODl94bK1bUDH55dgwFXhJbV+KM6ULyU
         SESTdVuSZpREql8AHR342eO4snvHRONY+XAyj2DocMnq8oIE4X0tjwB1JXvlYOmlCy7+
         k9WaPFbUkqFNgyFjkgRCP5WIC4U99k7GjKmUgBcDy2+CRDAw3fCuY1BIcghrt6gRqymA
         836qFB2uIO4vC3ZklQxFxTVd8DpLYn5PZ3DKTm+uTBQprkB9RCdVE5qsZn3ZJRL/JfHT
         znLJqO0PWY96drFHyk4E+IH9x+w+VEcMUFO1aY4dZFIV+c1W+ulo1pZNnzDDwLbIOUN2
         xURw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766370574; x=1766975374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=476fkJ2N7CcBIy6YgY0Yba+KKLkXGu7wmhQWauRSWmc=;
        b=Reb8Bs5tgKUOT5z9kKzbL8ljVOCAOb7pHrnnGaBvjJPtcLUByOkiKWndhxiuD83Rk2
         fHJNIwKEgcUJVoqSivY34R2T2+92jaQJ+gCYzHBBDF3B0PE0otIvs8VU1hO0ne46Jlea
         E0F2vJGDs+X1U3fvS25oW4DD1p5Jp3q7Hcf1lBd0yL7YUdg3Cte/0tM40xeLGWJLInrv
         MG1i0e6FfRcDKNgzRXaPTbRM4n4mR2YyzRATX7LsMvQ6lSWzetolG7YI3izb8K5lITQt
         +J0qfP3nyKegSCoZO8H1f492leX8RBoDiSDoaL+sFrNyldSUnjbtbBa9Wya6xdz7Xj8q
         +QGg==
X-Forwarded-Encrypted: i=2; AJvYcCXBcgDsR7sYH3eCfOmN2gTr5mapysk0QsTbhXMg5ttc8qwcHBLOaCtC1L1uXFYav2/3VReyzg==@lfdr.de
X-Gm-Message-State: AOJu0YwTUxMJOWVOL91rF9hjkZBInYFa4YRTk7zvJGlaYYZG4aRzvOJL
	Os2Ni8X2BNQ+Msyfh5J5+M3a9nL2VFq1lNJPiJlhacfRA+e4eeQ3J7P8
X-Google-Smtp-Source: AGHT+IFpsILMh1fjITYlLER5FOtIZQLqH4shako8eVaI/s5fhkhejVCZsEQPbpWl/v/dpRI4kQBKxA==
X-Received: by 2002:a17:90b:4b0b:b0:340:c094:fbff with SMTP id 98e67ed59e1d1-34e71e09fecmr10963995a91.10.1766370574406;
        Sun, 21 Dec 2025 18:29:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbaRt27O3cwvXI9T7Xeqqj3wtI/ihVmKo75GOEXu+zyGg=="
Received: by 2002:a17:90b:33d1:b0:34e:be5f:7cfe with SMTP id
 98e67ed59e1d1-34ebe5f7e66ls752889a91.2.-pod-prod-00-us-canary; Sun, 21 Dec
 2025 18:29:33 -0800 (PST)
X-Received: by 2002:a05:6a20:1590:b0:2cb:519b:33fe with SMTP id adf61e73a8af0-3769f335199mr10014326637.21.1766370572696;
        Sun, 21 Dec 2025 18:29:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766370572; cv=none;
        d=google.com; s=arc-20240605;
        b=hmrjBwnnKPd+wqb8T2aKHAuq8uXXo5haaAp3blrSGM6AF2kT6/xMzpCv3zyxUpBffu
         bb8cksyRw4NFR9HX1mA9m0jVjK/pW2QNDhyc/TBvZHMhMIYWBCJy06t+harMYAIAzzLu
         3hDFxUU44xUZ9thUnu7PQAsqqnfOebboUrZrezsykDGxjsJ9t5QwXBv5l3yxMNnw6wEe
         QsfuP15VBOTanj30BkkEEd9VpX4aaq8rBwjSJbNQ3CY6Zq/USXsKxdRhUdOfC8iHMldn
         gwkgCUtsHmrQhSuOV/aMGOdGiCCyBdBS7YAVVh3PtoKEmG5MF/tkbKiGe/VJqMhHwipb
         Lkag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=67S7jtqEyIAjmc8iOFtroavzClzTqG3x+Ggk79bh834=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=L31BH+e+VhsTlTNvU7WZ9vX4S2Ntol9mIFAyWCieYJ/W1jMDK/xoS3YmtvGGuSBJAq
         gxPCyXpn5tcGAK4lpd2a2TYnk63ETqC66rQRv3rE3BGrKf9CRkK5mYd/ee7/ecvQnGTF
         D9PtqSuBzwfn8nm22ezQI0zHL9lcG5efk9vWBiUoP0scsBLAnQem61v59o0y38CIJM2T
         L2F4ALkZbZdacSrcBqzKfZC6Juwp7rr+s3+L3qj1T88BjwCUsNQsOEQzrBAWNvXX6CXn
         BgAlVuOcJKgWhezkydiUm4ScZlfVzA8guzp0iVyNUBZlTst2ToRvpiWNfRcrEdDqVqr1
         aKxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zl32QyNi;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e76be0e12si220103a91.1.2025.12.21.18.29.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Dec 2025 18:29:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4EEA04067F
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 02:29:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 20E44C116B1
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 02:29:32 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 14B43C41614; Mon, 22 Dec 2025 02:29:32 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] New: KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Mon, 22 Dec 2025 02:29:31 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: joonki.min@samsung.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys bug_status bug_severity priority
 component assigned_to reporter cc cf_regression
Message-ID: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Zl32QyNi;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=220889

            Bug ID: 220889
           Summary: KASAN: invalid-access in
                    bpf_patch_insn_data+0x22c/0x2f0
           Product: Memory Management
           Version: 2.5
    Kernel Version: v6.18
          Hardware: ARM
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: joonki.min@samsung.com
                CC: kasan-dev@googlegroups.com
        Regression: No

When SW tag KASAN is enabled, we got kernel crash from bpf/verifier.

I found that it occurred only from 6.18, not 6.12 LTS we're working on.

After some tests, I found that the device is booted when 2 commits are
reverted.


bpf: potential double-free of env->insn_aux_data
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b13448dd64e27752fad252cec7da1a50ab9f0b6f

bpf: use realloc in bpf_patch_insn_data
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=77620d1267392b1a34bfc437d2adea3006f95865


==================================================================
[   79.419177] [4:     netbpfload:  825] BUG: KASAN: invalid-access in
bpf_patch_insn_data+0x22c/0x2f0
[   79.419415] [4:     netbpfload:  825] Write of size 27896 at addr
25ffffc08e6314d0 by task netbpfload/825
[   79.419984] [4:     netbpfload:  825] Pointer tag: [25], memory tag: [fa]
[   79.425193] [4:     netbpfload:  825] 
[   79.427365] [4:     netbpfload:  825] CPU: 4 UID: 0 PID: 825 Comm:
netbpfload Tainted: G           OE      
6.18.0-rc6-android17-0-gd28deb424356-4k #1 PREEMPT 
92293e52a7788dc6ec1b9dff6625aaee925f3475
[   79.427374] [4:     netbpfload:  825] Tainted: [O]=OOT_MODULE,
[E]=UNSIGNED_MODULE
[   79.427378] [4:     netbpfload:  825] Hardware name: Samsung ERD9965 board
based on S5E9965 (DT)
[   79.427382] [4:     netbpfload:  825] Call trace:
[   79.427385] [4:     netbpfload:  825]  show_stack+0x18/0x28 (C)
[   79.427394] [4:     netbpfload:  825]  __dump_stack+0x28/0x3c
[   79.427401] [4:     netbpfload:  825]  dump_stack_lvl+0x7c/0xa8
[   79.427407] [4:     netbpfload:  825]  print_address_description+0x7c/0x20c
[   79.427414] [4:     netbpfload:  825]  print_report+0x70/0x8c
[   79.427421] [4:     netbpfload:  825]  kasan_report+0xb4/0x114
[   79.427427] [4:     netbpfload:  825]  kasan_check_range+0x94/0xa0
[   79.427432] [4:     netbpfload:  825]  __asan_memmove+0x54/0x88
[   79.427437] [4:     netbpfload:  825]  bpf_patch_insn_data+0x22c/0x2f0
[   79.427442] [4:     netbpfload:  825]  bpf_check+0x2b44/0x8c34
[   79.427449] [4:     netbpfload:  825]  bpf_prog_load+0x8dc/0x990
[   79.427453] [4:     netbpfload:  825]  __sys_bpf+0x300/0x4c8
[   79.427458] [4:     netbpfload:  825]  __arm64_sys_bpf+0x48/0x64
[   79.427465] [4:     netbpfload:  825]  invoke_syscall+0x6c/0x13c
[   79.427471] [4:     netbpfload:  825]  el0_svc_common+0xf8/0x138
[   79.427478] [4:     netbpfload:  825]  do_el0_svc+0x30/0x40
[   79.427484] [4:     netbpfload:  825]  el0_svc+0x38/0x8c
[   79.427491] [4:     netbpfload:  825]  el0t_64_sync_handler+0x68/0xdc
[   79.427497] [4:     netbpfload:  825]  el0t_64_sync+0x1b8/0x1bc
[   79.427502] [4:     netbpfload:  825] 
[   79.545586] [4:     netbpfload:  825] The buggy address belongs to a 8-page
vmalloc region starting at 0x25ffffc08e631000 allocated at
bpf_patch_insn_data+0x8c/0x2f0
[   79.558777] [4:     netbpfload:  825] The buggy address belongs to the
physical page:
[   79.565029] [4:     netbpfload:  825] page: refcount:1 mapcount:0
mapping:0000000000000000 index:0x0 pfn:0x8b308b
[   79.573710] [4:     netbpfload:  825] memcg:c6ffff882d1d6402
[   79.577791] [4:     netbpfload:  825] flags:
0x6f80000000000000(zone=1|kasantag=0xbe)
[   79.584042] [4:     netbpfload:  825] raw: 6f80000000000000 0000000000000000
dead000000000122 0000000000000000
[   79.592460] [4:     netbpfload:  825] raw: 0000000000000000 0000000000000000
00000001ffffffff c6ffff882d1d6402
[   79.600877] [4:     netbpfload:  825] page dumped because: kasan: bad access
detected
[   79.607126] [4:     netbpfload:  825] 
[   79.609296] [4:     netbpfload:  825] Memory state around the buggy address:
[   79.614766] [4:     netbpfload:  825]  ffffffc08e637f00: 25 25 25 25 25 25
25 25 25 25 25 25 25 25 25 25
[   79.622665] [4:     netbpfload:  825]  ffffffc08e638000: 25 25 25 25 25 25
25 25 25 25 25 25 25 25 25 25
[   79.630562] [4:     netbpfload:  825] >ffffffc08e638100: 25 25 25 25 25 25
25 fa fa fa fa fa fa fe fe fe
[   79.638463] [4:     netbpfload:  825]                                       
 ^
[   79.644190] [4:     netbpfload:  825]  ffffffc08e638200: fe fe fe fe fe fe
fe fe fe fe fe fe fe fe fe fe
[   79.652089] [4:     netbpfload:  825]  ffffffc08e638300: fe fe fe fe fe fe
fe fe fe fe fe fe fe fe fe fe
[   79.659987] [4:     netbpfload:  825]
==================================================================

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747%40https.bugzilla.kernel.org/.
