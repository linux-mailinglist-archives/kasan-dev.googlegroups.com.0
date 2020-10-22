Return-Path: <kasan-dev+bncBC24VNFHTMIBBSHTY76AKGQEQVPIY7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 87AF42966A5
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 23:29:46 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id c4sf1713674pll.20
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 14:29:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603402185; cv=pass;
        d=google.com; s=arc-20160816;
        b=nKRIAXmDjYnIL8+CIZubuvBqzVJ2iy1WQR5tm1oC82kL70KLhBPkV0cicijIZeCgTc
         KjluXfFx0EGjrCLFhaMFXQ51avCkoLSaFetMDCNUsy5swLldDHMg93d2bUWUhARf/7lS
         3W8QRc0QDm5vgRj1RMdoej9+FaSbiFrVAU10pFiJxevFqHoPZ3zrtrWettf2RRgWmFvo
         VkOOA2zvu4AswEvFqGFHr6IklFOo8kE/t0UhpmrJcmtLzzCHxmytr0L6MmTQT3FA+ojm
         Sq12r/QstOpEMMJoNbQP9qemCe23n0OVDvhR4Lc70b+V+nDDVC7+cCSZTSFjdDY3v1Hv
         AKXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=KLH1WeYW+9KnIIdOjGzarsPXuK+3dmzDrSs+2hhCs1k=;
        b=HEfo29nGsWKeac2QRxZawK4pAiuF7h9alaoBRE2HDYKkzq8skaFn4x07TNazpJhQx2
         WehaOWyEz2NjJOGdpXArNboAUt3mCiFgiIedA3OkBWSm6PdbcuR7cG4URWFyOU3r2yYh
         vMUz+9Z8oiJfHnBKvseoXBeuHCCyJ1jqP48oyzlkaCPfNTVJWcW2GBX9CvL5z+zL4HRY
         PR5yiRNXPTORyD8jRe7c+4yd9ftG3aaF2VyfSS9SX1FdeuDlm5j8+Uui8N80Ik8smzV3
         82qH2ZpydaVOTgByRgs+zu50jYsYZKVmgFZKwmVhc4w6URQFyZOOKQKDhZzQdKhnUoK7
         +eVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=igqz=d5=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IgQZ=D5=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KLH1WeYW+9KnIIdOjGzarsPXuK+3dmzDrSs+2hhCs1k=;
        b=FMTxddcbQIrGkU/jLKwyOhSJnqx/EWZv0SbF2uDY25oKuR2qnTaecuohIe6cVEgObK
         Cih0VGsejTkYbPjIkr2MJ8H9ZfkhrLAuDD2PCRb+zSEq0YisMEpcrmj0unTW84sycftS
         LW7//Pg6vYwyLsoTmU044+ZqQmEUHFGVMP6wbTTWZrUMpQiA3nQ5TeIqO2YnGdGFMwcm
         Tu7x07q+COOlyLebMlN2C2EGD918iESX7byJ/k+sRYTqBweKImk8yvayTRy4IA6uF+E6
         VVSezEK0H/sv3etY/WurINr7d3zmIYQJbTS8xVEh86KNr52yTaIwBIJds7x/otilp+Ti
         ORDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KLH1WeYW+9KnIIdOjGzarsPXuK+3dmzDrSs+2hhCs1k=;
        b=hik7wvtEEkmSpPBq8dx97Z4h39F8If9WzizeOrQvc0dYTw8WmlmF5Co6b0N9hvNNs6
         vip7NG4xjAEonKalwf892C+gfDljKvbnGMM205VfU61oekLwGi2qix/1IDrhhv26jPFP
         AeNc+Xu7idD+syBMZvEllc/AmfH9XA9zO5wYQ8sjTfDXssVg6ZJl3jxPXMOiK0x/+XwT
         aqgHSAOre6Z+tILLBuJcergET92OZKIv/hR3n4yl6zjmfcVQxz49v3ipAh9m00IUs9P0
         YTAFzczUFW9yz9JDtABo2x5JZIJTqQVCOVE0EGGk1PUQ0fymGwU0edrtDWr35Zf52XzC
         9zfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311azsjnBNRxH8nQEAg22VCBO+0yAlStp2efGeXIpG02pWfzQ1P
	nFp3Y7MTn61BV63FG/w9VZA=
X-Google-Smtp-Source: ABdhPJyKCe7fnSYkyPs5Arp1M4dUfsMI96yf68fwA35dd5VnWDuAkcVfb5m7PXaAYmWN2G0E53SaEQ==
X-Received: by 2002:aa7:9201:0:b029:156:1a1f:5291 with SMTP id 1-20020aa792010000b02901561a1f5291mr4568754pfo.13.1603402184938;
        Thu, 22 Oct 2020 14:29:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc20:: with SMTP id j32ls1065007pgi.11.gmail; Thu, 22
 Oct 2020 14:29:44 -0700 (PDT)
X-Received: by 2002:a63:8c59:: with SMTP id q25mr2823010pgn.15.1603402184431;
        Thu, 22 Oct 2020 14:29:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603402184; cv=none;
        d=google.com; s=arc-20160816;
        b=lE8ilYZn8bYo5rBK7FgP8UAeHbnasMQzqxRJbylm4tvMfxPFXmM54GPADP7cYIh6m7
         euyA4RCY0FcJk/UNtQMZTKbLMF9NueF4qno47ad2L22Xvvo1Kaq69X9u47htmjhSNIZw
         b6eKGW4xMi9p6HeHyI+UuyeF77mg4OA02KOmqsAUBwLgT7VfK7/ZMsxVZTXuychoTZxI
         S5PyKKrMcEsxluv0u1gR/EObgbUUW3YxFbb02iE/eyjngyIw+rjuRZ/3SQVulbRyh9Fs
         KbdzQGsmI6bM0bWUW+6EiwZGIesJOfwDn4AutLQrJE5CGOzweZF6GV+S37YcpKMPtR/W
         gtgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=hwMKuJ9rFs4fPocU/5U8oJHXPxczUJzjhKIu0mX4dRA=;
        b=CqQ/aFxT4l/ZbIqvUV09cQVv1uxPgVZ0vJQybgIfpIJMNJFQ9KJkaaVgxrFfMz0ooV
         4t+DojvdNzzOYcIqgbGx5iKDAOabdjfJvrTOJhRG4XwZFYpIAv4Y9gy4s9oADFUo8xbw
         3Qel7QhZicjHRWhHkPUml5HYjrPNQyUkZIw5V6MR7PywpWDT7f+zC+6pd8BrZGQHB3GB
         E/4WDd0tQt//UP9fYEeuJ5n90RwjO1ZZTfJDkeJI6pmW6O39OmATO5OAOweMdrXJVRqS
         XydpZha1GNSCx8h7Zwt2CGF3ABksZnrOMiOwvApV7efctZf+9sznJTBTK17hMVGfgffO
         ujLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=igqz=d5=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IgQZ=D5=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e22si246472pgv.5.2020.10.22.14.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Oct 2020 14:29:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=igqz=d5=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209821] New: KASAN: improve x2 memory overhead for kmalloc
 objects
Date: Thu, 22 Oct 2020 21:29:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-209821-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=igqz=d5=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IgQZ=D5=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209821

            Bug ID: 209821
           Summary: KASAN: improve x2 memory overhead for kmalloc objects
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

As of [1] kmalloc return value is aligned to the size of the allocation for
power-of-two kmalloc caches. As KASAN adds just a few bytes of metadata after
each object, this results in x2 memory usage increase for such kmalloc caches.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=59bb47985c1db229ccff8c5deebecd54fc77d2a9

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209821-199747%40https.bugzilla.kernel.org/.
