Return-Path: <kasan-dev+bncBC24VNFHTMIBBMHCZL6QKGQEGBTWHPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ED032B4C14
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 18:04:49 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id o1sf10572442qtp.7
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 09:04:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605546288; cv=pass;
        d=google.com; s=arc-20160816;
        b=CnfOOuiJwTruKE+SSTjKGK+U1U3V7DiOpLEOBX4/aXe6Dqxfov6AHqr/wa3xCwbss4
         inBq78xH2nVjIGGfUjLFE4LT8eIIHDqOUyyGYjyfwJKg9qr9e7yf/Z6BEsp8N6wDXCus
         ETPY8meYcLvMSGF4Evy336ALpj/HanKOXl/GWdBtJysCO0Ct8imqWOLLdhtlzWoW/1Vt
         q84UtFI61xuMhCKL9pawVmqoXh4L4xBlMsScnglJwUvYTz1PyhfD43gvviMoHR6SHjzs
         kvOJpYZ0OzFBvynn/66vR7RLNxKu7nw4cNlm7Q4zqPGb31hmhwRffSbZyj3WwP+Kj51+
         7plA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Ia3I9cuid9w/gzyEmBWEVfgSAoK8R6iZTjaNIPuChEk=;
        b=CrA8QPdJsG6Z+88PHhsTPGC/hYJ9kDjmt1vRMP8G/6V0cL+jEnv9uD8xSG96SpFRCr
         ILLV+CZXQPeMF0XgttTQZtRlg+lPCXT1pVZ9JkaG6sHp1zT+swVwgG3cfciXvq0N/U7L
         F7U0ol3AkFbRcKqP0jUL2vI9FFhGXk1fa//I9Yyh3eGNyKUHEe3LG4HLHSwI3HcOFGt+
         fGxOcYXOmbqjgIzEGsGugIujLr0sJycyhwVzhK44e7G6kMx5MSuPvTZ6867b9NYL4VN6
         AFUCPwvoL239Z/2ZmFEdGGX7jU/HWQX6P3eaSGAF4LS3gP/IP6r50yApoW//sdxA+G2d
         vfzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ia3I9cuid9w/gzyEmBWEVfgSAoK8R6iZTjaNIPuChEk=;
        b=eaQyLPaskfw8NWmhBYBnN/CICb4qX/cr2P2lkfyxiIEMFaZSRv9P5N8KkMCadnPhfe
         A9fU07AMXC2NV/m/m0rGBLiBBa2m8M205d4BHPvCjanG5+HU1SuIkDf3KMJv0wolI5j0
         khswlxvNZPA3ABkIr2NRlSBkvBbQwE5jgko16PZFmK2Of2NZ8JromZDwri0Bb0tIJ9Go
         QTXYAxk+5Q3eTZoNm7tcsaoih0ULeEAuR/v9Tj04BC+9LQw9SLkBLMH7X5JiblsFxxzT
         87oG3BJBgLGdTkqbobzARW897v/Fgq1i7qpU41XaMC0eizyJRJiDBZbaOKgrFTCxn+lZ
         LO2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ia3I9cuid9w/gzyEmBWEVfgSAoK8R6iZTjaNIPuChEk=;
        b=BDzcmktVLmtqxYLg8hUs1iDk1XjyGLxv/uyxEyut/A+5UTDNfMmqke/DTTEWH71T7g
         0MJAufwGL2KJDz3CiltONk1UW5DhWTiicB7S1CIoNHFV6ERB/G00pyjak4vUWwiSo1La
         Fd+DTt1id+Oz+Tm4rWvNCKTJnrBArOx/3yXfBdwgP6Uafk6IjZQEvpuiuAZN/lZq3DGm
         4cGXhn6e+NcSFWGr0POW4ErUqALw41FL7Q+hqXROw1wd3azYGGn4mb2NphVU98IRmTf4
         GA0JPV9vSnUdcmjk8OLqB780RjC/v/hl1EqtUN22Ojpfegot3FOEBxLcfbL6UDgKDZHH
         sukg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D2MGCWszkHdXfYalxkx5Vv7naKR8vrCNqvbtq5/+WlYCNKRuG
	VYRaVUwJhclOAXmdmvoe+uA=
X-Google-Smtp-Source: ABdhPJwo7cIwHmwoB9MUVI9qOI+mJxCOSKObLwWiZvkLWAMt6GAUQqsRKJHpk1H0dYNvz0Ueviw65A==
X-Received: by 2002:aed:2f03:: with SMTP id l3mr15776381qtd.303.1605546288340;
        Mon, 16 Nov 2020 09:04:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6655:: with SMTP id j21ls1533414qtp.5.gmail; Mon, 16 Nov
 2020 09:04:47 -0800 (PST)
X-Received: by 2002:aed:2843:: with SMTP id r61mr15227157qtd.166.1605546287821;
        Mon, 16 Nov 2020 09:04:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605546287; cv=none;
        d=google.com; s=arc-20160816;
        b=zg5ZhpMUS9CnKxw16+XKptgAOdhkoNp0UUENLKLmhsE/rngnGj84wSlC8VGv/2G7Dy
         kLVxqehlEXGi+nfQBasw50roNXsOplH38DcTFoCQTEDMGF4uIsj1XlyYnXKC78XnlAqq
         JkvEJmDuXeAJWR4AOgWV1IWMrmiwKXqdIjuHwdoQ+bBAaIHixGLl4hehqxRvWVLO1r6m
         jCA+nr0fxgeTRVkFMb/Kp3uwRnWU/ij1wOvNPjxr/OKELTI9D5Of59Hjht3PZBPF8DoB
         0eCjZ+VmOu6yQIci6/fDklocnkqogz0apvaTyt2gw+raRsaGA6g04BmI1fJl1HxkqmWY
         GVgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=pACAn+/tNm6jiz9UYYvERQ5Ifn76P6MaI1mNPkwFGOI=;
        b=im8dn7IIcb9X0ZFiqEGFKePEGu1zDZOtxBiFp2FfD7P36upXQH13ahs3pADfWSwbs1
         hRn7vEXL6bqMgCDeGyLAVxih/glrnidp1VZELK0kqWdVTh6QQpdb83K+aWgmAav1fBRX
         WZdAFMvinHHmWXNPUS5fuEi0vtWoVuQq5WCYXEnmuO+QUAs9e0fWIfdlHazpruWyK7iB
         dPLvvrwXBGIZaCrSwhb4lzceZyS350Lx3u1r7L0sbMbyPptqH7X2UM93KrgGqIaqLmvD
         2Sawr3rgXlewCGYX9EVu6+e66Pt/hl3bLeVLSgEvEdzPm2u8+VMDUqo1yRXM9te2i8Jf
         pRlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s190si1171916qkf.4.2020.11.16.09.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 09:04:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210225] New: KCOV: allow both remote and normal coverage
 collection on the same thread
Date: Mon, 16 Nov 2020 17:04:46 +0000
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
Message-ID: <bug-210225-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210225

            Bug ID: 210225
           Summary: KCOV: allow both remote and normal coverage collection
                    on the same thread
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

See some details here: https://www.spinics.net/lists/kernel/msg3736819.html

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210225-199747%40https.bugzilla.kernel.org/.
