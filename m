Return-Path: <kasan-dev+bncBC24VNFHTMIBBK5673ZAKGQE37ABFVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33EC7179060
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 13:29:32 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id n130sf1147535qke.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 04:29:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583324971; cv=pass;
        d=google.com; s=arc-20160816;
        b=pEV+UWQgaE6ZWs2tyKQq7bh4wXu8N0gI9EznwQW3f6R22RTJUQvMMfmlHAXA2xU9qa
         Ty7jsO/BQA3sYhBTuwacV5wgYvUf/S7K+aki1Pmmzl0BrJ1aJEDT5t1jj7txvXH2iqMf
         twEd/d/A3jcwz/31JbtAC32nJ4rML4tQ98G0kfLW+xS+CVk+ECSUj9Fq9VkhEa6dIfN7
         K7HcHre+6Dtpmf9WjpD/We93Hfa2yVtFLUTJUcL+lnWEI8rd6u+ppJLKXsv1vKwKbKHe
         Fjd3pjN32BfwH309x/3yagFJuGY/yGejyzt2YSKbErmpgtWJ76RnoSk3hAL/OSuSAiI2
         6IHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=IwvlFWVFmt3sMcfifPgToFrox22C9DdFAaYdHhtGFk8=;
        b=JfFCwMYyGXGDAeuOILcN1YDiw0EBnPhFA6vKlFlEH0aD/WDFNJB/bhGuIt3pgTtLyW
         EKgPmKj9sFSHhlcDRYMqu/q3qfrksJFfgNL9w0XKW8drhkPfHQifaR3Mwz/nHNeBQmWK
         oWiIZ2+R1g4fN22pTPM0RC9X/9ZK/I+DVhocaDDrU1GLlKcp7EhECEJJF43mk3S8GSd7
         ts8t+F0wHRsjTQ5n7hd1T7jC3/uK2bX7LWbvqsr+Xy0gLqNL0yG6CtiM9AiOEiPhqyJj
         v0accR9XgGU92AYcGKTfX9UedKPeoy10uI/TtIdRvH9kZKWCjL4eFuQc7x6MqfrXk+f7
         0coA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwvlFWVFmt3sMcfifPgToFrox22C9DdFAaYdHhtGFk8=;
        b=DtoA/bM5B/+ol76a4aRkmlvioeT3Rhb6nzUMmx7DXw6+ZDMTrdqRHy7xOy4YSVkryP
         em/5Vx+gpVwrFn0/P0C+x3/o8v9zy56t5/6V4uiZ8Q7qV/g0WaPJRjTSjWw4HH6UhNr1
         ZkEa3vXCVTe7uLwjZOz8ybHWJmgMcjsLicx7q1pFB9rN0T9GO4eMueQYHxC5wPaJcqET
         B7F7pPoZ854pOyBWNSlMfQnQK8P0M+fC5Q1qpSi/+BS1I5LJDEPfV7y69ITbF9Xb6iro
         Xi45UpZBvNurf/Hw0mWptSRXl4RMy3DAPkpkDEtN2GhZdjBO8/Rp9nDeYQF97O271xI9
         Wvvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwvlFWVFmt3sMcfifPgToFrox22C9DdFAaYdHhtGFk8=;
        b=PBswyrk+kR2AJz2UqkkYquqHxFikF4ORArzyVAFdTPyvNFP3qwitUl0OJxoyl8MjUY
         5nCoakKjLq7ryh/sGYXG8oqfLHABhwlwMVycVuMNbHupC4NxYbu4K2eckkg7sUy2D6EF
         CaUx68t4epOHGJeXbjD5Dyp/AjOYlVY4wmtjBAx/LseyyhD48IVvMROZgRqjaYD8bYL8
         iTpgNfgxAwRXgFvXq+Tv34nI+l8FE199E6TpDDwttn65U442uuA3r5JbJWFQx18oMZaq
         Dgl03FYBecUAWLc7sKHsuY53GEHwZ9dBz1X+Ibe10eGrYrgjTjv8yczL9mLL52EpZ9DC
         n6Mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ28YNitevZC7kcLvZz5UIV17MTZ3dzXnRRbfXa87qly7bpGqI4T
	Xpd4puKbMEunCKu7Z+bnEOM=
X-Google-Smtp-Source: ADFU+vtXZM3F9U0OP3q2/cFlFXg0uKyHbAB24Ppot6L8AEk73x6U+Pdj1tWBaJo4YMiBBNazykzn0w==
X-Received: by 2002:a05:620a:12a5:: with SMTP id x5mr2646024qki.478.1583324971098;
        Wed, 04 Mar 2020 04:29:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:15d8:: with SMTP id o24ls1012064qkm.10.gmail; Wed,
 04 Mar 2020 04:29:30 -0800 (PST)
X-Received: by 2002:a05:620a:22ea:: with SMTP id p10mr2604891qki.75.1583324970779;
        Wed, 04 Mar 2020 04:29:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583324970; cv=none;
        d=google.com; s=arc-20160816;
        b=AQxF8SANBFcVX2Cuhqml73BJL2mo9v4ocmscNWvIz7R3RS24BiPBmIzDRoTCl5Q1a/
         pKP1OJWSl4mRU+CfsRPXynaeJp/DRS3s1riiF3fhUKBOZYAvR3wDNyqkwqtT2htWPgSS
         Bh6LoMGZU8F+21nYXQ0ClCVYCNtFH4wo7frmKwE6HS7ggIbUyxuW1u9dXY9RAO9Le1jn
         6BYu5n3QWz0SHTqa/HoZ1TLMyfUkzvhydODj5eVoPxBf0nv5aMQNpnEG5ARsJ0rBdszN
         2qpTAwOT0hoFxTPHthN4CTqneYmF/i4k+dKEMOL59vYhUhrNfeOjw9XlTqi0A39r1Xu/
         6hlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=JB+TwfRec8aYo8nMK1dP4oTb47odZZW2rqPYcT1J5Mw=;
        b=cWdiv+EkxK7HWVuimez6au4YW2HEqG0+jfvIEIFZuBxKpC/8FhAqgUgSuLu392c4N4
         E6sviVnlRwZ7RvdGwVyQInqzmJjfDyIV+lduIB9xx6gwltpT7B4++FALY7znHR5ELzAG
         AlTW4S2qJmzhH0XI7MRQDsxEbCVjrL7Gdwnqgt68x57V8O3XosoZW9s7vPh+LGpZgGcp
         SpX2SGuD1ZkX7wiHHHFQzUxNSuj0Q646aT50ueEWNKV+DROtYdHjsbMgqJgC5sv8EBpd
         Q96K3IKW5IWvNOfrB5/1oke/ndOmTryZFvFsyJtBaQMMRLlP7pGQg1jXokBWR0wIZQy6
         wUfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c6si107403qko.3.2020.03.04.04.29.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 04:29:30 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206755] New: KASAN: some flags are gcc-isms, not understood by
 clang
Date: Wed, 04 Mar 2020 12:29:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-206755-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206755

            Bug ID: 206755
           Summary: KASAN: some flags are gcc-isms, not understood by
                    clang
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

scripts/Makefile.kasan contains:

CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
                -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET) \
                --param asan-stack=1 --param asan-globals=1 \
                --param
asan-instrumentation-with-call-threshold=$(call_threshold))

This --param is gcc-ism. Clang always had
asan-instrumentation-with-call-threshold flag, but it needs to be passed with
-mllvm or something. The same for stack instrumentation.

There is an interesting story with -fasan-shadow-offset. Clang does not
understand it as well, it has asan-mapping-offset instead. However the value
hardcoded in clang just happens to be the right one (for now... and for
x86_64).

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206755-199747%40https.bugzilla.kernel.org/.
