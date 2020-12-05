Return-Path: <kasan-dev+bncBC24VNFHTMIBBQOBV77AKGQE2T3OV5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 449872CFE6D
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Dec 2020 20:34:27 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id j18sf8448874ilc.9
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Dec 2020 11:34:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607196866; cv=pass;
        d=google.com; s=arc-20160816;
        b=A+kobvYEJKgoP0UO73w1St6Ag5nWUoNipfvGmBcAGgAU9gGG/ZeoDiFoRIdOFbQNQ3
         5y7pdjSeu3cCcp6FDmhMHXyZxrBiwvMZErGYIuttOeRlXtbjpsjvlTE22J3rUpLDsHJf
         NmSdZVz0nh9nZYBywBe0HSrka8UQ2p0laWdYXiu+ejfftXNj0xN3iglsAI0IVkP9Y5GV
         3HwO5u73zSVG0SLU+tboMcJ4nZw+2fkGw5JQiFgg06bJEYfwQ9F/CTgFWvIZ5WmfhIEY
         Pra5posUA+cBUbsJGk50JNXVUkaMsFTlH+LEv2mfGPsf/eyUTxQPXoScvHyEaRmj3okW
         ysPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=R8lcL/MXaQL3QYgeTqViSHmoYmjGAl85rFn5ZjHYR3A=;
        b=O+ZL2+FLmRIFxpkNFPKs+iy1y57H8dcjdFnwC/x4W4YpWCId8nPwb2ojWrUh3vJFnm
         Jn+qpsKARfgZ9Gqm06YKGQLl77LBGodRLmZoxAgA7k1U2xMWARlJwDuyPZvoE8JCMvv9
         u3tT2favGVvTLXvMPhSFNie7oKDKBAnTvJlSoAICp2dzKFPrWLp8MfS4fM0VO0dOqC8N
         /91ZJzkD7XlmLnKiqUdUrKA+WT3mXYQb2nuW6q466vdebQdel+7nVWEz2V27MCuo8sWQ
         kx7nmYy9XxyHJyi8/AJuEWdawxtCYvQ1+HyCQSbrYtZVUS3QbR+/quVsHBhfbqbq6rwH
         eFDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R8lcL/MXaQL3QYgeTqViSHmoYmjGAl85rFn5ZjHYR3A=;
        b=Qd/Fl5Dr6A8TbTWhPozvqYblO4oyGGs9NqTwyK32SRhET1H/typtabLoeQCxx7ug8f
         7+FtrTPUP8vTVnXGHJWIlcXbrxSK+Pp7ZmyV4jAgxYdK8mfZ1KnuitpRiOhP+uxD29Py
         P0th95k6ZXFyBpiQma1AVkS82fkcVsDVQ5ORZLWAiIdvsqw7H6NqKappOX5TAr/zErMD
         1DaVxHW3b5ImXlx+FfmBXPETOhQ9pVqlB2gMUkElucMwDKxiX1NwaJVupWXbwXunMSgO
         URecWnM+zqZ6eo57gnJdocT/ZALKDlQ4Fd7arr6uHT8OsiZzfhDSvREM+F3tqs3PgV8+
         NnNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R8lcL/MXaQL3QYgeTqViSHmoYmjGAl85rFn5ZjHYR3A=;
        b=raN53dwCcHTP7VdDSNWuKYc9uCnrcRSe2uKzIhG0xprgTdN9lN+eGAUwrWojeSNSP6
         oABWWnl/+VAP3yKb5lgOPe641TuTfo+r1LXu7wC080QzLm+J+8rAfk1i1wQXBfhQ9hQl
         piKQjfH64vNMHPv3AKvY4yXWe0JRoBikoHGms+j+t29MGZRq+vMLCsOXeUa8rcqv3Ao+
         jgC9fG8QoIK54MEno0Z+dAyq3SSFXMp7aldhofiPmU4OVByJUIoozsoMaKgMPzNQVlML
         o6NkI+gnbwEYT/VviQAQqZPzOozs/lnhBjs23kVyrDdwoWMJ5wjXqFxjxGlIhzDEgLas
         Xiyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530beNFJuWlrBHvFqlIiSxyIdfXRd4Wz2vjwvGmCYgp+tdbF15eI
	kO91k/PMry2WSH7FdAllmHU=
X-Google-Smtp-Source: ABdhPJx1XI3wM5gAH1uoabynzls5hgjIFuRcmhVjmBwSlPeI84WxyApTYXJMsyVDES2QYx/VUc8dCg==
X-Received: by 2002:a05:6638:dc3:: with SMTP id m3mr12505362jaj.78.1607196865833;
        Sat, 05 Dec 2020 11:34:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a41:: with SMTP id 62ls1622040jaw.1.gmail; Sat, 05 Dec
 2020 11:34:25 -0800 (PST)
X-Received: by 2002:a02:c804:: with SMTP id p4mr12454613jao.110.1607196864980;
        Sat, 05 Dec 2020 11:34:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607196864; cv=none;
        d=google.com; s=arc-20160816;
        b=jvwinkR9eFr5fu/ha2iHgqW2jeE4LoLzqCIPQeFqH0XqRF1WfX3VfVnz+9xMm1az9O
         k6kOHWBHAcO21gUtYFNqi/ay9ce5dfK4JjHhTWT0SohGrPttyxovloffDeCWhoSUEmIV
         IBGmr/xDOkP12KqF7HY6KUqvVjxj5kTQ1DQUaPqRSe2NGPA6pGOVRMiVAr/KrLP3Krm6
         kKNeAuEIijJ0iH1+GhKP5QTM81YIXDJRRZ7zoA8O5alUCXnheO6+OpUPdiIbpmKBcr+v
         mbCEhuYtfr5+FeaxvdAgY5usiWg6Pm33hKFjFn7u0NktOIJSOcTa1mQcyOwmUb4KZ+fz
         SEmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=4ZpzOQZxhqiuX/6GZFN4IG0Pde+hOtxgEVrpeFhvZ2w=;
        b=LUkGNi4JwVNx7Zf8K6Ohgt00Ls6cdleA5+L52zzpqx7DEMLGOJUGN+OKJ1T/nXLXsn
         EmjUMJreF+PhtoQwfR0PpD8keesi1QcLdlhz6ITfZ6V3r/nxR3VDBM84PqpHApmHjLq6
         dnNpaf2He0g7EYcVB7a8fLbm4uGhIUnyb3FZ/T4ZO5iEafIkOD0EMLPSYpyiAo/uPZTh
         wuLuZPe1PTZgh33hF4dDpoUskyAFFsmu3b/UvtbaRCK4Z4xhgbL+RnWN9QAXpbVJC4Iv
         PY8scydAtQayRZqdn0d3ISatTg88tiD1F+fg42McEv4zTOmjI1VdMf+qP4DwJIorQdud
         qd+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u4si447572ilk.5.2020.12.05.11.34.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Dec 2020 11:34:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] New: KASAN: handle copy_from/to_kernel_nofault
Date: Sat, 05 Dec 2020 19:34:23 +0000
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
Message-ID: <bug-210505-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

            Bug ID: 210505
           Summary: KASAN: handle copy_from/to_kernel_nofault
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

KASAN should check both arguments of copy_from/to_kernel_nofault() for
accessibility when both are fault-safe.

KASAN also needs some reasonable checking scheme when accessing one of the
arguments leads to a fault.

==== Test

static void copy_from_to_kernel(struct kunit *test)
{
        char *ptr;
        char buf[16];
        size_t size = sizeof(buf);

        ptr = kmalloc(size, GFP_KERNEL);
        KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
        kfree(ptr);

        KUNIT_EXPECT_KASAN_FAIL(test,
                copy_from_kernel_nofault(&buf[0], ptr, size)); // fails
        KUNIT_EXPECT_KASAN_FAIL(test,
                copy_from_kernel_nofault(ptr, &buf[0], size));
        KUNIT_EXPECT_KASAN_FAIL(test,
                copy_to_kernel_nofault(&buf[0], ptr, size));
        KUNIT_EXPECT_KASAN_FAIL(test,
                copy_to_kernel_nofault(ptr, &buf[0], size)); // fails
}

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747%40https.bugzilla.kernel.org/.
