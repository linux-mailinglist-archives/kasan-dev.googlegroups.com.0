Return-Path: <kasan-dev+bncBC24VNFHTMIBBD737H6QKGQEANRSVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1CC2C4479
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 16:51:44 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id x20sf1925445pfm.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 07:51:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606319503; cv=pass;
        d=google.com; s=arc-20160816;
        b=OsjqlSiNCC9p1jJF5WV0Q0hlE27op8QbgLNEJY6VT3tKZ2s3hAXWqvB7BCzWmW8Svv
         46cS98AEwqRsda4hV31LHdo7rs7rOXAEOTO2uEAUV2NVbG63+YwTnmMahhwkx9uD2Rdj
         xaHv3y9clsboXwzGy5ggEAyFKW1zl9+u/dOX3fa7mA+8yf1tHJnftlQYYOn1G1utvzmb
         d5MSgPXlqJdrkzjWfDzhOs8XelMN3mSyf1IEwb67FtqeaZlKlk6YQrKXoEGBUrc3QvTX
         7VG69YtVIBZ6m+62P+Xf7AQ2hIWG84LLsbhlYGljyBl3KFiUiEFL5bgdcjnEvxYJsHpc
         FdQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=rKcD0ZJqc1CiQYDh71kyaEuyI+FZUnmi6JGRquHJ+9s=;
        b=ZqnWHXA7gcYDRq+FB+N0hG64M1QL2kTT3nQkOR73QYxZCpHDos0W8nE7hV0XEwuIKv
         EW6/9WgmtA49ZYV7nZo6WYNUdG5yU5UYUGPlWrr80ICvXLn3TOi/Ndi+rmu83EDCFfQT
         UK6bUw/v5Ud0t54exIJqtqMM1nHh/3FQnxoEzIc3SPMLygC+cWHcNLlqGThwq2tSNft3
         n/gtEPwZOpKmODh87WCiASk1eTGcHdYekyHMfRli3P64pFUE2Ucgudd4eHTexNIOuQI3
         5DG4ILPzT102z2pp2atcizXqqinrkxoIuPs+wNLMiMxq8BSkEIBODk2+50SGKI6gOQEE
         eu4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rKcD0ZJqc1CiQYDh71kyaEuyI+FZUnmi6JGRquHJ+9s=;
        b=WRKbjDqNnYyI9c/bAHFq1PjC8z26kC5BMGDHig+L9zRdw6a4hD7Ie17t0grgQppPJY
         DrbGsR5Z9P+vMyLWszINYQOrERaR7Mht2IaLVf2hQo8HbbtsrccsE2bBpDs/bakDBiCS
         0kP2VxixApIIJTJ2GyBkpm6EPGZathz+EAHfyQwhNjKptezqO5cwry5UeuGswDXVsWbT
         fyR+OFJH4HYIGKj1FG3z5MY/G3Mp4PhlstqaUIqBhJwrFBxwpiW2iDwrgmM6d3n60Zqt
         Osqrll6LdZgp3VKB/Sq37uKYnIVisdU8icNxHnOxk7SVxEcY8+orRzhlPRyjrc6VaE+r
         Q8DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rKcD0ZJqc1CiQYDh71kyaEuyI+FZUnmi6JGRquHJ+9s=;
        b=bJfSFm53BoodWmznXqTB1JMWqin90VHlaGp4Vn/BxDO11XqDroaCZVL5fkeyA+RuIn
         OivegXIhRxU3bR7+ROvD78vko5jVJFiwJDqXitXrNLpU+WBQDYP18MyWlN4NCIF+dFhS
         FJmly8W1gBQjjC+eVDmKRqoxBrrz8h4qJHjjMExbhdZ7Q9oypQTH3UnofxeOjv05mhpk
         FPy8596CVfq49ZLP7NbIb6YdHs4BYmmgSmoqv3iM68cr3QQ/fxzpR4KE1aoPGeU11u8P
         gSfu8ho2N/EmHHuNb+fl/s8g1KH/kejwt2wGthbJoonaIUyErM1HCKAbR+Q5GSvmcld+
         7cdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UQoeNrO0MH13b4Fm7VoD9eanvHM7WatlDaYk/fHLSQ3VgaelY
	JbcF671zatKwdnjh/wbJCQ8=
X-Google-Smtp-Source: ABdhPJyfmP//DQ7GyreakBQx9vASFAJSvJw3qFLtgF3MZ1Ff9dAfDjfO4ztN6S/o5p5lVkiGjJ1gJg==
X-Received: by 2002:a17:90b:249:: with SMTP id fz9mr4840945pjb.233.1606319503465;
        Wed, 25 Nov 2020 07:51:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8508:: with SMTP id bj8ls1256349plb.2.gmail; Wed, 25
 Nov 2020 07:51:42 -0800 (PST)
X-Received: by 2002:a17:902:ee15:b029:da:d7b:c6b5 with SMTP id z21-20020a170902ee15b02900da0d7bc6b5mr2958290plb.14.1606319502615;
        Wed, 25 Nov 2020 07:51:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606319502; cv=none;
        d=google.com; s=arc-20160816;
        b=S9IXN8rMIta7IsODhmQKCUNMXL0bC7/vs+dpa5zXb19HMbMJNUHbzDi+cM0cC6fSKd
         MEJjYe9MSZqp3m+tDP1nX4V0CDySgIR+arapPBRSkCbA2C2XuW2w4BUtb8V+24vaDEkn
         raot3NGci0AefaEw7edfGoAHKun5YIpPfU1rVgR0KhbY4P57hPODq8YCam1d3+lVeiAC
         AgXgpCwmyL34oCU1M2Wc/f4K7+c8lNYfRlvOCnG5Z7fyn4yjAbchW6ycfSF0E4ewtxF1
         XKpUswrwvirYCQQEnyCkBaguier4OY3YepDMc8MPHWBxAmqFzlrH+6Yo4VItPvK3C+Cc
         0Lzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=+A1uVwf7AX/G2jBtjCVjpwwr3/yOGvBtvf1BVYNO5b4=;
        b=NXv6b9mdypyjVNO0IyaxosebFP64KhFD6jofbOMkKSCJeqlUCgpzrFUCjUOKpHvlV6
         iTD/mTvCnigTIbYv8sIej6jZuM6u5xDMEeBkyjnle1wPH4R30qQLqvIEux6sZniDeBmY
         g5UiDgi7ySXKtzVSoBwMcgnIhh8ZPs1wBtbXNx8PDAVgYvvFoPUwoZdbQrWKDa4Msll5
         CCot13RThi7y0vGmtgud4/HO7V61NEqUxsfhWbhFcvy2QNwrS/vX1+gvlVAPiN184w8J
         DxxxCLwYQJpNTUg+9jAxJHRqXLouBIe6eObhVLH9QEXR6RmgMTM/YFBF0wBMeHOMA6+e
         54HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gg20si242393pjb.3.2020.11.25.07.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 07:51:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 15:51:41 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-5648Cpc1Ey@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #8 from vtolkm@googlemail.com ---
>Why do you have KCOV enabled?

it is not enabled

# Kernel Testing and Coverage
#
# CONFIG_KUNIT is not set
# CONFIG_NOTIFIER_ERROR_INJECTION is not set
# CONFIG_FAULT_INJECTION is not set
CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
# CONFIG_KCOV is not set
# CONFIG_RUNTIME_TESTING_MENU is not set
# CONFIG_MEMTEST is not set
# end of Kernel Testing and Coverage
# end of Kernel hacking

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-5648Cpc1Ey%40https.bugzilla.kernel.org/.
