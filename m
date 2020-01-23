Return-Path: <kasan-dev+bncBC24VNFHTMIBBTFXUXYQKGQEGXWEA4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD061463A1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 09:39:41 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id e28sf234938vsb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 00:39:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579768780; cv=pass;
        d=google.com; s=arc-20160816;
        b=dgZswBmDGlIels5gCvISL9LC00/fNNsvuQMrPOddMKI+5HRIcbTqPJpTJjxDQvICa2
         RGxc8v1WQaVwFr+UkD+BvPdEgxJL6CCa56AhdK80A+eF1C4lD3kFsyWJslbPAX9I5AFw
         2cDUUthIg5gpio5/EjH1cXTw22wkBYNp//wRe5riev3iNswwUWinoVP3+lxHEh/6aFO1
         TPSDT4O5s2ZppZp8trVwTmFMlW/ya0+h+2qDsRllmF2bYSIWLb1s18qG77u4ZeX7xOE1
         QJHL2o0d5wZKCDZySOxftUoFV6fp1zaP5QqDW/nRjWmZMsR0IWilbdX6a7i4sMpDvq3a
         s+iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zmH1KG+7UAiG2jqmSDkIzUnIsSNSAkGIJOQL7FuGp7c=;
        b=txX+VxKOpNpyuWD50PszjeL36gXtmEcsvReBlP5oQVGlmkBkTDoZaqHtLRV0WYaR9m
         r6AsjLPnG8IwpEMSLyM0rcZbM2wBdHTDxxz10V9H+6B+N/fyt8e19QTqB9UulBdZugRW
         vURHKnj+tGx+fMfWE3RvunLD3ei9ukJQa6u+CHPftlB3CnGlLLPsufDlWPiY2VYw5MCf
         IDXgrSyFOY2b7G4b8VyPq5u+ZFkNqmOnQXRaK/Za7FT/jz9w96o6BBc/h5/raqY/S8OD
         oEpaeCaaRJ9YvjwDMQLIVQ5jO2MZS5ilqnmHmldSut9MD8hHnhx5HzlPqVqzFNaWe5z9
         m8+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zmH1KG+7UAiG2jqmSDkIzUnIsSNSAkGIJOQL7FuGp7c=;
        b=qVyueqApwsSsg6rW6PPNZ86lttWHJgWUKeny5wB/ljZPYghH5AL+I2Rb8mLu5n1bt7
         7Nlv849NsELxtwWIPioTo5wm9v/9nfynPabPDcc8/+g4jsLKiBUF4+kGkEC3p6WVAYJU
         pUtKAcqu5iJY0dTBzi/kopEIE1D3+6YlMaw9UdTLnx+kY/a1t9jD46euBh1iYyfaEM8F
         Hd3FXjSrbCoBbuypteXLHj8O2vcyWyJaxofK5XP9DmKXBw1FlkuQELJ/UI9VlGovwfA9
         xc12y0cgqVYGmvsMx9yd/gqy2BNI5J5GMQiZ3n11EjVn3nh/C6o/L+6pKkAx0fsziR+Z
         u5nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zmH1KG+7UAiG2jqmSDkIzUnIsSNSAkGIJOQL7FuGp7c=;
        b=I67haHqHlmFa6cg61H0G5Da3yiFx5QCu/dGxWTDlWvOzByjmwXBElHQjlks2MuLIRD
         qYSAIA90p3bPbdh5zzHm39LhqBrscIDG1C5+xO6e+tff+7uofNINNnZFMFCLSRZXezTI
         sRkblQoJsYAnVBARz4ULqgAWXqXEyD+UTSSyfxV/RyPCdPbrOJX4q60P+3d1+HmCeB+s
         /zBgIiysVEKjw2nnnLs/toNCq7DpTPA4PxZWrdLTt8yZ0fa6wc2w8TxVgv/gJFJ7pUXK
         GemJtFM7xEfNuckZ6kSGmAp0FCW1Nq7XdD2eOJ8XCM2udQ/iDH0fQiycIyQCEUi/kKOL
         CFqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSnB0nQC/v+qeIQayBd49N2IVr4PJvVQoYTucdrpJPuTLOnqkd
	7iOJ7i7/TpFNlR/uzN7sKlc=
X-Google-Smtp-Source: APXvYqxwLKt0BDMcypmWl9Vxv5DB8U/5Wri1gqVPRhyU3lJ3mkEHLPUcfYqYAf/Oj2JUvyqmyfAeeg==
X-Received: by 2002:ab0:6e6:: with SMTP id g93mr9370828uag.105.1579768780567;
        Thu, 23 Jan 2020 00:39:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b41:: with SMTP id 62ls3888040vsl.9.gmail; Thu, 23 Jan
 2020 00:39:40 -0800 (PST)
X-Received: by 2002:a05:6102:d2:: with SMTP id u18mr5555030vsp.192.1579768780002;
        Thu, 23 Jan 2020 00:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579768780; cv=none;
        d=google.com; s=arc-20160816;
        b=qz6kTKJe+FOvbAZvHefEIF7khWPTEh4bjWyeh8rR9OOV11tLUP/kfNS3Gxz5JmwjgK
         v7m6MgQNVK9YjBENHI2xxrDj9Y0PXW8hYDpS9Gh8+fEGfAstpUvXyWTbmopT13j4WCuF
         15g4kOKIMh57HShTqrQDevHhvHCr08ew45x974upigifHWmzfdrYB1VZaF7Eskr72ZDy
         6WvxsVPIY7J7ieHMrO5nbfeb6e3hH9p7rM+UP3LSy8tyuAolDtyF4yzlgzzrWAUkPKRA
         DfpsY5vh1sTwJHrEe/AfBZh3YNb0k26Pmipp+++/aNXM01Yr3KEFWdmwn/q7sdXsO00o
         9Xdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=qFGAHg7VmNk8NoPzjvklcn9+kStYCHHUj9jM2uk6EMY=;
        b=UzhMFkAtTgM/cd2YPxxk2HyKSLUCjz1sWAjoeXuN9cJs1FANG0rY7v1+oIE8VSm/re
         m0V6fvjNwt1jMcUQilvHt8m1AlTMLastt9OzXzynv+Hsjg067CSsAhoTAHEzhqioFyup
         2VkjdbLVScehqpmQPwpEFwEad+Iwx3Loh6mZPAcFC/C34fxrlswWlpAMH86x3FEn1f3N
         0i6jF5ozaimEe15pKbwurqX76POXiILAvmWvz2cVOKtUJyjXj3kPokW1lqPmoPcGWBo4
         V/V9cbWziv5flblsAKl0v9oI8E/dP+4l/hUMr5qVCnLk6PRqfgWckNyLaXkBVQ2HD8iy
         mqkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x127si69874vkc.0.2020.01.23.00.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jan 2020 00:39:39 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206285] New: KASAN: instrument pv_queued_spin_unlock
Date: Thu, 23 Jan 2020 08:39:38 +0000
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
Message-ID: <bug-206285-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206285

            Bug ID: 206285
           Summary: KASAN: instrument pv_queued_spin_unlock
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

pv_queued_spin_unlock contains a chunk of asm that touches memory and we don't
instrument:
https://elixir.bootlin.com/linux/v5.5-rc7/source/arch/x86/include/asm/qspinlock_paravirt.h#L37

This code seems to be used in most virt environments (including syzbot testing)
and was reported to be involved in a use-after-free bug that KASAN did not
detect.
We should instrument it for KASAN and maybe other sanitizers.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206285-199747%40https.bugzilla.kernel.org/.
