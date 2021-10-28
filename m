Return-Path: <kasan-dev+bncBC24VNFHTMIBBQXM5OFQMGQEJ3IHGPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E41943E8E3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 21:13:08 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id mn8-20020a17090b188800b001a2257579b9sf6083070pjb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 12:13:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635448387; cv=pass;
        d=google.com; s=arc-20160816;
        b=hyvnqCMqVZ+RaO5ji9mkhLJ/tXDmXkUgndKOs6nnTwLFJPDqgqwVIkX+YkZBchzUPv
         dmRRLk4+rL8+p+6sD1uv2S2TBZRSLxp7FYjDhXR+1YyUlVVNB0Qm+gxH+TTeWs9/kwpB
         AsVrIlbZUwlgP+mFFL8r1/YfwjbWPrZI0DtLxbSZVmw93enOQZXZd816Y2LncSg2LB6z
         9kHAGyq1Jpy0kiVrKF297sw7qyDvmmLSeHfBf3/WaXDVbf6iODMu5BKEVuOVLNcv3T3B
         3a5GNhaHlMg0KeirG1cAcwlpSCBqiWMirRmCQU1qWqc3/kZTkfQJLe2FePFt6TZHWXy+
         ty8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=8Y/HDPtltaNZ5Q+ixb33n5+pBxJ+N37aBZFip1fURkY=;
        b=jzY35KzN19VXl5EkcyHZfvPr4WuoIn16a8nbZ8VXCeGfLmcdm7obNqeFprLrVPFgDi
         qM6oQczF64nA8U101gWQJTn16Z24PXTF7eg6sgszaxlZD12Qx1yYYTb12JQdbqsTjUix
         +x+MyoAxmVWPUeOVPlsxh3zABxHw04Dt2tmK1liBOxD4zZ0rShjwxPva11Y+g2F3AM7y
         WsR/rivvOx1SbU2llyZTDGR+b/5FNQjg1cH6uXbcGQ0dZGgnh392jTPul1Vv+wwoWumh
         MHYJaAaH7e9S9vP6duNZi3bk0DwbufY7OdJu1U5g6lMX55hWX800ZupVe0uUDwzW9hhz
         YykA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VWrVfJCd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Y/HDPtltaNZ5Q+ixb33n5+pBxJ+N37aBZFip1fURkY=;
        b=gC5iKni1ECGiEIBbfA/5D1uNGf1Jsphsm8ZywUWFwRQFrol8WTiebWAV0dZwOwI9sW
         ep5RbjWqOwJG/c+M1WrE2NtKu43haKvMT06DxAHIghRelbnOIWmSyPXSlRGB8NHmC1Fn
         /6DJ/4jim1/i5i0eV2JMuQOs3MK2Dd0nsyzQiu/evgSGFTmnxjarWJYqmv0Ivc3OBRwd
         Kh+Lc5jOAnNaWeV81IWhINmcFL91B94nT3VXyXH0bxL6qxM58o8U9EsS6WiZGvoy03JU
         Qhh6JjE9VICZ7wjiC8sZk9HwDLsVup2KSNr4yJnkSB99pOXWce950ArrS6fS0U2HC8f/
         P/gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Y/HDPtltaNZ5Q+ixb33n5+pBxJ+N37aBZFip1fURkY=;
        b=sG2bkbRfVc2LSYtkZIKGHM51gPPZf+IMOfMkq7M3RyopqDsE0Ccn4KviqmS6N2HT8S
         ftf/a+9eY2qOCIbtztx+CtH0xDQEy2MOtNnnFiHTdxE9Sin7dY1T+C/3AgY6thLZytlo
         GwyjQAG+iSlsklmMM6svo59QYpqxUWjn8fFFoTmbgcJX7gQsLIEOPFsDLYuNywU91pEW
         3zC+hFs6lEJvXdRrWo/JUobBNaLvO/Cqew6M+KCbBcRmYb6csvmlS5ENyY2BSoiSnBfB
         uyky5maFM8VxfS/3SwKOxvb4HCKn7hCyhj7YV+VJFVMkqzkXtDHg24L2vK+yLUhXWeez
         VFAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SmT7jv7yTfOKsay4CnpShgdcgyiQyqxQ2Fc8htfP/jkEXMf5M
	XgwjnfFsXIClhj/QEymMW/Y=
X-Google-Smtp-Source: ABdhPJyltoSWZBlr9CGNexSJyuCm1w9DXIX5uK36u2vzsoB8Di++sGevFtZjfkurV0ysp7T7SkVv1w==
X-Received: by 2002:a17:902:c102:b0:13f:5507:bdc9 with SMTP id 2-20020a170902c10200b0013f5507bdc9mr5487294pli.8.1635448386909;
        Thu, 28 Oct 2021 12:13:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:982:: with SMTP id u2ls1976704pfg.11.gmail; Thu, 28
 Oct 2021 12:13:06 -0700 (PDT)
X-Received: by 2002:a63:ab02:: with SMTP id p2mr4488612pgf.209.1635448386332;
        Thu, 28 Oct 2021 12:13:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635448386; cv=none;
        d=google.com; s=arc-20160816;
        b=Cz5GHBsJS5YYljGjEU600lf67ffZYS5PZmk187HpNEZ7pya+uKFC/N55XVknNH2kEa
         iUk7kSRqPAdiN8ur4AtL4gPZyJILz8/2JzRnyGwLsthq4yb6nlOOLXUKm9f8ehPkFAW4
         5h5EFQS39PkJAjR/zstCURtaS2OPRSiS+gNmkx7VV1swkLvC4ghs2846T5Z93PlvAX7M
         r/lx+sHiQmgiKeWoJFm+HQ6nkOhS0zuo+etzY3rYBCQp9iRJqEKv8yvwh7WpIUUbzcqB
         XPc2mw4xQvvxZDogzEb0jm+FOAFE99KOcC7shaSJSP7HAdYnnAFEwv56sCPWVBxY5tJu
         EOBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=lPd51K6B/NMpNdGcVlZ4xE9bTz8pKKM41/O0g8UQBV8=;
        b=HLJbtscg5z3ubtBhb7uPbERkb2ExOuopgxW9kmNBuuhUHBUP0MfZsR9mFMnnHFKQfJ
         LTre8ugjPzLdedCq2QyMrpQ/5DCD/sOR8hk5BAuPIdUJ76psjm+EWyilVJ8rWnm3HVV4
         +WrjAr/V3ovyH2eFLDABMmgb7JnOeSxGKGl3CNWtrh2pLqBhL6gyFmoF+LaxaO9LpB/L
         FXTORLFJDF3qELtUTWFGxbUJRZ3ymyL/la/9gmqBlhxz5doSw1+yb3wBpskE4I03qkDK
         oguH0M1+HJAvN7I5J0RFdJQ6OxCZYH2LlapuhHMMI0FPvZa5vCCMa5Omxh8noB0PDrpI
         JDSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VWrVfJCd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o22si556381pjp.2.2021.10.28.12.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Oct 2021 12:13:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id F1734610FD
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 19:13:05 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E7BDD610FD; Thu, 28 Oct 2021 19:13:05 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] New: UBSAN_OBJECT_SIZE=y results in a non-booting
 kernel (32 bit, i686)
Date: Thu, 28 Oct 2021 19:13:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression attachments.created
Message-ID: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VWrVfJCd;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

            Bug ID: 214861
           Summary: UBSAN_OBJECT_SIZE=y results in a non-booting kernel
                    (32 bit, i686)
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.15-rc7
          Hardware: i386
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: erhard_f@mailbox.org
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 299353
  --> https://bugzilla.kernel.org/attachment.cgi?id=299353&action=edit
kernel .config (kernel 5.15-rc7, Shuttle XPC FS51, Pentium 4)

There seems to be a problem with UBSAN_OBJECT_SIZE, at least on my Pentium 4
box.

The machine boots fine with CONFIG_UBSAN_BOUNDS, UBSAN_ARRAY_BOUNDS,
UBSAN_SHIFT, UBSAN_BOOL, UBSAN_ENUM, UBSAN_SANITIZE_ALL enabled but when I
build the kernel with UBSAN_OBJECT_SIZE=y the machine won't boot at all.

The problem seems to be very early at boot as I don't get any output on screen
or via netconsole, only a blinking grey cursor on an otherwise black screen...

Kernel is built with clang 12.0.1 on another machine (Ryzen 5950x) and copied
over to the target machine via nfs.

The attached kernel config is the failing one, the attached dmesg is the same
config without UBSAN_OBJECT_SIZE, just booting fine.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747%40https.bugzilla.kernel.org/.
