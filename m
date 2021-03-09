Return-Path: <kasan-dev+bncBC24VNFHTMIBB5GAT2BAMGQETULSOUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BCA46332BC4
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:21:09 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id d26sf10524835qve.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:21:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615306869; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZhAUsrtU3UZ+YMKGyvifQ7yppe6RKLa/ntAPpj+y3Lvsh55tXshq6RPFK605O8MlRr
         Gch0slDHWY3pgC3+4O+ALzdg9I++5EC2XFkFduskev+Xd6kVoRdjFjG7jeXgrDwgMCFH
         G+Sn6dvdMl3ylDSZVNGw8ye1bQXJXzwXlHEQK9ZJLb2eXpb57PqZromYMu4tY7r2Y3HA
         mL9GUgMqzlY0XkAAbXK9Ngdf7DNz8mP4AMkOyyoGUxA63zm8YbsgZGp5whHlG3vxMbm4
         /C0StA+yNlMMcFL2MmKZOAvnXw9MaWSUPb34aJYiNMnefxLYq+zVV56I1xjKUoGyJTdG
         4UmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=xgY8tmW+2gplEHhxrAwqM5wMscIFhr7MBQS8tcj5IUg=;
        b=Fn9hRwKkIsi+KO9C60C4HVLnM9/IDPQlIIuh7psEdpXDDjxw7Z68mC/jChFwTFuVdD
         Cok96pd0YHZFdHq6PbjekZV9l0KSP3+KaGpwRkod5QnDGehMISJKS0XEsrwBt0QjqCVr
         Amo8NUUvcC7MaPYBysTT7M6X9gME1IfXf32eAWt9lTMPEDn+oT5cpUB/HxJ9S0hldMR2
         7wpBLaEKVZr5I5hlR6CRYTHhYELcggdCV6AfQ98Nz1uo4EU3QRw0poEuYLOytlFhxYQA
         yNzlfvZpUr0D5LT7LCx70UQGEkfBGzueXCJrRHugJP30vqXPAdsCBTvDG+dn4MCt0c2W
         cJWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dYvkunva;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xgY8tmW+2gplEHhxrAwqM5wMscIFhr7MBQS8tcj5IUg=;
        b=NvB/Om21GN7EvHK8+8yIfbNJKrioliu2VawtVymHuTckX1ib+o7JIksgE3GoEXKWmv
         Op9oNNLl+sKFdlwivsgZBbIFnw/t5YzTFB7MwgQv1tGFg7yi6GJJ+DAYQeHw9tBdjJEb
         H1jLrFRs6/re82+LbrNTfYJ7KqsZP4jadIIAzidNUeWGwLaUy0At85vQf/JjDnjl3obR
         T2jZw55xKI9pxhmy3EKD1AD4/KdyKPJKVLaPdCrWsUzTKbA1F6lmkUOS6R7Ow9jxrv/a
         cHC1Ed/k+2gCWt2h/hxik/eXqqCHXxkjPnOAE1QtJiVqADxUE/Wv/J/E+10alnoqi/ES
         1sVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xgY8tmW+2gplEHhxrAwqM5wMscIFhr7MBQS8tcj5IUg=;
        b=QbWqm/DP7CRx/t8FpOlqu0X3Dk9R9uPkIAEw6c2IBt/sagETbhB5xfIcCDOdh02EIN
         7ubdU80i1p78tFhnIRQdjCHJ7B1OnoHZrihKdOM2q2HMa5pFmqc6qlzutXBqvXMwd6dy
         69yQfyaSWBz5ZpSMkpqreiDjy82q5hTO7EGJzLU2V1P1xLM3qqmRnFDQzV002cOx6e6G
         CeFYHVEUD89/gLziyPu+GfzvM/WRb7i+rRvD2jNIEyAVOAsfb796jAG8/4uHo31G8V7u
         zOXe9IDdI9aRkBPIOe11WHDzgJE8xQt1EKHY3mx0efx/0jO4lrffIhfIToAxW6Zxd0F9
         2ILQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533pUV9rauK7N3lLFN6usCG65upB2rptH+FuRCSaYk08Et8Tli4W
	RN0mpaeeWob7iITPpsPTMcM=
X-Google-Smtp-Source: ABdhPJyWb7E8C0cQ2e/nW+4x4Y1XnRDIUN6Neq4dqYLvlghwNaciv+k+bD9W3aOCQqjoPW6V4exD9A==
X-Received: by 2002:a37:6889:: with SMTP id d131mr25877165qkc.264.1615306868885;
        Tue, 09 Mar 2021 08:21:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:a98:: with SMTP id v24ls10859574qkg.6.gmail; Tue,
 09 Mar 2021 08:21:08 -0800 (PST)
X-Received: by 2002:a05:620a:15d4:: with SMTP id o20mr26227646qkm.81.1615306868487;
        Tue, 09 Mar 2021 08:21:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615306868; cv=none;
        d=google.com; s=arc-20160816;
        b=VOGYmrMyHA6i3LFKDD6MgkDBKL7MU9IWXqCKwuy7k4h7TGql7bvZSrcVTEzsfxOuCs
         0Ea03E9+soVla9bBZ2LcsGIHTuysn1PUqNjaVVnvoww13vCjZv+reAyORY5vINscZx5d
         ct87m4mSIBGG8BoqtFThK+yTQu2yXmGnIlYI8Q6C2hrwRD2Qq5Q8IiPaMP9Kih2CcBSk
         xT/uc66BWRYNBRFyRzHFFra0IVPTl9Mfw7DOMTFa+P8eJgOouEz0sThdLjUXi9RbbwwP
         uIa5yi2u1mOLvN9ltp7pxdmNV07tDKxbwW2MR5UTrTQvdPHHQotPB2FUkT16ydRygdQV
         N6hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=igSFNXr35t+PANEFBn+uHTK4HWmop56vCRS5c3A+sr8=;
        b=DAU3RHG57UmbBDPaQJKZlEskqeMsb+ySsHWpVf4VzF1iGi3Rjg6zqIIa4IxGyJ6sGW
         pIRn2ud6a1QqJdLf2kWkaYLA9ntczazsqr1G6CFxJAO83iBOXbRLjo7qVylPwCKHMv3E
         yzht5VTvInG2tBT2Hoguf1BsBC5jKF5KQtk2FmbqAiqg/Wi/GOiayKFtWg+lY0u2+9e0
         I6AFDRZGvoPVtbVcGW8prSuZXz+72ndyDNqP+07Jugy04poGAwmzCkbJUrst6LgxFDlA
         zmYQFNPFIA6ourpRy6ADKl3fbZzVjM/AREa2UwbFkva4bUHFIYqwxpdN0nIyIshMOliz
         9JGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dYvkunva;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h28si1065124qkl.1.2021.03.09.08.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:21:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 5D4DB65239
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:21:07 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 59C3865349; Tue,  9 Mar 2021 16:21:07 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212201] New: KASAN: move tests to mm/kasan/
Date: Tue, 09 Mar 2021 16:21:07 +0000
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
Message-ID: <bug-212201-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dYvkunva;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212201

            Bug ID: 212201
           Summary: KASAN: move tests to mm/kasan/
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

Currently, KASAN tests are in lib/test_kasan*.c. It makes sense to keep them
together with the code that's being tested like KFENCE/KCSAN do and thus move
them to mm/kasan/.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212201-199747%40https.bugzilla.kernel.org/.
