Return-Path: <kasan-dev+bncBC24VNFHTMIBBNPVQ6BQMGQELJTGOJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F12B34D472
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 18:05:10 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id x129sf5498870oia.10
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 09:05:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617033909; cv=pass;
        d=google.com; s=arc-20160816;
        b=swM0JzfxN5dgY9HE+N5dEG2FampiWvIW6C2EgFDYcBzi7OERVEDiHK1hC+/UnC8MA+
         bYOhu/zw/DwxYtC+HwkDLIF8Birw/QvblmppyaaOBFzBu3dZTNQmuk8MSGbPp0S+jzjR
         HY1ecTN6lWg8BKRyHexQLhqc/3tufvqiDNUalovuKkn9yGp9qXIG+pKuLlpDsSdEAqgj
         HJ3ynCNL7l98pIuvmdcW/tvhSY1pt6FE6rLQ7ypnId6DFj/6GBBlzYi52m6AHH8LSBQa
         RmOxNZFBmn/UwK8CxFcG5lXnjZF76ZPFkIOdlL22xOOSNGsY0QkHxZG5FqNC5BMai60H
         TWMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=M0QAIKN6eU1tMsZEHnlVHvK9i5+TmbFu1VTuJLRq/n4=;
        b=ulM+081sI6SCdm/CiX8TeNpj4+DP81k0W5Ob2RAo0Dhb7465vyeQ/iJ4ujKdWgLDeR
         ZNhK28rpFPLJroVnwNtNIqxV4ClzFtsj+QICVsCNh8ffubgbt5PbA3mtNpa+VxW+XK0E
         7g+bsQyAXTCS8MEk+axM8xTQEC5vHav7xwvfbtRK77D5hgIBX8zhfBER+Y4TaWyCd8ed
         CS8EAe+8SaE/sQigdldueQbZggcCDoZHWZiipo12d0BW/vffpeWxSP7FCF+QzCgOfJlc
         3MqFc5xdZoykL9HXedKWqRrHY/LwMZxY5fyw7HXMQiUwSCF0OSMXBgUkTkaBadr0lqjq
         SLyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NUlL+7mi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0QAIKN6eU1tMsZEHnlVHvK9i5+TmbFu1VTuJLRq/n4=;
        b=d4R+BUqoJj48BIqFxCnC94Pf7jAqn9ORryycnZMi45sd6O2sctvoPM+/RUjxqeAVy5
         NtBHSfP6VH1pVAZtKaPscrg340yPNQTeTGhLK7cf4r8FsPQn4/MxlGCjMlNykjmSZcTe
         841R/EIITg5kR/1Hb5F4Yi7bs9STg7ooYliFeXrawSoVJ8oWmjnBvUJhwYTAQQsVorSx
         TXu/FSMPhciRcgS73XEIJcPVsA++KAIYjxeLecja5G5a7a1nNJjs7h6Q43P6E7xsT89E
         gZTDsU5EJqc2RGJjuhzEh2fUascL34Fz+3BR9TKDhzjws5ilysTHf9AvKcTiWAFuzPsC
         Iq2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0QAIKN6eU1tMsZEHnlVHvK9i5+TmbFu1VTuJLRq/n4=;
        b=RPP1bzMHrYqKy7nOtws4EHDUBXQrqi17MYtabTCVJdCVKceRXokL0DSmqJx0EoweiL
         ogLJHApzxq1pJcsZDCYDuWfkEGWP+/9pKRzQRI9IOBwfiePNDVR/WwqvaLlA9IYrPPcs
         acsqFspMxryjX4I1oSW7N3ammX//5360u8Gzc01ECjJiByj//V7hvSnMv12WOhNMn+G7
         UL14a8k4r/3SAeuQqIvWBYu4bDdGbPPQUVFAUJqy9T2Mn7WGqPGy6HrvrXbAHbMX7v9b
         AXuOaJCcobVtUcsXEaPYknjuR6SVi1W2ZV63cg/9UPmb+xPyRt7aYsybilHPRQDvxi2f
         e9dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310nhuVH0qHVv4IJidO9OcFsSRV/Jtu9CvAaiDMGlVy4x27FR6V
	ljvdW0yPem4sTLYtqkEhfbA=
X-Google-Smtp-Source: ABdhPJx4JcseNrVmbBEQnHB8piLPG1Ae8HXoi6tAromxBQeF/4QrIqY8ceI8amJU8CHy6SaXJkL7Ng==
X-Received: by 2002:a9d:ec4:: with SMTP id 62mr23530418otj.277.1617033909413;
        Mon, 29 Mar 2021 09:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c650:: with SMTP id w77ls3887901oif.1.gmail; Mon, 29 Mar
 2021 09:05:09 -0700 (PDT)
X-Received: by 2002:aca:d70a:: with SMTP id o10mr19031267oig.143.1617033909109;
        Mon, 29 Mar 2021 09:05:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617033909; cv=none;
        d=google.com; s=arc-20160816;
        b=QfRDAwHRMXfcGjxkI1AACDVQGJd2/DH9A9E92z0Tcp2L+zKvfFrlKpBOq9z0GgQmZ5
         CjAAxlfsJ9PdTYft2of3h0oQzhO/SzaO6YFpCuV5cRtBVqJRAQURUsG3wAs7BhJNHQ6Y
         4dm2GAPcBI1chHDU0H9sL/aJjVlzLTiUUtPYDF7wGiZ0F/fJUnfnx0I0ey4+EKd0d3Hz
         q2DgMFVwO2cYz3h654AOBlj3mI+nF9qk99Cuk+FqdJDz/v7Ikts/M2tDw7bGzF1tjZpU
         m1Vpu0T6EiIidLOAhvsc8M+pNzEMD0Kxe0n9aC0I5Jgihl7e8WqIy+rIQJEtbXwM+Jhq
         KxIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=kq0fr82+XxELu4qhAS57woyy7RN1EeDeUMexhhSpY/Q=;
        b=QFy23yQKRWY8+YK9zi1nCIXSFReuvrcHWUKBsn58LDZZgQij1xyoea2WAw7r4ZXADG
         7FBs2ThTV0utjUCm/tl6HDY/bpUcH/CjjRQlnYWlzZ++1QIPo/5UhmidqjGzmKkiFwB2
         h+9QYIwYokuMFYQYNTdAfl5Ex/OMmUE2+AWQfSvyvOVdQVCpE5swQE21SH6RA+v/DdGh
         /qcdWt4ftKnltWXcD3O7Qcaf5b4OE76P56ph89P7mdR9ooUjCGsd+NvH/6Su9BC7WanS
         evVW9aR0soyQ7FGK4ND9E9u3pWHmyHKGnWjzcI1mbIQSEaezDFmIoKAvl7LI2j0uDaGS
         eR2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NUlL+7mi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k10si947734otj.2.2021.03.29.09.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 09:05:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3BA0A6188B
	for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 16:05:08 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 31E3062AB1; Mon, 29 Mar 2021 16:05:08 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212479] New: KASAN (tags): tests failing with KFENCE enabled
Date: Mon, 29 Mar 2021 16:05:07 +0000
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
Message-ID: <bug-212479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NUlL+7mi;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212479

            Bug ID: 212479
           Summary: KASAN (tags): tests failing with KFENCE enabled
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

Some of KASAN tests might fail if the allocation goes through KFENCE instead of
going through allocation paths that are covered by KASAN. The suggested fix
would be to disable KASAN tests when KFENCE is enabled.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212479-199747%40https.bugzilla.kernel.org/.
