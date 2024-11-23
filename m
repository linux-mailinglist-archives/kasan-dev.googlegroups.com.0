Return-Path: <kasan-dev+bncBAABBWP2RC5AMGQEQBEGN2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 402349D6B79
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:38:51 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-460b07774a7sf50091881cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:38:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394330; cv=pass;
        d=google.com; s=arc-20240605;
        b=MClIH/L/+8ARr9p7dJvaS13kKwlTYmslLCSCIFoAEgxmmp8lEAMO3SXAEoPui8pK6G
         j0HDcWycupSiddLT8CdvKdrqrT+PiH3iPPWl2hZlZ/XiP9ziUl9I+4OTwv5OdPDTjFoQ
         7xxGQtYsYn+VNg21jt4+Pgz/tR5K8L5t9EmK9iSO9sgh9DdmvYhUu3+/LLJYvq4Voj62
         wcJLiYpXHW5ilNGB3QFZ7p7Y50S7x2riGLK16CHwnNiltSAIdq3sKdRiOh32LKOrmj10
         nsWBWQllyMpr28StFZ7f9QXMukVSC5LDD44GlW6jY2VuKgh5Q4djzDuKttRy1Qt5VpK3
         ud5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=0AiBhiX1MghxW/8UMcPrO+VsonZCsj8B6jaMCjfR+DM=;
        fh=JMElotQjPshRZ/WjLwIEF3iXT0SoUEwB2TsBGmKVtQU=;
        b=Td7eXqomPHuqUUXkC7FP3PFz8lMXCrdq1vh8bv2nkUlHdKfksG/L5xZGjtmaeeJDE4
         zWJuotBXtb/BLHhyUNgZExUBE63J0BjLiWEk+vNh7iD/os6vo5sEGh/hGiBFm6+FWuuV
         PC8RAYjaz2JfQxtx1UuGuUgThuARxzktVhZ3Mm3y1sz2LmX5huVxDjClxJMDAlA0wcX4
         DJASg3fCrSar3yWNYHG/7gPPwzWENaLqFNZtBM5B8wey0ZjhzCCGMcjkbTe0lT6TfRLl
         TiMux0WyAkn+4MdNspXm/fiNmIQA3twCWZ+wdFjMcJCIE5lozV4Nr0SXRSseh6qXdxFR
         6OUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lyD+Ktn5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394330; x=1732999130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0AiBhiX1MghxW/8UMcPrO+VsonZCsj8B6jaMCjfR+DM=;
        b=FfAl4OtImWlZ04ArN3Gx5b71fnmsdyvNBOBeKjO4JtGep4/Hb6xvLUF5FjlvK4PugX
         Da7bW091QBqHRnJj8z3qEJajcboUXn6hvCD/rtg0V+vqUazhSZ+9vCRo4UXdaVFn1IEL
         N7AGeySe4LWHD2ftSkKV+IdInZoR2cN7vY1HjTDKCBFUIHv5j86ZTZfU4E2fMhicgYlY
         hfxuzwbZbpSR3gDMhA8Ol6uyfsHmNYMjlD/VVCv9yZPlm5AKCp0S171KGlHP0+FnMJKD
         oDfL9fUztU3HF1TbpZjnx6s0lkrITzo+aFyme4uff0zszH6KeF5Tml5vRImUvNFE0eev
         H27A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394330; x=1732999130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0AiBhiX1MghxW/8UMcPrO+VsonZCsj8B6jaMCjfR+DM=;
        b=aFf18CeuVP/1Rqvq6L6nSKj3eU22OXG3LUnmWIzoNiZpF3HlSvsoolBHK3KNcFf/1E
         Mnuq0b1x5FrBtRRm88LDrpwjg7ero1JMOsILIVogfvl0zV0dhdEaWHtX4DW+HMzsnBpI
         X38R4MPlIPF7waGs/8MqVUTqPqslJG0bfcydYk84l5mw5K5PKkosr8tBYISbY80mYGLo
         guucyWnyV/7LxPC9wEOpl4pAhElse1ko0Hwu9du9lBTSI1f99wTJzmE2/kOY+Z72ukhP
         jDpkb/U9q4vqK8vy2YCc+6a2nufses4ZZNPcDxC5Us6hCib4kjIgwxSKjscJINEVBmVs
         7Zcg==
X-Forwarded-Encrypted: i=2; AJvYcCUraJVFAofpCO7HEQNu3rb/Wxx8BmHrGPfudX0FNDL3U8tPQ0ypq+Sc7MYDIPJ/2UFnPSsuNg==@lfdr.de
X-Gm-Message-State: AOJu0YzHtMNCSeiHu1k1geJiiht2a+q4r1E8yLm/cNZca/hYTbfna3Om
	YWFgB75LISV8LBtaLe3JgyiMMapy8Mne0+d/V3+SA+ZpO3kfVAYH
X-Google-Smtp-Source: AGHT+IGElZOj0XK06L65ZkUNdnxqNBMNvTJxrG8agPfog3opbNW2uGNMxY99d7P/da/96m4IO3jM7w==
X-Received: by 2002:a05:622a:1a05:b0:464:fa08:a6e8 with SMTP id d75a77b69052e-4653d61dd23mr110106751cf.38.1732394329875;
        Sat, 23 Nov 2024 12:38:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:57c5:0:b0:463:f0e:44c6 with SMTP id d75a77b69052e-4652f4ea922ls40258281cf.0.-pod-prod-01-us;
 Sat, 23 Nov 2024 12:38:49 -0800 (PST)
X-Received: by 2002:ac8:5fcd:0:b0:461:1be:9b55 with SMTP id d75a77b69052e-4653d61daf9mr127363101cf.40.1732394329102;
        Sat, 23 Nov 2024 12:38:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394329; cv=none;
        d=google.com; s=arc-20240605;
        b=YgcL9GLPPdMLB1rYILY1YVVbB5Ai8atIrQwwwLrFp8tDWR0oXU9OEjWaaUAx1sGYYS
         RbyBCy7yjJ08JlrOqd363KX8WK2oH41+8zY2HucvrUQoTL5XGUHnzFJpZtILAkj+1MH9
         7QFYThw+ytUJ0QzX+tt8BcJAwqOO/vN+MU3iIWYVP34vt7cYPsC1xhMiUArFoLLDdOli
         PsKCdWOqn8joCycL122xTCUkKLVT1lJd+UbD2ue4EU3rFaHJNvA23gM8rpqq84K/NlQr
         0XaqaMj7SLKNQOy+9kbC3phXCIwd6eWGEvSDm+/ejwus3v13eo/VkmTFDWSx2V1PEfLL
         xlpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=rTD00CQuEE9TZzV/Erx6O3HYsEJPy0wgRlq9BsaJsL8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=cbN9nh1B7VdN/VdBPDXbAIZkUe3cC37db52u4tjTRLgETZ8Dx8F6V+QJd9YEMJmaZb
         HB/E69N34tHX3C3XIMaFcuGfif1PcAL174XQKp678NhhQi4w6lcznXTd+2+V0PZNHdfz
         0uA4WvzcECFGw7pb0+ZMqWj5SBFX31NHlodrVbMQxTLZ7CzWjJDHSiIr7ywIVuWw9kck
         HZ+xeDHfqM4L0Y62NzkXAnzviK4H5LsdhGuALy4dPcMl8xZV4klbUx3zGU1u10zs3vwd
         jkhWGqa2SL7e1o1U92vK82BTsfWhiIQ2VPNi1Dj9XSjlq2oFin4P3zeyqBV3Ed3w3g6u
         XcRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lyD+Ktn5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4653c4860b9si2130811cf.3.2024.11.23.12.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:38:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8C27EA4070B
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:36:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 012DAC4CECD
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:38:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E8E5CC53BC7; Sat, 23 Nov 2024 20:38:47 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219523] New: KASAN (hw-tags): fix copy_to_kernel_nofault_oob
 test
Date: Sat, 23 Nov 2024 20:38:47 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-219523-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lyD+Ktn5;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=219523

            Bug ID: 219523
           Summary: KASAN (hw-tags): fix copy_to_kernel_nofault_oob test
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

The copy_to_kernel_nofault_oob test added in [1] fails with
CONFIG_KASAN_HW_TAGS. This needs to be investigated and fixed.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e4137f08816bbf91fe76d1b60fa16862a4827ac1

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219523-199747%40https.bugzilla.kernel.org/.
