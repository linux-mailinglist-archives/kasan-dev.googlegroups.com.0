Return-Path: <kasan-dev+bncBC24VNFHTMIBBEVWWLVAKGQEOYHZITI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 06C9486CCF
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 23:58:44 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id r206sf7546124ybc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 14:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565301523; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUSQCXY3Maydl/8Zi4jJ0QDXOfUZVOLCgIOGTAPlb8jrQL1ag5jgb9jAARrH7eNiWL
         tiGWnrBDXiC5i5tfhgCkjbtyi3QIvUtv3nDQ6k/2x7/bdyAUHrN2a16mrrbHdLX11n9B
         d5OsxOYqhYjtbwBmCOk7E0Qqf+cMg46hGHMoI9zynVMbx0uHTu4zhX2y1N0YAcV81MiL
         tWM0/QF65l6TxQTPiUSN3nZHX7uUKuxsSXyLlWGde+fn8osFCtyS9Ka1zffbuwxhnjy2
         BdU6nnTjmtx1kPul/Ap99a0PHUIhILWPR8oHi+HMrPNBieSoBB5KyPEsvxVeywFfj5/g
         /kSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=VcTH1GDVUw3Z2/ilZ5b3QpD0u0nBfYYv7jocHQc6gCw=;
        b=WhNKZqvWMVbrRlHG3PzIyZ3ujoMKA+ySZiX/iYZjPfdCsyLKPOHmEMkKJ+LwG5Jbo3
         ppayGdJsiwHUoQyJGm2fJh/5cDD6xgT6zMzY3uXOwW3oA9f5B/Qa5+PwJKHuzP9XLAAv
         Uwc71DpVlbtkJ8P4tkTYyf8hmZZmYkpbXDAh2XlOmdtwydkTEprPXFLJ8NG23hynLk4/
         tZuaviERByFM7+wE0FrJa3s7GOdRYIpKaZZYVfQ0SxvFM88aT0QoVelPoplmAEJGRs4P
         XHpmpj+TbLjuktLxcnfOczUai+SiUyYStKoXEPcnvyk6MVZxqOSOhPSpFR/3w6kgcwmx
         Uukw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VcTH1GDVUw3Z2/ilZ5b3QpD0u0nBfYYv7jocHQc6gCw=;
        b=KISW6KHBoYrSde0ZgHuO1B1H5qPKonT/D9YeH60gsbeGPPHR2Uxe2VjEZfLaw6creB
         scaKpFHOlSbnLKTJJLzZxlKU/BpbhAoTBXrMDxNKzwOQhzMfSwDtF8ur0aa3M7kB5V1t
         ErwQ01d7fIcnEd42QIjqCmrT/7TMDHoiMcwNMfzP2T0W8sa2DPMGs6pnzuPXbqDW7ur2
         MXifoYMWu2aTeXq9B6qd+7E5zoiU6qG9PY72LiJI2Zl37c1J1epktqtUVzB/8sUrX87T
         dLkbl44jX7/srr7Si1hHn3QRWY0i5xdEoEQowfhSa7CiPjvc8PJm9gUGgNJKoBXlJVmd
         thtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VcTH1GDVUw3Z2/ilZ5b3QpD0u0nBfYYv7jocHQc6gCw=;
        b=kL7U9NzqC6scnh/B0sHLULEF1MLJAkBoLHmpAl+Xq2gZCr+aHSp96fYPWba6Z74q6U
         cBOCE4GU8K+O8dN3x7N7MMqvu42BfAY/i77xp7uTVAVzfRsDkW9g+EfvdPvW9DlX03dg
         HE9XI26qQUUCZNirhNNkjXO/GFt2DkJiEWnoLxZer9pz9aeqWJWpBqfx5JWlwRXUQrFI
         BpYBtHXzJ8GijX76TIm1VqDGorn4VgSxG8WvdMRbmPE1EXjUfV2xQUsUGwOe/vfyEJh7
         ZXRE4pTIpmQ+qZ4PtmKVMhXGVPVBMHfnVJK1yxPE5XIjd0s0myZDj7Jr8gy9+eBDx0oj
         R4Iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUrGNcKXjcyS4IKF1J3ah7dJclA1qyT+fMPVqRBCpbFsrr7KPvy
	pslp9L1EJeyIVlJJPlvrEJ0=
X-Google-Smtp-Source: APXvYqwYOcRCXpcjw7RTrGqxbIyUC5S/dPKI87b+x1crLueon93ufP4Vy1e2auZRJbiakX88rrxAtA==
X-Received: by 2002:a25:b784:: with SMTP id n4mr3325275ybh.76.1565301523058;
        Thu, 08 Aug 2019 14:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:42c7:: with SMTP id p190ls309514yba.7.gmail; Thu, 08 Aug
 2019 14:58:42 -0700 (PDT)
X-Received: by 2002:a25:591:: with SMTP id 139mr12322571ybf.195.1565301522841;
        Thu, 08 Aug 2019 14:58:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565301522; cv=none;
        d=google.com; s=arc-20160816;
        b=xqiBsk+uCPJWpL/9pD0hIoJNUy4uLx44+MrkG8PTPMLmrv+PypawbbYJqv7UQrhDNc
         GmxMngrhT6JWWlzGcfXnKRO9P0t1gVZ2w/k3FEfmvWwwFwWvSyB5Rl2dXNqyeBg7agaT
         KSpR1YgQCf1yKsibOJeD4YXS4tSOQojXVzbH/ZivIOuTvDAujm/vMUsIV9rkmLxYQgoa
         j4F+2LtP8JaIHe9PW86aZ1fWUWdVOYLo3JbA6CMrd3MDOqcL1x4psa1nok7KjgZH5jUD
         abHyiu9UaYSU5G8r14CvHg55Q6qzLINWReWGtj0t7i7wCN7dVoev2MVuJ75bkAi09ocp
         E/3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=gbfebSXHFypD0khDwgtB8xIZjfZDYdNQ3o4gcNb+oLI=;
        b=pe0LCbZyE/p/PEWKIGS2oX1QfIDNh7FqJNu29q1DQRt3mNDMotK7HP8puEiAlt/TMg
         qgeXigxxSi/2z64NsOr2kUnGXD4lWPF8/KdSyeY+Ca5UwGEH5VKrHeIUoW9KoqdhfkzV
         GKWKlj+w0hFHJb/BY+Bj3/Ozgb36qxXBblWi+IPweqwoDWRtvQAJKnQ0Uvs0sf2/fZ32
         R+eOB45L9gel4txNFqixxWEEbDJBwXc6gDbVP21GoEU69sKtB2g5q2X3F3etjubpoNWz
         PrJ24zUTlXHC2KqHz9FHl7JsaiKwzzeYxHF07NxbBRuw8TU/ewp/40FGWFPpWqmdr1Al
         lrrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id p188si4429347ywd.1.2019.08.08.14.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 14:58:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id DA26228BD0
	for <kasan-dev@googlegroups.com>; Thu,  8 Aug 2019 21:58:41 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id CCB4D28BD5; Thu,  8 Aug 2019 21:58:41 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Thu, 08 Aug 2019 21:58:41 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.isobsolete attachments.created
Message-ID: <bug-204479-199747-8FbUOTT20K@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
 Attachment #284175|0                           |1
        is obsolete|                            |

--- Comment #7 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284273
  --> https://bugzilla.kernel.org/attachment.cgi?id=284273&action=edit
dmesg (kernel 5.3-rc3 + patch, PowerMac G4 DP)

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-8FbUOTT20K%40https.bugzilla.kernel.org/.
