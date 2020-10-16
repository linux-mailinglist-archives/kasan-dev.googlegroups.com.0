Return-Path: <kasan-dev+bncBC24VNFHTMIBB27PU76AKGQEYPB3R6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CE57290C61
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:43:41 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id f23sf1510296oot.14
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602877419; cv=pass;
        d=google.com; s=arc-20160816;
        b=RgJwbgJTCQI+YmRghlzYg+KZrDz7+2galqxDrO7zDk9CjEFpYq1IY6KqOmKl8u5IFI
         slSTqtb2TPEstvA09JBN4b1tij6SnL5KpIbsZpUmyhFA21LXgCp+aklly4uOgZzKgpFb
         IaMb721LHziPlz7bENzOGFl90vDcQ5kbgE7eaCUKuwwd5N/BGQIhxpP/aaYA2ScqIVJd
         2CfQSkavWBvK4taU+nzww0smyRzEqs1HXnAFnbeuFocReiJ4+NgiEhGCYPCcS8MUpvd+
         nSCt0J1XuvMh7hHHmr0HewPatBgEvUJsylFHDhHaN41TAlyyG6ACDh01bUDYtqEqxlHN
         QT5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=siSjgezZguGCMWz+0mo6dx/D7bndNNrE5A2xXimJJAQ=;
        b=R5p19nx3wbfuNeQFnFngslvAA0yRf5MD3bYzh2nhH37wMg0a2hSZqIzUGMn1j2euDW
         YkJQgvSVn67BdGoA4/rCbARbZpMM5eD7UMu/Mdt3gNEHJuqqqvKxrrf8c6y4cBI3IdDD
         uElBD383M28a6WpCYI4bTROwOWLxtjYboTCrw7IqGyqaVMi3qpLuxOyhGbK4MPWE88Xw
         LUe/B29TzP0vGSmLZIQ9XVzWtBUwCuw/2Wz/pnPZ5VPnMt0fkwc6pDAyJH+EMFI68dub
         XoKrSuLq0Q3IHKArwnBrAKlHU7S8+QuIoR297JmAvPYnZXFeAaJ1fAn0m6NvEVWpVdoo
         4LvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=siSjgezZguGCMWz+0mo6dx/D7bndNNrE5A2xXimJJAQ=;
        b=izfl6I8TDAyO44z4YEzzkwmpF8Ux3bL60l4h6PtZn/IS9WE0V0weI5JhVcQyXxa8dO
         /RjVMhUm3XFmYvuhHgPnIoRUam5wVMkq4KLb2DxBmZ7XwxGOMJWUunxQOBTaS1aTnqOE
         yAMypfrihB+3ngCyc6PSIU3GSkpPwL6KhVM4SC9FRSu5xm1GOsOnOr3FwEVRcgMkuC3I
         p8MOvyHteG5SVWbSPAMC0Jy2BxJPDfKdei4Sp5AoXqp/nQgqRO3MoIl5cI5NXxS1VOap
         uXifYJsxNA/R9gEntmk1IAxSVZNC1pJg2Jbzdqs8QFO40TNrSitBf6tqYDBDYMAtSN5B
         DGEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=siSjgezZguGCMWz+0mo6dx/D7bndNNrE5A2xXimJJAQ=;
        b=PvexLfTAiwkB5CJ9RagL3ZuRsFhkivDc66QIpKwancTZ9p8pviOO4b80dw/hyTWiu0
         8armdbZWgili8GsMZXderTWVFigpdPdQ6kT6XGsizabawlKpsx+PwhZiIX04qOzVUPV8
         ojIBMFVVxq0Q/h2vB6IUrGW375JF25bCBKWFRcTeKUBBxwbovA8TtdS7l1XNmhBVP3QN
         3/mfIo304C1HpVpT8Oc2dE3TxQidLFD/B1YvMz7ObJsv6ipaDS/U3Z9ZVH+Gbduzu9d6
         iYilMuQDFm+UBw0V+fTfcFaBHat6oFsODar+TW9YYk54vEvT8eIrVzfmqCqk/XwtbmOE
         87Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315d4T+ssTBm+goHp10yYpG0K4Wl356hdYBCAtrnsopBIHzvUKE
	Ujth+kCovyMXi+WM6wd0o8E=
X-Google-Smtp-Source: ABdhPJy2pkUTNN5+o8xugXCObZs11J8s44Puq4WNnn0jnecErX0vnCNTKytDh+StxuHMP0Sbsq34nw==
X-Received: by 2002:a05:6830:1f01:: with SMTP id u1mr3758455otg.271.1602877419747;
        Fri, 16 Oct 2020 12:43:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6949:: with SMTP id p9ls61461oto.6.gmail; Fri, 16 Oct
 2020 12:43:39 -0700 (PDT)
X-Received: by 2002:a9d:12cd:: with SMTP id g71mr3947095otg.323.1602877419409;
        Fri, 16 Oct 2020 12:43:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602877419; cv=none;
        d=google.com; s=arc-20160816;
        b=Jx5SWq+gSv7ttesqLls01K2vufdzG45lcf+QuJj3zSSVR+k90gdOFCbqGq279UdzHF
         O7sz1uAKBxYdqbtXD2MDZKgs1TwIgDKYw40ygFsVIdQXhm+5JXsd8DJviT5Lk3dADs+o
         Lq0Q0B0eALJyiIp3BsHI6RBKb9kwfxKvT0Yh4lVLhh0qclgJBpubsMYVvAARXbkQyDY7
         1pCCbQrMd8AeibKuiNXTb+Nmnf07fIQ4E9DD2KT1tiusjaIDvCSmrbcPvo70g3XcU3DT
         r0fKfIjWMweTYZ80l7nybvU/nvJAZHxqzKiudoDXj+/qfZ4sZSLR347+R9SrEZmD7L6J
         GURQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/cruFkP2naFqyADOBntNP7MkE+HEMbGfkdvNI7xGafQ=;
        b=DzKC6WdxONX6nNoop+uCztLff/45PprmIcAiujuDHA44RRyB3V3C9IZEHAvb/tEVke
         ejkHiNaE3tAZYqCVce1ALiKUVxhAMNhG3zBIyYBLVPDLHf36W9VDquOXDs6XPhB+v3fR
         xij5g5gajldEgczsApafZJU5Y1m8+P45Masdhd8Gw9SDLS6hpBCgcHNxUpggcQP1eC4D
         Tzy0KioWhiMPN3m4265iyvky9K8vwVNiXxE7EWEMOXSr86Qq4GvVAsKrxQbVXDTVK+9W
         DTUkhDlwpqu6PqKbXR32RoAXwtpJgM8IEb39dVMJfyxNuaC1Q8fms/R4l1WkJ0UwF3w0
         xu1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n185si134452oih.3.2020.10.16.12.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:43:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Fri, 16 Oct 2020 19:43:38 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203493-199747-kkPDxC35Gk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

--- Comment #9 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is fixed for generic mode, but not for sw-tags.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-kkPDxC35Gk%40https.bugzilla.kernel.org/.
