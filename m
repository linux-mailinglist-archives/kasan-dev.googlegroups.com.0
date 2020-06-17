Return-Path: <kasan-dev+bncBC24VNFHTMIBBS44VD3QKGQEXHLWCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id EB0561FCD81
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 14:36:28 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id t69sf1389155ilk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 05:36:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592397387; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKDdXjoCMzDdtmnRuN5HWNNqJb9PdsNCaE5Ja+iYqo/YzOnSkVslJaJD47B1t4g4YD
         Xfgo0Fa5nMkuRMkRcOVzNHoy9fsfBGi5iCgHQmasMk/ZWErotKxjWHk/G8kzBsBRu3RK
         1rYBwtgS7n5aTn5Bs7l+Fjh+dYC5hEHrz0JcGf0bYoc0z5fAJO7eGjbYahd+JSo5tMbp
         RgegfomqIPvQVjPRRN1xi0+aXW2za+dIUcz1pcDg2cBI/0fov+LdshqwBofwJHLZ/2Jt
         2R/CPtquwye2VkVoZc5mltr4fOQy5F38lXetNP+rOs8X9BWLTXD4/igXxCa0cNGYKbiw
         Unlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=TiXhNa9Ywz4jXzL/wQh2rq8hy1tcrN9VKnWIyXvpR0A=;
        b=X/f02h1IFw7VEKLRMHArj8T+NnvkwSYTaiDisoN32aQMmFDJu9QV9erhbLmpy1O8bi
         2XjDlR+aWp9+kt7e2Zvv/4oDD3khPzIjxmxLVPsOuXOrV3Nafh19zqYpOLEf81huorFs
         ciC5WXHsv41REG9XgK/OH0CiT82f/TiwFgEI1X4qS2uTRYXVRrOrmJXpTIcZAnKs5oPK
         ZXC8MddkHIz2gJCsnJDDMABzdiVU9MB2MDlWpMd3xkhorae5xajAkmF1iYSpnnBVKzPw
         Qw1bvjvOcq19KEiC45QmD8yf/5Yau96VtOmMYzFjSrbMrb/5IZ1V2awAZdvy51pl1+TJ
         G7Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TiXhNa9Ywz4jXzL/wQh2rq8hy1tcrN9VKnWIyXvpR0A=;
        b=qJ3+YwuQNsBiYYSA6IgCAmziduOy+Xgh2F8FeKG7Ns7yqkktTwRleu1K9IYq1TVETJ
         DtJFaoDWwzmSF6yr+P+1p3wnxscLlWbBgWDd801g6dKcGnzDGpqQ57Lw9Z+hLyqjLY1y
         ruP6hqn+hJZVBlDhGwFyEYGIFAgcjXyjp3ZkcC+skjEjAAn8DCCPX30DGtIR4vEQUuzH
         jefJUyboG+6dCpIQDNeZGu+swZiF5az1PjlwFDjaoVGcswXRptdnuSJzC3Gy1X7X9v5H
         Gnz+M5eWyPv6kmwjLrTFYEC4/YAcILjHaEIr6hVhj7tTNvHp3DqHON94AVZC8d+nTzU+
         mIsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TiXhNa9Ywz4jXzL/wQh2rq8hy1tcrN9VKnWIyXvpR0A=;
        b=ipFpASlnoGTfzDzYpTITujqrFP3KuMxKFVPmfR/U+cAmSbmCxJYql/8f26sOgUjxA1
         ffXHRmX24fLps1ISrSP76sxoAPqVt0+6lCRQxEZyLN1m7wJe6On203tB+TnpYkyGPIms
         tLbq7ZQSKbn/1J749T1QSjD9AcGfI5TUIBXMW51ZuelZaet44mAaM1Um+UMxTd+NLkiG
         EcjeMnQs226953OryHOSER99jAJXTa+uxxbsFSPyweobdfVHxkbD85wn6miMm9i9RovT
         BT2xIiVMUJxt3se+RqiXpFoghf+aa8n9lB8Gw0z6TPOv1z4w2ZodrHKHKkL3L+0yNmYq
         ++ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533alMBFaWyqDKECw6fIgxWTermGVYLEEDChzzDUqw2XpvOA7Ria
	gFvUmlxVi0uto2Xgv7V5LV0=
X-Google-Smtp-Source: ABdhPJyIWd/kX1sucGphOBARml9EiC9xKJouv3Oet2ousicCIxYLT8AdyAjenra8Z7CE8fJhLx5a6A==
X-Received: by 2002:a5e:de03:: with SMTP id e3mr8326977iok.0.1592397387661;
        Wed, 17 Jun 2020 05:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1584:: with SMTP id e4ls453735iow.0.gmail; Wed, 17
 Jun 2020 05:36:27 -0700 (PDT)
X-Received: by 2002:a05:6602:2f0f:: with SMTP id q15mr8000952iow.23.1592397387308;
        Wed, 17 Jun 2020 05:36:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592397387; cv=none;
        d=google.com; s=arc-20160816;
        b=a8ipDNLUQgDbKk+dwZxLSf/kGwQKl1GtsPYyc4OoLDiCxK6SIOV1j5cF7IOJCZT59B
         GmOLqdRlTnTHTyvHhgjF0k8F5GngBXfpa78UcHTWifY0AR8SsQmBw7m+btZFM1QqISuF
         h+OHwZuHiZUc7kmWmHlrjgRNqiDL6uiUKg//pZuqKXNj4hTyeeMMS+V8i5G1Yzf7N39H
         Glgh1bubPs6tyJWVu4zC1FE1BT9mwEHzbh2N8HOp2GhFwcto56Y7AMDTtSqFXuQecqP1
         lRn3HpOP+aCA0OydP4PRKrf1ER2cqWYRO3IO3R90w+Gh9QbQNCtPZwULtwMFFDWgzIiZ
         K+VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=6fmGx9fTHBGIIWSFmJkSks3F2fsXeb7LpWGRdm4GDWQ=;
        b=wLGZElGEF5MIcBvnRIzhVGAHbTUR0ZmIVduuwIqLzStu15Ek5hTb24xnimfiFJB8HU
         b/LTimkVDiq6OR/OYr8iB4zriLwehLY/m87i1PN3whAl6dRm+QRygPLh6664AM1ORtx8
         0+1wrtrmlbovg23m2M055LZ3/G+h4iGydRGBaRJHVN0GXOuDxMY46lttM5SXDQ+LYTGL
         sk/2Dz0qiE/3W4+ETcSNmT+ndsJzyoNT3E6IgRWT7IlPnP1Vs8JDYeHCtbem03TPnlLg
         +RfEdB4EtehDs76YZ7sT46wkrFgaCZjEnbqWmR6HX0Ld4f0Qz8+dBYChrhpXas7mSjpm
         PNWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d3si27038iow.4.2020.06.17.05.36.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jun 2020 05:36:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 17 Jun 2020 12:36:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-1hjjHIF3Gx@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #7 from Walter Wu (walter-zh.wu@mediatek.com) ---
I forget it is syscall, we should not need modify this sp.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-1hjjHIF3Gx%40https.bugzilla.kernel.org/.
