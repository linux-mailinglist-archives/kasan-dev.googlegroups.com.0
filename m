Return-Path: <kasan-dev+bncBC24VNFHTMIBBH5N3P4QKGQEHX5LAUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F119244E72
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 20:23:29 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id b85sf952976ilg.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 11:23:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597429408; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zbeo1XWLvhmrM1JvF8hblG8d1myUo3zbJYthUWPzW6gR6DkcB3MIU84+/8e7A2iF7k
         YWdv5Dx0A4Hk6/Yb2xau552TudqScBPlG3LhSkaRzP7U1Um1ObWhWTC3I2mfHsWQ57XI
         jX6WCpDQhbszWquilhds7o1PHc3FjOGyGTB5WMDO+wV0O/nb4g5P9Da/lBua1ri/YT/I
         A0Hu8hRPBLpwp0w1G9fzlasTA4t2f6qyshkSA0BFSS1c8S0NO7d4t2BahXxE7gA3K7Ag
         mwx+tv7tQ3Ys1yGnuV6Gg2hpfudHcmuiCRP2X1g8SPWmefTQs5c6tY8s9uQNZChdb4J7
         /f/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=PjwSTA5gbw9aqX/MZJRzyUleQQG7oVpbaDyjRUwhQRA=;
        b=kcVxxnY0/iwv/JGtrsAFdzr8YahcHawpwxCuScNOxA+cZ/ZyAQt1CJtBZ9B9ihr0NY
         kNvxxBhtTaxPntKyyP5eb6xZpyIPlxUGGLdRVyeOR5pdQa9GlipGKDknfn3UeMYqm6ZX
         GMtpOylrVxrQhgyGkJQyFVOnsL07Zf6f/gdmygQOhBEt564w/sAlu580A7tAb8ZtNzM+
         X37mFoBPU7L+dvEiIUcZPUJnJ2ZIKbKm2ilvidkSsPPerjXrEK9aAXMDcZ+34RQrFQmK
         bgPbPNbg2FvoX8DbQaJ50plHGr2BbaVGTT8434hRX414N5cmdIjohUJp8JYrOY4SA0th
         vZdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=e3d4=by=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=e3D4=BY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjwSTA5gbw9aqX/MZJRzyUleQQG7oVpbaDyjRUwhQRA=;
        b=c1A10AJs573npqwVHXFabI33VoDNrgzkG0V9ecByODvNRtZ5VwMNho7F/dT8uRXsjr
         Dd94Lffh07FHZPpCBoxslKgXZHeOkhDnzaYOqQzOwAubS/zpMZ1Z1JZBgQDPOJE7bvhv
         vF0L5EnHlC6+9yldU+tEbOsicj3lnQ9PsZ56Zsq6DnP2yyBsG6KrLKd9m+UHombvdEjh
         O/Ue0UaxiiW7i1wL+WOyVE4HFsP9rYwaOHufQ6sRyD06zQEmY2LasHZQnpH4Ngn0SanE
         VB5hEZYjj1sj9Nf2Cw39GqTgOQbEMG8VncApshPGr+Lr3fhxX53rlazm1/1dpD3r5ttX
         A5cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjwSTA5gbw9aqX/MZJRzyUleQQG7oVpbaDyjRUwhQRA=;
        b=qWD5QAl4K1bAgtBm0SVjK9AalD3ruMW0K9FeiFlgqXSDXPthQbQt9dRIG0cJFpv8ee
         oelBRudgZmuhf9gkcZ9R1qKGjelodRq9Z7GvIr8YKA1Oyu1wcLhm1ZLKj6cmivV68fEk
         lydQ9mHn1zuV8RvjKctnID6DcBCeVZT+dF/kjL1f7KwynQ0FgZFa9FR/kIkIOTX7Vd7s
         0bKcp+o6Pu/p+bMCoFR60+MPsOhm3TNRVYh/5hrfYVvwiAWQLmCLgFrPsaxgagvxU6gr
         iPPrO3qwg0Y4bAVj9GV8O9WEFhf9ARJj4jmgjyRGk02g2AXVllSkX2Agz/wfhw52ZF5q
         882w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cSBNTrjbgdRwMfH5DMYhBZXfqiekU7rz5wumZwuaZ1APvdmXL
	IFt8Fq2lXlSZD32qg/Tf+nY=
X-Google-Smtp-Source: ABdhPJyTLGjVWKc3/6jOJ3EyVNfjBKPUV5KJ6b8ZddtcRc+RjfSnILoyiM76Z+crMZaDGLX6xwNOXg==
X-Received: by 2002:a05:6e02:ca3:: with SMTP id 3mr3542791ilg.8.1597429407772;
        Fri, 14 Aug 2020 11:23:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f702:: with SMTP id k2ls1677261iog.0.gmail; Fri, 14 Aug
 2020 11:23:27 -0700 (PDT)
X-Received: by 2002:a6b:185:: with SMTP id 127mr3195620iob.153.1597429407393;
        Fri, 14 Aug 2020 11:23:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597429407; cv=none;
        d=google.com; s=arc-20160816;
        b=SzUL+kSFc/OeQYbW+rdhzY3+4hQR7geTD14K0ATEenTCGSr3QwxozITyTikduDcyyL
         oCNWpEeNyPyx2DqjjKYZfZDzP7pKf2n9zxWjBIgwKKdrVtksxGsySFiAQYbYqIy/DE+o
         SypF7pY4fqz13kjEv3/FIks45Z7MRcwPMrOJYFtQBnNpgLJkh7kd5+c7RZq35ukzGu6a
         44z8MqyUmu/iN6jYDT9tQHApvy334ENYcccmvFGt47I8hf3LicAmIo8jKGtxKGVLSfZ8
         Wq8IWUA1/Q+/jS527wUXEq6VbIDnroDpsG7qsMTQ6ILWShee0NB4VdWQbHF27DEaAuC7
         b5ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=W261qPI9jNPaBdmwZbhI62+67wB6Jr/svVpURSFXwSM=;
        b=sNhHOj6mqOPTCettWHB0CiY2y7/9CAsNuLnlR9QyQ63ykP9G468y2zA6LpqSM7FcSX
         QZ72VbM3AjG17RxYAZKlTwTC2SftpnRLlPqmuzvJ/VTAZxLUrJsRcfqJEwR3m4rZK1Sc
         MZ5HY6MmDBBu30VzeIirutujLHtIVe5B9cbf7VIbHm4BaMVLdsPkrbHA4EiE/b9H4vkK
         gA+1Q7d1qqmg60ISO3qRS+e8utAlrFqUHEaPbtoH2gzjgAfzO4aXM7Fj+x6uySugiyMX
         CSa3LQXGGFSX2Q20nGpnZC6aFDjpDVCnJJzpcbRJe7c3iwKHjNL4VSPp7naWcfar1VGC
         tNFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=e3d4=by=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=e3D4=BY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y21si651255ior.2.2020.08.14.11.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Aug 2020 11:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=e3d4=by=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208905] New: KASAN (sw-tags): print detailed reports for stack
 bugs
Date: Fri, 14 Aug 2020 18:23:25 +0000
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
Message-ID: <bug-208905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=e3d4=by=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=e3D4=BY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208905

            Bug ID: 208905
           Summary: KASAN (sw-tags): print detailed reports for stack bugs
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

Software tag-based KASAN currently doesn't decode the stack frame as generic
KASAN does it.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208905-199747%40https.bugzilla.kernel.org/.
