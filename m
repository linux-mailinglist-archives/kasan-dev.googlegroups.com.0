Return-Path: <kasan-dev+bncBC24VNFHTMIBBXWNWHTAKGQEWNEXKBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 54572131D3
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 18:05:52 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id i8sf912007pfo.21
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 09:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556899551; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ecm1xabDJdUIP4yv8Q8mUUj2kRCcgY2VPcfV+MtUmF2rNqMGE0T3s/84A68XHDcVDr
         +6BW8u5gnO654AvymRzUOLgd2EheCXaX0oZCicPKmCqWmKqOMjtZ0EeYTyHwFPIdSGft
         P4Yjl9VPVjKsQurduNm+I/LcWSa+i/uUMvuduAXbetAKjs6kqgduFNC5BPq6PUmqBOV2
         X90jhbbug7SnzLSu1+kNEjdL0AfQCeRqtaOaKU1zQsC/YHlmHFDWINw1y+efBmfYAM03
         kUIdWp6MKjsmbEV3eUDOmckBAyDCuT2ZFh3JtdEJ2FYNjJTSl0g9IJ4417R93cX8RMXx
         9qUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=IeUU3eE8S9OBkWwMcokD3L1FEmxvYvaMksr5ie62wA4=;
        b=JDRnydFl4yAsMkal0tkDErixkmg+Km2C7yeoH5WxzAV7vDfgcMj+wICOqH/Y/7mqBm
         1Vp0pExc1kOrGfVyw2rXlsEWUWQ+uKaY6MeXfepEYM0UOPufKv0rQCdNzqr4ntp3A2Nr
         PCW6CYqR+pZTVTOQgjxcEu/aKSGvnsRQDoMaRZahQsHAg0d1xxc/ACnQhKdtXCmeW2bQ
         vI8dYyQeRySnWEgqwp98WxwpSFxOpulS46ajoX3UA0QUwcN1MU3X8Ml3G9rZkffOT4zf
         u8qxypc2vTHcXQ4wA6YpOdb3jVRnFSMsd5YciLRg1C7NafPFyux7DmsjbJMmpmovJiJZ
         IcPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IeUU3eE8S9OBkWwMcokD3L1FEmxvYvaMksr5ie62wA4=;
        b=mRUMNzNcXVlaTBMfN49v1cgrhAHyC/CEWTcUzFX4NyM1qfSF++bOAM04B+dozU9jbf
         Cfm7E+vx8NZ8sKwyEcDKuQM40pUht5nhImoQwIZxqUHr3xhZ3kUv32/3dZJpbpEI+tJx
         uC2luc+LAO9sTmWdz0tM2McdxSKypA6dbDd+fNihaeVFLbSQDFIIO/vksI1xW30jxVi+
         TVlKS0jN+CJI5eozgM+MpfB61AyoV4Y37/lCqPpu1BlY+IwwVvTT5W9a8hQeCawu2IfG
         Kae476DLRNP8ysINWhHLjqVwPF52ILK7n0M1YJduuYikqfUFFQRdhuruuQ0rSs1Nyek0
         DFzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IeUU3eE8S9OBkWwMcokD3L1FEmxvYvaMksr5ie62wA4=;
        b=i456c0bDxZY2ZO9z113vSKHzgpSMIqtfj0u728OAcOFF7xROoDPBnYhOfo5Gpn8xWZ
         DlQNSJis3nVtP50eh4o/SaJpSORw+e/QYS90cyifa71cAqQHrAfv/EfHFio4YsiwnZm5
         a31uhlj3tK26SCioPyBF9G3ZRm27+UnVVDp2E8JxxpRyc2Wje6g4SkTMrdJ3zRs0W34n
         24j/O/aZXPH+SBoujxtZjlEhgpPGv8S2ZE9LGuFv8b7vZmWtP72anZBh7j5MGk/q0v8E
         M4SoanVWx5S8bhdD0FXL3pS8J3SpPjs/nKPPUJkU4GIF0v0d+w2OUJ6QxTPGZM7667al
         TPbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUV6GOyOJTJAVTIMCu0PBeXEKhX9yDdFgD80txtva1lyDJ76F1g
	G9W2jivZEBpeC1OukBIxoyY=
X-Google-Smtp-Source: APXvYqyW0Kn1vTtGEQ0bLah4k6oA+UrnaGkXWL2vtr4QkgN9jctoNKbQViqrlM+iWprE0Iu80+JQSA==
X-Received: by 2002:a63:4b20:: with SMTP id y32mr11416747pga.244.1556899550943;
        Fri, 03 May 2019 09:05:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9148:: with SMTP id 8ls1557575pfi.2.gmail; Fri, 03 May
 2019 09:05:50 -0700 (PDT)
X-Received: by 2002:a63:bf0d:: with SMTP id v13mr11328987pgf.186.1556899550539;
        Fri, 03 May 2019 09:05:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556899550; cv=none;
        d=google.com; s=arc-20160816;
        b=hc/ccpIz1AwbWglnLpLiywkuMJ3BasBtAjqvSM31wC0wv/ZApgiqZuTvQ3Dl1/23e6
         5Q8PmWwZNKaccNT5vQyPnUy3XFklZX6YdlWabnwjKfll5z8nJhvna1NdvnDtAnYM7QOB
         3JMUvp8O5PwrzOaW+LAnQ+mZE20RkWOXhyECgUVhGziQTz1g8rZaMTgSQtgKhx6b/N3w
         1qqug/9X86Rblqd8+i4r5xjVNS4ROvcu75wSCpa/nM2hHw/GPuvJ3m4hU8r+jjfxJPSG
         10cQSUiyLJ1dRTR9s9QL3xiGmGxX0yV1L8Xx8BoVmxqBgoKfqf/Z4+hoMJ7LGhJQ4VOI
         KA1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=SRNeNuLa9gjwfqAkn9EVlV+ApUwxUnrujLg+xnWnnYA=;
        b=o3cTf3behlAwnLq4S4JIp2+aXKEdd1BtM/IH1H3KGg/ZdP9plTY85RtbmCcdnQBkjS
         V1nlO/TZcXxTG0nsuktITb7qMPXe0BJFGVPAivWADD5yXglYuu1XXXev3yK8pByEhBOv
         2yrnL4eRmDNqxeYO2/eGcIib2v6N/qy/LLnTy8IJCKy0wNN/msTKJG6tVMiSv+INQSpG
         b+jVL5ahbj0xwIDt72LE60wNcCLWPgcKXM4wyy2IpjSzp3Bo9jttuUMTCGj/BCS+RW3V
         1tkqsWX6wEWSDS3GOZj2TAIgqmkJQHD0GJx1od3jBRmenfpdnTT5cGnW1F+fQkOqpJKM
         oZOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id j11si84434pll.5.2019.05.03.09.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 09:05:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 5063C284C3
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 16:05:50 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 44BDD285A8; Fri,  3 May 2019 16:05:50 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203499] New: KASAN (tags): add tagging to kasan_kmalloc_large
Date: Fri, 03 May 2019 16:05:49 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203499-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203499

            Bug ID: 203499
           Summary: KASAN (tags): add tagging to kasan_kmalloc_large
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
          Reporter: andreyknvl@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently there's no pointer/memory tagging in kasan_kmalloc_large() for
KASAN_SW_TAGS.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203499-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
