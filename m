Return-Path: <kasan-dev+bncBC24VNFHTMIBBIE3QL4AKGQEM4GVCDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C57321465B
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Jul 2020 16:09:38 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id l17sf24089101ilj.17
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Jul 2020 07:09:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593871776; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8v37nubz7XgvD6Lo3RxT+erJeNeAQt+lDlc7RRJcqh0XieMuLztQAMlvSkase6eVL
         wJ2155R42Xngx/vxhkNS2CEabGoJ81Ai+SSfuOoOPzR8CeEcQH+Li2xxwvCtQ+au/aRm
         aXES6Tox50zB6w+Quy6vVKKEQE0cnnvz+STDDtbUy4/V6CRNjis840RVp66jBWH39NRK
         6f4283mL679svLEw83ijgGd2UhgpR8SpdexjYThMxHAb6jgbjyI1FsYmNU7X416i6E8g
         Kv7iP+wQbH2OFTdKsTSDFCaPTzB7Gygk/bsj8j9UGhHuxUThH26A/faKh0Le/9zi+XT0
         JhtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=DcJTGQMVbFmFdOJKIAvyKGxBkPzny6AKnUqttVJrUD8=;
        b=CzfxLz2vAMQNio3XKeX/sSk5GJv3nvDsK+P5rfAVMq1NRXAmaXVfanlzel2BCMoZ/U
         FxhcD3aV1kJATM3suctdvfaC4g2u2oMVJrIgGMSPPChqOvxpkp4GPqao0CwCJjKYelVB
         9ChtNnMmkTIy86IRc6hoCWoOWm7w/hdx3U2xzl/Wa2cusT3vpgEGlI9ITnP5QRNiPs8/
         b9c7zr4PuEZdeA9osvsiKBw8z5kd5bSlqMQrwuQ/4Z2w/1s/Dp1cb5M1poMZerZOAe2r
         0S8bx9LxRsCkFnqYOIv+4t66ySNvlbUkEu/xrfGIISwSr/wXVbEJO5vdZf8+Vd6zS3mo
         4HYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DcJTGQMVbFmFdOJKIAvyKGxBkPzny6AKnUqttVJrUD8=;
        b=Eo0c+lbvbssIl6s+DWSLnH3k7fhwe301eKSa0jTDEcu67Cjo7JiRPRCc4zYKodxQlK
         OfEx66FaKJhs2iVAigYq8yOJSzjNSuaZ5OvI4JUfk7U4jpGF4JJTIw7jb7UjDpRmz1Ij
         9/NUz1d+STu3mk36goSfLSt/zu4vt7gMTO3/bbQqaJRDAQ6IzvZLGeN7APGakX4ZR8O5
         6ZWot7zNdfYiagmV/N4M7MbZ7pPtTC4S10MRdLqf+n9pT7PCTr/HK487EDoGXSxTWFWm
         t7+A6CnRXKCKwodw5vQJ+Krm2tzBSO86LtfxUGGNQF6vdKaQIHS2wtHoqQ5s/31JE82j
         PLPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DcJTGQMVbFmFdOJKIAvyKGxBkPzny6AKnUqttVJrUD8=;
        b=lltWh83Zr/UtMe6AfgE4+MXDEWK4bbMlprBh9ABGxbsO/PP34cdeNb8eotHkG9VZ2o
         8thS2rC+yJI1OX7Bqmwt71jkqaRftI9r4Qp0WLA/spa6rtWfejmio9GjWcL+r407tenE
         nCYWvDYZQ6Rs1K/Uz4IMTi33hXiUbCi/t9XGgvG5/dY0FHXqyEdUR07wYT4zsCil7U2l
         hiZEpRpVgFaYljfyehdqMzGHAQnMNk3rz9ZVl4BTBFHwgjElxI2RSyU8EsMoxmPKMPhU
         ifkSUl4DSv7TtX+JTxk5yXfUZteqUJgoAM2hawWiAe8q2OfmfVm1J7vet13RoytG+/ZI
         iOXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eR6Hjzk+rpz4oDgN33HDxwmnI4E2K7FOz+6JackYzGrgdelbE
	lMeWgtK1Y2w+ujSOEcBt8Ks=
X-Google-Smtp-Source: ABdhPJxc4RW/vLcvi/5EgEKjZtsG7YoQrIURA6rIAnB6tGIVBix6PPkTMwZ/cXguCflyW6k8yl3e9g==
X-Received: by 2002:a02:9f8e:: with SMTP id a14mr45286252jam.95.1593871776600;
        Sat, 04 Jul 2020 07:09:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9a03:: with SMTP id b3ls1709476jal.3.gmail; Sat, 04 Jul
 2020 07:09:36 -0700 (PDT)
X-Received: by 2002:a02:cd28:: with SMTP id h8mr31961330jaq.40.1593871776325;
        Sat, 04 Jul 2020 07:09:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593871776; cv=none;
        d=google.com; s=arc-20160816;
        b=yOFQK4KIAgsjDEkVg/u/TpJM28p0nQoWHYRsiKu3D2qjqO10O8cNvx2CKTMi/4jUE9
         ZWKggpJ9zeARm42IgH9MXn/PCFZ2vqxbu1X1odh6zsUtE7FEOEoBPF184k3ogiUOL8kR
         8fM00dcglyNcQL1RSzp6m7r30xzrLcMNA4BajhSJO7WRHLSXHEMhnDkXGNVmLbujYYva
         Ag75tbC6x2jQ4qbXJJhJN56bLZf/2Nnn4/sDtjeTT0nKGOORlZRD5uuv76W1niaj5r22
         MEH3vPkXpe2AphQTmsa/jaCRKIBvh64gNOrpBas4oGFmVgNDRA+y0lLhkrPwaoFI7brS
         UhwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=NIX/bdq4BP22KeEmTyRluWPStFcAFXGSsWlfWePAU+g=;
        b=WIwIzOtryd7Zv+ENfqMwYFvu5uWsMX/Wu/HB8ccswSB/8IEBnFVgp95q4NTX3XYONC
         YDsF2YXo8C6oZfmQ8jGx8vR525ga9BAttVBPloF4aYwIeIhYgvKmkXG/m+tEz+qxTEj4
         vn61LGCJ1oeIRETPfCo8bB2PiQGbEHfUTgtVOJdT0p7XNHeEU05N7o4rTZDyytZfUyT2
         gA+5Y6esFUJPKMQbO3vLJnBTXVvQ/wCr/qZwkAlI4hxG2AYa+flX2iNQZUDhFst3T2uF
         bCPPfsZZLXQp2JyZd/BUOhR6WbStzx+BWMfuamadBVpeHreFNSggpUfB89QriKzaIn8g
         +/Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b2si1336528ile.1.2020.07.04.07.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 04 Jul 2020 07:09:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203499] KASAN (tags): add tagging to kasan_kmalloc_large
Date: Sat, 04 Jul 2020 14:09:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-203499-199747-yuuCg9fBS8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203499-199747@https.bugzilla.kernel.org/>
References: <bug-203499-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
I don't remember what's the story with this bug, but currently
kasan_kmalloc_large() memory comes from alloc_pages(), so the tagging is there.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203499-199747-yuuCg9fBS8%40https.bugzilla.kernel.org/.
