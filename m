Return-Path: <kasan-dev+bncBC24VNFHTMIBB2ELWTVAKGQEKIRH2TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id C56A487186
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 07:34:33 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id m198sf84550591qke.22
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 22:34:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565328873; cv=pass;
        d=google.com; s=arc-20160816;
        b=EsCz23WspKMHY2XKx6CoDuDoeyLQGcXQqU+yPzyxsqhyYmGMJQnxN06/qiEbS/W7Ij
         OvSpHjR9YgZeP8Krqy8zVoHYNXIMpFgmlwm5xMbx1Fn7js41+vISveq9+SjFpWCgYGDv
         9kyObT3Bu7twW8jP7xSlV5PSTVI5x5ODJdiiUmGGvK6yYB0yZCOC174tHwnXKp7UWkty
         0Ai1G0GDI0fkrN57V0UsR9YP+2sYHs3I4ZyP4AnUFM3ZQ4LSNAceHFMbfcb6eFntfumG
         qqm+67wQ8XWDq3DXS4Edm6/DXaVEftF/lEDvz/+UzQ035f87WDaRvjLjbhkI6ET9iueR
         2XoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=xJI9M6jT8B4q60UwHx7S+q/bXzseYgYVLyJq/Mu9uLA=;
        b=JKL1WDCfZRR6vbV33zWIs6s/4AKoF5pfbz3aToGrc5xrua0N7mX+FlJH0BqHW8cMyQ
         OkieJe3U6aEwvNgdyhZ3WafnfL2HbPwo3VUikpIVJOXZPxfVsIOZteaJSgwDUgpA6LY9
         WTWIQEXMBYhDklfyBmHafMkS8hfqf90cpxu4+/HLYCBSN85cBoKOECf3N1E5ZpjQLovZ
         69b97exyk6LJMczxv4DryEmD8hOeBXXOsxjuQsLlWQJM+SRbXxbSL3LADjHoKlhPy4rQ
         qXr7UdUPNT7BqET+rqE2TuYBpF4rGmHfqn7XXYr7YDkMAlzrJjmKYYm10TfjvsQ3qcry
         JQ3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xJI9M6jT8B4q60UwHx7S+q/bXzseYgYVLyJq/Mu9uLA=;
        b=CmnXMk5IQ2gdJTSUWiI73XK34dNngs+ni+PbSZA+S1iZsPmWxybC1b5rBJ0BfBOZmi
         PFxr1k88xprzW4mFmF2qXT5lvS99bun6/kTO8c40Z3Y45CPca3yIeh7GrwYT3gakI+aS
         pJy0nyVaxRHPjmtTwEeV+nRW6JrlirtS9XLFAm/YWbR4SJ/e4n636kG7Jqc1lBPG0QEE
         Dg5CQzdj2QPibRcawQD7im1g38yvY96YUzppjfc4uNgnapP1g/gUxP6o5hUP6XdQr5QQ
         H8JFTnNP8ooNCJcmyBLnecQfFiN2Qj5vhwKfQda50Smmb+QuUjDoHUo6waEb2Mt+M23q
         O+zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xJI9M6jT8B4q60UwHx7S+q/bXzseYgYVLyJq/Mu9uLA=;
        b=InP0UFVcTduYtOF493kTZG0RhA6P1uxNnkcFyGs/W8SCXgI/oDCyLm1dMZCn4yOH2x
         ja46DutDx4SQ3ZTN2TPq2xP9Ur9x4IjrT8Mxq871n/MOzzdSma78pVj2mc213NqNgs5k
         SH14CRF+g3CGz7ODCw+fjOW1oWfK4jXUXNHJKNRgpIZVCvl0tuDxv1cJdx2zkqECizKT
         X3EwgS+EGH0Nx3rEYPB7aYrLBC3dhOB05cqpM6qnDEdFtPyPMm+DaYjsFGWhE4GvAzid
         kaRUGJGvVbWI2wCnQqeRzHsNZXEABbVLnvL4MtQq1Px9zbFEILlxNmAQUn8ZVSgfvgud
         AJZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV2qkvtHp8p9SmIjJW+akkJJAmQoFo9PQiFLwWZoyuFnBCPHGWq
	Bb+mzTrynmRCzE7WUv8uErE=
X-Google-Smtp-Source: APXvYqzRarbhZDxq4jMYXBQdmxoPMe6MpOA6fcTuYaaxscU+32jdS1UZds8TI3iNcpGFE81gJ5g6mQ==
X-Received: by 2002:ad4:4974:: with SMTP id p20mr6043699qvy.29.1565328872886;
        Thu, 08 Aug 2019 22:34:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7743:: with SMTP id s64ls3128014qkc.15.gmail; Thu, 08
 Aug 2019 22:34:32 -0700 (PDT)
X-Received: by 2002:a37:a358:: with SMTP id m85mr17076677qke.190.1565328872592;
        Thu, 08 Aug 2019 22:34:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565328872; cv=none;
        d=google.com; s=arc-20160816;
        b=iSdXur2oFtSYZ3SMjHHnlIlbhNPiowp1G/8rjPsW3KSJBEfZPurMQkKOXgGDYC/oNS
         injfgj60I8pdyFPmdGiVc/rGSViKYjpLnGNJP7g8pC+qtkTMB4p7YKsyFUvJXjvQ/3IV
         IC5UML0rK20E84yOpVWSczA95TAu07agqIrQ4Chq9Tjl1WVsj5P3iq38iSptiRIBOZrA
         UUHCVDoFiNnOhyy6nesVoiqivY6OkBanicZeMACOTrS9RNOPe0W4SN9VNF0nErMBtQC+
         eMuxFwaxfBkQwTHxH9Vh0Mk7mIp5C0qplMsoP/+vl1lVlBnsHV9SohYGA92Phao2H/Hd
         dLRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=MbwDNcKUwetiUMBL8IqRfXlYOmKQ1U8Z702XYTdnxsE=;
        b=Ey/SBkufptTRPDjRTadv+XbtZGY+kS88fjh7VS0ou1zfMsZqEQn3F5Kf+usnosOHxg
         UxHN2oFaSGkBDJhQGLMRNLb4KVAIBJ6uiaQtH4k/9dgnbkw9KYU+di6gK7zDJbEH5yhN
         lR3O8Q11UZO86jlGor7svvVympe0ReAfdvmmfNSrWdCCw8NHAN7vxXLKhm0LJe/yQCZU
         s9fbxhuYBqhNCQg9QXTaZv+95d3YkfO6x9RGMsBza8nXcb3jjgDmJ6IISB+IZqJik+pP
         1STqM9tMtLW0RqTwmrwC7gGHP01hxQNTtpkKyDBZkcELzNocXrDG2bN/crh/sHCzEdL6
         I/NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id u204si4363634qka.6.2019.08.08.22.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 22:34:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 4DC6428C2D
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 05:34:31 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 3149228C1C; Fri,  9 Aug 2019 05:34:31 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 05:34:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: christophe.leroy@c-s.fr
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-R2H0e2RPCB@https.bugzilla.kernel.org/>
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

--- Comment #8 from Christophe Leroy (christophe.leroy@c-s.fr) ---
List of allocated areas with associated kasan shadow area in [ ], together with
the addresses when shadow initialisation fails:

Aug 08 23:39:58 T600 kernel: ###### module_alloc(c78c) = f1470000
[fe28e000-fe28f8f1]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(36f8) = f147e000
[fe28fc00-fe2902df]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(c78c) = f1483000
[fe290600-fe291ef1]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(c78c) = f1491000
[fe292200-fe293af1]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(36f8) = f1502000
[fe2a0400-fe2a0adf]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(1521) = f1013000
[fe202600-fe2028a4]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(13bc5) = f103d000
[fe207a00-fe20a178]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(1357) = f1027000
[fe204e00-fe20506a]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(36f8) = f102a000
[fe205400-fe205adf]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(4301) = f102f000
[fe205e00-fe206660]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(4718) = f1065000
[fe20ca00-fe20d2e3]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(19ac) = f1076000
[fe20ec00-fe20ef35]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(4718) = f129d000
[fe253a00-fe2542e3]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(16ca) = f102a000
[fe205400-fe2056d9]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(1f81) = f1079000
[fe20f200-fe20f5f0]
Aug 08 23:39:58 T600 kernel: ###### module_alloc(1f81) = f1027000
[fe204e00-fe2051f0]
Aug 08 23:39:59 T600 kernel: BUG: Unable to handle kernel data access at
0xfe20d040
Aug 08 23:39:59 T600 kernel: ###### module_alloc(185ef) = f12d0000
[fe25a000-fe25d0bd]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4035) = f106b000
[fe20d600-fe20de06]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(6196) = f12b3000
[fe256600-fe257232]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1d27) = f1071000
[fe20e200-fe20e5a4]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4035) = f102d000
[fe205a00-fe206206]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(a11b) = f13ad000
[fe275a00-fe276e23]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4035) = f12b3000
[fe256600-fe256e06]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4035) = f12ea000
[fe25d400-fe25dc06]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1d27) = f1033000
[fe206600-fe2069a4]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4035) = f1397000
[fe272e00-fe273606]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(307a) = f12f0000
[fe25e000-fe25e60f]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1d27) = f1062000
[fe20c400-fe20c7a4]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1d27) = f12f7000
[fe25ee00-fe25f1a4]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1d27) = f12fd000
[fe25fa00-fe25fda4]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(d102) = f1429000
[fe285200-fe286c20]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(2a37) = f1033000
[fe206600-fe206b46]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(4718) = f106b000
[fe20d600-fe20dee3]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(9a3f2) = f1db8000
[fe3b7000-fe3ca47e]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(18571) = f13cd000
[fe279a00-fe27caae]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1f81) = f1071000
[fe20e200-fe20e5f0]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(1fdb9) = f1438000
[fe287000-fe28afb7]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(56a49) = f1e54000
[fe3ca800-fe3d5549]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(56a49) = f1eac000
[fe3d5800-fe3e0549]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(56a49) = f1f04000
[fe3e0800-fe3eb549]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(7c61) = f12ea000
[fe25d400-fe25e38c]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(e011) = f140c000
[fe281800-fe283402]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(56a49) = f1f5c000
[fe3eb800-fe3f6549]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(56a49) = f1fb4000
[fe3f6800-fe401549]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(e011) = f1459000
[fe28b200-fe28ce02]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(e011) = f147e000
[fe28fc00-fe291802]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(2561) = f1033000
[fe206600-fe206aac]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(6ae1) = f12b3000
[fe256600-fe25735c]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(e011) = f148e000
[fe291c00-fe293802]
Aug 08 23:39:59 T600 kernel: ###### module_alloc(e011) = f200c000
[fe401800-fe403402]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3355) = f1397000
[fe272e00-fe27346a]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(1c8f) = f12f7000
[fe25ee00-fe25f191]
Aug 08 23:40:00 T600 kernel: BUG: Unable to handle kernel data access at
0xfe2731a0
Aug 08 23:40:00 T600 kernel: ###### module_alloc(1c078) = f13cd000
[fe279a00-fe27d20f]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(12f27) = f13eb000
[fe27d600-fe27fbe4]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(12f27) = f13ff000
[fe27fe00-fe2823e4]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(12f27) = f1413000
[fe282600-fe284be4]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(12f27) = f1459000
[fe28b200-fe28d7e4]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(601c) = f12b3000
[fe256600-fe257203]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3716) = f147e000
[fe28fc00-fe2902e2]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3716) = f1483000
[fe290600-fe290ce2]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3716) = f1488000
[fe291000-fe2916e2]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3716) = f148d000
[fe291a00-fe2920e2]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(12f27) = f1647000
[fe2c8e00-fe2cb3e4]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(1b7a) = f1033000
[fe206600-fe20696f]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(3716) = f165b000
[fe2cb600-fe2cbce2]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(15f7) = f12fd000
[fe25fa00-fe25fcbe]
Aug 08 23:40:00 T600 kernel: ###### module_alloc(fe69) = f13ff000
[fe27fe00-fe281dcd]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(fe69) = f1410000
[fe282000-fe283fcd]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(fe69) = f1459000
[fe28b200-fe28d1cd]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(fe69) = f147e000
[fe28fc00-fe291bcd]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(3087) = f12b3000
[fe256600-fe256c10]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(3087) = f1421000
[fe284200-fe284810]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(3087) = f146a000
[fe28d400-fe28da10]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2d72) = f1592000
[fe2b2400-fe2b29ae]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1c09) = f12b8000
[fe257000-fe257381]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1e4d) = f12fd000
[fe25fa00-fe25fdc9]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(3087) = f1596000
[fe2b2c00-fe2b3210]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1562) = f1426000
[fe284c00-fe284eac]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2d72) = f15ab000
[fe2b5600-fe2b5bae]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(24c2) = f15bc000
[fe2b7800-fe2b7c98]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2d72) = f12b3000
[fe256600-fe256bae]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2d72) = f1420000
[fe284000-fe2845ae]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1c09) = f1424000
[fe284800-fe284b81]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(15b9) = f1469000
[fe28d200-fe28d4b7]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1c09) = f146c000
[fe28d800-fe28db81]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1c09) = f147e000
[fe28fc00-fe28ff81]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2d72) = f1491000
[fe292200-fe2927ae]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(1c09) = f1495000
[fe292a00-fe292d81]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(2068) = f1498000
[fe293000-fe29340d]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(13c0) = f1469000
[fe28d200-fe28d478]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(3f159) = f149c000
[fe293800-fe29b62b]
Aug 08 23:40:01 T600 kernel: ###### module_alloc(d8e5) = f14dd000
[fe29ba00-fe29d51c]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(4ed5) = f1500000
[fe2a0000-fe2a09da]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2843) = f12b3000
[fe256600-fe256b08]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2843) = f12b7000
[fe256e00-fe257308]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2843) = f141e000
[fe283c00-fe284108]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2584) = f1422000
[fe284400-fe2848b0]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(1be5) = f1426000
[fe284c00-fe284f7c]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(1be5) = f1467000
[fe28ce00-fe28d17c]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2843) = f146a000
[fe28d400-fe28d908]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(1be5) = f147e000
[fe28fc00-fe28ff7c]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(1be5) = f1491000
[fe292200-fe29257c]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(3921) = f1523000
[fe2a4600-fe2a4d24]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(199d) = f1410000
[fe282000-fe282333]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(9d3b) = f1412000
[fe282400-fe2837a7]
Aug 08 23:40:02 T600 kernel: ###### module_alloc(2bfc) = f1422000
[fe284400-fe28497f]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(19a6) = f1422000
[fe284400-fe284734]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(5215) = f1514000
[fe2a2800-fe2a3242]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(1524) = f148b000
[fe291600-fe2918a4]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(1d62) = f148e000
[fe291c00-fe291fac]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(bf4f) = f1596000
[fe2b2c00-fe2b43e9]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(19bf4) = f15f7000
[fe2bee00-fe2c217e]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(2851) = f1481000
[fe290200-fe29070a]
Aug 08 23:40:03 T600 kernel: ###### module_alloc(52fd) = f1485000
[fe290a00-fe29145f]
Aug 08 23:40:04 T600 kernel: BUG: Unable to handle kernel data access at
0xfe2b40dc
Aug 08 23:40:04 T600 kernel: ###### module_alloc(f30b) = f14eb000
[fe29d600-fe29f461]
Aug 08 23:40:04 T600 kernel: ###### module_alloc(2d9d) = f1485000
[fe290a00-fe290fb3]
Aug 08 23:40:04 T600 kernel: BUG: Unable to handle kernel data access at
0xfe29f0b0
Aug 08 23:40:05 T600 kernel: ###### module_alloc(3f9d) = f1489000
[fe291200-fe2919f3]
Aug 08 23:40:05 T600 kernel: ###### module_alloc(1e82) = f148e000
[fe291c00-fe291fd0]
Aug 08 23:40:05 T600 kernel: ###### module_alloc(666f) = f151b000
[fe2a3600-fe2a42cd]
Aug 08 23:40:05 T600 kernel: ###### module_alloc(264d) = f14fc000
[fe29f800-fe29fcc9]
Aug 08 23:40:06 T600 kernel: ###### module_alloc(180d) = f12b3000
[fe256600-fe256901]
Aug 08 23:40:06 T600 kernel: ###### module_alloc(13fa) = f141d000
[fe283a00-fe283c7f]
Aug 08 23:40:06 T600 kernel: ###### module_alloc(74a8) = f1459000
[fe28b200-fe28c095]
Aug 08 23:40:06 T600 kernel: ###### module_alloc(2cc6) = f141d000
[fe283a00-fe283f98]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(eeb18) = f19ee000
[fe33dc00-fe35b963]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(2f546) = f1528000
[fe2a5000-fe2aaea8]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(37fed) = f1559000
[fe2ab200-fe2b21fd]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(37fed) = f1c94000
[fe392800-fe3997fd]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(37fed) = f1ccd000
[fe399a00-fe3a09fd]
Aug 08 23:40:07 T600 kernel: ###### module_alloc(4fa5) = f1462000
[fe28c400-fe28cdf4]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(4fa5) = f1468000
[fe28d000-fe28d9f4]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(4fa5) = f148e000
[fe291c00-fe2925f4]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(37fed) = f1e54000
[fe3ca800-fe3d17fd]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(4fa5) = f14dd000
[fe29ba00-fe29c3f4]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(114e6) = f15a3000
[fe2b4600-fe2b689c]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(114e6) = f15c0000
[fe2b8000-fe2ba29c]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(114e6) = f15d3000
[fe2ba600-fe2bc89c]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(3afc) = f141d000
[fe283a00-fe28415f]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(3afc) = f1462000
[fe28c400-fe28cb5f]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(114e6) = f16de000
[fe2dbc00-fe2dde9c]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(3afc) = f1467000
[fe28ce00-fe28d55f]
Aug 08 23:40:08 T600 kernel: ###### module_alloc(3afc) = f148e000
[fe291c00-fe29235f]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(1bde) = f141d000
[fe283a00-fe283d7b]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(16f8) = f146d000
[fe28da00-fe28dcdf]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(1bde) = f147e000
[fe28fc00-fe28ff7b]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(1bde) = f148e000
[fe291c00-fe291f7b]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(1bde) = f1491000
[fe292200-fe29257b]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(16f8) = f14e8000
[fe29d000-fe29d2df]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(16f8) = f14fc000
[fe29f800-fe29fadf]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(16f8) = f1511000
[fe2a2200-fe2a24df]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(105dd6) = f1612000
[fe2c2400-fe2e2fba]
Aug 08 23:40:09 T600 kernel: ###### module_alloc(2b1fa) = f1719000
[fe2e3200-fe2e883f]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(35b8) = f1466000
[fe28cc00-fe28d2b7]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(2006) = f1554000
[fe2aa800-fe2aac00]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(2c633) = f1528000
[fe2a5000-fe2aa8c6]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(5c9d) = f14dd000
[fe29ba00-fe29c593]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(571d) = f14e4000
[fe29c800-fe29d2e3]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(571d) = f1506000
[fe2a0c00-fe2a16e3]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(571d) = f150d000
[fe2a1a00-fe2a24e3]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(22af) = f1462000
[fe28c400-fe28c855]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(22af) = f146b000
[fe28d600-fe28da55]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(2946) = f148e000
[fe291c00-fe292128]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(22af) = f14fc000
[fe29f800-fe29fc55]
Aug 08 23:40:10 T600 kernel: ###### module_alloc(18bc) = f147e000
[fe28fc00-fe28ff17]

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-R2H0e2RPCB%40https.bugzilla.kernel.org/.
