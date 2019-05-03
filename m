Return-Path: <kasan-dev+bncBC24VNFHTMIBBXOHWHTAKGQEIMI2X5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 826DB1317D
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 17:53:02 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id v123sf10241593ywf.16
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 08:53:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556898781; cv=pass;
        d=google.com; s=arc-20160816;
        b=L3GqkcdO0QShEjCbGDbtDuSk+1vEkEG6JtGQVn8rQEqFzbXvFCLKcbmhrmlfooZW4T
         VB1eJaVmUrlGO2WgPji4CmzLXw7uGPgielpyWlTPA2EqFtjF7zSTK/3JNPWnGA4x0zU/
         buY26saKiJSxDcrPTCvjZrGNbiJkgLOe+rzutCa8mlLM+eFIw0eZi2wqDAu2+9rTT7rq
         CrwdgQVGoFRg5UZ+It6BYyJ4k1f/6I9qTI5jM0YSsFfqc6dBrwdH0GcnauKVkp7R2El6
         64aH5wTR/IOYun/Bpj6Bv08MKHAWsLm8/rgG7k2AuoCtsOOOsGTvlrGu/dnz+2+yZ9Pp
         WkxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=aXkmjZ/M4yyyX5ceOuNX7SMtm6BiqJRvW+o4RpQy0p8=;
        b=ZGAZTwbfCCUPEC8DzDvtqZm79R+JbNe6P0hXDDkJiGs7ti9fOtQJWLf2eZWJVGYo9+
         5wj8kU6/khQVFQQwv7ffxSd+gDrUNnZkp+0ucBjNWyONzYdNVrtzD6gZaWh7BPUVs2W4
         u5ZHs4ioUd9mupsavBXAN7xfXY0up5wRi1kgBOVsu0c0+C2PPem2VuwHGLXx5uxZkDjg
         cIg29JexL1/a8IyCdW7C91gJgMybFPNeERixUwKx8PO/SlDIzA5rGKJVSuQhVtanYh+j
         yiB6kFYSc8QdAg/se3/WWxBZ/isxoHnMM95PggJuh5SjFAfdthjMXbk3fhS5xQHLD4pT
         oQxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aXkmjZ/M4yyyX5ceOuNX7SMtm6BiqJRvW+o4RpQy0p8=;
        b=NbOUez9k7QlvegmzU1TdBaSsTGgaiMsQpYhr4tH8/RdtnaGxxfpRGnbuTEaReLB0SC
         d42hKue9SYi+XhoP7c5SbltF4On7Dypkt7mt6RQZy/U1g2FYrq8+IfbHbqDN40bor8Rf
         owjTX/7t9RNxFpVtpp28w1shio8jd6Ot9kWFQZ0MxCpZ5m1qk7MEwWccWNtwX5Wis4gW
         VSziALYLYQ/rL+GrMIy1xX9x4I3eZ2p/VEzLeYOAb1FSse5Gm57dI2AzPkde4hc5xEzt
         nJuHXfcKnJfjNfi41LLorkH2UpVhDFPGs1a22txs+9Dlf/coXbIWhNxVHvTqT2G+d2Jt
         a+rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aXkmjZ/M4yyyX5ceOuNX7SMtm6BiqJRvW+o4RpQy0p8=;
        b=JcYoj1Cw7YSdqKcPtjlknzkoesCl4n9eIM4FtTAKrg5i05tQStKqV616vYL1942Czu
         RnVkc/ptOV/iqPmj1uZD6ZXJo01/2sJQwPMi63fG3ydsqR+1doMBikr5ErIaR8Bg4I06
         ZxaSwSnkkQaoVvW+mBHh8J1G6XDyJIw6J3xxp6IawVBUW5+e390DbXNURcXrKXyV3EDi
         KqlMZ9cPI0WoyPdrZP6px5JfAjxZM5v/u6b5YBaKFMJjbR5sxLHEyNLeimhOdQo8Mh0g
         HHDzWgnO5UkdpcxD3EcKpfQR2TlqALeDY3W19wWSiXV6uEY6DWJfHtbC55m1lG0kIsQW
         SzqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxLCShZE6Rtz93+g4lSp2xA55oWGone5WiSyxDc4gwbGjmrJBh
	fUku0bpIOthk7iWQ0+1qOVI=
X-Google-Smtp-Source: APXvYqxptQR+DuNUMtn6MOGEpzGMyoudKYvzmW1vYxkTTUj4Z0KSjpJNtGoZRgY6IPPLL2zm3zVTkQ==
X-Received: by 2002:a81:1383:: with SMTP id 125mr8394566ywt.265.1556898781265;
        Fri, 03 May 2019 08:53:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c041:: with SMTP id c62ls1305409ybf.0.gmail; Fri, 03 May
 2019 08:53:00 -0700 (PDT)
X-Received: by 2002:a25:1f02:: with SMTP id f2mr8096043ybf.111.1556898780802;
        Fri, 03 May 2019 08:53:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556898780; cv=none;
        d=google.com; s=arc-20160816;
        b=EbaAuOIHX53xsIn5MjcIRvMf5NEg2CRVKWwP+Cjk/7TW1+E2aRbyDC8/CufXg1DGhy
         i5dhinNNpgbfmKublzuQMp2NHlVPqnlzhMqiKHbsuG2dB4EcINqJHGE5X16MJL6mKOKE
         7phf6heqVs2843oE83y2rHrXZg//uwmCweBs8q81WpVzYnK2dKt6DYABr75UJOPHT76t
         yPc6JU8cJyLl9vKOGN+s6EYBrQpT9JDGrf5wb8w8eR2HPnJyoQt67n823TCQlbXILLxY
         04TMFyK3YmSoumHlwF/ycdYJjtyTGPMtetv3gXWGzFB3A+KaPxsx2d8EcxJYfJrYjqy6
         atsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=V78xxtu57jTGYAcDyBY6NU/zsDzA8J8y8vnEEjpdRf0=;
        b=Yb0cKgX+325vEAkG+jwyhY8H3MTVddFelae97flJr6KuwsQBCiVgNc+UE1JbHLScOy
         tIDwhtDjvOO7tmMME8Pt7Fcnu6cEEr4rp+C72kscv202qiAs0bDjGZS5HubrqJjnYZEL
         KAoH9PZ5pkrtMeIrxlO7Q2l6GQYNu9Jf0fCe8fd08dUIdjtOyZdcJMbp4ezLH6zfYxKw
         A99Ly/1lwN6ukuzASNDJdNPnShDkdYMQmwc3xshC5YLP9/KmbyA4bsdP9JJv6P72pbPc
         iLVWSKxycVBttfeY5HAb6CuGDLtGv1tPzwzof9Yy/pVTMBg/bMCx3tMRUdI73tZxYUUx
         El/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id p130si162102ybb.4.2019.05.03.08.53.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 08:53:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id BCB3328613
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 15:52:59 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id B11FE2862A; Fri,  3 May 2019 15:52:59 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Fri, 03 May 2019 15:52:59 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-203491-199747-lKfOt7Hmgv@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Andrey Konovalov (andreyknvl@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN: ouble unpoisoning in |KASAN: double unpoisoning
                   |kmalloc()                   |in kmalloc()

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-lKfOt7Hmgv%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
