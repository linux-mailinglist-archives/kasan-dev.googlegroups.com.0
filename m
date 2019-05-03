Return-Path: <kasan-dev+bncBC24VNFHTMIBBYWSWDTAKGQEIEVKK4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 83E2112C97
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 13:43:32 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id n3sf2934331pff.4
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 04:43:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556883811; cv=pass;
        d=google.com; s=arc-20160816;
        b=rB0xFTu6291BZzcXxk4FyWxbDzNUhqwr7Wlanjg2/71Rktzfb4FNWuYidTpUhb9Ije
         qQ22iaEMcZvLHhBOB0U23/U14WNq9QSRFw+BOrnCb1/K4QDA2lp0ueJepQr/p5ghXB0/
         hkzRUOxKfLpNzncvy+3MnEJaJ055ksTtyMbltl3nq+hf5n6dsRLOIoBlWD+Ve3+Cm3sO
         TY3g5ZQPoDkrCS2eXq63wTTFgAPq3vRYtXil09VqdlvRiBN808ryrlak/568HyYM4fWM
         BsIIee3BW6FfDQ0DO325fayFwxsVjF1gdU2eSupHGg+Y7PoSy5YoPLmm67tMFOma8SlU
         qvwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lJUi9uYpBKn1Afp5d6hjo12EUptfMNvfj8tTXl7nl+U=;
        b=iqkGfAErhWuug7nQQzjNBf8F23zK39SttVOUzFW/pTYMx/BYtpexhtdpiys7h6ZWHB
         2Q2PWu2M0Yxo2U/ttFxR4OSa8x9+4xrZ1GrPDiwTGatWw9/seOWfHi5WCQQrmBZ40Lem
         bqzOtLEZn0GBt3Blor6C4lDnZMsD25iPnsRF3pQT9BtL1I9TU0RGh5NKGo9Hr7dxiU8+
         3pR7eaRM8ubFwlQsyejyOB4uL4GCBpW0tMNeiby/8GPj+ClN6FnWetSoMLaRqLA/Kdpu
         b35OfjPB9oGqXJFLG/lELhBMTAjEBDR9oAtotfmu0eCw/8SWzpXP0NAk9rNlv/HxxjEH
         EoYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lJUi9uYpBKn1Afp5d6hjo12EUptfMNvfj8tTXl7nl+U=;
        b=APBL6gbYaMwL7AgRog27AXiVC0Y+AcfNHN2h6tvkAGSwy7fs2SWNh4osPXqp+oHb0X
         EoUtckeC3GMvEcVAJPyKRj0PTFxlHINu2T2Eb0Pk5VUScO+A6ffJI3RRGHhCU3KB1app
         NBR+OK7uD1bp6d0AjF1YwJYl97j0IVrLkqNcW3+90rm13hFmQRvHswr/nyrR0gNQb2z9
         vuGdxRDVEpZKShA1CjLq9f/enunblPyHn2xEc4u9pnuVm8k4AeGF3P5PucimG+4rRklg
         i52aIKtYLGQcHuul0cAYZpEUw6B1PmdtTRB3iAouqGR4hBIeGTnFnmv4ggMRhjAg4yRS
         zZSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lJUi9uYpBKn1Afp5d6hjo12EUptfMNvfj8tTXl7nl+U=;
        b=pR2Kwf29qY/tIN0HnljavevwIeYuHQYSY/Bwe4szTj560ZJmyZQuaqNAo3g5lakvmW
         0hxM+3z2Ee6k5jka6N1EWqCx4Yad5xBO7BO3HRCfWPVo/xBIedi+gRoQdN0Ymf6j3F3h
         3BzZumnb/JVsLml+19e6a2GFXren2K98dznmsyT2iWLLyfzYJ5YVHiVNDn04xR88eKlM
         dCDvtbpiLbuWDpNPugkNDWvDASCGcB2YzIN1+wcnMjlz7X3XuR/mMugmXeJA0Oe1GnJe
         Peh+0QgwbxqR79aBPiL3pD5Kh+NtgNqDipcVacuTKmcGABzqB2rP2ABvvkYlEXcXRFuU
         Tifg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUypMwzOHv4L/F2O8HICKxyuAcZ/qUZHRLPhnAvTBpqjVIeFOwT
	K3juQm2F4yE5bda/aNnduOY=
X-Google-Smtp-Source: APXvYqwkET3/8JiFc9wfUPScCm0VR/sTNN7MGs/QTQxWgpxBDxkU6uk+c3DQqjns0rLkyy85mbAjbw==
X-Received: by 2002:aa7:8a8d:: with SMTP id a13mr10398125pfc.2.1556883810927;
        Fri, 03 May 2019 04:43:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8206:: with SMTP id x6ls1294710pln.6.gmail; Fri, 03
 May 2019 04:43:30 -0700 (PDT)
X-Received: by 2002:a17:902:7783:: with SMTP id o3mr9617528pll.159.1556883810637;
        Fri, 03 May 2019 04:43:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556883810; cv=none;
        d=google.com; s=arc-20160816;
        b=zNEyE78h/giUTN9WeExBKtKUfI0vhSIWaUHgbwxKu/QR8jBv57CQtYg+BRL49Zjq0N
         ZzKg/KX+apWc4vcOK8p4+suRjiDvcRTAcbgFRxHTSZZcgIZ/O1B/DrKDm51C8vRWHWPU
         MMvs7YJx9s9cmh6FNnzTCZd1vJ3CTXfaAFvltR9Gpts4nTkG5NhXleZ8gViFP+phx4d+
         On3WrmFgFhOKlNgI94KLBNA6kxtg4sJPZO8azDDw2hV32sndNd7uHh6R3peNCnjWqlr7
         4ZS9R4cVYK1RjT8N8E3xfwffTaIMpgAsZmX8Q+KUC7xSDHFgIrc4WcDdjckIh1tW96Mm
         B0pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Gfkotgj77Sg48jvratag04kyloeQ0AvHMzMXdxk/vE4=;
        b=M6h96/4fjqgIoHbVmNn54Bt4nB2wev7PB4ERUD4gnMRdJyR917NLXt5KWwWZWpkATi
         XEv3fNlnVA5uOGC2WbmTG5G44H3EUCo7mU1WrrFKfUhg0+DGTcZqskzmxMUi3KEBF1ji
         92mMyzf4WzFpqO+aVFQMLPUyd28lQJSGV2+koMNhbUE/lHbktgvYgrtbN6MsFaEfWxyl
         ZOT+UkQsYV1SWWgKG9lL6eJZV5bK1pcjc120g+2ZZkAEyTnvP0mdOoRbL1Y+pTJlYVmP
         CrnoEdz+MqcmNiqPPjloulOLrDtAArOrmYtKnGaubLgwIA2PKM6LuNI+bFTnH8592ECQ
         YvYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id b87si98015pfj.0.2019.05.03.04.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 04:43:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 5786F28450
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 11:43:30 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 4429028478; Fri,  3 May 2019 11:43:30 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203267] KASAN: zero heap objects to prevent uninit pointers
Date: Fri, 03 May 2019 11:43:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: glider@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203267-199747-KiDUvniuXA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203267-199747@https.bugzilla.kernel.org/>
References: <bug-203267-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203267

--- Comment #1 from Alexander Potapenko (glider@google.com) ---
This one will be addressed by the upcoming KASAN-inspecific heap initialization
patches.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203267-199747-KiDUvniuXA%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
