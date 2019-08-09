Return-Path: <kasan-dev+bncBC24VNFHTMIBBQ4NWTVAKGQEKP3K4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 12CD387199
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 07:38:13 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 21sf60701384pfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 22:38:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565329091; cv=pass;
        d=google.com; s=arc-20160816;
        b=zUbV4z9UGDwDwUO0Avcfx31U8ohQIl6PwpDHHioQJLGgMky2byh0YFXyEOdTKvqqLB
         m0D6GdVHKTyTUkP/otmmfIbRrSuF6y2iLeNT2kfyou2pzi68jdiQjDSoTXtac0kRKvP+
         OZ7BQXuWZU+qFNGrmXa21q60fPtDt+pdwB5BDUYSnrEj09VBgJQNHWXWrCatQAOTEAWf
         +OnmCWbT75aLU977YulWLeXrjh7O8E/qHotC74KcblUQPvl9Ake/oRIw6STF8KAS+6PI
         MLQqB0KDUW7W/LHEqjynAI1aZXjk9p7rFbz4CF54GWMbzO8qQcvNchY2Gd+aTi/hTrjt
         Y/YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=5QgRKd9LJNrY0wnP5aJ2vMgrX6HzJ5URpGXm59Ij32Y=;
        b=g6EsQVb6utMdExxfDVbxvOeY7iUzkWL8Auttmr9lfv2BrlEiK9l8SIU7TZ43BcoBx6
         Mw7HEUX6aLD4xSTP+2O7sA3pTm7f9lYsjE8Ae6DtOc/H0rbXPvdhUZT5VLc046xxfz4j
         u/cj4XDz4qFBt2ZS7Q1bZq++oX6aUOM4vjZ5P2ydmGgJcQ6FNjDqpCM9TJjMyTzMKMTG
         k73IhdW3Tz2zB9YsHnG3qOlObyzW3EjsDxXzhaildb6so3LR2RoP5Tor79vZN8v0AAMY
         nSTFnABE+jE716ZPZrfMrlK1MOB7lNZnvaDY2nZeRv8dt7np7mGZ3rm1SaVAfhl4DULX
         +HpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5QgRKd9LJNrY0wnP5aJ2vMgrX6HzJ5URpGXm59Ij32Y=;
        b=sb3C8uVI3haJ3dsAXMibaj9PnluF5IPaqLrHtk1npGQqaQXvqFLjoD7fnUVEMtIVeb
         eW4XRQqIG156MXw0lLi6c4Nf9CugUM7vicWyef7jKhnoYLd3yfmeWKAHqL/jsyKE0zcF
         +cHoHJNgcC99SCHAoniJJG2fUSxfsSqXd+/mHZ+tGnbu7d85aITUO2KJQTlzSksyN1ao
         UWPP2INDrtTlaJwwVdjmmGSskg8y0ebMamZgEAuX9/emRQEEFgjgHJPM4FWetIbOKyfi
         JTZOMLnbabT8mYDO4NTQrVK1l7DkboNp0sYSMIe3xK8nSTVvnYmXXwC2cQ+Af2ghwPm4
         CbaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5QgRKd9LJNrY0wnP5aJ2vMgrX6HzJ5URpGXm59Ij32Y=;
        b=KUOxM0gmY48PvIcPUO3MCmgYcSA7Lk1KFVDLMjs4U7kq2F5FgkxJu9hSYwmLPJZZw6
         eHfA2WWbo7w/BcTRshRga6+6xk24tppX+NBxRxdwSx/cyFYTT0GApY1d1kIdJDNg9WR5
         mA+EGLNsPjS4nBf1pX4Nc+oQ+Vpg+plmGi0pQfUa6nmVeinAke92wJywkenIhNJKypN5
         10Pso6mPPBy7D7AvPriIMszEL3hjzmOaZO/IhbQyKnJ2Na8kOLRBOF5ixQ1TVJvhbvoz
         1ZH0iMsT4BI4E5eNK344gmsIkP51e7Sw/LGhgXqAbqtODZybXHCqRTI4An6yGCcsLl8k
         OnWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDPCeHdGHDX0KqKeOGJmdwnRhIBZCNtfxZiJXfttRgnvI5f8Px
	2NLcXUi79yz9p4/slYDLZq0=
X-Google-Smtp-Source: APXvYqyRsuq/B/wVxdVKgdrtJSd7FRePtk6pFD6t3IAPUUQdQgL+v3eDCSRouCpPpPidvdGoCzioDg==
X-Received: by 2002:a63:3147:: with SMTP id x68mr16394948pgx.212.1565329091688;
        Thu, 08 Aug 2019 22:38:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:580d:: with SMTP id g13ls20073556pgr.5.gmail; Thu, 08
 Aug 2019 22:38:11 -0700 (PDT)
X-Received: by 2002:aa7:8502:: with SMTP id v2mr19060825pfn.98.1565329091393;
        Thu, 08 Aug 2019 22:38:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565329091; cv=none;
        d=google.com; s=arc-20160816;
        b=iLjwtUfsil8lqyy5GsA94HutGn1cCKDmzqIFWMe6DpEm7HFP1SoBjA2HGItAwuFP/1
         h2OPpS0J3p30KADkCGw2hG31LR/cyam2cc3UqiUwmUokl5Ick2NjjLNxTG68fq+wqS0y
         FuVYSCR6I3hCVJJ6hsv7iuKZT5Y3/fAirKiYlGZ2y3L6ivaQjYeCxmfoZxthP/pjxD2s
         U9QS2UWGZK6gOU992ZlLZ9Ka1Fwae2aomLByyrfrrQUFC76uLC3/3SZIv3VTApe2AQZn
         0eEgiAdg86WuTsqjDo4YvSSriLf8A0RN+2ysGFU2igNYtheO2TBstYmgEer/ORYepR4G
         Pbww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=qNKXaF0Zao2lXjtJ7NJQjFYcgD+zZYizxNDlwNQJbDg=;
        b=fR+w75JtOkGbsaqOzPmmFBv9ZavIIQfE9uH82hcNlB+AQkhxFvUrucpQz0KOFi1Fn1
         hS8b2M5Fu6H8q/QZ4mDSTX6CLknIsgxNHlPqq70MVq14gedbdG0NO7HnoCdufgVF8r99
         gxb9glBo06DIw7WhP359fCXT5QgxVGm154OwarDfQQwQxzWbHjwxVjk46A3UmRWVvYbx
         cvFO5nVtYyKgwSgIlbdBn8ZwOfo0snsgQ66RIDmtJR4Kl6aeWhVIJTr1vQLcAG4HMB8W
         Jt3EHchvHgvhbojcj4cr9c6169dgo0lMoVGCKFr5Gh5P8geSk69HSvRSMtLctOiRZ9Z4
         eWfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id m128si1591332pfb.5.2019.08.08.22.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 22:38:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 2099C28C08
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 05:38:11 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 1507E28C28; Fri,  9 Aug 2019 05:38:11 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 05:38:09 +0000
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
Message-ID: <bug-204479-199747-t3HDsk0OuJ@https.bugzilla.kernel.org/>
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

--- Comment #9 from Christophe Leroy (christophe.leroy@c-s.fr) ---
The module loads seems to be nested. It might then be an SMP issue,
kasan_init_region() is most likely not SMP safe.

Could you test without CONFIG_SMP or with only one CPU ?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-t3HDsk0OuJ%40https.bugzilla.kernel.org/.
