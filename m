Return-Path: <kasan-dev+bncBC24VNFHTMIBBWWKT2BAMGQES3LKKVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F2C6332C56
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:42:03 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id j7sf10653947ilu.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615308122; cv=pass;
        d=google.com; s=arc-20160816;
        b=JEmCgp/6vrmRY0bQiBiiIWT+vpo1zXWntdGsmSfGS8ceB/wVVtaf/zRI4SUj67DK7p
         +25mvjHs0iyUi3A9MloP5s+l8G02SGgYL+1ZrPi2mENkLDNcVUCYDMiyX103/eFFPGDU
         h0HCtvl+RjSBr9DUoo37W5s/avfRbGMRDPkoKw3jMYRNtyiZnVwrhV4KHj+GbTlW277T
         yn8XecIm7sfoeVLhTdc6rxskAX6ePnI/qGGEOsjGV6X6WW9HF4UpxmM0o4JhRwuhPa2Z
         JZ/Qf39JFl/f1soy1Lk3hHHDbdzw/asu4cMegudsch6OlvTL3C1zL856pILNqQK8oCir
         ZzBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=WO6guoc/jEFc1bMjz3GFaP7y/r/JWsElFm01PDWDGUY=;
        b=mPUnL/DS5mgFjbdHxs6tSjtE9fh8R4tvP+Qec0PL5ZL1rObSEvFt8tIvSolmTwPcdS
         VD2OlJLcc0Ka+7rA4BBd9tgfz9A82QAsyhX69b/GpledS+g5DDu1UFSdwHqkSNUyWHLO
         WwHTUQNQyPdlff+Cp9MjaGABtX5s38CO+Ycn+Kf8nKNhEc8X9P0eUXfH0rNjP/OSVy8Y
         wAtWciNhHTWI7rrbACJIf2XCiscNTB+XjfDs9slYI81bbhCAO5sm73kN8hT/EHkKgCBt
         VrKpjjbHngG3Z+mVgi9z1Id36WQ7e0khXUza1cQaG6DwdWxE/rMfW6WOGlNqQSATCU43
         9r7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vPfRtDhD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WO6guoc/jEFc1bMjz3GFaP7y/r/JWsElFm01PDWDGUY=;
        b=Th+YBvCDgXJvJhoWNJ3zpVJLXDh0L/yjFDgeq/ALzan6S1eD47TDSzHyjyUjHQWDuw
         uiaorKtuidLyFC7X8egotM/3qVuDCUVT4wdLxXS97UQUIsnzh42Q8bhA+mJd7aSIOrwz
         XgvpqJLXLWBQ3XjoJyBevKf7CPY5kYMPIsE3qup8puYQKhz1g3LGcw3Fk+HW6gbgewrY
         MHkHGfcWdwZjWIGXeLXPM8jEPG9aBrIlau/+Et4NvbU5CcC5CyFuP61b27qgJUcljSoZ
         r7mQsBOvKC1S8Nu0FSkSEof5RUWAnXn1GDtA7WUNe4OOjd2au11UXGfJCmIkTPWgcVZz
         YqmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WO6guoc/jEFc1bMjz3GFaP7y/r/JWsElFm01PDWDGUY=;
        b=U3gLa8GH8GIcsqEYx4BVJXmI5tLFefKwf/3pppw3iHAdeCELQRg/o4nL1C2KOgmoUR
         x4mT50QI8Z5v63MlL6ySMda9/p95kesM33LswHmaasIvA3FlsPjnbL88EbVERN73XIFL
         POg7wAb1xdGxOlYyWkgBXCcmcoC5GDRrkGopjEXGejDVmLZJng4kcazS9ax5A6TfissH
         kXclrGbJWiJn/jP0S9aT84xxvcYTWyO6rFC+egCzW1phvyQc24GG2QyDe/N3Q/d8no00
         rZftAZWOspRuAilzG+twUTyZTt8sRa02zQ1lmZJ1vGH8jiJui20HfeltJZSY3o5IuqK+
         y9PQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530K+oEKod5ldTk0IBV9JX3zVtdi3z/4zKQ82EOZH2/s7fQj0ywk
	mkhvQc9iXjCT7SQT75ErW/g=
X-Google-Smtp-Source: ABdhPJzqaNfgnWww/ddu38Y48Jajn9V7ixK/SaXrmOBMhPSExYALcep2EFX82OX6mX/S4j8q2TrGKg==
X-Received: by 2002:a05:6e02:138f:: with SMTP id d15mr25293459ilo.217.1615308122401;
        Tue, 09 Mar 2021 08:42:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:860b:: with SMTP id f11ls3434451iol.10.gmail; Tue, 09
 Mar 2021 08:42:02 -0800 (PST)
X-Received: by 2002:a5d:9506:: with SMTP id d6mr23325522iom.37.1615308121966;
        Tue, 09 Mar 2021 08:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615308121; cv=none;
        d=google.com; s=arc-20160816;
        b=G6Bq1Qr0Z8CulE9H5ImpLSsxsrtTym7+HuEA9ASmqdH6N9z/MhjfP1+i3qUQvwpQQO
         TdEcIuIsNilFECnPOqX1GBLjzcjOeZYjm9Ifa+unXsDgOCM+C6s3/s4cQybKYn2UuE9E
         tF3NXlrceCIPk/ng2ufGuUEOZu2sUiarre2NFvW8MdE8/leV+7XHf/Ee6igTPYKXQdls
         Ngfiym8b8/M3P6jgnkJSUMAzBUjKzEgDLb1hUE86GdLFJP3+7SxRfMZicb3MnRZgEcA2
         7izlBoIB+q0fnvuZnWdDnUMOrY9Sup3HOPzotYcEe7V7c/wROg5SywRyJCF/9W2o4g2/
         L6BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=mfp5EvYYeHYv/rk0V2/+iFm3Iz677RzDSJXb9hS06TA=;
        b=mwRxTiJiYsCB0A7pDtefeyDEZn1PFaJ8hEude8WfmR0grwYBJgA+lsgE5oRuMIWG8T
         YC07B+NdisjXw37kVsfIYXldNHFueXBPxcOhA52wW8myWBqobnW+14uBuniaU/ya5bCb
         B724D+c66j7JFhgDiSoWMFMq2CkVc5SN8WCzwInPdhtGInQvpJvqwvgE4XFKkjkg0Iyi
         lOu30dbry1Z/OqRTLgh3ntuTtUgCihJclObJDkQ4AD0Nx3tVYNI8wqmG16f9b1jMVvSi
         7KbbHPazjGZba/3q13cVtYrDCCnC8dmkHrOU9ZEUK5P7mOiTMfwnEYF8CTGpbleTWnu1
         zwgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vPfRtDhD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s10si627002ild.2.2021.03.09.08.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3D2726521D
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:42:01 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2764965368; Tue,  9 Mar 2021 16:42:01 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Tue, 09 Mar 2021 16:42:00 +0000
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
Message-ID: <bug-212205-199747-ePEOqR4XmK@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vPfRtDhD;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Note: currently, lib/kasan_test_module.c doesn't work with HW_TAGS KASAN. When
the tests are ported to KUnit, they should be explicitly checked with that
KASAN mode.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-ePEOqR4XmK%40https.bugzilla.kernel.org/.
