Return-Path: <kasan-dev+bncBC24VNFHTMIBBFPEX7YQKGQE4KLUUVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id D36F614B0E5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 09:34:30 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id l62sf4004074ioa.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 00:34:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580200469; cv=pass;
        d=google.com; s=arc-20160816;
        b=cAvQRRHeXDwkPife+NwzyH3YSsDaCXQNDV7rRrrfPP+VRj/3XF9J6Icz8+qQiX3eZb
         5nUHAGqTdxAJTZrzLUJr8VWYkLIkokyGSExb9soQNXCLleocXyLOBBSIatY9fvBN+C2m
         iqIZb8POOfl0l29okCmqv8UiB4Yxx4wd7khl/FwqsZMEkCruAFggJTJR9o82NQlBUQek
         hR3kleANt5r/DRjH66WQ9aLNZEr5nkGN3XBUvmXeX8N0axuvEx4Pmd/VCsr5+yVYgCM4
         Rn1YDgBrtcouAhYspkNtsasjIGnDo5oBSlY3CG+bqpmXrTCgKQ+AtC545vIhGfoXonwe
         XsVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=i1yV9xMJH/Ttvzze3puOiphyems1tnMRxsmjFibb2Jw=;
        b=UbpGpTAW/gqpEDGmPP7FDkGw0lLjJT+pyREFwJ7h/vkQkZ2tDT4VJnfZj9lbNNH9gQ
         6LoxrzxI2oCnUL6eDU2Ho4sbALTlUQlrkOFF7PqY/vx6vAD6EtiUUZGqKlOZ+Rwhz75t
         H3SaukZiCjEJ6MT18hVhsnkaJ9aApQkRdpSMzWijBOZvBSVjDNbGdrfzzt7EMDR1NGkH
         dixgDVJ//w4or1Mwu4dRJdhv1ZgFty3id9Nc0XpMWf1vNJrFBuaUUj/LvWIF3JhrE8q/
         eM/AcpXCNqrmLDqoJUYk+oDqxOePKoHkGh/KvDO4ROByCU/cjwfqKzRjIKlEViU6fymP
         1WNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i1yV9xMJH/Ttvzze3puOiphyems1tnMRxsmjFibb2Jw=;
        b=C1405MPir5Qb2vLF8S15UYp8n+fPYXgpu7psr8E/IF1EtYj5c9BMKjPDzZcnYme2x3
         jy+OhmEFLD8WhVYHcmbmI0sZyMsWLC8ePgAEwZUCSEjhnXPiUj5tFFU0mLewAcmCO4As
         hBBaufgikQ1Rf5rV13gj0DdJUMQimHP4y9zBnbFcNm7dR8mp4X2TLaVan5WQ44w/JZ20
         qJnjjiZ5ByNNmA4yjMhyH98g+XONNg41T438mk/d/c4jocfZKtPMJs77j6EnIq4w2sBw
         L/7OBId+yWMEsUn+sFRvlq0wSeND1UYPkhfUQce5BpPGEWUTjbgPdBx4akMVpdBgqw2o
         Zs8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=i1yV9xMJH/Ttvzze3puOiphyems1tnMRxsmjFibb2Jw=;
        b=MqIKoa2waNKDrqQ6dDiXylKHneV0niXE0ypThHxGsEbhG8Wy8CaFd4RBmIrKQ8hR4o
         pXRmt1ymkXa/39aaR3N1BzvkAutZDJg+OWvBs5sEhIG/jkB74phcOQm4JDa2DMQDYFKp
         IXdzwWVpr/kaUfZr7fslPXghAWq+lXU0PJd38dPHcF2I8kELMYIa1UAo8IHDewyWU1zr
         14rctksdVueEEZWtnMb6xJ48JLcS7oJ5GYUcZtz1hpPk/QLkd+pKD9r8iPViW0ZMIala
         8aBzYwx+1NlLlty3nCnGI1528Yy2Mvdd6hD3rbQFS/gg/GlUSDcZ3yfQ76S66lOv4Pkv
         SE9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWEHqWVyfAVpyzDwG3CK/boNwB4AjKVpgRlq8ZWOtZS5O0Nbyx4
	gt0h22jloQb38N8RRbw4jXw=
X-Google-Smtp-Source: APXvYqxkk2vpRdrydEaOcPp5x5n3ykwFny67KR8XK4bbGTxOoExnfng17WLfIW7yspMM8lnAN+LsIA==
X-Received: by 2002:a02:7fd0:: with SMTP id r199mr17045675jac.126.1580200469406;
        Tue, 28 Jan 2020 00:34:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls2700071iln.5.gmail; Tue, 28 Jan
 2020 00:34:29 -0800 (PST)
X-Received: by 2002:a92:3d8d:: with SMTP id k13mr9512337ilf.229.1580200469002;
        Tue, 28 Jan 2020 00:34:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580200468; cv=none;
        d=google.com; s=arc-20160816;
        b=xz9S9FLpTq4EQGRPfnl3oaN/vqPmOAR1KWPdDC/FJRT09/TeTPMI8Oe/UqGXCIl8qE
         WP3WbG3N8C9TL4eLvYFoaAyhBLOsyCb+U57zSkez9hcKlRICuHhCyI6nQNjuh6qNZtx0
         cXWrUA+I0s6BMMGGOzzop5st5pjsmb6qESxE+Jm8akP8+3ajC/iJPmabv8tXeJH1cEG8
         A/4h26Rr3rWnP37F98lPZbPTuUWWGrJOtJ4WZL/OB0o7to6/dX2cVLiJYOWHXKw71/MQ
         Po2iic8FQXP1ZkiRvp+MZLMO9Uj5d0rsJZR3AL8ylojkZaPfekh8jYmJWaIYt/72B+ro
         mUJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=LLgUAMUoxC9KPqsS2kRXuJ383rGJSMt5BQdWgl0gjrU=;
        b=AN7FWpHyG4qWB86pu6cqDz+t+qMW7RyC0vW5UHR225Ox2rDwozaxChbx6G4H0toH4l
         jygL9ckjDrUZNZZs4WlgXnSZN299jXpIhpl1pwAj08V68+2upCAmmH0FQ10eEFb0XHyv
         ykcQQow3sEI16ZJAZn52fF4IJf/owJmxPb9q8zdCoZiqQmOiyeGMxV+u9TqOi3+lMr30
         84okvQcT8JXpqK9z/o7AVCS5w4qGdYUhljBkG7CXdexJM8vVzdK6rSajWSjHBjPhNMk3
         KIQWnHAYoJ9hN+8ExtI46evqMQo3Al81th5Ft1ZcwT9xUyDYvZv4PG8PDXYKGFQ7O9qa
         bV+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k18si920213ilg.0.2020.01.28.00.34.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 00:34:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 08:34:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206337-199747-ak7heaQvXB@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206337-199747@https.bugzilla.kernel.org/>
References: <bug-206337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206337

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
FTR, I got auto-response that the email can't be delivered to the Gary's email
address (does not exist anymore).

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747-ak7heaQvXB%40https.bugzilla.kernel.org/.
