Return-Path: <kasan-dev+bncBC24VNFHTMIBBFEY5D5AKGQEBGPYJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FF6A264549
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 13:20:54 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id j189sf2175960oih.16
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 04:20:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599736852; cv=pass;
        d=google.com; s=arc-20160816;
        b=kRAmsTYwQzv24Lc5HN/R14tNAsZhohLHgU0yhrzc0wG1uKEjMAyvD5IhegBI+SKMgX
         BPXBzYUkVLfX+SqeoFAVempSjNjgEQEe5UrxuVZ0AXcxLS4MrSE+G4rO2BkSN1I/zzT7
         NdOUi07+sR3eOs4PnfJ+6cpz07UOFNrb+nqiuSpmE7CWQD553y3tAigPcuEV5btWkXBr
         q0JcvgPKclr1e+W5c45iAkZhvZDC841xyAJS7Y5xJeseKCeb2gulKcoZwgQJmVtCR4QQ
         fe7Peo/KbsJtYkgi/ejh5b2DT8Co593N9Tp6MLLI7ga+WvjH3ZV6GDwMzgn1IInLOeNm
         1etQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=OwW0/Dzh//KlWAX1A9yg69Y5uEmngObw7lKGNQcmy+g=;
        b=0QT3qyVMRmJHZvUVqEOWPmpViHXWufMsc28RuR+Uek9LDfDALNbJujdEPD8g+7H7fn
         an6H/1dwV8kG6kkobGXBYA/YtVx7L67+WKqxDGFHpNJFcRPF1SZmvo2ZQCRrucmvqLic
         XSTFcgq4cBDRQj03LBd1wblduolJdlgZmaxcxYmHK6sG9aJo8c1eGk7rK0SnqSq6eEEt
         US0CB1t3zBPFQAJdQHEi6MuI3UqL57GhTKF+RI3er4WAIFAjJWtz3gVFmVjmr+uN4wUX
         0jMl0lsYa/nCFdbdH2GUmZ7xHXabxEmXXsKbP8vFL06XsI49+NHl+doEC0Xj2bfgtKMA
         my3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OwW0/Dzh//KlWAX1A9yg69Y5uEmngObw7lKGNQcmy+g=;
        b=Qw6smTW4br8QR2tfYmFjrP+9DktMMD3yH52VN4zu7h7REYDpypnMYuMpHHICX9LvXm
         W27QlqM3Dnq4SYw/P0f3+i3Nmj8Qq/ENhn3/+GjG/W6afGJkABtX/aeiimocQeHp32qB
         +pQd546woBS1jhDk2jHX7NG58HiPLI7JHbIqI49cZJGd1ggNxzgcU8Ux/qbbbPvbMwzp
         caA8X9GYAcpcvNVqLX7Am5yPnsTVsRiDaAhbIxCtZPNPhRSK2bewfRzNx5vh0vmKhlVR
         Rxh2QzOsgWsBDoXTlF760x6aoZu6gObfygwXzhTjL17+GlqEF6GWg2rqB7kQ0DXUqsZg
         iR9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OwW0/Dzh//KlWAX1A9yg69Y5uEmngObw7lKGNQcmy+g=;
        b=A5yFoYLnGdGJdGbc5mqnOWk3Mf1sDLIrZ1IM8jb2m6nW5ip1s7t20uDeeh6vY6m+WV
         j5T+f3gd72/PRXMBsD0aRLeZz2Cmwp++y+8MRJ6mXKI5RwfpoUIx7yR907uNQpf43LAN
         jhaHuEFqPbhClS1x0+TEkd+BebbFV8uu0+jHC8sirk116GPg7dEz32p+yR3VqQj7mLWi
         qAlIsWSXid89LkBCiBoXMSE9GfIisLWK4I9YUAou/XpItk8gwWgSoxc6O02FjhQn/1pe
         apiMNR9tFOMFOkq9PvnWyAhJsCqcB9xuNosLDyLCIl4dwhaawgYLGKebqoiB9Y6HOA0p
         RYLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320iKaJNovnJOdOfpuMhY9e7veGe86Q3m8owPt4mH0R+i9Kr5mH
	uK/1cJb8HJXMsciZHySnVec=
X-Google-Smtp-Source: ABdhPJyiBLU0gKPsNDhe4gAab/XFjGyvn1r2goMCRdJOIKBM5uopoRISkkJtvLcBlcX8txJCgF6lew==
X-Received: by 2002:aca:220e:: with SMTP id b14mr3241370oic.97.1599736852809;
        Thu, 10 Sep 2020 04:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7ad8:: with SMTP id m24ls1360106otn.8.gmail; Thu, 10 Sep
 2020 04:20:52 -0700 (PDT)
X-Received: by 2002:a9d:768e:: with SMTP id j14mr3770303otl.50.1599736852518;
        Thu, 10 Sep 2020 04:20:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599736852; cv=none;
        d=google.com; s=arc-20160816;
        b=cXvu1Qfmgj/ndTNuUxsWIyMEgIU9Q4enhv09UtZbZ0oU5yEoDpGkf92Vl/K687TQDD
         PVcHE/eY00ZFcgRsd3+7QYO25Xn4shlXbioFF/hTYkhxheXaCL4yPolL3CYrlVFnAWnr
         62mf8+MQeSqxwUTnOlAIPLYW8KRaeVH/NnaWcgMmqTSgkh3CfdV6UgziIEvR0SXnVxhi
         VVwALcNwPAGaWZBOTw7urVek1zn36nZn+P4/I42Tfbd1qQ58/W4NEcAijUapb2fMKvI8
         yjHMJa+liYa4Toup50HkqGvXvAP+Uw373PT6i9TQvXs5neUI40h/CkjiyP+f5/FgQtNI
         WC7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=FeqR9Lu1TSwm0Clpd20tro5fdCWLEGQNtdJQA5OEFtI=;
        b=iTqPKr7UA4V4r5yMCOyF/rff/GXmYK5UmvRhKB3+fSJz1dsqshzAPEv16h8WusI7It
         tTXKjOeNPmXUS6d7ZZUBFcUy/ONolFPXsPqOKzzxBlNPZ0XrYGiW2g55ui2Pf/nTzyT3
         R7z3D10PkUskNs0gmjb4AolgNUN8tdTGDw1XFPck0OhpYqkE6O6pb6FflDyb7PB12T8y
         pgfjBR4hampn5EPQGaiG4Mb6awuhDmMFvgCjQ2tuWSdH8v5r7xhiPB6jnzjPVhkHXPZh
         TdC5BZj/vx5KtYIYnlN0N2C2/NGUHLguKPBstQPnE9tJCpoTTTv0eMipXOX1e+mYX5Yg
         kj3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si328849oti.2.2020.09.10.04.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 04:20:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 11:20:51 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-Hv5wFgeWLu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #3 from Marco Elver (elver@google.com) ---
Another idea: if the places we would be interested in inserting delays are
limited we could use kprobes.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-Hv5wFgeWLu%40https.bugzilla.kernel.org/.
