Return-Path: <kasan-dev+bncBC24VNFHTMIBBFOS5DWAKGQEX4KY4QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 99F51CD689
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Oct 2019 19:49:10 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i187sf9016894pfc.10
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Oct 2019 10:49:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570384149; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8g08zk3wh348wzcd30/B/O7yyc3/FoksYP4l5jk6Z02RTCzKKgg+ZPVjHpH+mtOg+
         rqvWY+47xMPOlnZhkcE11GzspCjR4j1aJS/iobPoxIueZJVJSOI/Vv0qmgQZYlYJBM1A
         tFFWm5feBFc7QfRpLKM/+uFVe3XM87Y2l0UbrrijvnKMDjSHdrEGb/s5jG7q7/Kv5rSX
         JUCPrHIaPRD2Bs0k71nqpbHiJ0b3Y29LenacwSiRqzG9t0nmtefsPornUu5/pWez2JWa
         ZkdFa0CcVICPmnMYw2qhVAnE1n0ZPGCIM14cZq3FvqX/mS5n5bUChAj2u8NhU3HZub5h
         loPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=peVWbwu2degCs39q2+BDArgeBGf1Y0N9cEwvJY0TIBU=;
        b=Db1aL+hV6jnw+WrNXfP6uuL2J4/tnIB3q9I63bph8AvuakLTVL14O1JWhxer3E/R3A
         hX5l4g7qAMqdDYzbkeKTUWBuSVhjXP43BGNOMIA/xwAXV0tJltN3ENzkh0MlBUz9PCMz
         FIOehV8WI8fyHy3284/DUfgRL5F2htm5JUiAFEw6rHzFkTLiHWvWzlCT9jkw2oXbNNGi
         G2ahYxVjWI9a4i00fUvUzcXTpobhdbqyGBkA4xNOTEtVUu2fSiaGw3ZcwO8uWEkIbKg4
         9W6jJQWHtL6JF7SQqvdAe30u5ldRMdLsEWHyArk2SqzesShDixqvoI8av73P/rB5gh+L
         GbrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=peVWbwu2degCs39q2+BDArgeBGf1Y0N9cEwvJY0TIBU=;
        b=r58FRW46vQ9yB/k/gLi4QSu0Kxn1YVfasaMu6xi/fmJ3G+AmcdknCoJ+JJreJfQb3e
         47wLDqCOD0tBT1mqsYF8tZefJZ19oMBCH7ZDPf507GYOmDl7Dmip4dUMMh3BOTa5pFJU
         oZh/5eaVZgBwtH6nZnuwzi8APpgRxr9tx5z4CX23Gq7+rsO1qCC5Eh4Jd06Oau6enJUB
         9rvyqk8oDiFqVKWBFbAxznZBtLoXL6r/oduuqXcP3OiNJIHREgRxDMzZ4XJbnk+PMDUD
         f1Ke7qrG61WmLAs1tYuCE1KRWd1l0i5iub4f1qMIphPJcDs3JIfeoVJxkvODiBuEXFdn
         FaPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=peVWbwu2degCs39q2+BDArgeBGf1Y0N9cEwvJY0TIBU=;
        b=Jta7hzLsCdYXRuGqsiceqyU1rcMP7s81tkbcXHRnHalNlnlYWd1LbDBMqmr2/NSNLF
         zVz0vkjFEFaRA3O+c3odtnB+VGn3LklGa0gyPVIr+I980rEsDkTYUiYq3uv599pAJAri
         mx1+fBnC/tTMrcWFZxxnLFg6IPzCwEap6qFJR8W5NE0XICqTZqw5hwaCQyz0nOHaIeJr
         lUpBWi5AdHkE1ReerS8Fy9wSBuGruHAi46lRnBQoUbPMy2eYyrL8yQcR5CVmm83kRNcm
         oT1xzqfjNqBI8Ja+TmZKkkmVEk5ohlJS04LxPpOt7g//Z+q/pbNeCdgRdTWe2spxjNW0
         3IOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU51FP41PoqMG0haJSJKLtMlt8vyDF2qD+ev8H31T34bS2KDozb
	tqxRW+qarqMtsdLKg64ncLk=
X-Google-Smtp-Source: APXvYqxWoYgSrz5/jOuSCM5BJlh3WHiJJLdSmefuBmJbC0ieSETJVLHUHzCwXYHRVEblD/cYFdBGSA==
X-Received: by 2002:a17:902:9888:: with SMTP id s8mr26556642plp.130.1570384149107;
        Sun, 06 Oct 2019 10:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:24f:: with SMTP id t15ls2357109pje.1.canary-gmail;
 Sun, 06 Oct 2019 10:49:08 -0700 (PDT)
X-Received: by 2002:a17:902:968e:: with SMTP id n14mr18781259plp.339.1570384148282;
        Sun, 06 Oct 2019 10:49:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570384148; cv=none;
        d=google.com; s=arc-20160816;
        b=Nzzh/vy8x5VP60a4pKyI2DdDtqoVgBzVl4bjf7zYkYJmoWc0Xr2qPZ3gwjZtwiCjy5
         WNf0Hrz04LB5Y/NZ0GTjhwl8RNcICLB+f1RHwkp8rqI6Op1JGsMs9tkhhY8xz0CAFP0S
         LlCQ3xu7LwWp3iWaHXnDsvTeI3Sio02n0yRycCotbedeYWL/GDxzeexaZVLLICrYKQGi
         Fn0PsP0lTd6NwEOpQ89QBIp8pWMEv089kxOkUXb+kBngHJxqLkImSYnWxmdltHsU/0ju
         VCZ7cNHCAnWN6+EA/Ytj3zK4LTfHbc+THT/0aNgx842t4pFfSwwwYvvZ7QG0WGUJChGA
         mSrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=IH8R0EWscaCUu4EQNGMJMsn+S1tR3pku7F4Cx8E/RGQ=;
        b=xfjYfUn7i/9G6IflruoeImeuRVrM9u++TGt7OJysgPQv9UYxV80vHtaUm+uAmRXRXs
         /k7vl98ojz2YOmkszmYuT7XRYe1yOp6m484l4sLTjIwc+/bWFrERtxFEfpdlpF53eSof
         5aYfvwLe6ogDVjUXdIxxfpkoC6eQrRmJ5KGIM+88qcVJ0WFa996DWEsv+JSRJRR6Pee3
         wSgnBVf+20r+tQ1SyUJrhiI7slA6yse5zDq9Lt4bXFCdqgnLx96YCat6ZH8E3B8OYGQt
         BteKkqv6V5gA93dyrLa+Yo5th+yEWtYZ2HwNCGZ0mwnj2RiVKVU/kbgzhWQJytSBlrvA
         SUSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g12si1160764pfi.5.2019.10.06.10.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Oct 2019 10:49:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Sun, 06 Oct 2019 17:49:07 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: see_also
Message-ID: <bug-204479-199747-EKQnENczTi@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           See Also|                            |https://bugzilla.kernel.org
                   |                            |/show_bug.cgi?id=205099

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-EKQnENczTi%40https.bugzilla.kernel.org/.
