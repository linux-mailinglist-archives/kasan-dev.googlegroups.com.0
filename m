Return-Path: <kasan-dev+bncBC24VNFHTMIBBJVSTH2QKGQEWQS75DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D05F71B95A8
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 06:01:43 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id w65sf1753792ilk.14
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Apr 2020 21:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587960102; cv=pass;
        d=google.com; s=arc-20160816;
        b=fziOkUyKNcXr2BBsGPbBG3cew7VdgnnujA/+bz7pzah2/+WIwxUoSEiVwJ6G8CN7Ea
         UKloKZdfB5MvYz1Mk9feRLELh/Tv7860776jTBeOUxuE5tDVY2T6Zv+xRT3BCg25Jfxj
         8pNSSADKzyz/ljKzaetnDbLrIKiceGvTvD53denSZipQiH8EPx8yBrloSswFHDyGuaB5
         c8odK5x5mnbGdG3g2xphlw9ZZuNlUChhcxE3MCE4Wroel2MSmSTdvWM84RINewwCpINo
         5mhvmH9vx7fcUoa1kDrb21jpOuEJu5rApFrw1qXl20xHrAa3Y0M/MCzODPbXdhNRYfdG
         mang==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=xn0werNaZ6Ah4V3kqrJdrTxij4y93gk0hXqCjR4wG6w=;
        b=eLu+J/zU6Uay50MqpCkML2FWcwMHw0rb5BHyuhmDlNeXOtTqnPS55j+9Bx5gvGw5xH
         6azwGjSgl/xCI7vrzgqnNyJeZGDfattQFPDCxMRSK8NyxmsHimvxPfFtc7d1SOBh5kmi
         JCl0yC0Cn9MKSuCEG8potBWHQ2R/CTUIR5fi2dEv/m+XyrZBaablHCFxqKhMgYqxpGc4
         5waLLEYuJ7uSD2vAXWAzaR/TJ8CLn0fmCIxvoOEM+ZqYLNhS0I82Y6DkIaQDIuYa/zwW
         sJjboFU+I1KYNMubGNh8bwn4rnZYUeYM+vM4kCawKNpj7hHGPlEUjJnoNNppg8qlOSWK
         TwRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ke3m=6l=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ke3m=6L=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xn0werNaZ6Ah4V3kqrJdrTxij4y93gk0hXqCjR4wG6w=;
        b=Xs+WO4cy6HpzB90/jXBGCPyXreu5qbc0jy4rC/IwzqnvO4o3a2MIVM3inkHzTYMWkf
         tbdFfA7lDVBubR8iJHVcw85VUc6XgZWnLX/t0bTa7pvktq7H9nNKT93QZftTEJ9Yew/y
         s3xprq2/xIVkiyujnDjkwevFhvWyN6XgqcOm5P7z6TEjwSFTdwFqU4iQ+lStZGFw/3Su
         WTh0XMhw29orwtWkqnFJnSvzJrSN8i8oLG0ky//qknYd1hDVzFA4DckEWx4Zg1A+F3ai
         6z6iILWBVBBMzgnveXY6FSUenQIq4KLGvLJsp0aGCGbudqDGaXEkLYdzTdimG5ivzrSM
         oSbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xn0werNaZ6Ah4V3kqrJdrTxij4y93gk0hXqCjR4wG6w=;
        b=omJoWD2ypIyRzv+zkD3I3QdXbfP8XDVO/rDEv/aYslJZfkwnM0vsgx63ElfJvjVAjz
         0Nsl3bBuoia/0A3tmc5JNnyOnMISLr1waVD6DWnG0xAj2gq85/KJ589jHk+OcQHTafdr
         C/khZ8c2aGFSN2bMkXAWt5mhb6LQWoeyfR9LrAgJMYPuec7aR0luG6vawjB1vud7IvhM
         1y3ajXABK5lsWkgw84AANNCpvfLYxPcDh6KRX07+112Q8BHvvi+4lDlYM5XrKLQyrxSv
         GMZBzgv744VqJ1XkrzrNmggJV0OoMS2SjIVO4UKSkvirQAm/JJybV4OnK5i1Lfkmf313
         EC9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYZk6BY6lhuDwbXiKdXZh3xg6A6oMK6vPN3GQx2xwS1RjuZBQdX
	4kA/+99o5uD1pbkiefQolh8=
X-Google-Smtp-Source: APiQypLkkfvcYSXGLzQbHFvDEyB2k++vdjIvK9rhE16f3bX8d+0aijch/b5onZMapzghpmYeGg6/RA==
X-Received: by 2002:a92:c794:: with SMTP id c20mr19534847ilk.273.1587960102574;
        Sun, 26 Apr 2020 21:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:5244:: with SMTP id d65ls4339512jab.3.gmail; Sun, 26 Apr
 2020 21:01:42 -0700 (PDT)
X-Received: by 2002:a02:cc19:: with SMTP id n25mr18124203jap.107.1587960101906;
        Sun, 26 Apr 2020 21:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587960101; cv=none;
        d=google.com; s=arc-20160816;
        b=GVHQOyiW0QmrWsOwF3W3m/+Kr3mBqDldzgd5R7DPNl6H4kZQhJVQZQWdZslkQnH7pV
         jODyPbocJLnqb+owGeAoRAjShjkfDo0vgCDS2RPe5dV22hm3qIiJUcaEUWS/uwuQc9aJ
         14jqzPyC5QBjm0OOcdFbyC7wWyrlCRMokmQiapVmFF7vTMiC+AfrMsq8dNhv3glVLcHx
         qZSqEoYGIEOg8jWSuOdPLmCV8evm6Z0pwkt1v8TXpTGq9NQqzSMGxcniYFJdNrmGekoM
         OLQKbqWSVcV/HbWchWMW5EhAnAzxyqb258EOoaLlKe+Q9vOfZba4XkSpJo+IDULf0cyh
         MYbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=TmSdy7GAVd3zul56Rgpaql0rLlKdpvyoDSbLkf4r2B8=;
        b=ObEWnGggdVNBSW8kbD5uwe1f5cC32cCDkeCaLhFRB8fG2fPyiqzJZxvb9hmPjC9VlR
         ilbow/dFqNreRb8KvOoaHHwLujBsEJpDXfnTHTT65m3Sp2tK0jeBOGPdGyioz9dIlu03
         3Bi0e52adOritDVkIb7uli8HIbPK1ebML09idE8JsKLaj0Or757N/XNyKGXzBD4OYeuj
         wMjK57qcZkPOp0WfM3c1eee6qrQMURpqfYQ9IdJXrwPdepIdv3FmCd7/rUctxqT5t693
         zNX1R1XLAd94qUXzidCrVrO+nb32AIHbwq3aall6R5D3QjdBcmFTWm6qITxvNeD5HraE
         BfaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ke3m=6l=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ke3m=6L=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g17si1193262ioe.0.2020.04.26.21.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Apr 2020 21:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ke3m=6l=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Mon, 27 Apr 2020 04:01:41 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-wbSgrsTyUf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ke3m=6l=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ke3m=6L=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #7 from Walter Wu (walter-zh.wu@mediatek.com) ---
Thank you for good suggestion. It seems to be a working solution, we will try
to implement it. 

Thanks

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-wbSgrsTyUf%40https.bugzilla.kernel.org/.
