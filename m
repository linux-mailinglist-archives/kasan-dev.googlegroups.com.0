Return-Path: <kasan-dev+bncBC24VNFHTMIBBC7OU76AKGQEBQFYQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2AC9290C5E
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:39:56 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id e1sf1192078otb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:39:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602877196; cv=pass;
        d=google.com; s=arc-20160816;
        b=jEklVfuT1yUVCZKf/ReR7bQa2JSqWcdaXNHr1qMNWsI+hUChJVnP2KUoGp1IHzTRxF
         HCtH/L2x1zna15lSmjo5nFoqHXAgFUvn2co7hBg0T3i/dEWdnW9z2JZ8O3TnCtflgDTQ
         Q9UfH9tA2XTImbTlZlXc0fqCFQL2At+/8MYDDnh/4aN83n7QQiUaF7ETzbht/4XUMigp
         Yjf8hAefzCVHSsnMIPTolWgURcEnfvht4zqHEKbHgRU3wrfB1skCMqP0znv2dn1njZIC
         Hl0aMBlcRn23fhQRlEJjERg9BRiDHNL1Yk2zpO/0u2pXTpO7Ja939C3aVY6MnBTTmRcK
         WqNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+Nf4mdTpkJQyQOxCAMjeY6KtzvaHJlMfA/yahW/HsVU=;
        b=XsQb9sSHtgDQLlG6lH/y6b1Ah1x1+jrhLBUnJgsKRJxw6dC3RXVaU5UjfXzkIcqomJ
         QKaxVr3so7DsqtWzEaFn6zBE7IyWSvMRdRW1u5nkSGszb9IFNwqgvcKeCE3kN0nvwus+
         RQu74xlHVMuddY1Jt+i0t+7nD+k0ldRHm6UYJfMdE/6ssRyJJ7/LbMNAvCgLKIFfO4A9
         /hHpiePvHRy9gcArqW1bULrQKzUewIdM+5YIBlPq3nNsP4YOQqcsQDlI7KnLtKF7mDOR
         5MXOdTI2v+8Gxbi+34ntYQBehmzAn7esDj/P75TgOuDmHbEB8OzQOifxxCfHCzqTGXip
         wzFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+Nf4mdTpkJQyQOxCAMjeY6KtzvaHJlMfA/yahW/HsVU=;
        b=Kfub02czUtAsqkyJh8o6iLJJ607NYGC0MRqruXZsuOAVLzrNzSIxamzt/e8+neDmEM
         VctjuihQuuqsZDesHDjpZjBDeFGo/EPyFwUfkephUc8CHtsNop01+b+lVX1M8jw1cQ5c
         na+nNQg1RfKWgH1VbMeBUL+/mwn/wI8x7NnsDxj+Vg1v/eoeq9klo9gUogOWCXIqhXrH
         y2kPeid+H4I6N1Xo3bK3ER7/MW/Y7QB1u5z54KDRfSpeSovOyC12ecrzHpEx0KVC6146
         DxmEh12xh+2QNNknuoARfULk2/jcNn8xzyR49aBD/D5ET6LiZjUmDmh+O7LIG90ubERW
         TLXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+Nf4mdTpkJQyQOxCAMjeY6KtzvaHJlMfA/yahW/HsVU=;
        b=Wd0u4IJKiEwln0EqSpuRbkaB7pX08IPSwiD7BIayzwCewBI1yptFm1Shi429jMvHTE
         pM6AlV0WglrFUkxc4fWbNm88x5W16IIcuFSbZd6bUb4cqS67C4N14441zTV1fggcKJbp
         cJfyg+6D76HB5LAibMt9vJf0pj+opf9FNt5rO9WYnmP7BkeyJGCDDGghBxHHGqTg10Rz
         F6ZM8QrshnxZjMSU8J85ahBxKzFLNy7nSjgg05O2+qDbptIXpxUw0oACZFvbM73U4n1k
         CN/AkxxU4vd4GWinPZ1Qg4/MV6X88c3L70RUu+KXYXKBGKtRxVXZMDsAKpoidwaXPYhJ
         5Hkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bnLAJhvUn2UOT1GBYP+XAA62WAwKtRhsJGn2NSzCGai2WaXw4
	jdeHHSS82Ela2OV6QlMRwm4=
X-Google-Smtp-Source: ABdhPJwZpMs6lrGdUV8LJiVicas7UBCnfyKPNX6AuloH+g3eychbmWgj2Lpj+aUoj18FWWIITkiyZQ==
X-Received: by 2002:a9d:4d0f:: with SMTP id n15mr3625303otf.84.1602877195938;
        Fri, 16 Oct 2020 12:39:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:de07:: with SMTP id y7ls221711oot.7.gmail; Fri, 16 Oct
 2020 12:39:55 -0700 (PDT)
X-Received: by 2002:a4a:c54:: with SMTP id n20mr3942885ooe.66.1602877195595;
        Fri, 16 Oct 2020 12:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602877195; cv=none;
        d=google.com; s=arc-20160816;
        b=RXEBVBylXYr4D7vIGoKA4aaLxyIuF2DWwDLECx8l0599JZsx77vqkmIWuQ4mzMJ7sQ
         mCh78NS9+fiUN2EuA9SJcYuz5L3yGko/H0IbFRkxXNjCi5tDSI4hq4hXKUDIxezFuzXB
         0A+so9r0CBUcJx7xALsi10wEdMyCSVEgkhTRv4SmCdZYQjz/QjVvRa0nzE6RQ/uVHq3n
         xPNL7e4FZAR3xRAJEqdiIiXeyntlPMJhunwnDkanXhsIUE37mjI0heCrWQ5aLMN7SJG0
         bA3Fs2CUpPcFgEGbQ3wZO5THDJV1PeNyEXjzyIv8kIeSKkreaoF8fm5WHT0EJA67G4MD
         Yitw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=ouB5xe3zBbz7SAQBmmMvuHH7/NuDQYRPtn+JpW+44K4=;
        b=PT0q7tABqJI+Z0xAz3XvZqhkV88m3VebtYCmHtMAIEy6qf+M1XvnW+48dNEKhUN4f6
         JCgyafWJCjVcLRPncw6Ypsc9PX0VkAaS8BcUXPqDvnNO/7agTPKkN047B7VQ7Yn2Ne7I
         3/sBwLBjl2LzzpGrCIRxW1IB3H8D+HcSj1yVzmm9zbhAGZPwbl74jNT33+6L5iU9915k
         sVLVAHiPuU3TJNXV46NKDjXfJt7MQzp2cnnHZM5pBChFnqSI/KDJk476/+aMKc9PADSF
         Yz7oCapxs4RM8hB+vWkPEZ32Us6suD6R/6+kdpdWMLQD1kNLjRxz1Kxj88c9KHfQy/TG
         z2Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r6si612097oth.4.2020.10.16.12.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203503] KASAN (tags): add 16-byte aligned tests
Date: Fri, 16 Oct 2020 19:39:54 +0000
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
Message-ID: <bug-203503-199747-LB8aqIH0UL@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203503-199747@https.bugzilla.kernel.org/>
References: <bug-203503-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203503

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Patch #1 merged:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f33a01492a24a276e0bc1c932bcefdb8c1125159

Patch #2 sent: https://lkml.org/lkml/2020/10/16/943

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203503-199747-LB8aqIH0UL%40https.bugzilla.kernel.org/.
