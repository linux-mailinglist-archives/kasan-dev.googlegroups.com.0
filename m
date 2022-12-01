Return-Path: <kasan-dev+bncBAABBCGBUKOAMGQERWIFKVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D051C63F0AB
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Dec 2022 13:39:37 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id n10-20020a056e02140a00b00302aa23f73fsf1804656ilo.20
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Dec 2022 04:39:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669898376; cv=pass;
        d=google.com; s=arc-20160816;
        b=nvoGeRseVlPVkBRRvZDCPm+L/NHGVM8nDeLsxL+J6um1yef/6ZYu67FpyJzWOTFV8E
         z3yWJSVvaLsFfQVBgCEw+ahsQAkFTirVE1BCISkEdupkgoDS5N6Z/Ar7RRyiX8717ple
         bCmPQ6JXKYao/m/HzzszcZvhS37H7CoQekiwPQECa5SCe9apLpM6qx16wEh9i7BiE94W
         nZB2T3Qxtz3MMf1i4cwMeQQ0B/4AclrQO1DndiPl+8Y3mTQJFgfkhSpAzHbqqb4Kty2k
         JRMF2Fh6wOZOk3+2HhvG8iFwysLMx7Wb40vIiZKwpkgu/ClfGn265SmloCO0XBra3u+1
         Fc5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=v376vwpCpJmSBW5LkeQk11esexuKH/Dft75Jdg6yecs=;
        b=Irw+POMcecmTeTkmmVRi/g9UgB5WT6otORgLmFG6qcSfQHqzNnayFO1JAYoxffcRe6
         aPL7ETf9PaqgzQmoA1kB3NvaAXeFGOCXyx5WWz84JS18o8b2fvrj4p2jxlJFTDFwtHsb
         X9m12JtzLIV5ui3PNc3MYxi7DdDYNmWHpi7PCJdv+H9dBXzDoHBkkd8nj/HZCiuSk6bh
         TxdMo6nt7Jwm+YvliiCAVVq7FgNZzaPc831lMqOZ9lyo9EBFa57voMScbPuDi3+5bTA2
         OQlim8ypDL8g+Hx1WJobFw0cMC8vX0MQb+H3/vsqOdirtdqTkP+RGrq3h5cdd28BjBWn
         TDhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AuohijoG;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v376vwpCpJmSBW5LkeQk11esexuKH/Dft75Jdg6yecs=;
        b=qHHkbk6kEn+r3WdFZJ4SlQh6w+eahMh53lYEs7GWtrwMjCEH/Pcx6tKBDMEh75zDDP
         eo06IE+m5m33wzoT28OBm0Ms1LSlXPOG0ShnjjkolmtpCsVeKMR/4fzDoM4Ye6BssBql
         YSBQEJahrXaIWwj1wyZmdPpInU4aDfBuUK4tgcToNABAD2F6mK4iNSb23p1BBLZ3o+GL
         vmytytaeQHA1ZtzdY9/8JudzUy5rGNk2J2Kj+Ctx0bWQJw2dM6+0MgXPsOIBxP6tQIyP
         wJSM7hnxwkwEua8cH+r4kNFeEyyXtD/2DlA1gtI/e7wD8wILSOddeu1sjWoPDNHrUo7k
         MP3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v376vwpCpJmSBW5LkeQk11esexuKH/Dft75Jdg6yecs=;
        b=K53FrgMlTXVswk/uygsXcqUkbFk6cK/QQmrjiTAkmW3M1CNAzYshxTNuN8cMqif91A
         TpIeI28sV8Z18Xkz1SKYor7dNqmK/guQ9bZ4NCNSqX0vghO4cAmBErz8kjl1r3h6T86Q
         rc69gZp3LLNS7+eCqQEyCqkuwq2W6S+blwXfwYdax04GNG+wXdF694e4adBfM/p1wJc6
         z1EUJcjFR5YxniKQTyLHRJOFhFVp5DuZEvor3NqdfMz76PaINP/BJ+P4YSY9upJVYBbT
         68NmtJRxogbvv0hu4woLX/IBygajJpZtQ/ieXTlLv0GrUcgvmLdFgF0b+ZaGSXSKkIpD
         mIgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnZm533RBHNllq8pEyv4FNQy3hc9QSsfDaPN4Z8FsBjaQ53EqEx
	cE/QfnurHAv7QunpvTWU+nk=
X-Google-Smtp-Source: AA0mqf55dSYYo48KIcWSEfyd2SZF4LAHMyoGSTrzKcXR8/u9d2oBIhwhnXnRfkm2b03M2nkjBiEy+A==
X-Received: by 2002:a5d:8492:0:b0:6df:bdc1:2421 with SMTP id t18-20020a5d8492000000b006dfbdc12421mr4258685iom.116.1669898376249;
        Thu, 01 Dec 2022 04:39:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8d16:0:b0:6da:9bee:b03e with SMTP id p22-20020a5d8d16000000b006da9beeb03els176098ioj.2.-pod-prod-gmail;
 Thu, 01 Dec 2022 04:39:35 -0800 (PST)
X-Received: by 2002:a5d:8492:0:b0:6df:bdc1:2421 with SMTP id t18-20020a5d8492000000b006dfbdc12421mr4258681iom.116.1669898375860;
        Thu, 01 Dec 2022 04:39:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669898375; cv=none;
        d=google.com; s=arc-20160816;
        b=Balj3aSTBSjP28pCZTpACDMg+gvQXeB9+CErX8IKsHLWWgTAYkMM/WfPL/7Tp6ep+z
         LFqOKkJlIBzrNiH0gaW69e4j6d32rT1+5tjERSyWw1lEnCSFDFEhfWiML6Nu4MFUAhqS
         GQcTYe9F1qpm8Me4GZiMY/5uQfcEEdPBJd5+nAddVWL4z0SdxxfHYxo5fLH//TZRhE0R
         RoJSU8ztQIucw1/HJHqp/ftTdd9FCqj2l0ivzaROaBlL7+RqLxLm2Rrr6547RCEZfHGD
         glZE7XPgWbwsesoFEYOWYenxHdZVqIux8mNWHUwi2GYSLR9Zuk5k2cnL7xcbAgnMP/Be
         I2uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=bdIQW7KeVHjLzu36DIDsCU7GsT6cBJo/0Tn6xlN9HSw=;
        b=0iP2w+yrlD9yzCptpyZdlp1xC8/zynA6gnh07M58qKOcDY4F7ns5m8e233B5u7sYaV
         PhzjzHQ1Nu5mB2Yodb3SQOsjzVZDFEhVzZt0rAI1NNtq/Lqo48Vjx/ErhHH7usYb4vHM
         FvlCOm6VBLSHQrx+dWbF2ddQHQ8X5zWy8SyodcWlvgSFH5Mwu3U24S1lyx7Ml4TuMn4H
         BjzzaL/UoT0EL8f54ajGYNo5waRJg4Uq9Vyg293YFjE7A8FiVP7WK5Y8OrS7lRPe8EFn
         9IEyV2Xht4K3rK0mX31hjXF3Jf4yBuPKlr+sfYmZ0uDkas97gKUCOQZurWvsiGh3QprK
         jokg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AuohijoG;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id f10-20020a056e020b4a00b00302bbaab7fcsi204570ilu.4.2022.12.01.04.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Dec 2022 04:39:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7AEB361FDB
	for <kasan-dev@googlegroups.com>; Thu,  1 Dec 2022 12:39:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E0E13C433C1
	for <kasan-dev@googlegroups.com>; Thu,  1 Dec 2022 12:39:34 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 86A3FC433E4; Thu,  1 Dec 2022 12:39:34 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216762] New: KASAN: more reliably detect page OOBs
Date: Thu, 01 Dec 2022 12:39:33 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216762-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AuohijoG;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216762

            Bug ID: 216762
           Summary: KASAN: more reliably detect page OOBs
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Page allocations don't have redzones. So when we are checking shadow for OOB
accesses (in particular, memset/cpy) we can miss OOB if the next page happens
to be allocated (for kernel/user/pagecache).

As the result such OOBs can lead to silent memory corruptions, which are very
expensive to debug.

I think it's an overkill to add additional checks for normal memory accesses,
but for memory_is_poisoned_n (memset/cpy) we could well check that all accessed
pages belong to the same allocation:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/generic.c?id=04aa64375f48a5d430b5550d9271f8428883e550#n123

Simiarly to how copy_to/from_user checks that the access does not cross object
boundaries.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216762-199747%40https.bugzilla.kernel.org/.
