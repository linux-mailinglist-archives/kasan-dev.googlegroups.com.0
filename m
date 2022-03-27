Return-Path: <kasan-dev+bncBAABBM7SQGJAMGQEJ5ZURJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 745FA4E883D
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:48:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id s24-20020a2e98d8000000b00249800e5b87sf4711232ljj.22
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:48:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648392500; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hq7mS12LeiDXklgAxUQPtg9/n8tWxF7iE++FZ1Npb+pelvoSdU79Ck3GvlOkQfAnoh
         75Vc6K8z7Q3BZlC0jMpjO0Gzacct0f+oY3+E0tpTfT4m88WH65vpHcyUnTT0NFtdW8qG
         imCECORU6whzOgN9lMJZjlLXbP8UqevLNY+NEFHc4kOEHKR6eCacc2PAcotBhfNlnB+i
         yqU+OBMTpgN9WdLPgV2Y0gZ3axsB7QQelxcX6bKjgwhuL45xYUZg4waAkzXUIzqRBXoO
         o+McO0GN4WGtW4BmZ3IIEuaEYG1rPoboxPhZa3ETgjZz10FK187dP1TAWxbsPmQoo9hH
         8WzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=cOaNHx6uZlIG24UzMudxaHiBUHjuwJ0yz7fbe4MBB70=;
        b=lZn+dCmog2dcHby27m+lkJL78xci+6O8wjNy2lzooX/fVtgpP3sfC9NVdHT+MEDpTM
         iv31cftaungeVB4n+khurCi7iWQ0eT4LCTVXaurtsg7HeZEKUQCiEMy8pDW8GPtW6zxA
         LArkCqn4VJjUS/xCZkW8sAFHhKRJqBQvAqb+FSdrpnLB6RuWJ7pBHpwHzKAPiEJwSi0v
         Bl73uYlXeIFIIBQ7ECVPisfmCZI7uPBicoElu8lsCEBOqLSrQp7Qys6g5jHTmg5XD08G
         y+zvIHFjcg8IE3YgVgo24OaMar1FryhqOS5eFxSEIsQN6hfTIm9Z4I+jEn7UI3Iwykcr
         HwdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PSdHfcaT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cOaNHx6uZlIG24UzMudxaHiBUHjuwJ0yz7fbe4MBB70=;
        b=iAzgYunIV3yTw1ltYiGwkLP8MVnwk0fTVYyLFCJT2hc/gl8dpZNN6R5t0v0/FDOeXn
         l1hX7qJlH14pyGr+2SKgNB4oyIrRjTh2bzv2r5QQkPqE1IMGPqltz+4NE072GqLLuN2t
         bnz+/kH4SKKxgxWSteuT/3GuOZMfyBXruuhsPCAaTOurTH1ZCJdB5FI2HhKRGt7MS6v4
         iy+QFqKWi/HhYBRajtNyyHuYa96S2roYKuZg/2+9v12IFE2WxliBWllvTvqrx9FLpJ2Q
         d4LTk92lLZVp179kgjGx1SPQAHOKe0zacw1pEgQncCDRVLUpCE52dTy5dyyZKwFdusrf
         c2cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cOaNHx6uZlIG24UzMudxaHiBUHjuwJ0yz7fbe4MBB70=;
        b=xUzg6/z+SIeZJXg6FNvIlGYprk/sb2NU/Y1kEEd9YEmvBt9Uj73YRMwuVyog/vaLwG
         5RgVFua4XEJ3eUFs8NU4jEvdQsWUh2XGY2hv+qnS0QBIqc7ETbrZYF20TYWl/JTc/OCp
         xUShmkXs8qho3XUKgT0gOUcb+SIEZfOjLce68GmnmMJLNDcXfB2o4lOLOyOcAAHug+VF
         nYtUzanPxBFi4xBUTqmc9PKFd77R5lxpA1PZbA1XoZ/AE5vYsn5aFcD85nDf358vGBUc
         0xAr4+gZHDYJ9atbV9tdtuE2R5mJ8Y+kZu/IhHjIqwDLMRxiu/mO89xik8pv+0GU878H
         ocUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mYx443wAJqrA4Sx/NafmNuLRj3sR3wOfJDOAA94gB1DxIEjb0
	6sLn48u+8R4YPhb2ueJDJ60=
X-Google-Smtp-Source: ABdhPJzl/XulqyT2nn8Tk21SuJyCZwpAlpL28acIPnLjUXGBevbSfW5utDltKBlKDUcExOH7oJ8QZg==
X-Received: by 2002:a05:651c:150a:b0:249:a0b1:2e15 with SMTP id e10-20020a05651c150a00b00249a0b12e15mr16509360ljf.182.1648392500041;
        Sun, 27 Mar 2022 07:48:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9983:0:b0:249:7c7a:28d8 with SMTP id w3-20020a2e9983000000b002497c7a28d8ls706359lji.3.gmail;
 Sun, 27 Mar 2022 07:48:19 -0700 (PDT)
X-Received: by 2002:a2e:a16e:0:b0:249:388a:313b with SMTP id u14-20020a2ea16e000000b00249388a313bmr16441090ljl.446.1648392499184;
        Sun, 27 Mar 2022 07:48:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648392499; cv=none;
        d=google.com; s=arc-20160816;
        b=Ljm3PwRpZMV1ghdqaQ5giyKLvUxqslJcdNYx9JuruybKeLrgCa6RTjgV6Fwll7gfrZ
         gkoCim0taxEeAW9k8rDQanHUgOxXdK92Xn951tUxaqH8DT+tKmFAhOUBdIi6ScRoIvr3
         XM2GoCQGqQC0Sj8vNkYZHBzsWiWrNIGVnKhq67wJ/KqAm4deehdeKaMRyJf4JpH836C+
         SQfrJtA2r4st3Qe1Q3B6Pz8DcbyPaKMesziJOas5FHlPMojlR6cRKoiktlfrcGjkmXm4
         UujSteg85hXpsq4Xe4l/U4ZH98NdzZIS70mLHw0uH/AHLHNVMjLRmYL2gKnC5xWkwGvu
         chAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=7ZeO1peVexmFmP/9fQUwctTzAbX+/eprOWMuaIjouUU=;
        b=T2j3TWaOdBwT9nTS++E8mfXT52bUW2hUUuRzimk8rEJGGcZ2MNq9esl195yfKWRuNy
         Wfe4VVKDlLk9TytHz+fhyaTgk6VL45+gzwnRq52bnbdVEhuffQTXGjqOmxaV/Xxnpp1R
         rWwEZG5t2F1NsvmoCdg8Ylobh2u2Ss7b3BGjHn60APODljEPbWo4SxogXVoPIFIhMG+g
         KzMnuYk0aWHYvoj8j+Bsw+VOeOHrM6BIPnewol4+H0fYAsyTFBuzPhXRdVouM8hKcH5Y
         sYvasxlNa883YVcRO8m1VZWKtc8UvWx9gwFRcDmxm5e4buJDiZqqWNaUrWzZxMkAlcVZ
         q8/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PSdHfcaT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p1-20020ac24ec1000000b0044a984833cesi24769lfr.7.2022.03.27.07.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:48:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9BC5EB80C6A
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:48:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 409AEC340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:48:17 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 24F6CC05FD4; Sun, 27 Mar 2022 14:48:17 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215756] New: KASAN: filter unnecessary stack frames in reports
Date: Sun, 27 Mar 2022 14:48:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-215756-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PSdHfcaT;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=215756

            Bug ID: 215756
           Summary: KASAN: filter unnecessary stack frames in reports
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Filter out KASAN-related stack frames in reports like KCSAN does [1].

[1] https://elixir.bootlin.com/linux/v5.17/source/kernel/kcsan/report.c#L277

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215756-199747%40https.bugzilla.kernel.org/.
