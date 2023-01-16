Return-Path: <kasan-dev+bncBAABB27MSOPAMGQEHG23WDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA6666B7B3
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 08:02:05 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id k5-20020a170902c40500b001947b539123sf4221498plk.19
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Jan 2023 23:02:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673852523; cv=pass;
        d=google.com; s=arc-20160816;
        b=dTGitdjOKrNegTtqK1kYBwDYtomSrEuYIXoXtVQmX4azu1RKcUDYLJjr0/F3Xi8j0e
         Eq0165uX36laAKchkMGtunLcTbQtSn+hE/fheKUXgHY0cosHe744pJ+UkL5OHTL3tnVw
         UXP0x2h0t6b46kxdwPKY9ZuuXZNii/4ZNyaY/qu8xwolETfYq78xF/NfgmCOq3t1WAg+
         HPkGKyTgZKrsmkko1CYoDl5FTnuAQEtEW5RAErYRcctzjg28XRBMUox2H5UhJ5zwZmDx
         FgNjqwHNDgFgMSA/EaQhakZUv3ZERWjdg2UhKRsK1AMHVu6FLn3vdr/1VhsdDuwoNMIP
         yNSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=OmFwfZ8fTnN31NJjJmZI/gF7Byr8uQsRl73HiThNqNA=;
        b=fPGWmE14QQ1RIcUg7PgWGShfOBTQS0jHDP5VstkI3hn51yIDQytweMQetlr51hZO0B
         XpkYoZSQ6wAhL9SEMGs43ya0nRgTW/RPJH0JFZuILQDcNjGU14S7YgD2DS89G35yd9a2
         rCQC0xm0aHkKdwmoXUWvOmKqIUmVoivf5Mlg9iAR7hydSCddJtwPcvhkg/CdW0KW6GzH
         ZbtzZxkwwCA9L3F5iEldADRkhdB4WWu/2ZbsYgIdkVUkfrcIF/u5/+3uWVfJpHloAw/V
         T9qzXAg7qlhfSSiMTBSG3/yCkjnkuhwXqhRldm4bmbJuBpK4lZsL0wU979NYRKy25vxt
         PG4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KQN++aYV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OmFwfZ8fTnN31NJjJmZI/gF7Byr8uQsRl73HiThNqNA=;
        b=gMIS0t8qFZumrE6t9JykX8sFtK3xPuSuMMDljRgSmBSwaylJR5P6uw1YJc2jXJ71Gc
         v+sbr7lNBCO0FySUlDJpuZNKDOEl02VUnXYYE6dMjacuudvew9GlVKmL9NG5Pvfl/uFu
         haVkeMd25zyD6wwny0jrWPfOiFxw0hP2zJKWabK3YKo9IeFsqlXQjjtG/aYkyvGbwihu
         8OrD/Q3fxTIJYQ2j7sQGfM0fdSU9OQ/S08m8c/uUsAjt7FYdnxKM5poFvY/nMeRpnknn
         mIKxbLKThDVOowrW68Nl5R/UhENSIhAf4svavGJmP2rij5fkfokyGP/epdo1Rsf9dWbp
         kAdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OmFwfZ8fTnN31NJjJmZI/gF7Byr8uQsRl73HiThNqNA=;
        b=gNdaI7uWqN3KU3Hb9CEtTsEJ99KEm3DiGfmRSTa14mo+n0a4Ss1BmltM7GCNmPmq/q
         sAUc/ItK7OhkfSOajTP+YQuvH6lj40diWT9Dd9Y81Z6/FuZv6qFnOsnJreIqLKjiPWYE
         XZ0rGlgq2lH+ACE6QzU/sPz6uSJDTLhuRxvtrGMcM1V+wfPyMt3M6b+TOPYZtc0LZfUx
         p305KtZkz3fw4Vu4CL6vJwM8sqiFCJz7z6qgW9wNckhFDhnOK9MK5WuDD9he7tg3MzBG
         2bk82Thfknxaj8pvSBV/KkMPqV+RTo9FWp1KwIKjifu0WUhYyzcDq/cJe/Nxyeip3OLr
         yrfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko4wyw2hQUgaORtlzT+FQQO1zdr3YO0VBQ1Bs2oyypUUIeAzqZC
	e/IRacJI7jxw+0wna5RKrBk=
X-Google-Smtp-Source: AMrXdXvHYJoPliZwmcA7lvlE6T5rr8gjjowSnYcR18rp05DB62Ov7nQD4dunimhWnYzuUWv08GyyzQ==
X-Received: by 2002:aa7:973b:0:b0:589:76e1:e8a with SMTP id k27-20020aa7973b000000b0058976e10e8amr2070683pfg.49.1673852523622;
        Sun, 15 Jan 2023 23:02:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b88e:b0:226:caf5:8958 with SMTP id
 o14-20020a17090ab88e00b00226caf58958ls12302076pjr.0.-pod-control-gmail; Sun,
 15 Jan 2023 23:02:03 -0800 (PST)
X-Received: by 2002:a17:902:cf42:b0:194:7b3f:ceed with SMTP id e2-20020a170902cf4200b001947b3fceedmr9187829plg.43.1673852523051;
        Sun, 15 Jan 2023 23:02:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673852523; cv=none;
        d=google.com; s=arc-20160816;
        b=T9xhbuFJLGmuJ/oeOC1XHjlGTwUkf4Uc8PcJHI4oc5Kk6J5OT/zcIA4DqtCZq2LnaB
         BHGPIVedusypdxzL3UxpCHbYs39LFUPPhh8hTa4D30U/VM9U8O5WM7DEt/U/sqBSVLPl
         JGuLF9ukSPzSj5CaLxKtkUbPtC95DvVs7K8+bG06JVtm4eSL4kD/GCLxBaGa/8WjY0XB
         3lR8XKiQKU0SKr2J0ClB3nNOHFyWWcm3lCdgkNErJRPnvCTx4OHtLU/ZeLJqyt9ZL8Da
         QPOcS/Ekhy5GqwhL1J13i9XUAZCtb6yJUPNEiiie/7lTBQm44+QNzhWzE2MFCjrXTH74
         ENKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=+3eAiocos3awAGBpwQHYWDfR8OPO08eXHasHT4NFpV0=;
        b=ysGbO6LLE9thsGvnEEMgWciP5gMKecpm0RdGcP5H0YVQ1Xsjna4O43Bx9vEXIHZMiY
         aSP649nrH5gN/mMY71mJjxAp+3B/U3yT1Y/jdhm38PVXYG7ntodJQpXXq/tU+hGFwdDp
         h+ab+XrgcWKMbfIEXxrivMzRrLajWO0GFT/STPWto8LlttYb7BauW+OhnsII8EArouby
         K44wUxTKUut6dIIrggQRoN77yg1Sie2sEZn/ZiHGWlk1BqZekLtGWjpmrTn96Wp3oX08
         T+SxlriEwPd3bm9kxkM4flga3Zr/z3WSxWg+0cQAFmYpZiqia/qD3OnMYdn3cc5BIU+B
         wrhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KQN++aYV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o18-20020a170902d4d200b0019465fac347si1035569plg.3.2023.01.15.23.02.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 15 Jan 2023 23:02:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7192A60ECB
	for <kasan-dev@googlegroups.com>; Mon, 16 Jan 2023 07:02:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D5D6BC433EF
	for <kasan-dev@googlegroups.com>; Mon, 16 Jan 2023 07:02:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B9E47C43142; Mon, 16 Jan 2023 07:02:01 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216905] Kernel won't compile with KASAN
Date: Mon, 16 Jan 2023 07:02:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: nanook@eskimo.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: ANSWERED
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-216905-199747-pi3ROjHKNQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216905-199747@https.bugzilla.kernel.org/>
References: <bug-216905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KQN++aYV;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216905

Robert Dinse (nanook@eskimo.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |ANSWERED

--- Comment #8 from Robert Dinse (nanook@eskimo.com) ---
Since this got around the compile issue, I am closing this ticket.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216905-199747-pi3ROjHKNQ%40https.bugzilla.kernel.org/.
