Return-Path: <kasan-dev+bncBAABB6NTTGOQMGQE7XW4F2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id CCFBE6557F6
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 02:46:33 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id ga21-20020a1709070c1500b007c171be7cd7sf4315432ejc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 17:46:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671846393; cv=pass;
        d=google.com; s=arc-20160816;
        b=saQS+4Ei+e3/VyHYfUJJG/ZzSIPPSscXk5S2lyUjeey8SkuO2TAvO0nrIZrSDw6V6V
         T5wUfaUKJkepVl+ep6rXyI1IHj+dCs7TFSPe6LnE8s9u92Z/YDiCgdOgvM8tRBPD2I/d
         ZGh8mj04el9CBBEPI2wS5pTexgBRgrJhHySKeUsSU2RdmVXgrIOYJBiCgtIfQ50mSG2E
         rqKdMVH5PNkeY9pYAhutiU29hVGlCq3cadslx2Y0wJ9hczoyIJ8wGglQ+hqWiywd89gX
         /vnOelczf8MosO4inTQFC7T1mJ1bvBtvZgXlHIizo4WXhqGur4XjJE8geNrW1Lgb6ZUK
         c53g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zEBZ67kFJCZJt38EklBsiznRKCOMo/lovJsmDVrP0jE=;
        b=Wg2Si7XzlZL8xPrDtCbEW0Er/ITAeC7iRpKJtQv4vtcsugXqJ4NWMzXyxVm/N4jVo1
         RQg6wEozlSpPmmmtJfPpHzV6lQXrOM/QdKVFohNjttIiazTfisOYqXAwketYa6Z6uNPo
         MO6Kuv7WkoqEQMWHV11679lPbKLzY0aMSXrAb+9DO6k1aQ4fca+sSJynHAqxxBwPK2Oy
         VfV/WfTGLuLev4cThMz8VNrau+yaSBiAtR3NDJ68a97M5hX+eFNfJJXPRKTzRvDwkkSu
         fwgV9iKs/p13+g0E8iCLGSG6gPBdGo3SUn6H+FDf55p/++PekImRBMCMxQCeQ/Tw7WUh
         Tw4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c9l2220V;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zEBZ67kFJCZJt38EklBsiznRKCOMo/lovJsmDVrP0jE=;
        b=Qlt4gW4ZxVv2SqwUQidcGN2bvctZEcXWdp6YHpDlygsXqUN63fRaWq2o6Z6QDyRp0k
         Nx01cJ5WCIbOhg/h9WbdeVuGpGfZ2CihDrE4v3OvuK+EUAWHOTFUfC16QziHameTpWsg
         aqRZa7eL4jsY+GIzOnk1cHN/FYAv3HpTzSmsmuiF1E+uTQM//PTXDS2FVBiRcmfwCrbj
         7LgAEJWXIWrRjs4JhkJBo1wBCni6HkwBHOkxkYhrJvLnlp1CbrBoG2sk1rKcX/qavu23
         Qf+ifCDyS96igBtZ+xCBREQy7DDZexdfWirfKckV+GQWc5xz3bdWJF8TO9fyp2rKJN/K
         74Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zEBZ67kFJCZJt38EklBsiznRKCOMo/lovJsmDVrP0jE=;
        b=bUXR8wjVxIfJv0iKNT90KHVDg9KopUFdgGa9kS9FK4asItWjGd4SQln5muGn4ZZYn+
         y3KMDqNOqHxb2mYTFRZAiq0pcUxatMrTBcvd5R89bszCFeswPqDXgQhgbgCbFWilYkcv
         3sm5ZTymsMWM6UP1f8dAPuiqMlobovY3iOY3a87YqG+qyXMSOcNVmaDheX0IX8NLYJE/
         Np9bu7v4jxQuA/6av2yBLarXCGiGD5E8+IrTLxyjqvvXrLg3YQ/CZW9Nxvw4aJ76gsNj
         lnlgcZVKLKtgGoNjjfU5KhhNl3rcuF03x5rDr1tu29HcQpcsMdLHYLX8iwFED4xOJC6t
         Bxeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr1kOo12+mO1UEUr913sDsEUF2R9saVuac1NBKSXr6jqHXsgSfP
	JBJiwa8yWudhuleF803bvOA=
X-Google-Smtp-Source: AMrXdXuWPLTyZMxGn3a+aRFf563WaYqjjOKqwy3UoNxikDvi31Sr/MIWdTWvTD6OJ8jFE2eyc4rhHw==
X-Received: by 2002:a50:c90b:0:b0:464:1297:8412 with SMTP id o11-20020a50c90b000000b0046412978412mr1103092edh.50.1671846393421;
        Fri, 23 Dec 2022 17:46:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7141:b0:7c1:6e9c:4a2c with SMTP id
 z1-20020a170906714100b007c16e9c4a2cls3699100ejj.1.-pod-prod-gmail; Fri, 23
 Dec 2022 17:46:32 -0800 (PST)
X-Received: by 2002:a17:907:d68b:b0:7c1:691a:6d2c with SMTP id wf11-20020a170907d68b00b007c1691a6d2cmr12310682ejc.7.1671846392655;
        Fri, 23 Dec 2022 17:46:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671846392; cv=none;
        d=google.com; s=arc-20160816;
        b=M1xA0NMieJOPqJ1Oy9ldv7+FCjQr9ZCW8pPR3l1xqzFq/mX4HYZSxemQNqHIuRWlTT
         6ONAAnG6Z+PH6r89Y/TP/1QCJAuHu/WyRkXljWDP+VRiIlpMQv46VfJCLTK6/0RgZWhS
         2rpHCvI5dmE96d1XDC/iP1ZC58/e+UDPzyhNMGrLuxvF1xPlWSe/rZHmCORT/p2DC6j3
         3JlTfO3/HcjzBIL0XNxTRKHbwX9g7xbC//Y87ZyRH3uFpKODH//9DDRZ83NY+ROgzyYh
         LAooVscfOCjm9sZbZ08JGZ7RR+KSOWGwESD9hG29dU6HscT18KLaY6RwjCPu9kaqHjyU
         tSew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=HFdZ6MeU+7RZUE2LmD53smj9JlLrUUghW8PunCcSUXc=;
        b=w8bQYBKmbcrlTMvzJnRJ3Tgv0OdUw8iiGkMKS45dbZbEe1ueBAlgRNYIhGleWfs5gR
         X/zRZ2xtAZ4YEYUelwZfLon8X722E+/vFlZP8yawiqVtO3NSgqSovdydod0OhXgGIc7p
         fhuVQvnhe2znAkpZ8C9JL6Kb8eWhb4uqQQTImZ0URUhdYH5ywB/fGbduFWC5lXV7IPP7
         KEN7JvoFvZ9R39w5+sos2Ljn8hFI3r+Tdo2I1EeWD1doH/zaVJG/W/unFBfKUOcPdE9i
         VRFKSO/KSbM4O8YmVik4wnTky2KVW55x7T6WOU/PqNJAFtIllo34yyKILuwGzQiby8O+
         Slng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c9l2220V;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id w13-20020a170907270d00b007f20a95ead5si245914ejk.1.2022.12.23.17.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 17:46:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 68F94B820E5
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:46:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 128EAC433D2
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:46:31 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F1A6BC43143; Sat, 24 Dec 2022 01:46:30 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216842] New: KASAN (tags): use stack ring for page_alloc and
 vmalloc
Date: Sat, 24 Dec 2022 01:46:30 +0000
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
Message-ID: <bug-216842-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=c9l2220V;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216842

            Bug ID: 216842
           Summary: KASAN (tags): use stack ring for page_alloc and
                    vmalloc
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

Stack ring allows to find relevant alloc/free stack traces for the tag-based
modes, but it's currently only used by slab allocations.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216842-199747%40https.bugzilla.kernel.org/.
