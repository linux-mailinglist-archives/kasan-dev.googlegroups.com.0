Return-Path: <kasan-dev+bncBAABBAU5SWNQMGQE5FKO34Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 76FBD619EF9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 18:40:19 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id v188-20020a1cacc5000000b003cf76c4ae66sf4563470wme.7
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 10:40:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667583619; cv=pass;
        d=google.com; s=arc-20160816;
        b=cVDcLh+OwSjINpFWjJynCjU7+ikXKElOjp5wCIWDtKV5BytwMvILMGkphA/1r99vYd
         dxjrZwhWyBYzBJjArLqGjOtYUnRzT+HN5TOlMsdBM94OFbcN3pQ6Nm+lGB0kOJZ8Q8jS
         VmgwL1qFjhrqTLUx1zm7gNw6qNslfaoMGLZcP6OhYBQR6gy+OvpkzuIg0eDs+TGJenY/
         HXxoBxIto6aeu7Kw8SRpB+675NVM8GZ4kcnHGyM2spSz3FS+RZNNbC+vEkq124xZrfS0
         u61d/A4mTpNc3O9/yLL0iucYgg7reAZpB853+j+EjfwowSpZ0HsnYV2Q8/QOXOq6qLRf
         l78Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=2VeB19zDGXFmXiqu1ODV1/Uaj+Yt2HKtBzTyzvfYe/c=;
        b=rstTA2n/Ofh/YsrNCWBJ6X0mlJTvKBrQppq8LmedbFL6QIn7AH2uNoZsTqji7rQ50j
         0xvmDPta4oNAb4GlaFoEUIvivdmFS30mV1r81uiYBDJzCdWskfPe9mncVYLbh/oV1iMo
         puK3MrfJDqfvd5LaaqG8EJv5ZCKdw9KD09SfaQsv45hGEDwPa8sANTjrR/ls2Pg+I5X2
         kwlfkpgz5SLfa0VI9esoh69fBqkQhaR2EhTwG3bkS5zFt5ObJc9+U1RBJFIuvTM0HTxt
         /kTH0o7e1eIHQ2bFRktmvueq9/bGWcA2rxBf0iVw3jxLZtT5zTrOqGIjc5oOXGzJkZkn
         tA1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H33MfAkH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2VeB19zDGXFmXiqu1ODV1/Uaj+Yt2HKtBzTyzvfYe/c=;
        b=fFkZ2hfRZHHECOrb8G+egjCP0MyLCp+f571VuoL4lF6u7dlHR1O9CvMYFFdiz0eS1p
         TsdjjgjNrZ2cGh8qbfyOVWtemOraFuOifno4ynr/fG4kuPNDbcsfCaZwrY2djpCs5JbF
         ZlPqbi9/MyC68fMm3EWVyz6tWtGi8AZnk1t5MII2dImx1iiWF4lV1wD4momoVy0P8gvP
         2oVFEaljrfj6nGLo62/7nNjML+TjYlRTlp1pFuuU4o32CD6uqC7uybFehHlbT/jCD6lU
         e61VYilMvN2nR0I8cjZDbcBlBh8EMePq74tCsbCv+/F490rJV5iap1Kcjir50Im9Zp+6
         +uug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2VeB19zDGXFmXiqu1ODV1/Uaj+Yt2HKtBzTyzvfYe/c=;
        b=W74u3L76HbYvV3PUSiiuFQ1D6CFIg7oeMt1i22UEJpYtR/EgIQdjtMCwh6iRZQNC6+
         un65Rm4Vbd9ceQ93xhjvEcdqfdjznLfn5pvJtbNVKMmv6I8O6puCegzOOt9CE16aqiOB
         faExwTjf7/9uCApylCehTS9Qia+272oxSEeqifQjXJ/jkFKsyuzLL6QtK3GxYe6IhTbV
         r3bd+A6E0TxiU97tYNhXPtV2pPmsIY+bjkbl/Eyh6EVAHz4PHEUdiWNP8Ou9Qyc8rkfX
         uveFCLSuX2AocuJqScjMepnqO5/ZWMZG2YBJ+ZV7tDBM3A+svZRc2RYnd3RePXJ0RVES
         L4lQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3FCu9UQ6YygDVh0akwPdZ40jm4ivAAz6t1oKbS7noOGHoyzFbu
	B3NPltPhwBJcdv+BQydVLwM=
X-Google-Smtp-Source: AMsMyM5Y7LxC+k7InRlLZSMxiIh7xFpoSJeQL3GonP7l7jrKAdKAaRGblOC3MIXxf0PAXeYASjRDFQ==
X-Received: by 2002:a05:600c:1609:b0:3cf:4dc4:5a99 with SMTP id m9-20020a05600c160900b003cf4dc45a99mr24874750wmn.67.1667583618840;
        Fri, 04 Nov 2022 10:40:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1caa:b0:3a8:3c9f:7e90 with SMTP id
 k42-20020a05600c1caa00b003a83c9f7e90ls4598108wms.1.-pod-canary-gmail; Fri, 04
 Nov 2022 10:40:18 -0700 (PDT)
X-Received: by 2002:a05:600c:3c82:b0:3b5:60a6:c80f with SMTP id bg2-20020a05600c3c8200b003b560a6c80fmr24966050wmb.199.1667583617998;
        Fri, 04 Nov 2022 10:40:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667583617; cv=none;
        d=google.com; s=arc-20160816;
        b=YUeKX0gPErN6S45eWJ4KZaKGOX+uQbFywKknKazzSDAdnqFQkkl2z83+1TrxC9OnqP
         mx+OO31+/QpPYJYczvu4iFenT9udI4m2YB0Akj42fhNnH7aDiDIAq0Pba9u5xZfT2ilt
         d3TgFKsokBy15KvzlkcJf2eWxQQ2Q8X9WAd6IDFn3f3H1wkiyIOEl7bNm8u1zWTTVrmW
         ihIqLLRe9kaU8QYvahJuqyLMfaCNAzV0E3XgmueiEbE8aLPPEiclaDa26NzExoZB++jW
         OBFtEJQNIs9VohZClgbpmJRvMxQUa8iSaq7OY0RamoLVxZEKaLRu3w7QM1H2FhV3yWLf
         2hdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=RKlEQo2dPRhouQu76mQ/mUNtGVGs5yscgvhherfVqz0=;
        b=vur9FEiED4LSW9BOUD8iqXtu/E8y+Yjc68dD/bXVvvl3AyGpxxat53jVPGwzUpaIWp
         4HBL1rJi8CC1V8MeSZZMu6dJi5/hFTurKHqXChOIgR7ZGzL7iY6fm9zlhIKdTHHFhSK6
         bUOVtSS+pcYfxKsrukSDJD+O7TD9XMC/H2/w++CchvT6WLPViCRBIE7bnIJfnEchs6hn
         sZqc6JEUgDqEC4bNq90ZteaRhcxua60u8kq/ovduIMSaQyXGAfB7JOxirbyh1qYZzWyJ
         qzKH0Uny9UvBYj/oQ9xCmLDH1oQ23X43okorkNElXUVYncp00ZD/HxhKX2wPN5rp2pbO
         yj5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H33MfAkH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id n7-20020a1c2707000000b003cf992fa3ccsi91692wmn.2.2022.11.04.10.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 10:40:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8C8E7B82CD4
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:40:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 36B0BC433C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:40:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 19B68C433E4; Fri,  4 Nov 2022 17:40:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216661] New: fail-nth: support multiple failures
Date: Fri, 04 Nov 2022 17:40:15 +0000
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
Message-ID: <bug-216661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H33MfAkH;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216661

            Bug ID: 216661
           Summary: fail-nth: support multiple failures
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

Some functions try to allocate with GFP_ATOMIC and if it fails retry the
allocation with GFP_KERNEL. Such allocations cannot be failed by the current
fail-nth since it fails only 1 allocation, so the second one succeeds.

We could support arming fail-nth for several allocations, e.g. "5,7", or
"5-100", or even "3,6,8-12,15". But probably does not make sense to support it
in all generality if it makes the implementation too complex.

Reported-by: Jason Gunthorpe <jgg@nvidia.com>
Link: https://lore.kernel.org/all/Y2RbCUdEY2syxRLW@nvidia.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216661-199747%40https.bugzilla.kernel.org/.
