Return-Path: <kasan-dev+bncBC24VNFHTMIBBY76TWBAMGQEVEWPCWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 969BA3327F7
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 15:00:04 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id p71sf3816425vke.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 06:00:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615298403; cv=pass;
        d=google.com; s=arc-20160816;
        b=xQcmjbi4xEw4QEkNR5+oIXTkBU/OMj4AuvhzDkPIp5QO01LpN+yNpSPjaOPjIcrMcT
         IWcrooiUamu9uzm9k6nljOWXdxMvOwZ8RCiJx4IF8tTGpv1CvqFYVLJLXZpyxNMU1j85
         9ZCOidSaZp9XNWahuwqYGzQfbP/o7RNTf/Utdi9zyiyFYfA4jK0DK88GR+eTeqdWmqk8
         DiQh7hyQsmHRCCPnlTU+lmzPDlfd1oBhEJA7WnfJZDLYJj/xphYN3iiVbelofg0CoAFc
         7dzSTsu/1tn1n2uzaC1PZSgbiVpUSvqJN70GBEdOtN3UHElXDAY68eN6vxoEZiPeP3Qo
         DP6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=3OAZg2+KCR0ogPZGyEhkPXs6DS25Us618nCQJKFYuco=;
        b=QWeCuGOcWzAL4eWszMN9O893Un5N9b7Jgy02C1fc7I0IGHxCInwgjtNrByGWdq022R
         vWqMVR/RqDy+201+w5i5tUm1ri/LaF2ESTmutMvlqUU2TyE3xnnxLjUtLw6hKHjoTRju
         RCNDaQnw16IiAlFzHLrtLDpchmdhtTMLzzwpP4EJB/QYcoAoCQMT4ex9QVymE+IPUK27
         08atbaWJvK5pVQ9uPztkRdygJD41Q+n9q7PwV3LnUmkJBtgFQfa3uQZkQyOHN5Ej8pk0
         eRG8eGAlQ3uJIKe8hrZUXpSL3mee0zNuRx38XWxa0zwM/gFC361TU0N7JAWcNevyyqjw
         A6yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QGveW9bD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3OAZg2+KCR0ogPZGyEhkPXs6DS25Us618nCQJKFYuco=;
        b=aoqx+3caSxJIuRrfvoKcDZxzO9xGIo2U1zSi5BGOdi7bp8chp4c3C8/Xmu5cX8/fZ2
         ZSGvD5jNTdMKGAoxEGJlPTzLoRxwFJTmn6iTLGx9fWEoVOxm3gSSN6DV0uLWI0+Lk0c0
         FMinbkxy46ygijo1Q3Psw05uVR30ScWVZfshpEaaleXCoCYvhrmwEekDklLE1U3O41iM
         w69tauWICf7KBYXem/GTKvTWq/YNxES/C8Lv5iiRzSddKvXUUF1YgwV29Zl9l3nREBlf
         +mBafUsEDq0gNWEkzzOtXhuSD0rjDfWGOQwnV/akcgNQAogxFL1snav0syeohMdSCA3o
         VZCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3OAZg2+KCR0ogPZGyEhkPXs6DS25Us618nCQJKFYuco=;
        b=TMByzdqn/NL6MMkefOAcdFuo1NjBnFO0xogU5Qsj6DCtm8eWEL+zQug5MfJrLppGah
         pFYaRIhoY7N1iT4zMw6kXeJOnxMpx5jqk0DaoxV5fkubonLR+DIPnvdTgq03mlahcEvY
         lH9q3KhRXJIq/51dTp0hStEleZcZPYedBjtmL9kvslwwyTkCyQQe94MGOBkIyxyNlVtr
         KmnxGtlgAurxUUSkEQjLoDdrEptDKna9e49MsP3kzCTCqMd6t+KxpAtIEGxAEtJ8x4y+
         dAoHF8mudBkpC3tKljalKzUn8b8aw3b804y5yuoMBVFWeLSbYoNMZ0IdMp4Y0fQ5+Zdq
         bzEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UgsHs75Y6Ip+FE86/jVc7A46WkcAnWieAWTG7xXYEVZscxoVn
	TPjuEm2kTpOyqNiqsBDaCWg=
X-Google-Smtp-Source: ABdhPJwptBG4fXXUauD0bNnw/quX2dBWN+cyqDPpHLeyRcwFlokqLiFXd1fR+RO73e55YHOhSJYODA==
X-Received: by 2002:a9f:374d:: with SMTP id a13mr15884182uae.122.1615298403600;
        Tue, 09 Mar 2021 06:00:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:268b:: with SMTP id m133ls1094241vkm.6.gmail; Tue, 09
 Mar 2021 06:00:03 -0800 (PST)
X-Received: by 2002:a1f:2f44:: with SMTP id v65mr4864934vkv.4.1615298402923;
        Tue, 09 Mar 2021 06:00:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615298402; cv=none;
        d=google.com; s=arc-20160816;
        b=mhsMyN2MyhY7xYBo0M2tPtbyH14sxA2PUyrS2183EXqIMxxpWUqRd0Pela14hiTIUj
         71z2Pj0FsPhxVhl5ushQ77OfFIJJgQhLGT/+8IfBdxZy5CdMq6OEGk/9iznoTXqdt966
         8bmoHGyIhNAa9pxeKzNUM2GBzRhZThy2Zmx22XICRpiP5J7pO0qr82iNvokP6SlKcnpo
         59Bk3wDZQQXvS62t+WIMZ0y0RwS+QHyVcl9/9uGdIaYZ820+mNtdKWazlB1VZ3SaiEC0
         gNfmkzSiY7E+cTQ4fxy4USdA238eo2D2JzR6Vsb62r9+JjrzSP0htt+yRjsrnM9tpoqy
         Y/hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=sZl9OWe8efV3w/cqNjESnLBs3dx8abLwD0wji33IRCQ=;
        b=MP4Q3u/1XYkiVLelCNmmSfKXBBa2IzPP8+Fpd6okvMBqE8QLvvyoOfwFyry1kIk+kj
         sbagTtJbebnmqrY4msHPLHpEaPDUMGr8zyVgwBGyq3kxVC7MtFEKPRn+Kyg2dY34J9Xq
         ADyn2Df3qapojGdVsBQbuwIKhGSBTdmylmASPzAPsTC0SFVRk482jJor7EWJU+1ofsOI
         rJbtHNO0tq/LSBdm795hy6TScDUyhljcuVbabOOYWS/rrrLqNFbw/sbmuZbtJklflA6Y
         MMw4scojQxDQbVyAB+4G2tJaiGFJezGXtRQBikHXi9/aztPO+WvmmTDzdMjZFoJ0l1BX
         +p/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QGveW9bD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w26si868329vse.2.2021.03.09.06.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 06:00:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id AEBB26509B
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 14:00:01 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 99BC365368; Tue,  9 Mar 2021 14:00:01 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212177] New: KASAN (tags): improve use-after-reallocate
 detection
Date: Tue, 09 Mar 2021 14:00:01 +0000
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
Message-ID: <bug-212177-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QGveW9bD;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212177

            Bug ID: 212177
           Summary: KASAN (tags): improve use-after-reallocate detection
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

Currently, a fully random tag is generated for each allocated memory block.
This means, that there's a 1/14 probability that the same tag will be used when
memory is freed and then allocated. KASAN could generate a non-matching tag in
such cases.

Related bug: https://bugzilla.kernel.org/show_bug.cgi?id=203505

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212177-199747%40https.bugzilla.kernel.org/.
