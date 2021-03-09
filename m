Return-Path: <kasan-dev+bncBC24VNFHTMIBBJ5MT2BAMGQEHAR24QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BC68332AA1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:37:12 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id i19sf10498977ioh.18
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:37:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615304231; cv=pass;
        d=google.com; s=arc-20160816;
        b=ScNSyYa8d4yEbj32B9rnUgb3PW9zsWDJc0NcW0aEq5LYUR/Sy9Pp5WzAc1Dcg7OOot
         ekrsMG21O4p9PTCuVSv9p2F4E3uLV/KNjOg+yuIgy/1Z9yTn+qP/2586ZF56jngjcnLc
         ltghybhskglFvFer4m+mdLtbr93dEbwaA/IT/cd2W7WhQZJR07M9JiBNOIYcXWHa2s2f
         cqe2Lky1aW1yxGftVCmdOcF8VakxbusP5RIfwfhBSMwJbMwDjQLPe6tq+76e/4z0PrW/
         CsNy5uut3Xwoa8BoCEtlwyMV2pfrEruVDebaHU+EwO3VY5vxHGGhcZVN7Jsh5lwH6rC3
         9xsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=2QLN+2Dawtm5X1IDQUstbjKMoIQTPzaUaLRLVjQ9cI0=;
        b=UI+0w6S9KtMnsjSHrEXUy/1qv7C8fsSkn6RXOPlyOUyd2JgJiCv4GqNQ/YactD/8ik
         3PVuwkJCrX+WAbwMTEvq5dpi1k6ausrnTyGsT3yliQZilYHOqJ+olwyBEFlcDb6gEo2p
         S5gy5xvrQ/2UQea0y1J0eS6oe5ABiXZCjT9wU1Io0oX5RQlQYo4Ga046ogjXZZx5GlJ8
         qemwnf8wthTBDAhY+bb3KHpTYOTtIN9O7SQEqsd99Ehk+gz0hk/JKF0sJyh+88D1E0J5
         /d+wVF2tMuGCZG7GQKx07YdBLMNIq9jObkSn687gyhLll7DPUt55gsa68KTVz+4+kpzw
         RIBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k5dWCfGi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2QLN+2Dawtm5X1IDQUstbjKMoIQTPzaUaLRLVjQ9cI0=;
        b=Cqmf9K9v+OM9SChv3ApKLlbCC646/L+vATjgRYHyEu3F1oyKqDAsmst+TvrWvL5w7F
         3brmH+R4VFLSgwgLLt4lKhKpvfwMlBY82Mv+QG/S0SerXwFawGreWW7yMOj1cEx+tkCx
         92U/haA82L+4O9iPY7LV7iIVl+9atG0RgWlv1kI4hn1RwpkK5YAvETS6NLiohkkx5VHH
         g0a9O4AYhA52oO27hgvqfGXXaTSapYdK5YKNdYafZMmLZvqnhUln0BBbHuoULdt5KYbd
         V+WSzu6ToRZTTk76x/2YyBtGUxZ4uTehaC0CAPXrFMUXZks/xiFuhBwHYh+whP1pJnTf
         WWqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2QLN+2Dawtm5X1IDQUstbjKMoIQTPzaUaLRLVjQ9cI0=;
        b=FJuJylvyNNl2lv6oXnsiP3C6kArp3hrIchoGU3G1cQZUavZkg92Jmf3V9rQwGlP2R+
         L4E0igI0/oQQU/xIbHt30j041piRFEGHKHrCvje6oJZZmlIftW4f3SlNYOG5XWEIYCBy
         Lg3kLc9vuFOKpUbYkmnz/O+dkomkYOkjWiNX7LhCL7mkiikN9Zi0n01dIF+gGAaP7+R7
         JcqmrgmO53ChLKbMTNbB+xw+FWqmkyHr5ydOGVigpbW7UBfRTcj+YybRPZw2TU63IYJP
         6+zI1fbw4AQ8JcsiHcHKVElRPledk3Hkivt9/8lLZpXhYqEXZUqUsZrel9Q6PRV3vSRl
         G9lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OKuBBCgq5TiYqoc/azdB4EjEv0NG0Rx/CYC+K/JsGHMY1b1pB
	5ZkMeUvdRZ0c9tT2BpXIdPM=
X-Google-Smtp-Source: ABdhPJw2hZKofbfxvQQTfYHEAQoL5hqxeMrXmvRvbei25nLFur1T6e0B0tJz2Q0f+adYaLyEitOfBg==
X-Received: by 2002:a05:6e02:c7:: with SMTP id r7mr24739126ilq.288.1615304231530;
        Tue, 09 Mar 2021 07:37:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:138c:: with SMTP id w12ls2997500jad.3.gmail; Tue,
 09 Mar 2021 07:37:11 -0800 (PST)
X-Received: by 2002:a02:ec6:: with SMTP id 189mr24431597jae.91.1615304231260;
        Tue, 09 Mar 2021 07:37:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615304231; cv=none;
        d=google.com; s=arc-20160816;
        b=M1PC9IOjI6jC61XjcWtmyiHltIy/018BHY8VngyJSZrpIeOD1DRV/DQxuUe1bJWc1K
         ZLyYLJx6K/fwiiwvX/Gzy6VeGO+ZQm8EExJJxmkO3gGjZn095SFACoGQQXW8TMFuxaTE
         I2EBGPHsV8f/0B0/zreEZRzlqlrXmdU+gdcayRPcH2jADg+goCx68ILzL+7xO6D/N38d
         KjWG7YeewPq8rfK8uhQ6yiSSpd2rRQU2RJY6qdHTb2RKGc292kB//wLOAIBwp+lANnlX
         dxhL26M0Vrl8KcTOoRqxPC9X/7gmrk8Q/kE4+5LsHyZK5ixYL4LKFEwa8yTCTQeHUXW6
         Z01Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=ewt/O34Qk9ABAZHyiyoON7dgL9UB9X8BzGTodXI1HxY=;
        b=M0puxOIo/+EJnBg9vXSatvR2tH9zlDJ+35jpTcngtGrH9tGjh3jtuodFXsy5UsWyYk
         gDIsABgKErxq/NEphbxcs2mTSBfpj3Gn/tIsfdvPUDAbRQoSNFmB1Ko91aqLUjaHDVgl
         A/CXB5bR5WyDpopILKs8BiizI/RT4Uowvl09jBCiiv0IfqX++4FNst74I1zyHpUV1/+u
         4fBbwZ4ihtXShE3g88dqncLw+Vl9VfHeJQ35xJlXT6Qf59ReZyho8NX2f4VPFA2/RUQh
         sFEOakO8j6tzg6vodyDt7mJgy7Bto2t2z+u9bcr++6SiOdIXB+IsyEKeaBwpyg2o7fvA
         Jr2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k5dWCfGi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y6si778877ill.1.2021.03.09.07.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:37:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 7090565238
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 15:37:10 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5DBD565368; Tue,  9 Mar 2021 15:37:10 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212191] New: KASAN (tags): better use-after-free report header
Date: Tue, 09 Mar 2021 15:37:10 +0000
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
Message-ID: <bug-212191-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k5dWCfGi;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212191

            Bug ID: 212191
           Summary: KASAN (tags): better use-after-free report header
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

Currently, tag-based KASAN modes describe all detected bugs as
"invalid-access". KASAN could describe some of them as "use-after-free". In
particular when the accessed memory is tagged with the invalid (0xfe) tag as it
is used for marking freed memory.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212191-199747%40https.bugzilla.kernel.org/.
