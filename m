Return-Path: <kasan-dev+bncBC24VNFHTMIBBKOJ475AKGQE6C7OL4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E249263FF3
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 10:32:42 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id l1sf2918207qvr.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 01:32:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599726761; cv=pass;
        d=google.com; s=arc-20160816;
        b=MFgXgiPNLyn+bPvLdJkw903qqyDzrADaWeqkFb9mrrVEovj0wN8vjguN/j3WMPbsqt
         ftfIF07LVTPhKMryM7VskYZrfaI9+uGtxye6qtorGC1/J2lP6DGsEv9FOc07kZrPN4g3
         2BHBJCxtQzoozvzVdNMu0dqsVehwjF1qPDHlfH2nprrftv86BDrzXUbLhkFQCVvV7NCg
         zseGgl7zsXEhugNB4QFwWsGFvphPUaxS48hyEz9qUfYRe0JM4yuKnQZpsKG0gjA0+MYf
         YQDP4+XZrOxaZoJuNSSW+VABSe2Qn0bWQ61TzX2v4IrW67eu6LAWqGiPWT53cRU3exL3
         kC7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=msNKrHpJLxC0Hm7pvphyiLMOHJINEeMqE7lRNCBFrRk=;
        b=p+JNDOsOEt4pbWoivOj2FUypXFR3YUePhfTFvJDLeCftCD3IPTipsy/MVJaH/VN3g0
         wCl7suwveP1ka34LBuAIAO62uzlnLqwgRPI25vLIg3D5YHts2uJtVfQKsjZA9qWfbcmp
         HMQOUCyGs/wHZa7qFbXjxmFLvPURj2py3ptDws1/eErDGGglNCflBvTfYkmaQLChAUwo
         NrjMbwp3+UQshQrg8PXOBd6er8ARsfjz1XeWhAI2PNuEBjgPkNu7fKH2VYBkOoge5iHI
         fz13XmsgsL4wmacoBDDf6elI6aRueiYLpC5ZXDW4nMrUkAZsZAjVQYqItOXNIMnO9OeH
         dbgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=msNKrHpJLxC0Hm7pvphyiLMOHJINEeMqE7lRNCBFrRk=;
        b=LunuZMriRNshE9RyCm0YzuxjOysSJoLips34GNeHEIGZw15SimVgNUD75EvhljVw/6
         9E7AhT6Ose1ZmQOUUa7swCGbF+cnSYJ8FgZNuTcAeETyg1SGdI2iZtNvISKxx5P9fPQd
         VNwPftZJ9/BoYjvM/R7ehcjFy7gSvMKVV5dml4i8x6q+OE0lgSHmqZjIg6s6sI3NMcMe
         1lMfr1eJvoOHIhwh6cMkGntb2rGSF6BDj1U7RSBjEpspj+dwgvYjFQhuaLR9qKhGs0an
         CC7K+5aje2GpWuRDeeod/APJu2kIxMUG30Al9qOuzk/vojthDaN+xPqA1iDIwqPhXSrS
         N/QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=msNKrHpJLxC0Hm7pvphyiLMOHJINEeMqE7lRNCBFrRk=;
        b=dkO7YusxBKzYPUFjxZt9K1XxHzj1zcvFlVhBBgRG2WJ+92oFyLM0Q3l2JyqLhoM3oL
         vL6mOD0qnG1jw6Ei6TZ20AmifVTCHyJwLJeG3CvNaCC4GNcgy2WvkDaV/vqBehVfiGP7
         Ut0HHegbcR/AMV4qr5FYvGO2uCNfbuV225UGZ/CTr5y0pBiecbOZTswOuSt28j8LQ2S4
         hYh7wDbz18Sa8jznyxUNLqAHRKyNxZlsht4BUXipAlaumf0e01+hKQEiTNi7K63ASzff
         iZj286ooizV6XBvSU8PUXPQW/yKHDz+fmsPICptcnILFXsy+tHtuUDL2JHpjUCC2CPxQ
         ocjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mriFDcHKZeFezwxHBoluthTJ5yE+t+g+3Be8SMa0HRp4xqeXw
	0byv2nF+VCroi7lvwuPJJZw=
X-Google-Smtp-Source: ABdhPJzs/aOnXuM0vdOA+KD2xcBX6ncNelavspt+TjyVI1py9QNoIFgFJoWFZfTCUwt+FlEZrEO7yA==
X-Received: by 2002:ac8:fbb:: with SMTP id b56mr6921269qtk.307.1599726761129;
        Thu, 10 Sep 2020 01:32:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c20d:: with SMTP id j13ls2674087qkg.2.gmail; Thu, 10 Sep
 2020 01:32:40 -0700 (PDT)
X-Received: by 2002:ae9:d802:: with SMTP id u2mr7034232qkf.234.1599726760758;
        Thu, 10 Sep 2020 01:32:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599726760; cv=none;
        d=google.com; s=arc-20160816;
        b=DoksysIRW1sEsP8UOnG4/oAZ3R+Rdlrdd6p4MPe/C8IPSt8OVY6fWlZ51BAhKPf14v
         mjREAd97Psc7Z1Qu453y4A9YtOFSbm4E+K28JDKlPiMIY6kVQxo5FtM9w2b4NTs5sZ+W
         VJj0ilGunHgCupLzIrbYvVwIsm1X0rrd9QpUY+YaIwzIeoPq7NKk5rx1nL9jVGxGzLvY
         JQU1W2zL1wArOE+rOjR823vlbyTeiqkLwaVg1Rtuw4GFmB+eT/NfCLkuo+lX7CCqkmSY
         SCxpVVGbEQsWT73NqTd1GFUnzVLaNEDgcIte/haI5uwazZWC364C5HDxUfcLgEgDHQF9
         PDIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=Hwf0Bnyr+wSsxAZJixnbCMcMF59awMV5EDElokmPmB8=;
        b=dFds5rjpnEU8RYTYQTqccb9LbGRxV1fZCvjISk/rvNxcjYV/mrhAu/DWhXLgEjSnbQ
         zVUWM9asBz505HT7VFGevPp17WMIUjp3/3mJzCiGCgcMehfd/OQQmvrR57mLuY02CTn2
         ktK7IXMZp7vxOJSw108mBBwYdwWXT6We/q587lEM5HZlrzUQJYBxYF3aAPb4lMi7toY+
         d9iGgm3l3a/5K+LoptJ28Drftud8tRcw2zNq4VkCc3sqCpb47IfdlW/VLOIjhvC9dpmg
         xl6JU8oB1kwjdHWlLza8ntAafTTFTcbPUwC8YDQFxYTMt+Px05dt16M74GmJoEoXNy5f
         IbIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l38si312311qta.5.2020.09.10.01.32.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 01:32:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] New: KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 08:32:39 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

            Bug ID: 209219
           Summary: KSHAKER: scheduling/execution timing perturbations
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Two recent bug examples:
https://lore.kernel.org/netdev/20200908104025.4009085-1-edumazet@google.com/
https://lore.kernel.org/netdev/20200908145911.4090480-1-edumazet@google.com/
In both cases the race window is extremely narrow. And I suspect in the first
case it's not just the race window, but also the typical scheduling of events
is such that the UAF won't happen. Namely here:

-       ieee802154_xmit_complete(&local->hw, skb, false);
-
        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;

+       ieee802154_xmit_complete(&local->hw, skb, false);
+

The dev is _usually_ not freed by the call to ieee802154_xmit_complete. But the
bug is very straightforward (we literally free the object and use it after
that) and was introduced and unnoticed since 2014(!).
The other one was present in WireGuard initial implementation and was not
noticed since then as well.
There are sure way more examples like this -- most of the bugs that happen few
times and don't have reproducers.

The proposal is to introduce artificial random delays into execution and/or
some atypical scheduler perturbations. There are some sound approaches for
systematic enumeration of all possible executions (or specific subsets of
executions), but that's probably not feasible for kernel. Just some random
(maybe somewhat intelligently random) perturbations should be good enough for
starters.

For race-free programs it's enough to introduce delays only before
synchronization actions (atomic/lock operations). Any delays between local
actions can't lead to observable behavior differences. Now the kernel is not
race-free, so it does not have this nice properly. But we probably still want
to start with introducing delays only before synchronizations actions, that's
still a good oracle.

We already have some instrumentation hooks in atomic ops. Not sure about locks
(maybe something like might_sleep() will do?).

This should be useful for any automated/manual testing/fuzzing.
The proposed name: KSHAKER.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747%40https.bugzilla.kernel.org/.
