Return-Path: <kasan-dev+bncBC24VNFHTMIBBBOVRL2QKGQE5V7566A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 003341B702C
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 10:59:50 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id j21sf7183824pgh.12
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 01:59:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587718789; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICCHBs54bbzueHoIBexbZ9KvdYe0CDUAef8MPKTZFA/Enos6o1xku6H8/P7vRIMjRx
         WaQBIV6qOIePgY8LzGXI8DA4exr9c+hMizJUJeBfKgKdBePlTEEiGiiwPy8ENEtMJXQS
         31PXBKQSa5u/QJp5+fuXk5ANhHDc0+rlPv9kbkYkM2sLMZaAE2Bn6sAuvz4yJLULl2J2
         aDhdb7Kutzk2xPyHUPi7SlzRm7Lxz7uoxn5rSQvNNLIFfy0EHVNuDOVw4I7aHeG7GJxO
         zzQQZ+8LXIiZSPzNAMFEyGorlLXSN+fNaZKjqfri5ENLVqz+Se+Q57E8XxuFGoQQmBZ5
         OwwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LCyb7MSXx8z7zzkjOmflXxfBhb9OpyNCOo0MlflztwQ=;
        b=QRYA8hDJHE7bqHx9Udo7IvBRTXGWBjsiJBtHcvn3J1exllmKstpSg33Sm8nqflYDJV
         Dtgmwrjk0wEGzt87S4PoXCERxdIGLuQbNjmV8Zxo3GJSScE6RRu3HVf8aYghuoDbDPQN
         SLoQsBNmWBBxZEBc3UImQuKKzG7hiFdQiTzDsqMEbdzJ+gqseRp3PUhT9OTWL8xTVA6C
         XzrQsrpmKoAv/FvYKo/Jh7/Byw0W7REWLR3EAT9YytK3gvOCKeyQ8w9XtYR+PbE4KNVr
         KTIOfBhfAzqH3pvtJVEiy443WORTtYykIyQEEW1jZI6eTwvnkwu9+K+Y/siBnBzjEG9X
         vwFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LCyb7MSXx8z7zzkjOmflXxfBhb9OpyNCOo0MlflztwQ=;
        b=mCOpRoltv+8pgCEwbdHWlm2NWY2lpA8DFVbc2lZgUP3A7zDQN9CufLaCvPTdDINDIM
         Ih6aP7psXbaYS69ZHHUJL3KtJ/F//p8wIXJ6fd37Y2wjyr48SsEFPnk9+l5h8E3cIkyP
         yLyj+Phxqv/K4R6tZPDkRzXR1an/yyrIzpxb7z5C2BVtO3WTnhb3/CeuafhAYjoRT3zB
         K0DIHOb51aYIFtS9DeZim6K//03v5tE7FHOemuhFeLkF771e30ipa95Ef9/oJTfyh1xd
         juvJBW9AKi7xXhJZVJM2hiY+oUZ+/TSppJXrKz5WUU+zxbkzWqfv7Vq5SNnoKbvuqLVo
         rhPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LCyb7MSXx8z7zzkjOmflXxfBhb9OpyNCOo0MlflztwQ=;
        b=WPPCWGRQ/OOv/WTJahqYMH0VxzIF5RtVS2qM3ibkAufaBoExXH+jgA41YQiEILMsQG
         sNmlccn5vWSv25Qc3iSj3H620ZK5X/y4aIBxKNrDd9D0LO2FDA2fd4yGJkfZUaGZ6lA4
         4WAJt7XkXkD0gcG5d9qXvIrtvvOXo4SPw5pYttlEdL4F1iaYs909rUD46yuTWGIU4p3I
         HZ7XKERlD+thanp9hSKuPhRNHyMUcYW7MUdDUx6dfGy6rERO2Pk3flRPML8zn4StN0Jc
         8A6JFWIjmjJakBjEHH+23lVawaJTnSq7h7tlB/w5fXoni+ZHVpplDT1i8oDKO1Naa/7A
         gYuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYJnqhkY0MQlJuu/wZkO3m85hPHbr/X9iL2b/KL0lA6B15uSiAf
	6d/N0DQzBxPOUCZEfWvP+o8=
X-Google-Smtp-Source: APiQypLxztsAdtZ9bdssAgNR+thFm5LPYo3Slqch74rCF4NRcaZM1AS+w4BPiBwld9HN50D/5PhcYQ==
X-Received: by 2002:a63:1e18:: with SMTP id e24mr5933243pge.296.1587718789645;
        Fri, 24 Apr 2020 01:59:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8c85:: with SMTP id t5ls6380453plo.9.gmail; Fri, 24
 Apr 2020 01:59:49 -0700 (PDT)
X-Received: by 2002:a17:90a:d504:: with SMTP id t4mr5217641pju.123.1587718789298;
        Fri, 24 Apr 2020 01:59:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587718789; cv=none;
        d=google.com; s=arc-20160816;
        b=Rto7mlpXGcqr7svfWmdpisHevtCGdy+6iQ5sy6KzZA99whF8cABlNNh/vYioERhA1K
         PwtqIZErM7XwS65EvRZ7vqy+yAAY3XPECJkfj/alONAEPcOSC676wShKxWzGMHs5y7wJ
         kIdCYNzWVC0aq2PKjTXpWsKSRnlfANnp1izXBhknuRWoBb3MRPKqbCaR4/SUHS0xy/W8
         KCnKwgXWIm2vds/VG9Ifg9/16jNFNC32FYnP4paJsGQKPIhY8cxIRyCsx6fWBXKJvcje
         L0hEOsmsDTjM/5aDbEVDq2RywN59V0gkwX22zGRnxTZs4I2kWhPglgOFs1BtPmL5itp3
         ZSoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/rf5S6rQ0dtHB4rocxAraGpf0xQ0/Z9/XkdpyLm+gYE=;
        b=cz7jD8hbrQoznwZh9MKMKtCnXs7mnaOKijSQ5+dQ8GvD8z0j+kp8oOWtKBHTUAV5Xj
         KwrowsYrhMbPA8oHKZFlfyetRbrPFwn8p8XGlKzpuENSUitIMi2wPEAyq6Q1uvBuiX6R
         hMapZqEoEoiCwCeHfDogQ4Vbdctmow7a78QWgFOMLpa9caMtc9Ihody8/x7AqPcKWwdC
         J8x2qLk2c44MyJtEmCvcbsygb4f4l+UDUqbOhsGULHbnNb+TvVRh4PdKDNkfkYjdpB+h
         fqqKlx0pZ8oRBClceiLxY9YJzZ9kjfZKJPTTpSpFF1ui/2MqC0VMyLHnorxMkBC3EKGH
         KPJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t141si413105pfc.5.2020.04.24.01.59.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 01:59:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 08:59:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-mCtItLet9i@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #6 from Dmitry Vyukov (dvyukov@google.com) ---
If it would be trivial, it would be already done :)

Current header is:

struct kasan_alloc_meta {
        struct kasan_track alloc_track;
        struct kasan_track free_track;
};

This is 16 bytes. This is a good size because this is the minimal redzone size
(see optimal_redzone) and a good number of alignment.

We can remove free_track by restoring kasan_free_meta (storing free meta data
in the freed object). This gives us space to memorize 2 more stacks (without
pid, just depot_stack_handle_t).

A simple version may memorize 2 stacks, and after that if we need to memorize
more either (1) overwrite a random slot, (2) always overwrite the second slot.
(2) may be better because it deterministically gives first and last aux stacks,
and we know which one is which (can say in the report that this is the "last"
one).

A more elaborate version could also store a bit somewhere which would say what
of the 2 stacks is the oldest one, and then we can overwrite the oldest one, so
we always have 2 latest stacks and we know which one is which.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-mCtItLet9i%40https.bugzilla.kernel.org/.
