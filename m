Return-Path: <kasan-dev+bncBC24VNFHTMIBBVFJZD3QKGQEJ5CGFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id DEC9420550C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 16:42:29 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id t23sf15218355iog.21
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 07:42:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592923348; cv=pass;
        d=google.com; s=arc-20160816;
        b=BiUiFRIgfpmLOM4BvdKcj/BojgfnLfHo5dAx3343G6mIO/yEXtrhJ8PE+TkbbCLOi0
         vsN00T1CnNxJvkc66wCzqFJbAO5dt4MgDS00avATFuuArOYDQC9lLjucvusJqvz4HlRk
         Xq8lieNMlTOMVp3ihpMViMFhKqkzYZ5XAyNCcKTgF4rCgLQMzvjVAhLfhHh9hsS+GSiR
         RiIAgEI3EyfIRe19Mc7hIq/mPxGLi8VP8VUQMY30eeF3SW8Kj0toe2uOyQJrrmKt73ic
         yaT1gU5ATC525Fkardh1sNGA9Xg2ZfYHNuhR7MiczFMUUkFLooCh5qvZIjfCBX4Edsgx
         s8Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=jAnY9Gh+v+zmoOey8dUboSa2RIFCYmqwZaBLy48XuLo=;
        b=SBN/UhLU+Q0SvzKs0sCZBjGTOI5bbYPzAENXqvzM6HXlZ6Pc+1eKgeGfHAXWvrSFFM
         XfMEF2vl8ZygaZb6RV17l92cRQcgOc5TLTiOEMLyJwQa36jZhpbF/h0Gwd1WLMyz42vV
         tS0mMrWStZyopoHtt+mJYh4y9dKgy0/iOBk33V2VacO6tDHdzoGy15w0Je9X4ltl1Ke1
         uwgUpgl2vWgiAfhjf1TQO015QqATKYcC7Xxp0skmkI1fJDQ5cumMea6b+AarlC9u9ul2
         RaDzl2EdO+9vWvJWn2CvHtkknn4nOF6AV63dch5ja2HqAo2sXc3vw5qxT+11hA0D4YJV
         5z8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAnY9Gh+v+zmoOey8dUboSa2RIFCYmqwZaBLy48XuLo=;
        b=T3R9qCQfbohNNHd7x+Lu6bXibKLJZkJch70X3Xl+4BsN6Fw8eBWvam6wBR4e15+yNK
         Zr4PQs1Jot+EFVwI9VN2aFQOsLUvoY5zLkWrZci18s/1rzsftbG2uwy4SAfVbPcBXIEA
         RUQEhUbdS0rqMILk9yPKBjR/mTBKrWEB4Tt8vLRQ9sL/a6rcgjI43APfsBI8At2RUsFf
         VhF0b8Um7NGh0T1pGszTyPN6cjdwHk9hzo7nrKbioR3B8IIZpb8ozHorCiGoXyyejumT
         wNguC6hOfo5ArwqxYUpuclutP6lsyLih2BKEjXB4r72FASRUwqe+lLSLWnrGsvbFS6lO
         sRIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAnY9Gh+v+zmoOey8dUboSa2RIFCYmqwZaBLy48XuLo=;
        b=Jh1R+1FQ79QeNc0AMqBsmSvpFjUi4C36X+W8rSeIgfS1bAqLOc1KsHu9Dpa+O7ErXP
         RNHhun1qsMGwohgeWhe5kJBvHr15gheOhYvfbArNkHLy4eLSCLr4K2k0BX0OGfcrLJGG
         D0u4WektNjRqeMQxEU+5XxdQ3JRy7+trFAshHzeWdHjg2M5DMTKI/Oy2Vg3W3fg8Nwo9
         gKIkE2c2HusdkQFd3V6GwE6e6pLtjcSkAIW40Cc0pxpQbUMLW5wKTAVFuBnxjuWNY6fl
         7nbf2Swse42huhTZ5A1fY6JSNxDqrEJF+/CP8jAVF08BKefBJqSAh4Ow0fc3CHe9rLh5
         S85g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YaRscuweoZ2J3oOTPYDNr0mdjZ2QKQ66ea+BmEUt1huD7LZzF
	QxTj8tk04VtnfN7nuEw1OsQ=
X-Google-Smtp-Source: ABdhPJz1OvdoEscmBNqtp+c6xNdhUBMU8YOCJcABoMxEBig/+vOgQBptYs2l1DUaaLIl8vhaPTE1wQ==
X-Received: by 2002:a92:5ecf:: with SMTP id f76mr17821823ilg.281.1592923348575;
        Tue, 23 Jun 2020 07:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:da02:: with SMTP id x2ls931413ioj.3.gmail; Tue, 23 Jun
 2020 07:42:28 -0700 (PDT)
X-Received: by 2002:a05:6602:164f:: with SMTP id y15mr25963775iow.210.1592923347710;
        Tue, 23 Jun 2020 07:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592923347; cv=none;
        d=google.com; s=arc-20160816;
        b=tgnr7BAKFLJIpn1KfpwaQNwHgAxwDQX+nG9/4a8e0iCKDBtkXU5x/97A2UraC+yFqF
         noREMD5doNN/ISwGFe+Cz66KWTxUrJwzKURvFSrflMz/RFxuVGXbALoW+gW8A0r+CCNg
         AOmQafPla897P0x80bp+PaqasTE6ml1lIdCyaDCWTjxxbM52FsZVquoicmzuTAk4XVma
         FMnpFWPZZpGgWMfHUbjBP5TUH27IDzBMvEMS+5QbPdn4eXav02zrNFh44aJECn5DP62B
         t54/2RZ7jEokHnXOPuIbWS3ddvwkzXGxgZ9tMhrd3XRIGj+uo76PBw2suQo39sp9vSyX
         I2Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=sA/upk8tfug94SQa8PTMCkcir3ImQnFcTju/PKkWSNg=;
        b=Cmc+vX5brS4wXzozVbTDXV5BCs+0UvrDunIrjBO9EvUiSblyvfVdm0uO2kbtdzMsop
         7ty+yGnoICtnIBTsLRm9SBjbQa49L1HeBAk2Z48WCj1inhzZo/8xanZNfNkZUcugZsfT
         K9t/bGBVaJot3G2eITTrRhLN9ZIBQ6lWQ5DB3RoZq36NgKj7nw+HCS4aST3OqrH83A5r
         e5XDshCc67sHdtxB/eDELciZ8sWL8hnvpUnPxhKqhHI5Ew2B+41Y1wrKL95m7hopnM6F
         gIh9X0X/vLtcp45nkCHJ04FQXZOHth5a+s/ed6TVBphd2LfU9CxRf/d5RMh6OU+rkQU4
         QCOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f15si417182ilr.0.2020.06.23.07.42.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 07:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208295] New: Normalize ->ctor slabs and TYPESAFE_BY_RCU slabs
Date: Tue, 23 Jun 2020 14:42:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: jannh@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-208295-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208295

            Bug ID: 208295
           Summary: Normalize ->ctor slabs and TYPESAFE_BY_RCU slabs
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.7
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: jannh@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Copypasted from
<https://lore.kernel.org/kernel-hardening/CAG_fn=VWwfpn6HNNm3V8woK7BcLgAJ9k8WYNghwxz7FF6+QZRg@mail.gmail.com/T/#m01f90bf7c5a7166c9ad716e43c79266ea7e03097>:

The slab allocator interface has two features that are problematic for
security testing and/or hardening:

 - constructor slabs: These things come with an object constructor
that doesn't run when an object is allocated, but instead when the
slab allocator grabs a new page from the page allocator. This is
problematic for use-after-free detection mechanisms such as HWASAN and
Memory Tagging, which can only do their job properly if the address of
an object is allowed to change every time the object is
freed/reallocated. (You can't change the address of an object without
reinitializing the entire object because e.g. an empty list_head
points to itself.)

 - RCU slabs: These things basically permit use-after-frees by design,
and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work on
them.


It would be nice to have a config flag or so that changes the SLUB
allocator's behavior such that these slabs can be instrumented
properly. Something like:

 - Let calculate_sizes() reserve space for an rcu_head on each object
in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
call_rcu() for these slabs, and remove most of the other
special-casing, so that KASAN can instrument these slabs.
 - For all constructor slabs, let slab_post_alloc_hook() call the
->ctor() function on each allocated object, so that Memory Tagging and
HWASAN will work on them.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208295-199747%40https.bugzilla.kernel.org/.
