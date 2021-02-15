Return-Path: <kasan-dev+bncBC24VNFHTMIBBW4JVOAQMGQEI4D4Q2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E00031C213
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 20:00:46 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id y15sf3976652pgk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 11:00:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613415644; cv=pass;
        d=google.com; s=arc-20160816;
        b=XHehICAMDVWYO/21AkhUiLZm38Sh5lwj6XSElMOEPQ67lHRBBbUjWDFO+4KYEuFNpd
         fEEsVAZhIBJVD5gROTkgqWoxt3Qcsydy+FE38LEk/3zyE9vwp0b/iPATzYjNu2IZ2EC7
         +kcczsLB3nbxmR7+ikbw93YgBPNSW8Eln0Dr1RuuEZ4NOezaVu9UnCdig6kBj8rP1B1h
         +3aN6sN/PM9fy4wT4cFN81EeBlLXZjlVci6yLlpo78ldHDuiRagc42gHeOOJp1TwyhiU
         CFhwwgm4SnNMjaqLOUXThToB5AkTTtzyDb7s5o6Zxd6erNLwA503a9WFRDWgsK13aheV
         /pJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=6KYfuo+bXfkNJvK4NpulDjBkip1lBhmlsloUh1SgRnE=;
        b=s9CNqk7nDCespX5MBMiiLWf5N4B23pwmbpwjzrl5Yz9ZMf4wC1Ua5egKOp648W0kyq
         HyUm2oIUbneMYNvxZ6nRaQHnmlWxPd0pxvbGLoiua/1r47NPXMt2vMoUYzSDL7BOgTxU
         Dxuzmkyt3vyaQbRosaYl2qc1qF4+jLw1Dp348RYwdjrERa2O8btqqDmE6G6sQ8D/3oJN
         eFOJ1Wcr24d7DiOSDGbPuH0XAzvhLOBLRrrd1ZcFpa4oxkBxJMnhVO+/fS9WXex4DaNx
         MefEm0ciFjWVF/O5Nkkhj5nqcOTM9ADyQbMYafcHKsblBVsxMKv0JecU1CxGenKfY5kD
         TMxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lnRgtM15;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KYfuo+bXfkNJvK4NpulDjBkip1lBhmlsloUh1SgRnE=;
        b=CC6ywxElAbwxe6E4iHBCHDsqMP8GPXpU/Jy3m3yu03mL7IkUUB014LMLF1zY2aONHU
         wdlb7GsH16gHLoNOKUtYeAnC42MgIkpv6b6WGh6GNepnZ/PdyI3w7SbwQ4oORhO93GkF
         2lWL6Z/uCaFuP+dO+yisBX+V5DfHAZOgPXn6vWI4PKJqJUFwgeC3wTHOkCt3F+8FIitS
         hWaf0+HM1nQvD5JRDIjAQonwYYUS1ZywhSh0t8jIcTvRS+d404SwVB3SlzW3Yqq6ANSs
         /reCQsel5ak9NU47ed5FRSNikvLuPdxgKTTdW4/WaQYIc6SgJjQYt69iHGd2Pqdk6kZR
         DBGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KYfuo+bXfkNJvK4NpulDjBkip1lBhmlsloUh1SgRnE=;
        b=oEExTwWvldZDgfGe8KwGTB4J75UbtORaHMYHPUxvX21N6sA7h3pZztXQpyZgcCZ+ye
         ouvBCXEgWNnVwxKaGKY+5vBpLE9IMLsHqP55vw7xcdPsNXd1MgNZ1IOg7IZZbfqtNBOD
         x1s0RO8W27jAVbjgBmKqQDfKx4FzQ9ZT1nEykayiiUK5FmI9QsSRO61voL3BPXpB9E/5
         O977bFBwbWw4qErceAJ8D85nCKyn6pL6EbPfXgT1dhmniD8vtsZTRKgJwpZn7yowiBr5
         n0xA0s7UAqSgzG5/PxztJCAhMOXlXM6VirZWUY+oq+3qCAVUpuz/iCweMODS2V1qZ/hE
         DiDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gjLRLCHLNiqJ1PwTaVcwC2zxVSD1Jt+yS1DI61u7CYrF5/W3X
	QThlk1pQEbLjh0b2KFmPa3o=
X-Google-Smtp-Source: ABdhPJyTJWPL4S9xI2h+OFsSERaPU882XdDLFe0J4U/AQzFcR5M/13aDlvx7gpmdwhhY22xGzXo2RQ==
X-Received: by 2002:a63:eb42:: with SMTP id b2mr15884592pgk.284.1613415644164;
        Mon, 15 Feb 2021 11:00:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c401:: with SMTP id k1ls7851177plk.1.gmail; Mon, 15
 Feb 2021 11:00:43 -0800 (PST)
X-Received: by 2002:a17:90b:4004:: with SMTP id ie4mr286243pjb.114.1613415643455;
        Mon, 15 Feb 2021 11:00:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613415643; cv=none;
        d=google.com; s=arc-20160816;
        b=NXPfiNbEkeBTdBIWuYUvs13VjWzsvTg/GhZcCg3QxMXniAnwjzJfcpo2iitp+5WLJ5
         Qy+BJn3U8Q+egCvvRe5S3tZRIrHEdIfLeYkWKaRqdAproBeHrYwLqA9N3jeGqwuw8mZ9
         uSbVAXrB/AVnoV3bDIxSLTS992fSKx6+EfOZHXhDLK9wYsmdzy6cNiNMWqqwNCB5HPcL
         HfT7bkTdnLfiElzzsjMviXDS3SAJB7oiKlDD2Vnkw0HgVHdB7h6kw9gX8E+pJrMhXVrX
         ePCr8sfEemxEBh9+EEOc+uvxHS6bR+ODxhY5gdChRyCQKS5fTO7EY9p5ep61G7FKXA2c
         cWGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=5nzgNoXRYX/Egy8bNlwO0uGdH7KqkKIy5ffB57WzZBw=;
        b=UEXeegm7En2wSMgO2l+eGQvoxNrhnhiHyqkcR4PWz9tx1OGf5xWRYcBlIZFDwJsdjo
         2NDLHlGwKACTfK6NHnnnqd7xplUqKUOMleCMQVSDaNxxYJ6mjbyTWGpPy70S0upW5+2B
         +8epv0ofw7LpMMddcWnJQOyEVleER/PoNFd+CMzlyNabf+/ylJu6sQZaroCJRPd46RKY
         jfwarShY3U9CJ8eowWlxCiirIGlremdiGC2VzcD5n1Yglqhx7npx9Zc/HlcyS7aCD7J8
         VwYCbAS+zAcblPeT8SIlaAJZMtllaY6rnbMqD45sA7J/QLS5n655ol7s0Aw1p3QHckHX
         pjgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lnRgtM15;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q21si1191479pgt.3.2021.02.15.11.00.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 11:00:43 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 2343064DFD
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 19:00:43 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 12464653AC; Mon, 15 Feb 2021 19:00:43 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211781] New: KASAN (hw-tags): support globals tagging
Date: Mon, 15 Feb 2021 19:00:42 +0000
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
Message-ID: <bug-211781-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lnRgtM15;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211781

            Bug ID: 211781
           Summary: KASAN (hw-tags): support globals tagging
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

Add HW_TAGS support for tagging and checking global variables.

The generic mode already supports that, while the SW_TAGS mode doesn't:

https://bugzilla.kernel.org/show_bug.cgi?id=203493

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211781-199747%40https.bugzilla.kernel.org/.
