Return-Path: <kasan-dev+bncBC24VNFHTMIBBEH3TWBAMGQEXVCRPOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B89D3327BF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:52:17 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id t11sf7694585pgr.22
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:52:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297936; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGbwGxn2WlKKntXvrBNMGNxCNEEuM7nh0/9VxvK84qzl0fSkXFanAWEZRJit80tOcb
         FSnC6x49l0LVtFtLdE7tGADTtK6vrFBq/i96yN+EuwFztaesTUJ+fq1KCKo89cziIGjF
         rgQ52EUbHnzyA5FCR6TFUgpEv/Kp3c1qJh/dsn5jvyXQ58dpntRHL08rUfdfe7Ud3Cmj
         F/FcoGp9ZYgO4TdMQqezrwfukAPcjXrB9MTwevkBbFvl4/b5mnnU8YiEh67Cru+t4D3Y
         VSnr0PTQRWloFDDeYLL80861cxvckiQuxWmg2rxby2DiD3wMNRvINuk8t9mG3rVBQE47
         teWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=YkuP86Cmvvmak59it81hQaOynNvKXeBKv4iIMZulC8g=;
        b=FeI9Kj8TmZM7xI1F2/PzeG5BGMyxSNRu2zqC4A9oHDdEQ0b1QGdkulOiCDkpiAhN2y
         v59r6kOvmew94BtCx0dIQMEqKIrOIDMGhdFha1hYJlVJYIma6n50j4pKokLDOGPP+1c6
         BshuhGGxm0MbweOCpjmECYfBxOb9pD0x2glDG4lflDkuRYOEalXhboBWyaOMDOlE0jPx
         QZKWT4+w1aRDrEBrwhl9qTy5qxIF/z+6s9Gamxgcvml9eCzryrggyCd5jC5raKWmm9i5
         5hozMHXZw+BiPaBYZpo0lV4AC66gDI16j2IULhLTAIHG5y1H0+xATWKZPhdk0VN9+nQu
         a9HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=spSUcVNH;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YkuP86Cmvvmak59it81hQaOynNvKXeBKv4iIMZulC8g=;
        b=qHGTYLAvRU6KZWxq1G7ObI76cWNn2LCN2z5zKJ/UR9ASVOPjMcOFXpvtV3TbYkUgZq
         EYdxUC8LuxsJ1LDA6foRBowQyJlsaG5C3jPdTD0ip2MdbwFFGeQ6plNv+n5WU02LAkva
         TtluAb9g9PD5cBn3dx43lFhZKp7iK+OrTUDNtaQLrH286l5smUV4I9f4dAcZv3HXxX4O
         hKX7crlg60p4X28yUAu8eUfWx+ywf3RgikDvrSfdKv9kCuOHHWLWsybHg7iMWpaf1Kyg
         HxMMxjlpn7zVVk2auYuzgRBtQvyuL8oZxSBJnLdg1ouQCz+MZjfyaNfEAW+tS7MCwsMP
         BBhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YkuP86Cmvvmak59it81hQaOynNvKXeBKv4iIMZulC8g=;
        b=QKZmyh4pGpvhcvpplqVyJVjX7B2dDPNbLn8r8ovmz3w4pUeaUDqhrHwtcNabmeLtLH
         mXdHjJ/+eVXnPEtjajVkfk1+l2MJ7/wq/lt+Vl/k9XBNdba+yCvwWi4Sk9UwP8/PVLTJ
         /ajawJcZMTEDoMZQNQEfJg/+AW7dXOxdnJh2Lx483Nl92Nl10vDw3p0HzcGCR8wH3Ali
         sVuOr1NkxedT4VY7wfWEGZ/qV3PfsyXzq+iOxjk1UJbTHvZiRmjKVQF/0ZZp/s+27/mD
         42R1Q5kaFkwqaVjY8RVHccDyZeeKRT1XkbHA8K7iiboImVyNmi1qaiiZ7KJrz2s05y2W
         WXSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533okqdy7jm9ERody+uYdvWvkmcNng4lnMS2rykZCsIuge2wIccJ
	rC5MsC2brWwfD2yoONKOAzk=
X-Google-Smtp-Source: ABdhPJzlZwUVZv7bB7CVAtLmvS1UEwpQygX2zNPbNbVl7x8fSxL0uXff4rXClhRsrIl9/cu8lubi7g==
X-Received: by 2002:a17:90a:3902:: with SMTP id y2mr4888198pjb.202.1615297936178;
        Tue, 09 Mar 2021 05:52:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7246:: with SMTP id c6ls122552pll.4.gmail; Tue, 09
 Mar 2021 05:52:15 -0800 (PST)
X-Received: by 2002:a17:902:e889:b029:e6:4c9:ef02 with SMTP id w9-20020a170902e889b02900e604c9ef02mr16636359plg.1.1615297935613;
        Tue, 09 Mar 2021 05:52:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297935; cv=none;
        d=google.com; s=arc-20160816;
        b=NkulJGPZhh5WidFf01wJd1tGn8rEC9RHvBumRJqazORKAulHU+Sf2oCQfMF14L9mTr
         dAtaCifHnnSKdVBopKOOyZpHzDCqCWzrSy/UJMjk5LTlsFmx5e5KEUKYbGfsJiGnGE8T
         Gn8rG+xIMlEMT7utnpPQ6IGyhArjB59SRm0jY4Nh1Ep/CF01hMPWVqnxYQd2IyoSbLk5
         wfdx0KcUUd+fxJmehiX4DnlDFvqFZkjOp3K7TBaPosTgOVnYsfI7Mna8vJLQH+Cm7eI1
         Z3GZvtGTBNKlVoJc5UvFRjcnnfeiHFRVAX7TdDeWSlDEByrbYUWLQgguxc8609Klpy91
         Vlog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=tuGgWGEG7XIn/VY+Mz3BFaFA9a6SlcglqDpaNAQiTDo=;
        b=bVOcnK6+vUVkJFoSI8thi/fmZaJg+HUz8Axg8HGE0ptenmgZi/Te7dmVmVkExEvHDh
         jvXsMW7dpJAt4mbdjEgb/tV3fKxoGtdYeQbLqkp1jJ3lHzUnI/wY3nExLFO5DiFpj/uR
         Mcn4fZgqlXmxTB4lagj0ocklOp+cnUJsT9G7R0rJGd3Z7GfMS7s1AXLBx1cmOUdgr2A9
         I87XlVS+NOU7D98Jow61xEunuD7yGHeZJThbwXb7RPUpSHr2De8Ud2GiSVe4/NpPMIT1
         pp3Zh7ZpEp3AqDSeHOC/Vrik8Up2ZXpIw+hAh1rfV3x+iImgsaG34nBhfGcI2NvXgGtt
         Sz9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=spSUcVNH;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 131si31278pfa.2.2021.03.09.05.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:52:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3A717650F2
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:52:15 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2B2A265368; Tue,  9 Mar 2021 13:52:15 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212173] New: KASAN (tags): explore possibility of not using a
 match-all pointer tag
Date: Tue, 09 Mar 2021 13:52:14 +0000
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
Message-ID: <bug-212173-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=spSUcVNH;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212173

            Bug ID: 212173
           Summary: KASAN (tags): explore possibility of not using a
                    match-all pointer tag
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

Currently, tag-based KASAN modes uses 0xFF as a match-all pinter tag. This
means that memory with arbitrary memory tags can be accessed through such
pointer. This is a weakness against memory corruption exploits if the attacker
can craft such pointers.

Ideally, there should be no match-all pointer tags. The feasibility of this
needs to be investigated.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212173-199747%40https.bugzilla.kernel.org/.
