Return-Path: <kasan-dev+bncBC24VNFHTMIBBJWXSSBQMGQEV32O2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 13B2E350C66
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Apr 2021 04:10:48 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id bt20sf2487696qvb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 19:10:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617243047; cv=pass;
        d=google.com; s=arc-20160816;
        b=WZABboC0SZK5by0+gvhPMdEsKENH2eJL3GOZTe/4ZiwVXIjDFypVOB9sKCQpFkKiQw
         GU4UjNnrjwq6JvbP1jrjHQgNCxE7TsEG6GtqUQJ1SZ6NZUcBduLV1XutzvcDyjsTaWzE
         0d2fZJ4tQyUFnrYn+W+rTi28ZojsSehh4ywMSAQ16NMmD2PVO5z6Wtct3RwjG9w/quzl
         xPHJG+NhdnCR2FrKu6Ske5sqX1S+xbhwMxu9ZgW91Qs6HkHemUAa0B3xNL5cqqT6N3jw
         32Gw5FnFEmrrg5WF4LmYQreq65V4ht/m9Zb3YJgSFIqYtbGtyU2waS3jVvm4birU0q+k
         vQWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=8emwguwGXVoSQXwuToFypGcfIYaJ8CPzlU2Ib9s/NN0=;
        b=UfuX4BVquOyY6wH4mVjs592NKo5feAwM5EzZ0jRpVImEJkAoGwYHGSeFtPoSbq/++J
         TTFNf+nEUzu0Ez3HZwsH4EED5yhmKQwYKfs9xjyMG9WGnyGfyVMIkAaMxW6384WZWlfd
         efSPPu+I7H0/m+xSJTTsNGGIkoTcsDjVQksyZqdUNpaJSOA9RETvWsgxwTs62cjJgu4M
         vCeLImX7n1L1bq6BWW/Owp4JXRzhipIQVV577x9baw7Zw4wBjqXDVowhdqotGpwe7Kix
         xrf3+ndb7jKgpk1vQvNiu5BHtTL6F/lfLVnlhUM+rPGqp+aO4Qz1xgqKYqmSFH74QexH
         iAyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QlIZcbMZ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8emwguwGXVoSQXwuToFypGcfIYaJ8CPzlU2Ib9s/NN0=;
        b=mO6wHgTmSuJ6eF/1gQfZ/i8chW33Kpexw1lGU2wz5aN2pa1nT6NdJGjdNwZpKCzntV
         3AllIrmT8NaCacP3Q23jITQqLbgzRQrB9o/Fe7V16e1wLlofVVnvRf07Xe+n5O1IoeGC
         M5f1iiY5wS30XIgk1xkCAlsDh8zD2QQHbfKfwA+Nl28kH9VGVsOB1rF1dSbGsnn2FgeG
         wcTO4cs1eEFsphmf7xC6Wkkp4Leduhpfuti1exSDUvtY6vzCSHltc8oEbG/gvf/KMUBw
         CtYDMD6lZGt7T5uMbuGmNwAFJ9nbdGtBufDNIFMIZudeaPSixt2GQ/bn/YHyHMGIs3kp
         8CbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8emwguwGXVoSQXwuToFypGcfIYaJ8CPzlU2Ib9s/NN0=;
        b=UwHRQiqZvVl78Yrx1T64yeq+1DAQPH6mYCb9TBq37HC38e+y7QK6Wdyh+mZ/SXNKBI
         EfvHmYBRWkddreJPeN4/iHMvIKQ3g1m6fAkcA2QzhiqINRST4a5NsLrc2ZV/pG0aDq+j
         U1gc2N6rq1GHE1auVTebfb5q5uYQuKT7w2Ht1in3P+qHwAsoCnIfTiqAZgULoC5hwKYQ
         Cn7STH8r6j3m0J6+3/ps29NBPAa8Mg461ptcKAYugQkp11aMMUNVk+2H5xEGyS81sAi+
         0XB8JTLsgJDxPzIWd32Xmnsvzu8vwFacrIb3t57mC6mHeZ24TOtYbIEmp2Bl+i9/BhP8
         w9qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wqAHwXD3YC+6Muo4GDT6GMNypgzIYTOIips8zbs0DC1bkg4SE
	rom085xu5BLu8CDbZoS3ozQ=
X-Google-Smtp-Source: ABdhPJwJWq5NLOXuaWqMEIRAbcYf/j9tS3PEIdV71Gc5+JuL80zfZjJebC31aRiOhT9lBlG49AyICA==
X-Received: by 2002:ac8:44b2:: with SMTP id a18mr4961485qto.285.1617243047049;
        Wed, 31 Mar 2021 19:10:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c83:: with SMTP id r3ls1160858qvr.5.gmail; Wed, 31
 Mar 2021 19:10:46 -0700 (PDT)
X-Received: by 2002:a0c:aa45:: with SMTP id e5mr5715214qvb.44.1617243046613;
        Wed, 31 Mar 2021 19:10:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617243046; cv=none;
        d=google.com; s=arc-20160816;
        b=oDGNHFFvhG8KXpwiTTJ0oHAJt0QyvST342ALpFHt6Bn+hD6EsQm0XrS9Nx6j+Y3iSb
         jygNinF6qyud76oiL2jaddCcLhFp6Oc8j+Z2NZ+iLqq7OWlq3n1ubejmfkAKYFphTyDJ
         jEWjjPQsRa7G0KQOpVUFSZCvuKkX5kAPgtD9238uD7pw2ONl1jug9oCEV2ny9EcpXVwt
         ZknkM0QU+MOPpbd8Ox9JQ0t0hCQFue94cbwMV08n9wF4BsJTkZcDa9Sr9qPMRKwYiN2m
         C5dfkFNWg6rkyMNUiq2gtAC03Ht5q4begCr7CdPHBvOkjps8CfOD6oIHLMqg9p2Y9rqd
         kJyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=48WBlCay5/aVD/oLSE9Ag3xkXObWcZ1Ryex/ccFovHU=;
        b=Itc9ER4BW3uJqt1WQOP+NnNxUrDvzjdCId2Sr42F11aa+9DUXmoTMdCS3Dy3Q0y3rn
         VUo/Apyx8Ot9js32n3XaXiLAdPD0FgDeopjdX1+yz77a+Bjr/EhdP8EtNAUOj/Tybr2J
         VlSJnrs3jQw3TnP3oTugZnFy1VG1NnnFZeSAenFBCWNh+Jls8035j8A/kOpQsmcbHfbS
         mwimCSWqTxTpRpZthm3lsaNvpU1AndjZnM24aK7JOpxgi93A1Tt/c/+GhC5bPVmNaqpx
         F5s1Xg7Tdm+kiQd89NN7tLrsAU0RZqZVYU3JwCgFrA48T/LX4gajtJ7c2qaxQVzmRSZB
         yyuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QlIZcbMZ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k1si447804qtg.2.2021.03.31.19.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Mar 2021 19:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 372E36109D
	for <kasan-dev@googlegroups.com>; Thu,  1 Apr 2021 02:10:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2A75060F24; Thu,  1 Apr 2021 02:10:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] KASAN (hw-tags): annotate no_sanitize_address functions
Date: Thu, 01 Apr 2021 02:10:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: pcc@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-212513-199747-9wvlWRDqRU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212513-199747@https.bugzilla.kernel.org/>
References: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QlIZcbMZ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212513

Peter Collingbourne (pcc@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |pcc@google.com

--- Comment #2 from Peter Collingbourne (pcc@google.com) ---
An alternative idea would be to create a compiler attribute that does

mrs reg, tco
msr tco, #1

on entry and

msr tco, reg

on exit.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747-9wvlWRDqRU%40https.bugzilla.kernel.org/.
