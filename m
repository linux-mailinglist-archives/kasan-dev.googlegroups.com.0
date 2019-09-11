Return-Path: <kasan-dev+bncBC24VNFHTMIBBCPT4XVQKGQEJD323II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CD40B05BC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 00:47:39 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id y6sf12864834plt.10
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 15:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568242057; cv=pass;
        d=google.com; s=arc-20160816;
        b=RtOoh/9C414i/WGMy3w0iRcdhqqNwOY2m43DkN71kmiOFx4vIj6E5IwL4L5A0rYgRv
         RT2mAFShXKGoRifzTcIJhw9DUDl3PB3VGyE0RVNo2lq2bGd7Epq6Fz0WMIMTT8bLxW94
         QxwMeTgyL0CUeyIhHS+/mPs3sWaB7arpKWejhDBXJrgms+R8Bhgy0MimAG1pdJMzXs26
         I7Izsz74fxLBjLqzMDANJ7wmqXUXI/q5+/51KU8RAoVo/1AZlX1Kz0laWoym5iqcTugq
         z33BtYlbq2x5iYxwIhNO+G5BbXJbAkgThsB4Z+O91aXAQQ0gas5E7LVle6jTq1yiwgtZ
         gxdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Fi3HBBgGxTpDcyTz/j+m2ym4ilIpcb1oejzcX0Q5nT8=;
        b=w0/osElttI9Vd/7Db51f3xFC8UkgOxdNDsWgUBVtxmYsVr9o1mWj1PUFl31bbnB9ar
         CTHPrbu8Ju7oBrIEhXnkP2UhxjByxmVObB2Nr04cHQQFl9ZqcLb8ECe2F5xPzJmvvA59
         8hSP9pstK28iSm+mEfSWF1iP7Fvh7xXusQRW2I+pXmiajPAzShRdfYjcUS1obIJ5iV+2
         W96xvqTKlI9SPhrvKAOvhDmQoJr113noVNI4129xf7LxaTc+mx+6BdJ/zfG7hK1DEkHi
         IvF+1e+KSd3wfRnh6Th9myELE/k/qTT+B07oBWovQxYxklQhG1lIxLzleaeSDDu9oqJY
         Pjrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6mxq=xg=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6MXq=XG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fi3HBBgGxTpDcyTz/j+m2ym4ilIpcb1oejzcX0Q5nT8=;
        b=rqKr/axROSZX7N+heRvJqw2MPPZmjGEG0S57jHtnNyVMxKZvMR2HKkkwFQgpf2XVV7
         D+V4at6NWt92wdSp+nHYh2cKYilyge9FvSFabDANYwn7qu48+8fHqmfeFMo2xoK9nAY3
         WF6ZWdaSmrp2H8CHbwIZjdL724NYkMU769FqJmYnpOaO7fGU4hsq/ZZXAagxAQ1m3xzQ
         mSC+UpN4IGO6d6J/dKP8HrZyf9yQJCLdIL9cA+kH0YtS9KH6BBtOXKYruApI3fJMJ15J
         8nfGkVG7tleoXwOGBKq0/zJ6Pjz3xWSUY5ztJ1G7etItD6NxN7z399MeSn7bsyzFvUej
         W57g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fi3HBBgGxTpDcyTz/j+m2ym4ilIpcb1oejzcX0Q5nT8=;
        b=I0pBZ0lzrfIf5U5K+0xIi/XuuuR70JjZt/sNd8dMKutTSv50q/O4iVQPyU3sOa7mh5
         lro6Ejz1VF8/pwFG+WfbRjg6rMAQeVQ0ouG5MaSSvR8Ts/XW0T63e3WkJT0bXgTjtPxu
         vzIUT9SC8wSMN5fgKN24TzdfTcJyNk2rWZtYiucNwztx2gKRObZLvp9h4dP5zIZzN0AM
         eRAgYyPTVCeBc+NGB4VeCJ6hCvoX+CVPvgQYsY6h8ebfbrzkoZJNm0ZNGugOnBm8eiCa
         /uQxmso3/MaqOgDExxNuNpo7eAn+nueEbP5NugUL1oFSKw0riMNzN7bWHH8UwUh3VAc8
         14/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUmmoKpJjzb6Ejlzhpx+60zBaWNpAervkduV/j9VY288f9n57dw
	g63Plxd9Il8sGtyU/UpEtK4=
X-Google-Smtp-Source: APXvYqymav454e40oYEfUzSUN0c1RNe/lA1Dpn/PWi+5JePcQSV9lw2MwcydKEm04ySAFVXpwUJvQA==
X-Received: by 2002:a65:4786:: with SMTP id e6mr34479637pgs.448.1568242057630;
        Wed, 11 Sep 2019 15:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:20c8:: with SMTP id v8ls5727299plg.11.gmail; Wed, 11
 Sep 2019 15:47:37 -0700 (PDT)
X-Received: by 2002:a17:90a:266c:: with SMTP id l99mr8202245pje.93.1568242057340;
        Wed, 11 Sep 2019 15:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568242057; cv=none;
        d=google.com; s=arc-20160816;
        b=Ea6v8qI7KSQwg0lzAKUf1BVI76BYUcsFni3cngnzECBfJwhIJfduH9znqZ4W1AQ8p6
         7//5Z889s8X7EwNbjX8MOF1fZ+UWQtU7EgKmaB94StnU510vFMQPL8rrcdBzHM0bYGbB
         bj+juE01q28R6m9AGLdbyhosl00NJc5c6VQj1UNikQ3t4AW3omUprOUTbqr9TjseyTTj
         p7tP9ChUqN0lbqqLA7VKjY802k69hqPMKAAdpSCGxxiF8kCPoEcmnRn20fJttN5XNnjY
         aAuHbcO7QDODTX3powRKqJmIjeOYS76ugA4lwSbZwpLsJSFMc+LmMLpv4KBfLs/brNo5
         jxng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=HOPuNhGGlvKjraGMtAvOP0McpOXVNhUBC2jFaH+IFqs=;
        b=pkK6HB1wEy773G+0JCkdkPOHVRb5S/XrwFi0Zso73uU8bxpxCYiVQk0xVjNbQuFVX/
         FG7R7g247W/x2/WAezi+oglwb5tkUk0gJy1l4GriS0wwDcmiSeh2IhinGNv1YTrXFEuw
         MoxED/t4dp3MabEotrTvXkBWQBun589yDN1JcyvwU+8YKfZ42FAcgm2Iu/Sij8DcIsAF
         ujiFYGsAzBKy+x0M9xWEq/ux8ax4WAbfqWr2XQkYsgP5LDUMUSkRLhvY8fFxhdS+q8OM
         2u/2euRHH16F0jKSVPWQZTU/pqfQ/rkpX+k21XIX+AEnQ1GHIEfBADDtQoUNwU3cE61h
         Sytw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6mxq=xg=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6MXq=XG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b64si1557226pfg.0.2019.09.11.15.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Sep 2019 15:47:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6mxq=xg=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Wed, 11 Sep 2019 22:47:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: see_also
Message-ID: <bug-204479-199747-TcAZ7Ft5i7@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=6mxq=xg=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6MXq=XG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           See Also|                            |https://bugzilla.kernel.org
                   |                            |/show_bug.cgi?id=204819

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-TcAZ7Ft5i7%40https.bugzilla.kernel.org/.
