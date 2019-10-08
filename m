Return-Path: <kasan-dev+bncBC24VNFHTMIBBK756HWAKGQEHDRDOAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42490CF99F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 14:18:53 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id q187sf6414185vkq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 05:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570537132; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZK7hHUBYZ9s6FBt0h3g4RVmq1CCmifEYCcFBu/dZx7FkC8TsIwIROCi2EaptfRqeMZ
         gGLYPWkpzg5KeSQtjDX29C4doEevEzbvGMM8Nwhj0EOKyPTy25YdSe4L20cAoH9M678R
         KAG4ZlTQWPSXo/dF4I8UaKNHDPa0qLYiYxNNYm2RPEXMoVWsKCePDOv6O8qhj1Z0aSsh
         CE3Q4j2KMp2JJcQGRW4erQjBNK9NdVofzBb20926Tht6xMFN0VOO9+AwL190PfbzWmJP
         BdE4iyF6GOWfLeayx46B/W39v6/PtGVxrtmYj3/ZruwogU5CTS8WPrZF+Rj+ZF60/ziY
         hVqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=FHzTGQkznenpuGYsRxCw1jFEFB7N/GcEoDEiOnYz+3U=;
        b=B8lYuWvL4K20Al6zr3xmH+o4WX6qcrXE4y8eUhjWLxDhaDq8z9jluoiTDQj6MnRfFq
         Z/q1+hJWu4VtOnwaFj8pZQGP3rj078wEa3LC23rDZRT5Nt9tpXn6QF2OXvbMSk+CbI1F
         QIIg1TvNR4kuG7/zGE5ux/u34VLEVd6PGIzn6cVgBoA5VNVZqFJGVUHKzAK+cQxl7578
         1RT6xvfkC4KETGh0drr7h9ytQCC6YjubCDvfT6+LkyqPuHF7adoRh6yiqb2WwwtuqhAQ
         8b4f0y3xy9mybGyx25ZkPPAOC6ZzDOUevG9OpIpw9Z19TOjZ/fsjDWbCNo/FfBf1iNaP
         h0sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FHzTGQkznenpuGYsRxCw1jFEFB7N/GcEoDEiOnYz+3U=;
        b=ajuBhFo+M4LyhF1In+NpLYZqLIBHZPv5Jm2iwX9WBeGLDa/pUnZEhw1+a6bzopy3CN
         G0y1MP1X1sshWOB+1Z2xLgBCon+zga2bEGshp9XucH58F8AmCb4Qruf12B8VvESPYUMa
         fI+Ou1sQM93emN7Qin2mdEugdAHj3SZfY22alh09QoNWVBBdUwQ7/5G73sBYZmQqwB/A
         wfTlyoEibWRVRvbXHGGYiuYB44A+bcA0Ne9kbMttIMwc34dU8n4ULdS0NRv5Eq0YaGja
         Tdr/tpUqepClDNWgIoZWzKKNIniYacM+0hRsDC3aKsfeZ99Y/+Qbf2PPEqZKZNzEDRIn
         pT/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FHzTGQkznenpuGYsRxCw1jFEFB7N/GcEoDEiOnYz+3U=;
        b=AgQQogxzgN+Fk6t8EQcphJd2ev9+qF/63g6ZT61YHRL3Phmezh2NFSLKQMRq+xZunh
         6zdZeloFCB0J3hNjDZD4KGhhYc08+BHEC6VZzC0eRz3CbFXQeTbeK9rpEf/ITwT1TWAA
         R4R+h9nrs8U/w0bm90wD4JBE9mTksNJgqEMjcztCDRsQbzyrEq/XPGxVr3eke7HCzsZE
         VWtIfs1OxbztFzqQLQL01BRdAst/jY/svAV4UcuTscLOi4K9zgkZn6GGF3JuZpDeNc1B
         2pr0I6WA42LGDNIgaMkl4ZEhTL4KxkOX8OlPRei1LLBAWAsRbH9sTlKFTHuqFlOYoEgC
         jOtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUkspzkcfH9S//ZqG0Zx9uRyyQJFqd/Yj5YmWA4drcNjI+7xp9r
	oBrw+35BQFOWinOVIdyZ4Lo=
X-Google-Smtp-Source: APXvYqxWUDffEu7n871gVHiEJIwLkDNnBSOxg4i/PLsjwzNmN5HRJDgK+VcEQRt+2uEvTU6Yeu814A==
X-Received: by 2002:a67:1387:: with SMTP id 129mr17602789vst.108.1570537132043;
        Tue, 08 Oct 2019 05:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2b2:: with SMTP id 47ls155583uah.9.gmail; Tue, 08 Oct
 2019 05:18:51 -0700 (PDT)
X-Received: by 2002:ab0:2041:: with SMTP id g1mr1278039ual.45.1570537131572;
        Tue, 08 Oct 2019 05:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570537131; cv=none;
        d=google.com; s=arc-20160816;
        b=ECxKNVzxUNoWRW58bn5kDDjXdeP6J7MfnaMGVVR//W2pJ+Jns9pDroMt0twv7KaC3P
         vMzlFYI6DVqJg2lhx5yIKCCVfAmIIbPyJJKzHG1HRdrKaPkDITm15zgWmQ21Wc3zyEl7
         cwAQpQVzOxmI3wtXP6Fhf7sAh4Jry8ot7AXy1+Z0Idl+bBJFSU8lgG9vy4g1IH6Rjh8N
         eCz7IkNHi/D+8q6XxEsfYG0D1HI0ijywnsDpyCTeMvq364ulxI8YXMj4FFxfOaTox5oI
         PPRSdHtE9j4/lIhEulwIZPYLm9HdkqPVOW6BWhaGLWe59iAmIr5WWmdtSWx3YLro+mm0
         bfkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=8na7EgCM7aI+KM9pEPnS7jdk5nCIBKF/fDJsDDJv0L8=;
        b=tqX5b5XbnwvqP6Mpzv4OKYMrD6TQx90QZ3VHaQW7CTjr3Jcv0QkH7TyhXujA33X+n2
         riNzoehP/5ZfHhsXh6P59nUR5cEPjrNqp83NHgv630whmm4rAtYX7yz0RJ6pAQ1ut4CP
         dkxe/3RcP8DxR7OO+Ht9YNwmf9GsdcIgV+QwUXZEgXusR7dI9NOmdnKZf4WYayD4FUmV
         AhA65XGqIoRvWwpyBpQeNEqJfRmpL6Eg2mG30zqTy7ui7pMDUq8n9eC0fDXnRG7XHLjI
         0RMc7SVrfYE2nPlcr48uuCAEEPScQ3/Xyb6tCs+H2kYxRQTpbj8Gw+mChS4Dtt8GIy3p
         E3Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i13si1024527uan.1.2019.10.08.05.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Oct 2019 05:18:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 08 Oct 2019 12:18:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203493-199747-FCxvWzhEwY@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

Walter Wu (walter-zh.wu@mediatek.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |walter-zh.wu@mediatek.com

--- Comment #1 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Andrey,

We try to reproduce this issue on my environment(Linus 5.3-rc1 + clang 9), but
it seem like not to support detection of out-of-bounds accesses for global
variables yet. so Does this issue exist?

If yes, Should this issue be fixed by compiler or kernel?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-FCxvWzhEwY%40https.bugzilla.kernel.org/.
