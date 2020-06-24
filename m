Return-Path: <kasan-dev+bncBC24VNFHTMIBBZ5OZ33QKGQELQGTN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16721207B3C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 20:11:53 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id co8sf2068621pjb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 11:11:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593022311; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zfx2H+1ZpfxWcRLcQ2Gv6kEmIBHk30PzH+1vcusytIpDx/gYcAIfx7roQ57qWpuB4A
         15JXNlDTNQrhw08+M543s3lsSNyYdOXtWgceTk+o0CCYSktoQEW9UYRpA9WP/jccYszG
         Lz0GuTeeIwCsPAJFMdmd0YFuO2O19n3Hx5wp7Ht2azBgs4Eu71vT7KZmzbcU0UQw/g0Z
         GHN7GELhM2DqnGCWft6xiPAk5W0fq9J/vLuuCWIYCqTrhyhqAvplSZ3nRq0pZtM3Wdeu
         hdTvi/MznZocHABMv9WNTCJwBX0uPr2ngebdJPvXZlai/ejdaESahU4JuLk14FklKCYw
         W42g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=rQqrn/uWIq+vCp08d27EQiRde5609Rn6CZ38SAaU9bU=;
        b=PEve8CfzITp2O2AEG4AZff5fOSPZM6gYUrRjeSGJ225QCvoz0SKU29KbFO1uxcQQM7
         dUfTqc2a/0lhGO5vG7CLDuONE97oj5W3qzdbxZwZMOSdw8kGb33dbnqo43z0PNZhfu6q
         HemzSEHyjiiqs+ZjuYtkF++ZoCk9eAgp3zw6Ng5cmyA+hPA2VUcEn3MzgIbCnsrdYO9w
         X7ao0/9KBw+qwdnTEhA34Wg9htcIS8XEZ47J59F6fRofgt8kJjcasuQWTZx1PuMR5WWJ
         7mLtfYV6NGQPswZw9g80EXMEJ8Bafb1a55hnPE6fadRvz6i50EHm+YHH51SrAgwVVY47
         0b5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rQqrn/uWIq+vCp08d27EQiRde5609Rn6CZ38SAaU9bU=;
        b=ZJiWuK/UEDXcLmUNKtSVsSV8a1xxJe17/PIsjsHtWzRl/TS/es4FfnXsvqjtPE7REA
         IGmixVZ3PNedKdvu91uCSZw/3q2LOMNDdvgFGpBZvtzVIPkBsLv5Txbn5fT7JnK45iWx
         6iVe4UKajZ4qbpTO2wZYP8xHfDx4tBjk39K8MQBp7cPWe974SE9zSBlBsT3R9hqnE7Yo
         NmQWyH6JSvhfJoPawbXuFCvL0BYSt1MFlb9gx4o1aV2inq5sbyNaRe7wSnUh9x6GuPAg
         qrXMSAVYbH5yXjGcLqCQ2hFU4eicHBW0ZJ0YAGoXSWrLKn8ANsH4rId/V90QRQC5d9pi
         oBww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rQqrn/uWIq+vCp08d27EQiRde5609Rn6CZ38SAaU9bU=;
        b=WeHj6AukxLwtRHejFs9EPt/oKyx3SywTyJB3k+mhYAkFjOZH/ss4zQSlV90RLN2ad5
         wOzUdUPJGc9ZgBZ2x8N10QtgexP5cgNmXDjA94L7ZNp1v60tbJR0L7qbl1nK+x5IfEgp
         caHPA7W2cFORJ7I5M80ZWRe/hPa409lwXFp0xuBrhn6Oaq+dVa6DVD6JEaa+IPqLw4HM
         ygFV+zha+35pwS58jqPhLorAd5cn9qotn+L6vlrCqkiJomP8isGAhmtVbyKlzalNhfJZ
         /aqOFOBiU1SRdB6vcRLnXaZYnL7bdOlMnRNHyYpqC+tTJS5MFH0UkcHkYb9je6uKYKz4
         KVYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336u0lSR4hMojso2QyXFdEqTXsxOSLd20trJkDVoigGC1cqpJfA
	HytT0n9Pon6tO0HoQDWlnrU=
X-Google-Smtp-Source: ABdhPJyu4e6d4/Pmsv/cBLWmfRMTK8C9YywMaWZbFiuSBo6U1taVSTDgPKRAx2mpwJjgpCzpHtv7qQ==
X-Received: by 2002:a17:90a:f3c4:: with SMTP id ha4mr30329326pjb.18.1593022311283;
        Wed, 24 Jun 2020 11:11:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c910:: with SMTP id o16ls901322pgg.4.gmail; Wed, 24 Jun
 2020 11:11:50 -0700 (PDT)
X-Received: by 2002:a63:1617:: with SMTP id w23mr23355075pgl.248.1593022310812;
        Wed, 24 Jun 2020 11:11:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593022310; cv=none;
        d=google.com; s=arc-20160816;
        b=JUEZeluAJzxby7J2i3Nn0CFPRxYkP9C6a3n62cDQXHagTNKwJ5kAf5HXlL8Ev9K6DP
         BRP9hcWRgq2axq1rVSXh4CAjuLEFRv0/dBTm3/VJUQ7pKlzJhyNoIacsfhcHRTLqgRnu
         GgiF4GiTiinMJihklxKWHKZtH1uxZILKn6VsoRi6oql+80SbpALDNn1cV7NZBIgNO14p
         qZptR0JYIU5DFg+GdN4DFLNOk8RZLkvN6sRxZY4EcW+BGPxD8xwTAnmuDYQdFQwBlttD
         ZO3JmGS+9BmUKh+c3heYE6OIEem8myX9ZKPBd2JRYdq4TY5UufScZ3LURsG/6uDWbBWZ
         m/dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=V62a5M7PzSMUD5RQmQrDWWpai9PyRBy0YKp5U/gCyss=;
        b=nVW3Iu3m4xrX5SxxbKqffSg0didzzwUrJpGGFijHG52yTeDSzqDShn4xZZcLFPS7NK
         pjT19+b1G7CGETsczfLgNT7HRRhfpickeQJJv2NWFB4ntQWK5RN/SglK59VP4mApLg6x
         CCE52YMQHc/7rQTW+qrjlT2JvA2d5Gvtzso51SrBXivb76gX0xaJZCUjrBrJK8AUL8eX
         mS9MmrQiwELb5vQdVEYS9wQQivtKpHOcFCld+bflYbuD+ilyZQXZ3IINFCEbjUcb1dTk
         NMbVDAcrHllZ8PlAuI6+R9lFijUBEpG0KO9ZmRIQ0BKbIjyLrMbF8DbRfbTUhqtnPL2a
         mc+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i17si274384pjv.1.2020.06.24.11.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 11:11:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 24 Jun 2020 18:11:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-BIR56vfo2U@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #14 from Andrey Konovalov (andreyknvl@gmail.com) ---
Hm, right, then the issue I'm getting is probably unrelated. Let me debug
further. Thanks!

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-BIR56vfo2U%40https.bugzilla.kernel.org/.
