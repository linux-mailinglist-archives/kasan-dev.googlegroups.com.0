Return-Path: <kasan-dev+bncBAABB6HDYKRAMGQEG7S6XUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DBF016F3DB6
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 08:47:21 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-24e1b29c112sf592553a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 23:47:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683010040; cv=pass;
        d=google.com; s=arc-20160816;
        b=d/J0PCz84Kx+d8wc5UCWkvycCGKfIxMbuzntbGeCmKhhAN+I+bhIOvTMnYEwDi4oCC
         gW72A+S7BSHnKEEZ8GMKDqHbK0W3eIKL9yLxmb5p60LUBvaS0dLdPqNP/ImrbZNuN+VT
         hwdMa6+NCT8MZ52V+Ra4lKNbhl18prCbLdKpAyXOVLLc6pHeBarbU2IERM3U9e2HDZEN
         FtB/AxqB1jlMxBgmlSFrig/KQH4kvxiCyrctm8WNgq5vv5+yZhtik4NhINyScXjxhjEK
         J+lYy8T7C30hayQ+NRM6T8mxyrY02LmVGDJ36kqSpjCgclxX3BvnslsjENToWNPPPjNC
         IseA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cnMiW/Cjc9T0K2RX2xbyDYqm4tvYV8RUKJQiCI4gVKU=;
        b=yTwp0i7gQHhvFCazoahxrQKHUGq62Dr0nU6i5FuEdfSxdf9pBH2MCuqYz7xbsVrqaU
         9nXz1RHy6ZV8iEd6cPRTW0AlhnltZamiE21ayAPr9mHxvAVhbK5kq1KM71LwYvBPHWmq
         yebwy+3720P65T8kgUAMC3T5KZ0METQPahiL0LmsBBHzp7q+KtVLgt1rrq/jUYYIyyVX
         6b9rDZxnQzH2qHdkXsPfuHZxKZMGvAYVvgD60j3URj2/0qhX2SladFC9+kjEHtx7MOnH
         /ezdBbJTnpzqhnLAoqK8QLNhCafCWV84JxAJ8/vt9+VL1EUEDOcp9+jtz82CMYY+Pft0
         e/9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gIAwHB5S;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683010040; x=1685602040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cnMiW/Cjc9T0K2RX2xbyDYqm4tvYV8RUKJQiCI4gVKU=;
        b=ZFTb65+uKsOjVRG7T/q2ATwSZI3Eq5fycp2Y8aZ/3BNDu3lX4VTvcUPf4vL0JV2FTI
         jvI+MyIrSEXcqnbQonxmPkec8WBcw7Va4I5mWPc74bW4UcbY7KlZpR9ctIkDVhi+JNoj
         WjagrtG3VOjnaevL8dg2BOsheomWWJv4wsIHupzcV95sZpLD4qQdxtXfuUsmgirqCaCM
         Q6AgQx8jYAjvPAORYorX6MMTDopGkWaL+o9oLlrtrR7Fiexbok/LFbbWLmMbFw01BqTG
         S5XSYbqbvvyB+Iqgf6i9kQIbixaKENQzyn+Mz4P3NHTbEGD8rBIkiwHnp9cL11Vp/4Vj
         Wm4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683010040; x=1685602040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cnMiW/Cjc9T0K2RX2xbyDYqm4tvYV8RUKJQiCI4gVKU=;
        b=Od0HPLwusQbrHQBxvbMImpEIZ/O2eOJkGs0FRoMcxvFTYKOWTFN0NyMji2vlUrgdVb
         +10oU//pXEfwtWKrKTu6laJnsdEJ1zvzp54dnB0FZxplwn30XC8wjhOpaFO7UL63kEhv
         X/AS8QO+tGvqJOqkR94f28ycGRON1X9NUPaxBK8Z/38GB+Pi2WEjb84S+s1LP+GkoHoX
         m5Q0j8aBve/QUFTmQRVJjmlNSmubh+0t9AxN7bYPhil0y3gsjApqUqIA8k7biSinyalV
         LQlY74Aj38zRbt+dwSAVuVfQXyjdQSm06IGQqktC+vmo2ctqFMlzlCfdxRFMYNYfhTB1
         lV5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyTIVD/eOrzYenUY91Js6lKP8BJWdpGto4vEgJCJ7pqoiFu5t4D
	7ejIYDEDPpsN6nB1msW6oA0=
X-Google-Smtp-Source: ACHHUZ4NjCziLBwDjSXLTBZMHgGQyM/1EYMAbrT5ElI+HgbfoSyKt/oHzHDi8qlMDtbbY2yUuJe4ZA==
X-Received: by 2002:a17:90a:7802:b0:24b:a5b6:e87a with SMTP id w2-20020a17090a780200b0024ba5b6e87amr4119745pjk.7.1683010040199;
        Mon, 01 May 2023 23:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:78d:b0:234:2ef4:2e9 with SMTP id l13-20020a17090b078d00b002342ef402e9ls13196205pjz.0.-pod-control-gmail;
 Mon, 01 May 2023 23:47:19 -0700 (PDT)
X-Received: by 2002:a05:6a20:258b:b0:f4:3935:4470 with SMTP id k11-20020a056a20258b00b000f439354470mr21223764pzd.8.1683010039610;
        Mon, 01 May 2023 23:47:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683010039; cv=none;
        d=google.com; s=arc-20160816;
        b=0TetTIFSUo7aq8QjzfqzJBG25sbgRPcTINK7j8i4sLm0Htac3sr5g7YInKSim4rsF6
         PsHSvzeKhxy8IrIGeIbk0XhXREYFPnoImfgbqULiJh3p4Y5VVswMIaFcFFvqkfm58FPI
         e+XAbIjbLSeVnf9UweTeuT0+yawZ1u0J84CPqDpXs4MfTq6+JYDPvpOQghUjd82Ln1g8
         6lL4TzSnDuMx6yaKd+YboZh2fOJ8e5FE2SlUt7GzHzA2x9OL4CIOFgjr5Wc3YDlPlDFd
         +7O1j+TzABjkQUacA95MTEm8m2GpHVY+0211hp6oqHTv2wz7eUxnEvSjBITvkLaUVt4v
         7nLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=mmAN36h0zT8sAFObcQarw87PHLV+ekaYesDBhoRQkbw=;
        b=MK2TldInJ8A2UtKl6m5By2qphZcE5afdGtT4vczPTrKBB45XZDUKZ2SPFnajEbaIuB
         rIeNqDVRSha9XQk0annY4qIj/pZV45Tvuph6AunPKqE0uWhzubHnsFrQtkr5aLjbcYKz
         S29X8JUmyjpveL5cSOYUgANfhyGuyo8F30AZBNoSx+CWLoBnykLLPuzg4yKslsF5Stx0
         N+pnWb9BqHZ9rCuDTaMSr94Wuu/xjPKtMgwyhD1Ow40cHTwj5sFsz8linYS8MgesoL6S
         SQ5IGJ5PKxcleoNUkt9fiyJJUGEEkYvaCQ6/J6vfwSsq75/o1M042WthbKpZVHtirqeS
         fIUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gIAwHB5S;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o23-20020a637e57000000b00513924516ddsi1638629pgn.5.2023.05.01.23.47.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 May 2023 23:47:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0790D61AD7
	for <kasan-dev@googlegroups.com>; Tue,  2 May 2023 06:47:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6B6DBC433EF
	for <kasan-dev@googlegroups.com>; Tue,  2 May 2023 06:47:18 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4CE3BC43142; Tue,  2 May 2023 06:47:18 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198443] KCOV: trace arch/x86/kernel code
Date: Tue, 02 May 2023 06:47:18 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198443-199747-78soLhoQjY@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198443-199747@https.bugzilla.kernel.org/>
References: <bug-198443-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gIAwHB5S;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198443

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Probably makes more sense to do as a allowlist instead:

KCOV_INSTRUMENT                 := n
KCOV_INSTRUMENT_foo                     := y

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198443-199747-78soLhoQjY%40https.bugzilla.kernel.org/.
