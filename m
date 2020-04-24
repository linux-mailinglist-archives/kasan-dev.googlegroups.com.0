Return-Path: <kasan-dev+bncBC24VNFHTMIBBDV6RL2QKGQEHQHZDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id A55FA1B6F95
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 10:10:55 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 189sf7096234pgb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 01:10:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587715854; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4z1M0WUouRk6/OXpt47EDjtJqQReI2emksgHaB1Nd4Dr3q/b7DNH3sJutCfIZaQP0
         0JtHV+5hwUYL81uV2e4fua2XJvF6QHCRcGr9g1i1uzveFI8UYJBiYYqLl0oItgW9bWOM
         p7quhuirSw1gc6Luw0JP9E+3cMkjNOyiTsa0wIg2a36Rv9dXBcpQN7jEfBQWHYTOQ9kR
         ag/jxV9BBDIHGa9+AMOwaP//yBWoQRABZWphwCQyQcXKACoigQcIYo6ekABZRh5SC26X
         kWzXV1FVSgNU6fc7Zht0rZ+Axs98kMg67XInIxwYZaHJpqsTtboH8lO6Qw5/D53ozsJ/
         /3kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=S5PShHgaymmoaiLe/o89iwUdRcerbn1CjQqC4yOfsIA=;
        b=02Wa0ZdCXDBL+cwdaJmNAfp3FCAS4HesQoEZgemVi6Sa7V8ltm1zgk7uwoNIP2AMv5
         bfmJpmvU4b49ny4KEXl5XzN434/O48cbeBDsuwGAwEqd1+XbVo3gAHFs783iTrz/Nofd
         ZO2kSFJxSoI8bmhVtApaV9IT5cubnmPsaOMmBQykYs2roWmbhAeadlYkPzppX5v7QPLN
         MlXe9NE+9Ndz87U368A640NbAne6xXZMsbGcotHCZWv8Tpom9t9d0hZSlb9Xu+xYuXWq
         fpE0WcLguvDNbHbCNvFQmzLmKkLaXwDDPXy9mpvKvwlwQVfwz8Fou5Y+zarsqZXPXUWL
         Jydw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S5PShHgaymmoaiLe/o89iwUdRcerbn1CjQqC4yOfsIA=;
        b=TkNo7A4VEu6XvuVvqZtO3Gkn+qp3ynryC6AerJUWVrHXDPmDkxOR3Lw63TSqifTIyH
         rB5RJGli+Wfn2iMamAP2q8MqkIBvi/0JMp8FfrC2ZzF+TNUWHXyO/hk+JvFnWHk5FFYC
         pYWRyfzIOUT6DPRHVom2bsDLlYcPpAWwZHjUxYqRrR38WMtWOejJfImcYOEDwhQ45SMP
         De28zcJDiCq9dIlN2gnihclHXtt0nttJ5Ea4x1vS9qkmGlFATs7XJ91fcKuQJlfjWRkK
         0YSTV+Ali3zeBzl5ADSwyJKsJVAuojzIb8L+SSn0XtML2EY5tNBaFPxOWdtTHj6qBhKa
         Uqqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S5PShHgaymmoaiLe/o89iwUdRcerbn1CjQqC4yOfsIA=;
        b=b1k8TPHWEo9SQ5v0scfC0CHSuTORVJrExgm8aTGjES+pe+c23sCCVhslM6LHqk1q8j
         OOkI+RErMTQlHh1ANRt1khiex/IqmOh8rH2i6+0oVGc3zeJBs9WD9lMmGg70MZl3iYaU
         gYbuoqhSOLvsNwRPouVUy2D9/PlJ+KXa57nJUA51vI6WRVYVwcsgkp8XvYKggdjqeYrE
         5KBZ2V7TSpMsQhSXuEVjzkCfuJ6dHRx5OcrYR5y8ZK7kc0O5yfGnwJXoJegMDg7+4Z37
         uIjhh4Gw2x2pljTHklHpjxK8c6XbhRp74zo1sgjtBD7k6BK8Lhj0jocKC3QtgweXOcEi
         O0Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYypW5myFeFyq1pchLqhwlE/oaPivSHPPT9uWamh8OM6g3KAzSx
	N2MxtovZ/pQ69nstxWP0LV0=
X-Google-Smtp-Source: APiQypJWqIXxVuasM8Hr0kpLbQASWiMj708j1CyYJUaKiWYDjomC/FkNWPa8IJro9VQmhpgzoEdBfw==
X-Received: by 2002:a17:90a:8994:: with SMTP id v20mr5154116pjn.76.1587715854245;
        Fri, 24 Apr 2020 01:10:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:834c:: with SMTP id z12ls6332086pln.5.gmail; Fri, 24
 Apr 2020 01:10:53 -0700 (PDT)
X-Received: by 2002:a17:90a:ad93:: with SMTP id s19mr5152968pjq.73.1587715853676;
        Fri, 24 Apr 2020 01:10:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587715853; cv=none;
        d=google.com; s=arc-20160816;
        b=OCvPy0Td/uhKhvFPAuuJbtPdDUASkMuw65/80aPDNxmNuuOQcliRqWT7GZ0xfiHDIA
         dlLAK8x1Cpr6hvxicHi0epoU9FLEI3Ej/VCDhBoXrcmrvGzWsEPv8/OBmMsEn0N4e9Xf
         02SyRfszcU0d28UWF4SW80W954/Jb13dQmro36Ygs0UzzOoYLQoFBbi3yCYKVakhoVkT
         1nbjMb63tQ4zZSrMmfgnu6w4xtAQX3sK7L8yQYSfAc6WTDi4Q3hiWCk/Y6LG6QI4lyOv
         5LKWOegNpJ1ckp0au0xhthSBG4jFHQL59w149cX3GQM8GUHMdQzF90Bk8IJ/jaexa03J
         0L7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=XRV+B26NS8GCIbcXrI8b0gSkQaa0nyJcLwwUuELxu4A=;
        b=fpVsQG/uAFN7bBt9s8O+mbF8smq2bTMPRJR8GyO+kZS2DFDHMl0CjY/LsNf6NKIjA6
         kmM18eWfUhvSnaWJWunLncLGPrExd1HurKE4XFm4XkyX62JXFbBB5eSq64ENVQYCtTIV
         T+r7xKFCQln8yvgnHYFo4NbudsK6PuFfcfkUvj99Hl1pHGLrbNf811W6uLXM3eTIVv5b
         X9BxHfWJCQSx7BKb/jTOiDaKTuanjIoFF84r6x9Kl9PgFu/ebc4fLidOKg7z5NKH5y1J
         iuGscGkbhevGJoCu5pPzkqTs3Iyki3xvbbAUZK//9B4r0tzJZTBuvhNjy2CR7tuwdHXk
         YrpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g20si318051pfb.2.2020.04.24.01.10.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 01:10:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 08:10:53 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-ly4nwhtvRJ@https.bugzilla.kernel.org/>
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

--- Comment #3 from Walter Wu (walter-zh.wu@mediatek.com) ---
Yes, I know to record call_rcu and print a backtrace to get where call
call_rcu. 
My original thought is simultaneously to print two stack(free stack and
call_rcu call stack) in report. If we only want to print one of stack, then we
need to know who should be replaced?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-ly4nwhtvRJ%40https.bugzilla.kernel.org/.
