Return-Path: <kasan-dev+bncBC24VNFHTMIBBW465L3AKGQEN2IJDYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA6C31EFFE4
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 20:30:53 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id u204sf7021500ilc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 11:30:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591381852; cv=pass;
        d=google.com; s=arc-20160816;
        b=lW9r6XSowbmhBZImpF9HhbghWeAj90gqTJbDNdu3+rQ3Jad0xmZtdyi4GVqIXy9gF1
         e1D6SLYbFwopGOkR8EXNFb7d8k1gR+2ZzFBxBzXJEmGdLdarEvdQEyKg5VNVv07ybs29
         z8hBoGbuQcPswr8dwnvpzmhBu9+wmXJez3SRe6AwTUK1ZgQ4s9wC6cm0gZpAAHl3D6lD
         OlMcMlekAy4KPvldB1RH+nqvcXAkY7cjpgRkP4mPxHTm/9UU639MVES0GqpE2NxL+H3R
         YSs+7nT7ltGRLSzrspsmBc9LFlhyJDsUu4GKROqV0WHiP/gup48OMNmqmbt7Kmo51I8A
         Y4gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=J9ZGM+V7NF4Yxgxe16ijbYzlgfSKU07sYEGyGhrvPT4=;
        b=YWebJ0KLr0gOemEPz8sv1ZrY4mgoQpcI7rHJOwoVePXUOYwkv8apFEa8v0/MKUKQ/X
         RPtAW5rTzsOhC0eCM2xYvV9Yxsqn/7cMkuA0xBKghdtl3IDF81y+6BnBWuzXCKbAeZyO
         GZMpkM5KX5C7sEmt6AsoCt7MVzH8Jgg52BI8ugzUCzHPgNCSKF/t1G4b5feeFocozETS
         vTy4gCbpgrWrnjdvLPbnlSmkZzyTCU/ovNREV/f+a/S7wQjwWub422TNnuQR9nychfL0
         QuHOq0jClZZfPLTPhVQexLm9TRRE/iqt7wMdu1KUoYrFzJaugc5K8hnIKO55zwiHNrqA
         xbaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=sxn6=7s=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Sxn6=7S=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J9ZGM+V7NF4Yxgxe16ijbYzlgfSKU07sYEGyGhrvPT4=;
        b=R+Phf4/rTTBMRKm9Ec+f/ESjibCEKlhxipEMwvQyDPxuZBUPgX1M02bHm8Jchx98ly
         2EzB54g0pnQnXBcODILqtM+IymSLEkfVpXmTnCJS3Ql+Hh1raETK/H7KqJWvGNIXgJm1
         bJlKSwj/Q56mPgHp4GuOmbdoo4cwe8NAoC+DD6qiO+T57W10vgJYeTAWeQsFQXdLeGJR
         ivDB8pfIkhvRw5ks59wVyMZ/mHPdAEn5PpL0CHF2hyIxuN+GuWS/io4oAhfbzQUn9oEQ
         op0eBaQKzqrSePzbcUCtHOTNTnp3RqCEkndLtrPNznK1C7/rQu5gUbAlWfJQVxHLZeyI
         hj/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J9ZGM+V7NF4Yxgxe16ijbYzlgfSKU07sYEGyGhrvPT4=;
        b=TR2hDbTp+bpTsjNhOsHzFthYWDQVKj0tBkxQqZDYTJVGnyq+6ohq/KPUJoDEvHeUZl
         Q3T+jAQU/zOX2b/gsS5f9TfhSqsv9ToPvg2gUH5x2QsIslCNJCH7u8z0hwR6oqgVHhC+
         0AvMN5SvNwxd/NBcDxCG9qYXybOtiwnb0fWTW24cNyVWtdVH3ecgBERnTaFzHg1qn4ao
         Zzr5cXuMCMS2KO/WMpi8Aj6ZNn3yYZRUmwRSB4oW48+Fscx5Dq82vwksrG6j3LD66ixl
         zGyT7ZpfnvbD7U0DubhWS6mGnBCUgiaeg4XphaOWlCq+Lgc6yowIK3elT/Y64gJOfvin
         PQmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531blsObMuGMZ/lp4g15gSRtJYJ0MXAgTwa4wz3wsiMv+EnG34ro
	eSBhHho2mgx6QhdqeOY4ur4=
X-Google-Smtp-Source: ABdhPJzC6ZMsdFc5LKJqr8Ehg/LMDIafX19kYiWraLFdU5Ll5o6H8V9ESQDdtH+MgeMJMEVaASCOJw==
X-Received: by 2002:a02:6cd8:: with SMTP id w207mr9895761jab.49.1591381851124;
        Fri, 05 Jun 2020 11:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c9cd:: with SMTP id k13ls2764601ilq.2.gmail; Fri, 05 Jun
 2020 11:30:50 -0700 (PDT)
X-Received: by 2002:a92:905:: with SMTP id y5mr3473915ilg.128.1591381850163;
        Fri, 05 Jun 2020 11:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591381850; cv=none;
        d=google.com; s=arc-20160816;
        b=Eg7+iLrXM80LibR5sNcl0z4jFCLBrQT/3nL4S2XGi74yboF7BytpWWrk+ZEzRqBD6e
         yqCp2COnC5AegPzLhlJGHRkv2VXSaBXrp1GRLGXG6oekj9/ST6TKvvTGlbmujHeF791s
         M2biM/cIAO5OC1MEtL6gCsz/iSbDms5vEmLX7GDYdKJjjujd01fk31KEHys/nifuVCeg
         i07vYQ9zNXHynSFVHMZZ5NocL4BA87XH2VlS3vrNTtS9duyRjwPpAHrWhS+8pBZVOBt0
         /wH5VZ0UVOU2CwZW9NLQMAXMurUnLr7C+HojJcXnqtU/acbmNgv4+SCGHy368HSmdd9l
         HVPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=SiyudQhpIZqdqHwJyzRkycnxwM/vKLmqwazUVI8yR4w=;
        b=WQuKozCvGuoIHPKHQu7m4P+70RFlUKRaHeG9sa/1tLnHotEb7z/cH1hJREd9L2Prhr
         AKNDFjk+fE0eTBXe+99VOgNtrWf5+z2291Q3ITThq0EHDzhEUNqa7DbDx1BURt0p11Sq
         GoYUWwBmDeVHA2XotSpY0P2LnyrXpT9X2TuI43iTa8l4SCFzZDHx24D4C1buIq5g1qLW
         Z+Lf8rLELVPiT9udeSOtT6y1hdQI4MrD+U2ABmGdfpC1Ra5eHQBPNIJ6dsqNkn34SpUK
         8T69+10tOaM6NIb0M4f121stAOVPJqHE+SINkLbDGwcMkO2aA8QVRhZ5psVjJqyBIyuM
         H9Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=sxn6=7s=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Sxn6=7S=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z11si233654ilq.5.2020.06.05.11.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Jun 2020 11:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=sxn6=7s=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Fri, 05 Jun 2020 18:30:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203493-199747-vFYsUWRzGN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=sxn6=7s=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Sxn6=7S=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #7 from Marco Elver (elver@google.com) ---
Globals supported added in:
https://github.com/llvm/llvm-project/commit/866ee2353f7d0224644799d0d1faed53c7f3a06d

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-vFYsUWRzGN%40https.bugzilla.kernel.org/.
