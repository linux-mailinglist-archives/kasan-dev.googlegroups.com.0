Return-Path: <kasan-dev+bncBAABBEEF7LFQMGQEKP7WPMI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GE7rHJOCfmlQaAIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBEEF7LFQMGQEKP7WPMI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jan 2026 23:30:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 175B5C43AF
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jan 2026 23:30:43 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a7701b6353sf33683595ad.3
        for <lists+kasan-dev@lfdr.de>; Sat, 31 Jan 2026 14:30:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769898641; cv=pass;
        d=google.com; s=arc-20240605;
        b=a9iDvAroDxXu4plC4OZ3Q4dndRVzTRxJXtDRTDcedWhHRX6hZLfW8u0fnLX70cjBRW
         tBw9ptsXA4EHDxhYhQZOu5VHNRXiLWlvlHr4g/jQMwXP4sTF2ceWKKbCOQYLms055YhF
         /GSEeqh5tMyf/lK7wf8pgE4Haup92HhMO2+HjyxIRzllj5T9UWhrC7R2PgXwOfdY9qJ+
         QczjbTNuvlFdxbQDL5qBUbdbEFUldlDcELaGsLPaEWpBjVKOvOpA1w2jRmtEW822GFRT
         2BR3cvLdbfA78QffriDx76UPALlqXsUKg+OnEp3wSeGK9CiYVw1zL4oR182Y9cRWf/8r
         x3OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=9wBKR95W7tBqXHvhbZlWeu/PfX4W8Swk/CHG7L6nvsA=;
        fh=LCPtnkI4esEZaGSgV4JYdqJewhl9wtkKs8gLJUnmN+Q=;
        b=M2B7uLKUDkisL62C/QE3vrs+UPjjtUcDqJ5XLRZS8Cg7x04p5zsKipi3wR3+hmnI5O
         OtosXLVv9Rs5nsaL7UrOnmUAeO48nrCrsVYbt4c64VJBhH396oU7JMlI8PABsg5rJZ62
         8TI8BwkIlnSSyEyRHBEZBkAtDp4PKqZS7soWV4iWaqN/vU1CO3q+CEUouX4dyu0wKV0t
         l3iL46wRmIakTeG45hDHWv4ReVv1oVpP/7u5DV0kAtNTM1HlAulWcWMbiP+P+JG+qoy/
         REjR/kfnIAZgOX9qQuNUXO9UH/mExHrPEfE3Ey+VR8smtPaDnYWlTOhsMY+LU5uMEz8O
         By5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jY9XtYn5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769898641; x=1770503441; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=9wBKR95W7tBqXHvhbZlWeu/PfX4W8Swk/CHG7L6nvsA=;
        b=sprfqqvG87fYr7jW2oNzPK8ReMrRM4oyJpx07O/tmtZ/NRFii3GGjrl7EFVlZj9jOu
         M15EGvLkW5ycUAzZoIYIJtnygPlYShBN/144p4Z0LIW7Cg5eDF6gE2m1hXrU6sO4BqYt
         8MylyGQTMMwzF6Skcp0gjXksNBZtG14gMxaC/UI1fPfMINSjRZbCAat+IlI8w9XJoOX0
         CxSwotigMP3n9q/kVOvdHhlUEKTlKS5HWQpaSLmaldx4SRZli0F3ZzcEfcY9QqCCaG+l
         GT8fh91vsgkXl8Gg7Rarb/8E7OGvgVM2jyAfO5yPO7IHxcKQfy5uaxD6+0EpqA14z+os
         LXyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769898641; x=1770503441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9wBKR95W7tBqXHvhbZlWeu/PfX4W8Swk/CHG7L6nvsA=;
        b=BCrWz1wuovV0uU5bs26VVTnTqG8Aurzf1rzRX5zpwJHTBO88W9iSgWp6ZLnH/P4UMl
         scjBGPV866yOpxFTdo0uOrFqtlmyVfOuYKndNsC/+vKDX8VpqX4baoq0wUHbHBfNcC81
         sOwRhudzY7eh1GgA/8QS9buMEmp3d3jTKlH6CyhhwF8fo2j/2zZcChclJ4teEmXhFmc2
         EDxaOUQ9sxKNMJIupNwWR+MM9OdAUEqF9GaJbBmlE+W0BXZIr1a0SvYmK4UvxNFhgNIq
         gK4GXSU25LqiN+4xQ/XDuWn6/KjI1i79MdwBn1OIb2emvUIE2JKfdzOM6oR7UFAyDQFn
         LJuQ==
X-Forwarded-Encrypted: i=2; AJvYcCVMeCEaReKfziKt7b53fR+p5w3n+5lHZG/047uXnsQ8v/FEt5d+3nr3T71LVowbmlrGLomUKw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0oMvp+KCgNRw8FIHz5DzoJyBKlgH19iwEs+GMdVDmh6ek7cmr
	7OIYS7v6YQQ8Xul94k23WT4bp6zUie1/1bv5SL4yS9go9cepadtZAT0Z
X-Received: by 2002:a17:902:d4cd:b0:2a3:e6fa:4a06 with SMTP id d9443c01a7336-2a8d8037a68mr74037515ad.39.1769898640928;
        Sat, 31 Jan 2026 14:30:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fcbhgqqyz2mubbyQEBc/L/Ixpy6OCnsgHrmx42/lVx2Q=="
Received: by 2002:a17:902:f2d2:b0:29b:96c1:2de3 with SMTP id
 d9443c01a7336-2a8f3fba5e8ls5228585ad.0.-pod-prod-05-us; Sat, 31 Jan 2026
 14:30:39 -0800 (PST)
X-Received: by 2002:a17:902:ce83:b0:2a7:7e00:6a96 with SMTP id d9443c01a7336-2a8d7edda5emr78917355ad.25.1769898639726;
        Sat, 31 Jan 2026 14:30:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769898639; cv=none;
        d=google.com; s=arc-20240605;
        b=ZldRftqOLpmZsgIvwK9JFj37YvdIe9vPvETDS5NeIwXy2p2bkxZ0ZP0eLhLRfxz3Pj
         87INq2H9f3KPbLi/Gx5QkX57/4eGP7SXq8xYSAQ3S/Yi6ApkaaDua7IVVcxUOV70EL4m
         A821p94xyDTtic3ARjjppX0J2c9hkMsTRD/DZehFTjSSsLbHc2Cvg0BYHFQvBzhr17L1
         SFH/RymfHL6qB9ngtMQOfxRbwwCYPkcjk2EgyRoq/ZT7WV8jhJZJZjlLBJMRYsjuowqq
         Y8gIu7fCGqR8DbfCzpIvJLzHeK1AeSz0pDmWZ7sh++QMXswILDGvJdYVCgMizbBGKANo
         9uUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=TJu0lP9L/n119VBWY0jYZEBer70kbKugavaVSxOGtzc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=IWEAbBbPKZyDFwCyaFdMACs2jcjhlCmt4ctuicKb1c+QbsZYu6ogHfHXw0/5P5qQAl
         h8GpPQFGeL3uTRQd5NruuTaOiLjrIP53iA9ovAPu/UIdoorzdgBdn5ltNJ0qF1FY6UeZ
         mFQONJzLfrC4PzrZc6d7mzVWe20lL60Ya70Xl62O8FQ1U28bLxEE/mFFWBWwNKVpMHGq
         +/+JeRpFR7YhBuQLZfNC8vT5YH1tDlsMwOHlXWV/56LwNjCc2g3g2EFDtCOqolSVxgm0
         AQX4Vwpide8Jqz1tes6tahenSzA+aFefeWLW0gs+J7mSNiNKj7oQTsLHdNffH1vkJ4vx
         N4fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jY9XtYn5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a88b80aba2si4448665ad.10.2026.01.31.14.30.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 31 Jan 2026 14:30:39 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4520442D7A
	for <kasan-dev@googlegroups.com>; Sat, 31 Jan 2026 22:30:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1BBEAC19425
	for <kasan-dev@googlegroups.com>; Sat, 31 Jan 2026 22:30:39 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 147D7C53BC7; Sat, 31 Jan 2026 22:30:39 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Sat, 31 Jan 2026 22:30:38 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-220889-199747-WAtUGkeFTA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jY9XtYn5;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBEEF7LFQMGQEKP7WPMI];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_ONE(0.00)[1];
	RCVD_TLS_LAST(0.00)[];
	TO_EQ_FROM(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_NONE(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[bugzilla-daemon@kernel.org];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-pl1-x640.google.com:helo,mail-pl1-x640.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 175B5C43AF
X-Rspamd-Action: no action

https://bugzilla.kernel.org/show_bug.cgi?id=220889

--- Comment #7 from Andrey Konovalov (andreyknvl@gmail.com) ---
Should be fixed by:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9b47d4eea3f7c1f620e95bda1d6221660bde7d7b

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-WAtUGkeFTA%40https.bugzilla.kernel.org/.
