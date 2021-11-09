Return-Path: <kasan-dev+bncBC24VNFHTMIBBDFHVKGAMGQE7WUTAVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 73CF144B054
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Nov 2021 16:28:13 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id c15-20020a0cd60f000000b0038509b60a93sf19379585qvj.20
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Nov 2021 07:28:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636471692; cv=pass;
        d=google.com; s=arc-20160816;
        b=KVDPeUDsm/BAlvwfskzhZ/mZV6Bd3SWfwTZ5lMZiTKt8UNTjl/XbTStnFK/dqeVXpp
         05t7nJpuZsfiV8EeW6DqNmDWEuj63zpOGCAitj7a02MwHYtJBprSM7uKmQMQYj7TQ8o8
         lkIhmCkvbOVhukNXMddEN5vjhOTjiiv/2aF76SxYQghOvHH12voGXv4lrDrIL8vNjf7x
         2jw2fUpoEE26+UKH7NDsDLw5ru4rze7tpynSqHHQjJsYQM1syUzbwtuccDvsoelHR3Es
         HCz7OpigZKbOI02f80v+rcJbwa1LAqgbN96I23/2pgUQY0eGj/BZ1m3mm4sw0V3GvV+b
         8vOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=5nLe0/8/OPdx6jUPLEoCcwfq7szHlimaPDO5ilRuNJQ=;
        b=eqoCswyGOSatr8oqtZkguFFgpyi7366YFxVsOrd443ILLrc6t+19IXsMfVTnsua4Rp
         tt+iyDdsqUY5pPBrfklXnLdrYX7Zwkkt2rkQoxBKfqDNGz/gPmAeWqKlsp2J6fOabjDz
         SXH/rcijfygsIOjpKqjK9yH3p88k0gHpKlGmjTiQE0VF+MTZeIOxtS/Fn4sVyvIng0u+
         /2Hkz8/XeOP9M4i+ddZsH56tElcemSzEBzMosxqJemHQkBYQ8sAxjdJQH59ll1KDypJ8
         hkLSLYNlX3HEZX9lhht5wJbPhr0B76Eyh6hrVIVon3OLvVMKXx3TKhaaXvt0mKSvsNfi
         SNKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DZ5DIv78;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5nLe0/8/OPdx6jUPLEoCcwfq7szHlimaPDO5ilRuNJQ=;
        b=TX3RIrpJoNSFjBDzxPA5ZGz9PSsuRu50JfwH6arxEquZA1S9i0WmbJ3PSdzfcepoKm
         0lR84NzfJsbvt1daOFkBUL4Snm5OTLokfye3aTTS3aMH1LeBCyxMNxvgSCgXaHzCoaRi
         zbkzfdpuNWbRZ6Eq+AENjC56Lzm2tnTH9cL2gV9przWWg+6uIPuANs/GPN0BPBE4f/35
         TNGUNweSxgTlmaRp44ObxWHYPv9F3Js3ytvmXAkQMIHJlJGRYRHjkLBUOedna+IGItsi
         lwm/bR/dYGEfgkSE1eooOvKshil96+B0d1Vl/UTMCJ2K18Ep0uQ6IdoeKt3ZTpNeOXZn
         5qWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5nLe0/8/OPdx6jUPLEoCcwfq7szHlimaPDO5ilRuNJQ=;
        b=TNuOBqhTo6IaxCz7964n3OBxbQi2Ss7f2Gt4bjxM1twVEyQ8ZAoKIBWuP6tpE8pw/7
         RPY+0c/swpQRZh1vLw95tVHImdCG7SUFMlf7olDRWt9YBu+btrdBf5Z8HPGER8rd3D1l
         WAmNv22hqT+Bbkgf6pqadK9s/QcWjbfsUEvqisAuF8xIk4oog0LyrSRPsjiX32GTkdpF
         0q7LFA2gL6cgL+mosjudsCxOijN/Yl1fxPPZrfTb70fTTa0goO1oX2uxlL52RvTbFMKC
         XzlnUP2ZzrIFIXukGTq5TxNy91tt4v6QoFznTrN9we1sCzyBovlmxSI0X/GW7uB0hfmd
         pPsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309aUsySVZADSEU7oYv6i4tDwv3SkC2kSGhf+/HzJ0uVmQvdzJY
	D1x+BbV+uUwBRYpgLVPyxpQ=
X-Google-Smtp-Source: ABdhPJxwghCEtr0ZB/wq0dH2+zCjz/Z7gaVjdwJB/XSYjnI5YNqjcGhr0ofl4WIjOZ8ltxdd6jSyVQ==
X-Received: by 2002:a37:3d6:: with SMTP id 205mr4978491qkd.250.1636471692324;
        Tue, 09 Nov 2021 07:28:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e34c:: with SMTP id a12ls1309866qvm.2.gmail; Tue, 09 Nov
 2021 07:28:11 -0800 (PST)
X-Received: by 2002:a05:6214:e83:: with SMTP id hf3mr8235575qvb.52.1636471691877;
        Tue, 09 Nov 2021 07:28:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636471691; cv=none;
        d=google.com; s=arc-20160816;
        b=SB2WnajE6rkQhSAE4uhNGb+B0jptl3/FULVPdj3zgeAYOGevhwk6XgapKB1fItOvHP
         xpDxFTFfwxXeWR8rNe6+M+LKxEc/fXhuhT+EhEefGuXAnLh9e9sRn6I9d+tJROtr/6IY
         ueaDyQ4BbyRDGhEUgakK90VmH3Ph5oq8SJoQvyArbNOGX2O7Ng+lKY4jY6KRGLnFK5+8
         ecJzs7Dxpfc2rSTlPG4110a9kLwswJj2nT95Y+9XHDg1feTo/l4Hegm2pqopCTp1OotQ
         UqHU93twJibeGGfpm1qqzOHgu8UknuF+C0v0Q7kA/mviCIzTVEj9mJf+1tsIDKP69V+p
         RxZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=MWKMopMq9DF8NPgbkBVFe0FnK3IK8keOaxol7w8qIPg=;
        b=dwKW1DbzV3lfc0N6Pnt34PB3cozalc85FzuUngE3u+SWkdEY44M61gnYfU80r0ttDI
         aP5Sh7bixqtn0nhHwzMH0SgY5Wyj/ZrhhHVHlftNz7RoqxVc9DvAn42h36YHgZ4d1s+8
         hgYOLVZHh8QK5rxIXoC39EVm7z5MxQ/mJNwvzPw4aQF+3xt4dp8Q3R7/oNZmTJ5Saf80
         U5OWc8r7Tvmfv/tc3QsKG0ZiF5iMy177Se2zZtKa+F7d2id1D7uwMEHHMKokVhr0pbyW
         7G8uhHKbaWXVT9Niw/6id4N7dCfsJExT+5NFDgrzCste437QJIA2qAyiYM1luq9Zc0Eo
         80jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DZ5DIv78;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k12si1103436qko.5.2021.11.09.07.28.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Nov 2021 07:28:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B4DE26108E
	for <kasan-dev@googlegroups.com>; Tue,  9 Nov 2021 15:28:10 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id A6F0C60FED; Tue,  9 Nov 2021 15:28:10 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214977] New: u64_stats_update_begin() should always check
 preemption disabled
Date: Tue, 09 Nov 2021 15:28:10 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-214977-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DZ5DIv78;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214977

            Bug ID: 214977
           Summary: u64_stats_update_begin() should always check
                    preemption disabled
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

u64_stats_update_begin() uses seqcount only on 32-bit kernels:

static inline void u64_stats_update_begin(struct u64_stats_sync *syncp)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
        write_seqcount_begin(&syncp->seq);
#endif
}
https://elixir.bootlin.com/linux/v5.15.1/source/include/linux/u64_stats_sync.h#L129

write_seqcount_begin() eventually includes lockdep_assert_preemption_disabled()
check.

Since most kernel testing is done on 64-bit kernels or w/o lockdep, this
requirement of disabling preemption around u64_stats_update_begin() is
frequently got wrong, for example:
https://groups.google.com/g/syzkaller-bugs/c/w0LYzs1jUlc/m/DMaRQM3uGQAJ
https://groups.google.com/g/syzkaller-bugs/c/876hMz7fO3c/m/PsQD-aUTAgAJ

u64_stats_update_begin() should do lockdep_assert_preemption_disabled() check
even on 64-bit kernels to catch this type of error earlier.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214977-199747%40https.bugzilla.kernel.org/.
