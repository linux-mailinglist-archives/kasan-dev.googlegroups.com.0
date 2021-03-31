Return-Path: <kasan-dev+bncBC24VNFHTMIBBKO6SOBQMGQEKUXBMXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B2C33509C8
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 23:52:42 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id dz17sf2129320qvb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 14:52:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617227561; cv=pass;
        d=google.com; s=arc-20160816;
        b=B7QtdeSnglc3vWlBuZsF95bBuQoRhFF9ao1funVPu3ajvTFMVMeN8xFWnRqVctSdwJ
         sRwbA/6xRBUTxm4w9rDgLBvI7dxHPrBze57bTGgAGwHslP/B4tcX4L0aDIMeQpo9eNkw
         y7w5KS3a9cEdNUSCvHDIYD7l1ejPMrE6wYd3mUNHgRuyV2B9nKS8ynt4WQz+VKUph1G4
         R0aLpHRaJtfuEbU6PDdOMhrElQ3QkZKXIcJb5/Sm2swLF7o9mEDytr4tHI6NNGl4R/r7
         WVVPj0IBSUaN9vjr77vl4ryQap5+HA6aSD9bRFSy3B6iVeRWTF+QjmiIQCoAL3+6PkcQ
         +4dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=VvF/46saSwu8cC/MUy6rHJB9HGLv1hSIh9XRqPDHI00=;
        b=OcwASk/suyqXOsA2LzENFG6xAOUDefvmEhw/Xg7j/a9MeRfAG+p+x49i10XMZDjATP
         UsaxgNFz7i14nAl+NHSy5vl0naCoZDWanHj9wrSIwAuIAJusgzVgvk3/E3PeGPo/Zhp1
         XVty4BjbRlO28+ubCt76uH6+edjSbnsgeJ7SoHRiw1j+NRD2cJYfqsEl5Wm26KwZX6sz
         K7k2qoNKVpWOXxLmo7RUyO1LLkXMZN4g7580SZ+XCuT6fSKw9Rz/wy0ih9SdjDUNkpLz
         1SYuFktnMLvjS8mqVbgrYdl4+fqw7S0AyN+U4eYzS2O10S/CD7/sLuZRmdS0UOCga49M
         sVSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="bKwrsVg/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvF/46saSwu8cC/MUy6rHJB9HGLv1hSIh9XRqPDHI00=;
        b=dTdxIigeaDZQP5MWR7rc/aQ6PLSWiklAnV1fVgxAiMInu9BDCNrED33+ir2KRtEDN0
         psINpBTcegji2wnMFs+sY0x3GZQkvJzNPf4fr13UYHAG/VRt//c+2XFUfWRe0mrgQ0sf
         toHgDjzXus7+hrnvFhWDrfO828Dvx+vR1zLpDv6ICOwQf8Sx4dhxzp5pxli8l8Xf2NQ5
         8IEDlAyLrFMyRqSqmYYcOPGx4N5AuW5Uv6u7jrfgdO+LRZ3ifD30SZKnfSRv+4SZXFbY
         CyugRCMKqd/Ou/J1UzcP4eNDOqh6rGdwG7Zrrswxi3jyjtLpeNTRP/PCfzYD4pzRCqAZ
         wcJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvF/46saSwu8cC/MUy6rHJB9HGLv1hSIh9XRqPDHI00=;
        b=qChzeAjrVhbPOajpXS2/54xkaSjNM1ym0HAN5Ja5x1v0ayaXLbc2lbS8j3Epvd8Jje
         oaVT7phK2AEUIOevQCI4E6KJBguXr87yYlGC0tknWm4B42qu7jWU6DTEVAHljqfF7duK
         ITMfRALZjc5LFJeMTBuIVephc3I2HnOoSLUVR8VRKgE6207V2Cds8UwzRQQ/CSUjxGVw
         Cm1zrE6TIW20K+jjeMj+JFfoxF4t8vzomEWrI5aNz5Bn9hmLw1YpXDqShluxD5LqxXTe
         IgRhNiMwkw2V7eB5popDPvWbBHVlH11arq6KisXSLVts+tIVX86X2UFPD7u3eSScHRGy
         SamQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GmT481qoouCD7XL9tBQ+BrDj9hopA3wYM98W4f+vD97C1W5gx
	nNv2qZ96x/DwhPnuj1kk2Uw=
X-Google-Smtp-Source: ABdhPJxtADZOQFH+BUVELvg786Mnw1SDHvhEkEU8jCaLvao24lRtd7uriNDEvji8YknC+9toiHHRcA==
X-Received: by 2002:a37:596:: with SMTP id 144mr5551172qkf.387.1617227561561;
        Wed, 31 Mar 2021 14:52:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:3db:: with SMTP id r27ls2132381qkm.5.gmail; Wed, 31
 Mar 2021 14:52:41 -0700 (PDT)
X-Received: by 2002:a37:589:: with SMTP id 131mr5423242qkf.97.1617227561154;
        Wed, 31 Mar 2021 14:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617227561; cv=none;
        d=google.com; s=arc-20160816;
        b=H0pTFelvqtOFQHGkKrAsD2+V3dKsDxZoZAAcCc0b1QdicV9/4mgbxmX66X6Pz5BllR
         T4JQ2tGQoX1fI7EXPs0aISSVnMt+lyUrefPcxZ8Rq13mD7XEwT4JxPgZr1gYlTqFshdx
         p0KSt+gTpv0Zx2AyiTk2KZQJ9e8/SQYGCb+svJvlwfPkpB0/VYGUHc+pFb6n8AyQUQ8G
         7HOfJvIG33MdvLabslIta77a3giSkKt1j4KsekRX9qWJpfFaILr0/uLF0I1qSYsH8TOt
         hb+DjBQW0NRENQNbJBBr1Y1yS0AtH4v8LdaQAoJLi5Vaxrfl86vi8Xh5DXMurNopFzBC
         lc3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=9PGEWWstp+d3kYRf3WFSaQfkjhoSDJOKPPQYgypHwU0=;
        b=N7j4l77jwBTMieikO6hOzwnuKDmwoVDSdV6u11IOMWXed+5kOo3UHZHHyu8yX/8e+m
         6W0irJyNw3W8eIrL0qB3wMsYalrpD9rPLGQyltJwbGMAMUJw6B7ATH8U2SaTZDR87XD8
         f8HA3fVxXJtn3s8Wvbznyg4uajSYlI0qK+dozZ7JCuXwlsn149K63T3yntydB9oi4eYp
         MHgMdPq+gy48VhSdso1omMxF/ZC04/69znTSBiTom2Thb9TTS60DCoqBlqLtEHN72Jf6
         2x6F+2J45TYjsH783abPt1x5tieY/Nuf+AT6wChWJva5cdd97hdTkOkMV77LfzkC4i0y
         IvCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="bKwrsVg/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a15si522408qtn.4.2021.03.31.14.52.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Mar 2021 14:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id CF68761075
	for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 21:52:39 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id C0FF460EE5; Wed, 31 Mar 2021 21:52:39 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] New: KASAN (hw-tags): annotate no_sanitize_address
 functions
Date: Wed, 31 Mar 2021 21:52:39 +0000
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
Message-ID: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="bKwrsVg/";       spf=pass
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

            Bug ID: 212513
           Summary: KASAN (hw-tags): annotate no_sanitize_address
                    functions
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

For software modes, KASAN relies on the no_sanitize_address function attribute
to disable instrumentation in some functions. There a few annotations that
enable this attribute: __no_sanitize_address, __no_kasan_or_inline,
__no_sanitize_or_inline.

For the HW_TAGS mode, nothing is done at the moment. Accesses in these
annotated functions are still checked and this might lead to false-positive
reports. We need to annotate those functions with kasan_reset_tag() to ignore
the accesses.

Note, that some of the no_sanitize_address functions (e.g.
read_word_at_a_time()) perform custom KASAN checks with
kasan_check_read/write(), which are currently ignored for HW_TAGS. This needs
to be addressed as well, when adding kasan_reset_tag() annotations.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747%40https.bugzilla.kernel.org/.
