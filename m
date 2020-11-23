Return-Path: <kasan-dev+bncBC24VNFHTMIBB3HW6D6QKGQENC4WAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7944B2C18B2
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 23:45:01 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id q8sf7834333ioh.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:45:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606171500; cv=pass;
        d=google.com; s=arc-20160816;
        b=bXF/ulXD6G7bNwYcI/h7r1iGN4rB2Sy/wy5BRX7K4zXlMvRthqbAhTOoAxHVXazFDP
         RuHEmFx0Ty2Zfdme9oVSfvOtlpsH39Ll5fqIXCMd2aLGt2EuP3omPumqXvoMpHvZlQAw
         1Z3hg7tHNMUhunqDjJFgehN84uiZbm9+07MzMWgwazPnoojj31hFLD3Vhzt3vXkY8LyV
         DoDmTgmeNrN4LyYzMSypKsCFO7/YcDIaoYyecuLw3/IJwSpkwlMOlaEFwk6iBB4b7/NH
         /Fn/N3irpy2ZrC4U0L3yTR/U7nc4dxvO5KWb92NIHLzqhb7XmINUkZGMNbaCyZ9izIXc
         NbPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=x4dX0aMUzhcTZw3xPV+2KoBJcjI75eBSxaPIS4fw+Zo=;
        b=S93ldcDgdFF0seeR8s+XLE+9YSoyL975ahEjE+n5kVjYNGdLt3bqp4FSA7YPOCmltw
         BMR8FN8UkE64ZIlPsYhXbXCGbxkhTHF4AHuUNwT/wHXwgB4PZcq1thglxDE8iCM4ils+
         aFwXPaCqZjIh7DqKTHidqpa7dA+5bZCv4i6y6+tb1uUHglxK3Gm6YlT5FUcxGxRf8xQa
         DvKJIyTPWauw38Il5Wwt8CUfjRDyM27XtwiE0+j/xB/V0GUvo9WiUTPRScrNSyhFmAx1
         UWXGJFRy6xF7+rSO/xvoGcmQlGDQCDXfzM3UX/PkgSDU29/7p95YWTgT7dt/1l0nHLM4
         sheA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4dX0aMUzhcTZw3xPV+2KoBJcjI75eBSxaPIS4fw+Zo=;
        b=SxcBzv5uu1BxPvpmVIdbc4SL2fkugp8ZsgB83Kt8A7kgeOqWDsBeeyril+NBw/snGx
         1aySKKhy1EB7hfFR0WjLQ5jTyFuD2ITxtavRudJ/DVfOj+bLkMu6gBA45RUt+k/j8jdQ
         4a0a9VYX9pClEmoagRlVplUlHzCtnd6sXvVmo5o5kuHhqRgAt9/0aG/oV2rS7c2fJp8O
         1DdS4AIMCyrJY+uSm1lW3w8vwhTX+/s2A8BwfaQrzpH5gnDA0xFdwddnAnsnF7tnmh04
         xq0R4F24reoxZ3lfxkBiZ8WCy7dJ+lB8URQkudf08SNyNxDVjMuF1t5kZlQfVEj2ncu/
         LWCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4dX0aMUzhcTZw3xPV+2KoBJcjI75eBSxaPIS4fw+Zo=;
        b=quYXqzRHRuJtfRnSFRlbuM9hoJPCdDJPP7KlWdYTsiOL/WCLRHEY1xTWRMrfaffeXB
         T+3hhE3B8tZTwNSmeQN1rhq46ZnhbbIs9zBt7adfswk9Mw8IHGTF7hddesasGB9u27sd
         6Adc7TG8ZtiVOOI9FQK4tjhJPqxi/rB32rBliNvSLsk8ztHRdjsoD3MjRAl50nk9CUUX
         Py1jcpnPuySBV+QP4rbi1wWqjrqnViGw1DOKsGuhREnCzRS8Ad/SJvexE9uj+r4bKHdb
         4OQjSfAkqXttd35l7JpB2e+aYR2gVxv5hA6OWYB0HIr3sdl8K0Jn6I0ZFSzLn8JBiVsE
         iDvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533odIpwGR89eQd4D4rCcRwKqNc/n1rCH8NBnd/ITciLKAopjeln
	K8vYPQss0n/HXRJO6X5odbY=
X-Google-Smtp-Source: ABdhPJyuIkMtuLhuMBSa6g8BFe1mUBkzRj/mRabPNE/PzgwWIV57rUzXDHerFg93DjAJdkmnjZ9L7Q==
X-Received: by 2002:a02:4:: with SMTP id 4mr1720591jaa.121.1606171500078;
        Mon, 23 Nov 2020 14:45:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:140f:: with SMTP id n15ls4001193ilo.4.gmail; Mon,
 23 Nov 2020 14:44:59 -0800 (PST)
X-Received: by 2002:a92:4993:: with SMTP id k19mr1815414ilg.237.1606171499205;
        Mon, 23 Nov 2020 14:44:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606171499; cv=none;
        d=google.com; s=arc-20160816;
        b=y9mAYg4KL8kFr5TNW+WsBoJ682AQzu3wiJEqlvNc6STPHKAz8Mmh+0CZv3+dFWNbG3
         /ahwsaUcUWu9cVYsxAg8mC6tm9JyAEcx60zaSA3BK4PD0IpeiozUr7nlbzWZndCmaalL
         p7NkhZE+my0wfVIHfwPyHfRtrlgzLrZO0jPcSxuFmP3jvgbCnIo8VVRgekE/nwxQ57BH
         cQ61+Rz77lI0P0yi/QQ9wk7pgUJsQDsKBaKVdNJcRLkAwYWm2s4to8vfx2EBbt86Kbh/
         7Ozdd0algcORK9iAo1jVPRIkuHaZ0yjnJxWwRH9BjmwMd26QowD3OIFc5rlCK0QCSwEy
         mnEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=vcTA0JxL3jL+H6mSUAFtLKkpo3Vlz6CDAdbSQwY8Isg=;
        b=jymmyS86ZRMO8W4abEOcB4EsQVC6BXIYhuhmKrNJaj4FpkRVqrIvcpv0t+NyGUDMZy
         7HSA7sOd3W3zmFm3xu5Ep6RRAV94U6VMLEbc3syA7NNAhTAo2Iq9yWSIbs6mDy55+kpW
         KDjOqiJqVhTFNgVBoLuwn5MIy1+SANcVKCgSnJDbRd0i3IMSnvgHTYQYTZYhXsxTIBqg
         XqHGRhazXo/aTmFRvZM2z/zxDfn/QWgym5MCxGN//CFMaOecpD3VMzuR/MLOy4wy8Glz
         MrveBwS99lwmA578U/DNz7QeVmt71oNniLjc0z6flyxmE32CRcbiKgBY2/wXbj0eWLgP
         mhOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o11si754757ilo.0.2020.11.23.14.44.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 14:44:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210337] New: KCOV: allow nested remote coverage sections in
 task context
Date: Mon, 23 Nov 2020 22:44:57 +0000
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
Message-ID: <bug-210337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210337

            Bug ID: 210337
           Summary: KCOV: allow nested remote coverage sections in task
                    context
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

KCOV currently supports collecting coverage when an interrupt with a remote
coverage collection section comes in the middle of a remote coverage collection
section for a task. However, there's no support for having nested remote
coverage collection sections when both happen in the task context. Support for
this would be useful at least for USB/IP, see [1] for details.


[1] https://lkml.org/lkml/2020/10/16/592

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210337-199747%40https.bugzilla.kernel.org/.
