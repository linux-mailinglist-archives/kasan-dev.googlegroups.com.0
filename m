Return-Path: <kasan-dev+bncBC24VNFHTMIBBRUCT2BAMGQEE4ABVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 398AD332823
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 15:08:07 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id v5sf10269886ioq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 06:08:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615298886; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIDzqD/83rE6DP2DPy+OGvhZRTMwjfFYD8FBt7I10I05/+EuwGY5usAYHfOAcqjMQf
         7CVffNhmNw1mMRQHitKPkYmNk9ch7hI+ssXmnPYcjpxuKks0rjuK9lAWkMZ8ltalryp3
         I0oou+WL3FYhqMhCK1H/uq53rs8AC6XGwZ5/cGy4A2uJqM2d/EuiDUyF6GfpnqmqJXxX
         o6Gpey2x1MMw5w/LIsmA7l/dn448UWY0Mv2ij823/RoBtVODvDnRoSH2QUQ2XvtUBBzX
         ZOcCLAbfAfgsRBQuZihhSaAA+zevO1N8irkvgjorGg/CPWlrQ56gDilEpIOosycLK3s2
         WqjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=v1HgQ1bLp8hRS9oIhp+Ymf0XzlvpReZMjndf9RE5EgI=;
        b=RoGmJ9wwgJFc2WTIg8zdAiWrDkdLMHlUy3NJAC1fWUzXQ/3wK/Hf+rqaJ8snkPrcvd
         Zqc6+6uB1XTUGINwmsWV+HDA5Xl8PEaaQjlpydzdWHjdNAWW0WHp2aGe4vy3+1xF/LKU
         kBe3umlOCCGLCYUJuIFw0c17DankMIzHJT477wj4+ryeMRq7iApb3zu+R/67penLx7uB
         +e1WorKhE61jrBjJoJ8fmTwLvnnnGmV37wxqGp6dIiC6v8gaQh/41WgMrCPHAi4GH/3J
         FBj4BNrjiOTURW8YkiXEESfho1L+UiDndqy8lvRtpDVLqHY1iTmT+RcLrGH5GwPjvike
         +shA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YYK7NGzI;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1HgQ1bLp8hRS9oIhp+Ymf0XzlvpReZMjndf9RE5EgI=;
        b=kxkrqp7Hzd2sZv0s8q5kZJ4YxCr5GvW4yiXPWNI1QcQSKDWLz2x6PMP+7yxL68jwuM
         nKwe66al1pM52vIZN5rrfKWB2/LguAAEtIxjzKtSr17Z7uCRrntvHn89B8KllMNzvAwT
         0qTZLV0BqId1fnvqZ1ZhJEr/IGaYJvD2Tv44hWp1JaLWKBRn1F+ZO4fa1zsrDNx4Jqf+
         +sxt122Ijryu0SgEAlHAAv7As0z1WlUIDNb54VOkz/U1XR7GHSdKh6Z3wyDKnvQR0ew/
         JutaRyqazFkRvDHjpAF720f0fsf8C2Ept+r1ldiybKMJRj3sFgvn45YFTEMef9TDWiHB
         nEwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1HgQ1bLp8hRS9oIhp+Ymf0XzlvpReZMjndf9RE5EgI=;
        b=M3zBWtfceHPnjJr4cCH9tLr3DbTfJwpIwlkkUKhPuTTpF+2vLcwPpZXews+kv+qf18
         yDY9SsNCM4jivplqCPxfuOFdJcMhA4p2f6hXAnT3vjH01EHpd8DmmkFo3dTkPQ3EeWIs
         J1S3i89NcW0zppDOwNO4f1CTOWRB4yjp5jdJI75vW61HbEKB0DjvPyB9dGivErHCg26g
         J/rkara3XjXByw0JGqjZgCNb4QET1q2df9CtMIItzQ4/FzZC9mhiYJaUuI9lQsuJTMly
         fLNuXloBZ8I8hI+SkzcS/51IYWGvc18yWPXnX8OGnDvoh6xMO478qB7Oi2IRJeZ5IEx8
         KVVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MLkF8OmJTNSnJE3F5GF2JdH/NMDU+4vHN3dc1m2NfpNBi77Wg
	oyGqcZ2JO75YyYgYEfCmSDI=
X-Google-Smtp-Source: ABdhPJwimmtCeEfUEoElj8dslZKnrpEJjGrzk3VpFKT/09iWmpuhS+PA1ev2ekIJfYrfjdj+nVBccg==
X-Received: by 2002:a5e:9612:: with SMTP id a18mr22567458ioq.209.1615298886300;
        Tue, 09 Mar 2021 06:08:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:860b:: with SMTP id f11ls3362749iol.10.gmail; Tue, 09
 Mar 2021 06:08:05 -0800 (PST)
X-Received: by 2002:a5d:9250:: with SMTP id e16mr23258743iol.27.1615298885920;
        Tue, 09 Mar 2021 06:08:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615298885; cv=none;
        d=google.com; s=arc-20160816;
        b=JsgTQ0CGFucsmPVfNBiF7pV69zUAb7oasYcxdX3x9sM0qGLwzE+keL61y5gZbnFxwY
         Dlw8t8QS+h/6kFRuUlQ/QqnZCIIavR7VbjWiZ6NgEDC4C6HrKnjYlYljr55E3Rq6yNrV
         F/Sl37z4cFTC20zfmCwDq/+9s65mExXXBgxVaJNMIm20Jj8KsgkGRuefnRL/J3LM0fol
         LvVh8k0Yo8PZ0LYZJKG251RXR4Xlczrn2Zmm5kHEvK39vw383T+pcBROzjMtHaIutjoH
         rnHS1P5edBkwlMVzsi1d3AU5TJIL1ZYMcgYHDouFSbTkVmrxONa8z4pwhzgIB+V4qWw2
         x/PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=DLu3HKcE6QCuSMz3ZUvgp+RYKaDeh8UoZOKCS87uFy0=;
        b=quvbxyJbyPBX1EpRoGS8kIcWXk9F+3F5baunKE/aucvNf3NGLVtdCqHQHpeSkMO+GH
         fjLVb8mUvUFoWF6WyGCsJWl3LITJkKSLYHVouzzpNQWUW3XGvOx1aLeSW1hmrtmZRQmo
         RBGiAPrmzaxv40PUyoEKKbhRgckrD8WTrnJM0p9T89y2Y5YYVTB+Go6whGaPKXWWYo4H
         tD4BaoAtAra2wrsNMmJMeBBqNmbQDkRCcjsPBJKh0S6A6T+FV2bxAtCjjW5x48YiD7WA
         RiifffkXaSOQAKhZEWpVt4Ybgxv39Jm/WboWgxAWUWo64pcr0Lg3QG2ZAT+ji2s7BMAu
         DyoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YYK7NGzI;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si994672ilj.4.2021.03.09.06.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 06:08:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1A4CC651C7
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 14:08:05 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 067A465349; Tue,  9 Mar 2021 14:08:05 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212181] New: KASAN (hw-tags): use read-only static keys
Date: Tue, 09 Mar 2021 14:08:04 +0000
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
Message-ID: <bug-212181-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YYK7NGzI;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212181

            Bug ID: 212181
           Summary: KASAN (hw-tags): use read-only static keys
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

Currently, HW_TAGS KASAN uses read/write static keys (search for
DEFINE_STATIC_KEY) as the read-only static keys were buggy when HW_TAGS was
being worked on.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212181-199747%40https.bugzilla.kernel.org/.
