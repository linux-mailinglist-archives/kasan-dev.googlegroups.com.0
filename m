Return-Path: <kasan-dev+bncBAABBN6OUKZAMGQE3U6ACDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 156988C914F
	for <lists+kasan-dev@lfdr.de>; Sat, 18 May 2024 15:03:53 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-36c7ba4fe7asf106919175ab.3
        for <lists+kasan-dev@lfdr.de>; Sat, 18 May 2024 06:03:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716037431; cv=pass;
        d=google.com; s=arc-20160816;
        b=OgUGDJsi61AmtyQ4t2i5ePRhb0w0mtGsvKuUmddIXaF8ecr1nshi82tWCefvB2omnx
         bbWrWhHi4q7KroTC8mTDvubnT/IRJSL9XuZloFswihake+Zy2gGZ4T6eZ2D26h3g4TFa
         7b8lTo/Xh4N39W/rn7G3NVxQJSToldqi2638Mc9d4TudfPvNDu0aABLIYTaS+hqZZ+V+
         Qo0QOzdp9d4PKkq5Ei6Ugp7wHfUWVKwlBqLJPzhLOurXgxIW/Ur4FlcWBgFUTBU279yH
         BLSO5CcmK4wjdrRH89PEPSq7U5h9PjZZaF7hnnTiMirVZQFHN9RHXgxNX8NhhXQEeh5+
         aHHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Q8rO+lWgw0M5+F9gB7rTm/LcjuQRQoDR9wzo23nywB8=;
        fh=o+oEU412p3fN7jDsS+LMGic7HiV4aF1VIxfyAz7JO2E=;
        b=UmlNCY9gn9k79KNoJ2UU+KmoWJqFF1mz8VR6RUxQuSFCxOblTU1x2j5FUSkKUpG7q5
         GCcs/yF2eqRxvdeHvOvPK/jMaxVOR+PWd182OH5QzPv517W/F5YAn1Js6rKjQLxc2p3D
         /0jPiR9DgudAG0MnmpEOcRjUvuA7z+Lnz3Df8Qq0BEBPpEZAOl5sZ9Lyd4IQa8aRKDOl
         T1A7VubRRVpMfFf5UWD1L3n0iu+m9jrJNOk+s4cZFtX4q3DgEEGoNTFTFOgr8xUGy65E
         YKLxGKULIcWnwN1A3FyGGTwQlBT9hB2lNI0aGFLZpau2Z3AmqdfN9xDIaF5imEutBNuH
         E2Cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YKH4zYv3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716037431; x=1716642231; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q8rO+lWgw0M5+F9gB7rTm/LcjuQRQoDR9wzo23nywB8=;
        b=TDaC1QZJ5f4I5nHW6Mm+at3YxqzA0pNVDrbUTQL2PQ9IjAJD9r87u3txDHlqYIIDqM
         CWJLnIs5oarqgi0BP8kVIVBxq/nLU4UY45kl3nYYCY6rD5MCUV4PfdWn+yhS+i4WSGsN
         bB3LslPPM+MccU7VAYViiCLr0OQINds/xKVdYwWZcuFHZMpvEhqkTVp4dgBy8smn2AZJ
         xfxz4Qwkix9D592HEn0+PVO+D1nGlxEcGRALRQBuBsKRG0NmWfGg2AO0OTcKCQma4rPh
         2q9n4Jb0zIgC3InpHPM1X/d5bghJDlWzOAR9pTzfeFT/8g+zRPjWktzD5wOk2c40EMVi
         w7rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716037431; x=1716642231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q8rO+lWgw0M5+F9gB7rTm/LcjuQRQoDR9wzo23nywB8=;
        b=Sp9jWCiwhVgMTC2PUEy9rYPfPD4YleXgfNZZ4o6QF3MUTIOWFGymOT1ezYsie+Ckf6
         f30bQsqWmCwkfeDhz8aI3G8sjP3S3beyQWlc/KhzxTF86JRQb6adEvDS4lC1zpL7xBMJ
         Xm1w999apk3YXnGhzuHGcJqOJNH08FV9bzZ3dIuOrZ+NEvlZXGzKHKOr2oMUSw2d5Pbz
         Igks0Til00Tz46xy7luQv7vXlF5AZYh/i26ts9RCm8n/ivmxQnYcgKImRxITj378VpOr
         TlKRmkCUCd9YXZSw14ZdSVhOUS8Wd2pS/uS+7uoLEihzGKD9bdYn+Hr1/kgA4bvxiH/7
         bR4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrtdViUBKWk4b0bosYBjlD+Kbt7BcHvi0F9dIg4PLZ2hF4g522mR08kg23CjxgXZRDATKPTZ2HbXIrsxVuSe5p5inntle7iA==
X-Gm-Message-State: AOJu0YxXahnR533Ei/a1me/Q3kL6lyOx/oSZW6eggJq7vGIfWS5qlex/
	ge+65ZoBA/h2hOVzd+U8HTMd0fQYSHjXU+SsqbNV7P0CKgQzlFbI
X-Google-Smtp-Source: AGHT+IHqYHnG72hiy8CHQfsyfgxyn8FVqE7mQifwlUJdKFFmNGmdVqVFOrJ7RKVH+Gxqfc6iC6sx6Q==
X-Received: by 2002:a05:6e02:20cf:b0:36d:b51c:4b87 with SMTP id e9e14a558f8ab-36db51c541fmr133268865ab.18.1716037431320;
        Sat, 18 May 2024 06:03:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cd87:0:b0:36d:b53f:6af4 with SMTP id e9e14a558f8ab-36db53f6e3bls14516535ab.2.-pod-prod-05-us;
 Sat, 18 May 2024 06:03:50 -0700 (PDT)
X-Received: by 2002:a5d:984a:0:b0:7da:cbc2:7caa with SMTP id ca18e2360f4ac-7e1b51c5129mr2554997939f.9.1716037430335;
        Sat, 18 May 2024 06:03:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716037430; cv=none;
        d=google.com; s=arc-20160816;
        b=oVTu13zVX9cNvYTlMqhfCT6D4cNEUU6dDZU4inNcrJuv4qnFSPZvJtYd8C2ZduMBKJ
         +6ozxN0svzv00ocl5lcYMPCEeEYwCHdHmkGVG/46QD47k9SwwyVZS/397/gMuuK2g17M
         G0vc6DkanmCb6da0lcEarqt6qeWS1BjZvVLNInYbNtDTGsqd0CodYPDeGJFFPTkmBTY1
         5BlqaTxSNsWZkaG6vgo3tIZq1OACuG0ce5EjzZwEb7oV01C8+DizOHhKG2+aphnj8Jha
         eH4njHLTBhvlR1llJGiMCQqEjJyzQ9IZ9puC1g9Hjj5zZrPsIlCMzNAJTOhMWcu8+bNO
         4ZOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=pahOEJsBgDFl8QXwJE9UH5kquInyHH1COFwMHwwaMbU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Z39L3RjyX1Ja0jnTP7mjtOBnIITcddeP4m302t8r13HhSQm4K0uvyK7G9T9pAb49m+
         qmzkUp7ccK7cr23g8PyCBEMe+BMlR12xs6eCu0IBIN+kexjnOEDQzSuHT1JB5+qqTwRO
         sbmi9aF0zssIrHjAkFlqb9n9GHzWBT34NTeQT1YcpHj3Rik6DTNzJ77AMpEnpYbqxm7l
         cEhK5NSRmzrj8pIERACanRxO+AWFQJ9klmrdFIOm4hn4Pil4rj67Olb0YIlKpGI7kIqF
         uELogIBnImislLkIXMwv+gy3yfix0E/XixCkChqCREOxHPtJcHS2Oz8J4ko/b3W4vABV
         BfSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YKH4zYv3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7e1a88922f8si127089239f.2.2024.05.18.06.03.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 18 May 2024 06:03:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id BA1F5CE0689
	for <kasan-dev@googlegroups.com>; Sat, 18 May 2024 13:03:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8D75DC32782
	for <kasan-dev@googlegroups.com>; Sat, 18 May 2024 13:03:46 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7D4F2C433DE; Sat, 18 May 2024 13:03:46 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218854] New: KASAN (sw-tags): multiple issues with GCC 13
Date: Sat, 18 May 2024 13:03:46 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression attachments.created
Message-ID: <bug-218854-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YKH4zYv3;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218854

            Bug ID: 218854
           Summary: KASAN (sw-tags): multiple issues with GCC 13
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 306305
  --> https://bugzilla.kernel.org/attachment.cgi?id=306305&action=edit
.config

Noticed a few issues when running Software Tag-Based KASAN with GCC 13:

1. There's a boot-time KASAN report coming from smp_build_mpidr_hash. The code
looks legit, so it's likely either a compiler bug or missing KASAN annotations.

2. The kmalloc_memmove_negative_size KASAN Kunit test hangs. Also either a
compiler bug or some missing annotations related to
CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX.

3. With CONFIG_FORTIFY_SOURCE enabled (and [1] applied to pass
memmove/memset/memcpy tests), kasan_strings tests fails.  Might also be a
compiler issue.

Both Clang + KASAN_SW_TAGS and GCC 13 + KASAN_GENERIC combinations work fine.

.config for reproducing is attached. For #3, also enable CONFIG_FORTIFY_SOURCE.

[1]
https://lore.kernel.org/linux-mm/20240517130118.759301-1-andrey.konovalov@linux.dev/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218854-199747%40https.bugzilla.kernel.org/.
