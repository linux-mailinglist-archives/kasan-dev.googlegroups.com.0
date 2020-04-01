Return-Path: <kasan-dev+bncBDK3TPOVRULBBSFRSP2AKGQEW7O5YWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D41319B51D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 20:09:13 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id x189sf334950pfd.6
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 11:09:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585764552; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYtmkJ5bKB0rsvFo1Tc5Wmy1eNQ1tAsiEKsEGRc1/uyq5ewjQ72ByyQaMZeJNdaCrm
         PDTRrFZXRT2HLJoH4a0UmRaw8h+n14WgoTNw20d5PnAvoWKbb0mUZl0Tq+BeiULBl73k
         qW6TsJoQ9E84Yej2lAkkuT7p+7F/BQXoxL+dCQX4obaGPwkiqT6lP4oZSJ9kckNSeMwW
         Po1kTgVMO7o36hMANJhPg9aAEr9wp/sfp5aCE/RzYjoz+hQERJgKY7LeFnhjPjBgvG2L
         yDuPbLxqweV9ukPA4LbLugQ4tEEvEtv6GgV2dn7SkLQobMu5PnOd3YC6KMYUXkYhY+RY
         fNlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=iNlDgASr+6e4qS8mB3KuieW1rbZnacTatAh4Yz5U0rg=;
        b=bKeLzMHc/Lhp2Q3z4pZBkSUc/m6yE1p61vNyP19/gkiVap3gSUC0PttR1sUFizHPzv
         s8hSJNzB47Ihsjl9NsmC40MK7D25kFsN2fZGRmaKPAq6lxvjnzJqWtfT6A1bOsEZIhGf
         p0GTxSN/QgYPZqHdwny0XKIv8wmyGhAu/2tm/bg3CMTybW313QRzaiJ6QFHSgRtg/gFC
         HkufL1/qyZWblwGtwk6UIRyCDF+LiB/5iUY7p6eLLQYcORovFRl71XD3dN3XuRsJylVi
         eNT3iJPapXBFIwEWNdv0mp1lk+qFaBqaE4rD+lE6JWuHWOaOF0BXovY4NfnqbFK5pXsl
         nDMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rv2jM3Dg;
       spf=pass (google.com: domain of 3x9iexgwkcyy31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3x9iEXgwKCYY31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iNlDgASr+6e4qS8mB3KuieW1rbZnacTatAh4Yz5U0rg=;
        b=AnDF8h+wM7g5KuQa6ba4NV0rOe4VU304JapEDDm4IJ0T7potg3JZpJpuxGAuY2TScZ
         h1juERRbsvx1MfN3Ss1+KhdzHxRx7eqaWT1iHCFoW4dL8c3o41cKABrrWbKGZHLG/8Y1
         EH16rpUn6fRcJjLVO6Dtf1cM9YHZVIClhPvjSaAZWAckuS1sXxpyAckThbD9jNiXhe3D
         pNwZf5VO+c1QY6ZUjWAcJwav809UdmyahTHSH9HJIS/DbOko4ETULV8vArDqzbgW/Abf
         hMhtedGwdUF61NBNK/0Y6h9WAGP8vuSkBEUy9tj+e9jw85ZwQG8dwPZLYoSD3ISCTHvX
         SjNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iNlDgASr+6e4qS8mB3KuieW1rbZnacTatAh4Yz5U0rg=;
        b=Dl3a9hPD3huwqzWfFx3VVCnxPMhAuHf288b2YyXddaE11vYalmHCUwzjrBN+6+bkt6
         WbyDxgpZvFQKT5+GyUBDaIdXUxfuOQmqvMvuHOGIrt1egud/EnZ331kRFCUuHfQAyLOd
         29Xg89C+yqBvyoIPOWzol0nBxgz2jfaeISSBa4ljvrb0mRbezMhcpP1mvfKqUkmG9cgO
         LPXjM13YmSHVNrtNbwoGzqzu2lKoqBAimBYMBApmcG3J0JcuEtwWlmuoY7xGnmQ5NP1i
         XCKh3b28tKM+VWdfav3iGJ5AUVC9CsUigMZZiF+2Ok8WZJZBBBhOEyoZEGIC9moxAybX
         8peA==
X-Gm-Message-State: ANhLgQ3XGtx2X9Fh7wtZo+tWHFxXLR8rS6GjC0CpxO+w1wMHvMVGjgBB
	haFzU+GFSEVXLt1IiEm4BnQ=
X-Google-Smtp-Source: ADFU+vsRWG7uY/JrfEjEwtPdJR8rua8rNV2rd6CwJdRj6nvZ0Enni41VenauSyfnYavBhM+1weNekg==
X-Received: by 2002:a62:de83:: with SMTP id h125mr23997928pfg.161.1585764552128;
        Wed, 01 Apr 2020 11:09:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb93:: with SMTP id m19ls304361pls.6.gmail; Wed, 01
 Apr 2020 11:09:11 -0700 (PDT)
X-Received: by 2002:a17:90a:94c8:: with SMTP id j8mr6416624pjw.155.1585764551743;
        Wed, 01 Apr 2020 11:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585764551; cv=none;
        d=google.com; s=arc-20160816;
        b=C2Couuhqk8vSctC6ga8KAOy7Tk1CA9rkYbJ2T2nkuuGhqMk0JdSCeoqUXOdgSZL57U
         R+XIpC8d1Y8xa3JyTAxASCdi4GxkA6SQ9iMWGjQeY/kFETCnI1PH61B1POmAAdpS5p8M
         aIepd9tVdg+0DptXiJ1zpB/bsbsoWF6s0/M9qSfKqM/OM7jScSSoSHq6hgIq+CYhWf9d
         Y3TQjlruouyxWa6dZzqko1TPV/av0TIw2JhpH1ESAM5zwUuRORRlbInjVRR7Nb+jf2lx
         KQxRoFPyGs8ZA8Nn9oSZl7f0WKGi0Mip1w+4bw8j7Pki7AujdsljsPTXJOwaUhOEOUF/
         HJRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=jmllqegwWYAse5zHietOLbFHZdle7VlA5/QFT40kKC8=;
        b=IGaNOJ/j9o9dPmpF89LxHLG0FTS7dulhxwlY+/arPPTwwEbCSe/jNBHn9Ac+OBApjY
         xPrM5EOBIDpfP9SsK5d+RSD3F7kbjABPzZgsXHugFSfAmEG4QsmvLusOQ96yb4tIDBlm
         6PmtlEkrq+Wnnrd34P6epEKuYYbc+4u4WywRnjTZoaXbAmOowOOePETPEZweiMA8lRBf
         isRLYrKE8JKOV3q3m6N6HQPhUqahF6RrOQqFia0upOaOJOSp8VzDnj6JS6OXmEVknqok
         dUlVayyXQGXCpHenQD3lXvUcOyra+RsHQuQwtqdzovZckba8BXvyYI4aZLyJ4kcgWqjt
         DYdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rv2jM3Dg;
       spf=pass (google.com: domain of 3x9iexgwkcyy31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3x9iEXgwKCYY31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id c207si173368pfc.3.2020.04.01.11.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 11:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x9iexgwkcyy31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id p25so389718pli.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 11:09:11 -0700 (PDT)
X-Received: by 2002:a17:90a:25a8:: with SMTP id k37mr6384885pje.14.1585764551345;
 Wed, 01 Apr 2020 11:09:11 -0700 (PDT)
Date: Wed,  1 Apr 2020 11:09:03 -0700
Message-Id: <20200401180907.202604-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH v3 0/4] KUnit-KASAN Integration
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Rv2jM3Dg;       spf=pass
 (google.com: domain of 3x9iexgwkcyy31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3x9iEXgwKCYY31s2rkvpyx2yqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

This patchset contains everything needed to integrate KASAN and KUnit.

KUnit will be able to:
(1) Fail tests when an unexpected KASAN error occurs
(2) Pass tests when an expected KASAN error occurs

Convert KASAN tests to KUnit with the exception of copy_user_test
because KUnit is unable to test those.

Add documentation on how to run the KASAN tests with KUnit and what to
expect when running these tests.

Depends on [1].

Changes since v2:
 - Due to Alan's changes in [1], KUnit can be built as a module.
 - The name of the tests that could not be run with KUnit has been
 changed to be more generic: test_kasan_module.
 - Documentation on how to run the new KASAN tests and what to expect
 when running them has been added.
 - Some variables and functions are now static.
 - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
 and renamed the init/exit functions to be more generic to accommodate.
 - Due to [2] in kasan_strings, kasan_memchr, and
 kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
 early and print message explaining this circumstance.
 - Changed preprocessor checks to C checks where applicable.

[1] https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
[2] https://bugzilla.kernel.org/show_bug.cgi?id=206337

Patricia Alfonso (4):
  Add KUnit Struct to Current Task
  KUnit: KASAN Integration
  KASAN: Port KASAN Tests to KUnit
  KASAN: Testing Documentation

 Documentation/dev-tools/kasan.rst |  70 +++
 include/kunit/test.h              |   5 +
 include/linux/kasan.h             |   6 +
 include/linux/sched.h             |   4 +
 lib/Kconfig.kasan                 |  15 +-
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 686 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  33 ++
 10 files changed, 521 insertions(+), 390 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401180907.202604-1-trishalfonso%40google.com.
