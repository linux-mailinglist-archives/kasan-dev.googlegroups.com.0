Return-Path: <kasan-dev+bncBDK3TPOVRULBBNE6TH2AKGQEEOF3NSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id A857D19CBD5
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 22:46:45 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id a13sf4485016oii.23
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 13:46:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585860404; cv=pass;
        d=google.com; s=arc-20160816;
        b=mX3T7exn64CunL+JpKXLIDDZwta0dZCuZ5zdDSz/EtjzlJCO3H1MZGq8YXL/JZ1MZZ
         2Z6at0+TD4z5gEomwQYJHAEGWk3YN/eBfamMRsUz7tkQL/VdH0RYt16r7BXMdnMecHlw
         Pfd15Xyc6NbMDZpiPKBeUMO812JEbd/qM1+SbrwGsl/uzjKCSaBVGoE+/PKyXL2aCVNY
         yUvv3SIfX6xkdFOPSaIcWcCoVK4mvwXTV8b21XusPiJYxx5uTBL5SL01cYKZcOlobG9F
         h8020yNwuftq8jRbhTZGnNVN645ftWzuonK5/DLxd8AZiJQ8+ruHYYGoU6p33dFvYu7w
         d0qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=jjabW0DBog3zlRy8Wusz66OZyUbDDGez8jtgGsqGmxc=;
        b=cSBbggAMmi4LNkAH2uTtGj/9vweU8S+li0E+qcB4so/39X/VQDgQ0l5PvocE3I4Yu4
         ugtC1AOAP3c8o7/Mi7GxuN2MHjOrmHh69k5wUyjwW99o2G+5SvaEZyH6Cd9tBj4qX4hC
         IDUTeSAA7nF6iY5QKXZuSEROUt9q544dl7F51Bje/z/ypSoTa+0ye8JQvjvrDSCrHpc9
         UHSlLtf4vyAX3fAsruJJe+RnZcwQ2GpLnpTbIp4DpHVPfPP9gLIM0a4egd/VAq6Zz/2j
         lFH1TXFTXQTN4udCfFBv1nXburA+RhCS0v+wRR1shFlbLNKszSzc4VVP5u1bOmkqqTJZ
         XRlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RBbZn9mY;
       spf=pass (google.com: domain of 3m0-gxgwkceqzxoyngrlutyumuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3M0-GXgwKCeQZXOYNGRLUTYUMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jjabW0DBog3zlRy8Wusz66OZyUbDDGez8jtgGsqGmxc=;
        b=Zgzo2qTD3xVJ1dQmxw5uo72mrrhjDLHL2bpD0dxqzwWuNGXOptK7AJA9zhhw/Jdc/6
         pkDmlSI2D7DchoH9W85E2V1YzVr/JrnhNExodXtN/vzYhe3RxTCzQwtmctmiUaCHdqzZ
         KZIqj32lnba4p9NmgA9g2hWjyOnfMa8irHD91Jt5C5DkUEl4HEhDAfDLTv6CQDfNH+Vi
         9XQVaj6rCodbbDGUkIIrqeDWU4bK4/IM21pu1iiI72Tiqik/BvLmlMXOEDkdJnMwuwEq
         7NlGcIaCv4Qm032Eg4QMVBXF+z8WY9QJrHSQ8ikEcy+XelsNAlMV8rNckX6JUAykCxIy
         3u4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jjabW0DBog3zlRy8Wusz66OZyUbDDGez8jtgGsqGmxc=;
        b=GP4w2STzGmzIf/ugfLuRvXvZbSezpG3qNnKvxm1GPCxPE+G45KEnb/jLHr5sUb1BYn
         feolsZmtdw0J8kOLZygqnTENfKfV+dR0cYCq9eJPj5bzRLvDhuNrFHw8UGeo9MznFfGU
         GKk/BKGg2HOqBvoKed0WeYQYEQaPBRrNzENeMrEFWO71DMLSi/Lw6948zERWWmSu/Fhg
         MnI3KqIqZ0hlBrmLgZfEJADaQpvbTwwqr6Ok3fCg3dPTca5rjUpvcLGgdNljE1xdhPDw
         xi+g357RvdpxhDKTqS36qHwuiuShJiX2ClNbQEGSytk4dO151NG+liFYZIAhFvmnpSsb
         nYPA==
X-Gm-Message-State: AGi0PuayHP3RIOML+jU+pztztHzbSWK7EjpCed/H8iobjObB/nYPthBR
	pmQsly6bOCrrFBMrD8Fh+/o=
X-Google-Smtp-Source: APiQypLMIQpgg2I1C1rgCGfeLZBlGNm9bXxUXNivGjulVtE0rhYqUQ+NBZr29pqd9uCXecJQX4NDWQ==
X-Received: by 2002:aca:c4c5:: with SMTP id u188mr657054oif.139.1585860404651;
        Thu, 02 Apr 2020 13:46:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:30c4:: with SMTP id r4ls2142320otg.9.gmail; Thu, 02 Apr
 2020 13:46:44 -0700 (PDT)
X-Received: by 2002:a9d:228:: with SMTP id 37mr4169954otb.52.1585860404277;
        Thu, 02 Apr 2020 13:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585860404; cv=none;
        d=google.com; s=arc-20160816;
        b=k52z4NPG4ABd64LLAq850jLFxSLktLepuxYJfyUbB8hR4lhHd5h4gaIdwNPnyHvYQf
         PQeWZwHs3S7nt6TEC8qgZDasG8Q35eduVCiVo/1uowlImPLJNUk4RXKTHC7WB0DC0K8S
         oyI/QAEVmWB3kotLn913D/9PphFCe+iofWSoB5XYE0WXP86Kr+5QD0Z+c5OH9tmcJia8
         uE9bceKoKjY4jBBZCU0HLwT21gvjKmVAy9pfwTeI71h/OX2zgnGV2MyRkdcfDfs9QZJf
         K5myFXSWEuxcxvXzH8s/7hDw6o13L7WzoA3uKVMj6/1QWoBeKE35JLMMcnZNp3+Jgeez
         G/cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=doFYw6zYWi88EjcRuuk27vmWcX6A0cdwO9jpkk/bWtM=;
        b=lcoNsxfS/lSlObzQvFcZadq3oghCtUXDFZ2rjskwSKSXkknbb8iTivtTfBsFBTb28/
         SwJlfd/Cf54DX5Tnp7AdRXTd9Ykz1bhNXwMBGyKqbGm9cJujmXVwXBpSUHMpGIoQiewt
         8aRXqppziQIKawBFp0FUHXs9AQ1JUUD4S/u9sjii3Yyk0Ulbd/0NLeRrskVBvHkfdl7O
         fLdZC8SkSpntX1E3KMpYqvAuoC4vMLQkDEKWzLoFIRS1sK+SjMIy39H5BWlnLpJrc8K8
         EQ06tLRT2H4dcDdSLyt9mNdV9RrF1+hfl+wuMKJNiEsqgFnnMgLG2n7Z4dgmkMudWnBN
         g+Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RBbZn9mY;
       spf=pass (google.com: domain of 3m0-gxgwkceqzxoyngrlutyumuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3M0-GXgwKCeQZXOYNGRLUTYUMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p29si433064oof.2.2020.04.02.13.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 13:46:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m0-gxgwkceqzxoyngrlutyumuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id a188so4018241pfa.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 13:46:44 -0700 (PDT)
X-Received: by 2002:a63:d013:: with SMTP id z19mr5212048pgf.349.1585860403382;
 Thu, 02 Apr 2020 13:46:43 -0700 (PDT)
Date: Thu,  2 Apr 2020 13:46:35 -0700
Message-Id: <20200402204639.161637-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.292.g33ef6b2f38-goog
Subject: [PATCH v4 0/4] KUnit-KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=RBbZn9mY;       spf=pass
 (google.com: domain of 3m0-gxgwkceqzxoyngrlutyumuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3M0-GXgwKCeQZXOYNGRLUTYUMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--trishalfonso.bounces.google.com;
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

Depends on "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources
API" patchset [1]

[1] https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t

Changes from v3:
 - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
 combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
 - Reordered logic in kasan_update_kunit_status() in report.c to be
 easier to read.
 - Added comment to not use the name "kasan_data" for any kunit tests
 outside of KUNIT_EXPECT_KASAN_FAIL().

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
 lib/test_kasan.c                  | 680 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  30 ++
 10 files changed, 511 insertions(+), 391 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.26.0.292.g33ef6b2f38-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-1-trishalfonso%40google.com.
