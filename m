Return-Path: <kasan-dev+bncBC24VNFHTMIBBHEHZL6QKGQE7RSHDPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 12D642B44FC
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 14:50:22 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id a27sf11643022pga.6
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 05:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605534620; cv=pass;
        d=google.com; s=arc-20160816;
        b=wuwonqFsx1IFJK4zYfROV22OvpfjHc/8fJaBPKjjngq5jRCorU/K1lNF30qiNGxncY
         1BSEwSbg49GU4ztJmAE7sQlyLCPVubZviLk8YfY+jJ+14z3nqYt2fOEE+y9SxzwSM3vA
         w+ZH7lez0XGrVdInpAT169qpYkPw93OzmpPdyt6swefk8ruhgLYzn3l9tpdVR1OtP91E
         EpFYo7z1DatHXnSkd8o8WObMhzDOzr+QwDe/2w1z1f7ajfM85e8ZZalAXP/9wGafBw34
         8kr6RgZA/l9xivMbNiaCj1CssYM+mH8unwEbm+W9skBlYuvy9PBj7sD3ePhgWVr/wNNW
         W/Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=UM34INbx8aQL5gsLagxdHC7Lf9k5g+tKKm9Yh9WzGCI=;
        b=Un+Iy34VDz9iqrAdnQqwNFXZRlCAkyQy8Kk27TY/x9Y//I2T6vgoZYkEwOGjj2brSo
         RNpgmrECyoQX4G5Hnw/fnIlKMqkzPll9L1qiYVaO+VTWuyU06QYtG3UXnp4uhc02s/xO
         gJlRxZ1EOn0v5mO+90BOZxmv+qReJhImrfBfr5uWpgMzAkQL4OT3RfcVAJyTfcwGdAZa
         O5aChSQxI5J5zjKl8tdD/6Ba8kBO97DkzmRKnKFY5SAMxVkIMThOKit721nOgaoSKALL
         YTrFQjrlZaQphlqbl0V0xeYE3QlrE2YopwjmrZzB44vquRiWI63Kh18pFJrgyMuAOKvh
         QWVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UM34INbx8aQL5gsLagxdHC7Lf9k5g+tKKm9Yh9WzGCI=;
        b=JJrS04XIokGKQWQ9kbQgPp2/8HpiacaHVbSs4tyGe4Hoer9UhoNZqNvXeg6yyzRwtw
         y6HJsZIzu/4oiBp7eFLgVoE5D12A99G8os1R32SKAXPHH060oTDV32nPPxzrRZohRo05
         wpJoRCm+QXEilIEN2oZi6y74YzWji9jx3Rt/X/JFRTxExldHhgh6pfih44g+GxY9bzrZ
         hLIoYiiHuKAcHjLmJVkOFWuxlOLh60bochDTcYNfLxlWHqF6qHkTniwuIUdL9ffEo9Cg
         8QWKpGe4PnTdUk1P317zlcW/S4iIaSV5YjYg5kaQafTrai3V/X2Kq/7ELy2+IZve0f9c
         cC8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UM34INbx8aQL5gsLagxdHC7Lf9k5g+tKKm9Yh9WzGCI=;
        b=jW7LCXUiqI8A2RxdKQUD7JiZhxoBD0s1G127k3pLMVan189sGHzHgBUQJWKaOOqyK7
         QtBr1K47+ClLfKROZKI0wG0DuNEiEe6igfXUm6I1K8cZzWuuG6TtRcF5QXE3X2qxHHDt
         ZgG0GCbqRBq+642csAiKF6o7OfoZ0gNtIz8SUyfVK26rU3KeCRvVyDP/Raw5KQ5F25cI
         MdM2gAmtmaH79cfA6A5LBAh7VYERYw3P+Dw1FNNFLUHOoZCEUsfqY1mYoL0685enUnUN
         igkU3o8lGeltKH3LdZ4C12OnrjcsRpVwN+dE8wz9eeuyovG37UlzIq/mLf8qD//yeH0P
         wMzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EYu4mk57BlJ+I7RDHgNURyVDCNaUVUyQc5AemcBLvdMjEFMgs
	uT2Xe/S6D5bwuxOfnp7SFFo=
X-Google-Smtp-Source: ABdhPJybHURUiVvoQodBMkCX4Lw8afc8AIG0ZVuFAoj7sPhDiP+2Eb9NwL7riRD4nyqIQUiBRAKVvw==
X-Received: by 2002:a17:90b:384b:: with SMTP id nl11mr16362040pjb.126.1605534620826;
        Mon, 16 Nov 2020 05:50:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8616:: with SMTP id p22ls5059112pfn.3.gmail; Mon, 16 Nov
 2020 05:50:20 -0800 (PST)
X-Received: by 2002:a62:768e:0:b029:18a:d54d:3921 with SMTP id r136-20020a62768e0000b029018ad54d3921mr14450825pfc.31.1605534620277;
        Mon, 16 Nov 2020 05:50:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605534620; cv=none;
        d=google.com; s=arc-20160816;
        b=uTxgLWpHrYUcQOYIs7QjuZU6lmu/BlYgFihj9oC6P6KlcK5sqRu8Ff1E5rcqjQE+Vw
         VyvLKkTpl0hMA4jIrPbl1/u6R59sujzMkDo8MZ4p+cxohwcwu4Utoy0LgDLRM87Ipnrc
         3PjTBMbNziLh6d/but9tjWXz8eQ2y+Wn6ly6uDzgmmEZbNI8f/smx/hUjcimNG1pasaj
         xfZfsmSGcq2bpy4693B0pFD2SRkG4EyAy9SkhvFanMGhQelHTR42ibgKCnRZlrpqdboz
         nSlNDIrwJjcyRkgjlKAEadMQqFdoWApWzARleACxWT5O+2Xa1jciDlP5B+q8lZ1VO4+4
         HGvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=npmnmB1BoTHJ8vPRXrhDobcSIoOQtf4nTwxXbPQQgTQ=;
        b=VX03KOQNrstMJp8tEpjDRIHkzIddcmbAbTsuhehZ+aEnShgynq95hCKc5Mu+z4Utue
         cOHo+uDSh9uRLpM7ENCaNqR58A7P8EjM+gNCxp8k88IjShnQecWUlLoeJcpA7OG9d4YI
         /HyVM5ihFvY4MHbucFNzyOUSVzYs5Db0r+dAOoJ1OcPC/VqzKt6cU9QZBxfjWYxXCF7i
         G5zVVPHSdNTfXuwA1j80auOh0btChTDWDoIjLDE298uzfcUzGYxJkTcj4sfOhqAkm7GX
         q3NLDYlCZ56v20C99DE8liSHwfy3nJuBVb265TbtnyDUV2+0KebzQORQSl7byHpNL2RL
         kwOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bg19si790680pjb.2.2020.11.16.05.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 05:50:20 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210221] New: KASAN: turn CONFIG_KASAN_STACK into bool
Date: Mon, 16 Nov 2020 13:50:19 +0000
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
Message-ID: <bug-210221-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=210221

            Bug ID: 210221
           Summary: KASAN: turn CONFIG_KASAN_STACK into bool
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

CONFIG_KASAN_STACK config option is currently defined as an int, while it's
logically a bool. This is a bit confusing and is worth fixing.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210221-199747%40https.bugzilla.kernel.org/.
