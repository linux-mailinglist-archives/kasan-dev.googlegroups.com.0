Return-Path: <kasan-dev+bncBCIO53XE7YHBBXM72D5AKGQEZJ4ABGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B0B0A25EB64
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Sep 2020 00:23:26 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id dj20sf5675216qvb.23
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599344605; cv=pass;
        d=google.com; s=arc-20160816;
        b=w6eBgwCe7EKAKWiI8A1Zl4ox2sTvyCvGsXDqg6dE3Ry269ukJ93RuelN2Yln191ffK
         bV2RyTVaONsxlZPWBx0yS2oA6T0KWRgPuVMZiA1Lz7m3XUa8FLlu24QApyQtb8W7xnwM
         VecRuCrs87QXzfmYMBdn6NAitliXp6CEkvw9xWINzs4CZIjZZ8I5YB+Fw+LOIldFSI60
         H10Ppi0pV857pa4En4gAcTvHBKITlR3kXUpy9lz7TGQmBVBxunhrqDWHLKhlKdElxsaq
         mFaNtsuWNq0ByYOyfhVLXFg1ZuFlCNeunB98eSKu6dTrUpXffOYgUGqmKivtEudgiZXS
         Po9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=17X0t5hn/ASAQzj0v8ga8GX4zmk/BXBV9ynuAf0tQrk=;
        b=nFUs83+/EKINFol1p+9LsWURvvD4utdnQ3sCuKkYNt7/LU5uRM6pJ9Wx5YROH07cJW
         MwaSTuwFolEbSNr1acjgD88PeQWl40c7tzA7V4cbOaollSf9iKGpAOGXvhmhP+Ne5H9S
         x3oE1l63skggnvSr1kaHG/o+UeKPkBPStTFduPbZ4DSvrovI28wSY5AgLMBIz7CHn/wY
         cx1KwHTPdB9/dCqqFzyBApOlTl3KMHdmAr1Fqq8gZHYbG3uRjGhjQZuv9p2qjJjTtoRD
         umkZ1vwrtlurSOPH3kwOEEHEmUuf5SrK1b+H4LMHyYmLOGyBSIQg1ofkVmU7LtXYUuQp
         jP1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.219.65 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17X0t5hn/ASAQzj0v8ga8GX4zmk/BXBV9ynuAf0tQrk=;
        b=IskpEWuQ+6zUdmX4zT6Sa+54W/N1L9CUvrF8QFl+U88/jf/wvVU8A1BQnjl//GpBfg
         DoeVJwD0OiJJ2qD2Y/8SbTmC08CfJCTUxbPVBxxAljDDiu6FbiYvheCqZlRBpmtkLAqe
         tyymj/xCVOPlaMxmVn7LweZUrf2cxVfJ7dqLUzLhgQm8jTInTedWKRH19j7+kC4u4WPd
         IiI8x56e/WagwbE5N59YcaJj4MQh5AVlCkN4k1dFyQKSoYMjKqoz2tGX+bgbsH2YRILO
         BbWvmccao6H66DaoFy4n1S0jntt6LtOdxCwVlzHnaZ+DafPfQA68Suf8UkMH5a9ctNlu
         t78A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=17X0t5hn/ASAQzj0v8ga8GX4zmk/BXBV9ynuAf0tQrk=;
        b=CiOSaF86SNB+3LEFiFbNjOVb6rqvELq7uxYiKxl+8apR2aWAQyyHokWJ95RalvzVgS
         +ev08IXRLl/mY4ntVRZphagv2pAqy7HCUyMJ0U6sUGLnyH6KSK2ce8ZTm+9p0i+9EvAP
         JObTUMkzStXYPlbcrqBXPG0EB59I/78n0lQUtRp4EA6WfyJ85ZaS1lfDAt5IRM2VxAiO
         wMOsDsrv+8/kg5y1CpJHABHT47CjmvyuVhj6S52H65faxyN28cJcJInwQ/jjpUN1EvxM
         67WC+c4KNI5HfDLF/OIyOWqjDeKsfUuq96V449KegVApf5cYCC5zD9gQ/6iZc63DmQGI
         6OAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+/Xfl3H3OMnPcujdH3bcu5I5i4s355Zqw/z3Yr4LIIc/Ailv2
	o5ESrOVUx6IJiN7O+L4vsF0=
X-Google-Smtp-Source: ABdhPJzotx52u7VEr4JksUyz8mJaiD3dj4sw4W+RA7J99JwWboUfrQkYGB7rPm9MrOJ/R8M1nalWcQ==
X-Received: by 2002:aed:36aa:: with SMTP id f39mr1665392qtb.297.1599344605498;
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f50b:: with SMTP id l11ls6377405qkk.6.gmail; Sat, 05 Sep
 2020 15:23:25 -0700 (PDT)
X-Received: by 2002:a37:9c4f:: with SMTP id f76mr13961451qke.250.1599344605072;
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599344605; cv=none;
        d=google.com; s=arc-20160816;
        b=OchVa7lnr/qt1wdDWarRmGSg0qoVVzQs0GFkh92lLTxCQur5WGxbnjI0vWy7ZHBBF6
         FebIZh7wgV3dVPzi5bqqSHmIpdg4jH6PsPQb+x2Gmmcu9rCIZn+SUuKbxnfLsWXhf4wM
         t3o6P3J/XIm+Ox/Yba4wW2NMHlUIBqZlg+Po+++JxCH1Nvk9uSoRjdjUnbJrXEiC3I54
         RnyiE33cjEfe3r3ESmqGih+eM/3/LkvS+YZtUDw76f9S23QcOHY82ivzr3QsNqe1Jyoe
         RbJfeIY0AAW3vVDkFt18rBxn9+qOmxKOGBxaUPQE6RWme5b58qx4SNvHNK1FdUfc+gJS
         fqGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=o9C3RF43smdLyRCYoPU7N3p1alftqLdC9coi9jw2anA=;
        b=vu/+P0bN5A3vl+Gz4D5uqx29AozqPRQ6a6KicYO5kTEWWpvuRpznK0SL0zs2TFK4jI
         MfMZ2D4rDcFbueX9RwWCXzz6eQdjKZEGjHhwNpizfxyd4tZxdXGPZ2jCIWfqddwlPSkj
         B5kxgZUHbKCNrtkdUorP0QT6KXc/zg78yCE8f81+vGnftK6CtnhF8OQCtin27ifc/gts
         kLr9rncT48rhIq0iTK6xtQDoXoFnFeLeFa6nGGzODBJvS1Mk4Sc9AWt5IVcDlKKxmqTw
         +upbf26uvUQqt7/PTK5K2aXZ/s6VAtNHqe/YnZKgoC+sWi+XiPQ49+ZUBiGc69pV4mOu
         qHvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.219.65 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qv1-f65.google.com (mail-qv1-f65.google.com. [209.85.219.65])
        by gmr-mx.google.com with ESMTPS id a27si642297qtw.4.2020.09.05.15.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Sep 2020 15:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 209.85.219.65 as permitted sender) client-ip=209.85.219.65;
Received: by mail-qv1-f65.google.com with SMTP id c6so1607654qvj.1
        for <kasan-dev@googlegroups.com>; Sat, 05 Sep 2020 15:23:24 -0700 (PDT)
X-Received: by 2002:a0c:e303:: with SMTP id s3mr3593467qvl.61.1599344604618;
        Sat, 05 Sep 2020 15:23:24 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id n203sm7323886qke.66.2020.09.05.15.23.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Sep 2020 15:23:24 -0700 (PDT)
From: Arvind Sankar <nivedita@alum.mit.edu>
To: x86@kernel.org,
	kasan-dev@googlegroups.com
Cc: Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 0/2] Allow use of lib/string in early boot
Date: Sat,  5 Sep 2020 18:23:21 -0400
Message-Id: <20200905222323.1408968-1-nivedita@alum.mit.edu>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 209.85.219.65 as
 permitted sender) smtp.mailfrom=niveditas98@gmail.com
Content-Type: text/plain; charset="UTF-8"
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

The string functions can currently not be used safely in early boot
code, at least on x86, as some of that code will be executing out of
the identity mapping rather than kernel virtual address space.
Instrumentation options that insert accesses to any global data will
cause a crash.

I'm proposing to disable instrumentation for lib/string.c to allow the
string functions to be usable, and the second patch is an example use
case.

However, I'm not very familiar with the actual uses of that
instrumentation and don't know whether disabling it all for lib/string
would be a terrible idea, hence the RFC.

Thanks.

Arvind Sankar (2):
  lib/string: Disable instrumentation
  x86/cmdline: Use strscpy to initialize boot_command_line

 arch/x86/kernel/head64.c  |  2 +-
 arch/x86/kernel/head_32.S | 11 +++++------
 lib/Makefile              | 11 +++++++----
 3 files changed, 13 insertions(+), 11 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200905222323.1408968-1-nivedita%40alum.mit.edu.
