Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXVLXLTQKGQEHOSHXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1E332DF97
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 16:23:27 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 11sf1984905pfb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 07:23:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559139806; cv=pass;
        d=google.com; s=arc-20160816;
        b=rNmmXajhpiNb/3VxAbgqTQI8GZDLpzK0WhfBlmPWnC3HseP+Fxt1osv+DpB2MTqtiP
         s/DxDgLW09lTFmONF/XO8dn95iww9mFtRtWcWskdhppn8qeaDgyvNjREJGUpO7WBzErp
         kXTiE0tKDwCskJrejVihvMwhzXxwwj9ZsIa04iUfk/23HmZ81ycwgyysB3ZK+6jkHvZD
         YY6m0+gkndSnsR6k0zfH2kOelw2MzCYlhMF7U4H4uLSXAO3vR5n4xLs84N9aQND9iGel
         j+a58pqGUfHNO/+r9KioflYrlKbexukM/VpjJSzODMqYUYeoItkkSm92MKim1eJadyr+
         4pyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=/pX5YIJcX9Q7p3LEHJqEZxpt0FsZZsIL8irSK6GzV10=;
        b=0lTK3cs+2Qy31CUgHuv3gLyOw/r/RY8It7Oh93fdpGu+Uwg+yHconk9Lj89hAKpJXG
         P/RChDYjMxF6dD481n/g1EuAtA1k2lU4LHWDrzARlFdiuQwHEOWhyM9yMwri5HH7WL4b
         0NwCXpD0ZT4LDB/T3DP+VKZN0XQA8/7x7wb2g+tFNMQerwT7KVC1DKxrTPc1lpzIZjsM
         ko/SWycybSDaY8VahGh3XivWUHU0MlWyabGnJ0Y+1lKikRvv9OLBJkvnADeVQOGpFR2F
         KUNDsAyV+9bH0yMYd8vB95DRE8e9x+tO1uTlaB7AjRxFE7ZxuT9vIvs2GgSUKc725APm
         zrgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Guy5Xjr5;
       spf=pass (google.com: domain of 33zxuxaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33ZXuXAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/pX5YIJcX9Q7p3LEHJqEZxpt0FsZZsIL8irSK6GzV10=;
        b=rH8Bw3J+aOQEkJnlyWGFH4qOUP9cPWO4R6Syo7tyo3ScvOKHFrYl4rm/xPkg7bfWZB
         ZiC8ZNKRWE30ChW9g/ZIfv3H6lTCEN6PloEtpzZIGnpvO0enEPBp0cI4wTdKHiqqPvVF
         IOqM6ri7b3bVG/DsANenrxFPsi61aLxxFy6DApbuasz/IHL23OKfXwQW96zJGMPjd1Nf
         761QhibuQYG5ati37Y+0oJwM2EZDNiMdewO3PfhLM9jsrVIC6hF++bKu/2Creg3DegHy
         bEyPWFRpOI/O/1+hZVUl+RpdeU2Dgi1Y6I1No5hj6iqR9bcgA2mznIAdZjHVyO3Hno+J
         sXOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/pX5YIJcX9Q7p3LEHJqEZxpt0FsZZsIL8irSK6GzV10=;
        b=lt2fg45UagG8M7yZKVRWpTNqF6N8EATwctZyKd0PJXROmvrhi1K04PTFMG2DGiPM5V
         br25zFThSn5xRSSeIjkMNRHlOZmWIGM2bM3UQyFttd3M0ttT+iKhMQeNq9TWF7qw5f7g
         MkMnSVC/0e5EnO/k6/4K8WVPtN3koMl/Oww5mpSxBWfVJpLG7ne6ICPTQ7vfXQk5bGrp
         +RJ3xkZkfKyoLS83Z/C/YSxbCoiaBFIU4Hvbku29sHMErp1kITsJCueM+xvB5ccj96Kv
         cmHk+Fku6hu6mxKkN5pEzPzdh0StrXBecOeS6YxnX6MDJZLpgIvMC4AhQVPsENji6Y4e
         eS+w==
X-Gm-Message-State: APjAAAVfD2jMMjuTyOnjG3mm84BxN/lLl+PmqSAqRFwyYOHgY9WOvsMf
	cY036uVUUJUQPPtFhEscELI=
X-Google-Smtp-Source: APXvYqyorS2vpO31uYO+Q4vyixfI0i+uIt/RSofitXNYPMuU8Hj5ibdbFIxRRbiMuMe15v9WfMFYUA==
X-Received: by 2002:a63:c14:: with SMTP id b20mr139572539pgl.163.1559139806543;
        Wed, 29 May 2019 07:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3841:: with SMTP id f62ls691195pfa.2.gmail; Wed, 29 May
 2019 07:23:26 -0700 (PDT)
X-Received: by 2002:aa7:8c12:: with SMTP id c18mr152889681pfd.194.1559139806191;
        Wed, 29 May 2019 07:23:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559139806; cv=none;
        d=google.com; s=arc-20160816;
        b=NyoLAw4vJa+2pNpNLkpvqNrnDt3z6wB8O0XWxi6fDDmFZPxtsX2PgV+GuDY9ZfE5Dv
         90LapNUfP93+GURESDWyNFDY0YqwghrzdPGfYtq4OLR2u32sohY9xjx/5H2r1Rc7Cunn
         QBg+3M4Xt+Fg7yZSaxjO4+crmrDviWZtaTk/MwhtyF/faEA5d7IMI620r2DcIBRS/V2Z
         ZINThsN2mQCtb1U6cm2OjqaQIK+7KeuvlLKdlqcLw0ukTkKILnPZVzeubdB2IsZQaFti
         gIHrtFe+3HnsvnNcl15jCrto6bVVPfPTsBovrg9gbji+Q3oBXEp6VV/80KW8vvBHe3/q
         LbJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=PLHql6HuZD0bzmA8PfaTdvUizoR7LXyZ6UL9cOmZOnQ=;
        b=AAl7y3blJgD6hXZE+K2k9bQKIH7gQzzFmgpsbyDXVD2RsGUwDHJ+locM5VovfBaGFi
         QZ8ICqvp8TQJLGtouUj9duJWVOp7o1C4ROmASCDq6ci5sOXKuILLBBFNolnjLUUFDcmP
         B61UZn3tSXUu8MG28xpDkuhS2hpiMnRsSvq+nfOoc9Y4blhqx4Z60PWHztICS7D+9ItZ
         twSSQQfvXupI6JYtr7YqvfoDRdnOIcyL1m1hzXfhnwWsNnBskTI2ya5Jx2qCA8z+t8y8
         8j5Lj/WorVIeFsK3303FQO8qnRApy/ObdJTmHWKJ6Mm/6cf/FuOw81Y2OT09sCXGXaRS
         JNvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Guy5Xjr5;
       spf=pass (google.com: domain of 33zxuxaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33ZXuXAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n93si117643pjc.2.2019.05.29.07.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 07:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33zxuxaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id w6so2014088ybp.19
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 07:23:26 -0700 (PDT)
X-Received: by 2002:a25:c0c6:: with SMTP id c189mr43131422ybf.339.1559139805383;
 Wed, 29 May 2019 07:23:25 -0700 (PDT)
Date: Wed, 29 May 2019 16:14:58 +0200
Message-Id: <20190529141500.193390-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v2 0/3] Bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Guy5Xjr5;       spf=pass
 (google.com: domain of 33zxuxaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33ZXuXAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The previous version of this patch series and discussion can be found
here:  https://lkml.org/lkml/2019/5/28/769

The most significant change is the change of the instrumented access
size to cover the entire word of a bit.

Marco Elver (3):
  lib/test_kasan: Add bitops tests
  x86: Move CPU feature test out of uaccess region
  asm-generic, x86: Add bitops instrumentation for KASAN

 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/ia32/ia32_signal.c               |   9 +-
 arch/x86/include/asm/bitops.h             | 210 ++++----------
 include/asm-generic/bitops-instrumented.h | 317 ++++++++++++++++++++++
 lib/test_kasan.c                          |  75 ++++-
 5 files changed, 450 insertions(+), 163 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529141500.193390-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
