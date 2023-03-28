Return-Path: <kasan-dev+bncBDKPDS4R5ECRBRPURKQQMGQENLMNLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BB06F6CBB95
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:30 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id d12-20020a056e020bec00b00325e125fbe5sf7282734ilu.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997509; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpV2e2iskoFPN6dWpicZmFNOLoRWdYqxUgo78iWZx2by6cvAQEWGh/MpVSLX9gFe+m
         QODPStKYSYFr9UduEJm3zfvRntXVpD66+LYBnmpdHktvZVzperdeaKkZkNQzvN1jwUx+
         Oj8a+Mb2LAONKtNhnGq6o/xFrFQp08iC9Y3IebTeXKr+tbUV9oe4JOMZ5nIddybDJ73E
         tWWirCDmeLMMbOwQZmRw6wczqeiHTb5qqYfdXmpWHEzZRDf/xlateqXklqCCBUmLMTDY
         U7tYsHFMijIKm1/u3KJ/kzGhy8B7/1KcPfjB8ciaL4dJ59q0aa822G8nx4d1j9LsFU5F
         ldhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=skRhYjaGtyWg6fyXmm55wo9G2VHG0Gd/X0VOm1Cka4w=;
        b=GyFUU08OIYL4hrdjSDvjh2SwPqKXHNLttlKex8IAINplXbiKKnddHhmXecnqKdHSmr
         FYOjboEhqg8QxLU65Lw1Cx28JmkzjuDadbOUw2v8SRP21yD+XPbtWi3zx6AslM9TjwXq
         rF1vg8KO49w5sRDOgYysjKeey+BNa4oDPk+PoBU8unGb9BUwgHX8E/7cxCz89U+0cwiC
         qAxY8rnJH2slQ8TohJ3gHyJ3wL2gdFS8HoEVfMGBaXjhKgUYT/d6sIIip5vnmo857dd2
         WLcXlYVts5ur7YtMBzaO6BUkHJnAgv2mZOaHFaFNehxZ2f+UXtE4d8blDLT4YmgrTVUh
         3duA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=H20nkFH8;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=skRhYjaGtyWg6fyXmm55wo9G2VHG0Gd/X0VOm1Cka4w=;
        b=hlPP/+HzucWRW5bMBNletkZqvpWfJJMyNGEYdDfr6Mlg58UTiw/ZzCp0X5Dvs0AlY6
         ER43vOdBf+SUjfB+CuMlnQxQ/x/Khp3foaDSF+EcJEua6Q4TwLZAkP04P848Jtif8sOC
         HrIEM3CnM5t4SMgUljJZAwwj1VtHb/HEK8/A1jgznKuqiNT3Xyy1FVFGd63Suj4vB23P
         4hCTHeShftQZq4bNE6tglWyDyNXeZcxFUpP05OvRHTaguCHFs+bLSeCLIk5wfpJ5IPto
         F5eovYp+UnG0eudhWs/tLeKW95kzZCyv9pJ/DZ2kW9hNV88ENwFqQXLRbpoTwKNHOy6U
         UHpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=skRhYjaGtyWg6fyXmm55wo9G2VHG0Gd/X0VOm1Cka4w=;
        b=lF3nlzakwYvTi+LyBzPbnq1ebFcjkTCjq29Y1N/7Kq2hhMoDswDBEGD+XjJrOhr5Dp
         O37mFW1BYU/XvIVDeEQ7h/HDllBYG62tk2TAnxjatDg9qLBdnaCddeQOi7zE6Bi8gdIk
         WhIC4yrMezryWle0gx51cozrk/y7oUPITYPENpNrWw2kwIjXjBMwv3C3UkbsIJXm9xA5
         6esYgQv3wLf/38tOiJaFTs4x7AjyePW1kgfGyiBgKFNgf1Awey+SiMoptWjcYhi54zI8
         CzM3gtgFKvQafMZARLE9dmRKHAAPCzC+EJVpwnIBevWSOToH1Dxl+ztV17L7lxQw9TRe
         6kWw==
X-Gm-Message-State: AAQBX9eBMhUSeSEXV/uZheMHSZVchWWcK1pZSY/6nNBoR6F5pFe2h/a4
	Q8sGU1hOrnku4BAwgHxQ5dw=
X-Google-Smtp-Source: AKy350YK/uQ2ZlL5Zi/6MgPl9kd3Zp8Kn0ln673h/u7Jv7FSFlVQg8ytl9U89SqS8NwMXNrdpBaW3w==
X-Received: by 2002:a05:6e02:1be1:b0:325:e0bd:d1c7 with SMTP id y1-20020a056e021be100b00325e0bdd1c7mr6971119ilv.2.1679997509160;
        Tue, 28 Mar 2023 02:58:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:71a:b0:751:9df6:9336 with SMTP id
 f26-20020a056602071a00b007519df69336ls2004662iox.1.-pod-prod-gmail; Tue, 28
 Mar 2023 02:58:28 -0700 (PDT)
X-Received: by 2002:a6b:720b:0:b0:758:ad48:6924 with SMTP id n11-20020a6b720b000000b00758ad486924mr11450030ioc.15.1679997508661;
        Tue, 28 Mar 2023 02:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997508; cv=none;
        d=google.com; s=arc-20160816;
        b=kAQAJWll6NONfj1JwFsuSX+yzbI8ZxYQ4uPAzApSD2aLMAv5UD3J1AAs1YFV6i4EYK
         g7qNBQOOtPg/a5Qdo/g0WHjlTllN2crukjGb2qnMee4EOeLd4/D2A2rj6sH4wJqd+flh
         IYd5aSB9QIyDFYWi7beJwOdKEzv5c7J95TLXDIflvzRAnpfh7sJM8u9xIqflowWAVWX3
         0B18T7enbExUm+Z/Cx3LK02obkdt/6IjsqAhiP7rpYKi45E/kUOjPCDZ4kfU/X/AGZwx
         g44kBLwtDVE2564Kj2EoZnmAVLzu0rePOpGD5LSNd+6bCe8oE7T1RbJLeA+17Yu9tJes
         T7YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6MISSvCouqA9cx2hoXCbIEOFQ/tw2bO4d83GG2zGgvE=;
        b=n8eGZde3cKWYQIkLbND2GJnJeUb0NZ4GeaA5kUSgoydnOCG7GJr2WR2hPRtE0MvU+I
         RpUOi+A7fFgMZg0RgArVaMncRQa9oI7w5QfTMj7qCN4XnrPZTDjx8kpRX6BI3ro/Q2Jl
         Q5HtDS40oVp8wJGHATgEnykxZBMQn+9P3VVPYR/Va5iXgLWmdwY8zje0tgDeoYOtaU99
         rl9BVy4SddIbmvfmQQ6j8Cfq0ZhV/X3OPS5DKIiVBpw4KKyne4IOklS++bzvvU7+aoPl
         IB2aUTspLR+2AjQ5uZ6H8fSj+2YAPODQRmrIs4KjPUiJJiUjoTc8o5+LQ3/K8j6NZ0P2
         CPoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=H20nkFH8;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id f12-20020a056638168c00b004063285e3f3si3280185jat.7.2023.03.28.02.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id cm5so1747804pfb.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:28 -0700 (PDT)
X-Received: by 2002:aa7:9629:0:b0:628:1274:4d60 with SMTP id r9-20020aa79629000000b0062812744d60mr15936639pfg.21.1679997507878;
        Tue, 28 Mar 2023 02:58:27 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.23
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:27 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 0/6] Simplify kfence code
Date: Tue, 28 Mar 2023 17:58:01 +0800
Message-Id: <20230328095807.7014-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=H20nkFH8;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

This series aims to simplify kfence code, please review each patch separately.

Thanks.

Muchun Song (6):
  mm: kfence: simplify kfence pool initialization
  mm: kfence: check kfence pool size at building time
  mm: kfence: make kfence_protect_page() void
  mm: kfence: remove useless check for CONFIG_KFENCE_NUM_OBJECTS
  mm: kfence: change kfence pool page layout
  mm: kfence: replace ALIGN_DOWN(x, PAGE_SIZE) with PAGE_ALIGN_DOWN(x)

 arch/arm/include/asm/kfence.h     |   4 +-
 arch/arm64/include/asm/kfence.h   |   4 +-
 arch/parisc/include/asm/kfence.h  |   7 +-
 arch/powerpc/include/asm/kfence.h |   8 +-
 arch/riscv/include/asm/kfence.h   |   4 +-
 arch/s390/include/asm/kfence.h    |   3 +-
 arch/x86/include/asm/kfence.h     |   9 +-
 include/linux/kfence.h            |   8 +-
 mm/kfence/core.c                  | 229 +++++++++++++-------------------------
 mm/kfence/kfence.h                |   2 +-
 mm/kfence/kfence_test.c           |  14 ---
 11 files changed, 89 insertions(+), 203 deletions(-)

-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-1-songmuchun%40bytedance.com.
