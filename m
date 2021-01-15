Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ5HQ6AAMGQET6AKLUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AEB02F82A6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:42:01 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id t10sf859408pjw.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:42:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610732520; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaPQHH4mHCOvf/Fm+ecst2kwOiZDW2tJoUm5JB9V6xZIxqwo6r34nk8XkV8525KS4N
         SH2dYSow/i41oZrOy6H8Dys0Qu55HB+qMJ3clT96sTA0aYL/GDMXQoXDiEqSodxBFnKm
         WoMPOy3JJBb0r4EMl2BJ2F+h6mcMdGWa7zSiKD4yrnPAhoSS4XkIxB7wexsvsgFExwNz
         2ZI+SSZ+ye9kbzteFXvIdyyAWzfBRuQCzqGxMLrOiQ39D8xVB20B7OqFq3dM8Wo1GuhW
         hdNTpv8oI15TVDpgiOCbxMa5cVlhANR7RRuTDp/eLD/3MkwMkLUyw/k0Sgn7cjvJ/ytJ
         98Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=xfWs4RCFixvoxr3k5lrHdusZHvWU6D5lJStcggXXaEc=;
        b=R07GX24QBK/ygGTlskeDDu/Q7vAB6gI0WNxd0ysR0DZLxImcTS+6Sek5FxZejUhky6
         vWYB7Ga9O9QlUeOr1t+9xuJDPwTemskV2IaUYp1lXgEqLp9RtMVBQ1s5EMCNl1tx43GG
         W5onrRltnkGWz3x3FpMvPw5o5hMuxbYY6/5Tt2+xgLppjWxJxC7q63i5GjqnrwyzrwP4
         Z4e4ro6XUIekZH8Dy8+0Xl+hByhW9w5qn/Y8RLlJJvUibjwmZ8ukmNc+vQFMLZUinifL
         EtwQ+YsdRjXaCipjCbF6K+iPtOLiTjwFcVkpy1GJZOava11VnpefRbfZ4LDb5NASwzY6
         YigA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fZny2t5N;
       spf=pass (google.com: domain of 35tmbyaokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35tMBYAoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xfWs4RCFixvoxr3k5lrHdusZHvWU6D5lJStcggXXaEc=;
        b=jRLdEbsei4hmOreUbMJcLynVL10wNHroeD+6W1zBVlqbzBmCzGAtyELDjFk/U+sjfN
         x630RE0uvE4kJqx5SNStCvAvY/wBnDaFQP0oWXqpUXGP3WURoI/wNRgxO5IRj32uUXEJ
         KH7rR00+jDxzDvDD3q4VQxM0DbjlKg3qe9oEh4VmFweD+TG3g6/Rpciqi+Pi4vG5NTf7
         z0yMba0jcKSSrJVkoxgg0hCh/G5v97mA7h8EBfzrreW7kQLtaeRb37/bNSx2IKfnw9j/
         EbFyFeGE0bX590znbrr1PlNldWbXjRm7ENf1fvAp0caGeFGuub7W9PGrmnqhGavCDsjw
         /V5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xfWs4RCFixvoxr3k5lrHdusZHvWU6D5lJStcggXXaEc=;
        b=mmRblWciRLH+uiav9UVUzJwYBe0swxargoGUGr/IfH3xWCUuQHvdtQPohpsKoUP8s8
         KeV7IDsC7hSu2nawBRdns78kdlnlRuqedjxraoXCXdPPNdsBkX9XBIbVNOHe4kluBnIz
         Xyjpim/Xre+j7MffHlLiT7YxRfbjMLtgatu7GfI27CCsQZwWLLO55LKIuckQzpq6G3p5
         Oa0NP/uvbI0iXDXDFHu4Oxgpb+Yl6Ls2VTycyCI3xipLI/eS5DJ9JIXc5Gn9IHjgMYGD
         kOQJYhjBKymjEZOxKdWmRZyEsh4ehUPqxiGdL6UjhWpbf3E2JlKUlomJCHtk9viOw5GV
         6J/Q==
X-Gm-Message-State: AOAM533rpzYgoxQFZEcrgsoMZQ1dSk735FmHVxEb7qRJBePETBG8ciBS
	0ygiyDvR3wfccvW4BeuSbA0=
X-Google-Smtp-Source: ABdhPJz2JIR40/MHR1zk8G7KuJbS7VT9p2C3huxY/iX+kwQ/M01UCD0xarctfExLQ8sE7CZpEy41qg==
X-Received: by 2002:a63:6686:: with SMTP id a128mr13573114pgc.96.1610732519885;
        Fri, 15 Jan 2021 09:41:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4881:: with SMTP id b1ls4999676pjh.1.gmail; Fri, 15
 Jan 2021 09:41:59 -0800 (PST)
X-Received: by 2002:a17:90b:a4a:: with SMTP id gw10mr11608754pjb.29.1610732519286;
        Fri, 15 Jan 2021 09:41:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610732519; cv=none;
        d=google.com; s=arc-20160816;
        b=RqwDHjMH/fJGxc63RFGqFXMy4T8N/HqxxfdCvd7kR4ITV2tPPWxp4SoTI5K7lvBdvA
         CUlBBd6r9b17iTxUq1c5FcN6c+0doHxrAwfyyrNXkeXQUnTLP2j8iTZ9P/Y7+gP8wdhF
         q3segM8CwWXALMX845LEdPGsRh62twt/TCbAcefyU2CZwH6QpcZAKQkhzsipIBo0n5mU
         eNMo++SDxMtGtB0r8ciC9qsW05ZSYtfJQgotph0LSQYZE9m4szS/sCeBfv8O01FU5+Rz
         fbuI7fB56F2xD5+8XWZkl2XxspNCbmXYRH2/LzmRjbr4Jh/KVu6M+1MAF54m370PO4NH
         kCZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=s2BQxqmasNBEOjHNthhB8zI5jOrrfc4sePLKP1wu5tY=;
        b=zHFQmxsotAYu9yNLr9vozMwkGV8NqPtmIoxShpHPoA5vRK2poSH0aQK/9cgqVms/JP
         GHJqBEXbQ2OxqjvJgjFXgvQnW+clIqlM1TIn5VzHM3wEKYozbcVV8hBc7VNWJxBG007h
         gMOjq4RhOxE1ZKhaksA55t7IOey5jawdLIN+7oyLKPktMnoZwyGAhEL5A0IqFgxoSEO0
         PfJUITHo9lPd6J6Bfy3Wlx4ajkjOTpxVnZk3qPFkupw64HBRtk+t6XnxGKS/nX0UYvtn
         Pi0QqpdN0LrBBxVbVbAJv25QQ9pdulCVtYleRNl4+OeFVzJNDpcGzLglYOsNnfYiRgDx
         ieEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fZny2t5N;
       spf=pass (google.com: domain of 35tmbyaokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35tMBYAoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id ce15si823169pjb.3.2021.01.15.09.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:41:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 35tmbyaokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i1so7957794qtw.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:41:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:434e:: with SMTP id
 q14mr13123760qvs.15.1610732518339; Fri, 15 Jan 2021 09:41:58 -0800 (PST)
Date: Fri, 15 Jan 2021 18:41:51 +0100
Message-Id: <cover.1610731872.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 0/2] kasan: fixes for 5.11-rc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fZny2t5N;       spf=pass
 (google.com: domain of 35tmbyaokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35tMBYAoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Changes v2->v3:
- Fix up kernel pointer tag in do_tag_check_fault() instead of
  report_tag_fault().

Andrey Konovalov (2):
  kasan, mm: fix conflicts with init_on_alloc/free
  kasan, arm64: fix pointer tags in KASAN reports

 arch/arm64/mm/fault.c | 7 ++++---
 mm/slub.c             | 7 ++++---
 2 files changed, 8 insertions(+), 6 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610731872.git.andreyknvl%40google.com.
