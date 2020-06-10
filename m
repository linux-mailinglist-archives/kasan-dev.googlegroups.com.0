Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOP3QL3QKGQELJYOF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C61CA1F52C0
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 13:02:17 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id r1sf377421wmh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 04:02:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591786937; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9Mx6VJV3EB/DDUuqCzb9k62Wot7xOFt34QIQa/PmI1SVPDxatCD5VZ3cl7mdXlW37
         p4Zzs6RSpy+Aj+HQyexe4I9J/zlc7f1ZKsZoUGhaXzg5grbvXTnjWprzQ953CJ6sjyNp
         7NKN1doXZfutk4CIvxM/VZYiY20sx1jJvVedpGJVmqz93aXsZeVWyFaDkY/D0O9ewxdt
         ddZk3SdxIMXSMAzqOXP4XTzDuySmSogvdhAv/77SEctMHK6P40Yq7IkJh0+loYXivCLA
         ZLn8t8rIrhhZL0HjWjq+WZAbNKlgrJc5QyAnraauzX+1R8lYRNr8p9pubsHeMda+BsNW
         cdfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qdqluFG26YPGKzEGYfK8OFTjU+OJieX8X9rfVlvcuxk=;
        b=OTdsW1Ldl4BHXkwdbFhRdLSGANFp+BPHzz7oqRUyRbDa6HHADPt0fo0d/Ivrcr9d9T
         X1H7NLe59gaSvSq1fRhJoypqsSnrzE4Jc1dOj/P1siCLYTTynviW31zNCXNo2wF+Ww8Q
         27CtzoSs4HAwb8GtsvFWtaKEANkN23c2udv82Ub7Cm79L1bzuXmhsDcDSV9Hn71zlwml
         1TWoMt9dFeG3QYrtqIlcBfFIU9knN0Q3q/j7W/FXyvySGhWIr0BpjmPcr9P9UKngSPE4
         d/b9CUI3v7BWf/vFJBzyR7qQouJG+b2LWEFuIK8XA3H8oKHMQzzrLT0z6p3X7Jo+PU+/
         fUhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CF/wuS5V";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qdqluFG26YPGKzEGYfK8OFTjU+OJieX8X9rfVlvcuxk=;
        b=tGfVck7uc7JOth48H/68IuIUHURmCJymv6dM1ztte3vBmrI9MAW9IPE+KkUzDY3czO
         A1tfjxHlltBDB8rRDnihhGmILvo8jVVSoraRkPr9dt6C0hw/jPNnlUh3CgEJQIHIgNyj
         pb+WNz6QBGqULRKOBWmmlwlMSb5K8qL4raf6zeElkK9+l6EfFn7k3sSuhZAsDkPFdjvN
         AS/dHo/1m4PTCo+Ub9B0Kkg4aJbJHUY609Cj0XFXXLR5uZvTDTuoT2fkPPlkIecMB6h5
         rKnD+etBm8oADlXjhmbKc1dCGsYA+V4tQb9iVw/rOncZhnJg5xYgswyKItSkP9xZ4w/d
         GIoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qdqluFG26YPGKzEGYfK8OFTjU+OJieX8X9rfVlvcuxk=;
        b=C7fol7ySkqnjsi8yQhODfHNhT1PMlr1wZRgsG9Cw7tXtMYJaJKiZjKA5pMjtk7yfBs
         jYgitRxCUqWJpyzvGGuBoXYQC+gPTHok1P+pngVu1PdGdyQDpqg+RXPFbVW4W42k86sV
         0el1xII294B1wPyP3mskvjSauCJ+0Ob1SWrRdMGnOVmLA3UB0D17gjZq1j6Q0PLVGG5b
         /EQxRTTR6gjDUWEOUEw+vxn+YlOEy7anuyhBMfeFVLoqQ5Ko+/69dOxEvZ1u2sI8Y14j
         rgmDdLNYpeKCV3XdPrG+nAJOlXqrXmLrjII+wSNtNY8Xmjoo21MC5jqrbNurqeDIZhOJ
         SFxw==
X-Gm-Message-State: AOAM53297EzThMQ/bPN+zYgFSoMorztftS4J4Rq+3TNw62/YCo4lw6wt
	fHEzXFNWncPAkujfO9E2Bx0=
X-Google-Smtp-Source: ABdhPJxoafrRRPtCQSofN0utlgxJAO+UNA2ltFoiZiJh4s+Luqk11llcrURB0secIHwygh+xY6zGIw==
X-Received: by 2002:a1c:7c02:: with SMTP id x2mr2734495wmc.183.1591786937512;
        Wed, 10 Jun 2020 04:02:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6484:: with SMTP id y126ls1015106wmb.0.canary-gmail;
 Wed, 10 Jun 2020 04:02:17 -0700 (PDT)
X-Received: by 2002:a1c:188:: with SMTP id 130mr2669373wmb.93.1591786936944;
        Wed, 10 Jun 2020 04:02:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591786936; cv=none;
        d=google.com; s=arc-20160816;
        b=iZ2ktJ3Su+6TU/QwtHXJ7Ze8a2s6a28+lriWvroabPlmN62G7Ieslf2Q8Jdm9XVTp+
         t74JektPinJmYs5yLK4++YXFf3kwim9a+9WSQ63b7/tDG+D07AkbeUiC6H70LHjEV68Y
         j1LBK7hkBOXlEgCpwQEuO/a2rTUSvCAlQ/AoTTndTzG4Yz6f6YgnntwwcAs6ki53gukW
         mX5YlWd4/cM+4BxBRVxYVzNgylRi0CjEiTCRjWeo/Q82wd5K6BUpQ7gal2CClNfyDbWW
         vcr4L2ffz3ONtZ3ppllREAOz6RntFVSAu02u1ppyDohE3dErhaORJLQXW0qxV4FAs+nN
         HAcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7rhDhb7XG1irEJ3s4PZgrsrHfWLraefC8nvpXB2M8Mc=;
        b=ndkvZ/BSaRlzAvRSx1wkSCuyXEgncrU4jO7IBC65FOQju7aaFA4mGkxYuXbylrywg6
         uJCJ0OB+yc9pBZEbm7TcuyYfc8fCSNKOLtAqHmvJPSp6vCrVjpye4cEX1t1BKnixQIRg
         Ob2UdhoRT4IFyUoDLbn8yp8XYUezP/DfQ00NTA9MyVkazm/LoH9czDQtOIOzdRsaB+VJ
         Jf+rMAuk//f8E54g0dLsevkUNLdEUkNI0GhkH5xALbA8nwz3R02k+HnEBSv1vyS8+ETQ
         J5kc7rplvbv0WSzNB8/qsPZZm7e2puhpDgi11oF/xqNy5rrtTa2fmQbV2b7HLMHMwuYL
         BnlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CF/wuS5V";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f1si306514wrp.4.2020.06.10.04.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jun 2020 04:02:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id d128so1419500wmc.1
        for <kasan-dev@googlegroups.com>; Wed, 10 Jun 2020 04:02:16 -0700 (PDT)
X-Received: by 2002:a1c:2082:: with SMTP id g124mr2706952wmg.21.1591786936358;
 Wed, 10 Jun 2020 04:02:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200610052154.5180-1-cai@lca.pw> <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Jun 2020 13:02:04 +0200
Message-ID: <CAG_fn=X-da3V0OC-Bzd2rmkNuZ_bVpH_n7Sp5P_hSGXD4ryyBA@mail.gmail.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>, Andrew Morton <akpm@linux-foundation.org>, 
	Christian Borntraeger <borntraeger@de.ibm.com>, Kees Cook <keescook@chromium.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	linux-s390 <linux-s390@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="CF/wuS5V";       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Jun 10, 2020 at 7:55 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jun 10, 2020 at 7:22 AM Qian Cai <cai@lca.pw> wrote:
> >
> > kernel_init_free_pages() will use memset() on s390 to clear all pages
> > from kmalloc_order() which will override KASAN redzones because a
> > redzone was setup from the end of the allocation size to the end of the
> > last page. Silence it by not reporting it there. An example of the
> > report is,
>
> Interesting. The reason why we did not hit it on x86_64 is because
> clear_page is implemented in asm (arch/x86/lib/clear_page_64.S) and
> thus is not instrumented. Arm64 probably does the same. However, on
> s390 clear_page is defined to memset.

Can we define it to __memset() instead?
__memset() is supposed to be ignored by KASAN, e.g. KASAN runtime uses
it in the places where we don't care about bugs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX-da3V0OC-Bzd2rmkNuZ_bVpH_n7Sp5P_hSGXD4ryyBA%40mail.gmail.com.
