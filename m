Return-Path: <kasan-dev+bncBCA2BG6MWAHBBMOE773AKGQEELMMQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 22CE41F470F
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 21:25:39 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id m6sf9377560oie.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 12:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591730737; cv=pass;
        d=google.com; s=arc-20160816;
        b=GRMPS/lQJfX3w0O8ts5WdlGcRFLA591PMpxCqXJieZbITIYqLY3+iAvAWdToug9/Yc
         ccBag2EErz7Iwr8vgPRvOBetxn+bV4a2fDz0naYWxgsXj7WAClTLlaU7FRO4/Mx94fVz
         WhKQElGeTMKUY9pMgJb7eauf9+0UkXRn1/KOPy3137ttE0H+VMT3QioGK3LVEPcPL0uj
         8BIwM6/pwdvaskwJ0FRLNOMlOepRbJv5jViD4Tln08sw6e59PWZHfU64VFBmc9YQa8cn
         fte1cGSfKr8YEG0lCNpsiVJc7b3JLGagppdGVt+Ivphu6fnRsuke15GHVXQ4fUPAo96H
         OmeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q1miORQoYQHCxmUzi7GwfQEXwfTmuWD+jjqqQHISvjs=;
        b=ULsdbf02UD7dzTgFRc5Mud4WTL9JbQBdoNjJovUbG4E8Z4ruLVUQtsrwb9qsjNcLO2
         Fwhxijvulp9iZXikcib7czhywGUOBSi0JxSBHluI2Sygua0ZqDFgo6YUQlgTRvBX/lw8
         YpblHtH38LNYE899jJrUal+BiQk2aH8zmndZFskzLu87rlPV2dFLMqDQuNxUkB/XeVB+
         R5UjIhMktPvG1zExs7j7EYCEx7NA+2fyULdVWClgmERiQCgXmTRPV8sGDgp7YKrPQAfI
         rlzQlIS4yuddjeYsHf0O2zNmoaNYTd/UlH24q5GA4pFjqLWnGmnTyfVa44+KQSIOP0WR
         /+AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhEEqpsf;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q1miORQoYQHCxmUzi7GwfQEXwfTmuWD+jjqqQHISvjs=;
        b=IQwwQhDUqfK6bmo7/kdV5iAFEseDWpeCHhXDWMJKA1rCRlYag3Wvrqt/UW+1tgodvO
         FXngzPM9Khq7eRZMJ0inyF9+3IoPLFttmyuGQ0Bl4m+3rpb5vacSjoxIWqM+uirI0MXF
         4X6mXs99sljymHmjgAvK1Qec9/aBrndrfvI21RVJpFHqdZ4f4MUYt+WDWeeijqfNmbP6
         Yh3hR584l+aBfQbqYJ76eyJMBVrAKh2eavrJCvf+WPHRwmRIU+ur2tzmEvtMgbpq2EzX
         wPPeVds/g9U1X6pwQ5pI8j5kcohYKrhgS4x6MtpsBYUFw3QZ4lPIxPkIMnkjQBKNK+B4
         2rHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q1miORQoYQHCxmUzi7GwfQEXwfTmuWD+jjqqQHISvjs=;
        b=qVWrFzGMhmqm+qjONDOPU1anQ0uT+BpLFbZxoqVgN4n/LqYQcOwUiAshLUcTVRw/1m
         wlXpekF/VGh/TFscgR1RqxDhjpSjY6enrsdbTVJadR/cyLF9IzLOEtM72Yxd0ZnfA5O7
         W0H1aVX6iTSD0gY6/8AtxFsWrG55V6WY3y3Y8L4B6ls2y8YXCvnKsRYnvxjlxW6Wy+JU
         sbPlewMgZ7VtW8+u9ZPtE+eVtQOX2Dhj5e86XfOvjCuaob1fFhudLJAcr1Vb9omf4RWf
         Pyk7esPWxWtWC24zUkFd7nEFRvLhddvLbrkWEMs0JMkflYiZI0tGdZZR1LaerzVFjq+o
         xOKg==
X-Gm-Message-State: AOAM530NISYbhDWM09wZcH0zpqTT5qqDwhClODHqAbDc1Bi7+m4jhq6c
	mtOQZvxPZef0HvkAxiSkiYI=
X-Google-Smtp-Source: ABdhPJwOmBdBTrC2Ryt0FL6Og0GmJ5AQgqoqjevWnMhyngsYkTdxmAa7wWhsoqOOFNAajeFpyNA3cg==
X-Received: by 2002:a9d:3df7:: with SMTP id l110mr22148167otc.214.1591730737572;
        Tue, 09 Jun 2020 12:25:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1db7:: with SMTP id z23ls3295708oti.9.gmail; Tue,
 09 Jun 2020 12:25:37 -0700 (PDT)
X-Received: by 2002:a9d:1296:: with SMTP id g22mr24534331otg.102.1591730737257;
        Tue, 09 Jun 2020 12:25:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591730737; cv=none;
        d=google.com; s=arc-20160816;
        b=tYTBASiY94gk0O3d95/D6NyTrGY6u4pC/3biGPGgQ/WB+oUxMrk64xfcuD8vcvRmGm
         CdtpYiDrtyQA/R450cUWiPTSVxZLYNy6WhETw11wfGDwS/tj27Zk2S1L8hnvqm6WqcbF
         2cpv4rnDwyP3+T8J0kG2d5sNT4x21dUEz2dwkKrJ1K9bGRV4CL2c614S7qa03FvLrE7a
         MJtt/TYlPpUqAuzu4HPrPpeUJRf8wvwCG+PdCq9Spd/9jgie8rB7lBnQnfPNBX9qFtR/
         t5zGc064l9O6dFV0S+SnG/UdwH8+xEj0fMvIlh1sp1//4m5boILHlt3rlrD1Vx5GkqK3
         vxxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kFFH4rN6KjxMJmlzDoLxm8Mltw2hQsIo+kpRF7qr7R0=;
        b=xdlWkWL/CUQJ1eBEBiAowgwxVzNsGufFkaUXMrcb7V1DVK5bIRvBObiaP+Y/UQLBHB
         vRu8J64FyUo4MpOzDI00lmJ4mL0Y7TGGx/wcOhLOMgf6IyShFvdYWIumf48eVPvcROTY
         Mze72UCLOEl/UnB2XNPW7pbEwqXlGSBoOE8SWRlp+mONNMzXUc8GZ/zDlv0hRrhCOb+S
         AFEa/DjTkbYu8OXvdEbEsMZ9QUruJfbm5Mp1ismDVU3sO0rHKtZsexwJpqZZ+a8GT50n
         /vWkp4Q9Cq0j440hF2Z7uCWU22dpdvikaSVeBjYucCQcT+qvnQK43bVOLObPL8hfzT2y
         esng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhEEqpsf;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id h13si541964otk.1.2020.06.09.12.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 12:25:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id m1so10761112pgk.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 12:25:37 -0700 (PDT)
X-Received: by 2002:a62:6583:: with SMTP id z125mr26502301pfb.106.1591730736382;
 Tue, 09 Jun 2020 12:25:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com> <20200606040349.246780-5-davidgow@google.com>
In-Reply-To: <20200606040349.246780-5-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 12:25:25 -0700
Message-ID: <CAFd5g46Zn6DuDVB+2SLFd=ofc3J9DXEZ1cn9eTva5-EHueRONw@mail.gmail.com>
Subject: Re: [PATCH v8 4/5] KASAN: Testing Documentation
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, andreyknvl@google.com, 
	shuah <shuah@kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WhEEqpsf;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Jun 5, 2020 at 9:04 PM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Include documentation on how to test KASAN using CONFIG_TEST_KASAN_KUNIT
> and CONFIG_TEST_KASAN_MODULE.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46Zn6DuDVB%2B2SLFd%3Dofc3J9DXEZ1cn9eTva5-EHueRONw%40mail.gmail.com.
