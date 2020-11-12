Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWEWT6QKGQEWPMKXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 572EA2B046C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 12:54:12 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id o23sf3504102pgv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 03:54:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605182051; cv=pass;
        d=google.com; s=arc-20160816;
        b=nr9NHrF7hu83G2cFiH0rKc3NhpkuRupTlxsOmkYPdBWmQIHpAcgzOqP1e8GtDEaJTO
         FwcxdB0MWGlG1flv6DTGitTFaBFCPNbAfNmlUzhB9bBpLW4xd1o5HGw8uqw6Z6ULfmCp
         VNT3cYuzzsnyu25b9m0L2FhTHWDUqx4zniNkB1AQm3FgSeO//C+AI4MIiQ1D1OSH+qKv
         I1224kCNxcuNJuoutoAAUNFpbjKlgTbQ6gomfXSJ5STogfSPTrH3RNGQxJWIOqOvDZeC
         t2qIR7nmykmrOq9haR6dl48oZZhPfJ31EDcnuEXiH2vXq9H/P/UDt5lqE7CSifInZEV0
         KA2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eLmc7SM+TipnO8Zg9gLAzbYvQB/3FIS16Sc1RYzCh4k=;
        b=Ogzh9x/e7f1MGcZqXgN3mmVbfejePzE1coveHL1Dd6eO4MKn4CeUWyGiTmYTW7UG74
         swmbMNwzV0VvFxMnW+urLdIav4bTzon6XnbBl/Gqc2k2CU6VRmOukNGiLbKPdfkjQJo1
         K16PTOIoHWKWOCQ3Codu0vDE5Gv06z/F5EyIaCZMRKynIt9UrOQ5F9F1BevrLhxK62u4
         2BBxuBPm78I6G64piYkl3CrWo+IpYWhl9R+d0Rq0cGoE8Z0i+gYTG3IUUgLb2f1AHbjd
         6JD0EU6De+m72+DB2eBt5wDlu3noZHwESrSA7gWZ8nw4LdANnijxeid5sSuYyAyVNhCr
         NYlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qyNRVH7u;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eLmc7SM+TipnO8Zg9gLAzbYvQB/3FIS16Sc1RYzCh4k=;
        b=cVf8aIi1UT1Owvr0WHl3c7NyyWC/FPyn01jnWyG1O7pfRcl3FR1thyMl36eMM4d70x
         vydERlW7mRRI2rXw1TrBkVK4goMFaGcHEubnCpIAicxTH9aXsokE8ScJDWgMbuE1UwnA
         bej4NVdRUDzuzmAidqBle9f+7aSK4fqT6Ds8YzgZC0E5utmcDiXcO8jHkLBUjJPmfkEt
         Qze0wz0DSysRP3Rva/HCJwaAwU29wa5ndraopMCs8icDft4QT8taJYkOMdQGoWuD6qAV
         HnZzcFwcW79uck3aaWO0eiNWCj8Tze3U/+4Pd/vfPvxFHHAslp5vhmHFXl+bDh2dIE1/
         T4Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eLmc7SM+TipnO8Zg9gLAzbYvQB/3FIS16Sc1RYzCh4k=;
        b=XyE7iZ0701KnbutIK4XJVE/y8KqamXDiY+pO68oa364q6gfJlYJHqZ+B3Lz0QFIt/H
         9Lq6yFYzZIqkjPmobpdLmxi1gWSf35Cs5enqLNMgDYL6TzQ5avb93BuFI5b9mRrT+YjZ
         IBLktVaZqC8akpqAbkHfhri4Sel2hzQoIvKj7HmyYyo79Bxs4LTqYqiBKp0SDb/IRj/X
         nbYsYuDZ5JmuMGKv8COzX7iNkXuiKThZzHWMhdpbqJyJN3oMS3tzhBlKbG7R0jGAnPJs
         1luQsfMBU9CeKlcapxIwvw4FnE+kdc+Zmm8cq7uNBh2iKeih6S/rUKcqYLtpJm73eVUT
         1B7Q==
X-Gm-Message-State: AOAM531F+EEfz3PWSQzknxE8wKYMjd61zOGZM0ezqrJaKrp2p4ok2oJl
	LmAp6CFk7/jdMX8At4+RksI=
X-Google-Smtp-Source: ABdhPJyzfhtLaltxtMcYaZ7AUVpIMfKv2HOitRw5q/SA/I8Pdc8hy/Lrn+wJJukch48OkSq3BBi2Kw==
X-Received: by 2002:a17:902:6545:b029:d6:9a59:800d with SMTP id d5-20020a1709026545b02900d69a59800dmr25467225pln.31.1605182051049;
        Thu, 12 Nov 2020 03:54:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8cc4:: with SMTP id m187ls973960pfd.4.gmail; Thu, 12 Nov
 2020 03:54:10 -0800 (PST)
X-Received: by 2002:a63:fd0c:: with SMTP id d12mr4657323pgh.380.1605182050396;
        Thu, 12 Nov 2020 03:54:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605182050; cv=none;
        d=google.com; s=arc-20160816;
        b=bwPUFVPnR8fPrdJFhc5kFJmPlqvOojvDxvX/s8MeBNhz9WUVpYhf8L+uPpi2+sKYNo
         n7+fbtH1CTJjJGjmjwnY2UNtBwWELQp08U0K8XUgWu9GKQIyuyHOdEsrJuPkAdV+o5Wr
         satDIv2tf2lLj8MI7bAdJ3KBixZSaGLCrfwIs2YapVycPEysDCsq3rGY5C8hM60R++XT
         KHNm2SBg2oD6+p9pLzGqVMqCwrvqO2mjSs5eYzo8GbmBGm4e0d4ymj0xvs93T6nhDvBp
         hlUlr/K3ZuNQGPsxoWffBpHfi19GCCWtqzauEpvPsH5vpW1Tx6n50gMDC/wy8GYjPo/k
         zMSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1o9Kbu1VGM16HQ/aEUEXh5dMeJ0YbhrbAtdFyS8sHt8=;
        b=tPH7jLaCzz5hHKS6+kAVliCQH9sn0ZvQQcznSX5VNt6pKugLXqVaWy1Y75oNsOND+u
         Y6aWcbHTj4YZZcWQMrTmWpl9HX1jWo51TAZwxyPlCEmkS7Vw6oIRU0gGgEHS7zyXUBMU
         NFV3Yb8RYdAKn5us+lzpLZBJ3IuMYY4Lk6VFu8iNeFtKSMQUq2zvPOkOSAZuho4zEnuc
         pQEzWzuJiUFeHGvgwrbj+P3S633o2lSawtup2zebthRcxbBTIGuN1yHzOLJDjSk2TBxy
         Xv/YjEqkhpn1tVMC3jzEc28XKjMIfOhU9WFmvRMwY2bde68w3zyXzAsE0JMP6T6R79+L
         EZYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qyNRVH7u;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id x24si304178pll.5.2020.11.12.03.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 03:54:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id m13so6041425oih.8
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 03:54:10 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr5397138oie.172.1605182049579;
 Thu, 12 Nov 2020 03:54:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
 <20201112113541.GK29613@gaia>
In-Reply-To: <20201112113541.GK29613@gaia>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 12:53:58 +0100
Message-ID: <CANpmjNMsxME==wFhk=aSaz19iX4Dj8HBXqjhDg5aG_iR-uk7Cg@mail.gmail.com>
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qyNRVH7u;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 12 Nov 2020 at 12:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20:15PM +0100, Andrey Konovalov wrote:
> > Hardware tag-based KASAN mode is intended to eventually be used in
> > production as a security mitigation. Therefore there's a need for finer
> > control over KASAN features and for an existence of a kill switch.
> >
> > This change adds a few boot parameters for hardware tag-based KASAN that
> > allow to disable or otherwise control particular KASAN features.
> >
> > The features that can be controlled are:
> >
> > 1. Whether KASAN is enabled at all.
> > 2. Whether KASAN collects and saves alloc/free stacks.
> > 3. Whether KASAN panics on a detected bug or not.
> >
> > With this change a new boot parameter kasan.mode allows to choose one of
> > three main modes:
> >
> > - kasan.mode=off - KASAN is disabled, no tag checks are performed
> > - kasan.mode=prod - only essential production features are enabled
> > - kasan.mode=full - all KASAN features are enabled
>
> Alternative naming if we want to avoid "production" (in case someone
> considers MTE to be expensive in a production system):
>
> - kasan.mode=off
> - kasan.mode=on
> - kasan.mode=debug

I believe this was what it was in RFC, and we had a long discussion on
what might be the most intuitive options. Since KASAN is still a
debugging tool for the most part, an "on" mode might imply we get all
the debugging facilities of regular KASAN. However, this is not the
case and misleading. Hence, we decided to be more explicit and avoid
"on".

> Anyway, whatever you prefer is fine by me:
>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMsxME%3D%3DwFhk%3DaSaz19iX4Dj8HBXqjhDg5aG_iR-uk7Cg%40mail.gmail.com.
