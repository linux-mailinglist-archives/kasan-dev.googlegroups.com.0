Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG76677QKGQESC5IQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id E6E0F2F3B4F
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 20:57:16 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id n13sf2375398qkn.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 11:57:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610481436; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eaw5fbQxKQjQyK3FinhYbap/dRm69wYgYB09UQNwxLRaqn1GiD9qBbyA17+/ybC97r
         0ShaAZStc9wZSla5ATm1mWvQoWUYSrxCo8o3iwAufQOqwMaxjK04W/5jOPabmDR+uJnA
         xDaZoJCh1P3LRQSIdjnmq4VXXls2DcOYr3yROVf5I9S5NsIO+ALHXZvjFjQ+W5fbx+IS
         rOSHO21XRcZXH+WAZOv2T6H6vWUzUC+LJBfR7X85pcz/XfYfd7fzar8gG20ngjhntnA9
         nSFyD1i1ig8n3yZ9//vGU3sJxk+gVcvb8Wc/+Y+XA3cBRnKyl3fJFy1hyOx+cPyIh511
         cOOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bkPl0tCY5kVdwm2Rw4KSSJenh0sHBeelwAatt2fzitM=;
        b=PqlHY7Vtydvr2VRR3FueaAWpPSYCnTAaGhDOiEbYYCkCXf142aelHuvIa9Jvn/IG8N
         TPWAEueDVOH3yZ9upUMWt2q23fdlkbbStXB8GJLXh33rzSpCLrDszs7TaTqVtwgh5iXJ
         SsBNh2Wej2mhTk08k4CUH9PYY+0YCE94PqQMuvZ3QtdyZ/DTSX0icnzp1/ylOptJ6W51
         9JeU6cDl7Jla7v2rL/sPJVq0L6LOI+2Samfn6qChvjBQ3dE2u8w+LezIpJII0fHqtRbG
         GMEnLk+4XzX9JrfGYmrTtGekWqDmx9gumVLSNiGWYYmyOiOQ1tTkFHdr+MIm4Fv8E4Zv
         WhJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j+uYJ02W;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bkPl0tCY5kVdwm2Rw4KSSJenh0sHBeelwAatt2fzitM=;
        b=C5jMlu9Dhaamc7S0U4dTnaH4JT7JObQMXuNsoACn97oInpQ9BQIeaM+g8zB7FoI+7d
         O/5thReHrxHoHlghPlvFA+gMO5oFqiaMwsZH36JthXtydkGmQdyHPxcAB0U5kFGDBnJm
         tEVgc6BOJfI+hmg2fQlgrmipHDub4vRp0JiU+QanvXELgG+KdfyWxAk73Kxbj30Jd4D3
         SOoXIuWP78JToFaYVzDyAe+WXLL5cM4DOsfmXJtxaCvl6YzgWpXBmzLHyqE0dQpZVJ9z
         foDHFDnA199ULqJbtQOytEGoRPORpdhfLaHaMXf4E3AdXR27NpJ+S7D/PbKVHN3Oy7i7
         +RpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bkPl0tCY5kVdwm2Rw4KSSJenh0sHBeelwAatt2fzitM=;
        b=Ama7YGP0H2M091TB32SVNj/I0XyVtO/mRIqom54+VUcNrBXKrKmNyrCI/hpqqju/Ax
         AoRSybMdXvSl5M3yIjHponMU1XCVvF47ZUbxwmJn1qjlPfzufIX8c1yunw0eKZT7zueV
         bCDQYqUj580b+QEuHLM8xJOZDCsZWkDrnnpHjITUj15JDRkbeigs8yZrGL65bjDPcxsH
         FqFcxzDkN34GCK2/69w3EHJFDQa5anwYo5UCyl95mqMKcb0RIAJ080u3q8JwcOoqA/9w
         z1Cgyi5FyoYklshtkzniQh1o4+kekTxol9Glfhzrr7rbjWykVJO+KBRAAlSc/lCw+nkp
         4Wqw==
X-Gm-Message-State: AOAM53101tOHqJqnXRn7/2BQPSJ8U/oj1xjhJk4wpWodZozM1cvIrBXJ
	W91PHM72kg6beDkrDdXuRsI=
X-Google-Smtp-Source: ABdhPJxbliA8USWLhHZaD52qizp/ukRtX21D+VknSTDZXZkdnAGmQiOpcRekplGyqaVrKQqkj+3fUg==
X-Received: by 2002:a37:b983:: with SMTP id j125mr1085163qkf.418.1610481435897;
        Tue, 12 Jan 2021 11:57:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b590:: with SMTP id g16ls984463qve.2.gmail; Tue, 12 Jan
 2021 11:57:15 -0800 (PST)
X-Received: by 2002:a05:6214:1187:: with SMTP id t7mr1156526qvv.58.1610481435481;
        Tue, 12 Jan 2021 11:57:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610481435; cv=none;
        d=google.com; s=arc-20160816;
        b=TbaI+86/458JyRURWDQHAeSnN+Ew+hY2IkiLGn4tPD4n48f2+OEmrbliDn7auDjvzJ
         dViU1rQueL3uP7y7RQwdUmODLyhGaJ8dRgzXa4iTFRBpZ07fO5FYuve9i69gIMv4c4/L
         xywKYAEGLWZVwr0TIDesB0CaHnnBEDPjrpmno9X8Pus9EE1WmKEzH0w7Al7jAeF4ZPrP
         wevZ/PLTQr6W6hKrIGN0pZHGS2hBSW6rInuQaUhTv6xhmY2tU+LirswRvlKA2F/N6jat
         ou+/kgbA6/R13i+6pL3WmdCvwJkq7W1gFkg69Mn6NqM78/+d6oySECCaEBEdlXPKeays
         wNzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lgOj3ewtZHsgYpuiLe3BFwKHrGEWEDXGYzULDKuvxQQ=;
        b=XVJhFJZFGOiQuO4Natcw1PDNdDjueH+BaLJKSf/wLA8GxWMxPdYtqGEzHDFhJmlQdI
         PzU5DDAkMN6H5YFVFkwn36HDLyBt4am4R744MNbleEryBcOPA+VBy7FND1RHcU352HCb
         Yns5BRp8qMEqK3h/ynsRgshYOQDnY5fFH0Z0ZnfbacT7V1TJMl4U9D0KwKTC5lsI3GLD
         ZkOfZz+pOt1H9/hiPigwtV1Kp7DFHKMZbKfFWZR0uxZt8ttCkpifOLa7mmzDYyMHM/a8
         yqvBR88Fv8QX8Cu2yGrzTFj5wqzedcVujEF7EJkUcu8wYB3HwjCRzE5Gq7M263GB+bO2
         Vbag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j+uYJ02W;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id z94si463167qtc.0.2021.01.12.11.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 11:57:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id v1so2287330pjr.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 11:57:15 -0800 (PST)
X-Received: by 2002:a17:90a:f683:: with SMTP id cl3mr813985pjb.136.1610481434518;
 Tue, 12 Jan 2021 11:57:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
 <CAG_fn=Uqp6dt5VGF8Dt6FeQzDgcEbVY8fs+5+wyMp2d1Z98sEw@mail.gmail.com> <CAAeHK+yFw5YcR1jAYbE+PSLc0NowCv88mS8kJLspe_RkSjX37w@mail.gmail.com>
In-Reply-To: <CAAeHK+yFw5YcR1jAYbE+PSLc0NowCv88mS8kJLspe_RkSjX37w@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 20:57:03 +0100
Message-ID: <CAAeHK+yf4omWg-UHLiy4-6NjWXQs7pe4GyOgQOZnnpkhco1DGw@mail.gmail.com>
Subject: Re: [PATCH 07/11] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j+uYJ02W;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Jan 12, 2021 at 8:50 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Tue, Jan 12, 2021 at 9:18 AM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > It might not be obvious to the compiler that the expression must be
> > > executed between writing and reading to fail_data. In this case, the
> > > compiler might reorder or optimize away some of the accesses, and
> > > the tests will fail.
> >
> > Have you seen this happen in practice?
>
> Yes.
>
> > Are these accesses to fail_data that are optimized (in which case we
> > could make it volatile)?
>
> Yes. AFAIU compiler doesn't expect expression to change fail_data
> fields, no those accesses and checks are optimized away.

Ah, actually no, it reorders the expression and puts it after
fail_data fields checks. That's why I put the barriers.

> > Note that compiler barriers won't probably help against removing
> > memory accesses, they only prevent reordering.

But using WRITE/READ_ONCE() might also be a good idea, as technically
the compiler can optimize away the accesses.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byf4omWg-UHLiy4-6NjWXQs7pe4GyOgQOZnnpkhco1DGw%40mail.gmail.com.
