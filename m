Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU6F2OEAMGQEASQIRRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A9D23EA123
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:59:00 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id h9-20020a17090a470900b001791c0352aasf1176851pjg.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758739; cv=pass;
        d=google.com; s=arc-20160816;
        b=eOynGPjatZZDZ8lEA+vfExmsKV6azJxr+1vaPZiR1mP3mgNX6pAaE1SIsfiOfz3tSo
         oTXtjPsXToBosFwKd9QdXtnuF7QUiUplX3adfyG+AFdrvu2XKa0lEFIEgM0WgV5YiKqd
         GvtsLTINyrs/PA9gGmeRflgUZmz4G+PziM7kJIv5hQ+WrJkrG5ZzdbC6W2Ue69QVTdxv
         C6mzB4U8icc2hZRP69mkGxuMgdicuxYtSjSQoNM5ancb2T+GsjV+Ge3eUzxzUVEvy7pL
         dVMuBg8014DOcN9WgYiSUueD0kJGpeQclK7pStbDFJUIBZddq6I8zBty34wkFYPwsnaA
         scpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vYg/Rk8mAwUgtfVjR2zkecneRxf1g4r5PDACN8Mtd/Y=;
        b=YtDQHC/2gRdQ3c+bw/xTzHC3fI+M/PqvIlMlrLNq9lLY5Mk3dC0fhOalYbMRufsvl9
         Lbviqr1Ai2ZyFfdqYbTX7QUSg/92KNrFQTsX5SGmhIJ5cAp+NH5tf3PjpG1jF481ypAV
         9kNHvxyF6DiDdAVSsIlp4GsOrSvhZdMGntLqH1skuaHBryD7TZxsO7NMKwlzZbOQzaoA
         W5fo3kvqLBNRYTJKd0bAHIScpxsbiSkuc9q6Y28iEu3M5ToYxwGFHpkmiLUEN01nJfLs
         p6zmPAQG0YegyZtN0or6LDKez6tVrgY7cLo0R+Bu64pOS/KmwuJMaNxD5SYeZUfW25Fm
         JSAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHg5LO9a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYg/Rk8mAwUgtfVjR2zkecneRxf1g4r5PDACN8Mtd/Y=;
        b=Yl/S0hg4miTkeSBhLndXzlX46aJnaNMMwH6QOQdolFVNMndNBEqjUU15FPOCrLo8Y7
         cKnmnUil+p0b30POUcBhI9lMX2Iv9RBbL85NMZDFiePsIkD1dnkVAZ+NAHZJrldyGAVE
         IhwF5hEVZMJB4G4buHmy6OnWPVe5hnQ6rU0ViSzL840i+eLShT1M0bYO5KppfXLCCDW+
         8RuKkiCrlEtML04I8+mcyFXBnsAS2J02VljE5qL7+xb2/vHLWb2RG7WSP7HjM2FE8iSp
         U7JUFvC9OBKFk/IFF5J8DAYqfFS1qecBKIm5AlC50gBRBpz8hUM4sUtYgp66HmfU6MSm
         71IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYg/Rk8mAwUgtfVjR2zkecneRxf1g4r5PDACN8Mtd/Y=;
        b=W+j5jf/Bw9lluz7ZSNnSBbY5mZHJLwxN2v2U8Ini3VM0Hjgys4lvT+WPq6iO+YEjqH
         giaJHhLedIxTD27fIVfgrqvdGc5OIkwwJQcaPJzSEbK5j6vVW/9Nc1dYcf1JF82FZYJ/
         tsTcjSpwLuJM4WMgBWoRg2gPXCnBMUGe19Fpz+agfdggN9KE34PYtGyFbJSX8mAX8pmt
         gkK8wY2v21ywXGTP1QAAhS0G6eI8+RtDKZ2XIVXa5HcV6w+DXTTYEVv1Ujuzn6yXEFkB
         3wjCk83q7QcgSXHr/7zWSE7hzEF9HrIwDnIProRWlvwhxmKNEwzTlqUWk37L/MWTU+DV
         7yKA==
X-Gm-Message-State: AOAM530826jyyiUQ0tL7kp+RdCXUsv16k3LhIyK8+OSIXTfHV6vS752Q
	hLJqLLjm2bQRaUJ1ExOhfwQ=
X-Google-Smtp-Source: ABdhPJxnMg4Z1KVDhQmzuhA/nikYlZo1Cx4kZF3z97zeSJOI/hKWxBH8Ae0u267Bl7JqWeiJzAUJbw==
X-Received: by 2002:a17:90a:2a83:: with SMTP id j3mr14657659pjd.185.1628758739308;
        Thu, 12 Aug 2021 01:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1cc2:: with SMTP id c185ls1863254pfc.2.gmail; Thu, 12
 Aug 2021 01:58:58 -0700 (PDT)
X-Received: by 2002:a63:515:: with SMTP id 21mr3038774pgf.70.1628758738786;
        Thu, 12 Aug 2021 01:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758738; cv=none;
        d=google.com; s=arc-20160816;
        b=c4Rh3eMrmTt/BaBzsMNPsPGkluH+Fd/RJGnS1sFLb4mqgEudz/e9dIPzUv9lQGGjLH
         NrLk4v4SR9xscml2P00l6ya4mHo83RblhrTvM9T+v2S38uWdXWXPF57drJRdbkAKVObe
         vDNuzQ5cCzkE/Pe6fGG4uZbafjVfqRjoyNVknlUAZn0Yl2ytyYP4FVtj7+d5iX4Zyv3o
         Ht/EPXAJzx+s2g7gLOMITbataNRsIO6WF8n3chdtookBOzz7WKfeTtXnaRmCVZFR/bU0
         wzruqPk1GKvOzT3of0A6t9iQDnvvDHUjDJTKynDZWuY1pOi6FkDGR2bz0Iaiu8XtHfr9
         S09A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=glSRtZn0PFX+XapwdsQxtT//X4Ni5wcQnHCn2+naPE0=;
        b=K2tm1pmpvmgz3UfcIaB7oE15XYjyCv8oFflVRw2BntMj+ph4ESZXa84G5g9nUyGTfQ
         vAqnNZdvx/LKBtDveFxEil+vMjsyN7978WAy9RLVnB0sFWkjZNU/DURiq9I9/W0TpfT2
         fy3+aAK6TBnF8qRhKCa0pA3CnivGXLO3rIRHiiItpI11f0XH+S+wkJWXKawduXyjOpMV
         n44D7QUq3kfmo9G6aaTxvXQbc4bFU+HppCkUYbnLMJ+ss0ZxuQvxl2FcLYBvXtDePF88
         VNkCjyJ+C9hL5yzVW5XVWzLzDUEjbXDR/cdMzf03D0ifMB81Z6LTCGjW433PMShaAXkX
         Dtcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHg5LO9a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id u5si579714pji.0.2021.08.12.01.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id be20so9216763oib.8
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:58:58 -0700 (PDT)
X-Received: by 2002:aca:eb8a:: with SMTP id j132mr2513361oih.121.1628758737993;
 Thu, 12 Aug 2021 01:58:57 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:58:46 +0200
Message-ID: <CANpmjNO+mvUF4S5n8QSDrB+caU_V79MH8_iw2=3V_W=Eh+SAHQ@mail.gmail.com>
Subject: Re: [PATCH 0/8] kasan: test: avoid crashing the kernel with HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UHg5LO9a;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> KASAN tests do out-of-bounds and use-after-free accesses. Running the
> tests works fine for the GENERIC mode, as it uses qurantine and redzones.
> But the HW_TAGS mode uses neither, and running the tests might crash
> the kernel.
>
> Rework the tests to avoid corrupting kernel memory.

Thanks for this!

I think only 1 change is questionable ("kasan: test: avoid corrupting
memory via memset") because it no longer checks overlapping valid to
invalid range writes.

> Andrey Konovalov (8):
>   kasan: test: rework kmalloc_oob_right
>   kasan: test: avoid writing invalid memory
>   kasan: test: avoid corrupting memory via memset
>   kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
>   kasan: test: only do kmalloc_uaf_memset for generic mode
>   kasan: test: clean up ksize_uaf
>   kasan: test: avoid corrupting memory in copy_user_test
>   kasan: test: avoid corrupting memory in kasan_rcu_uaf
>
>  lib/test_kasan.c        | 74 ++++++++++++++++++++++++++++-------------
>  lib/test_kasan_module.c | 20 +++++------
>  2 files changed, 60 insertions(+), 34 deletions(-)
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%2BmvUF4S5n8QSDrB%2BcaU_V79MH8_iw2%3D3V_W%3DEh%2BSAHQ%40mail.gmail.com.
