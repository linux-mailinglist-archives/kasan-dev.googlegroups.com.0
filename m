Return-Path: <kasan-dev+bncBDW2JDUY5AORBVM2YSHAMGQEA4JAV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C16F94828EE
	for <lists+kasan-dev@lfdr.de>; Sun,  2 Jan 2022 03:26:31 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id f13-20020a17090a664d00b001b10156c751sf20288374pjm.9
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Jan 2022 18:26:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641090390; cv=pass;
        d=google.com; s=arc-20160816;
        b=j1sQ0nK3GVorRZUjxHJYJc5a/bQxNyXV+WSStjOB+sK4i5B2zHTw89Rwoto3jpmQZx
         oY8PyVF+b3I3M2MMac6zWHryTNzDvUJV5cfKxi6NrmhCcb8PcKbrGUzz3nAC4FimU8K/
         azsB2eOpX/kY6qbo60WyeXJ9tlecF2KW5KQEPHkG87Hp9+ZCvGH0fMAr3fGzyvExEe2B
         FMOFQ7ZJuGv0p0Int+bxP8uHtSLJu3hM3l4stgURZMWuUqaTrk2aQVK94S70Q/Dl05J/
         bqtoehLJ3cbXZzMFc7GWZozX3yX+aaJSme8AYMZOq+xlYuAx7tgkhGfR8zcZOjGu27sq
         VRbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4lztehxs/TH/ZI2kcPkpbZ1KH44LDivTGSRDGekVs6g=;
        b=AIO5lm6iT+8O9zK8A9zwDNPG2RnQ8Nwgnlu22+K1QaHyMhtvyzcWeiFdpbKc0/4cAm
         Um2gWIRvrszV7bQ128nmByfOZbnliAAw3cq8qXTSGhb9MWyiNlpZtF7NMUkAnyD4en4j
         9/3sUP7PVG3qXaLZH275LDJClGYEr0RbMEp6gbEfuhpjsVRQSe01+ivOn1TY5lYNOJiX
         kbZipd0ZHZexl6ix/Wkh0pE/W6phDEj4gllD+IHK6glUEIVyLXEuoCknX4aEboMSc2mr
         l/q7g22Q0jzkcxHdLCKR0VAwPMJ7zBp03XaR9ZKgwLVZ7sLGYxq7RWESK5aSnEd1lKTg
         DJAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hC0djHOV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4lztehxs/TH/ZI2kcPkpbZ1KH44LDivTGSRDGekVs6g=;
        b=T5Mk/0HWqn49a8c+3mp5m/fadSxAmHmqNOc3FNFGU+rxwSEvka1Y+Sf3uP5LNo4DsV
         EWNlhAaLJQZU/m+8AuJJjbbKMJUIxOrFcAbGiDvSXjea7hEzBZ61CsV5Vs7VsMrO6Aum
         UEHBAntOumF+X9CREoYIZR91+r88EROfTKE4I1WMVbWWDwCLqZEMIX7cUd+4HuQAQmZx
         NdN4cdo8l3yKQCe5NJbce06iCsz8CWUOji91VN+Xe4FAwDMz5P256r2y5NdPqEUDk+W/
         AA+5kmjNI8XrIwv39bJmbSxvTZvp7W0C9atRncvgUthcSl8dfeEumaH8jnEV3rMz9ICu
         1qOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4lztehxs/TH/ZI2kcPkpbZ1KH44LDivTGSRDGekVs6g=;
        b=ISIFxav1+046yxx8LzBcRcf2O9/Zfsi4o1QQpRgevKgSz+sVh7P3kGi3TXz7hqBwHY
         ZvzT9L3eORNdQ6Aw3bxhgh6+nobYO3YCutIHKDZTscWSsi3LQ9Khzq/YjMcGJpbmnggC
         e3FDpzxleLE596U7QwpJwGa28N9LzSKph5ip6Ot9bxdG/pIWJXzBDgf4M97cbU9wF27O
         rxO13UkWRzK72iPOG3EoN0pbG+wUPcsi21ARQ8qPi9psx9aBRsloTHUq2PqI3H9Yd47d
         mViqaghO3n6rtYXKQhh0RwURSg3GNcXpcSZFgXps1kC8/ybX893LgzMQPsnt29cKsM45
         gVCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4lztehxs/TH/ZI2kcPkpbZ1KH44LDivTGSRDGekVs6g=;
        b=tQC9xhdAaXh2ExQqAZZG770JgLZo9gKAzpdZLDU5saBfXjeq5RFIdHIz5ovFxIxhr/
         klI6RSLUiKnese8SIZoYcTxF/6teeFl23+On7Q5YcdEn3wCLC/PrlRBEYd9QTW/D1SyS
         szUraGoGNxdxbcaYU2NfADxkfG6wOvQ2vH3O2ZCv0r898qQ4i/OPTONQvFJPV9jUxCyE
         ZMIQ8CoDgZt0EVOW3m9p0G+w/twE1P5y5+0T4/u51pfcZaqxPmRhkizSYNRM3fY5rWu4
         EjYBIbdiL9E1dN5X5KuXp9YhACiIok30uNkgKq009vY4WWdy40G3xlEMVrVeQmVkiw0T
         lHKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MNe0SIMYLMPKUcI3YXLf25u7o1UnTQgl0pumWIjMI9ebQbaAa
	UTtJ2lrZ7lQrCjib9+PGmog=
X-Google-Smtp-Source: ABdhPJwmVpPmmHLy+XKQBAiL65clmWCVtEkexwUvMWdX49fkN/3zcgrZxIMnHrUJ8tYHXCcEQ5N3yA==
X-Received: by 2002:a17:90b:50e:: with SMTP id r14mr49468153pjz.175.1641090390136;
        Sat, 01 Jan 2022 18:26:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:174d:: with SMTP id j13ls7385426pfc.0.gmail; Sat,
 01 Jan 2022 18:26:29 -0800 (PST)
X-Received: by 2002:aa7:92d1:0:b0:4bb:9d7:6951 with SMTP id k17-20020aa792d1000000b004bb09d76951mr41163515pfa.40.1641090389437;
        Sat, 01 Jan 2022 18:26:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641090389; cv=none;
        d=google.com; s=arc-20160816;
        b=zexJ2bFiTgGrchDwgBnp+uQl93m4sokpAPEG/zfQOtRUEhJ60Yos0Cg/o5K6PjgPgL
         1QUuDjVSfJmAtz4uxSObvsScCbuFnJ8GVhXMh/9crYgWqTp9VwaM1EmPv1hZ6w0It6rL
         KoP/2au4oqERV7vdgxsBPPqHyUw0F6zUEecvIr2S1Ppgb6zwNlIYHHCdrDlJ5+vJC+96
         u2m2JCbSaYTRwuOO7ImiEmkyVP6qvPS0ic0X4DIkxvkMPN5bBy7dCFMB80tTb6vbs8ku
         ggIprySL+nqOMgC1aXIDpqloLUJBfCI/XMzmAhbV5WdxMDQk6UU1XRBINZSSGPAl4Iqr
         SF5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UG2jSb8kA9oRJcvsbOmwOU1T1yK/woIGtRAfnSrv0BY=;
        b=ghr6Jvg5+PjgLLqJEP1FzSxaCtyoMu9cmoAyIo2X53VRs7u2d57B31yeAK+7qdOjZT
         uK9ySbkX0t00kxM5VBHX+oa+N2OvA/riLynFBZm1cYqT0Jdo6jhvvRga7v89tG+N4WWl
         cirWcQ3S/VM8jKVLU/DKIGJckBNRL8qoARIr5TtyG+jfYZZpN/A88blI76rhhr7hGERq
         bI+zMNy8vNf76Gqr7WC5iioYclvzAv5KDjz8u6RA5G27OueE48lS/0kN+z6ysN+4u7Zu
         /6CMtVXhGEo4FohapUjiiozY3PBZub7+x+U6a2ryVncgbvVBzG9YfgXREJgxox999gar
         ezlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hC0djHOV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id fa11si1493363pjb.0.2022.01.01.18.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Jan 2022 18:26:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id e8so23543353ilm.13
        for <kasan-dev@googlegroups.com>; Sat, 01 Jan 2022 18:26:29 -0800 (PST)
X-Received: by 2002:a92:1e0a:: with SMTP id e10mr18753598ile.28.1641090388894;
 Sat, 01 Jan 2022 18:26:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640891329.git.andreyknvl@google.com> <CA+fCnZd+sBzecOGBD8zR3CxXS1yjV-X3-epAb6N=ZT8rJdCU6A@mail.gmail.com>
 <20211230183054.a06a88b459b393957cb2d823@linux-foundation.org>
In-Reply-To: <20211230183054.a06a88b459b393957cb2d823@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 2 Jan 2022 03:26:18 +0100
Message-ID: <CA+fCnZfgBKMN967XfbtOpGJJmpw-5_M2M_hd4fSM7gSsqvd=bw@mail.gmail.com>
Subject: Re: [PATCH mm v5 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=hC0djHOV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 31, 2021 at 3:30 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 30 Dec 2021 20:19:01 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> > Could you PTAL and consider taking this into mm?
>
> What's PTAL?

It stands for "Please take a look".

> We're at -rc7 so I'll process this after -rc1.

Sounds good, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfgBKMN967XfbtOpGJJmpw-5_M2M_hd4fSM7gSsqvd%3Dbw%40mail.gmail.com.
