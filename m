Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIPT5SGQMGQEU4EAAWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC06D4772A5
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 14:05:38 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id p8-20020a17090a748800b001a6cceee8afsf13936015pjk.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 05:05:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639659937; cv=pass;
        d=google.com; s=arc-20160816;
        b=JQCZaypAK2xRIcGvjRqCcSh8xrnY52PRTW9O02z+S72TgDtx7Ew3/6op8tp/PK0Gjd
         3AX8v0SLlYXaj+dU0BYwNZzmRpokdpCPy6BnF9EhfwqSG6f76dDWqmVfu39fXUniAQ+i
         ZY/AVsYx0TuNuYVM+BlnLDoKf/aVuJ8qFOMJa4CvW6OVSABQMS9L8jLrHqV4fMg02PoE
         5HLH3kREa1GleO6DZq0OcGHWN6ZFvHYRT/k8+AXQJqR82nB/kwcnSK42KwrAzOYUinnH
         NQSFC/ch7ae1VE43j1eT591gL3SpLX2RNWNlh+nrls1/WLQrAveU3a8tR5azlDt1dHHU
         uPOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oHU67qLd0XNPExmdxYQQ/RMJqa5thwubqPqf3WsDgCA=;
        b=fR0jHpcM54mOSapQqHEycgErWLXM6i063KVB9npGN3u+elesviM+CxoxT/RxCT9ko5
         lpf8Hsp6ukhvrH6tFf7eVg73KaPQikG+cmbV7ux4HHaMRxQ5cfr+3YZfdIBKATPoK4kl
         /eRRtsMcBOtP6AwWlAbsV9LNs6MIo/kd6mnOJbXIV1DH/TkCYsxS6WLeQm4QL1ACPWRy
         Kd4zBc3UV5erpS4hhZe4lI2bOvIRayqtQ63/tUClIIENgqUb7gqRRryp6mpLSzHnVxqH
         Zpv8nSGvPyqNeaHNJC+w0hsR77W05YM1dJBQf506YhsDmaOhHjYbIdks9LAG4RWbYWG1
         0PdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sFkavAu2;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHU67qLd0XNPExmdxYQQ/RMJqa5thwubqPqf3WsDgCA=;
        b=VOmAvbooHPRX0MpiwT6dwHgprxlNiOoCS2etaPtbtE79H9a5BzhA55GNFhGBv89rSv
         HRqcJDsWmPHD9HE3DsLv7AfvCkG8kEMCOtwEPkT3zMCK2EIahxvyQX8lkmXb3De34stk
         rxuZ+AxpJx5V2mJoN+/JYmPEaTFpuLBIAFBJud0e9KIGfs8PF81+AoKLY6fdFZJ/P7cB
         snrzYlizBsz5Iz6loPhUvKi119ibMN1YHHLw+kv3kvxOygIWxU8rRnWqC8YThXTyITJy
         HWwyrtbrp0wDyXn8sp826Z1SlFFACZSbtjVcxeoW+Fwsdly6L2HibjykBmV2Vwh8jBA2
         pR+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHU67qLd0XNPExmdxYQQ/RMJqa5thwubqPqf3WsDgCA=;
        b=YPX9n5pT2ndiGnMS9Lx0f+O5sDIQdF3k+zDmCf0QVBZhrdsybB0rkEaTSKYG5pfhLO
         NbbH/2cCCRzC1vX6TSLFAHwaDUJcMSY8UGAK2D8LxnNzumjr7u/Co4dYl+DGkAhFWZEG
         LdVCz3BHw771VN8tTouGxcwlPt81cajpBc6K80aAbrn7hI4mwDylqWuKC1c8S+AYvOk9
         TfVB+Bm83AjzUvJFbT7y6toNV1135dyGUS1mygHLK+HZkufPkX+Xah/YJA8RKzJTOoTR
         012mn3ohr6bFOblnYlXc5MTQBgmruLca5IqkrsrkcTUrJftPWSlNNZ+VcNFxKSullEI0
         Knrw==
X-Gm-Message-State: AOAM533fRfqkteKxXrHNyda4zwKX5Rb9UpqvImJ4nH5WXRT9McG9yiin
	ZD+EsZcp0wplv1LgotfGWqo=
X-Google-Smtp-Source: ABdhPJyr55PQgf5XMKwQxVDAAmmUIs0IvGvgWF9flQF/Ft5WxpX8i44hx+Dqwrxx5QrYk2v3TnxEjw==
X-Received: by 2002:a63:6cc2:: with SMTP id h185mr12542017pgc.306.1639659937552;
        Thu, 16 Dec 2021 05:05:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f687:: with SMTP id l7ls3763031plg.10.gmail; Thu, 16
 Dec 2021 05:05:37 -0800 (PST)
X-Received: by 2002:a17:902:e544:b0:144:e3fa:3c2e with SMTP id n4-20020a170902e54400b00144e3fa3c2emr16563676plf.17.1639659937011;
        Thu, 16 Dec 2021 05:05:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639659937; cv=none;
        d=google.com; s=arc-20160816;
        b=SggJ6zbWWWMv2lm9Am/FXa4/6+JN7MhsJOW/z9oTOcKpskwD80//jxQ8HX1FRpn3BY
         /fYjAdm33q9xcHirfLbKGBP1fUUKpWvRIFbK4bjkIjAeVQTkhbw7YGd4rVX5GiDAtQ+F
         ymZuCFjEG9ZMpeCjLVtRXiCPbXUHFxydfNeCXotLcYzXzdaRMnMBdY1iehkcHyb+4rvZ
         0vsr5RpI0RuX4P96x9r95AjMj4biftk6X7IJVRnNR+GOc28qs9d0seXjI6TifSjTSRR2
         oxjCpJ+xGh9kpUGfaFGF/sSCnT+IP4bJEHetA4y2e1fZ38EXpfIlQviGJHnZmupJscf8
         PVgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/pM8lzFE2adl9e7OGeD04l8kwcRxPJfnL9cXWkQLHi0=;
        b=ec2gpfBUc7UibHww1Z8BCnB46vRSZJq2jOn54l4x8quNWy40pieB37pe++T1rvHEIN
         Hfo8dH8ftLdOUWvqDpXpMVZ358NFZdAIwxLcbmgVzkzLdirUH5Ak5UAy0+dKkvdTvlwW
         vqxm8iNhkdo0aH2XkwHgVYQMtB8n8w2cPEHYrj0fXToCpmHM+28MW9R0w85MCy67judX
         ma5vPF6zPJvaiY7R8XpFjpcmOf7E4gyAqKTZuUXJML0Q8654GFj0tXcBUJ7U4Dc5gzXo
         w/4KD4MOjqZ98rJWOx2m65Gn0QRGGx8CzI//dlujMcsuamdZA3LXThbtH8etw/lEEroL
         zisA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sFkavAu2;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id d23si395925pfr.1.2021.12.16.05.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 05:05:37 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id t83so23158978qke.8
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 05:05:36 -0800 (PST)
X-Received: by 2002:a05:620a:2955:: with SMTP id n21mr11809849qkp.581.1639659936010;
 Thu, 16 Dec 2021 05:05:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <585c27bfa692331cd75de7c9dc713a318d3db466.1639432170.git.andreyknvl@google.com>
In-Reply-To: <585c27bfa692331cd75de7c9dc713a318d3db466.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 14:04:59 +0100
Message-ID: <CAG_fn=Vo9d3xrE_HGqZEHyT4jkkKy6-Raqqvz_a8b9TCqisPuA@mail.gmail.com>
Subject: Re: [PATCH mm v3 11/38] kasan, page_alloc: combine tag_clear_highpage
 calls in post_alloc_hook
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sFkavAu2;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
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

On Mon, Dec 13, 2021 at 10:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Move tag_clear_highpage() loops out of the kasan_has_integrated_init()
> clause as a code simplification.
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVo9d3xrE_HGqZEHyT4jkkKy6-Raqqvz_a8b9TCqisPuA%40mail.gmail.com.
