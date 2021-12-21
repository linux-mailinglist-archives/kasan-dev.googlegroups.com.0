Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHGGQ6HAMGQEGTN6QNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 277F747C160
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 15:22:22 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id p21-20020a1f2915000000b0031302e2fe0bsf1145154vkp.10
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 06:22:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640096541; cv=pass;
        d=google.com; s=arc-20160816;
        b=tFudBOYOqj+BtSSLsaCl/oKGPO0fqje8D64bf4uLwBK977Yy4VxJa9qFDRbJjSQkP/
         C/l3Ze8hYr4llReAhgvhPD8igRg+C8lyWVsf9kimMpE7RUecLmD0hGqx55GhzfZnqLfJ
         fox4Pb48I3mQhUjlbaLH+POdB62KkhtnZBVee0tobW7zDmh4U1WMY8kqBKgZWnPlEW5B
         t/DmT8WM94vrBiN4C14Byn5JjJbh6C3ZqxLa8vdPZD/uReUaLLA+7llgNaRyUc8qBcE1
         dTo2OTpJBbOjM4SDDwDsC4rT3khjwxOZyvWgCdhbRlS8MfTgtW0Het+E0uotXBwh+Pvf
         ta3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=02nCOs3O2xc9850BTOr4ZvZWKCIyNRu1H52scZQXfVU=;
        b=Z1QBuFgCMIP3r84HSFfKjYNPyyejs7a9RhXyLQH5uuM9E8myj/OIPt84KX5XxckQ9Z
         oWFGekHycdw8FXMQbnuuNnNZXEO3WA+1UV3hCeabzfgY7P4Kc6gfLWentRl4bCHKS7kv
         gX3xWv/mm9QxNKWEsIfl642lIe/lPcjGwXbrsytcPjmw8tzrBBuaXFHPyVxEzdNVMmEz
         TpdjOI5dIQXqnP0MNkZHMOvxiezAId3hoMUEPANOFNMng25GS79LEZg/NxzVIPyWi1v1
         jv02h1JZ7Ktr28ubVh4GxnWh8RsoE41cke9HPWahebjQDkC9aGhLnwIigo3tWTNK9C1e
         z/Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jV5Jbe2G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02nCOs3O2xc9850BTOr4ZvZWKCIyNRu1H52scZQXfVU=;
        b=S/iTaWQF+W2EvcvIcjvkzMKK/FYArnlW1rDT3rPlYT4MedZ+dIAwKjjMUqIarFirqQ
         bTAyTuoH9aLbcDW4ZF3Tb18TZ2BZD/kWiJBUAhbp7CNhEwiHUNNzAf8A26MFzWFHcJqg
         zvR4GEymDJdVCRI/NwXxJSCtXcPIVAJiOtORKWey7F4dwE60AlPamsQK0oEE1IggA9wV
         T179de9vFQ5eXqOfWM5pHPxcO9CK2izXS8dyFcu88e59xcuNDIH25InaxmO/d9Hteaki
         tm+v4AUlHlFXbD186KUGzdhTYi54oHM2fhtGOZrXeKE/lcE7UD30jUevLAN3HgFqWvEr
         r4gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02nCOs3O2xc9850BTOr4ZvZWKCIyNRu1H52scZQXfVU=;
        b=TcQ6feFBujX88I2cl4Ppf1voTwt0O0wz9K+fEyer8f8oEkQQHnL/P0PjBy0z0RcxDX
         DKVgttdgeJg83u3QGb2KdkLZB+m2Syxj8ucBA95W9cOIO/mZ+kUeuD2VPZ5pIH6EeNLz
         8gXorWjbWpd+wqGX5n0KRDdTSjB0EHP7Mfmn7wUjU2qcwccRoR3XFlok7zTtyVTjbb+C
         4YPKa9ZK28xlaienNS/M4UMgrbUHsoAymJOmVOobvSgN24UDP3mUDjrTTMJP3elUe3Rm
         Z+n7QNqsUbIfMNsF2yl57sc8iS8o9K77D3OZ1ZMeL0akLp3o9gkVJX6ZPHTdYbVPXmPm
         lx7Q==
X-Gm-Message-State: AOAM532hIKKBexIqoASP/9b5wE/70BAqHYmSY3GxMxQU/5HQ3+dg4C/H
	QrNTgJgrqrzPiwJ5qvuCiNI=
X-Google-Smtp-Source: ABdhPJz+aTA90Im0EYWec3ylBjEgyPgZIk2lEZynSl2XcBWSFEAjbMapcT+Vj9JZlBJMNWRFqs07tQ==
X-Received: by 2002:a05:6102:240c:: with SMTP id j12mr1300699vsi.26.1640096540889;
        Tue, 21 Dec 2021 06:22:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d314:: with SMTP id a20ls1502136vsj.4.gmail; Tue, 21 Dec
 2021 06:22:20 -0800 (PST)
X-Received: by 2002:a05:6102:a11:: with SMTP id t17mr1360827vsa.34.1640096540418;
        Tue, 21 Dec 2021 06:22:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640096540; cv=none;
        d=google.com; s=arc-20160816;
        b=cl0lrkCBVxQDBOtjyUqdrffdmiU7jSv+j0r32UPK2jYczsq2moyO3smkuBNzF+TJYJ
         gwczvAg/mHxk5ndKDpUGYy8dOJj9xMYTSpkJn/P8I3TdlyWpPoJkDxhlgaTSz+XCw2Pz
         x1aVA0pVKEk2oSepvUyP71IV4o0vHM8mN21y/dKF4kKpi6U3jDt89AsDvRLxNw2+3/V4
         TVGP/o6xv1q6VUi5FdAqW+l7K0tyv69piT91TjXmgcabzFCAVpEb4hZxOSjLrtZK7QYE
         iPicKqfPYnRZ0yZPoY2vBkOpFVijFKrCn0VUYuxCVFc5ptuJVb8pJrqYQs0aHJZkEcNW
         r/fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yqzH7iHpoKe60vr6KOoVUYsNEptHbcvizk4re1JPTdE=;
        b=02mr4URyP7CMuRDNuj1B0YCok+Nf9KZLX/TnxWCG+Uuk0Pejtcz//NUNIVccP5F6FR
         6Sxq4ZMFblDdaoX7sc5lmh67VHyfd9nsjNzfcUEyAWVWgjWhOLnMr6Njrpt0cN38MsN/
         6A68NNNMaMvfaP1HogUWxUlj8DXKXccrG6oOfk9RsEx7Q7aeG1SxpzbovELxtjEuBO4S
         E7fXQPaNB+sXZQJJeWKZCDt2ywCBbv7Dy+oftH9R1qnsaDS3n+VH1mBN+nsTXYNujzN/
         aylQFI9O8zYC0+JSQNjTt2Uv1Ip0wwoxMn6A/fjyq16fA5okKcVSQtn4LYieJbBCoyW+
         N1Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jV5Jbe2G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id q70si298252vka.0.2021.12.21.06.22.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 06:22:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id l17so481473qtk.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 06:22:20 -0800 (PST)
X-Received: by 2002:ac8:7fc5:: with SMTP id b5mr2375326qtk.492.1640096539840;
 Tue, 21 Dec 2021 06:22:19 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <f69174e2f6196fb502afa5785612e3a30e6a71c7.1640036051.git.andreyknvl@google.com>
In-Reply-To: <f69174e2f6196fb502afa5785612e3a30e6a71c7.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 15:21:43 +0100
Message-ID: <CAG_fn=WUEDxwSRP5U+3ybXLfWUtHDb66_GVabNWrxKLSD3sZ7w@mail.gmail.com>
Subject: Re: [PATCH mm v4 20/39] kasan: add wrappers for vmalloc hooks
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jV5Jbe2G;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as
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

On Mon, Dec 20, 2021 at 11:00 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add wrappers around functions that [un]poison memory for vmalloc
> allocations. These functions will be used by HW_TAGS KASAN and
> therefore need to be disabled when kasan=off command line argument
> is provided.
>
> This patch does no functional changes for software KASAN modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWUEDxwSRP5U%2B3ybXLfWUtHDb66_GVabNWrxKLSD3sZ7w%40mail.gmail.com.
