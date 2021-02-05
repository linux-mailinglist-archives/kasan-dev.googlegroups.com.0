Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHXQ6WAAMGQEBV7PRSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 88D25310E31
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:53:52 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id b81sf5404587pfb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:53:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612544031; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kymlf3G0eOgaxxjNQBpjP6xXMKRPDyReLUuofVIqPBXS4NWCQv+FdhZNNF31k955jV
         IShfVheBVCIlgDaFRWz8GpnQHo9R7c0k0dZm9ru1/ohTirWnhC+OGGuJHZ2OdxyLbqCk
         oQD8dv06TOUXrtqUlEk6VSjwtBJZJu2K1c556Gsxbc9JyDOmHgNTGN+hIcUbPcgDojQy
         bhs+TdOMiPdkpA0PyswbLQjvgoRXuhnzFQQb2bRPozngoTU9GbVrnhyYKFbm8drziMET
         4lzQz9LPXgd2d/PZKlW8osO8e6wxBhPhEcygBVOiLOmzyM/WgR7ZfzvJj/xS3C29U7yU
         qvSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h3HrqMJS3c1P5G5qXsymNRsFPxy4d9dB1aMQDQ0qY+s=;
        b=Gf5haqW4iVIK+xk2HlJQhHVf7Yy5G/T3+MNXyjcwVDXNDICClj0SopNfK27w+yBwr2
         kk6NI8Rhz/zgFUEWbr2kgmxbleSAxJn7muAWdafKBJF2xA1a3rcKlVqez8eSDo//17UC
         8M15xi8d2bCuZIzVH8rxRXHuCNVkle83ALxm27DatX4eo95AXBahW65kDC3+ttijAzpG
         EYVJW7Vx8I4gOWGi07r6VFFhz1P2oNnvj/hF0okl6M270hl8GZdkt9AVn/5lnu7eSLzD
         mPJY+Uek7olICDPmLBSSj+aGAmjwApjwCaBYAqLDqhtNWEaThT6VCI25ZjsZ/Zf/uxu2
         mNkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VozpUkTk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h3HrqMJS3c1P5G5qXsymNRsFPxy4d9dB1aMQDQ0qY+s=;
        b=pbQ1Bv9YE7LIu3DgDlYEmz/3ohlBLi2gOE8/bLX0saP2sPzPuI3GdYxpsXhYSJIo9O
         f5jggdPgYf7ypJlh4CMhZG0R7VwnA59EBIu1nFjnnhWAJCWRAlYXTfsGIgg4nQHOXfzj
         wj+pP+2OHVez1Y9fzE8CYBsGN4E+dBkU5xYbtBRR+I0CqRqotECnk+WrtpE3tmhbJ2lf
         RCjw4dxROVbqW/TuASc3aR/8C+BBdQ9SGqYzIeWYBILe61+EwR7FHfTpw9hUSpiw0yK6
         OqXmGpfbFPOFrxNJH0tH7cOAdmfwpivXOwxU+qUfUtDuVGdkiut4xEYabfZ9a/9FuDKK
         MQeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h3HrqMJS3c1P5G5qXsymNRsFPxy4d9dB1aMQDQ0qY+s=;
        b=FtM+MuYKoLGvGcMVvJ1RJjBOzDA/R19UXHFyvJ1xD1+mdpKeP/IMnpo+7udBUYqp2Y
         gucC0BpYZ529eJT5UojsV6bpCyWtyXrNDsiF7nFx5Yvqjm1mVUQELvrCLiN4Fz8VsLqC
         LQDfsLRq3Jc5ajtn2gIzpSKu+h3gHlg6qGKKlEY+//iptaeylKsi41+6JshuCw0PA3+J
         P4j2LuD1nKHiXsTbB9fYBVOM4srN3Jf8coLA+PnkN8QfOKTTAC3MK0S2x00zsaM1oxm+
         aEKBbjFyQczoXCnb3G0M1bTQR2GnTl+FbucInbQDVPt5t1GfEX3ba34eOAm45dpwfpvd
         suUw==
X-Gm-Message-State: AOAM531/Oev4mfgGGcJ6TOF+8FBFaBiktnoAeD+WKG9wRdygHdk6Iltw
	7sQs87wJg31SR6Xt+pLNjfA=
X-Google-Smtp-Source: ABdhPJyO7p83tZ9YJhVUuF4s3ho03zyiH+OnqA1KQVS0f6QTukZUDuPEn3PacltFu5d7SDcjAiK6CQ==
X-Received: by 2002:a62:8445:0:b029:1c1:c862:8fc4 with SMTP id k66-20020a6284450000b02901c1c8628fc4mr5340726pfd.77.1612544031035;
        Fri, 05 Feb 2021 08:53:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:778c:: with SMTP id s134ls4010422pgc.0.gmail; Fri, 05
 Feb 2021 08:53:50 -0800 (PST)
X-Received: by 2002:a63:1f1e:: with SMTP id f30mr5363863pgf.141.1612544030456;
        Fri, 05 Feb 2021 08:53:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612544030; cv=none;
        d=google.com; s=arc-20160816;
        b=I4s4k43yQhmepuQG7+1aqlPN9aVEtaHECLDEl8/YoryhhspMK4x1Y9ViGoJzfrFNMS
         J8nY8vScAdqoydrzcZAJHbqmNlEuX66cyvyjIxrqi61fOzYvxlMnWe/aIET+q0VPCs5N
         jFvCmPG+x7tLnX0UbmxKbhg/t0OoI/byonwokUkV72UUc2E8P2YaouSbFaMw13Y+8GLR
         mdVB/J+mApxPcL3kp1zKdeNeK+bX8AZIpPFKUlcEwHm1Xy81y5Ptb2c62gSbbSFN/rfo
         iAV+GbIns88Y3VCimbSVo9UC8sB4n4XaTRosufH/HF5bCxfpnCi88hl/ENVdjEBaitpD
         sO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hcw9n9RMMUVWxg70MWeK9kZh+kpeij9pYEkv2fQx0mw=;
        b=qxX23xWGPUH0d9qJ7PBhHsvEN1l8cpiTbQL0t5zTwDs454MKvw8Wl9l0Bzv+xMMwu4
         IgRUULuTW0vuweY9KKfD7Sy5TaoGCtU6GmBs8cYpOVpr5Ox8uV2NYZprDmen0l5RxA95
         3HkbBEfhcfzWZzhk4QFmHYU7NzJTO49tds2cgd8NIStfw/Q7yyg267YkvE6fnfMFPHei
         V3uIjlXHpHFAyDEG2sDzHVXVbGqhvaRvkvHM/yRQJ1lb35Q1bdFmU8yqIy/rr6rV9uz4
         R0VQfixIZOOtxtc2wddQJ+p7hX+CAF5Jaqx2BIh1mWXvt629uOVMaFeotUfVX14vC0/x
         hKDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VozpUkTk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id d13si484716pgm.5.2021.02.05.08.53.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 08:53:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id cl8so3952331pjb.0
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 08:53:50 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr4916787pjb.166.1612544030033;
 Fri, 05 Feb 2021 08:53:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Feb 2021 17:53:39 +0100
Message-ID: <CAAeHK+zNRd4BZz4v2r2Q__Px+Cs1ncmBiYbLPyaTnixbiCp0nw@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] kasan: optimizations and fixes for HW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VozpUkTk;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036
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

On Fri, Feb 5, 2021 at 4:39 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This patchset goes on top of:
>
> 1. Vincenzo's async support patches [1], and

Nevermind this, Vincenzo is planning to do more work on the async
patches, so I'll post v3 of this patchset based on the mm tree.


> 2. "kasan: untag addresses for KFENCE" fix [2] (already in mm).
>
> [1] https://lore.kernel.org/linux-arm-kernel/20210130165225.54047-1-vincenzo.frascino@arm.com/
> [2] https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=akpm&id=dec4728fab910da0c86cf9a97e980f4244ebae9f

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzNRd4BZz4v2r2Q__Px%2BCs1ncmBiYbLPyaTnixbiCp0nw%40mail.gmail.com.
