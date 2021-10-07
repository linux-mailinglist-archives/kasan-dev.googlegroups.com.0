Return-Path: <kasan-dev+bncBDRZHGH43YJRB3PD7SFAMGQEDCWML4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80CC24259B1
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 19:44:14 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id u19-20020a0568301f1300b005472c85a1fesf3840390otg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 10:44:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633628653; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cpy8oT9IFJtrdbJX8GNlheEpbNufdLPMPa37B8noMLUh/wJZ7cGCj1ZDGzWYMOFpmy
         Skg+jDumWbmeA2tkoVr17isR4JfbR4wpC5Mr1tFrnHBevWt2dOgXLyounlPWUjvSkI0+
         q2bfq56G3aW2vt94BR2bHjXk6wtHL3215QlGX1D8wmdWKtTMMhicMy57x86fmIu48ao3
         UDr8FFq1NbyeGKrdpsEJLiBJCbroE02SJ8IaniDvOpVcmvjSpPzWaSmbFGggCxqGr0uu
         G3tHGE4phiVe7+HDpHMASiVNrNA9WYUtai98Bs2T+EYt2DObZm5c2cZpaLC5OUolOTcM
         QrZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ZqEfkS9wAaGsOsr6KhKX3muEce0zmLe2wzNq5/xZ260=;
        b=F3y63qnuBmj0czeTKb6Bc1Lwffqg4f3QSnhZ5WlCsLAO1vVgrrB+c/wFZkv3kcyY8E
         K704rfVkVuTi3IU1E1L1Oz4x4SyNxEyIkqh/YCDFMu9LU28sKkQ9PKLQMlrsKAGI8ZsP
         3Mt/fKc6foM8oMm3JkGtTMU0IrCaP/psrMj51U2E5m0bVM28B+k6Ar5YmyvT7kTpq5WE
         JVLhELOWaJdCuKEW75piVvHhp/Q/79j78UTXY5v4Z+dj7TzCoJz7nJY8v3liCY6Z26kS
         rjd+XWqkHkiJd35cEXpzbj5lo1jJPr5YsRrNCWebeSvNmsK5jvA4MJ70CDKfnfMTNIOD
         i89A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Ts9uM/Uz";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZqEfkS9wAaGsOsr6KhKX3muEce0zmLe2wzNq5/xZ260=;
        b=ck7v1cYfCNcIjTEWp9GPu8v53KvjspvAp6ThbeJMzcQYxt/2LjXOWQNi5nFWITEoaI
         GWc3H/dIPoY9OEST54Dxuk3uhOwxLafPghp6jlgx2EKYHfNmIvys0G5vOYOADMOlgBkB
         BevtF/9+mmKuBIPak0k+9Xaj1e0wifI9Ab8dYncERFLVvSd3bBUzpdIhS5s19nMDZ3pk
         14cKiUPI/0rMddZ5116eFHxSlNe4IR96oPACppQAZpVj0+Gdc+jV9MHqeh5S9XoRuqeT
         zArps633nBrJXzNlz4Mo/qCqz2beNvESHp1phsvJP3UOQPr3I7/hMWrVhvBn7UkaH+0J
         PYfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZqEfkS9wAaGsOsr6KhKX3muEce0zmLe2wzNq5/xZ260=;
        b=g8a/U3sCtHp8qtfMgSMqZjd6iuiD2+QIBkiaRf1evZgyC/72JW4CejepKRd1g7MmKj
         pQjireMkh3kniq5i/eG51BIQ1o1xYaWW6EIxLn+toa7h0DNHxDUyynGpid6elmItwjeC
         mt1zQ2er6qhiF+JYmmbFPXMth6feu6SFCCUffV/psdPM5E0X01JhbWmdPEh8FVcJbyJq
         +4p8xth8cDX5xu9GiZdL4889X/rL5OMtqCUvmQDtyNh2H/uTrvv58CeWJCzmCVRaePHo
         xLfF3VV+DeEA8E0szFQ8ENlSjiJUEnw57hefiG1WqK7SfV7QRvZBY9NF8Ch93FWLJAgP
         0PPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZqEfkS9wAaGsOsr6KhKX3muEce0zmLe2wzNq5/xZ260=;
        b=zeyL78/DukHQMS5M4+FNmK45DSml8csKh446rdueXk/DbuBCHrw+pLoy8VnZ/JpChK
         Zseneb+sNWRwMg/lMT3uUKQ9mQTPZ+D82HGReoS9mqhwfhPHx8HnM8rXROAFFkFBVK2V
         2FkpzE3/X9LBPhFA6kYQp2TbiGh8tElfwkbeo8ofm34rz9LT1Dvvz/oBjTTon4ZOE/B7
         Bmu0Y7I3YEptniNRZ7VSBl/qSMOJa1QzaoSbFj9v582wnqqnFRWCZn5oCLSZ3sRGdLNL
         tKhUF7HOW0y1pNpxFrAzuWgUkWo2/fN5Ls+2Iz/zOvPhXrFTPb5OQFaA+jVuYygPnrNg
         qU5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531w8oibQd6/gs/Srq90f35Bn7KJKxgOXCoQW/HVsilWKz0U+4Gg
	FdEzq7yN1A3NNlAaqVxXseA=
X-Google-Smtp-Source: ABdhPJzChIOAZGLncHIS+XLVgPTILn8EjT3Nv7diJEbIJq3DI37Hnial6Stm0mZBKsP6ULB7XIspIA==
X-Received: by 2002:aca:1101:: with SMTP id 1mr12853957oir.85.1633628653493;
        Thu, 07 Oct 2021 10:44:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:196:: with SMTP id w22ls222427oic.9.gmail; Thu, 07
 Oct 2021 10:44:13 -0700 (PDT)
X-Received: by 2002:a05:6808:1992:: with SMTP id bj18mr12900044oib.125.1633628653012;
        Thu, 07 Oct 2021 10:44:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633628653; cv=none;
        d=google.com; s=arc-20160816;
        b=K6LRML/WI42uhdlwi2TT7LXRASCWl0GaFnsx1v1Ft6tt6KZ98HTnlcWCt6CWMBXjaq
         qOFaIANcgJmSJ1dd8/YfW+wVQUbWT+WNbX/kx3mQWdFILV2SBucTSFnkIW4rbhmbrq4R
         LSVctGWFwiealATtumTonJCnb6eEOANvgRn/UHq7RCfEnC09fm/8yHSEjmfElG3Codl2
         BHZO1zGnjExA7eSndVIWNHgE9tux50wRYUiWoegIW2wdfLkh31RFzilTRGfsBEYbc8c8
         TCdm25fE/vhJ2pLN/WcFNZGd/y6/0SKZWPLTxF5VW64TCFi6RZCwcy7wQEQKG/kaUpWb
         rs5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+Z2Nt1ECMKgdwM/761fTZR4jFazW97iKGpDreDJ78HM=;
        b=QqO2rjZoXVm8fMO+/dqrcajpAb27R/ytWsVuQ6qo5yA4fSdHph59tWKycW7Ky3aQQV
         5r7I4B+UPj5U2aGIYLrqXtJQUKuT4sqXSCHQhRpYcJROMYlolfZWU1/sFWea8EWJfwhU
         Qc7ap/O35SA+9E8gsGYhs4D/ndMCz0iGq8SFu6Bw16Bxcf+JmdO4n38Tvol3/WUpCNIU
         v15GR4Qyw3Vy3KZyQ6SMR8R8xq4T0JxK/gU3ztuVv+3zpDe0Ce3AKVEdceEUd8FsjoM9
         8MGbzCNc/V6C6hRPzaBIyNm48oe4P5IHV1yfVGpNpso4V+h9DBLa574Ve3r2da5IeKJY
         T1/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Ts9uM/Uz";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id bi42si21665oib.4.2021.10.07.10.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 10:44:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id x1so3749313iof.7
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 10:44:12 -0700 (PDT)
X-Received: by 2002:a05:6638:297:: with SMTP id c23mr4122812jaq.131.1633628652593;
 Thu, 07 Oct 2021 10:44:12 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux> <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
In-Reply-To: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Thu, 7 Oct 2021 19:44:01 +0200
Message-ID: <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Ts9uM/Uz";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Oct 7, 2021 at 5:47 PM Marco Elver <elver@google.com> wrote:
>
> So if rustc lowers core::ptr::{read,write}_volatile() to volatile in
> LLVM IR (which I assume it does)

Yeah, it should, e.g. https://godbolt.org/z/hsnozhvc4

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72k2TwCY1Os2siGB%3DhBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q%40mail.gmail.com.
