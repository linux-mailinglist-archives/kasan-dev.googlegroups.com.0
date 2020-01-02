Return-Path: <kasan-dev+bncBDVIHK4E4ILBBO7ZW3YAKGQEOXJLVXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id CADE012E492
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2020 10:49:47 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id k21sf1205281ljg.3
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jan 2020 01:49:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577958587; cv=pass;
        d=google.com; s=arc-20160816;
        b=hewJVEswUFnbYkQI4xYJPkcUfzRaRyiotrp843L8c8joUF8d2lrnfp5K9+d1Y7wYDT
         JBtxF3DxgdOFqQf7iTQo0xooJ7o4si8xcBH7y9J0wo1uuUMA6sdaiDXh0lljH7oB3Fhn
         bOjlYO0WD+z6MNQLIiwfF4+d+LTg1ORlfRXzjvl0553JwMQCZylJdcZVOTQOR8hPXaJZ
         Jf6bj/d6I4a/OrBo1JxOSWoVzuKUCpC9wMKqGbt4jz6jETDMPcRhXYSYDM2TOnoB2uPc
         XgAT9C75NlS4g2i9qgVxP86hbQa2M+YKLQHiHSpZj//VBhyTfCmder9ywRzRneBn99Yy
         D0uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ecVpfC/Mcgp70qFisOmdoRoKR7VW0RAXdkWkwv1qC7o=;
        b=KvErbqTw6615zWvMht+OFkgTkKOvMdGHcDgYGXeQQ/4hU8gXb/ScOmaUFm1mqC9jPe
         0xbTB6mutI+qAV7rQ0XSBeBfN+yDwRWpTQtsJXf51bcOvbsLlbRakkbKX9fKd0a/+16j
         Bg2TK1Rv8ReEtr+A5KxqqvZkinI3xA5N4XtL+PY3kTiMAlIRORzl59HMzyZfMVUyvBJc
         hWfMczNB7CnciYDC0U37RZORlnRpSlLrWMbfakmo0kbTODOvM9dYXpeJw9C5NrP5ixMd
         IJNwniRRXtLvXOl4NBmkNJYd2uaO8hUMkG7zQn4FIztSWroocZtLvtQQ2E2rbsSW7hZP
         +/fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=bfxdHICm;
       spf=neutral (google.com: 2a00:1450:4864:20::241 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ecVpfC/Mcgp70qFisOmdoRoKR7VW0RAXdkWkwv1qC7o=;
        b=e4Y60OxjB0WNipag+dZ1PgYJP93yswE4dNEdA37LYMJVfc99pdJkXGy4C2TY1zj3jq
         6xWWaKrhfhRL5ykNVJMLH3aV7IO02hVpS8b+7auJZSy28eNL5CVVo7Oi0pHEGVeTYkCX
         YNlAWu4dvJK9ofYsX7QmvwPX8ehlZW1jMyEKC1zWNs9rmVc34XgdrYmNJJX3zQiLq8Wx
         WhhrUGeOcz5M0M2lQuTFJ3BuBocH0F270r6j8DFy8xyQ+g0BhzkfCDUngBiahiz/inTt
         s5L7qrYSp8r6wTwuGvAe2aiYGtkWq/Te4wuvZJCovZXnJUEXxC6zlQoqadxIicBn160Q
         432w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ecVpfC/Mcgp70qFisOmdoRoKR7VW0RAXdkWkwv1qC7o=;
        b=O04I/YRBELgQq027yK6RVZNzoQE/f15itzwDSf9FX4V/cIPyMRNc70RBJiBK8yIgQa
         atUB4QOpFYHtu7FnCN4UhSF6kUjcz+Cp9ocuPpZbIM1AjzISh2gwX6+7tQegdVne/WiG
         DnZVsAVcNBdG1nmh9lCVPYBcWoIMOH/edLLOQ38P3a32PNVAT6hRlMYFA9N05mQgQPkX
         N2KvdsBCZhXUG1/6w8n6pLF7HMe0IaTity/aBbyiWEK4s57C/rhNAskWYiHmvevfIrt7
         dWtk441I88Owq42P0FRZ6IUlglQu2qJwWv1NLlpa06ij8DP6rm/Vyhs/naKSGE0HC7n6
         kPwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX1FWE2+y/Y9fHng17+ofTsIV0eKVnzYyRrIlrkV5tLIeKRWzJj
	Rc78Qv5vGrb2b+xQy9Execw=
X-Google-Smtp-Source: APXvYqzx3MAf6DqvrB6ctqACn47wEZ2Q8WTz0aD9zMDJTRurxVXzNBphS3b3Ff87ruB7Kgou6DQZtQ==
X-Received: by 2002:ac2:44a2:: with SMTP id c2mr47744081lfm.105.1577958587269;
        Thu, 02 Jan 2020 01:49:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c09:: with SMTP id j9ls4607623lja.2.gmail; Thu, 02 Jan
 2020 01:49:46 -0800 (PST)
X-Received: by 2002:a05:651c:102c:: with SMTP id w12mr47840087ljm.53.1577958586754;
        Thu, 02 Jan 2020 01:49:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577958586; cv=none;
        d=google.com; s=arc-20160816;
        b=smYBPKp6dmUP7uEDPSvsKi9YYOPM2S3Q4JJMr7SiY2DEUFbJO826yWdkul6Aav66Vq
         fBX//Ifr/y7El5NOI7V9EwZy0917FmU/G06JDZURmjtiEyV62zlPXXd2dZAi3dZ0o9cU
         JJwp/KK+scl/i2a4h3tT8FGIBR/6MdFDqIfxDfs9Sc8pRGbQiGggE3jTq4ppFQ1ZEb0b
         TfMKG2GJRd2tEwzR6ZmUJaucL7s/In6bDgPBZDz7SdW9yYbSXmc6cdpoc1/Ri74u6iic
         82AA/YQog9nyHHWKwDJGDC27m04whtJqeSb7hC7fBYx5kmMgg7rA4T1I2ZWPMPzeQvZQ
         MFYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CJNF7zzDiHYcqJL9y97v859TagsM8CsUOrBW1KXmnOw=;
        b=x6QDZ3p9Lt8Z0KyPv7zB6SpD/Jn2YCXCWSbdTQZ9agjo83tWytvlWfUDeHNr6Hygl5
         K1j0B0VaeYNKnXdmfhYOqvyykI8GZSvcM/i+bqZmFqBN5UlCwJr0beHs8wmQtU16QbJX
         crejOLVglA346adQ3qoa8mvumllR7Ac663SYojpKcMehLkjY8e1E7qBW8ngVkiKFBFUU
         uWuK+cb8JLehdCorLepygxFoNLi4h3A2gbldkZGnbyynNgzMU52Nb7ruKHA3evs/qp5Y
         uq2wWt4PItVu8vZqxVGSXgFPvu8UkKVGLj92T3eNVPsIEBT2S+HTwukVNpvje8+PdtfE
         wD4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=bfxdHICm;
       spf=neutral (google.com: 2a00:1450:4864:20::241 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id u5si2302631lfm.0.2020.01.02.01.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Jan 2020 01:49:46 -0800 (PST)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::241 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id z22so35336153ljg.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Jan 2020 01:49:46 -0800 (PST)
X-Received: by 2002:a2e:9008:: with SMTP id h8mr49408333ljg.217.1577958586448;
        Thu, 02 Jan 2020 01:49:46 -0800 (PST)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id m11sm23025754lfj.89.2020.01.02.01.49.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Jan 2020 01:49:45 -0800 (PST)
Received: by box.localdomain (Postfix, from userid 1000)
	id 1A2C410006A; Thu,  2 Jan 2020 12:49:46 +0300 (+03)
Date: Thu, 2 Jan 2020 12:49:46 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Borislav Petkov <bp@alien8.de>
Cc: Andy Lutomirski <luto@amacapital.net>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
Message-ID: <20200102094946.3vtwrvxcyohlqoxh@box.shutemov.name>
References: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
 <498AAA9C-4779-4557-BBF5-A05C55563204@amacapital.net>
 <20200102092733.GA8345@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200102092733.GA8345@zn.tnic>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=bfxdHICm;       spf=neutral (google.com: 2a00:1450:4864:20::241 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Thu, Jan 02, 2020 at 10:27:33AM +0100, Borislav Petkov wrote:
> On Thu, Jan 02, 2020 at 04:55:22PM +0900, Andy Lutomirski wrote:
> > > In most cases you have struct insn around (or can easily pass it down to
> > > the place). Why not use insn->x86_64?
> > 
> > What populates that?
> 
> insn_init() AFAICT.
> 
> However, you have cases where you don't have struct insn:
> fixup_umip_exception() uses it and it calls insn_get_seg_base() which
> does use it too.

Caller can indicate the bitness directly. It's always 32-bit for UMIP and
get_seg_base_limit() can use insn->x86_64.

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200102094946.3vtwrvxcyohlqoxh%40box.shutemov.name.
